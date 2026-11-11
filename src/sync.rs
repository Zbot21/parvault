use crate::bootstrap::{
    LiteRestoreRoute, LiteStripeSyndicationBundle, LiteSyndicationReceipt, PersonalDeviceCert,
    ZeroTrustSeedServer,
};
use crate::config::ErasureTier;
use crate::crypto::{
    compute_sha256, decrypt_manifest, decrypt_stripe, derive_unlinkable_shard_pseudonym,
    encrypt_manifest, MasterKey, NodeIdentity, PqVaultMasterKey,
};
use crate::sharding::merkle::{compute_file_merkle_root, hash_shard_leaf, Hash32};
use crate::sharding::reconstruct_ciphertext_stripe;
use crate::storage::{
    BlockStore, FileManifest, ShardId, SignedDhtManifestEnvelope, StorageError, ZeroTrustDhtStore,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Default stripe size (16 MiB) for incremental folder synchronization (ADR-01).
pub const DEFAULT_SYNC_STRIPE_BYTES: usize = 16 * 1024 * 1024;

/// Built-in default directory names excluded by `ParvaultIgnore`.
const DEFAULT_IGNORED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    ".parvault",
    ".parvault-data",
    ".parvault-seed-data",
    "__pycache__",
    ".venv",
];

/// Built-in default exact filenames excluded by `ParvaultIgnore`.
const DEFAULT_IGNORED_FILES: &[&str] = &[
    ".parvaultignore",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".parvault_sync_manifest.bin",
    "folder_snapshot.manifest.bin",
];

/// Built-in default glob patterns (suffixes / prefixes) excluded by `ParvaultIgnore`.
const DEFAULT_IGNORED_GLOBS: &[&str] = &[
    "*.tmp",
    "*.swp",
    "*.bak",
    "*~",
    "*.parvault_restore_staging",
    ".*.tmp.*",
    ".parvault*",
    "*.manifest.bin",
    "*.catalog.bin",
    "*.envelope.bin",
];

/// Streams a file from disk in 64 KiB chunks to compute its byte length and SHA-256 digest
/// without allocating the full file in RAM.
pub fn compute_file_sha256_streaming(path: &Path) -> Result<(u64, Hash32), std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total_bytes += n as u64;
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok((total_bytes, out))
}

/// Stack/slice core backing [`sanitize_sync_relative_path`] (`ADR-33` Path-Traversal Defense).
///
/// Validates `raw_bytes` in a single flat pass with **zero heap allocations** and writes the
/// normalized `/`-joined relative path into `out[..len]` (`out.len() >= raw_bytes.len()`).
/// Rejects empty inputs, NUL (`\0`) bytes, leading `/` or `\`, Windows drive or stream colons
/// (`:`), and `.` or `..` segments, collapsing duplicate or trailing separators cleanly.
pub fn sanitize_sync_relative_path_into(raw_bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    if raw_bytes.is_empty()
        || out.len() < raw_bytes.len()
        || raw_bytes[0] == b'/'
        || raw_bytes[0] == b'\\'
    {
        return None;
    }

    let mut idx = 0usize;
    let mut w = 0usize;
    let mut seg_len = 0usize;
    let mut seg_dots = 0usize;
    let mut seg_count = 0usize;
    let mut need_sep = false;

    while idx < raw_bytes.len() {
        let b = raw_bytes[idx];
        if b == 0 || b == b':' {
            return None;
        }
        if b == b'/' || b == b'\\' {
            if seg_len > 0 {
                if (seg_len == 1 && seg_dots == 1) || (seg_len == 2 && seg_dots == 2) {
                    return None;
                }
                seg_count += 1;
                seg_len = 0;
                seg_dots = 0;
                need_sep = true;
            }
        } else {
            if need_sep {
                out[w] = b'/';
                w += 1;
                need_sep = false;
            }
            if b == b'.' {
                seg_dots += 1;
            }
            out[w] = b;
            w += 1;
            seg_len += 1;
        }
        idx += 1;
    }

    if seg_len > 0 {
        if (seg_len == 1 && seg_dots == 1) || (seg_len == 2 && seg_dots == 2) {
            return None;
        }
        seg_count += 1;
    }

    if seg_count == 0 {
        return None;
    }
    Some(w)
}

/// Validates and normalizes a relative synchronization path (`ADR-33` Path-Traversal Defense).
///
/// Rejects empty strings, NUL (`\0`) bytes, leading `/` or `\`, Windows drive prefixes or colons
/// (such as `C:` or NTFS ADS `file:stream`), and `.` or `..` components, returning a normalized
/// `/`-joined relative path with zero leading, trailing, or duplicate separators.
///
/// Formally verified panic-free and traversal-free under Kani harness
/// `proof_sanitize_sync_relative_path_no_traversal`.
pub fn sanitize_sync_relative_path(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    if bytes.len() <= 256 {
        let mut stack = [0u8; 256];
        let len = sanitize_sync_relative_path_into(bytes, &mut stack[..bytes.len()])?;
        return core::str::from_utf8(&stack[..len]).ok().map(String::from);
    }
    let mut out = vec![0u8; bytes.len()];
    let len = sanitize_sync_relative_path_into(bytes, &mut out)?;
    out.truncate(len);
    String::from_utf8(out).ok()
}

#[derive(Debug, Clone)]
struct IgnoreRule {
    pattern: String,
    negated: bool,
    dir_only: bool,
}

/// `.parvaultignore` and built-in default exclusion matcher for `FolderSyncEngine`.
#[derive(Debug, Clone, Default)]
pub struct ParvaultIgnore {
    custom_rules: Vec<IgnoreRule>,
}

impl ParvaultIgnore {
    pub fn new() -> Self {
        Self {
            custom_rules: Vec::new(),
        }
    }

    /// Initializes `ParvaultIgnore` with built-in defaults and parses `<folder_path>/.parvaultignore`
    /// if present (supporting `#` comments, blank lines, `dir/` rules, `*` and `?` wildcards,
    /// and `!pattern` negation rules).
    pub fn from_folder(folder_path: &Path) -> Self {
        let mut ignore = Self::new();
        let ignore_path = folder_path.join(".parvaultignore");
        if ignore_path.is_file() {
            if let Ok(raw) = fs::read_to_string(&ignore_path) {
                ignore.parse_rules(&raw);
            }
        }
        ignore
    }

    /// Parses `.parvaultignore` lines and appends them to the rule list.
    pub fn parse_rules(&mut self, content: &str) {
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (negated, rest) = if let Some(stripped) = line.strip_prefix('!') {
                (true, stripped.trim())
            } else {
                (false, line)
            };
            if rest.is_empty() {
                continue;
            }
            let normalized = rest.replace('\\', "/");
            let (dir_only, pat) = if let Some(stripped) = normalized.strip_suffix('/') {
                (true, stripped.trim_start_matches('/').to_string())
            } else {
                (false, normalized.trim_start_matches('/').to_string())
            };
            if pat.is_empty() {
                continue;
            }
            self.custom_rules.push(IgnoreRule {
                pattern: pat,
                negated,
                dir_only,
            });
        }
    }

    /// Returns `true` if `rel_path` should be excluded from synchronization.
    pub fn is_ignored(&self, rel_path: &str, is_dir: bool) -> bool {
        let normalized = rel_path.replace('\\', "/");
        let norm_path = normalized
            .trim_start_matches("./")
            .trim_start_matches('/')
            .trim_end_matches('/');
        if norm_path.is_empty() {
            return false;
        }

        let parts: Vec<&str> = norm_path.split('/').filter(|s| !s.is_empty()).collect();
        let Some(&basename) = parts.last() else {
            return false;
        };

        let mut ignored = Self::matches_builtin_defaults(&parts, basename, is_dir);

        for rule in &self.custom_rules {
            if Self::matches_custom_rule(rule, norm_path, &parts, basename, is_dir) {
                ignored = !rule.negated;
            }
        }

        ignored
    }

    fn matches_builtin_defaults(parts: &[&str], basename: &str, is_dir: bool) -> bool {
        // Any ancestor directory matching a default ignored directory name excludes the path.
        if parts.len() > 1 {
            for &ancestor in &parts[..parts.len() - 1] {
                if DEFAULT_IGNORED_DIRS.contains(&ancestor)
                    || DEFAULT_IGNORED_GLOBS
                        .iter()
                        .any(|pat| Self::wildcard_match(pat, ancestor))
                {
                    return true;
                }
            }
        }

        if is_dir && DEFAULT_IGNORED_DIRS.contains(&basename) {
            return true;
        }

        if DEFAULT_IGNORED_DIRS.contains(&basename) || DEFAULT_IGNORED_FILES.contains(&basename) {
            return true;
        }

        if DEFAULT_IGNORED_GLOBS
            .iter()
            .any(|pat| Self::wildcard_match(pat, basename))
        {
            return true;
        }

        false
    }

    fn matches_custom_rule(
        rule: &IgnoreRule,
        norm_path: &str,
        parts: &[&str],
        basename: &str,
        is_dir: bool,
    ) -> bool {
        let pat = rule.pattern.as_str();
        let has_slash = pat.contains('/');

        if rule.dir_only {
            if is_dir {
                if has_slash {
                    if Self::wildcard_match(pat, norm_path)
                        || norm_path.starts_with(&format!("{pat}/"))
                    {
                        return true;
                    }
                } else if Self::wildcard_match(pat, basename)
                    || parts.iter().any(|c| Self::wildcard_match(pat, c))
                {
                    return true;
                }
            } else if parts.len() > 1 {
                if has_slash {
                    let mut prefix = String::new();
                    for (idx, comp) in parts[..parts.len() - 1].iter().enumerate() {
                        if idx > 0 {
                            prefix.push('/');
                        }
                        prefix.push_str(comp);
                        if Self::wildcard_match(pat, &prefix) {
                            return true;
                        }
                    }
                } else if parts[..parts.len() - 1]
                    .iter()
                    .any(|c| Self::wildcard_match(pat, c))
                {
                    return true;
                }
            }
            return false;
        }

        if has_slash {
            if let Some(sub_pat) = pat.strip_prefix("**/") {
                if Self::wildcard_match(sub_pat, basename)
                    || Self::wildcard_match(sub_pat, norm_path)
                {
                    return true;
                }
            }
            Self::wildcard_match(pat, norm_path) || norm_path.starts_with(&format!("{pat}/"))
        } else {
            Self::wildcard_match(pat, basename)
                || Self::wildcard_match(pat, norm_path)
                || parts.iter().any(|c| Self::wildcard_match(pat, c))
        }
    }

    /// Wildcard matcher supporting `*` (0 or more chars) and `?` (single char).
    pub fn wildcard_match(pattern: &str, text: &str) -> bool {
        let p: Vec<char> = pattern.chars().collect();
        let t: Vec<char> = text.chars().collect();
        let (mut pi, mut ti) = (0usize, 0usize);
        let mut star_idx: Option<usize> = None;
        let mut match_idx = 0usize;

        while ti < t.len() {
            if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
                pi += 1;
                ti += 1;
            } else if pi < p.len() && p[pi] == '*' {
                star_idx = Some(pi);
                match_idx = ti;
                pi += 1;
            } else if let Some(s_idx) = star_idx {
                pi = s_idx + 1;
                match_idx += 1;
                ti = match_idx;
            } else {
                return false;
            }
        }

        while pi < p.len() && p[pi] == '*' {
            pi += 1;
        }

        pi == p.len()
    }
}

/// Encrypted, Monotonically Signed Kademlia Root Superblock Catalog (`ADR-15` "House Fire" Disaster Recovery).
/// Allows a user whose local disks were completely destroyed to recover their entire directory tree
/// using ONLY their memorized recovery seed phrase and `vault_namespace` (zero local `.manifest.bin` files).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedVaultCatalogEnvelope {
    pub dht_key: [u8; 32],
    pub owner_pubkey: [u8; 32],
    pub monotonic_version: u64,
    pub envelope_salt: [u8; 32],
    pub ciphertext_sha256: [u8; 32],
    pub encrypted_catalog_bytes: Vec<u8>,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl EncryptedVaultCatalogEnvelope {
    /// Encrypts the full `FolderSnapshotManifest` under both `MasterKey` and 512-bit `PqVaultMasterKey`
    /// with a fresh CSPRNG `envelope_salt` and signs the envelope at the deterministic `dht_key`.
    pub fn seal(
        master_key: &MasterKey,
        pq_master_key: &PqVaultMasterKey,
        owner_identity: &NodeIdentity,
        vault_namespace: &str,
        snapshot: &FolderSnapshotManifest,
    ) -> Result<Self, StorageError> {
        let dht_key = master_key.derive_vault_root_dht_key(vault_namespace);
        let raw_snapshot = bincode::serialize(snapshot)?;
        let inner_ct = encrypt_manifest(master_key, &raw_snapshot)?;
        let envelope_salt = crate::crypto::generate_file_salt();
        let encrypted_catalog_bytes =
            pq_master_key.encrypt_stripe_pq(&envelope_salt, snapshot.version, &inner_ct)?;
        let ciphertext_sha256 = compute_sha256(&encrypted_catalog_bytes);
        let owner_pubkey = owner_identity.public_key_bytes();

        let msg = Self::canonical_bytes(
            &dht_key,
            &owner_pubkey,
            snapshot.version,
            &envelope_salt,
            &ciphertext_sha256,
        );
        let sig = owner_identity.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Ok(Self {
            dht_key,
            owner_pubkey,
            monotonic_version: snapshot.version,
            envelope_salt,
            ciphertext_sha256,
            encrypted_catalog_bytes,
            sig_r,
            sig_s,
        })
    }

    pub fn verify_zero_knowledge(&self) -> bool {
        if self.monotonic_version == 0 {
            return false;
        }
        if compute_sha256(&self.encrypted_catalog_bytes) != self.ciphertext_sha256 {
            return false;
        }
        let msg = Self::canonical_bytes(
            &self.dht_key,
            &self.owner_pubkey,
            self.monotonic_version,
            &self.envelope_salt,
            &self.ciphertext_sha256,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.owner_pubkey, &msg, &sig)
    }

    pub fn open(
        &self,
        master_key: &MasterKey,
        pq_master_key: &PqVaultMasterKey,
    ) -> Result<FolderSnapshotManifest, StorageError> {
        if !self.verify_zero_knowledge() {
            return Err(StorageError::DhtManifestPoisonedOrRollback);
        }
        let inner_ct = pq_master_key.decrypt_stripe_pq(
            &self.envelope_salt,
            self.monotonic_version,
            &self.encrypted_catalog_bytes,
        )?;
        let raw_snapshot = decrypt_manifest(master_key, &inner_ct)?;
        let snapshot: FolderSnapshotManifest = bincode::deserialize(&raw_snapshot)?;
        Ok(snapshot)
    }

    fn canonical_bytes(
        dht_key: &[u8; 32],
        owner_pubkey: &[u8; 32],
        monotonic_version: u64,
        envelope_salt: &[u8; 32],
        ciphertext_sha256: &[u8; 32],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(168);
        buf.extend_from_slice(b"parvault-vault-root-catalog-v1:");
        buf.extend_from_slice(dht_key);
        buf.extend_from_slice(owner_pubkey);
        buf.extend_from_slice(&monotonic_version.to_be_bytes());
        buf.extend_from_slice(envelope_salt);
        buf.extend_from_slice(ciphertext_sha256);
        buf
    }
}

/// Metadata record for a single file tracked inside a `FolderSnapshotManifest`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncedFileEntry {
    pub relative_path: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub modified_unix_ms: u64,
    pub plaintext_sha256: Hash32,
    pub file_merkle_root: Hash32,
    pub manifest: FileManifest,
    pub shard_pseudonyms: Vec<String>,
}

/// Tombstone record tracking a file deleted from a synchronized folder across snapshot versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeletedFileTombstone {
    pub relative_path: String,
    pub deleted_at_version: u64,
    pub previous_merkle_root: Hash32,
}

/// Dry-run folder synchronization diff report (`diff-folder` / `watch-folder --dry-run`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderSyncDiff {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    pub unchanged: Vec<String>,
    pub ignored: Vec<String>,
    pub total_upload_bytes: u64,
}

/// Complete, cryptographically verifiable snapshot of a backed-up directory tree (ADR-10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderSnapshotManifest {
    pub version: u64,
    pub folder_merkle_root: Hash32,
    pub tier: ErasureTier,
    pub files: BTreeMap<String, SyncedFileEntry>,
    pub signed_dht_envelope: Option<SignedDhtManifestEnvelope>,
    #[serde(default)]
    pub deleted_tombstones: BTreeMap<String, DeletedFileTombstone>,
}

/// Lightweight file metadata entry returned by `FolderSyncEngine::list_snapshot_catalog` (`ADR-17`)
/// allowing a Lite Client to browse its remote/local vault catalog with zero shard downloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogFileMetadata {
    pub relative_path: String,
    pub size_bytes: u64,
    pub modified_unix_ms: u64,
    pub stripe_count: usize,
    pub file_merkle_root: Hash32,
}

/// Summary report returned by `FolderSyncEngine::restore_selective_subset` and
/// `FolderSyncEngine::restore_selective_with_seed_fallback` (`ADR-17`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveRestoreReport {
    pub route_used: LiteRestoreRoute,
    pub files_restored: Vec<String>,
    pub files_skipped: usize,
    pub bytes_restored: u64,
    pub bytes_saved_not_downloaded: u64,
}

/// Incremental Zero-Trust Folder-Backup & Auto-Sync Engine (`parvault::sync`).
/// Powers continuous directory backup for Neighborhood Cloud.
pub struct FolderSyncEngine {
    store: BlockStore,
    master_key: MasterKey,
    owner_identity: NodeIdentity,
    tier: ErasureTier,
    current_version: u64,
    cached_entries: BTreeMap<String, SyncedFileEntry>,
    deleted_tombstones: BTreeMap<String, DeletedFileTombstone>,
    dht_store: ZeroTrustDhtStore,
}

impl FolderSyncEngine {
    pub fn new(
        mut store: BlockStore,
        master_key: MasterKey,
        owner_identity: NodeIdentity,
        tier: ErasureTier,
    ) -> Self {
        if let Some(client) = store.mesh_client().cloned() {
            store.set_mesh_client(Some(client.with_identity(owner_identity.clone())));
        }
        let dht_store = ZeroTrustDhtStore::with_persistence_dir(store.root_dir());
        Self {
            store,
            master_key,
            owner_identity,
            tier,
            current_version: 0,
            cached_entries: BTreeMap::new(),
            deleted_tombstones: BTreeMap::new(),
            dht_store,
        }
    }

    pub const fn current_version(&self) -> u64 {
        self.current_version
    }

    pub const fn dht_store(&self) -> &ZeroTrustDhtStore {
        &self.dht_store
    }

    pub const fn deleted_tombstones(&self) -> &BTreeMap<String, DeletedFileTombstone> {
        &self.deleted_tombstones
    }

    /// Resumes incremental synchronization state from a previously saved `FolderSnapshotManifest`.
    pub fn load_previous_snapshot(&mut self, snapshot: &FolderSnapshotManifest) {
        self.current_version = snapshot.version;
        self.tier = snapshot.tier;
        self.cached_entries = snapshot.files.clone();
        self.deleted_tombstones = snapshot.deleted_tombstones.clone();
        if let Some(env) = &snapshot.signed_dht_envelope {
            let _ = self.dht_store.put_manifest_envelope(env.clone());
        }
    }

    /// Prunes local shards and encrypted manifests belonging to deleted files recorded in
    /// `snapshot.deleted_tombstones` (skipping any Merkle roots still referenced by active files).
    pub fn prune_deleted_file_shards(
        &self,
        snapshot: &FolderSnapshotManifest,
    ) -> Result<usize, StorageError> {
        let active_roots: HashSet<Hash32> = snapshot
            .files
            .values()
            .map(|entry| entry.file_merkle_root)
            .collect();

        let mut pruned_shards = 0usize;
        for tombstone in snapshot.deleted_tombstones.values() {
            if active_roots.contains(&tombstone.previous_merkle_root) {
                continue;
            }
            if let Ok(manifest) = self
                .store
                .load_manifest(&self.master_key, &tombstone.previous_merkle_root)
            {
                for stripe in &manifest.stripes {
                    for (idx, &shard_hash) in stripe.shard_hashes.iter().enumerate() {
                        let shard_id = ShardId {
                            stripe_merkle_root: stripe.stripe_merkle_root,
                            shard_index: idx as u32,
                            shard_hash,
                        };
                        let mut deleted_any = self
                            .store
                            .delete_shard(&self.owner_identity.device_peer_id(), &shard_id)?
                            || self.store.delete_shard("local", &shard_id)?;
                        if let Some(client) = self.store.mesh_client() {
                            let mut target_endpoints = BTreeSet::new();
                            if let Some(peer_addr) = stripe.assigned_peers.get(idx) {
                                if crate::network::is_network_peer_addr(peer_addr) {
                                    target_endpoints.insert(peer_addr.clone());
                                }
                            }
                            if let Some(seed_addr) = client.seed_addr() {
                                if crate::network::is_network_peer_addr(seed_addr) {
                                    target_endpoints.insert(seed_addr.to_string());
                                }
                            }
                            if client.peers().len() < stripe.shard_hashes.len() {
                                for peer_addr in client.peers() {
                                    if crate::network::is_network_peer_addr(peer_addr) {
                                        target_endpoints.insert(peer_addr.clone());
                                    }
                                }
                            }
                            for endpoint in target_endpoints {
                                if client
                                    .delete_shard(&endpoint, shard_id, &self.owner_identity)
                                    .unwrap_or(false)
                                {
                                    deleted_any = true;
                                }
                            }
                        }
                        if deleted_any {
                            pruned_shards += 1;
                        }
                    }
                }
                let manifest_path = self.store.root_dir().join("manifests").join(format!(
                    "{}.manifest.bin",
                    hex::encode(tombstone.previous_merkle_root)
                ));
                let _ = fs::remove_file(manifest_path);
            }
        }

        Ok(pruned_shards)
    }

    /// Computes a dry-run `FolderSyncDiff` against the currently cached snapshot entries without
    /// encrypting or writing any shards.
    pub fn diff_folder(&self, folder_path: &Path) -> Result<FolderSyncDiff, StorageError> {
        let ignore = ParvaultIgnore::from_folder(folder_path);
        let mut discovered_files = Vec::new();
        let mut ignored = Vec::new();
        Self::collect_files_recursive(
            folder_path,
            folder_path,
            &ignore,
            &mut discovered_files,
            Some(&mut ignored),
        )?;
        discovered_files.sort_by(|a, b| a.0.cmp(&b.0));
        ignored.sort();

        let mut diff = FolderSyncDiff {
            ignored,
            ..Default::default()
        };
        let mut seen_paths = BTreeSet::new();

        for (rel_path, abs_path) in discovered_files {
            seen_paths.insert(rel_path.clone());
            let meta = fs::metadata(&abs_path)?;
            let size_bytes = meta.len();
            let modified_unix_ms = Self::file_modified_unix_ms(&meta);

            if let Some(prev) = self.cached_entries.get(&rel_path) {
                if prev.size_bytes == size_bytes
                    && prev.modified_unix_ms > 0
                    && prev.modified_unix_ms == modified_unix_ms
                {
                    diff.unchanged.push(rel_path);
                } else {
                    let (streamed_size, plaintext_sha256) =
                        compute_file_sha256_streaming(&abs_path)?;
                    if prev.plaintext_sha256 == plaintext_sha256 && prev.size_bytes == streamed_size
                    {
                        diff.unchanged.push(rel_path);
                    } else {
                        diff.modified.push(rel_path);
                        diff.total_upload_bytes =
                            diff.total_upload_bytes.saturating_add(streamed_size);
                    }
                }
            } else {
                diff.added.push(rel_path);
                diff.total_upload_bytes = diff.total_upload_bytes.saturating_add(size_bytes);
            }
        }

        for old_path in self.cached_entries.keys() {
            if !seen_paths.contains(old_path) {
                diff.deleted.push(old_path.clone());
            }
        }

        Ok(diff)
    }

    /// Recursively scans `folder_path`, incrementally encrypts and shards only new or modified
    /// files, derives unlinkable per-shard HMAC pseudonyms, updates the monotonic
    /// `SignedDhtManifestEnvelope`, and returns the updated `FolderSnapshotManifest`.
    pub fn sync_folder_once(
        &mut self,
        folder_path: &Path,
    ) -> Result<FolderSnapshotManifest, StorageError> {
        let ignore = ParvaultIgnore::from_folder(folder_path);
        let mut discovered_files = Vec::new();
        Self::collect_files_recursive(
            folder_path,
            folder_path,
            &ignore,
            &mut discovered_files,
            None,
        )?;
        discovered_files.sort_by(|a, b| a.0.cmp(&b.0));

        let mut next_entries = BTreeMap::new();
        let mut file_roots = Vec::with_capacity(discovered_files.len());

        for (rel_path, abs_path) in discovered_files {
            let meta = fs::metadata(&abs_path)?;
            let size_bytes = meta.len();
            let modified_unix_ms = Self::file_modified_unix_ms(&meta);

            // Fast incremental deduplication:
            // 1. Metadata fast-path: if `(size_bytes, modified_unix_ms)` matches cached entry, skip reading file.
            // 2. Streaming SHA-256 fast-path: if mtime changed, stream-hash in 64 KiB chunks; if SHA-256 matches,
            //    update `modified_unix_ms` and reuse existing shards without re-uploading.
            let entry = if let Some(prev) = self.cached_entries.get(&rel_path) {
                if prev.size_bytes == size_bytes
                    && prev.modified_unix_ms > 0
                    && prev.modified_unix_ms == modified_unix_ms
                {
                    prev.clone()
                } else {
                    let (streamed_size, plaintext_sha256) =
                        compute_file_sha256_streaming(&abs_path)?;
                    if prev.plaintext_sha256 == plaintext_sha256 && prev.size_bytes == streamed_size
                    {
                        let mut updated = prev.clone();
                        updated.modified_unix_ms = modified_unix_ms;
                        updated
                    } else {
                        self.backup_single_file(
                            &rel_path,
                            &abs_path,
                            streamed_size,
                            modified_unix_ms,
                            plaintext_sha256,
                        )?
                    }
                }
            } else {
                let (streamed_size, plaintext_sha256) = compute_file_sha256_streaming(&abs_path)?;
                self.backup_single_file(
                    &rel_path,
                    &abs_path,
                    streamed_size,
                    modified_unix_ms,
                    plaintext_sha256,
                )?
            };

            file_roots.push(entry.file_merkle_root);
            self.deleted_tombstones.remove(&rel_path);
            next_entries.insert(rel_path, entry);
        }

        self.current_version = self.current_version.saturating_add(1);

        // Record tombstones for any previously tracked files that were deleted in this pass.
        for (old_path, old_entry) in &self.cached_entries {
            if !next_entries.contains_key(old_path) {
                self.deleted_tombstones.insert(
                    old_path.clone(),
                    DeletedFileTombstone {
                        relative_path: old_path.clone(),
                        deleted_at_version: self.current_version,
                        previous_merkle_root: old_entry.file_merkle_root,
                    },
                );
            }
        }

        self.cached_entries = next_entries.clone();

        let folder_merkle_root = compute_file_merkle_root(&file_roots);

        // Seal a monotonic SignedDhtManifestEnvelope anchored at the first file's manifest (or synthetic folder root).
        let signed_dht_envelope = if let Some((_, first_entry)) = next_entries.iter().next() {
            let now_ms = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let monotonic_ver = now_ms
                .max(1_700_000_000_000)
                .saturating_add(self.current_version);
            let env = SignedDhtManifestEnvelope::seal(
                &self.master_key,
                &self.owner_identity,
                &first_entry.manifest,
                monotonic_ver,
                monotonic_ver,
            )?;
            let _ = self.dht_store.put_manifest_envelope(env.clone());
            let _ = self.store.put_dht_manifest_envelope(env.clone());
            if let Some(client) = self.store.mesh_client() {
                if !client.all_network_endpoints().is_empty() {
                    let _ = client.put_dht_envelope(
                        crate::network::DhtWireEnvelope::ClassicalManifest(env.clone()),
                    );
                }
            }
            Some(env)
        } else {
            None
        };

        Ok(FolderSnapshotManifest {
            version: self.current_version,
            folder_merkle_root,
            tier: self.tier,
            files: next_entries,
            signed_dht_envelope,
            deleted_tombstones: self.deleted_tombstones.clone(),
        })
    }

    /// Validates and resolves a relative restore path inside `target_dir` (`ADR-15` Path-Traversal Defense).
    /// Strictly rejects `..` (`ParentDir`), `/` (`RootDir`), Windows drive/UNC prefixes (`Prefix`),
    /// backslashes, colons, null bytes, key/entry mismatches, and symlink traversal.
    pub fn resolve_safe_restore_path(
        target_dir: &Path,
        map_key: &str,
        entry_rel_path: &str,
    ) -> Result<PathBuf, StorageError> {
        if map_key.is_empty()
            || map_key != entry_rel_path
            || map_key.contains('\0')
            || map_key.contains('\\')
            || map_key.contains(':')
        {
            return Err(StorageError::InvalidRestorePath(map_key.to_string()));
        }

        let candidate = Path::new(map_key);
        let mut safe_path = target_dir.to_path_buf();
        let mut has_normal_component = false;

        for comp in candidate.components() {
            match comp {
                Component::Normal(seg) => {
                    let s = seg.to_string_lossy();
                    if s.is_empty() || s == "." || s == ".." {
                        return Err(StorageError::InvalidRestorePath(map_key.to_string()));
                    }
                    safe_path.push(seg);
                    if safe_path.exists() {
                        let meta = fs::symlink_metadata(&safe_path)?;
                        if meta.file_type().is_symlink() {
                            return Err(StorageError::InvalidRestorePath(map_key.to_string()));
                        }
                    }
                    has_normal_component = true;
                }
                _ => {
                    return Err(StorageError::InvalidRestorePath(map_key.to_string()));
                }
            }
        }

        if !has_normal_component {
            return Err(StorageError::InvalidRestorePath(map_key.to_string()));
        }
        Ok(safe_path)
    }

    /// Selectively restores a single file identified by `relative_path` from `snapshot` into
    /// `target_dir` using streaming reconstruction, 64 KiB streaming SHA-256 verification,
    /// `sync_all()`, and atomic rename.
    pub fn restore_single_file(
        &self,
        snapshot: &FolderSnapshotManifest,
        relative_path: &str,
        target_dir: &Path,
    ) -> Result<PathBuf, StorageError> {
        fs::create_dir_all(target_dir)?;
        let _ = Self::resolve_safe_restore_path(target_dir, relative_path, relative_path)?;
        let entry = snapshot
            .files
            .get(relative_path)
            .ok_or_else(|| StorageError::ShardNotFound(relative_path.to_string()))?;
        let out_path =
            Self::resolve_safe_restore_path(target_dir, relative_path, &entry.relative_path)?;
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let staging_path = out_path.with_extension("parvault_restore_staging");
        self.store
            .restore_file_streaming(&entry.manifest, &self.master_key, &staging_path)?;

        let (restored_len, actual_sha) = compute_file_sha256_streaming(&staging_path)?;
        if actual_sha != entry.plaintext_sha256 || restored_len != entry.size_bytes {
            let _ = fs::remove_file(&staging_path);
            return Err(StorageError::CorruptedShard);
        }
        {
            let staging_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&staging_path)?;
            staging_file.sync_all()?;
        }
        if let Err(e) = fs::rename(&staging_path, &out_path) {
            let _ = fs::remove_file(&staging_path);
            return Err(StorageError::Io(e));
        }
        Ok(out_path)
    }

    /// Restores all files in `snapshot` into `target_dir`, recreating subdirectories,
    /// reconstructing Reed-Solomon shards in `GF(2^8)`, authenticating AES-256-GCM tags,
    /// and verifying every restored file's SHA-256 against `plaintext_sha256` in streaming
    /// 64 KiB chunks BEFORE atomically placing the file at its destination path.
    pub fn restore_folder(
        &self,
        snapshot: &FolderSnapshotManifest,
        target_dir: &Path,
    ) -> Result<usize, StorageError> {
        fs::create_dir_all(target_dir)?;
        let mut restored_count = 0usize;

        for (tomb_key, tomb) in &snapshot.deleted_tombstones {
            if !snapshot.files.contains_key(tomb_key) {
                if let Ok(stale_path) =
                    Self::resolve_safe_restore_path(target_dir, tomb_key, &tomb.relative_path)
                {
                    if stale_path.is_file() {
                        let _ = fs::remove_file(stale_path);
                    }
                }
            }
        }

        for (rel_path, entry) in &snapshot.files {
            let _ = Self::resolve_safe_restore_path(target_dir, rel_path, &entry.relative_path)?;
            self.restore_single_file(snapshot, rel_path, target_dir)?;
            restored_count += 1;
        }

        Ok(restored_count)
    }

    /// Lists all file entries in a `FolderSnapshotManifest` (`ADR-17`) so a Lite Client can browse
    /// its remote vault catalog ("Cloud-Away-From-Home") with zero shard downloads.
    pub fn list_snapshot_catalog(snapshot: &FolderSnapshotManifest) -> Vec<CatalogFileMetadata> {
        snapshot
            .files
            .values()
            .map(|entry| CatalogFileMetadata {
                relative_path: entry.relative_path.clone(),
                size_bytes: entry.size_bytes,
                modified_unix_ms: entry.modified_unix_ms,
                stripe_count: entry.manifest.stripes.len(),
                file_merkle_root: entry.file_merkle_root,
            })
            .collect()
    }

    /// Checks whether `relative_path` matches at least one user-supplied glob, directory prefix, or exact filter.
    pub fn matches_selective_filters(relative_path: &str, filters: &[String]) -> bool {
        if filters.is_empty() {
            return true;
        }
        let normalized = relative_path.replace('\\', "/");
        let basename = normalized.rsplit('/').next().unwrap_or(&normalized);

        for raw_filter in filters {
            let f = raw_filter.trim().replace('\\', "/");
            if f.is_empty() {
                continue;
            }
            if f == normalized || f == basename {
                return true;
            }
            let dir_prefix = f.trim_end_matches('/');
            if normalized.starts_with(&format!("{dir_prefix}/")) {
                return true;
            }
            if ParvaultIgnore::wildcard_match(&f, &normalized)
                || ParvaultIgnore::wildcard_match(&f, basename)
            {
                return true;
            }
        }
        false
    }

    /// Selective On-Demand Subset Restore (`ADR-17`):
    /// Restores **only** the files in `snapshot` matching `filters` (exact paths, directory prefixes,
    /// or `*`/`?` globs) without downloading or reconstructing any other files in the vault.
    pub fn restore_selective_subset(
        &self,
        snapshot: &FolderSnapshotManifest,
        filters: &[String],
        target_dir: &Path,
    ) -> Result<SelectiveRestoreReport, StorageError> {
        fs::create_dir_all(target_dir)?;
        let mut files_restored = Vec::new();
        let mut files_skipped = 0usize;
        let mut bytes_restored = 0u64;
        let mut bytes_saved_not_downloaded = 0u64;

        for (rel_path, entry) in &snapshot.files {
            if Self::matches_selective_filters(rel_path, filters) {
                let _ =
                    Self::resolve_safe_restore_path(target_dir, rel_path, &entry.relative_path)?;
                self.restore_single_file(snapshot, rel_path, target_dir)?;
                files_restored.push(rel_path.clone());
                bytes_restored = bytes_restored.saturating_add(entry.size_bytes);
            } else {
                files_skipped += 1;
                bytes_saved_not_downloaded =
                    bytes_saved_not_downloaded.saturating_add(entry.size_bytes);
            }
        }

        let route_used = if self
            .store
            .mesh_client()
            .and_then(|c| c.seed_addr())
            .is_some()
        {
            LiteRestoreRoute::ViaSeedServerFastPath
        } else {
            LiteRestoreRoute::DirectFromMeshPeersFallback
        };

        Ok(SelectiveRestoreReport {
            route_used,
            files_restored,
            files_skipped,
            bytes_restored,
            bytes_saved_not_downloaded,
        })
    }

    /// Lite-Client Folder Sync via Paired `ZeroTrustSeedServer` (`ADR-17`):
    ///
    /// 1. Encrypts modified files on the laptop (`K_user` never leaves the laptop).
    /// 2. Sends a `1.0x` encrypted ciphertext stripe bundle (`LiteStripeSyndicationBundle`)
    ///    authenticated by the laptop's post-quantum `PersonalDeviceCert` to `seed_server`.
    /// 3. `seed_server` caches the shards for fast 1-hop "Cloud-Away-From-Home" access AND
    ///    syndicates all `N` Reed-Solomon shards across `mesh_peer_stores` in the wider
    ///    Neighborhood Cloud so that if the NAS / `seed_server` ever dies, the laptop can
    ///    recover directly from any `K`-of-`N` surviving mesh peers!
    pub fn sync_folder_lite_via_seed(
        &mut self,
        folder_path: &Path,
        cert: &PersonalDeviceCert,
        seed_server: &mut ZeroTrustSeedServer,
        mesh_peer_stores: &[&BlockStore],
    ) -> Result<(FolderSnapshotManifest, Vec<LiteSyndicationReceipt>), StorageError> {
        let snapshot = self.sync_folder_once(folder_path)?;
        let mut receipts = Vec::new();
        let (k_data, m_parity, _n_total) = snapshot.tier.params();

        for entry in snapshot.files.values() {
            for stripe_meta in &entry.manifest.stripes {
                // Reassemble the 1.0x encrypted stripe ciphertext from the local K data shards
                let mut surviving = vec![None; stripe_meta.shard_hashes.len()];
                for (idx, slot) in surviving.iter_mut().enumerate().take(k_data) {
                    let shard_id = ShardId {
                        stripe_merkle_root: stripe_meta.stripe_merkle_root,
                        shard_index: idx as u32,
                        shard_hash: stripe_meta.shard_hashes[idx],
                    };
                    let bytes = self.store.get_shard(&shard_id)?;
                    *slot = Some(bytes);
                }
                let ciphertext_bytes = reconstruct_ciphertext_stripe(
                    surviving,
                    k_data,
                    m_parity,
                    stripe_meta.original_ciphertext_len,
                    Some(&stripe_meta.shard_hashes),
                    Some(stripe_meta.stripe_merkle_root),
                )?;

                let bundle = LiteStripeSyndicationBundle {
                    stripe_index: stripe_meta.stripe_index,
                    tier: snapshot.tier,
                    ciphertext_bytes,
                    expected_stripe_merkle_root: stripe_meta.stripe_merkle_root,
                    expected_shard_hashes: stripe_meta.shard_hashes.clone(),
                };

                let receipt = seed_server
                    .ingest_and_syndicate_lite_stripe(cert, &bundle, mesh_peer_stores)
                    .map_err(|_| StorageError::CorruptedShard)?;
                receipts.push(receipt);
            }
        }

        Ok((snapshot, receipts))
    }

    /// Reconstructs and decrypts a single stripe (`stripe_meta`) for a Lite Client, automatically
    /// using the 1-hop `seed_server` fast-path if online (`ViaSeedServerFastPath`) OR seamlessly
    /// failing over to `mesh_peer_stores` (`DirectFromMeshPeersFallback`) if the NAS / `seed_server`
    /// is dead or unreachable (`ADR-17`).
    fn reconstruct_and_decrypt_stripe_with_fallback(
        &self,
        manifest: &FileManifest,
        stripe_pos: usize,
        cert: Option<&PersonalDeviceCert>,
        seed_server: Option<&ZeroTrustSeedServer>,
        mesh_peer_stores: &[&BlockStore],
    ) -> Result<(Vec<u8>, LiteRestoreRoute), StorageError> {
        let stripe_meta = &manifest.stripes[stripe_pos];
        let (k_data, m_parity, n_total) = manifest.tier.params();

        // 1. Try 1-Hop Fast Path via `parvault-seed` server if online
        if let Some(seed) = seed_server {
            let mut seed_shards = vec![None; n_total];
            let mut gathered = 0usize;
            for (idx, slot) in seed_shards.iter_mut().enumerate().take(n_total) {
                let shard_id = ShardId {
                    stripe_merkle_root: stripe_meta.stripe_merkle_root,
                    shard_index: idx as u32,
                    shard_hash: stripe_meta.shard_hashes[idx],
                };
                let maybe_bytes = if let Some(c) = cert {
                    seed.get_personal_device_shard(c, &shard_id).ok()
                } else {
                    seed.block_store().get_shard(&shard_id).ok()
                };
                if let Some(bytes) = maybe_bytes {
                    if hash_shard_leaf(idx as u32, &bytes) == stripe_meta.shard_hashes[idx] {
                        *slot = Some(bytes);
                        gathered += 1;
                        if gathered >= k_data {
                            break;
                        }
                    }
                }
            }

            if gathered >= k_data {
                let ct = reconstruct_ciphertext_stripe(
                    seed_shards,
                    k_data,
                    m_parity,
                    stripe_meta.original_ciphertext_len,
                    Some(&stripe_meta.shard_hashes),
                    Some(stripe_meta.stripe_merkle_root),
                )?;
                let pt = decrypt_stripe(
                    &self.master_key,
                    &manifest.file_salt,
                    stripe_meta.stripe_index,
                    &ct,
                )?;
                return Ok((pt, LiteRestoreRoute::ViaSeedServerFastPath));
            }
        }

        // 2. NAS / Seedbox is Dead or Unreachable -> Fail over to Direct Mesh Reconstruction!
        let mut mesh_shards = vec![None; n_total];
        let mut gathered_mesh = 0usize;
        for (idx, slot) in mesh_shards.iter_mut().enumerate().take(n_total) {
            let shard_id = ShardId {
                stripe_merkle_root: stripe_meta.stripe_merkle_root,
                shard_index: idx as u32,
                shard_hash: stripe_meta.shard_hashes[idx],
            };
            for peer_store in mesh_peer_stores {
                if let Ok(bytes) = peer_store.get_shard(&shard_id) {
                    if hash_shard_leaf(idx as u32, &bytes) == stripe_meta.shard_hashes[idx] {
                        *slot = Some(bytes);
                        gathered_mesh += 1;
                        break;
                    }
                }
            }
            if gathered_mesh >= k_data {
                break;
            }
        }

        if gathered_mesh < k_data {
            return Err(StorageError::ShardNotFound(format!(
                "insufficient surviving mesh shards ({}/{}) for stripe {}",
                gathered_mesh, k_data, stripe_meta.stripe_index
            )));
        }

        let ct = reconstruct_ciphertext_stripe(
            mesh_shards,
            k_data,
            m_parity,
            stripe_meta.original_ciphertext_len,
            Some(&stripe_meta.shard_hashes),
            Some(stripe_meta.stripe_merkle_root),
        )?;
        let pt = decrypt_stripe(
            &self.master_key,
            &manifest.file_salt,
            stripe_meta.stripe_index,
            &ct,
        )?;
        Ok((pt, LiteRestoreRoute::DirectFromMeshPeersFallback))
    }

    /// Selective Restore with Automatic NAS-Death Mesh Failover (`ADR-17`):
    ///
    /// Restores only the files matching `filters` into `target_dir`:
    /// - When `seed_server` is `Some` (NAS online / "Cloud-Away-From-Home"), fetches directly from
    ///   the seed server (`LiteRestoreRoute::ViaSeedServerFastPath`).
    /// - When `seed_server` is `None` (NAS died!), seamlessly fails over to reconstructing any `K`
    ///   of `N` syndicated shards from `mesh_peer_stores` (`LiteRestoreRoute::DirectFromMeshPeersFallback`)
    ///   using the exact same protocol on the laptop!
    pub fn restore_selective_with_seed_fallback(
        &self,
        snapshot: &FolderSnapshotManifest,
        filters: &[String],
        cert: &PersonalDeviceCert,
        seed_server: Option<&ZeroTrustSeedServer>,
        mesh_peer_stores: &[&BlockStore],
        target_dir: &Path,
    ) -> Result<SelectiveRestoreReport, StorageError> {
        fs::create_dir_all(target_dir)?;
        let mut files_restored = Vec::new();
        let mut files_skipped = 0usize;
        let mut bytes_restored = 0u64;
        let mut bytes_saved_not_downloaded = 0u64;
        let mut observed_route = if seed_server.is_some() {
            LiteRestoreRoute::ViaSeedServerFastPath
        } else {
            LiteRestoreRoute::DirectFromMeshPeersFallback
        };

        for (rel_path, entry) in &snapshot.files {
            if !Self::matches_selective_filters(rel_path, filters) {
                files_skipped += 1;
                bytes_saved_not_downloaded =
                    bytes_saved_not_downloaded.saturating_add(entry.size_bytes);
                continue;
            }

            let out_path =
                Self::resolve_safe_restore_path(target_dir, rel_path, &entry.relative_path)?;
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut file_plaintext = Vec::with_capacity(entry.size_bytes as usize);
            for stripe_pos in 0..entry.manifest.stripes.len() {
                let (stripe_pt, route) = self.reconstruct_and_decrypt_stripe_with_fallback(
                    &entry.manifest,
                    stripe_pos,
                    Some(cert),
                    seed_server,
                    mesh_peer_stores,
                )?;
                observed_route = route;
                file_plaintext.extend_from_slice(&stripe_pt);
            }
            file_plaintext.truncate(entry.size_bytes as usize);

            let actual_sha: Hash32 = Sha256::digest(&file_plaintext).into();
            if actual_sha != entry.plaintext_sha256 {
                return Err(StorageError::CorruptedShard);
            }

            BlockStore::atomic_write_file(&out_path, &file_plaintext)?;
            files_restored.push(rel_path.clone());
            bytes_restored = bytes_restored.saturating_add(entry.size_bytes);
        }

        Ok(SelectiveRestoreReport {
            route_used: observed_route,
            files_restored,
            files_skipped,
            bytes_restored,
            bytes_saved_not_downloaded,
        })
    }

    /// Partial Stripe / Byte-Range Restore (`ADR-17`):
    ///
    /// Reconstructs and decrypts **only** the 16 MiB stripe(s) overlapping `[offset, offset + length)`
    /// (`byte_range = (offset, length)`) of `relative_path` (via `seed_server` fast-path or direct
    /// `mesh_peer_stores` fallback if the NAS is dead), returning the exact requested plaintext slice
    /// without downloading the rest of the file!
    pub fn restore_file_byte_range(
        &self,
        snapshot: &FolderSnapshotManifest,
        relative_path: &str,
        byte_range: (u64, u64),
        cert: Option<&PersonalDeviceCert>,
        seed_server: Option<&ZeroTrustSeedServer>,
        mesh_peer_stores: &[&BlockStore],
    ) -> Result<(Vec<u8>, LiteRestoreRoute), StorageError> {
        let (offset, length) = byte_range;
        let normalized_rel = relative_path.replace('\\', "/");
        let entry = snapshot
            .files
            .get(&normalized_rel)
            .or_else(|| snapshot.files.get(relative_path))
            .ok_or_else(|| StorageError::ShardNotFound(relative_path.to_string()))?;

        if length == 0 || offset >= entry.size_bytes {
            let default_route = if seed_server.is_some() {
                LiteRestoreRoute::ViaSeedServerFastPath
            } else {
                LiteRestoreRoute::DirectFromMeshPeersFallback
            };
            return Ok((Vec::new(), default_route));
        }

        let end_offset = offset.saturating_add(length).min(entry.size_bytes);
        let stripe_size = (entry.manifest.stripe_size_bytes as u64).max(1);
        let first_stripe = (offset / stripe_size) as usize;
        let last_stripe = ((end_offset - 1) / stripe_size) as usize;

        let mut out_slice = Vec::with_capacity((end_offset - offset) as usize);
        let mut route_used = LiteRestoreRoute::ViaSeedServerFastPath;

        for s_idx in first_stripe..=last_stripe.min(entry.manifest.stripes.len().saturating_sub(1))
        {
            let (stripe_pt, route) = self.reconstruct_and_decrypt_stripe_with_fallback(
                &entry.manifest,
                s_idx,
                cert,
                seed_server,
                mesh_peer_stores,
            )?;
            route_used = route;

            let stripe_start_byte = (s_idx as u64) * stripe_size;
            let stripe_end_byte = stripe_start_byte + (stripe_pt.len() as u64);

            let copy_start = offset.max(stripe_start_byte) - stripe_start_byte;
            let copy_end = end_offset.min(stripe_end_byte) - stripe_start_byte;
            if copy_end > copy_start {
                out_slice.extend_from_slice(&stripe_pt[copy_start as usize..copy_end as usize]);
            }
        }

        Ok((out_slice, route_used))
    }

    /// Exports an encrypted, post-quantum-protected `EncryptedVaultCatalogEnvelope` (`ADR-15`)
    /// keyed at the deterministic `derive_vault_root_dht_key(vault_namespace)` so the entire
    /// folder snapshot can be discovered and recovered from a memorized seed phrase alone.
    /// Automatically persists to local `ZeroTrustDhtStore` and publishes to Kademlia DHT peers
    /// over `libp2p` when a `MeshClient` is configured.
    pub fn export_encrypted_vault_catalog(
        &self,
        seed_phrase: &str,
        vault_namespace: &str,
        snapshot: &FolderSnapshotManifest,
    ) -> Result<EncryptedVaultCatalogEnvelope, StorageError> {
        let canonical = crate::crypto::validate_recovery_seed_phrase_or_passphrase(seed_phrase)?;
        let pq_master_key =
            PqVaultMasterKey::from_recovery_seed_phrase(&canonical, vault_namespace);
        let env = EncryptedVaultCatalogEnvelope::seal(
            &self.master_key,
            &pq_master_key,
            &self.owner_identity,
            vault_namespace,
            snapshot,
        )?;
        let _ = self.store.put_dht_vault_catalog_envelope(env.clone());
        if let Some(client) = self.store.mesh_client() {
            if !client.all_network_endpoints().is_empty() {
                let _ = client
                    .put_dht_envelope(crate::network::DhtWireEnvelope::VaultCatalog(env.clone()));
            }
        }
        Ok(env)
    }

    /// Zero-Local-State "House Fire" Disaster Recovery (`ADR-15`):
    /// Reconstructs the user's `MasterKey`, `PqVaultMasterKey`, `NodeIdentity`, and deterministic
    /// `root_catalog_dht_key` strictly from `(seed_phrase, vault_namespace)`, verifies and decrypts
    /// `catalog_envelope`, and restores the entire directory tree into `target_dir` with zero prior local files.
    pub fn recover_folder_from_seed_phrase<B: Borrow<BlockStore>>(
        store: B,
        seed_phrase: &str,
        vault_namespace: &str,
        catalog_envelope: &EncryptedVaultCatalogEnvelope,
        target_dir: &Path,
    ) -> Result<usize, StorageError> {
        let canonical = crate::crypto::validate_recovery_seed_phrase_or_passphrase(seed_phrase)?;
        let master_key = MasterKey::from_recovery_seed_phrase(&canonical, vault_namespace);
        let pq_master_key =
            PqVaultMasterKey::from_recovery_seed_phrase(&canonical, vault_namespace);
        let owner_identity = NodeIdentity::from_recovery_seed_phrase(&canonical, vault_namespace);

        let expected_dht_key = master_key.derive_vault_root_dht_key(vault_namespace);
        if catalog_envelope.dht_key != expected_dht_key
            || catalog_envelope.owner_pubkey != owner_identity.public_key_bytes()
        {
            return Err(StorageError::DhtManifestPoisonedOrRollback);
        }

        let snapshot = catalog_envelope.open(&master_key, &pq_master_key)?;
        let mut store_with_owner = store.borrow().clone();
        if let Some(client) = store_with_owner.mesh_client().cloned() {
            store_with_owner.set_mesh_client(Some(client.with_identity(owner_identity.clone())));
        }
        let engine = Self::new(store_with_owner, master_key, owner_identity, snapshot.tier);
        engine.restore_folder(&snapshot, target_dir)
    }

    /// Fetches the `EncryptedVaultCatalogEnvelope` from the mesh Kademlia DHT (or local `ZeroTrustDhtStore`)
    /// using only `(seed_phrase, vault_namespace)` and restores the entire directory tree into `target_dir`.
    pub fn recover_folder_from_seed_phrase_via_dht<B: Borrow<BlockStore>>(
        store: B,
        seed_phrase: &str,
        vault_namespace: &str,
        target_dir: &Path,
    ) -> Result<usize, StorageError> {
        let canonical = crate::crypto::validate_recovery_seed_phrase_or_passphrase(seed_phrase)?;
        let master_key = MasterKey::from_recovery_seed_phrase(&canonical, vault_namespace);
        let dht_key = master_key.derive_vault_root_dht_key(vault_namespace);
        let store_ref = store.borrow();

        let catalog_envelope = if let Some(client) = store_ref.mesh_client() {
            if !client.all_network_endpoints().is_empty() {
                match client
                    .get_dht_envelope(&dht_key, crate::network::DhtEnvelopeKind::VaultCatalog)
                {
                    Ok(crate::network::DhtWireEnvelope::VaultCatalog(env)) => env,
                    _ => store_ref
                        .get_dht_vault_catalog_envelope(&dht_key)
                        .ok_or(StorageError::DhtManifestPoisonedOrRollback)?,
                }
            } else {
                store_ref
                    .get_dht_vault_catalog_envelope(&dht_key)
                    .ok_or(StorageError::DhtManifestPoisonedOrRollback)?
            }
        } else {
            store_ref
                .get_dht_vault_catalog_envelope(&dht_key)
                .ok_or(StorageError::DhtManifestPoisonedOrRollback)?
        };

        Self::recover_folder_from_seed_phrase(
            store_ref,
            &canonical,
            vault_namespace,
            &catalog_envelope,
            target_dir,
        )
    }

    fn file_modified_unix_ms(meta: &fs::Metadata) -> u64 {
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn backup_single_file(
        &self,
        rel_path: &str,
        abs_path: &Path,
        size_bytes: u64,
        modified_unix_ms: u64,
        plaintext_sha256: Hash32,
    ) -> Result<SyncedFileEntry, StorageError> {
        let manifest = self.store.store_file_streaming(
            &self.owner_identity.device_peer_id(),
            abs_path,
            &self.master_key,
            self.tier,
            DEFAULT_SYNC_STRIPE_BYTES,
        )?;

        let (_, _, n_total) = self.tier.params();
        let shard_pseudonyms: Vec<String> = (0..n_total as u32)
            .map(|idx| {
                derive_unlinkable_shard_pseudonym(&self.master_key, &manifest.file_merkle_root, idx)
            })
            .collect();

        Ok(SyncedFileEntry {
            relative_path: rel_path.to_string(),
            size_bytes,
            modified_unix_ms,
            plaintext_sha256,
            file_merkle_root: manifest.file_merkle_root,
            manifest,
            shard_pseudonyms,
        })
    }

    fn collect_files_recursive(
        base_dir: &Path,
        current_dir: &Path,
        ignore: &ParvaultIgnore,
        out: &mut Vec<(String, PathBuf)>,
        mut ignored_out: Option<&mut Vec<String>>,
    ) -> Result<(), StorageError> {
        if !current_dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(current_dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let Ok(rel) = path.strip_prefix(base_dir) else {
                continue;
            };
            let normalized = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let is_dir = file_type.is_dir();

            if ignore.is_ignored(&normalized, is_dir) {
                if let Some(ig) = ignored_out.as_deref_mut() {
                    ig.push(normalized);
                }
                continue;
            }

            if is_dir {
                Self::collect_files_recursive(
                    base_dir,
                    &path,
                    ignore,
                    out,
                    ignored_out.as_deref_mut(),
                )?;
            } else if file_type.is_file() {
                out.push((normalized, path));
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
mod gateway_sync {
    use super::{
        compute_file_merkle_root, compute_file_sha256_streaming, sanitize_sync_relative_path,
        DeletedFileTombstone, FolderSyncDiff, FolderSyncEngine, Hash32, ParvaultIgnore,
    };
    use crate::capabilities::CapabilityMacaroon;
    use crate::gateway::ipc::{create_memfd, EphemeralShardManifest, GatewayBus, RetentionPolicy};
    use bincode::Options;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{self, File};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::time::UNIX_EPOCH;

    /// Hard deserialization ceiling (`64 MiB`) on serialized [`GatewayFolderCatalog`] files.
    pub const MAX_GATEWAY_CATALOG_BYTES: u64 = 64 * 1024 * 1024;

    /// Range chunk size (`1 MiB`) used by [`GatewayFolderSync::restore_to_folder`].
    const GATEWAY_RESTORE_CHUNK_BYTES: u64 = 1024 * 1024;

    fn catalog_bincode() -> impl Options {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_GATEWAY_CATALOG_BYTES)
    }

    /// Zero-key metadata record for a single file synchronized through [`GatewayBus`] (`ADR-33`).
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct GatewaySyncedFileEntry {
        pub relative_path: String,
        pub size_bytes: u64,
        pub modified_unix_ms: u64,
        pub plaintext_sha256: Hash32,
        pub ephemeral_manifest: EphemeralShardManifest,
    }

    /// Zero-key incremental folder catalog persisted by `parvault-sync` (`ADR-33`).
    /// Holds only content digests and opaque [`EphemeralShardManifest`] handles — never `MasterKey`
    /// or `NodeIdentity` secret material.
    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
    pub struct GatewayFolderCatalog {
        pub version: u64,
        pub folder_merkle_root: Hash32,
        pub files: BTreeMap<String, GatewaySyncedFileEntry>,
        #[serde(default)]
        pub deleted_tombstones: BTreeMap<String, DeletedFileTombstone>,
    }

    impl GatewayFolderCatalog {
        /// Atomically serializes and syncs this catalog to `path` (`write tmp` + `sync_all` + `rename`).
        pub fn save_to_file(&self, path: &Path) -> io::Result<()> {
            let encoded = catalog_bincode()
                .serialize(self)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("catalog.bin");
            let tmp_path = path.with_file_name(format!(".{file_name}.tmp.{}", std::process::id()));
            {
                let mut f = File::create(&tmp_path)?;
                f.write_all(&encoded)?;
                f.sync_all()?;
            }
            if let Err(e) = fs::rename(&tmp_path, path) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
            Ok(())
        }

        /// Loads and deserializes a [`GatewayFolderCatalog`] from `path` with a strict `64 MiB` cap.
        pub fn load_from_file(path: &Path) -> io::Result<Self> {
            let meta = fs::metadata(path)?;
            if meta.len() > MAX_GATEWAY_CATALOG_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "gateway catalog size {} exceeds ceiling {}",
                        meta.len(),
                        MAX_GATEWAY_CATALOG_BYTES
                    ),
                ));
            }
            let raw = fs::read(path)?;
            catalog_bincode()
                .deserialize(&raw)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        }
    }

    /// Zero-key sibling incremental folder synchronizer communicating exclusively over [`GatewayBus`]
    /// (`GatewayBus::InProcess` or `GatewayBus::UnixSocket`).
    ///
    /// ### Architectural Invariant (`ADR-33`)
    /// Holds **zero** `MasterKey` and **zero** `NodeIdentity` fields: encryption, Reed-Solomon
    /// erasure coding, and `CapabilityMacaroon` verification remain isolated inside `GatewayEngine`.
    pub struct GatewayFolderSync {
        bus: GatewayBus,
        default_macaroon: Option<CapabilityMacaroon>,
        catalog: GatewayFolderCatalog,
    }

    impl GatewayFolderSync {
        pub fn new(bus: GatewayBus) -> Self {
            Self {
                bus,
                default_macaroon: None,
                catalog: GatewayFolderCatalog::default(),
            }
        }

        pub fn with_catalog(bus: GatewayBus, catalog: GatewayFolderCatalog) -> Self {
            Self {
                bus,
                default_macaroon: None,
                catalog,
            }
        }

        pub fn with_default_macaroon(mut self, macaroon: Option<CapabilityMacaroon>) -> Self {
            self.default_macaroon = macaroon;
            self
        }

        pub fn set_default_macaroon(&mut self, macaroon: Option<CapabilityMacaroon>) {
            self.default_macaroon = macaroon;
        }

        pub fn load_catalog(&mut self, catalog: GatewayFolderCatalog) {
            self.catalog = catalog;
        }

        pub fn catalog(&self) -> &GatewayFolderCatalog {
            &self.catalog
        }

        pub fn catalog_mut(&mut self) -> &mut GatewayFolderCatalog {
            &mut self.catalog
        }

        pub fn bus(&self) -> &GatewayBus {
            &self.bus
        }

        /// Computes a dry-run [`FolderSyncDiff`] against `self.catalog` using `ParvaultIgnore` and
        /// `64 KiB` streaming SHA-256 (fast-pathing unchanged files when `size_bytes` and
        /// `modified_unix_ms > 0` match).
        pub fn diff_folder(&self, folder_path: &Path) -> io::Result<FolderSyncDiff> {
            let ignore = ParvaultIgnore::from_folder(folder_path);
            let mut discovered = Vec::new();
            let mut ignored = Vec::new();
            Self::collect_files_recursive(
                folder_path,
                folder_path,
                &ignore,
                &mut discovered,
                Some(&mut ignored),
            )?;
            discovered.sort_by(|a, b| a.0.cmp(&b.0));
            ignored.sort();

            let mut diff = FolderSyncDiff {
                ignored,
                ..Default::default()
            };
            let mut seen_paths = BTreeSet::new();

            for (rel_path, abs_path) in discovered {
                seen_paths.insert(rel_path.clone());
                let meta = fs::metadata(&abs_path)?;
                let size_bytes = meta.len();
                let modified_unix_ms = Self::file_modified_unix_ms(&meta);

                if let Some(prev) = self.catalog.files.get(&rel_path) {
                    if prev.size_bytes == size_bytes
                        && prev.modified_unix_ms > 0
                        && prev.modified_unix_ms == modified_unix_ms
                    {
                        diff.unchanged.push(rel_path);
                    } else {
                        let (streamed_size, plaintext_sha256) =
                            compute_file_sha256_streaming(&abs_path)?;
                        if prev.plaintext_sha256 == plaintext_sha256
                            && prev.size_bytes == streamed_size
                        {
                            diff.unchanged.push(rel_path);
                        } else {
                            diff.modified.push(rel_path);
                            diff.total_upload_bytes =
                                diff.total_upload_bytes.saturating_add(streamed_size);
                        }
                    }
                } else {
                    diff.added.push(rel_path);
                    diff.total_upload_bytes = diff.total_upload_bytes.saturating_add(size_bytes);
                }
            }

            for old_path in self.catalog.files.keys() {
                if !seen_paths.contains(old_path) {
                    diff.deleted.push(old_path.clone());
                }
            }

            Ok(diff)
        }

        /// Incrementally synchronizes `folder_path` over [`GatewayBus`], streaming only added or
        /// modified files in `64 KiB` chunks into an immutably sealed `memfd`
        /// (`store_sealed_memfd_sync`), carrying forward unchanged entries, and recording
        /// [`DeletedFileTombstone`]s for deleted paths.
        pub fn sync_folder_once(
            &mut self,
            folder_path: &Path,
            retention: RetentionPolicy,
        ) -> io::Result<GatewayFolderCatalog> {
            let ignore = ParvaultIgnore::from_folder(folder_path);
            let mut discovered = Vec::new();
            Self::collect_files_recursive(
                folder_path,
                folder_path,
                &ignore,
                &mut discovered,
                None,
            )?;
            discovered.sort_by(|a, b| a.0.cmp(&b.0));

            let mut next_files = BTreeMap::new();
            let mut file_roots = Vec::with_capacity(discovered.len());

            for (rel_path, abs_path) in discovered {
                let meta = fs::metadata(&abs_path)?;
                let size_bytes = meta.len();
                let modified_unix_ms = Self::file_modified_unix_ms(&meta);

                let entry = if let Some(prev) = self.catalog.files.get(&rel_path) {
                    if prev.size_bytes == size_bytes
                        && prev.modified_unix_ms > 0
                        && prev.modified_unix_ms == modified_unix_ms
                    {
                        prev.clone()
                    } else {
                        let (streamed_size, plaintext_sha256) =
                            compute_file_sha256_streaming(&abs_path)?;
                        if prev.plaintext_sha256 == plaintext_sha256
                            && prev.size_bytes == streamed_size
                        {
                            let mut carried = prev.clone();
                            carried.modified_unix_ms = modified_unix_ms;
                            carried
                        } else {
                            self.ingest_file_sealed(
                                &rel_path,
                                &abs_path,
                                modified_unix_ms,
                                retention,
                            )?
                        }
                    }
                } else {
                    self.ingest_file_sealed(&rel_path, &abs_path, modified_unix_ms, retention)?
                };

                file_roots.push(entry.ephemeral_manifest.file_merkle_root);
                self.catalog.deleted_tombstones.remove(&rel_path);
                next_files.insert(rel_path, entry);
            }

            self.catalog.version = self.catalog.version.saturating_add(1);

            for (old_path, old_entry) in &self.catalog.files {
                if !next_files.contains_key(old_path) {
                    self.catalog.deleted_tombstones.insert(
                        old_path.clone(),
                        DeletedFileTombstone {
                            relative_path: old_path.clone(),
                            deleted_at_version: self.catalog.version,
                            previous_merkle_root: old_entry.ephemeral_manifest.file_merkle_root,
                        },
                    );
                }
            }

            self.catalog.files = next_files;
            self.catalog.folder_merkle_root = compute_file_merkle_root(&file_roots);

            Ok(self.catalog.clone())
        }

        /// Restores files from `self.catalog` into `output_dir` (optionally filtered by
        /// `filter_prefixes`), validating every relative path with [`sanitize_sync_relative_path`],
        /// streaming `1 MiB` ranges via [`GatewayBus::fetch_range_into_memfd_sync`] with
        /// `self.default_macaroon`, and verifying end-to-end streaming `SHA-256` integrity before
        /// atomic rename into `output_dir`.
        pub fn restore_to_folder(
            &self,
            output_dir: &Path,
            filter_prefixes: &[String],
        ) -> io::Result<usize> {
            // Up-front catalog traversal & consistency audit before touching the filesystem.
            for (map_key, entry) in &self.catalog.files {
                let Some(norm_key) = sanitize_sync_relative_path(map_key) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unsafe relative path key in GatewayFolderCatalog: {map_key:?}"),
                    ));
                };
                let Some(norm_rel) = sanitize_sync_relative_path(&entry.relative_path) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "unsafe entry relative_path in GatewayFolderCatalog: {:?}",
                            entry.relative_path
                        ),
                    ));
                };
                if norm_key != *map_key || norm_rel != norm_key {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "non-canonical or mismatched catalog entry key={map_key:?} rel={:?}",
                            entry.relative_path
                        ),
                    ));
                }
            }

            for (tomb_key, tomb) in &self.catalog.deleted_tombstones {
                let Some(norm_tk) = sanitize_sync_relative_path(tomb_key) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unsafe tombstone key in GatewayFolderCatalog: {tomb_key:?}"),
                    ));
                };
                let Some(norm_tr) = sanitize_sync_relative_path(&tomb.relative_path) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "unsafe tombstone relative_path in GatewayFolderCatalog: {:?}",
                            tomb.relative_path
                        ),
                    ));
                };
                if norm_tk != *tomb_key || norm_tr != norm_tk {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "mismatched tombstone key={tomb_key:?} rel={:?}",
                            tomb.relative_path
                        ),
                    ));
                }
            }

            if output_dir.exists() && fs::symlink_metadata(output_dir)?.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "output_dir must not be a symlink",
                ));
            }
            fs::create_dir_all(output_dir)?;

            if filter_prefixes.is_empty() {
                for tomb_key in self.catalog.deleted_tombstones.keys() {
                    if !self.catalog.files.contains_key(tomb_key) {
                        if let Ok(stale_path) = Self::resolve_safe_dest(output_dir, tomb_key) {
                            if stale_path.is_file() {
                                let _ = fs::remove_file(stale_path);
                            }
                        }
                    }
                }
            }

            let mut restored_count = 0usize;
            for (rel_path, entry) in &self.catalog.files {
                if !filter_prefixes.is_empty()
                    && !FolderSyncEngine::matches_selective_filters(rel_path, filter_prefixes)
                {
                    continue;
                }
                let dest_path = Self::resolve_safe_dest(output_dir, rel_path)?;
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let file_name = dest_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("payload");
                let staging_path = dest_path.with_file_name(format!(
                    ".{file_name}.{}.{restored_count}.parvault_restore_staging",
                    std::process::id()
                ));

                if let Err(e) = self.stream_restore_entry_to_staging(entry, &staging_path) {
                    let _ = fs::remove_file(&staging_path);
                    return Err(e);
                }
                if let Err(e) = fs::rename(&staging_path, &dest_path) {
                    let _ = fs::remove_file(&staging_path);
                    return Err(e);
                }
                restored_count += 1;
            }

            Ok(restored_count)
        }

        fn stream_restore_entry_to_staging(
            &self,
            entry: &GatewaySyncedFileEntry,
            staging_path: &Path,
        ) -> io::Result<()> {
            let mfd = create_memfd("parvault-gw-pull")?;
            let mut mfd_file = File::from(mfd);
            let mut staging_file = File::create(staging_path)?;
            let mut hasher = Sha256::new();
            let mut copy_buf = [0u8; 64 * 1024];

            if entry.size_bytes == 0 {
                let streamed = self.bus.fetch_range_into_memfd_sync(
                    &entry.ephemeral_manifest,
                    0,
                    0,
                    mfd_file.as_raw_fd(),
                    self.default_macaroon.clone(),
                )?;
                if streamed != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("expected 0 bytes for empty file, received {streamed}"),
                    ));
                }
            } else {
                let mut offset = 0u64;
                while offset < entry.size_bytes {
                    let req_len = (entry.size_bytes - offset).min(GATEWAY_RESTORE_CHUNK_BYTES);
                    let _ = mfd_file.set_len(0);
                    let streamed = self.bus.fetch_range_into_memfd_sync(
                        &entry.ephemeral_manifest,
                        offset,
                        req_len,
                        mfd_file.as_raw_fd(),
                        self.default_macaroon.clone(),
                    )?;
                    if streamed == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "gateway returned 0 bytes at offset {offset}/{}",
                                entry.size_bytes
                            ),
                        ));
                    }
                    mfd_file.seek(SeekFrom::Start(0))?;
                    let mut rem = streamed as usize;
                    while rem > 0 {
                        let step = rem.min(copy_buf.len());
                        mfd_file.read_exact(&mut copy_buf[..step])?;
                        hasher.update(&copy_buf[..step]);
                        staging_file.write_all(&copy_buf[..step])?;
                        rem -= step;
                    }
                    offset = offset.saturating_add(streamed);
                }
                if offset != entry.size_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "restored byte count {offset} != expected {}",
                            entry.size_bytes
                        ),
                    ));
                }
            }

            let digest = hasher.finalize();
            let mut actual_sha = [0u8; 32];
            actual_sha.copy_from_slice(&digest);
            if actual_sha != entry.plaintext_sha256 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "end-to-end SHA-256 mismatch restoring '{}'",
                        entry.relative_path
                    ),
                ));
            }
            staging_file.sync_all()
        }

        fn ingest_file_sealed(
            &self,
            rel_path: &str,
            abs_path: &Path,
            modified_unix_ms: u64,
            retention: RetentionPolicy,
        ) -> io::Result<GatewaySyncedFileEntry> {
            let mut src = File::open(abs_path)?;
            let mfd = create_memfd("parvault-gwsync-in")?;
            let mut mfd_file = File::from(mfd);
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            let mut total_bytes = 0u64;

            loop {
                let n = src.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                mfd_file.write_all(&buf[..n])?;
                total_bytes = total_bytes.saturating_add(n as u64);
            }
            mfd_file.seek(SeekFrom::Start(0))?;

            let digest = hasher.finalize();
            let mut plaintext_sha256 = [0u8; 32];
            plaintext_sha256.copy_from_slice(&digest);

            let ephemeral_manifest =
                self.bus
                    .store_sealed_memfd_sync(mfd_file.as_raw_fd(), total_bytes, retention)?;

            Ok(GatewaySyncedFileEntry {
                relative_path: rel_path.to_string(),
                size_bytes: total_bytes,
                modified_unix_ms,
                plaintext_sha256,
                ephemeral_manifest,
            })
        }

        fn resolve_safe_dest(output_dir: &Path, sanitized_rel: &str) -> io::Result<PathBuf> {
            let Some(norm) = sanitize_sync_relative_path(sanitized_rel) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid relative path: {sanitized_rel:?}"),
                ));
            };
            if norm != sanitized_rel {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("non-canonical relative path: {sanitized_rel:?}"),
                ));
            }
            let mut cur = output_dir.to_path_buf();
            for seg in norm.split('/') {
                cur.push(seg);
                if cur.exists() && fs::symlink_metadata(&cur)?.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("symlink traversal rejected along '{}'", cur.display()),
                    ));
                }
            }
            Ok(cur)
        }

        fn file_modified_unix_ms(meta: &fs::Metadata) -> u64 {
            meta.modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        }

        fn collect_files_recursive(
            base_dir: &Path,
            current_dir: &Path,
            ignore: &ParvaultIgnore,
            out: &mut Vec<(String, PathBuf)>,
            mut ignored_out: Option<&mut Vec<String>>,
        ) -> io::Result<()> {
            if !current_dir.exists() {
                return Ok(());
            }
            for entry in fs::read_dir(current_dir)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_symlink() {
                    continue;
                }
                let path = entry.path();
                let Ok(rel) = path.strip_prefix(base_dir) else {
                    continue;
                };
                let raw_rel = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                let Some(normalized) = sanitize_sync_relative_path(&raw_rel) else {
                    continue;
                };
                let is_dir = file_type.is_dir();

                if ignore.is_ignored(&normalized, is_dir) {
                    if let Some(ig) = ignored_out.as_deref_mut() {
                        ig.push(normalized);
                    }
                    continue;
                }

                if is_dir {
                    Self::collect_files_recursive(
                        base_dir,
                        &path,
                        ignore,
                        out,
                        ignored_out.as_deref_mut(),
                    )?;
                } else if file_type.is_file() {
                    out.push((normalized, path));
                }
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
pub use gateway_sync::{
    GatewayFolderCatalog, GatewayFolderSync, GatewaySyncedFileEntry, MAX_GATEWAY_CATALOG_BYTES,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::QuotaManager;

    #[test]
    fn test_parvault_ignore_defaults_and_custom_rules() {
        let mut ignore = ParvaultIgnore::new();
        assert!(ignore.is_ignored(".git", true));
        assert!(ignore.is_ignored(".git/config", false));
        assert!(ignore.is_ignored("node_modules/pkg/index.js", false));
        assert!(ignore.is_ignored("notes.swp", false));
        assert!(ignore.is_ignored("folder_snapshot.manifest.bin", false));
        assert!(!ignore.is_ignored("src/main.rs", false));

        ignore.parse_rules(
            r#"
            # Ignore logs except important.log
            *.log
            !important.log
            build/
            temp_?.dat
            "#,
        );
        assert!(ignore.is_ignored("debug.log", false));
        assert!(!ignore.is_ignored("important.log", false));
        assert!(ignore.is_ignored("build", true));
        assert!(ignore.is_ignored("build/output.bin", false));
        assert!(ignore.is_ignored("temp_1.dat", false));
        assert!(!ignore.is_ignored("temp_12.dat", false));
    }

    #[test]
    fn test_sync_diff_tombstones_and_single_file_restore() -> Result<(), Box<dyn std::error::Error>>
    {
        let base = std::env::temp_dir().join(format!(
            "parvault-sync-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let store_dir = base.join("store");
        let src_dir = base.join("src_folder");
        let out_dir = base.join("restored");
        fs::create_dir_all(src_dir.join("sub"))?;
        fs::create_dir_all(src_dir.join(".git"))?;

        fs::write(
            src_dir.join(".parvaultignore"),
            "*.ignored\n!keep.ignored\n",
        )?;
        fs::write(src_dir.join(".git/HEAD"), b"ref: refs/heads/main")?;
        fs::write(src_dir.join("skip.ignored"), b"should be skipped")?;
        fs::write(src_dir.join("keep.ignored"), b"negated rule stays")?;
        fs::write(src_dir.join("a.txt"), b"alpha payload")?;
        fs::write(src_dir.join("sub/b.txt"), b"bravo payload")?;

        let quota = QuotaManager::new(100 * 1024 * 1024, 10 * 1024 * 1024);
        let store = BlockStore::new(&store_dir, quota)?;
        let mk = MasterKey::generate();
        let id = NodeIdentity::generate();
        let mut engine =
            FolderSyncEngine::new(store.clone(), mk.clone(), id.clone(), ErasureTier::Homelab);

        let initial_diff = engine.diff_folder(&src_dir)?;
        assert_eq!(initial_diff.added.len(), 3);
        assert!(initial_diff.ignored.contains(&".git".to_string()));
        assert!(initial_diff.ignored.contains(&"skip.ignored".to_string()));

        let snap1 = engine.sync_folder_once(&src_dir)?;
        assert_eq!(snap1.files.len(), 3);
        assert!(snap1.deleted_tombstones.is_empty());

        // Delete a.txt and modify sub/b.txt
        fs::remove_file(src_dir.join("a.txt"))?;
        fs::write(src_dir.join("sub/b.txt"), b"bravo payload updated")?;

        let mut resumed_engine = FolderSyncEngine::new(store, mk, id, ErasureTier::Homelab);
        resumed_engine.load_previous_snapshot(&snap1);

        let diff2 = resumed_engine.diff_folder(&src_dir)?;
        assert_eq!(diff2.deleted, vec!["a.txt".to_string()]);
        assert_eq!(diff2.modified, vec!["sub/b.txt".to_string()]);
        assert_eq!(diff2.unchanged, vec!["keep.ignored".to_string()]);

        let snap2 = resumed_engine.sync_folder_once(&src_dir)?;
        assert_eq!(snap2.deleted_tombstones.len(), 1);
        assert!(snap2.deleted_tombstones.contains_key("a.txt"));

        let pruned = resumed_engine.prune_deleted_file_shards(&snap2)?;
        assert_eq!(pruned, 20);

        let single_path = resumed_engine.restore_single_file(&snap2, "sub/b.txt", &out_dir)?;
        assert_eq!(fs::read(&single_path)?, b"bravo payload updated");
        assert!(!out_dir.join("keep.ignored").exists());

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn test_sanitize_sync_relative_path_production_equivalence() {
        let long_seg = "segment_".repeat(40);
        let long_input = format!("{long_seg}\\{long_seg}//tail.bin");
        let expected_long = format!("{long_seg}/{long_seg}/tail.bin");

        let cases: Vec<(&str, Option<&str>)> = vec![
            ("", None),
            ("/", None),
            ("\\", None),
            ("///", None),
            (".", None),
            ("..", None),
            ("./a", None),
            ("../a", None),
            ("a/./b", None),
            ("a/../b", None),
            ("a/..", None),
            ("/etc/passwd", None),
            ("\\Windows\\System32", None),
            ("C:secret.txt", None),
            ("C:\\Users\\alice\\key", None),
            ("file:ads_stream", None),
            ("bad\0nul.txt", None),
            ("a", Some("a")),
            ("docs/readme.md", Some("docs/readme.md")),
            ("docs\\sub//notes.md/", Some("docs/sub/notes.md")),
            ("a/.../b/..hidden", Some("a/.../b/..hidden")),
            ("résumé\\2026//ümlaut.txt", Some("résumé/2026/ümlaut.txt")),
            (&long_input, Some(&expected_long)),
        ];

        for (raw, expected) in cases {
            let prod = sanitize_sync_relative_path(raw);
            assert_eq!(prod.as_deref(), expected, "mismatch for input {raw:?}");

            let mut out = vec![0u8; raw.len()];
            let into_res = sanitize_sync_relative_path_into(raw.as_bytes(), &mut out)
                .and_then(|n| String::from_utf8(out[..n].to_vec()).ok());
            assert_eq!(
                prod, into_res,
                "production equivalence mismatch on input {raw:?}"
            );
        }
    }
}
