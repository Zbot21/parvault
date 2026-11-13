//! The folder sync engine (runtime: block store, seed server, DHT). Split from `sync/mod.rs`
//! in item 3 so the client-side parts build without tokio or libp2p.

use super::common::*;
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
use std::fs::{self, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Default stripe size (16 MiB) for incremental folder synchronization (ADR-01).
pub const DEFAULT_SYNC_STRIPE_BYTES: usize = 16 * 1024 * 1024;

/// Encrypted, Monotonically Signed Kademlia Root Superblock Catalog (`ADR-18` "House Fire" Disaster Recovery).
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
        FolderSnapshotManifest::decode_bytes(&raw_snapshot)
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

impl FolderSnapshotManifest {
    /// Decodes a bincode snapshot of either layout. The current layout embeds version-2 file
    /// manifests (with chunk roots); snapshots written before that embed version-1 manifests
    /// and decode through the frozen [`snapshot_v1`] structs with empty chunk roots.
    ///
    /// The snapshot has no layout tag of its own, so the current layout is tried first and
    /// accepted only if every embedded manifest says version 2. A version-1 stream cannot pass
    /// that check: the first embedded manifest's version is read before the layouts diverge.
    pub fn decode_bytes(raw: &[u8]) -> Result<Self, StorageError> {
        if let Ok(snap) = bincode::deserialize::<Self>(raw) {
            let current = snap.files.values().all(|f| {
                f.manifest.version == crate::storage::block_store::FILE_MANIFEST_VERSION
                    && f.manifest.check_chunk_roots_aligned().is_ok()
            });
            if current {
                return Ok(snap);
            }
        }
        Ok(bincode::deserialize::<snapshot_v1::FolderSnapshotManifestV1>(raw)?.into())
    }
}

/// Frozen snapshot layouts embedding version-1 file manifests. Never change these structs.
pub mod snapshot_v1 {
    use super::{DeletedFileTombstone, FolderSnapshotManifest, SyncedFileEntry};
    use crate::config::ErasureTier;
    use crate::sharding::merkle::Hash32;
    use crate::storage::block_store::manifest_v1::FileManifestV1;
    use crate::storage::SignedDhtManifestEnvelope;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SyncedFileEntryV1 {
        pub relative_path: String,
        pub size_bytes: u64,
        pub modified_unix_ms: u64,
        pub plaintext_sha256: Hash32,
        pub file_merkle_root: Hash32,
        pub manifest: FileManifestV1,
        pub shard_pseudonyms: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FolderSnapshotManifestV1 {
        pub version: u64,
        pub folder_merkle_root: Hash32,
        pub tier: ErasureTier,
        pub files: BTreeMap<String, SyncedFileEntryV1>,
        pub signed_dht_envelope: Option<SignedDhtManifestEnvelope>,
        pub deleted_tombstones: BTreeMap<String, DeletedFileTombstone>,
    }

    impl From<FolderSnapshotManifestV1> for FolderSnapshotManifest {
        fn from(v1: FolderSnapshotManifestV1) -> Self {
            FolderSnapshotManifest {
                version: v1.version,
                folder_merkle_root: v1.folder_merkle_root,
                tier: v1.tier,
                files: v1
                    .files
                    .into_iter()
                    .map(|(k, f)| {
                        (
                            k,
                            SyncedFileEntry {
                                relative_path: f.relative_path,
                                size_bytes: f.size_bytes,
                                modified_unix_ms: f.modified_unix_ms,
                                plaintext_sha256: f.plaintext_sha256,
                                file_merkle_root: f.file_merkle_root,
                                manifest: f.manifest.into(),
                                shard_pseudonyms: f.shard_pseudonyms,
                            },
                        )
                    })
                    .collect(),
                signed_dht_envelope: v1.signed_dht_envelope,
                deleted_tombstones: v1.deleted_tombstones,
            }
        }
    }
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
        super::common::matches_selective_filters(relative_path, filters)
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

    /// Exports an encrypted, post-quantum-protected `EncryptedVaultCatalogEnvelope` (`ADR-18`)
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

    /// Zero-Local-State "House Fire" Disaster Recovery (`ADR-18`):
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_roots_v1_snapshot_decodes_with_empty_roots() {
        use crate::storage::block_store::manifest_v1::{FileManifestV1, StripeManifestEntryV1};
        let fm = FileManifestV1 {
            version: 1,
            file_merkle_root: [0x11; 32],
            file_salt: [0x22; 32],
            original_file_size: 10,
            stripe_size_bytes: 1024 * 1024,
            tier: ErasureTier::Homelab,
            stripes: vec![StripeManifestEntryV1 {
                stripe_index: 0,
                k_data: 16,
                m_parity: 4,
                original_ciphertext_len: 32,
                shard_len: 2,
                stripe_merkle_root: [0x33; 32],
                shard_hashes: vec![[0x44; 32]; 20],
                assigned_peers: vec![],
            }],
            witness_peers: vec![],
        };
        let mut files = BTreeMap::new();
        for name in ["a", "b"] {
            files.insert(
                name.to_string(),
                snapshot_v1::SyncedFileEntryV1 {
                    relative_path: name.to_string(),
                    size_bytes: 10,
                    modified_unix_ms: 7,
                    plaintext_sha256: [0x55; 32],
                    file_merkle_root: [0x11; 32],
                    manifest: fm.clone(),
                    shard_pseudonyms: vec!["p".to_string()],
                },
            );
        }
        let v1 = snapshot_v1::FolderSnapshotManifestV1 {
            version: 9,
            folder_merkle_root: [0x66; 32],
            tier: ErasureTier::Homelab,
            files,
            signed_dht_envelope: None,
            deleted_tombstones: BTreeMap::new(),
        };
        let raw = bincode::serialize(&v1).unwrap();
        let snap = FolderSnapshotManifest::decode_bytes(&raw).expect("v1 snapshot decodes");
        assert_eq!(snap.version, 9);
        assert_eq!(snap.files.len(), 2);
        for f in snap.files.values() {
            assert_eq!(f.manifest.version, crate::storage::FILE_MANIFEST_VERSION);
            assert!(f.manifest.stripes[0].shard_chunk_roots.is_empty());
            assert_eq!(f.modified_unix_ms, 7);
        }

        // A current snapshot round-trips unchanged, chunk roots included.
        let mut current = snap.clone();
        for f in current.files.values_mut() {
            f.manifest.stripes[0].shard_chunk_roots = vec![[0x77; 32]; 20];
        }
        let raw2 = bincode::serialize(&current).unwrap();
        let back = FolderSnapshotManifest::decode_bytes(&raw2).unwrap();
        for (a, b) in back.files.values().zip(current.files.values()) {
            assert_eq!(a, b);
        }
    }
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
