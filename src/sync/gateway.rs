//! Zero-key folder sync over `GatewayBus` (client-side: no runtime dependencies).

use super::common::{
    compute_file_sha256_streaming, matches_selective_filters, sanitize_sync_relative_path,
    DeletedFileTombstone, FolderSyncDiff, ParvaultIgnore,
};
use crate::capabilities::CapabilityMacaroon;
use crate::gateway::ipc::{create_memfd, EphemeralShardManifest, GatewayBus, RetentionPolicy};
use crate::sharding::merkle::{compute_file_merkle_root, Hash32};
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
/// ### Architectural Invariant (`ADR-33` zero-key sync)
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
        Self::collect_files_recursive(folder_path, folder_path, &ignore, &mut discovered, None)?;
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
                    if prev.plaintext_sha256 == plaintext_sha256 && prev.size_bytes == streamed_size
                    {
                        let mut carried = prev.clone();
                        carried.modified_unix_ms = modified_unix_ms;
                        carried
                    } else {
                        self.ingest_file_sealed(&rel_path, &abs_path, modified_unix_ms, retention)?
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
            if !filter_prefixes.is_empty() && !matches_selective_filters(rel_path, filter_prefixes)
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
