//! Lazy-Streaming Virtual File System (`parvault::vfs`) backed by [`crate::gateway::ipc::GatewayBus`].
//!
//! Supports both `=y` built-in in-process mode (`GatewayBus::InProcess(Arc<GatewayEngine>)`,
//! `--no-socket` zero `.sock` file on disk) and `=m` split-plugin mode
//! (`GatewayBus::UnixSocket(GatewayIpcClient)` over `/var/run/parvault.sock`):
//! 1. **Instant Lazy-Loaded Metadata Inodes (`VfsLazyNode`)**: Mounts `10 GiB+` virtual vaults
//!    instantaneously in RAM (`O(1)` POSIX inode registration with zero eager shard downloads,
//!    backed at read time by `GatewayBus` Reed-Solomon streaming).
//! 2. **Targeted On-Demand Range Retrieval (`< 50 ms` TTFB)**: Translates POSIX `(inode, offset, len)`
//!    reads into `1 MiB` block-aligned `fetch_range_bytes_sync` calls (`SCM_RIGHTS` `memfd` or in-process).
//! 3. **Bounded LRU Disk Cache (`LruBlockCache`)**: Caches fetched `1 MiB` blocks on local disk and
//!    deterministically evicts least-recently-used `.blk` files whenever `used_bytes` would exceed
//!    `capacity_bytes`.
//! 4. **Triple Frontend Support**:
//!    - Pure-Rust Linux `/dev/fuse` protocol loop (ABI `7.31`, zero C `libfuse` linkage for static `musl`).
//!    - Unprivileged HTTP `Range` (`206 Partial Content`) + WebDAV (`PROPFIND`) server for locked-down
//!      `prplOS` / `RDK-B` LXC containers lacking `/dev/fuse`.
//!    - Userspace folder seed/ingest helper honoring `.parvaultignore`.

use crate::capabilities::CapabilityMacaroon;
use crate::gateway::ipc::EphemeralShardManifest;
#[cfg(unix)]
use crate::gateway::ipc::{create_memfd, GatewayBus, RetentionPolicy};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Default lazy VFS block granularity (`1 MiB`, aligned with `ROUTER_SOC_STRIPE_SIZE_BYTES`).
pub const DEFAULT_VFS_BLOCK_BYTES: usize = 1024 * 1024;

/// Root directory inode number in POSIX / FUSE (`FUSE_ROOT_ID = 1`).
pub const VFS_ROOT_INO: u64 = 1;

/// Computes `(clamped_end_offset, first_block_idx, last_block_idx)` for a POSIX read request
/// `[offset .. offset + length]` against a file of `file_size` bytes with `block_size` blocks,
/// without integer overflow or division by zero. Returns `None` when `offset >= file_size` or
/// `length == 0` (EOF / empty read).
pub const fn compute_vfs_block_window(
    file_size: u64,
    offset: u64,
    length: u64,
    block_size: usize,
) -> Option<(u64, u64, u64)> {
    if block_size == 0 || length == 0 || offset >= file_size {
        return None;
    }
    let end = match offset.checked_add(length) {
        Some(sum) if sum < file_size => sum,
        _ => file_size,
    };
    let bsz = block_size as u64;
    let first_blk = offset / bsz;
    let last_blk = (end - 1) / bsz;
    Some((end, first_blk, last_blk))
}

/// Strict bounded-capacity on-disk LRU block cache for `VirtualVaultFs`.
#[derive(Debug)]
pub struct LruBlockCache {
    cache_dir: PathBuf,
    capacity_bytes: u64,
    used_bytes: u64,
    sizes: HashMap<(u64, u64), u64>,
    lru_order: VecDeque<(u64, u64)>,
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl LruBlockCache {
    pub fn new(cache_dir: impl Into<PathBuf>, capacity_bytes: u64) -> io::Result<Self> {
        let cache_dir = cache_dir.into();
        fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            cache_dir,
            capacity_bytes,
            used_bytes: 0,
            sizes: HashMap::new(),
            lru_order: VecDeque::new(),
            hits: 0,
            misses: 0,
            evictions: 0,
        })
    }

    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    pub const fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    pub const fn hits(&self) -> u64 {
        self.hits
    }

    pub const fn misses(&self) -> u64 {
        self.misses
    }

    pub const fn evictions(&self) -> u64 {
        self.evictions
    }

    pub fn cached_blocks(&self) -> usize {
        self.sizes.len()
    }

    /// Whether `(ino, block_idx)` is cached (no hit or miss is counted).
    pub fn contains(&self, ino: u64, block_idx: u64) -> bool {
        self.sizes.contains_key(&(ino, block_idx))
    }

    /// Drops every cached block of `ino` (a replaced or removed file).
    pub fn forget_ino(&mut self, ino: u64) {
        let keys: Vec<(u64, u64)> = self.sizes.keys().filter(|k| k.0 == ino).copied().collect();
        for key in keys {
            if let Some(sz) = self.sizes.remove(&key) {
                self.used_bytes = self.used_bytes.saturating_sub(sz);
            }
            let _ = fs::remove_file(self.block_path(key.0, key.1));
        }
        self.lru_order.retain(|k| k.0 != ino);
    }

    fn block_path(&self, ino: u64, block_idx: u64) -> PathBuf {
        self.cache_dir.join(format!("ino{ino}_blk{block_idx}.blk"))
    }

    fn touch_key(&mut self, key: (u64, u64)) {
        self.lru_order.retain(|k| *k != key);
        self.lru_order.push_back(key);
    }

    pub fn get(&mut self, ino: u64, block_idx: u64) -> io::Result<Option<Vec<u8>>> {
        let key = (ino, block_idx);
        if !self.sizes.contains_key(&key) {
            self.misses = self.misses.saturating_add(1);
            return Ok(None);
        }
        let path = self.block_path(ino, block_idx);
        match fs::read(&path) {
            Ok(bytes) => {
                self.hits = self.hits.saturating_add(1);
                self.touch_key(key);
                Ok(Some(bytes))
            }
            Err(_) => {
                if let Some(removed_sz) = self.sizes.remove(&key) {
                    self.used_bytes = self.used_bytes.saturating_sub(removed_sz);
                }
                self.lru_order.retain(|k| *k != key);
                self.misses = self.misses.saturating_add(1);
                Ok(None)
            }
        }
    }

    /// Inserts `(ino, block_idx)` onto local disk cache, evicting oldest LRU blocks first whenever
    /// `used_bytes + bytes.len() > capacity_bytes`. If a single block exceeds `capacity_bytes`,
    /// bypasses caching cleanly without violating the capacity ceiling.
    pub fn insert(&mut self, ino: u64, block_idx: u64, bytes: &[u8]) -> io::Result<()> {
        let blk_len = bytes.len() as u64;
        if blk_len == 0 || blk_len > self.capacity_bytes {
            return Ok(());
        }
        let key = (ino, block_idx);
        if let Some(prev) = self.sizes.remove(&key) {
            self.used_bytes = self.used_bytes.saturating_sub(prev);
            self.lru_order.retain(|k| *k != key);
        }

        while self.used_bytes.saturating_add(blk_len) > self.capacity_bytes {
            let Some(victim) = self.lru_order.pop_front() else {
                break;
            };
            if let Some(v_sz) = self.sizes.remove(&victim) {
                self.used_bytes = self.used_bytes.saturating_sub(v_sz);
                self.evictions = self.evictions.saturating_add(1);
                let _ = fs::remove_file(self.block_path(victim.0, victim.1));
            }
        }

        let path = self.block_path(ino, block_idx);
        fs::write(&path, bytes)?;
        self.sizes.insert(key, blk_len);
        self.used_bytes = self.used_bytes.saturating_add(blk_len);
        self.lru_order.push_back(key);
        debug_assert!(self.used_bytes <= self.capacity_bytes);
        Ok(())
    }
}

/// Lazy-loaded POSIX VFS metadata inode representing a virtual directory or on-demand vault file.
///
/// Note on naming: `VfsLazyNode` denotes a dehydrated cloud-filesystem metadata inode (holding
/// POSIX `ino`, `size_bytes`, `mode`, `mtime_unix_secs`, [`EphemeralShardManifest`], and optional
/// [`CapabilityMacaroon`]) whose payload blocks are fetched lazily on demand over real
/// [`GatewayIpcServer`](crate::gateway::ipc::GatewayIpcServer) + `memfd` `SCM_RIGHTS` IPC. It is a
/// production lazy-mount data structure used by the shipped FUSE and WebDAV mounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsLazyNode {
    pub ino: u64,
    pub parent_ino: u64,
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub mtime_unix_secs: u64,
    pub mode: u32,
    pub manifest: Option<EphemeralShardManifest>,
    pub macaroon: Option<CapabilityMacaroon>,
}

/// Snapshot of VFS cache telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VfsCacheStats {
    pub capacity_bytes: u64,
    pub used_bytes: u64,
    pub cached_blocks: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

/// Serialized byte size of a Linux FUSE request header (`fuse_in_header`, ABI `7.31`).
pub const FUSE_IN_HEADER_BYTES: usize = 40;

/// Serialized byte size of a Linux FUSE `READ` / `READDIR` request body (`fuse_read_in`, ABI `7.31`).
pub const FUSE_READ_IN_BYTES: usize = 40;

/// Safe, unaligned-pointer-free Linux FUSE request header (`fuse_in_header`, ABI `7.31`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}

impl FuseInHeader {
    /// Encodes this 40-byte `fuse_in_header` in native endianness without raw pointer casts.
    pub fn to_ne_bytes(self) -> [u8; FUSE_IN_HEADER_BYTES] {
        let mut out = [0u8; FUSE_IN_HEADER_BYTES];
        out[0..4].copy_from_slice(&self.len.to_ne_bytes());
        out[4..8].copy_from_slice(&self.opcode.to_ne_bytes());
        out[8..16].copy_from_slice(&self.unique.to_ne_bytes());
        out[16..24].copy_from_slice(&self.nodeid.to_ne_bytes());
        out[24..28].copy_from_slice(&self.uid.to_ne_bytes());
        out[28..32].copy_from_slice(&self.gid.to_ne_bytes());
        out[32..36].copy_from_slice(&self.pid.to_ne_bytes());
        out[36..40].copy_from_slice(&self.padding.to_ne_bytes());
        out
    }
}

/// Safe, unaligned-pointer-free Linux FUSE `READ` / `READDIR` request body (`fuse_read_in`, ABI `7.31`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

impl FuseReadIn {
    /// Encodes this 40-byte `fuse_read_in` payload in native endianness without raw pointer casts.
    pub fn to_ne_bytes(self) -> [u8; FUSE_READ_IN_BYTES] {
        let mut out = [0u8; FUSE_READ_IN_BYTES];
        out[0..8].copy_from_slice(&self.fh.to_ne_bytes());
        out[8..16].copy_from_slice(&self.offset.to_ne_bytes());
        out[16..20].copy_from_slice(&self.size.to_ne_bytes());
        out[20..24].copy_from_slice(&self.read_flags.to_ne_bytes());
        out[24..32].copy_from_slice(&self.lock_owner.to_ne_bytes());
        out[32..36].copy_from_slice(&self.flags.to_ne_bytes());
        out[36..40].copy_from_slice(&self.padding.to_ne_bytes());
        out
    }
}

/// Parses a 40-byte Linux FUSE `fuse_in_header` from `buf` using safe `from_ne_bytes` slice
/// conversions (`0` `unsafe` blocks, `0` raw pointer casts, formally verified panic-free for
/// arbitrary byte slices under Kani `proof_fuse_header_parser_no_panic`).
pub const fn parse_fuse_in_header(buf: &[u8]) -> Option<FuseInHeader> {
    if buf.len() < FUSE_IN_HEADER_BYTES {
        return None;
    }
    let len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if (len as usize) < FUSE_IN_HEADER_BYTES || (len as usize) > buf.len() {
        return None;
    }
    let opcode = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let unique = u64::from_ne_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let nodeid = u64::from_ne_bytes([
        buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ]);
    let uid = u32::from_ne_bytes([buf[24], buf[25], buf[26], buf[27]]);
    let gid = u32::from_ne_bytes([buf[28], buf[29], buf[30], buf[31]]);
    let pid = u32::from_ne_bytes([buf[32], buf[33], buf[34], buf[35]]);
    let padding = u32::from_ne_bytes([buf[36], buf[37], buf[38], buf[39]]);
    Some(FuseInHeader {
        len,
        opcode,
        unique,
        nodeid,
        uid,
        gid,
        pid,
        padding,
    })
}

/// Parses a 40-byte Linux FUSE `fuse_read_in` payload from `payload` using safe `from_ne_bytes`
/// slice conversions (`0` `unsafe` blocks, formally verified panic-free for arbitrary byte slices).
pub const fn parse_fuse_read_in(payload: &[u8]) -> Option<FuseReadIn> {
    if payload.len() < FUSE_READ_IN_BYTES {
        return None;
    }
    let fh = u64::from_ne_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]);
    let offset = u64::from_ne_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ]);
    let size = u32::from_ne_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let read_flags = u32::from_ne_bytes([payload[20], payload[21], payload[22], payload[23]]);
    let lock_owner = u64::from_ne_bytes([
        payload[24],
        payload[25],
        payload[26],
        payload[27],
        payload[28],
        payload[29],
        payload[30],
        payload[31],
    ]);
    let flags = u32::from_ne_bytes([payload[32], payload[33], payload[34], payload[35]]);
    let padding = u32::from_ne_bytes([payload[36], payload[37], payload[38], payload[39]]);
    Some(FuseReadIn {
        fh,
        offset,
        size,
        read_flags,
        lock_owner,
        flags,
        padding,
    })
}

/// An inode number of the virtual file system.
pub type Ino = u64;

/// One file for [`VirtualVaultFs::upsert_file`] (`v0.5.6` T0 item 4): what a catalog import
/// knows about it.
#[derive(Debug, Clone)]
pub struct LazyFileSpec {
    pub manifest: EphemeralShardManifest,
    /// A per-file token for its `FetchRange` calls (else the VFS default).
    pub macaroon: Option<CapabilityMacaroon>,
    /// Modification time to show (else the import time).
    pub mtime_unix_secs: Option<u64>,
}

/// What [`VirtualVaultFs::remove_path`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRemoval {
    /// Nothing was at the path.
    Absent,
    /// A file was removed.
    Removed,
    /// A folder is at the path; it was left in place.
    Folder,
}

/// What [`catalog_import_decision`] allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogImport {
    /// A newer catalog: apply it.
    Apply,
    /// The version already loaded: nothing to do.
    Unchanged,
}

/// Claim `B20-LIST` (`@guard`): whether a fetched vault catalog is imported. A catalog that
/// fails verification or names another vault key is foreign (`reject.catalog_foreign`); one
/// older than the loaded version is a rollback (`reject.catalog_rollback`).
pub const fn catalog_import_decision(
    envelope_verifies: bool,
    key_matches: bool,
    envelope_version: u64,
    loaded_version: u64,
) -> Result<CatalogImport, &'static str> {
    if !envelope_verifies || !key_matches {
        return Err("reject.catalog_foreign");
    }
    if envelope_version < loaded_version {
        return Err("reject.catalog_rollback");
    }
    if envelope_version == loaded_version {
        return Ok(CatalogImport::Unchanged);
    }
    Ok(CatalogImport::Apply)
}

/// Path segments as [`VirtualVaultFs::register_lazy_file`] reads them (`.` and `..` dropped).
#[cfg(unix)]
fn vfs_path_parts(virtual_path: &str) -> Vec<&str> {
    virtual_path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .collect()
}

// v0.5.6 T0 (B-1 P0): the WebDAV HTTP server and its F-43 decision live in `crate::webdav`;
// these names stay importable from `vfs` so embedders and the plugin keep their paths.
pub use crate::webdav::{
    presented_webdav_token, webdav_auth_decision, PresentedToken, WebdavAuthFacts,
    WebdavAuthRefusal, WebdavVerifier, WEBDAV_MAX_TOKEN_CHARS,
};

#[cfg(unix)]
mod unix_vfs {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;

    /// Lazy-streaming Virtual File System backed by [`GatewayBus`] (`InProcess` or `UnixSocket`).
    #[derive(Clone)]
    pub struct VirtualVaultFs {
        bus: GatewayBus,
        block_size: usize,
        default_macaroon: Option<CapabilityMacaroon>,
        nodes: Arc<Mutex<BTreeMap<u64, VfsLazyNode>>>,
        children: Arc<Mutex<HashMap<u64, BTreeMap<String, u64>>>>,
        next_ino: Arc<Mutex<u64>>,
        cache: Arc<Mutex<LruBlockCache>>,
        /// B-24: one in-flight fetch per `(inode, block)`; concurrent misses join it.
        inflight: Arc<Mutex<InflightMap>>,
        /// B-20 (T2): re-imports the catalogs once after a failed read of a catalog file.
        reimport: Arc<Mutex<Option<ReimportHook>>>,
    }

    /// The catalog re-import a failed read calls (T2).
    pub type ReimportHook = Arc<dyn Fn() + Send + Sync>;

    type InflightMap = HashMap<(u64, u64), Arc<BlockFlight>>;
    /// A finished fetch: the bytes, or the error's kind and text (`io::Error` is not `Clone`).
    type FlightResult = Result<Vec<u8>, (io::ErrorKind, String)>;

    /// One in-flight block fetch (B-24).
    struct BlockFlight {
        result: Mutex<Option<FlightResult>>,
        done: std::sync::Condvar,
        /// Set when a scavenger owns the fetch: a joining foreground reader promotes it (S6).
        promote: Option<Arc<std::sync::atomic::AtomicBool>>,
    }

    impl VirtualVaultFs {
        pub fn new(
            socket_path: impl Into<PathBuf>,
            cache_dir: impl Into<PathBuf>,
            cache_capacity_bytes: u64,
        ) -> io::Result<Self> {
            Self::with_block_size(
                socket_path,
                cache_dir,
                cache_capacity_bytes,
                DEFAULT_VFS_BLOCK_BYTES,
            )
        }

        pub fn with_block_size(
            socket_path: impl Into<PathBuf>,
            cache_dir: impl Into<PathBuf>,
            cache_capacity_bytes: u64,
            block_size: usize,
        ) -> io::Result<Self> {
            Self::with_bus_and_block_size(
                GatewayBus::unix_socket(socket_path.into()),
                cache_dir,
                cache_capacity_bytes,
                block_size,
            )
        }

        pub fn with_bus(
            bus: GatewayBus,
            cache_dir: impl Into<PathBuf>,
            cache_capacity_bytes: u64,
        ) -> io::Result<Self> {
            Self::with_bus_and_block_size(
                bus,
                cache_dir,
                cache_capacity_bytes,
                DEFAULT_VFS_BLOCK_BYTES,
            )
        }

        pub fn with_bus_and_block_size(
            bus: GatewayBus,
            cache_dir: impl Into<PathBuf>,
            cache_capacity_bytes: u64,
            block_size: usize,
        ) -> io::Result<Self> {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut nodes = BTreeMap::new();
            nodes.insert(
                VFS_ROOT_INO,
                VfsLazyNode {
                    ino: VFS_ROOT_INO,
                    parent_ino: VFS_ROOT_INO,
                    name: "/".into(),
                    is_dir: true,
                    size_bytes: 0,
                    mtime_unix_secs: now_secs,
                    mode: 0o040755,
                    manifest: None,
                    macaroon: None,
                },
            );
            let mut children = HashMap::new();
            children.insert(VFS_ROOT_INO, BTreeMap::new());
            let cache = LruBlockCache::new(cache_dir, cache_capacity_bytes)?;
            Ok(Self {
                bus,
                block_size: block_size.max(4096),
                default_macaroon: None,
                nodes: Arc::new(Mutex::new(nodes)),
                children: Arc::new(Mutex::new(children)),
                next_ino: Arc::new(Mutex::new(2)),
                cache: Arc::new(Mutex::new(cache)),
                inflight: Arc::new(Mutex::new(HashMap::new())),
                reimport: Arc::new(Mutex::new(None)),
            })
        }

        /// Returns a reference to the underlying transport-agnostic [`GatewayBus`].
        pub fn bus(&self) -> &GatewayBus {
            &self.bus
        }

        /// Attaches a default [`CapabilityMacaroon`] presented on lazy `FetchRange` calls when an
        /// individual inode does not carry its own per-file token.
        pub fn with_default_macaroon(mut self, macaroon: Option<CapabilityMacaroon>) -> Self {
            self.default_macaroon = macaroon;
            self
        }

        /// B-20 (`v0.5.6` track C): imports the vault catalogs `data_dir` holds keys for, at
        /// start and on a timer, through [`Self::upsert_file`] and [`Self::remove_path`]; the
        /// scavenger then hydrates them (L-94, S1). Called by the daemon once the built-in VFS
        /// exists. A socket-bus VFS (a plugin) has no engine to index manifests in, so it
        /// imports nothing. `PARVAULT_CATALOG_IMPORT_SECS` overrides the period (tests).
        #[cfg(feature = "daemon-runtime")]
        pub fn start_catalog_import(
            &self,
            data_dir: &Path,
            block_store: &crate::storage::BlockStore,
        ) -> io::Result<()> {
            let _ = block_store;
            let GatewayBus::InProcess(engine) = &self.bus else {
                return Ok(());
            };
            let interval = std::env::var("PARVAULT_CATALOG_IMPORT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|s| Duration::from_secs(s.max(1)))
                .unwrap_or(super::catalog::IMPORT_INTERVAL);
            let importer =
                super::catalog::CatalogImporter::new(self.clone(), Arc::clone(engine), data_dir);
            importer.start(interval)
        }

        /// Registers a virtual file path (e.g. `"/movies/archive_10gb.bin"` or `"backup.tar"`)
        /// instantaneously as an in-memory lazy metadata inode without fetching any shard bytes.
        pub fn register_lazy_file(
            &self,
            virtual_path: &str,
            manifest: EphemeralShardManifest,
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<u64> {
            let parts: Vec<&str> = virtual_path
                .trim_matches('/')
                .split('/')
                .filter(|s| !s.is_empty() && *s != "." && *s != "..")
                .collect();
            if parts.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "virtual_path must name a file",
                ));
            }
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let mut cur_parent = VFS_ROOT_INO;
            for dir_name in &parts[..parts.len() - 1] {
                let existing = {
                    let ch = self.children.lock().unwrap();
                    ch.get(&cur_parent).and_then(|m| m.get(*dir_name)).copied()
                };
                if let Some(dir_ino) = existing {
                    cur_parent = dir_ino;
                } else {
                    let dir_ino = self.alloc_ino();
                    let node = VfsLazyNode {
                        ino: dir_ino,
                        parent_ino: cur_parent,
                        name: (*dir_name).to_string(),
                        is_dir: true,
                        size_bytes: 0,
                        mtime_unix_secs: now_secs,
                        mode: 0o040755,
                        manifest: None,
                        macaroon: None,
                    };
                    self.nodes.lock().unwrap().insert(dir_ino, node);
                    self.children
                        .lock()
                        .unwrap()
                        .entry(cur_parent)
                        .or_default()
                        .insert((*dir_name).to_string(), dir_ino);
                    self.children.lock().unwrap().entry(dir_ino).or_default();
                    cur_parent = dir_ino;
                }
            }

            let file_name = parts[parts.len() - 1].to_string();
            let ino = self.alloc_ino();
            let size_bytes = manifest.total_size;
            let file_node = VfsLazyNode {
                ino,
                parent_ino: cur_parent,
                name: file_name.clone(),
                is_dir: false,
                size_bytes,
                mtime_unix_secs: now_secs,
                mode: 0o100644,
                manifest: Some(manifest),
                macaroon,
            };
            self.nodes.lock().unwrap().insert(ino, file_node);
            self.children
                .lock()
                .unwrap()
                .entry(cur_parent)
                .or_default()
                .insert(file_name, ino);
            Ok(ino)
        }

        /// Inserts or replaces the file at `virtual_path` (`v0.5.6` T0 item 4, for B-20's
        /// catalog import): a changed file gets a new inode, so no cached block of the old
        /// bytes is served for it (T1: the cache is keyed by inode and block). Parent folders
        /// are created as needed. A folder at `virtual_path` is refused.
        pub fn upsert_file(&self, virtual_path: &str, spec: LazyFileSpec) -> io::Result<Ino> {
            let parts = vfs_path_parts(virtual_path);
            let Some((name, dirs)) = parts.split_last() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "virtual_path must name a file",
                ));
            };
            let parent = self.ensure_dirs(dirs)?;
            let ino = self.alloc_ino();
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let node = VfsLazyNode {
                ino,
                parent_ino: parent,
                name: (*name).to_string(),
                is_dir: false,
                size_bytes: spec.manifest.total_size,
                mtime_unix_secs: spec.mtime_unix_secs.unwrap_or(now_secs),
                mode: 0o100644,
                manifest: Some(spec.manifest),
                macaroon: spec.macaroon,
            };
            // The new node exists before its name points at it, and the name moves in one step
            // under the children lock, so a reader's lookup finds the old file or the new one,
            // never neither (qa-t0 INFO: the T0 version removed first).
            self.nodes.lock().unwrap().insert(ino, node);
            let replaced = {
                let mut ch = self.children.lock().unwrap();
                let entries = ch.entry(parent).or_default();
                let old = entries.get(*name).copied();
                let old_is_dir = old
                    .is_some_and(|o| self.nodes.lock().unwrap().get(&o).is_some_and(|n| n.is_dir));
                if old_is_dir {
                    None
                } else {
                    entries.insert((*name).to_string(), ino);
                    Some(old)
                }
            };
            match replaced {
                None => {
                    self.nodes.lock().unwrap().remove(&ino);
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "upsert_file: the path is a folder",
                    ))
                }
                Some(old) => {
                    if let Some(old) = old {
                        self.nodes.lock().unwrap().remove(&old);
                        self.cache.lock().unwrap().forget_ino(old);
                    }
                    Ok(ino)
                }
            }
        }

        /// The folder inode at `dirs` under the root, creating missing folders.
        fn ensure_dirs(&self, dirs: &[&str]) -> io::Result<Ino> {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut cur = VFS_ROOT_INO;
            for dir_name in dirs {
                let mut ch = self.children.lock().unwrap();
                let existing = ch.get(&cur).and_then(|m| m.get(*dir_name)).copied();
                if let Some(ino) = existing {
                    drop(ch);
                    match self.getattr(ino) {
                        Some(n) if n.is_dir => cur = ino,
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "a parent of the path is a file",
                            ))
                        }
                    }
                    continue;
                }
                let dir_ino = self.alloc_ino();
                self.nodes.lock().unwrap().insert(
                    dir_ino,
                    VfsLazyNode {
                        ino: dir_ino,
                        parent_ino: cur,
                        name: (*dir_name).to_string(),
                        is_dir: true,
                        size_bytes: 0,
                        mtime_unix_secs: now_secs,
                        mode: 0o040755,
                        manifest: None,
                        macaroon: None,
                    },
                );
                ch.entry(cur)
                    .or_default()
                    .insert((*dir_name).to_string(), dir_ino);
                ch.entry(dir_ino).or_default();
                cur = dir_ino;
            }
            Ok(cur)
        }

        /// Removes the file at `virtual_path` (T4: a file gone from the catalog leaves the
        /// listing). A folder is left in place.
        pub fn remove_path(&self, virtual_path: &str) -> PathRemoval {
            let parts = vfs_path_parts(virtual_path);
            let Some((name, dirs)) = parts.split_last() else {
                return PathRemoval::Folder;
            };
            let mut parent = VFS_ROOT_INO;
            for d in dirs {
                match self.lookup(parent, d) {
                    Some(n) if n.is_dir => parent = n.ino,
                    _ => return PathRemoval::Absent,
                }
            }
            let Some(node) = self.lookup(parent, name) else {
                return PathRemoval::Absent;
            };
            if node.is_dir {
                return PathRemoval::Folder;
            }
            if let Some(m) = self.children.lock().unwrap().get_mut(&parent) {
                m.remove(*name);
            }
            self.nodes.lock().unwrap().remove(&node.ino);
            self.cache.lock().unwrap().forget_ino(node.ino);
            PathRemoval::Removed
        }

        /// The entries of the folder at `virtual_path`, or `None` when it is not a folder.
        pub fn list_children(&self, virtual_path: &str) -> Option<Vec<VfsLazyNode>> {
            let mut node = self.getattr(VFS_ROOT_INO)?;
            for p in vfs_path_parts(virtual_path) {
                node = self.lookup(node.ino, p)?;
            }
            node.is_dir.then(|| self.readdir(node.ino))
        }

        fn alloc_ino(&self) -> u64 {
            let mut g = self.next_ino.lock().unwrap();
            let id = *g;
            *g += 1;
            id
        }

        pub fn getattr(&self, ino: u64) -> Option<VfsLazyNode> {
            self.nodes.lock().unwrap().get(&ino).cloned()
        }

        pub fn lookup(&self, parent_ino: u64, name: &str) -> Option<VfsLazyNode> {
            // Both locks at once (children, then nodes, the order every writer takes), so a
            // name being swapped by `upsert_file` resolves to the old node or the new one.
            let ch = self.children.lock().unwrap();
            let child_ino = ch.get(&parent_ino).and_then(|m| m.get(name)).copied()?;
            let nodes = self.nodes.lock().unwrap();
            nodes.get(&child_ino).cloned()
        }

        pub fn lookup_path(&self, virtual_path: &str) -> Option<VfsLazyNode> {
            let parts: Vec<&str> = virtual_path
                .trim_matches('/')
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() {
                return self.getattr(VFS_ROOT_INO);
            }
            // The last lookup's node itself, not a second read by inode: a name swapped by
            // `upsert_file` in between would otherwise resolve to a removed inode.
            let mut node = self.getattr(VFS_ROOT_INO)?;
            for p in parts {
                node = self.lookup(node.ino, p)?;
            }
            Some(node)
        }

        pub fn readdir(&self, dir_ino: u64) -> Vec<VfsLazyNode> {
            let ch = self.children.lock().unwrap();
            let child_inos: Vec<u64> = ch
                .get(&dir_ino)
                .map(|m| m.values().copied().collect())
                .unwrap_or_default();
            let nodes = self.nodes.lock().unwrap();
            child_inos
                .into_iter()
                .filter_map(|id| nodes.get(&id).cloned())
                .collect()
        }

        pub fn cache_stats(&self) -> VfsCacheStats {
            let c = self.cache.lock().unwrap();
            VfsCacheStats {
                capacity_bytes: c.capacity_bytes(),
                used_bytes: c.used_bytes(),
                cached_blocks: c.cached_blocks(),
                hits: c.hits(),
                misses: c.misses(),
                evictions: c.evictions(),
            }
        }

        /// Lazily reads `[offset .. offset + length]` for `ino`, pulling only missing `block_size`
        /// ranges over `/var/run/parvault.sock` (`FetchRange` + `SCM_RIGHTS` `memfd`), populating
        /// `LruBlockCache`, and returning `(bytes, time_to_first_byte)`.
        pub fn read_range_with_ttfb(
            &self,
            ino: u64,
            offset: u64,
            length: u64,
        ) -> io::Result<(Vec<u8>, Duration)> {
            let first = self.read_range_once(ino, offset, length);
            let Err(e) = first else {
                return first;
            };
            // T2: a catalog file whose read fails (for example a stripe freed by version GC)
            // re-imports the catalogs once; if that gave the path a new inode, read it once.
            let hook = self.reimport.lock().unwrap().clone();
            let (Some(hook), Some(node)) = (hook, self.getattr(ino)) else {
                return Err(e);
            };
            if node.is_dir || node.manifest.is_none() {
                return Err(e);
            }
            hook();
            match self.lookup(node.parent_ino, &node.name) {
                Some(n) if n.ino != ino && !n.is_dir => self.read_range_once(n.ino, offset, length),
                _ => Err(e),
            }
        }

        /// Sets the catalog re-import a failed read calls (T2).
        pub fn set_reimport_hook(&self, hook: Option<ReimportHook>) {
            *self.reimport.lock().unwrap() = hook;
        }

        /// The block size reads are split into.
        pub const fn block_size(&self) -> usize {
            self.block_size
        }

        /// Whether `(ino, block)` is in the cache now (counts neither a hit nor a miss).
        pub fn block_cached(&self, ino: u64, blk_idx: u64) -> bool {
            self.cache.lock().unwrap().contains(ino, blk_idx)
        }

        fn read_range_once(
            &self,
            ino: u64,
            offset: u64,
            length: u64,
        ) -> io::Result<(Vec<u8>, Duration)> {
            let t0 = Instant::now();
            let node = self.getattr(ino).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("inode {ino} not found"))
            })?;
            if node.is_dir {
                return Err(io::Error::new(
                    io::ErrorKind::IsADirectory,
                    "cannot read bytes from directory inode",
                ));
            }
            let Some(manifest) = node.manifest else {
                return Ok((Vec::new(), t0.elapsed()));
            };
            let Some((end_offset, first_blk, last_blk)) =
                compute_vfs_block_window(node.size_bytes, offset, length, self.block_size)
            else {
                return Ok((Vec::new(), t0.elapsed()));
            };

            let total_out_len = (end_offset - offset) as usize;
            let mut out = Vec::with_capacity(total_out_len);
            let mut ttfb: Option<Duration> = None;
            let bsz = self.block_size as u64;

            for blk_idx in first_blk..=last_blk {
                let blk_start = blk_idx.saturating_mul(bsz);
                let blk_len = node.size_bytes.saturating_sub(blk_start).min(bsz);

                // F-43 (L-44 item 4): a cache hit is served without a gateway `FetchRange`, so for
                // WebDAV the edge `webdav_auth_decision` (for the plugin host: `is_attenuation_of`
                // against the pinned token) is the only check on this read.
                let effective_mac = node
                    .macaroon
                    .clone()
                    .or_else(|| self.default_macaroon.clone());
                let blk_bytes =
                    self.read_block(ino, blk_idx, &manifest, blk_start, blk_len, effective_mac)?;

                if ttfb.is_none() {
                    ttfb = Some(t0.elapsed());
                }

                let local_start = offset.saturating_sub(blk_start) as usize;
                let local_end = ((end_offset - blk_start) as usize).min(blk_bytes.len());
                if local_start < local_end {
                    out.extend_from_slice(&blk_bytes[local_start..local_end]);
                }
            }

            Ok((out, ttfb.unwrap_or_else(|| t0.elapsed())))
        }

        /// One block through the cache, with single-flight misses (B-24): the first reader of a
        /// missing block fetches it; concurrent readers of the same block wait for that fetch.
        /// A foreground reader joining a scavenger's fetch promotes it (S6).
        fn read_block(
            &self,
            ino: u64,
            blk_idx: u64,
            manifest: &EphemeralShardManifest,
            blk_start: u64,
            blk_len: u64,
            mac: Option<CapabilityMacaroon>,
        ) -> io::Result<Vec<u8>> {
            use crate::fetch_sched::{self as fs_sched, FetchClass};
            use std::sync::atomic::AtomicBool;
            let key = (ino, blk_idx);
            let (flight, leader) = {
                let mut inflight = self.inflight.lock().unwrap();
                if let Some(f) = inflight.get(&key) {
                    (Arc::clone(f), false)
                } else {
                    // F-43 (L-44 item 4): a cache hit is served without a gateway `FetchRange`,
                    // so for WebDAV the edge `webdav_auth_decision` is the only check on it.
                    if let Some(hit) = self.cache.lock().unwrap().get(ino, blk_idx)? {
                        return Ok(hit);
                    }
                    let promote = (fs_sched::current_class() == FetchClass::Scavenger)
                        .then(|| Arc::new(AtomicBool::new(false)));
                    let f = Arc::new(BlockFlight {
                        result: Mutex::new(None),
                        done: std::sync::Condvar::new(),
                        promote,
                    });
                    inflight.insert(key, Arc::clone(&f));
                    (f, true)
                }
            };
            if !leader {
                if fs_sched::current_class() == FetchClass::Foreground {
                    if let Some(p) = &flight.promote {
                        fs_sched::global().promote(p);
                    }
                }
                let mut g = flight.result.lock().unwrap();
                while g.is_none() {
                    g = flight.done.wait(g).unwrap();
                }
                return match g.as_ref() {
                    Some(Ok(b)) => Ok(b.clone()),
                    Some(Err((kind, msg))) => Err(io::Error::new(*kind, msg.clone())),
                    None => unreachable!("loop exits with a result"),
                };
            }
            fs_sched::note_cache_miss();
            let fetch = || {
                self.bus
                    .fetch_range_bytes_sync(manifest, blk_start, blk_len, mac)
            };
            let res = match &flight.promote {
                Some(p) => fs_sched::run_as_scavenger(Arc::clone(p), fetch),
                None => fetch(),
            };
            let res = res.and_then(|b| {
                self.cache.lock().unwrap().insert(ino, blk_idx, &b)?;
                Ok(b)
            });
            *flight.result.lock().unwrap() = Some(match &res {
                Ok(b) => Ok(b.clone()),
                Err(e) => Err((e.kind(), e.to_string())),
            });
            self.inflight.lock().unwrap().remove(&key);
            flight.done.notify_all();
            res
        }

        /// Convenience POSIX `pread`-equivalent returning the requested byte range.
        pub fn read_at(&self, ino: u64, offset: u64, length: u64) -> io::Result<Vec<u8>> {
            let (bytes, _ttfb) = self.read_range_with_ttfb(ino, offset, length)?;
            Ok(bytes)
        }

        /// Synchronizes all non-ignored regular files in `local_dir` into `parvault` via sealed
        /// `memfd` (`store_sealed_memfd_sync`) and mounts them as lazy VFS inodes, honoring
        /// [`crate::sync::ParvaultIgnore::from_folder`].
        ///
        /// B-16: each store presents the bus's token source; a socket bus without one presents
        /// this VFS's default macaroon (which must then be a write token).
        pub fn ingest_local_directory(&self, local_dir: &Path) -> io::Result<usize> {
            let ignore = crate::sync::ParvaultIgnore::from_folder(local_dir);
            let mut count = 0usize;
            let bus = match (&self.default_macaroon, self.bus.has_token_source()) {
                (Some(m), false) => self.bus.clone().with_token_source(Some(std::sync::Arc::new(
                    crate::capabilities::GatewayTokenSource::Fixed(m.clone()),
                ))),
                _ => self.bus.clone(),
            };
            self.ingest_dir_recursive(&bus, local_dir, local_dir, &ignore, &mut count)?;
            Ok(count)
        }

        fn ingest_dir_recursive(
            &self,
            bus: &GatewayBus,
            base: &Path,
            cur: &Path,
            ignore: &crate::sync::ParvaultIgnore,
            count: &mut usize,
        ) -> io::Result<()> {
            for entry in fs::read_dir(cur)? {
                let entry = entry?;
                let ft = entry.file_type()?;
                if ft.is_symlink() {
                    continue;
                }
                let path = entry.path();
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if ft.is_dir() {
                    if ignore.is_ignored(&rel, true) {
                        continue;
                    }
                    self.ingest_dir_recursive(bus, base, &path, ignore, count)?;
                } else if ft.is_file() {
                    if ignore.is_ignored(&rel, false) {
                        continue;
                    }
                    let mfd = create_memfd("parvault-sync-in")?;
                    let mut mfd_file = std::fs::File::from(mfd);
                    let mut src = std::fs::File::open(&path)?;
                    let copied = io::copy(&mut src, &mut mfd_file)?;
                    mfd_file.seek(SeekFrom::Start(0))?;
                    let manifest = bus.store_sealed_memfd_sync(
                        mfd_file.as_raw_fd(),
                        copied,
                        RetentionPolicy::Persistent,
                    )?;
                    self.register_lazy_file(&rel, manifest, None)?;
                    *count += 1;
                }
            }
            Ok(())
        }

        /// Serves the pure-Rust Linux `/dev/fuse` kernel wire protocol (`ABI 7.31`, zero C
        /// `libfuse` dependency) on an already-mounted `/dev/fuse` file descriptor.
        pub fn serve_fuse_fd_blocking(&self, fuse_dev: std::fs::File) -> io::Result<()> {
            serve_pure_rust_fuse_loop(fuse_dev, self)
        }
    }

    // Minimal Pure-Rust Linux FUSE Kernel Protocol (`ABI 7.31`, zero C `libfuse`, zero `unsafe`).
    const FUSE_KERNEL_VERSION: u32 = 7;
    const FUSE_KERNEL_MINOR_VERSION: u32 = 31;
    const FUSE_LOOKUP: u32 = 1;
    const FUSE_GETATTR: u32 = 3;
    const FUSE_OPEN: u32 = 14;
    const FUSE_READ: u32 = 15;
    const FUSE_RELEASE: u32 = 18;
    const FUSE_OPENDIR: u32 = 27;
    const FUSE_READDIR: u32 = 28;
    const FUSE_RELEASEDIR: u32 = 29;
    const FUSE_INIT: u32 = 26;
    const FUSE_DESTROY: u32 = 38;
    /// Requests the kernel expects no reply to; replying fails with `ENOENT` (plan-5 D-1).
    const FUSE_FORGET: u32 = 2;
    const FUSE_INTERRUPT: u32 = 36;
    const FUSE_BATCH_FORGET: u32 = 42;
    const FUSE_OUT_HEADER_BYTES: usize = 16;

    #[derive(Clone, Copy)]
    struct FuseOutHeader {
        len: u32,
        error: i32,
        unique: u64,
    }

    impl FuseOutHeader {
        fn to_ne_bytes(self) -> [u8; FUSE_OUT_HEADER_BYTES] {
            let mut out = [0u8; FUSE_OUT_HEADER_BYTES];
            out[0..4].copy_from_slice(&self.len.to_ne_bytes());
            out[4..8].copy_from_slice(&self.error.to_ne_bytes());
            out[8..16].copy_from_slice(&self.unique.to_ne_bytes());
            out
        }
    }

    #[derive(Clone, Copy, Default)]
    struct FuseAttr {
        ino: u64,
        size: u64,
        blocks: u64,
        atime: u64,
        mtime: u64,
        ctime: u64,
        atimensec: u32,
        mtimensec: u32,
        ctimensec: u32,
        mode: u32,
        nlink: u32,
        uid: u32,
        gid: u32,
        rdev: u32,
        blksize: u32,
        padding: u32,
    }

    impl FuseAttr {
        fn to_ne_bytes(self) -> [u8; 88] {
            let mut out = [0u8; 88];
            out[0..8].copy_from_slice(&self.ino.to_ne_bytes());
            out[8..16].copy_from_slice(&self.size.to_ne_bytes());
            out[16..24].copy_from_slice(&self.blocks.to_ne_bytes());
            out[24..32].copy_from_slice(&self.atime.to_ne_bytes());
            out[32..40].copy_from_slice(&self.mtime.to_ne_bytes());
            out[40..48].copy_from_slice(&self.ctime.to_ne_bytes());
            out[48..52].copy_from_slice(&self.atimensec.to_ne_bytes());
            out[52..56].copy_from_slice(&self.mtimensec.to_ne_bytes());
            out[56..60].copy_from_slice(&self.ctimensec.to_ne_bytes());
            out[60..64].copy_from_slice(&self.mode.to_ne_bytes());
            out[64..68].copy_from_slice(&self.nlink.to_ne_bytes());
            out[68..72].copy_from_slice(&self.uid.to_ne_bytes());
            out[72..76].copy_from_slice(&self.gid.to_ne_bytes());
            out[76..80].copy_from_slice(&self.rdev.to_ne_bytes());
            out[80..84].copy_from_slice(&self.blksize.to_ne_bytes());
            out[84..88].copy_from_slice(&self.padding.to_ne_bytes());
            out
        }
    }

    #[derive(Clone, Copy)]
    struct FuseInitOut {
        major: u32,
        minor: u32,
        max_readahead: u32,
        flags: u32,
        max_background: u16,
        congestion_threshold: u16,
        max_write: u32,
        time_gran: u32,
        max_pages: u16,
        map_alignment: u16,
        unused: [u32; 8],
    }

    impl FuseInitOut {
        fn to_ne_bytes(self) -> [u8; 64] {
            let mut out = [0u8; 64];
            out[0..4].copy_from_slice(&self.major.to_ne_bytes());
            out[4..8].copy_from_slice(&self.minor.to_ne_bytes());
            out[8..12].copy_from_slice(&self.max_readahead.to_ne_bytes());
            out[12..16].copy_from_slice(&self.flags.to_ne_bytes());
            out[16..18].copy_from_slice(&self.max_background.to_ne_bytes());
            out[18..20].copy_from_slice(&self.congestion_threshold.to_ne_bytes());
            out[20..24].copy_from_slice(&self.max_write.to_ne_bytes());
            out[24..28].copy_from_slice(&self.time_gran.to_ne_bytes());
            out[28..30].copy_from_slice(&self.max_pages.to_ne_bytes());
            out[30..32].copy_from_slice(&self.map_alignment.to_ne_bytes());
            for (idx, word) in self.unused.iter().enumerate() {
                let start = 32 + idx * 4;
                out[start..start + 4].copy_from_slice(&word.to_ne_bytes());
            }
            out
        }
    }

    #[derive(Clone, Copy)]
    struct FuseAttrOut {
        attr_valid: u64,
        attr_valid_nsec: u32,
        dummy: u32,
        attr: FuseAttr,
    }

    impl FuseAttrOut {
        fn to_ne_bytes(self) -> [u8; 104] {
            let mut out = [0u8; 104];
            out[0..8].copy_from_slice(&self.attr_valid.to_ne_bytes());
            out[8..12].copy_from_slice(&self.attr_valid_nsec.to_ne_bytes());
            out[12..16].copy_from_slice(&self.dummy.to_ne_bytes());
            out[16..104].copy_from_slice(&self.attr.to_ne_bytes());
            out
        }
    }

    #[derive(Clone, Copy)]
    struct FuseEntryOut {
        nodeid: u64,
        generation: u64,
        entry_valid: u64,
        attr_valid: u64,
        entry_valid_nsec: u32,
        attr_valid_nsec: u32,
        attr: FuseAttr,
    }

    impl FuseEntryOut {
        fn to_ne_bytes(self) -> [u8; 128] {
            let mut out = [0u8; 128];
            out[0..8].copy_from_slice(&self.nodeid.to_ne_bytes());
            out[8..16].copy_from_slice(&self.generation.to_ne_bytes());
            out[16..24].copy_from_slice(&self.entry_valid.to_ne_bytes());
            out[24..32].copy_from_slice(&self.attr_valid.to_ne_bytes());
            out[32..36].copy_from_slice(&self.entry_valid_nsec.to_ne_bytes());
            out[36..40].copy_from_slice(&self.attr_valid_nsec.to_ne_bytes());
            out[40..128].copy_from_slice(&self.attr.to_ne_bytes());
            out
        }
    }

    #[derive(Clone, Copy)]
    struct FuseOpenOut {
        fh: u64,
        open_flags: u32,
        padding: u32,
    }

    impl FuseOpenOut {
        fn to_ne_bytes(self) -> [u8; 16] {
            let mut out = [0u8; 16];
            out[0..8].copy_from_slice(&self.fh.to_ne_bytes());
            out[8..12].copy_from_slice(&self.open_flags.to_ne_bytes());
            out[12..16].copy_from_slice(&self.padding.to_ne_bytes());
            out
        }
    }

    fn lazy_to_fuse_attr(node: &VfsLazyNode) -> FuseAttr {
        FuseAttr {
            ino: node.ino,
            size: node.size_bytes,
            blocks: node.size_bytes.div_ceil(512),
            atime: node.mtime_unix_secs,
            mtime: node.mtime_unix_secs,
            ctime: node.mtime_unix_secs,
            mode: node.mode,
            nlink: if node.is_dir { 2 } else { 1 },
            uid: crate::os_sys::geteuid(),
            gid: crate::os_sys::getegid(),
            blksize: DEFAULT_VFS_BLOCK_BYTES as u32,
            ..FuseAttr::default()
        }
    }

    fn write_fuse_reply(
        dev: &mut std::fs::File,
        unique: u64,
        error: i32,
        body: &[u8],
    ) -> io::Result<()> {
        let hdr = FuseOutHeader {
            len: (FUSE_OUT_HEADER_BYTES + body.len()) as u32,
            error,
            unique,
        };
        let mut pkt = Vec::with_capacity(hdr.len as usize);
        pkt.extend_from_slice(&hdr.to_ne_bytes());
        pkt.extend_from_slice(body);
        match dev.write_all(&pkt) {
            // The kernel already dropped this request (interrupted or aborted): not fatal. Logged,
            // so a reply with a wrong `unique` (the same errno) is not silent.
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                tracing::debug!(
                    unique,
                    "FUSE reply refused with ENOENT (request already gone)"
                );
                Ok(())
            }
            other => other,
        }
    }

    fn serve_pure_rust_fuse_loop(mut dev: std::fs::File, vfs: &VirtualVaultFs) -> io::Result<()> {
        let mut buf = vec![0u8; DEFAULT_VFS_BLOCK_BYTES + 4096];
        loop {
            let n = match dev.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) if e.raw_os_error() == Some(libc::ENODEV) => return Ok(()),
                // An aborted request (ENOENT) or a signal: read the next one, as libfuse does.
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let Some(in_hdr) = parse_fuse_in_header(&buf[..n]) else {
                continue;
            };
            let frame_end = in_hdr.len as usize;
            let payload = &buf[FUSE_IN_HEADER_BYTES..frame_end];

            match in_hdr.opcode {
                // No reply: the kernel only informs us (inode dropped, request interrupted).
                FUSE_FORGET | FUSE_BATCH_FORGET | FUSE_INTERRUPT => {}
                FUSE_INIT => {
                    let out = FuseInitOut {
                        major: FUSE_KERNEL_VERSION,
                        minor: FUSE_KERNEL_MINOR_VERSION,
                        max_readahead: DEFAULT_VFS_BLOCK_BYTES as u32,
                        flags: 0,
                        max_background: 16,
                        congestion_threshold: 12,
                        max_write: DEFAULT_VFS_BLOCK_BYTES as u32,
                        time_gran: 1,
                        max_pages: 256,
                        map_alignment: 0,
                        unused: [0; 8],
                    };
                    write_fuse_reply(&mut dev, in_hdr.unique, 0, &out.to_ne_bytes())?;
                }
                FUSE_GETATTR => {
                    if let Some(node) = vfs.getattr(in_hdr.nodeid) {
                        let out = FuseAttrOut {
                            attr_valid: 60,
                            attr_valid_nsec: 0,
                            dummy: 0,
                            attr: lazy_to_fuse_attr(&node),
                        };
                        write_fuse_reply(&mut dev, in_hdr.unique, 0, &out.to_ne_bytes())?;
                    } else {
                        write_fuse_reply(&mut dev, in_hdr.unique, -libc::ENOENT, &[])?;
                    }
                }
                FUSE_LOOKUP => {
                    let nul = payload
                        .iter()
                        .position(|b| *b == 0)
                        .unwrap_or(payload.len());
                    let name = String::from_utf8_lossy(&payload[..nul]);
                    if let Some(node) = vfs.lookup(in_hdr.nodeid, &name) {
                        let out = FuseEntryOut {
                            nodeid: node.ino,
                            generation: 1,
                            entry_valid: 60,
                            attr_valid: 60,
                            entry_valid_nsec: 0,
                            attr_valid_nsec: 0,
                            attr: lazy_to_fuse_attr(&node),
                        };
                        write_fuse_reply(&mut dev, in_hdr.unique, 0, &out.to_ne_bytes())?;
                    } else {
                        write_fuse_reply(&mut dev, in_hdr.unique, -libc::ENOENT, &[])?;
                    }
                }
                FUSE_OPEN | FUSE_OPENDIR => {
                    let out = FuseOpenOut {
                        fh: in_hdr.nodeid,
                        open_flags: 0,
                        padding: 0,
                    };
                    write_fuse_reply(&mut dev, in_hdr.unique, 0, &out.to_ne_bytes())?;
                }
                FUSE_RELEASE | FUSE_RELEASEDIR => {
                    write_fuse_reply(&mut dev, in_hdr.unique, 0, &[])?;
                }
                FUSE_READ => {
                    let Some(read_in) = parse_fuse_read_in(payload) else {
                        write_fuse_reply(&mut dev, in_hdr.unique, -libc::EINVAL, &[])?;
                        continue;
                    };
                    match vfs.read_at(in_hdr.nodeid, read_in.offset, read_in.size as u64) {
                        Ok(bytes) => write_fuse_reply(&mut dev, in_hdr.unique, 0, &bytes)?,
                        Err(_) => write_fuse_reply(&mut dev, in_hdr.unique, -libc::EIO, &[])?,
                    }
                }
                FUSE_READDIR => {
                    let Some(read_in) = parse_fuse_read_in(payload) else {
                        write_fuse_reply(&mut dev, in_hdr.unique, -libc::EINVAL, &[])?;
                        continue;
                    };
                    let entries = vfs.readdir(in_hdr.nodeid);
                    let start_idx = read_in.offset as usize;
                    let mut out_bytes = Vec::new();
                    for (idx, item) in entries.iter().enumerate().skip(start_idx) {
                        let name_b = item.name.as_bytes();
                        let ent_len = (24 + name_b.len() + 7) & !7;
                        if out_bytes.len() + ent_len > read_in.size as usize {
                            break;
                        }
                        out_bytes.extend_from_slice(&item.ino.to_ne_bytes());
                        out_bytes.extend_from_slice(&((idx + 1) as u64).to_ne_bytes());
                        out_bytes.extend_from_slice(&(name_b.len() as u32).to_ne_bytes());
                        let typ: u32 = if item.is_dir { 4 } else { 8 };
                        out_bytes.extend_from_slice(&typ.to_ne_bytes());
                        out_bytes.extend_from_slice(name_b);
                        while out_bytes.len() % 8 != 0 {
                            out_bytes.push(0);
                        }
                    }
                    write_fuse_reply(&mut dev, in_hdr.unique, 0, &out_bytes)?;
                }
                FUSE_DESTROY => {
                    write_fuse_reply(&mut dev, in_hdr.unique, 0, &[])?;
                    return Ok(());
                }
                _ => {
                    write_fuse_reply(&mut dev, in_hdr.unique, -libc::ENOSYS, &[])?;
                }
            }
        }
    }
}

#[cfg(unix)]
pub use crate::webdav::VfsWebdavServerHandle;
#[cfg(unix)]
pub use unix_vfs::VirtualVaultFs;

/// B-20 catalog import and the in-daemon scavenger (L-94, arch056b S1), `v0.5.6` track C.
#[cfg(all(unix, feature = "daemon-runtime"))]
pub mod catalog {
    use super::{catalog_import_decision, CatalogImport, Ino, LazyFileSpec, VirtualVaultFs};
    use crate::fetch_sched;
    use crate::gateway::GatewayEngine;
    use crate::sync::{sanitize_sync_relative_path, FolderSnapshotManifest};
    use std::collections::{BTreeMap, VecDeque};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, Weak};
    use std::time::{Duration, Instant};

    /// The snapshot the daemon's own folder sync (`up --watch-folder`) keeps in its data dir.
    pub const DEVICE_SNAPSHOT_FILE: &str = "appliance_folder_snapshot.manifest.bin";
    /// The folder the device vault is listed under (`/<folder>/`).
    pub const DEVICE_FOLDER: &str = "watched";
    /// Catalog import period.
    pub const IMPORT_INTERVAL: Duration = Duration::from_secs(60);
    /// The scavenger's hourly byte cap.
    pub const SCAVENGER_BYTES_PER_HOUR: u64 = 4 * 1024 * 1024 * 1024;
    /// The scavenger fills the block cache up to this share (percent).
    pub const SCAVENGER_CACHE_SHARE_PCT: u64 = 75;

    /// What one import did.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct ImportReport {
        pub upserted: usize,
        pub removed: usize,
        pub unchanged: usize,
    }

    #[derive(Default)]
    struct SourceState {
        loaded_version: u64,
        /// Listed path to (file Merkle root, inode).
        files: BTreeMap<String, ([u8; 32], Ino)>,
    }

    /// Imports vault catalogs into a [`VirtualVaultFs`] and hydrates them (S1).
    pub struct CatalogImporter {
        vfs: VirtualVaultFs,
        engine: Arc<GatewayEngine>,
        data_dir: PathBuf,
        sources: Mutex<BTreeMap<String, SourceState>>,
        hydrate: Mutex<VecDeque<Ino>>,
        hydrated_bytes: AtomicU64,
    }

    impl CatalogImporter {
        pub fn new(vfs: VirtualVaultFs, engine: Arc<GatewayEngine>, data_dir: &Path) -> Arc<Self> {
            Arc::new(Self {
                vfs,
                engine,
                data_dir: data_dir.to_path_buf(),
                sources: Mutex::new(BTreeMap::new()),
                hydrate: Mutex::new(VecDeque::new()),
                hydrated_bytes: AtomicU64::new(0),
            })
        }

        /// Bytes the scavenger has hydrated so far.
        pub fn hydrated_bytes(&self) -> u64 {
            self.hydrated_bytes.load(Ordering::Relaxed)
        }

        /// Files waiting for the scavenger.
        pub fn hydrate_queue_len(&self) -> usize {
            self.hydrate.lock().unwrap_or_else(|e| e.into_inner()).len()
        }

        /// Applies `snapshot` under `/<folder>/` if [`catalog_import_decision`] allows: a changed
        /// file gets a new inode (T1), a file gone from the catalog leaves the listing (T4),
        /// an unchanged one keeps its inode and cached blocks.
        pub fn import_snapshot(
            &self,
            folder: &str,
            envelope_verifies: bool,
            key_matches: bool,
            snapshot: &FolderSnapshotManifest,
        ) -> Result<ImportReport, &'static str> {
            // A folder name that is not one path segment is not one of this data dir's vaults.
            let folder_ok =
                !(folder.is_empty() || folder.contains('/') || folder == "." || folder == "..");
            if !folder_ok {
                return catalog_import_decision(true, false, 0, 0).map(|_| ImportReport::default());
            }
            let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
            let st = sources.entry(folder.to_string()).or_default();
            let decision = catalog_import_decision(
                envelope_verifies,
                key_matches,
                snapshot.version,
                st.loaded_version,
            );
            match decision {
                Err(code) => {
                    tracing::warn!(code, folder, version = snapshot.version, "catalog refused");
                    return Err(code);
                }
                Ok(CatalogImport::Unchanged) => {
                    return Ok(ImportReport {
                        unchanged: st.files.len(),
                        ..ImportReport::default()
                    })
                }
                Ok(CatalogImport::Apply) => {}
            }
            let mut report = ImportReport::default();
            let mut next = BTreeMap::new();
            let mut fresh = Vec::new();
            for entry in snapshot.files.values() {
                let Some(rel) = sanitize_sync_relative_path(&entry.relative_path) else {
                    continue;
                };
                let path = format!("/{folder}/{rel}");
                if let Some(&(root, ino)) = st.files.get(&path) {
                    if root == entry.file_merkle_root && self.vfs.getattr(ino).is_some() {
                        next.insert(path, (root, ino));
                        report.unchanged += 1;
                        continue;
                    }
                }
                let eph = self.engine.index_catalog_manifest(entry.manifest.clone());
                let spec = LazyFileSpec {
                    manifest: eph,
                    macaroon: None,
                    mtime_unix_secs: Some(entry.modified_unix_ms / 1000),
                };
                match self.vfs.upsert_file(&path, spec) {
                    Ok(ino) => {
                        next.insert(path, (entry.file_merkle_root, ino));
                        fresh.push(ino);
                        report.upserted += 1;
                    }
                    Err(e) => tracing::warn!(path, error = %e, "catalog file not listed"),
                }
            }
            for path in st.files.keys() {
                if !next.contains_key(path) {
                    self.vfs.remove_path(path);
                    report.removed += 1;
                }
            }
            st.files = next;
            st.loaded_version = snapshot.version;
            drop(sources);
            self.hydrate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(fresh);
            Ok(report)
        }

        /// The device vault: the snapshot the daemon's own folder sync writes in its data dir,
        /// under the data dir's key (a local source: the daemon wrote it, so it verifies).
        pub fn import_device_snapshot(&self) -> Option<Result<ImportReport, &'static str>> {
            let raw = std::fs::read(self.data_dir.join(DEVICE_SNAPSHOT_FILE)).ok()?;
            let Ok(snap) = FolderSnapshotManifest::decode_bytes(&raw) else {
                // A file that does not decode does not verify.
                let refused = catalog_import_decision(false, false, 0, 0);
                if let Err(code) = refused {
                    tracing::warn!(code, "device catalog does not decode");
                }
                return Some(refused.map(|_| ImportReport::default()));
            };
            // The snapshot's signed manifest envelope proves whose key wrote it: it must be
            // signed by this data dir's owner and open under its key. An empty snapshot has
            // none and lists nothing.
            let (verifies, key_matches) = match &snap.signed_dht_envelope {
                Some(env) => (
                    env.verify_zero_knowledge(),
                    self.engine.owns_signed_manifest(env),
                ),
                None => (snap.files.is_empty(), snap.files.is_empty()),
            };
            Some(self.import_snapshot(DEVICE_FOLDER, verifies, key_matches, &snap))
        }

        /// One import of every source this data dir holds keys for.
        pub fn import_all(&self) {
            if let Some(Ok(r)) = self.import_device_snapshot() {
                if r.upserted + r.removed > 0 {
                    tracing::info!(
                        upserted = r.upserted,
                        removed = r.removed,
                        "catalog imported"
                    );
                }
            }
        }

        /// One scavenger pass over the queued files: each block not cached is read as the
        /// scavenger (S4) by `SLOTS` workers, so its fetches fill what the scheduler lets it
        /// hold (S2) and a foreground read is granted ahead of a queued one
        /// (`defer.scavenger_preempted`). Workers pause while a foreground read is queued and
        /// stay within the hourly cap and the cache share. Returns the bytes hydrated.
        pub fn hydrate_pass(&self, hour: &Mutex<HourBudget>) -> u64 {
            let bs = self.vfs.block_size() as u64;
            let cache_cap = self.vfs.cache_stats().capacity_bytes;
            let share_cap = cache_cap / 100 * SCAVENGER_CACHE_SHARE_PCT;
            let pass_bytes = AtomicU64::new(0);
            loop {
                let next = self
                    .hydrate
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .pop_front();
                let Some(ino) = next else {
                    return pass_bytes.into_inner();
                };
                let Some(node) = self.vfs.getattr(ino) else {
                    continue;
                };
                tracing::info!(ino, bytes = node.size_bytes, "scavenger: hydrating");
                let blocks = node.size_bytes.div_ceil(bs.max(1));
                let next_blk = AtomicU64::new(0);
                let stop = AtomicBool::new(false);
                std::thread::scope(|sc| {
                    for _ in 0..fetch_sched::SLOTS {
                        sc.spawn(|| loop {
                            let blk = next_blk.fetch_add(1, Ordering::Relaxed);
                            if blk >= blocks || stop.load(Ordering::Relaxed) {
                                return;
                            }
                            if self.vfs.getattr(ino).is_none() {
                                stop.store(true, Ordering::Relaxed);
                                return;
                            }
                            if self.vfs.block_cached(ino, blk) {
                                continue;
                            }
                            let len = node.size_bytes.saturating_sub(blk * bs).min(bs);
                            // Capped by cache size: the scavenger fills at most its share of
                            // the cache, so it never evicts what readers fetched.
                            let used = self.vfs.cache_stats().used_bytes;
                            if used.saturating_add(len) > share_cap {
                                stop.store(true, Ordering::Relaxed);
                                return;
                            }
                            pass_bytes.fetch_add(len, Ordering::Relaxed);
                            hour.lock().unwrap_or_else(|e| e.into_inner()).wait_for(len);
                            while fetch_sched::global().queued().0 > 0 {
                                std::thread::sleep(Duration::from_millis(2));
                            }
                            let flag = Arc::new(AtomicBool::new(false));
                            let res = fetch_sched::run_as_scavenger(flag, || {
                                self.vfs.read_at(ino, blk * bs, len)
                            });
                            match res {
                                Ok(_) => {
                                    self.hydrated_bytes.fetch_add(len, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    tracing::debug!(ino, blk, error = %e, "scavenger skipped a file");
                                    stop.store(true, Ordering::Relaxed);
                                    return;
                                }
                            }
                        });
                    }
                });
            }
        }

        /// Starts the import timer and the scavenger threads; sets the VFS re-import hook (T2).
        pub fn start(self: &Arc<Self>, interval: Duration) -> std::io::Result<()> {
            self.import_all();
            let weak: Weak<Self> = Arc::downgrade(self);
            self.vfs.set_reimport_hook(Some(Arc::new(move || {
                if let Some(me) = weak.upgrade() {
                    me.import_all();
                }
            })));
            let me = Arc::clone(self);
            std::thread::Builder::new()
                .name("pv-catalog".into())
                .spawn(move || {
                    let mut last = fetch_sched::counters();
                    loop {
                        std::thread::sleep(interval);
                        me.import_all();
                        // S7: the counters in the log too (live status reads `counters()`).
                        let c = fetch_sched::counters();
                        if c != last {
                            tracing::info!(
                                preempted = c.scavenger_preempted,
                                cache_misses = c.cache_misses,
                                fetches = c.network_fetches,
                                hydrated = me.hydrated_bytes(),
                                "fetch_sched counters"
                            );
                            last = c;
                        }
                    }
                })?;
            let me = Arc::clone(self);
            std::thread::Builder::new()
                .name("pv-scavenger".into())
                .spawn(move || {
                    let hour = Mutex::new(HourBudget::new(SCAVENGER_BYTES_PER_HOUR));
                    loop {
                        if me.hydrate_pass(&hour) == 0 {
                            std::thread::sleep(Duration::from_millis(200));
                        }
                    }
                })?;
            Ok(())
        }
    }

    /// The scavenger's hourly byte cap.
    pub struct HourBudget {
        cap: u64,
        window: Instant,
        used: u64,
    }

    impl HourBudget {
        pub fn new(cap: u64) -> Self {
            Self {
                cap,
                window: Instant::now(),
                used: 0,
            }
        }

        /// Blocks until `len` more bytes fit in the current hour, then counts them.
        pub fn wait_for(&mut self, len: u64) {
            loop {
                if self.window.elapsed() >= Duration::from_secs(3600) {
                    self.window = Instant::now();
                    self.used = 0;
                }
                if self.used.saturating_add(len) <= self.cap {
                    self.used += len;
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

#[cfg(all(test, unix))]
mod upsert_api_tests {
    use super::*;

    fn spec(size: u64, root: u8) -> LazyFileSpec {
        LazyFileSpec {
            manifest: EphemeralShardManifest {
                file_merkle_root: [root; 32],
                shard_hashes: Vec::new(),
                total_size: size,
                stripe_size_bytes: 1 << 20,
            },
            macaroon: None,
            mtime_unix_secs: Some(7),
        }
    }

    fn vfs(dir: &Path) -> VirtualVaultFs {
        VirtualVaultFs::new(dir.join("no.sock"), dir.join("cache"), 1 << 20).unwrap()
    }

    /// T0 item 4 (T1, T4): a changed file gets a new inode; a removed file leaves the listing;
    /// folders are kept and never replaced by a file.
    #[test]
    fn upsert_replaces_with_a_new_inode_and_remove_drops_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let fs = vfs(dir.path());
        let a = fs.upsert_file("/docs/a.txt", spec(3, 1)).unwrap();
        assert_eq!(fs.lookup_path("/docs/a.txt").unwrap().mtime_unix_secs, 7);
        let b = fs.upsert_file("docs/a.txt", spec(5, 2)).unwrap();
        assert_ne!(a, b, "a changed file gets a new inode");
        assert!(fs.getattr(a).is_none(), "the old inode is gone");
        assert_eq!(fs.lookup_path("/docs/a.txt").unwrap().size_bytes, 5);
        let names: Vec<_> = fs
            .list_children("/docs")
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .collect();
        assert_eq!(names, vec!["a.txt".to_string()]);
        assert!(fs.list_children("/docs/a.txt").is_none());
        assert!(fs.upsert_file("/docs", spec(1, 3)).is_err());
        assert_eq!(fs.remove_path("/docs"), PathRemoval::Folder);
        assert_eq!(fs.remove_path("/docs/a.txt"), PathRemoval::Removed);
        assert_eq!(fs.remove_path("/docs/a.txt"), PathRemoval::Absent);
        assert!(fs.lookup_path("/docs/a.txt").is_none());
        assert_eq!(fs.list_children("/docs").unwrap().len(), 0);
        assert_eq!(fs.list_children("/").unwrap().len(), 1);
    }
}
