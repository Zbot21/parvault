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

        /// B-20 (`v0.5.6` track C): starts importing the vault catalogs `data_dir` holds keys
        /// for (`derive_vault_root_dht_key`), at start and on a timer, through
        /// [`Self::upsert_file`] and [`Self::remove_path`]; the scavenger then hydrates them
        /// (L-94, S1). Called by the daemon once the built-in VFS exists. T0 stub: imports
        /// nothing, so the mount lists only `--vfs-seed-dir` files, as before `v0.5.6`.
        #[cfg(feature = "daemon-runtime")]
        pub fn start_catalog_import(
            &self,
            data_dir: &Path,
            block_store: &crate::storage::BlockStore,
        ) -> io::Result<()> {
            let _ = (data_dir, block_store);
            Ok(())
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
            if self.remove_path(virtual_path) == PathRemoval::Folder {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "upsert_file: the path is a folder",
                ));
            }
            let ino = self.register_lazy_file(virtual_path, spec.manifest, spec.macaroon)?;
            if let Some(mtime) = spec.mtime_unix_secs {
                if let Some(n) = self.nodes.lock().unwrap().get_mut(&ino) {
                    n.mtime_unix_secs = mtime;
                }
            }
            Ok(ino)
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
            PathRemoval::Removed
        }

        /// The entries of the folder at `virtual_path`, or `None` when it is not a folder.
        pub fn list_children(&self, virtual_path: &str) -> Option<Vec<VfsLazyNode>> {
            let mut cur = VFS_ROOT_INO;
            for p in vfs_path_parts(virtual_path) {
                cur = self.lookup(cur, p)?.ino;
            }
            let node = self.getattr(cur)?;
            node.is_dir.then(|| self.readdir(cur))
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
            let child_ino = self
                .children
                .lock()
                .unwrap()
                .get(&parent_ino)
                .and_then(|m| m.get(name))
                .copied()?;
            self.getattr(child_ino)
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
            let mut cur = VFS_ROOT_INO;
            for p in parts {
                let node = self.lookup(cur, p)?;
                cur = node.ino;
            }
            self.getattr(cur)
        }

        pub fn readdir(&self, dir_ino: u64) -> Vec<VfsLazyNode> {
            let child_inos: Vec<u64> = self
                .children
                .lock()
                .unwrap()
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
                let cached = self.cache.lock().unwrap().get(ino, blk_idx)?;
                let blk_bytes = match cached {
                    Some(hit_bytes) => hit_bytes,
                    None => {
                        let effective_mac = node
                            .macaroon
                            .clone()
                            .or_else(|| self.default_macaroon.clone());
                        let fetched = self.bus.fetch_range_bytes_sync(
                            &manifest,
                            blk_start,
                            blk_len,
                            effective_mac,
                        )?;
                        self.cache.lock().unwrap().insert(ino, blk_idx, &fetched)?;
                        fetched
                    }
                };

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
