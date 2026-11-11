//! Lazy-Streaming Virtual File System (`parvault::vfs`) backed by `/var/run/parvault.sock`.
//!
//! Built strictly as a zero-copy Unix Domain Socket client of [`crate::gateway::ipc::GatewayIpcClient`]:
//! 1. **Instant Metadata Stubs**: Mounts `10 GiB+` virtual vaults instantaneously in RAM (`O(1)`
//!    inode registration, zero eager shard downloads).
//! 2. **Targeted On-Demand Range Retrieval (`< 50 ms` TTFB)**: Translates POSIX `(inode, offset, len)`
//!    reads into `1 MiB` block-aligned `IpcCommand::FetchRange` calls (`SCM_RIGHTS` `memfd`).
//! 3. **Bounded LRU Disk Cache (`LruBlockCache`)**: Caches fetched `1 MiB` blocks on local disk and
//!    deterministically evicts least-recently-used `.blk` files whenever `used_bytes` would exceed
//!    `capacity_bytes`.
//! 4. **Triple Frontend Support**:
//!    - Pure-Rust Linux `/dev/fuse` protocol loop (ABI `7.31`, zero C `libfuse` linkage for static `musl`).
//!    - Unprivileged HTTP `Range` (`206 Partial Content`) + WebDAV (`PROPFIND`) server for locked-down
//!      `prplOS` / `RDK-B` LXC containers lacking `/dev/fuse`.
//!    - Userspace folder push/pull reconciler over `/var/run/parvault.sock`.

use crate::capabilities::CapabilityMacaroon;
use crate::gateway::ipc::EphemeralShardManifest;
#[cfg(unix)]
use crate::gateway::ipc::{create_memfd, GatewayIpcClient, RetentionPolicy};
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

/// Lightweight metadata stub representing a virtual directory or lazy-loaded vault file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsStubNode {
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

#[cfg(unix)]
mod unix_vfs {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;

    /// Lazy-streaming Virtual File System client communicating with `parvault-gateway` over
    /// `/var/run/parvault.sock`.
    #[derive(Clone)]
    pub struct VirtualVaultFs {
        ipc: GatewayIpcClient,
        block_size: usize,
        nodes: Arc<Mutex<BTreeMap<u64, VfsStubNode>>>,
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
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut nodes = BTreeMap::new();
            nodes.insert(
                VFS_ROOT_INO,
                VfsStubNode {
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
                ipc: GatewayIpcClient::new(socket_path),
                block_size: block_size.max(4096),
                nodes: Arc::new(Mutex::new(nodes)),
                children: Arc::new(Mutex::new(children)),
                next_ino: Arc::new(Mutex::new(2)),
                cache: Arc::new(Mutex::new(cache)),
            })
        }

        /// Registers a virtual file path (e.g. `"/movies/archive_10gb.bin"` or `"backup.tar"`)
        /// instantaneously as an in-memory metadata stub without fetching any shard bytes.
        pub fn register_stub_file(
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
                    let stub = VfsStubNode {
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
                    self.nodes.lock().unwrap().insert(dir_ino, stub);
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
            let file_stub = VfsStubNode {
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
            self.nodes.lock().unwrap().insert(ino, file_stub);
            self.children
                .lock()
                .unwrap()
                .entry(cur_parent)
                .or_default()
                .insert(file_name, ino);
            Ok(ino)
        }

        fn alloc_ino(&self) -> u64 {
            let mut g = self.next_ino.lock().unwrap();
            let id = *g;
            *g += 1;
            id
        }

        pub fn getattr(&self, ino: u64) -> Option<VfsStubNode> {
            self.nodes.lock().unwrap().get(&ino).cloned()
        }

        pub fn lookup(&self, parent_ino: u64, name: &str) -> Option<VfsStubNode> {
            let child_ino = self
                .children
                .lock()
                .unwrap()
                .get(&parent_ino)
                .and_then(|m| m.get(name))
                .copied()?;
            self.getattr(child_ino)
        }

        pub fn lookup_path(&self, virtual_path: &str) -> Option<VfsStubNode> {
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

        pub fn readdir(&self, dir_ino: u64) -> Vec<VfsStubNode> {
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
            let stub = self.getattr(ino).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("inode {ino} not found"))
            })?;
            if stub.is_dir {
                return Err(io::Error::new(
                    io::ErrorKind::IsADirectory,
                    "cannot read bytes from directory inode",
                ));
            }
            let Some(manifest) = stub.manifest else {
                return Ok((Vec::new(), t0.elapsed()));
            };
            let Some((end_offset, first_blk, last_blk)) =
                compute_vfs_block_window(stub.size_bytes, offset, length, self.block_size)
            else {
                return Ok((Vec::new(), t0.elapsed()));
            };

            let total_out_len = (end_offset - offset) as usize;
            let mut out = Vec::with_capacity(total_out_len);
            let mut ttfb: Option<Duration> = None;
            let bsz = self.block_size as u64;

            for blk_idx in first_blk..=last_blk {
                let blk_start = blk_idx.saturating_mul(bsz);
                let blk_len = stub.size_bytes.saturating_sub(blk_start).min(bsz);

                let cached = self.cache.lock().unwrap().get(ino, blk_idx)?;
                let blk_bytes = match cached {
                    Some(hit_bytes) => hit_bytes,
                    None => {
                        let fetched = self.ipc.fetch_range_bytes(
                            &manifest,
                            blk_start,
                            blk_len,
                            stub.macaroon.clone(),
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

        /// Synchronizes all regular files in `local_dir` into `parvault-gateway` via zero-copy
        /// `memfd` `SCM_RIGHTS` (`StorePayload`) and mounts them as lazy VFS stubs.
        pub fn ingest_local_directory(&self, local_dir: &Path) -> io::Result<usize> {
            let mut count = 0usize;
            self.ingest_dir_recursive(local_dir, local_dir, &mut count)?;
            Ok(count)
        }

        fn ingest_dir_recursive(
            &self,
            base: &Path,
            cur: &Path,
            count: &mut usize,
        ) -> io::Result<()> {
            for entry in fs::read_dir(cur)? {
                let entry = entry?;
                let path = entry.path();
                let meta = entry.metadata()?;
                if meta.is_dir() {
                    self.ingest_dir_recursive(base, &path, count)?;
                } else if meta.is_file() {
                    let rel = path
                        .strip_prefix(base)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    let mfd = create_memfd("parvault-sync-in")?;
                    let mut mfd_file = std::fs::File::from(mfd);
                    let mut src = std::fs::File::open(&path)?;
                    let copied = io::copy(&mut src, &mut mfd_file)?;
                    mfd_file.seek(SeekFrom::Start(0))?;
                    let manifest = self.ipc.store_memfd(
                        mfd_file.as_raw_fd(),
                        copied,
                        RetentionPolicy::Persistent,
                    )?;
                    self.register_stub_file(&rel, manifest, None)?;
                    *count += 1;
                }
            }
            Ok(())
        }

        /// Serves an unprivileged HTTP `Range` (`206 Partial Content`) + WebDAV (`OPTIONS` /
        /// `PROPFIND`) endpoint for locked-down `prplOS` / `RDK-B` LXC containers without `/dev/fuse`.
        pub fn serve_webdav_blocking(&self, bind_addr: &str) -> io::Result<()> {
            let listener = TcpListener::bind(bind_addr)?;
            for conn in listener.incoming() {
                let Ok(mut stream) = conn else {
                    continue;
                };
                let vfs = self.clone();
                std::thread::spawn(move || {
                    let _ = handle_webdav_http_conn(&mut stream, &vfs);
                });
            }
            Ok(())
        }

        /// Serves the pure-Rust Linux `/dev/fuse` kernel wire protocol (`ABI 7.31`, zero C
        /// `libfuse` dependency) on an already-mounted `/dev/fuse` file descriptor.
        pub fn serve_fuse_fd_blocking(&self, fuse_dev: std::fs::File) -> io::Result<()> {
            serve_pure_rust_fuse_loop(fuse_dev, self)
        }
    }

    fn handle_webdav_http_conn(
        stream: &mut std::net::TcpStream,
        vfs: &VirtualVaultFs,
    ) -> io::Result<()> {
        let mut req_buf = [0u8; 8192];
        let n = stream.read(&mut req_buf)?;
        if n == 0 {
            return Ok(());
        }
        let req_str = String::from_utf8_lossy(&req_buf[..n]);
        let mut lines = req_str.lines();
        let Some(request_line) = lines.next() else {
            return Ok(());
        };
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let raw_path = parts.next().unwrap_or("/");

        let mut range_header: Option<(u64, Option<u64>)> = None;
        for hdr in lines {
            if hdr.is_empty() {
                break;
            }
            if let Some((k, v)) = hdr.split_once(':') {
                if k.eq_ignore_ascii_case("range") {
                    if let Some(spec) = v.trim().strip_prefix("bytes=") {
                        if let Some((s, e)) = spec.split_once('-') {
                            if let Ok(start) = s.trim().parse::<u64>() {
                                let end_opt = e.trim().parse::<u64>().ok();
                                range_header = Some((start, end_opt));
                            }
                        }
                    }
                }
            }
        }

        match method {
            "OPTIONS" => {
                stream.write_all(
                    b"HTTP/1.1 200 OK\r\nDAV: 1\r\nAllow: OPTIONS, GET, HEAD, PROPFIND\r\nAccept-Ranges: bytes\r\nContent-Length: 0\r\n\r\n",
                )?;
            }
            "PROPFIND" => {
                let Some(node) = vfs.lookup_path(raw_path) else {
                    stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")?;
                    return Ok(());
                };
                let mut xml = String::from(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">",
                );
                let entries = if node.is_dir {
                    let mut v = vec![node.clone()];
                    v.extend(vfs.readdir(node.ino));
                    v
                } else {
                    vec![node]
                };
                for item in entries {
                    let href = if item.ino == VFS_ROOT_INO {
                        "/".to_string()
                    } else {
                        format!("/{}", item.name)
                    };
                    let res_type = if item.is_dir { "<D:collection/>" } else { "" };
                    xml.push_str(&format!(
                        "<D:response><D:href>{href}</D:href><D:propstat><D:prop><D:resourcetype>{res_type}</D:resourcetype><D:getcontentlength>{}</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
                        item.size_bytes
                    ));
                }
                xml.push_str("</D:multistatus>");
                let hdr = format!(
                    "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
                    xml.len()
                );
                stream.write_all(hdr.as_bytes())?;
                stream.write_all(xml.as_bytes())?;
            }
            "HEAD" | "GET" => {
                let Some(node) = vfs.lookup_path(raw_path) else {
                    stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")?;
                    return Ok(());
                };
                if node.is_dir {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
                    return Ok(());
                }
                if let Some((start, end_opt)) = range_header {
                    if start >= node.size_bytes {
                        stream.write_all(
                            b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n",
                        )?;
                        return Ok(());
                    }
                    let end_incl = end_opt
                        .unwrap_or_else(|| node.size_bytes.saturating_sub(1))
                        .min(node.size_bytes.saturating_sub(1));
                    let len = end_incl.saturating_sub(start) + 1;
                    let body = if method == "GET" {
                        vfs.read_at(node.ino, start, len)?
                    } else {
                        Vec::new()
                    };
                    let hdr = format!(
                        "HTTP/1.1 206 Partial Content\r\nAccept-Ranges: bytes\r\nContent-Range: bytes {start}-{end_incl}/{}\r\nContent-Length: {}\r\n\r\n",
                        node.size_bytes,
                        if method == "GET" { body.len() as u64 } else { len }
                    );
                    stream.write_all(hdr.as_bytes())?;
                    if method == "GET" {
                        stream.write_all(&body)?;
                    }
                } else {
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Length: {}\r\n\r\n",
                        node.size_bytes
                    );
                    stream.write_all(hdr.as_bytes())?;
                    if method == "GET" {
                        let mut off = 0u64;
                        while off < node.size_bytes {
                            let chunk =
                                vfs.read_at(node.ino, off, DEFAULT_VFS_BLOCK_BYTES as u64)?;
                            if chunk.is_empty() {
                                break;
                            }
                            stream.write_all(&chunk)?;
                            off += chunk.len() as u64;
                        }
                    }
                }
            }
            _ => {
                stream
                    .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")?;
            }
        }
        stream.flush()
    }

    // Minimal Pure-Rust Linux FUSE Kernel Protocol (`ABI 7.31`, zero C `libfuse`).
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

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FuseInHeader {
        len: u32,
        opcode: u32,
        unique: u64,
        nodeid: u64,
        uid: u32,
        gid: u32,
        pid: u32,
        padding: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FuseOutHeader {
        len: u32,
        error: i32,
        unique: u64,
    }

    #[repr(C)]
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

    #[repr(C)]
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

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FuseAttrOut {
        attr_valid: u64,
        attr_valid_nsec: u32,
        dummy: u32,
        attr: FuseAttr,
    }

    #[repr(C)]
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

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FuseOpenOut {
        fh: u64,
        open_flags: u32,
        padding: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FuseReadIn {
        fh: u64,
        offset: u64,
        size: u32,
        read_flags: u32,
        lock_owner: u64,
        flags: u32,
        padding: u32,
    }

    fn stub_to_fuse_attr(node: &VfsStubNode) -> FuseAttr {
        FuseAttr {
            ino: node.ino,
            size: node.size_bytes,
            blocks: node.size_bytes.div_ceil(512),
            atime: node.mtime_unix_secs,
            mtime: node.mtime_unix_secs,
            ctime: node.mtime_unix_secs,
            mode: node.mode,
            nlink: if node.is_dir { 2 } else { 1 },
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            blksize: DEFAULT_VFS_BLOCK_BYTES as u32,
            ..FuseAttr::default()
        }
    }

    fn as_bytes<T: Copy>(val: &T) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((val as *const T).cast::<u8>(), std::mem::size_of::<T>())
        }
    }

    fn write_fuse_reply(
        dev: &mut std::fs::File,
        unique: u64,
        error: i32,
        body: &[u8],
    ) -> io::Result<()> {
        let hdr = FuseOutHeader {
            len: (std::mem::size_of::<FuseOutHeader>() + body.len()) as u32,
            error,
            unique,
        };
        let mut pkt = Vec::with_capacity(hdr.len as usize);
        pkt.extend_from_slice(as_bytes(&hdr));
        pkt.extend_from_slice(body);
        dev.write_all(&pkt)
    }

    fn serve_pure_rust_fuse_loop(mut dev: std::fs::File, vfs: &VirtualVaultFs) -> io::Result<()> {
        let mut buf = vec![0u8; DEFAULT_VFS_BLOCK_BYTES + 4096];
        let hdr_sz = std::mem::size_of::<FuseInHeader>();
        loop {
            let n = match dev.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) if e.raw_os_error() == Some(libc::ENODEV) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if n < hdr_sz {
                continue;
            }
            let in_hdr: FuseInHeader =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<FuseInHeader>()) };
            let payload = &buf[hdr_sz..n];

            match in_hdr.opcode {
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
                    write_fuse_reply(&mut dev, in_hdr.unique, 0, as_bytes(&out))?;
                }
                FUSE_GETATTR => {
                    if let Some(node) = vfs.getattr(in_hdr.nodeid) {
                        let out = FuseAttrOut {
                            attr_valid: 60,
                            attr_valid_nsec: 0,
                            dummy: 0,
                            attr: stub_to_fuse_attr(&node),
                        };
                        write_fuse_reply(&mut dev, in_hdr.unique, 0, as_bytes(&out))?;
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
                            attr: stub_to_fuse_attr(&node),
                        };
                        write_fuse_reply(&mut dev, in_hdr.unique, 0, as_bytes(&out))?;
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
                    write_fuse_reply(&mut dev, in_hdr.unique, 0, as_bytes(&out))?;
                }
                FUSE_RELEASE | FUSE_RELEASEDIR => {
                    write_fuse_reply(&mut dev, in_hdr.unique, 0, &[])?;
                }
                FUSE_READ => {
                    if payload.len() < std::mem::size_of::<FuseReadIn>() {
                        write_fuse_reply(&mut dev, in_hdr.unique, -libc::EINVAL, &[])?;
                        continue;
                    }
                    let read_in: FuseReadIn =
                        unsafe { std::ptr::read_unaligned(payload.as_ptr().cast::<FuseReadIn>()) };
                    match vfs.read_at(in_hdr.nodeid, read_in.offset, read_in.size as u64) {
                        Ok(bytes) => write_fuse_reply(&mut dev, in_hdr.unique, 0, &bytes)?,
                        Err(_) => write_fuse_reply(&mut dev, in_hdr.unique, -libc::EIO, &[])?,
                    }
                }
                FUSE_READDIR => {
                    if payload.len() < std::mem::size_of::<FuseReadIn>() {
                        write_fuse_reply(&mut dev, in_hdr.unique, -libc::EINVAL, &[])?;
                        continue;
                    }
                    let read_in: FuseReadIn =
                        unsafe { std::ptr::read_unaligned(payload.as_ptr().cast::<FuseReadIn>()) };
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
pub use unix_vfs::VirtualVaultFs;
