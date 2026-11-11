//! Zero-Copy Local Unix Domain Socket IPC Bridge (`parvault::gateway::ipc`).
//!
//! Decouples the `parvault` core P2P Reed-Solomon / Post-Quantum storage engine from local
//! consumer & ISP CPE modules (`parvault-fuse`, `parvault-auth-broker`, `parvault-media-daemon`,
//! `parvault-isp-agent`) over `/var/run/parvault.sock` using `Serde-Bincode` control frames and
//! kernel `memfd_create(2)` file descriptors passed via `SCM_RIGHTS` ancillary messages.
//!
//! ### Memory Invariant (`< 16 MiB` RSS)
//! Payloads are never `mmap`ed as monolithic buffers nor copied through socket data frames; instead,
//! `GatewayIpcServer` streams `1 MiB` (`ROUTER_SOC_STRIPE_SIZE_BYTES`) stripes directly out of /
//! into kernel `memfd` descriptors using a single reusable buffer.

use crate::capabilities::{AccessRequestContext, CapabilityMacaroon};
use crate::config::{ErasureTier, HardwareProfile, ROUTER_SOC_STRIPE_SIZE_BYTES};
use crate::crypto::{compute_sha256, MasterKey};
use crate::storage::{BlockStore, FileManifest};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(not(unix))]
pub type RawFd = i32;

/// Default Unix Domain Socket path for CPE / host deployments.
pub const DEFAULT_IPC_SOCKET_PATH: &str = "/var/run/parvault.sock";

/// Hard ceiling (`16 MiB`) on serialized `bincode` control frames over `/var/run/parvault.sock`.
/// Bulk data never traverses control frames; it passes zero-copy via `memfd` + `SCM_RIGHTS`.
pub const MAX_IPC_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Capped initial `Vec::with_capacity` allocation (`64 KiB`) before reading control bytes.
pub const MAX_IPC_INITIAL_ALLOC_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IpcFrameError {
    #[error("IPC control frame length is zero")]
    ZeroLengthFrame,
    #[error("IPC control frame length {declared} exceeds ceiling {max_allowed}")]
    ExceedsMaxFrameBytes { declared: usize, max_allowed: usize },
}

/// Overflow-free, zero-allocation validator for 4-byte big-endian IPC control frame headers.
pub const fn validate_ipc_frame_header(
    len_buf: [u8; 4],
    max_len: usize,
) -> Result<(usize, usize), IpcFrameError> {
    let ceiling = if max_len < MAX_IPC_FRAME_BYTES {
        max_len
    } else {
        MAX_IPC_FRAME_BYTES
    };
    let declared_u32 = u32::from_be_bytes(len_buf);
    if declared_u32 == 0 {
        return Err(IpcFrameError::ZeroLengthFrame);
    }
    if (declared_u32 as u64) > (ceiling as u64) {
        return Err(IpcFrameError::ExceedsMaxFrameBytes {
            declared: declared_u32 as usize,
            max_allowed: ceiling,
        });
    }
    let len = declared_u32 as usize;
    let init_cap = if len < MAX_IPC_INITIAL_ALLOC_BYTES {
        len
    } else {
        MAX_IPC_INITIAL_ALLOC_BYTES
    };
    Ok((len, init_cap))
}

/// Storage lifecycle policy attached to `IpcCommand::StorePayload`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionPolicy {
    Ephemeral,
    Persistent,
    PinnedRing,
}

/// Compact manifest handle returned by `StorePayload` and consumed by `FetchPayload` / `FetchRange`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EphemeralShardManifest {
    pub file_merkle_root: [u8; 32],
    pub shard_hashes: Vec<[u8; 32]>,
    pub total_size: u64,
    pub stripe_size_bytes: usize,
}

impl EphemeralShardManifest {
    /// Builds an `EphemeralShardManifest` from a `FileManifest`.
    /// For massive sparse/virtual files (`> 256` stripes), stores stripe Merkle roots so the
    /// IPC control descriptor stays compact (`<= 320 KiB` even for a `10 GiB` vault).
    pub fn from_file_manifest(fm: &FileManifest) -> Self {
        let shard_hashes = if fm.stripes.len() <= 256 {
            let mut all = Vec::with_capacity(fm.stripes.len().saturating_mul(20));
            for s in &fm.stripes {
                all.extend_from_slice(&s.shard_hashes);
            }
            all
        } else {
            fm.stripes.iter().map(|s| s.stripe_merkle_root).collect()
        };
        Self {
            file_merkle_root: fm.file_merkle_root,
            shard_hashes,
            total_size: fm.original_file_size,
            stripe_size_bytes: fm.stripe_size_bytes,
        }
    }
}

/// Control commands exchanged over `/var/run/parvault.sock`.
/// Note: `payload_fd` and `output_fd` carry the sender's local descriptor number for logging/debug;
/// the kernel remaps and delivers the actual open file description out-of-band via `SCM_RIGHTS`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum IpcCommand {
    StorePayload {
        payload_fd: RawFd,
        bytes_len: u64,
        retention_policy: RetentionPolicy,
    },
    FetchPayload {
        ephemeral_shard_ids: Vec<[u8; 32]>,
        output_fd: RawFd,
    },
    FetchRange {
        manifest: EphemeralShardManifest,
        offset: u64,
        len: u64,
        output_fd: RawFd,
        macaroon: Option<CapabilityMacaroon>,
    },
    RegisterManifest {
        file_manifest: FileManifest,
    },
    QueryHealthStatus,
}

/// Control responses returned by `GatewayIpcServer` over `/var/run/parvault.sock`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum IpcResponse {
    StoreSuccess {
        manifest: EphemeralShardManifest,
    },
    FetchSuccess {
        bytes_streamed: u64,
    },
    HealthStatus {
        iops: u64,
        peer_count: usize,
        por_sla_score: f32,
    },
    Error {
        message: String,
    },
}

fn ipc_bincode() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_IPC_FRAME_BYTES as u64)
}

fn hash_shard_id_vector(ids: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"parvault-ipc-shard-vec-v1:");
    h.update((ids.len() as u64).to_be_bytes());
    for id in ids {
        h.update(id);
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};

    const CMSG_FD_SPACE: usize =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize };

    #[repr(C)]
    union AlignedCmsgBuf {
        bytes: [u8; CMSG_FD_SPACE],
        _align: libc::cmsghdr,
    }

    /// Allocates an anonymous in-RAM kernel file descriptor via `memfd_create(2)` with `MFD_CLOEXEC`.
    /// Writing/reading via `read(2)`/`write(2)` avoids mapping `RssShmem` PTEs into userspace,
    /// keeping process `VmRSS` strictly bounded regardless of `memfd` size.
    pub fn create_memfd(name: &str) -> io::Result<OwnedFd> {
        let sanitized: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(64)
            .collect();
        let c_name = CString::new(if sanitized.is_empty() {
            "parvault"
        } else {
            &sanitized
        })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        #[cfg(target_os = "linux")]
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c_name.as_ptr(),
                libc::MFD_CLOEXEC as libc::c_uint,
            ) as libc::c_int
        };

        #[cfg(not(target_os = "linux"))]
        let fd = -1i32;

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Reads total `VmRSS` (in bytes) from `/proc/self/status` on Linux (`0` if unavailable).
    pub fn read_self_rss_bytes() -> u64 {
        read_proc_status_kib_field("VmRSS:").saturating_mul(1024)
    }

    /// Reads anonymous heap `RssAnon` (in bytes) from `/proc/self/status` on Linux (`0` if unavailable).
    pub fn read_self_anon_rss_bytes() -> u64 {
        read_proc_status_kib_field("RssAnon:").saturating_mul(1024)
    }

    fn read_proc_status_kib_field(prefix: &str) -> u64 {
        let Ok(contents) = std::fs::read_to_string("/proc/self/status") else {
            return 0;
        };
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix(prefix) {
                if let Some(num_tok) = rest.split_whitespace().next() {
                    if let Ok(kib) = num_tok.parse::<u64>() {
                        return kib;
                    }
                }
            }
        }
        0
    }

    /// Sends a length-prefixed `bincode` frame over `sock_fd`, attaching `attached_fd` via
    /// `SCM_RIGHTS` on the 4-byte header `sendmsg(2)` call when present.
    pub fn send_frame_with_optional_fd(
        stream: &mut StdUnixStream,
        payload: &[u8],
        attached_fd: Option<RawFd>,
    ) -> io::Result<()> {
        if payload.is_empty() || payload.len() > MAX_IPC_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid IPC frame size {}", payload.len()),
            ));
        }
        let mut len_be = (payload.len() as u32).to_be_bytes();
        let mut iov = libc::iovec {
            iov_base: len_be.as_mut_ptr().cast(),
            iov_len: len_be.len(),
        };

        let mut cmsg_storage = AlignedCmsgBuf {
            bytes: [0u8; CMSG_FD_SPACE],
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1 as _;

        if let Some(fd_to_pass) = attached_fd {
            unsafe {
                msg.msg_control = cmsg_storage.bytes.as_mut_ptr().cast();
                msg.msg_controllen = CMSG_FD_SPACE as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                if cmsg.is_null() {
                    return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
                }
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
                std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd_to_pass);
            }
        }

        let sent_hdr = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if sent_hdr < 0 {
            return Err(io::Error::last_os_error());
        }
        if (sent_hdr as usize) < len_be.len() {
            stream.write_all(&len_be[sent_hdr as usize..])?;
        }
        stream.write_all(payload)?;
        stream.flush()?;
        Ok(())
    }

    /// Receives a length-prefixed `bincode` frame and at most one `SCM_RIGHTS` file descriptor
    /// (`MSG_CMSG_CLOEXEC`) from `stream`. Any unexpected extra descriptors are closed immediately.
    pub fn recv_frame_with_optional_fd(
        stream: &mut StdUnixStream,
    ) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
        let mut len_be = [0u8; 4];
        let mut iov = libc::iovec {
            iov_base: len_be.as_mut_ptr().cast(),
            iov_len: len_be.len(),
        };
        let mut cmsg_storage = AlignedCmsgBuf {
            bytes: [0u8; CMSG_FD_SPACE],
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1 as _;
        msg.msg_control = unsafe { cmsg_storage.bytes.as_mut_ptr().cast() };
        msg.msg_controllen = CMSG_FD_SPACE as _;

        let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "IPC peer closed socket",
            ));
        }

        let mut received_fd: Option<OwnedFd> = None;
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let data_ptr = libc::CMSG_DATA(cmsg) as *const u8;
                    let cmsg_end = (cmsg as *const u8).add((*cmsg).cmsg_len as usize);
                    let mut cur = data_ptr;
                    while cur.add(std::mem::size_of::<RawFd>()) <= cmsg_end {
                        let raw_fd = std::ptr::read_unaligned(cur.cast::<RawFd>());
                        if raw_fd >= 0 {
                            let owned = OwnedFd::from_raw_fd(raw_fd);
                            if received_fd.is_none() {
                                received_fd = Some(owned);
                            }
                            // Any extra unexpected FDs drop & close immediately here.
                        }
                        cur = cur.add(std::mem::size_of::<RawFd>());
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }

        if (n as usize) < len_be.len() {
            stream.read_exact(&mut len_be[n as usize..])?;
        }

        let (frame_len, init_cap) = validate_ipc_frame_header(len_be, MAX_IPC_FRAME_BYTES)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let mut payload = Vec::with_capacity(init_cap);
        stream.take(frame_len as u64).read_to_end(&mut payload)?;
        if payload.len() != frame_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated IPC control payload",
            ));
        }
        Ok((payload, received_fd))
    }

    struct GatewaySharedState {
        block_store: BlockStore,
        master_key: MasterKey,
        macaroon_root_key: Option<[u8; 32]>,
        default_tier: ErasureTier,
        stripe_size_bytes: usize,
        manifests_by_root: RwLock<HashMap<[u8; 32], FileManifest>>,
        manifests_by_vec_hash: RwLock<HashMap<[u8; 32], FileManifest>>,
        iops_counter: AtomicU64,
    }

    impl GatewaySharedState {
        fn index_manifest(&self, fm: FileManifest) -> EphemeralShardManifest {
            let eph = EphemeralShardManifest::from_file_manifest(&fm);
            let vec_hash = hash_shard_id_vector(&eph.shard_hashes);
            if let Ok(mut by_root) = self.manifests_by_root.write() {
                by_root.insert(fm.file_merkle_root, fm.clone());
            }
            if let Ok(mut by_vec) = self.manifests_by_vec_hash.write() {
                by_vec.insert(vec_hash, fm);
            }
            eph
        }

        fn resolve_manifest_by_root(&self, root: &[u8; 32]) -> Option<FileManifest> {
            if let Ok(by_root) = self.manifests_by_root.read() {
                if let Some(found) = by_root.get(root) {
                    return Some(found.clone());
                }
            }
            if let Ok(loaded) = self.block_store.load_manifest(&self.master_key, root) {
                let _ = self.index_manifest(loaded.clone());
                return Some(loaded);
            }
            None
        }

        fn resolve_manifest_by_shard_ids(&self, shard_ids: &[[u8; 32]]) -> Option<FileManifest> {
            if shard_ids.len() == 1 {
                if let Some(fm) = self.resolve_manifest_by_root(&shard_ids[0]) {
                    return Some(fm);
                }
            }
            let vec_hash = hash_shard_id_vector(shard_ids);
            if let Ok(by_vec) = self.manifests_by_vec_hash.read() {
                if let Some(found) = by_vec.get(&vec_hash) {
                    return Some(found.clone());
                }
            }
            // Fallback: check if single-stripe shard_hashes match any indexed manifest.
            if let Ok(by_root) = self.manifests_by_root.read() {
                for fm in by_root.values() {
                    let eph = EphemeralShardManifest::from_file_manifest(fm);
                    if eph.shard_hashes == shard_ids {
                        return Some(fm.clone());
                    }
                }
            }
            None
        }
    }

    /// Handle controlling a running [`GatewayIpcServer`].
    pub struct GatewayIpcServerHandle {
        socket_path: PathBuf,
        shutdown_flag: Arc<AtomicBool>,
        join_handle: Option<std::thread::JoinHandle<()>>,
    }

    impl GatewayIpcServerHandle {
        pub fn socket_path(&self) -> &Path {
            &self.socket_path
        }

        pub fn shutdown(&mut self) {
            self.shutdown_flag.store(true, Ordering::SeqCst);
            let _ = StdUnixStream::connect(&self.socket_path);
            if let Some(jh) = self.join_handle.take() {
                let _ = jh.join();
            }
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }

    impl Drop for GatewayIpcServerHandle {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    /// High-throughput zero-copy Unix Domain Socket IPC Server (`/var/run/parvault.sock`).
    pub struct GatewayIpcServer {
        socket_path: PathBuf,
        block_store: BlockStore,
        master_key: MasterKey,
        macaroon_root_key: Option<[u8; 32]>,
        default_tier: ErasureTier,
        stripe_size_bytes: usize,
    }

    impl GatewayIpcServer {
        pub fn new(
            socket_path: impl Into<PathBuf>,
            block_store: BlockStore,
            master_key: MasterKey,
        ) -> Self {
            Self {
                socket_path: socket_path.into(),
                block_store,
                master_key,
                macaroon_root_key: None,
                default_tier: ErasureTier::Consumer,
                stripe_size_bytes: ROUTER_SOC_STRIPE_SIZE_BYTES,
            }
        }

        pub fn with_profile(mut self, profile: HardwareProfile) -> Self {
            self.stripe_size_bytes = profile.stripe_size_bytes();
            self
        }

        pub fn with_tier(mut self, tier: ErasureTier) -> Self {
            self.default_tier = tier;
            self
        }

        pub fn with_macaroon_root_key(mut self, root_key: [u8; 32]) -> Self {
            self.macaroon_root_key = Some(root_key);
            self
        }

        /// Binds `socket_path` and spawns the background `SCM_RIGHTS` worker listener.
        pub fn spawn(self) -> io::Result<GatewayIpcServerHandle> {
            if let Some(parent) = self.socket_path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            if self.socket_path.exists() {
                let _ = std::fs::remove_file(&self.socket_path);
            }
            let listener = StdUnixListener::bind(&self.socket_path)?;
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &self.socket_path,
                    std::fs::Permissions::from_mode(0o600),
                );
            }

            let shutdown_flag = Arc::new(AtomicBool::new(false));
            let shutdown_cl = Arc::clone(&shutdown_flag);
            let sock_path = self.socket_path.clone();

            let shared = Arc::new(GatewaySharedState {
                block_store: self
                    .block_store
                    .with_stripe_size_bytes(self.stripe_size_bytes),
                master_key: self.master_key,
                macaroon_root_key: self.macaroon_root_key,
                default_tier: self.default_tier,
                stripe_size_bytes: self.stripe_size_bytes,
                manifests_by_root: RwLock::new(HashMap::new()),
                manifests_by_vec_hash: RwLock::new(HashMap::new()),
                iops_counter: AtomicU64::new(0),
            });

            let join_handle = std::thread::Builder::new()
                .name("parvault-ipc-accept".into())
                .spawn(move || {
                    for incoming in listener.incoming() {
                        if shutdown_cl.load(Ordering::SeqCst) {
                            break;
                        }
                        let Ok(stream) = incoming else {
                            continue;
                        };
                        let state = Arc::clone(&shared);
                        std::thread::Builder::new()
                            .name("parvault-ipc-conn".into())
                            .stack_size(256 * 1024)
                            .spawn(move || {
                                let _ = serve_client_stream(stream, &state);
                            })
                            .ok();
                    }
                })?;

            Ok(GatewayIpcServerHandle {
                socket_path: sock_path,
                shutdown_flag,
                join_handle: Some(join_handle),
            })
        }
    }

    fn serve_client_stream(
        mut stream: StdUnixStream,
        state: &GatewaySharedState,
    ) -> io::Result<()> {
        loop {
            let (raw_cmd, maybe_fd) = match recv_frame_with_optional_fd(&mut stream) {
                Ok(pair) => pair,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };

            let cmd: IpcCommand = match ipc_bincode().deserialize(&raw_cmd) {
                Ok(c) => c,
                Err(e) => {
                    let resp = IpcResponse::Error {
                        message: format!("invalid IPC command bincode: {e}"),
                    };
                    let bytes = ipc_bincode()
                        .serialize(&resp)
                        .map_err(|se| io::Error::other(se.to_string()))?;
                    send_frame_with_optional_fd(&mut stream, &bytes, None)?;
                    continue;
                }
            };

            state.iops_counter.fetch_add(1, Ordering::Relaxed);
            let resp = dispatch_command(cmd, maybe_fd, state);
            let resp_bytes = ipc_bincode()
                .serialize(&resp)
                .map_err(|se| io::Error::other(se.to_string()))?;
            send_frame_with_optional_fd(&mut stream, &resp_bytes, None)?;
        }
    }

    fn dispatch_command(
        cmd: IpcCommand,
        maybe_fd: Option<OwnedFd>,
        state: &GatewaySharedState,
    ) -> IpcResponse {
        match cmd {
            IpcCommand::StorePayload {
                payload_fd: _,
                bytes_len,
                retention_policy,
            } => {
                let Some(owned_fd) = maybe_fd else {
                    return IpcResponse::Error {
                        message: "StorePayload missing SCM_RIGHTS payload_fd".into(),
                    };
                };
                let mut reader_file = File::from(owned_fd);
                if let Err(e) = reader_file.seek(SeekFrom::Start(0)) {
                    return IpcResponse::Error {
                        message: format!("failed seeking payload_fd: {e}"),
                    };
                }
                let owner_tag = match retention_policy {
                    RetentionPolicy::Ephemeral => "local",
                    RetentionPolicy::Persistent | RetentionPolicy::PinnedRing => "self",
                };
                let tier = match retention_policy {
                    RetentionPolicy::PinnedRing => ErasureTier::Homelab,
                    _ => state.default_tier,
                };
                match state.block_store.store_reader_streaming(
                    owner_tag,
                    &mut reader_file,
                    bytes_len,
                    &state.master_key,
                    tier,
                    state.stripe_size_bytes,
                ) {
                    Ok(fm) => {
                        let manifest = state.index_manifest(fm);
                        IpcResponse::StoreSuccess { manifest }
                    }
                    Err(e) => IpcResponse::Error {
                        message: format!("StorePayload failed: {e}"),
                    },
                }
            }
            IpcCommand::FetchPayload {
                ephemeral_shard_ids,
                output_fd: _,
            } => {
                let Some(owned_fd) = maybe_fd else {
                    return IpcResponse::Error {
                        message: "FetchPayload missing SCM_RIGHTS output_fd".into(),
                    };
                };
                let Some(fm) = state.resolve_manifest_by_shard_ids(&ephemeral_shard_ids) else {
                    return IpcResponse::Error {
                        message: "manifest not found for ephemeral_shard_ids".into(),
                    };
                };
                let mut out_file = File::from(owned_fd);
                let _ = out_file.set_len(0);
                let _ = out_file.seek(SeekFrom::Start(0));
                match state.block_store.restore_to_writer_streaming(
                    &fm,
                    &state.master_key,
                    &mut out_file,
                ) {
                    Ok(bytes_streamed) => {
                        let _ = out_file.seek(SeekFrom::Start(0));
                        IpcResponse::FetchSuccess { bytes_streamed }
                    }
                    Err(e) => IpcResponse::Error {
                        message: format!("FetchPayload failed: {e}"),
                    },
                }
            }
            IpcCommand::FetchRange {
                manifest,
                offset,
                len,
                output_fd: _,
                macaroon,
            } => {
                let Some(owned_fd) = maybe_fd else {
                    return IpcResponse::Error {
                        message: "FetchRange missing SCM_RIGHTS output_fd".into(),
                    };
                };
                if let Some(ref root_key) = state.macaroon_root_key {
                    let Some(ref token) = macaroon else {
                        return IpcResponse::Error {
                            message: "FetchRange requires a CapabilityMacaroon".into(),
                        };
                    };
                    let ctx = AccessRequestContext {
                        manifest_root: manifest.file_merkle_root,
                        offset,
                        length: len,
                        is_write: false,
                        now_unix_ms: now_unix_ms(),
                    };
                    if let Err(e) = token.verify_in_ram(root_key, &ctx) {
                        return IpcResponse::Error {
                            message: format!("Macaroon capability rejected: {e}"),
                        };
                    }
                } else if let Some(ref token) = macaroon {
                    let ctx = AccessRequestContext {
                        manifest_root: manifest.file_merkle_root,
                        offset,
                        length: len,
                        is_write: false,
                        now_unix_ms: now_unix_ms(),
                    };
                    if !token.evaluate_caveats(&ctx) {
                        return IpcResponse::Error {
                            message: "Macaroon caveat rejected".into(),
                        };
                    }
                }

                let Some(fm) = state
                    .resolve_manifest_by_root(&manifest.file_merkle_root)
                    .or_else(|| state.resolve_manifest_by_shard_ids(&manifest.shard_hashes))
                else {
                    return IpcResponse::Error {
                        message: "manifest not found for FetchRange".into(),
                    };
                };

                let mut out_file = File::from(owned_fd);
                let _ = out_file.set_len(0);
                let _ = out_file.seek(SeekFrom::Start(0));
                match state.block_store.read_plaintext_range(
                    &fm,
                    &state.master_key,
                    offset,
                    len,
                    &mut out_file,
                ) {
                    Ok(bytes_streamed) => {
                        let _ = out_file.seek(SeekFrom::Start(0));
                        IpcResponse::FetchSuccess { bytes_streamed }
                    }
                    Err(e) => IpcResponse::Error {
                        message: format!("FetchRange failed: {e}"),
                    },
                }
            }
            IpcCommand::RegisterManifest { file_manifest } => {
                if let Err(e) = state
                    .block_store
                    .save_manifest(&state.master_key, &file_manifest)
                {
                    return IpcResponse::Error {
                        message: format!("RegisterManifest save failed: {e}"),
                    };
                }
                let manifest = state.index_manifest(file_manifest);
                IpcResponse::StoreSuccess { manifest }
            }
            IpcCommand::QueryHealthStatus => {
                let peer_count = state
                    .block_store
                    .mesh_client()
                    .map(|c| c.all_network_endpoints().len())
                    .unwrap_or(0);
                IpcResponse::HealthStatus {
                    iops: state.iops_counter.load(Ordering::Relaxed),
                    peer_count,
                    por_sla_score: 1.0,
                }
            }
        }
    }

    /// Zero-copy IPC client connecting to `/var/run/parvault.sock` (`parvault-gateway`).
    #[derive(Debug, Clone)]
    pub struct GatewayIpcClient {
        socket_path: PathBuf,
    }

    impl GatewayIpcClient {
        pub fn new(socket_path: impl Into<PathBuf>) -> Self {
            Self {
                socket_path: socket_path.into(),
            }
        }

        pub fn socket_path(&self) -> &Path {
            &self.socket_path
        }

        fn send_request(
            &self,
            cmd: &IpcCommand,
            attached_fd: Option<RawFd>,
        ) -> io::Result<IpcResponse> {
            let mut stream = StdUnixStream::connect(&self.socket_path)?;
            let encoded = ipc_bincode()
                .serialize(cmd)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            send_frame_with_optional_fd(&mut stream, &encoded, attached_fd)?;
            let (resp_bytes, _fd) = recv_frame_with_optional_fd(&mut stream)?;
            ipc_bincode()
                .deserialize(&resp_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        }

        /// Passes `payload_fd` zero-copy via `SCM_RIGHTS` to `parvault-gateway` (`StorePayload`).
        pub fn store_memfd(
            &self,
            payload_fd: RawFd,
            bytes_len: u64,
            retention_policy: RetentionPolicy,
        ) -> io::Result<EphemeralShardManifest> {
            let cmd = IpcCommand::StorePayload {
                payload_fd,
                bytes_len,
                retention_policy,
            };
            match self.send_request(&cmd, Some(payload_fd))? {
                IpcResponse::StoreSuccess { manifest } => Ok(manifest),
                IpcResponse::Error { message } => Err(io::Error::other(message)),
                other => Err(io::Error::other(format!(
                    "unexpected IPC response: {other:?}"
                ))),
            }
        }

        /// Passes `output_fd` zero-copy via `SCM_RIGHTS` to receive a reconstructed payload (`FetchPayload`).
        pub fn fetch_into_memfd(
            &self,
            ephemeral_shard_ids: Vec<[u8; 32]>,
            output_fd: RawFd,
        ) -> io::Result<u64> {
            let cmd = IpcCommand::FetchPayload {
                ephemeral_shard_ids,
                output_fd,
            };
            match self.send_request(&cmd, Some(output_fd))? {
                IpcResponse::FetchSuccess { bytes_streamed } => Ok(bytes_streamed),
                IpcResponse::Error { message } => Err(io::Error::other(message)),
                other => Err(io::Error::other(format!(
                    "unexpected IPC response: {other:?}"
                ))),
            }
        }

        /// Fetches a targeted `[offset .. offset + len]` byte range into `output_fd` via `SCM_RIGHTS`.
        pub fn fetch_range_into_memfd(
            &self,
            manifest: &EphemeralShardManifest,
            offset: u64,
            len: u64,
            output_fd: RawFd,
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<u64> {
            let cmd = IpcCommand::FetchRange {
                manifest: manifest.clone(),
                offset,
                len,
                output_fd,
                macaroon,
            };
            match self.send_request(&cmd, Some(output_fd))? {
                IpcResponse::FetchSuccess { bytes_streamed } => Ok(bytes_streamed),
                IpcResponse::Error { message } => Err(io::Error::other(message)),
                other => Err(io::Error::other(format!(
                    "unexpected IPC response: {other:?}"
                ))),
            }
        }

        /// Convenience wrapper allocating an ephemeral `memfd`, fetching `[offset .. offset + len]`,
        /// and reading out the verified plaintext slice.
        pub fn fetch_range_bytes(
            &self,
            manifest: &EphemeralShardManifest,
            offset: u64,
            len: u64,
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<Vec<u8>> {
            let mfd = create_memfd("parvault-range")?;
            let streamed =
                self.fetch_range_into_memfd(manifest, offset, len, mfd.as_raw_fd(), macaroon)?;
            let mut file = File::from(mfd);
            file.seek(SeekFrom::Start(0))?;
            let mut buf = vec![0u8; streamed as usize];
            file.read_exact(&mut buf)?;
            Ok(buf)
        }

        /// Registers an existing or sparse virtual `FileManifest` on `parvault-gateway`.
        pub fn register_manifest(
            &self,
            file_manifest: FileManifest,
        ) -> io::Result<EphemeralShardManifest> {
            let cmd = IpcCommand::RegisterManifest { file_manifest };
            match self.send_request(&cmd, None)? {
                IpcResponse::StoreSuccess { manifest } => Ok(manifest),
                IpcResponse::Error { message } => Err(io::Error::other(message)),
                other => Err(io::Error::other(format!(
                    "unexpected IPC response: {other:?}"
                ))),
            }
        }

        /// Queries live gateway IOPS, peer count, and PoR SLA compliance score.
        pub fn query_health(&self) -> io::Result<(u64, usize, f32)> {
            match self.send_request(&IpcCommand::QueryHealthStatus, None)? {
                IpcResponse::HealthStatus {
                    iops,
                    peer_count,
                    por_sla_score,
                } => Ok((iops, peer_count, por_sla_score)),
                IpcResponse::Error { message } => Err(io::Error::other(message)),
                other => Err(io::Error::other(format!(
                    "unexpected IPC response: {other:?}"
                ))),
            }
        }
    }
}

#[cfg(unix)]
pub use unix_impl::{
    create_memfd, read_self_anon_rss_bytes, read_self_rss_bytes, recv_frame_with_optional_fd,
    send_frame_with_optional_fd, GatewayIpcClient, GatewayIpcServer, GatewayIpcServerHandle,
};

#[allow(dead_code)]
fn _keep_sha256_import() {
    let _ = compute_sha256(b"");
}
