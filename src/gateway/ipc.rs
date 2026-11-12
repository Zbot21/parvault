//! Canonical Zero-Copy Local Unix Domain Socket IPC Bridge (`parvault::gateway::ipc`).
//!
//! Decouples the `parvault` core P2P Reed-Solomon / Post-Quantum storage engine from local
//! consumer & ISP CPE modules (`parvault-fuse`, `parvault-auth-broker`, `parvault-media-daemon`,
//! `parvault-isp-agent`) over `/var/run/parvault.sock` using `Serde-Bincode` control frames and
//! kernel `memfd_create(2)` file descriptors passed via `SCM_RIGHTS` ancillary messages.
//!
//! ### Memory & Safety Invariants
//! - **Zero `unsafe` in `gateway`**: All `memfd_create` / `SCM_RIGHTS` syscalls delegate to minimal
//!   audited wrappers in [`crate::os_sys`].
//! - **`< 16 MiB` RSS**: Payloads are never `mmap`ed as monolithic buffers nor copied through
//!   userspace socket frames; [`super::engine::GatewayEngine`] streams `1 MiB` stripes directly via
//!   safe `pread`/`pwrite` (`FileExt::{read_at, write_at}`).

use crate::capabilities::CapabilityMacaroon;
use crate::storage::FileManifest;
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(unix)]
use std::os::fd::RawFd;
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

/// Storage lifecycle policy attached to [`IpcCommand::StorePayload`].
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
    /// Builds an `EphemeralShardManifest` from a [`FileManifest`].
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

/// Control responses returned by [`GatewayIpcServer`] over `/var/run/parvault.sock`.
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
    /// Appended (R3-1): stored, but `local_only_stripes` stripes are only on the daemon's machine
    /// (no ring peer accepted them), so they are not backed up. Clients count them on the
    /// calling thread (`storage::local_only`).
    StoreSuccessLocalOnly {
        manifest: EphemeralShardManifest,
        local_only_stripes: u64,
    },
}

/// Domain-separated SHA-256 digest of a vector of 32-byte shard/stripe identifiers used to index
/// [`EphemeralShardManifest`] entries in RAM for `FetchPayload`.
pub fn hash_shard_id_vector(ids: &[[u8; 32]]) -> [u8; 32] {
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

pub(crate) fn ipc_bincode() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_IPC_FRAME_BYTES as u64)
}

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use crate::config::{ErasureTier, HardwareProfile};
    use crate::crypto::MasterKey;
    use crate::gateway::engine::GatewayEngine;
    use crate::gateway::shm::{pwrite_all, recv_frame_with_fd, send_frame_with_fd};
    use crate::os_sys::{recvmsg_scm_rights, sendmsg_scm_rights};
    use crate::storage::BlockStore;
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::net::{UnixListener as TokioUnixListener, UnixStream as TokioUnixStream};
    use tokio::sync::watch;

    pub use crate::os_sys::{read_self_anon_rss_bytes, read_self_rss_bytes};

    /// Allocates an anonymous in-RAM kernel file descriptor via `memfd_create(2)` (`MFD_CLOEXEC`).
    /// Reading/writing via `pread`/`pwrite` avoids mapping `RssShmem` PTEs into userspace, keeping
    /// process `VmRSS` strictly bounded (`< 16 MiB`) regardless of `memfd` size.
    pub fn create_memfd(name: &str) -> io::Result<OwnedFd> {
        crate::os_sys::create_memfd(name, 0)
    }

    /// Allocates an anonymous kernel `memfd` pre-sized to `initial_size` bytes.
    pub fn create_memfd_sized(name: &str, initial_size: u64) -> io::Result<OwnedFd> {
        crate::os_sys::create_memfd(name, initial_size)
    }

    /// Sends a length-prefixed `bincode` frame over synchronous `stream`, attaching `attached_fd`
    /// via `SCM_RIGHTS` on the 4-byte header `sendmsg(2)` call when present.
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
        let len_be = (payload.len() as u32).to_be_bytes();
        let sent_hdr = sendmsg_scm_rights(stream.as_fd(), &len_be, attached_fd)?;
        if sent_hdr == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Unix socket closed during SCM_RIGHTS header send",
            ));
        }
        if sent_hdr < len_be.len() {
            stream.write_all(&len_be[sent_hdr..])?;
        }
        stream.write_all(payload)?;
        stream.flush()?;
        Ok(())
    }

    /// Receives a length-prefixed `bincode` frame and at most one `SCM_RIGHTS` file descriptor
    /// (`MSG_CMSG_CLOEXEC`) from synchronous `stream`.
    pub fn recv_frame_with_optional_fd(
        stream: &mut StdUnixStream,
    ) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
        let mut len_be = [0u8; 4];
        let (n, received_fd) = recvmsg_scm_rights(stream.as_fd(), &mut len_be)?;
        if n == 0 {
            drop(received_fd);
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "IPC peer closed socket",
            ));
        }
        if n < len_be.len() {
            stream.read_exact(&mut len_be[n..])?;
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

    fn bind_clean_std_listener(path: &Path) -> io::Result<StdUnixListener> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        let listener = StdUnixListener::bind(path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(listener)
    }

    /// Handle controlling a background thread-spawned [`GatewayIpcServer`].
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

    /// Canonical zero-copy Unix Domain Socket IPC Server (`/var/run/parvault.sock`) backed by
    /// [`GatewayEngine`]. Supports both synchronous background thread spawning (`new(..).spawn()`)
    /// and asynchronous Tokio accept loops (`bind(..).serve(shutdown_rx)`).
    pub struct GatewayIpcServer {
        socket_path: PathBuf,
        bound_listener: Option<StdUnixListener>,
        engine: Arc<GatewayEngine>,
    }

    impl GatewayIpcServer {
        /// Constructs an embedded `GatewayIpcServer` wrapping `block_store` and `master_key`.
        pub fn new(
            socket_path: impl AsRef<Path>,
            block_store: BlockStore,
            master_key: MasterKey,
        ) -> Self {
            Self {
                socket_path: socket_path.as_ref().to_path_buf(),
                bound_listener: None,
                engine: Arc::new(GatewayEngine::from_local_block_store(
                    block_store,
                    master_key,
                )),
            }
        }

        /// Binds `socket_path` immediately against an existing `Arc<GatewayEngine>` (ready for
        /// [`Self::serve`] or [`Self::spawn`]).
        pub fn bind(socket_path: impl AsRef<Path>, engine: Arc<GatewayEngine>) -> io::Result<Self> {
            let path = socket_path.as_ref().to_path_buf();
            let std_listener = bind_clean_std_listener(&path)?;
            Ok(Self {
                socket_path: path,
                bound_listener: Some(std_listener),
                engine,
            })
        }

        pub fn socket_path(&self) -> &Path {
            &self.socket_path
        }

        pub fn engine(&self) -> &Arc<GatewayEngine> {
            &self.engine
        }

        pub fn with_profile(self, profile: HardwareProfile) -> Self {
            self.engine
                .set_stripe_size_bytes(profile.stripe_size_bytes());
            self
        }

        pub fn with_tier(self, tier: ErasureTier) -> Self {
            self.engine.set_tier(tier);
            self
        }

        pub fn with_macaroon_root_key(self, root_key: [u8; 32]) -> Self {
            self.engine.set_macaroon_root_key(Some(root_key));
            self
        }

        pub fn with_strict_allowed_peer_uids(self, uids: Vec<u32>) -> Self {
            self.engine.set_strict_allowed_peer_uids(Some(uids));
            self
        }

        pub fn with_require_sealed_ingest_memfd(self, required: bool) -> Self {
            self.engine.set_require_sealed_ingest_memfd(required);
            self
        }

        /// Binds (if not already bound) and spawns a background worker accept loop, returning an
        /// RAII [`GatewayIpcServerHandle`].
        pub fn spawn(mut self) -> io::Result<GatewayIpcServerHandle> {
            let listener = match self.bound_listener.take() {
                Some(l) => l,
                None => bind_clean_std_listener(&self.socket_path)?,
            };
            listener.set_nonblocking(false)?;

            let shutdown_flag = Arc::new(AtomicBool::new(false));
            let shutdown_cl = Arc::clone(&shutdown_flag);
            let sock_path = self.socket_path.clone();
            let engine = Arc::clone(&self.engine);

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
                        let peer_uid = crate::os_sys::peer_socket_ucred(stream.as_fd())
                            .ok()
                            .map(|u| u.uid);
                        if !engine.is_peer_uid_allowed(peer_uid) {
                            drop(stream);
                            continue;
                        }
                        let eng = Arc::clone(&engine);
                        std::thread::Builder::new()
                            .name("parvault-ipc-conn".into())
                            .stack_size(256 * 1024)
                            .spawn(move || {
                                let _ = serve_client_stream_sync(stream, &eng, peer_uid);
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

        /// Runs an asynchronous Tokio accept loop until `shutdown_rx` signals `true`.
        pub async fn serve(mut self, mut shutdown_rx: watch::Receiver<bool>) -> io::Result<()> {
            let std_listener = match self.bound_listener.take() {
                Some(l) => l,
                None => bind_clean_std_listener(&self.socket_path)?,
            };
            std_listener.set_nonblocking(true)?;
            let listener = TokioUnixListener::from_std(std_listener)?;

            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accept_res = listener.accept() => {
                        let (stream, _) = accept_res?;
                        let peer_uid = crate::os_sys::peer_socket_ucred(stream.as_fd())
                            .ok()
                            .map(|u| u.uid);
                        if !self.engine.is_peer_uid_allowed(peer_uid) {
                            drop(stream);
                            continue;
                        }
                        let engine = Arc::clone(&self.engine);
                        tokio::spawn(async move {
                            let _ = serve_client_stream_async(stream, engine, peer_uid).await;
                        });
                    }
                }
            }
            let _ = std::fs::remove_file(&self.socket_path);
            Ok(())
        }
    }

    fn execute_engine_command(
        engine: &GatewayEngine,
        cmd: IpcCommand,
        maybe_fd: Option<OwnedFd>,
        peer_uid: Option<u32>,
    ) -> IpcResponse {
        match cmd {
            IpcCommand::StorePayload {
                bytes_len,
                retention_policy,
                ..
            } => {
                let Some(owned_fd) = maybe_fd else {
                    return IpcResponse::Error {
                        message: "StorePayload missing SCM_RIGHTS payload_fd".into(),
                    };
                };
                if engine.require_sealed_ingest_memfd()
                    && !crate::os_sys::has_immutable_memfd_seals(owned_fd.as_fd()).unwrap_or(false)
                {
                    return IpcResponse::Error {
                        message: "unsealed ingest memfd rejected (F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW required)".into(),
                    };
                }
                let (stored, local_only_stripes) = crate::storage::local_only::track(|| {
                    engine.store_from_owned_fd(owned_fd, bytes_len, retention_policy)
                });
                match stored {
                    Ok(manifest) if local_only_stripes > 0 => IpcResponse::StoreSuccessLocalOnly {
                        manifest,
                        local_only_stripes,
                    },
                    Ok(manifest) => IpcResponse::StoreSuccess { manifest },
                    Err(e) => IpcResponse::Error {
                        message: format!("StorePayload failed: {e}"),
                    },
                }
            }
            IpcCommand::FetchPayload {
                ephemeral_shard_ids,
                ..
            } => {
                let Some(owned_fd) = maybe_fd else {
                    return IpcResponse::Error {
                        message: "FetchPayload missing SCM_RIGHTS output_fd".into(),
                    };
                };
                match engine.fetch_by_shard_ids_to_owned_fd(&ephemeral_shard_ids, owned_fd) {
                    Ok(bytes_streamed) => IpcResponse::FetchSuccess { bytes_streamed },
                    Err(e) => IpcResponse::Error {
                        message: format!("FetchPayload failed: {e}"),
                    },
                }
            }
            IpcCommand::FetchRange {
                manifest,
                offset,
                len,
                macaroon,
                ..
            } => {
                let Some(owned_fd) = maybe_fd else {
                    return IpcResponse::Error {
                        message: "FetchRange missing SCM_RIGHTS output_fd".into(),
                    };
                };
                match engine.fetch_range_to_owned_fd_with_peer_uid(
                    &manifest,
                    offset,
                    len,
                    macaroon.as_ref(),
                    peer_uid,
                    owned_fd,
                ) {
                    Ok(bytes_streamed) => IpcResponse::FetchSuccess { bytes_streamed },
                    Err(e) => IpcResponse::Error {
                        message: format!("FetchRange failed: {e}"),
                    },
                }
            }
            IpcCommand::RegisterManifest { file_manifest } => {
                let manifest = engine.register_manifest(file_manifest);
                IpcResponse::StoreSuccess { manifest }
            }
            IpcCommand::QueryHealthStatus => {
                let (iops, peer_count, por_sla_score) = engine.health_snapshot();
                IpcResponse::HealthStatus {
                    iops,
                    peer_count,
                    por_sla_score,
                }
            }
        }
    }

    fn serve_client_stream_sync(
        mut stream: StdUnixStream,
        engine: &GatewayEngine,
        peer_uid: Option<u32>,
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
                    drop(maybe_fd);
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

            let resp = execute_engine_command(engine, cmd, maybe_fd, peer_uid);
            let resp_bytes = ipc_bincode()
                .serialize(&resp)
                .map_err(|se| io::Error::other(se.to_string()))?;
            send_frame_with_optional_fd(&mut stream, &resp_bytes, None)?;
        }
    }

    async fn serve_client_stream_async(
        mut stream: TokioUnixStream,
        engine: Arc<GatewayEngine>,
        peer_uid: Option<u32>,
    ) -> anyhow::Result<()> {
        loop {
            let (frame_bytes, received_fd) = match recv_frame_with_fd(&mut stream).await {
                Ok(pair) => pair,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e.into()),
            };

            let cmd: IpcCommand = match ipc_bincode().deserialize(&frame_bytes) {
                Ok(c) => c,
                Err(e) => {
                    drop(received_fd);
                    let resp = IpcResponse::Error {
                        message: format!("invalid IPC command frame: {e}"),
                    };
                    let enc = ipc_bincode().serialize(&resp)?;
                    send_frame_with_fd(&mut stream, &enc, None).await?;
                    continue;
                }
            };

            let eng = Arc::clone(&engine);
            let response = match tokio::task::spawn_blocking(move || {
                execute_engine_command(&eng, cmd, received_fd, peer_uid)
            })
            .await
            {
                Ok(resp) => resp,
                Err(e) => IpcResponse::Error {
                    message: format!("gateway worker join error: {e}"),
                },
            };
            let enc = ipc_bincode().serialize(&response)?;
            send_frame_with_fd(&mut stream, &enc, None).await?;
        }
    }

    /// Zero-copy Unix Domain Socket IPC client connecting to `/var/run/parvault.sock`
    /// (`parvault-gateway`). Provides both asynchronous Tokio methods (`store_payload_fd`,
    /// `fetch_payload_to_fd`, `fetch_range_to_fd`, `store_bytes`, `query_health`, `send_command`)
    /// and synchronous blocking methods (`store_memfd`, `fetch_into_memfd`,
    /// `fetch_range_into_memfd`, `fetch_range_bytes`, `register_manifest`, `query_health_sync`).
    #[derive(Debug, Clone)]
    pub struct GatewayIpcClient {
        socket_path: PathBuf,
    }

    impl GatewayIpcClient {
        pub fn new(socket_path: impl AsRef<Path>) -> Self {
            Self {
                socket_path: socket_path.as_ref().to_path_buf(),
            }
        }

        pub fn socket_path(&self) -> &Path {
            &self.socket_path
        }

        // --- Asynchronous Tokio Client Surface ---

        /// Sends a raw [`IpcCommand`] with an optional `SCM_RIGHTS` file descriptor over Tokio `UnixStream`.
        pub async fn send_command(
            &self,
            cmd: &IpcCommand,
            attached_fd: Option<RawFd>,
        ) -> anyhow::Result<IpcResponse> {
            let mut stream = TokioUnixStream::connect(&self.socket_path).await?;
            let encoded = ipc_bincode().serialize(cmd)?;
            send_frame_with_fd(&mut stream, &encoded, attached_fd).await?;
            let (resp_bytes, extra_fd) = recv_frame_with_fd(&mut stream).await?;
            drop(extra_fd);
            let resp: IpcResponse = ipc_bincode().deserialize(&resp_bytes)?;
            Ok(resp)
        }

        /// Passes `payload_fd` (`memfd` or file) zero-copy via `SCM_RIGHTS` for streaming encryption & sharding.
        pub async fn store_payload_fd(
            &self,
            payload_fd: RawFd,
            bytes_len: u64,
            retention_policy: RetentionPolicy,
        ) -> anyhow::Result<EphemeralShardManifest> {
            let cmd = IpcCommand::StorePayload {
                payload_fd,
                bytes_len,
                retention_policy,
            };
            match self.send_command(&cmd, Some(payload_fd)).await? {
                IpcResponse::StoreSuccessLocalOnly {
                    manifest,
                    local_only_stripes,
                } => {
                    crate::storage::local_only::note(local_only_stripes);
                    Ok(manifest)
                }
                IpcResponse::StoreSuccess { manifest } => Ok(manifest),
                IpcResponse::Error { message } => {
                    anyhow::bail!("gateway StorePayload error: {message}")
                }
                other => anyhow::bail!("unexpected StorePayload response: {other:?}"),
            }
        }

        /// Seals `fd` with `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE` (unless already
        /// immutably sealed) and passes it zero-copy via `SCM_RIGHTS` (`StorePayload`).
        pub async fn store_sealed_payload_fd(
            &self,
            fd: RawFd,
            bytes_len: u64,
            retention: RetentionPolicy,
        ) -> anyhow::Result<EphemeralShardManifest> {
            let dup = crate::os_sys::dup_fd_cloexec(fd)?;
            if !crate::os_sys::has_immutable_memfd_seals(dup.as_fd())? {
                crate::os_sys::seal_memfd_immutable(dup.as_fd())?;
            }
            drop(dup);
            self.store_payload_fd(fd, bytes_len, retention).await
        }

        /// Reconstructs the full payload identified by `ephemeral_shard_ids` directly into `output_fd` via `SCM_RIGHTS`.
        pub async fn fetch_payload_to_fd(
            &self,
            ephemeral_shard_ids: Vec<[u8; 32]>,
            output_fd: RawFd,
        ) -> anyhow::Result<u64> {
            let cmd = IpcCommand::FetchPayload {
                ephemeral_shard_ids,
                output_fd,
            };
            match self.send_command(&cmd, Some(output_fd)).await? {
                IpcResponse::FetchSuccess { bytes_streamed } => Ok(bytes_streamed),
                IpcResponse::Error { message } => {
                    anyhow::bail!("gateway FetchPayload error: {message}")
                }
                other => anyhow::bail!("unexpected FetchPayload response: {other:?}"),
            }
        }

        /// Fetches a targeted byte-range (`[offset .. offset + len]`) into `output_fd` via `SCM_RIGHTS`,
        /// optionally enforcing an attached [`CapabilityMacaroon`] in RAM (`< 1 ms`).
        pub async fn fetch_range_to_fd(
            &self,
            manifest: EphemeralShardManifest,
            offset: u64,
            len: u64,
            output_fd: RawFd,
            macaroon: Option<CapabilityMacaroon>,
        ) -> anyhow::Result<u64> {
            let cmd = IpcCommand::FetchRange {
                manifest,
                offset,
                len,
                output_fd,
                macaroon,
            };
            match self.send_command(&cmd, Some(output_fd)).await? {
                IpcResponse::FetchSuccess { bytes_streamed } => Ok(bytes_streamed),
                IpcResponse::Error { message } => {
                    anyhow::bail!("gateway FetchRange error: {message}")
                }
                other => anyhow::bail!("unexpected FetchRange response: {other:?}"),
            }
        }

        /// Allocates an anonymous `memfd`, writes `bytes` via safe `pwrite_all`, applies immutable
        /// seals (`F_ADD_SEALS`), and stores via `SCM_RIGHTS`.
        pub async fn store_bytes(
            &self,
            bytes: &[u8],
            retention_policy: RetentionPolicy,
        ) -> anyhow::Result<EphemeralShardManifest> {
            let mfd = create_memfd_sized("parvault-store", bytes.len() as u64)?;
            let file = File::from(mfd);
            pwrite_all(&file, 0, bytes)?;
            let _ = crate::os_sys::seal_memfd_immutable(file.as_fd());
            self.store_payload_fd(file.as_raw_fd(), bytes.len() as u64, retention_policy)
                .await
        }

        /// Registers an existing or sparse virtual `FileManifest` asynchronously over `/var/run/parvault.sock`.
        pub async fn register_manifest_async(
            &self,
            file_manifest: FileManifest,
        ) -> anyhow::Result<EphemeralShardManifest> {
            let cmd = IpcCommand::RegisterManifest { file_manifest };
            match self.send_command(&cmd, None).await? {
                IpcResponse::StoreSuccess { manifest } => Ok(manifest),
                IpcResponse::Error { message } => {
                    anyhow::bail!("gateway RegisterManifest error: {message}")
                }
                other => anyhow::bail!("unexpected RegisterManifest response: {other:?}"),
            }
        }

        /// Queries real-time gateway IOPS, connected peer count, and PoR SLA compliance score asynchronously.
        pub async fn query_health(&self) -> anyhow::Result<(u64, usize, f32)> {
            match self
                .send_command(&IpcCommand::QueryHealthStatus, None)
                .await?
            {
                IpcResponse::HealthStatus {
                    iops,
                    peer_count,
                    por_sla_score,
                } => Ok((iops, peer_count, por_sla_score)),
                IpcResponse::Error { message } => anyhow::bail!("gateway health error: {message}"),
                other => anyhow::bail!("unexpected QueryHealthStatus response: {other:?}"),
            }
        }

        // --- Synchronous Blocking Client Surface (FUSE / Sync CLI / Benchmarks) ---

        fn send_request_sync(
            &self,
            cmd: &IpcCommand,
            attached_fd: Option<RawFd>,
        ) -> io::Result<IpcResponse> {
            let mut stream = StdUnixStream::connect(&self.socket_path)?;
            let encoded = ipc_bincode()
                .serialize(cmd)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            send_frame_with_optional_fd(&mut stream, &encoded, attached_fd)?;
            let (resp_bytes, extra_fd) = recv_frame_with_optional_fd(&mut stream)?;
            drop(extra_fd);
            ipc_bincode()
                .deserialize(&resp_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        }

        /// Passes `payload_fd` zero-copy via `SCM_RIGHTS` to `parvault` (`StorePayload`).
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
            match self.send_request_sync(&cmd, Some(payload_fd))? {
                IpcResponse::StoreSuccessLocalOnly {
                    manifest,
                    local_only_stripes,
                } => {
                    crate::storage::local_only::note(local_only_stripes);
                    Ok(manifest)
                }
                IpcResponse::StoreSuccess { manifest } => Ok(manifest),
                IpcResponse::Error { message } => Err(io::Error::other(message)),
                other => Err(io::Error::other(format!(
                    "unexpected IPC response: {other:?}"
                ))),
            }
        }

        /// Seals `payload_fd` with `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`
        /// (unless already immutably sealed) and passes it zero-copy via `SCM_RIGHTS` (`StorePayload`).
        pub fn store_sealed_memfd(
            &self,
            payload_fd: RawFd,
            bytes_len: u64,
            retention_policy: RetentionPolicy,
        ) -> io::Result<EphemeralShardManifest> {
            let dup = crate::os_sys::dup_fd_cloexec(payload_fd)?;
            if !crate::os_sys::has_immutable_memfd_seals(dup.as_fd())? {
                crate::os_sys::seal_memfd_immutable(dup.as_fd())?;
            }
            drop(dup);
            self.store_memfd(payload_fd, bytes_len, retention_policy)
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
            match self.send_request_sync(&cmd, Some(output_fd))? {
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
            match self.send_request_sync(&cmd, Some(output_fd))? {
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
            match self.send_request_sync(&cmd, None)? {
                IpcResponse::StoreSuccess { manifest } => Ok(manifest),
                IpcResponse::Error { message } => Err(io::Error::other(message)),
                other => Err(io::Error::other(format!(
                    "unexpected IPC response: {other:?}"
                ))),
            }
        }

        /// Queries live gateway IOPS, peer count, and PoR SLA compliance score synchronously.
        pub fn query_health_sync(&self) -> io::Result<(u64, usize, f32)> {
            match self.send_request_sync(&IpcCommand::QueryHealthStatus, None)? {
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

    /// Unified transport-agnostic gateway bus (`ADR-32`) allowing embedded callers and plugins to
    /// switch between zero-socket in-process execution (`--no-socket`) and hardened Unix Domain
    /// Socket IPC (`/var/run/parvault.sock`) with bit-for-bit identical semantics.
    #[derive(Clone)]
    pub enum GatewayBus {
        InProcess(Arc<GatewayEngine>),
        UnixSocket(GatewayIpcClient),
    }

    impl std::fmt::Debug for GatewayBus {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::InProcess(_) => f.write_str("GatewayBus::InProcess(..)"),
                Self::UnixSocket(client) => f
                    .debug_tuple("GatewayBus::UnixSocket")
                    .field(&client.socket_path())
                    .finish(),
            }
        }
    }

    impl GatewayBus {
        pub fn in_process(engine: Arc<GatewayEngine>) -> Self {
            Self::InProcess(engine)
        }

        pub fn unix_socket(socket_path: impl AsRef<Path>) -> Self {
            Self::UnixSocket(GatewayIpcClient::new(socket_path))
        }

        /// Streams `bytes_len` bytes from `payload_fd` into the gateway (`StorePayload`).
        pub async fn store_payload_fd(
            &self,
            payload_fd: RawFd,
            bytes_len: u64,
            retention: RetentionPolicy,
        ) -> anyhow::Result<EphemeralShardManifest> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(payload_fd)?;
                    let eng = Arc::clone(engine);
                    tokio::task::spawn_blocking(move || {
                        eng.store_from_owned_fd(dup, bytes_len, retention)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("in-process StorePayload join error: {e}"))?
                }
                Self::UnixSocket(client) => {
                    client
                        .store_payload_fd(payload_fd, bytes_len, retention)
                        .await
                }
            }
        }

        /// Seals `fd` with `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE` (unless
        /// already immutably sealed) and streams `bytes_len` bytes into the gateway (`StorePayload`).
        pub async fn store_sealed_payload_fd(
            &self,
            fd: RawFd,
            bytes_len: u64,
            retention: RetentionPolicy,
        ) -> anyhow::Result<EphemeralShardManifest> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(fd)?;
                    if !crate::os_sys::has_immutable_memfd_seals(dup.as_fd())? {
                        crate::os_sys::seal_memfd_immutable(dup.as_fd())?;
                    }
                    let eng = Arc::clone(engine);
                    tokio::task::spawn_blocking(move || {
                        eng.store_from_owned_fd(dup, bytes_len, retention)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("in-process StorePayload join error: {e}"))?
                }
                Self::UnixSocket(client) => {
                    client
                        .store_sealed_payload_fd(fd, bytes_len, retention)
                        .await
                }
            }
        }

        /// Reconstructs the full payload identified by `ephemeral_shard_ids` directly into `output_fd`.
        pub async fn fetch_payload_to_fd(
            &self,
            ephemeral_shard_ids: Vec<[u8; 32]>,
            output_fd: RawFd,
        ) -> anyhow::Result<u64> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(output_fd)?;
                    let eng = Arc::clone(engine);
                    tokio::task::spawn_blocking(move || {
                        eng.fetch_by_shard_ids_to_owned_fd(&ephemeral_shard_ids, dup)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("in-process FetchPayload join error: {e}"))?
                }
                Self::UnixSocket(client) => {
                    client
                        .fetch_payload_to_fd(ephemeral_shard_ids, output_fd)
                        .await
                }
            }
        }

        /// Fetches `[offset .. offset + len]` into `output_fd`, enforcing `macaroon` in RAM (`< 1 ms`).
        /// Both `InProcess` (`Some(geteuid())`) and `UnixSocket` (`SO_PEERCRED`) bind `peer_uid` identically.
        pub async fn fetch_range_to_fd(
            &self,
            manifest: EphemeralShardManifest,
            offset: u64,
            len: u64,
            output_fd: RawFd,
            macaroon: Option<CapabilityMacaroon>,
        ) -> anyhow::Result<u64> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(output_fd)?;
                    let eng = Arc::clone(engine);
                    tokio::task::spawn_blocking(move || {
                        eng.fetch_range_to_owned_fd(&manifest, offset, len, macaroon.as_ref(), dup)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("in-process FetchRange join error: {e}"))?
                }
                Self::UnixSocket(client) => {
                    client
                        .fetch_range_to_fd(manifest, offset, len, output_fd, macaroon)
                        .await
                }
            }
        }

        /// Registers an existing or sparse virtual `FileManifest` into the gateway.
        pub async fn register_manifest(
            &self,
            file_manifest: FileManifest,
        ) -> anyhow::Result<EphemeralShardManifest> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    Ok(engine.register_manifest(file_manifest))
                }
                Self::UnixSocket(client) => client.register_manifest_async(file_manifest).await,
            }
        }

        /// Queries `(iops, peer_count, por_sla_score)` telemetry from the gateway.
        pub async fn query_health(&self) -> anyhow::Result<(u64, usize, f32)> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    Ok(engine.health_snapshot())
                }
                Self::UnixSocket(client) => client.query_health().await,
            }
        }

        // --- Synchronous Blocking Surface (`FUSE`, `WebDAV`, `GatewayFolderSync`) ---

        fn ensure_in_process_peer_uid(engine: &GatewayEngine) -> io::Result<()> {
            let uid = Some(crate::os_sys::geteuid());
            if !engine.is_peer_uid_allowed(uid) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("peer UID {uid:?} rejected by strict_allowed_peer_uids policy"),
                ));
            }
            Ok(())
        }

        /// Blocking `StorePayload` over either in-process `Arc<GatewayEngine>` or `GatewayIpcClient`.
        /// Enforces `require_sealed_ingest_memfd` identically across `InProcess` and `UnixSocket`.
        pub fn store_memfd_sync(
            &self,
            payload_fd: RawFd,
            bytes_len: u64,
            retention: RetentionPolicy,
        ) -> io::Result<EphemeralShardManifest> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(payload_fd)?;
                    if engine.require_sealed_ingest_memfd()
                        && !crate::os_sys::has_immutable_memfd_seals(dup.as_fd()).unwrap_or(false)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "unsealed ingest memfd rejected (F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW required)",
                        ));
                    }
                    engine
                        .store_from_owned_fd(dup, bytes_len, retention)
                        .map_err(|e| io::Error::other(format!("StorePayload failed: {e}")))
                }
                Self::UnixSocket(client) => client.store_memfd(payload_fd, bytes_len, retention),
            }
        }

        /// Seals `payload_fd` with `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`
        /// (if not already immutably sealed) and stores `bytes_len` bytes synchronously.
        pub fn store_sealed_memfd_sync(
            &self,
            payload_fd: RawFd,
            bytes_len: u64,
            retention: RetentionPolicy,
        ) -> io::Result<EphemeralShardManifest> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(payload_fd)?;
                    if !crate::os_sys::has_immutable_memfd_seals(dup.as_fd())? {
                        crate::os_sys::seal_memfd_immutable(dup.as_fd())?;
                    }
                    engine
                        .store_from_owned_fd(dup, bytes_len, retention)
                        .map_err(|e| io::Error::other(format!("StorePayload failed: {e}")))
                }
                Self::UnixSocket(client) => {
                    client.store_sealed_memfd(payload_fd, bytes_len, retention)
                }
            }
        }

        /// Reconstructs the full payload identified by `ephemeral_shard_ids` into `output_fd` synchronously.
        pub fn fetch_into_memfd_sync(
            &self,
            ephemeral_shard_ids: Vec<[u8; 32]>,
            output_fd: RawFd,
        ) -> io::Result<u64> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(output_fd)?;
                    engine
                        .fetch_by_shard_ids_to_owned_fd(&ephemeral_shard_ids, dup)
                        .map_err(|e| io::Error::other(format!("FetchPayload failed: {e}")))
                }
                Self::UnixSocket(client) => client.fetch_into_memfd(ephemeral_shard_ids, output_fd),
            }
        }

        /// Fetches `[offset .. offset + len]` into `output_fd` synchronously, enforcing `macaroon`
        /// and `peer_uid` (`Some(geteuid())` in-process vs `SO_PEERCRED` over Unix socket) identically.
        pub fn fetch_range_into_memfd_sync(
            &self,
            manifest: &EphemeralShardManifest,
            offset: u64,
            len: u64,
            output_fd: RawFd,
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<u64> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(output_fd)?;
                    engine
                        .fetch_range_to_owned_fd(manifest, offset, len, macaroon.as_ref(), dup)
                        .map_err(|e| io::Error::other(format!("FetchRange failed: {e}")))
                }
                Self::UnixSocket(client) => {
                    client.fetch_range_into_memfd(manifest, offset, len, output_fd, macaroon)
                }
            }
        }

        /// Allocates an ephemeral `memfd`, fetches `[offset .. offset + len]` synchronously, and
        /// returns the verified plaintext slice.
        pub fn fetch_range_bytes_sync(
            &self,
            manifest: &EphemeralShardManifest,
            offset: u64,
            len: u64,
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<Vec<u8>> {
            match self {
                Self::InProcess(_) => {
                    let mfd = create_memfd("parvault-range")?;
                    let streamed = self.fetch_range_into_memfd_sync(
                        manifest,
                        offset,
                        len,
                        mfd.as_raw_fd(),
                        macaroon,
                    )?;
                    let mut file = File::from(mfd);
                    file.seek(SeekFrom::Start(0))?;
                    let mut buf = vec![0u8; streamed as usize];
                    file.read_exact(&mut buf)?;
                    Ok(buf)
                }
                Self::UnixSocket(client) => {
                    client.fetch_range_bytes(manifest, offset, len, macaroon)
                }
            }
        }

        /// Registers an existing or sparse virtual `FileManifest` synchronously.
        pub fn register_manifest_sync(
            &self,
            file_manifest: FileManifest,
        ) -> io::Result<EphemeralShardManifest> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    Ok(engine.register_manifest(file_manifest))
                }
                Self::UnixSocket(client) => client.register_manifest(file_manifest),
            }
        }

        /// Queries `(iops, peer_count, por_sla_score)` synchronously.
        pub fn query_health_sync(&self) -> io::Result<(u64, usize, f32)> {
            match self {
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    Ok(engine.health_snapshot())
                }
                Self::UnixSocket(client) => client.query_health_sync(),
            }
        }
    }
}

#[cfg(unix)]
pub use unix_impl::{
    create_memfd, create_memfd_sized, read_self_anon_rss_bytes, read_self_rss_bytes,
    recv_frame_with_optional_fd, send_frame_with_optional_fd, GatewayBus, GatewayIpcClient,
    GatewayIpcServer, GatewayIpcServerHandle,
};
