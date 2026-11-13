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
        /// Checked like `FetchRange`'s, against the whole file (F-47, item 3). Appended.
        macaroon: Option<CapabilityMacaroon>,
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
    /// Appended (item 3): the node's [`StatusSnapshot`]. Always carries a token, checked by
    /// [`crate::http_edge::status_auth_decision`]; refused without a root key or a published
    /// snapshot.
    QueryStatus {
        macaroon: Option<CapabilityMacaroon>,
    },
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
    /// Appended (item 3): the answer to `QueryStatus`.
    StatusSnapshot(StatusSnapshot),
}

/// Most LAN peers a [`StatusSnapshot`] carries (item 3, ruling change 3).
pub const MAX_STATUS_PEERS: usize = 128;
/// Longest string field, in bytes, a [`StatusSnapshot`] carries.
pub const MAX_STATUS_STRING_BYTES: usize = 256;
// 10 top-level strings and 4 per peer, each with an 8-byte length prefix, plus 6 + 1 u64s per
// snapshot and peer: far below one IPC frame.
const _: () = assert!(
    (10 + 4 * MAX_STATUS_PEERS) * (MAX_STATUS_STRING_BYTES + 8) + (7 + MAX_STATUS_PEERS) * 8 + 64
        < MAX_IPC_FRAME_BYTES
);

/// One LAN peer in a [`StatusSnapshot`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusPeerEntry {
    pub peer_id: String,
    pub label: String,
    pub role: String,
    pub multiaddr: String,
    pub available_bytes: u64,
}

/// The node status served to the status page and over `QueryStatus` (was
/// `router_nas::RouterNasLiveSnapshot`, which is now an alias). Item 3 dropped
/// `pairing_sas_code` and `watched_folder`; strings and the peer list are capped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusSnapshot {
    pub version: String,
    pub node_label: String,
    pub hardware_profile: String,
    pub device_peer_id: String,
    pub libp2p_peer_id: String,
    pub owner_pq_fingerprint: String,
    pub stripe_size_bytes: u64,
    pub sla_tier: String,
    pub used_storage_bytes: u64,
    pub max_storage_bytes: u64,
    pub rss_kib: u64,
    pub hwm_kib: u64,
    pub uptime_secs: u64,
    pub lan_peers: Vec<StatusPeerEntry>,
}

impl Default for StatusSnapshot {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            node_label: "parvault-router-nas".to_string(),
            hardware_profile: "router-soc".to_string(),
            device_peer_id: String::new(),
            libp2p_peer_id: String::new(),
            owner_pq_fingerprint: String::new(),
            stripe_size_bytes: 1024 * 1024,
            sla_tier: "Community".to_string(),
            used_storage_bytes: 0,
            max_storage_bytes: 0,
            rss_kib: 0,
            hwm_kib: 0,
            uptime_secs: 0,
            lan_peers: Vec::new(),
        }
    }
}

fn cap_string(s: &mut String) {
    if s.len() > MAX_STATUS_STRING_BYTES {
        let mut end = MAX_STATUS_STRING_BYTES;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

impl StatusSnapshot {
    /// Truncates strings and the peer list to the caps (the daemon publishes only capped
    /// snapshots).
    pub fn capped(mut self) -> Self {
        for s in [
            &mut self.version,
            &mut self.node_label,
            &mut self.hardware_profile,
            &mut self.device_peer_id,
            &mut self.libp2p_peer_id,
            &mut self.owner_pq_fingerprint,
            &mut self.sla_tier,
        ] {
            cap_string(s);
        }
        self.lan_peers.truncate(MAX_STATUS_PEERS);
        for p in &mut self.lan_peers {
            for s in [&mut p.peer_id, &mut p.label, &mut p.role, &mut p.multiaddr] {
                cap_string(s);
            }
        }
        self
    }

    /// True when every string and the peer list are within the caps (clients check a decoded
    /// snapshot with this).
    pub fn within_caps(&self) -> bool {
        let ok = |s: &String| s.len() <= MAX_STATUS_STRING_BYTES;
        [
            &self.version,
            &self.node_label,
            &self.hardware_profile,
            &self.device_peer_id,
            &self.libp2p_peer_id,
            &self.owner_pq_fingerprint,
            &self.sla_tier,
        ]
        .into_iter()
        .all(ok)
            && self.lan_peers.len() <= MAX_STATUS_PEERS
            && self
                .lan_peers
                .iter()
                .all(|p| ok(&p.peer_id) && ok(&p.label) && ok(&p.role) && ok(&p.multiaddr))
    }
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
    #[cfg(feature = "daemon-runtime")]
    use crate::gateway::engine::GatewayEngine;
    #[cfg(feature = "daemon-runtime")]
    use crate::gateway::shm::{pwrite_all, recv_frame_with_fd, send_frame_with_fd};
    use crate::os_sys::{recvmsg_scm_rights, sendmsg_scm_rights};
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::path::{Path, PathBuf};
    #[cfg(feature = "daemon-runtime")]
    use std::sync::Arc;
    #[cfg(feature = "daemon-runtime")]
    use tokio::net::UnixStream as TokioUnixStream;

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
    }

    /// Asynchronous Tokio client surface (`daemon-runtime`).
    #[cfg(feature = "daemon-runtime")]
    impl GatewayIpcClient {
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
            let (manifest, local_only_stripes) = self
                .store_payload_fd_counted(payload_fd, bytes_len, retention_policy)
                .await?;
            crate::storage::local_only::note(local_only_stripes);
            Ok(manifest)
        }

        /// Like [`Self::store_payload_fd`], returning how many stripes stayed only on the
        /// daemon's machine (not backed up, R3-1). Async callers that need the count use this:
        /// the thread-local count does not follow a task across `.await`.
        pub async fn store_payload_fd_counted(
            &self,
            payload_fd: RawFd,
            bytes_len: u64,
            retention_policy: RetentionPolicy,
        ) -> anyhow::Result<(EphemeralShardManifest, u64)> {
            let cmd = IpcCommand::StorePayload {
                payload_fd,
                bytes_len,
                retention_policy,
            };
            match self.send_command(&cmd, Some(payload_fd)).await? {
                IpcResponse::StoreSuccessLocalOnly {
                    manifest,
                    local_only_stripes,
                } => Ok((manifest, local_only_stripes)),
                IpcResponse::StoreSuccess { manifest } => Ok((manifest, 0)),
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
            let (manifest, local_only_stripes) = self
                .store_sealed_payload_fd_counted(fd, bytes_len, retention)
                .await?;
            crate::storage::local_only::note(local_only_stripes);
            Ok(manifest)
        }

        /// Like [`Self::store_sealed_payload_fd`], returning the local-only stripe count.
        pub async fn store_sealed_payload_fd_counted(
            &self,
            fd: RawFd,
            bytes_len: u64,
            retention: RetentionPolicy,
        ) -> anyhow::Result<(EphemeralShardManifest, u64)> {
            let dup = crate::os_sys::dup_fd_cloexec(fd)?;
            if !crate::os_sys::has_immutable_memfd_seals(dup.as_fd())? {
                crate::os_sys::seal_memfd_immutable(dup.as_fd())?;
            }
            drop(dup);
            self.store_payload_fd_counted(fd, bytes_len, retention)
                .await
        }

        /// Reconstructs the full payload identified by `ephemeral_shard_ids` directly into `output_fd` via `SCM_RIGHTS`.
        pub async fn fetch_payload_to_fd(
            &self,
            ephemeral_shard_ids: Vec<[u8; 32]>,
            output_fd: RawFd,
            macaroon: Option<CapabilityMacaroon>,
        ) -> anyhow::Result<u64> {
            let cmd = IpcCommand::FetchPayload {
                ephemeral_shard_ids,
                output_fd,
                macaroon,
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
            let (manifest, local_only_stripes) =
                self.store_bytes_counted(bytes, retention_policy).await?;
            crate::storage::local_only::note(local_only_stripes);
            Ok(manifest)
        }

        /// Like [`Self::store_bytes`], returning the local-only stripe count.
        pub async fn store_bytes_counted(
            &self,
            bytes: &[u8],
            retention_policy: RetentionPolicy,
        ) -> anyhow::Result<(EphemeralShardManifest, u64)> {
            let mfd = create_memfd_sized("parvault-store", bytes.len() as u64)?;
            let file = File::from(mfd);
            pwrite_all(&file, 0, bytes)?;
            let _ = crate::os_sys::seal_memfd_immutable(file.as_fd());
            self.store_payload_fd_counted(file.as_raw_fd(), bytes.len() as u64, retention_policy)
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
    }

    impl GatewayIpcClient {
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
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<u64> {
            let cmd = IpcCommand::FetchPayload {
                ephemeral_shard_ids,
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

        /// Fetches a whole file (`FetchPayload`) into a fresh memfd and returns its bytes.
        pub fn fetch_payload_bytes(
            &self,
            ephemeral_shard_ids: Vec<[u8; 32]>,
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<Vec<u8>> {
            let mfd = create_memfd("parvault-payload")?;
            let streamed = self.fetch_into_memfd(ephemeral_shard_ids, mfd.as_raw_fd(), macaroon)?;
            let mut file = File::from(mfd);
            file.seek(SeekFrom::Start(0))?;
            let mut buf = vec![0u8; streamed as usize];
            file.read_exact(&mut buf)?;
            Ok(buf)
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

        /// `QueryStatus` (item 3): the node's [`StatusSnapshot`], presenting `macaroon`. A daemon
        /// older than v0.5.0 does not know the command; that is reported as such.
        pub fn query_status(
            &self,
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<StatusSnapshot> {
            let resp = self
                .send_request_sync(&IpcCommand::QueryStatus { macaroon }, None)
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "QueryStatus failed ({e}); the daemon on {} may predate v0.5.0, which added it",
                            self.socket_path.display()
                        ),
                    )
                })?;
            match resp {
                IpcResponse::StatusSnapshot(snap) if snap.within_caps() => Ok(snap),
                IpcResponse::StatusSnapshot(_) => {
                    Err(io::Error::other("QueryStatus: snapshot over its size caps"))
                }
                IpcResponse::Error { message } => Err(io::Error::other(message)),
                other => Err(io::Error::other(format!(
                    "unexpected QueryStatus response: {other:?}"
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
        /// In-process engine (`daemon-runtime` only; item 3).
        #[cfg(feature = "daemon-runtime")]
        InProcess(Arc<GatewayEngine>),
        UnixSocket(GatewayIpcClient),
    }

    impl std::fmt::Debug for GatewayBus {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                #[cfg(feature = "daemon-runtime")]
                Self::InProcess(_) => f.write_str("GatewayBus::InProcess(..)"),
                Self::UnixSocket(client) => f
                    .debug_tuple("GatewayBus::UnixSocket")
                    .field(&client.socket_path())
                    .finish(),
            }
        }
    }

    impl GatewayBus {
        #[cfg(feature = "daemon-runtime")]
        pub fn in_process(engine: Arc<GatewayEngine>) -> Self {
            Self::InProcess(engine)
        }

        pub fn unix_socket(socket_path: impl AsRef<Path>) -> Self {
            Self::UnixSocket(GatewayIpcClient::new(socket_path))
        }
    }

    /// Asynchronous surface (`daemon-runtime`).
    #[cfg(feature = "daemon-runtime")]
    impl GatewayBus {
        /// Streams `bytes_len` bytes from `payload_fd` into the gateway (`StorePayload`).
        pub async fn store_payload_fd(
            &self,
            payload_fd: RawFd,
            bytes_len: u64,
            retention: RetentionPolicy,
        ) -> anyhow::Result<EphemeralShardManifest> {
            let (manifest, local_only_stripes) = self
                .store_payload_fd_counted(payload_fd, bytes_len, retention)
                .await?;
            crate::storage::local_only::note(local_only_stripes);
            Ok(manifest)
        }

        /// Like [`Self::store_payload_fd`], returning how many stripes stayed only on this
        /// machine (not backed up, R3-1). The in-process store runs on the blocking pool, so the
        /// count is taken there and returned rather than left in a thread-local.
        pub async fn store_payload_fd_counted(
            &self,
            payload_fd: RawFd,
            bytes_len: u64,
            retention: RetentionPolicy,
        ) -> anyhow::Result<(EphemeralShardManifest, u64)> {
            match self {
                #[cfg(feature = "daemon-runtime")]
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(payload_fd)?;
                    let eng = Arc::clone(engine);
                    let (stored, local_only_stripes) = tokio::task::spawn_blocking(move || {
                        crate::storage::local_only::track(|| {
                            eng.store_from_owned_fd(dup, bytes_len, retention)
                        })
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("in-process StorePayload join error: {e}"))?;
                    Ok((stored?, local_only_stripes))
                }
                Self::UnixSocket(client) => {
                    client
                        .store_payload_fd_counted(payload_fd, bytes_len, retention)
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
            let (manifest, local_only_stripes) = self
                .store_sealed_payload_fd_counted(fd, bytes_len, retention)
                .await?;
            crate::storage::local_only::note(local_only_stripes);
            Ok(manifest)
        }

        /// Like [`Self::store_sealed_payload_fd`], returning the local-only stripe count.
        pub async fn store_sealed_payload_fd_counted(
            &self,
            fd: RawFd,
            bytes_len: u64,
            retention: RetentionPolicy,
        ) -> anyhow::Result<(EphemeralShardManifest, u64)> {
            match self {
                #[cfg(feature = "daemon-runtime")]
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(fd)?;
                    if !crate::os_sys::has_immutable_memfd_seals(dup.as_fd())? {
                        crate::os_sys::seal_memfd_immutable(dup.as_fd())?;
                    }
                    drop(dup);
                    self.store_payload_fd_counted(fd, bytes_len, retention)
                        .await
                }
                Self::UnixSocket(client) => {
                    client
                        .store_sealed_payload_fd_counted(fd, bytes_len, retention)
                        .await
                }
            }
        }

        /// Reconstructs the full payload identified by `ephemeral_shard_ids` directly into `output_fd`.
        pub async fn fetch_payload_to_fd(
            &self,
            ephemeral_shard_ids: Vec<[u8; 32]>,
            output_fd: RawFd,
            macaroon: Option<CapabilityMacaroon>,
        ) -> anyhow::Result<u64> {
            match self {
                #[cfg(feature = "daemon-runtime")]
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(output_fd)?;
                    let eng = Arc::clone(engine);
                    tokio::task::spawn_blocking(move || {
                        eng.fetch_by_shard_ids_to_owned_fd_with_peer_uid(
                            &ephemeral_shard_ids,
                            macaroon.as_ref(),
                            Some(crate::os_sys::geteuid()),
                            dup,
                        )
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("in-process FetchPayload join error: {e}"))?
                }
                Self::UnixSocket(client) => {
                    client
                        .fetch_payload_to_fd(ephemeral_shard_ids, output_fd, macaroon)
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
                #[cfg(feature = "daemon-runtime")]
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
                #[cfg(feature = "daemon-runtime")]
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
                #[cfg(feature = "daemon-runtime")]
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    Ok(engine.health_snapshot())
                }
                Self::UnixSocket(client) => client.query_health().await,
            }
        }
    }

    impl GatewayBus {
        // --- Synchronous Blocking Surface (`FUSE`, `WebDAV`, `GatewayFolderSync`) ---

        #[cfg(feature = "daemon-runtime")]
        fn ensure_in_process_peer_uid(engine: &GatewayEngine) -> io::Result<()> {
            let uid = Some(crate::os_sys::geteuid());
            if let Err(code) = engine.peer_uid_decision(uid) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("peer UID {uid:?} rejected by strict_allowed_peer_uids policy: {code}"),
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
                #[cfg(feature = "daemon-runtime")]
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(payload_fd)?;
                    if let Err(code) = engine.ingest_seal_decision(dup.as_fd()) {
                        tracing::warn!(code, "refused an unsealed ingest memfd");
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("unsealed ingest memfd rejected (F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW required): {code}"),
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
                #[cfg(feature = "daemon-runtime")]
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
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<u64> {
            match self {
                #[cfg(feature = "daemon-runtime")]
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    let dup = crate::os_sys::dup_fd_cloexec(output_fd)?;
                    engine
                        .fetch_by_shard_ids_to_owned_fd_with_peer_uid(
                            &ephemeral_shard_ids,
                            macaroon.as_ref(),
                            Some(crate::os_sys::geteuid()),
                            dup,
                        )
                        .map_err(|e| io::Error::other(format!("FetchPayload failed: {e}")))
                }
                Self::UnixSocket(client) => {
                    client.fetch_into_memfd(ephemeral_shard_ids, output_fd, macaroon)
                }
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
                #[cfg(feature = "daemon-runtime")]
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
                #[cfg(feature = "daemon-runtime")]
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

        /// Fetches a whole file (`FetchPayload`) synchronously and returns its bytes; the token is
        /// checked against the whole file (F-47).
        pub fn fetch_payload_bytes_sync(
            &self,
            ephemeral_shard_ids: Vec<[u8; 32]>,
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<Vec<u8>> {
            match self {
                #[cfg(feature = "daemon-runtime")]
                Self::InProcess(engine) => {
                    let mfd = create_memfd("parvault-payload")?;
                    let dup = crate::os_sys::dup_fd_cloexec(mfd.as_raw_fd())?;
                    let streamed = engine
                        .fetch_by_shard_ids_to_owned_fd_with_peer_uid(
                            &ephemeral_shard_ids,
                            macaroon.as_ref(),
                            Some(crate::os_sys::geteuid()),
                            dup,
                        )
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    let mut file = File::from(mfd);
                    file.seek(SeekFrom::Start(0))?;
                    let mut buf = vec![0u8; streamed as usize];
                    file.read_exact(&mut buf)?;
                    Ok(buf)
                }
                Self::UnixSocket(client) => {
                    client.fetch_payload_bytes(ephemeral_shard_ids, macaroon)
                }
            }
        }

        /// `QueryStatus` (item 3) synchronously: in-process, the engine runs the same decision
        /// with this process's UID; over the socket, the daemon does.
        pub fn query_status_sync(
            &self,
            macaroon: Option<CapabilityMacaroon>,
        ) -> io::Result<StatusSnapshot> {
            match self {
                #[cfg(feature = "daemon-runtime")]
                Self::InProcess(engine) => engine
                    .query_status(macaroon.as_ref(), Some(crate::os_sys::geteuid()))
                    .map_err(|e| io::Error::other(e.to_string())),
                Self::UnixSocket(client) => client.query_status(macaroon),
            }
        }

        /// Registers an existing or sparse virtual `FileManifest` synchronously.
        pub fn register_manifest_sync(
            &self,
            file_manifest: FileManifest,
        ) -> io::Result<EphemeralShardManifest> {
            match self {
                #[cfg(feature = "daemon-runtime")]
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
                #[cfg(feature = "daemon-runtime")]
                Self::InProcess(engine) => {
                    Self::ensure_in_process_peer_uid(engine)?;
                    Ok(engine.health_snapshot())
                }
                Self::UnixSocket(client) => client.query_health_sync(),
            }
        }
    }
}

/// The server half lives in `gateway::server` (`daemon-runtime`; item 3); re-exported here so the
/// old paths stay valid.
#[cfg(all(unix, feature = "daemon-runtime"))]
pub use crate::gateway::server::{GatewayIpcServer, GatewayIpcServerHandle};
#[cfg(unix)]
pub use unix_impl::{
    create_memfd, create_memfd_sized, read_self_anon_rss_bytes, read_self_rss_bytes,
    recv_frame_with_optional_fd, send_frame_with_optional_fd, GatewayBus, GatewayIpcClient,
};

/// Golden wire bytes (item 3, plan-3 ruling): one fixed value per `IpcCommand` / `IpcResponse`
/// variant, encoded with the frame codec. Each row pins the variant index and the SHA-256 of
/// the bytes, so a renumbered, reordered or re-typed variant or field fails here. Run under the
/// default features and under `--no-default-features --features ipc-client` (CI does both):
/// the layout is the same in every feature set.
#[cfg(test)]
mod golden_wire {
    use super::*;
    use crate::capabilities::Caveat;
    use crate::profile::ErasureTier;

    fn tok() -> CapabilityMacaroon {
        CapabilityMacaroon {
            nonce_id: [0x11; 32],
            issuer_fingerprint: [0x22; 32],
            caveats: vec![Caveat::ReadOnly, Caveat::ExpiresAtUnixMs(7)],
            tag: [0x33; 32],
        }
    }

    fn eph() -> EphemeralShardManifest {
        EphemeralShardManifest {
            file_merkle_root: [0x44; 32],
            shard_hashes: vec![[0x55; 32], [0x66; 32]],
            total_size: 4096,
            stripe_size_bytes: 1 << 20,
        }
    }

    fn commands() -> Vec<IpcCommand> {
        vec![
            IpcCommand::StorePayload {
                payload_fd: 3,
                bytes_len: 4096,
                retention_policy: RetentionPolicy::Persistent,
            },
            IpcCommand::FetchPayload {
                ephemeral_shard_ids: vec![[0x77; 32]],
                output_fd: 4,
                macaroon: Some(tok()),
            },
            IpcCommand::FetchRange {
                manifest: eph(),
                offset: 1,
                len: 2,
                output_fd: 5,
                macaroon: None,
            },
            IpcCommand::RegisterManifest {
                file_manifest: FileManifest {
                    version: 2,
                    file_merkle_root: [0x88; 32],
                    file_salt: [0x99; 32],
                    original_file_size: 9,
                    stripe_size_bytes: 1 << 20,
                    tier: ErasureTier::Mixed,
                    stripes: Vec::new(),
                    witness_peers: vec!["w".into()],
                },
            },
            IpcCommand::QueryHealthStatus,
            IpcCommand::QueryStatus {
                macaroon: Some(tok()),
            },
        ]
    }

    fn responses() -> Vec<IpcResponse> {
        vec![
            IpcResponse::StoreSuccess { manifest: eph() },
            IpcResponse::FetchSuccess { bytes_streamed: 8 },
            IpcResponse::HealthStatus {
                iops: 1,
                peer_count: 2,
                por_sla_score: 0.5,
            },
            IpcResponse::Error {
                message: "e".into(),
            },
            IpcResponse::StoreSuccessLocalOnly {
                manifest: eph(),
                local_only_stripes: 3,
            },
            IpcResponse::StatusSnapshot(StatusSnapshot {
                version: "0.5.0".into(),
                lan_peers: vec![StatusPeerEntry {
                    peer_id: "p".into(),
                    label: "l".into(),
                    role: "r".into(),
                    multiaddr: "/ip4/127.0.0.1/tcp/1".into(),
                    available_bytes: 5,
                }],
                ..StatusSnapshot::default()
            }),
        ]
    }

    // Exhaustive (no wildcard): a new variant does not compile until it has a golden row.
    fn cmd_name(c: &IpcCommand) -> &'static str {
        match c {
            IpcCommand::StorePayload { .. } => "StorePayload",
            IpcCommand::FetchPayload { .. } => "FetchPayload",
            IpcCommand::FetchRange { .. } => "FetchRange",
            IpcCommand::RegisterManifest { .. } => "RegisterManifest",
            IpcCommand::QueryHealthStatus => "QueryHealthStatus",
            IpcCommand::QueryStatus { .. } => "QueryStatus",
        }
    }

    fn resp_name(r: &IpcResponse) -> &'static str {
        match r {
            IpcResponse::StoreSuccess { .. } => "StoreSuccess",
            IpcResponse::FetchSuccess { .. } => "FetchSuccess",
            IpcResponse::HealthStatus { .. } => "HealthStatus",
            IpcResponse::Error { .. } => "Error",
            IpcResponse::StoreSuccessLocalOnly { .. } => "StoreSuccessLocalOnly",
            IpcResponse::StatusSnapshot(_) => "StatusSnapshot",
        }
    }

    fn row(name: &str, bytes: &[u8]) -> String {
        let idx = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        format!("{name} {idx} {}", hex::encode(Sha256::digest(bytes)))
    }

    const GOLDEN: &[&str] = &[
        "cmd StorePayload 0 7b0dbf38038f7d8066e4ba2c6b92391311224d8fdd74b9ca8e177582d1655144",
        "cmd FetchPayload 1 cb9ee27d569a133d75be31d0bfd6262c40ce321ab590c9acf14d8652517a9a66",
        "cmd FetchRange 2 0f48d64bf090dec6706c52c923f99c9ebb550605bad2a329329909fcfa23d61b",
        "cmd RegisterManifest 3 bb9d2f5b2ef768d98e3f4b80ba0c63e4a4e74b14f71ac816610103854faad27e",
        "cmd QueryHealthStatus 4 fb5e512425fc9449316ec95969ebe71e2d576dbab833d61e2a5b9330fd70ee02",
        "cmd QueryStatus 5 90690e4aee4f4c975bb59f0b9edcc0b1603f1e3e871933889e314a4e5d768f64",
        "resp StoreSuccess 0 d0cbeed4caa773256e6190330f1d22bc4a0bb707981381ea504318bb9dd22d28",
        "resp FetchSuccess 1 3cf4c6d7d35690bf9cefc706492dccabc67d6e25ff145e0a681864bc0e3db0da",
        "resp HealthStatus 2 42c3ccd517cfe720bf02dd2c56c9f606cc40fbd10ff238e4d9ef3215faeda5a1",
        "resp Error 3 b7c04c4052c347008dfd50308f5eec48d49ea14b6799fbaf6766fd909f843bab",
        "resp StoreSuccessLocalOnly 4 89d1aa480b45d25c240e8e575927ccf33ddb8bdef94edaa84e56a433b1e369ad",
        "resp StatusSnapshot 5 91e96c3e3aa3aef402af076f2034354a657615f15706c1db41bc9c923896c556",
    ];

    #[test]
    fn ipc_wire_layout_matches_golden() {
        let mut got = Vec::new();
        for c in commands() {
            let b = ipc_bincode().serialize(&c).unwrap();
            let back: IpcCommand = ipc_bincode().deserialize(&b).unwrap();
            assert_eq!(ipc_bincode().serialize(&back).unwrap(), b);
            got.push(format!("cmd {}", row(cmd_name(&c), &b)));
        }
        for r in responses() {
            let b = ipc_bincode().serialize(&r).unwrap();
            let back: IpcResponse = ipc_bincode().deserialize(&b).unwrap();
            assert_eq!(back, r);
            got.push(format!("resp {}", row(resp_name(&r), &b)));
        }
        assert_eq!(got, GOLDEN, "IPC wire layout changed:\n{}", got.join("\n"));
    }
}
