//! Canonical Local CPE / Host Zero-Copy Unix Domain Socket Gateway (`parvault::gateway`).

pub mod engine;
pub mod ipc;
#[cfg(unix)]
pub mod shm;

pub use engine::{GatewayConfig, PinnedRingBudget, GATEWAY_STRIPE_BYTES, MESH_POOL_CONCURRENCY};
pub use ipc::{
    hash_shard_id_vector, validate_ipc_frame_header, EphemeralShardManifest, IpcCommand,
    IpcFrameError, IpcResponse, RetentionPolicy, DEFAULT_IPC_SOCKET_PATH, MAX_IPC_FRAME_BYTES,
};

#[cfg(unix)]
pub use engine::GatewayEngine;
#[cfg(unix)]
pub use ipc::{
    create_memfd, create_memfd_sized, read_self_anon_rss_bytes, read_self_rss_bytes,
    GatewayIpcClient, GatewayIpcServer, GatewayIpcServerHandle,
};
#[cfg(unix)]
pub use shm::{pread_full_or_eof, pwrite_all, recv_frame_with_fd, send_frame_with_fd};
