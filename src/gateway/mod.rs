//! Local CPE / Host Zero-Copy Unix Domain Socket Gateway (`parvault::gateway`).

pub mod ipc;

pub use ipc::{
    validate_ipc_frame_header, EphemeralShardManifest, IpcCommand, IpcFrameError, IpcResponse,
    RetentionPolicy, DEFAULT_IPC_SOCKET_PATH, MAX_IPC_FRAME_BYTES,
};

#[cfg(unix)]
pub use ipc::{
    create_memfd, read_self_anon_rss_bytes, read_self_rss_bytes, GatewayIpcClient,
    GatewayIpcServer, GatewayIpcServerHandle,
};
