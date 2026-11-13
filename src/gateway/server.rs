//! Gateway IPC server: the socket listener, per-connection loop and command dispatch onto
//! `GatewayEngine` (`daemon-runtime`). Split from `gateway::ipc` in item 3; `gateway::ipc`
//! re-exports `GatewayIpcServer` and `GatewayIpcServerHandle`.

use crate::crypto::MasterKey;
use crate::gateway::engine::GatewayEngine;
use crate::gateway::ipc::*;
use crate::gateway::shm::{recv_frame_with_fd, send_frame_with_fd};
use crate::profile::{ErasureTier, HardwareProfile};
use crate::storage::BlockStore;
use bincode::Options;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::{UnixListener as TokioUnixListener, UnixStream as TokioUnixStream};
use tokio::sync::watch;

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
                    if let Err(code) = engine.peer_uid_decision(peer_uid) {
                        tracing::warn!(code, ?peer_uid, "refused a gateway client by peer UID");
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
                    if let Err(code) = self.engine.peer_uid_decision(peer_uid) {
                        tracing::warn!(code, ?peer_uid, "refused a gateway client by peer UID");
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
            if let Err(code) = engine.ingest_seal_decision(owned_fd.as_fd()) {
                tracing::warn!(code, "refused an unsealed ingest memfd");
                return IpcResponse::Error {
                    message: format!("unsealed ingest memfd rejected (F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW required): {code}"),
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
            macaroon,
            ..
        } => {
            let Some(owned_fd) = maybe_fd else {
                return IpcResponse::Error {
                    message: "FetchPayload missing SCM_RIGHTS output_fd".into(),
                };
            };
            match engine.fetch_by_shard_ids_to_owned_fd_with_peer_uid(
                &ephemeral_shard_ids,
                macaroon.as_ref(),
                peer_uid,
                owned_fd,
            ) {
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
