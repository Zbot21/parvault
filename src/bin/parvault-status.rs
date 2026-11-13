//! `parvault-status`: the status page as a separate process (item 3, plan-3 option A).
//!
//! It holds no key. It pins one read-only token (`--macaroon-file`, or `--macaroon`): a browser or script must present
//! that token or an offline attenuation of it, only in the `Authorization` header (L-52), and
//! the page checks it with `http_edge::status_auth_decision` (Host check included) before
//! asking the daemon for the snapshot over the gateway socket with the same token. Built with
//! `--no-default-features --features status-ui`: no tokio, no libp2p.
#![forbid(unsafe_code)]

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "parvault-status",
    version,
    about = "ParVault status page sidecar: serves the daemon's status over HTTP to token holders"
)]
struct StatusCli {
    /// The daemon's gateway socket (`parvault up --ipc-socket ...`).
    #[arg(long, default_value = parvault::gateway::ipc::DEFAULT_IPC_SOCKET_PATH)]
    socket: PathBuf,

    /// Address to serve the status page on (e.g. `127.0.0.1:4080`). Required: no default.
    #[arg(long, value_name = "ADDR")]
    listen: SocketAddr,

    /// The pinned read-only `PARVAULT-MAC-V1:` token (`parvault token mint --read-only`).
    /// Requests must present it or an offline attenuation of it.
    /// Visible to every local user in the process list (`/proc/<pid>/cmdline`); prefer `--macaroon-file`.
    #[arg(
        long,
        value_name = "PARVAULT-MAC-V1:...",
        required_unless_present = "macaroon_file"
    )]
    macaroon: Option<String>,

    /// File holding the pinned token (mode 600; refused if group or others can read it).
    #[arg(long, value_name = "PATH")]
    macaroon_file: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("parvault=info,warn")),
        )
        .init();
    let cli = StatusCli::parse();
    let pinned = parvault::capabilities::token_from_args(
        cli.macaroon.as_deref(),
        cli.macaroon_file.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!(e))?
    .ok_or_else(|| anyhow::anyhow!("--macaroon or --macaroon-file is required"))?;

    // Fail at start, not on the first request: the daemon must know QueryStatus and accept
    // the pinned token.
    let client = parvault::gateway::ipc::GatewayIpcClient::new(&cli.socket);
    client.query_status(Some(pinned.clone())).map_err(|e| {
        anyhow::anyhow!(
            "parvault-status: cannot read status from {}: {e}",
            cli.socket.display()
        )
    })?;

    let (bound, handle) = parvault::router_nas::RouterNasStatusServer::bind_and_spawn(
        cli.listen,
        parvault::gateway::ipc::GatewayBus::unix_socket(&cli.socket),
        parvault::http_edge::EdgeVerifier::PinnedParent(pinned),
    )?;
    println!(
        "[parvault-status] Status Server listening on http://{bound} (gateway={})",
        cli.socket.display()
    );
    handle.wait();
    Ok(())
}
