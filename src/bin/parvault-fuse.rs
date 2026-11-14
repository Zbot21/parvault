//! `parvault-fuse` — Canonical Open-Source Reference Plugin & Lazy-Streaming Virtual File System
//! Client for `parvault` (`/var/run/parvault.sock`, `docs/GATEWAY_SOCKET_PROTOCOL.md`).
//!
//! Packaged as a standalone static-`musl` plugin binary (zero C `libfuse3` dependency) so it can
//! run under a dedicated unprivileged UID (`parvault up --strict-plugins --allow-peer-uid <UID>`)
//! while isolating `/dev/fuse`, `fusermount3`, and LAN HTTP/WebDAV ports from `MasterKey` memory.
//!
//! Supports three operational modes over the exact same lazy `FetchRange` + LRU block cache engine:
//! 1. `mount-fd`: Pure-Rust Linux `/dev/fuse` kernel VFS loop (`ABI 7.31`, zero C `libfuse` dependency).
//! 2. `webdav`: Unprivileged HTTP `Range` (`206 Partial Content`) + WebDAV (`PROPFIND`) LAN drive
//!    for locked-down `prplOS` / `RDK-B` LXC containers lacking `/dev/fuse`.
//! 3. `sync`: Userspace folder push/ingest over `/var/run/parvault.sock` via sealed `memfd` `SCM_RIGHTS`.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use parvault::gateway::ipc::DEFAULT_IPC_SOCKET_PATH;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "parvault-fuse",
    version,
    about = "ParVault Canonical Reference Plugin: Lazy-Streaming VFS (/dev/fuse, HTTP-Range/WebDAV & Userspace Sync over /var/run/parvault.sock)"
)]
struct FuseCli {
    /// Path to the `parvault` Unix Domain Socket (`parvault up --ipc-socket ...`).
    #[arg(long, default_value = DEFAULT_IPC_SOCKET_PATH, global = true)]
    socket: PathBuf,

    /// Local directory for the bounded LRU block cache.
    #[arg(long, default_value = "./parvault-vfs-cache", global = true)]
    cache_dir: PathBuf,

    /// Maximum local LRU disk cache capacity in MiB.
    #[arg(long, default_value_t = 64, global = true)]
    cache_mib: u64,

    /// Optional `PARVAULT-MAC-V1:` attenuated capability macaroon presented on lazy `FetchRange` reads.
    /// Visible to every local user in the process list (`/proc/<pid>/cmdline`); prefer `--macaroon-file`.
    #[arg(long, global = true, value_name = "PARVAULT-MAC-V1:...")]
    macaroon: Option<String>,

    /// File holding the token (mode 600; refused if group or others can read it).
    #[arg(long, value_name = "PATH", global = true)]
    macaroon_file: Option<PathBuf>,

    #[command(subcommand)]
    command: FuseCommand,
}

#[derive(Debug, Subcommand)]
enum FuseCommand {
    /// Serve the pure-Rust Linux `/dev/fuse` wire protocol over an open `/dev/fuse` descriptor (`--fuse-fd`).
    MountFd {
        /// Open `/dev/fuse` file descriptor number (e.g. passed by `fusermount3` or container init).
        #[arg(long)]
        fuse_fd: i32,
        /// Optional local seed directory to ingest & expose as metadata stubs on startup.
        #[arg(long)]
        seed_dir: Option<PathBuf>,
    },
    /// Serve an unprivileged HTTP `Range` (`206 Partial Content`) + WebDAV (`PROPFIND`) virtual drive.
    Webdav {
        /// TCP address to bind (e.g. `127.0.0.1:4918` or `0.0.0.0:4918`).
        #[arg(long, default_value = "127.0.0.1:4918")]
        listen: String,
        /// Optional local directory to ingest into `parvault` and expose lazily.
        #[arg(long)]
        seed_dir: Option<PathBuf>,
    },
    /// Ingest a local folder into `parvault` via sealed zero-copy `memfd` `SCM_RIGHTS`.
    Sync {
        /// Local directory to ingest.
        #[arg(long)]
        folder: PathBuf,
    },
    /// Self-test against the daemon on `--socket` (presents `--macaroon`): `< 50 ms` TTFB lazy
    /// range streaming and LRU cache eviction.
    SelfTest,
}

fn main() -> anyhow::Result<()> {
    // Refusals (e.g. F-43 WebDAV reason codes) are logged through `tracing`.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("parvault=info,warn")),
        )
        .init();
    let cli = FuseCli::parse();
    let default_macaroon = parvault::capabilities::token_from_args(
        cli.macaroon.as_deref(),
        cli.macaroon_file.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    #[cfg(not(unix))]
    {
        let _ = (&cli, &default_macaroon);
        anyhow::bail!("parvault-fuse requires Unix Domain Sockets (Linux / Unix)");
    }

    #[cfg(unix)]
    {
        use parvault::{
            gateway::ipc::{create_memfd, GatewayIpcClient, RetentionPolicy},
            vfs::VirtualVaultFs,
        };
        use std::io::{Seek, SeekFrom, Write};
        use std::os::fd::AsRawFd;

        let cache_bytes = cli.cache_mib.saturating_mul(1024 * 1024);

        match cli.command {
            FuseCommand::MountFd { fuse_fd, seed_dir } => {
                if fuse_fd < 0 {
                    anyhow::bail!("invalid --fuse-fd {fuse_fd}");
                }
                let vfs = VirtualVaultFs::new(&cli.socket, &cli.cache_dir, cache_bytes)?
                    .with_default_macaroon(default_macaroon);
                if let Some(dir) = seed_dir {
                    let count = vfs.ingest_local_directory(&dir)?;
                    eprintln!(
                        "[parvault-fuse] ingested {count} lazy-loaded file inode(s) from {}",
                        dir.display()
                    );
                }
                let dev_file = parvault::os_sys::adopt_fuse_dev_fd(fuse_fd)?;
                vfs.serve_fuse_fd_blocking(dev_file)?;
            }
            FuseCommand::Webdav { listen, seed_dir } => {
                // F-43 (L-44): every request must present this token or an offline attenuation
                // of it; the plugin holds no root key, so there is no server without one.
                let pinned = default_macaroon.clone().ok_or_else(|| {
                    anyhow::anyhow!("webdav needs --macaroon: every request must present it or an attenuation of it (F-43)")
                })?;
                let vfs = VirtualVaultFs::new(&cli.socket, &cli.cache_dir, cache_bytes)?
                    .with_default_macaroon(default_macaroon);
                if let Some(dir) = seed_dir {
                    let count = vfs.ingest_local_directory(&dir)?;
                    println!(
                        "[parvault-fuse] mounted {count} file(s) from {}",
                        dir.display()
                    );
                }
                let handle = vfs.spawn_webdav_server(
                    &listen,
                    parvault::vfs::WebdavVerifier::PinnedParent(pinned),
                )?;
                println!(
                    "[parvault-fuse] serving HTTP-Range / WebDAV VFS on http://{} (gateway={})",
                    handle.local_addr(),
                    cli.socket.display()
                );
                handle.wait();
            }
            FuseCommand::Sync { folder } => {
                let vfs = VirtualVaultFs::new(&cli.socket, &cli.cache_dir, cache_bytes)?
                    .with_default_macaroon(default_macaroon);
                let count = vfs.ingest_local_directory(&folder)?;
                println!(
                    "[parvault-fuse] synced {count} file(s) from {} over {}",
                    folder.display(),
                    cli.socket.display()
                );
            }
            FuseCommand::SelfTest => {
                // Client-only (item 3): runs against the daemon on `--socket`, presenting
                // `--macaroon` when the gateway has a root key. The in-process variant lives in
                // tests/plugin_self_test.rs.
                struct TempDirGuard(PathBuf);
                impl Drop for TempDirGuard {
                    fn drop(&mut self) {
                        let _ = std::fs::remove_dir_all(&self.0);
                    }
                }
                let mut nonce = [0u8; 6];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
                let tmp_dir = std::env::temp_dir().join(format!(
                    "parvault_vfs_selftest_{}_{}",
                    std::process::id(),
                    hex::encode(nonce)
                ));
                std::fs::create_dir_all(&tmp_dir)?;
                let _guard = TempDirGuard(tmp_dir.clone());

                let client = GatewayIpcClient::new(&cli.socket);
                let mfd = create_memfd("vfs-selftest")?;
                let mut f = std::fs::File::from(mfd);
                let payload: Vec<u8> = (0..(4 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
                f.write_all(&payload)?;
                f.seek(SeekFrom::Start(0))?;
                let manifest = client
                    .store_sealed_memfd(
                        f.as_raw_fd(),
                        payload.len() as u64,
                        RetentionPolicy::Persistent,
                    )
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "self-test needs a running daemon on {} (`parvault up --ipc-socket` or `parvault gateway serve`): {e}",
                            cli.socket.display()
                        )
                    })?;

                // Cap cache at 2 MiB and read 4 MiB across blocks to verify LRU eviction + <50ms TTFB.
                let vfs = VirtualVaultFs::new(&cli.socket, tmp_dir.join("cache"), 2 * 1024 * 1024)?
                    .with_default_macaroon(default_macaroon);
                let ino = vfs.register_stub_file("/vault/test.bin", manifest, None)?;
                let (slice, ttfb) =
                    vfs.read_range_with_ttfb(ino, 1024 * 1024 + 17, 2 * 1024 * 1024)?;
                anyhow::ensure!(
                    slice == payload[1024 * 1024 + 17..3 * 1024 * 1024 + 17],
                    "range bytes differ"
                );
                let stats = vfs.cache_stats();
                anyhow::ensure!(stats.used_bytes <= 2 * 1024 * 1024, "cache over its cap");
                anyhow::ensure!(stats.evictions >= 1, "no LRU eviction");
                println!(
                    "parvault-fuse self-test: PASS (TTFB={:.2} ms < 50 ms, cache_used={} B, evictions={})",
                    ttfb.as_secs_f64() * 1000.0,
                    stats.used_bytes,
                    stats.evictions
                );
            }
        }
        Ok(())
    }
}
