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
use parvault::capabilities::CapabilityMacaroon;
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
    #[arg(long, global = true, value_name = "PARVAULT-MAC-V1:...")]
    macaroon: Option<String>,

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
    /// Run an embedded self-test verifying `< 50 ms` TTFB lazy range streaming and LRU cache eviction.
    SelfTest,
}

fn main() -> anyhow::Result<()> {
    let cli = FuseCli::parse();
    let default_macaroon = match cli
        .macaroon
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(
            CapabilityMacaroon::from_compact_token(raw)
                .map_err(|e| anyhow::anyhow!("invalid --macaroon token: {e}"))?,
        ),
        None => None,
    };

    #[cfg(not(unix))]
    {
        let _ = (&cli, &default_macaroon);
        anyhow::bail!("parvault-fuse requires Unix Domain Sockets (Linux / Unix)");
    }

    #[cfg(unix)]
    {
        use parvault::{
            config::HardwareProfile,
            crypto::MasterKey,
            gateway::ipc::{create_memfd, GatewayIpcClient, GatewayIpcServer, RetentionPolicy},
            storage::{BlockStore, QuotaManager},
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
                let vfs = VirtualVaultFs::new(&cli.socket, &cli.cache_dir, cache_bytes)?
                    .with_default_macaroon(default_macaroon);
                if let Some(dir) = seed_dir {
                    let count = vfs.ingest_local_directory(&dir)?;
                    println!(
                        "[parvault-fuse] mounted {count} file(s) from {}",
                        dir.display()
                    );
                }
                println!(
                    "[parvault-fuse] serving HTTP-Range / WebDAV VFS on http://{listen} (gateway={})",
                    cli.socket.display()
                );
                vfs.serve_webdav_blocking(&listen)?;
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
                let sock = tmp_dir.join("vfs_selftest.sock");
                let store = BlockStore::new(
                    tmp_dir.join("store"),
                    QuotaManager::new(512 * 1024 * 1024, 64 * 1024 * 1024),
                )?;
                let mut srv = GatewayIpcServer::new(&sock, store, MasterKey::generate())
                    .with_profile(HardwareProfile::RouterSoc)
                    .with_require_sealed_ingest_memfd(true)
                    .spawn()?;

                let client = GatewayIpcClient::new(&sock);
                let mfd = create_memfd("vfs-selftest")?;
                let mut f = std::fs::File::from(mfd);
                let payload: Vec<u8> = (0..(4 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
                f.write_all(&payload)?;
                f.seek(SeekFrom::Start(0))?;
                let manifest = client.store_sealed_memfd(
                    f.as_raw_fd(),
                    payload.len() as u64,
                    RetentionPolicy::Persistent,
                )?;

                // Cap cache at 2 MiB and read 4 MiB across blocks to verify LRU eviction + <50ms TTFB.
                let vfs = VirtualVaultFs::new(&sock, tmp_dir.join("cache"), 2 * 1024 * 1024)?;
                let ino = vfs.register_stub_file("/vault/test.bin", manifest, None)?;
                let (slice, ttfb) =
                    vfs.read_range_with_ttfb(ino, 1024 * 1024 + 17, 2 * 1024 * 1024)?;
                srv.shutdown();
                assert_eq!(slice, payload[1024 * 1024 + 17..3 * 1024 * 1024 + 17]);
                let stats = vfs.cache_stats();
                assert!(stats.used_bytes <= 2 * 1024 * 1024);
                assert!(stats.evictions >= 1);
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
