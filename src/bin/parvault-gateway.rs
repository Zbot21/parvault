//! `parvault-gateway` — Canonical CPE / Host Zero-Copy Unix Domain Socket IPC Bridge & 40-Lane
//! Single-Wave `libp2p` Mesh P2P Router (`/var/run/parvault.sock`, `Serde-Bincode` + `memfd` `SCM_RIGHTS`).

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use parvault::{
    config::{ErasureTier, HardwareProfile},
    crypto::{LocalFileKeystore, MasterKey},
    gateway::{GatewayConfig, DEFAULT_IPC_SOCKET_PATH, GATEWAY_STRIPE_BYTES},
};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "parvault-gateway",
    version,
    about = "ParVault Canonical Zero-Copy Unix Domain Socket IPC Bridge & 40-Lane Mesh P2P Router (/var/run/parvault.sock)"
)]
struct GatewayCli {
    /// Unix Domain Socket path to bind or query.
    #[arg(long, default_value = DEFAULT_IPC_SOCKET_PATH, global = true)]
    socket: PathBuf,

    /// Local shard & manifest storage directory.
    #[arg(long, default_value = "/var/lib/parvault-gateway", global = true)]
    data_dir: PathBuf,

    /// Hardware profile (`router-soc` = 1 MiB stripes / <16 MiB IPC RSS, `homelab-nas` = 4 MiB, `desktop` = 16 MiB).
    #[arg(long, value_enum, default_value_t = HardwareProfile::RouterSoc, global = true)]
    profile: HardwareProfile,

    /// Default Reed-Solomon erasure tier (`consumer`, `homelab`, `mixed`, `relay`).
    #[arg(long, value_enum, default_value_t = ErasureTier::Consumer, global = true)]
    tier: ErasureTier,

    /// Optional comma-separated remote `libp2p` peer Multiaddrs for 40-lane single-wave P2P shard distribution.
    #[arg(long, value_delimiter = ',', global = true)]
    peers: Vec<String>,

    /// Optional explicit streaming stripe size in bytes (defaults to `512 KiB` when `--peers` is set, else profile stripe size).
    #[arg(long, global = true)]
    stripe_bytes: Option<usize>,

    /// Optional 64-character hex-encoded 32-byte `K_macaroon_root` key enforcing `< 1 ms` in-RAM capability verification.
    #[arg(long, global = true)]
    macaroon_root_key_hex: Option<String>,

    #[command(subcommand)]
    command: Option<GatewayCommand>,
}

#[derive(Debug, Subcommand)]
enum GatewayCommand {
    /// Start the zero-copy `/var/run/parvault.sock` IPC listener (default action).
    Serve,
    /// Query live health status (`IpcCommand::QueryHealthStatus`) from `--socket` and emit JSON.
    #[command(visible_alias = "status")]
    Health,
    /// Execute an end-to-end `memfd` + `SCM_RIGHTS` sharding upload, 64 KiB TTFB probe, and
    /// full SHA-256 restore benchmark against `--socket`, outputting JSON metrics.
    IpcRoundtrip {
        /// Total streaming payload size in MiB.
        #[arg(long, default_value_t = 100)]
        size_mib: usize,
        /// Network interface name in `/proc/net/dev` to sample TX/RX byte deltas.
        #[arg(long, default_value = "eth0")]
        net_iface: String,
    },
    /// Run a self-contained in-process `memfd` + `SCM_RIGHTS` zero-copy round-trip smoke test.
    SelfTest,
}

fn load_or_init_gateway_master_key(data_dir: &Path) -> anyhow::Result<MasterKey> {
    std::fs::create_dir_all(data_dir)?;
    let sealer = LocalFileKeystore::from_passphrase_or_csprng_in_dir(data_dir, None)?;
    let sealed_path = data_dir.join("master_key.sealed");
    sealer.load_or_create_master_key(&sealed_path)
}

fn parse_optional_macaroon_key(hex_opt: Option<&str>) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(raw) = hex_opt.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let decoded =
        hex::decode(raw).map_err(|e| anyhow::anyhow!("invalid --macaroon-root-key-hex: {e}"))?;
    anyhow::ensure!(
        decoded.len() == 32,
        "--macaroon-root-key-hex must decode to exactly 32 bytes (got {})",
        decoded.len()
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(Some(key))
}

#[cfg(unix)]
async fn run_ipc_roundtrip_probe(
    socket_path: &Path,
    size_mib: usize,
    net_iface: &str,
) -> anyhow::Result<()> {
    use parvault::gateway::{
        create_memfd_sized, pread_full_or_eof, pwrite_all, read_self_rss_bytes, GatewayIpcClient,
        RetentionPolicy,
    };
    use parvault::os_sys::read_net_dev_bytes;
    use sha2::{Digest, Sha256};
    use std::os::fd::AsRawFd;
    use std::time::Instant;

    let total_bytes = (size_mib as u64) * 1024 * 1024;
    let client = GatewayIpcClient::new(socket_path);
    let (rx_before, tx_before) = read_net_dev_bytes(net_iface).unwrap_or((0, 0));

    // 1. Stream deterministic pseudo-random bytes into anonymous memfd in 1 MiB chunks (< 16 MiB RSS).
    let in_mfd = create_memfd_sized("parvault-gate-in", total_bytes)?;
    let in_file = std::fs::File::from(in_mfd);
    let mut chunk = vec![0u8; GATEWAY_STRIPE_BYTES];
    let mut in_hasher = Sha256::new();
    let mut rng_state = 0xCAFE_BABE_1337_4242u64;
    let mut written = 0u64;
    while written < total_bytes {
        let len = ((total_bytes - written) as usize).min(GATEWAY_STRIPE_BYTES);
        for word in chunk[..len].as_chunks_mut::<8>().0 {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            word.copy_from_slice(&rng_state.to_le_bytes());
        }
        in_hasher.update(&chunk[..len]);
        pwrite_all(&in_file, written, &chunk[..len])?;
        written += len as u64;
    }
    let sha256_in = hex::encode(in_hasher.finalize());

    // 2. StorePayload via SCM_RIGHTS zero-copy FD pass -> Reed-Solomon sharding.
    let t_store = Instant::now();
    let manifest = client
        .store_payload_fd(
            in_file.as_raw_fd(),
            total_bytes,
            RetentionPolicy::Persistent,
        )
        .await?;
    let upload_ms = t_store.elapsed().as_secs_f64() * 1000.0;
    drop(in_file); // Release local source memfd prior to network reconstruction.

    // 3. Measure real Time-To-First-Byte (TTFB) fetching a 64 KiB slice over network sockets.
    let ttfb_len = 65_536u64.min(total_bytes);
    let ttfb_mfd = create_memfd_sized("parvault-ttfb", ttfb_len)?;
    let ttfb_file = std::fs::File::from(ttfb_mfd);
    let t_ttfb = Instant::now();
    let ttfb_bytes = client
        .fetch_range_to_fd(manifest.clone(), 0, ttfb_len, ttfb_file.as_raw_fd(), None)
        .await?;
    let ttfb_ms = t_ttfb.elapsed().as_secs_f64() * 1000.0;
    anyhow::ensure!(ttfb_bytes == ttfb_len, "TTFB slice incomplete");
    drop(ttfb_file);

    // 4. Full payload reconstruction into fresh memfd & streaming SHA-256 verification.
    let out_mfd = create_memfd_sized("parvault-gate-out", total_bytes)?;
    let out_file = std::fs::File::from(out_mfd);
    let t_restore = Instant::now();
    let restored_bytes = client
        .fetch_payload_to_fd(manifest.shard_hashes.clone(), out_file.as_raw_fd())
        .await?;
    let restore_ms = t_restore.elapsed().as_secs_f64() * 1000.0;
    anyhow::ensure!(
        restored_bytes == total_bytes,
        "restored {restored_bytes} != expected {total_bytes}"
    );

    let mut out_hasher = Sha256::new();
    let mut rd_off = 0u64;
    while rd_off < total_bytes {
        let len = ((total_bytes - rd_off) as usize).min(GATEWAY_STRIPE_BYTES);
        let n = pread_full_or_eof(&out_file, rd_off, &mut chunk[..len])?;
        anyhow::ensure!(n == len, "short pread from restored memfd");
        out_hasher.update(&chunk[..n]);
        rd_off += n as u64;
    }
    let sha256_out = hex::encode(out_hasher.finalize());
    anyhow::ensure!(
        sha256_in == sha256_out,
        "SHA-256 mismatch: in={sha256_in} out={sha256_out}"
    );

    let (rx_after, tx_after) = read_net_dev_bytes(net_iface).unwrap_or((0, 0));
    let tx_delta = tx_after.saturating_sub(tx_before);
    let rx_delta = rx_after.saturating_sub(rx_before);
    let vm_rss_bytes = read_self_rss_bytes();

    println!(
        "{}",
        serde_json::json!({
            "size_bytes": total_bytes,
            "sha256_in": sha256_in,
            "sha256_out": sha256_out,
            "bit_for_bit_verified": true,
            "ttfb_ms": ttfb_ms,
            "upload_ms": upload_ms,
            "restore_ms": restore_ms,
            "iface": net_iface,
            "tx_bytes_delta": tx_delta,
            "rx_bytes_delta": rx_delta,
            "client_vm_rss_bytes": vm_rss_bytes,
            "shard_count": manifest.shard_hashes.len()
        })
    );
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = GatewayCli::parse();
    let action = cli.command.unwrap_or(GatewayCommand::Serve);

    #[cfg(not(unix))]
    {
        let _ = (
            &cli.socket,
            &cli.data_dir,
            &cli.profile,
            &cli.tier,
            &cli.peers,
            &cli.stripe_bytes,
            &cli.macaroon_root_key_hex,
            &action,
            load_or_init_gateway_master_key,
            parse_optional_macaroon_key,
        );
        anyhow::bail!("parvault-gateway requires Unix Domain Sockets (Linux / Unix)");
    }

    #[cfg(unix)]
    {
        use parvault::{
            gateway::{
                create_memfd, pread_full_or_eof, pwrite_all, read_self_rss_bytes, GatewayEngine,
                GatewayIpcClient, GatewayIpcServer, RetentionPolicy,
            },
            storage::{BlockStore, QuotaManager},
        };
        use std::os::fd::AsRawFd;
        use std::sync::Arc;
        use tokio::sync::watch;

        match action {
            GatewayCommand::Health => {
                let client = GatewayIpcClient::new(&cli.socket);
                let (iops, peer_count, por_sla_score) = client.query_health().await?;
                println!(
                    "{}",
                    serde_json::json!({
                        "socket": cli.socket.display().to_string(),
                        "iops": iops,
                        "peer_count": peer_count,
                        "por_sla_score": por_sla_score
                    })
                );
            }
            GatewayCommand::IpcRoundtrip {
                size_mib,
                net_iface,
            } => {
                run_ipc_roundtrip_probe(&cli.socket, size_mib, &net_iface).await?;
            }
            GatewayCommand::SelfTest => {
                struct TempDirGuard(PathBuf);
                impl Drop for TempDirGuard {
                    fn drop(&mut self) {
                        let _ = std::fs::remove_dir_all(&self.0);
                    }
                }
                let mut nonce = [0u8; 6];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
                let tmp_dir = std::env::temp_dir().join(format!(
                    "parvault_gw_selftest_{}_{}",
                    std::process::id(),
                    hex::encode(nonce)
                ));
                std::fs::create_dir_all(&tmp_dir)?;
                let _guard = TempDirGuard(tmp_dir.clone());
                let sock = tmp_dir.join("parvault_selftest.sock");
                let store_dir = tmp_dir.join("store");
                let quota = QuotaManager::new(512 * 1024 * 1024, 64 * 1024 * 1024);
                let store = BlockStore::new(&store_dir, quota)?;
                let mk = MasterKey::generate();
                let mut srv = GatewayIpcServer::new(&sock, store, mk)
                    .with_profile(HardwareProfile::RouterSoc)
                    .spawn()?;

                let client = GatewayIpcClient::new(&sock);
                let in_mfd = create_memfd("selftest-in")?;
                let in_file = std::fs::File::from(in_mfd);
                let sample = vec![0x5Au8; 2 * 1024 * 1024];
                pwrite_all(&in_file, 0, &sample)?;

                let manifest = client.store_memfd(
                    in_file.as_raw_fd(),
                    sample.len() as u64,
                    RetentionPolicy::Ephemeral,
                )?;

                let out_mfd = create_memfd("selftest-out")?;
                let out_file = std::fs::File::from(out_mfd);
                let streamed =
                    client.fetch_into_memfd(manifest.shard_hashes.clone(), out_file.as_raw_fd())?;
                assert_eq!(streamed, sample.len() as u64);
                let mut roundtrip = vec![0u8; sample.len()];
                let read_n = pread_full_or_eof(&out_file, 0, &mut roundtrip)?;
                assert_eq!(read_n, sample.len());
                srv.shutdown();
                if roundtrip != sample {
                    anyhow::bail!("parvault-gateway self-test payload mismatch");
                }
                let rss_mib = read_self_rss_bytes() as f64 / (1024.0 * 1024.0);
                println!(
                    "parvault-gateway self-test: PASS (2 MiB memfd SCM_RIGHTS round-trip verified, RSS={rss_mib:.2} MiB)"
                );
            }
            GatewayCommand::Serve => {
                std::fs::create_dir_all(&cli.data_dir)?;
                let mk = load_or_init_gateway_master_key(&cli.data_dir)?;
                let macaroon_root_key =
                    parse_optional_macaroon_key(cli.macaroon_root_key_hex.as_deref())?;
                let peers: Vec<String> = cli
                    .peers
                    .iter()
                    .flat_map(|s| s.split(','))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let stripe_size_bytes = cli.stripe_bytes.unwrap_or_else(|| {
                    if peers.is_empty() {
                        cli.profile.stripe_size_bytes()
                    } else {
                        512 * 1024
                    }
                });
                let cfg = GatewayConfig {
                    stripe_size_bytes,
                    tier: cli.tier,
                    peers: peers.clone(),
                    macaroon_root_key,
                };
                let engine = Arc::new(GatewayEngine::new(&cli.data_dir, mk, cfg)?);
                if !peers.is_empty() {
                    let warm_ref = Arc::clone(&engine);
                    tokio::task::spawn_blocking(move || warm_ref.warm_mesh_connections()).await?;
                }
                let server = GatewayIpcServer::bind(&cli.socket, engine)?;
                println!(
                    "[parvault-gateway] listening on {} (profile={}, stripe={} B, peers={})",
                    cli.socket.display(),
                    cli.profile,
                    stripe_size_bytes,
                    peers.len()
                );
                let (tx, rx) = watch::channel(false);
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = tx.send(true);
                });
                server.serve(rx).await?;
            }
        }
        Ok(())
    }
}
