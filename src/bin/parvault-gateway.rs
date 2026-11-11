//! `parvault-gateway` — Local CPE / Host Zero-Copy Unix Domain Socket IPC Bridge
//! (`/var/run/parvault.sock`, `Serde-Bincode` + `memfd` `SCM_RIGHTS`).

use clap::{Parser, Subcommand};
use parvault::{
    config::{ErasureTier, HardwareProfile, NodeConfig},
    crypto::{LocalFileKeystore, MasterKey, NodeIdentity},
    gateway::ipc::DEFAULT_IPC_SOCKET_PATH,
    network::MeshClient,
    storage::{BlockStore, QuotaManager},
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "parvault-gateway",
    version,
    about = "ParVault Zero-Copy Unix Domain Socket IPC Bridge (/var/run/parvault.sock + memfd SCM_RIGHTS)"
)]
struct GatewayCli {
    /// Unix Domain Socket path to bind.
    #[arg(long, default_value = DEFAULT_IPC_SOCKET_PATH)]
    socket: PathBuf,

    /// Local shard & manifest storage directory.
    #[arg(long, default_value = "./parvault-gateway-data")]
    data_dir: PathBuf,

    /// Hardware profile (`router-soc` = 1 MiB stripes / <16 MiB IPC RSS, `homelab-nas` = 4 MiB, `desktop` = 16 MiB).
    #[arg(long, value_enum, default_value_t = HardwareProfile::RouterSoc)]
    profile: HardwareProfile,

    /// Default Reed-Solomon erasure tier.
    #[arg(long, value_enum, default_value_t = ErasureTier::Consumer)]
    tier: ErasureTier,

    /// Optional comma-separated remote `libp2p` peer Multiaddrs for real TCP/Noise shard distribution.
    #[arg(long, value_delimiter = ',')]
    peers: Vec<String>,

    #[command(subcommand)]
    command: Option<GatewayCommand>,
}

#[derive(Debug, Subcommand)]
enum GatewayCommand {
    /// Start the zero-copy `/var/run/parvault.sock` IPC listener (default action).
    Serve,
    /// Query live health status (`IpcCommand::QueryHealthStatus`) from a running gateway socket.
    Status,
    /// Run a self-contained in-process `memfd` + `SCM_RIGHTS` zero-copy round-trip smoke test.
    SelfTest,
}

fn load_or_init_gateway_master_key(data_dir: &std::path::Path) -> anyhow::Result<MasterKey> {
    std::fs::create_dir_all(data_dir)?;
    let sealer = LocalFileKeystore::from_passphrase_or_csprng_in_dir(data_dir, None)?;
    let sealed_path = data_dir.join("master_key.sealed");
    sealer.load_or_create_master_key(&sealed_path)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = GatewayCli::parse();
    let action = cli.command.unwrap_or(GatewayCommand::Serve);

    #[cfg(not(unix))]
    {
        let _ = (&cli, &action);
        anyhow::bail!("parvault-gateway requires Unix Domain Sockets (Linux / Unix)");
    }

    #[cfg(unix)]
    {
        use parvault::gateway::ipc::{
            create_memfd, read_self_rss_bytes, GatewayIpcClient, GatewayIpcServer, RetentionPolicy,
        };
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::AsRawFd;

        match action {
            GatewayCommand::Status => {
                let client = GatewayIpcClient::new(&cli.socket);
                let (iops, peer_count, por_sla_score) = client.query_health()?;
                println!(
                    "{{\"socket\":\"{}\",\"iops\":{iops},\"peer_count\":{peer_count},\"por_sla_score\":{por_sla_score:.4}}}",
                    cli.socket.display()
                );
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
                let mut in_file = std::fs::File::from(in_mfd);
                let sample = vec![0x5Au8; 2 * 1024 * 1024];
                in_file.write_all(&sample)?;
                in_file.seek(SeekFrom::Start(0))?;

                let manifest = client.store_memfd(
                    in_file.as_raw_fd(),
                    sample.len() as u64,
                    RetentionPolicy::Ephemeral,
                )?;

                let out_mfd = create_memfd("selftest-out")?;
                let streamed =
                    client.fetch_into_memfd(manifest.shard_hashes.clone(), out_mfd.as_raw_fd())?;
                assert_eq!(streamed, sample.len() as u64);
                let mut out_file = std::fs::File::from(out_mfd);
                out_file.seek(SeekFrom::Start(0))?;
                let mut roundtrip = Vec::new();
                out_file.read_to_end(&mut roundtrip)?;
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
                let mut cfg = NodeConfig::default();
                cfg.apply_hardware_profile(cli.profile);
                std::fs::create_dir_all(&cli.data_dir)?;
                let identity = NodeIdentity::load_or_generate_in_dir(&cli.data_dir)?;
                let mk = load_or_init_gateway_master_key(&cli.data_dir)?;
                let mut quota = QuotaManager::with_persistence_dir(
                    cfg.max_storage_bytes,
                    10 * 1024 * 1024 * 1024,
                    &cli.data_dir,
                );
                quota.set_min_free_disk_bytes(cli.profile.min_free_disk_bytes());
                let mut store = BlockStore::new(&cli.data_dir, quota)?
                    .with_stripe_size_bytes(cli.profile.stripe_size_bytes());
                if !cli.peers.is_empty() {
                    let mesh_client = MeshClient::new(identity, cli.peers.clone(), None);
                    store = store.with_mesh_client(mesh_client);
                }
                let _handle = GatewayIpcServer::new(&cli.socket, store, mk)
                    .with_profile(cli.profile)
                    .with_tier(cli.tier)
                    .spawn()?;
                println!(
                    "[parvault-gateway] listening on {} (profile={}, stripe={} B)",
                    cli.socket.display(),
                    cli.profile,
                    cli.profile.stripe_size_bytes()
                );
                tokio::signal::ctrl_c().await?;
            }
        }
        Ok(())
    }
}
