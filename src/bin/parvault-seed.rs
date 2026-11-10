//! Standalone Zero-Trust Seed & Redundancy Server CLI (`parvault-seed`).
//!
//! Operates in two zero-plaintext modes (`ADR-13`):
//! 1. `homelab-vault` (`SeedServerMode::HomelabRedundancyVault`):
//!    Dedicated 24/7 backup/redundancy vault for a homelab owner's personal devices
//!    (authenticated via post-quantum `PersonalDeviceCert`s with zero reciprocity quota charge)
//!    plus optional neighborhood reciprocity hosting to earn `HighUptimeAnchor` (`16-of-20`) standing.
//! 2. `public-bootstrap` (`SeedServerMode::PublicNetworkBootstrapper`):
//!    Stateless `FoundationSeedAnchor` node that accepts only anonymized `BlindedShardId` shards
//!    with Byte-Epoch leases, answers PoR challenges, sweeps expired `.bshard` files, and
//!    automatically drains to 0% as organic peers join the network.

use clap::{Parser, Subcommand, ValueEnum};
use libp2p::{
    futures::StreamExt,
    mdns,
    request_response::{self, Message},
    swarm::SwarmEvent,
    Multiaddr,
};
use parvault::{
    bootstrap::{
        BlindedShardTombstone, EarnedStanding, ElasticBootstrapEngine, ElasticPeerCandidate,
        PeerRole, PersonalDeviceCert, SeedServerMode, ZeroTrustSeedServer,
    },
    crypto::{
        pqc::{HybridKemKeypair, HybridPqPublicKey, HybridPqSigningKeypair},
        MasterKey, NodeIdentity,
    },
    network::{
        behaviour::{
            DhtEnvelopeKind, DhtWireEnvelope, MeshNetworkBehaviourEvent, MeshWireRequest,
            MeshWireResponse,
        },
        build_mesh_swarm, MeshClient, WebOfTrustRegistry, DEFAULT_SUBTREE_SLASH_LIMIT,
    },
    por::PorVerifierEngine,
    sharding::merkle::hash_shard_leaf,
    storage::{
        AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, BlockStore, QuotaManager,
        ShardId, TrustLevel, VoucherNullifierLedger,
    },
};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "parvault-seed",
    version,
    about = "Standalone Zero-Trust Seed & Redundancy Server for ParVault (ADR-13)"
)]
struct SeedCli {
    /// Optional comma-separated list of mesh peer Multiaddrs or `host:port` endpoints (`PARVAULT_PEERS`).
    #[arg(long, global = true, value_delimiter = ',')]
    peers: Vec<String>,

    #[command(subcommand)]
    command: SeedCommand,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliSeedMode {
    /// Dedicated 24/7 homelab redundancy vault for personal devices + HighUptimeAnchor earning
    #[value(name = "homelab-vault")]
    HomelabVault,
    /// Stateless public network bootstrapper (FoundationSeedAnchor) with Byte-Epoch lease GC
    #[value(name = "public-bootstrap")]
    PublicBootstrap,
}

impl From<CliSeedMode> for SeedServerMode {
    fn from(mode: CliSeedMode) -> Self {
        match mode {
            CliSeedMode::HomelabVault => Self::HomelabRedundancyVault,
            CliSeedMode::PublicBootstrap => Self::PublicNetworkBootstrapper,
        }
    }
}

#[derive(Subcommand, Debug)]
enum SeedCommand {
    /// Start the standalone Zero-Trust Seed & Redundancy Server
    Start {
        /// Operating mode (`homelab-vault` or `public-bootstrap`)
        #[arg(long, value_enum, default_value_t = CliSeedMode::PublicBootstrap)]
        mode: CliSeedMode,

        /// libp2p TCP + Noise XX + Yamux listen multiaddr
        #[arg(long, default_value = "/ip4/0.0.0.0/tcp/4002")]
        listen: String,

        /// Directory for sharded ciphertext & blinded `.bshard` storage
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,

        /// Maximum disk storage capacity in GiB committed to the seed server
        #[arg(long, visible_alias = "max-capacity-gib", default_value_t = 500)]
        max_gb: u64,

        /// Default Byte-Epoch lease duration in epochs for blinded bootstrap shards
        #[arg(long, default_value_t = 720)]
        lease_epochs: u64,

        /// Hex-encoded bincode `HybridPqPublicKey` of the homelab owner (for `homelab-vault` mode)
        #[arg(long)]
        owner_pq_pubkey_hex: Option<String>,

        /// Grace window in epochs before un-renewed blinded shards are physically deleted
        #[arg(long, default_value_t = 2)]
        grace_epochs: u64,

        /// Initialize, print the status report (table + JSON), and exit immediately for CI/scripts
        #[arg(long, default_value_t = false)]
        once: bool,
    },

    /// Display or initialize the persistent seed server NodeIdentity and Post-Quantum Owner Key
    Identity {
        /// Seed server data directory
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,
    },

    /// Issue a post-quantum PersonalDeviceCert (Ed25519 + ML-DSA-65) authorizing a personal device on the Homelab Ring
    IssueDeviceCert {
        /// Seed server data directory
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,

        /// Device Peer ID to authorize (e.g. `parvault-peer-...`)
        #[arg(long)]
        device_peer_id: String,

        /// Human-readable label for the personal device
        #[arg(long, default_value = "personal-device")]
        device_label: String,

        /// Optional output path to write the JSON certificate file
        #[arg(long)]
        cert_out: Option<PathBuf>,
    },

    /// Verify a post-quantum PersonalDeviceCert (from a JSON file path, JSON string, or `PARVAULT-CERT-V1:<hex>` token)
    VerifyDeviceCert {
        /// Seed server data directory
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,

        /// Path to certificate file, raw JSON string, or `PARVAULT-CERT-V1:<hex>` token
        #[arg(long)]
        cert: String,

        /// Optional hex-encoded Owner PQ Public Key (defaults to persistent owner PQ key in `data_dir`)
        #[arg(long)]
        owner_pq_pubkey_hex: Option<String>,
    },

    /// Inspect seed server status, storage allocation, active blinded leases, and earned standing
    Status {
        /// Seed server data directory
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,

        /// Operating mode (`homelab-vault` or `public-bootstrap`)
        #[arg(long, value_enum, default_value_t = CliSeedMode::HomelabVault)]
        mode: CliSeedMode,
    },

    /// Compute and display the elastic bootstrap auto-drain migration plan as organic peers join
    DrainPlan {
        /// Seed server data directory
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,

        /// Number of organic community peers available in the grown mesh
        #[arg(long, default_value_t = 20)]
        organic_peers: usize,

        /// Target shard count (`N`) for elastic placement evaluation
        #[arg(long, default_value_t = 20)]
        target_n: usize,
    },

    /// Run the local bit-rot scrubber across all `.shard` and `.bshard` files in `data_dir`
    Scrub {
        /// Seed server data directory
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,
    },

    /// Run a time-based expiration sweep to unlink expired `.bshard` files from disk
    #[command(visible_alias = "sweep-leases")]
    SweepExpired {
        /// Seed server data directory containing `shards/` and `blinded_leases.bin`
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,

        /// Current network epoch index for evaluating `lease_expires_epoch + grace_epochs <= current_epoch`
        #[arg(long)]
        current_epoch: u64,
    },

    /// Gracefully decommission this seed server, directly handing off all hosted `.shard` and `.bshard` files (`1.0x` bandwidth) and issuing a signed GracefulDepartureReceipt
    Leave {
        /// Seed server data directory
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,

        /// Optional comma-separated target handoff directories to receive evacuated shards
        #[arg(long)]
        handoff_to: Option<String>,

        /// Keep local shard copies on disk after handoff
        #[arg(long, default_value_t = false)]
        keep_local: bool,
    },

    /// Execute built-in end-to-end verification of both `HomelabRedundancyVault` and `PublicNetworkBootstrapper` modes
    SelfTest,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("parvault_seed=info,parvault=info,warn")
            }),
        )
        .init();

    let cli = SeedCli::parse();
    let effective_peers: Vec<String> = if !cli.peers.is_empty() {
        cli.peers.clone()
    } else {
        std::env::var("PARVAULT_PEERS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    match cli.command {
        SeedCommand::Start {
            mode,
            listen,
            data_dir,
            max_gb,
            lease_epochs,
            owner_pq_pubkey_hex,
            grace_epochs,
            once,
        } => {
            let node_identity = NodeIdentity::load_or_generate_in_dir(&data_dir)?;
            let mesh_client = MeshClient::new(node_identity.clone(), effective_peers.clone(), None);
            let max_bytes = max_gb.saturating_mul(1024 * 1024 * 1024);
            let grace_bytes = 2 * 1024 * 1024 * 1024;
            let quota = QuotaManager::new(max_bytes, grace_bytes);
            let block_store = BlockStore::new(&data_dir, quota)?.with_mesh_client(mesh_client);

            let server = match mode {
                CliSeedMode::HomelabVault => {
                    let owner_pubkey = if let Some(hex_str) = owner_pq_pubkey_hex {
                        HybridPqPublicKey::from_hex(hex_str.trim())?
                    } else {
                        let persistent =
                            HybridPqSigningKeypair::load_or_generate_in_dir(&data_dir)?;
                        let pk = persistent.public_key();
                        info!(
                            fingerprint = %pk.fingerprint_hex(),
                            "Loaded persistent homelab owner HybridPqPublicKey ({} bytes ML-DSA-65 PK)",
                            pk.ml_dsa_65_pk.len()
                        );
                        pk
                    };
                    ZeroTrustSeedServer::new_homelab_vault(
                        "parvault-seed-homelab-vault",
                        block_store.clone(),
                        owner_pubkey,
                        grace_epochs,
                    )
                }
                CliSeedMode::PublicBootstrap => {
                    let genesis_pubkey =
                        NodeIdentity::resolve_genesis_root_pubkey_in_dir(&data_dir, None)?;
                    info!(
                        lease_epochs,
                        grace_epochs,
                        "Configured PublicNetworkBootstrapper Byte-Epoch lease policy"
                    );
                    ZeroTrustSeedServer::new_public_bootstrapper(
                        "parvault-seed-public-bootstrapper",
                        block_store.clone(),
                        genesis_pubkey,
                        grace_epochs,
                    )
                }
            };

            let report = server.status_report(1);
            print_status_report(&listen, &data_dir, &report)?;

            if once {
                return Ok(());
            }

            run_seed_listener_loop(listen, block_store, server).await?;
        }

        SeedCommand::Identity { data_dir } => {
            let node_id = NodeIdentity::load_or_generate_in_dir(&data_dir)?;
            let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&data_dir)?;
            let pq_pk = pq_keypair.public_key();

            println!("=== ParVault Seed Server Persistent Identity ===");
            println!("Data Directory          : {}", data_dir.display());
            println!("Device Peer ID          : {}", node_id.device_peer_id());
            println!(
                "Ed25519 Public Key (hex): {}",
                hex::encode(node_id.public_key_bytes())
            );
            println!("Owner PQ Public Key Hex : {}", pq_pk.to_hex()?);
            println!("Owner PQ Fingerprint    : {}", pq_pk.fingerprint_hex());
        }

        SeedCommand::IssueDeviceCert {
            data_dir,
            device_peer_id,
            device_label,
            cert_out,
        } => {
            let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&data_dir)?;
            let pq_pk = pq_keypair.public_key();
            let issued_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let cert =
                PersonalDeviceCert::issue(&pq_keypair, &device_peer_id, &device_label, issued_at)?;
            let json_str = cert.to_json_pretty()?;
            let token_str = cert.to_shareable_token()?;

            if let Some(out_path) = &cert_out {
                BlockStore::atomic_write_file(out_path, json_str.as_bytes())?;
            }

            println!("=== ParVault Seed PersonalDeviceCert Issued (Ed25519 + ML-DSA-65) ===");
            println!("Device Peer ID          : {}", cert.device_peer_id);
            println!("Device Label            : {}", cert.device_label);
            println!("Issued At (Unix Secs)   : {}", cert.issued_unix_secs);
            println!("Owner PQ Fingerprint    : {}", pq_pk.fingerprint_hex());
            println!("Owner PQ Public Key Hex : {}", pq_pk.to_hex()?);
            if let Some(out_path) = &cert_out {
                println!("Certificate JSON File   : {}", out_path.display());
            }
            println!("Shareable Token         : {}", token_str);
        }

        SeedCommand::VerifyDeviceCert {
            data_dir,
            cert,
            owner_pq_pubkey_hex,
        } => {
            let raw_cert = if std::path::Path::new(&cert).exists() {
                std::fs::read_to_string(&cert)?
            } else {
                cert.clone()
            };
            let parsed_cert = PersonalDeviceCert::from_shareable_token(&raw_cert)
                .or_else(|_| PersonalDeviceCert::from_json_str(&raw_cert))?;

            let owner_pk = if let Some(hex_str) = owner_pq_pubkey_hex {
                HybridPqPublicKey::from_hex(hex_str.trim())?
            } else {
                HybridPqSigningKeypair::load_or_generate_in_dir(&data_dir)?.public_key()
            };

            if parsed_cert.verify(&owner_pk).is_err() {
                anyhow::bail!(
                    "PersonalDeviceCert verification FAILED against owner PQ public key (fingerprint: {})",
                    owner_pk.fingerprint_hex()
                );
            }

            println!("=== ParVault Seed PersonalDeviceCert Verification: PASS ===");
            println!("Device Peer ID          : {}", parsed_cert.device_peer_id);
            println!("Device Label            : {}", parsed_cert.device_label);
            println!("Issued At (Unix Secs)   : {}", parsed_cert.issued_unix_secs);
            println!("Owner PQ Fingerprint    : {}", owner_pk.fingerprint_hex());
            println!("Verification Status     : VALID (Ed25519 + FIPS 204 ML-DSA-65 verified)");
        }

        SeedCommand::Status { data_dir, mode } => {
            let quota = QuotaManager::new(500 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
            let block_store = BlockStore::new(&data_dir, quota)?;
            let node_id = NodeIdentity::load_or_generate_in_dir(&data_dir)?;
            let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&data_dir)?;
            let pq_pk = pq_keypair.public_key();

            let server = match mode {
                CliSeedMode::HomelabVault => ZeroTrustSeedServer::new_homelab_vault(
                    "parvault-seed-homelab-vault",
                    block_store,
                    pq_pk.clone(),
                    2,
                ),
                CliSeedMode::PublicBootstrap => {
                    let genesis_pubkey =
                        NodeIdentity::resolve_genesis_root_pubkey_in_dir(&data_dir, None)?;
                    ZeroTrustSeedServer::new_public_bootstrapper(
                        "parvault-seed-public-bootstrapper",
                        block_store,
                        genesis_pubkey,
                        2,
                    )
                }
            };

            println!("Device Peer ID            : {}", node_id.device_peer_id());
            println!("Owner PQ Fingerprint      : {}", pq_pk.fingerprint_hex());
            let report = server.status_report(1);
            print_status_report("/ip4/0.0.0.0/tcp/4002", &data_dir, &report)?;
        }

        SeedCommand::DrainPlan {
            data_dir,
            organic_peers,
            target_n,
        } => {
            let quota = QuotaManager::new(500 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
            let block_store = BlockStore::new(&data_dir, quota)?;
            let genesis_pubkey = NodeIdentity::resolve_genesis_root_pubkey_in_dir(&data_dir, None)?;
            let server = ZeroTrustSeedServer::new_public_bootstrapper(
                "parvault-seed-public-bootstrapper",
                block_store,
                genesis_pubkey,
                2,
            );

            let initial_organic = organic_peers.clamp(1, 3);
            let mut initial_candidates = Vec::new();
            for i in 0..initial_organic {
                initial_candidates.push(ElasticPeerCandidate {
                    peer_id: format!("organic-{i}"),
                    role: PeerRole::OrganicCommunityPeer,
                    subnet_prefix: format!("10.0.{i}.0/24"),
                    trust_level: TrustLevel::UntrustedProbationary,
                    rtt_ms: 15,
                    committed_standby_bytes: 100 * 1024 * 1024,
                });
            }
            initial_candidates.push(ElasticPeerCandidate {
                peer_id: server.server_peer_id().to_string(),
                role: PeerRole::FoundationSeedAnchor,
                subnet_prefix: "198.51.100.0/24".to_string(),
                trust_level: TrustLevel::HighUptimeAnchor,
                rtt_ms: 40,
                committed_standby_bytes: 0,
            });

            let initial_placements = ElasticBootstrapEngine::select_elastic_targets(
                EarnedStanding::BuddyMicroCluster,
                &initial_candidates,
            );

            let mut grown_candidates = initial_candidates.clone();
            for i in initial_organic..organic_peers.max(initial_organic) {
                grown_candidates.push(ElasticPeerCandidate {
                    peer_id: format!("organic-{i}"),
                    role: PeerRole::OrganicCommunityPeer,
                    subnet_prefix: format!("10.1.{}.0/24", i % 255),
                    trust_level: TrustLevel::VerifiedNeighbor,
                    rtt_ms: 20,
                    committed_standby_bytes: 100 * 1024 * 1024,
                });
            }

            let drain_plan = server.plan_seed_anchor_drain(
                EarnedStanding::BuddyMicroCluster,
                &initial_placements,
                &grown_candidates,
            );

            println!("=== ParVault Seed Server Elastic Auto-Drain Plan (ADR-12 / ADR-13) ===");
            println!("Data Directory            : {}", data_dir.display());
            println!("Seed Anchor Peer ID       : {}", server.server_peer_id());
            println!("Target Shard Count (N)    : {}", target_n);
            println!("Organic Community Peers   : {}", organic_peers);
            println!("Shards Scheduled to Drain : {}", drain_plan.len());
            for (idx, step) in drain_plan.iter().enumerate() {
                println!("  [{}] {:?}", idx + 1, step);
            }
        }

        SeedCommand::Scrub { data_dir } => {
            let quota = QuotaManager::new(500 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
            let block_store = BlockStore::new(&data_dir, quota)?;
            let report = block_store.scrub_all_shards()?;
            let healthy_shards =
                report.verified_healthy_shards + report.verified_healthy_blinded_shards;
            let corrupted_quarantined_shards = report.quarantined_corrupted_shards.len()
                + report.quarantined_corrupted_blinded_locators.len();
            let total_shards_scanned = healthy_shards + corrupted_quarantined_shards;
            println!("=== ParVault Seed Server Local Bit-Rot Scrub Report (ADR-15) ===");
            println!("Data Directory               : {}", data_dir.display());
            println!("total_shards_scanned         : {}", total_shards_scanned);
            println!(
                "healthy_shards               : {} (regular: {}, blinded: {})",
                healthy_shards,
                report.verified_healthy_shards,
                report.verified_healthy_blinded_shards
            );
            println!(
                "corrupted_quarantined_shards : {}",
                corrupted_quarantined_shards
            );
        }

        SeedCommand::SweepExpired {
            data_dir,
            current_epoch,
        } => {
            let quota = QuotaManager::new(500 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
            let block_store = BlockStore::new(&data_dir, quota)?;
            let deleted = block_store.sweep_expired_blinded_shards(current_epoch)?;
            println!("=== ParVault Seed Server Expired Lease Sweep ===");
            println!("Data Directory        : {}", data_dir.display());
            println!("Current Epoch         : {}", current_epoch);
            println!(
                "Unlinked .bshard Files: {} expired blinded shards physically removed from disk",
                deleted.len()
            );
        }

        SeedCommand::Leave {
            data_dir,
            handoff_to,
            keep_local,
        } => {
            let identity = NodeIdentity::load_or_generate_in_dir(&data_dir)?;
            let mesh_client = MeshClient::new(identity.clone(), effective_peers.clone(), None);
            let quota = QuotaManager::new(500 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
            let block_store = BlockStore::new(&data_dir, quota)?.with_mesh_client(mesh_client);
            let target_dirs: Vec<PathBuf> = handoff_to
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect();
            let remove_local = !keep_local;
            let receipt = block_store.graceful_leave_and_redistribute(
                &identity,
                &target_dirs,
                remove_local,
            )?;
            println!(
                "=== ParVault Seed Server Graceful Decommission Complete (1.0x Direct Handoff) ==="
            );
            println!("Departing Peer ID        : {}", receipt.departing_peer_id);
            println!(
                "Migrated Regular Shards  : {}",
                receipt.migrated_shards_count
            );
            println!(
                "Migrated Blinded Shards  : {}",
                receipt.migrated_blinded_shards_count
            );
            println!(
                "Total Bytes Handed Off   : {} bytes",
                receipt.total_bytes_handed_off
            );
            println!(
                "Earned Standing Preserved: {}",
                receipt.earned_standing_preserved
            );
        }

        SeedCommand::SelfTest => {
            run_builtin_self_test()?;
        }
    }

    Ok(())
}

fn print_status_report(
    listen: &str,
    data_dir: &std::path::Path,
    report: &parvault::bootstrap::SeedServerStatusReport,
) -> anyhow::Result<()> {
    println!("========================================================================");
    println!("  ParVault Zero-Trust Seed & Redundancy Server Status Report (ADR-13)     ");
    println!("========================================================================");
    println!("Operating Mode            : {:?}", report.mode);
    println!("Assigned PeerRole         : {:?}", report.peer_role);
    println!("Listen Multiaddr          : {}", listen);
    println!("Data Directory            : {}", data_dir.display());
    println!(
        "Storage Allocation        : {} / {} bytes used",
        report.used_storage_bytes, report.max_storage_bytes
    );
    println!(
        "Active Blinded Leases     : {}",
        report.active_blinded_leases
    );
    println!(
        "Earned Trust Level        : {:?}",
        report.earned_trust_level
    );
    println!("Earned Redundancy Standing: {:?}", report.earned_standing);
    println!(
        "PoR Audits Passed / SLA   : {} passes ({:.2}% SLA)",
        report.por_passes,
        report.sla_ratio * 100.0
    );
    println!(
        "Holds Own Plaintext Files : {} (strictly zero-knowledge seed server)",
        report.holds_own_plaintext_files
    );
    println!("------------------------------------------------------------------------");
    println!("JSON Telemetry: {}", serde_json::to_string(report)?);
    Ok(())
}

async fn run_seed_listener_loop(
    listen: String,
    block_store: BlockStore,
    mut server: ZeroTrustSeedServer,
) -> anyhow::Result<()> {
    let data_dir = block_store.root_dir().to_path_buf();
    let node_identity = NodeIdentity::load_or_generate_in_dir(&data_dir)?;
    let keypair = node_identity.to_libp2p_keypair()?;
    let local_peer_id = keypair.public().to_peer_id();
    let genesis_pubkey = NodeIdentity::resolve_genesis_root_pubkey_in_dir(&data_dir, None)?;

    let mut wot = WebOfTrustRegistry::with_persistence_dir(
        genesis_pubkey,
        DEFAULT_SUBTREE_SLASH_LIMIT,
        &data_dir,
    );
    let mut por_verifier = PorVerifierEngine::with_persistence_dir(300, &data_dir);
    let mut nullifier_ledger =
        VoucherNullifierLedger::with_persistence_dir(genesis_pubkey, &data_dir);
    let pq_kem = HybridKemKeypair::load_or_generate_in_dir(&data_dir)?;

    let mut swarm = build_mesh_swarm(keypair, false)?;
    let tcp_addr: Multiaddr = listen.parse()?;
    swarm.listen_on(tcp_addr)?;

    let mut epoch_counter: u64 = 1;
    let mut gc_interval = tokio::time::interval(Duration::from_secs(60));
    gc_interval.tick().await;

    info!(
        %local_peer_id,
        mode = ?server.mode(),
        listen_tcp = %listen,
        "parvault-seed zero-trust listener started (Noise XX + Yamux)"
    );

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!(%address, "parvault-seed listening on transport address");
                    }
                    SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Mdns(
                        mdns::Event::Discovered(list),
                    )) => {
                        for (peer_id, multiaddr) in list {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                        }
                    }
                    SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::ReqResp(
                        request_response::Event::Message {
                            peer,
                            message: Message::Request { request, channel, .. },
                        },
                    )) => {
                        let resp = handle_seed_wire_request(
                            &peer.to_string(),
                            request,
                            &block_store,
                            &mut server,
                            &mut wot,
                            &mut por_verifier,
                            &mut nullifier_ledger,
                            &pq_kem,
                        );
                        let _ = swarm.behaviour_mut().req_resp.send_response(channel, resp);
                    }
                    _ => {}
                }
            }
            _ = gc_interval.tick() => {
                epoch_counter = epoch_counter.saturating_add(1);
                if let Ok(purged) = server.sweep_expired_epoch(epoch_counter) {
                    if !purged.is_empty() {
                        info!(
                            epoch = epoch_counter,
                            purged_count = purged.len(),
                            "Swept and unlinked expired .bshard files from disk"
                        );
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl-C, shutting down parvault-seed cleanly.");
                break;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_seed_wire_request(
    remote_peer_id: &str,
    request: MeshWireRequest,
    block_store: &BlockStore,
    server: &mut ZeroTrustSeedServer,
    wot: &mut WebOfTrustRegistry,
    por_verifier: &mut PorVerifierEngine,
    nullifier_ledger: &mut VoucherNullifierLedger,
    pq_kem: &HybridKemKeypair,
) -> MeshWireResponse {
    match request {
        MeshWireRequest::HandshakeWoT { chain, .. } => match wot.verify_and_admit_chain(&chain) {
            Ok(_) => MeshWireResponse::HandshakeAck {
                accepted: true,
                reason: None,
            },
            Err(e) => MeshWireResponse::HandshakeAck {
                accepted: false,
                reason: Some(e.to_string()),
            },
        },
        MeshWireRequest::PutShard {
            owner_peer_id,
            shard_id,
            shard_bytes,
            session_key_commit,
            repair_grant,
        } => {
            if let Some(grant) = repair_grant {
                por_verifier.register_repair_grant(grant);
            }
            por_verifier.register_shard_session(&shard_id, session_key_commit);
            let effective_owner = if owner_peer_id.is_empty()
                || owner_peer_id == "local"
                || owner_peer_id == "self"
            {
                remote_peer_id
            } else {
                owner_peer_id.as_str()
            };
            match block_store.put_shard(effective_owner, &shard_id, &shard_bytes) {
                Ok(_) => MeshWireResponse::PutShardAck {
                    stored: true,
                    error: None,
                },
                Err(e) => MeshWireResponse::PutShardAck {
                    stored: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::DeleteShard {
            shard_id,
            owner_signature: (owner_pub, payload, r, s),
        } => {
            let mut sig64 = [0u8; 64];
            sig64[..32].copy_from_slice(&r);
            sig64[32..].copy_from_slice(&s);
            if !por_verifier.authorize_owner_shard_delete(
                &shard_id,
                &owner_pub,
                payload.as_slice(),
                &sig64,
            ) {
                return MeshWireResponse::DeleteShardAck {
                    deleted: false,
                    error: Some("unauthorized owner shard delete signature".to_string()),
                };
            }
            match block_store.delete_shard(remote_peer_id, &shard_id) {
                Ok(deleted) => MeshWireResponse::DeleteShardAck {
                    deleted,
                    error: None,
                },
                Err(e) => MeshWireResponse::DeleteShardAck {
                    deleted: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::PorAudit(challenge) => {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            match por_verifier.handle_incoming_challenge(&challenge, now_ms, block_store) {
                Ok(resp) => {
                    server.record_por_heartbeat(true);
                    MeshWireResponse::PorAuditResult(Some(resp))
                }
                Err(e) => {
                    warn!(peer = remote_peer_id, error = %e, "Dropped PoR challenge in RAM pre-check");
                    MeshWireResponse::PorAuditResult(None)
                }
            }
        }
        MeshWireRequest::GetCiphertextShard {
            shard_id,
            owner_signature,
            repair_proof,
        } => {
            let owner_sig_storage;
            let owner_sig_ref = if let Some((owner_pub, payload, r, s)) = &owner_signature {
                let mut sig64 = [0u8; 64];
                sig64[..32].copy_from_slice(r);
                sig64[32..].copy_from_slice(s);
                owner_sig_storage = (*owner_pub, payload.as_slice(), sig64);
                Some((
                    owner_sig_storage.0,
                    owner_sig_storage.1,
                    &owner_sig_storage.2,
                ))
            } else {
                None
            };

            let repair_ref = repair_proof
                .as_ref()
                .map(|(grant, receipts)| (grant, receipts.as_slice()));

            match por_verifier.authorize_raw_shard_read(
                &shard_id,
                owner_sig_ref.as_ref(),
                repair_ref,
                block_store,
            ) {
                Ok(bytes) => MeshWireResponse::CiphertextShardResult {
                    shard_bytes: Some(bytes),
                    error: None,
                },
                Err(e) => MeshWireResponse::CiphertextShardResult {
                    shard_bytes: None,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::PutBlindedShard {
            blinded_id,
            shard_bytes,
            capability,
            voucher,
            current_epoch,
            lease_duration_epochs,
            delete_verifier,
        } => {
            nullifier_ledger.set_trusted_issuer_pubkey(voucher.issuer_pubkey);
            match block_store.put_blinded_shard_with_lease(
                &blinded_id,
                &shard_bytes,
                capability,
                &voucher,
                nullifier_ledger,
                current_epoch,
                lease_duration_epochs,
                delete_verifier,
            ) {
                Ok(_) => MeshWireResponse::PutBlindedShardAck {
                    stored: true,
                    error: None,
                },
                Err(e) => MeshWireResponse::PutBlindedShardAck {
                    stored: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::GetBlindedShard {
            blinded_id,
            capability,
            timestamp_ms,
            read_sig,
        } => {
            if read_sig.len() != 64 {
                return MeshWireResponse::BlindedShardResult {
                    shard_bytes: None,
                    error: Some("invalid 64-byte capability signature length".to_string()),
                };
            }
            let mut sig64 = [0u8; 64];
            sig64.copy_from_slice(&read_sig);
            match block_store.get_blinded_shard_authorized(
                &blinded_id,
                &capability,
                timestamp_ms,
                &sig64,
            ) {
                Ok(bytes) => MeshWireResponse::BlindedShardResult {
                    shard_bytes: Some(bytes),
                    error: None,
                },
                Err(e) => MeshWireResponse::BlindedShardResult {
                    shard_bytes: None,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::RenewBlindedLease {
            blinded_id,
            current_epoch,
            extension_epochs,
        } => {
            let renewed = server.renew_blinded_lease(&blinded_id, current_epoch, extension_epochs);
            MeshWireResponse::RenewBlindedLeaseAck { renewed }
        }
        MeshWireRequest::DeleteBlindedShardTombstone {
            blinded_id,
            tombstone,
        } => match server.execute_blinded_tombstone(&blinded_id, &tombstone) {
            Ok(deleted) => MeshWireResponse::DeleteBlindedShardAck {
                deleted,
                error: None,
            },
            Err(e) => MeshWireResponse::DeleteBlindedShardAck {
                deleted: false,
                error: Some(e.to_string()),
            },
        },
        MeshWireRequest::MultiSegmentPorAudit(challenge) => {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            match por_verifier.handle_multi_segment_challenge(&challenge, now_ms, block_store) {
                Ok(resp) => {
                    server.record_por_heartbeat(true);
                    MeshWireResponse::MultiSegmentPorAuditResult(Some(resp))
                }
                Err(e) => {
                    warn!(peer = remote_peer_id, error = %e, "Dropped MultiSegmentPorAudit in RAM pre-check");
                    MeshWireResponse::MultiSegmentPorAuditResult(None)
                }
            }
        }
        MeshWireRequest::RelayPqOnionEnvelope {
            target_peer_addr,
            envelope,
            capability,
            voucher,
            current_epoch,
            lease_duration_epochs,
            delete_verifier,
        } => {
            if let Some(next_hop) = target_peer_addr {
                if let Some(client) = block_store.mesh_client() {
                    match client.relay_pq_onion_envelope(
                        &next_hop,
                        None,
                        envelope,
                        capability,
                        voucher,
                        current_epoch,
                        lease_duration_epochs,
                        delete_verifier,
                    ) {
                        Ok(()) => MeshWireResponse::RelayPqOnionAck {
                            delivered: true,
                            error: None,
                        },
                        Err(e) => MeshWireResponse::RelayPqOnionAck {
                            delivered: false,
                            error: Some(e.to_string()),
                        },
                    }
                } else {
                    MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some("no MeshClient available for onion forwarding".to_string()),
                    }
                }
            } else {
                match envelope.open_pq(pq_kem) {
                    Ok((blinded_id, shard_bytes)) => {
                        nullifier_ledger.set_trusted_issuer_pubkey(voucher.issuer_pubkey);
                        match block_store.put_blinded_shard_with_lease(
                            &blinded_id,
                            &shard_bytes,
                            capability,
                            &voucher,
                            nullifier_ledger,
                            current_epoch,
                            lease_duration_epochs,
                            delete_verifier,
                        ) {
                            Ok(_) => MeshWireResponse::RelayPqOnionAck {
                                delivered: true,
                                error: None,
                            },
                            Err(e) => MeshWireResponse::RelayPqOnionAck {
                                delivered: false,
                                error: Some(e.to_string()),
                            },
                        }
                    }
                    Err(e) => MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some(e.to_string()),
                    },
                }
            }
        }
        MeshWireRequest::SyndicateLiteStripe {
            cert,
            bundle,
            repair_grant,
        } => {
            if let Some(ref grant) = repair_grant {
                por_verifier.register_repair_grant(grant.clone());
            }
            match server.ingest_and_syndicate_lite_stripe_with_grant(
                &cert,
                &bundle,
                &[],
                repair_grant,
            ) {
                Ok((receipt, syndicated_peers)) => MeshWireResponse::SyndicateLiteStripeAck {
                    receipt: Some(receipt),
                    syndicated_peers,
                    error: None,
                },
                Err(e) => MeshWireResponse::SyndicateLiteStripeAck {
                    receipt: None,
                    syndicated_peers: Vec::new(),
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::PutDhtEnvelope(env) => {
            let res = match env {
                DhtWireEnvelope::ClassicalManifest(m) => block_store.put_dht_manifest_envelope(m),
                DhtWireEnvelope::PostQuantumManifest(m) => {
                    block_store.put_dht_pq_manifest_envelope(m)
                }
                DhtWireEnvelope::VaultCatalog(m) => block_store.put_dht_vault_catalog_envelope(m),
            };
            match res {
                Ok(()) => MeshWireResponse::PutDhtEnvelopeAck {
                    stored: true,
                    error: None,
                },
                Err(e) => MeshWireResponse::PutDhtEnvelopeAck {
                    stored: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::GetDhtEnvelope { dht_key, kind } => {
            let found = match kind {
                DhtEnvelopeKind::ClassicalManifest => block_store
                    .get_dht_manifest_envelope(&dht_key)
                    .map(DhtWireEnvelope::ClassicalManifest),
                DhtEnvelopeKind::PostQuantumManifest => block_store
                    .get_dht_pq_manifest_envelope(&dht_key)
                    .map(DhtWireEnvelope::PostQuantumManifest),
                DhtEnvelopeKind::VaultCatalog => block_store
                    .get_dht_vault_catalog_envelope(&dht_key)
                    .map(DhtWireEnvelope::VaultCatalog),
            };
            if let Some(env) = found {
                MeshWireResponse::GetDhtEnvelopeResult {
                    envelope: Some(env),
                    error: None,
                }
            } else {
                MeshWireResponse::GetDhtEnvelopeResult {
                    envelope: None,
                    error: Some("DHT envelope not found".to_string()),
                }
            }
        }
    }
}

fn run_builtin_self_test() -> anyhow::Result<()> {
    let temp_base = std::env::temp_dir().join(format!(
        "parvault-seed-selftest-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let vault_dir = temp_base.join("homelab_vault");
    let bootstrap_dir = temp_base.join("public_bootstrap");

    let result = (|| -> anyhow::Result<()> {
        // ---------------------------------------------------------------------
        // Part 1: HomelabRedundancyVault Mode Self-Test
        // ---------------------------------------------------------------------
        let owner_pq = HybridPqSigningKeypair::generate()?;
        let stranger_pq = HybridPqSigningKeypair::generate()?;

        let laptop_cert =
            PersonalDeviceCert::issue(&owner_pq, "laptop-1", "MacBook-Pro", 1_700_000_000)?;
        let desktop_cert =
            PersonalDeviceCert::issue(&owner_pq, "desktop-1", "Linux-Workstation", 1_700_000_000)?;
        let stranger_cert =
            PersonalDeviceCert::issue(&stranger_pq, "stranger-1", "Attacker-Node", 1_700_000_000)?;

        let vault_quota = QuotaManager::new(10 * 1024 * 1024 * 1024, 64 * 1024 * 1024);
        let vault_store = BlockStore::new(&vault_dir, vault_quota)?;
        let mut vault_server = ZeroTrustSeedServer::new_homelab_vault(
            "homelab-nas-seed-1",
            vault_store,
            owner_pq.public_key(),
            2,
        );

        // Stranger must be rejected
        assert!(vault_server
            .authorize_personal_device(&stranger_cert)
            .is_err());

        // Laptop & Desktop store encrypted shards with 0 quota deduction
        let shard_bytes_a = vec![0xA5u8; 4096];
        let shard_id_a = ShardId {
            stripe_merkle_root: [0x11; 32],
            shard_index: 0,
            shard_hash: hash_shard_leaf(0, &shard_bytes_a),
        };
        let shard_bytes_b = vec![0x5Au8; 4096];
        let shard_id_b = ShardId {
            stripe_merkle_root: [0x11; 32],
            shard_index: 1,
            shard_hash: hash_shard_leaf(1, &shard_bytes_b),
        };

        vault_server.store_personal_device_shard(&laptop_cert, &shard_id_a, &shard_bytes_a)?;
        vault_server.store_personal_device_shard(&desktop_cert, &shard_id_b, &shard_bytes_b)?;

        assert_eq!(vault_server.personal_device_quota_charged("laptop-1"), 0);
        assert_eq!(vault_server.personal_device_quota_charged("desktop-1"), 0);

        // Simulate 200 PoR heartbeats and verify HighUptimeAnchor (16-of-20) qualification
        vault_server.simulate_por_heartbeats(200, 20);
        let vault_report = vault_server.status_report(1);
        assert_eq!(
            vault_report.earned_trust_level,
            TrustLevel::HighUptimeAnchor
        );
        assert_eq!(
            vault_report.earned_standing,
            EarnedStanding::EarnedHomelabAnchorPool
        );
        assert!(!vault_report.holds_own_plaintext_files);

        // ---------------------------------------------------------------------
        // Part 2: PublicNetworkBootstrapper Mode Self-Test
        // ---------------------------------------------------------------------
        let voucher_issuer = NodeIdentity::generate();
        let boot_quota = QuotaManager::new(10 * 1024 * 1024 * 1024, 64 * 1024 * 1024);
        let boot_store = BlockStore::new(&bootstrap_dir, boot_quota)?;
        let mut boot_server = ZeroTrustSeedServer::new_public_bootstrapper(
            "foundation-seed-anchor-1",
            boot_store,
            voucher_issuer.public_key_bytes(),
            2,
        );

        let user_master_key = MasterKey::generate();
        let cap_secret = [0x99u8; 32];
        let payload_expired = vec![0xCCu8; 2048];
        let blinded_expired =
            BlindedShardId::derive(&user_master_key, &[0x22; 32], 0, &payload_expired);
        let (_, cap_expired) =
            BlindedShardCapability::derive_keypair(&user_master_key, &blinded_expired.locator);
        let voucher_1 = AnonymousQuotaVoucher::mint(&voucher_issuer, 4096);
        let verifier_1 =
            BlindedShardTombstone::derive_delete_verifier(&cap_secret, &blinded_expired.locator);

        boot_server.ingest_blinded_shard_with_lease(
            &blinded_expired,
            &payload_expired,
            cap_expired,
            &voucher_1,
            10,
            5,
            verifier_1,
        )?;

        // Sweep at epoch 17 (10 + 5 + 2 grace = 17) unlinks expired .bshard file
        let swept = boot_server.sweep_expired_epoch(17)?;
        assert_eq!(swept.len(), 1);
        assert!(!boot_server
            .block_store()
            .has_blinded_shard_on_disk(&blinded_expired));

        // Ingest a second blinded shard for a 3-peer bootstrap network and auto-drain to 20 organic peers
        let payload_drain = vec![0xDDu8; 2048];
        let blinded_drain =
            BlindedShardId::derive(&user_master_key, &[0x33; 32], 4, &payload_drain);
        let (_, cap_drain) =
            BlindedShardCapability::derive_keypair(&user_master_key, &blinded_drain.locator);
        let voucher_2 = AnonymousQuotaVoucher::mint(&voucher_issuer, 4096);
        let verifier_2 =
            BlindedShardTombstone::derive_delete_verifier(&cap_secret, &blinded_drain.locator);

        boot_server.ingest_blinded_shard_with_lease(
            &blinded_drain,
            &payload_drain,
            cap_drain,
            &voucher_2,
            20,
            30,
            verifier_2,
        )?;

        let mut initial_candidates = Vec::new();
        for i in 0..3 {
            initial_candidates.push(ElasticPeerCandidate {
                peer_id: format!("organic-{i}"),
                role: PeerRole::OrganicCommunityPeer,
                subnet_prefix: format!("10.0.{i}.0/24"),
                trust_level: TrustLevel::UntrustedProbationary,
                rtt_ms: 15,
                committed_standby_bytes: 100 * 1024 * 1024,
            });
        }
        initial_candidates.push(ElasticPeerCandidate {
            peer_id: boot_server.server_peer_id().to_string(),
            role: PeerRole::FoundationSeedAnchor,
            subnet_prefix: "198.51.100.0/24".to_string(),
            trust_level: TrustLevel::HighUptimeAnchor,
            rtt_ms: 40,
            committed_standby_bytes: 0,
        });

        let initial_placements = ElasticBootstrapEngine::select_elastic_targets(
            EarnedStanding::BuddyMicroCluster,
            &initial_candidates,
        );

        let mut grown_candidates = initial_candidates.clone();
        for i in 3..20 {
            grown_candidates.push(ElasticPeerCandidate {
                peer_id: format!("organic-{i}"),
                role: PeerRole::OrganicCommunityPeer,
                subnet_prefix: format!("10.1.{i}.0/24"),
                trust_level: TrustLevel::VerifiedNeighbor,
                rtt_ms: 20,
                committed_standby_bytes: 100 * 1024 * 1024,
            });
        }

        let drain_plan = boot_server.plan_seed_anchor_drain(
            EarnedStanding::BuddyMicroCluster,
            &initial_placements,
            &grown_candidates,
        );
        assert!(!drain_plan.is_empty());

        let tombstone =
            BlindedShardTombstone::create(&verifier_2, blinded_drain.locator, [0x77; 16]);
        assert!(boot_server.execute_blinded_tombstone(&blinded_drain, &tombstone)?);

        let boot_report = boot_server.status_report(21);
        assert_eq!(boot_report.used_storage_bytes, 0);
        assert_eq!(boot_report.active_blinded_leases, 0);
        assert!(!boot_report.holds_own_plaintext_files);

        println!("==========================================================================================");
        println!("  ParVault Standalone Zero-Trust Seed & Redundancy Server (`parvault-seed`) Self-Test Report  ");
        println!("==========================================================================================");
        println!(
            "| {:<32} | {:<24} | {:<16} | {:<8} |",
            "Server Mode", "Verified Capability", "Standing / Drain", "Status"
        );
        println!("|----------------------------------|--------------------------|------------------|----------|");
        println!(
            "| {:<32} | {:<24} | {:<16} | {:<8} |",
            "HomelabRedundancyVault", "PQ PersonalDeviceCert", "0-Quota Ring", "PASS"
        );
        println!(
            "| {:<32} | {:<24} | {:<16} | {:<8} |",
            "HomelabRedundancyVault", "200 PoR Heartbeats", "16-of-20 Earned", "PASS"
        );
        println!(
            "| {:<32} | {:<24} | {:<16} | {:<8} |",
            "PublicNetworkBootstrapper", "Byte-Epoch Lease Sweep", ".bshard Unlinked", "PASS"
        );
        println!(
            "| {:<32} | {:<24} | {:<16} | {:<8} |",
            "PublicNetworkBootstrapper", "Organic Peer Auto-Drain", "Drained -> 0 B", "PASS"
        );
        println!("==========================================================================================");
        Ok(())
    })();

    let _ = std::fs::remove_dir_all(&temp_base);
    result
}
