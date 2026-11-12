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

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use libp2p::{futures::StreamExt, swarm::SwarmEvent, Multiaddr};
use parvault::network::server_events::ServerSwarmEvents;
use parvault::network::wire_handler::{
    extract_ip_from_multiaddr, handle_seed_wire_request, resolve_seed_council_and_quorum,
    SeedWireHandlerCtx,
};
use parvault::{
    admin_rpc::{
        spawn_admin_rpc_listener, SeedAdminRequest, SeedAdminResponse, SeedTelemetrySnapshot,
    },
    bootstrap::{
        BlindedShardTombstone, EarnedStanding, ElasticBootstrapEngine, ElasticPeerCandidate,
        PeerRole, PersonalDeviceCert, SeedServerMode, ZeroTrustSeedServer,
    },
    crypto::{
        pqc::{HybridKemKeypair, HybridPqPublicKey, HybridPqSigningKeypair},
        MasterKey, NodeIdentity,
    },
    network::{
        build_mesh_server_swarm, derive_4word_pairing_sas, extract_listen_port_and_ip,
        open_public_tracker_card, resolve_zero_config_peers, KnownPeersStore, LanBeaconConfig,
        LanBeaconResponder, MeshClient, TrustPoolMode, WanRendezvousRegistry, WebOfTrustRegistry,
        DEFAULT_LAN_DISCOVERY_PORT, DEFAULT_LAN_PAIRING_NONCE, DEFAULT_PUBLIC_WOT_POW_BITS,
        DEFAULT_SUBTREE_SLASH_LIMIT,
    },
    por::PorVerifierEngine,
    router_nas::read_linux_process_memory_kib,
    sharding::merkle::hash_shard_leaf,
    storage::{
        load_or_generate_tracker_admin_identity, AnonymousQuotaVoucher, BlindedShardCapability,
        BlindedShardId, BlockStore, EvictionPurgeReport, EvictionTarget,
        PrivacyPreservingEvictionEngine, PublicTrackerTakedownQueue, QuotaManager, ShardId,
        SignedBadActorEvictionOrder, TakedownReviewStatus, TrustLevel, VoucherNullifierLedger,
    },
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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

        /// Optional UDP port for signed Home LAN zero-IP discovery (default: 4009)
        #[arg(long)]
        lan_discovery_port: Option<u16>,

        /// Disable signed Home LAN UDP/registry beacon responder
        #[arg(long, default_value_t = false)]
        no_lan_discovery: bool,

        /// Opt-in out-of-band `parvault-control` Admin RPC TCP listen address (disabled by default when omitted)
        #[arg(long)]
        admin_rpc_listen: Option<SocketAddr>,

        /// Authorized 64-char hex Ed25519 operator public key(s) for Zero-Key-On-VPS Admin RPC (`--admin-rpc-pubkey <HEX>`)
        #[arg(long, visible_alias = "admin-rpc-pubkeys", value_delimiter = ',')]
        admin_rpc_pubkey: Vec<String>,

        /// Optional Federated M-of-N Public Tracker Council 64-char hex Ed25519 public keys (`--council-pubkeys <CSV>`)
        #[arg(long, visible_alias = "council-pubkey", value_delimiter = ',')]
        council_pubkeys: Vec<String>,

        /// Optional explicit M-of-N tracker eviction quorum threshold override
        #[arg(long)]
        council_quorum: Option<usize>,

        /// Zero-filesystem mode for read-only containers (`docker run --read-only`) and NAND/eMMC routers (`0` disk writes)
        #[arg(long, default_value_t = false)]
        no_fs: bool,

        /// Bounded in-memory shard cache ceiling in MiB (implies `--no-fs`; defaults to `64` MiB when `--no-fs` is set)
        #[arg(long, value_name = "MIB")]
        in_memory_mb: Option<u64>,

        /// Optional environment variable holding a 64-char hex Ed25519 seed for deterministic identity in `--no-fs` mode
        #[arg(long, value_name = "ENV_VAR")]
        identity_env: Option<String>,

        /// Optional read-only file (raw 32-byte seed or 64-char hex) for deterministic identity in `--no-fs` mode
        #[arg(long, value_name = "PATH")]
        identity_file: Option<PathBuf>,
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

    /// Evict and zero-shred (0x00) shards linked to a bad-actor IP, subnet, PeerId, Ed25519 pubkey, Merkle root, or blinded locator (ADR-19)
    Evict {
        /// Seed server data directory
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,

        /// Bad-actor IPv4 or IPv6 address (stored only as keyed HMAC-SHA256 tag)
        #[arg(long)]
        ip: Option<std::net::IpAddr>,

        /// Bad-actor IPv4 `/24` or IPv6 `/48` CIDR subnet (stored only as keyed HMAC-SHA256 tag)
        #[arg(long)]
        subnet: Option<String>,

        /// Bad-actor libp2p PeerId or device_peer_id
        #[arg(long)]
        peer_id: Option<String>,

        /// Bad-actor or voucher cohort 64-char hex Ed25519 public key
        #[arg(long)]
        pubkey_hex: Option<String>,

        /// Illegal-content 64-char hex Stripe Merkle Root
        #[arg(long)]
        merkle_root: Option<String>,

        /// Anonymized 64-char hex BlindedShardId locator
        #[arg(long)]
        locator: Option<String>,

        /// Human-readable audit reason (<= 256 bytes)
        #[arg(long, default_value = "seed-operator-eviction")]
        reason: String,

        /// Sign and propagate eviction order(s) (including resolved IP cohort pubkeys) to peers
        #[arg(long, default_value_t = false)]
        propagate: bool,
    },

    /// Public Tracker Operator governance, abuse takedown review queue, emergency warrants, and M-of-N council co-signing (ADR-19)
    Admin {
        #[command(subcommand)]
        action: SeedAdminAction,
    },

    /// Execute built-in end-to-end verification of both `HomelabRedundancyVault` and `PublicNetworkBootstrapper` modes
    SelfTest,
}

#[derive(Subcommand, Debug)]
enum SeedAdminAction {
    /// Display this Public Tracker's persistent `tracker_admin.seed` Ed25519 authority public key
    ShowAuthority {
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,
    },
    /// List queued cryptographic abuse takedown reports and emergency warrant audit records
    ListTakedowns {
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,
    },
    /// Inspect cryptographic burden-of-proof details (`verified_plaintext_sha256`, stripes, reporter) for a queued report
    InspectTakedown {
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,
        #[arg(long)]
        report_id: String,
    },
    /// Approve a PendingAdminReview takedown, zero-shred local shards, sign eviction orders, and optionally export/propagate
    ApproveTakedown {
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,
        #[arg(long)]
        report_id: String,
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long)]
        export_order: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        propagate: bool,
    },
    /// Reject a baseless or non-violating PendingAdminReview takedown report without deleting shards
    RejectTakedown {
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,
        #[arg(long)]
        report_id: String,
        #[arg(long, default_value = "rejected-by-admin")]
        reason: String,
    },
    /// Issue an audited emergency law-enforcement / warrant eviction (strictly restricted to Public Trackers)
    EmergencyEvict {
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,
        #[arg(long)]
        ip: Option<std::net::IpAddr>,
        #[arg(long)]
        subnet: Option<String>,
        #[arg(long)]
        peer_id: Option<String>,
        #[arg(long)]
        pubkey_hex: Option<String>,
        #[arg(long)]
        merkle_root: Option<String>,
        #[arg(long)]
        locator: Option<String>,
        #[arg(long, visible_alias = "reason")]
        warrant_ref: String,
        #[arg(long)]
        export_order: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        propagate: bool,
    },
    /// Co-sign an exported `SignedBadActorEvictionOrder` bundle as an independent M-of-N Public Tracker Council operator
    CosignEviction {
        #[arg(long, default_value = "./.parvault-seed-data")]
        data_dir: PathBuf,
        #[arg(long)]
        order_file: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        propagate: bool,
    },
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
            lan_discovery_port,
            no_lan_discovery,
            admin_rpc_listen,
            admin_rpc_pubkey,
            council_pubkeys,
            council_quorum,
            no_fs,
            in_memory_mb,
            identity_env,
            identity_file,
        } => {
            let mut explicit_admin_pks = Vec::new();
            for raw_hex in &admin_rpc_pubkey {
                if !raw_hex.trim().is_empty() {
                    let pk = parse_hex_32(raw_hex, "--admin-rpc-pubkey")?;
                    if !explicit_admin_pks.contains(&pk) {
                        explicit_admin_pks.push(pk);
                    }
                }
            }
            let mut explicit_council_pks = Vec::new();
            for raw_hex in &council_pubkeys {
                if !raw_hex.trim().is_empty() {
                    let pk = parse_hex_32(raw_hex, "--council-pubkeys")?;
                    if !explicit_council_pks.contains(&pk) {
                        explicit_council_pks.push(pk);
                    }
                }
            }
            let has_external_admin_keys =
                !explicit_admin_pks.is_empty() || !explicit_council_pks.is_empty();
            let in_memory_mode = no_fs || in_memory_mb.is_some();

            let discovery_port = resolve_seed_lan_port(lan_discovery_port);
            let lan_enabled = resolve_seed_lan_enabled(no_lan_discovery);
            let node_identity = if let Some(ref env_name) = identity_env {
                let raw_val = std::env::var(env_name.trim()).map_err(|_| {
                    anyhow::anyhow!("--identity-env variable '{}' is not set", env_name.trim())
                })?;
                let seed = parse_hex_32(&raw_val, "--identity-env")?;
                NodeIdentity::from_seed(seed)
            } else if let Some(ref id_path) = identity_file {
                let raw_bytes = std::fs::read(id_path)?;
                let seed = if raw_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&raw_bytes);
                    arr
                } else {
                    let as_txt = std::str::from_utf8(&raw_bytes).map_err(|_| {
                        anyhow::anyhow!("--identity-file must be 32 raw bytes or 64-char hex")
                    })?;
                    parse_hex_32(as_txt, "--identity-file")?
                };
                NodeIdentity::from_seed(seed)
            } else if in_memory_mode {
                NodeIdentity::generate()
            } else {
                NodeIdentity::load_or_generate_in_dir(&data_dir)?
            };

            parvault::network::admission::install_process_source(
                &data_dir,
                mode == CliSeedMode::PublicBootstrap,
            );
            let seed_peers =
                if effective_peers.is_empty() && lan_enabled && !once && !in_memory_mode {
                    resolve_zero_config_peers(
                        &data_dir,
                        &[],
                        discovery_port,
                        Duration::from_millis(200),
                    )
                } else {
                    effective_peers.clone()
                };
            let mesh_client = if in_memory_mode {
                MeshClient::new(node_identity.clone(), seed_peers, None)
            } else {
                MeshClient::new(node_identity.clone(), seed_peers, None)
                    .with_data_dir_discovery(data_dir.clone(), discovery_port)
            };

            let block_store = if in_memory_mode {
                let ram_cap_bytes = in_memory_mb
                    .unwrap_or(64)
                    .max(1)
                    .saturating_mul(1024 * 1024);
                let mut quota = QuotaManager::new(ram_cap_bytes, ram_cap_bytes);
                quota.set_min_free_disk_bytes(0);
                BlockStore::new_in_memory(quota).with_mesh_client(mesh_client)
            } else {
                let max_bytes = max_gb.saturating_mul(1024 * 1024 * 1024);
                let grace_bytes = 2 * 1024 * 1024 * 1024;
                let quota = QuotaManager::new(max_bytes, grace_bytes);
                let bs = BlockStore::new(&data_dir, quota)?.with_mesh_client(mesh_client);
                let mode_marker = match mode {
                    CliSeedMode::HomelabVault => "homelab-vault",
                    CliSeedMode::PublicBootstrap => "public-bootstrap",
                };
                let _ = BlockStore::atomic_write_file(
                    &data_dir.join("seed_mode.txt"),
                    mode_marker.as_bytes(),
                );
                // Zero-Private-Key-On-VPS invariant (`ADR-19`): NEVER auto-generate `tracker_admin.seed`
                // when `--admin-rpc-pubkey` or `--council-pubkeys` is supplied!
                if mode == CliSeedMode::PublicBootstrap
                    && (!has_external_admin_keys || data_dir.join("tracker_admin.seed").exists())
                {
                    let _ = load_or_generate_tracker_admin_identity(&data_dir)?;
                }
                bs
            };

            let mut ephemeral_pq_fp: Option<String> = None;
            let server = match mode {
                CliSeedMode::HomelabVault => {
                    let owner_pubkey = if let Some(hex_str) = owner_pq_pubkey_hex {
                        HybridPqPublicKey::from_hex(hex_str.trim())?
                    } else if in_memory_mode {
                        let eph = HybridPqSigningKeypair::generate()?;
                        let pk = eph.public_key();
                        info!(
                            fingerprint = %pk.fingerprint_hex(),
                            "Generated ephemeral in-memory homelab HybridPqPublicKey (--no-fs)"
                        );
                        pk
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
                    ephemeral_pq_fp = Some(owner_pubkey.fingerprint_hex());
                    ZeroTrustSeedServer::new_homelab_vault(
                        "parvault-seed-homelab-vault",
                        block_store.clone(),
                        owner_pubkey,
                        grace_epochs,
                    )
                }
                CliSeedMode::PublicBootstrap => {
                    let genesis_pubkey = if in_memory_mode {
                        if let Ok(env_hex) = std::env::var("PARVAULT_GENESIS_PUBKEY_HEX") {
                            parse_hex_32(&env_hex, "PARVAULT_GENESIS_PUBKEY_HEX")
                                .unwrap_or_else(|_| node_identity.public_key_bytes())
                        } else {
                            node_identity.public_key_bytes()
                        }
                    } else {
                        parvault::network::admission::server_ring_genesis(&data_dir, None, true)?
                    };
                    info!(
                        lease_epochs,
                        grace_epochs,
                        in_memory_mode,
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
            let display_dir = if in_memory_mode {
                Path::new("in-memory (--no-fs)")
            } else {
                data_dir.as_path()
            };
            print_status_report(&listen, display_dir, &report)?;

            if once {
                return Ok(());
            }

            run_seed_listener_loop(SeedListenerConfig {
                listen,
                node_identity,
                precomputed_pq_fp: ephemeral_pq_fp,
                block_store,
                server,
                lan_discovery_port,
                no_lan_discovery,
                admin_rpc_listen,
                explicit_admin_pks,
                explicit_council_pks,
                council_quorum,
                effective_peers,
            })
            .await?;
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
                        parvault::network::admission::server_ring_genesis(&data_dir, None, true)?;
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
            let genesis_pubkey =
                parvault::network::admission::server_ring_genesis(&data_dir, None, true)?;
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
            let discovery_port = resolve_seed_lan_port(None);
            let identity = NodeIdentity::load_or_generate_in_dir(&data_dir)?;
            let resolved_peers = if effective_peers.is_empty() {
                resolve_zero_config_peers(
                    &data_dir,
                    &[],
                    discovery_port,
                    Duration::from_millis(300),
                )
            } else {
                effective_peers.clone()
            };
            let mesh_client = MeshClient::new(identity.clone(), resolved_peers, None)
                .with_data_dir_discovery(data_dir.clone(), discovery_port);
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

        SeedCommand::Evict {
            data_dir,
            ip,
            subnet,
            peer_id,
            pubkey_hex,
            merkle_root,
            locator,
            reason,
            propagate,
        } => {
            let target =
                parse_seed_eviction_target(ip, subnet, peer_id, pubkey_hex, merkle_root, locator)?;
            let quota = QuotaManager::new(500 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
            let block_store = BlockStore::new(&data_dir, quota)?;
            let mut eviction = PrivacyPreservingEvictionEngine::load_or_init(&data_dir)?;
            let local_report = eviction.evict_target(&target, &block_store)?;

            let mut remote_report = EvictionPurgeReport::default();
            let mut propagated_orders = 0usize;
            if propagate {
                let is_homelab = is_seed_homelab_mode(&data_dir);
                let issuer = if is_homelab {
                    NodeIdentity::load_or_generate_in_dir(&data_dir)?
                } else {
                    load_or_generate_tracker_admin_identity(&data_dir)?
                };
                let now_ms = seed_now_ms();
                let mut orders = vec![SignedBadActorEvictionOrder::issue(
                    &issuer,
                    target.clone(),
                    reason.clone(),
                    now_ms,
                    0,
                )];
                match &target {
                    EvictionTarget::IpAddress(bad_ip) => {
                        for pk in eviction.resolve_pubkeys_for_ip(*bad_ip) {
                            orders.push(SignedBadActorEvictionOrder::issue(
                                &issuer,
                                EvictionTarget::PeerOrIssuerPubkey(pk),
                                reason.clone(),
                                now_ms,
                                0,
                            ));
                        }
                    }
                    EvictionTarget::IpSubnet(cidr) => {
                        for pk in eviction.resolve_pubkeys_for_subnet(cidr) {
                            orders.push(SignedBadActorEvictionOrder::issue(
                                &issuer,
                                EvictionTarget::PeerOrIssuerPubkey(pk),
                                reason.clone(),
                                now_ms,
                                0,
                            ));
                        }
                    }
                    _ => {}
                }
                propagated_orders = orders.len();
                let mesh_client = build_seed_propagation_client(&data_dir, &effective_peers)?;
                for order in &orders {
                    let rep = mesh_client.propagate_eviction_order_to_peers(&[], order);
                    remote_report.merge(&rep);
                }
            }

            println!("=== ParVault Seed Privacy-Preserving Eviction Complete (ADR-19) ===");
            println!("Data Directory           : {}", data_dir.display());
            println!(
                "Local Regular Shards     : {} zero-shredded (0x00)",
                local_report.purged_regular_shards
            );
            println!(
                "Local Blinded Shards     : {} zero-shredded (0x00)",
                local_report.purged_blinded_shards
            );
            println!(
                "Local Zero-Wiped Bytes   : {} bytes",
                local_report.zero_wiped_bytes
            );
            println!(
                "HMAC Firewall Installed  : {} (zero plaintext IPs on disk)",
                local_report.firewall_rule_installed
            );
            if propagate {
                println!(
                    "Mesh Propagation         : {} signed order(s) broadcast (remote purged: {} regular, {} blinded, {} bytes)",
                    propagated_orders,
                    remote_report.purged_regular_shards,
                    remote_report.purged_blinded_shards,
                    remote_report.zero_wiped_bytes
                );
            }
        }

        SeedCommand::Admin { action } => match action {
            SeedAdminAction::ShowAuthority { data_dir } => {
                let admin_id = load_or_generate_tracker_admin_identity(&data_dir)?;
                let node_id = NodeIdentity::load_or_generate_in_dir(&data_dir)?;
                println!("=== ParVault Public Tracker Admin Authority (ADR-19) ===");
                println!("Data Directory              : {}", data_dir.display());
                println!(
                    "Tracker Admin Pubkey (hex)  : {}",
                    hex::encode(admin_id.public_key_bytes())
                );
                println!("Node Transport Peer ID      : {}", node_id.device_peer_id());
                println!(
                    "Council Config Snippet      : eviction_authorities = [\"{}\"]",
                    hex::encode(admin_id.public_key_bytes())
                );
            }
            SeedAdminAction::ListTakedowns { data_dir } => {
                let queue = PublicTrackerTakedownQueue::load_or_init(&data_dir)?;
                let entries = queue.list_entries();
                let emergencies = queue.list_emergency_actions();
                println!("=== ParVault Public Tracker Takedown Governance Queue (ADR-19) ===");
                println!("Data Directory              : {}", data_dir.display());
                println!("Queued Abuse Reports        : {}", entries.len());
                for entry in &entries {
                    let status_label = match &entry.status {
                        TakedownReviewStatus::PendingAdminReview => {
                            "PendingAdminReview".to_string()
                        }
                        TakedownReviewStatus::Approved {
                            issued_order_ids, ..
                        } => {
                            format!("Approved ({} orders)", issued_order_ids.len())
                        }
                        TakedownReviewStatus::Rejected { reason, .. } => {
                            format!("Rejected ({reason})")
                        }
                    };
                    println!(
                        "  - report_id={} | status={} | file_root={} | plaintext_sha256={} | stripes={}",
                        hex::encode(entry.report.report_id),
                        status_label,
                        hex::encode(entry.proof_outcome.file_merkle_root),
                        hex::encode(entry.proof_outcome.verified_plaintext_sha256),
                        entry.proof_outcome.stripe_merkle_roots.len()
                    );
                }
                if !emergencies.is_empty() {
                    println!("Audited Emergency Actions   : {}", emergencies.len());
                    for act in &emergencies {
                        println!(
                            "  - action_id={} | warrant_ref={} | orders={} | wiped={} bytes",
                            hex::encode(act.action_id),
                            act.warrant_or_emergency_ref,
                            act.issued_order_ids.len(),
                            act.local_purge.zero_wiped_bytes
                        );
                    }
                }
            }
            SeedAdminAction::InspectTakedown {
                data_dir,
                report_id,
            } => {
                let rid = parse_hex_32(&report_id, "report_id")?;
                let queue = PublicTrackerTakedownQueue::load_or_init(&data_dir)?;
                let entry = queue.get_entry(&rid).ok_or_else(|| {
                    anyhow::anyhow!("Takedown report {} not found in queue", hex::encode(rid))
                })?;
                println!("=== ParVault Verifiable Abuse Report Inspection (ADR-19) ===");
                println!(
                    "Report ID                   : {}",
                    hex::encode(entry.report.report_id)
                );
                println!("Status                      : {:?}", entry.status);
                println!(
                    "Submitted At (Unix ms)      : {}",
                    entry.report.submitted_at_ms
                );
                println!(
                    "Reporter Contact            : {}",
                    entry.report.reporter_id_or_contact
                );
                println!(
                    "Reporter Ed25519 Pubkey     : {}",
                    hex::encode(entry.report.reporter_ed25519_pubkey)
                );
                println!(
                    "Legal Allegation            : {}",
                    entry.report.legal_allegation
                );
                println!(
                    "File Merkle Root            : {}",
                    hex::encode(entry.proof_outcome.file_merkle_root)
                );
                println!(
                    "Verified Stripe Index       : {} ({} total stripes)",
                    entry.proof_outcome.verified_stripe_index,
                    entry.proof_outcome.stripe_merkle_roots.len()
                );
                println!(
                    "Verified Plaintext SHA-256  : {} ({} bytes; plaintext zeroized in RAM)",
                    hex::encode(entry.proof_outcome.verified_plaintext_sha256),
                    entry.proof_outcome.verified_plaintext_len
                );
            }
            SeedAdminAction::ApproveTakedown {
                data_dir,
                report_id,
                note,
                export_order,
                propagate,
            } => {
                ensure_public_tracker_mode(&data_dir, "approve-takedown")?;
                let rid = parse_hex_32(&report_id, "report_id")?;
                let admin_id = load_or_generate_tracker_admin_identity(&data_dir)?;
                let quota = QuotaManager::new(500 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
                let block_store = BlockStore::new(&data_dir, quota)?;
                let mut eviction = PrivacyPreservingEvictionEngine::load_or_init(&data_dir)?;
                let mut queue = PublicTrackerTakedownQueue::load_or_init(&data_dir)?;
                let (orders, local_purge) = queue.approve_takedown(
                    &rid,
                    &admin_id,
                    &note,
                    seed_now_ms(),
                    &mut eviction,
                    &block_store,
                )?;
                if let Some(ref out_path) = export_order {
                    export_eviction_orders_json(out_path, &orders)?;
                }
                let mut remote_purge = EvictionPurgeReport::default();
                if propagate {
                    let mesh_client = build_seed_propagation_client(&data_dir, &effective_peers)?;
                    for order in &orders {
                        let rep = mesh_client.propagate_eviction_order_to_peers(&[], order);
                        remote_purge.merge(&rep);
                    }
                }
                println!("=== ParVault Public Tracker Takedown Approved (ADR-19) ===");
                println!("Report ID                   : {}", hex::encode(rid));
                println!(
                    "Admin Signer Pubkey         : {}",
                    hex::encode(admin_id.public_key_bytes())
                );
                println!("Signed Eviction Orders      : {}", orders.len());
                println!(
                    "Local Shards Shredded (0x00): {} regular, {} blinded ({} bytes wiped)",
                    local_purge.purged_regular_shards,
                    local_purge.purged_blinded_shards,
                    local_purge.zero_wiped_bytes
                );
                if let Some(ref out_path) = export_order {
                    println!("Exported Order Bundle       : {}", out_path.display());
                }
                if propagate {
                    println!(
                        "Swarm Broadcast Summary     : {} regular, {} blinded ({} bytes wiped across peers)",
                        remote_purge.purged_regular_shards,
                        remote_purge.purged_blinded_shards,
                        remote_purge.zero_wiped_bytes
                    );
                }
            }
            SeedAdminAction::RejectTakedown {
                data_dir,
                report_id,
                reason,
            } => {
                let rid = parse_hex_32(&report_id, "report_id")?;
                let admin_id = load_or_generate_tracker_admin_identity(&data_dir)?;
                let mut queue = PublicTrackerTakedownQueue::load_or_init(&data_dir)?;
                queue.reject_takedown(&rid, &admin_id, &reason, seed_now_ms())?;
                println!("=== ParVault Public Tracker Takedown Rejected (No Shards Deleted) ===");
                println!("Report ID                   : {}", hex::encode(rid));
                println!("Rejection Reason            : {}", reason);
            }
            SeedAdminAction::EmergencyEvict {
                data_dir,
                ip,
                subnet,
                peer_id,
                pubkey_hex,
                merkle_root,
                locator,
                warrant_ref,
                export_order,
                propagate,
            } => {
                ensure_public_tracker_mode(&data_dir, "emergency-evict")?;
                if warrant_ref.trim().is_empty() {
                    anyhow::bail!("--warrant-ref cannot be empty for audited emergency eviction");
                }
                let target = parse_seed_eviction_target(
                    ip,
                    subnet,
                    peer_id,
                    pubkey_hex,
                    merkle_root,
                    locator,
                )?;
                let admin_id = load_or_generate_tracker_admin_identity(&data_dir)?;
                let quota = QuotaManager::new(500 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
                let block_store = BlockStore::new(&data_dir, quota)?;
                let mut eviction = PrivacyPreservingEvictionEngine::load_or_init(&data_dir)?;
                let mut queue = PublicTrackerTakedownQueue::load_or_init(&data_dir)?;
                let (orders, local_purge) = queue.issue_emergency_admin_eviction(
                    &admin_id,
                    target,
                    &warrant_ref,
                    seed_now_ms(),
                    &mut eviction,
                    &block_store,
                )?;
                if let Some(ref out_path) = export_order {
                    export_eviction_orders_json(out_path, &orders)?;
                }
                let mut remote_purge = EvictionPurgeReport::default();
                if propagate {
                    let mesh_client = build_seed_propagation_client(&data_dir, &effective_peers)?;
                    for order in &orders {
                        let rep = mesh_client.propagate_eviction_order_to_peers(&[], order);
                        remote_purge.merge(&rep);
                    }
                }
                println!(
                    "=== ParVault Public Tracker Emergency Warrant Eviction Issued (ADR-19) ==="
                );
                println!("Warrant / Emergency Ref     : {}", warrant_ref.trim());
                println!(
                    "Admin Signer Pubkey         : {}",
                    hex::encode(admin_id.public_key_bytes())
                );
                println!("Signed Eviction Orders      : {}", orders.len());
                println!(
                    "Local Shards Shredded (0x00): {} regular, {} blinded ({} bytes wiped)",
                    local_purge.purged_regular_shards,
                    local_purge.purged_blinded_shards,
                    local_purge.zero_wiped_bytes
                );
                if let Some(ref out_path) = export_order {
                    println!("Exported Order Bundle       : {}", out_path.display());
                }
                if propagate {
                    println!(
                        "Swarm Broadcast Summary     : {} regular, {} blinded ({} bytes wiped across peers)",
                        remote_purge.purged_regular_shards,
                        remote_purge.purged_blinded_shards,
                        remote_purge.zero_wiped_bytes
                    );
                }
            }
            SeedAdminAction::CosignEviction {
                data_dir,
                order_file,
                out,
                propagate,
            } => {
                ensure_public_tracker_mode(&data_dir, "cosign-eviction")?;
                let admin_id = load_or_generate_tracker_admin_identity(&data_dir)?;
                let dest_path = out.as_ref().unwrap_or(&order_file);
                let (orders, newly_cosigned) =
                    load_and_cosign_eviction_orders(&order_file, dest_path, &admin_id)?;

                let mut local_purge = EvictionPurgeReport::default();
                let quota = QuotaManager::new(500 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
                let block_store = BlockStore::new(&data_dir, quota)?;
                let mut eviction = PrivacyPreservingEvictionEngine::load_or_init(&data_dir)?;
                let genesis_pk =
                    parvault::network::admission::server_ring_genesis(&data_dir, None, true)?;
                let (council, min_quorum) = resolve_seed_council_and_quorum(
                    &data_dir,
                    SeedServerMode::PublicNetworkBootstrapper,
                    Some(admin_id.public_key_bytes()),
                    &[],
                    None,
                    genesis_pk,
                );
                let now_ms = seed_now_ms();
                for order in &orders {
                    if let Ok(rep) = eviction.apply_signed_eviction_order_with_quorum(
                        order,
                        None,
                        &council,
                        min_quorum,
                        now_ms,
                        &block_store,
                    ) {
                        local_purge.merge(&rep);
                    }
                }

                let mut remote_purge = EvictionPurgeReport::default();
                if propagate {
                    let mesh_client = build_seed_propagation_client(&data_dir, &effective_peers)?;
                    for order in &orders {
                        let rep = mesh_client.propagate_eviction_order_to_peers(&[], order);
                        remote_purge.merge(&rep);
                    }
                }

                let total_sigs = orders
                    .first()
                    .map(|o| 1 + o.cosignatures.len())
                    .unwrap_or(0);
                println!(
                    "=== ParVault Tracker Council Co-Signature Applied (M-of-N Quorum, ADR-19) ==="
                );
                println!(
                    "Cosigner Admin Pubkey       : {}",
                    hex::encode(admin_id.public_key_bytes())
                );
                println!(
                    "Orders Processed            : {} ({} newly co-signed, {} total signers on bundle)",
                    orders.len(),
                    newly_cosigned,
                    total_sigs
                );
                println!("Saved Co-Signed Bundle      : {}", dest_path.display());
                println!(
                    "Local Purge Summary         : {} regular, {} blinded ({} bytes wiped)",
                    local_purge.purged_regular_shards,
                    local_purge.purged_blinded_shards,
                    local_purge.zero_wiped_bytes
                );
                if propagate {
                    println!(
                        "Swarm Broadcast Summary     : {} regular, {} blinded ({} bytes wiped across peers)",
                        remote_purge.purged_regular_shards,
                        remote_purge.purged_blinded_shards,
                        remote_purge.zero_wiped_bytes
                    );
                }
            }
        },

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

fn resolve_seed_lan_port(cli_port: Option<u16>) -> u16 {
    if let Some(port) = cli_port {
        return port;
    }
    if let Ok(env_port) = std::env::var("PARVAULT_LAN_DISCOVERY_PORT") {
        if let Ok(parsed) = env_port.trim().parse::<u16>() {
            if parsed > 0 {
                return parsed;
            }
        }
    }
    DEFAULT_LAN_DISCOVERY_PORT
}

fn resolve_seed_lan_enabled(cli_no_lan_discovery: bool) -> bool {
    if cli_no_lan_discovery {
        return false;
    }
    if let Ok(env_dis) = std::env::var("PARVAULT_NO_LAN_DISCOVERY") {
        let v = env_dis.trim().to_ascii_lowercase();
        if matches!(v.as_str(), "1" | "true" | "yes") {
            return false;
        }
    }
    true
}

fn is_seed_homelab_mode(data_dir: &Path) -> bool {
    std::fs::read_to_string(data_dir.join("seed_mode.txt"))
        .map(|s| s.trim() == "homelab-vault")
        .unwrap_or(false)
}

fn ensure_public_tracker_mode(data_dir: &Path, subcommand: &str) -> anyhow::Result<()> {
    if is_seed_homelab_mode(data_dir) {
        anyhow::bail!(
            "Refused: `parvault-seed admin {subcommand}` is strictly disabled in `homelab-vault` (PrivateRing) mode (ADR-19 Strict Mode Isolation)"
        );
    }
    Ok(())
}

fn parse_hex_32(hex_str: &str, field_name: &str) -> anyhow::Result<[u8; 32]> {
    let raw = hex::decode(hex_str.trim())
        .map_err(|e| anyhow::anyhow!("Invalid hex in {field_name}: {e}"))?;
    if raw.len() != 32 {
        anyhow::bail!(
            "Expected 64-character hex (32 bytes) for {field_name}, got {} bytes",
            raw.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn parse_seed_eviction_target(
    ip: Option<std::net::IpAddr>,
    subnet: Option<String>,
    peer_id: Option<String>,
    pubkey_hex: Option<String>,
    merkle_root: Option<String>,
    locator: Option<String>,
) -> anyhow::Result<EvictionTarget> {
    let provided = [
        ip.is_some(),
        subnet.is_some(),
        peer_id.is_some(),
        pubkey_hex.is_some(),
        merkle_root.is_some(),
        locator.is_some(),
    ]
    .into_iter()
    .filter(|b| *b)
    .count();
    if provided != 1 {
        anyhow::bail!(
            "Specify exactly one eviction target flag: --ip, --subnet, --peer-id, --pubkey-hex, --merkle-root, or --locator"
        );
    }
    if let Some(addr) = ip {
        Ok(EvictionTarget::IpAddress(addr))
    } else if let Some(cidr) = subnet {
        Ok(EvictionTarget::IpSubnet(cidr.trim().to_string()))
    } else if let Some(pid) = peer_id {
        Ok(EvictionTarget::Libp2pPeerId(pid.trim().to_string()))
    } else if let Some(pk) = pubkey_hex {
        Ok(EvictionTarget::PeerOrIssuerPubkey(parse_hex_32(
            &pk,
            "--pubkey-hex",
        )?))
    } else if let Some(root) = merkle_root {
        Ok(EvictionTarget::StripeMerkleRoot(parse_hex_32(
            &root,
            "--merkle-root",
        )?))
    } else if let Some(loc) = locator {
        Ok(EvictionTarget::BlindedLocator(parse_hex_32(
            &loc,
            "--locator",
        )?))
    } else {
        unreachable!()
    }
}

fn export_eviction_orders_json(
    out_path: &Path,
    orders: &[SignedBadActorEvictionOrder],
) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(orders)?;
    BlockStore::atomic_write_file(out_path, &json)?;
    Ok(())
}

fn load_and_cosign_eviction_orders(
    in_path: &Path,
    out_path: &Path,
    cosigner: &NodeIdentity,
) -> anyhow::Result<(Vec<SignedBadActorEvictionOrder>, usize)> {
    let raw = std::fs::read(in_path)?;
    if let Ok(mut list) = serde_json::from_slice::<Vec<SignedBadActorEvictionOrder>>(&raw) {
        if list.is_empty() {
            anyhow::bail!(
                "Order file {} contains zero eviction orders",
                in_path.display()
            );
        }
        let mut added = 0usize;
        for o in &mut list {
            if !o.verify_signature() {
                anyhow::bail!("Primary signature verification failed on eviction order");
            }
            if o.add_cosignature(cosigner) {
                added += 1;
            }
        }
        BlockStore::atomic_write_file(out_path, &serde_json::to_vec_pretty(&list)?)?;
        return Ok((list, added));
    }
    if let Ok(mut single) = serde_json::from_slice::<SignedBadActorEvictionOrder>(&raw) {
        if !single.verify_signature() {
            anyhow::bail!("Primary signature verification failed on eviction order");
        }
        let added = usize::from(single.add_cosignature(cosigner));
        BlockStore::atomic_write_file(out_path, &serde_json::to_vec_pretty(&single)?)?;
        return Ok((vec![single], added));
    }
    if let Ok(mut single_bin) = bincode::deserialize::<SignedBadActorEvictionOrder>(&raw) {
        if !single_bin.verify_signature() {
            anyhow::bail!("Primary signature verification failed on binary eviction order");
        }
        let added = usize::from(single_bin.add_cosignature(cosigner));
        BlockStore::atomic_write_file(out_path, &bincode::serialize(&single_bin)?)?;
        return Ok((vec![single_bin], added));
    }
    let mut list_bin: Vec<SignedBadActorEvictionOrder> =
        bincode::deserialize(&raw).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse eviction order file {}: {e}",
                in_path.display()
            )
        })?;
    let mut added = 0usize;
    for o in &mut list_bin {
        if !o.verify_signature() {
            anyhow::bail!("Primary signature verification failed on binary eviction order");
        }
        if o.add_cosignature(cosigner) {
            added += 1;
        }
    }
    BlockStore::atomic_write_file(out_path, &bincode::serialize(&list_bin)?)?;
    Ok((list_bin, added))
}

fn push_unique_peer(peers: &mut Vec<String>, addr: String) {
    let t = addr.trim();
    if !t.is_empty() && !peers.iter().any(|existing| existing == t) {
        peers.push(t.to_string());
    }
}

fn build_seed_propagation_client(
    data_dir: &Path,
    explicit_peers: &[String],
) -> anyhow::Result<MeshClient> {
    let discovery_port = resolve_seed_lan_port(None);
    let node_id = NodeIdentity::load_or_generate_in_dir(data_dir)?;
    let mut peers: Vec<String> = Vec::new();
    for p in explicit_peers {
        push_unique_peer(&mut peers, p.clone());
    }
    let wan_reg_path = data_dir.join("wan_rendezvous.bin");
    if wan_reg_path.exists() {
        let mut reg = WanRendezvousRegistry::load_or_new(Some(&wan_reg_path));
        for entry in reg.lookup_public_swarm(64, seed_now_ms()) {
            if let Ok(card) = open_public_tracker_card(&entry) {
                for maddr in card.wan_multiaddrs {
                    let full = if maddr.contains("/p2p/") {
                        maddr
                    } else {
                        format!("{maddr}/p2p/{}", card.libp2p_peer_id)
                    };
                    push_unique_peer(&mut peers, full);
                }
            }
        }
    }
    if peers.is_empty() {
        for p in
            resolve_zero_config_peers(data_dir, &[], discovery_port, Duration::from_millis(250))
        {
            push_unique_peer(&mut peers, p);
        }
    } else {
        for p in KnownPeersStore::load(data_dir).active_multiaddrs() {
            push_unique_peer(&mut peers, p);
        }
    }
    Ok(MeshClient::new(node_id, peers, None)
        .with_data_dir_discovery(data_dir.to_path_buf(), discovery_port))
}

fn seed_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct SeedSharedState {
    server: ZeroTrustSeedServer,
    wot: WebOfTrustRegistry,
    por_verifier: PorVerifierEngine,
    nullifier_ledger: VoucherNullifierLedger,
    wan_registry: WanRendezvousRegistry,
    eviction: PrivacyPreservingEvictionEngine,
    takedown_queue: PublicTrackerTakedownQueue,
    max_probationary_lease_bytes: u64,
    epoch_counter: u64,
}

fn count_blinded_shards_on_disk(block_store: &BlockStore) -> usize {
    if block_store.is_in_memory() {
        return block_store.blinded_lease_stats().1;
    }
    let Ok(rd) = std::fs::read_dir(block_store.shards_dir()) else {
        return 0;
    };
    rd.flatten()
        .filter(|entry| {
            entry
                .path()
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|s| s.ends_with(".bshard"))
        })
        .count()
}

fn collect_public_swarm_diversity(
    wan_registry: &mut WanRendezvousRegistry,
    now_ms: u64,
) -> (usize, usize, usize, Vec<String>) {
    let entries = wan_registry.lookup_public_swarm(64, now_ms);
    let mut active_peers = 0usize;
    let mut v4_subnets: HashSet<[u8; 3]> = HashSet::new();
    let mut v6_subnets: HashSet<[u16; 3]> = HashSet::new();
    let mut multiaddrs: Vec<String> = Vec::new();

    for entry in &entries {
        if let Ok(card) = open_public_tracker_card(entry) {
            active_peers += 1;
            for raw_maddr in &card.wan_multiaddrs {
                if let Ok(maddr) = raw_maddr.parse::<Multiaddr>() {
                    if let Some(ip) = extract_ip_from_multiaddr(&maddr) {
                        match PrivacyPreservingEvictionEngine::normalize_ip(ip) {
                            std::net::IpAddr::V4(v4) => {
                                let o = v4.octets();
                                v4_subnets.insert([o[0], o[1], o[2]]);
                            }
                            std::net::IpAddr::V6(v6) => {
                                let s = v6.segments();
                                v6_subnets.insert([s[0], s[1], s[2]]);
                            }
                        }
                    }
                }
                let full = if raw_maddr.contains("/p2p/") {
                    raw_maddr.clone()
                } else {
                    format!("{raw_maddr}/p2p/{}", card.libp2p_peer_id)
                };
                push_unique_peer(&mut multiaddrs, full);
            }
        }
    }

    (active_peers, v4_subnets.len(), v6_subnets.len(), multiaddrs)
}

struct SeedListenerConfig {
    listen: String,
    node_identity: NodeIdentity,
    precomputed_pq_fp: Option<String>,
    block_store: BlockStore,
    server: ZeroTrustSeedServer,
    lan_discovery_port: Option<u16>,
    no_lan_discovery: bool,
    admin_rpc_listen: Option<SocketAddr>,
    explicit_admin_pks: Vec<[u8; 32]>,
    explicit_council_pks: Vec<[u8; 32]>,
    council_quorum: Option<usize>,
    effective_peers: Vec<String>,
}

async fn run_seed_listener_loop(cfg: SeedListenerConfig) -> anyhow::Result<()> {
    let SeedListenerConfig {
        listen,
        node_identity,
        precomputed_pq_fp,
        block_store,
        server,
        lan_discovery_port,
        no_lan_discovery,
        admin_rpc_listen,
        explicit_admin_pks,
        explicit_council_pks,
        council_quorum,
        effective_peers,
    } = cfg;
    let start_instant = Instant::now();
    let in_memory_mode = block_store.is_in_memory();
    let data_dir = block_store.root_dir().to_path_buf();
    let has_external_admin_keys =
        !explicit_admin_pks.is_empty() || !explicit_council_pks.is_empty();
    let local_tracker_admin = if in_memory_mode {
        if !has_external_admin_keys {
            Some(node_identity.clone())
        } else {
            None
        }
    } else if !has_external_admin_keys || data_dir.join("tracker_admin.seed").exists() {
        Some(load_or_generate_tracker_admin_identity(&data_dir)?)
    } else {
        None
    };
    let local_tracker_admin_pk = local_tracker_admin.as_ref().map(|id| id.public_key_bytes());

    let mut extra_council_pks = Vec::new();
    for pk in explicit_council_pks.iter().chain(explicit_admin_pks.iter()) {
        if *pk != [0u8; 32] && !extra_council_pks.contains(pk) {
            extra_council_pks.push(*pk);
        }
    }
    let advertised_admin_pk = if server.mode() == SeedServerMode::PublicNetworkBootstrapper {
        local_tracker_admin_pk
            .or_else(|| explicit_admin_pks.first().copied())
            .or_else(|| explicit_council_pks.first().copied())
    } else {
        None
    };

    let keypair = node_identity.to_libp2p_keypair()?;
    let local_peer_id = keypair.public().to_peer_id();
    let genesis_pubkey = if in_memory_mode {
        if let Ok(env_hex) = std::env::var("PARVAULT_GENESIS_PUBKEY_HEX") {
            parse_hex_32(&env_hex, "PARVAULT_GENESIS_PUBKEY_HEX")
                .unwrap_or_else(|_| node_identity.public_key_bytes())
        } else {
            node_identity.public_key_bytes()
        }
    } else {
        parvault::network::admission::server_ring_genesis(
            &data_dir,
            None,
            server.mode() == SeedServerMode::PublicNetworkBootstrapper,
        )?
    };

    let mut wot = if in_memory_mode {
        WebOfTrustRegistry::new(genesis_pubkey, DEFAULT_SUBTREE_SLASH_LIMIT)
    } else {
        WebOfTrustRegistry::with_persistence_dir(
            genesis_pubkey,
            DEFAULT_SUBTREE_SLASH_LIMIT,
            &data_dir,
        )
    };
    if server.mode() == SeedServerMode::PublicNetworkBootstrapper {
        wot.set_trust_pool_mode(TrustPoolMode::Hybrid, DEFAULT_PUBLIC_WOT_POW_BITS);
    }
    wot.protect_key(node_identity.public_key_bytes());
    let por_verifier = if in_memory_mode {
        PorVerifierEngine::new(300)
    } else {
        PorVerifierEngine::with_persistence_dir(300, &data_dir)
    };
    let nullifier_ledger = if in_memory_mode {
        VoucherNullifierLedger::new(genesis_pubkey)
    } else {
        VoucherNullifierLedger::with_persistence_dir(genesis_pubkey, &data_dir)
    };
    let pq_kem = if in_memory_mode {
        HybridKemKeypair::generate()?
    } else {
        HybridKemKeypair::load_or_generate_in_dir(&data_dir)?
    };
    let wan_registry = if in_memory_mode {
        WanRendezvousRegistry::load_or_new(None)
    } else {
        WanRendezvousRegistry::load_or_new(Some(&data_dir.join("wan_rendezvous.bin")))
    };
    let eviction = if in_memory_mode {
        PrivacyPreservingEvictionEngine::new_in_memory()
    } else {
        PrivacyPreservingEvictionEngine::load_or_init(&data_dir)?
    };
    let takedown_queue = if in_memory_mode {
        PublicTrackerTakedownQueue::new_in_memory()
    } else {
        PublicTrackerTakedownQueue::load_or_init(&data_dir)?
    };
    let mut server_events = ServerSwarmEvents::new(false);

    let mut swarm =
        build_mesh_server_swarm(keypair, false, resolve_seed_lan_enabled(no_lan_discovery))?;
    let tcp_addr: Multiaddr = listen.parse()?;
    swarm.listen_on(tcp_addr.clone())?;

    let seed_mode = server.mode();
    let init_report = server.status_report(1);
    let shared = Arc::new(Mutex::new(SeedSharedState {
        server,
        wot,
        por_verifier,
        nullifier_ledger,
        wan_registry,
        eviction,
        takedown_queue,
        max_probationary_lease_bytes: 64 * 1024 * 1024,
        epoch_counter: 1,
    }));

    let _admin_rpc_handle = if let Some(bind_addr) = admin_rpc_listen {
        let mut allowed_pks: Vec<[u8; 32]> = Vec::new();
        for pk in explicit_admin_pks
            .iter()
            .chain(explicit_council_pks.iter())
            .copied()
        {
            if pk != [0u8; 32] && !allowed_pks.contains(&pk) {
                allowed_pks.push(pk);
            }
        }
        if let Some(local_admin_pk) = local_tracker_admin_pk {
            if !allowed_pks.contains(&local_admin_pk) {
                allowed_pks.push(local_admin_pk);
            }
        }
        if let Ok(env_auth) = std::env::var("PARVAULT_EVICTION_AUTHORITIES") {
            for part in env_auth.split(',') {
                if let Ok(bytes) = hex::decode(part.trim()) {
                    if bytes.len() == 32 {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&bytes);
                        if pk != [0u8; 32] && !allowed_pks.contains(&pk) {
                            allowed_pks.push(pk);
                        }
                    }
                }
            }
        }
        if allowed_pks.is_empty() {
            anyhow::bail!(
                "--admin-rpc-listen requires at least one authorized operator key via --admin-rpc-pubkey <HEX> (or an existing tracker_admin.seed)"
            );
        }

        let rpc_shared = Arc::clone(&shared);
        let rpc_store = block_store.clone();
        let rpc_data_dir = data_dir.clone();
        let rpc_node_id = node_identity.clone();
        let rpc_peer_id_str = local_peer_id.to_string();
        let rpc_extra_council = extra_council_pks.clone();
        let rpc_effective_peers = effective_peers.clone();

        let (bound_rpc_addr, handle) =
            spawn_admin_rpc_listener(bind_addr, node_identity.clone(), allowed_pks, move |req| {
                handle_seed_admin_rpc_request(
                    req,
                    SeedAdminRpcCtx {
                        shared: &rpc_shared,
                        block_store: &rpc_store,
                        data_dir: &rpc_data_dir,
                        node_identity: &rpc_node_id,
                        local_peer_id_str: &rpc_peer_id_str,
                        seed_mode,
                        local_tracker_admin_pk,
                        extra_council_pks: &rpc_extra_council,
                        council_quorum,
                        genesis_pubkey,
                        effective_peers: &rpc_effective_peers,
                        start_instant,
                    },
                )
            })
            .await?;
        println!("Admin RPC Listen Addr     : {}", bound_rpc_addr);
        info!(%bound_rpc_addr, "parvault-seed out-of-band Admin RPC listener active");
        Some(handle)
    } else {
        None
    };

    let beacon_handle = if resolve_seed_lan_enabled(no_lan_discovery) {
        let discovery_port = resolve_seed_lan_port(lan_discovery_port);
        let (init_port, init_ip) = extract_listen_port_and_ip(&tcp_addr).unwrap_or((4002, None));
        let avail = init_report
            .max_storage_bytes
            .saturating_sub(init_report.used_storage_bytes);
        let role = match seed_mode {
            SeedServerMode::HomelabRedundancyVault => "homelab-seed",
            SeedServerMode::PublicNetworkBootstrapper => "public-seed",
        };
        let pq_fp = if in_memory_mode {
            precomputed_pq_fp
        } else {
            precomputed_pq_fp.or_else(|| {
                HybridPqSigningKeypair::load_or_generate_in_dir(&data_dir)
                    .ok()
                    .map(|kp| kp.public_key().fingerprint_hex())
            })
        };
        let sas = derive_4word_pairing_sas(
            &local_peer_id.to_string(),
            pq_fp.as_deref(),
            DEFAULT_LAN_PAIRING_NONCE,
        );
        let beacon_cfg = LanBeaconConfig::new("parvault-seed", role, init_port)
            .with_discovery_port(discovery_port)
            .with_explicit_listen_ip(init_ip)
            .with_available_bytes(avail)
            .with_owner_pq_fingerprint(pq_fp)
            .with_pairing_sas_commitment(Some(sas.commitment));
        match LanBeaconResponder::spawn(node_identity.clone(), beacon_cfg) {
            Ok(h) => Some(h),
            Err(e) => {
                warn!(error = %e, "Failed to bind parvault-seed LAN beacon responder; continuing without LAN UDP beacon");
                None
            }
        }
    } else {
        None
    };

    let mut gc_interval = tokio::time::interval(Duration::from_secs(60));
    gc_interval.tick().await;

    info!(
        %local_peer_id,
        mode = ?seed_mode,
        listen_tcp = %listen,
        "parvault-seed zero-trust listener started (Noise XX + Yamux)"
    );

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                let unhandled = server_events.handle(&mut swarm, event, |peer_str, remote_addr, request| {
                            let mut st = shared
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            let SeedSharedState {
                                ref mut server,
                                ref mut wot,
                                ref mut por_verifier,
                                ref mut nullifier_ledger,
                                ref mut wan_registry,
                                ref mut eviction,
                                ref mut takedown_queue,
                                max_probationary_lease_bytes,
                                ..
                            } = *st;
                            handle_seed_wire_request(
                                peer_str,
                                remote_addr,
                                request,
                                SeedWireHandlerCtx {
                                    data_dir: &data_dir,
                                    node_identity: &node_identity,
                                    advertised_admin_pk,
                                    local_tracker_admin_pk,
                                    extra_council_pks: &extra_council_pks,
                                    council_quorum,
                                    max_probationary_lease_bytes,
                                    genesis_pubkey,
                                    block_store: &block_store,
                                    server,
                                    wot,
                                    por_verifier,
                                    nullifier_ledger,
                                    pq_kem: &pq_kem,
                                    wan_registry,
                                    eviction,
                                    takedown_queue,
                                },
                            )
                });
                if let Some(SwarmEvent::NewListenAddr { address, .. }) = unhandled {
                    info!(%address, "parvault-seed listening on transport address");
                    if let Some(ref beacon) = beacon_handle {
                        if let Some((bound_port, bound_ip)) = extract_listen_port_and_ip(&address) {
                            beacon.update_listen_endpoint(bound_port, bound_ip);
                        }
                    }
                }
            }
            _ = gc_interval.tick() => {
                let mut avail_opt = None;
                {
                    let mut st = shared
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    st.epoch_counter = st.epoch_counter.saturating_add(1);
                    let ep = st.epoch_counter;
                    // Admissions are written in batches (F-27, F-30).
                    st.wot.flush();
                    st.wan_registry.prune_expired(seed_now_ms());
                    if let Ok(purged) = st.server.sweep_expired_epoch(ep) {
                        if !purged.is_empty() {
                            info!(
                                epoch = ep,
                                purged_count = purged.len(),
                                "Swept and unlinked expired .bshard files from disk"
                            );
                        }
                    }
                    if beacon_handle.is_some() {
                        let rep = st.server.status_report(ep);
                        avail_opt = Some(rep.max_storage_bytes.saturating_sub(rep.used_storage_bytes));
                    }
                }
                if let (Some(ref beacon), Some(avail)) = (&beacon_handle, avail_opt) {
                    beacon.update_available_bytes(avail);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl-C, shutting down parvault-seed cleanly.");
                shared
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .wot
                    .flush();
                break;
            }
        }
    }

    Ok(())
}

struct SeedAdminRpcCtx<'a> {
    shared: &'a Arc<Mutex<SeedSharedState>>,
    block_store: &'a BlockStore,
    data_dir: &'a Path,
    node_identity: &'a NodeIdentity,
    local_peer_id_str: &'a str,
    seed_mode: SeedServerMode,
    local_tracker_admin_pk: Option<[u8; 32]>,
    extra_council_pks: &'a [[u8; 32]],
    council_quorum: Option<usize>,
    genesis_pubkey: [u8; 32],
    effective_peers: &'a [String],
    start_instant: Instant,
}

fn handle_seed_admin_rpc_request(
    request: SeedAdminRequest,
    ctx: SeedAdminRpcCtx<'_>,
) -> SeedAdminResponse {
    let SeedAdminRpcCtx {
        shared,
        block_store,
        data_dir,
        node_identity,
        local_peer_id_str,
        seed_mode,
        local_tracker_admin_pk,
        extra_council_pks,
        council_quorum,
        genesis_pubkey,
        effective_peers,
        start_instant,
    } = ctx;
    match request {
        SeedAdminRequest::GetSeedTelemetry => {
            let mut st = shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let rep = st.server.status_report(st.epoch_counter);
            let (rss_kib, hwm_kib) = read_linux_process_memory_kib();
            let stored_regular_shards = block_store
                .list_stored_shards()
                .map(|v| v.len())
                .unwrap_or(0);
            let stored_blinded_shards = count_blinded_shards_on_disk(block_store);
            let (active_public_peers, unique_ipv4_24_subnets, unique_ipv6_48_subnets, _) =
                collect_public_swarm_diversity(&mut st.wan_registry, seed_now_ms());
            let pending_takedowns_count = st
                .takedown_queue
                .list_entries()
                .iter()
                .filter(|e| matches!(e.status, TakedownReviewStatus::PendingAdminReview))
                .count();
            let (_, min_quorum) = resolve_seed_council_and_quorum(
                data_dir,
                seed_mode,
                local_tracker_admin_pk,
                extra_council_pks,
                council_quorum,
                genesis_pubkey,
            );
            let mode_str = match seed_mode {
                SeedServerMode::PublicNetworkBootstrapper => "public-bootstrap",
                SeedServerMode::HomelabRedundancyVault => "homelab-vault",
            };
            SeedAdminResponse::Telemetry(SeedTelemetrySnapshot {
                seed_peer_id: local_peer_id_str.to_string(),
                seed_ed25519_pubkey: node_identity.public_key_bytes(),
                mode: mode_str.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: start_instant.elapsed().as_secs(),
                rss_kib,
                hwm_kib,
                stored_regular_shards,
                stored_blinded_shards,
                used_storage_bytes: rep.used_storage_bytes,
                max_storage_bytes: rep.max_storage_bytes,
                active_public_peers,
                unique_ipv4_24_subnets,
                unique_ipv6_48_subnets,
                min_public_pow_bits: st.wot.min_public_pow_bits(),
                max_probationary_lease_bytes: st.max_probationary_lease_bytes,
                pending_takedowns_count,
                active_eviction_blocks_count: st.eviction.active_block_rules_count(),
                council_quorum_threshold: min_quorum,
            })
        }

        SeedAdminRequest::SyncTakedownQueue { since_timestamp_ms } => {
            let st = shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let filtered = st
                .takedown_queue
                .list_entries()
                .into_iter()
                .filter(|entry| {
                    let decision_ts = match &entry.status {
                        TakedownReviewStatus::PendingAdminReview => 0,
                        TakedownReviewStatus::Approved { approved_at_ms, .. } => *approved_at_ms,
                        TakedownReviewStatus::Rejected { rejected_at_ms, .. } => *rejected_at_ms,
                    };
                    entry.report.submitted_at_ms >= since_timestamp_ms
                        || decision_ts >= since_timestamp_ms
                })
                .collect();
            SeedAdminResponse::TakedownEntries(filtered)
        }

        SeedAdminRequest::ResolveTargetImpact { target } => {
            let mut st = shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            st.eviction.refresh_from_disk_readonly();
            let (
                resolved_pubkeys,
                local_regular_shards,
                local_blinded_shards,
                estimated_local_bytes,
            ) = st
                .eviction
                .count_matching_shards_dry_run(&target, block_store);
            let (reachable_public_peers, _, _, _) =
                collect_public_swarm_diversity(&mut st.wan_registry, seed_now_ms());
            SeedAdminResponse::TargetImpact {
                resolved_pubkeys,
                local_regular_shards,
                local_blinded_shards,
                estimated_local_bytes,
                reachable_public_peers,
            }
        }

        SeedAdminRequest::ExecuteSignedEvictionBatch {
            orders,
            propagate_to_swarm,
        } => {
            if seed_mode != SeedServerMode::PublicNetworkBootstrapper {
                return SeedAdminResponse::Error {
                    message: "Refused: ExecuteSignedEvictionBatch is strictly disabled in homelab-vault private mode".to_string(),
                };
            }
            let (council, min_quorum) = resolve_seed_council_and_quorum(
                data_dir,
                seed_mode,
                local_tracker_admin_pk,
                extra_council_pks,
                council_quorum,
                genesis_pubkey,
            );
            let local_pk = node_identity.public_key_bytes();
            let now_ms = seed_now_ms();

            let (local_report, live_swarm_peers) = {
                let mut st = shared
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let mut combined_local = EvictionPurgeReport::default();
                for order in &orders {
                    match st.eviction.apply_signed_eviction_order_with_quorum(
                        order,
                        Some(&local_pk),
                        &council,
                        min_quorum,
                        now_ms,
                        block_store,
                    ) {
                        Ok(rep) => combined_local.merge(&rep),
                        Err(e) if e.to_string().contains("duplicate_replayed_eviction_order") => {}
                        Err(e) => {
                            return SeedAdminResponse::Error {
                                message: format!("eviction order rejected on seed: {e}"),
                            };
                        }
                    }
                }
                let (_, _, _, peers) = collect_public_swarm_diversity(&mut st.wan_registry, now_ms);
                (combined_local, peers)
            };

            let mut swarm_propagated_report = EvictionPurgeReport::default();
            let mut peers_contacted = 0usize;
            let mut peers_accepted = 0usize;

            if propagate_to_swarm && !orders.is_empty() {
                let mut target_peers: Vec<String> = Vec::new();
                for p in live_swarm_peers {
                    if !p.ends_with(&format!("/p2p/{local_peer_id_str}")) {
                        push_unique_peer(&mut target_peers, p);
                    }
                }
                for p in effective_peers {
                    if !p.ends_with(&format!("/p2p/{local_peer_id_str}")) {
                        push_unique_peer(&mut target_peers, p.clone());
                    }
                }
                if !data_dir.as_os_str().is_empty() {
                    for p in KnownPeersStore::load(data_dir).active_multiaddrs() {
                        if !p.ends_with(&format!("/p2p/{local_peer_id_str}")) {
                            push_unique_peer(&mut target_peers, p);
                        }
                    }
                }
                if target_peers.is_empty() && !data_dir.as_os_str().is_empty() {
                    let discovery_port = resolve_seed_lan_port(None);
                    for p in resolve_zero_config_peers(
                        data_dir,
                        &[],
                        discovery_port,
                        Duration::from_millis(200),
                    ) {
                        if !p.ends_with(&format!("/p2p/{local_peer_id_str}")) {
                            push_unique_peer(&mut target_peers, p);
                        }
                    }
                }

                if !target_peers.is_empty() {
                    let discovery_port = resolve_seed_lan_port(None);
                    let client = if data_dir.as_os_str().is_empty() {
                        MeshClient::new(node_identity.clone(), target_peers.clone(), None)
                    } else {
                        MeshClient::new(node_identity.clone(), target_peers.clone(), None)
                            .with_data_dir_discovery(data_dir.to_path_buf(), discovery_port)
                    };
                    peers_contacted = target_peers.len();
                    for peer_addr in &target_peers {
                        let mut peer_ok = false;
                        for order in &orders {
                            if let Ok(rep) =
                                client.broadcast_eviction_order(peer_addr, order.clone())
                            {
                                swarm_propagated_report.merge(&rep);
                                peer_ok = true;
                            }
                        }
                        if peer_ok {
                            peers_accepted += 1;
                        }
                    }
                }
            }

            SeedAdminResponse::EvictionBatchResult {
                local_report,
                swarm_propagated_report,
                peers_contacted,
                peers_accepted,
            }
        }

        SeedAdminRequest::RecordTakedownDecision {
            report_id,
            approved,
            admin_pubkey,
            note,
        } => {
            if seed_mode != SeedServerMode::PublicNetworkBootstrapper {
                return SeedAdminResponse::Error {
                    message:
                        "Refused: RecordTakedownDecision disabled in homelab-vault private mode"
                            .to_string(),
                };
            }
            let mut st = shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match st.takedown_queue.record_external_admin_decision(
                &report_id,
                approved,
                admin_pubkey,
                &note,
                seed_now_ms(),
            ) {
                Ok(found) => SeedAdminResponse::Ack {
                    ok: true,
                    message: Some(if found {
                        "takedown_decision_recorded".to_string()
                    } else {
                        "report_not_present_on_this_seed".to_string()
                    }),
                },
                Err(e) => SeedAdminResponse::Error {
                    message: format!("failed to persist takedown decision: {e}"),
                },
            }
        }

        SeedAdminRequest::UpdateAdmissionPolicy {
            min_public_pow_bits,
            max_probationary_lease_bytes,
        } => {
            if min_public_pow_bits > 32 {
                return SeedAdminResponse::Error {
                    message: format!("invalid min_public_pow_bits {min_public_pow_bits} (max 32)"),
                };
            }
            let mut st = shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let pool_mode = if seed_mode == SeedServerMode::PublicNetworkBootstrapper {
                TrustPoolMode::Hybrid
            } else {
                TrustPoolMode::PrivateRing
            };
            st.wot.set_trust_pool_mode(pool_mode, min_public_pow_bits);
            st.max_probationary_lease_bytes = max_probationary_lease_bytes;
            SeedAdminResponse::Ack {
                ok: true,
                message: Some(format!(
                    "updated min_public_pow_bits={min_public_pow_bits}, max_probationary_lease_bytes={max_probationary_lease_bytes}"
                )),
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
            parvault::storage::BlindedLeaseSpec::new(10, 5, verifier_1),
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
            parvault::storage::BlindedLeaseSpec::new(20, 30, verifier_2),
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
