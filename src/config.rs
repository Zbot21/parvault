use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default streaming stripe size (16 MiB) per ADR-01 to cap RAM < 32 MiB on gateways.
pub const DEFAULT_STRIPE_SIZE_BYTES: usize = 16 * 1024 * 1024;

/// Default Proof-of-Retrievability (PoR) latency ceiling (300 ms).
pub const DEFAULT_POR_TIMEOUT_MS: u64 = 300;

/// Default local network neighborhood RTT ceiling (5 ms).
pub const DEFAULT_LOCAL_RTT_MS: u64 = 5;

/// Default Intra-ASN / Low-RTT shard placement ratio (70%).
pub const DEFAULT_INTRA_ASN_RATIO: f64 = 0.70;

/// Default bootstrap grace storage quota (10 GiB) for newly invited Web-of-Trust peers (ADR-07).
pub const DEFAULT_BOOTSTRAP_GRACE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Comparative Erasure Coding Schemes (k-of-n) and Dynamic SLA Pools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum ErasureTier {
    /// 10-of-20 (50.0% efficiency, 2.00x expansion, tolerates 10 failures) — Unmanaged Consumer Gateways
    Consumer,
    /// 16-of-24 (66.7% efficiency, 1.50x expansion, tolerates 8 failures) — Standard Mesh / Mixed Nodes
    Mixed,
    /// 16-of-20 (80.0% efficiency, 1.25x expansion, tolerates 4 failures) — High-SLA Homelab / Prosumer Pool (>99.5% SLA)
    Homelab,
    /// 20-of-24 (83.3% efficiency, 1.20x expansion, tolerates 4 failures) — Static Infrastructure Relays
    Relay,
}

impl ErasureTier {
    /// Returns `(k_data_shards, m_parity_shards, n_total_shards)`.
    pub const fn params(self) -> (usize, usize, usize) {
        match self {
            Self::Consumer => (10, 10, 20),
            Self::Mixed => (16, 8, 24),
            Self::Homelab => (16, 4, 20),
            Self::Relay => (20, 4, 24),
        }
    }

    /// Proactive repair trigger watermark (`T_repair`).
    /// For Homelab (16-of-20), proactive repair initiates as soon as active shards drop from 20 to 18.
    pub const fn repair_trigger_watermark(self) -> usize {
        match self {
            Self::Consumer => 16,
            Self::Mixed => 20,
            Self::Homelab => 18,
            Self::Relay => 22,
        }
    }

    /// Storage expansion / reciprocity multiplier required by `storage::quota` (ADR-07).
    pub const fn expansion_factor(self) -> f64 {
        match self {
            Self::Consumer => 2.00,
            Self::Mixed => 1.50,
            Self::Homelab => 1.25,
            Self::Relay => 1.20,
        }
    }
}

/// Top-level CLI entrypoint for `parvault`.
#[derive(Debug, Parser)]
#[command(
    name = "parvault",
    version,
    about = "ParVault — Zero-knowledge post-quantum erasure-coded backup & P2P storage utility"
)]
pub struct Cli {
    /// Path to optional TOML configuration file.
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Optional comma-separated list of mesh peer Multiaddrs or `host:port` endpoints (overrides `bootstrap_peers` / `PARVAULT_PEERS`).
    #[arg(long, global = true, value_delimiter = ',')]
    pub peers: Vec<String>,

    /// Optional `parvault-seed` Multiaddr or `host:port` endpoint (overrides `lite_seed_addr` / `PARVAULT_SEED_ADDR`).
    #[arg(long, global = true)]
    pub seed_addr: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Manage the background P2P storage & PoR daemon.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Encrypt, erasure-code, store, or restore vault files.
    File {
        #[command(subcommand)]
        action: FileAction,
    },
    /// Inspect local daemon health, SLA cohort tier, WoT peers, and storage quota.
    Status,
    /// Display or initialize the persistent NodeIdentity, Post-Quantum Owner Key, and Master Key fingerprints.
    Identity,
    /// Issue a post-quantum PersonalDeviceCert (Ed25519 + ML-DSA-65) authorizing a personal device on the Homelab Ring.
    IssueDeviceCert {
        /// Device Peer ID to authorize (e.g. `parvault-peer-...`).
        #[arg(long)]
        device_peer_id: String,

        /// Human-readable label for the personal device.
        #[arg(long, default_value = "personal-device")]
        device_label: String,

        /// Optional output path to write the JSON certificate file.
        #[arg(long)]
        cert_out: Option<PathBuf>,
    },
    /// Verify a post-quantum PersonalDeviceCert (from a JSON file path, JSON string, or `PARVAULT-CERT-V1:<hex>` token).
    VerifyDeviceCert {
        /// Path to certificate file, raw JSON string, or `PARVAULT-CERT-V1:<hex>` shareable token.
        #[arg(long)]
        cert: String,

        /// Optional hex-encoded Owner PQ Public Key (defaults to local persistent owner PQ key).
        #[arg(long)]
        owner_pq_pubkey_hex: Option<String>,
    },
    /// Dry-run diff of a local directory against a previous snapshot (or empty state) respecting `.parvaultignore`.
    DiffFolder {
        /// Path to the local directory to inspect.
        #[arg(long)]
        folder: PathBuf,

        /// Optional path to a previous `.manifest.bin` folder snapshot file.
        #[arg(long)]
        snapshot: Option<PathBuf>,

        /// Optional hex-encoded 32-byte master key.
        #[arg(long)]
        key_hex: Option<String>,
    },
    /// Continuously watch and back up a local directory tree to the Neighborhood Cloud mesh (ADR-10).
    WatchFolder {
        /// Path to the local directory to back up.
        #[arg(long)]
        folder: PathBuf,

        /// Output path for the signed folder snapshot manifest.
        #[arg(long, default_value = "./folder_snapshot.manifest.bin")]
        snapshot_out: PathBuf,

        /// Target SLA erasure coding tier (consumer=10/20, homelab=16/20, mixed=16/24, relay=20/24).
        #[arg(long, value_enum, default_value_t = ErasureTier::Homelab)]
        tier: ErasureTier,

        /// Sync polling interval in seconds (when running continuously).
        #[arg(long, default_value_t = 5)]
        interval_secs: u64,

        /// Run a single incremental sync pass and exit (useful for scripts/CI).
        #[arg(long, default_value_t = false)]
        once: bool,

        /// Optional hex-encoded 32-byte master key.
        #[arg(long)]
        key_hex: Option<String>,

        /// Perform a dry-run diff report and exit without writing shards.
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Prune local shards belonging to deleted file tombstones after syncing.
        #[arg(long, default_value_t = false)]
        prune_deleted: bool,

        /// Optional recovery seed phrase to derive deterministic keys and export an EncryptedVaultCatalogEnvelope.
        #[arg(long)]
        seed_phrase: Option<String>,

        /// Vault namespace used with `--seed-phrase` for deterministic disaster recovery (ADR-15).
        #[arg(long, default_value = "default")]
        vault_namespace: String,

        /// Optional output file path for the post-quantum EncryptedVaultCatalogEnvelope (`.catalog.bin`).
        #[arg(long)]
        catalog_out: Option<PathBuf>,

        /// Optional paired `parvault-seed` Multiaddr (e.g. `/ip4/10.42.1.10/tcp/4002`) or local directory for Lite-Client 1.0x stripe syndication (ADR-17).
        #[arg(long, visible_alias = "lite-seed-addr")]
        lite_seed_dir: Option<PathBuf>,

        /// Optional PersonalDeviceCert file or `PARVAULT-CERT-V1:` token for Lite-Client seed authentication (ADR-17).
        #[arg(long)]
        device_cert: Option<String>,
    },
    /// Browse and list all files, sizes, and stripe counts in a Folder Snapshot Manifest without downloading shards (ADR-17).
    ListSnapshot {
        /// Path to the `.manifest.bin` folder snapshot file.
        #[arg(long)]
        snapshot: PathBuf,
    },
    /// Restore an entire backed-up directory tree (or a selective subset via `--file` / `--filter`) from its signed Folder Snapshot Manifest.
    RestoreFolder {
        /// Path to the `.manifest.bin` folder snapshot file.
        #[arg(long)]
        snapshot: PathBuf,

        /// Target output directory where the restored folder tree will be written.
        #[arg(long, visible_alias = "target-dir")]
        out_dir: PathBuf,

        /// Optional hex-encoded 32-byte master key.
        #[arg(long)]
        key_hex: Option<String>,

        /// Optional relative file path inside the snapshot to selectively restore a single file.
        #[arg(long)]
        file: Option<String>,

        /// Optional comma-separated glob or directory prefix filter (e.g. `"docs/*.md,src/"`) for selective partial restore (ADR-17).
        #[arg(long)]
        filter: Option<String>,
    },
    /// Zero-Local-State "House Fire" Disaster Recovery from a memorized seed phrase and network peers or EncryptedVaultCatalogEnvelope (ADR-15 / ADR-17).
    RecoverFromSeed {
        /// Memorized recovery seed phrase.
        #[arg(long)]
        seed_phrase: String,

        /// Vault namespace (default: "default").
        #[arg(long, default_value = "default")]
        vault_namespace: String,

        /// Optional path to a local `.catalog.bin` EncryptedVaultCatalogEnvelope file (if omitted, queries Kademlia DHT over `--peers`).
        #[arg(long)]
        catalog_envelope: Option<PathBuf>,

        /// Target output directory where the recovered directory tree will be restored.
        #[arg(long, visible_alias = "target-dir", default_value = "./recovered_vault")]
        out_dir: PathBuf,

        /// Optional comma-separated glob or directory prefix filter to selectively recover only needed files (ADR-17).
        #[arg(long)]
        filter: Option<String>,
    },
    /// Run the local bit-rot scrubber across all `.shard` and `.bshard` files and quarantine corrupted shards.
    Scrub,
    /// Gracefully decommission this node, directly handing off all hosted `.shard` and `.bshard` files (`1.0x` bandwidth instead of `16.0x` RS lazy repair) and issuing a signed GracefulDepartureReceipt that preserves Earned Uptime Standing.
    Leave {
        /// Optional comma-separated target handoff directories or replacement peer store paths to receive evacuated shards.
        #[arg(long)]
        handoff_to: Option<String>,

        /// Keep local shard copies on disk after handoff (default: false — removes evacuated shards when `--handoff-to` is provided).
        #[arg(long, default_value_t = false)]
        keep_local: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DaemonAction {
    /// Start the asynchronous parvault-daemon service.
    Start {
        /// TCP listen multiaddr (Noise XX + Yamux primary transport per ADR-08).
        #[arg(long, default_value = "/ip4/0.0.0.0/tcp/4001")]
        listen: String,

        /// Optionally enable secondary QUIC transport listener (ADR-08).
        #[arg(long, default_value_t = false)]
        enable_quic: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum FileAction {
    /// Encrypt a file with AES-256-GCM in 16 MiB stripes, split into Reed-Solomon shards, and store.
    Store {
        /// Path to the plaintext input file (positional).
        #[arg(value_name = "PATH", required_unless_present = "path_flag")]
        path: Option<PathBuf>,

        /// Path to the plaintext input file (--path flag).
        #[arg(long = "path", value_name = "PATH")]
        path_flag: Option<PathBuf>,

        /// Target SLA erasure coding tier (consumer=10/20, homelab=16/20, mixed=16/24, relay=20/24).
        #[arg(long, value_enum, default_value_t = ErasureTier::Consumer)]
        tier: ErasureTier,

        /// Hex-encoded 32-byte master key (if omitted, uses or generates the local master key).
        #[arg(long)]
        key_hex: Option<String>,
    },
    /// Reconstruct and decrypt a file from its File Manifest or Merkle Root hex.
    Restore {
        /// File Merkle Root hex or path to a `.manifest.bin` file (positional).
        #[arg(
            value_name = "MANIFEST_OR_ROOT",
            required_unless_present = "manifest_or_root_flag"
        )]
        manifest_or_root: Option<String>,

        /// File Merkle Root hex or path to a `.manifest.bin` file (--manifest-or-root flag).
        #[arg(
            long = "manifest-or-root",
            visible_alias = "manifest",
            value_name = "MANIFEST_OR_ROOT"
        )]
        manifest_or_root_flag: Option<String>,

        /// Destination file path for the verified decrypted payload (positional).
        #[arg(value_name = "OUTPUT", required_unless_present = "output_flag")]
        output: Option<PathBuf>,

        /// Destination file path for the verified decrypted payload (--output flag).
        #[arg(long = "output", visible_alias = "out", value_name = "OUTPUT")]
        output_flag: Option<PathBuf>,

        /// Hex-encoded 32-byte master key.
        #[arg(long)]
        key_hex: Option<String>,
    },
}

/// Persistent node configuration loaded from `config.toml` or CLI defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub listen_tcp: String,
    pub enable_quic: bool,
    pub listen_quic: String,
    pub stripe_size_bytes: usize,
    pub default_tier: ErasureTier,
    pub max_storage_bytes: u64,
    pub bootstrap_grace_bytes: u64,
    pub por_timeout_ms: u64,
    pub local_rtt_threshold_ms: u64,
    pub intra_asn_ratio: f64,
    /// Optional ASN override for deterministic Docker / Shadow simulations (ADR-06).
    pub override_asn: Option<u32>,
    /// Optional region tag for cross-region cohort simulation (ADR-06).
    pub override_region: Option<String>,
    /// Configured bootstrap/storage peer Multiaddrs (`--peers` / `PARVAULT_PEERS`).
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    /// Optional paired `parvault-seed` Multiaddr (`--seed-addr` / `PARVAULT_SEED_ADDR`).
    #[serde(default)]
    pub lite_seed_addr: Option<String>,
    /// Optional hex-encoded 32-byte Web-of-Trust Genesis Root public key (`PARVAULT_GENESIS_PUBKEY_HEX`).
    #[serde(default)]
    pub genesis_root_pubkey_hex: Option<String>,
    /// Optional passphrase for Argon2id hardware enclave key sealing (`PARVAULT_PASSPHRASE`).
    #[serde(default)]
    pub device_sealing_passphrase: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(".parvault-data"),
            listen_tcp: "/ip4/0.0.0.0/tcp/4001".to_string(),
            enable_quic: false,
            listen_quic: "/ip4/0.0.0.0/udp/4001/quic-v1".to_string(),
            stripe_size_bytes: DEFAULT_STRIPE_SIZE_BYTES,
            default_tier: ErasureTier::Consumer,
            max_storage_bytes: 100 * 1024 * 1024 * 1024, // 100 GiB default local allocation
            bootstrap_grace_bytes: DEFAULT_BOOTSTRAP_GRACE_BYTES,
            por_timeout_ms: DEFAULT_POR_TIMEOUT_MS,
            local_rtt_threshold_ms: DEFAULT_LOCAL_RTT_MS,
            intra_asn_ratio: DEFAULT_INTRA_ASN_RATIO,
            override_asn: None,
            override_region: None,
            bootstrap_peers: Vec::new(),
            lite_seed_addr: None,
            genesis_root_pubkey_hex: None,
            device_sealing_passphrase: None,
        }
    }
}

impl NodeConfig {
    pub fn load_or_default(path: Option<&PathBuf>) -> anyhow::Result<Self> {
        if let Some(cfg_path) = path {
            let raw = std::fs::read_to_string(cfg_path)?;
            let cfg: Self = toml::from_str(&raw)?;
            Ok(cfg)
        } else {
            Ok(Self::default())
        }
    }

    pub fn effective_peers(&self, cli_peers: &[String]) -> Vec<String> {
        if !cli_peers.is_empty() {
            return cli_peers.to_vec();
        }
        if let Ok(env_peers) = std::env::var("PARVAULT_PEERS") {
            let parsed: Vec<String> = env_peers
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !parsed.is_empty() {
                return parsed;
            }
        }
        self.bootstrap_peers.clone()
    }

    pub fn effective_seed_addr(&self, cli_seed: Option<&str>) -> Option<String> {
        if let Some(s) = cli_seed.map(str::trim).filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
        if let Ok(env_seed) = std::env::var("PARVAULT_SEED_ADDR") {
            let trimmed = env_seed.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        self.lite_seed_addr.clone()
    }
}
