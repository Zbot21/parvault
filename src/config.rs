use clap::{Parser, Subcommand, ValueEnum};

/// `parvault wot` subcommands (ring admission, bootstrap option A).
#[derive(Debug, Clone, Subcommand)]
pub enum WotAction {
    /// Start a new ring on this node: creates the ring genesis secret
    /// (`<data_dir>/ring_genesis.seed`, 0600). The only way a node creates a genesis; refused if
    /// the node is already in a ring.
    Init,
    /// Print a ring invitation token admitting `--peer`. Needs the ring genesis secret (from
    /// `parvault wot init` on this node, or `PARVAULT_GENESIS_SEED_HEX`).
    Invite {
        /// The invitee's 32-byte Ed25519 public key (64 hex characters, from `parvault identity`).
        #[arg(long)]
        peer: String,
    },
    /// Install a ring invitation token (from `parvault wot invite`): verifies the chain against the
    /// ring's genesis key, pins that key (`<data_dir>/ring_genesis.pub`) and stores the chain.
    InstallChain {
        /// The hex chain token.
        #[arg(long)]
        token: String,
    },
}
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// Default streaming stripe size (16 MiB) per ADR-01 to cap RAM < 32 MiB on gateways.
pub const DEFAULT_STRIPE_SIZE_BYTES: usize = 16 * 1024 * 1024;

/// Balanced streaming stripe size (4 MiB) for 24/7 Homelab NAS nodes.
pub const HOMELAB_NAS_STRIPE_SIZE_BYTES: usize = 4 * 1024 * 1024;

/// Ultra-low-RAM streaming stripe size (1 MiB) for OpenWrt / prplOS / ARM64 Router SoCs (ADR-18).
pub const ROUTER_SOC_STRIPE_SIZE_BYTES: usize = 1024 * 1024;

/// Minimum streaming stripe size floor (`64 KiB`).
pub const MIN_STRIPE_SIZE_BYTES: usize = 64 * 1024;

/// Maximum logical file size supported by the streaming pipeline (`u64::MAX` bytes).
pub const MAX_FILE_BYTES: u64 = u64::MAX;

/// Strict Router-SoC peak concurrent per-stripe RAM ceiling (`32 MiB`, `ADR-01` / `ADR-18`).
pub const ROUTER_SOC_MAX_STRIPE_MEMORY_BYTES: usize = 32 * 1024 * 1024;

/// AES-256-GCM authentication tag overhead per encrypted stripe (`16` bytes).
pub const AES_GCM_TAG_OVERHEAD_BYTES: usize = 16;

/// Deterministic streaming stripe decomposition for a file of `file_size_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamingStripeLayout {
    pub stripe_size_bytes: usize,
    pub stripe_count: u64,
    pub last_stripe_plaintext_bytes: usize,
    pub max_stripe_plaintext_bytes: usize,
    pub max_stripe_ciphertext_bytes: usize,
}

/// Computes the exact overflow-free streaming stripe layout for `file_size_bytes` (`0..=u64::MAX`),
/// clamping `raw_stripe_size_bytes` into `[MIN_STRIPE_SIZE_BYTES, DEFAULT_STRIPE_SIZE_BYTES]`.
/// Empty files (`0` bytes) emit exactly `1` authenticated `0`-byte plaintext (`16`-byte GCM tag) stripe.
pub const fn compute_stripe_layout_for_size(
    file_size_bytes: u64,
    raw_stripe_size_bytes: usize,
) -> StreamingStripeLayout {
    let stripe_size_bytes = if raw_stripe_size_bytes < MIN_STRIPE_SIZE_BYTES {
        MIN_STRIPE_SIZE_BYTES
    } else if raw_stripe_size_bytes > DEFAULT_STRIPE_SIZE_BYTES {
        DEFAULT_STRIPE_SIZE_BYTES
    } else {
        raw_stripe_size_bytes
    };

    if file_size_bytes == 0 {
        StreamingStripeLayout {
            stripe_size_bytes,
            stripe_count: 1,
            last_stripe_plaintext_bytes: 0,
            max_stripe_plaintext_bytes: 0,
            max_stripe_ciphertext_bytes: AES_GCM_TAG_OVERHEAD_BYTES,
        }
    } else {
        let cap_u64 = stripe_size_bytes as u64;
        let full_stripes_before_last = (file_size_bytes - 1) / cap_u64;
        let stripe_count = full_stripes_before_last + 1;
        let last_stripe_plaintext_bytes = (((file_size_bytes - 1) % cap_u64) as usize) + 1;
        let max_stripe_plaintext_bytes = if stripe_count > 1 {
            stripe_size_bytes
        } else {
            last_stripe_plaintext_bytes
        };
        StreamingStripeLayout {
            stripe_size_bytes,
            stripe_count,
            last_stripe_plaintext_bytes,
            max_stripe_plaintext_bytes,
            max_stripe_ciphertext_bytes: max_stripe_plaintext_bytes + AES_GCM_TAG_OVERHEAD_BYTES,
        }
    }
}

/// Default UDP port for signed Home LAN zero-IP auto-discovery (`ADR-18`).
pub const DEFAULT_LAN_DISCOVERY_PORT: u16 = 4009;

/// Default Proof-of-Retrievability (PoR) latency ceiling (300 ms).
pub const DEFAULT_POR_TIMEOUT_MS: u64 = 300;

/// Default local network neighborhood RTT ceiling (5 ms).
pub const DEFAULT_LOCAL_RTT_MS: u64 = 5;

/// Default Intra-ASN / Low-RTT shard placement ratio (70%).
pub const DEFAULT_INTRA_ASN_RATIO: f64 = 0.70;

/// Default bootstrap grace storage quota (10 GiB) for newly invited Web-of-Trust peers (ADR-07).
pub const DEFAULT_BOOTSTRAP_GRACE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

const fn default_min_free_disk_bytes() -> u64 {
    crate::storage::quota::DEFAULT_MIN_FREE_DISK_BYTES
}

const fn default_max_connections() -> usize {
    HardwareProfile::Desktop.max_connections()
}

const fn default_lan_discovery_enabled() -> bool {
    true
}

const fn default_lan_discovery_port() -> u16 {
    DEFAULT_LAN_DISCOVERY_PORT
}

/// Hardware resource profiles tuning stripe sizing, disk safety guards, and peer fanout (`ADR-18`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
pub enum HardwareProfile {
    /// Workstation / laptop profile (`16 MiB` stripes, `5 GiB` disk guard, `128` max connections)
    #[default]
    #[serde(rename = "desktop", alias = "Desktop")]
    #[value(name = "desktop")]
    Desktop,
    /// Dedicated 24/7 home NAS / mini-server profile (`4 MiB` stripes, `1 GiB` disk guard, `64` max connections)
    #[serde(rename = "homelab-nas", alias = "HomelabNas", alias = "homelab_nas")]
    #[value(name = "homelab-nas")]
    HomelabNas,
    /// Constrained OpenWrt / prplOS / ARM64 router SoC profile (`1 MiB` stripes, `64 MiB` disk guard, `24` max connections)
    #[serde(rename = "router-soc", alias = "RouterSoc", alias = "router_soc")]
    #[value(name = "router-soc")]
    RouterSoc,
}

impl HardwareProfile {
    /// Streaming ciphertext stripe size in bytes for this hardware profile.
    pub const fn stripe_size_bytes(self) -> usize {
        match self {
            Self::Desktop => DEFAULT_STRIPE_SIZE_BYTES,
            Self::HomelabNas => HOMELAB_NAS_STRIPE_SIZE_BYTES,
            Self::RouterSoc => ROUTER_SOC_STRIPE_SIZE_BYTES,
        }
    }

    /// Computes the exact overflow-free streaming stripe decomposition (`stripe_count`,
    /// `last_stripe_plaintext_bytes`, and `max_stripe_ciphertext_bytes`) for `file_size_bytes`
    /// under this hardware profile.
    pub const fn compute_streaming_stripe_layout(
        self,
        file_size_bytes: u64,
    ) -> StreamingStripeLayout {
        compute_stripe_layout_for_size(file_size_bytes, self.stripe_size_bytes())
    }

    /// Minimum free OS filesystem space reserved as a safety guard against disk exhaustion.
    pub const fn min_free_disk_bytes(self) -> u64 {
        match self {
            Self::Desktop => crate::storage::quota::DEFAULT_MIN_FREE_DISK_BYTES,
            Self::HomelabNas => 1024 * 1024 * 1024, // 1 GiB
            Self::RouterSoc => 64 * 1024 * 1024,    // 64 MiB for small USB/eMMC partitions
        }
    }

    /// Recommended concurrent peer connection ceiling.
    pub const fn max_connections(self) -> usize {
        match self {
            Self::Desktop => 128,
            Self::HomelabNas => 64,
            Self::RouterSoc => 24,
        }
    }

    /// Recommended default local storage allocation when initializing a fresh node.
    pub const fn default_max_storage_gib(self) -> u64 {
        match self {
            Self::Desktop => 100,
            Self::HomelabNas => 500,
            Self::RouterSoc => 32,
        }
    }

    /// Canonical CLI / JSON / TOML profile slug (`"desktop"`, `"homelab-nas"`, `"router-soc"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::HomelabNas => "homelab-nas",
            Self::RouterSoc => "router-soc",
        }
    }

    /// Default role advertised in signed LAN beacons and WAN peer cards.
    pub const fn beacon_role(self) -> &'static str {
        match self {
            Self::Desktop => "daemon",
            Self::HomelabNas => "router-nas",
            Self::RouterSoc => "router-nas",
        }
    }
}

impl fmt::Display for HardwareProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Comparative Erasure Coding Schemes (k-of-n) and Dynamic SLA Pools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum ErasureTier {
    /// 10-of-20 (50.0% efficiency, 2.00x expansion, tolerates 10 failures) — Unmanaged Consumer Gateways
    #[serde(alias = "consumer")]
    Consumer,
    /// 16-of-24 (66.7% efficiency, 1.50x expansion, tolerates 8 failures) — Standard Mesh / Mixed Nodes
    #[serde(alias = "mixed")]
    Mixed,
    /// 16-of-20 (80.0% efficiency, 1.25x expansion, tolerates 4 failures) — High-SLA Homelab / Prosumer Pool (>99.5% SLA)
    #[serde(alias = "homelab")]
    Homelab,
    /// 20-of-24 (83.3% efficiency, 1.20x expansion, tolerates 4 failures) — Static Infrastructure Relays
    #[serde(alias = "relay")]
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
    about = "ParVault — Zero-IP post-quantum erasure-coded backup, Home LAN/WAN Cloud-NAS & P2P storage utility"
)]
pub struct Cli {
    /// Path to optional TOML configuration file.
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Optional local data directory for shards, manifests, and identity keys (overrides `data_dir`).
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,

    /// Hardware profile (`desktop` = 16 MiB stripes, `homelab-nas` = 4 MiB stripes, `router-soc` = 1 MiB stripes / <32 MiB RAM).
    #[arg(long, global = true, value_enum)]
    pub profile: Option<HardwareProfile>,

    /// Optional comma-separated list of mesh peer Multiaddrs or `host:port` endpoints (overrides `bootstrap_peers` / `PARVAULT_PEERS`).
    #[arg(long, global = true, value_delimiter = ',')]
    pub peers: Vec<String>,

    /// Optional `parvault-seed` Multiaddr or `/dns4/...` endpoint for Lite-Client syndication and Online WAN rendezvous (overrides `lite_seed_addr` / `PARVAULT_SEED_ADDR`).
    #[arg(long, global = true)]
    pub seed_addr: Option<String>,

    /// Optional comma-separated public WAN Multiaddrs or `/dns4/...` endpoints advertised during Online WAN pairing (`PARVAULT_EXTERNAL_ADDRS`).
    #[arg(
        long = "external-addr",
        visible_alias = "external-addrs",
        global = true,
        value_delimiter = ','
    )]
    pub external_addrs: Vec<String>,

    /// Optional UDP port for signed Home LAN zero-IP discovery (overrides `lan_discovery_port` / `PARVAULT_LAN_DISCOVERY_PORT`, default: `4009`).
    #[arg(long, global = true)]
    pub lan_discovery_port: Option<u16>,

    /// Disable automatic signed Home LAN UDP/registry beacon responder (`PARVAULT_NO_LAN_DISCOVERY`).
    #[arg(long, global = true, default_value_t = false)]
    pub no_lan_discovery: bool,

    /// Enable BitTorrent-style Zero-Pairing Public Commons mode (uses zero-knowledge client encryption + 10-of-20 RS + PoW self-admission).
    #[arg(long, global = true, default_value_t = false)]
    pub public: bool,

    /// Optional comma-separated Public Commons tracker Multiaddrs (e.g. `parvault-seed --mode public-bootstrap` endpoints, overrides `public_trackers` / `PARVAULT_TRACKERS`).
    #[arg(
        long = "tracker",
        visible_alias = "trackers",
        global = true,
        value_delimiter = ','
    )]
    pub trackers: Vec<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize keys (`0600`) and write a turnkey `config.toml`.
    Init {
        /// Optional folder to create and configure for automatic continuous backup.
        #[arg(long, value_name = "DIR", visible_alias = "folder")]
        watch: Option<PathBuf>,

        /// Human-friendly node label shown on LAN discovery and the Router Cloud-NAS dashboard.
        #[arg(long, value_name = "NAME")]
        label: Option<String>,

        /// Maximum local storage allocation in GiB (defaults to profile recommendation: 32/100/500 GiB).
        #[arg(long, value_name = "GIB")]
        max_storage_gib: Option<u64>,
    },
    /// Scan the Home LAN (and configured WAN rendezvous anchors) for ParVault nodes with zero IP configuration.
    Discover {
        /// LAN UDP broadcast/multicast discovery scan window in milliseconds.
        #[arg(long, default_value_t = 500)]
        timeout_ms: u64,

        /// LAN discovery UDP port (defaults to `config.toml` `lan_discovery_port` or `4009`).
        #[arg(long)]
        port: Option<u16>,

        /// Emit machine-readable JSON array of discovered peers.
        #[arg(long, default_value_t = false)]
        json: bool,

        /// Also query configured Online WAN rendezvous / DDNS anchors (`--seed-addr` / `wan_rendezvous_seeds`).
        #[arg(long, default_value_t = false)]
        wan: bool,
    },
    /// Generate a 4-word BIP-39 SAS pairing code and advertise this node over Home LAN and/or Online WAN rendezvous.
    Pair {
        /// LAN discovery UDP port (defaults to `config.toml` `lan_discovery_port` or `4009`).
        #[arg(long)]
        port: Option<u16>,

        /// How long (in seconds) to keep broadcasting the pairing beacon for incoming `parvault join` peers.
        #[arg(long, default_value_t = 120)]
        duration_secs: u64,

        /// Print the 4-word pairing code + compact pairing token, publish once, and exit immediately (for scripts/CI).
        #[arg(long, default_value_t = false)]
        once: bool,

        /// Publish an encrypted `WanPeerCard` to Online WAN rendezvous seed(s) (`--seed-addr` / `wan_rendezvous_seeds`) with STUN-over-Noise reflection.
        #[arg(long, default_value_t = false)]
        wan: bool,

        /// Optional TCP listen Multiaddr override advertised in the pairing beacon.
        #[arg(long)]
        listen: Option<String>,
    },
    /// Pair with a Home LAN Router/NAS or remote Online WAN peer using only its 4-word SAS code (zero IP addresses!).
    Join {
        /// 4-word BIP-39 SAS pairing code (e.g. `anchor-velvet-orbit-oak`) or compact pairing token.
        #[arg(long, value_name = "4-WORD-SAS-OR-PAIR-TOKEN")]
        code: String,

        /// Discovery / rendezvous lookup timeout in milliseconds.
        #[arg(long, default_value_t = 1500)]
        timeout_ms: u64,

        /// LAN discovery UDP port (defaults to `config.toml` `lan_discovery_port` or `4009`).
        #[arg(long)]
        port: Option<u16>,

        /// Query Online WAN rendezvous seed(s) (`--seed-addr` / `wan_rendezvous_seeds`) in addition to LAN.
        #[arg(long, default_value_t = false)]
        wan: bool,
    },
    /// Turnkey single-command appliance mode: starts P2P storage daemon, zero-IP LAN/WAN discovery, optional HTTP status dashboard, and optional continuous folder sync.
    Up {
        /// Optional local directory to continuously watch and back up in the background.
        #[arg(long, value_name = "DIR", visible_alias = "watch")]
        folder: Option<PathBuf>,

        /// Background folder sync polling interval in seconds (when `--folder` or `watched_folder` is active).
        #[arg(long, default_value_t = 5)]
        interval_secs: u64,

        /// Bind address for the embedded zero-dependency Router Cloud-NAS HTTP dashboard & JSON API (e.g. `0.0.0.0:4080` or `127.0.0.1:0`).
        #[arg(long, value_name = "ADDR")]
        status_http: Option<String>,

        /// Generate and advertise a 4-word SAS pairing code on startup (and display it on the status dashboard).
        #[arg(long, default_value_t = false)]
        pair: bool,

        /// Publish encrypted Online WAN rendezvous / dynamic-IP presence to `--seed-addr` / `wan_rendezvous_seeds`.
        #[arg(long, default_value_t = false)]
        wan: bool,

        /// Optional TCP listen multiaddr override (defaults to `config.toml` `listen_tcp` or `/ip4/0.0.0.0/tcp/4001`).
        #[arg(long)]
        listen: Option<String>,

        /// Optional target SLA erasure coding tier for background `--folder` sync.
        #[arg(long, value_enum)]
        tier: Option<ErasureTier>,

        /// Optional Unix Domain Socket path for the Zero-Copy IPC Gateway (e.g. `/var/run/parvault.sock`).
        #[arg(long, value_name = "SOCK_PATH")]
        ipc_socket: Option<PathBuf>,

        /// Explicitly disable binding any Unix Domain Socket (`GatewayBus::InProcess` only; incompatible with `--ipc-socket`).
        #[arg(long, default_value_t = false)]
        no_socket: bool,

        /// Reject any Unix socket plugin client whose kernel `SO_PEERCRED` UID is not in `--allow-peer-uid`.
        #[arg(long, default_value_t = false)]
        strict_plugins: bool,

        /// Comma-delimited list of POSIX UIDs authorized to connect when `--strict-plugins` is active.
        #[arg(long, value_delimiter = ',', value_name = "UID")]
        allow_peer_uid: Vec<u32>,

        /// Require immutable Linux `memfd` seals (`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW`) on all `StorePayload` calls.
        #[arg(long, default_value_t = false)]
        require_sealed_memfd: bool,

        /// Optional 64-character hex 32-byte `K_macaroon_root` key enforcing `< 1 ms` in-RAM capability verification.
        #[arg(long, value_name = "64-HEX")]
        macaroon_root_key_hex: Option<String>,

        /// Optional bind address for the built-in (`=y`) VFS HTTP `Range` (`206`) + WebDAV server (works even with `--no-socket`).
        #[arg(long, value_name = "ADDR")]
        vfs_webdav_listen: Option<String>,

        /// Optional pre-mounted `/dev/fuse` file descriptor for the built-in (`=y`) pure-Rust FUSE protocol loop.
        #[arg(long, value_name = "FD")]
        vfs_fuse_fd: Option<i32>,

        /// Optional local directory to ingest into the built-in (`=y`) VFS at startup (honors `.parvaultignore`).
        #[arg(long, value_name = "DIR")]
        vfs_seed_dir: Option<PathBuf>,

        /// Bounded local LRU block cache capacity in MiB for the built-in (`=y`) VFS.
        #[arg(long, default_value_t = 64, value_name = "MIB")]
        vfs_cache_mib: u64,
    },
    /// Evict a bad actor or illegal content (0x00 zero-wipe + unlink + keyed HMAC ingress firewall, zero plaintext IPs on disk — ADR-19).
    Evict {
        /// Evict all shards uploaded from this IPv4/IPv6 address and block future ingress via keyed HMAC tag.
        #[arg(long, value_name = "IP")]
        ip: Option<std::net::IpAddr>,

        /// Evict all shards uploaded from this canonical `/24` IPv4 or `/48` IPv6 CIDR subnet via keyed HMAC tag.
        #[arg(long, value_name = "CIDR")]
        subnet: Option<String>,

        /// Evict all shards associated with this libp2p `PeerId` via keyed HMAC tag.
        #[arg(long, value_name = "PEER_ID")]
        peer_id: Option<String>,

        /// Evict all regular or blinded shards associated with this 32-byte hex Ed25519 peer or voucher-issuer pubkey.
        #[arg(long, value_name = "HEX")]
        pubkey_hex: Option<String>,

        /// Evict and permanently tombstone all shards belonging to a 32-byte hex `stripe_merkle_root`.
        #[arg(long, value_name = "HEX")]
        merkle_root: Option<String>,

        /// Evict and permanently tombstone a specific 32-byte hex `blinded_locator` (`.bshard`).
        #[arg(long, value_name = "HEX")]
        locator: Option<String>,

        /// Short human-readable audit reason attached to signed propagation orders (<= 256 bytes).
        #[arg(long, value_name = "TEXT", default_value = "operator-eviction")]
        reason: String,

        /// Sign a `SignedBadActorEvictionOrder` and broadcast it to configured/known mesh peers & trackers.
        #[arg(long, default_value_t = false)]
        propagate: bool,
    },
    /// Submit a cryptographically verifiable illegal-content abuse report (AES-256-GCM burden-of-proof) to a Public Tracker Admin queue (`ADR-19`).
    ReportAbuse {
        /// Path to the leaked encrypted `.manifest.bin` (or serialized `FileManifest`) file.
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,

        /// Disclosed 64-character hex `MasterKey` proving knowledge of the publicly distributed capability.
        #[arg(long, value_name = "HEX")]
        disclosed_key_hex: String,

        /// Specific legal/abuse allegation explaining why the verified content is illegal (<= 512 bytes).
        #[arg(long, value_name = "TEXT")]
        allegation: String,

        /// Reporter contact handle, email, or organization identifier.
        #[arg(long, value_name = "TEXT", default_value = "anonymous-reporter")]
        contact: String,

        /// Optional observed IP address of the bad actor distributing the content.
        #[arg(long, value_name = "IP")]
        bad_actor_ip: Option<std::net::IpAddr>,

        /// Sample stripe index to reconstruct & authenticate via AES-256-GCM (default: `0`).
        #[arg(long, default_value_t = 0)]
        stripe_index: u64,
    },
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
    /// Print a fresh 24-word BIP-39 recovery phrase and store nothing. Back up with
    /// `watch-folder --seed-phrase` to make a folder recoverable with `recover-from-seed` (ADR-18).
    NewSeedPhrase,
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

        /// Recovery seed phrase (or `PARVAULT_SEED_PHRASE`): derives the vault keys and publishes an
        /// EncryptedVaultCatalogEnvelope, so `recover-from-seed` can restore this folder (ADR-18).
        /// Without it the folder has no phrase recovery.
        #[arg(long)]
        seed_phrase: Option<String>,

        /// Vault namespace used with `--seed-phrase` for disaster recovery (ADR-18).
        #[arg(long, default_value = "default")]
        vault_namespace: String,

        /// Optional output file path for the post-quantum EncryptedVaultCatalogEnvelope (`.catalog.bin`).
        /// Needs `--seed-phrase` (or `PARVAULT_SEED_PHRASE`).
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

        /// Recovery seed phrase the folder was backed up with (or `PARVAULT_SEED_PHRASE`). Without
        /// it, the node's own master key is used.
        #[arg(long)]
        seed_phrase: Option<String>,

        /// Vault namespace used with `--seed-phrase` (ADR-18).
        #[arg(long, default_value = "default")]
        vault_namespace: String,

        /// Optional relative file path inside the snapshot to selectively restore a single file.
        #[arg(long)]
        file: Option<String>,

        /// Optional comma-separated glob or directory prefix filter (e.g. `"docs/*.md,src/"`) for selective partial restore (ADR-17).
        #[arg(long)]
        filter: Option<String>,
    },
    /// Zero-Local-State "House Fire" Disaster Recovery from a memorized seed phrase and network peers or EncryptedVaultCatalogEnvelope (ADR-18). Recovers only folders backed up with
    /// `watch-folder --seed-phrase` and the same `--vault-namespace`.
    RecoverFromSeed {
        /// Memorized recovery seed phrase (default: `PARVAULT_SEED_PHRASE`, which keeps it out of
        /// the process list).
        #[arg(long)]
        seed_phrase: Option<String>,

        /// Vault namespace (default: "default").
        #[arg(long, default_value = "default")]
        vault_namespace: String,

        /// Optional path to a local `.catalog.bin` EncryptedVaultCatalogEnvelope file (if omitted, queries Kademlia DHT over `--peers`).
        #[arg(long)]
        catalog_envelope: Option<PathBuf>,

        /// Target output directory where the recovered directory tree will be restored.
        #[arg(
            long,
            visible_alias = "target-dir",
            default_value = "./recovered_vault"
        )]
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
    /// Ring admission (`ADR-05`): issue (`invite`) or install (`install-chain`) a Web-of-Trust
    /// delegation chain. A node needs a chain for every key it stores data as.
    Wot {
        #[command(subcommand)]
        action: WotAction,
    },
    /// Mint, offline-attenuate, and inspect `PARVAULT-MAC-V1:` capability macaroons (`ADR-32`).
    Token {
        #[command(subcommand)]
        action: crate::gateway::TokenAction,
    },
    /// Zero-copy Unix Domain Socket IPC gateway & 40-lane outbound mesh router (`serve`, `health`, `ipc-roundtrip`, `self-test`).
    Gateway {
        #[command(flatten)]
        opts: crate::gateway::GatewayCommonOpts,

        #[command(subcommand)]
        action: Option<crate::gateway::GatewayAction>,
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

        /// Optional bind address for the embedded Router Cloud-NAS HTTP dashboard & JSON API (e.g. `0.0.0.0:4080`).
        #[arg(long, value_name = "ADDR")]
        status_http: Option<String>,

        /// Optional Unix Domain Socket path for the Zero-Copy IPC Gateway (e.g. `/var/run/parvault.sock`).
        #[arg(long, value_name = "SOCK_PATH")]
        ipc_socket: Option<PathBuf>,

        /// Explicitly disable binding any Unix Domain Socket (`GatewayBus::InProcess` only; incompatible with `--ipc-socket`).
        #[arg(long, default_value_t = false)]
        no_socket: bool,

        /// Reject any Unix socket plugin client whose kernel `SO_PEERCRED` UID is not in `--allow-peer-uid`.
        #[arg(long, default_value_t = false)]
        strict_plugins: bool,

        /// Comma-delimited list of POSIX UIDs authorized to connect when `--strict-plugins` is active.
        #[arg(long, value_delimiter = ',', value_name = "UID")]
        allow_peer_uid: Vec<u32>,

        /// Require immutable Linux `memfd` seals (`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW`) on all `StorePayload` calls.
        #[arg(long, default_value_t = false)]
        require_sealed_memfd: bool,

        /// Optional 64-character hex 32-byte `K_macaroon_root` key enforcing `< 1 ms` in-RAM capability verification.
        #[arg(long, value_name = "64-HEX")]
        macaroon_root_key_hex: Option<String>,

        /// Optional bind address for the built-in (`=y`) VFS HTTP `Range` (`206`) + WebDAV server (works even with `--no-socket`).
        #[arg(long, value_name = "ADDR")]
        vfs_webdav_listen: Option<String>,

        /// Optional pre-mounted `/dev/fuse` file descriptor for the built-in (`=y`) pure-Rust FUSE protocol loop.
        #[arg(long, value_name = "FD")]
        vfs_fuse_fd: Option<i32>,

        /// Optional local directory to ingest into the built-in (`=y`) VFS at startup (honors `.parvaultignore`).
        #[arg(long, value_name = "DIR")]
        vfs_seed_dir: Option<PathBuf>,

        /// Bounded local LRU block cache capacity in MiB for the built-in (`=y`) VFS.
        #[arg(long, default_value_t = 64, value_name = "MIB")]
        vfs_cache_mib: u64,
    },
}

#[derive(Debug, Subcommand)]
pub enum FileAction {
    /// Encrypt a file with AES-256-GCM in streaming stripes, split into Reed-Solomon shards, and store.
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
#[serde(default)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub listen_tcp: String,
    pub enable_quic: bool,
    pub listen_quic: String,
    #[serde(default, alias = "profile")]
    pub hardware_profile: HardwareProfile,
    pub stripe_size_bytes: usize,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
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
    /// Optional Online WAN rendezvous / DDNS seed Multiaddrs (including `/dns4/...` hostnames).
    #[serde(default)]
    pub wan_rendezvous_seeds: Vec<String>,
    /// Optional BitTorrent-style Public Commons tracker Multiaddrs (`--tracker` / `PARVAULT_TRACKERS`).
    #[serde(default, alias = "trackers")]
    pub public_trackers: Vec<String>,
    /// Trust admission mode (`"private"` default, `"public"`, or `"hybrid"` — `ADR-18`).
    #[serde(default)]
    pub trust_mode: crate::network::wot::TrustPoolMode,
    /// Hex-encoded 32-byte Ed25519 public keys trusted to issue signed mesh eviction orders (`ADR-19`).
    #[serde(default)]
    pub eviction_authorities: Vec<String>,
    /// Optional explicit `M-of-N` federated Public Tracker Operator quorum threshold (`None` = auto strict majority).
    #[serde(default)]
    pub tracker_eviction_quorum: Option<usize>,
    /// Optional explicitly advertised public WAN Multiaddrs (`--external-addr` / `PARVAULT_EXTERNAL_ADDRS`).
    #[serde(default)]
    pub external_addrs: Vec<String>,
    /// Enable zero-IP signed Home LAN discovery responder & scanner (`default = true`).
    #[serde(default = "default_lan_discovery_enabled")]
    pub lan_discovery_enabled: bool,
    /// UDP port for signed Home LAN zero-IP discovery (`default = 4009`).
    #[serde(default = "default_lan_discovery_port")]
    pub lan_discovery_port: u16,
    /// Optional human-readable node label advertised on LAN/WAN discovery & status dashboard.
    #[serde(default, alias = "label")]
    pub node_label: Option<String>,
    /// Optional bind address for the embedded Router Cloud-NAS status HTTP server (e.g. `"0.0.0.0:4080"`).
    #[serde(default, alias = "status_http")]
    pub status_http_bind: Option<String>,
    /// Optional default folder watched in `parvault up` turnkey appliance mode.
    #[serde(default, alias = "watch_folder")]
    pub watched_folder: Option<PathBuf>,
    /// Optional hex-encoded 32-byte Web-of-Trust Genesis Root public key (`PARVAULT_GENESIS_PUBKEY_HEX`).
    #[serde(default)]
    pub genesis_root_pubkey_hex: Option<String>,
    /// Optional passphrase for Argon2id hardware enclave key sealing (`PARVAULT_PASSPHRASE`).
    #[serde(default)]
    pub device_sealing_passphrase: Option<String>,
    /// Minimum free OS filesystem space (default 5 GiB on Desktop, 1 GiB on HomelabNas, 64 MiB on RouterSoc).
    #[serde(default = "default_min_free_disk_bytes")]
    pub min_free_disk_bytes: u64,
    /// Optional upload bandwidth limit in Mbps (`0` = unlimited).
    #[serde(default)]
    pub max_upload_mbps: u64,
    /// Optional download bandwidth limit in Mbps (`0` = unlimited).
    #[serde(default)]
    pub max_download_mbps: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(".parvault-data"),
            listen_tcp: "/ip4/0.0.0.0/tcp/4001".to_string(),
            enable_quic: false,
            listen_quic: "/ip4/0.0.0.0/udp/4001/quic-v1".to_string(),
            hardware_profile: HardwareProfile::Desktop,
            stripe_size_bytes: DEFAULT_STRIPE_SIZE_BYTES,
            max_connections: default_max_connections(),
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
            wan_rendezvous_seeds: Vec::new(),
            public_trackers: Vec::new(),
            trust_mode: crate::network::wot::TrustPoolMode::PrivateRing,
            eviction_authorities: Vec::new(),
            tracker_eviction_quorum: None,
            external_addrs: Vec::new(),
            lan_discovery_enabled: default_lan_discovery_enabled(),
            lan_discovery_port: default_lan_discovery_port(),
            node_label: None,
            status_http_bind: None,
            watched_folder: None,
            genesis_root_pubkey_hex: None,
            device_sealing_passphrase: None,
            min_free_disk_bytes: default_min_free_disk_bytes(),
            max_upload_mbps: 0,
            max_download_mbps: 0,
        }
    }
}

impl NodeConfig {
    pub fn from_toml_str(raw: &str) -> anyhow::Result<Self> {
        let val: toml::Value = toml::from_str(raw)?;
        let mut cfg: Self = toml::from_str(raw)?;
        let has_profile = val.get("hardware_profile").is_some() || val.get("profile").is_some();
        if has_profile {
            if val.get("stripe_size_bytes").is_none() {
                cfg.stripe_size_bytes = cfg
                    .hardware_profile
                    .compute_streaming_stripe_layout(MAX_FILE_BYTES)
                    .stripe_size_bytes;
            }
            if val.get("min_free_disk_bytes").is_none() {
                cfg.min_free_disk_bytes = cfg.hardware_profile.min_free_disk_bytes();
            }
            if val.get("max_connections").is_none() {
                cfg.max_connections = cfg.hardware_profile.max_connections();
            }
        }
        Ok(cfg)
    }

    pub fn load_or_default(path: Option<&PathBuf>) -> anyhow::Result<Self> {
        if let Some(cfg_path) = path {
            let raw = std::fs::read_to_string(cfg_path)?;
            Self::from_toml_str(&raw)
        } else {
            Ok(Self::default())
        }
    }

    /// Loads `explicit_config` if provided; otherwise checks `<data_dir>/config.toml` if present,
    /// falling back to `NodeConfig::default()`. Then applies `--data-dir` and `--profile` overrides.
    pub fn load_for_cli(
        explicit_config: Option<&PathBuf>,
        cli_data_dir: Option<&Path>,
        cli_profile: Option<HardwareProfile>,
    ) -> anyhow::Result<Self> {
        let mut cfg = if let Some(cfg_path) = explicit_config {
            Self::load_or_default(Some(cfg_path))?
        } else {
            let candidate_dir = cli_data_dir
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".parvault-data"));
            let auto_cfg_path = candidate_dir.join("config.toml");
            if auto_cfg_path.is_file() {
                Self::load_or_default(Some(&auto_cfg_path))?
            } else {
                Self::default()
            }
        };

        if let Some(override_dir) = cli_data_dir {
            cfg.data_dir = override_dir.to_path_buf();
        }
        if let Some(profile) = cli_profile {
            cfg.apply_hardware_profile(profile);
        }
        Ok(cfg)
    }

    /// Applies `HardwareProfile` tuning (`stripe_size_bytes`, `min_free_disk_bytes`, `max_connections`).
    pub fn apply_hardware_profile(&mut self, profile: HardwareProfile) {
        self.hardware_profile = profile;
        self.stripe_size_bytes = profile.stripe_size_bytes();
        self.min_free_disk_bytes = profile.min_free_disk_bytes();
        self.max_connections = profile.max_connections();
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

    /// Collects deduplicated Online WAN rendezvous seed Multiaddrs from `--seed-addr`,
    /// `PARVAULT_WAN_SEEDS`, `PARVAULT_SEED_ADDR`, and `wan_rendezvous_seeds`.
    pub fn effective_wan_rendezvous_seeds(&self, cli_seed: Option<&str>) -> Vec<String> {
        let mut out = Vec::new();
        let mut push_unique = |s: &str| {
            let trimmed = s.trim();
            if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
                out.push(trimmed.to_string());
            }
        };

        if let Some(seed) = self.effective_seed_addr(cli_seed) {
            push_unique(&seed);
        }
        if let Ok(env_wan) = std::env::var("PARVAULT_WAN_SEEDS") {
            for part in env_wan.split(',') {
                push_unique(part);
            }
        }
        for seed in &self.wan_rendezvous_seeds {
            push_unique(seed);
        }
        out
    }

    /// Collects deduplicated Public Commons tracker Multiaddrs from `--tracker`,
    /// `PARVAULT_TRACKERS`, `public_trackers`, and (when `--public` is active) `--seed-addr`.
    pub fn effective_public_trackers(
        &self,
        cli_trackers: &[String],
        cli_seed: Option<&str>,
        public_mode: bool,
    ) -> Vec<String> {
        let mut out = Vec::new();
        let mut push_unique = |s: &str| {
            let trimmed = s.trim();
            if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
                out.push(trimmed.to_string());
            }
        };

        for t in cli_trackers {
            push_unique(t);
        }
        if let Ok(env_t) = std::env::var("PARVAULT_TRACKERS") {
            for part in env_t.split(',') {
                push_unique(part);
            }
        }
        for t in &self.public_trackers {
            push_unique(t);
        }
        if public_mode {
            if let Some(seed) = self.effective_seed_addr(cli_seed) {
                push_unique(&seed);
            }
        }
        out
    }

    /// Collects deduplicated external/public WAN Multiaddrs from `--external-addr`,
    /// `PARVAULT_EXTERNAL_ADDRS`, and `external_addrs`.
    pub fn effective_external_addrs(&self, cli_external: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        let mut push_unique = |s: &str| {
            let trimmed = s.trim();
            if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
                out.push(trimmed.to_string());
            }
        };

        for addr in cli_external {
            push_unique(addr);
        }
        if let Ok(env_ext) = std::env::var("PARVAULT_EXTERNAL_ADDRS") {
            for part in env_ext.split(',') {
                push_unique(part);
            }
        }
        for addr in &self.external_addrs {
            push_unique(addr);
        }
        out
    }

    pub fn effective_lan_discovery_port(&self, cli_port: Option<u16>) -> u16 {
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
        if self.lan_discovery_port == 0 {
            DEFAULT_LAN_DISCOVERY_PORT
        } else {
            self.lan_discovery_port
        }
    }

    pub fn effective_lan_discovery_enabled(&self, cli_no_lan_discovery: bool) -> bool {
        if cli_no_lan_discovery {
            return false;
        }
        if let Ok(env_dis) = std::env::var("PARVAULT_NO_LAN_DISCOVERY") {
            let v = env_dis.trim().to_ascii_lowercase();
            if matches!(v.as_str(), "1" | "true" | "yes") {
                return false;
            }
        }
        self.lan_discovery_enabled
    }

    pub fn effective_node_label(&self, fallback_peer_id: &str) -> String {
        if let Some(label) = self
            .node_label
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return label.to_string();
        }
        if let Ok(host) = std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")) {
            let trimmed = host.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        let suffix: String = fallback_peer_id
            .chars()
            .rev()
            .take(6)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("parvault-{}", suffix)
    }

    /// Resolves the active `TrustPoolMode` (`PrivateRing`, `PublicCommons`, or `Hybrid`)
    /// honoring `--public`, `PARVAULT_PUBLIC`, `--tracker`, and `config.toml` `trust_mode`.
    pub fn effective_trust_mode(
        &self,
        cli_public: bool,
        cli_trackers: &[String],
    ) -> crate::network::wot::TrustPoolMode {
        use crate::network::wot::TrustPoolMode;
        let env_public = std::env::var("PARVAULT_PUBLIC")
            .ok()
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        if (cli_public || env_public || !cli_trackers.is_empty())
            && self.trust_mode == TrustPoolMode::PrivateRing
        {
            return TrustPoolMode::Hybrid;
        }
        self.trust_mode
    }

    /// Extracts an inline Ed25519 32-byte public key from a `/p2p/<PeerId>` component in `addr`, if present.
    pub fn extract_ed25519_pubkey_from_peer_str(addr: &str) -> Option<[u8; 32]> {
        let peer_token = if let Some((_, tail)) = addr.rsplit_once("/p2p/") {
            tail.split('/').next().unwrap_or(tail).trim()
        } else {
            addr.trim()
        };
        let peer_id = peer_token.parse::<libp2p::PeerId>().ok()?;
        let mh = peer_id.as_ref();
        // Identity multihash (code 0x00) containing protobuf-encoded Ed25519 PublicKey: 0x08 0x01 0x12 0x20 <32 bytes>
        let digest = mh.digest();
        if mh.code() == 0 && digest.len() == 36 && digest[..4] == [0x08, 0x01, 0x12, 0x20] {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&digest[4..36]);
            return Some(pk);
        }
        None
    }

    /// Builds the deduplicated list of trusted 32-byte Ed25519 authority public keys allowed to issue
    /// `SignedBadActorEvictionOrder`s (`ADR-19` Strict Mode Isolation):
    /// - Always trusts `local_pubkey` and explicit `eviction_authorities` (`PARVAULT_EVICTION_AUTHORITIES`).
    /// - In `PrivateRing` mode (`!public_commons_active`): external `tracker_admin_pubkey`s are
    ///   **strictly ignored/rejected** so no public tracker authority can ever affect a private ring;
    ///   only `local_pubkey` and explicit `genesis_pubkey` (+ explicit `eviction_authorities`) are trusted.
    /// - In `--public` (`PublicCommons` / `Hybrid`) mode: trusts `local_pubkey` + pinned
    ///   `tracker_admin_pubkey`s (`extra_pinned_admin_pubkeys` + `<data_dir>/pinned_tracker_admins.json`)
    ///   + explicit `eviction_authorities`, rejecting all non-admin random public peers!
    pub fn resolve_eviction_authorities(
        &self,
        local_pubkey: [u8; 32],
        genesis_pubkey: [u8; 32],
        extra_pinned_admin_pubkeys: &[[u8; 32]],
        public_commons_active: bool,
    ) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        let mut push_pk = |pk: [u8; 32]| {
            if !out.contains(&pk) {
                out.push(pk);
            }
        };

        push_pk(local_pubkey);

        for hex_str in &self.eviction_authorities {
            if let Ok(bytes) = hex::decode(hex_str.trim()) {
                if bytes.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&bytes);
                    push_pk(pk);
                }
            }
        }
        if let Ok(env_auth) = std::env::var("PARVAULT_EVICTION_AUTHORITIES") {
            for part in env_auth.split(',') {
                if let Ok(bytes) = hex::decode(part.trim()) {
                    if bytes.len() == 32 {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&bytes);
                        push_pk(pk);
                    }
                }
            }
        }

        if public_commons_active {
            for &pk in extra_pinned_admin_pubkeys {
                push_pk(pk);
            }
            let pinned_path = self.data_dir.join("pinned_tracker_admins.json");
            if let Ok(raw) = std::fs::read_to_string(&pinned_path) {
                if let Ok(hex_list) = serde_json::from_str::<Vec<String>>(&raw) {
                    for hex_str in hex_list {
                        if let Ok(bytes) = hex::decode(hex_str.trim()) {
                            if bytes.len() == 32 {
                                let mut pk = [0u8; 32];
                                pk.copy_from_slice(&bytes);
                                push_pk(pk);
                            }
                        }
                    }
                }
            }
        } else {
            push_pk(genesis_pubkey);
        }
        out
    }

    /// Resolves `(trusted_council_pubkeys, min_quorum)` for `apply_signed_eviction_order_with_quorum`
    /// (`ADR-19` Strict Mode Isolation + `M-of-N` Federated Public Tracker Operator Council Quorum):
    /// - `local_pubkey` is passed separately as `local_owner_pubkey` (`1-of-1` local device sovereignty),
    ///   so it is not mixed into `trusted_council_pubkeys` when sizing the federated tracker council.
    /// - In `PrivateRing` mode (`!public_commons_active`), external `tracker_admin_pubkey`s are
    ///   strictly excluded; only `genesis_pubkey` + explicit `eviction_authorities` are trusted.
    /// - In `--public` mode (`public_commons_active`), `trusted_council_pubkeys` consists of pinned
    ///   `tracker_admin_pubkey`s + explicit `eviction_authorities`, and `min_quorum` defaults to
    ///   `SignedBadActorEvictionOrder::default_tracker_quorum_threshold(trusted_council.len())`
    ///   unless overridden via `tracker_eviction_quorum` or `PARVAULT_TRACKER_EVICTION_QUORUM`.
    pub fn resolve_eviction_council_and_quorum(
        &self,
        genesis_pubkey: [u8; 32],
        extra_pinned_admin_pubkeys: &[[u8; 32]],
        public_commons_active: bool,
    ) -> (Vec<[u8; 32]>, usize) {
        let mut council = Vec::new();
        let mut push_pk = |pk: [u8; 32]| {
            if pk != [0u8; 32] && !council.contains(&pk) {
                council.push(pk);
            }
        };

        for hex_str in &self.eviction_authorities {
            if let Ok(bytes) = hex::decode(hex_str.trim()) {
                if bytes.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&bytes);
                    push_pk(pk);
                }
            }
        }
        if let Ok(env_auth) = std::env::var("PARVAULT_EVICTION_AUTHORITIES") {
            for part in env_auth.split(',') {
                if let Ok(bytes) = hex::decode(part.trim()) {
                    if bytes.len() == 32 {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&bytes);
                        push_pk(pk);
                    }
                }
            }
        }

        let env_quorum = std::env::var("PARVAULT_TRACKER_EVICTION_QUORUM")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok());

        if public_commons_active {
            for &pk in extra_pinned_admin_pubkeys {
                push_pk(pk);
            }
            let pinned_path = self.data_dir.join("pinned_tracker_admins.json");
            if let Ok(raw) = std::fs::read_to_string(&pinned_path) {
                if let Ok(hex_list) = serde_json::from_str::<Vec<String>>(&raw) {
                    for hex_str in hex_list {
                        if let Ok(bytes) = hex::decode(hex_str.trim()) {
                            if bytes.len() == 32 {
                                let mut pk = [0u8; 32];
                                pk.copy_from_slice(&bytes);
                                push_pk(pk);
                            }
                        }
                    }
                }
            }
            let min_quorum = self
                .tracker_eviction_quorum
                .or(env_quorum)
                .unwrap_or_else(|| {
                    crate::storage::SignedBadActorEvictionOrder::default_tracker_quorum_threshold(
                        council.len(),
                    )
                })
                .max(1);
            (council, min_quorum)
        } else {
            push_pk(genesis_pubkey);
            let min_quorum = self
                .tracker_eviction_quorum
                .or(env_quorum)
                .unwrap_or(1)
                .max(1);
            (council, min_quorum)
        }
    }

    /// Persists a discovered Public Tracker Admin Ed25519 pubkey into `<data_dir>/pinned_tracker_admins.json`.
    pub fn persist_pinned_tracker_admin(&self, admin_pubkey: [u8; 32]) {
        let pinned_path = self.data_dir.join("pinned_tracker_admins.json");
        let mut list: Vec<String> = std::fs::read_to_string(&pinned_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let hex_pk = hex::encode(admin_pubkey);
        if !list.iter().any(|existing| existing == &hex_pk) {
            list.push(hex_pk);
            if let Ok(json) = serde_json::to_vec_pretty(&list) {
                let _ = crate::storage::BlockStore::atomic_write_file(&pinned_path, &json);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_profile_parameters_and_backward_compatible_toml() {
        assert_eq!(HardwareProfile::RouterSoc.stripe_size_bytes(), 1_048_576);
        assert_eq!(
            HardwareProfile::RouterSoc.min_free_disk_bytes(),
            64 * 1024 * 1024
        );
        assert_eq!(HardwareProfile::RouterSoc.max_connections(), 24);

        assert_eq!(HardwareProfile::HomelabNas.stripe_size_bytes(), 4_194_304);
        assert_eq!(
            HardwareProfile::HomelabNas.min_free_disk_bytes(),
            1024 * 1024 * 1024
        );

        assert_eq!(
            HardwareProfile::Desktop.stripe_size_bytes(),
            16 * 1024 * 1024
        );

        // Legacy v0.2.0 minimal TOML without new v0.3.0 fields must parse cleanly
        let legacy_toml = r#"
            data_dir = "/var/lib/parvault"
            listen_tcp = "/ip4/0.0.0.0/tcp/4001"
            enable_quic = false
            listen_quic = "/ip4/0.0.0.0/udp/4001/quic-v1"
            stripe_size_bytes = 16777216
            default_tier = "Consumer"
            max_storage_bytes = 10737418240
            bootstrap_grace_bytes = 1073741824
            por_timeout_ms = 300
            local_rtt_threshold_ms = 5
            intra_asn_ratio = 0.7
        "#;
        let parsed_legacy = NodeConfig::from_toml_str(legacy_toml).expect("parse legacy config");
        assert_eq!(parsed_legacy.hardware_profile, HardwareProfile::Desktop);
        assert!(parsed_legacy.lan_discovery_enabled);
        assert_eq!(parsed_legacy.lan_discovery_port, 4009);

        // Minimal v0.3.0 router-soc TOML automatically applies 1 MiB stripe & 64 MiB disk guard
        let router_toml = r#"
            hardware_profile = "router-soc"
            data_dir = "/mnt/nas/.parvault"
            node_label = "openwrt-gateway"
            status_http_bind = "0.0.0.0:4080"
        "#;
        let parsed_router = NodeConfig::from_toml_str(router_toml).expect("parse router config");
        assert_eq!(parsed_router.hardware_profile, HardwareProfile::RouterSoc);
        assert_eq!(parsed_router.stripe_size_bytes, 1_048_576);
        assert_eq!(parsed_router.min_free_disk_bytes, 64 * 1024 * 1024);
        assert_eq!(parsed_router.max_connections, 24);
        assert_eq!(parsed_router.node_label.as_deref(), Some("openwrt-gateway"));
        assert_eq!(
            parsed_router.status_http_bind.as_deref(),
            Some("0.0.0.0:4080")
        );
    }

    #[test]
    fn test_cli_parses_all_new_and_legacy_subcommands() {
        let init_cli = Cli::try_parse_from([
            "parvault",
            "init",
            "--profile",
            "router-soc",
            "--watch",
            "/mnt/usb/shared",
            "--label",
            "home-router",
            "--max-storage-gib",
            "64",
        ])
        .expect("parse init");
        assert_eq!(init_cli.profile, Some(HardwareProfile::RouterSoc));

        let up_cli = Cli::try_parse_from([
            "parvault",
            "--profile",
            "router-soc",
            "up",
            "--folder",
            "/mnt/usb/shared",
            "--status-http",
            "0.0.0.0:4080",
            "--pair",
        ])
        .expect("parse up");
        assert_eq!(up_cli.profile, Some(HardwareProfile::RouterSoc));

        let join_cli = Cli::try_parse_from([
            "parvault",
            "--seed-addr",
            "/dns4/seed.example.org/tcp/4002",
            "join",
            "--code",
            "anchor-velvet-orbit-oak",
            "--wan",
        ])
        .expect("parse join");
        assert_eq!(
            join_cli.seed_addr.as_deref(),
            Some("/dns4/seed.example.org/tcp/4002")
        );

        let evict_cli = Cli::try_parse_from([
            "parvault",
            "evict",
            "--ip",
            "203.0.113.42",
            "--reason",
            "abuse-report",
            "--propagate",
        ])
        .expect("parse evict");
        assert!(matches!(evict_cli.command, Commands::Evict { .. }));

        let public_toml = r#"
            trust_mode = "public"
            public_trackers = ["/dns4/tracker.example.org/tcp/4002"]
            eviction_authorities = ["1111111111111111111111111111111111111111111111111111111111111111"]
        "#;
        let parsed_pub = NodeConfig::from_toml_str(public_toml).expect("parse public toml");
        assert_eq!(
            parsed_pub.trust_mode,
            crate::network::wot::TrustPoolMode::PublicCommons
        );
        assert_eq!(parsed_pub.eviction_authorities.len(), 1);

        let id = crate::crypto::NodeIdentity::generate();
        let pid = crate::network::node_identity_libp2p_peer_id(&id).expect("peer id");
        let maddr = format!("/ip4/198.51.100.10/tcp/4002/p2p/{pid}");
        assert_eq!(
            NodeConfig::extract_ed25519_pubkey_from_peer_str(&maddr),
            Some(id.public_key_bytes())
        );

        let tok_cli = Cli::try_parse_from([
            "parvault",
            "token",
            "mint",
            "--key-id",
            "dvr-ring",
            "--byte-range",
            "0:65536",
            "--read-only",
            "--allow-peer-uid",
            "1000",
        ])
        .expect("parse token mint");
        assert!(matches!(tok_cli.command, Commands::Token { .. }));

        let gw_cli = Cli::try_parse_from([
            "parvault",
            "--profile",
            "router-soc",
            "gateway",
            "--strict-plugins",
            "--allow-peer-uid",
            "1000,1001",
            "--require-sealed-memfd",
            "serve",
        ])
        .expect("parse gateway serve");
        assert!(matches!(gw_cli.command, Commands::Gateway { .. }));

        let builtin_vfs_cli = Cli::try_parse_from([
            "parvault",
            "up",
            "--no-socket",
            "--vfs-webdav-listen",
            "127.0.0.1:0",
            "--vfs-fuse-fd",
            "3",
            "--vfs-seed-dir",
            "/mnt/usb/seed",
            "--vfs-cache-mib",
            "32",
        ])
        .expect("parse up with built-in vfs");
        assert!(matches!(
            builtin_vfs_cli.command,
            Commands::Up {
                no_socket: true,
                vfs_fuse_fd: Some(3),
                vfs_cache_mib: 32,
                ..
            }
        ));
    }
}
