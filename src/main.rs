#![forbid(unsafe_code)]

mod cli;
use clap::Parser;
use cli::daemon::{run_daemon, DaemonLaunchOptions};
use libp2p::{futures::StreamExt, swarm::SwarmEvent, Multiaddr};
use parvault::network::server_events::ServerSwarmEvents;
use parvault::network::wire_handler::{handle_daemon_wire_request, DaemonWireHandlerCtx};
use parvault::{
    bootstrap::{
        EarnedStanding, LiteStripeSyndicationBundle, PersonalDeviceCert, ZeroTrustSeedServer,
    },
    config::{Cli, Commands, DaemonAction, ErasureTier, FileAction, NodeConfig},
    crypto::{
        compute_sha256, encrypt_stripe, generate_bip39_mnemonic,
        pqc::{HybridKemKeypair, HybridPqPublicKey, HybridPqSigningKeypair},
        LocalFileKeystore, MasterKey, NodeIdentity,
    },
    network::{
        behaviour::{DhtEnvelopeKind, DhtWireEnvelope},
        build_mesh_server_swarm, derive_4word_pairing_sas, derive_slot_key_from_code,
        discover_lan_peers, extract_listen_port_and_ip, is_network_peer_addr,
        node_identity_libp2p_peer_id, reflect_observed_wan_multiaddr,
        resolve_zero_config_peers_with_wan, verify_lan_pairing_code, DiscoveredLanPeer,
        KnownPeersStore, LanBeaconConfig, LanBeaconResponder, MeshClient, TrustPoolMode,
        WanPeerCard, WanRendezvousRegistry, WebOfTrustRegistry, DEFAULT_LAN_PAIRING_NONCE,
        DEFAULT_PUBLIC_WOT_POW_BITS, DEFAULT_SUBTREE_SLASH_LIMIT, DEFAULT_WAN_TTL_SECS,
        PUBLIC_COMMONS_SWARM_SLOT,
    },
    por::{PorVerifierEngine, RepairGrant},
    router_nas::{RouterNasLiveSnapshot, RouterNasPeerEntry, RouterNasStatusServer},
    sharding::{merkle::hash_shard_leaf, Hash32},
    storage::{
        BlockStore, EvictionPurgeReport, EvictionTarget, FileManifest,
        PrivacyPreservingEvictionEngine, PublicTrackerTakedownQueue, QuotaManager, ShardId,
        SignedBadActorEvictionOrder, VerifiableAbuseReport, VoucherNullifierLedger,
    },
    sync::{
        EncryptedVaultCatalogEnvelope, FolderSnapshotManifest, FolderSyncDiff, FolderSyncEngine,
    },
};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize)]
struct DiscoverOutputEntry {
    peer_id: String,
    device_peer_id: String,
    label: String,
    role: String,
    multiaddr: String,
    available_bytes: u64,
    source: String,
}

fn validate_builtin_vfs_flags(
    vfs_webdav_listen: Option<&str>,
    vfs_fuse_fd: Option<i32>,
    vfs_seed_dir: Option<&Path>,
) -> anyhow::Result<()> {
    if vfs_webdav_listen.is_none() && vfs_fuse_fd.is_none() && vfs_seed_dir.is_none() {
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!(
            "Built-in VFS (--vfs-webdav-listen / --vfs-fuse-fd / --vfs-seed-dir) is only supported on Unix targets"
        );
    }
    #[cfg(all(unix, not(feature = "vfs")))]
    {
        anyhow::bail!(
            "Built-in VFS (--vfs-webdav-listen / --vfs-fuse-fd) is disabled in this --no-default-features build; run standalone `parvault-fuse` over `--ipc-socket <PATH>` or rebuild `parvault` with `--features vfs`"
        );
    }
    #[cfg(all(unix, feature = "vfs"))]
    {
        if let Some(fd) = vfs_fuse_fd {
            if fd < 0 {
                anyhow::bail!(
                    "--vfs-fuse-fd must be a non-negative open /dev/fuse file descriptor"
                );
            }
        }
        if let Some(dir) = vfs_seed_dir {
            if !dir.is_dir() {
                anyhow::bail!(
                    "--vfs-seed-dir '{}' is not an existing directory",
                    dir.display()
                );
            }
        }
        Ok(())
    }
}

fn validate_early_command_flags(cmd: &Commands) -> anyhow::Result<()> {
    match cmd {
        Commands::Up {
            vfs_webdav_listen,
            vfs_fuse_fd,
            vfs_seed_dir,
            ..
        }
        | Commands::Daemon {
            action:
                DaemonAction::Start {
                    vfs_webdav_listen,
                    vfs_fuse_fd,
                    vfs_seed_dir,
                    ..
                },
        } => validate_builtin_vfs_flags(
            vfs_webdav_listen.as_deref(),
            *vfs_fuse_fd,
            vfs_seed_dir.as_deref(),
        ),
        _ => Ok(()),
    }
}

fn command_needs_network_discovery(cmd: &Commands) -> bool {
    !matches!(
        cmd,
        Commands::Init { .. }
            | Commands::NewSeedPhrase
            | Commands::Discover { .. }
            | Commands::Pair { .. }
            | Commands::Join { .. }
            | Commands::Identity
            | Commands::IssueDeviceCert { .. }
            | Commands::VerifyDeviceCert { .. }
            | Commands::DiffFolder { .. }
            | Commands::ListSnapshot { .. }
            | Commands::Scrub
            | Commands::Token { .. }
            | Commands::Wot { .. }
            | Commands::Gateway { .. }
    )
}

fn format_bytes_human(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if bytes as f64 >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB)
    } else if bytes > 0 {
        format!("{:.1} MiB", bytes as f64 / MIB)
    } else {
        "0 B".to_string()
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn normalize_pairing_code_words(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("pvpair1:") {
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() == 3 {
            return parts[2].trim().to_ascii_lowercase();
        }
    }
    trimmed
        .split(|c: char| c == '-' || c.is_whitespace())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("-")
}

struct StunWanCardParams<'a> {
    mesh_client: &'a MeshClient,
    anchor_addr: &'a str,
    probe_slot: [u8; 32],
    identity: &'a NodeIdentity,
    label: &'a str,
    role: &'a str,
    explicit_external_addrs: &'a [String],
    local_tcp_port: u16,
    local_peer_id: &'a str,
    pq_fp: Option<String>,
}

fn build_wan_card_with_stun_port(params: StunWanCardParams<'_>) -> anyhow::Result<WanPeerCard> {
    let StunWanCardParams {
        mesh_client,
        anchor_addr,
        probe_slot,
        identity,
        label,
        role,
        explicit_external_addrs,
        local_tcp_port,
        local_peer_id,
        pq_fp,
    } = params;
    let mut wan_addrs: Vec<String> = explicit_external_addrs
        .iter()
        .map(|s| {
            let trimmed = s.trim();
            if trimmed.contains("/p2p/") || local_peer_id.is_empty() {
                trimmed.to_string()
            } else {
                format!("{trimmed}/p2p/{local_peer_id}")
            }
        })
        .filter(|s| !s.is_empty())
        .collect();

    if wan_addrs.is_empty() {
        if let Ok((_, Some(obs))) = mesh_client.lookup_wan_rendezvous(anchor_addr, probe_slot) {
            if let Ok(obs_maddr) = obs.parse::<Multiaddr>() {
                if let Some(rewritten) =
                    reflect_observed_wan_multiaddr(&obs_maddr, local_tcp_port, local_peer_id)
                {
                    wan_addrs.push(rewritten);
                } else {
                    wan_addrs.push(obs);
                }
            } else {
                wan_addrs.push(obs);
            }
        }
    }

    WanPeerCard::new(
        identity,
        label.to_string(),
        role.to_string(),
        wan_addrs,
        Some(anchor_addr.to_string()),
        pq_fp,
        DEFAULT_WAN_TTL_SECS,
        now_unix_ms(),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("parvault=info,warn")),
        )
        .init();

    let cli = Cli::parse();
    // Stores nothing and needs no data directory or configuration.
    if matches!(cli.command, Commands::NewSeedPhrase) {
        println!("{}", generate_bip39_mnemonic(24)?);
        return Ok(());
    }
    let cfg = NodeConfig::load_for_cli(cli.config.as_ref(), cli.data_dir.as_deref(), cli.profile)?;

    let lan_port = cfg.effective_lan_discovery_port(cli.lan_discovery_port);
    let lan_enabled = cfg.effective_lan_discovery_enabled(cli.no_lan_discovery);
    let trust_mode = cfg.effective_trust_mode(cli.public, &cli.trackers);
    let public_mode = trust_mode.allows_public_commons();
    parvault::network::admission::install_process_source(&cfg.data_dir, public_mode);
    let public_trackers =
        cfg.effective_public_trackers(&cli.trackers, cli.seed_addr.as_deref(), public_mode);
    let wan_seeds = cfg.effective_wan_rendezvous_seeds(cli.seed_addr.as_deref());
    let external_addrs = cfg.effective_external_addrs(&cli.external_addrs);

    // Handle `parvault init` first before pre-creating default keys so we can print initialization cleanly
    if matches!(cli.command, Commands::Init { .. }) {
        return cli::early::init(cfg, cli, external_addrs);
    }

    if let Commands::Wot { action } = cli.command {
        return cli::wot::run(action, &cfg.data_dir);
    }

    if let Commands::Token { action } = cli.command {
        return parvault::gateway::execute_token_cli(action, &cfg.data_dir);
    }

    if let Commands::Gateway { opts, action } = cli.command {
        return parvault::gateway::execute_gateway_cli(opts, action, &cfg, cli.profile, &cli.peers)
            .await;
    }

    validate_early_command_flags(&cli.command)?;

    let node_identity = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
    let explicit_peers = cfg.effective_peers(&cli.peers);
    let effective_seed = cfg.effective_seed_addr(cli.seed_addr.as_deref());

    let resolved_peers = if !explicit_peers.is_empty() {
        explicit_peers.clone()
    } else if command_needs_network_discovery(&cli.command) {
        let anchors: &[String] = if public_mode && !public_trackers.is_empty() {
            &public_trackers
        } else {
            &wan_seeds
        };
        let scan_timeout = if lan_enabled {
            Duration::from_millis(300)
        } else {
            Duration::ZERO
        };
        resolve_zero_config_peers_with_wan(
            &cfg.data_dir,
            &[],
            lan_port,
            scan_timeout,
            &node_identity,
            anchors,
            public_mode,
        )
    } else {
        Vec::new()
    };

    let mesh_client = MeshClient::new(node_identity.clone(), resolved_peers, effective_seed)
        .with_data_dir_discovery(cfg.data_dir.clone(), lan_port)
        .with_lan_discovery(lan_enabled);

    if public_mode && command_needs_network_discovery(&cli.command) {
        for tracker in &public_trackers {
            let _ = mesh_client.announce_and_discover_public_tracker(tracker, None);
        }
        for pk in mesh_client.pinned_tracker_admin_pubkeys() {
            cfg.persist_pinned_tracker_admin(pk);
        }
    }

    let mut quota = QuotaManager::new(cfg.max_storage_bytes, cfg.bootstrap_grace_bytes);
    quota.set_min_free_disk_bytes(cfg.min_free_disk_bytes);
    let block_store = BlockStore::new(&cfg.data_dir, quota)?
        .with_stripe_size_bytes(cfg.stripe_size_bytes)
        .with_mesh_client(mesh_client.clone());

    let env = cli::CliEnv {
        cfg,
        lan_port,
        lan_enabled,
        trust_mode,
        public_mode,
        public_trackers,
        wan_seeds,
        external_addrs,
        node_identity,
        mesh_client,
        block_store,
        cli: cli::CliGlobals {
            lan_discovery_port: cli.lan_discovery_port,
            seed_addr: cli.seed_addr.clone(),
            config: cli.config.clone(),
        },
    };
    match cli.command {
        Commands::Init { .. }
        | Commands::NewSeedPhrase
        | Commands::Token { .. }
        | Commands::Wot { .. }
        | Commands::Gateway { .. } => {
            unreachable!("handled above")
        }

        command @ Commands::Discover { .. } => cli::onboarding::discover(env, command).await?,
        command @ Commands::Pair { .. } => cli::onboarding::pair(env, command).await?,
        command @ Commands::Join { .. } => cli::onboarding::join(env, command).await?,
        command @ Commands::Up { .. } => cli::daemon_cmds::up(env, command).await?,
        command @ Commands::Evict { .. } => cli::abuse::evict(env, command).await?,
        command @ Commands::ReportAbuse { .. } => cli::abuse::report_abuse(env, command).await?,
        command @ Commands::Daemon { .. } => cli::daemon_cmds::daemon(env, command).await?,
        command @ Commands::File { .. } => cli::file::file(env, command).await?,
        command @ Commands::Status => cli::identity::status(env, command).await?,
        command @ Commands::Identity => cli::identity::identity(env, command).await?,
        command @ Commands::IssueDeviceCert { .. } => {
            cli::identity::issue_device_cert(env, command).await?
        }
        command @ Commands::VerifyDeviceCert { .. } => {
            cli::identity::verify_device_cert(env, command).await?
        }
        command @ Commands::DiffFolder { .. } => cli::folder::diff_folder(env, command).await?,
        command @ Commands::WatchFolder { .. } => cli::folder::watch_folder(env, command).await?,
        command @ Commands::ListSnapshot { .. } => cli::folder::list_snapshot(env, command).await?,
        command @ Commands::RestoreFolder { .. } => {
            cli::folder::restore_folder(env, command).await?
        }
        command @ Commands::RecoverFromSeed { .. } => {
            cli::folder::recover_from_seed(env, command).await?
        }
        command @ Commands::Scrub => cli::maintenance::scrub(env, command).await?,
        command @ Commands::Leave { .. } => cli::maintenance::leave(env, command).await?,
    }

    Ok(())
}

fn print_folder_sync_diff(folder: &Path, diff: &FolderSyncDiff) {
    println!("=== Neighborhood Cloud Dry-Run Folder Sync Diff ===");
    println!("Target Folder       : {}", folder.display());
    println!(
        "added               : {} {:?}",
        diff.added.len(),
        diff.added
    );
    println!(
        "modified            : {} {:?}",
        diff.modified.len(),
        diff.modified
    );
    println!(
        "deleted             : {} {:?}",
        diff.deleted.len(),
        diff.deleted
    );
    println!(
        "unchanged           : {} {:?}",
        diff.unchanged.len(),
        diff.unchanged
    );
    println!(
        "ignored             : {} {:?}",
        diff.ignored.len(),
        diff.ignored
    );
    println!("total_upload_bytes  : {}", diff.total_upload_bytes);
}

fn resolve_master_key(
    data_dir: &Path,
    key_hex: Option<&str>,
    passphrase: Option<&str>,
) -> anyhow::Result<MasterKey> {
    if let Some(hex_str) = key_hex {
        Ok(MasterKey::from_hex(hex_str)?)
    } else {
        let sealer = LocalFileKeystore::from_passphrase_or_csprng_in_dir(data_dir, passphrase)?;
        let sealed_path = data_dir.join("master_key.sealed");
        sealer.load_or_create_master_key(&sealed_path)
    }
}

fn load_manifest_by_arg(
    block_store: &BlockStore,
    master_key: &MasterKey,
    arg: &str,
) -> anyhow::Result<FileManifest> {
    let as_path = Path::new(arg);
    if as_path.exists() {
        let raw = std::fs::read(as_path)?;
        Ok(FileManifest::from_encrypted_dht_record(master_key, &raw)?)
    } else {
        let decoded = hex::decode(arg.trim())?;
        if decoded.len() != 32 {
            anyhow::bail!("Expected 64-character hex Merkle root or valid manifest path");
        }
        let mut root: Hash32 = [0u8; 32];
        root.copy_from_slice(&decoded);
        Ok(block_store.load_manifest(master_key, &root)?)
    }
}

fn parse_hex_32_cli(hex_str: &str, field_name: &str) -> anyhow::Result<[u8; 32]> {
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

fn parse_cli_eviction_target(
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
        Ok(EvictionTarget::PeerOrIssuerPubkey(parse_hex_32_cli(
            &pk,
            "--pubkey-hex",
        )?))
    } else if let Some(root) = merkle_root {
        Ok(EvictionTarget::StripeMerkleRoot(parse_hex_32_cli(
            &root,
            "--merkle-root",
        )?))
    } else if let Some(loc) = locator {
        Ok(EvictionTarget::BlindedLocator(parse_hex_32_cli(
            &loc,
            "--locator",
        )?))
    } else {
        unreachable!()
    }
}

fn load_manifest_for_abuse_report(
    block_store: &BlockStore,
    disclosed_mk: &MasterKey,
    manifest_arg: &Path,
) -> anyhow::Result<FileManifest> {
    if manifest_arg.exists() {
        let raw = std::fs::read(manifest_arg)?;
        if let Ok(m) = FileManifest::from_encrypted_dht_record(disclosed_mk, &raw) {
            return Ok(m);
        }
        if let Ok(m) = bincode::deserialize::<FileManifest>(&raw) {
            return Ok(m);
        }
        if let Ok(m) = serde_json::from_slice::<FileManifest>(&raw) {
            return Ok(m);
        }
        if let Ok(snap) = bincode::deserialize::<FolderSnapshotManifest>(&raw) {
            if let Some(first) = snap.files.values().next() {
                return Ok(first.manifest.clone());
            }
        }
        anyhow::bail!(
            "Failed to parse or decrypt FileManifest at {} with disclosed MasterKey",
            manifest_arg.display()
        );
    }
    load_manifest_by_arg(block_store, disclosed_mk, &manifest_arg.to_string_lossy())
}
