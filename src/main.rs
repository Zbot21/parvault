#![forbid(unsafe_code)]

mod cli;
use clap::Parser;
use cli::daemon::{run_daemon, DaemonLaunchOptions};
use libp2p::{futures::StreamExt, gossipsub, swarm::SwarmEvent, Multiaddr};
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
        behaviour::{DhtEnvelopeKind, DhtWireEnvelope, MeshNetworkBehaviourEvent},
        build_mesh_swarm, derive_4word_pairing_sas, derive_slot_key_from_code, discover_lan_peers,
        extract_listen_port_and_ip, is_network_peer_addr, node_identity_libp2p_peer_id,
        reflect_observed_wan_multiaddr, resolve_zero_config_peers_with_wan,
        verify_lan_pairing_code, DiscoveredLanPeer, KnownPeersStore, LanBeaconConfig,
        LanBeaconResponder, MeshClient, TrustPoolMode, WanPeerCard, WanRendezvousRegistry,
        WebOfTrustRegistry, DEFAULT_LAN_PAIRING_NONCE, DEFAULT_PUBLIC_WOT_POW_BITS,
        DEFAULT_SUBTREE_SLASH_LIMIT, DEFAULT_WAN_TTL_SECS, PUBLIC_COMMONS_SWARM_SLOT,
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
    let mut cfg =
        NodeConfig::load_for_cli(cli.config.as_ref(), cli.data_dir.as_deref(), cli.profile)?;

    let lan_port = cfg.effective_lan_discovery_port(cli.lan_discovery_port);
    let lan_enabled = cfg.effective_lan_discovery_enabled(cli.no_lan_discovery);
    let trust_mode = cfg.effective_trust_mode(cli.public, &cli.trackers);
    let public_mode = trust_mode.allows_public_commons();
    let public_trackers =
        cfg.effective_public_trackers(&cli.trackers, cli.seed_addr.as_deref(), public_mode);
    let wan_seeds = cfg.effective_wan_rendezvous_seeds(cli.seed_addr.as_deref());
    let external_addrs = cfg.effective_external_addrs(&cli.external_addrs);

    // Handle `parvault init` first before pre-creating default keys so we can print initialization cleanly
    if let Commands::Init {
        watch,
        label,
        max_storage_gib,
    } = cli.command
    {
        let profile = cli.profile.unwrap_or(cfg.hardware_profile);
        cfg.apply_hardware_profile(profile);
        let storage_gib = max_storage_gib.unwrap_or_else(|| profile.default_max_storage_gib());
        cfg.max_storage_bytes = storage_gib.saturating_mul(1024 * 1024 * 1024);
        if let Some(lbl) = label
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            cfg.node_label = Some(lbl);
        }
        if let Some(ref watch_dir) = watch {
            std::fs::create_dir_all(watch_dir)?;
            cfg.watched_folder = Some(watch_dir.clone());
        }
        if !cli.trackers.is_empty() {
            cfg.public_trackers = cli.trackers.clone();
        }
        if cli.public {
            cfg.trust_mode = TrustPoolMode::PublicCommons;
        }
        if let Some(ref seed) = cli.seed_addr {
            cfg.lite_seed_addr = Some(seed.clone());
            if !cfg.wan_rendezvous_seeds.contains(seed) {
                cfg.wan_rendezvous_seeds.push(seed.clone());
            }
        }
        if !external_addrs.is_empty() {
            cfg.external_addrs = external_addrs;
        }
        if let Some(port_override) = cli.lan_discovery_port {
            cfg.lan_discovery_port = port_override;
        }
        if cli.no_lan_discovery {
            cfg.lan_discovery_enabled = false;
        }

        std::fs::create_dir_all(&cfg.data_dir)?;
        let node_id = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
        let libp2p_pid = node_identity_libp2p_peer_id(&node_id)?;
        let pq_kp = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
        let _pq_kem = HybridKemKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
        let _mk = resolve_master_key(
            &cfg.data_dir,
            None,
            cfg.device_sealing_passphrase.as_deref(),
        )?;
        let mnemonic = generate_bip39_mnemonic(24)?;

        let cfg_out_path = cli
            .config
            .clone()
            .unwrap_or_else(|| cfg.data_dir.join("config.toml"));
        let toml_body = toml::to_string_pretty(&cfg)?;
        BlockStore::atomic_write_file(&cfg_out_path, toml_body.as_bytes())?;

        let display_label = cfg.effective_node_label(&libp2p_pid.to_string());
        println!(
            "=== ParVault Node Initialized (v{}) ===",
            env!("CARGO_PKG_VERSION")
        );
        println!("Data Directory          : {}", cfg.data_dir.display());
        println!("Configuration File      : {}", cfg_out_path.display());
        println!("Node Label              : {}", display_label);
        println!(
            "Hardware Profile        : {} (stripe={} MiB, min_free_disk={})",
            profile,
            cfg.stripe_size_bytes / (1024 * 1024),
            format_bytes_human(cfg.min_free_disk_bytes)
        );
        println!("Max Storage Allocation  : {} GiB", storage_gib);
        println!("Device Peer ID          : {}", node_id.device_peer_id());
        println!("libp2p Peer ID          : {}", libp2p_pid);
        println!(
            "Owner PQ Fingerprint    : {}",
            pq_kp.public_key().fingerprint_hex()
        );
        if let Some(ref wdir) = cfg.watched_folder {
            println!("Watched Folder          : {}", wdir.display());
        }
        println!("----------------------------------------------------------------------");
        println!("24-Word BIP-39 Recovery Mnemonic (Write this down offline!):");
        println!("  {}", mnemonic);
        println!("----------------------------------------------------------------------");
        println!("Next Steps (Zero-IP Quickstart):");
        println!(
            "  1. Start appliance : parvault --data-dir {} up --pair",
            cfg.data_dir.display()
        );
        println!("  2. Pair any laptop : parvault join --code <4-word-code>");
        return Ok(());
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
        .with_data_dir_discovery(cfg.data_dir.clone(), lan_port);

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

    match cli.command {
        Commands::Init { .. } | Commands::Token { .. } | Commands::Gateway { .. } => {
            unreachable!("handled above")
        }

        Commands::Discover {
            timeout_ms,
            port,
            json,
            wan,
        } => {
            let disc_port = port
                .or(cli.lan_discovery_port)
                .unwrap_or_else(|| cfg.effective_lan_discovery_port(None));
            let local_pid = node_identity_libp2p_peer_id(&node_identity)?.to_string();
            let lan_found: Vec<DiscoveredLanPeer> = if lan_enabled {
                discover_lan_peers(Duration::from_millis(timeout_ms), disc_port)
                    .into_iter()
                    .filter(|p| p.libp2p_peer_id != local_pid)
                    .collect()
            } else {
                Vec::new()
            };

            let mut known_store = KnownPeersStore::load(&cfg.data_dir);
            known_store.upsert_discovered(&lan_found);

            let mut entries: Vec<DiscoverOutputEntry> = lan_found
                .iter()
                .map(|p| DiscoverOutputEntry {
                    peer_id: p.libp2p_peer_id.clone(),
                    device_peer_id: p.device_peer_id.clone(),
                    label: p.node_label.clone(),
                    role: p.role.clone(),
                    multiaddr: p.multiaddr.clone(),
                    available_bytes: p.available_bytes,
                    source: "lan".to_string(),
                })
                .collect();

            if public_mode || !public_trackers.is_empty() {
                for tracker in &public_trackers {
                    if let Ok(cards) =
                        mesh_client.announce_and_discover_public_tracker(tracker, None)
                    {
                        for card in cards {
                            if card.libp2p_peer_id == local_pid
                                || entries.iter().any(|e| e.peer_id == card.libp2p_peer_id)
                            {
                                continue;
                            }
                            if let Some(raw_maddr) = card.wan_multiaddrs.first() {
                                let pinned = if raw_maddr.contains("/p2p/") {
                                    raw_maddr.clone()
                                } else {
                                    format!("{raw_maddr}/p2p/{}", card.libp2p_peer_id)
                                };
                                known_store.upsert_pinned_multiaddr(
                                    &card.libp2p_peer_id,
                                    &pinned,
                                    Some(&card.node_label),
                                    Some(&card.role),
                                );
                                entries.push(DiscoverOutputEntry {
                                    peer_id: card.libp2p_peer_id,
                                    device_peer_id: card.device_peer_id,
                                    label: card.node_label,
                                    role: card.role,
                                    multiaddr: pinned,
                                    available_bytes: 0,
                                    source: "public-tracker".to_string(),
                                });
                            }
                        }
                    }
                }
            }

            if wan && !wan_seeds.is_empty() {
                let pq_fp = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)
                    .ok()
                    .map(|kp| kp.public_key().fingerprint_hex());
                for anchor in &wan_seeds {
                    if let Some(ref fp) = pq_fp {
                        if let Ok(cards) = mesh_client.lookup_wan_ddns_cards(anchor, fp) {
                            for card in cards {
                                if card.libp2p_peer_id == local_pid
                                    || entries.iter().any(|e| e.peer_id == card.libp2p_peer_id)
                                {
                                    continue;
                                }
                                if let Some(raw_maddr) = card.wan_multiaddrs.first() {
                                    let pinned = if raw_maddr.contains("/p2p/") {
                                        raw_maddr.clone()
                                    } else {
                                        format!("{raw_maddr}/p2p/{}", card.libp2p_peer_id)
                                    };
                                    known_store.upsert_pinned_multiaddr(
                                        &card.libp2p_peer_id,
                                        &pinned,
                                        Some(&card.node_label),
                                        Some(&card.role),
                                    );
                                    entries.push(DiscoverOutputEntry {
                                        peer_id: card.libp2p_peer_id,
                                        device_peer_id: card.device_peer_id,
                                        label: card.node_label,
                                        role: card.role,
                                        multiaddr: pinned,
                                        available_bytes: 0,
                                        source: "wan-ddns".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            let _ = known_store.save(&cfg.data_dir);

            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                println!("DISCOVERED PARVAULT PEERS (Zero-IP Configuration)");
                println!("{:-<106}", "");
                println!(
                    "{:<18} | {:<12} | {:<54} | {:<12}",
                    "Label", "Role", "Multiaddr (Pinned PeerId)", "Free Space"
                );
                println!("{:-<106}", "");
                if entries.is_empty() {
                    println!(
                        "(No active LAN/WAN beacons detected within {} ms)",
                        timeout_ms
                    );
                } else {
                    for e in &entries {
                        println!(
                            "{:<18} | {:<12} | {:<54} | {:<12}",
                            e.label,
                            e.role,
                            e.multiaddr,
                            format_bytes_human(e.available_bytes)
                        );
                    }
                }
                println!("{:-<106}", "");
                println!(
                    "Discovered {} verified peer(s). Pinned in {}.",
                    entries.len(),
                    cfg.data_dir.join("known_peers.json").display()
                );
            }
        }

        Commands::Pair {
            port,
            duration_secs,
            once,
            wan,
            listen,
        } => {
            let disc_port = port
                .or(cli.lan_discovery_port)
                .unwrap_or_else(|| cfg.effective_lan_discovery_port(None));
            let listen_str = listen.unwrap_or_else(|| cfg.listen_tcp.clone());
            let listen_maddr: Multiaddr = listen_str.parse()?;
            let (tcp_port, explicit_ip) =
                extract_listen_port_and_ip(&listen_maddr).unwrap_or((4001, None));
            let local_pid = node_identity_libp2p_peer_id(&node_identity)?.to_string();
            let pq_fp = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?
                .public_key()
                .fingerprint_hex();
            let sas = derive_4word_pairing_sas(&local_pid, Some(&pq_fp), DEFAULT_LAN_PAIRING_NONCE);
            let node_label = cfg.effective_node_label(&local_pid);
            let role = cfg.hardware_profile.beacon_role();

            println!("========================================================");
            println!("Home LAN Pairing Code: {}", sas.code);
            println!("Compact Pairing Token: {}", sas.compact_token);
            println!("Node Label / Peer ID : {} ({})", node_label, local_pid);
            println!("Run on client        : parvault join --code {}", sas.code);
            println!("========================================================");

            if wan || !wan_seeds.is_empty() {
                let slot_key = derive_slot_key_from_code(&sas.code);
                for anchor in &wan_seeds {
                    if let Ok(card) = build_wan_card_with_stun_port(StunWanCardParams {
                        mesh_client: &mesh_client,
                        anchor_addr: anchor,
                        probe_slot: slot_key,
                        identity: &node_identity,
                        label: &node_label,
                        role,
                        explicit_external_addrs: &external_addrs,
                        local_tcp_port: tcp_port,
                        local_peer_id: &local_pid,
                        pq_fp: Some(pq_fp.clone()),
                    }) {
                        match mesh_client.publish_wan_pairing_card(anchor, &sas.code, &card) {
                            Ok(obs) => {
                                println!(
                                    "[parvault] Published encrypted WAN pairing card to {} (observed={})",
                                    anchor,
                                    obs.as_deref().unwrap_or("n/a")
                                );
                            }
                            Err(e) => {
                                warn!(anchor = %anchor, error = %e, "Failed to publish WAN pairing card");
                            }
                        }
                    }
                }
            }

            let avail = {
                let q = block_store.quota();
                let g = q.lock().expect("quota lock");
                g.max_storage_bytes().saturating_sub(g.used_storage_bytes())
            };
            let beacon_cfg = LanBeaconConfig::new(node_label, role, tcp_port)
                .with_discovery_port(disc_port)
                .with_explicit_listen_ip(explicit_ip)
                .with_available_bytes(avail)
                .with_owner_pq_fingerprint(Some(pq_fp))
                .with_pairing_sas_commitment(Some(sas.commitment));

            let _beacon = if lan_enabled {
                LanBeaconResponder::spawn(node_identity, beacon_cfg).ok()
            } else {
                None
            };

            if once {
                tokio::time::sleep(Duration::from_millis(60)).await;
                return Ok(());
            }

            println!(
                "Broadcasting signed pairing beacon for {}s (press Ctrl-C to stop)...",
                duration_secs
            );
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(duration_secs)) => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }

        Commands::Join {
            code,
            timeout_ms,
            port,
            wan,
        } => {
            let disc_port = port
                .or(cli.lan_discovery_port)
                .unwrap_or_else(|| cfg.effective_lan_discovery_port(None));
            let local_pid = node_identity_libp2p_peer_id(&node_identity)?.to_string();

            let mut matched: Option<(String, String, String, String)> = None;

            if lan_enabled {
                let lan_peers = discover_lan_peers(Duration::from_millis(timeout_ms), disc_port);
                if let Some(found) = lan_peers
                    .into_iter()
                    .find(|p| p.libp2p_peer_id != local_pid && verify_lan_pairing_code(p, &code))
                {
                    matched = Some((
                        found.libp2p_peer_id,
                        found.node_label,
                        found.role,
                        found.multiaddr,
                    ));
                }
            }

            if matched.is_none() && (wan || !wan_seeds.is_empty()) {
                let normalized_words = normalize_pairing_code_words(&code);
                for anchor in &wan_seeds {
                    for candidate_code in [code.trim(), normalized_words.as_str()] {
                        if let Ok((cards, _)) =
                            mesh_client.lookup_wan_pairing_cards(anchor, candidate_code)
                        {
                            if let Some(card) =
                                cards.into_iter().find(|c| c.libp2p_peer_id != local_pid)
                            {
                                let raw_maddr = card
                                    .wan_multiaddrs
                                    .first()
                                    .cloned()
                                    .or_else(|| card.relay_seed_addr.clone())
                                    .unwrap_or_else(|| anchor.clone());
                                let pinned = if raw_maddr.contains("/p2p/") {
                                    raw_maddr
                                } else {
                                    format!("{raw_maddr}/p2p/{}", card.libp2p_peer_id)
                                };
                                matched =
                                    Some((card.libp2p_peer_id, card.node_label, card.role, pinned));
                                break;
                            }
                        }
                    }
                    if matched.is_some() {
                        break;
                    }
                }
            }

            let Some((peer_id, label, role, multiaddr)) = matched else {
                anyhow::bail!(
                    "Pairing verification failed: no LAN or WAN peer matched code '{}'",
                    code.trim()
                );
            };

            let mut store = KnownPeersStore::load(&cfg.data_dir);
            store.upsert_pinned_multiaddr(&peer_id, &multiaddr, Some(&label), Some(&role));
            store.save(&cfg.data_dir)?;

            let cfg_file = cli
                .config
                .clone()
                .unwrap_or_else(|| cfg.data_dir.join("config.toml"));
            if cfg_file.is_file() && !cfg.bootstrap_peers.iter().any(|p| p == &multiaddr) {
                cfg.bootstrap_peers.push(multiaddr.clone());
                if let Ok(toml_str) = toml::to_string_pretty(&cfg) {
                    let _ = BlockStore::atomic_write_file(&cfg_file, toml_str.as_bytes());
                }
            }

            println!(
                "Paired with {} ({}) — zero IP config ready!",
                label, peer_id
            );
            println!("Pinned Multiaddr: {}", multiaddr);
        }

        Commands::Up {
            folder,
            interval_secs,
            status_http,
            pair,
            wan,
            listen,
            tier,
            ipc_socket,
            no_socket,
            strict_plugins,
            allow_peer_uid,
            require_sealed_memfd,
            macaroon_root_key_hex,
            vfs_webdav_listen,
            vfs_fuse_fd,
            vfs_seed_dir,
            vfs_cache_mib,
        } => {
            validate_builtin_vfs_flags(
                vfs_webdav_listen.as_deref(),
                vfs_fuse_fd,
                vfs_seed_dir.as_deref(),
            )?;
            let strict_allowed_peer_uids = parvault::gateway::validate_plugin_security_flags(
                ipc_socket.is_some(),
                no_socket,
                strict_plugins,
                &allow_peer_uid,
            )?;
            let macaroon_root_key = parvault::gateway::resolve_optional_macaroon_root_key(
                &cfg.data_dir,
                macaroon_root_key_hex.as_deref(),
            )?;
            if let Some(listen_override) = listen {
                cfg.listen_tcp = listen_override;
            }
            let effective_folder = folder.or_else(|| cfg.watched_folder.clone());
            let effective_status_http = status_http.or_else(|| cfg.status_http_bind.clone());
            let effective_tier = if public_mode {
                ErasureTier::Consumer
            } else {
                tier.unwrap_or(cfg.default_tier)
            };
            let opts = DaemonLaunchOptions {
                lan_discovery_enabled: lan_enabled,
                lan_discovery_port: lan_port,
                print_pairing_banner: pair,
                status_http_bind: effective_status_http,
                ipc_socket: if no_socket { None } else { ipc_socket },
                strict_allowed_peer_uids,
                require_sealed_ingest_memfd: require_sealed_memfd,
                macaroon_root_key,
                vfs_webdav_listen,
                vfs_fuse_fd,
                vfs_seed_dir,
                vfs_cache_mib,
                watch_folder: effective_folder,
                sync_interval_secs: interval_secs.max(1),
                sync_tier: effective_tier,
                wan_announce: wan || !wan_seeds.is_empty(),
                wan_seeds,
                public_mode,
                public_trackers,
                external_addrs,
                trust_mode,
            };
            run_daemon(cfg, block_store, opts).await?;
        }

        Commands::Evict {
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
                parse_cli_eviction_target(ip, subnet, peer_id, pubkey_hex, merkle_root, locator)?;
            let mut eviction = PrivacyPreservingEvictionEngine::load_or_init(&cfg.data_dir)?;
            let local_report = eviction.evict_target(&target, &block_store)?;

            let mut remote_report = EvictionPurgeReport::default();
            let mut propagated_orders = 0usize;
            if propagate {
                let now_ms = now_unix_ms();
                let mut orders = vec![SignedBadActorEvictionOrder::issue(
                    &node_identity,
                    target.clone(),
                    reason.clone(),
                    now_ms,
                    0,
                )];
                match &target {
                    EvictionTarget::IpAddress(bad_ip) => {
                        for pk in eviction.resolve_pubkeys_for_ip(*bad_ip) {
                            orders.push(SignedBadActorEvictionOrder::issue(
                                &node_identity,
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
                                &node_identity,
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
                for order in &orders {
                    let rep = mesh_client.propagate_eviction_order_to_peers(&[], order);
                    remote_report.merge(&rep);
                }
            }

            println!("=== ParVault Privacy-Preserving Eviction Complete (ADR-19) ===");
            println!("Data Directory           : {}", cfg.data_dir.display());
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

        Commands::ReportAbuse {
            manifest,
            disclosed_key_hex,
            allegation,
            contact,
            bad_actor_ip,
            stripe_index,
        } => {
            let target_tracker = public_trackers
                .first()
                .cloned()
                .or_else(|| cli.seed_addr.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Missing Public Tracker Multiaddr: pass `--tracker <MULTIADDR>`"
                    )
                })?;
            let disclosed_mk = MasterKey::from_hex(disclosed_key_hex.trim())?;
            let owner_identity = NodeIdentity::from_master_key(&disclosed_mk);
            let file_manifest =
                load_manifest_for_abuse_report(&block_store, &disclosed_mk, &manifest)?;
            let stripe = file_manifest
                .stripes
                .iter()
                .find(|s| s.stripe_index == stripe_index)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Stripe index {} not present in reported FileManifest ({} stripes)",
                        stripe_index,
                        file_manifest.stripes.len()
                    )
                })?;

            let total_shards = stripe.k_data + stripe.m_parity;
            let mut sample_shards: Vec<(u32, Vec<u8>)> = Vec::new();
            for idx in 0..total_shards {
                if sample_shards.len() >= stripe.k_data {
                    break;
                }
                let sid = ShardId {
                    stripe_merkle_root: stripe.stripe_merkle_root,
                    shard_index: idx as u32,
                    shard_hash: stripe.shard_hashes[idx],
                };
                if let Ok(bytes) = block_store.get_shard(&sid) {
                    if hash_shard_leaf(idx as u32, &bytes) == stripe.shard_hashes[idx] {
                        sample_shards.push((idx as u32, bytes));
                    }
                }
            }

            if sample_shards.len() < stripe.k_data {
                let client_for_fetch = mesh_client.with_identity(owner_identity.clone());
                let _ =
                    client_for_fetch.announce_and_discover_public_tracker(&target_tracker, None);
                let fetched_slots = client_for_fetch.fetch_stripe_shards(stripe, &owner_identity);
                for (idx, slot) in fetched_slots.into_iter().enumerate() {
                    if sample_shards.len() >= stripe.k_data {
                        break;
                    }
                    if sample_shards
                        .iter()
                        .any(|(existing, _)| *existing == idx as u32)
                    {
                        continue;
                    }
                    if let Some(bytes) = slot {
                        if hash_shard_leaf(idx as u32, &bytes) == stripe.shard_hashes[idx] {
                            sample_shards.push((idx as u32, bytes));
                        }
                    }
                }
                if sample_shards.len() < stripe.k_data {
                    for idx in 0..total_shards {
                        if sample_shards.len() >= stripe.k_data {
                            break;
                        }
                        if sample_shards
                            .iter()
                            .any(|(existing, _)| *existing == idx as u32)
                        {
                            continue;
                        }
                        let sid = ShardId {
                            stripe_merkle_root: stripe.stripe_merkle_root,
                            shard_index: idx as u32,
                            shard_hash: stripe.shard_hashes[idx],
                        };
                        if let Ok(bytes) = client_for_fetch.get_ciphertext_shard(
                            &target_tracker,
                            sid,
                            Some(&owner_identity),
                            None,
                        ) {
                            if hash_shard_leaf(idx as u32, &bytes) == stripe.shard_hashes[idx] {
                                sample_shards.push((idx as u32, bytes));
                            }
                        }
                    }
                }
            }

            if sample_shards.len() < stripe.k_data {
                anyhow::bail!(
                    "Unable to collect k_data={} verified sample shards for stripe {} (found {})",
                    stripe.k_data,
                    stripe_index,
                    sample_shards.len()
                );
            }

            let report = VerifiableAbuseReport::submit_signed(
                &node_identity,
                &contact,
                &allegation,
                bad_actor_ip,
                file_manifest,
                disclosed_key_hex.trim(),
                stripe_index,
                sample_shards,
                now_unix_ms(),
            );
            let local_proof = report
                .verify_cryptographic_burden_of_proof()
                .map_err(|e| anyhow::anyhow!("Cryptographic burden-of-proof check failed: {e}"))?;

            let (ack_report_id, ack_sha) =
                mesh_client.submit_abuse_takedown_report_detailed(&target_tracker, report)?;
            for pk in mesh_client.pinned_tracker_admin_pubkeys() {
                cfg.persist_pinned_tracker_admin(pk);
            }
            let verified_sha = ack_sha.unwrap_or(local_proof.verified_plaintext_sha256);

            println!("=== ParVault Verifiable Abuse Report Submitted (ADR-19) ===");
            println!("Public Tracker           : {}", target_tracker);
            println!("Report ID                : {}", hex::encode(ack_report_id));
            println!(
                "File Merkle Root         : {}",
                hex::encode(local_proof.file_merkle_root)
            );
            println!(
                "Verified Plaintext SHA256: {} ({} bytes; zeroized in RAM)",
                hex::encode(verified_sha),
                local_proof.verified_plaintext_len
            );
            println!("Governance Queue Status  : PendingAdminReview (awaiting Public Tracker Admin review)");
        }

        Commands::Daemon { action } => match action {
            DaemonAction::Start {
                listen,
                enable_quic,
                status_http,
                ipc_socket,
                no_socket,
                strict_plugins,
                allow_peer_uid,
                require_sealed_memfd,
                macaroon_root_key_hex,
                vfs_webdav_listen,
                vfs_fuse_fd,
                vfs_seed_dir,
                vfs_cache_mib,
            } => {
                validate_builtin_vfs_flags(
                    vfs_webdav_listen.as_deref(),
                    vfs_fuse_fd,
                    vfs_seed_dir.as_deref(),
                )?;
                let strict_allowed_peer_uids = parvault::gateway::validate_plugin_security_flags(
                    ipc_socket.is_some(),
                    no_socket,
                    strict_plugins,
                    &allow_peer_uid,
                )?;
                let macaroon_root_key = parvault::gateway::resolve_optional_macaroon_root_key(
                    &cfg.data_dir,
                    macaroon_root_key_hex.as_deref(),
                )?;
                cfg.listen_tcp = listen;
                cfg.enable_quic = enable_quic;
                let opts = DaemonLaunchOptions {
                    lan_discovery_enabled: lan_enabled,
                    lan_discovery_port: lan_port,
                    print_pairing_banner: false,
                    status_http_bind: status_http.or_else(|| cfg.status_http_bind.clone()),
                    ipc_socket: if no_socket { None } else { ipc_socket },
                    strict_allowed_peer_uids,
                    require_sealed_ingest_memfd: require_sealed_memfd,
                    macaroon_root_key,
                    vfs_webdav_listen,
                    vfs_fuse_fd,
                    vfs_seed_dir,
                    vfs_cache_mib,
                    watch_folder: None,
                    sync_interval_secs: 5,
                    sync_tier: cfg.default_tier,
                    wan_announce: !wan_seeds.is_empty(),
                    wan_seeds,
                    public_mode,
                    public_trackers,
                    external_addrs,
                    trust_mode,
                };
                run_daemon(cfg, block_store, opts).await?;
            }
        },

        Commands::File { action } => match action {
            FileAction::Store {
                path,
                path_flag,
                tier,
                key_hex,
            } => {
                let path = path
                    .or(path_flag)
                    .ok_or_else(|| anyhow::anyhow!("Missing input file path"))?;
                let effective_tier = if public_mode {
                    println!(
                        "[parvault] Public Commons mode active: zero-knowledge AES-256-GCM encryption + 10-of-20 Reed-Solomon sharding."
                    );
                    ErasureTier::Consumer
                } else {
                    tier
                };
                let master_key = resolve_master_key(
                    &cfg.data_dir,
                    key_hex.as_deref(),
                    cfg.device_sealing_passphrase.as_deref(),
                )?;
                let owner_identity = NodeIdentity::from_master_key(&master_key);
                let owner_peer_id = owner_identity.device_peer_id();
                let store_with_owner = block_store
                    .clone()
                    .with_mesh_client(mesh_client.with_identity(owner_identity));
                let (k, m, n) = effective_tier.params();
                info!(
                    file = %path.display(),
                    tier = ?effective_tier,
                    k_data = k,
                    m_parity = m,
                    n_total = n,
                    stripe_size_kib = cfg.stripe_size_bytes / 1024,
                    "Encrypting (AES-256-GCM) and Reed-Solomon sharding file..."
                );

                let manifest = store_with_owner.store_file_streaming(
                    &owner_peer_id,
                    &path,
                    &master_key,
                    effective_tier,
                    cfg.stripe_size_bytes,
                )?;
                let (dht_key, _) = manifest.to_encrypted_dht_record(&master_key)?;

                println!("=== ParVault Vault Store Complete ===");
                println!(
                    "File Merkle Root : {}",
                    hex::encode(manifest.file_merkle_root)
                );
                println!("DHT Manifest Key : {}", hex::encode(dht_key));
                println!("Master Key (hex) : {}", master_key.to_hex());
                println!("Original Size    : {} bytes", manifest.original_file_size);
                println!(
                    "Erasure Scheme   : {}-of-{} ({:.1}% efficiency, {:.2}x expansion)",
                    k,
                    n,
                    (k as f64 / n as f64) * 100.0,
                    effective_tier.expansion_factor()
                );
                println!("Total Stripes    : {}", manifest.stripes.len());
                println!("Total Shards     : {}", manifest.stripes.len() * n);
            }
            FileAction::Restore {
                manifest_or_root,
                manifest_or_root_flag,
                output,
                output_flag,
                key_hex,
            } => {
                let manifest_or_root = manifest_or_root
                    .or(manifest_or_root_flag)
                    .ok_or_else(|| anyhow::anyhow!("Missing manifest or Merkle root"))?;
                let output = output
                    .or(output_flag)
                    .ok_or_else(|| anyhow::anyhow!("Missing output path"))?;
                let master_key = resolve_master_key(
                    &cfg.data_dir,
                    key_hex.as_deref(),
                    cfg.device_sealing_passphrase.as_deref(),
                )?;
                let owner_identity = NodeIdentity::from_master_key(&master_key);
                let store_with_owner = block_store
                    .clone()
                    .with_mesh_client(mesh_client.with_identity(owner_identity));
                let manifest =
                    load_manifest_by_arg(&store_with_owner, &master_key, &manifest_or_root)?;

                info!(
                    merkle_root = %hex::encode(manifest.file_merkle_root),
                    output = %output.display(),
                    "Reconstructing Reed-Solomon ciphertext shards and decrypting stripes..."
                );

                store_with_owner.restore_file_streaming(&manifest, &master_key, &output)?;
                println!("=== ParVault Vault Restore Verified ===");
                println!("Restored File    : {}", output.display());
                println!(
                    "Verified Root    : {}",
                    hex::encode(manifest.file_merkle_root)
                );
                println!("Original Size    : {} bytes", manifest.original_file_size);
            }
        },

        Commands::Status => {
            let node_id = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
            let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
            let pq_fp = pq_keypair.public_key().fingerprint_hex();
            let q = block_store.quota();
            let q_guard = q.lock().expect("quota lock");
            println!("=== ParVault Daemon Node Status ===");
            println!("Data Directory        : {}", cfg.data_dir.display());
            println!("Device Peer ID        : {}", node_id.device_peer_id());
            println!("Owner PQ Fingerprint  : {}", pq_fp);
            println!("Hardware Profile      : {}", cfg.hardware_profile);
            println!("Trust Pool Mode       : {}", trust_mode);
            println!(
                "Primary Transport     : TCP + Noise XX + Yamux ({})",
                cfg.listen_tcp
            );
            println!(
                "Secondary QUIC        : {}",
                if cfg.enable_quic {
                    "Enabled"
                } else {
                    "Disabled (ADR-08)"
                }
            );
            println!(
                "Streaming Stripe Size : {} MiB (ADR-01)",
                cfg.stripe_size_bytes / (1024 * 1024)
            );
            println!(
                "PoR Latency Ceiling   : <= {} ms (ADR-03)",
                cfg.por_timeout_ms
            );
            println!(
                "Topology Split Policy : {:.0}% Intra-ASN (<= {} ms RTT) / {:.0}% Cross-Region (ADR-06)",
                cfg.intra_asn_ratio * 100.0,
                cfg.local_rtt_threshold_ms,
                (1.0 - cfg.intra_asn_ratio) * 100.0
            );
            println!(
                "Local Storage Quota   : {} / {} bytes used ({} bytes bootstrap grace)",
                q_guard.used_storage_bytes(),
                q_guard.max_storage_bytes(),
                cfg.bootstrap_grace_bytes
            );
            println!(
                "Min Free Disk Reserve : {} bytes ({:.2} GiB)",
                cfg.min_free_disk_bytes,
                cfg.min_free_disk_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
            );
            println!(
                "Bandwidth Rate Limits : upload={} Mbps, download={} Mbps (0 = unlimited)",
                cfg.max_upload_mbps, cfg.max_download_mbps
            );
            println!("\nEarned Standing Progression Ladder (ADR-12):");
            println!(
                "  SoloPersonalVault -> PersonalDeviceRing -> BuddyMicroCluster -> ProbationaryConsumerPool -> EarnedVerifiedMixedPool -> EarnedHomelabAnchorPool"
            );
            for standing in [
                EarnedStanding::SoloPersonalVault,
                EarnedStanding::PersonalDeviceRing,
                EarnedStanding::BuddyMicroCluster,
                EarnedStanding::ProbationaryConsumerPool,
                EarnedStanding::EarnedVerifiedMixedPool,
                EarnedStanding::EarnedHomelabAnchorPool,
            ] {
                println!("  - {:?}", standing);
            }
            println!("\nSupported SLA Erasure Coding Pools:");
            for tier in [
                ErasureTier::Consumer,
                ErasureTier::Mixed,
                ErasureTier::Homelab,
                ErasureTier::Relay,
            ] {
                let (k, _m, n) = tier.params();
                println!(
                    "  - {:?}: {}-of-{} ({:.1}% net efficiency, {:.2}x expansion, repair trigger @ {}/{})",
                    tier,
                    k,
                    n,
                    (k as f64 / n as f64) * 100.0,
                    tier.expansion_factor(),
                    tier.repair_trigger_watermark(),
                    n
                );
            }
        }

        Commands::Identity => {
            let node_id = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
            let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
            let pq_pk = pq_keypair.public_key();
            let master_key = resolve_master_key(
                &cfg.data_dir,
                None,
                cfg.device_sealing_passphrase.as_deref(),
            )?;
            let mk_sha = compute_sha256(master_key.as_bytes());
            let mk_fp = hex::encode(&mk_sha[..8]);

            println!("=== ParVault Persistent Node Identity ===");
            println!("Device Peer ID          : {}", node_id.device_peer_id());
            println!(
                "Ed25519 Public Key (hex): {}",
                hex::encode(node_id.public_key_bytes())
            );
            println!("Owner PQ Public Key Hex : {}", pq_pk.to_hex()?);
            println!("Owner PQ Fingerprint    : {}", pq_pk.fingerprint_hex());
            println!("Master Key Fingerprint  : {}", mk_fp);
        }

        Commands::IssueDeviceCert {
            device_peer_id,
            device_label,
            cert_out,
        } => {
            let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
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

            println!("=== ParVault PersonalDeviceCert Issued (Ed25519 + ML-DSA-65) ===");
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

        Commands::VerifyDeviceCert {
            cert,
            owner_pq_pubkey_hex,
        } => {
            let raw_cert = if Path::new(&cert).exists() {
                std::fs::read_to_string(&cert)?
            } else {
                cert.clone()
            };
            let parsed_cert = PersonalDeviceCert::from_shareable_token(&raw_cert)
                .or_else(|_| PersonalDeviceCert::from_json_str(&raw_cert))?;

            let owner_pk = if let Some(hex_str) = owner_pq_pubkey_hex {
                HybridPqPublicKey::from_hex(hex_str.trim())?
            } else {
                HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?.public_key()
            };

            if parsed_cert.verify(&owner_pk).is_err() {
                anyhow::bail!(
                    "PersonalDeviceCert verification FAILED against owner PQ public key (fingerprint: {})",
                    owner_pk.fingerprint_hex()
                );
            }

            println!("=== ParVault PersonalDeviceCert Verification: PASS ===");
            println!("Device Peer ID          : {}", parsed_cert.device_peer_id);
            println!("Device Label            : {}", parsed_cert.device_label);
            println!("Issued At (Unix Secs)   : {}", parsed_cert.issued_unix_secs);
            println!("Owner PQ Fingerprint    : {}", owner_pk.fingerprint_hex());
            println!("Verification Status     : VALID (Ed25519 + FIPS 204 ML-DSA-65 verified)");
        }

        Commands::DiffFolder {
            folder,
            snapshot,
            key_hex,
        } => {
            let master_key = resolve_master_key(
                &cfg.data_dir,
                key_hex.as_deref(),
                cfg.device_sealing_passphrase.as_deref(),
            )?;
            let owner_identity = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
            let mut engine =
                FolderSyncEngine::new(block_store, master_key, owner_identity, cfg.default_tier);
            if let Some(snap_path) = &snapshot {
                if snap_path.exists() {
                    let raw = std::fs::read(snap_path)?;
                    let prev_snap: FolderSnapshotManifest = bincode::deserialize(&raw)?;
                    engine.load_previous_snapshot(&prev_snap);
                }
            }
            let diff = engine.diff_folder(&folder)?;
            print_folder_sync_diff(&folder, &diff);
        }

        Commands::WatchFolder {
            folder,
            snapshot_out,
            tier,
            interval_secs,
            once,
            key_hex,
            dry_run,
            prune_deleted,
            seed_phrase,
            vault_namespace,
            catalog_out,
            lite_seed_dir,
            device_cert,
        } => {
            let effective_tier = if public_mode {
                println!(
                    "[parvault] Public Commons mode active: zero-knowledge AES-256-GCM encryption + 10-of-20 Reed-Solomon sharding."
                );
                ErasureTier::Consumer
            } else {
                tier
            };
            let effective_seed_phrase = seed_phrase
                .or_else(|| std::env::var("PARVAULT_SEED_PHRASE").ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let (master_key, owner_identity) =
                if let Some(phrase) = effective_seed_phrase.as_deref() {
                    let canonical =
                        parvault::crypto::validate_recovery_seed_phrase_or_passphrase(phrase)?;
                    (
                        MasterKey::from_recovery_seed_phrase(&canonical, &vault_namespace),
                        NodeIdentity::from_recovery_seed_phrase(&canonical, &vault_namespace),
                    )
                } else {
                    let mk = resolve_master_key(
                        &cfg.data_dir,
                        key_hex.as_deref(),
                        cfg.device_sealing_passphrase.as_deref(),
                    )?;
                    let id = NodeIdentity::from_master_key(&mk);
                    (mk, id)
                };

            let mut store_for_sync = block_store
                .clone()
                .with_mesh_client(mesh_client.with_identity(owner_identity.clone()));
            let is_lite_net_seed = lite_seed_dir
                .as_ref()
                .map(|d| is_network_peer_addr(&d.to_string_lossy()))
                .unwrap_or(false);
            if is_lite_net_seed {
                store_for_sync.set_mesh_client(None);
            }

            let mut engine = FolderSyncEngine::new(
                store_for_sync.clone(),
                master_key.clone(),
                owner_identity.clone(),
                effective_tier,
            );

            if snapshot_out.exists() {
                if let Ok(raw_prev) = std::fs::read(&snapshot_out) {
                    if let Ok(prev_snapshot) =
                        bincode::deserialize::<FolderSnapshotManifest>(&raw_prev)
                    {
                        engine.load_previous_snapshot(&prev_snapshot);
                    }
                }
            }

            if dry_run {
                let diff = engine.diff_folder(&folder)?;
                print_folder_sync_diff(&folder, &diff);
                return Ok(());
            }

            loop {
                let (snapshot, lite_receipts_count) = if let Some(seed_dir) = &lite_seed_dir {
                    let pq_kp = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
                    let cert = if let Some(cert_arg) = &device_cert {
                        let raw_cert = if Path::new(cert_arg).exists() {
                            std::fs::read_to_string(cert_arg)?
                        } else {
                            cert_arg.clone()
                        };
                        PersonalDeviceCert::from_shareable_token(&raw_cert)
                            .or_else(|_| PersonalDeviceCert::from_json_str(&raw_cert))?
                    } else {
                        let node_id = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
                        let issued_at = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        PersonalDeviceCert::issue(
                            &pq_kp,
                            &node_id.device_peer_id(),
                            "lite-client",
                            issued_at,
                        )?
                    };

                    let seed_str = seed_dir.to_string_lossy().to_string();
                    if is_network_peer_addr(&seed_str) {
                        let mut snap = engine.sync_folder_once(&folder)?;
                        let net_client = MeshClient::new(
                            owner_identity.clone(),
                            mesh_client.all_network_endpoints(),
                            Some(seed_str.clone()),
                        )
                        .with_data_dir_discovery(cfg.data_dir.clone(), lan_port);
                        let store_with_net =
                            block_store.clone().with_mesh_client(net_client.clone());
                        let mut receipt_count = 0usize;
                        for entry in snap.files.values_mut() {
                            let needs_syndication =
                                entry.manifest.stripes.iter().any(|s| {
                                    !s.assigned_peers.iter().any(|p| is_network_peer_addr(p))
                                });
                            if !needs_syndication {
                                continue;
                            }
                            let file_path = folder.join(&entry.relative_path);
                            if let Ok(mut file_handle) = std::fs::File::open(&file_path) {
                                use std::io::{Read, Seek, SeekFrom};
                                let stripe_cap = entry.manifest.stripe_size_bytes.max(1024);
                                for stripe_meta in &mut entry.manifest.stripes {
                                    if stripe_meta
                                        .assigned_peers
                                        .iter()
                                        .any(|p| is_network_peer_addr(p))
                                    {
                                        continue;
                                    }
                                    let start = stripe_meta.stripe_index * (stripe_cap as u64);
                                    let mut slice_buf = Vec::new();
                                    if file_handle.seek(SeekFrom::Start(start)).is_ok() {
                                        let _ = (&mut file_handle)
                                            .take(stripe_cap as u64)
                                            .read_to_end(&mut slice_buf);
                                    }
                                    if let Ok(ciphertext_bytes) = encrypt_stripe(
                                        &master_key,
                                        &entry.manifest.file_salt,
                                        stripe_meta.stripe_index,
                                        &slice_buf,
                                    ) {
                                        let bundle = LiteStripeSyndicationBundle {
                                            stripe_index: stripe_meta.stripe_index,
                                            tier: snap.tier,
                                            ciphertext_bytes,
                                            expected_stripe_merkle_root: stripe_meta
                                                .stripe_merkle_root,
                                            expected_shard_hashes: stripe_meta.shard_hashes.clone(),
                                        };
                                        let grant = RepairGrant::issue(
                                            &owner_identity,
                                            stripe_meta.stripe_merkle_root,
                                            Vec::new(),
                                            snap.tier,
                                        );
                                        if let Ok((_receipt, syndicated_peers)) = net_client
                                            .syndicate_lite_stripe_with_grant(
                                                &seed_str,
                                                cert.clone(),
                                                bundle,
                                                Some(grant),
                                            )
                                        {
                                            receipt_count += 1;
                                            let has_net = syndicated_peers
                                                .iter()
                                                .any(|p| is_network_peer_addr(p));
                                            stripe_meta.assigned_peers = if has_net {
                                                syndicated_peers
                                            } else {
                                                vec![
                                                    seed_str.clone();
                                                    stripe_meta.shard_hashes.len()
                                                ]
                                            };
                                            for (idx, &sh_hash) in
                                                stripe_meta.shard_hashes.iter().enumerate()
                                            {
                                                let sid = ShardId {
                                                    stripe_merkle_root: stripe_meta
                                                        .stripe_merkle_root,
                                                    shard_index: idx as u32,
                                                    shard_hash: sh_hash,
                                                };
                                                let _ = block_store.delete_shard(
                                                    &owner_identity.device_peer_id(),
                                                    &sid,
                                                );
                                                let _ = block_store.delete_shard("local", &sid);
                                            }
                                        }
                                    }
                                }
                                let _ = store_with_net.save_manifest(&master_key, &entry.manifest);
                            }
                        }
                        if let Some(ref env) = snap.signed_dht_envelope {
                            let _ = net_client
                                .put_dht_envelope(DhtWireEnvelope::ClassicalManifest(env.clone()));
                        }
                        engine.load_previous_snapshot(&snap);
                        (snap, receipt_count)
                    } else {
                        let seed_quota =
                            QuotaManager::new(cfg.max_storage_bytes, cfg.bootstrap_grace_bytes);
                        let seed_store = BlockStore::new(seed_dir, seed_quota)?
                            .with_stripe_size_bytes(cfg.stripe_size_bytes);
                        let mut seed_server = ZeroTrustSeedServer::new_homelab_vault(
                            "paired-homelab-seed",
                            seed_store,
                            pq_kp.public_key(),
                            2,
                        );
                        let (snap, receipts) = engine.sync_folder_lite_via_seed(
                            &folder,
                            &cert,
                            &mut seed_server,
                            &[],
                        )?;
                        (snap, receipts.len())
                    }
                } else {
                    (engine.sync_folder_once(&folder)?, 0)
                };
                let raw_snapshot = bincode::serialize(&snapshot)?;
                BlockStore::atomic_write_file(&snapshot_out, &raw_snapshot)?;

                let pruned_shards = if prune_deleted {
                    if is_lite_net_seed {
                        let seed_str = lite_seed_dir
                            .as_ref()
                            .map(|d| d.to_string_lossy().to_string());
                        let net_client = MeshClient::new(
                            owner_identity.clone(),
                            mesh_client.all_network_endpoints(),
                            seed_str,
                        )
                        .with_data_dir_discovery(cfg.data_dir.clone(), lan_port);
                        let net_engine = FolderSyncEngine::new(
                            block_store.clone().with_mesh_client(net_client),
                            master_key.clone(),
                            owner_identity.clone(),
                            effective_tier,
                        );
                        net_engine.prune_deleted_file_shards(&snapshot)?
                    } else {
                        engine.prune_deleted_file_shards(&snapshot)?
                    }
                } else {
                    0
                };

                println!("=== Neighborhood Cloud Folder Sync Pass Complete ===");
                println!("Watched Folder     : {}", folder.display());
                println!("Snapshot Version   : {}", snapshot.version);
                println!(
                    "Folder Merkle Root : {}",
                    hex::encode(snapshot.folder_merkle_root)
                );
                println!("Files Synced       : {}", snapshot.files.len());
                println!("Deleted Tombstones : {}", snapshot.deleted_tombstones.len());
                if lite_receipts_count > 0 {
                    println!(
                        "Lite Mode Syndicated: {} stripes cached on seed & syndicated (ADR-17)",
                        lite_receipts_count
                    );
                }
                if prune_deleted {
                    println!("Pruned Shards      : {}", pruned_shards);
                }
                println!("Snapshot Saved To  : {}", snapshot_out.display());
                println!("Master Key (hex)   : {}", master_key.to_hex());

                if let Some(cat_path) = &catalog_out {
                    let phrase = effective_seed_phrase
                        .as_deref()
                        .unwrap_or("parvault-default-local-catalog-seed");
                    let envelope = engine.export_encrypted_vault_catalog(
                        phrase,
                        &vault_namespace,
                        &snapshot,
                    )?;
                    if is_lite_net_seed {
                        let seed_str = lite_seed_dir
                            .as_ref()
                            .map(|d| d.to_string_lossy().to_string());
                        let net_client = MeshClient::new(
                            owner_identity.clone(),
                            mesh_client.all_network_endpoints(),
                            seed_str,
                        )
                        .with_data_dir_discovery(cfg.data_dir.clone(), lan_port);
                        let _ = net_client
                            .put_dht_envelope(DhtWireEnvelope::VaultCatalog(envelope.clone()));
                    }
                    let raw_env = bincode::serialize(&envelope)?;
                    BlockStore::atomic_write_file(cat_path, &raw_env)?;
                    println!("Catalog Envelope   : {}", cat_path.display());
                } else if let Some(phrase) = effective_seed_phrase.as_deref() {
                    let default_cat = snapshot_out.with_extension("catalog.bin");
                    let envelope = engine.export_encrypted_vault_catalog(
                        phrase,
                        &vault_namespace,
                        &snapshot,
                    )?;
                    if is_lite_net_seed {
                        let seed_str = lite_seed_dir
                            .as_ref()
                            .map(|d| d.to_string_lossy().to_string());
                        let net_client = MeshClient::new(
                            owner_identity.clone(),
                            mesh_client.all_network_endpoints(),
                            seed_str,
                        )
                        .with_data_dir_discovery(cfg.data_dir.clone(), lan_port);
                        let _ = net_client
                            .put_dht_envelope(DhtWireEnvelope::VaultCatalog(envelope.clone()));
                    }
                    let raw_env = bincode::serialize(&envelope)?;
                    BlockStore::atomic_write_file(&default_cat, &raw_env)?;
                    println!("Catalog Envelope   : {}", default_cat.display());
                }

                if once {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(interval_secs.max(1))).await;
            }
        }

        Commands::ListSnapshot { snapshot } => {
            let raw_snapshot = std::fs::read(&snapshot)?;
            let snapshot_manifest: FolderSnapshotManifest = bincode::deserialize(&raw_snapshot)?;
            let entries = FolderSyncEngine::list_snapshot_catalog(&snapshot_manifest);
            println!(
                "=== ParVault Vault Snapshot Catalog (Zero-Shard-Download Browse, ADR-17) ==="
            );
            println!("Snapshot File      : {}", snapshot.display());
            println!("Snapshot Version   : {}", snapshot_manifest.version);
            println!(
                "Folder Merkle Root : {}",
                hex::encode(snapshot_manifest.folder_merkle_root)
            );
            println!("Total Files        : {}", entries.len());
            for item in &entries {
                println!(
                    "  - {:<36} | {:>10} bytes | {} stripes | root={}",
                    item.relative_path,
                    item.size_bytes,
                    item.stripe_count,
                    &hex::encode(item.file_merkle_root)[..16]
                );
            }
        }

        Commands::RestoreFolder {
            snapshot,
            out_dir,
            key_hex,
            file,
            filter,
        } => {
            let master_key = resolve_master_key(
                &cfg.data_dir,
                key_hex.as_deref(),
                cfg.device_sealing_passphrase.as_deref(),
            )?;
            let raw_snapshot = std::fs::read(&snapshot)?;
            let snapshot_manifest: FolderSnapshotManifest = bincode::deserialize(&raw_snapshot)?;
            let owner_identity = NodeIdentity::from_master_key(&master_key);
            let store_with_owner = block_store
                .clone()
                .with_mesh_client(mesh_client.with_identity(owner_identity.clone()));
            let engine = FolderSyncEngine::new(
                store_with_owner,
                master_key,
                owner_identity,
                snapshot_manifest.tier,
            );
            if let Some(rel_file) = file {
                let restored_path =
                    engine.restore_single_file(&snapshot_manifest, &rel_file, &out_dir)?;
                println!("=== Neighborhood Cloud Selective File Restore Verified ===");
                println!("Restored File      : {}", restored_path.display());
                println!("Relative Path      : {}", rel_file);
                println!("Snapshot Version   : {}", snapshot_manifest.version);
                println!(
                    "Folder Merkle Root : {}",
                    hex::encode(snapshot_manifest.folder_merkle_root)
                );
            } else if let Some(filter_csv) = filter {
                let filters: Vec<String> = filter_csv
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let report =
                    engine.restore_selective_subset(&snapshot_manifest, &filters, &out_dir)?;
                println!("=== Neighborhood Cloud Selective Subset Restore Verified (ADR-17) ===");
                println!("Restored Directory : {}", out_dir.display());
                println!("Files Restored     : {:?}", report.files_restored);
                println!("Files Skipped      : {}", report.files_skipped);
                println!("Bytes Restored     : {} bytes", report.bytes_restored);
                println!(
                    "Bytes Saved        : {} bytes (not downloaded)",
                    report.bytes_saved_not_downloaded
                );
            } else {
                let count = engine.restore_folder(&snapshot_manifest, &out_dir)?;
                println!("=== Neighborhood Cloud Folder Restore Verified ===");
                println!("Restored Directory : {}", out_dir.display());
                println!("Snapshot Version   : {}", snapshot_manifest.version);
                println!(
                    "Folder Merkle Root : {}",
                    hex::encode(snapshot_manifest.folder_merkle_root)
                );
                println!(
                    "Files Restored     : {} (all SHA-256 & AES-256-GCM tags verified)",
                    count
                );
            }
        }

        Commands::RecoverFromSeed {
            seed_phrase,
            vault_namespace,
            catalog_envelope,
            out_dir,
            filter,
        } => {
            let canonical_seed =
                parvault::crypto::validate_recovery_seed_phrase_or_passphrase(&seed_phrase)?;
            let master_key =
                MasterKey::from_recovery_seed_phrase(&canonical_seed, &vault_namespace);
            let pq_master_key = parvault::crypto::PqVaultMasterKey::from_recovery_seed_phrase(
                &canonical_seed,
                &vault_namespace,
            );
            let owner_identity =
                NodeIdentity::from_recovery_seed_phrase(&canonical_seed, &vault_namespace);
            let recovery_store = block_store
                .clone()
                .with_mesh_client(mesh_client.with_identity(owner_identity.clone()));

            let envelope: EncryptedVaultCatalogEnvelope = if let Some(cat_path) = catalog_envelope {
                let raw_env = std::fs::read(&cat_path)?;
                bincode::deserialize(&raw_env).or_else(|_| {
                    serde_json::from_slice::<EncryptedVaultCatalogEnvelope>(&raw_env)
                })?
            } else {
                let dht_key = master_key.derive_vault_root_dht_key(&vault_namespace);
                if let Some(client) = recovery_store.mesh_client() {
                    if !client.all_network_endpoints().is_empty() {
                        match client.get_dht_envelope(&dht_key, DhtEnvelopeKind::VaultCatalog)? {
                            DhtWireEnvelope::VaultCatalog(env) => env,
                            _ => anyhow::bail!("unexpected DHT envelope kind for VaultCatalog"),
                        }
                    } else {
                        recovery_store
                            .get_dht_vault_catalog_envelope(&dht_key)
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "EncryptedVaultCatalogEnvelope not found in local DHT store"
                                )
                            })?
                    }
                } else {
                    recovery_store
                        .get_dht_vault_catalog_envelope(&dht_key)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "EncryptedVaultCatalogEnvelope not found in local DHT store"
                            )
                        })?
                }
            };

            if let Some(filter_csv) = filter {
                let filters: Vec<String> = filter_csv
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let snapshot = envelope.open(&master_key, &pq_master_key)?;
                let engine = FolderSyncEngine::new(
                    recovery_store,
                    master_key,
                    owner_identity,
                    snapshot.tier,
                );
                let report = engine.restore_selective_subset(&snapshot, &filters, &out_dir)?;
                println!(
                    "=== ParVault Selective Disaster Recovery From Seed Phrase Complete (ADR-17) ==="
                );
                println!("Vault Namespace    : {}", vault_namespace);
                println!("Files Restored     : {:?}", report.files_restored);
                println!("Files Skipped      : {}", report.files_skipped);
                println!(
                    "Bytes Saved        : {} bytes (not downloaded)",
                    report.bytes_saved_not_downloaded
                );
            } else {
                let recovered_count = FolderSyncEngine::recover_folder_from_seed_phrase(
                    &recovery_store,
                    &seed_phrase,
                    &vault_namespace,
                    &envelope,
                    &out_dir,
                )?;
                println!("=== ParVault Disaster Recovery From Seed Phrase Complete (ADR-15) ===");
                println!("Vault Namespace    : {}", vault_namespace);
                println!("Catalog Version    : {}", envelope.monotonic_version);
                println!("DHT Root Key (hex) : {}", hex::encode(envelope.dht_key));
                println!("Recovered To       : {}", out_dir.display());
                println!("Files Restored     : {}", recovered_count);
            }
        }

        Commands::Scrub => {
            let report = block_store.scrub_all_shards()?;
            let healthy_shards =
                report.verified_healthy_shards + report.verified_healthy_blinded_shards;
            let corrupted_quarantined_shards = report.quarantined_corrupted_shards.len()
                + report.quarantined_corrupted_blinded_locators.len();
            let total_shards_scanned = healthy_shards + corrupted_quarantined_shards;
            println!("=== ParVault Local Bit-Rot Scrub Report (ADR-15) ===");
            println!("Data Directory               : {}", cfg.data_dir.display());
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

        Commands::Leave {
            handoff_to,
            keep_local,
        } => {
            let identity = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
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
            println!("=== ParVault Graceful Node Decommission Complete (1.0x Direct Handoff) ===");
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
                "Total Bytes Handed Off   : {} bytes (saved 16x RS repair amplification)",
                receipt.total_bytes_handed_off
            );
            println!(
                "Handoff Manifest SHA-256 : {}",
                hex::encode(receipt.handoff_manifest_sha256)
            );
            println!(
                "Earned Standing Preserved: {} (zero PoR slashing penalty)",
                receipt.earned_standing_preserved
            );
            println!(
                "Signed Receipt Saved To  : {}",
                cfg.data_dir
                    .join("graceful_departure_receipt.json")
                    .display()
            );
        }
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
