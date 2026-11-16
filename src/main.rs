#![forbid(unsafe_code)]

mod cli;
use clap::{CommandFactory, FromArgMatches};
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
        derive_4word_pairing_sas, derive_slot_key_from_code, discover_lan_peers,
        extract_listen_port_and_ip, is_network_peer_addr, node_identity_libp2p_peer_id,
        reflect_observed_wan_multiaddr, resolve_zero_config_peers_with_wan,
        verify_lan_pairing_code, wan_card_pairing_decision, DiscoveredLanPeer, KnownPeersStore,
        LanBeaconConfig, LanBeaconResponder, MeshClient, TrustPoolMode, WanPeerCard,
        WanRendezvousRegistry, WebOfTrustRegistry, DEFAULT_LAN_PAIRING_NONCE,
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
    // C37 (glue G-22): the watch-interval floor, refused before `up --init-if-absent` creates a
    // ring or any other file.
    if let Commands::Up { interval_secs, .. } = cmd {
        let floor = parvault::sync::retention::MIN_WATCH_INTERVAL_SECS;
        if *interval_secs < floor {
            anyhow::bail!("reject.interval_below_floor: --interval-secs must be at least {floor}");
        }
    }
    match cmd {
        Commands::Up {
            vfs_webdav_listen,
            vfs_fuse_fd,
            vfs_seed_dir,
            ipc_socket,
            no_socket,
            tls_san,
            insecure_plain_http,
            gateway_socket_group,
            ..
        }
        | Commands::Daemon {
            action:
                DaemonAction::Start {
                    vfs_webdav_listen,
                    vfs_fuse_fd,
                    vfs_seed_dir,
                    ipc_socket,
                    no_socket,
                    tls_san,
                    insecure_plain_http,
                    gateway_socket_group,
                    ..
                },
        } => {
            validate_builtin_vfs_flags(
                vfs_webdav_listen.as_deref(),
                *vfs_fuse_fd,
                vfs_seed_dir.as_deref(),
            )?;
            refuse_unbuilt_daemon_flags(
                !tls_san.is_empty() || *insecure_plain_http,
                gateway_socket_group.is_some(),
                ipc_socket.is_some() && !*no_socket,
            )
        }
        _ => Ok(()),
    }
}

/// `up` / `daemon start` usage checks before any side effect: the gateway socket group applies to
/// the gateway socket only (B-180). The edge TLS flags and the socket group are built (track A,
/// integration glue G-14 removed their T0 refusals).
fn refuse_unbuilt_daemon_flags(
    edge_tls_flag: bool,
    socket_group: bool,
    has_ipc_socket: bool,
) -> anyhow::Result<()> {
    let _ = edge_tls_flag;
    if socket_group && !has_ipc_socket {
        anyhow::bail!("--gateway-socket-group needs --ipc-socket");
    }
    Ok(())
}

fn command_needs_network_discovery(cmd: &Commands) -> bool {
    !matches!(
        cmd,
        Commands::Init { .. }
            | Commands::NewSeedPhrase
            | Commands::Discover { .. }
            | Commands::Pair { .. }
            | Commands::Join { .. }
            | Commands::Identity { .. }
            | Commands::IssueDeviceCert { .. }
            | Commands::VerifyDeviceCert { .. }
            | Commands::DiffFolder { .. }
            | Commands::ListSnapshot { .. }
            | Commands::FolderStatus { .. }
            | Commands::Scrub
            | Commands::Token { .. }
            | Commands::Wot { .. }
            | Commands::Council { .. }
            | Commands::Gateway { .. }
            | Commands::Config { .. }
            | Commands::Net { .. }
            | Commands::Tls { .. }
            | Commands::Ring { .. }
    )
}

/// `config dump`, `up --dump-config` and `daemon start --dump-config`.
fn dump_requested(cmd: &Commands) -> bool {
    matches!(
        cmd,
        Commands::Config {
            action: parvault::config::ConfigAction::Dump
        } | Commands::Up {
            dump_config: true,
            ..
        } | Commands::Daemon {
            action: DaemonAction::Start {
                dump_config: true,
                ..
            }
        }
    )
}

/// The dump branch (`docs/LAB_MODE.md`): runs before identity, data-dir, key or network work,
/// so it reads only the config file. Exit 0 dumped, 3 when the config does not resolve.
fn run_dump(resolved: anyhow::Result<parvault::config::EffectiveConfig>) -> ! {
    let eff = match resolved {
        Ok(eff) => eff,
        Err(e) => {
            print!(
                "{}",
                parvault::config_dump::render_dump_error("reject.config_unreadable")
            );
            eprintln!("reject.config_unreadable: {e}");
            std::process::exit(3);
        }
    };
    if let Err((code, detail)) = parvault::config::lab_startup_decision(&eff) {
        print!("{}", parvault::config_dump::render_dump_error(code));
        eprintln!("{code}: {detail}");
        std::process::exit(3);
    }
    print!("{}", parvault::config_dump::render_dump(&eff));
    std::process::exit(0);
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

/// Parses the CLI and the config without a runtime, then builds the tokio runtime the hardware
/// profile asks for (B-53): the router profile gets a bounded pool (`HardwareProfile::
/// runtime_worker_threads`, `runtime_max_blocking_threads`); other profiles keep tokio's defaults.
fn main() -> anyhow::Result<()> {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("parvault=info,warn"));
    if matches!(cli.command, Commands::Net { .. }) {
        // `net probe` prints exactly one JSON document on stdout: logs go to stderr.
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    // Stores nothing and needs no data directory or configuration.
    if matches!(cli.command, Commands::NewSeedPhrase) {
        println!("{}", generate_bip39_mnemonic(24)?);
        return Ok(());
    }
    // NEW-5: one resolver for the dump and the command (`docs/LAB_MODE.md`).
    let resolved =
        parvault::config::ConfigFileInput::load(cli.config.as_deref(), cli.data_dir.as_deref())
            .and_then(|file| {
                parvault::config::EffectiveConfig::resolve(
                    &cli,
                    &matches,
                    parvault::config::EnvSnapshot::capture(),
                    file,
                )
            });
    if dump_requested(&cli.command) {
        run_dump(resolved);
    }
    let eff = resolved?;
    if let Err((code, detail)) = parvault::config::lab_startup_decision(&eff) {
        eprintln!("{code}: {detail}");
        std::process::exit(3);
    }
    // NEW-4: the probe runs before any identity, key or data-dir work (docs/LAB_MODE.md).
    if let Commands::Net {
        action:
            parvault::config::NetAction::Probe {
                peer,
                force_direct,
                timeout_ms,
                no_rpc,
            },
    } = &cli.command
    {
        std::process::exit(cli::net::run_probe(
            &eff,
            peer,
            *force_direct,
            *timeout_ms,
            *no_rpc,
        ));
    }
    // The digest of the dump this command would print, taken before any file is created.
    let config_digest = hex::encode(parvault::config_dump::config_digest(
        &parvault::config_dump::render_dump(&eff),
    ));
    parvault::runtime::build_runtime(eff.cfg.hardware_profile)?.block_on(run(
        cli,
        Arc::new(eff),
        config_digest,
    ))
}

async fn run(
    cli: Cli,
    eff: Arc<parvault::config::EffectiveConfig>,
    config_digest: String,
) -> anyhow::Result<()> {
    let cfg: NodeConfig = eff.cfg.clone();
    let lan_port = eff.lan_port;
    let lan_enabled = eff.lan_enabled;
    let trust_mode = eff.trust_mode;
    let public_mode = trust_mode.allows_public_commons();
    let deterministic = eff.deterministic();
    if matches!(
        cli.command,
        Commands::Up { .. }
            | Commands::Daemon {
                action: DaemonAction::Start { .. }
            }
    ) {
        // NEW-3: before any MeshClient exists, so every swarm of the daemon records into them.
        parvault::traversal_metrics::install_process_counters(Arc::new(
            parvault::traversal_metrics::TraversalCounters::new(
                parvault::traversal_metrics::BuildInfo {
                    profile: cfg.hardware_profile.as_str(),
                    deterministic,
                },
            ),
        ));
    }
    if deterministic {
        // Before any MeshClient exists: every client in this process is gated.
        parvault::network::client::install_process_dial_set(
            Arc::new(eff.dial_set()),
            eff.dial_set_entries(),
        );
    }
    parvault::network::admission::install_process_source(&cfg.data_dir, public_mode);
    let public_trackers = eff.public_trackers.clone();
    let wan_seeds = eff.wan_seeds.clone();
    let external_addrs = eff.external_addrs.clone();

    // Handle `parvault init` first before pre-creating default keys so we can print initialization cleanly
    if matches!(cli.command, Commands::Init { .. }) {
        return cli::early::init(cfg, cli, external_addrs);
    }

    if let Commands::Wot { action } = cli.command {
        return cli::wot::run(action, &cfg.data_dir);
    }

    // v0.5.6: the edge certificate (track A) reads only the data dir, like `wot`; the genesis
    // backup (track E) also reads the profile's KDF and the pinned genesis (K1, K6; glue G-13).
    if let Commands::Tls { action } = cli.command {
        return cli::tls::run(action, &cfg.data_dir);
    }

    if let Commands::Ring { action } = cli.command {
        return cli::ring_backup::run(action, &cfg);
    }

    if let Commands::Token { action } = cli.command {
        return parvault::gateway::execute_token_cli(action, &cfg.data_dir);
    }

    if let Commands::Council { action } = cli.command {
        return cli::council::run(action, &cfg, public_mode);
    }

    if let Commands::Gateway { opts, action } = cli.command {
        return parvault::gateway::execute_gateway_cli(opts, action, &cfg, cli.profile, &cli.peers)
            .await;
    }

    validate_early_command_flags(&cli.command)?;

    // v0.5.6 (B-146 item 8, A-146; track E): `up --init-if-absent` and `--join-token-file` run
    // before this command creates any file in the data dir.
    if let Commands::Up {
        init_if_absent,
        ref join_token_file,
        ..
    } = cli.command
    {
        cli::onboarding::up_setup_preflight(
            &cfg.data_dir,
            init_if_absent,
            join_token_file.as_deref(),
        )?;
    }

    let node_identity = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
    let explicit_peers = eff.explicit_peers.clone();
    let effective_seed = eff.seed_addr.clone();

    // Lab mode skips zero-config resolution: the resolved peers are the explicit ones.
    let resolved_peers = if !explicit_peers.is_empty() || deterministic {
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

    if public_mode {
        // F-53: finish a council re-pin a crash cut short, before the pins load into memory.
        parvault::storage::council::repair_council_pins(&cfg.data_dir)
            .map_err(|e| anyhow::anyhow!("council re-pin repair: {e}"))?;
    }
    let mesh_client = cli::mesh_client(&eff, node_identity.clone(), resolved_peers, effective_seed);

    if public_mode && command_needs_network_discovery(&cli.command) {
        for tracker in &public_trackers {
            let _ = mesh_client.announce_and_discover_public_tracker(tracker, None);
        }
        mesh_client.persist_tracker_admin_pins(&cfg)?;
    }

    let mut quota = QuotaManager::new(cfg.max_storage_bytes, cfg.bootstrap_grace_bytes);
    quota.set_min_free_disk_bytes(cfg.min_free_disk_bytes);
    quota.set_write_epoch_secs(cfg.quota_write_epoch_secs);
    // L-130 (track B1, glue G-15): the held-shard bound, from `max_held_shards` or memory,
    // logged (`info.held_shard_bound`) only by a command that starts the daemon: a CLI
    // command's logs share stdout with its output (`discover --json`).
    let starts_daemon = matches!(
        cli.command,
        Commands::Up { .. }
            | Commands::Daemon {
                action: DaemonAction::Start { .. }
            }
    );
    quota.set_held_shard_bound(if starts_daemon {
        parvault::storage::quota::held_shard_bound_at_startup(
            cfg.hardware_profile,
            cfg.max_held_shards,
        )
    } else {
        parvault::storage::quota::held_shard_bound_quiet(cfg.hardware_profile, cfg.max_held_shards)
    });
    let block_store = BlockStore::new(&cfg.data_dir, quota)?
        .with_stripe_size_bytes(cfg.stripe_size_bytes)
        .with_mesh_client(mesh_client.clone());

    let env = cli::CliEnv {
        eff: Arc::clone(&eff),
        config_digest,
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
        | Commands::Council { .. }
        | Commands::Gateway { .. }
        | Commands::Config { .. }
        | Commands::Net { .. }
        | Commands::Tls { .. }
        | Commands::Ring { .. } => {
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
        command @ Commands::Status { .. } => cli::identity::status(env, command).await?,
        command @ Commands::Identity { .. } => cli::identity::identity(env, command).await?,
        command @ Commands::IssueDeviceCert { .. } => {
            cli::identity::issue_device_cert(env, command).await?
        }
        command @ Commands::VerifyDeviceCert { .. } => {
            cli::identity::verify_device_cert(env, command).await?
        }
        command @ Commands::DiffFolder { .. } => cli::folder::diff_folder(env, command).await?,
        command @ Commands::WatchFolder { .. } => cli::folder::watch_folder(env, command).await?,
        command @ Commands::ListSnapshot { .. } => cli::folder::list_snapshot(env, command).await?,
        command @ Commands::FolderStatus { .. } => cli::folder::folder_status(env, command).await?,
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
        if let Ok(m) = FileManifest::decode_bytes(&raw) {
            return Ok(m);
        }
        if let Ok(m) = serde_json::from_slice::<FileManifest>(&raw) {
            return Ok(m);
        }
        if let Ok(snap) = FolderSnapshotManifest::decode_bytes(&raw) {
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
