//! `parvault init`.

use crate::*;

pub(crate) fn init(
    mut cfg: NodeConfig,
    cli: Cli,
    external_addrs: Vec<String>,
) -> anyhow::Result<()> {
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
    unreachable!("init() is only dispatched for Commands::Init")
}
