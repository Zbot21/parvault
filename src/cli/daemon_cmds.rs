//! `parvault` commands: daemon cmds.

use super::CliEnv;
use crate::*;

pub(crate) async fn up(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        eff,
        config_digest,
        cfg,
        lan_port,
        lan_enabled,
        trust_mode,
        public_mode,
        public_trackers,
        wan_seeds,
        external_addrs,
        block_store,
        ..
    } = env;
    let Commands::Up {
        folder,
        interval_secs,
        status_http,
        pair,
        wan,
        listen: _,
        tier,
        ipc_socket,
        no_socket,
        no_audit,
        strict_plugins,
        allow_peer_uid,
        require_sealed_memfd,
        macaroon_root_key_hex,
        vfs_webdav_listen,
        vfs_fuse_fd,
        vfs_seed_dir,
        vfs_cache_mib,
        // Run by `main` before this (`onboarding::up_setup_preflight`, track E).
        init_if_absent: _,
        join_token_file: _,
        tls_san,
        insecure_plain_http,
        gateway_socket_group,
        no_gc,
        dump_config: _,
    } = command
    else {
        unreachable!("up() is only dispatched for Commands::Up")
    };
    // C37: the watch interval has a floor. `main::validate_early_command_flags` refuses first,
    // before any file exists (glue G-22); this check stays as defence in depth.
    let floor = parvault::sync::retention::MIN_WATCH_INTERVAL_SECS;
    if interval_secs < floor {
        anyhow::bail!("reject.interval_below_floor: --interval-secs must be at least {floor}");
    }
    // B-174 (track E): the daemon holds the data-dir lock for its lifetime: the one
    // `onboarding::up_setup_preflight` took before any file was created.
    let _datadir_lock = parvault::datadir_lock::daemon_lock(&cfg.data_dir)?;
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
    let macaroon_root_key = resolve_daemon_macaroon_root_key(
        &cfg,
        macaroon_root_key_hex.as_deref(),
        vfs_webdav_listen.is_some() || status_http.is_some(),
    )?;
    // The resolver applied --listen, --no-audit, --folder and --status-http to `cfg`.
    let _ = (folder, status_http, no_audit);
    let deterministic = eff.deterministic();
    let effective_folder = cfg.watched_folder.clone();
    let effective_status_http = cfg.status_http_bind.clone();
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
        sync_interval_secs: interval_secs, // C37: at least MIN_WATCH_INTERVAL_SECS
        sync_tier: effective_tier,
        wan_announce: !deterministic && (wan || !wan_seeds.is_empty()),
        wan_seeds,
        public_mode,
        public_trackers,
        external_addrs,
        trust_mode,
        edge_tls: parvault::edge_tls::EdgeTlsConfig {
            extra_sans: tls_san,
            insecure_plain_http,
        },
        gateway_socket_group,
        no_gc,
        eff,
        config_digest,
        #[cfg(feature = "lab-insecure-metrics")]
        lab_insecure_metrics: None,
    };
    run_daemon(cfg, block_store, opts).await?;
    Ok(())
}

pub(crate) async fn daemon(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        eff,
        config_digest,
        cfg,
        lan_port,
        lan_enabled,
        trust_mode,
        public_mode,
        public_trackers,
        wan_seeds,
        external_addrs,
        block_store,
        ..
    } = env;
    let Commands::Daemon { action } = command else {
        unreachable!("daemon() is only dispatched for Commands::Daemon")
    };
    match action {
        DaemonAction::Start {
            listen: _,
            enable_quic: _,
            status_http,
            ipc_socket,
            no_socket,
            no_audit,
            strict_plugins,
            allow_peer_uid,
            require_sealed_memfd,
            macaroon_root_key_hex,
            vfs_webdav_listen,
            vfs_fuse_fd,
            vfs_seed_dir,
            vfs_cache_mib,
            tls_san,
            insecure_plain_http,
            gateway_socket_group,
            dump_config: _,
            #[cfg(feature = "lab-insecure-metrics")]
            lab_insecure_metrics,
        } => {
            // B-174 (track E): the daemon holds the data-dir lock for its lifetime.
            let _datadir_lock = parvault::datadir_lock::daemon_lock(&cfg.data_dir)?;
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
            let macaroon_root_key = resolve_daemon_macaroon_root_key(
                &cfg,
                macaroon_root_key_hex.as_deref(),
                vfs_webdav_listen.is_some() || status_http.is_some(),
            )?;
            // The resolver applied --listen, --enable-quic, --no-audit and --status-http.
            let _ = no_audit;
            let deterministic = eff.deterministic();
            let opts = DaemonLaunchOptions {
                lan_discovery_enabled: lan_enabled,
                lan_discovery_port: lan_port,
                print_pairing_banner: false,
                status_http_bind: cfg.status_http_bind.clone(),
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
                wan_announce: !deterministic && !wan_seeds.is_empty(),
                wan_seeds,
                public_mode,
                public_trackers,
                external_addrs,
                trust_mode,
                edge_tls: parvault::edge_tls::EdgeTlsConfig {
                    extra_sans: tls_san,
                    insecure_plain_http,
                },
                gateway_socket_group,
                no_gc: false,
                eff,
                config_digest,
                #[cfg(feature = "lab-insecure-metrics")]
                lab_insecure_metrics,
            };
            run_daemon(cfg, block_store, opts).await?;
        }
    }
    Ok(())
}

/// The gateway macaroon root key for `up` and `daemon start` (#codehealth: one copy). Every
/// daemon gateway has one (B-16, L-86: no root key, no service), loaded or created like
/// `parvault token mint` does. `needs_verifier` is kept for the callers' documentation: built-in
/// WebDAV (F-43) and the status page (item 3) verify against the same key.
fn resolve_daemon_macaroon_root_key(
    cfg: &NodeConfig,
    hex: Option<&str>,
    needs_verifier: bool,
) -> anyhow::Result<Option<[u8; 32]>> {
    let _ = needs_verifier;
    Ok(Some(parvault::gateway::load_or_create_macaroon_root_key(
        &cfg.data_dir,
        hex,
    )?))
}
