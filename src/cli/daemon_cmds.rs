//! `parvault` commands: daemon cmds.

use super::CliEnv;
use crate::*;

pub(crate) async fn up(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        mut cfg,
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
    } = command
    else {
        unreachable!("up() is only dispatched for Commands::Up")
    };
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
    // F-43 (L-44): built-in WebDAV verifies every request against the root key, so one
    // must exist when it is on (created like `parvault token mint` does).
    let macaroon_root_key = if vfs_webdav_listen.is_some() {
        Some(parvault::gateway::load_or_create_macaroon_root_key(
            &cfg.data_dir,
            macaroon_root_key_hex.as_deref(),
        )?)
    } else {
        parvault::gateway::resolve_optional_macaroon_root_key(
            &cfg.data_dir,
            macaroon_root_key_hex.as_deref(),
        )?
    };
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
    Ok(())
}

pub(crate) async fn daemon(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        mut cfg,
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
            // F-43 (L-44): built-in WebDAV verifies every request against the root key, so one
            // must exist when it is on (created like `parvault token mint` does).
            let macaroon_root_key = if vfs_webdav_listen.is_some() {
                Some(parvault::gateway::load_or_create_macaroon_root_key(
                    &cfg.data_dir,
                    macaroon_root_key_hex.as_deref(),
                )?)
            } else {
                parvault::gateway::resolve_optional_macaroon_root_key(
                    &cfg.data_dir,
                    macaroon_root_key_hex.as_deref(),
                )?
            };
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
    }
    Ok(())
}
