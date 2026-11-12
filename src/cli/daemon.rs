//! `parvault up` / `parvault daemon start`: the long-running daemon.

use crate::*;

#[derive(Debug, Clone)]
pub(crate) struct DaemonLaunchOptions {
    pub(crate) lan_discovery_enabled: bool,
    pub(crate) lan_discovery_port: u16,
    pub(crate) print_pairing_banner: bool,
    pub(crate) status_http_bind: Option<String>,
    pub(crate) ipc_socket: Option<PathBuf>,
    pub(crate) strict_allowed_peer_uids: Option<Vec<u32>>,
    pub(crate) require_sealed_ingest_memfd: bool,
    pub(crate) macaroon_root_key: Option<[u8; 32]>,
    pub(crate) vfs_webdav_listen: Option<String>,
    pub(crate) vfs_fuse_fd: Option<i32>,
    pub(crate) vfs_seed_dir: Option<PathBuf>,
    pub(crate) vfs_cache_mib: u64,
    pub(crate) watch_folder: Option<PathBuf>,
    pub(crate) sync_interval_secs: u64,
    pub(crate) sync_tier: ErasureTier,
    pub(crate) wan_announce: bool,
    pub(crate) wan_seeds: Vec<String>,
    pub(crate) public_mode: bool,
    pub(crate) public_trackers: Vec<String>,
    pub(crate) external_addrs: Vec<String>,
    pub(crate) trust_mode: TrustPoolMode,
}

pub(crate) async fn run_daemon(
    cfg: NodeConfig,
    block_store: BlockStore,
    opts: DaemonLaunchOptions,
) -> anyhow::Result<()> {
    let start_instant = Instant::now();
    let node_identity = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
    let keypair = node_identity.to_libp2p_keypair()?;
    let local_peer_id = keypair.public().to_peer_id();
    let local_pid_str = local_peer_id.to_string();
    let genesis_pubkey = parvault::network::admission::server_ring_genesis(
        &cfg.data_dir,
        cfg.genesis_root_pubkey_hex.as_deref(),
        opts.trust_mode.allows_public_commons(),
    )?;

    let mut wot = WebOfTrustRegistry::with_persistence_dir(
        genesis_pubkey,
        DEFAULT_SUBTREE_SLASH_LIMIT,
        &cfg.data_dir,
    );
    wot.set_trust_pool_mode(opts.trust_mode, DEFAULT_PUBLIC_WOT_POW_BITS);
    wot.protect_key(node_identity.public_key_bytes());

    let mut por_verifier =
        PorVerifierEngine::with_persistence_dir(cfg.por_timeout_ms, &cfg.data_dir);
    let mut nullifier_ledger =
        VoucherNullifierLedger::with_persistence_dir(genesis_pubkey, &cfg.data_dir);
    let pq_kem = HybridKemKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
    let pq_signer = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
    let pq_fp = pq_signer.public_key().fingerprint_hex();
    let mut lite_seed_server = ZeroTrustSeedServer::new_homelab_vault(
        node_identity.device_peer_id(),
        block_store.clone(),
        pq_signer.public_key(),
        2,
    );
    let mut wan_registry =
        WanRendezvousRegistry::load_or_new(Some(&cfg.data_dir.join("wan_rendezvous.bin")));
    let mut eviction = PrivacyPreservingEvictionEngine::load_or_init(&cfg.data_dir)?;
    let mut takedown_queue = PublicTrackerTakedownQueue::load_or_init(&cfg.data_dir)?;
    let mut server_events = ServerSwarmEvents::new(true);

    let mut swarm = build_mesh_server_swarm(keypair, cfg.enable_quic, opts.lan_discovery_enabled)?;
    let tcp_addr: Multiaddr = cfg.listen_tcp.parse()?;
    swarm.listen_on(tcp_addr.clone())?;

    if cfg.enable_quic {
        let quic_addr: Multiaddr = cfg.listen_quic.parse()?;
        swarm.listen_on(quic_addr)?;
    }

    let node_label = cfg.effective_node_label(&local_pid_str);
    let beacon_role = cfg.hardware_profile.beacon_role();
    let sas = derive_4word_pairing_sas(&local_pid_str, Some(&pq_fp), DEFAULT_LAN_PAIRING_NONCE);

    if opts.print_pairing_banner {
        println!("[parvault] ========================================================");
        println!("[parvault] Home LAN Pairing Code: {}", sas.code);
        println!(
            "[parvault] Run on client: parvault join --code {}",
            sas.code
        );
        println!("[parvault] ========================================================");
    }
    if opts.public_mode {
        println!(
            "[parvault] Public Commons mode active: zero-knowledge AES-256-GCM encryption + 10-of-20 RS + PoW admission."
        );
    }

    let (mut bound_tcp_port, init_explicit_ip) =
        extract_listen_port_and_ip(&tcp_addr).unwrap_or((4001, None));

    let local = DaemonLocal {
        node_identity: &node_identity,
        node_label: &node_label,
        local_pid_str: &local_pid_str,
        pq_fp: &pq_fp,
        sas: &sas,
        beacon_role,
    };
    let beacon_handle = spawn_beacon(&opts, &block_store, local, bound_tcp_port, init_explicit_ip);

    let status_state_and_handle =
        spawn_status_server(&opts, &cfg, &block_store, local, start_instant).await?;

    #[cfg(unix)]
    let builtin_vfs_requested = opts.vfs_webdav_listen.is_some()
        || opts.vfs_fuse_fd.is_some()
        || opts.vfs_seed_dir.is_some();

    #[cfg(unix)]
    let shared_gateway_engine = if opts.ipc_socket.is_some() || builtin_vfs_requested {
        let mk = resolve_master_key(
            &cfg.data_dir,
            None,
            cfg.device_sealing_passphrase.as_deref(),
        )?;
        let eng = parvault::gateway::GatewayEngine::from_local_block_store(block_store.clone(), mk);
        eng.set_stripe_size_bytes(cfg.hardware_profile.stripe_size_bytes());
        eng.set_tier(opts.sync_tier);
        eng.set_macaroon_root_key(opts.macaroon_root_key);
        eng.set_strict_allowed_peer_uids(opts.strict_allowed_peer_uids.clone());
        eng.set_require_sealed_ingest_memfd(opts.require_sealed_ingest_memfd);
        Some(Arc::new(eng))
    } else {
        None
    };

    #[cfg(unix)]
    let mut ipc_gateway_handle = if let (Some(ref sock_path), Some(ref eng)) =
        (&opts.ipc_socket, &shared_gateway_engine)
    {
        let handle =
            parvault::gateway::ipc::GatewayIpcServer::bind(sock_path, Arc::clone(eng))?.spawn()?;
        println!(
            "[parvault] Zero-Copy IPC Gateway listening on unix://{} (strict_plugins={}, sealed_memfd={})",
            sock_path.display(),
            opts.strict_allowed_peer_uids.is_some(),
            opts.require_sealed_ingest_memfd,
        );
        info!(socket = %sock_path.display(), "GatewayIpcServer active");
        Some(handle)
    } else {
        None
    };

    #[cfg(all(unix, feature = "vfs"))]
    let mut builtin_vfs_webdav_handle = if builtin_vfs_requested {
        let eng = shared_gateway_engine
            .as_ref()
            .expect("shared_gateway_engine initialized when builtin_vfs_requested");
        let cache_bytes = opts.vfs_cache_mib.max(1).saturating_mul(1024 * 1024);
        let vfs = parvault::vfs::VirtualVaultFs::with_bus(
            parvault::gateway::ipc::GatewayBus::in_process(Arc::clone(eng)),
            cfg.data_dir.join("vfs_cache"),
            cache_bytes,
        )?;
        if let Some(ref seed_dir) = opts.vfs_seed_dir {
            let seeded = vfs.ingest_local_directory(seed_dir)?;
            info!(
                seed_dir = %seed_dir.display(),
                seeded,
                "Ingested built-in VFS seed directory"
            );
        }
        if let Some(fuse_fd) = opts.vfs_fuse_fd {
            let fuse_dev = parvault::os_sys::adopt_fuse_dev_fd(fuse_fd)?;
            let vfs_fuse = vfs.clone();
            std::thread::Builder::new()
                .name("parvault-builtin-fuse".into())
                .spawn(move || {
                    if let Err(e) = vfs_fuse.serve_fuse_fd_blocking(fuse_dev) {
                        warn!(error = %e, "Built-in FUSE protocol loop exited with error");
                    }
                })?;
            println!(
                "[parvault] Built-in VFS FUSE active on fd {} (in-process GatewayBus, socket={})",
                fuse_fd,
                opts.ipc_socket.is_some()
            );
        }
        if let Some(ref webdav_addr) = opts.vfs_webdav_listen {
            let handle = vfs.spawn_webdav_server(webdav_addr)?;
            println!(
                "[parvault] Built-in VFS WebDAV listening on http://{} (in-process GatewayBus, socket={})",
                handle.local_addr(),
                opts.ipc_socket.is_some()
            );
            info!(addr = %handle.local_addr(), "Built-in VFS WebDAV server active");
            Some(handle)
        } else {
            None
        }
    } else {
        None
    };

    #[cfg(all(unix, not(feature = "vfs")))]
    {
        let _ = (
            &opts.vfs_webdav_listen,
            opts.vfs_fuse_fd,
            &opts.vfs_seed_dir,
            opts.vfs_cache_mib,
        );
    }

    #[cfg(not(unix))]
    {
        let _ = (
            &opts.strict_allowed_peer_uids,
            opts.require_sealed_ingest_memfd,
            &opts.macaroon_root_key,
            &opts.vfs_webdav_listen,
            opts.vfs_fuse_fd,
            &opts.vfs_seed_dir,
            opts.vfs_cache_mib,
        );
        if opts.ipc_socket.is_some() {
            anyhow::bail!(
                "--ipc-socket Unix Domain Socket gateway is only supported on Unix targets"
            );
        }
    }

    spawn_folder_sync(&opts, &cfg, &block_store);

    // No gossip topic is subscribed: slashing evidence is not applied from gossip until it is
    // proof-carrying (item 2c). A single reporter's accusation must never quarantine a key (F-01).

    if let Some(client) = block_store.mesh_client() {
        for peer_str in client.all_network_endpoints() {
            if let Ok(addr) = parvault::network::parse_peer_multiaddr(&peer_str) {
                let _ = swarm.dial(addr);
            }
        }
    }

    let mut telemetry_interval = tokio::time::interval(Duration::from_secs(5));
    telemetry_interval.tick().await;
    let mut scrub_interval = tokio::time::interval(Duration::from_secs(30));
    scrub_interval.tick().await;
    let mut maint_epoch: u64 = 1;
    let mut announced_wan_once = false;

    info!(
        %local_peer_id,
        profile = %cfg.hardware_profile,
        stripe_size_bytes = cfg.stripe_size_bytes,
        listen_tcp = %cfg.listen_tcp,
        enable_quic = cfg.enable_quic,
        "parvault-daemon started (Noise XX + Yamux active)"
    );

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                let unhandled = server_events.handle(&mut swarm, event, |peer_str, remote_addr, request| {
                    handle_daemon_wire_request(
                        peer_str,
                        remote_addr,
                        request,
                            DaemonWireHandlerCtx {
                                cfg: &cfg,
                                node_identity: &node_identity,
                                genesis_pubkey,
                                public_mode: opts.public_mode,
                                block_store: &block_store,
                                wot: &mut wot,
                                por_verifier: &mut por_verifier,
                                nullifier_ledger: &mut nullifier_ledger,
                                pq_kem: &pq_kem,
                                lite_seed_server: &mut lite_seed_server,
                                wan_registry: &mut wan_registry,
                                eviction: &mut eviction,
                                takedown_queue: &mut takedown_queue,
                            },
                    )
                });
                let Some(event) = unhandled else { continue };
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    info!(%address, "Listening on mesh transport address");
                    if let Some((p, ip_opt)) = extract_listen_port_and_ip(&address) {
                        bound_tcp_port = p;
                        if let Some(ref beacon) = beacon_handle {
                            beacon.update_listen_endpoint(p, ip_opt);
                        }
                    }
                    if !announced_wan_once
                        && ((opts.public_mode && !opts.public_trackers.is_empty())
                            || (opts.wan_announce && !opts.wan_seeds.is_empty()))
                    {
                        announced_wan_once = true;
                        spawn_wan_and_tracker_announce(WanAnnounceTaskConfig {
                            mesh_client_opt: block_store.mesh_client().cloned(),
                            identity: node_identity.clone(),
                            label: node_label.clone(),
                            role: beacon_role.to_string(),
                            external_addrs: opts.external_addrs.clone(),
                            bound_tcp_port,
                            local_pid: local_pid_str.clone(),
                            pq_fp: pq_fp.clone(),
                            sas_code: sas.code.clone(),
                            publish_pair_code: opts.print_pairing_banner,
                            public_mode: opts.public_mode,
                            public_trackers: opts.public_trackers.clone(),
                            wan_announce: opts.wan_announce,
                            wan_seeds: opts.wan_seeds.clone(),
                        });
                    }
                }
            }
            _ = telemetry_interval.tick() => {
                let (used_b, max_b) = {
                    let q = block_store.quota();
                    let g = q.lock().expect("quota lock");
                    (g.used_storage_bytes(), g.max_storage_bytes())
                };
                if let Some(ref beacon) = beacon_handle {
                    beacon.update_available_bytes(max_b.saturating_sub(used_b));
                }
                if let Some((ref state, _)) = status_state_and_handle {
                    let known = KnownPeersStore::load(&cfg.data_dir);
                    let peers_vec: Vec<RouterNasPeerEntry> = known
                        .peers
                        .values()
                        .filter(|r| r.libp2p_peer_id != local_pid_str)
                        .map(|r| RouterNasPeerEntry {
                            peer_id: r.libp2p_peer_id.clone(),
                            label: r.node_label.clone(),
                            role: r.role.clone(),
                            multiaddr: r.multiaddr.clone(),
                            available_bytes: r.available_bytes,
                        })
                        .collect();
                    let mut guard = state.write().await;
                    guard.used_storage_bytes = used_b;
                    guard.max_storage_bytes = max_b;
                    if !peers_vec.is_empty() {
                        guard.lan_peers = peers_vec;
                    }
                    guard.update_telemetry(start_instant);
                }
            }
            _ = scrub_interval.tick() => {
                maint_epoch = maint_epoch.saturating_add(1);
                wan_registry.prune_expired(now_unix_ms());
                let _ = block_store.sweep_expired_blinded_shards(maint_epoch);
                let _ = block_store.scrub_all_shards();
                if (opts.public_mode && !opts.public_trackers.is_empty())
                    || (opts.wan_announce && !opts.wan_seeds.is_empty())
                {
                    spawn_wan_and_tracker_announce(WanAnnounceTaskConfig {
                        mesh_client_opt: block_store.mesh_client().cloned(),
                        identity: node_identity.clone(),
                        label: node_label.clone(),
                        role: beacon_role.to_string(),
                        external_addrs: opts.external_addrs.clone(),
                        bound_tcp_port,
                        local_pid: local_pid_str.clone(),
                        pq_fp: pq_fp.clone(),
                        sas_code: sas.code.clone(),
                        publish_pair_code: opts.print_pairing_banner,
                        public_mode: opts.public_mode,
                        public_trackers: opts.public_trackers.clone(),
                        wan_announce: opts.wan_announce,
                        wan_seeds: opts.wan_seeds.clone(),
                    });
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl-C, shutting down parvault-daemon cleanly.");
                break;
            }
        }
    }

    #[cfg(all(unix, feature = "vfs"))]
    if let Some(ref mut webdav_handle) = builtin_vfs_webdav_handle {
        webdav_handle.shutdown();
    }
    #[cfg(unix)]
    if let Some(ref mut ipc_handle) = ipc_gateway_handle {
        ipc_handle.shutdown();
    }
    if let Some((_, http_handle)) = status_state_and_handle {
        http_handle.shutdown();
    }
    if let Some(beacon) = beacon_handle {
        beacon.shutdown();
    }

    Ok(())
}

/// Identity values of the running daemon shared by its setup phases.
#[derive(Clone, Copy)]
struct DaemonLocal<'a> {
    node_identity: &'a NodeIdentity,
    node_label: &'a String,
    local_pid_str: &'a String,
    pq_fp: &'a String,
    sas: &'a parvault::network::LanPairingCode,
    beacon_role: &'static str,
}

/// Starts the LAN beacon responder when LAN discovery is enabled.
fn spawn_beacon(
    opts: &DaemonLaunchOptions,
    block_store: &BlockStore,
    local: DaemonLocal<'_>,
    bound_tcp_port: u16,
    init_explicit_ip: Option<String>,
) -> Option<parvault::network::LanBeaconHandle> {
    let DaemonLocal {
        node_identity,
        node_label,
        pq_fp,
        sas,
        beacon_role,
        ..
    } = local;
    if opts.lan_discovery_enabled {
        let (used, max_b) = {
            let q = block_store.quota();
            let g = q.lock().expect("quota lock");
            (g.used_storage_bytes(), g.max_storage_bytes())
        };
        let beacon_cfg = LanBeaconConfig::new(node_label.clone(), beacon_role, bound_tcp_port)
            .with_discovery_port(opts.lan_discovery_port)
            .with_explicit_listen_ip(init_explicit_ip)
            .with_available_bytes(max_b.saturating_sub(used))
            .with_owner_pq_fingerprint(Some(pq_fp.clone()))
            .with_pairing_sas_commitment(Some(sas.commitment));
        match LanBeaconResponder::spawn(node_identity.clone(), beacon_cfg) {
            Ok(h) => {
                info!(
                    port = opts.lan_discovery_port,
                    role = beacon_role,
                    "LAN Beacon Responder active on UDP"
                );
                Some(h)
            }
            Err(e) => {
                warn!(error = %e, "Failed to bind LAN Beacon Responder; continuing without LAN UDP beacon");
                None
            }
        }
    } else {
        None
    }
}

/// Starts the embedded router/NAS status HTTP server when `--status-http-bind` is set.
async fn spawn_status_server(
    opts: &DaemonLaunchOptions,
    cfg: &NodeConfig,
    block_store: &BlockStore,
    local: DaemonLocal<'_>,
    start_instant: Instant,
) -> anyhow::Result<
    Option<(
        Arc<RwLock<RouterNasLiveSnapshot>>,
        parvault::router_nas::RouterNasServerHandle,
    )>,
> {
    let DaemonLocal {
        node_identity,
        node_label,
        local_pid_str,
        pq_fp,
        sas,
        ..
    } = local;
    Ok(if let Some(ref bind_str) = opts.status_http_bind {
        let sock_addr: SocketAddr = bind_str.parse()?;
        let (used_b, max_b) = {
            let q = block_store.quota();
            let g = q.lock().expect("quota lock");
            (g.used_storage_bytes(), g.max_storage_bytes())
        };
        let known_peers = KnownPeersStore::load(&cfg.data_dir);
        let initial_lan_peers: Vec<RouterNasPeerEntry> = known_peers
            .peers
            .values()
            .map(|r| RouterNasPeerEntry {
                peer_id: r.libp2p_peer_id.clone(),
                label: r.node_label.clone(),
                role: r.role.clone(),
                multiaddr: r.multiaddr.clone(),
                available_bytes: r.available_bytes,
            })
            .collect();
        let mut snap = RouterNasLiveSnapshot {
            version: env!("CARGO_PKG_VERSION").to_string(),
            node_label: node_label.clone(),
            hardware_profile: cfg.hardware_profile.to_string(),
            device_peer_id: node_identity.device_peer_id(),
            libp2p_peer_id: local_pid_str.clone(),
            owner_pq_fingerprint: pq_fp.clone(),
            stripe_size_bytes: cfg.stripe_size_bytes,
            watched_folder: opts.watch_folder.as_ref().map(|p| p.display().to_string()),
            pairing_sas_code: Some(sas.code.clone()),
            sla_tier: format!("{:?}", opts.sync_tier),
            used_storage_bytes: used_b,
            max_storage_bytes: max_b,
            rss_kib: 0,
            hwm_kib: 0,
            uptime_secs: 0,
            lan_peers: initial_lan_peers,
        };
        snap.update_telemetry(start_instant);
        let shared = Arc::new(RwLock::new(snap));
        let (bound_http, handle) =
            RouterNasStatusServer::bind_and_spawn(sock_addr, shared.clone()).await?;
        println!(
            "[parvault] Embedded Status Server listening on http://{}",
            bound_http
        );
        info!(%bound_http, "RouterNasStatusServer active");
        Some((shared, handle))
    } else {
        None
    })
}

/// Starts the background continuous folder sync for `--watch-folder`.
fn spawn_folder_sync(opts: &DaemonLaunchOptions, cfg: &NodeConfig, block_store: &BlockStore) {
    if let Some(ref folder_path) = opts.watch_folder {
        let _ = std::fs::create_dir_all(folder_path);
        let sync_folder = folder_path.clone();
        let sync_data_dir = cfg.data_dir.clone();
        let sync_passphrase = cfg.device_sealing_passphrase.clone();
        let sync_store = block_store.clone();
        let sync_tier = opts.sync_tier;
        let sync_interval = opts.sync_interval_secs.max(1);
        info!(folder = %sync_folder.display(), interval_secs = sync_interval, "Starting background continuous folder sync");
        tokio::spawn(async move {
            let snap_path = sync_data_dir.join("appliance_folder_snapshot.manifest.bin");
            loop {
                let folder_cl = sync_folder.clone();
                let data_dir_cl = sync_data_dir.clone();
                let pass_cl = sync_passphrase.clone();
                let store_cl = sync_store.clone();
                let snap_cl = snap_path.clone();
                let _ = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                    let mk = resolve_master_key(&data_dir_cl, None, pass_cl.as_deref())?;
                    let owner_id = NodeIdentity::from_master_key(&mk);
                    let store_owner = if let Some(mc) = store_cl.mesh_client().cloned() {
                        store_cl.with_mesh_client(mc.with_identity(owner_id.clone()))
                    } else {
                        store_cl
                    };
                    let mut engine = FolderSyncEngine::new(store_owner, mk, owner_id, sync_tier);
                    if snap_cl.exists() {
                        if let Ok(raw) = std::fs::read(&snap_cl) {
                            if let Ok(prev) = bincode::deserialize::<FolderSnapshotManifest>(&raw) {
                                engine.load_previous_snapshot(&prev);
                            }
                        }
                    }
                    let updated = engine.sync_folder_once(&folder_cl)?;
                    if let Ok(bytes) = bincode::serialize(&updated) {
                        let _ = BlockStore::atomic_write_file(&snap_cl, &bytes);
                    }
                    Ok(())
                })
                .await;
                tokio::time::sleep(Duration::from_secs(sync_interval)).await;
            }
        });
    }
}

pub(crate) struct WanAnnounceTaskConfig {
    pub(crate) mesh_client_opt: Option<MeshClient>,
    pub(crate) identity: NodeIdentity,
    pub(crate) label: String,
    pub(crate) role: String,
    pub(crate) external_addrs: Vec<String>,
    pub(crate) bound_tcp_port: u16,
    pub(crate) local_pid: String,
    pub(crate) pq_fp: String,
    pub(crate) sas_code: String,
    pub(crate) publish_pair_code: bool,
    pub(crate) public_mode: bool,
    pub(crate) public_trackers: Vec<String>,
    pub(crate) wan_announce: bool,
    pub(crate) wan_seeds: Vec<String>,
}

pub(crate) fn spawn_wan_and_tracker_announce(task_cfg: WanAnnounceTaskConfig) {
    let WanAnnounceTaskConfig {
        mesh_client_opt,
        identity,
        label,
        role,
        external_addrs,
        bound_tcp_port,
        local_pid,
        pq_fp,
        sas_code,
        publish_pair_code,
        public_mode,
        public_trackers,
        wan_announce,
        wan_seeds,
    } = task_cfg;
    let Some(mc) = mesh_client_opt else {
        return;
    };
    tokio::task::spawn_blocking(move || {
        if public_mode {
            for tracker in &public_trackers {
                if let Ok(card) = build_wan_card_with_stun_port(StunWanCardParams {
                    mesh_client: &mc,
                    anchor_addr: tracker,
                    probe_slot: PUBLIC_COMMONS_SWARM_SLOT,
                    identity: &identity,
                    label: &label,
                    role: &role,
                    explicit_external_addrs: &external_addrs,
                    local_tcp_port: bound_tcp_port,
                    local_peer_id: &local_pid,
                    pq_fp: Some(pq_fp.clone()),
                }) {
                    let _ = mc.announce_and_discover_public_tracker(tracker, Some(&card));
                }
            }
        }
        if wan_announce {
            let slot_probe = derive_slot_key_from_code(&sas_code);
            for anchor in &wan_seeds {
                if let Ok(card) = build_wan_card_with_stun_port(StunWanCardParams {
                    mesh_client: &mc,
                    anchor_addr: anchor,
                    probe_slot: slot_probe,
                    identity: &identity,
                    label: &label,
                    role: &role,
                    explicit_external_addrs: &external_addrs,
                    local_tcp_port: bound_tcp_port,
                    local_peer_id: &local_pid,
                    pq_fp: Some(pq_fp.clone()),
                }) {
                    let _ = mc.publish_wan_ddns_heartbeat(anchor, &pq_fp, &card);
                    if publish_pair_code {
                        let _ = mc.publish_wan_pairing_card(anchor, &sas_code, &card);
                    }
                }
            }
        }
    });
}
