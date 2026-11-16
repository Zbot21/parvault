//! `parvault` commands: onboarding.

use super::CliEnv;
use crate::*;

/// The file in the data dir that records the SHA-256 of every join token this node consumed
/// (A-146-4: a token is consumed once).
pub(crate) const JOIN_TOKEN_USED_FILE: &str = "join_tokens.used";

/// Refusal: `PARVAULT_JOIN_TOKEN` is set; join tokens come from a file only (A-146-5).
pub(crate) const JOIN_TOKEN_ENV: &str = "reject.join_token_env";

/// `up` before it creates any file in the data dir (B-146 item 8, B-174, A-146-1 to A-146-5;
/// `v0.5.6` track E), run by `main`. It takes the data-dir lock for every `up` and parks it for
/// the daemon, which holds it until it exits (qa-t0, proposal g), so a second `up` on the same
/// volume is refused (`reject.datadir_locked`) before it writes anything. Under the lock it
/// sweeps the genesis staging files (arch056c 2.4) and, with `--init-if-absent` or
/// `--join-token-file`, applies [`parvault::datadir_lock::init_if_absent_decision`].
pub(crate) fn up_setup_preflight(
    data_dir: &Path,
    init_if_absent: bool,
    join_token_file: Option<&Path>,
) -> anyhow::Result<()> {
    use parvault::datadir_lock::{
        classify_volume, hold_for_process, init_if_absent_decision, DataDirLock, InitIfAbsent,
        LockPurpose,
    };
    if std::env::var_os("PARVAULT_JOIN_TOKEN").is_some() {
        tracing::warn!(code = JOIN_TOKEN_ENV, "refused: PARVAULT_JOIN_TOKEN is set");
        anyhow::bail!(
            "{JOIN_TOKEN_ENV}: PARVAULT_JOIN_TOKEN is not read (an env var shows in `docker \
             inspect`); put the token in a 0600 file and pass --join-token-file <FILE>"
        );
    }
    let lock = DataDirLock::acquire(data_dir, LockPurpose::Daemon)?;
    let swept = NodeIdentity::sweep_genesis_staging_files(data_dir)?;
    if swept > 0 {
        tracing::info!(swept, "removed genesis staging files left by a killed init");
    }
    if init_if_absent || join_token_file.is_some() {
        // The token file is ignored by name when it lives in the data dir (A-146-3).
        let ignored = join_token_file
            .filter(|f| f.parent().is_some_and(|p| same_dir(p, data_dir)))
            .and_then(|f| f.file_name());
        let state = classify_volume(data_dir, ignored)?;
        match init_if_absent_decision(state, join_token_file.is_some(), init_if_absent) {
            InitIfAbsent::Skip | InitIfAbsent::OwnRing => {}
            InitIfAbsent::Init => {
                let genesis = NodeIdentity::init_ring_genesis_in_dir(data_dir)?;
                tracing::info!(
                    ring = %hex::encode(genesis.public_key_bytes()),
                    "started a new ring (up --init-if-absent)"
                );
                println!(
                    "Started a new ring. Genesis public key: {}",
                    hex::encode(genesis.public_key_bytes())
                );
            }
            InitIfAbsent::ResumePin => {
                let pk = NodeIdentity::resume_ring_pin_from_seed_file(data_dir)?;
                tracing::info!(ring = %hex::encode(pk), "completed an interrupted ring init");
            }
            InitIfAbsent::Join => {
                let file = join_token_file.expect("Join only with a token file");
                join_from_token_file(data_dir, file)?;
            }
            InitIfAbsent::Refuse(code) => {
                tracing::warn!(code, ?state, "refused: up --init-if-absent");
                anyhow::bail!("{code}: {}", refusal_text(code, data_dir));
            }
        }
    }
    hold_for_process(lock);
    Ok(())
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn refusal_text(code: &str, data_dir: &Path) -> String {
    match code {
        c if c.ends_with("volume_not_empty") => format!(
            "{} is not empty and holds no ring; refusing to start a new ring over it (use an \
             empty volume, or restore it with `parvault ring restore`)",
            data_dir.display()
        ),
        _ => format!(
            "{} holds a partial or conflicting ring state (a pin without its seed or chain, or \
             a seed and pin for different keys); it is left as it is",
            data_dir.display()
        ),
    }
}

/// What `up --join-token-file` does with a token (claim `B146-JOIN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JoinStep {
    /// Install it (first use).
    Install,
    /// Used before and this node is in its ring: nothing to do (a restart).
    AlreadyMember,
}

/// The join-token decision (claim `B146-JOIN`, A-146-4, A-146-5): a token file that is not a
/// regular `0600` file of this user is refused (`reject.join_token_mode`); a token whose hash
/// is recorded is a no-op while this node is in its ring and is refused otherwise
/// (`reject.join_token_used`: a consumed token is never replayed).
pub(crate) fn join_token_decision(
    owner_only: bool,
    used_before: bool,
    member: bool,
) -> Result<JoinStep, &'static str> {
    if !owner_only {
        return Err("reject.join_token_mode");
    }
    match (used_before, member) {
        (false, _) => Ok(JoinStep::Install),
        (true, true) => Ok(JoinStep::AlreadyMember),
        (true, false) => Err("reject.join_token_used"),
    }
}

/// `up --join-token-file` (A-146-4, A-146-5): the token is read with the owner-only rule, then
/// joined once, as this node's own key (A-146-7). A failed join is an error, never an init.
fn join_from_token_file(data_dir: &Path, file: &Path) -> anyhow::Result<()> {
    use parvault::capabilities::{read_owner_only_file, OwnerFileRefusal};
    use sha2::{Digest, Sha256};
    let (raw, owner_only) = match read_owner_only_file(file) {
        Ok(raw) => (Some(raw), true),
        Err(OwnerFileRefusal::NotOwnerOnly { is_file, uid, mode }) => {
            tracing::warn!(is_file, uid, mode, "join token file is not owner-only");
            (None, false)
        }
        Err(e) => anyhow::bail!("cannot read the join token file {}: {e:?}", file.display()),
    };
    if let Err(code) = join_token_decision(owner_only, false, false) {
        tracing::warn!(code, "refused: join token file");
        anyhow::bail!(
            "{code}: {} must be a regular file owned by this user with mode 0600 (chmod 600)",
            file.display()
        );
    }
    let raw = raw.expect("read when owner-only");
    let text = std::str::from_utf8(&raw)
        .map_err(|_| anyhow::anyhow!("{} is not a token: it is not text", file.display()))?
        .trim()
        .to_string();
    let hash = hex::encode(Sha256::digest(text.as_bytes()));
    let used_path = data_dir.join(JOIN_TOKEN_USED_FILE);
    let used = std::fs::read_to_string(&used_path).unwrap_or_default();
    let used_before = used.lines().any(|l| l.trim() == hash);
    let invitation = super::wot::decode_invitation(&text)?;
    let member = used_before && super::wot::is_member_of(data_dir, &invitation);
    match join_token_decision(true, used_before, member) {
        Ok(JoinStep::AlreadyMember) => {
            tracing::info!("join token already used; this node is in its ring");
            return Ok(());
        }
        Ok(JoinStep::Install) => {}
        Err(code) => {
            tracing::warn!(code, "refused: join token reused");
            anyhow::bail!(
                "{code}: this join token was used before and this node is no longer in its \
                 ring; ask the ring holder for a new invite"
            );
        }
    }
    // The invite is bound to the invitee's key (A-146-7): a daemon joins only as itself.
    let node = NodeIdentity::load_or_generate_in_dir(data_dir)?;
    if invitation.chain.leaf_pubkey() != Some(node.public_key_bytes()) {
        anyhow::bail!(
            "this join token is for the key {}, not this node's key {}: ask the ring holder to \
             invite this node's key (`parvault identity`)",
            invitation
                .chain
                .leaf_pubkey()
                .map(hex::encode)
                .unwrap_or_default(),
            hex::encode(node.public_key_bytes())
        );
    }
    let msg = super::wot::install_invitation(data_dir, &invitation)?;
    let mut next = used;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    next.push_str(&hash);
    next.push('\n');
    parvault::storage::fsio::atomic_write_file(&used_path, next.as_bytes())?;
    tracing::info!("{msg}");
    println!("{msg}");
    Ok(())
}

pub(crate) async fn discover(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        cfg,
        lan_enabled,
        public_mode,
        public_trackers,
        wan_seeds,
        node_identity,
        mesh_client,
        cli,
        ..
    } = env;
    let Commands::Discover {
        timeout_ms,
        port,
        json,
        wan,
    } = command
    else {
        unreachable!("discover() is only dispatched for Commands::Discover")
    };
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

    // B-52: the cards to pin, written once at the end through `KnownPeersStore::update`.
    let mut wan_pins: Vec<(String, String, String, String)> = Vec::new();

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
            if let Ok(cards) = mesh_client.announce_and_discover_public_tracker(tracker, None) {
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
                        wan_pins.push((
                            card.libp2p_peer_id.clone(),
                            pinned.clone(),
                            card.node_label.clone(),
                            card.role.clone(),
                        ));
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
                // B-91: the lookup returns only cards that heal an already pinned peer
                // (`wan_ddns_card_decision`); a stranger's heartbeat is refused there.
                if let Ok(cards) = mesh_client.lookup_wan_ddns_cards(anchor, fp) {
                    for card in cards {
                        if card.libp2p_peer_id == local_pid
                            || entries.iter().any(|e| e.peer_id == card.libp2p_peer_id)
                        {
                            continue;
                        }
                        if let Some(pinned) = card.pinned_multiaddr() {
                            wan_pins.push((
                                card.libp2p_peer_id.clone(),
                                pinned.clone(),
                                card.node_label.clone(),
                                card.role.clone(),
                            ));
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

    // B-52: a damaged `known_peers.json` is refused with its `reject.known_peers_*` code and kept;
    // the command fails closed instead of reporting peers it could not pin.
    KnownPeersStore::update(&cfg.data_dir, |store| {
        store.upsert_discovered(&lan_found);
        for (pid, maddr, label, role) in &wan_pins {
            store.upsert_pinned_multiaddr(pid, maddr, Some(label.as_str()), Some(role.as_str()));
        }
    })
    .inspect_err(parvault::network::discovery::log_known_peers_write_refused)?;

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
    Ok(())
}

pub(crate) async fn pair(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        cfg,
        lan_enabled,
        wan_seeds,
        external_addrs,
        node_identity,
        mesh_client,
        block_store,
        cli,
        ..
    } = env;
    let Commands::Pair {
        port,
        duration_secs,
        once,
        wan,
        listen,
    } = command
    else {
        unreachable!("pair() is only dispatched for Commands::Pair")
    };
    let disc_port = port
        .or(cli.lan_discovery_port)
        .unwrap_or_else(|| cfg.effective_lan_discovery_port(None));
    let listen_str = listen.unwrap_or_else(|| cfg.listen_tcp.clone());
    let listen_maddr: Multiaddr = listen_str.parse()?;
    let (tcp_port, explicit_ip) = extract_listen_port_and_ip(&listen_maddr).unwrap_or((4001, None));
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
    Ok(())
}

pub(crate) async fn join(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        mut cfg,
        lan_enabled,
        wan_seeds,
        node_identity,
        mesh_client,
        cli,
        ..
    } = env;
    let Commands::Join {
        code,
        timeout_ms,
        port,
        wan,
    } = command
    else {
        unreachable!("join() is only dispatched for Commands::Join")
    };
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
                if let Ok((cards, _)) = mesh_client.lookup_wan_pairing_cards(anchor, candidate_code)
                {
                    for card in cards.into_iter().filter(|c| c.libp2p_peer_id != local_pid) {
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
                        // F-54 / B-45: the typed code must derive from the card's own identity.
                        if let Err(code) = wan_card_pairing_decision(
                            &card.libp2p_peer_id,
                            card.owner_pq_fingerprint.as_deref(),
                            &pinned,
                            candidate_code,
                        ) {
                            tracing::warn!(code, peer = %card.libp2p_peer_id, "refused a WAN pairing card");
                            continue;
                        }
                        matched = Some((card.libp2p_peer_id, card.node_label, card.role, pinned));
                        break;
                    }
                    if matched.is_some() {
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

    // B-52: a known_peers.json that exists but does not load is refused, never replaced.
    let mut store = KnownPeersStore::try_load(&cfg.data_dir)?;
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
    Ok(())
}
