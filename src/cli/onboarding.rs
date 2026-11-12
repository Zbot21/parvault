//! `parvault` commands: onboarding.

use super::CliEnv;
use crate::*;

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
                    if let Some(card) = cards.into_iter().find(|c| c.libp2p_peer_id != local_pid) {
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
                        matched = Some((card.libp2p_peer_id, card.node_label, card.role, pinned));
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
    Ok(())
}
