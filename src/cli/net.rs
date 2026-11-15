//! `parvault net probe --force-direct` (`v0.5.4` NEW-4, `docs/LAB_MODE.md`): one dial, then one
//! ping and (unless `--no-rpc`) one `QueryNodeStatus`, with an ephemeral identity. Dispatched
//! before any identity, key or data-dir work: it creates and writes no file, and reads
//! `known_peers.json` only for a bare PeerId outside lab mode.

use crate::*;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::{multiaddr::Protocol, PeerId};
use parvault::network::behaviour::MeshNetworkBehaviourEvent;
use parvault::probe::{
    probe_exit_code, probe_target_decision, ProbeMode, ProbeResult, ProbeTargetFacts,
};
use parvault::traversal_metrics::TraversalReason;

/// The probe's target: one address (with its PeerId) or the refusal facts.
struct Target {
    addrs: Vec<Multiaddr>,
    bare_peer_id: bool,
    peer: Option<PeerId>,
}

fn resolve_target(raw: &str, data_dir: &Path, deterministic: bool) -> Result<Target, &'static str> {
    let raw = raw.trim();
    if raw.starts_with('/') {
        let maddr: Multiaddr = raw.parse().map_err(|_| "reject.probe_addr_invalid")?;
        let peer = parvault::network::client::extract_expected_peer_id(&maddr);
        return Ok(Target {
            addrs: vec![maddr],
            bare_peer_id: false,
            peer,
        });
    }
    let pid: PeerId = raw.parse().map_err(|_| "reject.probe_addr_invalid")?;
    if deterministic {
        // Lab mode reads no state file: the decision refuses a bare PeerId.
        return Ok(Target {
            addrs: Vec::new(),
            bare_peer_id: true,
            peer: Some(pid),
        });
    }
    let store = KnownPeersStore::try_load(data_dir).map_err(|_| "reject.probe_peer_unknown")?;
    let addrs = store
        .peers
        .values()
        .filter(|r| r.libp2p_peer_id == pid.to_string())
        .filter_map(|r| r.multiaddr.parse::<Multiaddr>().ok())
        .collect();
    Ok(Target {
        addrs,
        bare_peer_id: true,
        peer: Some(pid),
    })
}

fn facts(t: &Target, deterministic: bool, mode: ProbeMode) -> ProbeTargetFacts {
    let a = t.addrs.first();
    let has = |f: fn(&Protocol) -> bool| a.is_some_and(|m| m.iter().any(|p| f(&p)));
    ProbeTargetFacts {
        has_p2p: has(|p| matches!(p, Protocol::P2p(_))),
        has_circuit: has(|p| matches!(p, Protocol::P2pCircuit)),
        is_ip_literal: a.is_some_and(|m| {
            matches!(
                m.iter().next(),
                Some(Protocol::Ip4(_)) | Some(Protocol::Ip6(_))
            )
        }),
        bare_peer_id: t.bare_peer_id,
        deterministic,
        addr_count: u8::try_from(t.addrs.len()).unwrap_or(u8::MAX),
        mode,
    }
}

fn emit(r: &ProbeResult) -> i32 {
    println!(
        "{}",
        serde_json::to_string(r).unwrap_or_else(|_| "{}".to_string())
    );
    probe_exit_code(r)
}

/// Runs the probe and returns the exit code.
pub(crate) fn run_probe(
    eff: &parvault::config::EffectiveConfig,
    peer: &str,
    force_direct: bool,
    timeout_ms: u64,
    no_rpc: bool,
) -> i32 {
    let mut r = ProbeResult::new(now_unix_ms());
    let deterministic = eff.deterministic();
    let mode = if force_direct {
        ProbeMode::ForceDirect
    } else {
        ProbeMode::Unspecified
    };
    let target = match resolve_target(peer, &eff.cfg.data_dir, deterministic) {
        Ok(t) => t,
        Err(code) => {
            r.reason = code.to_string();
            eprintln!("{code}");
            return emit(&r);
        }
    };
    let f = facts(&target, deterministic, mode);
    // Lab mode names its address refusals the way startup does (`reject.lab_dns_addr` for a
    // name), before the probe's own rule.
    if deterministic && !target.bare_peer_id && !f.is_ip_literal {
        if let Err(code) = parvault::config::lab_addr_decision(peer) {
            r.reason = code.to_string();
            eprintln!("{code}");
            return emit(&r);
        }
    }
    if let Err(code) = probe_target_decision(&f) {
        r.reason = code.to_string();
        eprintln!("{code}");
        return emit(&r);
    }
    let addr = target.addrs[0].clone();
    let expected = target.peer.expect("decision requires /p2p/");
    let base = parvault::network::client::strip_p2p_protocol(&addr);
    let (path, transport) = parvault::network::traversal_classify::classify_addr(&addr);
    r.peer_id = Some(expected.to_string());
    r.addr = Some(addr.to_string());
    r.transport = Some(transport.label());
    let set = if deterministic {
        match parvault::network::traversal_gate::dial_entry_from_str(&addr.to_string()) {
            Some(e) => parvault::lab_dial::DialSet::Fixed(vec![e]),
            None => parvault::lab_dial::DialSet::Fixed(Vec::new()),
        }
    } else {
        parvault::lab_dial::DialSet::Open
    };
    let quic = transport == parvault::traversal_metrics::TransportKind::Quic;

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            r.reason = "reject.probe_runtime".into();
            return emit(&r);
        }
    };
    rt.block_on(async {
        // An ephemeral identity: nothing is pinned or written (D-44 Q7).
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let mut swarm = match parvault::network::build_mesh_client_swarm_gated(
            kp,
            quic,
            parvault::network::GateParams::for_set(Arc::new(set)),
        ) {
            Ok(s) => s,
            Err(_) => {
                r.reason = "reject.probe_swarm".into();
                return;
            }
        };
        let start = Instant::now();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        // Exactly one dial of one address: no retry, no other address.
        let opts = DialOpts::peer_id(expected)
            .addresses(vec![base])
            .condition(PeerCondition::Always)
            .build();
        if let Err(e) = swarm.dial(opts) {
            let (p, t, reason) = parvault::network::traversal_classify::classify_dial_error(&e)
                .unwrap_or((path, transport, TraversalReason::Other));
            r.result = "failed";
            r.path = Some(p.label());
            r.transport = Some(t.label());
            r.reason = reason.label().to_string();
            return;
        }
        r.path = Some(path.label());
        let mut rpc_sent = false;
        let mut pinged = false;
        loop {
            let ev = tokio::select! {
                ev = swarm.select_next_some() => ev,
                _ = tokio::time::sleep_until(deadline) => {
                    if r.result == "connected" {
                        if !no_rpc && r.timings_us.first_response.is_none() {
                            r.rpc_error = Some("timeout".into());
                        }
                    } else {
                        r.result = "failed";
                        r.reason = TraversalReason::Timeout.label().to_string();
                    }
                    return;
                }
            };
            match ev {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    established_in,
                    ..
                } if peer_id == expected => {
                    r.result = "connected";
                    r.reason = TraversalReason::Ok.label().to_string();
                    r.timings_us.established =
                        Some(u64::try_from(established_in.as_micros()).unwrap_or(u64::MAX));
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    let (p, t, reason) =
                        parvault::network::traversal_classify::classify_dial_error(&error)
                            .unwrap_or((path, transport, TraversalReason::Other));
                    r.result = "failed";
                    r.path = Some(p.label());
                    if t != parvault::traversal_metrics::TransportKind::None {
                        r.transport = Some(t.label());
                    }
                    r.reason = reason.label().to_string();
                    return;
                }
                SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Ping(libp2p::ping::Event {
                    peer,
                    result,
                    ..
                })) if peer == expected && !pinged => {
                    pinged = true;
                    if let Ok(rtt) = result {
                        r.timings_us.ping_rtt =
                            Some(u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX));
                    }
                    if no_rpc {
                        return;
                    }
                    rpc_sent = true;
                    swarm.behaviour_mut().req_resp.send_request(
                        &expected,
                        parvault::network::MeshWireRequest::QueryNodeStatus,
                    );
                }
                SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::ReqResp(
                    libp2p::request_response::Event::Message {
                        message: libp2p::request_response::Message::Response { .. },
                        ..
                    },
                )) if rpc_sent => {
                    r.timings_us.first_response =
                        Some(u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX));
                    return;
                }
                SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::ReqResp(
                    libp2p::request_response::Event::OutboundFailure { .. },
                )) if rpc_sent => {
                    r.rpc_error = Some("outbound_failure".into());
                    return;
                }
                SwarmEvent::ConnectionClosed { peer_id, .. }
                    if peer_id == expected && r.result == "connected" =>
                {
                    if !no_rpc && r.timings_us.first_response.is_none() {
                        r.rpc_error = Some("connection_closed".into());
                    }
                    return;
                }
                _ => {}
            }
        }
    });
    emit(&r)
}
