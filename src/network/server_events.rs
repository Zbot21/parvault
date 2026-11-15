//! Swarm event handling shared by the `parvault` daemon and `parvault-seed` server loops.
//!
//! Handles the arms both loops implemented identically (connection-address bookkeeping, mDNS
//! discovery into Kademlia, inbound request -> handler -> response) and returns every other
//! event, so each binary keeps its own `select!`, timers and role-specific arms.

use crate::network::behaviour::{
    DhtEnvelopeKind, DhtWireEnvelope, MeshNetworkBehaviour, MeshNetworkBehaviourEvent,
    MeshWireRequest, MeshWireResponse,
};
use crate::network::client::MeshClient;
use crate::network::wire_handler::WireReply;
use libp2p::futures::future::BoxFuture;
use libp2p::futures::stream::FuturesUnordered;
use libp2p::kad::{self, store::RecordStore};
use libp2p::request_response::ResponseChannel;
use libp2p::request_response::{self, Message};
use libp2p::swarm::SwarmEvent;
use libp2p::{mdns, Multiaddr, Swarm};
use std::collections::HashMap;
use tracing::{info, warn};

/// Onion relay forwards in flight on this node, across all peers (F-18, F-33). The default; see
/// [`max_inflight_relays`] for the per-profile cap.
pub const MAX_INFLIGHT_RELAYS: usize = 64;
/// The total relay cap on `router-soc`. Each forward holds a blocking-pool thread for its dial
/// and RPC, so the cap plus [`MAX_SYNDICATIONS_IN_FLIGHT`] stays below that profile's blocking
/// pool and leaves threads for the owner's gateway, admin RPC, status and sync work (B-53).
pub const ROUTER_SOC_MAX_INFLIGHT_RELAYS: usize = 4;

/// The total relay cap for `profile`: [`ROUTER_SOC_MAX_INFLIGHT_RELAYS`] on `router-soc`, else
/// [`MAX_INFLIGHT_RELAYS`].
pub const fn max_inflight_relays(profile: crate::config::HardwareProfile) -> usize {
    match profile {
        crate::config::HardwareProfile::RouterSoc => ROUTER_SOC_MAX_INFLIGHT_RELAYS,
        crate::config::HardwareProfile::Desktop | crate::config::HardwareProfile::HomelabNas => {
            MAX_INFLIGHT_RELAYS
        }
    }
}
/// Onion relay forwards in flight for one sending peer (F-33).
pub const MAX_INFLIGHT_RELAYS_PER_PEER: usize = 4;

/// Admits one more deferred onion forward only under both in-flight caps (`total_cap` from
/// [`max_inflight_relays`]). Removing the blocking forward removed the only back-pressure on
/// relaying; these caps replace it (F-33).
pub fn relay_forward_decision(
    in_flight_total: usize,
    in_flight_peer: usize,
    total_cap: usize,
) -> Result<(), &'static str> {
    if in_flight_total >= total_cap || in_flight_peer >= MAX_INFLIGHT_RELAYS_PER_PEER {
        Err("reject.relay_budget")
    } else {
        Ok(())
    }
}

/// Refusal text for a forward over the relay budget.
pub const RELAY_BUSY_TEXT: &str = "relay busy; retry later";

/// B-SEED-SYND (L-46): lite syndication fan-outs in flight on this node, across all senders.
pub const MAX_SYNDICATIONS_IN_FLIGHT: usize = 2;
/// B-SEED-SYND: lite syndication fan-outs in flight for one sender.
pub const MAX_SYNDICATIONS_PER_SENDER: usize = 1;

/// B-SEED-SYND: admits one more lite syndication only under both in-flight caps. Checked by the
/// handler before the local ingest (so a refusal costs no encode and no write) and again,
/// authoritatively, when the fan-out job is queued. Its own counter, separate from relays.
pub fn syndication_fanout_decision(
    in_flight_total: usize,
    in_flight_sender: usize,
) -> Result<(), &'static str> {
    if in_flight_total >= MAX_SYNDICATIONS_IN_FLIGHT
        || in_flight_sender >= MAX_SYNDICATIONS_PER_SENDER
    {
        Err("reject.syndication_busy")
    } else {
        Ok(())
    }
}

/// Refusal text for a syndication over the fan-out budget; clients back off and retry on it.
pub const SYNDICATION_BUSY_TEXT: &str = "seed syndication busy; retry later";

/// Lite syndication load seen by one request: fan-outs in flight in total and for its sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyndicationLoad {
    pub in_flight_total: usize,
    pub in_flight_sender: usize,
    /// Chunk-audit proofs in flight on this node (B-59, verdict change 5).
    pub chunk_proves_in_flight: usize,
    /// The node's cap on them: [`MAX_CHUNK_PROVES_IN_FLIGHT`] by default, 1 on `router-soc`.
    pub chunk_prove_cap: usize,
}

impl Default for SyndicationLoad {
    fn default() -> Self {
        Self {
            in_flight_total: 0,
            in_flight_sender: 0,
            chunk_proves_in_flight: 0,
            chunk_prove_cap: MAX_CHUNK_PROVES_IN_FLIGHT,
        }
    }
}

/// Chunk-audit proofs in flight on a desktop or NAS host (one shard read and hash each).
pub const MAX_CHUNK_PROVES_IN_FLIGHT: usize = 2;
/// The same on `router-soc` (verdict change 5).
pub const MAX_CHUNK_PROVES_IN_FLIGHT_ROUTER: usize = 1;

/// B-59 (verdict change 5): admits one more chunk-audit proof only under the prover's in-flight
/// cap. Checked by the handler before admission (so a busy host spends no nonce and none of the
/// owner's budget) and again, authoritatively, when the job is queued.
pub fn chunk_prove_slot_decision(in_flight: usize, cap: usize) -> Result<(), &'static str> {
    if in_flight >= cap {
        Err("reject.por_prover_busy")
    } else {
        Ok(())
    }
}

/// Which budget a deferred job holds a slot in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredKind {
    Relay,
    Syndication,
    ChunkProve,
}

pub type DeferredResponse = (
    ResponseChannel<MeshWireResponse>,
    String,
    MeshWireResponse,
    DeferredKind,
);

/// The routing-table rule (F-11): mDNS never feeds Kademlia; admission does. A peer enters the
/// table only when its handshake or public-commons ticket was accepted.
pub fn kad_routing_decision(admitted: bool) -> Result<(), &'static str> {
    if admitted {
        Ok(())
    } else {
        Err("reject.kad_peer_not_admitted")
    }
}

/// Whether `response` admitted its sender.
fn admits_sender(response: &MeshWireResponse) -> bool {
    matches!(
        response,
        MeshWireResponse::HandshakeAck { accepted: true, .. }
            | MeshWireResponse::AdmitPublicTicketAck { admitted: true, .. }
    )
}

/// (owner identity bytes, monotonic version) of a valid DHT envelope record.
type RecordIdentity = (Vec<u8>, u64);

/// What the Kademlia record decision needs to know (F-10b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadRecordFacts {
    /// The record's source was admitted on this node (handshake or ticket accepted, F-31).
    pub source_admitted: bool,
    /// The inbound record, if it is a self-consistent signed DHT envelope for its key.
    pub candidate: Option<RecordIdentity>,
    /// The record already stored under that key, if any.
    pub existing: Option<RecordIdentity>,
}

/// Stores an inbound Kademlia record only if it is a valid DHT envelope for its key, does not
/// replace another owner's record, and does not roll back its version (the same rules as the
/// `ZeroTrustDhtStore` behind `PutDhtEnvelope`).
pub fn kad_record_decision(facts: &KadRecordFacts) -> Result<(), &'static str> {
    if !facts.source_admitted {
        return Err("reject.dht_record_source_not_admitted");
    }
    let Some((owner, version)) = &facts.candidate else {
        return Err("reject.dht_record_invalid");
    };
    if let Some((existing_owner, existing_version)) = &facts.existing {
        if existing_owner != owner {
            return Err("reject.dht_record_owner_conflict");
        }
        if version < existing_version {
            return Err("reject.dht_record_rollback");
        }
    }
    Ok(())
}

/// The owner and version of `record` if it is a valid DHT envelope for its key.
fn record_identity(record: &kad::Record) -> Option<RecordIdentity> {
    let dht_key: [u8; 32] = record.key.as_ref().try_into().ok()?;
    let env: DhtWireEnvelope = bincode::deserialize(&record.value).ok()?;
    let (kind, owner) = match &env {
        DhtWireEnvelope::ClassicalManifest(m) => {
            (DhtEnvelopeKind::ClassicalManifest, m.owner_pubkey.to_vec())
        }
        DhtWireEnvelope::PostQuantumManifest(m) => (
            DhtEnvelopeKind::PostQuantumManifest,
            bincode::serialize(&m.owner_pq_pubkey).ok()?,
        ),
        DhtWireEnvelope::VaultCatalog(m) => {
            (DhtEnvelopeKind::VaultCatalog, m.owner_pubkey.to_vec())
        }
    };
    let version = MeshClient::self_consistent_version(&dht_key, kind, &env)?;
    Some((owner, version))
}

/// Event type of the mesh swarm used by the server loops.
pub type MeshSwarmEvent = SwarmEvent<MeshNetworkBehaviourEvent>;

/// Per-loop state for the common server swarm arms.
pub struct ServerSwarmEvents {
    peer_remote_addrs: HashMap<String, Multiaddr>,
    log_mdns_discoveries: bool,
    /// Peers whose handshake or ticket this node accepted since start (F-11 routing, F-31
    /// Kademlia records). In memory: a peer handshakes again after a restart.
    admitted_peers: std::collections::HashSet<libp2p::PeerId>,
    /// Deferred onion forwards; their responses go out from [`Self::next_deferred`].
    deferred: FuturesUnordered<BoxFuture<'static, DeferredResponse>>,
    relays_per_peer: HashMap<String, usize>,
    /// Total relay cap ([`max_inflight_relays`]).
    relay_cap: usize,
    /// B-SEED-SYND: lite syndication fan-outs in flight (total and per sender).
    syndications_total: usize,
    syndications_per_peer: HashMap<String, usize>,
    /// Chunk-audit proofs in flight (B-59) and their cap.
    chunk_proves: usize,
    chunk_prove_cap: usize,
    /// The lab dial gate (`docs/LAB_MODE.md`): an admitted peer's address enters Kademlia only
    /// if the gate allows dialling it.
    dial_set: std::sync::Arc<crate::lab_dial::DialSet>,
}

impl ServerSwarmEvents {
    /// `log_mdns_discoveries` keeps the daemon's per-peer mDNS log line (the seed has none).
    /// `relay_cap` is the total relay cap, from [`max_inflight_relays`].
    pub fn new(log_mdns_discoveries: bool, relay_cap: usize) -> Self {
        Self {
            peer_remote_addrs: HashMap::new(),
            log_mdns_discoveries,
            admitted_peers: std::collections::HashSet::new(),
            deferred: FuturesUnordered::new(),
            relays_per_peer: HashMap::new(),
            relay_cap,
            syndications_total: 0,
            syndications_per_peer: HashMap::new(),
            chunk_proves: 0,
            chunk_prove_cap: MAX_CHUNK_PROVES_IN_FLIGHT,
            dial_set: std::sync::Arc::new(crate::lab_dial::DialSet::Open),
        }
    }

    /// Sets the lab dial set (`Open` by default).
    pub fn set_dial_set(&mut self, set: std::sync::Arc<crate::lab_dial::DialSet>) {
        self.dial_set = set;
    }

    /// Sets the chunk-audit prover's in-flight cap (`router-soc`:
    /// [`MAX_CHUNK_PROVES_IN_FLIGHT_ROUTER`]).
    pub fn set_chunk_prove_cap(&mut self, cap: usize) {
        self.chunk_prove_cap = cap;
    }

    /// True while deferred forwards are pending; guard the `select!` arm on it.
    pub fn has_deferred(&self) -> bool {
        !self.deferred.is_empty()
    }

    /// Waits for the next deferred forward to finish. Call only when [`Self::has_deferred`].
    pub async fn next_deferred(&mut self) -> Option<DeferredResponse> {
        libp2p::futures::StreamExt::next(&mut self.deferred).await
    }

    /// Sends a finished deferred response and releases its slot in the relay budget.
    pub fn send_deferred(
        &mut self,
        swarm: &mut Swarm<MeshNetworkBehaviour>,
        done: DeferredResponse,
    ) {
        let (channel, peer, response, kind) = done;
        let per_peer = match kind {
            DeferredKind::ChunkProve => {
                self.chunk_proves = self.chunk_proves.saturating_sub(1);
                let _ = swarm
                    .behaviour_mut()
                    .req_resp
                    .send_response(channel, response);
                return;
            }
            DeferredKind::Relay => &mut self.relays_per_peer,
            DeferredKind::Syndication => {
                self.syndications_total = self.syndications_total.saturating_sub(1);
                &mut self.syndications_per_peer
            }
        };
        if let Some(n) = per_peer.get_mut(&peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per_peer.remove(&peer);
            }
        }
        let _ = swarm
            .behaviour_mut()
            .req_resp
            .send_response(channel, response);
    }

    /// Handles `event` if it is one of the common arms and returns `None`; otherwise returns the
    /// event unchanged for the caller. For an inbound request, `on_request` receives the remote
    /// peer id, its last connection address and the request, and its response is sent back.
    pub fn handle<F>(
        &mut self,
        swarm: &mut Swarm<MeshNetworkBehaviour>,
        event: MeshSwarmEvent,
        on_request: F,
    ) -> Option<MeshSwarmEvent>
    where
        F: FnOnce(&str, Option<&Multiaddr>, MeshWireRequest, SyndicationLoad) -> WireReply,
    {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                self.peer_remote_addrs
                    .insert(peer_id.to_string(), endpoint.get_remote_address().clone());
                None
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                if num_established == 0 {
                    self.peer_remote_addrs.remove(&peer_id.to_string());
                }
                None
            }
            SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Mdns(mdns::Event::Discovered(
                list,
            ))) => {
                // Logged only: mDNS never feeds the Kademlia routing table (F-11).
                for (peer_id, multiaddr) in list {
                    if self.log_mdns_discoveries {
                        info!(%peer_id, %multiaddr, "Discovered LAN peer via mDNS");
                    }
                }
                None
            }
            SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Kademlia(
                kad::Event::RoutingUpdated { peer, .. },
            )) => {
                info!(%peer, "Kademlia routing table updated");
                None
            }
            SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Kademlia(
                kad::Event::RoutablePeer { peer, .. }
                | kad::Event::PendingRoutablePeer { peer, .. }
                | kad::Event::UnroutablePeer { peer },
            )) => {
                if let Err(code) = kad_routing_decision(false) {
                    info!(code, %peer, "peer not added to the Kademlia routing table");
                }
                None
            }
            SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Kademlia(
                kad::Event::InboundRequest { request },
            )) => {
                match request {
                    kad::InboundRequest::PutRecord {
                        source,
                        record: Some(record),
                        ..
                    } => {
                        let store = swarm.behaviour_mut().kademlia.store_mut();
                        let existing = store.get(&record.key).and_then(|r| record_identity(&r));
                        let facts = KadRecordFacts {
                            source_admitted: self.admitted_peers.contains(&source),
                            candidate: record_identity(&record),
                            existing,
                        };
                        match kad_record_decision(&facts) {
                            Ok(()) => {
                                let _ = store.put(record);
                            }
                            Err(code) => warn!(code, %source, "refused an inbound Kademlia record"),
                        }
                    }
                    kad::InboundRequest::AddProvider {
                        record: Some(provider),
                    } => {
                        // No feature uses provider records; they are never stored.
                        info!(provider = %provider.provider, "ignored an inbound provider record");
                    }
                    _ => {}
                }
                None
            }
            SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::ReqResp(
                request_response::Event::Message {
                    peer,
                    message:
                        Message::Request {
                            request, channel, ..
                        },
                },
            )) => {
                let peer_str = peer.to_string();
                let remote_addr = self.peer_remote_addrs.get(&peer_str).cloned();
                let load = SyndicationLoad {
                    in_flight_total: self.syndications_total,
                    in_flight_sender: self
                        .syndications_per_peer
                        .get(&peer_str)
                        .copied()
                        .unwrap_or(0),
                    chunk_proves_in_flight: self.chunk_proves,
                    chunk_prove_cap: self.chunk_prove_cap,
                };
                let response = match on_request(&peer_str, remote_addr.as_ref(), request, load) {
                    WireReply::Ready(response) => *response,
                    WireReply::Deferred(job) if job.is_chunk_prove() => {
                        // Authoritative cap check (the handler checked before admitting too).
                        match chunk_prove_slot_decision(self.chunk_proves, self.chunk_prove_cap) {
                            Ok(()) => {
                                self.chunk_proves += 1;
                                self.deferred.push(Box::pin(async move {
                                    (channel, peer_str, job.run().await, DeferredKind::ChunkProve)
                                }));
                                return None;
                            }
                            Err(code) => {
                                warn!(code, peer = %peer_str, "refused a chunk audit");
                                MeshWireResponse::ChunkAuditResult(None)
                            }
                        }
                    }
                    WireReply::Deferred(job) if job.is_syndication() => {
                        // Authoritative enqueue check (the handler checked before ingest too).
                        match syndication_fanout_decision(
                            load.in_flight_total,
                            load.in_flight_sender,
                        ) {
                            Ok(()) => {
                                self.syndications_total += 1;
                                *self
                                    .syndications_per_peer
                                    .entry(peer_str.clone())
                                    .or_insert(0) += 1;
                                self.deferred.push(Box::pin(async move {
                                    (
                                        channel,
                                        peer_str,
                                        job.run().await,
                                        DeferredKind::Syndication,
                                    )
                                }));
                                return None;
                            }
                            Err(code) => {
                                warn!(code, peer = %peer_str, "refused a syndication fan-out");
                                MeshWireResponse::SyndicateLiteStripeAck {
                                    receipt: None,
                                    syndicated_peers: Vec::new(),
                                    error: Some(SYNDICATION_BUSY_TEXT.to_string()),
                                }
                            }
                        }
                    }
                    WireReply::Deferred(job) => {
                        let in_flight_peer =
                            self.relays_per_peer.get(&peer_str).copied().unwrap_or(0);
                        let relays_total: usize = self.relays_per_peer.values().sum();
                        match relay_forward_decision(relays_total, in_flight_peer, self.relay_cap) {
                            Ok(()) => {
                                *self.relays_per_peer.entry(peer_str.clone()).or_insert(0) += 1;
                                self.deferred.push(Box::pin(async move {
                                    (channel, peer_str, job.run().await, DeferredKind::Relay)
                                }));
                                return None;
                            }
                            Err(code) => {
                                warn!(code, peer = %peer_str, "refused an onion relay forward");
                                MeshWireResponse::RelayPqOnionAck {
                                    delivered: false,
                                    error: Some(RELAY_BUSY_TEXT.to_string()),
                                }
                            }
                        }
                    }
                };
                if kad_routing_decision(admits_sender(&response)).is_ok() {
                    self.admitted_peers.insert(peer);
                    if let Some(addr) = remote_addr {
                        if crate::network::traversal_gate::gate_addr_decision(
                            &addr,
                            Some(&peer),
                            &self.dial_set,
                        )
                        .is_ok()
                        {
                            swarm.behaviour_mut().kademlia.add_address(&peer, addr);
                        }
                    }
                }
                let _ = swarm
                    .behaviour_mut()
                    .req_resp
                    .send_response(channel, response);
                None
            }
            other => Some(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_budget_caps_total_and_per_peer() {
        let cap = MAX_INFLIGHT_RELAYS;
        assert_eq!(relay_forward_decision(0, 0, cap), Ok(()));
        assert_eq!(
            relay_forward_decision(cap - 1, MAX_INFLIGHT_RELAYS_PER_PEER - 1, cap),
            Ok(())
        );
        assert_eq!(
            relay_forward_decision(cap, 0, cap),
            Err("reject.relay_budget")
        );
        assert_eq!(
            relay_forward_decision(0, MAX_INFLIGHT_RELAYS_PER_PEER, cap),
            Err("reject.relay_budget")
        );
    }

    /// B-53: on `router-soc` the relay cap plus the syndication cap stays below the blocking
    /// pool, so relays cannot hold every blocking thread; the other profiles keep the default.
    #[test]
    fn router_relay_cap_leaves_blocking_threads_for_owner_work() {
        use crate::config::HardwareProfile;
        let router = HardwareProfile::RouterSoc;
        let pool = router
            .runtime_max_blocking_threads()
            .expect("router pool bound");
        assert_eq!(max_inflight_relays(router), ROUTER_SOC_MAX_INFLIGHT_RELAYS);
        assert!(max_inflight_relays(router) + MAX_SYNDICATIONS_IN_FLIGHT < pool);
        assert_eq!(
            relay_forward_decision(
                ROUTER_SOC_MAX_INFLIGHT_RELAYS,
                0,
                max_inflight_relays(router)
            ),
            Err("reject.relay_budget")
        );
        for p in [HardwareProfile::Desktop, HardwareProfile::HomelabNas] {
            assert_eq!(max_inflight_relays(p), MAX_INFLIGHT_RELAYS);
        }
    }

    #[test]
    fn kad_routing_requires_admission() {
        assert_eq!(kad_routing_decision(true), Ok(()));
        assert_eq!(
            kad_routing_decision(false),
            Err("reject.kad_peer_not_admitted")
        );
    }

    #[test]
    fn kad_record_decision_rules() {
        let facts =
            |candidate: Option<RecordIdentity>, existing: Option<RecordIdentity>| KadRecordFacts {
                source_admitted: true,
                candidate,
                existing,
            };
        let a = |v| Some((vec![1u8], v));
        assert_eq!(kad_record_decision(&facts(a(2), None)), Ok(()));
        assert_eq!(kad_record_decision(&facts(a(2), a(2))), Ok(()), "republish");
        assert_eq!(
            kad_record_decision(&facts(a(3), a(2))),
            Ok(()),
            "newer version"
        );
        assert_eq!(
            kad_record_decision(&facts(None, None)),
            Err("reject.dht_record_invalid")
        );
        assert_eq!(
            kad_record_decision(&facts(Some((vec![2u8], 9)), a(2))),
            Err("reject.dht_record_owner_conflict")
        );
        assert_eq!(
            kad_record_decision(&facts(a(1), a(2))),
            Err("reject.dht_record_rollback")
        );
        assert_eq!(
            kad_record_decision(&KadRecordFacts {
                source_admitted: false,
                candidate: a(2),
                existing: None,
            }),
            Err("reject.dht_record_source_not_admitted")
        );
    }
}
