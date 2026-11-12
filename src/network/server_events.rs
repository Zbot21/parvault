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
use libp2p::kad::{self, store::RecordStore};
use libp2p::request_response::{self, Message};
use libp2p::swarm::SwarmEvent;
use libp2p::{mdns, Multiaddr, Swarm};
use std::collections::HashMap;
use tracing::{info, warn};

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
    /// The inbound record, if it is a self-consistent signed DHT envelope for its key.
    pub candidate: Option<RecordIdentity>,
    /// The record already stored under that key, if any.
    pub existing: Option<RecordIdentity>,
}

/// Stores an inbound Kademlia record only if it is a valid DHT envelope for its key, does not
/// replace another owner's record, and does not roll back its version (the same rules as the
/// `ZeroTrustDhtStore` behind `PutDhtEnvelope`).
pub fn kad_record_decision(facts: &KadRecordFacts) -> Result<(), &'static str> {
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
}

impl ServerSwarmEvents {
    /// `log_mdns_discoveries` keeps the daemon's per-peer mDNS log line (the seed has none).
    pub fn new(log_mdns_discoveries: bool) -> Self {
        Self {
            peer_remote_addrs: HashMap::new(),
            log_mdns_discoveries,
        }
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
        F: FnOnce(&str, Option<&Multiaddr>, MeshWireRequest) -> MeshWireResponse,
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
                let response = on_request(&peer_str, remote_addr.as_ref(), request);
                if let (Ok(()), Some(addr)) =
                    (kad_routing_decision(admits_sender(&response)), remote_addr)
                {
                    swarm.behaviour_mut().kademlia.add_address(&peer, addr);
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
    }
}
