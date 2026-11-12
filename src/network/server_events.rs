//! Swarm event handling shared by the `parvault` daemon and `parvault-seed` server loops.
//!
//! Handles the arms both loops implemented identically (connection-address bookkeeping, mDNS
//! discovery into Kademlia, inbound request -> handler -> response) and returns every other
//! event, so each binary keeps its own `select!`, timers and role-specific arms.

use crate::network::behaviour::{
    MeshNetworkBehaviour, MeshNetworkBehaviourEvent, MeshWireRequest, MeshWireResponse,
};
use libp2p::request_response::{self, Message};
use libp2p::swarm::SwarmEvent;
use libp2p::{mdns, Multiaddr, Swarm};
use std::collections::HashMap;
use tracing::info;

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
                for (peer_id, multiaddr) in list {
                    if self.log_mdns_discoveries {
                        info!(%peer_id, %multiaddr, "Discovered LAN peer via mDNS");
                    }
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, multiaddr);
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
                let remote_addr = self.peer_remote_addrs.get(&peer_str);
                let response = on_request(&peer_str, remote_addr, request);
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
