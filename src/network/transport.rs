use crate::network::behaviour::{BincodeWireCodec, MeshNetworkBehaviour};
use libp2p::{
    gossipsub, identify, kad, mdns, noise, ping,
    request_response::{self, ProtocolSupport},
    tcp, yamux, StreamProtocol, Swarm,
};
use std::time::Duration;

/// What the dial gate needs to build a swarm (`v0.5.4` NEW-5, `docs/LAB_MODE.md`): the dial
/// set (`Open` outside deterministic mode) and the identify address cache (`0` when
/// deterministic, so identify supplies no dial addresses).
#[derive(Clone, Debug)]
pub struct GateParams {
    pub set: std::sync::Arc<crate::lab_dial::DialSet>,
    pub identify_cache: usize,
    /// The NEW-3 counters this swarm records into, and which swarm it is.
    pub counters: Option<std::sync::Arc<crate::traversal_metrics::TraversalCounters>>,
    pub origin: crate::traversal_metrics::Origin,
}

impl GateParams {
    /// No gate: every dial allowed, identify's default cache.
    pub fn open() -> Self {
        Self {
            set: std::sync::Arc::new(crate::lab_dial::DialSet::Open),
            identify_cache: IDENTIFY_DEFAULT_CACHE,
            counters: None,
            origin: crate::traversal_metrics::Origin::Daemon,
        }
    }

    /// The gate for `set`: a fixed set also turns the identify cache off.
    pub fn for_set(set: std::sync::Arc<crate::lab_dial::DialSet>) -> Self {
        let identify_cache = if set.is_fixed() {
            0
        } else {
            IDENTIFY_DEFAULT_CACHE
        };
        Self {
            set,
            identify_cache,
            counters: None,
            origin: crate::traversal_metrics::Origin::Daemon,
        }
    }

    /// Records into `counters` as `origin`.
    pub fn with_counters(
        mut self,
        counters: Option<std::sync::Arc<crate::traversal_metrics::TraversalCounters>>,
        origin: crate::traversal_metrics::Origin,
    ) -> Self {
        self.counters = counters;
        self.origin = origin;
        self
    }
}

/// libp2p-identify 0.45's default `cache_size`.
const IDENTIFY_DEFAULT_CACHE: usize = 100;

/// Builds the `libp2p::Swarm` configured per ADR-08:
/// - Primary transport: **TCP + Noise XX + Yamux** (stateless cryptographic framing, minimal musl footprint)
/// - Optional secondary transport: **QUIC** (enabled via `config.toml` / `--enable-quic`)
pub fn build_mesh_swarm(
    keypair: libp2p::identity::Keypair,
    enable_quic: bool,
) -> anyhow::Result<Swarm<MeshNetworkBehaviour>> {
    build_mesh_server_swarm(keypair, enable_quic, true)
}

/// Builds a server swarm (Kademlia server mode). `enable_mdns` only controls LAN multicast
/// discovery (off under `--no-lan-discovery`); it never changes the Kademlia mode. The routing
/// table takes no automatic inserts: a peer is added when it is admitted (F-11).
pub fn build_mesh_server_swarm(
    keypair: libp2p::identity::Keypair,
    enable_quic: bool,
    enable_mdns: bool,
) -> anyhow::Result<Swarm<MeshNetworkBehaviour>> {
    build_swarm(keypair, enable_quic, enable_mdns, true, GateParams::open())
}

/// The server swarm with the lab dial gate.
pub fn build_mesh_server_swarm_gated(
    keypair: libp2p::identity::Keypair,
    enable_quic: bool,
    enable_mdns: bool,
    gate: GateParams,
) -> anyhow::Result<Swarm<MeshNetworkBehaviour>> {
    build_swarm(keypair, enable_quic, enable_mdns, true, gate)
}

/// Builds a lightweight client `libp2p::Swarm` for outbound RPCs without binding a multicast mDNS listener.
pub fn build_mesh_client_swarm(
    keypair: libp2p::identity::Keypair,
    enable_quic: bool,
) -> anyhow::Result<Swarm<MeshNetworkBehaviour>> {
    build_swarm(keypair, enable_quic, false, false, GateParams::open())
}

/// The client swarm with the lab dial gate.
pub fn build_mesh_client_swarm_gated(
    keypair: libp2p::identity::Keypair,
    enable_quic: bool,
    gate: GateParams,
) -> anyhow::Result<Swarm<MeshNetworkBehaviour>> {
    build_swarm(keypair, enable_quic, false, false, gate)
}

/// Both swarms are built here. The transport is built by hand so the whole TCP (+ QUIC)
/// transport is wrapped in `LabDialTransport`, the choke point every dialled address passes.
fn build_swarm(
    keypair: libp2p::identity::Keypair,
    enable_quic: bool,
    enable_mdns: bool,
    kad_server: bool,
    gate: GateParams,
) -> anyhow::Result<Swarm<MeshNetworkBehaviour>> {
    use libp2p::core::{muxing::StreamMuxerBox, upgrade::Version, Transport};
    let tcp = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(&keypair)?)
        .multiplex(yamux::Config::default())
        .map_err(crate::network::traversal_classify::flatten_tcp_stack_error)
        .map(|(p, c), _| (p, StreamMuxerBox::new(c)));
    let inner = if enable_quic {
        let quic = libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(&keypair))
            .map(|(p, c), _| (p, StreamMuxerBox::new(c)));
        tcp.or_transport(quic)
            .map_err(crate::network::traversal_classify::flatten_or_error)
            .map(|either, _| either.into_inner())
            .boxed()
    } else {
        tcp.boxed()
    };
    let transport = crate::network::traversal_gate::LabDialTransport::new(
        inner,
        std::sync::Arc::clone(&gate.set),
    )
    .boxed();
    let behaviour = construct_behaviour(&keypair, enable_mdns, kad_server, &gate)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let peer_id = keypair.public().to_peer_id();
    Ok(Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(60)),
    ))
}

fn construct_behaviour(
    key: &libp2p::identity::Keypair,
    enable_mdns: bool,
    kad_server: bool,
    gate: &GateParams,
) -> Result<MeshNetworkBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let local_peer_id = key.public().to_peer_id();

    // 1. Kademlia DHT for peer discovery & encrypted FileManifest storage (ADR-02).
    let store_config = kad::store::MemoryStoreConfig {
        max_value_bytes: 2 * 1024 * 1024,
        ..Default::default()
    };
    let store = kad::store::MemoryStore::with_config(local_peer_id, store_config);
    let mut kad_config = kad::Config::new(StreamProtocol::new("/parvault/kad/1.0.0"));
    kad_config.set_query_timeout(Duration::from_secs(10));
    kad_config.set_max_packet_size(2 * 1024 * 1024);
    // F-10b: inbound records (and provider records) are handed to the application, which stores
    // a record only if it is a valid signed DHT envelope for its key (`server_events`).
    kad_config.set_record_filtering(kad::StoreInserts::FilterBoth);
    if kad_server {
        // F-11: connected or discovered peers never enter the routing table on their own.
        kad_config.set_kbucket_inserts(kad::BucketInserts::Manual);
    }
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);
    kademlia.set_mode(Some(if kad_server {
        kad::Mode::Server
    } else {
        kad::Mode::Client
    }));

    // 2. Gossipsub for Web-of-Trust certificate & SlashingEvidence propagation (ADR-05).
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .build()?;
    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub_config,
    )?;

    // 3. mDNS for sub-millisecond local LAN/WLAN subnet discovery (enabled for daemons, toggled off for one-shot RPCs).
    let mdns = if enable_mdns {
        libp2p::swarm::behaviour::toggle::Toggle::from(Some(mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        )?))
    } else {
        libp2p::swarm::behaviour::toggle::Toggle::from(None)
    };

    // 4. Active RTT probing (Ping) & Identify.
    let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(5)));
    let identify = identify::Behaviour::new(
        identify::Config::new("/parvault/id/1.0.0".to_string(), key.public())
            .with_cache_size(gate.identify_cache),
    );

    // 5. Bincode Request-Response wire protocol (32 MiB max frame) for 16 MiB stripes, PoR & RepairGrants.
    let req_resp = request_response::Behaviour::with_codec(
        BincodeWireCodec::default(),
        [(
            StreamProtocol::new("/parvault/wire/1.0.0"),
            ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(60)),
    );

    Ok(MeshNetworkBehaviour {
        gate: crate::network::traversal_gate::TraversalGate::with_counters(
            std::sync::Arc::clone(&gate.set),
            gate.counters.clone(),
            gate.origin,
        ),
        kademlia,
        gossipsub,
        mdns,
        ping,
        identify,
        req_resp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B-41 / F-11: the client swarm never runs mDNS, so its event loop has no mDNS arm.
    #[tokio::test]
    async fn client_swarm_has_mdns_off() {
        let swarm =
            build_mesh_client_swarm(libp2p::identity::Keypair::generate_ed25519(), false).unwrap();
        assert!(!swarm.behaviour().mdns.is_enabled());
    }
}
