use crate::network::behaviour::{BincodeWireCodec, MeshNetworkBehaviour};
use libp2p::{
    gossipsub, identify, kad, mdns, noise, ping,
    request_response::{self, ProtocolSupport},
    tcp, yamux, StreamProtocol, Swarm, SwarmBuilder,
};
use std::time::Duration;

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
    build_swarm(keypair, enable_quic, enable_mdns, true)
}

/// Builds a lightweight client `libp2p::Swarm` for outbound RPCs without binding a multicast mDNS listener.
pub fn build_mesh_client_swarm(
    keypair: libp2p::identity::Keypair,
    enable_quic: bool,
) -> anyhow::Result<Swarm<MeshNetworkBehaviour>> {
    build_swarm(keypair, enable_quic, false, false)
}

fn build_swarm(
    keypair: libp2p::identity::Keypair,
    enable_quic: bool,
    enable_mdns: bool,
    kad_server: bool,
) -> anyhow::Result<Swarm<MeshNetworkBehaviour>> {
    let builder = SwarmBuilder::with_existing_identity(keypair).with_tokio();

    let builder = builder.with_tcp(
        tcp::Config::default().nodelay(true),
        noise::Config::new,
        yamux::Config::default,
    )?;

    let swarm = if enable_quic {
        builder
            .with_quic()
            .with_behaviour(|key| construct_behaviour(key, enable_mdns, kad_server))?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    } else {
        builder
            .with_behaviour(|key| construct_behaviour(key, enable_mdns, kad_server))?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    };

    Ok(swarm)
}

fn construct_behaviour(
    key: &libp2p::identity::Keypair,
    enable_mdns: bool,
    kad_server: bool,
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
    let identify = identify::Behaviour::new(identify::Config::new(
        "/parvault/id/1.0.0".to_string(),
        key.public(),
    ));

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
        kademlia,
        gossipsub,
        mdns,
        ping,
        identify,
        req_resp,
    })
}
