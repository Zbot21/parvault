pub mod admission;
pub mod behaviour;
pub mod client;
pub mod council_fetch;
pub mod discovery;
pub mod placement;
pub mod rate_limit;
pub mod server_events;
pub mod transport;
pub mod wan_rendezvous;
pub mod wire_handler;
pub mod wot;

pub use behaviour::{
    classify_ip_asn, effective_kademlia_distance, ipv4_same_slash24, ipv6_same_slash48,
    is_routable_public_ip, DhtEnvelopeKind, DhtWireEnvelope, MeshNetworkBehaviour, MeshWireRequest,
    MeshWireResponse,
};
pub use client::{is_network_peer_addr, parse_peer_multiaddr, MeshClient, OnionOriginator};
pub use discovery::{
    compute_pairing_sas_commitment, derive_4word_pairing_sas,
    derive_libp2p_peer_id_from_ed25519_pubkey, detect_primary_lan_ipv4, discover_lan_peers,
    extract_listen_port_and_ip, generate_random_pairing_nonce, node_identity_libp2p_peer_id,
    normalize_4word_sas_code, resolve_zero_config_peers, resolve_zero_config_peers_with_wan,
    verify_lan_pairing_code, DiscoveredLanPeer, KnownPeerRecord, KnownPeersStore, LanBeaconConfig,
    LanBeaconHandle, LanBeaconPacket, LanBeaconResponder, LanPairingCode,
    DEFAULT_LAN_DISCOVERY_PORT, DEFAULT_LAN_PAIRING_NONCE, LAN_BEACON_SIGNING_DOMAIN,
    LAN_DISCOVER_PROBE_MAGIC, LAN_MULTICAST_ADDR_STR, LAN_MULTICAST_GROUP, LAN_REGISTRY_ENV_VAR,
    MAX_LAN_BEACON_AGE_MS,
};
pub use placement::{PeerTopologyMetrics, PlacementEngine, ShardPlacementPlan};
pub use rate_limit::TokenBucketRateLimiter;
pub use transport::{build_mesh_client_swarm, build_mesh_server_swarm, build_mesh_swarm};
pub use wan_rendezvous::*;
pub use wot::{
    DelegationChain, InvitationHop, PublicCommonsTicket, SlashingEvidence, SlashingReason,
    TicketFacts, TrustPoolMode, WebOfTrustError, WebOfTrustRegistry, WotError,
    DEFAULT_PUBLIC_WOT_POW_BITS, DEFAULT_SUBTREE_SLASH_LIMIT, MAX_LEAF_FAILURES,
    MAX_PUBLIC_COMMONS_PEERS, MAX_SEEN_SLASHING_NONCES, PUBLIC_COMMONS_GENESIS_SEED_DOMAIN,
    PUBLIC_COMMONS_POW_DOMAIN,
};
