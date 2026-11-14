use crate::bootstrap::{LiteStripeSyndicationBundle, LiteSyndicationReceipt, PersonalDeviceCert};
use crate::config::ErasureTier;
use crate::crypto::{compute_sha256, HybridKemPublicKey, NodeIdentity, PqRelayedShardEnvelope};
use crate::network::behaviour::{
    classify_ip_asn, DhtEnvelopeKind, DhtWireEnvelope, MeshNetworkBehaviour,
    MeshNetworkBehaviourEvent, MeshWireRequest, MeshWireResponse, PeerTopologyMetrics,
    PlacementEngine, SignedWanRendezvousEntry,
};
use crate::network::discovery::{
    discover_lan_peers, node_identity_libp2p_peer_id, KnownPeersStore, DEFAULT_LAN_DISCOVERY_PORT,
};
use crate::network::transport::build_mesh_client_swarm;
use crate::network::wan_rendezvous::{
    derive_peer_ddns_slot_key, derive_slot_key_from_code, now_ms as wan_now_ms,
    open_ddns_heartbeat, open_public_tracker_card, open_wan_peer_card, seal_ddns_heartbeat,
    seal_public_tracker_card, seal_wan_peer_card, WanPeerCard, PUBLIC_COMMONS_SWARM_SLOT,
};
use crate::network::wot::DelegationChain;
use crate::por::{
    MultiSegmentPorChallenge, PorChallenge, PorResponse, PorVerifierEngine, RepairGrant,
    WitnessFailureReceipt,
};
use crate::sharding::StripeShardSet;
use crate::storage::{
    AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, EvictionPurgeReport, ShardId,
    SignedBadActorEvictionOrder, StripeManifestEntry, VerifiableAbuseReport,
};
use libp2p::{
    futures::StreamExt,
    identify,
    kad::{self, store::RecordStore},
    mdns,
    multiaddr::Protocol,
    ping,
    request_response::{self, Message, OutboundRequestId},
    swarm::{dial_opts::DialOpts, ConnectionId, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// Typed error enumeration for `MeshClient` transport, authentication, and wire RPC failures.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MeshClientError {
    #[error("invalid peer address: {0}")]
    InvalidAddress(String),
    #[error("failed to connect to {peer}: {reason}")]
    ConnectFailed { peer: String, reason: String },
    #[error("wire request timed out after {timeout:?} to {peer}")]
    RequestTimedOut { peer: String, timeout: Duration },
    #[error("PeerId mismatch for {peer}: expected {expected}, got {actual}")]
    PeerIdMismatch {
        peer: String,
        expected: String,
        actual: String,
    },
    #[error("wire request outbound failure to {peer}: {reason}")]
    OutboundFailure { peer: String, reason: String },
    #[error("remote peer {peer} rejected request: {reason}")]
    RemoteRejected { peer: String, reason: String },
    #[error("wire protocol error: {0}")]
    ProtocolError(String),
}

impl MeshClientError {
    /// Returns `true` when the failure indicates that the target peer is unreachable, timed out,
    /// dropped the connection, or failed cryptographic `PeerId` authentication.
    pub const fn is_peer_unreachable(&self) -> bool {
        matches!(
            self,
            Self::ConnectFailed { .. }
                | Self::RequestTimedOut { .. }
                | Self::OutboundFailure { .. }
                | Self::PeerIdMismatch { .. }
        )
    }
}

/// Extracts an explicit `/p2p/<PeerId>` component from a `Multiaddr` if present.
pub fn extract_expected_peer_id(maddr: &Multiaddr) -> Option<PeerId> {
    maddr.iter().find_map(|proto| match proto {
        Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })
}

/// Returns a copy of `maddr` with any trailing `/p2p/<PeerId>` component removed.
pub fn strip_p2p_protocol(maddr: &Multiaddr) -> Multiaddr {
    maddr
        .iter()
        .filter(|p| !matches!(p, Protocol::P2p(_)))
        .collect()
}

/// Splits a 64-byte Ed25519 signature into `(r, s)` 32-byte halves after verifying length.
fn split_ed25519_signature(sig: &[u8]) -> Result<([u8; 32], [u8; 32]), MeshClientError> {
    if sig.len() != 64 {
        return Err(MeshClientError::ProtocolError(format!(
            "invalid 64-byte Ed25519 signature length: {}",
            sig.len()
        )));
    }
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&sig[..32]);
    sig_s.copy_from_slice(&sig[32..64]);
    Ok((sig_r, sig_s))
}

/// Parses a peer address string into a dialable `libp2p::Multiaddr`, preserving any `/p2p/<PeerId>`
/// component for cryptographic identity verification (`C2`).
///
/// Accepts:
/// - Standard Multiaddrs (`/ip4/10.42.1.11/tcp/4001`, `/ip4/10.42.1.11/tcp/4001/p2p/12D3KooW...`)
/// - DNS Multiaddrs (`/dns4/parvault-seed/tcp/4002`, `/dns/node1/tcp/4001/p2p/12D3KooW...`)
/// - Socket strings (`10.42.1.11:4001`, `parvault-seed:4002`, `localhost:4001`)
pub fn parse_peer_multiaddr(raw: &str) -> anyhow::Result<Multiaddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!(MeshClientError::InvalidAddress("empty peer address".into()));
    }

    if trimmed.starts_with("/dns4/")
        || trimmed.starts_with("/dns/")
        || trimmed.starts_with("/dns6/")
    {
        let parts: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() >= 4 && parts[2] == "tcp" {
            let host = parts[1];
            let port: u16 = parts[3]
                .parse()
                .map_err(|e| MeshClientError::InvalidAddress(format!("{trimmed}: {e}")))?;
            let trailing = if parts.len() > 4 {
                format!("/{}", parts[4..].join("/"))
            } else {
                String::new()
            };
            if let Ok(mut addrs) = (host, port).to_socket_addrs() {
                if let Some(sock) = addrs.next() {
                    let resolved = match sock.ip() {
                        IpAddr::V4(v4) => format!("/ip4/{v4}/tcp/{port}{trailing}"),
                        IpAddr::V6(v6) => format!("/ip6/{v6}/tcp/{port}{trailing}"),
                    };
                    return Ok(resolved.parse().map_err(|e| {
                        MeshClientError::InvalidAddress(format!("{resolved}: {e}"))
                    })?);
                }
            }
        }
    }

    if trimmed.starts_with('/') {
        return Ok(trimmed
            .parse()
            .map_err(|e| MeshClientError::InvalidAddress(format!("{trimmed}: {e}")))?);
    }

    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return match sock.ip() {
            IpAddr::V4(v4) => Ok(format!("/ip4/{v4}/tcp/{}", sock.port()).parse()?),
            IpAddr::V6(v6) => Ok(format!("/ip6/{v6}/tcp/{}", sock.port()).parse()?),
        };
    }

    // Handle `host:port` or `ip:port`
    if let Ok(mut addrs) = trimmed.to_socket_addrs() {
        if let Some(sock) = addrs.next() {
            return match sock.ip() {
                IpAddr::V4(v4) => Ok(format!("/ip4/{v4}/tcp/{}", sock.port()).parse()?),
                IpAddr::V6(v6) => Ok(format!("/ip6/{v6}/tcp/{}", sock.port()).parse()?),
            };
        }
    }

    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() == 2 {
        let ip = parts[0];
        let port = parts[1];
        return Ok(format!("/ip4/{ip}/tcp/{port}")
            .parse()
            .map_err(|e| MeshClientError::InvalidAddress(format!("{trimmed}: {e}")))?);
    }

    anyhow::bail!(MeshClientError::InvalidAddress(format!(
        "unable to parse peer address '{trimmed}' as Multiaddr or host:port"
    )))
}

/// Asynchronous DNS and Multiaddr resolver executed inside the persistent Swarm worker (`C10`),
/// preserving `/p2p/<PeerId>` suffixes for TOFU / explicit `PeerId` verification (`C2`).
async fn resolve_peer_multiaddr_async(
    raw: &str,
) -> Result<(Multiaddr, Option<PeerId>), MeshClientError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(MeshClientError::InvalidAddress("empty peer address".into()));
    }

    if trimmed.starts_with("/ip4/") || trimmed.starts_with("/ip6/") {
        let maddr: Multiaddr = trimmed
            .parse()
            .map_err(|e| MeshClientError::InvalidAddress(format!("{trimmed}: {e}")))?;
        let expected = extract_expected_peer_id(&maddr);
        return Ok((maddr, expected));
    }

    if trimmed.starts_with("/dns4/")
        || trimmed.starts_with("/dns/")
        || trimmed.starts_with("/dns6/")
    {
        let parts: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() >= 4 && parts[2] == "tcp" {
            let host = parts[1];
            let port: u16 = parts[3]
                .parse()
                .map_err(|e| MeshClientError::InvalidAddress(format!("{trimmed}: {e}")))?;
            let trailing = if parts.len() > 4 {
                format!("/{}", parts[4..].join("/"))
            } else {
                String::new()
            };
            if let Ok(mut addrs) = tokio::net::lookup_host((host, port)).await {
                if let Some(sock) = addrs.next() {
                    let resolved = match sock.ip() {
                        IpAddr::V4(v4) => format!("/ip4/{v4}/tcp/{port}{trailing}"),
                        IpAddr::V6(v6) => format!("/ip6/{v6}/tcp/{port}{trailing}"),
                    };
                    let maddr: Multiaddr = resolved
                        .parse()
                        .map_err(|e| MeshClientError::InvalidAddress(format!("{resolved}: {e}")))?;
                    let expected = extract_expected_peer_id(&maddr);
                    return Ok((maddr, expected));
                }
            }
        }
    }

    if trimmed.starts_with('/') {
        let maddr: Multiaddr = trimmed
            .parse()
            .map_err(|e| MeshClientError::InvalidAddress(format!("{trimmed}: {e}")))?;
        let expected = extract_expected_peer_id(&maddr);
        return Ok((maddr, expected));
    }

    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        let resolved = match sock.ip() {
            IpAddr::V4(v4) => format!("/ip4/{v4}/tcp/{}", sock.port()),
            IpAddr::V6(v6) => format!("/ip6/{v6}/tcp/{}", sock.port()),
        };
        let maddr: Multiaddr = resolved
            .parse()
            .map_err(|e| MeshClientError::InvalidAddress(format!("{resolved}: {e}")))?;
        return Ok((maddr, None));
    }

    if let Ok(mut addrs) = tokio::net::lookup_host(trimmed).await {
        if let Some(sock) = addrs.next() {
            let resolved = match sock.ip() {
                IpAddr::V4(v4) => format!("/ip4/{v4}/tcp/{}", sock.port()),
                IpAddr::V6(v6) => format!("/ip6/{v6}/tcp/{}", sock.port()),
            };
            let maddr: Multiaddr = resolved
                .parse()
                .map_err(|e| MeshClientError::InvalidAddress(format!("{resolved}: {e}")))?;
            return Ok((maddr, None));
        }
    }

    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() == 2 {
        let ip = parts[0];
        let port = parts[1];
        let maddr: Multiaddr = format!("/ip4/{ip}/tcp/{port}")
            .parse()
            .map_err(|e| MeshClientError::InvalidAddress(format!("{trimmed}: {e}")))?;
        return Ok((maddr, None));
    }

    Err(MeshClientError::InvalidAddress(format!(
        "unable to parse peer address '{trimmed}' as Multiaddr or host:port"
    )))
}

/// Checks whether a string looks like a network `Multiaddr` or `host:port` (as opposed to a local filesystem path).
pub fn is_network_peer_addr(raw: &str) -> bool {
    let s = raw.trim();
    if s.starts_with("/ip4/")
        || s.starts_with("/ip6/")
        || s.starts_with("/dns4/")
        || s.starts_with("/dns/")
        || s.starts_with("/dns6/")
    {
        return true;
    }
    // Check `host:port` where port is a valid u16 and not a Windows drive letter like `C:\...`
    if let Some((left, right)) = s.rsplit_once(':') {
        if left.len() > 1
            && !right.contains('/')
            && !right.contains('\\')
            && right.parse::<u16>().is_ok()
        {
            return true;
        }
    }
    false
}

/// Determines the local outbound IP address used to reach `peer_ip` via an OS kernel routing lookup (`C5`).
fn detect_local_ip_for_peer(peer_ip: IpAddr) -> IpAddr {
    let (bind_addr, target) = match peer_ip {
        IpAddr::V4(_) => ("0.0.0.0:0", SocketAddr::new(peer_ip, 4001)),
        IpAddr::V6(_) => ("[::]:0", SocketAddr::new(peer_ip, 4001)),
    };
    if let Ok(sock) = UdpSocket::bind(bind_addr) {
        if sock.connect(target).is_ok() {
            if let Ok(local_sock) = sock.local_addr() {
                return local_sock.ip();
            }
        }
    }
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}

/// Extracts an `IpAddr` from a `Multiaddr` if an `/ip4/` or `/ip6/` component is present.
fn extract_ip_from_multiaddr(maddr: &Multiaddr) -> Option<IpAddr> {
    maddr.iter().find_map(|proto| match proto {
        Protocol::Ip4(v4) => Some(IpAddr::V4(v4)),
        Protocol::Ip6(v6) => Some(IpAddr::V6(v6)),
        _ => None,
    })
}

/// Cached telemetry snapshot returned by a storage node via `MeshWireResponse::NodeStatusResult`.
#[derive(Debug, Clone)]
pub struct CachedNodeStatus {
    pub peer_id: String,
    pub asn: u32,
    pub region: String,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub sla_score: f64,
    pub pq_kem_pubkey: Option<HybridKemPublicKey>,
}

enum SwarmCommand {
    SendRequest {
        peer_addr: String,
        request: Box<MeshWireRequest>,
        timeout: Duration,
        reply_tx: mpsc::SyncSender<Result<MeshWireResponse, MeshClientError>>,
    },
    GetKadRecord {
        dht_key: [u8; 32],
        reply_tx: mpsc::SyncSender<Vec<Vec<u8>>>,
    },
}

#[derive(Debug)]
struct SwarmWorkerHandle {
    cmd_tx: tokio::sync::mpsc::UnboundedSender<SwarmCommand>,
}

struct PendingDialRpc {
    connection_id: ConnectionId,
    peer_addr_raw: String,
    base_maddr: Multiaddr,
    expected_peer_id: Option<PeerId>,
    request: MeshWireRequest,
    started_at: Instant,
    timeout: Duration,
    reply_tx: mpsc::SyncSender<Result<MeshWireResponse, MeshClientError>>,
}

struct InflightRpc {
    peer_addr_raw: String,
    base_maddr: Multiaddr,
    expected_peer_id: Option<PeerId>,
    peer_id: PeerId,
    request_clone: MeshWireRequest,
    was_warm_reuse: bool,
    started_at: Instant,
    timeout: Duration,
    reply_tx: mpsc::SyncSender<Result<MeshWireResponse, MeshClientError>>,
}

struct PendingKadGet {
    records: Vec<Vec<u8>>,
    started_at: Instant,
    reply_tx: mpsc::SyncSender<Vec<Vec<u8>>>,
}

struct OutboundRpcContext {
    peer_id: PeerId,
    peer_addr_raw: String,
    base_maddr: Multiaddr,
    expected_peer_id: Option<PeerId>,
    request: MeshWireRequest,
    was_warm_reuse: bool,
    started_at: Instant,
    timeout: Duration,
    reply_tx: mpsc::SyncSender<Result<MeshWireResponse, MeshClientError>>,
}

fn dispatch_rpc_on_established_peer(
    swarm: &mut Swarm<MeshNetworkBehaviour>,
    ctx: OutboundRpcContext,
    inflight_requests: &mut HashMap<OutboundRequestId, InflightRpc>,
) {
    let OutboundRpcContext {
        peer_id,
        peer_addr_raw,
        base_maddr,
        expected_peer_id,
        request,
        was_warm_reuse,
        started_at,
        timeout,
        reply_tx,
    } = ctx;
    if let MeshWireRequest::PutDhtEnvelope(ref env) = request {
        let dht_key = match env {
            DhtWireEnvelope::ClassicalManifest(m) => m.dht_key,
            DhtWireEnvelope::PostQuantumManifest(m) => m.dht_key,
            DhtWireEnvelope::VaultCatalog(m) => m.dht_key,
        };
        match bincode::serialize(env) {
            Ok(bytes) => {
                let record = kad::Record {
                    key: kad::RecordKey::new(&dht_key),
                    value: bytes,
                    publisher: Some(peer_id),
                    expires: None,
                };
                let _ = swarm
                    .behaviour_mut()
                    .kademlia
                    .store_mut()
                    .put(record.clone());
                let _ = swarm
                    .behaviour_mut()
                    .kademlia
                    .put_record(record, kad::Quorum::One);
            }
            Err(e) => {
                let _ = reply_tx.send(Err(MeshClientError::ProtocolError(format!(
                    "failed to serialize DhtWireEnvelope: {e}"
                ))));
                return;
            }
        }
    }

    let req_id = swarm
        .behaviour_mut()
        .req_resp
        .send_request(&peer_id, request.clone());
    inflight_requests.insert(
        req_id,
        InflightRpc {
            peer_addr_raw,
            base_maddr,
            expected_peer_id,
            peer_id,
            request_clone: request,
            was_warm_reuse,
            started_at,
            timeout,
            reply_tx,
        },
    );
}

fn verify_and_pin_peer_id(
    peer_addr_raw: &str,
    base_maddr: &Multiaddr,
    expected_peer_id: Option<PeerId>,
    actual_peer_id: PeerId,
    pinned_peers: &Arc<Mutex<HashMap<String, PeerId>>>,
) -> Result<(), MeshClientError> {
    if let Some(expected) = expected_peer_id {
        if actual_peer_id != expected {
            return Err(MeshClientError::PeerIdMismatch {
                peer: peer_addr_raw.to_string(),
                expected: expected.to_string(),
                actual: actual_peer_id.to_string(),
            });
        }
    }

    let base_key = base_maddr.to_string();
    let raw_key = peer_addr_raw.trim().to_string();
    if let Ok(mut guard) = pinned_peers.lock() {
        if let Some(&pinned) = guard.get(&base_key).or_else(|| guard.get(&raw_key)) {
            if pinned != actual_peer_id {
                return Err(MeshClientError::PeerIdMismatch {
                    peer: peer_addr_raw.to_string(),
                    expected: pinned.to_string(),
                    actual: actual_peer_id.to_string(),
                });
            }
        }
        guard.insert(base_key, actual_peer_id);
        guard.insert(raw_key, actual_peer_id);
    }
    Ok(())
}

fn record_rtt_sample(
    peer_rtt_ms: &Arc<Mutex<HashMap<String, f64>>>,
    keys: &[String],
    sample_ms: f64,
) {
    if let Ok(mut guard) = peer_rtt_ms.lock() {
        for k in keys {
            let updated = match guard.get(k) {
                Some(&prev) => 0.7 * prev + 0.3 * sample_ms,
                None => sample_ms,
            };
            guard.insert(k.clone(), updated);
        }
    }
}

fn spawn_swarm_worker(
    identity: NodeIdentity,
    pinned_peers: Arc<Mutex<HashMap<String, PeerId>>>,
    peer_rtt_ms: Arc<Mutex<HashMap<String, f64>>>,
    peer_status_cache: Arc<Mutex<HashMap<String, CachedNodeStatus>>>,
    discovered_peers: Arc<Mutex<HashSet<String>>>,
) -> anyhow::Result<SwarmWorkerHandle> {
    let keypair = identity.to_libp2p_keypair()?;
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<SwarmCommand>();

    std::thread::Builder::new()
        .name("parvault-mesh-client-swarm".to_string())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };

            rt.block_on(async move {
                let Ok(mut swarm) = build_mesh_client_swarm(keypair, false) else {
                    return;
                };

                let mut pending_dials: Vec<PendingDialRpc> = Vec::new();
                let mut inflight_requests: HashMap<OutboundRequestId, InflightRpc> = HashMap::new();
                let mut pending_kad_gets: HashMap<kad::QueryId, PendingKadGet> = HashMap::new();
                let mut cleanup_interval = tokio::time::interval(Duration::from_secs(15));
                cleanup_interval.tick().await;

                loop {
                    tokio::select! {
                        cmd = cmd_rx.recv() => {
                            let Some(cmd) = cmd else {
                                break;
                            };
                            match cmd {
                                SwarmCommand::SendRequest {
                                    peer_addr,
                                    request,
                                    timeout,
                                    reply_tx,
                                } => {
                                    let request = *request;
                                    let started_at = Instant::now();
                                    let (maddr, expected_peer_id) = match resolve_peer_multiaddr_async(&peer_addr).await {
                                        Ok(v) => v,
                                        Err(e) => {
                                            let _ = reply_tx.send(Err(e));
                                            continue;
                                        }
                                    };
                                    let base_maddr = strip_p2p_protocol(&maddr);
                                    let base_key = base_maddr.to_string();

                                    let known_peer_id = expected_peer_id.or_else(|| {
                                        pinned_peers
                                            .lock()
                                            .ok()
                                            .and_then(|g| g.get(&base_key).or_else(|| g.get(peer_addr.trim())).copied())
                                    });

                                    // If we already have a warm connection to this peer, verify pinning and reuse it directly!
                                    if let Some(peer_id) = known_peer_id {
                                        if let Err(mismatch) = verify_and_pin_peer_id(
                                            &peer_addr,
                                            &base_maddr,
                                            expected_peer_id,
                                            peer_id,
                                            &pinned_peers,
                                        ) {
                                            let _ = reply_tx.send(Err(mismatch));
                                            continue;
                                        }
                                        if swarm.is_connected(&peer_id) {
                                            dispatch_rpc_on_established_peer(
                                                &mut swarm,
                                                OutboundRpcContext {
                                                    peer_id,
                                                    peer_addr_raw: peer_addr,
                                                    base_maddr,
                                                    expected_peer_id,
                                                    request,
                                                    was_warm_reuse: true,
                                                    started_at,
                                                    timeout,
                                                    reply_tx,
                                                },
                                                &mut inflight_requests,
                                            );
                                            continue;
                                        }
                                    }

                                    // Dial the base Multiaddr so Noise XX authenticates the remote PeerId and
                                    // `ConnectionEstablished` can enforce explicit/TOFU PeerId pinning (`C2`).
                                    let opts = DialOpts::unknown_peer_id()
                                        .address(base_maddr.clone())
                                        .build();
                                    let connection_id = opts.connection_id();
                                    match swarm.dial(opts) {
                                        Ok(()) => {
                                            pending_dials.push(PendingDialRpc {
                                                connection_id,
                                                peer_addr_raw: peer_addr,
                                                base_maddr,
                                                expected_peer_id,
                                                request,
                                                started_at,
                                                timeout,
                                                reply_tx,
                                            });
                                        }
                                        Err(e) => {
                                            let _ = reply_tx.send(Err(MeshClientError::ConnectFailed {
                                                peer: peer_addr,
                                                reason: e.to_string(),
                                            }));
                                        }
                                    }
                                }
                                SwarmCommand::GetKadRecord { dht_key, reply_tx } => {
                                    let key = kad::RecordKey::new(&dht_key);
                                    let mut local_records = Vec::new();
                                    if let Some(cow) = swarm.behaviour_mut().kademlia.store_mut().get(&key) {
                                        local_records.push(cow.value.clone());
                                    }
                                    let query_id = swarm.behaviour_mut().kademlia.get_record(key);
                                    pending_kad_gets.insert(
                                        query_id,
                                        PendingKadGet {
                                            records: local_records,
                                            started_at: Instant::now(),
                                            reply_tx,
                                        },
                                    );
                                }
                            }
                        }
                        event = swarm.select_next_some() => {
                            match event {
                                SwarmEvent::ConnectionEstablished {
                                    peer_id,
                                    connection_id,
                                    endpoint,
                                    ..
                                } => {
                                    let remote_addr = endpoint.get_remote_address().clone();
                                    let remote_base = strip_p2p_protocol(&remote_addr);
                                    swarm
                                        .behaviour_mut()
                                        .kademlia
                                        .add_address(&peer_id, remote_addr);
                                    if let Ok(mut disc) = discovered_peers.lock() {
                                        disc.insert(format!("{remote_base}/p2p/{peer_id}"));
                                    }

                                    let mut remaining = Vec::with_capacity(pending_dials.len());
                                    let mut disconnect_bad_peer = false;
                                    for pending in pending_dials.drain(..) {
                                        if pending.connection_id == connection_id
                                            || pending.base_maddr == remote_base
                                        {
                                            match verify_and_pin_peer_id(
                                                &pending.peer_addr_raw,
                                                &pending.base_maddr,
                                                pending.expected_peer_id,
                                                peer_id,
                                                &pinned_peers,
                                            ) {
                                                Ok(()) => {
                                                    if pending.started_at.elapsed() <= pending.timeout {
                                                        dispatch_rpc_on_established_peer(
                                                            &mut swarm,
                                                            OutboundRpcContext {
                                                                peer_id,
                                                                peer_addr_raw: pending.peer_addr_raw,
                                                                base_maddr: pending.base_maddr,
                                                                expected_peer_id: pending.expected_peer_id,
                                                                request: pending.request,
                                                                was_warm_reuse: false,
                                                                started_at: pending.started_at,
                                                                timeout: pending.timeout,
                                                                reply_tx: pending.reply_tx,
                                                            },
                                                            &mut inflight_requests,
                                                        );
                                                    }
                                                }
                                                Err(mismatch) => {
                                                    disconnect_bad_peer = true;
                                                    let _ = pending.reply_tx.send(Err(mismatch));
                                                }
                                            }
                                        } else {
                                            remaining.push(pending);
                                        }
                                    }
                                    pending_dials = remaining;
                                    if disconnect_bad_peer {
                                        let _ = swarm.disconnect_peer_id(peer_id);
                                    }
                                }
                                SwarmEvent::OutgoingConnectionError {
                                    connection_id,
                                    error,
                                    ..
                                } => {
                                    let mut remaining = Vec::with_capacity(pending_dials.len());
                                    for pending in pending_dials.drain(..) {
                                        if pending.connection_id == connection_id {
                                            let _ = pending.reply_tx.send(Err(
                                                MeshClientError::ConnectFailed {
                                                    peer: pending.peer_addr_raw,
                                                    reason: error.to_string(),
                                                },
                                            ));
                                        } else {
                                            remaining.push(pending);
                                        }
                                    }
                                    pending_dials = remaining;
                                }
                                SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::ReqResp(
                                    request_response::Event::Message {
                                        message:
                                            Message::Response {
                                                request_id,
                                                response,
                                            },
                                        ..
                                    },
                                )) => {
                                    if let Some(inflight) = inflight_requests.remove(&request_id) {
                                        let rtt_ms = inflight.started_at.elapsed().as_secs_f64() * 1000.0;
                                        record_rtt_sample(
                                            &peer_rtt_ms,
                                            &[
                                                inflight.peer_addr_raw.clone(),
                                                inflight.base_maddr.to_string(),
                                                inflight.peer_id.to_string(),
                                            ],
                                            rtt_ms,
                                        );
                                        if let MeshWireResponse::NodeStatusResult {
                                            ref peer_id,
                                            asn,
                                            ref region,
                                            available_bytes,
                                            used_bytes,
                                            sla_score,
                                            ref pq_kem_pubkey,
                                        } = response
                                        {
                                            let status = CachedNodeStatus {
                                                peer_id: peer_id.clone(),
                                                asn,
                                                region: region.clone(),
                                                available_bytes,
                                                used_bytes,
                                                sla_score,
                                                pq_kem_pubkey: pq_kem_pubkey.clone(),
                                            };
                                            if let Ok(mut cache) = peer_status_cache.lock() {
                                                cache.insert(inflight.peer_addr_raw.clone(), status.clone());
                                                cache.insert(inflight.base_maddr.to_string(), status);
                                            }
                                        }
                                        let _ = inflight.reply_tx.send(Ok(response));
                                    }
                                }
                                SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::ReqResp(
                                    request_response::Event::OutboundFailure {
                                        request_id,
                                        error,
                                        ..
                                    },
                                )) => {
                                    if let Some(inflight) = inflight_requests.remove(&request_id) {
                                        // If a warm connection closed right as we reused it, re-dial once transparently
                                        if inflight.was_warm_reuse
                                            && inflight.started_at.elapsed() * 2 < inflight.timeout
                                        {
                                            let _ = swarm.disconnect_peer_id(inflight.peer_id);
                                            let opts = DialOpts::unknown_peer_id()
                                                .address(inflight.base_maddr.clone())
                                                .build();
                                            let connection_id = opts.connection_id();
                                            if swarm.dial(opts).is_ok() {
                                                pending_dials.push(PendingDialRpc {
                                                    connection_id,
                                                    peer_addr_raw: inflight.peer_addr_raw,
                                                    base_maddr: inflight.base_maddr,
                                                    expected_peer_id: inflight.expected_peer_id,
                                                    request: inflight.request_clone,
                                                    started_at: inflight.started_at,
                                                    timeout: inflight.timeout,
                                                    reply_tx: inflight.reply_tx,
                                                });
                                                continue;
                                            }
                                        }
                                        let _ = inflight.reply_tx.send(Err(
                                            MeshClientError::OutboundFailure {
                                                peer: inflight.peer_addr_raw,
                                                reason: format!("{error:?}"),
                                            },
                                        ));
                                    }
                                }
                                SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Ping(
                                    ping::Event {
                                        peer,
                                        result: Ok(rtt),
                                        ..
                                    },
                                )) => {
                                    let sample_ms = rtt.as_secs_f64() * 1000.0;
                                    let mut keys = vec![peer.to_string()];
                                    if let Ok(guard) = pinned_peers.lock() {
                                        for (addr, &p) in guard.iter() {
                                            if p == peer {
                                                keys.push(addr.clone());
                                            }
                                        }
                                    }
                                    record_rtt_sample(&peer_rtt_ms, &keys, sample_ms);
                                }
                                SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Identify(
                                    identify::Event::Received { peer_id, info, .. },
                                )) => {
                                    for addr in info.listen_addrs {
                                        if let Some(ip) = extract_ip_from_multiaddr(&addr) {
                                            if ip.is_unspecified() {
                                                continue;
                                            }
                                        }
                                        let base = strip_p2p_protocol(&addr);
                                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                        if let Ok(mut disc) = discovered_peers.lock() {
                                            disc.insert(format!("{base}/p2p/{peer_id}"));
                                        }
                                    }
                                }
                                SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Mdns(
                                    mdns::Event::Discovered(list),
                                )) => {
                                    for (peer_id, addr) in list {
                                        let base = strip_p2p_protocol(&addr);
                                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                        if let Ok(mut disc) = discovered_peers.lock() {
                                            disc.insert(format!("{base}/p2p/{peer_id}"));
                                        }
                                    }
                                }
                                SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Kademlia(
                                    kad::Event::RoutingUpdated {
                                        peer, addresses, ..
                                    },
                                )) => {
                                    if let Ok(mut disc) = discovered_peers.lock() {
                                        for addr in addresses.iter() {
                                            let base = strip_p2p_protocol(addr);
                                            disc.insert(format!("{base}/p2p/{peer}"));
                                        }
                                    }
                                }
                                SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Kademlia(
                                    kad::Event::OutboundQueryProgressed {
                                        id,
                                        result: kad::QueryResult::GetRecord(res),
                                        step,
                                        ..
                                    },
                                )) => {
                                    let mut finish = step.last;
                                    if let Some(pending) = pending_kad_gets.get_mut(&id) {
                                        match res {
                                            Ok(kad::GetRecordOk::FoundRecord(peer_rec)) => {
                                                pending.records.push(peer_rec.record.value);
                                            }
                                            Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. })
                                            | Err(_) => {
                                                finish = true;
                                            }
                                        }
                                    }
                                    if finish {
                                        if let Some(pending) = pending_kad_gets.remove(&id) {
                                            let _ = pending.reply_tx.send(pending.records);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ = cleanup_interval.tick() => {
                            pending_dials.retain(|p| p.started_at.elapsed() <= p.timeout + Duration::from_secs(5));
                            inflight_requests.retain(|_, r| r.started_at.elapsed() <= r.timeout + Duration::from_secs(5));
                            pending_kad_gets.retain(|_, q| q.started_at.elapsed() <= Duration::from_secs(15));
                        }
                    }
                }
            });
        })?;

    Ok(SwarmWorkerHandle { cmd_tx })
}

/// Live `libp2p` Mesh Client (TCP + Noise XX + Yamux + Kademlia DHT + `/parvault/wire/1.0.0`)
/// backed by a persistent background `Swarm` actor that reuses encrypted connections, enforces
/// TOFU / explicit `PeerId` pinning, and records live RTT & topology telemetry.
/// The DHT reader's owner binding (F-10a): a candidate counts only if the reading identity
/// sealed it. A candidate whose owner cannot be bound to an identity (`None`: a post-quantum
/// manifest, signed by a hybrid key no identity is bound to yet) is refused: fail closed.
pub fn dht_candidate_decision(
    candidate_owner: Option<[u8; 32]>,
    expected_owner: [u8; 32],
) -> Result<(), &'static str> {
    match candidate_owner {
        None => Err("reject.dht_owner_unbindable"),
        Some(owner) if owner == expected_owner => Ok(()),
        Some(_) => Err("reject.dht_owner_mismatch"),
    }
}

/// One onion send: the envelope, its capability and voucher, and the lease for final delivery.
struct OnionSend {
    target_peer_addr: Option<String>,
    envelope: PqRelayedShardEnvelope,
    capability: BlindedShardCapability,
    voucher: AnonymousQuotaVoucher,
    lease: crate::storage::BlindedLeaseSpec,
}

/// Originates onion uploads (ADR-11). It presents its ring credential at the entry relay,
/// which admits it (F-33, L-38) and so learns the originator's IP and ring identity. Onion routing hides the originator only from
/// the final target and the storage host. The relay's forward to the final target presents the
/// relay's own chain. Unlinkable entry (an ephemeral key) is planned for v0.6.0.
pub struct OnionOriginator {
    client: MeshClient,
}

impl OnionOriginator {
    pub fn new(identity: NodeIdentity, peers: Vec<String>) -> Self {
        Self {
            client: MeshClient::new(identity, peers, None),
        }
    }

    /// Sends a single-layer envelope to `entry_relay` (with `next_hop`, or for final delivery).
    pub fn send_onion(
        &self,
        entry_relay: &str,
        next_hop: Option<String>,
        envelope: PqRelayedShardEnvelope,
        capability: BlindedShardCapability,
        voucher: AnonymousQuotaVoucher,
        lease: crate::storage::BlindedLeaseSpec,
    ) -> anyhow::Result<()> {
        self.client.send_onion(
            entry_relay,
            OnionSend {
                target_peer_addr: next_hop,
                envelope,
                capability,
                voucher,
                lease,
            },
            true,
        )
    }

    /// Sends a 2-layer envelope to `entry_relay`, which peels it and forwards to the target.
    pub fn send_layered_onion(
        &self,
        entry_relay: &str,
        outer_envelope: PqRelayedShardEnvelope,
    ) -> anyhow::Result<()> {
        self.client
            .send_layered_onion(entry_relay, outer_envelope, true)
    }
}

/// How long a client waits after a refused handshake before presenting its credential again.
pub const ADMISSION_RETRY_BACKOFF: Duration = Duration::from_secs(60);

/// Whether `resp` is the server's "not admitted" refusal.
fn is_not_admitted_refusal(resp: &MeshWireResponse) -> bool {
    let text = crate::network::wire_handler::NOT_ADMITTED_TEXT;
    match resp {
        MeshWireResponse::PutShardAck { error, .. }
        | MeshWireResponse::PutBlindedShardAck { error, .. }
        | MeshWireResponse::RelayPqOnionAck { error, .. }
        | MeshWireResponse::PutDhtEnvelopeAck { error, .. }
        | MeshWireResponse::SyndicateLiteStripeAck { error, .. } => error.as_deref() == Some(text),
        _ => false,
    }
}

/// A (sender public key, peer address) pair that accepted this process's handshake.
type AdmittedAt = ([u8; 32], String);

#[derive(Clone, Debug)]
pub struct MeshClient {
    identity: NodeIdentity,
    peers: Vec<String>,
    seed_addr: Option<String>,
    request_timeout: Duration,
    discovery_data_dir: Option<PathBuf>,
    lan_discovery_port: u16,
    last_lan_refresh: Arc<Mutex<Option<Instant>>>,
    /// `false` with `--no-lan-discovery`: `refresh_lan_peers` neither scans nor pins.
    lan_discovery_enabled: bool,
    healed_peer_addrs: Arc<Mutex<HashMap<PeerId, String>>>,
    tracker_admin_pubkeys: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    dead_peers: Arc<Mutex<HashSet<String>>>,
    pinned_peers: Arc<Mutex<HashMap<String, PeerId>>>,
    peer_rtt_ms: Arc<Mutex<HashMap<String, f64>>>,
    peer_status_cache: Arc<Mutex<HashMap<String, CachedNodeStatus>>>,
    discovered_peers: Arc<Mutex<HashSet<String>>>,
    worker: Arc<Mutex<Option<SwarmWorkerHandle>>>,
    /// Explicit admission source; `None` falls back to the process-wide one.
    admission: Option<Arc<crate::network::admission::AdmissionSource>>,
    /// (sender pubkey, peer address) pairs that accepted this process's handshake.
    admitted_at: Arc<Mutex<HashSet<AdmittedAt>>>,
    /// When a handshake with (sender, peer) was last refused (backoff).
    admission_refused_at: Arc<Mutex<HashMap<AdmittedAt, Instant>>>,
}

impl MeshClient {
    pub fn new(identity: NodeIdentity, peers: Vec<String>, seed_addr: Option<String>) -> Self {
        let mut normalized_peers = Vec::new();
        let mut seen = HashSet::new();
        let mut initial_healed = HashMap::new();
        for p in peers {
            for item in p.split(',') {
                let t = item.trim();
                if !t.is_empty() && seen.insert(t.to_string()) {
                    if let Ok(maddr) = parse_peer_multiaddr(t) {
                        if let Some(pid) = extract_expected_peer_id(&maddr) {
                            initial_healed.insert(pid, t.to_string());
                        }
                    }
                    normalized_peers.push(t.to_string());
                }
            }
        }
        let seed_addr = seed_addr
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Self {
            identity,
            peers: normalized_peers,
            seed_addr,
            request_timeout: Duration::from_millis(1200),
            discovery_data_dir: None,
            lan_discovery_port: DEFAULT_LAN_DISCOVERY_PORT,
            last_lan_refresh: Arc::new(Mutex::new(None)),
            lan_discovery_enabled: true,
            healed_peer_addrs: Arc::new(Mutex::new(initial_healed)),
            tracker_admin_pubkeys: Arc::new(Mutex::new(HashMap::new())),
            dead_peers: Arc::new(Mutex::new(HashSet::new())),
            pinned_peers: Arc::new(Mutex::new(HashMap::new())),
            peer_rtt_ms: Arc::new(Mutex::new(HashMap::new())),
            peer_status_cache: Arc::new(Mutex::new(HashMap::new())),
            discovered_peers: Arc::new(Mutex::new(HashSet::new())),
            worker: Arc::new(Mutex::new(None)),
            admission: None,
            admitted_at: Arc::new(Mutex::new(HashSet::new())),
            admission_refused_at: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Uses `source` for ring admission instead of the process-wide source.
    pub fn with_admission(mut self, source: crate::network::admission::AdmissionSource) -> Self {
        self.admission = Some(Arc::new(source));
        self
    }

    /// Presents this identity's chain to `peer_addr` once, before the first request that needs an
    /// admitted sender. Without a credential nothing is sent and the peer decides.
    fn ensure_admitted(&self, peer_addr: &str) {
        let key = (self.identity.public_key_bytes(), peer_addr.to_string());
        if self
            .admitted_at
            .lock()
            .map(|s| s.contains(&key))
            .unwrap_or(false)
        {
            return;
        }
        // After a refused handshake, do not handshake again until the backoff has passed.
        if self
            .admission_refused_at
            .lock()
            .ok()
            .and_then(|m| m.get(&key).copied())
            .is_some_and(|t| t.elapsed() < ADMISSION_RETRY_BACKOFF)
        {
            return;
        }
        // A ticket is bound to the peer's key: known from a `/p2p/<PeerId>` address, else learned
        // from the peer's refusal, which states its key and required bits (one re-mint).
        let mut verifier = parse_peer_multiaddr(peer_addr)
            .ok()
            .and_then(|m| extract_expected_peer_id(&m))
            .and_then(|pid| {
                crate::config::NodeConfig::extract_ed25519_pubkey_from_peer_str(&pid.to_string())
            })
            .unwrap_or([0u8; 32]);
        let mut required_bits = None;
        let mut admitted = false;
        for _attempt in 0..2 {
            let Some(request) = self.admission_request(verifier, required_bits) else {
                return;
            };
            let is_ticket = matches!(request, MeshWireRequest::AdmitPublicTicket(_));
            match self.send_request(peer_addr, request) {
                Ok(MeshWireResponse::HandshakeAck { accepted: true, .. })
                | Ok(MeshWireResponse::AdmitPublicTicketAck { admitted: true, .. }) => {
                    admitted = true;
                    break;
                }
                Ok(MeshWireResponse::AdmitPublicTicketAck {
                    admitted: false,
                    verifier_pubkey,
                    required_pow_bits,
                    ..
                }) if is_ticket
                    && verifier_pubkey != [0u8; 32]
                    && (verifier_pubkey != verifier
                        || required_bits != Some(required_pow_bits)) =>
                {
                    let own = self
                        .admission
                        .as_deref()
                        .and_then(|s| s.public_ticket_bits())
                        .unwrap_or(crate::network::wot::DEFAULT_PUBLIC_WOT_POW_BITS);
                    if let Err(code) =
                        crate::network::wot::ticket_pow_demand_decision(required_pow_bits, own)
                    {
                        warn!(
                            code,
                            peer = peer_addr,
                            demanded = required_pow_bits,
                            "refused a peer's ticket PoW demand"
                        );
                        break;
                    }
                    verifier = verifier_pubkey;
                    required_bits = Some(required_pow_bits);
                }
                _ => break,
            }
        }
        if admitted {
            if let Ok(mut m) = self.admission_refused_at.lock() {
                m.remove(&key);
            }
            if let Ok(mut s) = self.admitted_at.lock() {
                s.insert(key);
            }
        } else if let Ok(mut m) = self.admission_refused_at.lock() {
            m.insert(key, Instant::now());
        }
    }

    /// The admission request this identity presents: a chain, or a ticket bound to `verifier`.
    fn admission_request(
        &self,
        verifier: [u8; 32],
        required_bits: Option<u8>,
    ) -> Option<MeshWireRequest> {
        use crate::network::admission::AdmissionCredential;
        let credential = match self.admission.as_deref() {
            Some(source) => source.credential(&self.identity, verifier, required_bits),
            None => crate::network::admission::process_source()
                .and_then(|source| source.credential(&self.identity, verifier, required_bits)),
        };
        Some(match credential? {
            AdmissionCredential::Chain(chain) => MeshWireRequest::HandshakeWoT {
                chain,
                asn: None,
                region: None,
            },
            AdmissionCredential::Ticket(ticket) => MeshWireRequest::AdmitPublicTicket(ticket),
        })
    }

    /// Enables Zero-IP LAN auto-discovery and DHCP IP/port-change self-healing backed by
    /// `<data_dir>/known_peers.json`. If `MeshClient` starts with 0 peers or encounters dead
    /// endpoints after a home DHCP renewal, it automatically re-scans LAN beacons and updates
    /// pinned `/p2p/<PeerId>` Multiaddrs seamlessly.
    pub fn with_data_dir_discovery(mut self, data_dir: PathBuf, discovery_port: u16) -> Self {
        let store = KnownPeersStore::load(&data_dir);
        if let (Ok(mut disc), Ok(mut healed)) =
            (self.discovered_peers.lock(), self.healed_peer_addrs.lock())
        {
            for rec in store.peers.values() {
                disc.insert(rec.multiaddr.clone());
                if let Ok(pid) = rec.libp2p_peer_id.parse::<PeerId>() {
                    healed.entry(pid).or_insert_with(|| rec.multiaddr.clone());
                }
            }
        }
        if let Ok(mut admins) = self.tracker_admin_pubkeys.lock() {
            for (k, &pk) in &store.tracker_admin_pubkeys {
                admins.entry(k.clone()).or_insert(pk);
            }
        }
        self.discovery_data_dir = Some(data_dir);
        self.lan_discovery_port = discovery_port;
        self
    }

    /// Actively scans the local network via `discover_lan_peers`, persists updated endpoints to
    /// `<data_dir>/known_peers.json` (if configured), updates DHCP-healed `PeerId -> Multiaddr`
    /// mappings, and returns all active discovered peer Multiaddrs.
    /// Turns LAN scanning and pinning off (`--no-lan-discovery`); pinned peers are still used.
    pub fn with_lan_discovery(mut self, enabled: bool) -> Self {
        self.lan_discovery_enabled = enabled;
        self
    }

    pub fn refresh_lan_peers(&self) -> Vec<String> {
        if !self.lan_discovery_enabled {
            return Vec::new();
        }
        let found = discover_lan_peers(Duration::from_millis(220), self.lan_discovery_port);
        if let Ok(mut ts) = self.last_lan_refresh.lock() {
            *ts = Some(Instant::now());
        }

        let mut active_addrs = Vec::new();
        if let Some(ref dir) = self.discovery_data_dir {
            let mut store = KnownPeersStore::load(dir);
            if !found.is_empty() {
                store.upsert_discovered(&found);
                let _ = store.save(dir);
            }
            if let Some(ref seed) = self.seed_addr {
                if is_network_peer_addr(seed) {
                    let lan_pids: HashSet<&str> =
                        found.iter().map(|p| p.libp2p_peer_id.as_str()).collect();
                    let stale_records: Vec<_> = store
                        .peers
                        .values()
                        .filter(|r| {
                            !lan_pids.contains(r.libp2p_peer_id.as_str())
                                && self.is_peer_marked_dead(&r.multiaddr)
                        })
                        .cloned()
                        .collect();
                    for rec in stale_records {
                        let _ = self.lookup_wan_ddns_cards(seed, &rec.libp2p_peer_id);
                        if let Some(ref fp) = rec.owner_pq_fingerprint {
                            let _ = self.lookup_wan_ddns_cards(seed, fp);
                        }
                    }
                    store = KnownPeersStore::load(dir);
                }
            }
            for rec in store.peers.values() {
                active_addrs.push(rec.multiaddr.clone());
                if let Ok(pid) = rec.libp2p_peer_id.parse::<PeerId>() {
                    if let Ok(mut healed) = self.healed_peer_addrs.lock() {
                        healed.insert(pid, rec.multiaddr.clone());
                    }
                }
                if let Ok(mut dead) = self.dead_peers.lock() {
                    dead.remove(&rec.multiaddr);
                }
                if let Ok(mut disc) = self.discovered_peers.lock() {
                    disc.insert(rec.multiaddr.clone());
                }
            }
        } else {
            for peer in &found {
                active_addrs.push(peer.multiaddr.clone());
                if let Ok(pid) = peer.libp2p_peer_id.parse::<PeerId>() {
                    if let Ok(mut healed) = self.healed_peer_addrs.lock() {
                        healed.insert(pid, peer.multiaddr.clone());
                    }
                }
                if let Ok(mut dead) = self.dead_peers.lock() {
                    dead.remove(&peer.multiaddr);
                }
                if let Ok(mut disc) = self.discovered_peers.lock() {
                    disc.insert(peer.multiaddr.clone());
                }
            }
        }
        active_addrs
    }

    fn maybe_refresh_lan_peers_throttled(&self) -> bool {
        if self.discovery_data_dir.is_none() {
            return false;
        }
        let recently_refreshed = self
            .last_lan_refresh
            .lock()
            .ok()
            .and_then(|g| *g)
            .is_some_and(|t| t.elapsed() < Duration::from_millis(350));
        if recently_refreshed {
            return false;
        }
        !self.refresh_lan_peers().is_empty()
    }

    fn resolve_healed_peer_addr(&self, raw_addr: &str) -> Option<String> {
        let maddr = parse_peer_multiaddr(raw_addr).ok()?;
        let pid = extract_expected_peer_id(&maddr)?;
        if let Ok(guard) = self.healed_peer_addrs.lock() {
            if let Some(updated) = guard.get(&pid) {
                if updated != raw_addr.trim() {
                    return Some(updated.clone());
                }
            }
        }
        None
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// The timeout this client applies to each request.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub fn with_identity(&self, identity: NodeIdentity) -> Self {
        let same_key = self.identity.public_key_bytes() == identity.public_key_bytes();
        let mut cloned = self.clone();
        cloned.identity = identity;
        if !same_key {
            cloned.worker = Arc::new(Mutex::new(None));
        }
        cloned
    }

    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    pub fn peers(&self) -> &[String] {
        &self.peers
    }

    pub fn seed_addr(&self) -> Option<&str> {
        self.seed_addr.as_deref()
    }

    /// Returns all candidate network endpoints (`peers` + `seed_addr`, falling back to dynamically
    /// discovered peers when no static `peers` list is configured, and remapping any DHCP-rotated
    /// endpoints to their latest verified `/p2p/<PeerId>` Multiaddr).
    pub fn all_network_endpoints(&self) -> Vec<String> {
        let self_pid = node_identity_libp2p_peer_id(&self.identity).ok();
        let build_list = || -> Vec<String> {
            let mut list = Vec::new();
            let mut seen = HashSet::new();
            let mut push_unique = |addr: String| {
                if let Some(local_pid) = self_pid {
                    if let Ok(m) = parse_peer_multiaddr(&addr) {
                        if extract_expected_peer_id(&m) == Some(local_pid) {
                            return;
                        }
                    }
                }
                if seen.insert(addr.clone()) {
                    list.push(addr);
                }
            };

            if !self.peers.is_empty() {
                for p in &self.peers {
                    if let Some(healed) = self.resolve_healed_peer_addr(p) {
                        push_unique(healed);
                    } else {
                        push_unique(p.clone());
                    }
                }
                if self.discovery_data_dir.is_some() {
                    for d in self.discovered_peers() {
                        push_unique(d);
                    }
                }
            } else {
                for d in self.discovered_peers() {
                    if let Some(healed) = self.resolve_healed_peer_addr(&d) {
                        push_unique(healed);
                    } else {
                        push_unique(d);
                    }
                }
            }
            if let Some(ref seed) = self.seed_addr {
                if is_network_peer_addr(seed) {
                    push_unique(seed.clone());
                }
            }
            list
        };

        let mut out = build_list();
        if out.is_empty() && self.maybe_refresh_lan_peers_throttled() {
            out = build_list();
        }
        out
    }

    /// Returns peer multiaddrs dynamically discovered via `Identify`, `mDNS`, and `Kademlia` (`C4`).
    pub fn discovered_peers(&self) -> Vec<String> {
        self.discovered_peers
            .lock()
            .map(|d| d.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the measured round-trip latency in milliseconds for `peer_addr` if observed (`C5`).
    pub fn measured_rtt_ms(&self, peer_addr: &str) -> Option<f64> {
        let guard = self.peer_rtt_ms.lock().ok()?;
        if let Some(&rtt) = guard.get(peer_addr.trim()) {
            return Some(rtt);
        }
        if let Ok(maddr) = parse_peer_multiaddr(peer_addr) {
            let base = strip_p2p_protocol(&maddr).to_string();
            if let Some(&rtt) = guard.get(&base) {
                return Some(rtt);
            }
        }
        None
    }

    /// Returns the TOFU-pinned or explicitly verified `PeerId` for `peer_addr` (`C2`).
    pub fn pinned_peer_id(&self, peer_addr: &str) -> Option<PeerId> {
        let guard = self.pinned_peers.lock().ok()?;
        if let Some(&pid) = guard.get(peer_addr.trim()) {
            return Some(pid);
        }
        if let Ok(maddr) = parse_peer_multiaddr(peer_addr) {
            if let Some(expected) = extract_expected_peer_id(&maddr) {
                return Some(expected);
            }
            let base = strip_p2p_protocol(&maddr).to_string();
            if let Some(&pid) = guard.get(&base) {
                return Some(pid);
            }
        }
        None
    }

    /// Explicitly pins an expected `PeerId` for `peer_addr` (`C2`).
    pub fn pin_peer_id(&self, peer_addr: &str, peer_id: PeerId) {
        if let Ok(mut guard) = self.pinned_peers.lock() {
            guard.insert(peer_addr.trim().to_string(), peer_id);
            if let Ok(maddr) = parse_peer_multiaddr(peer_addr) {
                let base = strip_p2p_protocol(&maddr).to_string();
                guard.insert(base, peer_id);
            }
        }
    }

    /// Clears a previously pinned `PeerId` for `peer_addr` after legitimate node rotation (`C2`).
    pub fn clear_pinned_peer(&self, peer_addr: &str) {
        if let Ok(mut guard) = self.pinned_peers.lock() {
            guard.remove(peer_addr.trim());
            if let Ok(maddr) = parse_peer_multiaddr(peer_addr) {
                let base = strip_p2p_protocol(&maddr).to_string();
                guard.remove(&base);
            }
        }
    }

    fn worker_sender(&self) -> anyhow::Result<tokio::sync::mpsc::UnboundedSender<SwarmCommand>> {
        let mut guard = self
            .worker
            .lock()
            .map_err(|_| anyhow::anyhow!("MeshClient worker mutex poisoned"))?;
        let needs_spawn = match guard.as_ref() {
            Some(handle) => handle.cmd_tx.is_closed(),
            None => true,
        };
        if needs_spawn {
            let handle = spawn_swarm_worker(
                self.identity.clone(),
                Arc::clone(&self.pinned_peers),
                Arc::clone(&self.peer_rtt_ms),
                Arc::clone(&self.peer_status_cache),
                Arc::clone(&self.discovered_peers),
            )?;
            *guard = Some(handle);
        }
        Ok(guard.as_ref().expect("worker initialized").cmd_tx.clone())
    }

    fn send_request_once(
        &self,
        trimmed: &str,
        request: MeshWireRequest,
    ) -> Result<MeshWireResponse, MeshClientError> {
        let cmd_tx = self
            .worker_sender()
            .map_err(|e| MeshClientError::ProtocolError(e.to_string()))?;
        let timeout = self.request_timeout;
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);

        cmd_tx
            .send(SwarmCommand::SendRequest {
                peer_addr: trimmed.to_string(),
                request: Box::new(request),
                timeout,
                reply_tx,
            })
            .map_err(|_| MeshClientError::OutboundFailure {
                peer: trimmed.to_string(),
                reason: "MeshClient background Swarm worker channel closed".to_string(),
            })?;

        let res: Result<MeshWireResponse, MeshClientError> = match reply_rx.recv_timeout(timeout) {
            Ok(inner) => inner,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(MeshClientError::RequestTimedOut {
                peer: trimmed.to_string(),
                timeout,
            }),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(MeshClientError::OutboundFailure {
                peer: trimmed.to_string(),
                reason: "worker channel disconnected before response".to_string(),
            }),
        };

        match &res {
            Ok(_) => {
                if let Ok(mut dead) = self.dead_peers.lock() {
                    dead.remove(trimmed);
                }
            }
            Err(err) => {
                if err.is_peer_unreachable() {
                    if let Ok(mut dead) = self.dead_peers.lock() {
                        dead.insert(trimmed.to_string());
                    }
                }
            }
        }

        res
    }

    /// Sends a `MeshWireRequest` to `peer_addr` over the persistent background `libp2p` `Swarm`
    /// (reusing open TCP + Noise XX + Yamux connections across RPCs, and automatically healing
    /// stale DHCP IP/port endpoints when `with_data_dir_discovery` is active).
    /// Sends `request` as this client's identity. Before a request that needs an admitted sender
    /// it first presents this identity's admission credential (once per peer).
    pub fn send_request(
        &self,
        peer_addr: &str,
        request: MeshWireRequest,
    ) -> anyhow::Result<MeshWireResponse> {
        self.send_request_inner(peer_addr, request, true)
    }

    fn send_request_inner(
        &self,
        peer_addr: &str,
        request: MeshWireRequest,
        present_credential: bool,
    ) -> anyhow::Result<MeshWireResponse> {
        let trimmed = peer_addr.trim();
        if trimmed.is_empty() {
            return Err(MeshClientError::InvalidAddress("empty peer address".into()).into());
        }
        let needs_admission =
            present_credential && crate::network::admission::requires_admitted_sender(&request);
        if !needs_admission {
            return self.send_request_transport(trimmed, request);
        }
        self.ensure_admitted(trimmed);
        let key = (self.identity.public_key_bytes(), trimmed.to_string());
        let was_admitted = self
            .admitted_at
            .lock()
            .map(|s| s.contains(&key))
            .unwrap_or(false);
        let resp = self.send_request_transport(trimmed, request.clone())?;
        // A peer that admitted us before but now answers "not admitted" lost our admission (for
        // example, a restart): forget it, handshake once more, and resend once.
        if was_admitted && is_not_admitted_refusal(&resp) {
            if let Ok(mut s) = self.admitted_at.lock() {
                s.remove(&key);
            }
            self.ensure_admitted(trimmed);
            let readmitted = self
                .admitted_at
                .lock()
                .map(|s| s.contains(&key))
                .unwrap_or(false);
            if readmitted {
                return self.send_request_transport(trimmed, request);
            }
        }
        Ok(resp)
    }

    /// Sends one request over the transport, with dead-peer healing and LAN refresh.
    fn send_request_transport(
        &self,
        trimmed: &str,
        request: MeshWireRequest,
    ) -> anyhow::Result<MeshWireResponse> {
        // If `trimmed` was already marked dead and we know a newer verified endpoint for the
        // exact same `/p2p/<PeerId>`, dial the healed endpoint directly.
        if self.is_peer_marked_dead(trimmed) {
            if let Some(healed) = self.resolve_healed_peer_addr(trimmed) {
                if let Ok(resp) = self.send_request_once(&healed, request.clone()) {
                    return Ok(resp);
                }
            }
        }

        match self.send_request_once(trimmed, request.clone()) {
            Ok(resp) => Ok(resp),
            Err(err) if err.is_peer_unreachable() => {
                if let Some(healed) = self.resolve_healed_peer_addr(trimmed) {
                    if let Ok(resp) = self.send_request_once(&healed, request.clone()) {
                        return Ok(resp);
                    }
                }
                if self.maybe_refresh_lan_peers_throttled() {
                    if let Some(healed) = self.resolve_healed_peer_addr(trimmed) {
                        if let Ok(resp) = self.send_request_once(&healed, request) {
                            return Ok(resp);
                        }
                    }
                }
                Err(err.into())
            }
            Err(err) => Err(err.into()),
        }
    }

    pub fn is_peer_marked_dead(&self, peer_addr: &str) -> bool {
        self.dead_peers
            .lock()
            .map(|d| d.contains(peer_addr.trim()))
            .unwrap_or(false)
    }

    /// Queries live node status telemetry (`QueryNodeStatus` -> `NodeStatusResult`) from `peer_addr`.
    pub fn query_node_status(&self, peer_addr: &str) -> anyhow::Result<CachedNodeStatus> {
        match self.send_request(peer_addr, MeshWireRequest::QueryNodeStatus)? {
            MeshWireResponse::NodeStatusResult {
                peer_id,
                asn,
                region,
                available_bytes,
                used_bytes,
                sla_score,
                pq_kem_pubkey,
            } => Ok(CachedNodeStatus {
                peer_id,
                asn,
                region,
                available_bytes,
                used_bytes,
                sla_score,
                pq_kem_pubkey,
            }),
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to QueryNodeStatus: {other:?}"
            ))
            .into()),
        }
    }

    fn record_tracker_admin_pubkey(&self, peer_addr: &str, admin_pk: Option<[u8; 32]>) {
        let Some(pk) = admin_pk.filter(|k| *k != [0u8; 32]) else {
            return;
        };
        let key = peer_addr.trim().to_string();
        if let Ok(mut guard) = self.tracker_admin_pubkeys.lock() {
            guard.entry(key.clone()).or_insert(pk);
            if let Ok(maddr) = parse_peer_multiaddr(&key) {
                guard
                    .entry(strip_p2p_protocol(&maddr).to_string())
                    .or_insert(pk);
                if let Some(pid) = extract_expected_peer_id(&maddr) {
                    guard.entry(pid.to_string()).or_insert(pk);
                }
            }
        }
        if let Some(ref dir) = self.discovery_data_dir {
            let mut store = KnownPeersStore::load(dir);
            store.pin_tracker_admin_pubkey(&key, pk);
            let _ = store.save(dir);
        }
    }

    /// Returns all TOFU-pinned `tracker_admin_pubkey` keys learned from Public Trackers (`ADR-19`).
    pub fn pinned_tracker_admin_pubkeys(&self) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        if let Ok(guard) = self.tracker_admin_pubkeys.lock() {
            for &pk in guard.values() {
                if !out.contains(&pk) {
                    out.push(pk);
                }
            }
        }
        out
    }

    /// Returns the TOFU-pinned `tracker_admin_pubkey` for `tracker_addr`, if advertised.
    pub fn tracker_admin_pubkey_for(&self, tracker_addr: &str) -> Option<[u8; 32]> {
        let trimmed = tracker_addr.trim();
        let guard = self.tracker_admin_pubkeys.lock().ok()?;
        if let Some(&pk) = guard.get(trimmed) {
            return Some(pk);
        }
        if let Ok(maddr) = parse_peer_multiaddr(trimmed) {
            if let Some(&pk) = guard.get(&strip_p2p_protocol(&maddr).to_string()) {
                return Some(pk);
            }
            if let Some(pid) = extract_expected_peer_id(&maddr) {
                if let Some(&pk) = guard.get(&pid.to_string()) {
                    return Some(pk);
                }
            }
        }
        None
    }

    /// Registers a signed zero-knowledge WAN rendezvous entry on `peer_addr` under `slot_key`,
    /// returning the STUN-over-Noise `observed_external_addr` reflected by the remote node and
    /// automatically TOFU-pinning any advertised `tracker_admin_pubkey`.
    pub fn register_wan_rendezvous(
        &self,
        peer_addr: &str,
        slot_key: [u8; 32],
        entry: SignedWanRendezvousEntry,
    ) -> anyhow::Result<Option<String>> {
        match self.send_request(
            peer_addr,
            MeshWireRequest::RegisterWanRendezvous { slot_key, entry },
        )? {
            MeshWireResponse::RegisterWanRendezvousAck {
                stored,
                observed_external_addr,
                error,
                tracker_admin_pubkey,
            } => {
                self.record_tracker_admin_pubkey(peer_addr, tracker_admin_pubkey);
                if !stored {
                    return Err(MeshClientError::RemoteRejected {
                        peer: peer_addr.to_string(),
                        reason: format!("RegisterWanRendezvous rejected: {error:?}"),
                    }
                    .into());
                }
                Ok(observed_external_addr)
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to RegisterWanRendezvous: {other:?}"
            ))
            .into()),
        }
    }

    /// Queries all unexpired `SignedWanRendezvousEntry` records under `slot_key` from `peer_addr`,
    /// returning `(entries, observed_external_addr)` and TOFU-pinning any advertised `tracker_admin_pubkey`.
    pub fn lookup_wan_rendezvous(
        &self,
        peer_addr: &str,
        slot_key: [u8; 32],
    ) -> anyhow::Result<(Vec<SignedWanRendezvousEntry>, Option<String>)> {
        match self.send_request(peer_addr, MeshWireRequest::LookupWanRendezvous { slot_key })? {
            MeshWireResponse::LookupWanRendezvousResult {
                entries,
                observed_external_addr,
                tracker_admin_pubkey,
            } => {
                self.record_tracker_admin_pubkey(peer_addr, tracker_admin_pubkey);
                Ok((entries, observed_external_addr))
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to LookupWanRendezvous: {other:?}"
            ))
            .into()),
        }
    }

    fn ingest_verified_wan_card(&self, card: &WanPeerCard) {
        let local_pid_str = node_identity_libp2p_peer_id(&self.identity)
            .ok()
            .map(|p| p.to_string());
        if local_pid_str.as_deref() == Some(card.libp2p_peer_id.as_str()) {
            return;
        }
        let Some(first_raw) = card
            .wan_multiaddrs
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
        else {
            return;
        };
        let pinned_maddr = if first_raw.contains("/p2p/") {
            first_raw.to_string()
        } else {
            format!("{first_raw}/p2p/{}", card.libp2p_peer_id)
        };

        if let Ok(pid) = card.libp2p_peer_id.parse::<PeerId>() {
            if let Ok(mut healed) = self.healed_peer_addrs.lock() {
                healed.insert(pid, pinned_maddr.clone());
            }
        }
        if let Ok(mut dead) = self.dead_peers.lock() {
            dead.remove(&pinned_maddr);
        }
        if let Ok(mut disc) = self.discovered_peers.lock() {
            disc.insert(pinned_maddr.clone());
        }
        if let Some(ref dir) = self.discovery_data_dir {
            let mut store = KnownPeersStore::load(dir);
            store.upsert_pinned_multiaddr(
                &card.libp2p_peer_id,
                &pinned_maddr,
                Some(&card.node_label),
                Some(&card.role),
            );
            let _ = store.save(dir);
        }
    }

    fn enrich_card_with_observed_addr(
        &self,
        card: &WanPeerCard,
        observed_addr: Option<&str>,
    ) -> anyhow::Result<WanPeerCard> {
        if !card.wan_multiaddrs.is_empty() {
            return Ok(card.clone());
        }
        let Some(obs) = observed_addr.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(card.clone());
        };
        WanPeerCard::new(
            &self.identity,
            card.node_label.clone(),
            card.role.clone(),
            vec![obs.to_string()],
            card.relay_seed_addr.clone(),
            card.owner_pq_fingerprint.clone(),
            card.ttl_secs,
            wan_now_ms(),
        )
    }

    /// Zero-Pairing BitTorrent-Tracker-style Public Commons Swarm helper (`--public --tracker <ADDR>`):
    /// 1. Queries `PUBLIC_COMMONS_SWARM_SLOT` on `tracker_addr` (obtaining STUN-reflected external IP).
    /// 2. Optionally announces `card` (auto-filling `observed_external_addr` if `card.wan_multiaddrs` is empty).
    /// 3. Decrypts, verifies, and pins all discovered public swarm `WanPeerCard`s into `MeshClient`
    ///    and `known_peers.json`.
    pub fn announce_and_discover_public_tracker(
        &self,
        tracker_addr: &str,
        card: Option<&WanPeerCard>,
    ) -> anyhow::Result<Vec<WanPeerCard>> {
        let (mut entries, observed) =
            self.lookup_wan_rendezvous(tracker_addr, PUBLIC_COMMONS_SWARM_SLOT)?;

        if let Some(my_card) = card {
            let enriched = self.enrich_card_with_observed_addr(my_card, observed.as_deref())?;
            let signed_entry = seal_public_tracker_card(&enriched, &self.identity)?;
            let _ = self.register_wan_rendezvous(
                tracker_addr,
                PUBLIC_COMMONS_SWARM_SLOT,
                signed_entry,
            )?;
            if let Ok((refreshed, _)) =
                self.lookup_wan_rendezvous(tracker_addr, PUBLIC_COMMONS_SWARM_SLOT)
            {
                entries = refreshed;
            }
        }

        let local_pid = node_identity_libp2p_peer_id(&self.identity)
            .ok()
            .map(|p| p.to_string());
        let now = wan_now_ms();
        let mut peers = Vec::new();
        for entry in &entries {
            if let Ok(opened) = open_public_tracker_card(entry) {
                if !opened.is_expired(now)
                    && local_pid.as_deref() != Some(opened.libp2p_peer_id.as_str())
                {
                    self.ingest_verified_wan_card(&opened);
                    peers.push(opened);
                }
            }
        }
        Ok(peers)
    }

    /// Publishes an AEAD-sealed 4-word WAN pairing card to `anchor_addr` (auto-filling STUN-reflected
    /// external address if `card.wan_multiaddrs` is empty).
    pub fn publish_wan_pairing_card(
        &self,
        anchor_addr: &str,
        code: &str,
        card: &WanPeerCard,
    ) -> anyhow::Result<Option<String>> {
        let slot_key = derive_slot_key_from_code(code);
        let pre_observed = if card.wan_multiaddrs.is_empty() {
            self.lookup_wan_rendezvous(anchor_addr, slot_key)
                .ok()
                .and_then(|(_, obs)| obs)
        } else {
            None
        };
        let enriched = self.enrich_card_with_observed_addr(card, pre_observed.as_deref())?;
        let entry = seal_wan_peer_card(code, &enriched, &self.identity)?;
        let ack_obs = self.register_wan_rendezvous(anchor_addr, slot_key, entry)?;
        Ok(ack_obs.or(pre_observed))
    }

    /// Looks up, decrypts, verifies, and pins 4-word WAN pairing cards from `anchor_addr`.
    pub fn lookup_wan_pairing_cards(
        &self,
        anchor_addr: &str,
        code: &str,
    ) -> anyhow::Result<(Vec<WanPeerCard>, Option<String>)> {
        let slot_key = derive_slot_key_from_code(code);
        let (entries, observed) = self.lookup_wan_rendezvous(anchor_addr, slot_key)?;
        let local_pid = node_identity_libp2p_peer_id(&self.identity)
            .ok()
            .map(|p| p.to_string());
        let now = wan_now_ms();
        let mut out = Vec::new();
        for entry in &entries {
            if let Ok(card) = open_wan_peer_card(code, entry) {
                if !card.is_expired(now)
                    && local_pid.as_deref() != Some(card.libp2p_peer_id.as_str())
                {
                    self.ingest_verified_wan_card(&card);
                    out.push(card);
                }
            }
        }
        Ok((out, observed))
    }

    /// Publishes an encrypted Dynamic-IP DDNS heartbeat under `fingerprint_or_secret` to `anchor_addr`.
    pub fn publish_wan_ddns_heartbeat(
        &self,
        anchor_addr: &str,
        fingerprint_or_secret: &str,
        card: &WanPeerCard,
    ) -> anyhow::Result<Option<String>> {
        let slot_key = derive_peer_ddns_slot_key(fingerprint_or_secret);
        let pre_observed = if card.wan_multiaddrs.is_empty() {
            self.lookup_wan_rendezvous(anchor_addr, slot_key)
                .ok()
                .and_then(|(_, obs)| obs)
        } else {
            None
        };
        let enriched = self.enrich_card_with_observed_addr(card, pre_observed.as_deref())?;
        let entry = seal_ddns_heartbeat(fingerprint_or_secret, &enriched, &self.identity)?;
        let ack_obs = self.register_wan_rendezvous(anchor_addr, slot_key, entry)?;
        Ok(ack_obs.or(pre_observed))
    }

    /// Resolves encrypted Dynamic-IP DDNS heartbeats under `fingerprint_or_secret` from `anchor_addr`,
    /// automatically healing `KnownPeersStore` and `MeshClient` `PeerId` mappings across ISP IP changes.
    pub fn lookup_wan_ddns_cards(
        &self,
        anchor_addr: &str,
        fingerprint_or_secret: &str,
    ) -> anyhow::Result<Vec<WanPeerCard>> {
        let slot_key = derive_peer_ddns_slot_key(fingerprint_or_secret);
        let (entries, _) = self.lookup_wan_rendezvous(anchor_addr, slot_key)?;
        let now = wan_now_ms();
        let mut out = Vec::new();
        for entry in &entries {
            if let Ok(card) = open_ddns_heartbeat(fingerprint_or_secret, entry) {
                if !card.is_expired(now) {
                    self.ingest_verified_wan_card(&card);
                    out.push(card);
                }
            }
        }
        Ok(out)
    }

    /// Submits a cryptographically verifiable abuse takedown report (`ADR-19`) to `tracker_addr`,
    /// returning `(report_id, verified_plaintext_sha256)` once queued for Public Tracker Admin review.
    pub fn submit_abuse_takedown_report_detailed(
        &self,
        tracker_addr: &str,
        report: VerifiableAbuseReport,
    ) -> anyhow::Result<([u8; 32], Option<[u8; 32]>)> {
        match self.send_request(
            tracker_addr,
            MeshWireRequest::SubmitAbuseTakedownReport(report),
        )? {
            MeshWireResponse::SubmitAbuseTakedownAck {
                queued_for_admin_review,
                report_id,
                verified_plaintext_sha256,
                error,
            } => {
                if !queued_for_admin_review {
                    return Err(MeshClientError::RemoteRejected {
                        peer: tracker_addr.to_string(),
                        reason: format!("SubmitAbuseTakedownReport rejected: {error:?}"),
                    }
                    .into());
                }
                Ok((report_id, verified_plaintext_sha256))
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to SubmitAbuseTakedownReport: {other:?}"
            ))
            .into()),
        }
    }

    /// Submits a cryptographically verifiable abuse takedown report (`ADR-19`) to `tracker_addr`,
    /// returning the queued `report_id` when cryptographic burden-of-proof verification succeeds.
    pub fn submit_abuse_takedown_report(
        &self,
        tracker_addr: &str,
        report: VerifiableAbuseReport,
    ) -> anyhow::Result<[u8; 32]> {
        let (report_id, _) = self.submit_abuse_takedown_report_detailed(tracker_addr, report)?;
        Ok(report_id)
    }

    /// Sends a signed bad-actor or illegal-content eviction order (`ADR-19`) to `peer_addr`,
    /// returning the remote node's `EvictionPurgeReport` if accepted.
    pub fn broadcast_eviction_order(
        &self,
        peer_addr: &str,
        order: SignedBadActorEvictionOrder,
    ) -> anyhow::Result<EvictionPurgeReport> {
        match self.send_request(peer_addr, MeshWireRequest::BroadcastEvictionOrder(order))? {
            MeshWireResponse::EvictionOrderAck {
                accepted,
                purged_regular_shards,
                purged_blinded_shards,
                zero_wiped_bytes,
                error,
            } => {
                if !accepted {
                    return Err(MeshClientError::RemoteRejected {
                        peer: peer_addr.to_string(),
                        reason: format!("BroadcastEvictionOrder rejected: {error:?}"),
                    }
                    .into());
                }
                Ok(EvictionPurgeReport {
                    purged_regular_shards,
                    purged_blinded_shards,
                    zero_wiped_bytes,
                    firewall_rule_installed: true,
                })
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to BroadcastEvictionOrder: {other:?}"
            ))
            .into()),
        }
    }

    /// Propagates a `SignedBadActorEvictionOrder` across `peers` (or `self.all_network_endpoints()`
    /// when `peers` is empty), aggregating the total `EvictionPurgeReport` across all accepting nodes.
    pub fn propagate_eviction_order_to_peers(
        &self,
        peers: &[String],
        order: &SignedBadActorEvictionOrder,
    ) -> EvictionPurgeReport {
        let self_pid = node_identity_libp2p_peer_id(&self.identity).ok();
        let mut targets = Vec::new();
        let mut seen = HashSet::new();
        let push_target = |raw: &str, targets: &mut Vec<String>, seen: &mut HashSet<String>| {
            for part in raw.split(',') {
                let trimmed = part.trim();
                if trimmed.is_empty() || !is_network_peer_addr(trimmed) {
                    continue;
                }
                if let Some(local_pid) = self_pid {
                    if let Ok(m) = parse_peer_multiaddr(trimmed) {
                        if extract_expected_peer_id(&m) == Some(local_pid) {
                            continue;
                        }
                    }
                }
                if seen.insert(trimmed.to_string()) {
                    targets.push(trimmed.to_string());
                }
            }
        };

        for p in peers {
            push_target(p, &mut targets, &mut seen);
        }
        if targets.is_empty() {
            for ep in self.all_network_endpoints() {
                push_target(&ep, &mut targets, &mut seen);
            }
        }

        let mut aggregate = EvictionPurgeReport::default();
        for peer in &targets {
            match self.broadcast_eviction_order(peer, order.clone()) {
                Ok(rep) => aggregate.merge(&rep),
                Err(e) => {
                    debug!(peer = %peer, error = %e, "Eviction order propagation skipped/rejected on peer");
                }
            }
        }
        aggregate
    }

    pub fn handshake_wot(
        &self,
        peer_addr: &str,
        chain: DelegationChain,
        asn: Option<u32>,
        region: Option<String>,
    ) -> anyhow::Result<bool> {
        match self.send_request(
            peer_addr,
            MeshWireRequest::HandshakeWoT { chain, asn, region },
        )? {
            MeshWireResponse::HandshakeAck { accepted, reason } => {
                if !accepted {
                    return Err(MeshClientError::RemoteRejected {
                        peer: peer_addr.to_string(),
                        reason: format!("WoT handshake rejected: {reason:?}"),
                    }
                    .into());
                }
                Ok(true)
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to HandshakeWoT: {other:?}"
            ))
            .into()),
        }
    }

    pub fn put_shard(
        &self,
        peer_addr: &str,
        owner_peer_id: &str,
        shard_id: ShardId,
        shard_bytes: Vec<u8>,
        session_key_commit: [u8; 32],
        repair_grant: Option<RepairGrant>,
    ) -> anyhow::Result<()> {
        match self.send_request(
            peer_addr,
            MeshWireRequest::PutShard {
                owner_peer_id: owner_peer_id.to_string(),
                shard_id,
                shard_bytes,
                session_key_commit,
                repair_grant,
            },
        )? {
            MeshWireResponse::PutShardAck { stored, error } => {
                if !stored {
                    return Err(MeshClientError::RemoteRejected {
                        peer: peer_addr.to_string(),
                        reason: format!("PutShard rejected: {error:?}"),
                    }
                    .into());
                }
                Ok(())
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to PutShard: {other:?}"
            ))
            .into()),
        }
    }

    pub fn get_ciphertext_shard(
        &self,
        peer_addr: &str,
        shard_id: ShardId,
        owner_identity: Option<&NodeIdentity>,
        repair_proof: Option<(RepairGrant, Vec<WitnessFailureReceipt>)>,
    ) -> anyhow::Result<Vec<u8>> {
        let owner_signature = if let Some(owner) = owner_identity {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let (owner_pub, payload, sig) =
                PorVerifierEngine::sign_owner_shard_read_token(owner, &shard_id, now_ms);
            let (sig_r, sig_s) = split_ed25519_signature(&sig)?;
            Some((owner_pub, payload, sig_r, sig_s))
        } else {
            None
        };

        match self.send_request(
            peer_addr,
            MeshWireRequest::GetCiphertextShard {
                shard_id,
                owner_signature,
                repair_proof,
            },
        )? {
            MeshWireResponse::CiphertextShardResult { shard_bytes, error } => shard_bytes
                .ok_or_else(|| {
                    MeshClientError::RemoteRejected {
                        peer: peer_addr.to_string(),
                        reason: format!("GetCiphertextShard failed: {error:?}"),
                    }
                    .into()
                }),
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to GetCiphertextShard: {other:?}"
            ))
            .into()),
        }
    }

    pub fn put_blinded_shard(
        &self,
        peer_addr: &str,
        blinded_id: BlindedShardId,
        shard_bytes: Vec<u8>,
        capability: BlindedShardCapability,
        voucher: AnonymousQuotaVoucher,
        lease: crate::storage::BlindedLeaseSpec,
    ) -> anyhow::Result<()> {
        match self.send_request(
            peer_addr,
            MeshWireRequest::PutBlindedShard {
                blinded_id,
                shard_bytes,
                capability,
                voucher,
                current_epoch: lease.current_epoch,
                lease_duration_epochs: lease.lease_duration_epochs,
                delete_verifier: lease.delete_verifier,
            },
        )? {
            MeshWireResponse::PutBlindedShardAck { stored, error } => {
                if !stored {
                    return Err(MeshClientError::RemoteRejected {
                        peer: peer_addr.to_string(),
                        reason: format!("PutBlindedShard rejected: {error:?}"),
                    }
                    .into());
                }
                Ok(())
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to PutBlindedShard: {other:?}"
            ))
            .into()),
        }
    }

    pub fn get_blinded_shard(
        &self,
        peer_addr: &str,
        blinded_id: BlindedShardId,
        capability: BlindedShardCapability,
        timestamp_ms: u64,
        read_sig: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        match self.send_request(
            peer_addr,
            MeshWireRequest::GetBlindedShard {
                blinded_id,
                capability,
                timestamp_ms,
                read_sig,
            },
        )? {
            MeshWireResponse::BlindedShardResult { shard_bytes, error } => {
                shard_bytes.ok_or_else(|| {
                    MeshClientError::RemoteRejected {
                        peer: peer_addr.to_string(),
                        reason: format!("GetBlindedShard failed: {error:?}"),
                    }
                    .into()
                })
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to GetBlindedShard: {other:?}"
            ))
            .into()),
        }
    }

    pub fn renew_blinded_lease(
        &self,
        peer_addr: &str,
        blinded_id: BlindedShardId,
        current_epoch: u64,
        extension_epochs: u64,
    ) -> anyhow::Result<bool> {
        match self.send_request(
            peer_addr,
            MeshWireRequest::RenewBlindedLease {
                blinded_id,
                current_epoch,
                extension_epochs,
            },
        )? {
            MeshWireResponse::RenewBlindedLeaseAck { renewed } => Ok(renewed),
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to RenewBlindedLease: {other:?}"
            ))
            .into()),
        }
    }

    /// Deletes a blinded shard on `peer_addr` with a delete signed by its capability key for
    /// that host (F-41). `peer_addr` must carry `/p2p/<PeerId>` (the host binding).
    pub fn delete_blinded_shard_signed(
        &self,
        peer_addr: &str,
        cap_identity: &NodeIdentity,
        blinded_id: BlindedShardId,
    ) -> anyhow::Result<bool> {
        let host = crate::config::NodeConfig::extract_ed25519_pubkey_from_peer_str(peer_addr)
            .ok_or_else(|| anyhow::anyhow!("a blinded delete needs a /p2p/ host address"))?;
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let sig =
            BlindedShardCapability::sign_delete(cap_identity, &host, &blinded_id, timestamp_ms);
        match self.send_request(
            peer_addr,
            MeshWireRequest::DeleteBlindedShardSigned {
                blinded_id,
                timestamp_ms,
                sig: sig.to_vec(),
            },
        )? {
            MeshWireResponse::DeleteBlindedShardAck { deleted, .. } => Ok(deleted),
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to DeleteBlindedShardSigned: {other:?}"
            ))
            .into()),
        }
    }

    pub fn delete_shard(
        &self,
        peer_addr: &str,
        shard_id: ShardId,
        owner: &NodeIdentity,
    ) -> anyhow::Result<bool> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let (owner_pub, payload, sig) =
            PorVerifierEngine::sign_owner_shard_delete_token(owner, &shard_id, now_ms);
        let (sig_r, sig_s) = split_ed25519_signature(&sig)?;
        match self.send_request(
            peer_addr,
            MeshWireRequest::DeleteShard {
                shard_id,
                owner_signature: (owner_pub, payload, sig_r, sig_s),
            },
        )? {
            MeshWireResponse::DeleteShardAck { deleted, error } => {
                if !deleted {
                    return Err(MeshClientError::RemoteRejected {
                        peer: peer_addr.to_string(),
                        reason: format!("DeleteShard failed: {error:?}"),
                    }
                    .into());
                }
                Ok(true)
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to DeleteShard: {other:?}"
            ))
            .into()),
        }
    }

    pub fn por_audit(
        &self,
        peer_addr: &str,
        challenge: PorChallenge,
    ) -> anyhow::Result<PorResponse> {
        match self.send_request(peer_addr, MeshWireRequest::PorAudit(challenge))? {
            MeshWireResponse::PorAuditResult(Some(resp)) => Ok(resp),
            MeshWireResponse::PorAuditResult(None) => Err(MeshClientError::RemoteRejected {
                peer: peer_addr.to_string(),
                reason: "PorAudit rejected".to_string(),
            }
            .into()),
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to PorAudit: {other:?}"
            ))
            .into()),
        }
    }

    pub fn multi_segment_por_audit(
        &self,
        peer_addr: &str,
        challenge: MultiSegmentPorChallenge,
    ) -> anyhow::Result<PorResponse> {
        match self.send_request(peer_addr, MeshWireRequest::MultiSegmentPorAudit(challenge))? {
            MeshWireResponse::MultiSegmentPorAuditResult(Some(resp)) => Ok(resp),
            MeshWireResponse::MultiSegmentPorAuditResult(None) => {
                Err(MeshClientError::RemoteRejected {
                    peer: peer_addr.to_string(),
                    reason: "MultiSegmentPorAudit rejected".to_string(),
                }
                .into())
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to MultiSegmentPorAudit: {other:?}"
            ))
            .into()),
        }
    }

    /// A relay's forward of an onion envelope to its next hop, sent as this node (admitted). Used
    /// by the wire handler for the last hop; originators use [`OnionOriginator`].
    pub fn relay_pq_onion_envelope(
        &self,
        relay_peer_addr: &str,
        target_peer_addr: Option<String>,
        envelope: PqRelayedShardEnvelope,
        capability: BlindedShardCapability,
        voucher: AnonymousQuotaVoucher,
        lease: crate::storage::BlindedLeaseSpec,
    ) -> anyhow::Result<()> {
        self.send_onion(
            relay_peer_addr,
            OnionSend {
                target_peer_addr,
                envelope,
                capability,
                voucher,
                lease,
            },
            true,
        )
    }

    fn send_onion(
        &self,
        relay_peer_addr: &str,
        onion: OnionSend,
        present_credential: bool,
    ) -> anyhow::Result<()> {
        let OnionSend {
            target_peer_addr,
            envelope,
            capability,
            voucher,
            lease,
        } = onion;
        match self.send_request_inner(
            relay_peer_addr,
            MeshWireRequest::RelayPqOnionEnvelope {
                target_peer_addr,
                envelope,
                capability,
                voucher,
                current_epoch: lease.current_epoch,
                lease_duration_epochs: lease.lease_duration_epochs,
                delete_verifier: lease.delete_verifier,
            },
            present_credential,
        )? {
            MeshWireResponse::RelayPqOnionAck { delivered, error } => {
                if !delivered {
                    return Err(MeshClientError::RemoteRejected {
                        peer: relay_peer_addr.to_string(),
                        reason: format!("RelayPqOnionEnvelope failed: {error:?}"),
                    }
                    .into());
                }
                Ok(())
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to RelayPqOnionEnvelope: {other:?}"
            ))
            .into()),
        }
    }

    /// Sends a 2-layer Post-Quantum Onion Envelope (`PqRelayedShardEnvelope::seal_layered_pq`)
    /// to an entry relay node (`C6`). Neither `target_peer_addr` nor the real `capability`/`voucher`
    /// is exposed on the wire: the relay peels the outer `X25519 + ML-KEM-768` layer to learn only
    /// the next-hop address, and the destination node opens the inner layer to recover the full
    /// `PqOnionFinalBundle`.
    pub fn relay_layered_pq_onion_envelope(
        &self,
        relay_peer_addr: &str,
        outer_envelope: PqRelayedShardEnvelope,
    ) -> anyhow::Result<()> {
        self.send_layered_onion(relay_peer_addr, outer_envelope, true)
    }

    fn send_layered_onion(
        &self,
        relay_peer_addr: &str,
        outer_envelope: PqRelayedShardEnvelope,
        present_credential: bool,
    ) -> anyhow::Result<()> {
        let dummy_capability = BlindedShardCapability {
            locator: [0u8; 32],
            capability_pubkey: [0u8; 32],
        };
        let dummy_voucher = AnonymousQuotaVoucher {
            voucher_nonce: [0u8; 32],
            max_bytes: 0,
            issuer_pubkey: [0u8; 32],
            sig_r: [0u8; 32],
            sig_s: [0u8; 32],
            expires_at_ms: 0,
        };
        self.send_onion(
            relay_peer_addr,
            OnionSend {
                target_peer_addr: None,
                envelope: outer_envelope,
                capability: dummy_capability,
                voucher: dummy_voucher,
                lease: crate::storage::BlindedLeaseSpec::new(0, 0, [0u8; 32]),
            },
            present_credential,
        )
    }

    pub fn syndicate_lite_stripe(
        &self,
        seed_addr: &str,
        cert: PersonalDeviceCert,
        bundle: LiteStripeSyndicationBundle,
    ) -> anyhow::Result<LiteSyndicationReceipt> {
        let (receipt, _) = self.syndicate_lite_stripe_with_grant(seed_addr, cert, bundle, None)?;
        Ok(receipt)
    }

    pub fn syndicate_lite_stripe_with_grant(
        &self,
        seed_addr: &str,
        cert: PersonalDeviceCert,
        bundle: LiteStripeSyndicationBundle,
        repair_grant: Option<RepairGrant>,
    ) -> anyhow::Result<(LiteSyndicationReceipt, Vec<String>)> {
        match self.send_request(
            seed_addr,
            MeshWireRequest::SyndicateLiteStripe {
                cert,
                bundle,
                repair_grant,
            },
        )? {
            MeshWireResponse::SyndicateLiteStripeAck {
                receipt,
                syndicated_peers,
                error,
            } => {
                let r = receipt.ok_or_else(|| MeshClientError::RemoteRejected {
                    peer: seed_addr.to_string(),
                    reason: format!("SyndicateLiteStripe rejected: {error:?}"),
                })?;
                Ok((r, syndicated_peers))
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to SyndicateLiteStripe: {other:?}"
            ))
            .into()),
        }
    }

    /// Publishes a `DhtWireEnvelope` into the persistent Kademlia DHT and replicates it across all
    /// configured mesh peers (and `seed_addr`), returning the count of peers that persisted the record.
    pub fn put_dht_envelope(&self, envelope: DhtWireEnvelope) -> anyhow::Result<usize> {
        let endpoints = self.all_network_endpoints();
        if endpoints.is_empty() {
            anyhow::bail!("no network peers configured for PutDhtEnvelope");
        }
        let mut stored_count = 0usize;
        let mut last_err = None;
        for ep in &endpoints {
            match self.send_request(ep, MeshWireRequest::PutDhtEnvelope(envelope.clone())) {
                Ok(MeshWireResponse::PutDhtEnvelopeAck { stored: true, .. }) => {
                    stored_count += 1;
                }
                Ok(MeshWireResponse::PutDhtEnvelopeAck {
                    stored: false,
                    error,
                }) => {
                    last_err = Some(
                        MeshClientError::RemoteRejected {
                            peer: ep.clone(),
                            reason: format!("PutDhtEnvelope rejected: {error:?}"),
                        }
                        .into(),
                    );
                }
                Ok(other) => {
                    last_err = Some(
                        MeshClientError::ProtocolError(format!(
                            "unexpected PutDhtEnvelope reply: {other:?}"
                        ))
                        .into(),
                    );
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        if stored_count == 0 && self.maybe_refresh_lan_peers_throttled() {
            for ep in self.all_network_endpoints() {
                if let Ok(MeshWireResponse::PutDhtEnvelopeAck { stored: true, .. }) =
                    self.send_request(&ep, MeshWireRequest::PutDhtEnvelope(envelope.clone()))
                {
                    stored_count += 1;
                }
            }
        }
        if stored_count == 0 {
            return Err(
                last_err.unwrap_or_else(|| anyhow::anyhow!("PutDhtEnvelope failed on all peers"))
            );
        }
        Ok(stored_count)
    }

    fn validate_dht_candidate(
        &self,
        dht_key: &[u8; 32],
        kind: DhtEnvelopeKind,
        env: &DhtWireEnvelope,
    ) -> Option<u64> {
        let version = Self::self_consistent_version(dht_key, kind, env)?;
        // F-10a: classical manifests and vault catalogs are sealed by the identity that reads
        // them back; a self-consistent envelope signed by anyone else is a squat. A post-quantum
        // manifest has no owner binding yet, so it is refused (PQ-DHT, fail closed).
        let owner = match env {
            DhtWireEnvelope::ClassicalManifest(m) => Some(m.owner_pubkey),
            DhtWireEnvelope::VaultCatalog(m) => Some(m.owner_pubkey),
            DhtWireEnvelope::PostQuantumManifest(_) => None,
        };
        if let Err(code) = dht_candidate_decision(owner, self.identity.public_key_bytes()) {
            warn!(
                code,
                owner = %owner.map(hex::encode).unwrap_or_default(),
                "ignored a DHT envelope not bound to this owner"
            );
            return None;
        }
        Some(version)
    }

    /// The monotonic version of `env` if it is a self-consistent envelope of `kind` at `dht_key`
    /// (key match and owner signature), else `None`.
    pub(crate) fn self_consistent_version(
        dht_key: &[u8; 32],
        kind: DhtEnvelopeKind,
        env: &DhtWireEnvelope,
    ) -> Option<u64> {
        match (kind, env) {
            (DhtEnvelopeKind::ClassicalManifest, DhtWireEnvelope::ClassicalManifest(m))
                if m.dht_key == *dht_key && m.verify_zero_knowledge() =>
            {
                Some(m.monotonic_version)
            }
            (DhtEnvelopeKind::PostQuantumManifest, DhtWireEnvelope::PostQuantumManifest(m))
                if m.dht_key == *dht_key && m.verify_zero_knowledge_pq() =>
            {
                Some(m.monotonic_version)
            }
            (DhtEnvelopeKind::VaultCatalog, DhtWireEnvelope::VaultCatalog(m))
                if m.dht_key == *dht_key && m.verify_zero_knowledge() =>
            {
                Some(m.monotonic_version)
            }
            _ => None,
        }
    }

    /// Queries both the persistent Kademlia DHT and configured mesh peers (and `seed_addr`) for a
    /// `DhtWireEnvelope` by `dht_key`, verifies zero-knowledge signature integrity on every
    /// candidate, and returns the highest `monotonic_version` (`C3`).
    pub fn get_dht_envelope(
        &self,
        dht_key: &[u8; 32],
        kind: DhtEnvelopeKind,
    ) -> anyhow::Result<DhtWireEnvelope> {
        let endpoints = self.all_network_endpoints();
        if endpoints.is_empty() {
            anyhow::bail!("no network peers configured for GetDhtEnvelope");
        }
        let mut best: Option<(u64, DhtWireEnvelope)> = None;

        // 1. Query the persistent Kademlia DHT store & routing table (`C3`).
        if let Ok(cmd_tx) = self.worker_sender() {
            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            if cmd_tx
                .send(SwarmCommand::GetKadRecord {
                    dht_key: *dht_key,
                    reply_tx,
                })
                .is_ok()
            {
                let kad_wait = self.request_timeout.min(Duration::from_millis(350));
                if let Ok(raw_records) = reply_rx.recv_timeout(kad_wait) {
                    for raw in raw_records {
                        if let Ok(env) = bincode::deserialize::<DhtWireEnvelope>(&raw) {
                            if let Some(ver) = self.validate_dht_candidate(dht_key, kind, &env) {
                                if best.as_ref().is_none_or(|(best_v, _)| ver > *best_v) {
                                    best = Some((ver, env));
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Query storage daemons' disk-persisted ZeroTrustDhtStore over `/parvault/wire/1.0.0`.
        for ep in &endpoints {
            if self.is_peer_marked_dead(ep) && self.resolve_healed_peer_addr(ep).is_none() {
                continue;
            }
            if let Ok(MeshWireResponse::GetDhtEnvelopeResult {
                envelope: Some(env),
                ..
            }) = self.send_request(
                ep,
                MeshWireRequest::GetDhtEnvelope {
                    dht_key: *dht_key,
                    kind,
                },
            ) {
                if let Some(ver) = self.validate_dht_candidate(dht_key, kind, &env) {
                    if best.as_ref().is_none_or(|(best_v, _)| ver > *best_v) {
                        best = Some((ver, env));
                    }
                }
            }
        }

        if best.is_none() && self.maybe_refresh_lan_peers_throttled() {
            for ep in self.all_network_endpoints() {
                if let Ok(MeshWireResponse::GetDhtEnvelopeResult {
                    envelope: Some(env),
                    ..
                }) = self.send_request(
                    &ep,
                    MeshWireRequest::GetDhtEnvelope {
                        dht_key: *dht_key,
                        kind,
                    },
                ) {
                    if let Some(ver) = self.validate_dht_candidate(dht_key, kind, &env) {
                        if best.as_ref().is_none_or(|(best_v, _)| ver > *best_v) {
                            best = Some((ver, env));
                        }
                    }
                }
            }
        }

        best.map(|(_, env)| env)
            .ok_or_else(|| anyhow::anyhow!("DHT envelope not found on any reachable mesh peer"))
    }

    /// Distributes all `N` shards of an encoded stripe across the configured network peers via `PutShard`,
    /// ordering peers through `PlacementEngine` (ADR-06 70/30 Intra-ASN / Cross-Region placement) using
    /// real measured RTTs, OS routing-table local IP discovery, and verified `PeerId` Kademlia hashes (`C5`).
    ///
    /// Registers an owner-signed `RepairGrant` with every storage peer so subsequent authenticated
    /// owner reads (`GetCiphertextShard`) and PoR audits succeed across restarts. When the physical
    /// peer count `P < N`, shards are replicated across shifted fault domains (`(idx + shift) % P`)
    /// so that correlated multi-shard losses on a single node cannot reduce surviving shards below `K` (`C12`).
    pub fn distribute_stripe_shards(
        &self,
        owner_identity: &NodeIdentity,
        owner_peer_id: &str,
        shard_set: &StripeShardSet,
        tier: ErasureTier,
        session_key: [u8; 32],
    ) -> anyhow::Result<Vec<String>> {
        let placed = self.distribute_stripe_shards_partial(
            owner_identity,
            owner_peer_id,
            shard_set,
            tier,
            session_key,
        )?;
        placed
            .into_iter()
            .enumerate()
            .map(|(idx, peer)| {
                peer.ok_or_else(|| {
                    anyhow::anyhow!("failed to store shard {idx} on any reachable mesh peer")
                })
            })
            .collect()
    }

    /// Like [`Self::distribute_stripe_shards`], but a shard no peer accepted is `None` instead of
    /// failing the stripe, so the caller keeps the shards already placed on peers (QA 2e M2).
    pub fn distribute_stripe_shards_partial(
        &self,
        owner_identity: &NodeIdentity,
        owner_peer_id: &str,
        shard_set: &StripeShardSet,
        tier: ErasureTier,
        session_key: [u8; 32],
    ) -> anyhow::Result<Vec<Option<String>>> {
        let raw_peers = if !self.peers.is_empty() && self.discovery_data_dir.is_none() {
            self.peers
                .iter()
                .map(|p| {
                    self.resolve_healed_peer_addr(p)
                        .unwrap_or_else(|| p.clone())
                })
                .collect()
        } else {
            self.all_network_endpoints()
        };
        if raw_peers.is_empty() {
            anyhow::bail!("no network peers configured for shard distribution");
        }

        let effective_owner_peer_id =
            if owner_peer_id.is_empty() || owner_peer_id == "local" || owner_peer_id == "self" {
                owner_identity.device_peer_id()
            } else {
                owner_peer_id.to_string()
            };

        // Filter out peers currently marked dead for primary topology selection (`C11`),
        // falling back to all configured peers only if every peer was previously marked dead.
        let live_candidates: Vec<String> = raw_peers
            .iter()
            .filter(|p| !self.is_peer_marked_dead(p))
            .cloned()
            .collect();
        let placement_candidates = if !live_candidates.is_empty() {
            &live_candidates
        } else {
            &raw_peers
        };

        // Build candidate PeerTopologyMetrics from real measured RTT, verified PeerId, and cached status (`C5`).
        let topos: Vec<PeerTopologyMetrics> = placement_candidates
            .iter()
            .map(|addr| {
                let parsed_maddr = parse_peer_multiaddr(addr).ok();
                let ip = parsed_maddr
                    .as_ref()
                    .and_then(extract_ip_from_multiaddr)
                    .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

                let kad_id_hash = if let Some(pid) = self.pinned_peer_id(addr) {
                    compute_sha256(&pid.to_bytes())
                } else {
                    compute_sha256(addr.as_bytes())
                };

                let cached_status = self.peer_status_cache.lock().ok().and_then(|cache| {
                    cache.get(addr.trim()).cloned().or_else(|| {
                        parsed_maddr
                            .as_ref()
                            .and_then(|m| cache.get(&strip_p2p_protocol(m).to_string()).cloned())
                    })
                });

                let asn = cached_status
                    .as_ref()
                    .map(|s| s.asn)
                    .unwrap_or_else(|| classify_ip_asn(ip, None));
                let region = cached_status
                    .as_ref()
                    .map(|s| s.region.clone())
                    .unwrap_or_else(|| format!("asn-{asn}"));
                let sla_score = cached_status.as_ref().map(|s| s.sla_score).unwrap_or(0.999);
                let available_bytes = cached_status
                    .as_ref()
                    .map(|s| s.available_bytes)
                    .unwrap_or(10 * 1024 * 1024 * 1024);

                let rtt_ms = self.measured_rtt_ms(addr).unwrap_or_else(|| {
                    if ip.is_loopback() || ip.is_private_or_lan_heuristic() {
                        2.0
                    } else {
                        25.0
                    }
                });

                PeerTopologyMetrics {
                    peer_id: addr.clone(),
                    kad_id_hash,
                    ip_addr: ip,
                    rtt_ms,
                    asn,
                    region,
                    sla_score,
                    available_bytes,
                }
            })
            .collect();

        let reference_peer_ip = topos
            .first()
            .map(|t| t.ip_addr)
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let local_ip = detect_local_ip_for_peer(reference_peer_ip);
        let local_asn = classify_ip_asn(local_ip, None);
        let placement =
            PlacementEngine::new(local_ip, local_asn, format!("asn-{local_asn}"), 5.0, 0.70);
        let plan = placement.select_target_peers(
            &shard_set.stripe_merkle_root,
            shard_set.k_data,
            shard_set.shards.len(),
            shard_set.shard_len as u64,
            &topos,
        );

        let primary_peers: Vec<String> = if !plan.selected_peers.is_empty() {
            plan.selected_peers.into_iter().map(|p| p.peer_id).collect()
        } else {
            placement_candidates.clone()
        };
        let standby_peers: Vec<String> = raw_peers
            .iter()
            .filter(|p| !primary_peers.contains(p))
            .cloned()
            .collect();

        let grant = RepairGrant::issue(
            owner_identity,
            shard_set.stripe_merkle_root,
            vec![owner_identity.public_key_bytes()],
            tier,
        );

        let num_peers = primary_peers.len();
        let n_total = shard_set.shards.len();
        let mut assigned_peers = Vec::with_capacity(n_total);

        // When the physical peer count P is smaller than the stripe width N, each node hosts
        // multiple shards (ceil(N / P)). Compute the fault-domain shift factor so correlated
        // multi-shard loss from offline nodes cannot drop surviving shards below K (`C12`).
        let shards_per_peer = n_total.div_ceil(num_peers);
        let replica_shifts =
            if num_peers < n_total && shard_set.k_data * shards_per_peer > num_peers {
                (shards_per_peer + 1).min(num_peers)
            } else {
                1usize
            };

        for (idx, shard_bytes) in shard_set.shards.iter().enumerate() {
            let shard_id = ShardId {
                stripe_merkle_root: shard_set.stripe_merkle_root,
                shard_index: idx as u32,
                shard_hash: shard_set.shard_hashes[idx],
            };

            let mut primary_peer = None;
            for shift in 0..replica_shifts {
                let peer_addr = &primary_peers[(idx + shift) % num_peers];
                if self.is_peer_marked_dead(peer_addr) {
                    continue;
                }
                if self
                    .put_shard(
                        peer_addr,
                        &effective_owner_peer_id,
                        shard_id,
                        shard_bytes.clone(),
                        session_key,
                        Some(grant.clone()),
                    )
                    .is_ok()
                    && primary_peer.is_none()
                {
                    primary_peer = Some(peer_addr.clone());
                }
            }

            // Failover pass 1: try any remaining live primary or standby peers (`C5`, `C11`).
            if primary_peer.is_none() {
                for peer_addr in primary_peers.iter().chain(standby_peers.iter()) {
                    if self.is_peer_marked_dead(peer_addr) {
                        continue;
                    }
                    if self
                        .put_shard(
                            peer_addr,
                            &effective_owner_peer_id,
                            shard_id,
                            shard_bytes.clone(),
                            session_key,
                            Some(grant.clone()),
                        )
                        .is_ok()
                    {
                        primary_peer = Some(peer_addr.clone());
                        break;
                    }
                }
            }

            // Failover pass 2: if all live peers failed, retry peers previously marked dead.
            if primary_peer.is_none() {
                for peer_addr in &raw_peers {
                    if self
                        .put_shard(
                            peer_addr,
                            &effective_owner_peer_id,
                            shard_id,
                            shard_bytes.clone(),
                            session_key,
                            Some(grant.clone()),
                        )
                        .is_ok()
                    {
                        primary_peer = Some(peer_addr.clone());
                        break;
                    }
                }
            }

            // Also syndicate to `seed_addr` if configured as a network Multiaddr
            if let Some(ref seed) = self.seed_addr {
                if is_network_peer_addr(seed) {
                    let _ = self.put_shard(
                        seed,
                        &effective_owner_peer_id,
                        shard_id,
                        shard_bytes.clone(),
                        session_key,
                        Some(grant.clone()),
                    );
                }
            }

            assigned_peers.push(primary_peer);
        }

        Ok(assigned_peers)
    }

    /// Fetches at least `stripe.k_data` surviving shards for `stripe` across `stripe.assigned_peers`
    /// and fallback `self.all_network_endpoints()`, tolerating offline/killed storage containers.
    pub fn fetch_stripe_shards(
        &self,
        stripe: &StripeManifestEntry,
        owner_identity: &NodeIdentity,
    ) -> Vec<Option<Vec<u8>>> {
        let total_shards = stripe.k_data + stripe.m_parity;
        let mut shard_slots: Vec<Option<Vec<u8>>> = vec![None; total_shards];
        let mut dead_peers: HashSet<String> = HashSet::new();
        let mut collected = 0usize;

        let fallback_endpoints = self.all_network_endpoints();

        for idx in 0..total_shards {
            if collected >= stripe.k_data {
                break;
            }
            let shard_id = ShardId {
                stripe_merkle_root: stripe.stripe_merkle_root,
                shard_index: idx as u32,
                shard_hash: stripe.shard_hashes[idx],
            };

            let mut candidate_addrs: Vec<String> = Vec::new();
            if let Some(assigned) = stripe.assigned_peers.get(idx) {
                if let Some(healed) = self.resolve_healed_peer_addr(assigned) {
                    if !dead_peers.contains(&healed) && !self.is_peer_marked_dead(&healed) {
                        candidate_addrs.push(healed);
                    }
                }
                if is_network_peer_addr(assigned)
                    && !dead_peers.contains(assigned)
                    && !self.is_peer_marked_dead(assigned)
                    && !candidate_addrs.contains(assigned)
                {
                    candidate_addrs.push(assigned.clone());
                }
            }
            let current_fallbacks = if self.discovery_data_dir.is_some() {
                self.all_network_endpoints()
            } else {
                fallback_endpoints.clone()
            };
            if !current_fallbacks.is_empty() {
                let n_ep = current_fallbacks.len();
                for shift in 0..n_ep {
                    let ep = &current_fallbacks[(idx + shift) % n_ep];
                    if !dead_peers.contains(ep)
                        && !self.is_peer_marked_dead(ep)
                        && !candidate_addrs.contains(ep)
                    {
                        candidate_addrs.push(ep.clone());
                    }
                }
            }

            for addr in candidate_addrs {
                match self.get_ciphertext_shard(&addr, shard_id, Some(owner_identity), None) {
                    Ok(bytes) => {
                        if crate::sharding::hash_shard_leaf(idx as u32, &bytes)
                            == stripe.shard_hashes[idx]
                        {
                            shard_slots[idx] = Some(bytes);
                            collected += 1;
                            break;
                        } else {
                            warn!(
                                peer = %addr,
                                shard_index = idx,
                                "Fetched ciphertext shard failed Merkle leaf hash verification"
                            );
                        }
                    }
                    Err(e) => {
                        debug!(
                            peer = %addr,
                            shard_index = idx,
                            error = %e,
                            "Failed to fetch ciphertext shard from candidate peer"
                        );
                        if e.downcast_ref::<MeshClientError>()
                            .is_some_and(|me| me.is_peer_unreachable())
                        {
                            dead_peers.insert(addr);
                        }
                    }
                }
            }
        }

        shard_slots
    }
}

trait IpLocalityExt {
    fn is_private_or_lan_heuristic(&self) -> bool;
}

impl IpLocalityExt for IpAddr {
    fn is_private_or_lan_heuristic(&self) -> bool {
        match self {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PQ-DHT: an owner that cannot be bound is refused; the F-10a binding is unchanged.
    #[test]
    fn dht_candidate_decision_fails_closed_on_unbindable_owner() {
        let me = [7u8; 32];
        assert_eq!(dht_candidate_decision(Some(me), me), Ok(()));
        assert_eq!(
            dht_candidate_decision(Some([8u8; 32]), me),
            Err("reject.dht_owner_mismatch")
        );
        assert_eq!(
            dht_candidate_decision(None, me),
            Err("reject.dht_owner_unbindable")
        );
    }

    #[test]
    fn test_parse_peer_multiaddr_preserves_p2p_peer_id() {
        let kp = NodeIdentity::generate()
            .to_libp2p_keypair()
            .expect("keypair");
        let pid = kp.public().to_peer_id();
        let raw = format!("/ip4/127.0.0.1/tcp/4001/p2p/{pid}");
        let maddr = parse_peer_multiaddr(&raw).expect("valid multiaddr");
        assert_eq!(extract_expected_peer_id(&maddr), Some(pid));
        assert_eq!(
            strip_p2p_protocol(&maddr).to_string(),
            "/ip4/127.0.0.1/tcp/4001"
        );

        let dns_raw = format!("/dns4/localhost/tcp/4001/p2p/{pid}");
        let dns_maddr = parse_peer_multiaddr(&dns_raw).expect("valid dns multiaddr");
        assert_eq!(extract_expected_peer_id(&dns_maddr), Some(pid));
    }

    #[test]
    fn test_tofu_peer_id_pinning_rejects_impersonator() {
        let kp1 = NodeIdentity::generate()
            .to_libp2p_keypair()
            .expect("keypair 1");
        let kp2 = NodeIdentity::generate()
            .to_libp2p_keypair()
            .expect("keypair 2");
        let pid1 = kp1.public().to_peer_id();
        let pid2 = kp2.public().to_peer_id();

        let pinned_map = Arc::new(Mutex::new(HashMap::new()));
        let base_maddr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();

        // First connection pins pid1 via TOFU
        assert!(
            verify_and_pin_peer_id("127.0.0.1:4001", &base_maddr, None, pid1, &pinned_map).is_ok()
        );

        // Subsequent connection with same PeerId succeeds
        assert!(
            verify_and_pin_peer_id("127.0.0.1:4001", &base_maddr, None, pid1, &pinned_map).is_ok()
        );

        // Subsequent connection with different PeerId is rejected with PeerIdMismatch
        let err = verify_and_pin_peer_id("127.0.0.1:4001", &base_maddr, None, pid2, &pinned_map)
            .expect_err("impersonator must be rejected");
        assert!(matches!(err, MeshClientError::PeerIdMismatch { .. }));
        assert!(err.is_peer_unreachable());
    }

    #[test]
    fn test_tracker_admin_pubkey_tofu_pinning_and_persistence() {
        let tmp = std::env::temp_dir().join(format!(
            "parvault-tracker-tofu-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).expect("create temp dir");

        let tracker_id = NodeIdentity::generate();
        let tracker_pid = node_identity_libp2p_peer_id(&tracker_id).expect("tracker peer id");
        let tracker_addr = format!("/ip4/198.51.100.10/tcp/4010/p2p/{tracker_pid}");
        let official_admin_pk = NodeIdentity::generate().public_key_bytes();
        let spoofed_admin_pk = NodeIdentity::generate().public_key_bytes();

        let client = MeshClient::new(NodeIdentity::generate(), Vec::new(), None)
            .with_data_dir_discovery(tmp.clone(), DEFAULT_LAN_DISCOVERY_PORT);

        // Zeroed key is ignored
        client.record_tracker_admin_pubkey(&tracker_addr, Some([0u8; 32]));
        assert!(client.pinned_tracker_admin_pubkeys().is_empty());

        // First valid advertisement pins via TOFU and persists to known_peers.json
        client.record_tracker_admin_pubkey(&tracker_addr, Some(official_admin_pk));
        assert_eq!(
            client.tracker_admin_pubkey_for(&tracker_addr),
            Some(official_admin_pk)
        );
        assert_eq!(
            client.tracker_admin_pubkey_for("/ip4/198.51.100.10/tcp/4010"),
            Some(official_admin_pk)
        );
        assert_eq!(
            client.pinned_tracker_admin_pubkeys(),
            vec![official_admin_pk]
        );

        // Spoofed rotation attempt is rejected by TOFU pin
        client.record_tracker_admin_pubkey(&tracker_addr, Some(spoofed_admin_pk));
        assert_eq!(
            client.tracker_admin_pubkey_for(&tracker_addr),
            Some(official_admin_pk)
        );

        // Reloading from data_dir restores pinned tracker_admin_pubkey automatically
        let reloaded = MeshClient::new(NodeIdentity::generate(), Vec::new(), None)
            .with_data_dir_discovery(tmp.clone(), DEFAULT_LAN_DISCOVERY_PORT);
        assert_eq!(
            reloaded.tracker_admin_pubkey_for(&tracker_addr),
            Some(official_admin_pk)
        );
        assert_eq!(
            reloaded.pinned_tracker_admin_pubkeys(),
            vec![official_admin_pk]
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
