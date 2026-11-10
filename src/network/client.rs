use crate::bootstrap::{
    BlindedShardTombstone, LiteStripeSyndicationBundle, LiteSyndicationReceipt, PersonalDeviceCert,
};
use crate::config::ErasureTier;
use crate::crypto::{compute_sha256, HybridKemPublicKey, NodeIdentity, PqRelayedShardEnvelope};
use crate::network::behaviour::{
    classify_ip_asn, DhtEnvelopeKind, DhtWireEnvelope, MeshNetworkBehaviour,
    MeshNetworkBehaviourEvent, MeshWireRequest, MeshWireResponse, PeerTopologyMetrics,
    PlacementEngine,
};
use crate::network::transport::build_mesh_client_swarm;
use crate::network::wot::DelegationChain;
use crate::por::{
    MultiSegmentPorChallenge, PorChallenge, PorResponse, PorVerifierEngine, RepairGrant,
    WitnessFailureReceipt,
};
use crate::sharding::StripeShardSet;
use crate::storage::{
    AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, ShardId, StripeManifestEntry,
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

#[allow(clippy::large_enum_variant)]
enum SwarmCommand {
    SendRequest {
        peer_addr: String,
        request: MeshWireRequest,
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

#[allow(clippy::too_many_arguments)]
fn dispatch_rpc_on_established_peer(
    swarm: &mut Swarm<MeshNetworkBehaviour>,
    peer_id: PeerId,
    peer_addr_raw: String,
    base_maddr: Multiaddr,
    expected_peer_id: Option<PeerId>,
    request: MeshWireRequest,
    was_warm_reuse: bool,
    started_at: Instant,
    timeout: Duration,
    reply_tx: mpsc::SyncSender<Result<MeshWireResponse, MeshClientError>>,
    inflight_requests: &mut HashMap<OutboundRequestId, InflightRpc>,
) {
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
                                                peer_id,
                                                peer_addr,
                                                base_maddr,
                                                expected_peer_id,
                                                request,
                                                true,
                                                started_at,
                                                timeout,
                                                reply_tx,
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
                                                            peer_id,
                                                            pending.peer_addr_raw,
                                                            pending.base_maddr,
                                                            pending.expected_peer_id,
                                                            pending.request,
                                                            false,
                                                            pending.started_at,
                                                            pending.timeout,
                                                            pending.reply_tx,
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
#[derive(Clone, Debug)]
pub struct MeshClient {
    identity: NodeIdentity,
    peers: Vec<String>,
    seed_addr: Option<String>,
    request_timeout: Duration,
    dead_peers: Arc<Mutex<HashSet<String>>>,
    pinned_peers: Arc<Mutex<HashMap<String, PeerId>>>,
    peer_rtt_ms: Arc<Mutex<HashMap<String, f64>>>,
    peer_status_cache: Arc<Mutex<HashMap<String, CachedNodeStatus>>>,
    discovered_peers: Arc<Mutex<HashSet<String>>>,
    worker: Arc<Mutex<Option<SwarmWorkerHandle>>>,
}

impl MeshClient {
    pub fn new(identity: NodeIdentity, peers: Vec<String>, seed_addr: Option<String>) -> Self {
        let mut normalized_peers = Vec::new();
        let mut seen = HashSet::new();
        for p in peers {
            for item in p.split(',') {
                let t = item.trim();
                if !t.is_empty() && seen.insert(t.to_string()) {
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
            dead_peers: Arc::new(Mutex::new(HashSet::new())),
            pinned_peers: Arc::new(Mutex::new(HashMap::new())),
            peer_rtt_ms: Arc::new(Mutex::new(HashMap::new())),
            peer_status_cache: Arc::new(Mutex::new(HashMap::new())),
            discovered_peers: Arc::new(Mutex::new(HashSet::new())),
            worker: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
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
    /// discovered peers when no static `peers` list is configured).
    pub fn all_network_endpoints(&self) -> Vec<String> {
        let mut out = if !self.peers.is_empty() {
            self.peers.clone()
        } else {
            self.discovered_peers()
        };
        if let Some(ref seed) = self.seed_addr {
            if is_network_peer_addr(seed) && !out.contains(seed) {
                out.push(seed.clone());
            }
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

    /// Sends a `MeshWireRequest` to `peer_addr` over the persistent background `libp2p` `Swarm`
    /// (reusing open TCP + Noise XX + Yamux connections across RPCs).
    pub fn send_request(
        &self,
        peer_addr: &str,
        request: MeshWireRequest,
    ) -> anyhow::Result<MeshWireResponse> {
        let trimmed = peer_addr.trim();
        if trimmed.is_empty() {
            return Err(MeshClientError::InvalidAddress("empty peer address".into()).into());
        }

        let cmd_tx = self.worker_sender()?;
        let timeout = self.request_timeout;
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);

        cmd_tx
            .send(SwarmCommand::SendRequest {
                peer_addr: trimmed.to_string(),
                request,
                timeout,
                reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("MeshClient background Swarm worker channel closed"))?;

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

        res.map_err(Into::into)
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

    #[allow(clippy::too_many_arguments)]
    pub fn put_blinded_shard(
        &self,
        peer_addr: &str,
        blinded_id: BlindedShardId,
        shard_bytes: Vec<u8>,
        capability: BlindedShardCapability,
        voucher: AnonymousQuotaVoucher,
        current_epoch: u64,
        lease_duration_epochs: u64,
        delete_verifier: [u8; 32],
    ) -> anyhow::Result<()> {
        match self.send_request(
            peer_addr,
            MeshWireRequest::PutBlindedShard {
                blinded_id,
                shard_bytes,
                capability,
                voucher,
                current_epoch,
                lease_duration_epochs,
                delete_verifier,
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

    pub fn delete_blinded_shard_tombstone(
        &self,
        peer_addr: &str,
        blinded_id: BlindedShardId,
        tombstone: BlindedShardTombstone,
    ) -> anyhow::Result<bool> {
        match self.send_request(
            peer_addr,
            MeshWireRequest::DeleteBlindedShardTombstone {
                blinded_id,
                tombstone,
            },
        )? {
            MeshWireResponse::DeleteBlindedShardAck { deleted, error } => {
                if !deleted {
                    return Err(MeshClientError::RemoteRejected {
                        peer: peer_addr.to_string(),
                        reason: format!("DeleteBlindedShardTombstone failed: {error:?}"),
                    }
                    .into());
                }
                Ok(true)
            }
            other => Err(MeshClientError::ProtocolError(format!(
                "unexpected response to DeleteBlindedShardTombstone: {other:?}"
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

    #[allow(clippy::too_many_arguments)]
    pub fn relay_pq_onion_envelope(
        &self,
        relay_peer_addr: &str,
        target_peer_addr: Option<String>,
        envelope: PqRelayedShardEnvelope,
        capability: BlindedShardCapability,
        voucher: AnonymousQuotaVoucher,
        current_epoch: u64,
        lease_duration_epochs: u64,
        delete_verifier: [u8; 32],
    ) -> anyhow::Result<()> {
        match self.send_request(
            relay_peer_addr,
            MeshWireRequest::RelayPqOnionEnvelope {
                target_peer_addr,
                envelope,
                capability,
                voucher,
                current_epoch,
                lease_duration_epochs,
                delete_verifier,
            },
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
        };
        self.relay_pq_onion_envelope(
            relay_peer_addr,
            None,
            outer_envelope,
            dummy_capability,
            dummy_voucher,
            0,
            0,
            [0u8; 32],
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
        if stored_count == 0 {
            return Err(
                last_err.unwrap_or_else(|| anyhow::anyhow!("PutDhtEnvelope failed on all peers"))
            );
        }
        Ok(stored_count)
    }

    fn validate_dht_candidate(
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
                            if let Some(ver) = Self::validate_dht_candidate(dht_key, kind, &env) {
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
            if self.is_peer_marked_dead(ep) {
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
                if let Some(ver) = Self::validate_dht_candidate(dht_key, kind, &env) {
                    if best.as_ref().is_none_or(|(best_v, _)| ver > *best_v) {
                        best = Some((ver, env));
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
        let raw_peers = if !self.peers.is_empty() {
            self.peers.clone()
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

            let chosen = primary_peer.ok_or_else(|| {
                anyhow::anyhow!("failed to store shard {idx} on any reachable mesh peer")
            })?;
            assigned_peers.push(chosen);
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
                if is_network_peer_addr(assigned)
                    && !dead_peers.contains(assigned)
                    && !self.is_peer_marked_dead(assigned)
                {
                    candidate_addrs.push(assigned.clone());
                }
            }
            if !fallback_endpoints.is_empty() {
                let n_ep = fallback_endpoints.len();
                for shift in 0..n_ep {
                    let ep = &fallback_endpoints[(idx + shift) % n_ep];
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
}
