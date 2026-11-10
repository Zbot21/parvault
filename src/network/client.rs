use crate::bootstrap::{
    BlindedShardTombstone, LiteStripeSyndicationBundle, LiteSyndicationReceipt, PersonalDeviceCert,
};
use crate::config::ErasureTier;
use crate::crypto::{compute_sha256, NodeIdentity, PqRelayedShardEnvelope};
use crate::network::behaviour::{
    classify_ip_asn, DhtEnvelopeKind, DhtWireEnvelope, MeshNetworkBehaviourEvent, MeshWireRequest,
    MeshWireResponse, PeerTopologyMetrics, PlacementEngine,
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
    kad,
    request_response::{self, Message},
    swarm::SwarmEvent,
    Multiaddr,
};
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Parses a peer address string into a dialable `libp2p::Multiaddr`.
/// Accepts:
/// - Standard Multiaddrs (`/ip4/10.42.1.11/tcp/4001`, `/ip6/::1/tcp/4001`)
/// - DNS Multiaddrs (`/dns4/parvault-seed/tcp/4002`, `/dns/node1/tcp/4001`), resolving hostnames to IP
/// - Socket strings (`10.42.1.11:4001`, `parvault-seed:4002`, `localhost:4001`)
pub fn parse_peer_multiaddr(raw: &str) -> anyhow::Result<Multiaddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty peer address");
    }

    if trimmed.starts_with("/dns4/")
        || trimmed.starts_with("/dns/")
        || trimmed.starts_with("/dns6/")
    {
        let parts: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() >= 4 && parts[2] == "tcp" {
            let host = parts[1];
            let port: u16 = parts[3].parse()?;
            if let Ok(mut addrs) = (host, port).to_socket_addrs() {
                if let Some(sock) = addrs.next() {
                    return match sock.ip() {
                        std::net::IpAddr::V4(v4) => Ok(format!("/ip4/{v4}/tcp/{port}").parse()?),
                        std::net::IpAddr::V6(v6) => Ok(format!("/ip6/{v6}/tcp/{port}").parse()?),
                    };
                }
            }
        }
    }

    if trimmed.starts_with('/') {
        return Ok(trimmed.parse()?);
    }

    // Handle `host:port` or `ip:port`
    if let Ok(mut addrs) = trimmed.to_socket_addrs() {
        if let Some(sock) = addrs.next() {
            return match sock.ip() {
                std::net::IpAddr::V4(v4) => Ok(format!("/ip4/{v4}/tcp/{}", sock.port()).parse()?),
                std::net::IpAddr::V6(v6) => Ok(format!("/ip6/{v6}/tcp/{}", sock.port()).parse()?),
            };
        }
    }

    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() == 2 {
        let ip = parts[0];
        let port = parts[1];
        return Ok(format!("/ip4/{ip}/tcp/{port}").parse()?);
    }

    anyhow::bail!("unable to parse peer address '{trimmed}' as Multiaddr or host:port")
}

/// Checks whether a string looks like a network `Multiaddr` or `host:port` (as opposed to a local filesystem path).
pub fn is_network_peer_addr(raw: &str) -> bool {
    let s = raw.trim();
    if s.starts_with("/ip4/")
        || s.starts_with("/ip6/")
        || s.starts_with("/dns4/")
        || s.starts_with("/dns/")
    {
        return true;
    }
    // Check `host:port` where port is a valid u16 and not a Windows drive letter like `C:\...`
    if let Some((left, right)) = s.rsplit_once(':') {
        if left.len() > 1 && !right.contains('/') && !right.contains('\\') {
            if right.parse::<u16>().is_ok() {
                return true;
            }
        }
    }
    false
}

/// Live `libp2p` Mesh Client (TCP + Noise XX + Yamux + Kademlia DHT + `/parvault/wire/1.0.0`).
#[derive(Clone, Debug)]
pub struct MeshClient {
    identity: NodeIdentity,
    peers: Vec<String>,
    seed_addr: Option<String>,
    request_timeout: Duration,
    dead_peers: Arc<Mutex<HashSet<String>>>,
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
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn with_identity(&self, identity: NodeIdentity) -> Self {
        let mut cloned = self.clone();
        cloned.identity = identity;
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

    /// Returns all candidate network endpoints (`peers` + `seed_addr` if it is a network address).
    pub fn all_network_endpoints(&self) -> Vec<String> {
        let mut out = self.peers.clone();
        if let Some(ref seed) = self.seed_addr {
            if is_network_peer_addr(seed) && !out.contains(seed) {
                out.push(seed.clone());
            }
        }
        out
    }

    /// Sends a single `MeshWireRequest` to `peer_addr` over `libp2p` (TCP + Noise XX + Yamux)
    /// using a dedicated background runtime thread so it can be called safely from both sync and async contexts.
    pub fn send_request(
        &self,
        peer_addr: &str,
        request: MeshWireRequest,
    ) -> anyhow::Result<MeshWireResponse> {
        let maddr = parse_peer_multiaddr(peer_addr)?;
        let identity = self.identity.clone();
        let timeout = self.request_timeout;

        let res = std::thread::scope(|s| {
            s.spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(async move {
                    Self::send_request_async(&identity, maddr, request, timeout).await
                })
            })
            .join()
            .map_err(|_| anyhow::anyhow!("MeshClient worker thread panicked"))?
        });

        match &res {
            Ok(_) => {
                if let Ok(mut dead) = self.dead_peers.lock() {
                    dead.remove(peer_addr);
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("failed to connect") || msg.contains("timed out") {
                    if let Ok(mut dead) = self.dead_peers.lock() {
                        dead.insert(peer_addr.to_string());
                    }
                }
            }
        }
        res
    }

    pub fn is_peer_marked_dead(&self, peer_addr: &str) -> bool {
        self.dead_peers
            .lock()
            .map(|d| d.contains(peer_addr))
            .unwrap_or(false)
    }

    async fn send_request_async(
        identity: &NodeIdentity,
        target_maddr: Multiaddr,
        request: MeshWireRequest,
        timeout: Duration,
    ) -> anyhow::Result<MeshWireResponse> {
        let keypair = identity.to_libp2p_keypair()?;
        let mut swarm = build_mesh_client_swarm(keypair, false)?;
        swarm.dial(target_maddr.clone())?;

        let fut = async {
            let mut target_req_id = None;
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    } => {
                        if target_req_id.is_none() {
                            swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, endpoint.get_remote_address().clone());
                            if let MeshWireRequest::PutDhtEnvelope(ref env) = request {
                                let (dht_key, bytes) = match env {
                                    DhtWireEnvelope::ClassicalManifest(m) => {
                                        (m.dht_key, bincode::serialize(env).unwrap_or_default())
                                    }
                                    DhtWireEnvelope::PostQuantumManifest(m) => {
                                        (m.dht_key, bincode::serialize(env).unwrap_or_default())
                                    }
                                    DhtWireEnvelope::VaultCatalog(m) => {
                                        (m.dht_key, bincode::serialize(env).unwrap_or_default())
                                    }
                                };
                                let record = kad::Record {
                                    key: kad::RecordKey::new(&dht_key),
                                    value: bytes,
                                    publisher: Some(peer_id),
                                    expires: None,
                                };
                                let _ = swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .put_record(record, kad::Quorum::One);
                            }
                            let req_id = swarm
                                .behaviour_mut()
                                .req_resp
                                .send_request(&peer_id, request.clone());
                            target_req_id = Some(req_id);
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        if target_req_id.is_none() {
                            anyhow::bail!("failed to connect to {target_maddr}: {error}");
                        }
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
                        if Some(request_id) == target_req_id {
                            return Ok(response);
                        }
                    }
                    SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::ReqResp(
                        request_response::Event::OutboundFailure {
                            request_id, error, ..
                        },
                    )) => {
                        if Some(request_id) == target_req_id {
                            anyhow::bail!("wire request failed to {target_maddr}: {error:?}");
                        }
                    }
                    _ => {}
                }
            }
        };

        tokio::time::timeout(timeout, fut).await.map_err(|_| {
            anyhow::anyhow!(
                "wire request timed out after {:?} to {target_maddr}",
                timeout
            )
        })?
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
                    anyhow::bail!("WoT handshake rejected by {peer_addr}: {reason:?}");
                }
                Ok(true)
            }
            other => anyhow::bail!("unexpected response to HandshakeWoT: {other:?}"),
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
                    anyhow::bail!("PutShard rejected by {peer_addr}: {error:?}");
                }
                Ok(())
            }
            other => anyhow::bail!("unexpected response to PutShard: {other:?}"),
        }
    }

    pub fn get_ciphertext_shard(
        &self,
        peer_addr: &str,
        shard_id: ShardId,
        owner_identity: Option<&NodeIdentity>,
        repair_proof: Option<(RepairGrant, Vec<WitnessFailureReceipt>)>,
    ) -> anyhow::Result<Vec<u8>> {
        let owner_signature = owner_identity.map(|owner| {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let (owner_pub, payload, sig) =
                PorVerifierEngine::sign_owner_shard_read_token(owner, &shard_id, now_ms);
            let mut sig_r = [0u8; 32];
            let mut sig_s = [0u8; 32];
            sig_r.copy_from_slice(&sig[..32]);
            sig_s.copy_from_slice(&sig[32..]);
            (owner_pub, payload, sig_r, sig_s)
        });

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
                    anyhow::anyhow!("GetCiphertextShard failed on {peer_addr}: {error:?}")
                }),
            other => anyhow::bail!("unexpected response to GetCiphertextShard: {other:?}"),
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
                    anyhow::bail!("PutBlindedShard rejected by {peer_addr}: {error:?}");
                }
                Ok(())
            }
            other => anyhow::bail!("unexpected response to PutBlindedShard: {other:?}"),
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
            MeshWireResponse::BlindedShardResult { shard_bytes, error } => shard_bytes
                .ok_or_else(|| anyhow::anyhow!("GetBlindedShard failed on {peer_addr}: {error:?}")),
            other => anyhow::bail!("unexpected response to GetBlindedShard: {other:?}"),
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
            other => anyhow::bail!("unexpected response to RenewBlindedLease: {other:?}"),
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
                    anyhow::bail!("DeleteBlindedShardTombstone failed on {peer_addr}: {error:?}");
                }
                Ok(true)
            }
            other => anyhow::bail!("unexpected response to DeleteBlindedShardTombstone: {other:?}"),
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
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);
        match self.send_request(
            peer_addr,
            MeshWireRequest::DeleteShard {
                shard_id,
                owner_signature: (owner_pub, payload, sig_r, sig_s),
            },
        )? {
            MeshWireResponse::DeleteShardAck { deleted, error } => {
                if !deleted {
                    anyhow::bail!("DeleteShard failed on {peer_addr}: {error:?}");
                }
                Ok(true)
            }
            other => anyhow::bail!("unexpected response to DeleteShard: {other:?}"),
        }
    }

    pub fn por_audit(
        &self,
        peer_addr: &str,
        challenge: PorChallenge,
    ) -> anyhow::Result<PorResponse> {
        match self.send_request(peer_addr, MeshWireRequest::PorAudit(challenge))? {
            MeshWireResponse::PorAuditResult(Some(resp)) => Ok(resp),
            MeshWireResponse::PorAuditResult(None) => {
                anyhow::bail!("PorAudit rejected by {peer_addr}")
            }
            other => anyhow::bail!("unexpected response to PorAudit: {other:?}"),
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
                anyhow::bail!("MultiSegmentPorAudit rejected by {peer_addr}")
            }
            other => anyhow::bail!("unexpected response to MultiSegmentPorAudit: {other:?}"),
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
                    anyhow::bail!("RelayPqOnionEnvelope failed on {relay_peer_addr}: {error:?}");
                }
                Ok(())
            }
            other => anyhow::bail!("unexpected response to RelayPqOnionEnvelope: {other:?}"),
        }
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
                let r = receipt.ok_or_else(|| {
                    anyhow::anyhow!("SyndicateLiteStripe rejected by {seed_addr}: {error:?}")
                })?;
                Ok((r, syndicated_peers))
            }
            other => anyhow::bail!("unexpected response to SyndicateLiteStripe: {other:?}"),
        }
    }

    /// Publishes a `DhtWireEnvelope` across all configured mesh peers (and `seed_addr`),
    /// returning the count of peers that accepted and persisted the record.
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
                    last_err = Some(anyhow::anyhow!(
                        "PutDhtEnvelope rejected by {ep}: {error:?}"
                    ));
                }
                Ok(other) => {
                    last_err = Some(anyhow::anyhow!(
                        "unexpected PutDhtEnvelope reply: {other:?}"
                    ));
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

    /// Queries all configured mesh peers (and `seed_addr`) for a `DhtWireEnvelope` by `dht_key`,
    /// verifies zero-knowledge signature integrity on every candidate, and returns the highest
    /// monotonic version.
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
                let valid_ver = match &env {
                    DhtWireEnvelope::ClassicalManifest(m)
                        if m.dht_key == *dht_key && m.verify_zero_knowledge() =>
                    {
                        Some(m.monotonic_version)
                    }
                    DhtWireEnvelope::PostQuantumManifest(m)
                        if m.dht_key == *dht_key && m.verify_zero_knowledge_pq() =>
                    {
                        Some(m.monotonic_version)
                    }
                    DhtWireEnvelope::VaultCatalog(m)
                        if m.dht_key == *dht_key && m.verify_zero_knowledge() =>
                    {
                        Some(m.monotonic_version)
                    }
                    _ => None,
                };
                if let Some(ver) = valid_ver {
                    if best.as_ref().map_or(true, |(best_v, _)| ver > *best_v) {
                        best = Some((ver, env));
                    }
                }
            }
        }
        best.map(|(_, env)| env)
            .ok_or_else(|| anyhow::anyhow!("DHT envelope not found on any reachable mesh peer"))
    }

    /// Distributes all `N` shards of an encoded stripe across the configured network peers via `PutShard`,
    /// ordering peers through `PlacementEngine` (70/30 Intra-ASN / Cross-Region placement) and
    /// registering an owner-signed `RepairGrant` with every storage peer so subsequent authenticated
    /// owner reads (`GetCiphertextShard`) and PoR audits succeed across restarts.
    ///
    /// When the cluster has fewer physical peers than `N` (e.g., 10 daemon nodes for a 20-shard stripe),
    /// shards are also mirrored to shifted backup peers (`(idx + 1) % P`, `(idx + 2) % P`) and `seed_addr`
    /// so that even if 4 of 10 storage nodes are hard-killed (`docker kill`), the remaining 6 nodes
    /// retain `>= K` distinct shards for both `Consumer` (10-of-20) and `Homelab` (16-of-20) tiers.
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

        // Rank candidate peers via PlacementEngine (ADR-06 70/30 Intra-ASN / Cross-Region policy)
        let topos: Vec<PeerTopologyMetrics> = raw_peers
            .iter()
            .map(|addr| {
                let ip = parse_peer_multiaddr(addr)
                    .ok()
                    .and_then(|m| {
                        let s = m.to_string();
                        s.split('/').nth(2)?.parse::<std::net::IpAddr>().ok()
                    })
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
                let asn = classify_ip_asn(ip, None);
                PeerTopologyMetrics {
                    peer_id: addr.clone(),
                    kad_id_hash: compute_sha256(addr.as_bytes()),
                    ip_addr: ip,
                    rtt_ms: 2.0,
                    asn,
                    region: format!("asn-{asn}"),
                    sla_score: 0.999,
                    available_bytes: 10 * 1024 * 1024 * 1024,
                }
            })
            .collect();
        let local_ip = topos
            .first()
            .map(|t| t.ip_addr)
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
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
        let mut peers: Vec<String> = plan.selected_peers.into_iter().map(|p| p.peer_id).collect();
        for p in raw_peers {
            if !peers.contains(&p) {
                peers.push(p);
            }
        }

        let grant = RepairGrant::issue(
            owner_identity,
            shard_set.stripe_merkle_root,
            vec![owner_identity.public_key_bytes()],
            tier,
        );

        let num_peers = peers.len();
        let n_total = shard_set.shards.len();
        let mut assigned_peers = Vec::with_capacity(n_total);

        // Determine how many shifted peers per shard are needed when `num_peers < n_total`
        // so that losing 40% of nodes (e.g. 4 of 10 containers) leaves >= K distinct shards.
        let replica_shifts = if num_peers < n_total && shard_set.k_data > (num_peers * 6) / 10 {
            3usize.min(num_peers)
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
                let peer_addr = &peers[(idx + shift) % num_peers];
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

            // If primary shifts failed because a peer was down during upload, try any live peer
            if primary_peer.is_none() {
                for peer_addr in &peers {
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
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("failed to connect") || msg.contains("timed out") {
                            dead_peers.insert(addr);
                        }
                    }
                }
            }
        }

        shard_slots
    }
}
