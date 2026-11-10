use crate::bootstrap::{
    BlindedShardTombstone, LiteStripeSyndicationBundle, LiteSyndicationReceipt, PersonalDeviceCert,
};
use crate::crypto::{PqRelayedShardEnvelope, PqSignedDhtManifestEnvelope};
use crate::network::wot::{DelegationChain, SlashingEvidence};
use crate::por::{
    MultiSegmentPorChallenge, PorChallenge, PorResponse, RepairGrant, WitnessFailureReceipt,
};
use crate::sharding::merkle::Hash32;
use crate::storage::{
    AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, ShardId,
    SignedDhtManifestEnvelope,
};
use crate::sync::EncryptedVaultCatalogEnvelope;
use libp2p::{
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    gossipsub, identify, kad, mdns, ping, request_response,
    swarm::NetworkBehaviour,
    StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maximum wire protocol frame size (32 MiB) so 1.6 MiB shards (from 16 MiB stripes per ADR-01)
/// stream natively with zero fragmentation.
pub const MAX_WIRE_FRAME_BYTES: usize = 32 * 1024 * 1024;

/// High-speed zero-expansion `bincode` wire codec for `/parvault/wire/1.0.0`.
#[derive(Debug, Clone)]
pub struct BincodeWireCodec {
    pub max_frame_bytes: usize,
}

impl Default for BincodeWireCodec {
    fn default() -> Self {
        Self {
            max_frame_bytes: MAX_WIRE_FRAME_BYTES,
        }
    }
}

use bincode::Options;

impl BincodeWireCodec {
    fn bincode_options(limit: usize) -> impl bincode::Options {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(limit as u64)
    }

    /// Bounded wire-frame deserializer (`ADR-15` Pre-Auth Heap OOM Bomb Defense):
    /// Caps `bincode`'s internal allocation budget (`Vec::with_capacity`) to `buf.len()`
    /// so a 16-byte malicious frame claiming a `Vec<u8>` of length `u64::MAX` is rejected
    /// immediately with `io::ErrorKind::InvalidData` instead of crashing the daemon with OOM.
    pub fn deserialize_request_bounded(&self, buf: &[u8]) -> io::Result<MeshWireRequest> {
        if buf.len() > self.max_frame_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "wire request length {} exceeds max {}",
                    buf.len(),
                    self.max_frame_bytes
                ),
            ));
        }
        Self::bincode_options(buf.len())
            .deserialize(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn deserialize_response_bounded(&self, buf: &[u8]) -> io::Result<MeshWireResponse> {
        if buf.len() > self.max_frame_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "wire response length {} exceeds max {}",
                    buf.len(),
                    self.max_frame_bytes
                ),
            ));
        }
        Self::bincode_options(buf.len())
            .deserialize(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_bounded_frame<T>(&self, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 8];
        io.read_exact(&mut len_buf).await?;
        let raw_len = u64::from_be_bytes(len_buf);
        let len = usize::try_from(raw_len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "wire frame length overflows usize",
            )
        })?;
        if len > self.max_frame_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "wire frame length {len} exceeds max {}",
                    self.max_frame_bytes
                ),
            ));
        }
        // Cap initial buffer reservation at 64 KiB so Slowloris connections cannot pin 32 MiB upfront
        let mut buf = Vec::with_capacity(len.min(64 * 1024));
        let mut limited = io.take(len as u64);
        let n = limited.read_to_end(&mut buf).await?;
        if n != len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("expected {len} bytes in wire frame, got {n}"),
            ));
        }
        Ok(buf)
    }
}

#[async_trait::async_trait]
impl request_response::Codec for BincodeWireCodec {
    type Protocol = StreamProtocol;
    type Request = MeshWireRequest;
    type Response = MeshWireResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = self.read_bounded_frame(io).await?;
        self.deserialize_request_bounded(&buf)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = self.read_bounded_frame(io).await?;
        self.deserialize_response_bounded(&buf)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = Self::bincode_options(self.max_frame_bytes)
            .serialize(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if bytes.len() > self.max_frame_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized request exceeds max_frame_bytes",
            ));
        }
        let len = bytes.len() as u64;
        io.write_all(&len.to_be_bytes()).await?;
        io.write_all(&bytes).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = Self::bincode_options(self.max_frame_bytes)
            .serialize(&resp)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if bytes.len() > self.max_frame_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized response exceeds max_frame_bytes",
            ));
        }
        let len = bytes.len() as u64;
        io.write_all(&len.to_be_bytes()).await?;
        io.write_all(&bytes).await?;
        io.close().await
    }
}

/// Discriminator for Kademlia DHT envelope queries over `/parvault/wire/1.0.0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhtEnvelopeKind {
    ClassicalManifest,
    PostQuantumManifest,
    VaultCatalog,
}

/// Unified zero-knowledge DHT envelope payload exchanged over `PutDhtEnvelope` / `GetDhtEnvelope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhtWireEnvelope {
    ClassicalManifest(SignedDhtManifestEnvelope),
    PostQuantumManifest(PqSignedDhtManifestEnvelope),
    VaultCatalog(EncryptedVaultCatalogEnvelope),
}

/// Wire-level request messages exchanged over `/parvault/wire/1.0.0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshWireRequest {
    /// Exchange Web-of-Trust delegation chain and topology metadata.
    HandshakeWoT {
        chain: DelegationChain,
        asn: Option<u32>,
        region: Option<String>,
    },
    /// Store an encrypted Reed-Solomon shard on a target peer.
    PutShard {
        owner_peer_id: String,
        shard_id: ShardId,
        shard_bytes: Vec<u8>,
        session_key_commit: [u8; 32],
        repair_grant: Option<RepairGrant>,
    },
    /// Issue a stateless Proof of Retrievability (PoR) byte-range challenge (ADR-03).
    PorAudit(PorChallenge),
    /// Fetch a full ciphertext shard for file restore or authenticated witness repair (ADR-04).
    /// `owner_signature` explicitly carries `(owner_pub, signed_payload, sig_r, sig_s)`.
    GetCiphertextShard {
        shard_id: ShardId,
        owner_signature: Option<([u8; 32], Vec<u8>, [u8; 32], [u8; 32])>,
        repair_proof: Option<(RepairGrant, Vec<WitnessFailureReceipt>)>,
    },
    /// Phase 2-4: Store an anonymized `BlindedShardId` with a single-use `AnonymousQuotaVoucher` and Byte-Epoch lease.
    PutBlindedShard {
        blinded_id: BlindedShardId,
        shard_bytes: Vec<u8>,
        capability: BlindedShardCapability,
        voucher: AnonymousQuotaVoucher,
        current_epoch: u64,
        lease_duration_epochs: u64,
        delete_verifier: [u8; 32],
    },
    /// Phase 2-4: Fetch an anonymized `BlindedShardId` using a per-locator capability signature.
    GetBlindedShard {
        blinded_id: BlindedShardId,
        capability: BlindedShardCapability,
        timestamp_ms: u64,
        read_sig: Vec<u8>,
    },
    /// Phase 2-4: Renew the Byte-Epoch lease on an anonymized `BlindedShardId`.
    RenewBlindedLease {
        blinded_id: BlindedShardId,
        current_epoch: u64,
        extension_epochs: u64,
    },
    /// Phase 2-4: Reclaim disk space immediately via a pre-image `BlindedShardTombstone`.
    DeleteBlindedShardTombstone {
        blinded_id: BlindedShardId,
        tombstone: BlindedShardTombstone,
    },
    /// Phase 2-4: Issue a stratified `MultiSegmentPorChallenge` (anti-partial-retention & anti-WAN-proxy).
    MultiSegmentPorAudit(MultiSegmentPorChallenge),
    /// Phase 2-4: Relay or deliver a Post-Quantum 1-Hop Onion Envelope (`X25519 + ML-KEM-768`).
    RelayPqOnionEnvelope {
        target_peer_addr: Option<String>,
        envelope: PqRelayedShardEnvelope,
        capability: BlindedShardCapability,
        voucher: AnonymousQuotaVoucher,
        current_epoch: u64,
        lease_duration_epochs: u64,
        delete_verifier: [u8; 32],
    },
    /// Phase 2-4: Syndicate a Lite-Client stripe bundle through a personal seed using a `PersonalDeviceCert`.
    SyndicateLiteStripe {
        cert: PersonalDeviceCert,
        bundle: LiteStripeSyndicationBundle,
        repair_grant: Option<RepairGrant>,
    },
    /// Phase 2-4: Publish a signed monotonic DHT manifest or disaster-recovery vault catalog envelope.
    PutDhtEnvelope(DhtWireEnvelope),
    /// Phase 2-4: Fetch a signed monotonic DHT manifest or disaster-recovery vault catalog envelope by `dht_key`.
    GetDhtEnvelope {
        dht_key: [u8; 32],
        kind: DhtEnvelopeKind,
    },
    /// Delete an unblinded ciphertext shard using an owner-signed `"parvault-owner-shard-delete-v1:"` token.
    DeleteShard {
        shard_id: ShardId,
        owner_signature: ([u8; 32], Vec<u8>, [u8; 32], [u8; 32]),
    },
}

/// Wire-level response messages exchanged over `/parvault/wire/1.0.0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshWireResponse {
    HandshakeAck {
        accepted: bool,
        reason: Option<String>,
    },
    PutShardAck {
        stored: bool,
        error: Option<String>,
    },
    PorAuditResult(Option<PorResponse>),
    CiphertextShardResult {
        shard_bytes: Option<Vec<u8>>,
        error: Option<String>,
    },
    SlashingBroadcast(SlashingEvidence),
    PutBlindedShardAck {
        stored: bool,
        error: Option<String>,
    },
    BlindedShardResult {
        shard_bytes: Option<Vec<u8>>,
        error: Option<String>,
    },
    RenewBlindedLeaseAck {
        renewed: bool,
    },
    DeleteBlindedShardAck {
        deleted: bool,
        error: Option<String>,
    },
    MultiSegmentPorAuditResult(Option<PorResponse>),
    RelayPqOnionAck {
        delivered: bool,
        error: Option<String>,
    },
    SyndicateLiteStripeAck {
        receipt: Option<LiteSyndicationReceipt>,
        syndicated_peers: Vec<String>,
        error: Option<String>,
    },
    PutDhtEnvelopeAck {
        stored: bool,
        error: Option<String>,
    },
    GetDhtEnvelopeResult {
        envelope: Option<DhtWireEnvelope>,
        error: Option<String>,
    },
    DeleteShardAck {
        deleted: bool,
        error: Option<String>,
    },
}

/// Composite libp2p `NetworkBehaviour` combining Kademlia DHT, Gossipsub, mDNS, Ping, Identify,
/// and Bincode Request-Response streams (`network::behaviour`).
#[derive(NetworkBehaviour)]
pub struct MeshNetworkBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: libp2p::swarm::behaviour::toggle::Toggle<mdns::tokio::Behaviour>,
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub req_resp: request_response::Behaviour<BincodeWireCodec>,
}

/// Network topology & latency profile for a candidate storage peer (ADR-06).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerTopologyMetrics {
    pub peer_id: String,
    pub kad_id_hash: Hash32,
    pub ip_addr: IpAddr,
    pub rtt_ms: f64,
    pub asn: u32,
    pub region: String,
    pub sla_score: f64,
    pub available_bytes: u64,
}

/// Checks `/24` IPv4 subnet prefix equality for local ISP loop affinity (ADR-06).
pub const fn ipv4_same_slash24(a: Ipv4Addr, b: Ipv4Addr) -> bool {
    let ao = a.octets();
    let bo = b.octets();
    ao[0] == bo[0] && ao[1] == bo[1] && ao[2] == bo[2]
}

/// Checks `/48` IPv6 subnet prefix equality for local ISP loop affinity (ADR-06).
pub const fn ipv6_same_slash48(a: Ipv6Addr, b: Ipv6Addr) -> bool {
    let asg = a.segments();
    let bsg = b.segments();
    asg[0] == bsg[0] && asg[1] == bsg[1] && asg[2] == bsg[2]
}

/// Checks whether `ip` is a globally routable unicast IP address suitable for public Kademlia DHT
/// routing tables (`ADR-15` Bogon / Loopback / RFC1918 / CGNAT Poisoning Filter).
pub const fn is_routable_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let is_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64;
            let is_benchmark = o[0] == 198 && (o[1] == 18 || o[1] == 19);
            !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !is_cgnat
                && !is_benchmark
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let is_ula = (s[0] & 0xfe00) == 0xfc00;
            let is_link_local = (s[0] & 0xffc0) == 0xfe80;
            let is_doc = s[0] == 0x2001 && s[1] == 0x0db8;
            !v6.is_loopback()
                && !v6.is_multicast()
                && !v6.is_unspecified()
                && !is_ula
                && !is_link_local
                && !is_doc
        }
    }
}

/// Embedded compact offline IP-to-ASN classifier with deterministic private subnet mapping
/// for Docker (`10.42.0.0/16`) and Shadow simulations (ADR-06 / ADR-15).
pub fn classify_ip_asn(ip: IpAddr, override_asn: Option<u32>) -> u32 {
    if let Some(asn) = override_asn {
        return asn;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // Deterministic subnet-to-ASN mapping for 10.42.X.0/24 validation meshes
            if o[0] == 10 && o[1] == 42 {
                return 64512 + (o[2] as u32);
            }
            let is_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64;
            if v4.is_loopback() || v4.is_private() || v4.is_link_local() || is_cgnat {
                return 64512;
            }
            // Compact prefix bucket for public IPv4 ranges when no override is configured
            ((o[0] as u32) << 8) | (o[1] as u32)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return 64512;
            }
            let s = v6.segments();
            // Use /32 LIR allocation prefix (top 32 bits) so distinct /48s inside one ISP/VPS share ASN bucket
            65000 + ((((s[0] as u32) << 16) | (s[1] as u32)) % 10_000)
        }
    }
}

/// Computes the RTT-weighted effective Kademlia distance metric:
/// `D_effective = D_XOR * RTT_weight`
/// where sub-5ms peers receive a priority multiplier (`<= 1.0`) and high-latency links are penalized.
pub fn effective_kademlia_distance(
    target_key: &Hash32,
    peer_kad_hash: &Hash32,
    rtt_ms: f64,
    local_rtt_ceiling_ms: f64,
) -> f64 {
    // Extract top 64 bits of XOR distance normalized to [0.0, 1.0].
    let mut xor_top64: u64 = 0;
    for i in 0..8 {
        xor_top64 = (xor_top64 << 8) | ((target_key[i] ^ peer_kad_hash[i]) as u64);
    }
    let d_xor = (xor_top64 as f64) / (u64::MAX as f64);

    let ceiling = local_rtt_ceiling_ms.max(1.0);
    let rtt_weight = if rtt_ms <= ceiling {
        // Sub-5ms local neighborhood bonus
        0.25 + 0.75 * (rtt_ms.max(0.1) / ceiling)
    } else {
        // Linear + quadratic penalty above 5ms ceiling
        1.0 + ((rtt_ms - ceiling) / ceiling).powf(1.3)
    };

    d_xor.max(1e-9) * rtt_weight
}

/// Result of running the 70/30 Network Topology Shard Placement Engine.
#[derive(Debug, Clone)]
pub struct ShardPlacementPlan {
    pub selected_peers: Vec<PeerTopologyMetrics>,
    pub intra_asn_count: usize,
    pub inter_asn_count: usize,
    pub used_dynamic_fallback: bool,
}

/// Shard Placement Policy Engine enforcing the 70% Intra-ASN / Low-RTT and 30% Inter-ASN /
/// Cross-Region split with automatic fallback when local peer density drops below `K` (ADR-06).
pub struct PlacementEngine {
    pub local_ip: IpAddr,
    pub local_asn: u32,
    pub local_region: String,
    pub local_rtt_ceiling_ms: f64,
    pub intra_asn_ratio: f64,
}

impl PlacementEngine {
    pub fn new(
        local_ip: IpAddr,
        local_asn: u32,
        local_region: impl Into<String>,
        local_rtt_ceiling_ms: f64,
        intra_asn_ratio: f64,
    ) -> Self {
        Self {
            local_ip,
            local_asn,
            local_region: local_region.into(),
            local_rtt_ceiling_ms,
            intra_asn_ratio: intra_asn_ratio.clamp(0.0, 1.0),
        }
    }

    /// Determines whether `peer` belongs to the Intra-ASN / Low-RTT Local Network Neighborhood.
    pub fn is_local_neighborhood(&self, peer: &PeerTopologyMetrics) -> bool {
        let same_subnet = match (self.local_ip, peer.ip_addr) {
            (IpAddr::V4(a), IpAddr::V4(b)) => ipv4_same_slash24(a, b),
            (IpAddr::V6(a), IpAddr::V6(b)) => ipv6_same_slash48(a, b),
            _ => false,
        };
        let same_asn = peer.asn == self.local_asn;
        let low_rtt = peer.rtt_ms <= self.local_rtt_ceiling_ms;

        same_subnet || (same_asn && low_rtt)
    }

    /// Selects `n_total` distinct target nodes (`k_data` minimum local density threshold)
    /// ordered by `D_effective = D_XOR * RTT_weight`.
    pub fn select_target_peers(
        &self,
        stripe_merkle_root: &Hash32,
        k_data: usize,
        n_total: usize,
        min_shard_bytes: u64,
        candidates: &[PeerTopologyMetrics],
    ) -> ShardPlacementPlan {
        let target_intra = ((n_total as f64) * self.intra_asn_ratio).round() as usize;
        let target_inter = n_total.saturating_sub(target_intra);

        let mut eligible: Vec<PeerTopologyMetrics> = candidates
            .iter()
            .filter(|p| p.available_bytes >= min_shard_bytes)
            .cloned()
            .collect();

        eligible.sort_by(|a, b| {
            let da = effective_kademlia_distance(
                stripe_merkle_root,
                &a.kad_id_hash,
                a.rtt_ms,
                self.local_rtt_ceiling_ms,
            );
            let db = effective_kademlia_distance(
                stripe_merkle_root,
                &b.kad_id_hash,
                b.rtt_ms,
                self.local_rtt_ceiling_ms,
            );
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut intra_pool = Vec::new();
        let mut inter_pool = Vec::new();
        for peer in eligible {
            if self.is_local_neighborhood(&peer) {
                intra_pool.push(peer);
            } else {
                inter_pool.push(peer);
            }
        }

        let used_dynamic_fallback = intra_pool.len() < k_data || intra_pool.len() < target_intra;

        let mut selected = Vec::with_capacity(n_total);
        let mut intra_taken = 0usize;
        let mut inter_taken = 0usize;

        for peer in intra_pool.iter().take(target_intra) {
            selected.push(peer.clone());
            intra_taken += 1;
        }
        for peer in inter_pool.iter().take(target_inter) {
            selected.push(peer.clone());
            inter_taken += 1;
        }

        // Dynamic fallback: fill remaining slots from whichever pool still has healthy nodes.
        if selected.len() < n_total {
            for peer in intra_pool.into_iter().skip(intra_taken) {
                if selected.len() >= n_total {
                    break;
                }
                selected.push(peer);
                intra_taken += 1;
            }
        }
        if selected.len() < n_total {
            for peer in inter_pool.into_iter().skip(inter_taken) {
                if selected.len() >= n_total {
                    break;
                }
                selected.push(peer);
                inter_taken += 1;
            }
        }

        ShardPlacementPlan {
            selected_peers: selected,
            intra_asn_count: intra_taken,
            inter_asn_count: inter_taken,
            used_dynamic_fallback,
        }
    }

    /// Selects target peers while enforcing Dynamic Uptime Trust Level per-subnet concentration caps (ADR-10):
    /// - `SlashedQuarantined`: 0 shards allowed
    /// - `UntrustedProbationary`: max 1 shard per subnet/region
    /// - `VerifiedNeighbor`: max 2 shards per subnet/region
    /// - `HighUptimeAnchor`: max 4 shards per subnet/region (strictly `< K / 3` so no subnet can reconstruct)
    pub fn select_trust_weighted_peers(
        &self,
        stripe_merkle_root: &Hash32,
        k_data: usize,
        n_total: usize,
        min_shard_bytes: u64,
        candidates: &[PeerTopologyMetrics],
        peer_trust: &std::collections::HashMap<String, crate::storage::TrustLevel>,
    ) -> ShardPlacementPlan {
        let hard_confidentiality_cap = (k_data / 3).max(1);
        let mut region_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut ip_subnet_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut filtered = Vec::with_capacity(candidates.len());

        for cand in candidates {
            let trust = peer_trust
                .get(&cand.peer_id)
                .copied()
                .unwrap_or(crate::storage::TrustLevel::UntrustedProbationary);
            let allowed_in_subnet = trust.max_shards_per_subnet().min(hard_confidentiality_cap);
            if allowed_in_subnet == 0 {
                continue;
            }
            let ip_subnet_key = crate::bootstrap::canonical_sybil_subnet_key(cand.ip_addr, None);
            let region_count = region_counts.get(&cand.region).copied().unwrap_or(0);
            let ip_subnet_count = ip_subnet_counts.get(&ip_subnet_key).copied().unwrap_or(0);
            if region_count < allowed_in_subnet && ip_subnet_count < allowed_in_subnet {
                *region_counts.entry(cand.region.clone()).or_insert(0) += 1;
                *ip_subnet_counts.entry(ip_subnet_key).or_insert(0) += 1;
                filtered.push(cand.clone());
            }
        }

        self.select_target_peers(
            stripe_merkle_root,
            k_data,
            n_total,
            min_shard_bytes,
            &filtered,
        )
    }
}

/// Deterministic token-bucket bandwidth rate limiter for background shard egress and repair traffic.
#[derive(Debug, Clone)]
pub struct TokenBucketRateLimiter {
    capacity_bytes: u64,
    tokens_bytes: f64,
    refill_bytes_per_sec: f64,
    last_refill_ms: u64,
}

impl TokenBucketRateLimiter {
    pub fn new(rate_bytes_per_sec: u64, burst_bytes: u64, now_ms: u64) -> Self {
        let capacity_bytes = if burst_bytes > 0 {
            burst_bytes
        } else {
            rate_bytes_per_sec.max(1)
        };
        Self {
            capacity_bytes,
            tokens_bytes: capacity_bytes as f64,
            refill_bytes_per_sec: (rate_bytes_per_sec.max(1)) as f64,
            last_refill_ms: now_ms,
        }
    }

    pub fn refill(&mut self, now_ms: u64) {
        if now_ms > self.last_refill_ms {
            let elapsed_sec = (now_ms - self.last_refill_ms) as f64 / 1000.0;
            self.tokens_bytes = (self.tokens_bytes + elapsed_sec * self.refill_bytes_per_sec)
                .min(self.capacity_bytes as f64);
            self.last_refill_ms = now_ms;
        }
    }

    pub fn try_consume(&mut self, bytes: u64, now_ms: u64) -> bool {
        self.refill(now_ms);
        let needed = bytes as f64;
        if self.tokens_bytes >= needed {
            self.tokens_bytes -= needed;
            true
        } else {
            false
        }
    }

    pub fn available_tokens(&mut self, now_ms: u64) -> u64 {
        self.refill(now_ms);
        self.tokens_bytes.max(0.0) as u64
    }

    pub fn wait_time_ms(&mut self, bytes: u64, now_ms: u64) -> u64 {
        self.refill(now_ms);
        let needed = bytes as f64;
        if self.tokens_bytes >= needed {
            return 0;
        }
        let deficit = needed - self.tokens_bytes;
        ((deficit / self.refill_bytes_per_sec) * 1000.0).ceil() as u64
    }
}
