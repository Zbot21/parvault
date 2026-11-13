use crate::bootstrap::{
    BlindedShardTombstone, LiteStripeSyndicationBundle, LiteSyndicationReceipt, PersonalDeviceCert,
};
use crate::crypto::{NodeIdentity, PqRelayedShardEnvelope, PqSignedDhtManifestEnvelope};
use crate::network::wot::{DelegationChain, PublicCommonsTicket, SlashingEvidence};
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

/// ADR-08: a frame longer than the codec's limit (`MAX_WIRE_FRAME_BYTES`) is refused from its
/// length prefix, before any buffer is reserved.
pub fn wire_frame_decision(len: usize, max_frame_bytes: usize) -> Result<(), &'static str> {
    if len > max_frame_bytes {
        Err("reject.wire_frame_oversized")
    } else {
        Ok(())
    }
}

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
        if let Err(code) = wire_frame_decision(len, self.max_frame_bytes) {
            tracing::warn!(code, len, "refused a wire frame before allocating it");
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

/// Signed WAN rendezvous entry stored under a blinded 32-byte slot key (ADR-18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWanRendezvousEntry {
    pub slot_key: [u8; 32],
    pub encrypted_peer_card: Vec<u8>,
    pub timestamp_ms: u64,
    pub ttl_secs: u64,
    pub ed25519_pubkey: [u8; 32],
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl SignedWanRendezvousEntry {
    /// Formats the canonical domain-separated byte payload for outer anti-spam signature:
    /// `"parvault-wan-entry-v1:" || slot_key || timestamp_ms_be64 || ttl_secs_be64 || encrypted_peer_card`.
    pub fn signing_payload(
        slot_key: &[u8; 32],
        timestamp_ms: u64,
        ttl_secs: u64,
        encrypted_peer_card: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 8 + 8 + encrypted_peer_card.len() + 24);
        out.extend_from_slice(b"parvault-wan-entry-v1:");
        out.extend_from_slice(slot_key);
        out.extend_from_slice(&timestamp_ms.to_be_bytes());
        out.extend_from_slice(&ttl_secs.to_be_bytes());
        out.extend_from_slice(encrypted_peer_card);
        out
    }

    /// Verifies the outer Ed25519 anti-spam signature against `self.ed25519_pubkey`.
    pub fn verify_signature(&self) -> bool {
        let payload = Self::signing_payload(
            &self.slot_key,
            self.timestamp_ms,
            self.ttl_secs,
            &self.encrypted_peer_card,
        );
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.sig_r);
        sig_bytes[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.ed25519_pubkey, &payload, &sig_bytes)
    }

    /// Checks whether this entry has expired relative to `now_ms`.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        let ttl_ms = self.ttl_secs.saturating_mul(1000);
        now_ms.saturating_sub(self.timestamp_ms) > ttl_ms
    }
}

/// Detached Ed25519 owner signature `(owner_pubkey, signed_payload, sig_r, sig_s)` authorizing
/// direct ciphertext shard reads or deletions (`ADR-04`).
pub type OwnerShardSignature = ([u8; 32], Vec<u8>, [u8; 32], [u8; 32]);

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
        owner_signature: Option<OwnerShardSignature>,
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
    /// Query live node topology, available quota, SLA score, and Post-Quantum KEM public key.
    QueryNodeStatus,
    /// Register a signed WAN rendezvous entry under a blinded slot key.
    RegisterWanRendezvous {
        slot_key: [u8; 32],
        entry: SignedWanRendezvousEntry,
    },
    /// Look up all fresh WAN rendezvous entries stored under a blinded slot key.
    LookupWanRendezvous { slot_key: [u8; 32] },
    /// Submit a cryptographically verifiable abuse takedown report against illegal content (ADR-19).
    SubmitAbuseTakedownReport(crate::storage::VerifiableAbuseReport),
    /// Broadcast a signed bad-actor or illegal-content eviction order across peers (ADR-19).
    BroadcastEvictionOrder(crate::storage::SignedBadActorEvictionOrder),
    /// Present a self-signed Hashcash `PublicCommonsTicket` for probationary admission to a
    /// node in public-commons or hybrid mode (ADR-24). Appended in v0.5.0; the ticket key must be
    /// the sender's transport key.
    AdmitPublicTicket(PublicCommonsTicket),
    /// Renews a blinded shard's lease, signed by its capability key (F-23). Appended; the
    /// unsigned `RenewBlindedLease` is refused.
    RenewBlindedLeaseSigned {
        blinded_id: BlindedShardId,
        current_epoch: u64,
        extension_epochs: u64,
        timestamp_ms: u64,
        sig: Vec<u8>,
    },
    /// Deletes a blinded shard on a signature by its lease's capability key over
    /// `"parvault-delete-blinded-v1" || host || locator || content_sha256 || timestamp_ms`
    /// (appended, F-41; replaces the forgeable `DeleteBlindedShardTombstone`, which is refused).
    DeleteBlindedShardSigned {
        blinded_id: BlindedShardId,
        timestamp_ms: u64,
        sig: Vec<u8>,
    },
    /// Asks an admitted peer for the council manifests of `scope_root` after `from_epoch` (the
    /// requester's epoch), appended, F-08/F-09: a node that sees an order from a newer council
    /// epoch fetches the chain up to it.
    GetCouncilManifest {
        scope_root: [u8; 32],
        from_epoch: u64,
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
    NodeStatusResult {
        peer_id: String,
        asn: u32,
        region: String,
        available_bytes: u64,
        used_bytes: u64,
        sla_score: f64,
        pq_kem_pubkey: Option<crate::crypto::HybridKemPublicKey>,
    },
    /// Acknowledgment of a WAN rendezvous registration with observed external address reflection.
    RegisterWanRendezvousAck {
        stored: bool,
        observed_external_addr: Option<String>,
        error: Option<String>,
        #[serde(default)]
        tracker_admin_pubkey: Option<[u8; 32]>,
    },
    /// Result of looking up WAN rendezvous entries under a slot key with observed external address reflection.
    LookupWanRendezvousResult {
        entries: Vec<SignedWanRendezvousEntry>,
        observed_external_addr: Option<String>,
        #[serde(default)]
        tracker_admin_pubkey: Option<[u8; 32]>,
    },
    /// Acknowledgment of a submitted abuse takedown report.
    SubmitAbuseTakedownAck {
        queued_for_admin_review: bool,
        report_id: [u8; 32],
        verified_plaintext_sha256: Option<[u8; 32]>,
        error: Option<String>,
    },
    /// Acknowledgment of an applied or rejected broadcast eviction order.
    EvictionOrderAck {
        accepted: bool,
        purged_regular_shards: usize,
        purged_blinded_shards: usize,
        zero_wiped_bytes: u64,
        error: Option<String>,
    },
    /// Result of `AdmitPublicTicket` (appended in v0.5.0).
    AdmitPublicTicketAck {
        admitted: bool,
        reason: Option<String>,
        /// The node a ticket must be bound to (its Ed25519 key).
        verifier_pubkey: [u8; 32],
        /// The PoW bits this node requires.
        required_pow_bits: u8,
    },
    /// Result of `GetCouncilManifest` (appended): the manifests after `from_epoch`, oldest
    /// first, at most 64 KiB in all (the oldest that fit; ask again from the new epoch).
    CouncilManifestResult {
        manifests: Vec<crate::storage::council::CouncilManifest>,
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

// Re-exported so `parvault::network::behaviour::*` paths keep resolving.
pub use super::placement::{PeerTopologyMetrics, PlacementEngine, ShardPlacementPlan};
pub use super::rate_limit::TokenBucketRateLimiter;
