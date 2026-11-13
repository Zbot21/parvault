//! Inbound `MeshWireRequest` handling shared by the `parvault` daemon and `parvault-seed`.
//!
//! [`handle_mesh_wire_request`] implements every variant once. The daemon and the seed differ
//! only through [`WireRolePolicy`] ([`DaemonWirePolicy`], [`SeedWirePolicy`]); the divergence
//! table is on the trait. [`admission_class`], `admit` and `shard_owner` are the single places for
//! an admission check and the shard-owner quota identity; both are inert in this version.

use crate::bootstrap::{SeedServerMode, ZeroTrustSeedServer};
use crate::config::NodeConfig;
use crate::crypto::{HybridKemKeypair, NodeIdentity};
use crate::network::behaviour::{
    DhtEnvelopeKind, DhtWireEnvelope, MeshWireRequest, MeshWireResponse,
};
use crate::network::discovery::KnownPeersStore;
use crate::network::wan_rendezvous::{
    open_public_tracker_card, reflect_observed_wan_multiaddr, WanRendezvousRegistry,
    PUBLIC_COMMONS_SWARM_SLOT,
};
use crate::network::wot::WebOfTrustRegistry;
use crate::por::PorVerifierEngine;
use crate::storage::{
    BlockStore, PrivacyPreservingEvictionEngine, PublicTrackerTakedownQueue,
    SignedBadActorEvictionOrder, VoucherNullifierLedger,
};
use libp2p::Multiaddr;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

/// Returns the first IPv4 / IPv6 address in a multiaddr.
pub fn extract_ip_from_multiaddr(addr: &Multiaddr) -> Option<std::net::IpAddr> {
    for proto in addr.iter() {
        match proto {
            libp2p::multiaddr::Protocol::Ip4(ip4) => return Some(std::net::IpAddr::V4(ip4)),
            libp2p::multiaddr::Protocol::Ip6(ip6) => return Some(std::net::IpAddr::V6(ip6)),
            _ => {}
        }
    }
    None
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Resolves the eviction council and quorum for a `parvault-seed` node.
pub fn resolve_seed_council_and_quorum(
    data_dir: &Path,
    mode: SeedServerMode,
    local_tracker_admin_pubkey: Option<[u8; 32]>,
    extra_council_pubkeys: &[[u8; 32]],
    cli_quorum_override: Option<usize>,
    genesis_pubkey: Option<[u8; 32]>,
) -> (Vec<[u8; 32]>, usize) {
    let mut council = Vec::new();
    let mut push_pk = |pk: [u8; 32]| {
        if pk != [0u8; 32] && !council.contains(&pk) {
            council.push(pk);
        }
    };
    if let Ok(env_auth) = std::env::var("PARVAULT_EVICTION_AUTHORITIES") {
        for part in env_auth.split(',') {
            if let Ok(bytes) = hex::decode(part.trim()) {
                if bytes.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&bytes);
                    push_pk(pk);
                }
            }
        }
    }
    let env_quorum = std::env::var("PARVAULT_TRACKER_EVICTION_QUORUM")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok());
    let quorum_override = cli_quorum_override.or(env_quorum);

    match mode {
        SeedServerMode::PublicNetworkBootstrapper => {
            if let Some(pk) = local_tracker_admin_pubkey {
                push_pk(pk);
            }
            for pk in extra_council_pubkeys {
                push_pk(*pk);
            }
            if !data_dir.as_os_str().is_empty() {
                for pk in KnownPeersStore::load(data_dir).pinned_tracker_admin_pubkeys() {
                    push_pk(pk);
                }
            }
            let min_quorum = quorum_override
                .unwrap_or_else(|| {
                    SignedBadActorEvictionOrder::default_tracker_quorum_threshold(council.len())
                })
                .max(1);
            (council, min_quorum)
        }
        SeedServerMode::HomelabRedundancyVault => {
            if let Some(pk) = genesis_pubkey {
                push_pk(pk);
            }
            let min_quorum = quorum_override.unwrap_or(1).max(1);
            (council, min_quorum)
        }
    }
}

/// State borrowed by the daemon wire handler for one request.
pub struct DaemonWireHandlerCtx<'a> {
    pub cfg: &'a NodeConfig,
    pub node_identity: &'a NodeIdentity,
    pub genesis_pubkey: Option<[u8; 32]>,
    pub public_mode: bool,
    pub block_store: &'a BlockStore,
    pub wot: &'a mut WebOfTrustRegistry,
    pub por_verifier: &'a mut PorVerifierEngine,
    pub nullifier_ledger: &'a mut VoucherNullifierLedger,
    pub pq_kem: &'a HybridKemKeypair,
    pub lite_seed_server: &'a mut ZeroTrustSeedServer,
    pub wan_registry: &'a mut WanRendezvousRegistry,
    pub eviction: &'a mut PrivacyPreservingEvictionEngine,
    pub takedown_queue: &'a mut PublicTrackerTakedownQueue,
}

/// State borrowed by the seed wire handler for one request.
pub struct SeedWireHandlerCtx<'a> {
    pub data_dir: &'a Path,
    pub node_identity: &'a NodeIdentity,
    pub advertised_admin_pk: Option<[u8; 32]>,
    pub local_tracker_admin_pk: Option<[u8; 32]>,
    pub extra_council_pks: &'a [[u8; 32]],
    pub council_quorum: Option<usize>,
    pub max_probationary_lease_bytes: u64,
    pub genesis_pubkey: Option<[u8; 32]>,
    pub block_store: &'a BlockStore,
    pub server: &'a mut ZeroTrustSeedServer,
    pub wot: &'a mut WebOfTrustRegistry,
    pub por_verifier: &'a mut PorVerifierEngine,
    pub nullifier_ledger: &'a mut VoucherNullifierLedger,
    pub pq_kem: &'a HybridKemKeypair,
    pub wan_registry: &'a mut WanRendezvousRegistry,
    pub eviction: &'a mut PrivacyPreservingEvictionEngine,
    pub takedown_queue: &'a mut PublicTrackerTakedownQueue,
}

// ---------------------------------------------------------------------------------------------
// Role entry points (one per binary). Each builds its policy per request from the ctx, so live
// seed state (`max_probationary_lease_bytes`, `server.mode()`) is read under the caller's lock.
// ---------------------------------------------------------------------------------------------

/// Handles one inbound request on the `parvault` daemon.
pub fn handle_daemon_wire_request(
    remote_peer_id: &str,
    remote_addr: Option<&Multiaddr>,
    request: MeshWireRequest,
    ctx: DaemonWireHandlerCtx<'_>,
) -> WireReply {
    let policy = DaemonWirePolicy {
        cfg: ctx.cfg,
        public_mode: ctx.public_mode,
    };
    let state = WireState {
        node_identity: ctx.node_identity,
        genesis_pubkey: ctx.genesis_pubkey,
        block_store: ctx.block_store,
        server: ctx.lite_seed_server,
        wot: ctx.wot,
        por_verifier: ctx.por_verifier,
        nullifier_ledger: ctx.nullifier_ledger,
        pq_kem: ctx.pq_kem,
        wan_registry: ctx.wan_registry,
        eviction: ctx.eviction,
        takedown_queue: ctx.takedown_queue,
    };
    handle_mesh_wire_reply(
        &WirePeer::new(remote_peer_id, remote_addr),
        request,
        state,
        &policy,
    )
}

/// Handles one inbound request on `parvault-seed`.
pub fn handle_seed_wire_request(
    remote_peer_id: &str,
    remote_addr: Option<&Multiaddr>,
    request: MeshWireRequest,
    ctx: SeedWireHandlerCtx<'_>,
) -> WireReply {
    let policy = SeedWirePolicy {
        data_dir: ctx.data_dir,
        advertised_admin_pk: ctx.advertised_admin_pk,
        local_tracker_admin_pk: ctx.local_tracker_admin_pk,
        extra_council_pks: ctx.extra_council_pks,
        council_quorum: ctx.council_quorum,
        max_probationary_lease_bytes: ctx.max_probationary_lease_bytes,
    };
    let state = WireState {
        node_identity: ctx.node_identity,
        genesis_pubkey: ctx.genesis_pubkey,
        block_store: ctx.block_store,
        server: ctx.server,
        wot: ctx.wot,
        por_verifier: ctx.por_verifier,
        nullifier_ledger: ctx.nullifier_ledger,
        pq_kem: ctx.pq_kem,
        wan_registry: ctx.wan_registry,
        eviction: ctx.eviction,
        takedown_queue: ctx.takedown_queue,
    };
    handle_mesh_wire_reply(
        &WirePeer::new(remote_peer_id, remote_addr),
        request,
        state,
        &policy,
    )
}

// ---------------------------------------------------------------------------------------------
// Shared handler
// ---------------------------------------------------------------------------------------------

/// The remote side of one request, with its IP and Ed25519 key derived once.
pub struct WirePeer<'a> {
    pub peer_id: &'a str,
    pub addr: Option<&'a Multiaddr>,
    pub ip: Option<IpAddr>,
    pub pubkey: Option<[u8; 32]>,
}

impl<'a> WirePeer<'a> {
    pub fn new(peer_id: &'a str, addr: Option<&'a Multiaddr>) -> Self {
        Self {
            peer_id,
            addr,
            ip: addr.and_then(extract_ip_from_multiaddr),
            pubkey: NodeConfig::extract_ed25519_pubkey_from_peer_str(peer_id),
        }
    }
}

/// Node state the handler reads and mutates for one request.
pub struct WireState<'a> {
    pub node_identity: &'a NodeIdentity,
    pub genesis_pubkey: Option<[u8; 32]>,
    pub block_store: &'a BlockStore,
    /// The daemon's embedded lite seed server, or the seed binary's server.
    pub server: &'a mut ZeroTrustSeedServer,
    pub wot: &'a mut WebOfTrustRegistry,
    pub por_verifier: &'a mut PorVerifierEngine,
    pub nullifier_ledger: &'a mut VoucherNullifierLedger,
    pub pq_kem: &'a HybridKemKeypair,
    pub wan_registry: &'a mut WanRendezvousRegistry,
    pub eviction: &'a mut PrivacyPreservingEvictionEngine,
    pub takedown_queue: &'a mut PublicTrackerTakedownQueue,
}

/// Role-specific behaviour of the shared handler: one method per row where the daemon and the
/// seed handlers differed before the merge. No method has a default body.
///
/// | Row | Variant | Daemon | Seed |
/// | :-- | :-- | :-- | :-- |
/// | 2 | `PutShard` | no extra record | also `record_peer_admission_ip(ip, pubkey)` |
/// | 6, 11 | `PutBlindedShard`, onion final delivery | no size limit | `max_probationary_lease_bytes` (0 = off) |
/// | 9 | `DeleteBlindedShardTombstone` | `BlockStore` error text | via the seed server: "Seed server storage error: " prefix |
/// | 15 | `QueryNodeStatus` | region `local-neighborhood` | region `seed-anchor` |
/// | 16, 17 | Register / Lookup rendezvous | `tracker_admin_pubkey: None` | advertised admin key |
/// | 16 | Register on the public slot | no extra record | records every advertised card IP |
/// | 18 | `SubmitAbuseTakedownReport` | always queued | refused unless public bootstrapper |
/// | 19 | `BroadcastEvictionOrder` | `NodeConfig` council resolver | `resolve_seed_council_and_quorum` |
pub trait WireRolePolicy {
    /// Row 2.
    fn record_put_shard_admission_ip(&self) -> bool;
    /// Rows 6 and 11: blinded shards longer than this are refused; 0 disables the check.
    fn max_probationary_lease_bytes(&self) -> u64;
    /// Row 9: route tombstones through the seed server (changes only the error text).
    fn tombstone_via_seed_server(&self) -> bool;
    /// Row 15.
    fn status_region(&self) -> &'static str;
    /// Rows 16 and 17.
    fn tracker_admin_pubkey(&self) -> Option<[u8; 32]>;
    /// Row 16.
    fn record_public_card_ips(&self) -> bool;
    /// Row 18: `Err(reason)` refuses the report before it reaches the queue.
    fn takedown_gate(&self, mode: SeedServerMode) -> Result<(), String>;
    /// Row 19: the eviction council and minimum quorum.
    fn eviction_council(
        &self,
        block_store: &BlockStore,
        mode: SeedServerMode,
        genesis_pubkey: Option<[u8; 32]>,
    ) -> (Vec<[u8; 32]>, usize);
}

/// Policy of the `parvault` daemon.
pub struct DaemonWirePolicy<'a> {
    pub cfg: &'a NodeConfig,
    pub public_mode: bool,
}

/// Policy of `parvault-seed`. Built per request from live seed state.
pub struct SeedWirePolicy<'a> {
    pub data_dir: &'a Path,
    pub advertised_admin_pk: Option<[u8; 32]>,
    pub local_tracker_admin_pk: Option<[u8; 32]>,
    pub extra_council_pks: &'a [[u8; 32]],
    pub council_quorum: Option<usize>,
    pub max_probationary_lease_bytes: u64,
}

impl WireRolePolicy for DaemonWirePolicy<'_> {
    fn record_put_shard_admission_ip(&self) -> bool {
        false
    }
    fn max_probationary_lease_bytes(&self) -> u64 {
        0
    }
    fn tombstone_via_seed_server(&self) -> bool {
        false
    }
    fn status_region(&self) -> &'static str {
        "local-neighborhood"
    }
    fn tracker_admin_pubkey(&self) -> Option<[u8; 32]> {
        None
    }
    fn record_public_card_ips(&self) -> bool {
        false
    }
    fn takedown_gate(&self, _mode: SeedServerMode) -> Result<(), String> {
        Ok(())
    }
    fn eviction_council(
        &self,
        block_store: &BlockStore,
        _mode: SeedServerMode,
        genesis_pubkey: Option<[u8; 32]>,
    ) -> (Vec<[u8; 32]>, usize) {
        let mut pinned_admins =
            KnownPeersStore::load(&self.cfg.data_dir).pinned_tracker_admin_pubkeys();
        if let Some(mc) = block_store.mesh_client() {
            for pk in mc.pinned_tracker_admin_pubkeys() {
                if !pinned_admins.contains(&pk) {
                    pinned_admins.push(pk);
                }
            }
        }
        self.cfg.resolve_eviction_council_and_quorum(
            genesis_pubkey,
            &pinned_admins,
            self.public_mode,
        )
    }
}

impl WireRolePolicy for SeedWirePolicy<'_> {
    fn record_put_shard_admission_ip(&self) -> bool {
        true
    }
    fn max_probationary_lease_bytes(&self) -> u64 {
        self.max_probationary_lease_bytes
    }
    fn tombstone_via_seed_server(&self) -> bool {
        true
    }
    fn status_region(&self) -> &'static str {
        "seed-anchor"
    }
    fn tracker_admin_pubkey(&self) -> Option<[u8; 32]> {
        self.advertised_admin_pk
    }
    fn record_public_card_ips(&self) -> bool {
        true
    }
    fn takedown_gate(&self, mode: SeedServerMode) -> Result<(), String> {
        if mode != SeedServerMode::PublicNetworkBootstrapper {
            return Err("abuse takedown queue disabled in homelab-vault private mode".to_string());
        }
        Ok(())
    }
    fn eviction_council(
        &self,
        _block_store: &BlockStore,
        mode: SeedServerMode,
        genesis_pubkey: Option<[u8; 32]>,
    ) -> (Vec<[u8; 32]>, usize) {
        resolve_seed_council_and_quorum(
            self.data_dir,
            mode,
            self.local_tracker_admin_pk,
            self.extra_council_pks,
            self.council_quorum,
            genesis_pubkey,
        )
    }
}

/// How a request may be authorised. Inert in 2a; the admission check (`admit`) will use it.
/// Every variant is listed (no wildcard), so a new request type must be classified to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionClass {
    /// Must stay reachable before a peer is admitted (handshake, rendezvous, status).
    PreAdmission,
    /// Authorised by the request itself: blinded vouchers / capabilities, onion relays,
    /// owner signatures, PoR session keys, signed DHT envelopes.
    SelfAuthorised,
    /// Authorised by a council or reporter signature checked inside the arm.
    CouncilSigned,
    /// Requires an admitted peer. Onion relays are in this class (F-33, L-38): the originator
    /// is admitted at the entry relay, and each relay's forward is admitted at the next hop.
    AdmittedPeer,
}

/// The refusal text sent to a sender that is not admitted (the reason code stays in the log).
pub const NOT_ADMITTED_TEXT: &str = "peer not admitted; v0.5.0 requires ring admission";

/// What the admission decision needs to know about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionFacts {
    pub class: AdmissionClass,
    /// The sender's Ed25519 key from its transport identity, if it has one.
    pub sender_pubkey: Option<[u8; 32]>,
    /// The sender is admitted (genesis, an unquarantined ring chain, or a public ticket) and not
    /// quarantined.
    pub sender_trusted: bool,
}

/// The single admission decision (F-03). `Err` carries the reason code for the local log.
pub fn admission_decision(facts: &AdmissionFacts) -> Result<(), &'static str> {
    if facts.class != AdmissionClass::AdmittedPeer {
        return Ok(());
    }
    if facts.sender_pubkey.is_none() {
        return Err("reject.peer_key_unknown");
    }
    if !facts.sender_trusted {
        return Err("reject.peer_not_admitted");
    }
    Ok(())
}

/// Facts for `class` about the sender of this request.
fn admission_facts(
    peer: &WirePeer<'_>,
    class: AdmissionClass,
    wot: &WebOfTrustRegistry,
) -> AdmissionFacts {
    AdmissionFacts {
        class,
        sender_pubkey: peer.pubkey,
        sender_trusted: peer.pubkey.is_some_and(|pk| wot.is_peer_trusted(&pk)),
    }
}

/// Runs the decision and logs a refusal; `true` admits.
fn admitted(peer: &WirePeer<'_>, class: AdmissionClass, wot: &WebOfTrustRegistry) -> bool {
    match admission_decision(&admission_facts(peer, class, wot)) {
        Ok(()) => true,
        Err(code) => {
            warn!(code, peer = %peer.peer_id, "refused a request from a peer that is not admitted");
            false
        }
    }
}

/// Classifies a request for admission.
pub const fn admission_class(request: &MeshWireRequest) -> AdmissionClass {
    match request {
        MeshWireRequest::HandshakeWoT { .. }
        | MeshWireRequest::AdmitPublicTicket(_)
        | MeshWireRequest::QueryNodeStatus
        | MeshWireRequest::RegisterWanRendezvous { .. }
        | MeshWireRequest::LookupWanRendezvous { .. } => AdmissionClass::PreAdmission,
        MeshWireRequest::GetBlindedShard { .. }
        | MeshWireRequest::RenewBlindedLease { .. }
        | MeshWireRequest::RenewBlindedLeaseSigned { .. }
        | MeshWireRequest::DeleteBlindedShardTombstone { .. }
        | MeshWireRequest::GetCiphertextShard { .. }
        | MeshWireRequest::DeleteShard { .. }
        | MeshWireRequest::PorAudit(_)
        | MeshWireRequest::MultiSegmentPorAudit(_)
        | MeshWireRequest::GetDhtEnvelope { .. } => AdmissionClass::SelfAuthorised,
        MeshWireRequest::RelayPqOnionEnvelope { .. } => AdmissionClass::AdmittedPeer,
        MeshWireRequest::SubmitAbuseTakedownReport(_)
        | MeshWireRequest::BroadcastEvictionOrder(_) => AdmissionClass::CouncilSigned,
        // v0.5.0: blinded-shard vouchers are self-certifying (F-24), so a blinded put needs an
        // admitted sender as well as its voucher.
        MeshWireRequest::PutShard { .. }
        | MeshWireRequest::SyndicateLiteStripe { .. }
        | MeshWireRequest::PutDhtEnvelope(_)
        | MeshWireRequest::PutBlindedShard { .. } => AdmissionClass::AdmittedPeer,
    }
}

/// The single admission check: `Some(rejection)` refuses the request before dispatch.
fn admit(
    peer: &WirePeer<'_>,
    request: &MeshWireRequest,
    class: AdmissionClass,
    st: &mut WireState<'_>,
) -> Option<MeshWireResponse> {
    (!admitted(peer, class, st.wot))
        .then(|| reject_response(request, NOT_ADMITTED_TEXT.to_string()))
}

/// What the shard-owner decision needs to know about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerFacts<'a> {
    /// The owner named in the request (`PutShard`), or `None` where none is sent (`DeleteShard`).
    pub claimed: Option<&'a str>,
    /// The sender's device peer id, if its transport identity carries an Ed25519 key.
    pub sender_device_id: Option<&'a str>,
    /// The sender's libp2p `PeerId` string.
    pub sender_peer_id: &'a str,
}

/// The single quota-identity decision (F-04): the accounted owner is always the sender's device
/// id. A claim may only name the sender (empty, `local`, `self`, its device id or its `PeerId`).
pub fn shard_owner_decision<'a>(facts: &OwnerFacts<'a>) -> Result<&'a str, &'static str> {
    let Some(device) = facts.sender_device_id else {
        return Err("reject.owner_not_sender");
    };
    match facts.claimed {
        None => Ok(device),
        Some(c)
            if c.is_empty()
                || c == "local"
                || c == "self"
                || c == device
                || c == facts.sender_peer_id =>
        {
            Ok(device)
        }
        Some(_) => Err("reject.owner_not_sender"),
    }
}

/// The accounted owner for a request from `peer`, or `None` (logged) when the claim does not
/// name the sender.
fn shard_owner(peer: &WirePeer<'_>, claimed: Option<&str>) -> Option<String> {
    let device = peer
        .pubkey
        .map(|pk| NodeIdentity::device_peer_id_for_pubkey(&pk));
    let facts = OwnerFacts {
        claimed,
        sender_device_id: device.as_deref(),
        sender_peer_id: peer.peer_id,
    };
    match shard_owner_decision(&facts) {
        Ok(owner) => Some(owner.to_string()),
        Err(code) => {
            warn!(code, peer = %peer.peer_id, "refused an owner claim that does not name the sender");
            None
        }
    }
}

/// The syndication binding (F-25): a personal-device cert authorises only the device it names,
/// so it must name the sender. Fails closed when the sender has no Ed25519 key.
pub fn device_cert_decision(
    cert_device_id: &str,
    sender_device_id: Option<&str>,
) -> Result<(), &'static str> {
    if sender_device_id == Some(cert_device_id) {
        Ok(())
    } else {
        Err("reject.device_cert_not_sender")
    }
}

/// What the lease-renewal decision needs to know (F-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewFacts {
    /// The shard has a registered capability key and the request is signed by it.
    pub signed_by_capability: bool,
    /// The signature's timestamp is within the capability clock-skew window.
    pub fresh: bool,
    pub extension_epochs: u64,
}

/// A blinded shard's lease may be renewed only by its capability holder, recently, and by at
/// most `MAX_LEASE_EXTENSION_EPOCHS` (F-23).
pub fn renew_decision(facts: &RenewFacts) -> Result<(), &'static str> {
    if !facts.signed_by_capability || !facts.fresh {
        return Err("reject.renew_capability_invalid");
    }
    if facts.extension_epochs == 0
        || facts.extension_epochs > crate::storage::MAX_LEASE_EXTENSION_EPOCHS
    {
        return Err("reject.renew_extension_unbounded");
    }
    Ok(())
}

/// The one refusal text for every failed handshake (F-30): the reason stays in the local log.
pub const HANDSHAKE_REFUSED_TEXT: &str = "handshake refused";

/// What the voucher issuer decision needs to know (F-24 issuer policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoucherIssuerFacts {
    /// The issuer is the ring genesis or holds an admitted ring chain on this node.
    pub issuer_is_ring_member: bool,
    /// The issuer is this node's configured voucher issuer (a seed's own issuer).
    pub issuer_is_configured: bool,
}

/// A blinded-shard voucher is honoured only if its issuer is a ring member this node knows or
/// its configured issuer; a voucher no longer certifies its own issuer (F-24). Ephemeral
/// per-shard issuers (ADR-11) are therefore refused until anonymous credentials (v0.6.0).
pub fn voucher_issuer_decision(facts: &VoucherIssuerFacts) -> Result<(), &'static str> {
    if facts.issuer_is_ring_member || facts.issuer_is_configured {
        Ok(())
    } else {
        Err("reject.voucher_issuer_untrusted")
    }
}

/// Text sent to a sender whose voucher issuer is not trusted (the reason code stays in the log).
pub const VOUCHER_ISSUER_UNTRUSTED_TEXT: &str = "voucher issuer not trusted by this node";

fn voucher_issuer_allowed(
    wot: &WebOfTrustRegistry,
    ledger: &VoucherNullifierLedger,
    issuer: &[u8; 32],
    peer: &str,
) -> bool {
    let facts = VoucherIssuerFacts {
        issuer_is_ring_member: (wot.genesis_pubkey() == Some(*issuer)
            || wot.is_private_ring_peer(issuer))
            && !wot.is_peer_quarantined(issuer),
        issuer_is_configured: *issuer == ledger.issuer_pubkey(),
    };
    match voucher_issuer_decision(&facts) {
        Ok(()) => true,
        Err(code) => {
            warn!(code, peer, "refused a voucher from an untrusted issuer");
            false
        }
    }
}

/// The local reason code for a failed handshake (never sent on the wire).
pub fn handshake_refusal_code(err: &crate::network::wot::WebOfTrustError) -> &'static str {
    match err {
        crate::network::wot::WebOfTrustError::QuarantinedSubtree => "reject.handshake_quarantined",
        // The code comes from its declared check, so it is built in one place (F-37).
        crate::network::wot::WebOfTrustError::NoRing => {
            crate::network::wot::WebOfTrustRegistry::ring_handshake_decision(None)
                .expect_err("no genesis is always refused")
        }
        _ => "reject.handshake_chain_invalid",
    }
}

fn handshake_refused() -> MeshWireResponse {
    MeshWireResponse::HandshakeAck {
        accepted: false,
        reason: Some(HANDSHAKE_REFUSED_TEXT.to_string()),
    }
}

/// The shard ids a syndicated stripe was stored as (its root and expected shard hashes).
fn syndicated_shard_ids(
    bundle: &crate::bootstrap::LiteStripeSyndicationBundle,
    root: crate::sharding::merkle::Hash32,
) -> Vec<crate::storage::ShardId> {
    bundle
        .expected_shard_hashes
        .iter()
        .enumerate()
        .map(|(i, h)| crate::storage::ShardId {
            stripe_merkle_root: root,
            shard_index: i as u32,
            shard_hash: *h,
        })
        .collect()
}

/// The refusal text for an owner claim that does not name the sender.
const OWNER_NOT_SENDER_TEXT: &str = "owner claim does not match the sender";

/// The negative acknowledgement for `request` carrying `reason` (for use by `admit`).
pub fn reject_response(request: &MeshWireRequest, reason: String) -> MeshWireResponse {
    match request {
        MeshWireRequest::HandshakeWoT { .. } => MeshWireResponse::HandshakeAck {
            accepted: false,
            reason: Some(reason),
        },
        MeshWireRequest::AdmitPublicTicket(_) => MeshWireResponse::AdmitPublicTicketAck {
            admitted: false,
            reason: Some(reason),
            verifier_pubkey: [0u8; 32],
            required_pow_bits: 0,
        },
        MeshWireRequest::PutShard { .. } => MeshWireResponse::PutShardAck {
            stored: false,
            error: Some(reason),
        },
        MeshWireRequest::PorAudit(_) => MeshWireResponse::PorAuditResult(None),
        MeshWireRequest::GetCiphertextShard { .. } => MeshWireResponse::CiphertextShardResult {
            shard_bytes: None,
            error: Some(reason),
        },
        MeshWireRequest::PutBlindedShard { .. } => MeshWireResponse::PutBlindedShardAck {
            stored: false,
            error: Some(reason),
        },
        MeshWireRequest::GetBlindedShard { .. } => MeshWireResponse::BlindedShardResult {
            shard_bytes: None,
            error: Some(reason),
        },
        MeshWireRequest::RenewBlindedLease { .. }
        | MeshWireRequest::RenewBlindedLeaseSigned { .. } => {
            MeshWireResponse::RenewBlindedLeaseAck { renewed: false }
        }
        MeshWireRequest::DeleteBlindedShardTombstone { .. } => {
            MeshWireResponse::DeleteBlindedShardAck {
                deleted: false,
                error: Some(reason),
            }
        }
        MeshWireRequest::MultiSegmentPorAudit(_) => {
            MeshWireResponse::MultiSegmentPorAuditResult(None)
        }
        MeshWireRequest::RelayPqOnionEnvelope { .. } => MeshWireResponse::RelayPqOnionAck {
            delivered: false,
            error: Some(reason),
        },
        MeshWireRequest::SyndicateLiteStripe { .. } => MeshWireResponse::SyndicateLiteStripeAck {
            receipt: None,
            syndicated_peers: Vec::new(),
            error: Some(reason),
        },
        MeshWireRequest::PutDhtEnvelope(_) => MeshWireResponse::PutDhtEnvelopeAck {
            stored: false,
            error: Some(reason),
        },
        MeshWireRequest::GetDhtEnvelope { .. } => MeshWireResponse::GetDhtEnvelopeResult {
            envelope: None,
            error: Some(reason),
        },
        MeshWireRequest::DeleteShard { .. } => MeshWireResponse::DeleteShardAck {
            deleted: false,
            error: Some(reason),
        },
        MeshWireRequest::QueryNodeStatus => MeshWireResponse::NodeStatusResult {
            peer_id: String::new(),
            asn: 0,
            region: String::new(),
            available_bytes: 0,
            used_bytes: 0,
            sla_score: 0.0,
            pq_kem_pubkey: None,
        },
        MeshWireRequest::RegisterWanRendezvous { .. } => {
            MeshWireResponse::RegisterWanRendezvousAck {
                stored: false,
                observed_external_addr: None,
                error: Some(reason),
                tracker_admin_pubkey: None,
            }
        }
        MeshWireRequest::LookupWanRendezvous { .. } => {
            MeshWireResponse::LookupWanRendezvousResult {
                entries: Vec::new(),
                observed_external_addr: None,
                tracker_admin_pubkey: None,
            }
        }
        MeshWireRequest::SubmitAbuseTakedownReport(report) => {
            MeshWireResponse::SubmitAbuseTakedownAck {
                queued_for_admin_review: false,
                report_id: report.report_id,
                verified_plaintext_sha256: None,
                error: Some(reason),
            }
        }
        MeshWireRequest::BroadcastEvictionOrder(_) => MeshWireResponse::EvictionOrderAck {
            accepted: false,
            purged_regular_shards: 0,
            purged_blinded_shards: 0,
            zero_wiped_bytes: 0,
            error: Some(reason),
        },
    }
}

fn lease_limit_error(len: usize, limit: u64) -> Option<String> {
    (limit > 0 && (len as u64) > limit)
        .then(|| format!("shard length {len} exceeds max_probationary_lease_bytes {limit}"))
}

/// Handles one inbound `MeshWireRequest` for either role. Onion relay forwards come back as
/// [`WireReply::Deferred`] so the swarm task never waits on the jitter or the next hop (F-18).
pub fn handle_mesh_wire_reply<P: WireRolePolicy>(
    peer: &WirePeer<'_>,
    request: MeshWireRequest,
    st: WireState<'_>,
    policy: &P,
) -> WireReply {
    let mut deferred = None;
    let response = handle_mesh_wire_request(peer, request, st, policy, &mut deferred);
    match deferred {
        Some(job) => WireReply::Deferred(Box::new(job)),
        None => WireReply::Ready(Box::new(response)),
    }
}

/// What a handler returns: a response now, or a relay forward to run off the swarm task.
pub enum WireReply {
    Ready(Box<MeshWireResponse>),
    Deferred(Box<RelayForward>),
}

impl WireReply {
    /// The immediate response, or `None` for a deferred relay forward.
    pub fn ready(self) -> Option<MeshWireResponse> {
        match self {
            WireReply::Ready(r) => Some(*r),
            WireReply::Deferred(_) => None,
        }
    }
}

/// Last relay: forward the envelope to the final target with its lease.
struct FinalHop {
    next_hop: String,
    envelope: crate::crypto::pqc::PqRelayedShardEnvelope,
    capability: crate::storage::BlindedShardCapability,
    voucher: crate::storage::AnonymousQuotaVoucher,
    lease: crate::storage::BlindedLeaseSpec,
}

enum RelayHop {
    Final(Box<FinalHop>),
    /// Middle relay: forward the peeled inner layer after the envelope's jitter.
    Layered {
        target: String,
        inner: crate::crypto::pqc::PqRelayedShardEnvelope,
    },
}

/// An onion relay forward taken off the swarm task (F-18): the jitter is a tokio sleep and the
/// blocking forward runs on the blocking pool, outside any handler lock. The relay still delays
/// each forward by the envelope's jitter, so the next hop sees the same timing as before.
pub struct RelayForward {
    client: crate::network::MeshClient,
    delay_ms: u64,
    hop: RelayHop,
}

impl RelayForward {
    /// Waits out the jitter, then forwards on the blocking pool and returns the ack to send.
    pub async fn run(self) -> MeshWireResponse {
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }
        match tokio::task::spawn_blocking(move || self.forward()).await {
            Ok(r) => r,
            Err(e) => relay_ack(Err(format!("relay forward task failed: {e}"))),
        }
    }

    fn forward(self) -> MeshWireResponse {
        let result = match self.hop {
            RelayHop::Final(hop) => {
                let FinalHop {
                    next_hop,
                    envelope,
                    capability,
                    voucher,
                    lease,
                } = *hop;
                self.client
                    .relay_pq_onion_envelope(&next_hop, None, envelope, capability, voucher, lease)
            }
            RelayHop::Layered { target, inner } => {
                self.client.relay_layered_pq_onion_envelope(&target, inner)
            }
        };
        relay_ack(result.map_err(|e| e.to_string()))
    }
}

fn relay_ack(result: Result<(), String>) -> MeshWireResponse {
    match result {
        Ok(()) => MeshWireResponse::RelayPqOnionAck {
            delivered: true,
            error: None,
        },
        Err(e) => MeshWireResponse::RelayPqOnionAck {
            delivered: false,
            error: Some(e),
        },
    }
}

fn handle_mesh_wire_request<P: WireRolePolicy>(
    peer: &WirePeer<'_>,
    request: MeshWireRequest,
    mut st: WireState<'_>,
    policy: &P,
    deferred: &mut Option<RelayForward>,
) -> MeshWireResponse {
    let class = admission_class(&request);
    if let Some(rejection) = admit(peer, &request, class, &mut st) {
        return rejection;
    }
    let WireState {
        node_identity,
        genesis_pubkey,
        block_store,
        server,
        wot,
        por_verifier,
        nullifier_ledger,
        pq_kem,
        wan_registry,
        eviction,
        takedown_queue,
    } = st;
    let remote_peer_id = peer.peer_id;
    let remote_addr = peer.addr;
    let remote_ip = peer.ip;
    let remote_pubkey = peer.pubkey;

    match request {
        MeshWireRequest::HandshakeWoT { chain, .. } => {
            let leaf_pk = chain.leaf_pubkey();
            if let Some(reason) = eviction.is_ingress_blocked(
                remote_ip,
                Some(remote_peer_id),
                leaf_pk.as_ref(),
                None,
                None,
            ) {
                warn!(%reason, peer = %remote_peer_id, "refused a handshake from a blocked peer");
                return handshake_refused();
            }
            if let Err(code) = WebOfTrustRegistry::ring_handshake_decision(wot.genesis_pubkey()) {
                warn!(code, peer = %remote_peer_id, "refused a handshake: this node is in no ring");
                return handshake_refused();
            }
            if let Err(code) = WebOfTrustRegistry::chain_leaf_decision(leaf_pk, remote_pubkey) {
                warn!(code, peer = %remote_peer_id, "refused a handshake for another key's chain");
                return handshake_refused();
            }
            match wot.verify_and_admit_chain(&chain) {
                Ok(_) => {
                    if let (Some(ip), Some(pk)) = (remote_ip, leaf_pk) {
                        let _ = eviction.record_peer_admission_ip(ip, pk);
                    }
                    MeshWireResponse::HandshakeAck {
                        accepted: true,
                        reason: None,
                    }
                }
                Err(e) => {
                    // ADR-15 Red-Team Fix (RT3-03): Never penalize `chain.leaf_pubkey()` on an
                    // unverified `HandshakeWoT` failure.
                    let code = handshake_refusal_code(&e);
                    warn!(code, error = %e, peer = %remote_peer_id, "refused a handshake");
                    handshake_refused()
                }
            }
        }
        MeshWireRequest::AdmitPublicTicket(ticket) => {
            let verifier_pubkey = node_identity.public_key_bytes();
            let required_pow_bits = wot.required_public_pow_bits();
            let ack =
                |admitted: bool, reason: Option<String>| MeshWireResponse::AdmitPublicTicketAck {
                    admitted,
                    reason,
                    verifier_pubkey,
                    required_pow_bits,
                };
            if let Some(reason) = eviction.is_ingress_blocked(
                remote_ip,
                Some(remote_peer_id),
                Some(&ticket.peer_pubkey),
                None,
                None,
            ) {
                return ack(false, Some(reason));
            }
            let subnet = remote_ip
                .map(PrivacyPreservingEvictionEngine::canonicalize_ip_subnet)
                .unwrap_or_else(|| "unknown".to_string());
            let facts = wot.ticket_facts(
                &ticket,
                remote_pubkey,
                verifier_pubkey,
                &subnet,
                now_unix_ms(),
            );
            if let Err(code) = WebOfTrustRegistry::public_ticket_decision(&facts) {
                warn!(code, peer = %remote_peer_id, "refused a public-commons ticket");
                return ack(false, Some("public-commons ticket refused".to_string()));
            }
            if facts.already_admitted {
                return ack(true, None);
            }
            match wot.verify_and_admit_public_ticket(&ticket) {
                Ok(()) => {
                    if let Some(ip) = remote_ip {
                        let _ = eviction.record_peer_admission_ip(ip, ticket.peer_pubkey);
                    }
                    ack(true, None)
                }
                Err(e) => ack(false, Some(e.to_string())),
            }
        }
        MeshWireRequest::PutShard {
            owner_peer_id,
            shard_id,
            shard_bytes,
            session_key_commit,
            repair_grant,
        } => {
            if let Some(reason) = eviction.is_ingress_blocked(
                remote_ip,
                Some(remote_peer_id),
                remote_pubkey.as_ref(),
                Some(&shard_id.stripe_merkle_root),
                None,
            ) {
                return MeshWireResponse::PutShardAck {
                    stored: false,
                    error: Some(reason),
                };
            }
            let Some(effective_owner) = shard_owner(peer, Some(owner_peer_id.as_str())) else {
                return MeshWireResponse::PutShardAck {
                    stored: false,
                    error: Some(OWNER_NOT_SENDER_TEXT.to_string()),
                };
            };
            let effective_owner = effective_owner.as_str();
            match block_store.put_shard(effective_owner, &shard_id, &shard_bytes) {
                Ok(_) => {
                    // The PoR session commit, like the grant, registers only after the owner
                    // decision and a successful store (a refused put must not replace it).
                    por_verifier.register_shard_session(&shard_id, session_key_commit);
                    // F-02a: a grant registers only after the shard is stored, for its stripe.
                    if let Some(grant) = repair_grant {
                        if let Err(code) =
                            por_verifier.register_repair_grant_for_stored(grant, &[shard_id])
                        {
                            warn!(code, peer = %remote_peer_id, "repair grant not registered");
                        }
                    }
                    let _ = eviction.record_regular_shard_ingress(
                        remote_ip,
                        Some(remote_peer_id),
                        remote_pubkey,
                        effective_owner,
                        shard_id,
                    );
                    if policy.record_put_shard_admission_ip() {
                        if let (Some(ip), Some(pk)) = (remote_ip, remote_pubkey) {
                            let _ = eviction.record_peer_admission_ip(ip, pk);
                        }
                    }
                    MeshWireResponse::PutShardAck {
                        stored: true,
                        error: None,
                    }
                }
                Err(e) => MeshWireResponse::PutShardAck {
                    stored: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::DeleteShard {
            shard_id,
            owner_signature: (owner_pub, payload, r, s),
        } => {
            let mut sig64 = [0u8; 64];
            sig64[..32].copy_from_slice(&r);
            sig64[32..].copy_from_slice(&s);
            let accounted_owner = block_store
                .quota()
                .lock()
                .ok()
                .and_then(|q| q.shard_owner(&shard_id.file_key()).map(str::to_string));
            if !por_verifier.authorize_owner_shard_delete(
                &shard_id,
                &owner_pub,
                payload.as_slice(),
                &sig64,
                accounted_owner.as_deref(),
            ) {
                return MeshWireResponse::DeleteShardAck {
                    deleted: false,
                    error: Some("unauthorized owner shard delete signature".to_string()),
                };
            }
            let Some(owner) = shard_owner(peer, None) else {
                return MeshWireResponse::DeleteShardAck {
                    deleted: false,
                    error: Some(OWNER_NOT_SENDER_TEXT.to_string()),
                };
            };
            match block_store.delete_shard(&owner, &shard_id) {
                Ok(deleted) => MeshWireResponse::DeleteShardAck {
                    deleted,
                    error: None,
                },
                Err(e) => MeshWireResponse::DeleteShardAck {
                    deleted: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::PorAudit(challenge) => {
            let now_ms = now_unix_ms();
            match por_verifier.handle_incoming_challenge(&challenge, now_ms, block_store) {
                // Answering a challenge earns the prover nothing (F-07): only a verifier's
                // own checks may credit a host.
                Ok(resp) => MeshWireResponse::PorAuditResult(Some(resp)),
                Err(e) => {
                    warn!(peer = remote_peer_id, error = %e, "Dropped PoR challenge in RAM pre-check");
                    MeshWireResponse::PorAuditResult(None)
                }
            }
        }
        MeshWireRequest::GetCiphertextShard {
            shard_id,
            owner_signature,
            repair_proof,
        } => {
            let owner_sig_storage;
            let owner_sig_ref = if let Some((owner_pub, payload, r, s)) = &owner_signature {
                let mut sig64 = [0u8; 64];
                sig64[..32].copy_from_slice(r);
                sig64[32..].copy_from_slice(s);
                owner_sig_storage = (*owner_pub, payload.as_slice(), sig64);
                Some((
                    owner_sig_storage.0,
                    owner_sig_storage.1,
                    &owner_sig_storage.2,
                ))
            } else {
                None
            };

            let repair_ref = repair_proof
                .as_ref()
                .map(|(grant, receipts)| (grant, receipts.as_slice()));

            match por_verifier.authorize_raw_shard_read(
                &shard_id,
                owner_sig_ref.as_ref(),
                repair_ref,
                block_store,
            ) {
                Ok(bytes) => MeshWireResponse::CiphertextShardResult {
                    shard_bytes: Some(bytes),
                    error: None,
                },
                Err(e) => MeshWireResponse::CiphertextShardResult {
                    shard_bytes: None,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::PutBlindedShard {
            blinded_id,
            shard_bytes,
            capability,
            voucher,
            current_epoch,
            lease_duration_epochs,
            delete_verifier,
        } => {
            if let Some(reason) = eviction
                .is_ingress_blocked(
                    remote_ip,
                    Some(remote_peer_id),
                    Some(&voucher.issuer_pubkey),
                    None,
                    Some(&blinded_id.locator),
                )
                .or_else(|| {
                    eviction.is_ingress_blocked(None, None, remote_pubkey.as_ref(), None, None)
                })
            {
                return MeshWireResponse::PutBlindedShardAck {
                    stored: false,
                    error: Some(reason),
                };
            }
            if let Some(err) =
                lease_limit_error(shard_bytes.len(), policy.max_probationary_lease_bytes())
            {
                return MeshWireResponse::PutBlindedShardAck {
                    stored: false,
                    error: Some(err),
                };
            }
            if !voucher_issuer_allowed(
                wot,
                nullifier_ledger,
                &voucher.issuer_pubkey,
                remote_peer_id,
            ) {
                return MeshWireResponse::PutBlindedShardAck {
                    stored: false,
                    error: Some(VOUCHER_ISSUER_UNTRUSTED_TEXT.to_string()),
                };
            }
            let issuer = voucher.issuer_pubkey;
            match nullifier_ledger.with_trusted_issuer(issuer, |ledger| {
                block_store.put_blinded_shard_with_lease(
                    &blinded_id,
                    &shard_bytes,
                    capability,
                    &voucher,
                    ledger,
                    crate::storage::BlindedLeaseSpec::new(
                        current_epoch,
                        lease_duration_epochs,
                        delete_verifier,
                    ),
                )
            }) {
                Ok(_) => {
                    let _ = eviction.record_blinded_shard_ingress(
                        remote_ip,
                        Some(remote_peer_id),
                        voucher.issuer_pubkey,
                        blinded_id,
                    );
                    if let Some(ip) = remote_ip {
                        let _ = eviction.record_peer_admission_ip(ip, voucher.issuer_pubkey);
                    }
                    MeshWireResponse::PutBlindedShardAck {
                        stored: true,
                        error: None,
                    }
                }
                Err(e) => MeshWireResponse::PutBlindedShardAck {
                    stored: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::GetBlindedShard {
            blinded_id,
            capability,
            timestamp_ms,
            read_sig,
        } => {
            if read_sig.len() != 64 {
                return MeshWireResponse::BlindedShardResult {
                    shard_bytes: None,
                    error: Some("invalid 64-byte capability signature length".to_string()),
                };
            }
            let mut sig64 = [0u8; 64];
            sig64.copy_from_slice(&read_sig);
            match block_store.get_blinded_shard_authorized(
                &blinded_id,
                &capability,
                timestamp_ms,
                &sig64,
            ) {
                Ok(bytes) => MeshWireResponse::BlindedShardResult {
                    shard_bytes: Some(bytes),
                    error: None,
                },
                Err(e) => MeshWireResponse::BlindedShardResult {
                    shard_bytes: None,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::RenewBlindedLease { .. } => {
            // Carries no credential (F-23): refused; use `RenewBlindedLeaseSigned`.
            let unsigned = RenewFacts {
                signed_by_capability: false,
                fresh: false,
                extension_epochs: 0,
            };
            if let Err(code) = renew_decision(&unsigned) {
                warn!(
                    code,
                    peer = remote_peer_id,
                    "refused an unsigned lease renewal"
                );
            }
            MeshWireResponse::RenewBlindedLeaseAck { renewed: false }
        }
        MeshWireRequest::RenewBlindedLeaseSigned {
            blinded_id,
            current_epoch,
            extension_epochs,
            timestamp_ms,
            sig,
        } => {
            let signed_by_capability = block_store
                .blinded_capability_pubkey(&blinded_id)
                .is_some_and(|pk| {
                    crate::storage::BlindedShardCapability {
                        locator: blinded_id.locator,
                        capability_pubkey: pk,
                    }
                    .verify_lease_renewal(
                        current_epoch,
                        extension_epochs,
                        timestamp_ms,
                        &sig,
                    )
                });
            let facts = RenewFacts {
                signed_by_capability,
                fresh: timestamp_ms.abs_diff(now_unix_ms())
                    <= crate::storage::MAX_CAPABILITY_CLOCK_SKEW_MS,
                extension_epochs,
            };
            if let Err(code) = renew_decision(&facts) {
                warn!(code, peer = remote_peer_id, "refused a lease renewal");
                return MeshWireResponse::RenewBlindedLeaseAck { renewed: false };
            }
            if eviction
                .is_ingress_blocked(
                    remote_ip,
                    Some(remote_peer_id),
                    remote_pubkey.as_ref(),
                    None,
                    Some(&blinded_id.locator),
                )
                .is_some()
            {
                return MeshWireResponse::RenewBlindedLeaseAck { renewed: false };
            }
            // The seed called `server.renew_blinded_lease`, a one-line delegate to this call on
            // the same (shared) store.
            let renewed =
                block_store.renew_blinded_shard_lease(&blinded_id, current_epoch, extension_epochs);
            MeshWireResponse::RenewBlindedLeaseAck { renewed }
        }
        MeshWireRequest::DeleteBlindedShardTombstone {
            blinded_id,
            tombstone,
        } => {
            let result = if policy.tombstone_via_seed_server() {
                server
                    .execute_blinded_tombstone(&blinded_id, &tombstone)
                    .map_err(|e| e.to_string())
            } else {
                block_store
                    .delete_blinded_shard_with_tombstone(&blinded_id, &tombstone)
                    .map_err(|e| e.to_string())
            };
            match result {
                Ok(deleted) => MeshWireResponse::DeleteBlindedShardAck {
                    deleted,
                    error: None,
                },
                Err(e) => MeshWireResponse::DeleteBlindedShardAck {
                    deleted: false,
                    error: Some(e),
                },
            }
        }
        MeshWireRequest::MultiSegmentPorAudit(challenge) => {
            let now_ms = now_unix_ms();
            match por_verifier.handle_multi_segment_challenge(&challenge, now_ms, block_store) {
                Ok(resp) => MeshWireResponse::MultiSegmentPorAuditResult(Some(resp)),
                Err(e) => {
                    warn!(peer = remote_peer_id, error = %e, "Dropped MultiSegmentPorAudit in RAM pre-check");
                    MeshWireResponse::MultiSegmentPorAuditResult(None)
                }
            }
        }
        MeshWireRequest::RelayPqOnionEnvelope {
            target_peer_addr,
            envelope,
            capability,
            voucher,
            current_epoch,
            lease_duration_epochs,
            delete_verifier,
        } => {
            if let Some(reason) = eviction.is_ingress_blocked(
                remote_ip,
                Some(remote_peer_id),
                remote_pubkey.as_ref(),
                None,
                None,
            ) {
                return MeshWireResponse::RelayPqOnionAck {
                    delivered: false,
                    error: Some(reason),
                };
            }
            if let Some(next_hop) = target_peer_addr {
                if let Some(client) = block_store.mesh_client() {
                    *deferred = Some(RelayForward {
                        client: client.clone(),
                        delay_ms: 0,
                        hop: RelayHop::Final(Box::new(FinalHop {
                            next_hop,
                            envelope,
                            capability,
                            voucher,
                            lease: crate::storage::BlindedLeaseSpec::new(
                                current_epoch,
                                lease_duration_epochs,
                                delete_verifier,
                            ),
                        })),
                    });
                    relay_ack(Err("deferred".to_string()))
                } else {
                    MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some("no MeshClient available for onion forwarding".to_string()),
                    }
                }
            } else if let Ok(hop) = envelope.peel_relay_hop_pq(pq_kem) {
                if let Some(client) = block_store.mesh_client() {
                    *deferred = Some(RelayForward {
                        client: client.clone(),
                        delay_ms: envelope.jitter_delay_ms.min(250),
                        hop: RelayHop::Layered {
                            target: hop.target_peer_addr,
                            inner: hop.inner_envelope,
                        },
                    });
                    relay_ack(Err("deferred".to_string()))
                } else {
                    MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some(
                            "no MeshClient available for 2-layer onion forwarding".to_string(),
                        ),
                    }
                }
            } else if let Ok(bundle) = envelope.open_final_target_pq(pq_kem) {
                if let Some(reason) = eviction.is_ingress_blocked(
                    remote_ip,
                    Some(remote_peer_id),
                    Some(&bundle.voucher.issuer_pubkey),
                    None,
                    Some(&bundle.blinded_id.locator),
                ) {
                    return MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some(reason),
                    };
                }
                if let Some(err) = lease_limit_error(
                    bundle.shard_bytes.len(),
                    policy.max_probationary_lease_bytes(),
                ) {
                    return MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some(err),
                    };
                }
                if !voucher_issuer_allowed(
                    wot,
                    nullifier_ledger,
                    &bundle.voucher.issuer_pubkey,
                    remote_peer_id,
                ) {
                    return MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some(VOUCHER_ISSUER_UNTRUSTED_TEXT.to_string()),
                    };
                }
                let issuer = bundle.voucher.issuer_pubkey;
                let voucher_pk = bundle.voucher.issuer_pubkey;
                let bid = bundle.blinded_id;
                match nullifier_ledger.with_trusted_issuer(issuer, |ledger| {
                    block_store.put_blinded_shard_with_lease(
                        &bundle.blinded_id,
                        &bundle.shard_bytes,
                        bundle.capability,
                        &bundle.voucher,
                        ledger,
                        crate::storage::BlindedLeaseSpec::new(
                            bundle.current_epoch,
                            bundle.lease_duration_epochs,
                            bundle.delete_verifier,
                        ),
                    )
                }) {
                    Ok(_) => {
                        let _ = eviction.record_blinded_shard_ingress(
                            remote_ip,
                            Some(remote_peer_id),
                            voucher_pk,
                            bid,
                        );
                        MeshWireResponse::RelayPqOnionAck {
                            delivered: true,
                            error: None,
                        }
                    }
                    Err(e) => MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some(e.to_string()),
                    },
                }
            } else {
                match envelope.open_pq(pq_kem) {
                    Ok((blinded_id, shard_bytes)) => {
                        if let Some(reason) = eviction.is_ingress_blocked(
                            remote_ip,
                            Some(remote_peer_id),
                            Some(&voucher.issuer_pubkey),
                            None,
                            Some(&blinded_id.locator),
                        ) {
                            return MeshWireResponse::RelayPqOnionAck {
                                delivered: false,
                                error: Some(reason),
                            };
                        }
                        if let Some(err) = lease_limit_error(
                            shard_bytes.len(),
                            policy.max_probationary_lease_bytes(),
                        ) {
                            return MeshWireResponse::RelayPqOnionAck {
                                delivered: false,
                                error: Some(err),
                            };
                        }
                        if !voucher_issuer_allowed(
                            wot,
                            nullifier_ledger,
                            &voucher.issuer_pubkey,
                            remote_peer_id,
                        ) {
                            return MeshWireResponse::RelayPqOnionAck {
                                delivered: false,
                                error: Some(VOUCHER_ISSUER_UNTRUSTED_TEXT.to_string()),
                            };
                        }
                        let issuer = voucher.issuer_pubkey;
                        let voucher_pk = voucher.issuer_pubkey;
                        match nullifier_ledger.with_trusted_issuer(issuer, |ledger| {
                            block_store.put_blinded_shard_with_lease(
                                &blinded_id,
                                &shard_bytes,
                                capability,
                                &voucher,
                                ledger,
                                crate::storage::BlindedLeaseSpec::new(
                                    current_epoch,
                                    lease_duration_epochs,
                                    delete_verifier,
                                ),
                            )
                        }) {
                            Ok(_) => {
                                let _ = eviction.record_blinded_shard_ingress(
                                    remote_ip,
                                    Some(remote_peer_id),
                                    voucher_pk,
                                    blinded_id,
                                );
                                MeshWireResponse::RelayPqOnionAck {
                                    delivered: true,
                                    error: None,
                                }
                            }
                            Err(e) => MeshWireResponse::RelayPqOnionAck {
                                delivered: false,
                                error: Some(e.to_string()),
                            },
                        }
                    }
                    Err(e) => MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some(e.to_string()),
                    },
                }
            }
        }
        MeshWireRequest::SyndicateLiteStripe {
            cert,
            bundle,
            repair_grant,
        } => {
            if let Some(reason) = eviction.is_ingress_blocked(
                remote_ip,
                Some(remote_peer_id),
                remote_pubkey.as_ref(),
                Some(&bundle.expected_stripe_merkle_root),
                None,
            ) {
                return MeshWireResponse::SyndicateLiteStripeAck {
                    receipt: None,
                    syndicated_peers: Vec::new(),
                    error: Some(reason),
                };
            }
            let sender_device =
                remote_pubkey.map(|pk| NodeIdentity::device_peer_id_for_pubkey(&pk));
            if let Err(code) = device_cert_decision(&cert.device_peer_id, sender_device.as_deref())
            {
                warn!(code, peer = %remote_peer_id, "refused a device cert issued to another device");
                return MeshWireResponse::SyndicateLiteStripeAck {
                    receipt: None,
                    syndicated_peers: Vec::new(),
                    error: Some("device cert does not name the sender".to_string()),
                };
            }
            let grant_to_register = repair_grant.clone();
            match server.ingest_and_syndicate_lite_stripe_with_grant(
                &cert,
                &bundle,
                &[],
                repair_grant,
            ) {
                Ok((receipt, syndicated_peers)) => {
                    // F-02a: register only after the stripe was ingested, for that stripe.
                    if let Some(grant) = grant_to_register {
                        if let Err(code) = por_verifier.register_repair_grant_for_stored(
                            grant,
                            &syndicated_shard_ids(&bundle, receipt.stripe_merkle_root),
                        ) {
                            warn!(code, peer = %remote_peer_id, "repair grant not registered");
                        }
                    }
                    MeshWireResponse::SyndicateLiteStripeAck {
                        receipt: Some(receipt),
                        syndicated_peers,
                        error: None,
                    }
                }
                Err(e) => MeshWireResponse::SyndicateLiteStripeAck {
                    receipt: None,
                    syndicated_peers: Vec::new(),
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::PutDhtEnvelope(env) => {
            let res = match env {
                DhtWireEnvelope::ClassicalManifest(m) => block_store.put_dht_manifest_envelope(m),
                DhtWireEnvelope::PostQuantumManifest(m) => {
                    block_store.put_dht_pq_manifest_envelope(m)
                }
                DhtWireEnvelope::VaultCatalog(m) => block_store.put_dht_vault_catalog_envelope(m),
            };
            match res {
                Ok(()) => MeshWireResponse::PutDhtEnvelopeAck {
                    stored: true,
                    error: None,
                },
                Err(e) => MeshWireResponse::PutDhtEnvelopeAck {
                    stored: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::GetDhtEnvelope { dht_key, kind } => {
            let found = match kind {
                DhtEnvelopeKind::ClassicalManifest => block_store
                    .get_dht_manifest_envelope(&dht_key)
                    .map(DhtWireEnvelope::ClassicalManifest),
                DhtEnvelopeKind::PostQuantumManifest => block_store
                    .get_dht_pq_manifest_envelope(&dht_key)
                    .map(DhtWireEnvelope::PostQuantumManifest),
                DhtEnvelopeKind::VaultCatalog => block_store
                    .get_dht_vault_catalog_envelope(&dht_key)
                    .map(DhtWireEnvelope::VaultCatalog),
            };
            if let Some(env) = found {
                MeshWireResponse::GetDhtEnvelopeResult {
                    envelope: Some(env),
                    error: None,
                }
            } else {
                MeshWireResponse::GetDhtEnvelopeResult {
                    envelope: None,
                    error: Some("DHT envelope not found".to_string()),
                }
            }
        }
        MeshWireRequest::QueryNodeStatus => {
            let rep = server.status_report(1);
            let available_bytes = rep.max_storage_bytes.saturating_sub(rep.used_storage_bytes);
            MeshWireResponse::NodeStatusResult {
                peer_id: server.server_peer_id().to_string(),
                asn: 64512,
                region: policy.status_region().to_string(),
                available_bytes,
                used_bytes: rep.used_storage_bytes,
                sla_score: rep.sla_ratio,
                pq_kem_pubkey: Some(pq_kem.public_key()),
            }
        }
        MeshWireRequest::RegisterWanRendezvous { slot_key, entry } => {
            let tracker_admin_pubkey = policy.tracker_admin_pubkey();
            if let Some(reason) = eviction
                .is_ingress_blocked(
                    remote_ip,
                    Some(remote_peer_id),
                    Some(&entry.ed25519_pubkey),
                    None,
                    None,
                )
                .or_else(|| {
                    eviction.is_ingress_blocked(None, None, remote_pubkey.as_ref(), None, None)
                })
            {
                return MeshWireResponse::RegisterWanRendezvousAck {
                    stored: false,
                    observed_external_addr: None,
                    error: Some(reason),
                    tracker_admin_pubkey,
                };
            }
            let observed_external_addr = remote_addr
                .and_then(|addr| reflect_observed_wan_multiaddr(addr, 0, remote_peer_id));
            let signer_pk = entry.ed25519_pubkey;
            let public_card_ips: Vec<IpAddr> =
                if policy.record_public_card_ips() && slot_key == PUBLIC_COMMONS_SWARM_SLOT {
                    open_public_tracker_card(&entry)
                        .ok()
                        .map(|card| {
                            card.wan_multiaddrs
                                .iter()
                                .filter_map(|s| s.parse::<Multiaddr>().ok())
                                .filter_map(|m| extract_ip_from_multiaddr(&m))
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
            let source_subnet =
                remote_ip.map(|ip| crate::bootstrap::canonical_sybil_subnet_key(ip, None));
            // F-22: the admission-IP map is written only for admitted signers.
            let signer_admitted = wot.is_peer_trusted(&signer_pk);
            match wan_registry.register_from(slot_key, entry, now_unix_ms(), source_subnet) {
                Ok(stored) => {
                    if stored && signer_admitted {
                        if let Some(ip) = remote_ip {
                            let _ = eviction.record_peer_admission_ip(ip, signer_pk);
                        }
                        for adv_ip in public_card_ips {
                            let _ = eviction.record_peer_admission_ip(adv_ip, signer_pk);
                        }
                    }
                    MeshWireResponse::RegisterWanRendezvousAck {
                        stored,
                        observed_external_addr,
                        error: None,
                        tracker_admin_pubkey,
                    }
                }
                Err(err) => MeshWireResponse::RegisterWanRendezvousAck {
                    stored: false,
                    observed_external_addr,
                    error: Some(err),
                    tracker_admin_pubkey,
                },
            }
        }
        MeshWireRequest::LookupWanRendezvous { slot_key } => {
            let observed_external_addr = remote_addr
                .and_then(|addr| reflect_observed_wan_multiaddr(addr, 0, remote_peer_id));
            let now = now_unix_ms();
            let entries = if slot_key == PUBLIC_COMMONS_SWARM_SLOT {
                wan_registry.lookup_public_swarm(32, now)
            } else {
                wan_registry.lookup(&slot_key, now)
            };
            MeshWireResponse::LookupWanRendezvousResult {
                entries,
                observed_external_addr,
                tracker_admin_pubkey: policy.tracker_admin_pubkey(),
            }
        }
        MeshWireRequest::SubmitAbuseTakedownReport(report) => {
            let report_id = report.report_id;
            if let Err(reason) = policy.takedown_gate(server.mode()) {
                return MeshWireResponse::SubmitAbuseTakedownAck {
                    queued_for_admin_review: false,
                    report_id,
                    verified_plaintext_sha256: None,
                    error: Some(reason),
                };
            }
            match takedown_queue.enqueue_verified_report(report) {
                Ok(outcome) => MeshWireResponse::SubmitAbuseTakedownAck {
                    queued_for_admin_review: true,
                    report_id,
                    verified_plaintext_sha256: Some(outcome.verified_plaintext_sha256),
                    error: None,
                },
                Err(err) => MeshWireResponse::SubmitAbuseTakedownAck {
                    queued_for_admin_review: false,
                    report_id,
                    verified_plaintext_sha256: None,
                    error: Some(err),
                },
            }
        }
        MeshWireRequest::BroadcastEvictionOrder(order) => {
            let (council, min_quorum) =
                policy.eviction_council(block_store, server.mode(), genesis_pubkey);
            let local_pk = node_identity.public_key_bytes();
            match eviction.apply_signed_eviction_order_with_quorum(
                &order,
                Some(&local_pk),
                &council,
                min_quorum,
                now_unix_ms(),
                block_store,
            ) {
                Ok(rep) => MeshWireResponse::EvictionOrderAck {
                    accepted: true,
                    purged_regular_shards: rep.purged_regular_shards,
                    purged_blinded_shards: rep.purged_blinded_shards,
                    zero_wiped_bytes: rep.zero_wiped_bytes,
                    error: None,
                },
                Err(err) => MeshWireResponse::EvictionOrderAck {
                    accepted: false,
                    purged_regular_shards: 0,
                    purged_blinded_shards: 0,
                    zero_wiped_bytes: 0,
                    error: Some(err.to_string()),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{
        BlindedShardTombstone, LiteStripeSyndicationBundle, PersonalDeviceCert,
    };
    use crate::config::ErasureTier;
    use crate::crypto::pqc::HybridPqSigningKeypair;
    use crate::crypto::{MasterKey, PqRelayedShardEnvelope};
    use crate::network::wan_rendezvous::{seal_public_tracker_card, WanPeerCard};
    use crate::network::wot::DelegationChain;
    use crate::por::{generate_multi_segment_por_challenge, generate_por_challenge};
    use crate::storage::{
        AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, EvictionTarget,
        FileManifest, ShardId, SignedDhtManifestEnvelope, VerifiableAbuseReport,
    };

    /// One request per variant (19), each paired with the response variant name it must
    /// produce on rejection and whether that response carries the reason string.
    fn all_requests() -> Vec<(MeshWireRequest, &'static str, bool)> {
        let id = NodeIdentity::from_seed([7; 32]);
        let shard_id = ShardId {
            stripe_merkle_root: [1; 32],
            shard_index: 0,
            shard_hash: [2; 32],
        };
        let mk = MasterKey::from_bytes([3; 32]);
        let bid = BlindedShardId::derive(&mk, &[4; 32], 0, b"x");
        let (_, cap) = BlindedShardCapability::derive_keypair(&mk, &bid.locator);
        let voucher = AnonymousQuotaVoucher::mint(&id, 64);
        let kem = HybridKemKeypair::generate().unwrap();
        let owner_pq = HybridPqSigningKeypair::generate().unwrap();
        let manifest = FileManifest {
            version: 2,
            file_merkle_root: [5; 32],
            file_salt: [6; 32],
            original_file_size: 1,
            stripe_size_bytes: 1024,
            tier: ErasureTier::Homelab,
            stripes: vec![],
            witness_peers: vec![],
        };
        let card = WanPeerCard::new(&id, "u", "daemon", vec![], None, None, 60, 1).unwrap();
        vec![
            (
                MeshWireRequest::HandshakeWoT {
                    chain: DelegationChain { hops: vec![] },
                    asn: None,
                    region: None,
                },
                "HandshakeAck",
                true,
            ),
            (
                MeshWireRequest::PutShard {
                    owner_peer_id: String::new(),
                    shard_id,
                    shard_bytes: vec![],
                    session_key_commit: [0; 32],
                    repair_grant: None,
                },
                "PutShardAck",
                true,
            ),
            (
                MeshWireRequest::PorAudit(generate_por_challenge(&[0; 32], shard_id, 64, 1)),
                "PorAuditResult",
                false,
            ),
            (
                MeshWireRequest::GetCiphertextShard {
                    shard_id,
                    owner_signature: None,
                    repair_proof: None,
                },
                "CiphertextShardResult",
                true,
            ),
            (
                MeshWireRequest::PutBlindedShard {
                    blinded_id: bid,
                    shard_bytes: vec![],
                    capability: cap,
                    voucher: voucher.clone(),
                    current_epoch: 1,
                    lease_duration_epochs: 1,
                    delete_verifier: [0; 32],
                },
                "PutBlindedShardAck",
                true,
            ),
            (
                MeshWireRequest::GetBlindedShard {
                    blinded_id: bid,
                    capability: cap,
                    timestamp_ms: 1,
                    read_sig: vec![],
                },
                "BlindedShardResult",
                true,
            ),
            (
                MeshWireRequest::RenewBlindedLease {
                    blinded_id: bid,
                    current_epoch: 1,
                    extension_epochs: 1,
                },
                "RenewBlindedLeaseAck",
                false,
            ),
            (
                MeshWireRequest::DeleteBlindedShardTombstone {
                    blinded_id: bid,
                    tombstone: BlindedShardTombstone::create(&[0; 32], bid.locator, [0; 16]),
                },
                "DeleteBlindedShardAck",
                true,
            ),
            (
                MeshWireRequest::MultiSegmentPorAudit(generate_multi_segment_por_challenge(
                    &[0; 32], shard_id, 64, 2, 10, 1,
                )),
                "MultiSegmentPorAuditResult",
                false,
            ),
            (
                MeshWireRequest::RelayPqOnionEnvelope {
                    target_peer_addr: None,
                    envelope: PqRelayedShardEnvelope::seal_pq(
                        &kem.public_key(),
                        "r",
                        &bid,
                        b"x",
                        0,
                    )
                    .unwrap(),
                    capability: cap,
                    voucher: voucher.clone(),
                    current_epoch: 1,
                    lease_duration_epochs: 1,
                    delete_verifier: [0; 32],
                },
                "RelayPqOnionAck",
                true,
            ),
            (
                MeshWireRequest::SyndicateLiteStripe {
                    cert: PersonalDeviceCert::issue(&owner_pq, "dev", "label", 1).unwrap(),
                    bundle: LiteStripeSyndicationBundle {
                        stripe_index: 0,
                        tier: ErasureTier::Homelab,
                        ciphertext_bytes: vec![],
                        expected_stripe_merkle_root: [0; 32],
                        expected_shard_hashes: vec![],
                    },
                    repair_grant: None,
                },
                "SyndicateLiteStripeAck",
                true,
            ),
            (
                MeshWireRequest::PutDhtEnvelope(DhtWireEnvelope::ClassicalManifest(
                    SignedDhtManifestEnvelope::seal(&mk, &id, &manifest, 1, 1).unwrap(),
                )),
                "PutDhtEnvelopeAck",
                true,
            ),
            (
                MeshWireRequest::GetDhtEnvelope {
                    dht_key: [0; 32],
                    kind: DhtEnvelopeKind::VaultCatalog,
                },
                "GetDhtEnvelopeResult",
                true,
            ),
            (
                MeshWireRequest::DeleteShard {
                    shard_id,
                    owner_signature: ([0; 32], vec![], [0; 32], [0; 32]),
                },
                "DeleteShardAck",
                true,
            ),
            (MeshWireRequest::QueryNodeStatus, "NodeStatusResult", false),
            (
                MeshWireRequest::RegisterWanRendezvous {
                    slot_key: PUBLIC_COMMONS_SWARM_SLOT,
                    entry: seal_public_tracker_card(&card, &id).unwrap(),
                },
                "RegisterWanRendezvousAck",
                true,
            ),
            (
                MeshWireRequest::LookupWanRendezvous { slot_key: [0; 32] },
                "LookupWanRendezvousResult",
                false,
            ),
            (
                MeshWireRequest::SubmitAbuseTakedownReport(VerifiableAbuseReport::submit_signed(
                    &id,
                    "r",
                    "d",
                    None,
                    manifest,
                    MasterKey::generate().to_hex(),
                    0,
                    vec![],
                    1,
                )),
                "SubmitAbuseTakedownAck",
                true,
            ),
            (
                MeshWireRequest::BroadcastEvictionOrder(SignedBadActorEvictionOrder::issue(
                    &id,
                    EvictionTarget::BlindedLocator([9; 32]),
                    "t",
                    1,
                    0,
                )),
                "EvictionOrderAck",
                true,
            ),
            (
                MeshWireRequest::AdmitPublicTicket(crate::network::wot::PublicCommonsTicket::mint(
                    &id, [0; 32], 1, 1,
                )),
                "AdmitPublicTicketAck",
                true,
            ),
        ]
    }

    #[test]
    fn reject_response_matches_each_variant() {
        let reqs = all_requests();
        assert_eq!(reqs.len(), 20);
        for (req, expected, carries_reason) in &reqs {
            let resp = format!("{:?}", reject_response(req, "admission-denied".into()));
            assert!(resp.starts_with(expected), "{expected}: {resp}");
            assert_eq!(
                resp.contains("admission-denied"),
                *carries_reason,
                "{expected}: {resp}"
            );
            assert!(
                !resp.contains("accepted: true")
                    && !resp.contains("stored: true")
                    && !resp.contains("deleted: true")
            );
        }
    }

    #[test]
    fn admission_decision_rules() {
        let facts = |class, sender_pubkey, sender_trusted| AdmissionFacts {
            class,
            sender_pubkey,
            sender_trusted,
        };
        let admitted = AdmissionClass::AdmittedPeer;
        assert_eq!(
            admission_decision(&facts(admitted, Some([1; 32]), true)),
            Ok(())
        );
        assert_eq!(
            admission_decision(&facts(admitted, Some([1; 32]), false)),
            Err("reject.peer_not_admitted")
        );
        // Fail closed when the transport identity carries no Ed25519 key.
        assert_eq!(
            admission_decision(&facts(admitted, None, true)),
            Err("reject.peer_key_unknown")
        );
        for class in [
            AdmissionClass::PreAdmission,
            AdmissionClass::SelfAuthorised,
            AdmissionClass::CouncilSigned,
        ] {
            assert_eq!(admission_decision(&facts(class, None, false)), Ok(()));
        }
    }

    #[test]
    fn admission_class_keeps_pre_admission_paths_open() {
        let classes: Vec<AdmissionClass> = all_requests()
            .iter()
            .map(|(r, _, _)| admission_class(r))
            .collect();
        let pre = classes
            .iter()
            .filter(|c| **c == AdmissionClass::PreAdmission)
            .count();
        assert_eq!(
            pre, 5,
            "handshake, public ticket, status, rendezvous register and lookup"
        );
        let admitted: Vec<&str> = all_requests()
            .iter()
            .filter(|(r, _, _)| admission_class(r) == AdmissionClass::AdmittedPeer)
            .map(|(_, name, _)| *name)
            .collect();
        assert_eq!(
            admitted.len(),
            5,
            "PutShard, SyndicateLiteStripe, PutDhtEnvelope, PutBlindedShard, RelayPqOnionEnvelope (F-33): {admitted:?}"
        );
        assert_eq!(
            admission_class(&MeshWireRequest::QueryNodeStatus),
            AdmissionClass::PreAdmission
        );
    }

    #[test]
    fn shard_owner_rule_binds_the_sender() {
        let facts = |claimed| OwnerFacts {
            claimed,
            sender_device_id: Some("parvault-peer-0011223344556677"),
            sender_peer_id: "12D3KooWsender",
        };
        for claim in [
            None,
            Some(""),
            Some("local"),
            Some("self"),
            Some("parvault-peer-0011223344556677"),
            Some("12D3KooWsender"),
        ] {
            assert_eq!(
                shard_owner_decision(&facts(claim)),
                Ok("parvault-peer-0011223344556677"),
                "{claim:?}"
            );
        }
        assert_eq!(
            shard_owner_decision(&facts(Some("alice"))),
            Err("reject.owner_not_sender")
        );
        let keyless = OwnerFacts {
            claimed: None,
            sender_device_id: None,
            sender_peer_id: "remote-peer",
        };
        assert_eq!(
            shard_owner_decision(&keyless),
            Err("reject.owner_not_sender"),
            "a sender without an Ed25519 key fails closed"
        );
    }
}
