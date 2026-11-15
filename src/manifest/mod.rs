//! The compiled-in manifest (L-16 seam, `v0.5.5`).
//!
//! A manifest fixes, at compile time, which wire variants a node serves and how a sender is
//! admitted. Exactly one `manifest-*` feature is enabled; [`Active`] names it. This module is
//! compiled only under `daemon-runtime` (G-1 C1): socket-only binaries carry no manifest.
//!
//! Selection is compile time only. `scripts/check_manifest_cfg.sh` fails any
//! `feature = "manifest-…"` outside this file and `Cargo.toml`, so no claimed function grows a
//! manifest branch. `Manifest::ID` enters no wire or signed payload in `v0.5.x` (G-1 C9).

use crate::network::behaviour::MeshWireRequest;
use crate::network::wire_handler::WirePeer;
use crate::network::wot::{DelegationChain, PublicCommonsTicket, WebOfTrustRegistry};
use crate::storage::PrivacyPreservingEvictionEngine;

#[cfg(not(any(
    feature = "manifest-household-ring-v1",
    feature = "manifest-test-restricted"
)))]
compile_error!(
    "parvault: no manifest selected; enable exactly one manifest-* feature with daemon-runtime (default: manifest-household-ring-v1)"
);

#[cfg(all(
    feature = "manifest-household-ring-v1",
    feature = "manifest-test-restricted"
))]
compile_error!(
    "parvault: more than one manifest selected; enable exactly one manifest-* feature (--all-features is not supported)"
);

// Each manifest module is gated at its `mod` line (G-1 C6), so code that names an inactive one
// does not compile; the role impls name only `Active`.
#[cfg(feature = "manifest-household-ring-v1")]
pub mod household_ring_v1;
#[cfg(feature = "manifest-test-restricted")]
pub mod test_restricted;

/// The manifest this build serves.
#[cfg(feature = "manifest-household-ring-v1")]
pub type Active = household_ring_v1::HouseholdRingV1;
/// The manifest this build serves (CI only; never shipped, `scripts/build_bins.sh` refuses it).
#[cfg(all(
    feature = "manifest-test-restricted",
    not(feature = "manifest-household-ring-v1")
))]
pub type Active = test_restricted::TestRestricted;

/// One compiled-in manifest.
pub trait Manifest {
    /// Printed by `--version` and local status only (C9).
    const NAME: &'static str;
    /// SHA-256 of `parvault-manifest-v1:<NAME>`. Not sent on the wire in `v0.5.x` (C9).
    const ID: [u8; 32];
    /// `<binary version> (manifest <NAME>)`, for clap's `version`.
    const VERSION_LINE: &'static str;
    type Admission: AdmissionPolicy;
}

/// The name of the active manifest.
pub const ACTIVE_NAME: &str = <Active as Manifest>::NAME;
/// The `--version` text of every daemon-runtime binary.
pub const ACTIVE_VERSION_LINE: &str = <Active as Manifest>::VERSION_LINE;

/// Admission facts and credential arms a manifest supplies (S2-S4). Stateless: the node state a
/// decision reads is passed in, so one zero-sized type per manifest is the whole dispatch.
pub trait AdmissionPolicy {
    /// S3: whether this manifest serves a wire variant at all.
    fn variant_enabled(kind: WireKind) -> bool;
    /// S2: the sender (its Ed25519 key) is admitted and not quarantined.
    fn is_admitted(wot: &WebOfTrustRegistry, sender: &[u8; 32], now_ms: u64) -> bool;
    /// S4: a credential arm (`HandshakeWoT`, `AdmitPublicTicket`). Logs its own refusal code.
    fn admit(
        ctx: AdmitCtx<'_>,
        cred: Credential<'_>,
        sender: &WirePeer<'_>,
        now_ms: u64,
    ) -> AdmitOutcome;
}

/// Node state a credential arm may read and change.
pub struct AdmitCtx<'a> {
    pub wot: &'a mut WebOfTrustRegistry,
    pub eviction: &'a mut PrivacyPreservingEvictionEngine,
    /// This node's Ed25519 key (a public ticket is bound to its verifier).
    pub verifier_pubkey: [u8; 32],
}

/// A credential presented on the wire.
pub enum Credential<'a> {
    Handshake(&'a DelegationChain),
    PublicTicket(&'a PublicCommonsTicket),
}

/// What a credential arm decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitOutcome {
    Admitted,
    /// Already admitted; nothing changed.
    AlreadyAdmitted,
    /// Refused. `reason` is the text a public-ticket ack carries (a handshake always sends
    /// `HANDSHAKE_REFUSED_TEXT`); the reason code went to the local log.
    Refused {
        reason: Option<String>,
    },
}

/// The text a peer gets for such a variant, in the request's existing refusal shape (C8).
pub const VARIANT_DISABLED_TEXT: &str = "request type not served by this node's manifest";

/// S3: the single variant decision (claim `MAN-VARIANT`). Runs before admission and before any
/// state change, so a refused variant spends nothing.
pub fn manifest_variant_decision(enabled: bool) -> Result<(), &'static str> {
    if enabled {
        Ok(())
    } else {
        Err("reject.variant_disabled_by_manifest")
    }
}

/// A fieldless mirror of [`MeshWireRequest`]. The `From` match is exhaustive, so a new variant
/// must be named here to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireKind {
    HandshakeWoT,
    PutShard,
    PorAudit,
    GetCiphertextShard,
    PutBlindedShard,
    GetBlindedShard,
    RenewBlindedLease,
    DeleteBlindedShardTombstone,
    MultiSegmentPorAudit,
    RelayPqOnionEnvelope,
    SyndicateLiteStripe,
    PutDhtEnvelope,
    GetDhtEnvelope,
    DeleteShard,
    QueryNodeStatus,
    RegisterWanRendezvous,
    LookupWanRendezvous,
    SubmitAbuseTakedownReport,
    BroadcastEvictionOrder,
    AdmitPublicTicket,
    RenewBlindedLeaseSigned,
    DeleteBlindedShardSigned,
    GetCouncilManifest,
    ChunkAudit,
}

impl WireKind {
    /// Every kind, in `MeshWireRequest` order.
    pub const ALL: [WireKind; 24] = [
        WireKind::HandshakeWoT,
        WireKind::PutShard,
        WireKind::PorAudit,
        WireKind::GetCiphertextShard,
        WireKind::PutBlindedShard,
        WireKind::GetBlindedShard,
        WireKind::RenewBlindedLease,
        WireKind::DeleteBlindedShardTombstone,
        WireKind::MultiSegmentPorAudit,
        WireKind::RelayPqOnionEnvelope,
        WireKind::SyndicateLiteStripe,
        WireKind::PutDhtEnvelope,
        WireKind::GetDhtEnvelope,
        WireKind::DeleteShard,
        WireKind::QueryNodeStatus,
        WireKind::RegisterWanRendezvous,
        WireKind::LookupWanRendezvous,
        WireKind::SubmitAbuseTakedownReport,
        WireKind::BroadcastEvictionOrder,
        WireKind::AdmitPublicTicket,
        WireKind::RenewBlindedLeaseSigned,
        WireKind::DeleteBlindedShardSigned,
        WireKind::GetCouncilManifest,
        WireKind::ChunkAudit,
    ];
}

impl From<&MeshWireRequest> for WireKind {
    fn from(r: &MeshWireRequest) -> Self {
        match r {
            MeshWireRequest::HandshakeWoT { .. } => WireKind::HandshakeWoT,
            MeshWireRequest::PutShard { .. } => WireKind::PutShard,
            MeshWireRequest::PorAudit(_) => WireKind::PorAudit,
            MeshWireRequest::GetCiphertextShard { .. } => WireKind::GetCiphertextShard,
            MeshWireRequest::PutBlindedShard { .. } => WireKind::PutBlindedShard,
            MeshWireRequest::GetBlindedShard { .. } => WireKind::GetBlindedShard,
            MeshWireRequest::RenewBlindedLease { .. } => WireKind::RenewBlindedLease,
            MeshWireRequest::DeleteBlindedShardTombstone { .. } => {
                WireKind::DeleteBlindedShardTombstone
            }
            MeshWireRequest::MultiSegmentPorAudit(_) => WireKind::MultiSegmentPorAudit,
            MeshWireRequest::RelayPqOnionEnvelope { .. } => WireKind::RelayPqOnionEnvelope,
            MeshWireRequest::SyndicateLiteStripe { .. } => WireKind::SyndicateLiteStripe,
            MeshWireRequest::PutDhtEnvelope(_) => WireKind::PutDhtEnvelope,
            MeshWireRequest::GetDhtEnvelope { .. } => WireKind::GetDhtEnvelope,
            MeshWireRequest::DeleteShard { .. } => WireKind::DeleteShard,
            MeshWireRequest::QueryNodeStatus => WireKind::QueryNodeStatus,
            MeshWireRequest::RegisterWanRendezvous { .. } => WireKind::RegisterWanRendezvous,
            MeshWireRequest::LookupWanRendezvous { .. } => WireKind::LookupWanRendezvous,
            MeshWireRequest::SubmitAbuseTakedownReport(_) => WireKind::SubmitAbuseTakedownReport,
            MeshWireRequest::BroadcastEvictionOrder(_) => WireKind::BroadcastEvictionOrder,
            MeshWireRequest::AdmitPublicTicket(_) => WireKind::AdmitPublicTicket,
            MeshWireRequest::RenewBlindedLeaseSigned { .. } => WireKind::RenewBlindedLeaseSigned,
            MeshWireRequest::DeleteBlindedShardSigned { .. } => WireKind::DeleteBlindedShardSigned,
            MeshWireRequest::GetCouncilManifest { .. } => WireKind::GetCouncilManifest,
            MeshWireRequest::ChunkAudit(_) => WireKind::ChunkAudit,
        }
    }
}

/// `SHA-256("parvault-manifest-v1:" || name)`, the derivation of every `Manifest::ID`.
pub fn manifest_id_for(name: &str) -> [u8; 32] {
    let mut buf = b"parvault-manifest-v1:".to_vec();
    buf.extend_from_slice(name.as_bytes());
    crate::crypto::compute_sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_manifest_id_and_version_line_derive_from_its_name() {
        assert_eq!(<Active as Manifest>::ID, manifest_id_for(ACTIVE_NAME));
        assert!(ACTIVE_VERSION_LINE.starts_with(env!("CARGO_PKG_VERSION")));
        assert!(ACTIVE_VERSION_LINE.ends_with(&format!("(manifest {ACTIVE_NAME})")));
    }

    #[test]
    fn manifest_variant_decision_refuses_iff_disabled() {
        assert_eq!(manifest_variant_decision(true), Ok(()));
        assert_eq!(
            manifest_variant_decision(false),
            Err("reject.variant_disabled_by_manifest")
        );
    }

    /// Which variants the active manifest serves: all of them in the household manifest, all but
    /// the two credential arms in the test-restricted one.
    #[test]
    fn active_manifest_variant_set() {
        type A = <Active as Manifest>::Admission;
        let restricted = ACTIVE_NAME == "test-restricted";
        for k in WireKind::ALL {
            let off =
                restricted && matches!(k, WireKind::HandshakeWoT | WireKind::AdmitPublicTicket);
            assert_eq!(A::variant_enabled(k), !off, "{k:?}");
        }
    }
}
