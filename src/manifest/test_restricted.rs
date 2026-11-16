//! `test-restricted`: a CI-only manifest that serves no credential arm (`HandshakeWoT`,
//! `AdmitPublicTicket`), so the per-manifest job is not vacuous before a second real manifest
//! exists (G-1 ruling 5, L-91). Never shipped: `scripts/build_bins.sh` refuses any manifest
//! feature but the default. With no credential arm nothing can be admitted on the wire, so the
//! shared claim suite (which needs `HandshakeWoT`) does not run against it (C10).

use super::{AdmissionPolicy, AdmitCtx, AdmitOutcome, Credential, Manifest, WireKind};
use crate::network::wire_handler::WirePeer;
use crate::network::wot::WebOfTrustRegistry;

/// The test-only restricted manifest.
pub struct TestRestricted;

/// Its admission policy.
pub struct TestRestrictedAdmission;

impl Manifest for TestRestricted {
    const NAME: &'static str = "test-restricted";
    const ID: [u8; 32] = [
        0x1d, 0x30, 0x14, 0x9e, 0xc2, 0x32, 0x64, 0x45, 0xd6, 0x69, 0x55, 0x4e, 0x39, 0xa1, 0x39,
        0x87, 0x5c, 0x81, 0x76, 0x72, 0x29, 0xa5, 0x6a, 0x92, 0xb3, 0x4b, 0xd5, 0x5a, 0x1a, 0xb4,
        0x91, 0x9e,
    ];
    const VERSION_LINE: &'static str =
        concat!(env!("CARGO_PKG_VERSION"), " (manifest test-restricted)");
    type Admission = TestRestrictedAdmission;
}

impl AdmissionPolicy for TestRestrictedAdmission {
    fn variant_enabled(kind: WireKind) -> bool {
        !matches!(kind, WireKind::HandshakeWoT | WireKind::AdmitPublicTicket)
    }

    fn is_admitted(wot: &WebOfTrustRegistry, sender: &[u8; 32], _now_ms: u64) -> bool {
        wot.is_peer_trusted(sender)
    }

    /// Unreachable from the wire (both credential variants are refused first); fails closed.
    fn admit(
        _ctx: AdmitCtx<'_>,
        _cred: Credential<'_>,
        _sender: &WirePeer<'_>,
        _now_ms: u64,
    ) -> AdmitOutcome {
        AdmitOutcome::Refused { reason: None }
    }
}
