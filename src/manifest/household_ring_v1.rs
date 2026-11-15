//! `household-ring-v1`: the shipped manifest. Serves every wire variant; admits a sender by ring
//! chain (`HandshakeWoT`) or public-commons ticket (`AdmitPublicTicket`), with the run-time
//! `TrustPoolMode` switch kept (D-45 Q5). The bodies below moved here unchanged from the
//! `HandshakeWoT` and `AdmitPublicTicket` arms of `handle_mesh_wire_request` (S4); the shared
//! decisions they call stay in `wot.rs`, cfg-free.

use super::{AdmissionPolicy, AdmitCtx, AdmitOutcome, Credential, Manifest, WireKind};
use crate::network::wire_handler::{handshake_refusal_code, WirePeer};
use crate::network::wot::WebOfTrustRegistry;
use crate::storage::PrivacyPreservingEvictionEngine;
use tracing::warn;

/// The household-ring manifest.
pub struct HouseholdRingV1;

/// Its admission policy.
pub struct HouseholdRingV1Admission;

impl Manifest for HouseholdRingV1 {
    const NAME: &'static str = "household-ring-v1";
    const ID: [u8; 32] = [
        0x33, 0x9b, 0x31, 0x6f, 0x8e, 0x74, 0x70, 0x8d, 0x4a, 0xa4, 0x5b, 0x4f, 0x18, 0xa2, 0x90,
        0x91, 0x62, 0xd5, 0x1b, 0xf5, 0xcd, 0xe2, 0x9a, 0x7f, 0xbe, 0xdd, 0x95, 0x42, 0x94, 0x56,
        0xf5, 0x8d,
    ];
    const VERSION_LINE: &'static str =
        concat!(env!("CARGO_PKG_VERSION"), " (manifest household-ring-v1)");
    type Admission = HouseholdRingV1Admission;
}

impl AdmissionPolicy for HouseholdRingV1Admission {
    fn variant_enabled(_kind: WireKind) -> bool {
        true
    }

    fn is_admitted(wot: &WebOfTrustRegistry, sender: &[u8; 32], _now_ms: u64) -> bool {
        wot.is_peer_trusted(sender)
    }

    fn admit(
        ctx: AdmitCtx<'_>,
        cred: Credential<'_>,
        sender: &WirePeer<'_>,
        now_ms: u64,
    ) -> AdmitOutcome {
        match cred {
            Credential::Handshake(chain) => admit_handshake(ctx, chain, sender),
            Credential::PublicTicket(ticket) => admit_ticket(ctx, ticket, sender, now_ms),
        }
    }
}

fn refused() -> AdmitOutcome {
    AdmitOutcome::Refused { reason: None }
}

fn admit_handshake(
    ctx: AdmitCtx<'_>,
    chain: &crate::network::wot::DelegationChain,
    peer: &WirePeer<'_>,
) -> AdmitOutcome {
    let AdmitCtx { wot, eviction, .. } = ctx;
    let leaf_pk = chain.leaf_pubkey();
    if let Some(reason) =
        eviction.is_ingress_blocked(peer.ip, Some(peer.peer_id), leaf_pk.as_ref(), None, None)
    {
        warn!(%reason, peer = %peer.peer_id, "refused a handshake from a blocked peer");
        return refused();
    }
    if let Err(code) = WebOfTrustRegistry::ring_handshake_decision(wot.genesis_pubkey()) {
        warn!(code, peer = %peer.peer_id, "refused a handshake: this node is in no ring");
        return refused();
    }
    if let Err(code) = WebOfTrustRegistry::chain_leaf_decision(leaf_pk, peer.pubkey) {
        warn!(code, peer = %peer.peer_id, "refused a handshake for another key's chain");
        return refused();
    }
    match wot.verify_and_admit_chain(chain) {
        Ok(_) => {
            if let (Some(ip), Some(pk)) = (peer.ip, leaf_pk) {
                let _ = eviction.record_peer_admission_ip(ip, pk);
            }
            AdmitOutcome::Admitted
        }
        Err(e) => {
            // ADR-05 Red-Team Fix (RT3-03): Never penalize `chain.leaf_pubkey()` on an
            // unverified `HandshakeWoT` failure.
            let code = handshake_refusal_code(&e);
            warn!(code, error = %e, peer = %peer.peer_id, "refused a handshake");
            refused()
        }
    }
}

fn admit_ticket(
    ctx: AdmitCtx<'_>,
    ticket: &crate::network::wot::PublicCommonsTicket,
    peer: &WirePeer<'_>,
    now_ms: u64,
) -> AdmitOutcome {
    let AdmitCtx {
        wot,
        eviction,
        verifier_pubkey,
    } = ctx;
    if let Some(reason) = eviction.is_ingress_blocked(
        peer.ip,
        Some(peer.peer_id),
        Some(&ticket.peer_pubkey),
        None,
        None,
    ) {
        return AdmitOutcome::Refused {
            reason: Some(reason),
        };
    }
    let subnet = peer
        .ip
        .map(PrivacyPreservingEvictionEngine::canonicalize_ip_subnet)
        .unwrap_or_else(|| "unknown".to_string());
    let facts = wot.ticket_facts(ticket, peer.pubkey, verifier_pubkey, &subnet, now_ms);
    if let Err(code) = WebOfTrustRegistry::public_ticket_decision(&facts) {
        warn!(code, peer = %peer.peer_id, "refused a public-commons ticket");
        return AdmitOutcome::Refused {
            reason: Some("public-commons ticket refused".to_string()),
        };
    }
    if facts.already_admitted {
        return AdmitOutcome::AlreadyAdmitted;
    }
    match wot.verify_and_admit_public_ticket(ticket) {
        Ok(()) => {
            if let Some(ip) = peer.ip {
                let _ = eviction.record_peer_admission_ip(ip, ticket.peer_pubkey);
            }
            AdmitOutcome::Admitted
        }
        Err(e) => AdmitOutcome::Refused {
            reason: Some(e.to_string()),
        },
    }
}
