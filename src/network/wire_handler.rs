//! Inbound `MeshWireRequest` handlers for the `parvault` daemon and the
//! `parvault-seed` server.
//!
//! Moved verbatim from `src/main.rs` and `src/bin/parvault-seed.rs`; behaviour
//! and wire format are unchanged.

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

fn seed_now_ms() -> u64 {
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
    genesis_pubkey: [u8; 32],
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
            push_pk(genesis_pubkey);
            let min_quorum = quorum_override.unwrap_or(1).max(1);
            (council, min_quorum)
        }
    }
}

/// State borrowed by the daemon wire handler for one request.
pub struct DaemonWireHandlerCtx<'a> {
    pub cfg: &'a NodeConfig,
    pub node_identity: &'a NodeIdentity,
    pub genesis_pubkey: [u8; 32],
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

/// Handles one inbound request on the `parvault` daemon.
pub fn handle_daemon_wire_request(
    remote_peer_id: &str,
    remote_addr: Option<&Multiaddr>,
    request: MeshWireRequest,
    ctx: DaemonWireHandlerCtx<'_>,
) -> MeshWireResponse {
    let DaemonWireHandlerCtx {
        cfg,
        node_identity,
        genesis_pubkey,
        public_mode,
        block_store,
        wot,
        por_verifier,
        nullifier_ledger,
        pq_kem,
        lite_seed_server,
        wan_registry,
        eviction,
        takedown_queue,
    } = ctx;
    let remote_ip = remote_addr.and_then(extract_ip_from_multiaddr);
    let remote_pubkey = NodeConfig::extract_ed25519_pubkey_from_peer_str(remote_peer_id);

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
                return MeshWireResponse::HandshakeAck {
                    accepted: false,
                    reason: Some(reason),
                };
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
                    MeshWireResponse::HandshakeAck {
                        accepted: false,
                        reason: Some(e.to_string()),
                    }
                }
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
            if let Some(grant) = repair_grant {
                por_verifier.register_repair_grant(grant);
            }
            por_verifier.register_shard_session(&shard_id, session_key_commit);
            let effective_owner = if owner_peer_id.is_empty()
                || owner_peer_id == "local"
                || owner_peer_id == "self"
            {
                remote_peer_id
            } else {
                owner_peer_id.as_str()
            };
            match block_store.put_shard(effective_owner, &shard_id, &shard_bytes) {
                Ok(_) => {
                    let _ = eviction.record_regular_shard_ingress(
                        remote_ip,
                        Some(remote_peer_id),
                        remote_pubkey,
                        effective_owner,
                        shard_id,
                    );
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
            if !por_verifier.authorize_owner_shard_delete(
                &shard_id,
                &owner_pub,
                payload.as_slice(),
                &sig64,
            ) {
                return MeshWireResponse::DeleteShardAck {
                    deleted: false,
                    error: Some("unauthorized owner shard delete signature".to_string()),
                };
            }
            match block_store.delete_shard(remote_peer_id, &shard_id) {
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
            nullifier_ledger.set_trusted_issuer_pubkey(voucher.issuer_pubkey);
            match block_store.put_blinded_shard_with_lease(
                &blinded_id,
                &shard_bytes,
                capability,
                &voucher,
                nullifier_ledger,
                crate::storage::BlindedLeaseSpec::new(
                    current_epoch,
                    lease_duration_epochs,
                    delete_verifier,
                ),
            ) {
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
        MeshWireRequest::RenewBlindedLease {
            blinded_id,
            current_epoch,
            extension_epochs,
        } => {
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
            let renewed =
                block_store.renew_blinded_shard_lease(&blinded_id, current_epoch, extension_epochs);
            MeshWireResponse::RenewBlindedLeaseAck { renewed }
        }
        MeshWireRequest::DeleteBlindedShardTombstone {
            blinded_id,
            tombstone,
        } => match block_store.delete_blinded_shard_with_tombstone(&blinded_id, &tombstone) {
            Ok(deleted) => MeshWireResponse::DeleteBlindedShardAck {
                deleted,
                error: None,
            },
            Err(e) => MeshWireResponse::DeleteBlindedShardAck {
                deleted: false,
                error: Some(e.to_string()),
            },
        },
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
                    match client.relay_pq_onion_envelope(
                        &next_hop,
                        None,
                        envelope,
                        capability,
                        voucher,
                        crate::storage::BlindedLeaseSpec::new(
                            current_epoch,
                            lease_duration_epochs,
                            delete_verifier,
                        ),
                    ) {
                        Ok(()) => MeshWireResponse::RelayPqOnionAck {
                            delivered: true,
                            error: None,
                        },
                        Err(e) => MeshWireResponse::RelayPqOnionAck {
                            delivered: false,
                            error: Some(e.to_string()),
                        },
                    }
                } else {
                    MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some("no MeshClient available for onion forwarding".to_string()),
                    }
                }
            } else if let Ok(hop) = envelope.peel_relay_hop_pq(pq_kem) {
                if envelope.jitter_delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(envelope.jitter_delay_ms.min(250)));
                }
                if let Some(client) = block_store.mesh_client() {
                    match client
                        .relay_layered_pq_onion_envelope(&hop.target_peer_addr, hop.inner_envelope)
                    {
                        Ok(()) => MeshWireResponse::RelayPqOnionAck {
                            delivered: true,
                            error: None,
                        },
                        Err(e) => MeshWireResponse::RelayPqOnionAck {
                            delivered: false,
                            error: Some(e.to_string()),
                        },
                    }
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
                nullifier_ledger.set_trusted_issuer_pubkey(bundle.voucher.issuer_pubkey);
                let voucher_pk = bundle.voucher.issuer_pubkey;
                let bid = bundle.blinded_id;
                match block_store.put_blinded_shard_with_lease(
                    &bundle.blinded_id,
                    &bundle.shard_bytes,
                    bundle.capability,
                    &bundle.voucher,
                    nullifier_ledger,
                    crate::storage::BlindedLeaseSpec::new(
                        bundle.current_epoch,
                        bundle.lease_duration_epochs,
                        bundle.delete_verifier,
                    ),
                ) {
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
                        nullifier_ledger.set_trusted_issuer_pubkey(voucher.issuer_pubkey);
                        let voucher_pk = voucher.issuer_pubkey;
                        match block_store.put_blinded_shard_with_lease(
                            &blinded_id,
                            &shard_bytes,
                            capability,
                            &voucher,
                            nullifier_ledger,
                            crate::storage::BlindedLeaseSpec::new(
                                current_epoch,
                                lease_duration_epochs,
                                delete_verifier,
                            ),
                        ) {
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
            if let Some(ref grant) = repair_grant {
                por_verifier.register_repair_grant(grant.clone());
            }
            match lite_seed_server.ingest_and_syndicate_lite_stripe_with_grant(
                &cert,
                &bundle,
                &[],
                repair_grant,
            ) {
                Ok((receipt, syndicated_peers)) => MeshWireResponse::SyndicateLiteStripeAck {
                    receipt: Some(receipt),
                    syndicated_peers,
                    error: None,
                },
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
            let rep = lite_seed_server.status_report(1);
            let available_bytes = rep.max_storage_bytes.saturating_sub(rep.used_storage_bytes);
            MeshWireResponse::NodeStatusResult {
                peer_id: lite_seed_server.server_peer_id().to_string(),
                asn: 64512,
                region: "local-neighborhood".to_string(),
                available_bytes,
                used_bytes: rep.used_storage_bytes,
                sla_score: rep.sla_ratio,
                pq_kem_pubkey: Some(pq_kem.public_key()),
            }
        }
        MeshWireRequest::RegisterWanRendezvous { slot_key, entry } => {
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
                    tracker_admin_pubkey: None,
                };
            }
            let observed_external_addr = remote_addr
                .and_then(|addr| reflect_observed_wan_multiaddr(addr, 0, remote_peer_id));
            let signer_pk = entry.ed25519_pubkey;
            match wan_registry.register(slot_key, entry, now_unix_ms()) {
                Ok(stored) => {
                    if stored {
                        if let Some(ip) = remote_ip {
                            let _ = eviction.record_peer_admission_ip(ip, signer_pk);
                        }
                    }
                    MeshWireResponse::RegisterWanRendezvousAck {
                        stored,
                        observed_external_addr,
                        error: None,
                        tracker_admin_pubkey: None,
                    }
                }
                Err(err) => MeshWireResponse::RegisterWanRendezvousAck {
                    stored: false,
                    observed_external_addr,
                    error: Some(err),
                    tracker_admin_pubkey: None,
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
                tracker_admin_pubkey: None,
            }
        }
        MeshWireRequest::SubmitAbuseTakedownReport(report) => {
            let report_id = report.report_id;
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
            let mut pinned_admins =
                KnownPeersStore::load(&cfg.data_dir).pinned_tracker_admin_pubkeys();
            if let Some(mc) = block_store.mesh_client() {
                for pk in mc.pinned_tracker_admin_pubkeys() {
                    if !pinned_admins.contains(&pk) {
                        pinned_admins.push(pk);
                    }
                }
            }
            let (council, min_quorum) = cfg.resolve_eviction_council_and_quorum(
                genesis_pubkey,
                &pinned_admins,
                public_mode,
            );
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

/// State borrowed by the seed wire handler for one request.
pub struct SeedWireHandlerCtx<'a> {
    pub data_dir: &'a Path,
    pub node_identity: &'a NodeIdentity,
    pub advertised_admin_pk: Option<[u8; 32]>,
    pub local_tracker_admin_pk: Option<[u8; 32]>,
    pub extra_council_pks: &'a [[u8; 32]],
    pub council_quorum: Option<usize>,
    pub max_probationary_lease_bytes: u64,
    pub genesis_pubkey: [u8; 32],
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

/// Handles one inbound request on `parvault-seed`.
pub fn handle_seed_wire_request(
    remote_peer_id: &str,
    remote_addr: Option<&Multiaddr>,
    request: MeshWireRequest,
    ctx: SeedWireHandlerCtx<'_>,
) -> MeshWireResponse {
    let SeedWireHandlerCtx {
        data_dir,
        node_identity,
        advertised_admin_pk,
        local_tracker_admin_pk,
        extra_council_pks,
        council_quorum,
        max_probationary_lease_bytes,
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
    } = ctx;
    let remote_ip = remote_addr.and_then(extract_ip_from_multiaddr);
    let remote_pubkey = NodeConfig::extract_ed25519_pubkey_from_peer_str(remote_peer_id);

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
                return MeshWireResponse::HandshakeAck {
                    accepted: false,
                    reason: Some(reason),
                };
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
                Err(e) => MeshWireResponse::HandshakeAck {
                    accepted: false,
                    reason: Some(e.to_string()),
                },
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
            if let Some(grant) = repair_grant {
                por_verifier.register_repair_grant(grant);
            }
            por_verifier.register_shard_session(&shard_id, session_key_commit);
            let effective_owner = if owner_peer_id.is_empty()
                || owner_peer_id == "local"
                || owner_peer_id == "self"
            {
                remote_peer_id
            } else {
                owner_peer_id.as_str()
            };
            match block_store.put_shard(effective_owner, &shard_id, &shard_bytes) {
                Ok(_) => {
                    let _ = eviction.record_regular_shard_ingress(
                        remote_ip,
                        Some(remote_peer_id),
                        remote_pubkey,
                        effective_owner,
                        shard_id,
                    );
                    if let (Some(ip), Some(pk)) = (remote_ip, remote_pubkey) {
                        let _ = eviction.record_peer_admission_ip(ip, pk);
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
            if !por_verifier.authorize_owner_shard_delete(
                &shard_id,
                &owner_pub,
                payload.as_slice(),
                &sig64,
            ) {
                return MeshWireResponse::DeleteShardAck {
                    deleted: false,
                    error: Some("unauthorized owner shard delete signature".to_string()),
                };
            }
            match block_store.delete_shard(remote_peer_id, &shard_id) {
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
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            match por_verifier.handle_incoming_challenge(&challenge, now_ms, block_store) {
                Ok(resp) => {
                    server.record_por_heartbeat(true);
                    MeshWireResponse::PorAuditResult(Some(resp))
                }
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
            if max_probationary_lease_bytes > 0
                && (shard_bytes.len() as u64) > max_probationary_lease_bytes
            {
                return MeshWireResponse::PutBlindedShardAck {
                    stored: false,
                    error: Some(format!(
                        "shard length {} exceeds max_probationary_lease_bytes {}",
                        shard_bytes.len(),
                        max_probationary_lease_bytes
                    )),
                };
            }
            nullifier_ledger.set_trusted_issuer_pubkey(voucher.issuer_pubkey);
            match block_store.put_blinded_shard_with_lease(
                &blinded_id,
                &shard_bytes,
                capability,
                &voucher,
                nullifier_ledger,
                crate::storage::BlindedLeaseSpec::new(
                    current_epoch,
                    lease_duration_epochs,
                    delete_verifier,
                ),
            ) {
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
        MeshWireRequest::RenewBlindedLease {
            blinded_id,
            current_epoch,
            extension_epochs,
        } => {
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
            let renewed = server.renew_blinded_lease(&blinded_id, current_epoch, extension_epochs);
            MeshWireResponse::RenewBlindedLeaseAck { renewed }
        }
        MeshWireRequest::DeleteBlindedShardTombstone {
            blinded_id,
            tombstone,
        } => match server.execute_blinded_tombstone(&blinded_id, &tombstone) {
            Ok(deleted) => MeshWireResponse::DeleteBlindedShardAck {
                deleted,
                error: None,
            },
            Err(e) => MeshWireResponse::DeleteBlindedShardAck {
                deleted: false,
                error: Some(e.to_string()),
            },
        },
        MeshWireRequest::MultiSegmentPorAudit(challenge) => {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            match por_verifier.handle_multi_segment_challenge(&challenge, now_ms, block_store) {
                Ok(resp) => {
                    server.record_por_heartbeat(true);
                    MeshWireResponse::MultiSegmentPorAuditResult(Some(resp))
                }
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
                    match client.relay_pq_onion_envelope(
                        &next_hop,
                        None,
                        envelope,
                        capability,
                        voucher,
                        crate::storage::BlindedLeaseSpec::new(
                            current_epoch,
                            lease_duration_epochs,
                            delete_verifier,
                        ),
                    ) {
                        Ok(()) => MeshWireResponse::RelayPqOnionAck {
                            delivered: true,
                            error: None,
                        },
                        Err(e) => MeshWireResponse::RelayPqOnionAck {
                            delivered: false,
                            error: Some(e.to_string()),
                        },
                    }
                } else {
                    MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some("no MeshClient available for onion forwarding".to_string()),
                    }
                }
            } else if let Ok(hop) = envelope.peel_relay_hop_pq(pq_kem) {
                if envelope.jitter_delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(envelope.jitter_delay_ms.min(250)));
                }
                if let Some(client) = block_store.mesh_client() {
                    match client
                        .relay_layered_pq_onion_envelope(&hop.target_peer_addr, hop.inner_envelope)
                    {
                        Ok(()) => MeshWireResponse::RelayPqOnionAck {
                            delivered: true,
                            error: None,
                        },
                        Err(e) => MeshWireResponse::RelayPqOnionAck {
                            delivered: false,
                            error: Some(e.to_string()),
                        },
                    }
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
                if max_probationary_lease_bytes > 0
                    && (bundle.shard_bytes.len() as u64) > max_probationary_lease_bytes
                {
                    return MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some(format!(
                            "shard length {} exceeds max_probationary_lease_bytes {}",
                            bundle.shard_bytes.len(),
                            max_probationary_lease_bytes
                        )),
                    };
                }
                nullifier_ledger.set_trusted_issuer_pubkey(bundle.voucher.issuer_pubkey);
                let voucher_pk = bundle.voucher.issuer_pubkey;
                let bid = bundle.blinded_id;
                match block_store.put_blinded_shard_with_lease(
                    &bundle.blinded_id,
                    &bundle.shard_bytes,
                    bundle.capability,
                    &bundle.voucher,
                    nullifier_ledger,
                    crate::storage::BlindedLeaseSpec::new(
                        bundle.current_epoch,
                        bundle.lease_duration_epochs,
                        bundle.delete_verifier,
                    ),
                ) {
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
                        if max_probationary_lease_bytes > 0
                            && (shard_bytes.len() as u64) > max_probationary_lease_bytes
                        {
                            return MeshWireResponse::RelayPqOnionAck {
                                delivered: false,
                                error: Some(format!(
                                    "shard length {} exceeds max_probationary_lease_bytes {}",
                                    shard_bytes.len(),
                                    max_probationary_lease_bytes
                                )),
                            };
                        }
                        nullifier_ledger.set_trusted_issuer_pubkey(voucher.issuer_pubkey);
                        let voucher_pk = voucher.issuer_pubkey;
                        match block_store.put_blinded_shard_with_lease(
                            &blinded_id,
                            &shard_bytes,
                            capability,
                            &voucher,
                            nullifier_ledger,
                            crate::storage::BlindedLeaseSpec::new(
                                current_epoch,
                                lease_duration_epochs,
                                delete_verifier,
                            ),
                        ) {
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
            if let Some(ref grant) = repair_grant {
                por_verifier.register_repair_grant(grant.clone());
            }
            match server.ingest_and_syndicate_lite_stripe_with_grant(
                &cert,
                &bundle,
                &[],
                repair_grant,
            ) {
                Ok((receipt, syndicated_peers)) => MeshWireResponse::SyndicateLiteStripeAck {
                    receipt: Some(receipt),
                    syndicated_peers,
                    error: None,
                },
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
                region: "seed-anchor".to_string(),
                available_bytes,
                used_bytes: rep.used_storage_bytes,
                sla_score: rep.sla_ratio,
                pq_kem_pubkey: Some(pq_kem.public_key()),
            }
        }
        MeshWireRequest::RegisterWanRendezvous { slot_key, entry } => {
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
                    tracker_admin_pubkey: advertised_admin_pk,
                };
            }
            let observed_external_addr = remote_addr
                .and_then(|addr| reflect_observed_wan_multiaddr(addr, 0, remote_peer_id));
            let signer_pk = entry.ed25519_pubkey;
            let public_card_ips: Vec<std::net::IpAddr> = if slot_key == PUBLIC_COMMONS_SWARM_SLOT {
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
            match wan_registry.register(slot_key, entry, seed_now_ms()) {
                Ok(stored) => {
                    if stored {
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
                        tracker_admin_pubkey: advertised_admin_pk,
                    }
                }
                Err(err) => MeshWireResponse::RegisterWanRendezvousAck {
                    stored: false,
                    observed_external_addr,
                    error: Some(err),
                    tracker_admin_pubkey: advertised_admin_pk,
                },
            }
        }
        MeshWireRequest::LookupWanRendezvous { slot_key } => {
            let observed_external_addr = remote_addr
                .and_then(|addr| reflect_observed_wan_multiaddr(addr, 0, remote_peer_id));
            let now = seed_now_ms();
            let entries = if slot_key == PUBLIC_COMMONS_SWARM_SLOT {
                wan_registry.lookup_public_swarm(32, now)
            } else {
                wan_registry.lookup(&slot_key, now)
            };
            MeshWireResponse::LookupWanRendezvousResult {
                entries,
                observed_external_addr,
                tracker_admin_pubkey: advertised_admin_pk,
            }
        }
        MeshWireRequest::SubmitAbuseTakedownReport(report) => {
            let report_id = report.report_id;
            if server.mode() != SeedServerMode::PublicNetworkBootstrapper {
                return MeshWireResponse::SubmitAbuseTakedownAck {
                    queued_for_admin_review: false,
                    report_id,
                    verified_plaintext_sha256: None,
                    error: Some(
                        "abuse takedown queue disabled in homelab-vault private mode".to_string(),
                    ),
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
            let (council, min_quorum) = resolve_seed_council_and_quorum(
                data_dir,
                server.mode(),
                local_tracker_admin_pk,
                extra_council_pks,
                council_quorum,
                genesis_pubkey,
            );
            let local_pk = node_identity.public_key_bytes();
            match eviction.apply_signed_eviction_order_with_quorum(
                &order,
                Some(&local_pk),
                &council,
                min_quorum,
                seed_now_ms(),
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
