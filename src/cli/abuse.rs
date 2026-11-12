//! `parvault` commands: abuse.

use super::CliEnv;
use crate::*;

pub(crate) async fn evict(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        cfg,
        node_identity,
        mesh_client,
        block_store,
        ..
    } = env;
    let Commands::Evict {
        ip,
        subnet,
        peer_id,
        pubkey_hex,
        merkle_root,
        locator,
        reason,
        propagate,
    } = command
    else {
        unreachable!("evict() is only dispatched for Commands::Evict")
    };
    let target = parse_cli_eviction_target(ip, subnet, peer_id, pubkey_hex, merkle_root, locator)?;
    let mut eviction = PrivacyPreservingEvictionEngine::load_or_init(&cfg.data_dir)?;
    let local_report = eviction.evict_target(&target, &block_store)?;

    let mut remote_report = EvictionPurgeReport::default();
    let mut propagated_orders = 0usize;
    if propagate {
        let now_ms = now_unix_ms();
        let mut orders = vec![SignedBadActorEvictionOrder::issue(
            &node_identity,
            target.clone(),
            reason.clone(),
            now_ms,
            0,
        )];
        match &target {
            EvictionTarget::IpAddress(bad_ip) => {
                for pk in eviction.resolve_pubkeys_for_ip(*bad_ip) {
                    orders.push(SignedBadActorEvictionOrder::issue(
                        &node_identity,
                        EvictionTarget::PeerOrIssuerPubkey(pk),
                        reason.clone(),
                        now_ms,
                        0,
                    ));
                }
            }
            EvictionTarget::IpSubnet(cidr) => {
                for pk in eviction.resolve_pubkeys_for_subnet(cidr) {
                    orders.push(SignedBadActorEvictionOrder::issue(
                        &node_identity,
                        EvictionTarget::PeerOrIssuerPubkey(pk),
                        reason.clone(),
                        now_ms,
                        0,
                    ));
                }
            }
            _ => {}
        }
        propagated_orders = orders.len();
        for order in &orders {
            let rep = mesh_client.propagate_eviction_order_to_peers(&[], order);
            remote_report.merge(&rep);
        }
    }

    println!("=== ParVault Privacy-Preserving Eviction Complete (ADR-19) ===");
    println!("Data Directory           : {}", cfg.data_dir.display());
    println!(
        "Local Regular Shards     : {} zero-shredded (0x00)",
        local_report.purged_regular_shards
    );
    println!(
        "Local Blinded Shards     : {} zero-shredded (0x00)",
        local_report.purged_blinded_shards
    );
    println!(
        "Local Zero-Wiped Bytes   : {} bytes",
        local_report.zero_wiped_bytes
    );
    println!(
        "HMAC Firewall Installed  : {} (zero plaintext IPs on disk)",
        local_report.firewall_rule_installed
    );
    if propagate {
        println!(
            "Mesh Propagation         : {} signed order(s) broadcast (remote purged: {} regular, {} blinded, {} bytes)",
            propagated_orders,
            remote_report.purged_regular_shards,
            remote_report.purged_blinded_shards,
            remote_report.zero_wiped_bytes
        );
    }
    Ok(())
}

pub(crate) async fn report_abuse(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        cfg,
        public_trackers,
        node_identity,
        mesh_client,
        block_store,
        cli,
        ..
    } = env;
    let Commands::ReportAbuse {
        manifest,
        disclosed_key_hex,
        allegation,
        contact,
        bad_actor_ip,
        stripe_index,
    } = command
    else {
        unreachable!("report_abuse() is only dispatched for Commands::ReportAbuse")
    };
    let target_tracker = public_trackers
        .first()
        .cloned()
        .or_else(|| cli.seed_addr.clone())
        .ok_or_else(|| {
            anyhow::anyhow!("Missing Public Tracker Multiaddr: pass `--tracker <MULTIADDR>`")
        })?;
    let disclosed_mk = MasterKey::from_hex(disclosed_key_hex.trim())?;
    let owner_identity = NodeIdentity::from_master_key(&disclosed_mk);
    let file_manifest = load_manifest_for_abuse_report(&block_store, &disclosed_mk, &manifest)?;
    let stripe = file_manifest
        .stripes
        .iter()
        .find(|s| s.stripe_index == stripe_index)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Stripe index {} not present in reported FileManifest ({} stripes)",
                stripe_index,
                file_manifest.stripes.len()
            )
        })?;

    let total_shards = stripe.k_data + stripe.m_parity;
    let mut sample_shards: Vec<(u32, Vec<u8>)> = Vec::new();
    for idx in 0..total_shards {
        if sample_shards.len() >= stripe.k_data {
            break;
        }
        let sid = ShardId {
            stripe_merkle_root: stripe.stripe_merkle_root,
            shard_index: idx as u32,
            shard_hash: stripe.shard_hashes[idx],
        };
        if let Ok(bytes) = block_store.get_shard(&sid) {
            if hash_shard_leaf(idx as u32, &bytes) == stripe.shard_hashes[idx] {
                sample_shards.push((idx as u32, bytes));
            }
        }
    }

    if sample_shards.len() < stripe.k_data {
        let client_for_fetch = mesh_client.with_identity(owner_identity.clone());
        let _ = client_for_fetch.announce_and_discover_public_tracker(&target_tracker, None);
        let fetched_slots = client_for_fetch.fetch_stripe_shards(stripe, &owner_identity);
        for (idx, slot) in fetched_slots.into_iter().enumerate() {
            if sample_shards.len() >= stripe.k_data {
                break;
            }
            if sample_shards
                .iter()
                .any(|(existing, _)| *existing == idx as u32)
            {
                continue;
            }
            if let Some(bytes) = slot {
                if hash_shard_leaf(idx as u32, &bytes) == stripe.shard_hashes[idx] {
                    sample_shards.push((idx as u32, bytes));
                }
            }
        }
        if sample_shards.len() < stripe.k_data {
            for idx in 0..total_shards {
                if sample_shards.len() >= stripe.k_data {
                    break;
                }
                if sample_shards
                    .iter()
                    .any(|(existing, _)| *existing == idx as u32)
                {
                    continue;
                }
                let sid = ShardId {
                    stripe_merkle_root: stripe.stripe_merkle_root,
                    shard_index: idx as u32,
                    shard_hash: stripe.shard_hashes[idx],
                };
                if let Ok(bytes) = client_for_fetch.get_ciphertext_shard(
                    &target_tracker,
                    sid,
                    Some(&owner_identity),
                    None,
                ) {
                    if hash_shard_leaf(idx as u32, &bytes) == stripe.shard_hashes[idx] {
                        sample_shards.push((idx as u32, bytes));
                    }
                }
            }
        }
    }

    if sample_shards.len() < stripe.k_data {
        anyhow::bail!(
            "Unable to collect k_data={} verified sample shards for stripe {} (found {})",
            stripe.k_data,
            stripe_index,
            sample_shards.len()
        );
    }

    let report = VerifiableAbuseReport::submit_signed(
        &node_identity,
        &contact,
        &allegation,
        bad_actor_ip,
        file_manifest,
        disclosed_key_hex.trim(),
        stripe_index,
        sample_shards,
        now_unix_ms(),
    );
    let local_proof = report
        .verify_cryptographic_burden_of_proof()
        .map_err(|e| anyhow::anyhow!("Cryptographic burden-of-proof check failed: {e}"))?;

    let (ack_report_id, ack_sha) =
        mesh_client.submit_abuse_takedown_report_detailed(&target_tracker, report)?;
    for pk in mesh_client.pinned_tracker_admin_pubkeys() {
        cfg.persist_pinned_tracker_admin(pk);
    }
    let verified_sha = ack_sha.unwrap_or(local_proof.verified_plaintext_sha256);

    println!("=== ParVault Verifiable Abuse Report Submitted (ADR-19) ===");
    println!("Public Tracker           : {}", target_tracker);
    println!("Report ID                : {}", hex::encode(ack_report_id));
    println!(
        "File Merkle Root         : {}",
        hex::encode(local_proof.file_merkle_root)
    );
    println!(
        "Verified Plaintext SHA256: {} ({} bytes; zeroized in RAM)",
        hex::encode(verified_sha),
        local_proof.verified_plaintext_len
    );
    println!(
        "Governance Queue Status  : PendingAdminReview (awaiting Public Tracker Admin review)"
    );
    Ok(())
}
