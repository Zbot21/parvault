use parvault::bootstrap::{EarnedStanding, PeerRole};
use parvault::crypto::HybridKemKeypair;
use parvault::telemetry::{
    round_to_pow2_gib, AnonymousTelemetryBeacon, NetworkCensusAggregator, TelemetryError,
    BYTES_PER_GIB,
};

#[test]
fn test_telemetry1_epoch_nullifier_deduplication_and_cross_epoch_unlinkability() {
    let node_secret = [0x42u8; 32];
    let epoch_100 = 100u64;
    let epoch_101 = 101u64;

    let beacon_e100 = AnonymousTelemetryBeacon::create(
        &node_secret,
        epoch_100,
        "NA-WEST",
        PeerRole::OrganicCommunityPeer,
        EarnedStanding::ProbationaryConsumerPool,
        500 * BYTES_PER_GIB,
        60 * BYTES_PER_GIB,
        35,
    )
    .expect("valid beacon");

    let mut agg_100 = NetworkCensusAggregator::new(epoch_100);
    assert!(
        agg_100
            .ingest_beacon(beacon_e100.clone())
            .expect("first beacon accepted"),
        "first beacon in epoch 100 must be counted"
    );

    // Spamming 5 more beacons from the same node in the same epoch (even with altered stats)
    // produces the exact same epoch_nullifier and is deduplicated.
    for i in 0..5 {
        let duplicate = AnonymousTelemetryBeacon::create(
            &node_secret,
            epoch_100,
            "NA-WEST",
            PeerRole::OrganicCommunityPeer,
            EarnedStanding::EarnedHomelabAnchorPool,
            (1000 + i) * BYTES_PER_GIB,
            (200 + i) * BYTES_PER_GIB,
            500,
        )
        .expect("valid beacon");
        assert_eq!(duplicate.epoch_nullifier, beacon_e100.epoch_nullifier);
        let counted = agg_100
            .ingest_beacon(duplicate)
            .expect("duplicate should not error");
        assert!(
            !counted,
            "duplicate nullifier in same epoch must be ignored"
        );
    }

    assert_eq!(agg_100.unique_beacon_count(), 1);

    // Tampering with a beacon field invalidates beacon_mac
    let mut tampered = beacon_e100.clone();
    tampered.committed_capacity_bucket_gib = 4096;
    assert!(matches!(
        agg_100.ingest_beacon(tampered),
        Err(TelemetryError::InvalidBeaconMac)
    ));

    // Next epoch (101) rotates the nullifier completely (unlinkable across epochs)
    let beacon_e101 = AnonymousTelemetryBeacon::create(
        &node_secret,
        epoch_101,
        "NA-WEST",
        PeerRole::OrganicCommunityPeer,
        EarnedStanding::ProbationaryConsumerPool,
        500 * BYTES_PER_GIB,
        60 * BYTES_PER_GIB,
        35,
    )
    .expect("valid epoch 101 beacon");

    assert_ne!(
        beacon_e100.epoch_nullifier, beacon_e101.epoch_nullifier,
        "epoch nullifiers must be cryptographically unlinkable across epochs"
    );

    // Sending an epoch 101 beacon to the epoch 100 aggregator is rejected
    assert!(matches!(
        agg_100.ingest_beacon(beacon_e101),
        Err(TelemetryError::EpochMismatch {
            expected: 100,
            actual: 101
        })
    ));
}

#[test]
fn test_telemetry2_power_of_two_capacity_bucketing_prevents_host_fingerprinting() {
    assert_eq!(round_to_pow2_gib(0), 0);
    assert_eq!(round_to_pow2_gib(512 * 1024 * 1024), 1); // 512 MiB -> 1 GiB bucket

    // Host A (476 GiB + odd filesystem overhead) and Host B (509 GiB) both map to 512 GiB
    let host_a_bytes = 476 * BYTES_PER_GIB + 987_654_321;
    let host_b_bytes = 509 * BYTES_PER_GIB;
    assert_eq!(round_to_pow2_gib(host_a_bytes), 512);
    assert_eq!(round_to_pow2_gib(host_b_bytes), 512);

    let b1 = AnonymousTelemetryBeacon::create(
        &[1u8; 32],
        10,
        "eu-central",
        PeerRole::OrganicCommunityPeer,
        EarnedStanding::EarnedVerifiedMixedPool,
        host_a_bytes,
        190 * BYTES_PER_GIB,
        40,
    )
    .expect("beacon 1");
    let b2 = AnonymousTelemetryBeacon::create(
        &[2u8; 32],
        10,
        "EU-CENTRAL",
        PeerRole::OrganicCommunityPeer,
        EarnedStanding::EarnedVerifiedMixedPool,
        host_b_bytes,
        240 * BYTES_PER_GIB,
        40,
    )
    .expect("beacon 2");

    assert_eq!(b1.coarse_region, "EU-CENTRAL");
    assert_eq!(b1.committed_capacity_bucket_gib, 512);
    assert_eq!(b2.committed_capacity_bucket_gib, 512);
    assert_eq!(b1.used_storage_bucket_gib, 256);
    assert_eq!(b2.used_storage_bucket_gib, 256);

    // Fine-grained IPv4, IPv6, or /24 CIDR strings in coarse_region must be rejected
    for forbidden_region in ["192.168.1.42", "10.0.24.0/24", "2001:db8::1", ""] {
        let res = AnonymousTelemetryBeacon::create(
            &[3u8; 32],
            10,
            forbidden_region,
            PeerRole::OrganicCommunityPeer,
            EarnedStanding::ProbationaryConsumerPool,
            100 * BYTES_PER_GIB,
            10 * BYTES_PER_GIB,
            10,
        );
        assert!(
            matches!(res, Err(TelemetryError::InvalidCoarseRegion(_))),
            "must reject fine-grained IP/subnet region: {forbidden_region}"
        );
    }
}

#[test]
fn test_telemetry3_network_census_extent_by_region_and_seed_anchor_drain_visibility() {
    let regions = ["NA-WEST", "NA-EAST", "EU-CENTRAL", "EU-WEST", "APAC"];

    // --- Phase 1 (Cold Start, Epoch 1): 5 organic peers + 20 Foundation Seed Anchors ---
    let mut agg_cold_start = NetworkCensusAggregator::new(1);

    for i in 0..5u8 {
        let mut seed = [0u8; 32];
        seed[0] = i + 1;
        let b = AnonymousTelemetryBeacon::create(
            &seed,
            1,
            regions[i as usize % regions.len()],
            PeerRole::OrganicCommunityPeer,
            EarnedStanding::ProbationaryConsumerPool,
            256 * BYTES_PER_GIB,
            16 * BYTES_PER_GIB,
            24,
        )
        .unwrap();
        agg_cold_start.ingest_beacon(b).unwrap();
    }

    for s in 0..20u8 {
        let mut seed = [0xAAu8; 32];
        seed[0] = s;
        let b = AnonymousTelemetryBeacon::create(
            &seed,
            1,
            regions[s as usize % regions.len()],
            PeerRole::FoundationSeedAnchor,
            EarnedStanding::ProbationaryConsumerPool,
            256 * BYTES_PER_GIB,
            16 * BYTES_PER_GIB, // Seed anchors still holding 16 GiB each during Cold Start
            24,
        )
        .unwrap();
        agg_cold_start.ingest_beacon(b).unwrap();
    }

    let report_cold = agg_cold_start.generate_report();
    assert_eq!(report_cold.unique_active_nodes, 25);
    assert_eq!(report_cold.organic_community_nodes, 5);
    assert_eq!(report_cold.foundation_seed_anchors, 20);
    // 320 GiB on Seed Anchors out of 400 GiB total = 80.0%
    assert!((report_cold.seed_anchor_storage_share_percent - 80.0).abs() < 1e-6);

    // --- Phase 2 (Drained Mesh, Epoch 50): 40 organic peers + 20 Seed Anchors (0 GiB used) ---
    let mut agg_drained = NetworkCensusAggregator::new(50);

    for i in 0..40u8 {
        let mut seed = [0x11u8; 32];
        seed[0] = i;
        let standing = if i < 10 {
            EarnedStanding::EarnedHomelabAnchorPool
        } else if i < 25 {
            EarnedStanding::EarnedVerifiedMixedPool
        } else {
            EarnedStanding::ProbationaryConsumerPool
        };
        // Node 39 is a malicious outlier claiming 999,999 DHT peers; median cross-check ignores it
        let observed_dht = if i == 39 { 999_999 } else { 420 };
        let b = AnonymousTelemetryBeacon::create(
            &seed,
            50,
            regions[i as usize % regions.len()],
            PeerRole::OrganicCommunityPeer,
            standing,
            512 * BYTES_PER_GIB,
            16 * BYTES_PER_GIB,
            observed_dht,
        )
        .unwrap();
        agg_drained.ingest_beacon(b).unwrap();
    }

    for s in 0..20u8 {
        let mut seed = [0xAAu8; 32];
        seed[0] = s;
        let b = AnonymousTelemetryBeacon::create(
            &seed,
            50,
            regions[s as usize % regions.len()],
            PeerRole::FoundationSeedAnchor,
            EarnedStanding::ProbationaryConsumerPool,
            256 * BYTES_PER_GIB,
            0, // Drained to 0 bytes!
            420,
        )
        .unwrap();
        agg_drained.ingest_beacon(b).unwrap();
    }

    let report_drained = agg_drained.generate_report();
    assert_eq!(report_drained.unique_active_nodes, 60);
    assert_eq!(report_drained.organic_community_nodes, 40);
    assert_eq!(report_drained.foundation_seed_anchors, 20);
    assert_eq!(report_drained.seed_anchor_storage_share_percent, 0.0);
    let prom_text = report_drained.to_prometheus_metrics();
    assert!(prom_text.contains("parvault_unique_active_nodes 60"));
    assert!(prom_text.contains("parvault_seed_anchor_storage_share_percent 0.0000"));
    assert_eq!(report_drained.dht_cross_checked_population_estimate, 421);

    for r in regions {
        assert_eq!(report_drained.extent_by_region.get(r).copied(), Some(12));
    }
    assert_eq!(
        report_drained
            .nodes_by_earned_standing
            .get("EarnedHomelabAnchorPool")
            .copied(),
        Some(10)
    );
    assert_eq!(
        report_drained
            .nodes_by_earned_standing
            .get("EarnedVerifiedMixedPool")
            .copied(),
        Some(15)
    );
}

#[test]
fn test_telemetry4_pq_onion_wrapped_telemetry_beacon_hides_origin_ip() {
    let seed_anchor_kem = HybridKemKeypair::generate().expect("ML-KEM-768 + X25519 keygen");
    let origin_secret = [0x77u8; 32];
    let epoch = 777u64;

    let beacon = AnonymousTelemetryBeacon::create(
        &origin_secret,
        epoch,
        "APAC",
        PeerRole::OrganicCommunityPeer,
        EarnedStanding::EarnedHomelabAnchorPool,
        1024 * BYTES_PER_GIB,
        256 * BYTES_PER_GIB,
        128,
    )
    .expect("create beacon");

    let pq_envelope = beacon
        .seal_pq_onion(&seed_anchor_kem.public_key(), "relay-peer-tokyo-01", 120)
        .expect("seal PQ onion telemetry envelope");

    assert_eq!(pq_envelope.relay_peer_id, "relay-peer-tokyo-01");
    // Ensure the encrypted payload does not leak the epoch_nullifier in cleartext to the relay
    assert!(
        !pq_envelope
            .encrypted_payload
            .windows(32)
            .any(|w| w == beacon.epoch_nullifier),
        "relay must not see epoch_nullifier in cleartext"
    );

    let mut aggregator = NetworkCensusAggregator::new(epoch);
    let accepted = aggregator
        .ingest_pq_onion_beacon(&pq_envelope, &seed_anchor_kem)
        .expect("unwrap and ingest PQ onion beacon");
    assert!(accepted);

    // Replaying the same onion envelope is deduplicated by epoch_nullifier
    let replayed = aggregator
        .ingest_pq_onion_beacon(&pq_envelope, &seed_anchor_kem)
        .expect("replay check");
    assert!(!replayed);

    let report = aggregator.generate_report();
    assert_eq!(report.unique_active_nodes, 1);
    assert_eq!(report.extent_by_region.get("APAC").copied(), Some(1));
    assert_eq!(report.total_committed_capacity_gib, 1024);
    assert_eq!(report.total_used_storage_gib, 256);
}
