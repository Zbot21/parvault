use parvault::{
    bootstrap::{
        BlindedShardTombstone, BootstrapError, EarnedStanding, ElasticBootstrapEngine,
        ElasticPeerCandidate, PeerRole, PersonalDeviceCert, SeedServerMode, ZeroTrustSeedServer,
    },
    crypto::{
        pqc::{HybridPqSigningKeypair, PqVaultMasterKey},
        MasterKey, NodeIdentity,
    },
    por::compute_salted_commitment,
    sharding::merkle::hash_shard_leaf,
    storage::{
        AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, BlockStore, QuotaManager,
        ShardId, TrustLevel,
    },
};
use tempfile::tempdir;

/// Test 1: Verifies that `ZeroTrustSeedServer` in `HomelabRedundancyVault` mode authenticates
/// the homelab owner's personal devices (`"laptop-1"`, `"desktop-1"`) using post-quantum
/// `PersonalDeviceCert`s (`Ed25519 + ML-DSA-65`), stores their encrypted shards with `0`
/// reciprocity quota deduction, and earns `TrustLevel::HighUptimeAnchor` +
/// `EarnedStanding::EarnedHomelabAnchorPool` (`16-of-20`) after 200 PoR heartbeats while
/// `holds_own_plaintext_files` remains `false`.
#[test]
fn test_seed_server_homelab_redundancy_vault_mode_for_personal_devices_and_uptime_earning() {
    let dir = tempdir().expect("create temp seed server dir");
    let quota = QuotaManager::new(50 * 1024 * 1024 * 1024, 64 * 1024 * 1024);
    let block_store = BlockStore::new(dir.path(), quota).expect("init block store");

    let homelab_owner_pq = HybridPqSigningKeypair::generate().expect("generate owner PQ keypair");
    let mut server = ZeroTrustSeedServer::new_homelab_vault(
        "homelab-vault-anchor-01",
        block_store,
        homelab_owner_pq.public_key(),
        2,
    );

    // Issue post-quantum PersonalDeviceCerts for "laptop-1" and "desktop-1"
    let laptop_cert =
        PersonalDeviceCert::issue(&homelab_owner_pq, "laptop-1", "ThinkPad-X1", 1_700_000_100)
            .expect("issue laptop cert");
    let desktop_cert = PersonalDeviceCert::issue(
        &homelab_owner_pq,
        "desktop-1",
        "Ryzen-Workstation",
        1_700_000_200,
    )
    .expect("issue desktop cert");

    // Encrypt stripe under 512-bit Grover-resistant PqVaultMasterKey before sending shards to vault
    let pq_vault_key = PqVaultMasterKey::generate();
    let file_salt = [0x42u8; 32];
    let ciphertext = pq_vault_key
        .encrypt_stripe_pq(
            &file_salt,
            0,
            b"Zero-knowledge personal ring backup payload across laptop + desktop + homelab server",
        )
        .expect("encrypt pq stripe");

    let (shards, stripe_root) = ElasticBootstrapEngine::encode_ciphertext_elastic(
        EarnedStanding::PersonalDeviceRing,
        &ciphertext,
    )
    .expect("encode 2-of-3 personal ring stripe");

    let shard_0 = ShardId {
        stripe_merkle_root: stripe_root,
        shard_index: 0,
        shard_hash: hash_shard_leaf(0, &shards[0]),
    };
    let shard_1 = ShardId {
        stripe_merkle_root: stripe_root,
        shard_index: 1,
        shard_hash: hash_shard_leaf(1, &shards[1]),
    };

    // Both personal devices store encrypted shards on the dedicated homelab redundancy vault
    server
        .store_personal_device_shard(&laptop_cert, &shard_0, &shards[0])
        .expect("laptop-1 store shard");
    server
        .store_personal_device_shard(&desktop_cert, &shard_1, &shards[1])
        .expect("desktop-1 store shard");

    // Verify zero reciprocity quota was deducted from either personal device
    assert_eq!(server.personal_device_quota_charged("laptop-1"), 0);
    assert_eq!(server.personal_device_quota_charged("desktop-1"), 0);

    // Verify both devices can read back their encrypted shards
    let fetched_0 = server
        .get_personal_device_shard(&laptop_cert, &shard_0)
        .expect("fetch shard 0");
    let fetched_1 = server
        .get_personal_device_shard(&desktop_cert, &shard_1)
        .expect("fetch shard 1");
    assert_eq!(fetched_0, shards[0]);
    assert_eq!(fetched_1, shards[1]);

    // Before neighborhood PoR heartbeats, server is in PersonalDeviceRing (2-of-3)
    let initial_report = server.status_report(1);
    assert_eq!(initial_report.mode, SeedServerMode::HomelabRedundancyVault);
    assert_eq!(initial_report.peer_role, PeerRole::PersonalDevice);
    assert_eq!(
        initial_report.earned_standing,
        EarnedStanding::PersonalDeviceRing
    );
    assert!(initial_report.used_storage_bytes > 0);
    assert!(!initial_report.holds_own_plaintext_files);

    // Simulate 200 PoR heartbeats on the 24/7 server with 20 reachable organic peers
    server.simulate_por_heartbeats(200, 20);

    let final_report = server.status_report(201);
    assert_eq!(final_report.por_passes, 200);
    assert!((final_report.sla_ratio - 1.0).abs() < f64::EPSILON);
    assert_eq!(
        final_report.earned_trust_level,
        TrustLevel::HighUptimeAnchor
    );
    assert_eq!(
        final_report.earned_standing,
        EarnedStanding::EarnedHomelabAnchorPool
    );
    assert_eq!(final_report.earned_standing.erasure_params(), (16, 4, 20));
    assert!(!final_report.holds_own_plaintext_files);
}

/// Test 2: Verifies that `ZeroTrustSeedServer` in `PublicNetworkBootstrapper` mode ingests
/// anonymized `BlindedShardId` shards for a brand-new network with only 3 organic peers,
/// answers PoR challenges, and when 20 organic peers join, generates drain migrations
/// (`plan_seed_anchor_drain`) and purges all drained shards off disk via `BlindedShardTombstone`
/// until `used_storage_bytes == 0`.
#[test]
fn test_seed_server_public_bootstrapper_mode_blinded_storage_and_auto_drain() {
    let dir = tempdir().expect("create temp bootstrap dir");
    let quota = QuotaManager::new(50 * 1024 * 1024 * 1024, 64 * 1024 * 1024);
    let block_store = BlockStore::new(dir.path(), quota).expect("init block store");

    let voucher_issuer = NodeIdentity::generate();
    let mut server = ZeroTrustSeedServer::new_public_bootstrapper(
        "foundation-seed-anchor-01",
        block_store,
        voucher_issuer.public_key_bytes(),
        2,
    );

    // Brand-new network with only 3 organic peers + 1 FoundationSeedAnchor
    let mut initial_candidates = Vec::new();
    for i in 0..3 {
        initial_candidates.push(ElasticPeerCandidate {
            peer_id: format!("organic-pioneer-{i}"),
            role: PeerRole::OrganicCommunityPeer,
            subnet_prefix: format!("192.0.{i}.0/24"),
            trust_level: TrustLevel::UntrustedProbationary,
            rtt_ms: 12 + i as u64,
            committed_standby_bytes: 50 * 1024 * 1024 * 1024,
        });
    }
    initial_candidates.push(ElasticPeerCandidate {
        peer_id: server.server_peer_id().to_string(),
        role: PeerRole::FoundationSeedAnchor,
        subnet_prefix: "198.51.100.0/24".to_string(),
        trust_level: TrustLevel::HighUptimeAnchor,
        rtt_ms: 35,
        committed_standby_bytes: 0,
    });

    // Under BuddyMicroCluster (3-of-5), 3 shards land on the 3 organic peers and 2 overflow onto the seed server
    let placements = ElasticBootstrapEngine::select_elastic_targets(
        EarnedStanding::BuddyMicroCluster,
        &initial_candidates,
    );
    assert_eq!(placements.len(), 5);
    let seed_placements: Vec<_> = placements
        .iter()
        .filter(|p| p.role == PeerRole::FoundationSeedAnchor)
        .collect();
    assert_eq!(seed_placements.len(), 2);

    // Client derives BlindedShardIds, Capabilities, Vouchers, and Delete Verifiers for the 2 seed shards
    let client_master_key = MasterKey::generate();
    let stripe_root = [0x77u8; 32];
    let delete_cap_secret = [0x88u8; 32];

    let mut stored_seed_shards = Vec::new();
    for placement in &seed_placements {
        let idx = placement.shard_index as u32;
        let shard_bytes = vec![0xA0 + idx as u8; 4096];
        let blinded_id =
            BlindedShardId::derive(&client_master_key, &stripe_root, idx, &shard_bytes);
        let (cap_identity, capability) =
            BlindedShardCapability::derive_keypair(&client_master_key, &blinded_id.locator);
        let voucher = AnonymousQuotaVoucher::mint(&voucher_issuer, 8192);
        let delete_verifier =
            BlindedShardTombstone::derive_delete_verifier(&delete_cap_secret, &blinded_id.locator);

        server
            .ingest_blinded_shard_with_lease(
                &blinded_id,
                &shard_bytes,
                capability,
                &voucher,
                parvault::storage::BlindedLeaseSpec::new(1, 30, delete_verifier),
            )
            .expect("ingest blinded bootstrap shard");

        // Verify seed server answers stateless PoR challenge on the blinded shard
        let chal_nonce = [0x55u8; 32];
        let read_sig =
            BlindedShardCapability::sign_read_token(&cap_identity, &blinded_id.locator, 1_000);
        let commitment = server
            .answer_blinded_por_challenge(
                &blinded_id,
                &capability,
                1_000,
                &read_sig,
                &chal_nonce,
                1_000,
            )
            .expect("answer blinded PoR challenge");
        assert_eq!(
            commitment,
            compute_salted_commitment(&chal_nonce, &shard_bytes)
        );

        stored_seed_shards.push((blinded_id, delete_verifier));
    }

    let mid_report = server.status_report(1);
    assert_eq!(mid_report.mode, SeedServerMode::PublicNetworkBootstrapper);
    assert_eq!(mid_report.peer_role, PeerRole::FoundationSeedAnchor);
    assert_eq!(mid_report.used_storage_bytes, 2 * 4096);
    assert_eq!(mid_report.active_blinded_leases, 2);
    assert!(!mid_report.holds_own_plaintext_files);

    // Now 20 organic peers join across distinct /24 subnets
    let mut grown_candidates = initial_candidates.clone();
    for i in 3..20 {
        grown_candidates.push(ElasticPeerCandidate {
            peer_id: format!("organic-pioneer-{i}"),
            role: PeerRole::OrganicCommunityPeer,
            subnet_prefix: format!("10.20.{i}.0/24"),
            trust_level: TrustLevel::VerifiedNeighbor,
            rtt_ms: 18,
            committed_standby_bytes: 50 * 1024 * 1024 * 1024,
        });
    }

    let drain_migrations = server.plan_seed_anchor_drain(
        EarnedStanding::BuddyMicroCluster,
        &placements,
        &grown_candidates,
    );
    assert_eq!(drain_migrations.len(), 2);
    for mig in &drain_migrations {
        assert_eq!(mig.from_seed_anchor_id, server.server_peer_id());
        assert!(mig.to_organic_peer_id.starts_with("organic-pioneer-"));
    }

    // Purge drained shards from the seed server using BlindedShardTombstones
    for (blinded_id, delete_verifier) in &stored_seed_shards {
        let tombstone =
            BlindedShardTombstone::create(delete_verifier, blinded_id.locator, [0x99u8; 16]);
        let deleted = server
            .execute_blinded_tombstone(blinded_id, &tombstone)
            .expect("execute tombstone");
        assert!(deleted);
        assert!(!server.block_store().has_blinded_shard_on_disk(blinded_id));
    }

    let drained_report = server.status_report(2);
    assert_eq!(drained_report.used_storage_bytes, 0);
    assert_eq!(drained_report.active_blinded_leases, 0);
    assert!(!drained_report.holds_own_plaintext_files);
}

/// Test 3: Verifies that `server.sweep_expired_epoch(epoch)` physically deletes un-renewed
/// `.bshard` files on disk once `epoch >= lease_expires_epoch + grace_epochs` while
/// preserving renewed shards.
#[test]
fn test_seed_server_time_based_eviction_sweep_deletes_abandoned_bshard_files() {
    let dir = tempdir().expect("create temp sweep dir");
    let quota = QuotaManager::new(10 * 1024 * 1024 * 1024, 64 * 1024 * 1024);
    let block_store = BlockStore::new(dir.path(), quota).expect("init block store");

    let voucher_issuer = NodeIdentity::generate();
    let grace_epochs = 2;
    let mut server = ZeroTrustSeedServer::new_public_bootstrapper(
        "foundation-seed-anchor-gc",
        block_store,
        voucher_issuer.public_key_bytes(),
        grace_epochs,
    );

    let master_key = MasterKey::generate();
    let stripe_root = [0xABu8; 32];
    let cap_secret = [0xCDu8; 32];

    // Shard A (abandoned by departed node): stored at epoch 10 with lease_duration = 5 (expires at 15, grace ends at 17)
    let bytes_abandoned = vec![0x11u8; 2048];
    let blinded_abandoned = BlindedShardId::derive(&master_key, &stripe_root, 0, &bytes_abandoned);
    let (_, cap_abandoned) =
        BlindedShardCapability::derive_keypair(&master_key, &blinded_abandoned.locator);
    let voucher_a = AnonymousQuotaVoucher::mint(&voucher_issuer, 4096);
    let verifier_a =
        BlindedShardTombstone::derive_delete_verifier(&cap_secret, &blinded_abandoned.locator);

    // Shard B (actively renewed by online node): stored at epoch 10 with lease_duration = 5
    let bytes_renewed = vec![0x22u8; 2048];
    let blinded_renewed = BlindedShardId::derive(&master_key, &stripe_root, 1, &bytes_renewed);
    let (_, cap_renewed) =
        BlindedShardCapability::derive_keypair(&master_key, &blinded_renewed.locator);
    let voucher_b = AnonymousQuotaVoucher::mint(&voucher_issuer, 4096);
    let verifier_b =
        BlindedShardTombstone::derive_delete_verifier(&cap_secret, &blinded_renewed.locator);

    server
        .ingest_blinded_shard_with_lease(
            &blinded_abandoned,
            &bytes_abandoned,
            cap_abandoned,
            &voucher_a,
            parvault::storage::BlindedLeaseSpec::new(10, 5, verifier_a),
        )
        .expect("store abandoned shard");
    server
        .ingest_blinded_shard_with_lease(
            &blinded_renewed,
            &bytes_renewed,
            cap_renewed,
            &voucher_b,
            parvault::storage::BlindedLeaseSpec::new(10, 5, verifier_b),
        )
        .expect("store renewed shard");

    assert!(server
        .block_store()
        .has_blinded_shard_on_disk(&blinded_abandoned));
    assert!(server
        .block_store()
        .has_blinded_shard_on_disk(&blinded_renewed));

    // Renew Shard B at epoch 14 for +20 epochs (new expiry = 34)
    assert!(server.renew_blinded_lease(&blinded_renewed, 14, 20));

    // At epoch 16 (before Shard A's grace window 15 + 2 = 17 expires), nothing is deleted
    let swept_early = server.sweep_expired_epoch(16).expect("sweep epoch 16");
    assert!(swept_early.is_empty());
    assert!(server
        .block_store()
        .has_blinded_shard_on_disk(&blinded_abandoned));
    assert!(server
        .block_store()
        .has_blinded_shard_on_disk(&blinded_renewed));

    // At epoch 17 (epoch >= lease_expires_epoch + grace_epochs for Shard A), Shard A is physically unlinked
    let swept_expired = server.sweep_expired_epoch(17).expect("sweep epoch 17");
    assert_eq!(swept_expired, vec![blinded_abandoned]);
    assert!(!server
        .block_store()
        .has_blinded_shard_on_disk(&blinded_abandoned));
    assert!(server
        .block_store()
        .has_blinded_shard_on_disk(&blinded_renewed));

    let report = server.status_report(17);
    assert_eq!(report.active_blinded_leases, 1);
    assert_eq!(report.used_storage_bytes, 2048);
}

/// Test 4: Verifies that a stranger with a different `HybridPqSigningKeypair` cannot use a
/// homelabber's `HomelabRedundancyVault` as a free personal device ring without a valid
/// `PersonalDeviceCert` signed by the homelab owner.
#[test]
fn test_seed_server_rejects_unauthorized_personal_device_cert() {
    let dir = tempdir().expect("create temp vault dir");
    let quota = QuotaManager::new(10 * 1024 * 1024 * 1024, 64 * 1024 * 1024);
    let block_store = BlockStore::new(dir.path(), quota).expect("init block store");

    let homelab_owner_pq = HybridPqSigningKeypair::generate().expect("owner PQ keypair");
    let stranger_pq = HybridPqSigningKeypair::generate().expect("stranger PQ keypair");

    let mut server = ZeroTrustSeedServer::new_homelab_vault(
        "homelab-vault-strict",
        block_store,
        homelab_owner_pq.public_key(),
        2,
    );

    // Case A: Stranger presents a certificate signed by their own HybridPqSigningKeypair
    let stranger_cert = PersonalDeviceCert::issue(
        &stranger_pq,
        "stranger-laptop",
        "Unauthorized-Device",
        1_700_000_500,
    )
    .expect("issue stranger cert");

    let shard_bytes = vec![0xEEu8; 4096];
    let shard_id = ShardId {
        stripe_merkle_root: [0x99; 32],
        shard_index: 0,
        shard_hash: hash_shard_leaf(0, &shard_bytes),
    };

    let err_a = server
        .store_personal_device_shard(&stranger_cert, &shard_id, &shard_bytes)
        .expect_err("stranger cert must be rejected");
    assert!(matches!(err_a, BootstrapError::InvalidPersonalDeviceCert));

    // Case B: Stranger spoofs owner_root_pubkey as homelab_owner_pq.public_key() but signs with stranger_pq
    let mut spoofed_cert = stranger_cert.clone();
    spoofed_cert.owner_root_pubkey = homelab_owner_pq.public_key();
    let err_b = server
        .store_personal_device_shard(&spoofed_cert, &shard_id, &shard_bytes)
        .expect_err("spoofed cert must be rejected");
    assert!(matches!(err_b, BootstrapError::InvalidPersonalDeviceCert));

    // Verify 0 bytes stored and shard does not exist on disk
    let report = server.status_report(1);
    assert_eq!(report.used_storage_bytes, 0);
    assert!(!server.block_store().has_shard(&shard_id));
}
