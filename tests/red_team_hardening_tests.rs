use parvault::bootstrap::{
    canonical_sybil_subnet_key, BlindedShardTombstone, EarnedStanding, ElasticBootstrapEngine,
    ElasticPeerCandidate, PeerRole,
};
use parvault::config::ErasureTier;
use parvault::crypto::{MasterKey, NodeIdentity, PqVaultMasterKey};
use parvault::network::behaviour::{is_routable_public_ip, BincodeWireCodec};
use parvault::network::wot::{DelegationChain, InvitationHop, WebOfTrustRegistry};
use parvault::por::{PorError, PorVerifierEngine, RepairGrant};
use parvault::sharding::encode_ciphertext_stripe;
use parvault::storage::{
    AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, BlockStore, QuotaManager,
    ShardId, StorageError, TrustLevel, VoucherNullifierLedger,
};
use parvault::sync::{EncryptedVaultCatalogEnvelope, FolderSyncEngine};
use parvault::telemetry::{
    AnonymousTelemetryBeacon, NetworkCensusAggregator, TelemetryError, BYTES_PER_GIB,
    MAX_SINGLE_NODE_BUCKET_GIB,
};
use std::fs;
use std::net::IpAddr;
use tempfile::tempdir;

/// ============================================================================
/// RED-TEAM TEST 1 (Domain 1 — Crypto & Disaster Recovery):
/// Total Local-Disk Loss ("House Fire") Zero-Local-State Recovery from Seed Phrase Alone
/// ============================================================================
#[test]
fn test_rt1_zero_local_state_house_fire_recovery_from_seed_phrase_alone() {
    let shard_storage_dir = tempdir().expect("shard storage dir");
    let source_dir = tempdir().expect("source dir");
    let restored_dir = tempdir().expect("restored dir");

    let seed_phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let vault_namespace = "chris-homelab-primary-vault";

    // 1. Machine A (before the house fire): derive keys deterministically from (seed_phrase, vault_namespace)
    let mk_a = MasterKey::from_recovery_seed_phrase(seed_phrase, vault_namespace);
    let pq_a = PqVaultMasterKey::from_recovery_seed_phrase(seed_phrase, vault_namespace);
    let id_a = NodeIdentity::from_recovery_seed_phrase(seed_phrase, vault_namespace);
    let dht_key_a = mk_a.derive_vault_root_dht_key(vault_namespace);

    let quota = QuotaManager::new(500 * 1024 * 1024, 100 * 1024 * 1024);
    let store = BlockStore::new(shard_storage_dir.path(), quota).expect("block store");

    // Create nested files on Machine A
    fs::create_dir_all(source_dir.path().join("finance/2026")).unwrap();
    fs::write(
        source_dir.path().join("finance/2026/tax_return.txt"),
        b"CONFIDENTIAL TAX RETURN 2026 - ZERO LOCAL STATE RECOVERY PROOF",
    )
    .unwrap();
    fs::write(
        source_dir.path().join("notes.md"),
        b"Homelab SSH & WireGuard configuration backup.",
    )
    .unwrap();

    let mut sync_engine = FolderSyncEngine::new(store.clone(), mk_a, id_a, ErasureTier::Homelab);
    let snapshot = sync_engine
        .sync_folder_once(source_dir.path())
        .expect("sync folder once");
    assert_eq!(snapshot.files.len(), 2);

    // Export the Post-Quantum Encrypted Root Catalog Envelope for Kademlia DHT storage
    let dht_catalog_envelope: EncryptedVaultCatalogEnvelope = sync_engine
        .export_encrypted_vault_catalog(seed_phrase, vault_namespace, &snapshot)
        .expect("export encrypted vault catalog");
    assert_eq!(dht_catalog_envelope.dht_key, dht_key_a);
    assert!(dht_catalog_envelope.verify_zero_knowledge());

    // 2. SIMULATE TOTAL HOUSE FIRE:
    //    - Destroy `source_dir` (all original files gone)
    //    - Delete all local `.manifest.bin` files inside `shard_storage_dir/manifests`
    //      (only the raw encrypted Reed-Solomon shards on remote peers and the DHT envelope survive!)
    drop(source_dir);
    drop(sync_engine);
    for entry in fs::read_dir(shard_storage_dir.path().join("manifests")).unwrap() {
        let entry = entry.unwrap();
        fs::remove_file(entry.path()).unwrap();
    }

    // 3. Machine B (brand-new laptop with ZERO local files):
    //    - Wrong seed phrase must fail closed
    assert!(FolderSyncEngine::recover_folder_from_seed_phrase(
        store.clone(),
        "wrong mnemonic phrase that attacker guessed",
        vault_namespace,
        &dht_catalog_envelope,
        restored_dir.path(),
    )
    .is_err());

    //    - Genuine seed phrase + vault_namespace deterministically derives identical keys
    //      and recovers the entire directory tree!
    let mk_b = MasterKey::from_recovery_seed_phrase(seed_phrase, vault_namespace);
    let pq_b = PqVaultMasterKey::from_recovery_seed_phrase(seed_phrase, vault_namespace);
    assert_eq!(
        mk_b.as_bytes(),
        MasterKey::from_recovery_seed_phrase(seed_phrase, vault_namespace).as_bytes()
    );
    assert_eq!(pq_b.as_bytes(), pq_a.as_bytes());

    let recovered_count = FolderSyncEngine::recover_folder_from_seed_phrase(
        store,
        seed_phrase,
        vault_namespace,
        &dht_catalog_envelope,
        restored_dir.path(),
    )
    .expect("zero-local-state disaster recovery from seed phrase");
    assert_eq!(recovered_count, 2);

    let restored_tax =
        fs::read_to_string(restored_dir.path().join("finance/2026/tax_return.txt")).unwrap();
    assert_eq!(
        restored_tax,
        "CONFIDENTIAL TAX RETURN 2026 - ZERO LOCAL STATE RECOVERY PROOF"
    );
}

/// ============================================================================
/// RED-TEAM TEST 2 (Domain 1 — Blinded Capability Pinning, Clock Skew & Tombstone Generation Replay):
/// ============================================================================
#[test]
fn test_rt2_blinded_capability_pinning_clock_skew_and_tombstone_generation_replay_defense() {
    let dir = tempdir().expect("tempdir");
    let quota = QuotaManager::new(100 * 1024 * 1024, 50 * 1024 * 1024);
    let store = BlockStore::new(dir.path(), quota).expect("store");

    let issuer = NodeIdentity::generate();
    let mut ledger = VoucherNullifierLedger::new(issuer.public_key_bytes());

    let owner_mk = MasterKey::generate();
    let stripe_root = [0x33u8; 32];
    let shard_bytes = vec![0xABu8; 4096];
    let blinded_id = BlindedShardId::derive(&owner_mk, &stripe_root, 0, &shard_bytes);
    let (owner_cap_id, owner_cap) =
        BlindedShardCapability::derive_keypair(&owner_mk, &blinded_id.locator);
    let delete_secret = [0x77u8; 32];
    let delete_verifier =
        BlindedShardTombstone::derive_delete_verifier(&delete_secret, &blinded_id.locator);

    // 1. Upload blinded shard at epoch 10 (binds `owner_cap.capability_pubkey` to lease generation 0)
    let v1 = AnonymousQuotaVoucher::mint(&issuer, 8192);
    store
        .put_blinded_shard_with_lease(
            &blinded_id,
            &shard_bytes,
            owner_cap,
            &v1,
            &mut ledger,
            parvault::storage::BlindedLeaseSpec::new(10, 20, delete_verifier),
        )
        .expect("put blinded shard gen 0");

    // 2. [CRITICAL-CRYPTO-01] Attacker knows `blinded_id.locator` and creates a self-signed
    //    `BlindedShardCapability` with their own Ed25519 keypair. Must be REJECTED because
    //    `BlockStore` pinned `owner_cap.capability_pubkey` on upload!
    let attacker_mk = MasterKey::generate();
    let (attacker_cap_id, attacker_forged_cap) =
        BlindedShardCapability::derive_keypair(&attacker_mk, &blinded_id.locator);
    let attacker_sig =
        BlindedShardCapability::sign_read_token(&attacker_cap_id, &blinded_id.locator, 1_000_000);
    assert!(matches!(
        store.get_blinded_shard_authorized(
            &blinded_id,
            &attacker_forged_cap,
            1_000_000,
            &attacker_sig,
            1_000_000
        ),
        Err(StorageError::QuotaExceeded(_))
    ));

    // Genuine owner capability succeeds
    let owner_sig =
        BlindedShardCapability::sign_read_token(&owner_cap_id, &blinded_id.locator, 1_000_000);
    let read_back = store
        .get_blinded_shard_authorized(&blinded_id, &owner_cap, 1_000_000, &owner_sig, 1_000_000)
        .expect("genuine owner read");
    assert_eq!(read_back, shard_bytes);

    // 3. [HIGH-CRYPTO-02] Clock-skew tolerance & far-future "immortal token" rejection:
    let now_ms = 1_700_000_000_000u64;
    let slight_skew_ts = now_ms + 5_000; // +5s NTP drift (within 30s tolerance)
    let sig_skew =
        BlindedShardCapability::sign_read_token(&owner_cap_id, &blinded_id.locator, slight_skew_ts);
    assert!(owner_cap.verify_read_token_with_skew(slight_skew_ts, now_ms, &sig_skew));

    let immortal_future_ts = u64::MAX - 1000;
    let sig_immortal = BlindedShardCapability::sign_read_token(
        &owner_cap_id,
        &blinded_id.locator,
        immortal_future_ts,
    );
    assert!(
        !owner_cap.verify_read_token_with_skew(immortal_future_ts, now_ms, &sig_immortal),
        "Far-future immortal capability timestamp must be rejected"
    );

    // 4. [CRITICAL-CRYPTO-03] Tombstone Generation Replay Defense:
    //    Owner deletes the shard with `tombstone_gen0`, then re-uploads the shard at epoch 15 (gen 1).
    //    An attacker who captured `tombstone_gen0` replays it against the re-uploaded shard!
    let tombstone_gen0 =
        BlindedShardTombstone::create(&delete_verifier, blinded_id.locator, [0x11u8; 16]);
    assert!(store
        .delete_blinded_shard_with_tombstone(&blinded_id, &tombstone_gen0)
        .unwrap());
    assert!(!store.has_blinded_shard_on_disk(&blinded_id));

    // Re-upload the exact same shard at epoch 15
    let v2 = AnonymousQuotaVoucher::mint(&issuer, 8192);
    store
        .put_blinded_shard_with_lease(
            &blinded_id,
            &shard_bytes,
            owner_cap,
            &v2,
            &mut ledger,
            parvault::storage::BlindedLeaseSpec::new(15, 20, delete_verifier),
        )
        .expect("re-upload blinded shard gen 1");
    assert!(store.has_blinded_shard_on_disk(&blinded_id));

    // Attacker replays `tombstone_gen0` -> MUST BE REJECTED! Shard remains intact on disk!
    assert!(
        !store
            .delete_blinded_shard_with_tombstone(&blinded_id, &tombstone_gen0)
            .unwrap(),
        "Replayed tombstone from prior lease generation must be rejected"
    );
    assert!(store.has_blinded_shard_on_disk(&blinded_id));

    // Fresh generation-1 tombstone from owner succeeds
    let tombstone_gen1 = BlindedShardTombstone::create_for_generation(
        &delete_verifier,
        blinded_id.locator,
        [0x22u8; 16],
        1,
    );
    assert!(store
        .delete_blinded_shard_with_tombstone(&blinded_id, &tombstone_gen1)
        .unwrap());
    assert!(!store.has_blinded_shard_on_disk(&blinded_id));
}

/// ============================================================================
/// RED-TEAM TEST 3 (Domain 2 — Game Theory, Sybil Seed Drain & CGNAT):
/// ============================================================================
#[test]
fn test_rt3_ephemeral_sybil_seed_drain_blocked_and_cgnat_fairness() {
    let standing = EarnedStanding::ProbationaryConsumerPool; // 10-of-20

    // 1. Initial network has 20 Foundation Seed Anchors holding a user's 20 shards
    let mut candidates = Vec::new();
    for s in 0..20 {
        candidates.push(ElasticPeerCandidate {
            peer_id: format!("seed-anchor-{s:02}"),
            role: PeerRole::FoundationSeedAnchor,
            subnet_prefix: format!("198.51.{}.0/24", 100 + s),
            trust_level: TrustLevel::HighUptimeAnchor,
            rtt_ms: 30,
            committed_standby_bytes: 0,
        });
    }
    let placements = ElasticBootstrapEngine::select_elastic_targets(standing, &candidates);
    assert_eq!(placements.len(), 20);

    // 2. [Finding 1 Report 2] Attacker spins up 25 ephemeral 1-hour Sybil VMs across distinct /24s.
    //    Because they are `UntrustedProbationary` (0 PoR passes), `plan_seed_anchor_drain` MUST
    //    refuse to drain any shards onto them!
    let mut sybil_candidates = candidates.clone();
    for i in 0..25 {
        sybil_candidates.push(ElasticPeerCandidate {
            peer_id: format!("ephemeral-sybil-{i:02}"),
            role: PeerRole::OrganicCommunityPeer,
            subnet_prefix: format!("203.0.{i}.0/24"),
            trust_level: TrustLevel::UntrustedProbationary,
            rtt_ms: 5,
            committed_standby_bytes: 100 * 1024 * 1024 * 1024,
        });
    }
    let sybil_drain =
        ElasticBootstrapEngine::plan_seed_anchor_drain(standing, &placements, &sybil_candidates);
    assert_eq!(
        sybil_drain.len(),
        0,
        "Zero-history UntrustedProbationary Sybil nodes must NEVER drain Foundation Seed Anchors"
    );

    // 3. [Finding 3 Report 2] IPv6 /48 Sybil collapse vs. RFC 6598 CGNAT (Starlink / 5G) fairness:
    let ipv6_sybil_1: IpAddr = "2001:db8:abcd:0001::1".parse().unwrap();
    let ipv6_sybil_2: IpAddr = "2001:db8:abcd:ffff::9999".parse().unwrap();
    assert_eq!(
        canonical_sybil_subnet_key(ipv6_sybil_1, None),
        canonical_sybil_subnet_key(ipv6_sybil_2, None),
        "All 65,536 /64 subnets inside an IPv6 /32 or /48 allocation must collapse into 1 Sybil bucket"
    );

    let starlink_house_a: IpAddr = "100.64.12.34".parse().unwrap();
    let starlink_house_b: IpAddr = "100.64.12.99".parse().unwrap();
    assert_ne!(
        canonical_sybil_subnet_key(starlink_house_a, Some(0)),
        canonical_sybil_subnet_key(starlink_house_b, Some(1)),
        "Distinct WoT-attested households behind RFC 6598 CGNAT (100.64.0.0/10) get up to 4 sub-slots"
    );
    // Slot 4 wraps modulo MAX_CGNAT_SLOTS_PER_SLASH24 (4) -> collides with slot 0 to cap CGNAT Sybils
    assert_eq!(
        canonical_sybil_subnet_key(starlink_house_a, Some(0)),
        canonical_sybil_subnet_key(starlink_house_b, Some(4))
    );
}

/// ============================================================================
/// RED-TEAM TEST 4 (Domain 3 — Wire OOM Bomb, PoR Cross-Protocol Replay, WoT Nonce & Telemetry PoW):
/// ============================================================================
#[test]
fn test_rt4_wire_codec_oom_bomb_defense_por_cross_protocol_replay_and_telemetry_sybil_pow() {
    // 1. [RT3-02] BincodeWireCodec Pre-Allocation OOM Bomb Defense:
    //    Craft a 16-byte payload claiming `MeshWireRequest::HandshakeWoT` (variant 0u32)
    //    with a `Vec<InvitationHop>` length prefix of `u64::MAX` (`0xFFFF_FFFF_FFFF_FFFF`).
    //    Unbounded `bincode::deserialize` would immediately panic with OOM trying to allocate
    //    `u64::MAX * sizeof(InvitationHop)` bytes. `deserialize_request_bounded` rejects it cleanly!
    let codec = BincodeWireCodec::default();
    let mut oom_bomb_frame = Vec::new();
    oom_bomb_frame.extend_from_slice(&0u32.to_le_bytes()); // variant 0 (HandshakeWoT)
    oom_bomb_frame.extend_from_slice(&u64::MAX.to_le_bytes()); // forged Vec length = u64::MAX
    oom_bomb_frame.extend_from_slice(&[0u8; 16]);
    let res = codec.deserialize_request_bounded(&oom_bomb_frame);
    assert!(
        res.is_err(),
        "Malicious bincode length-prefix OOM bomb must be rejected without allocating"
    );

    // 2. [RT3-04] Bogon / Loopback / RFC1918 / CGNAT IP Filter for Public Kademlia DHT:
    assert!(!is_routable_public_ip("127.0.0.1".parse().unwrap()));
    assert!(!is_routable_public_ip("192.168.1.50".parse().unwrap()));
    assert!(!is_routable_public_ip("100.64.10.1".parse().unwrap()));
    assert!(!is_routable_public_ip("::1".parse().unwrap()));
    assert!(is_routable_public_ip("8.8.8.8".parse().unwrap()));

    // 3. [CRITICAL-CRYPTO-05] Cross-Protocol Signature Replay on `PorVerifierEngine::authorize_raw_shard_read`:
    let dir = tempdir().expect("tempdir");
    let store = BlockStore::new(
        dir.path(),
        QuotaManager::new(50 * 1024 * 1024, 25 * 1024 * 1024),
    )
    .unwrap();
    let owner = NodeIdentity::generate();
    let witness1 = NodeIdentity::generate();
    let witness2 = NodeIdentity::generate();
    let shard_set = encode_ciphertext_stripe(0, &[0x44u8; 4096], ErasureTier::Homelab).unwrap();
    let shard_id = ShardId {
        stripe_merkle_root: shard_set.stripe_merkle_root,
        shard_index: 0,
        shard_hash: shard_set.shard_hashes[0],
    };
    store
        .put_shard("local", &shard_id, &shard_set.shards[0])
        .unwrap();

    let mut por_verifier = PorVerifierEngine::new(300);
    let grant = RepairGrant::issue(
        &owner,
        shard_set.stripe_merkle_root,
        vec![witness1.public_key_bytes(), witness2.public_key_bytes()],
        ErasureTier::Homelab,
    );
    // v0.5.0 (F-26): a grant authorises the shards stored with it.
    assert!(por_verifier
        .register_repair_grant_for_stored(grant.clone(), &[shard_id])
        .is_ok());

    // Attacker tries to replay the owner's signature over an arbitrary non-read-token message
    let arbitrary_msg = b"parvault-repair-grant-v1:replay-attempt";
    let arbitrary_sig = owner.sign(arbitrary_msg);
    let replay_tuple = (
        owner.public_key_bytes(),
        arbitrary_msg.as_slice(),
        &arbitrary_sig,
    );
    assert!(matches!(
        por_verifier.authorize_raw_shard_read(&shard_id, Some(&replay_tuple), None, &store),
        Err(PorError::UnauthorizedRawShardRead)
    ));

    // Genuine domain-separated owner read token (`parvault-owner-shard-read-v1:`) succeeds
    let (owner_pub, valid_payload, valid_sig) =
        PorVerifierEngine::sign_owner_shard_read_token(&owner, &shard_id, 1_700_000_000_000);
    let valid_tuple = (owner_pub, valid_payload.as_slice(), &valid_sig);
    let bytes = por_verifier
        .authorize_raw_shard_read(&shard_id, Some(&valid_tuple), None, &store)
        .expect("domain-separated owner read token");
    assert_eq!(bytes, shard_set.shards[0]);

    // 4. [RT3-03] WebOfTrust SlashingEvidence Nonce Deduplication:
    let genesis = NodeIdentity::generate();
    let reporter = NodeIdentity::generate();
    let offender = NodeIdentity::generate();
    let mut wot = WebOfTrustRegistry::new(genesis.public_key_bytes(), 5);
    let hop_rep = InvitationHop::issue(&genesis, reporter.public_key_bytes(), 1, 1_700_000_000_000);
    let hop_off = InvitationHop::issue(&genesis, offender.public_key_bytes(), 1, 1_700_000_000_000);
    wot.verify_and_admit_chain(&DelegationChain {
        hops: vec![hop_rep],
    })
    .unwrap();
    wot.verify_and_admit_chain(&DelegationChain {
        hops: vec![hop_off],
    })
    .unwrap();

    // Peer slashing evidence is not applied in v0.5.0 (apply_slashing_evidence is test-only);
    // its replay dedupe is covered by the network::wot unit tests.
    assert!(wot.is_peer_trusted(&offender.public_key_bytes()));
    assert!(wot.is_peer_trusted(&reporter.public_key_bytes()));

    // 5. [RT3-01] AnonymousTelemetryBeacon Hashcash PoW, Bucket Bounds & IQR Outlier Trimming:
    let mut agg = NetworkCensusAggregator::with_min_pow_bits(500, 8);
    let zero_pow_beacon = AnonymousTelemetryBeacon::create(
        &[0x11u8; 32],
        500,
        "NA-EAST",
        PeerRole::OrganicCommunityPeer,
        EarnedStanding::EarnedVerifiedMixedPool,
        512 * BYTES_PER_GIB,
        128 * BYTES_PER_GIB,
        50,
    )
    .unwrap();
    assert!(matches!(
        agg.ingest_beacon(zero_pow_beacon),
        Err(TelemetryError::InsufficientProofOfWork { .. })
    ));

    // Valid PoW beacon (8 leading zero bits) is accepted
    for i in 0..5u8 {
        let b = AnonymousTelemetryBeacon::create_with_pow(
            &[i + 1; 32],
            500,
            "NA-EAST",
            PeerRole::OrganicCommunityPeer,
            EarnedStanding::EarnedVerifiedMixedPool,
            512 * BYTES_PER_GIB,
            128 * BYTES_PER_GIB,
            if i == 4 { 999_999 } else { 40 }, // 1 extreme outlier (999,999) + 4 honest (40)
            8,
        )
        .unwrap();
        assert!(agg.ingest_beacon(b).unwrap());
    }

    // Forged bucket (> MAX_SINGLE_NODE_BUCKET_GIB or used > committed) is rejected
    let mut poisoned_bucket = AnonymousTelemetryBeacon::create_with_pow(
        &[0x99u8; 32],
        500,
        "EU-CENTRAL",
        PeerRole::OrganicCommunityPeer,
        EarnedStanding::EarnedVerifiedMixedPool,
        128 * BYTES_PER_GIB,
        64 * BYTES_PER_GIB,
        40,
        8,
    )
    .unwrap();
    poisoned_bucket.committed_capacity_bucket_gib = MAX_SINGLE_NODE_BUCKET_GIB * 2;
    assert!(matches!(
        agg.ingest_beacon(poisoned_bucket),
        Err(TelemetryError::InvalidCapacityBucket { .. })
    ));

    let report = agg.generate_report();
    assert_eq!(report.unique_active_nodes, 5);
    assert_eq!(
        report.dht_cross_checked_population_estimate, 41,
        "IQR-trimmed median must ignore the 999,999 Sybil outlier and report 40 + 1 = 41"
    );
}

/// ============================================================================
/// RED-TEAM TEST 5 (Domain 4 — Path Traversal, Local Bit-Rot Scrubber & LRU/SSD-Wear Quota):
/// ============================================================================
#[test]
fn test_rt5_folder_restore_path_traversal_blocked_bitrot_scrubber_and_lru_quota_accounting() {
    let storage_dir = tempdir().expect("storage dir");
    let source_dir = tempdir().expect("source dir");
    let restore_dir = tempdir().expect("restore dir");

    // 1. [Finding 2 Report 4] Path Traversal (`../../`, `/etc/passwd`, `C:\...`) in `restore_folder`:
    let mk = MasterKey::generate();
    let owner = NodeIdentity::generate();
    let store = BlockStore::new(
        storage_dir.path(),
        QuotaManager::new(200 * 1024 * 1024, 20 * 1024 * 1024),
    )
    .unwrap();

    fs::write(source_dir.path().join("legit.txt"), b"safe file content").unwrap();
    let mut engine = FolderSyncEngine::new(store.clone(), mk, owner, ErasureTier::Homelab);
    let snapshot = engine.sync_folder_once(source_dir.path()).unwrap();

    // Tamper with snapshot paths to attempt parent-directory and absolute-path traversal
    let legit_entry = snapshot.files.get("legit.txt").unwrap().clone();
    for malicious_path in [
        "../../escaped_pwned.txt",
        "/etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "subdir/../../outside.txt",
    ] {
        let mut bad_snapshot = snapshot.clone();
        bad_snapshot.files.clear();
        let mut bad_entry = legit_entry.clone();
        bad_entry.relative_path = malicious_path.to_string();
        bad_snapshot
            .files
            .insert(malicious_path.to_string(), bad_entry);

        let err = engine
            .restore_folder(&bad_snapshot, restore_dir.path())
            .expect_err("path traversal must be blocked");
        assert!(
            matches!(err, StorageError::InvalidRestorePath(_)),
            "Expected InvalidRestorePath for {malicious_path}, got {err:?}"
        );
    }

    // Legitimate snapshot still restores cleanly
    let count = engine
        .restore_folder(&snapshot, restore_dir.path())
        .unwrap();
    assert_eq!(count, 1);

    // 2. [Finding 3 Report 4] Background Local Bit-Rot Self-Scrubbing (`BlockStore::scrub_all_shards`):
    let scrub_before = store.scrub_all_shards().unwrap();
    assert_eq!(scrub_before.verified_healthy_shards, 20);
    assert!(scrub_before.quarantined_corrupted_shards.is_empty());

    // Flip 1 byte in one `.shard` file on disk to simulate silent SSD/ZFS bit-rot
    let first_shard_file = fs::read_dir(storage_dir.path().join("shards"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut raw_shard = fs::read(&first_shard_file).unwrap();
    raw_shard[0] ^= 0xFF;
    fs::write(&first_shard_file, &raw_shard).unwrap();

    let scrub_after = store.scrub_all_shards().unwrap();
    assert_eq!(scrub_after.verified_healthy_shards, 19);
    assert_eq!(scrub_after.quarantined_corrupted_shards.len(), 1);
    assert!(
        !first_shard_file.exists(),
        "Corrupted bit-rotted shard file must be unlinked from disk by scrub_all_shards"
    );

    // Even with 1 bit-rotted shard quarantined, 19 >= 16 surviving shards still restore the file!
    let restore_dir_2 = tempdir().unwrap();
    assert_eq!(
        engine
            .restore_folder(&snapshot, restore_dir_2.path())
            .unwrap(),
        1
    );

    // 3. [Finding 4 Report 2 & 4] LRU Eviction Quota Fix & Anti-SSD-Wear Write Amplification Cap:
    let mut qm = QuotaManager::new(10_000, 5_000);
    assert!(qm.can_accept_shard("peer-alpha", 4_000));
    qm.record_shard_stored("peer-alpha", "shard-1".to_string(), 4_000);
    assert_eq!(
        qm.peer_account("peer-alpha").unwrap().bytes_hosted_for_peer,
        4_000
    );

    // LRU eviction of `shard-1` must decrement `peer-alpha`'s `bytes_hosted_for_peer` back to 0!
    let evicted = qm.evict_lru_to_fit(8_000);
    assert_eq!(evicted, vec!["shard-1".to_string()]);
    assert_eq!(
        qm.peer_account("peer-alpha").unwrap().bytes_hosted_for_peer,
        0,
        "LRU eviction must release the peer's hosted byte balance"
    );

    // Rapid upload-delete SSD wear griefing loop hits the 4x per-epoch ingress write ceiling (`4 * 5000 = 20000`)
    for i in 0..4 {
        let key = format!("churn-{i}");
        assert!(qm.can_accept_shard("peer-alpha", 4_000));
        qm.record_shard_stored("peer-alpha", key.clone(), 4_000);
        qm.record_shard_removed("peer-alpha", &key, 4_000);
    }
    // Now `epoch_ingress_bytes_written` is 20,000 (4_000 initial + 16,000 churn) == `4 * 5,000` ceiling!
    assert!(
        !qm.can_accept_shard("peer-alpha", 4_000),
        "Peer exceeding 4x per-epoch write amplification ceiling must be throttled even if active hosted bytes == 0"
    );
    qm.reset_epoch_ingress_counters();
    assert!(qm.can_accept_shard("peer-alpha", 4_000));
}

// ============================================================================
// RED-TEAM TEST 6 (Review Remediations A1–A4, B1–B12, C6, D4):
// - Argon2id 64 MiB parameters (`A1`, `B7`), BIP-39 2,048-word validation + SHA-256 checksum
//   + Levenshtein typo suggestion + NFKD whitespace normalization (`A4`, `B6`)
// - Per-purpose HKDF-SHA256 subkeys on `MasterKey` (`B1`) and separated Ed25519/X25519 seeds (`B2`)
// - Atomic `0600` secret file permissions (`B4`) and `LocalFileKeystore` passphrase sealing (`B5`)
// - 2-Layer Post-Quantum Onion Routing (`seal_layered_pq` -> `peel_relay_hop_pq` -> `open_final_target_pq`, `C6`),
//   ephemeral blinded voucher minting, and uniform shard bucket padding (`D4`)
// ============================================================================
#[test]
fn test_rt6_review_remediation_bip39_subkeys_0600_and_2layer_pq_onion() {
    use parvault::crypto::{
        generate_bip39_mnemonic, normalize_seed_phrase_nfkd, validate_bip39_mnemonic,
        validate_recovery_seed_phrase_or_passphrase, HybridKemKeypair, HybridPqSigningKeypair,
        LocalFileKeystore, LocalKeystoreSealer, PqOnionFinalBundle, PqRelayedShardEnvelope,
        ARGON2_M_COST_KIB, ARGON2_P_COST, ARGON2_T_COST,
    };
    use parvault::storage::{pad_shard_uniform_bucket, unpad_shard_uniform_bucket};

    // 1. [A1 / B7] Verify Argon2id hardening parameters match documentation (64 MiB, t=3, p=4)
    assert_eq!(ARGON2_M_COST_KIB, 65_536);
    assert_eq!(ARGON2_T_COST, 3);
    assert_eq!(ARGON2_P_COST, 4);

    // 2. [A4 / B6] BIP-39 24-word generation, NFKD normalization, checksum & typo detection
    let m24 = generate_bip39_mnemonic(24).expect("generate 24-word BIP-39 mnemonic");
    assert_eq!(m24.split(' ').count(), 24);
    assert_eq!(validate_bip39_mnemonic(&m24).unwrap(), m24);

    let messy =
        "  ABANDON\t\tabandon\r\nAbandon   abandon abandon abandon abandon abandon abandon abandon abandon ABOUT ";
    assert_eq!(
        normalize_seed_phrase_nfkd(messy),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );

    let typo_phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon aboot";
    let typo_err = validate_recovery_seed_phrase_or_passphrase(typo_phrase)
        .unwrap_err()
        .to_string();
    assert!(
        typo_err.contains("unknown BIP-39 word 'aboot'") && typo_err.contains("did you mean"),
        "Expected Levenshtein suggestion on BIP-39 typo, got: {typo_err}"
    );

    let bad_checksum =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    let cs_err = validate_recovery_seed_phrase_or_passphrase(bad_checksum)
        .unwrap_err()
        .to_string();
    assert!(
        cs_err.contains("checksum verification failed"),
        "Expected BIP-39 checksum error, got: {cs_err}"
    );

    // 3. [B1 / B2] Per-purpose HKDF-SHA256 subkeys are mutually distinct and distinct from MasterKey
    let mk = MasterKey::generate();
    let subkeys = [
        *mk.as_bytes(),
        mk.stripe_aead_subkey(),
        mk.stripe_nonce_subkey(),
        mk.manifest_aead_subkey(),
        mk.dht_routing_subkey(),
        mk.blind_locator_subkey(),
        mk.blind_capability_subkey(),
        mk.shard_pseudonym_subkey(),
    ];
    for i in 0..subkeys.len() {
        for j in (i + 1)..subkeys.len() {
            assert_ne!(
                subkeys[i], subkeys[j],
                "Subkeys {i} and {j} must be cryptographically domain-separated"
            );
        }
    }

    // NodeIdentity::from_seed derives independent Ed25519 and X25519 keys
    let id = NodeIdentity::from_seed([0x42u8; 32]);
    assert_ne!(
        id.public_key_bytes(),
        *id.x25519_public().as_bytes(),
        "Ed25519 and X25519 public keys must be derived from domain-separated seeds"
    );

    // 4. [B4 / B5] Secret key files written with 0600 permissions + LocalFileKeystore sealing
    let key_dir = tempdir().expect("key tempdir");
    let _loaded_node = NodeIdentity::load_or_generate_in_dir(key_dir.path()).unwrap();
    // v0.5.0: a ring genesis exists only after the explicit `parvault wot init` action.
    let _loaded_genesis = NodeIdentity::init_ring_genesis_in_dir(key_dir.path()).unwrap();
    let _loaded_kem = HybridKemKeypair::load_or_generate_in_dir(key_dir.path()).unwrap();
    let _loaded_pq = HybridPqSigningKeypair::load_or_generate_in_dir(key_dir.path()).unwrap();
    let keystore = LocalFileKeystore::from_passphrase_or_csprng_in_dir(
        key_dir.path(),
        Some("high-entropy-keystore-passphrase-2026"),
    )
    .unwrap();
    let sealed_blob = keystore.seal_key(mk.as_bytes()).unwrap();
    let unsealed_mk = keystore.unseal_key(&sealed_blob).unwrap();
    assert_eq!(&unsealed_mk, mk.as_bytes());

    let local_sealer =
        LocalFileKeystore::from_passphrase_or_csprng_in_dir(key_dir.path(), None).unwrap();
    let _ = local_sealer
        .load_or_create_master_key(&key_dir.path().join("master_key.sealed"))
        .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for secret_file in [
            "node_identity.seed",
            "ring_genesis.seed",
            "node_pq_kem.bin",
            "owner_pq_keypair.bin",
            "enclave_sealing.seed",
            "master_key.sealed",
        ] {
            let p = key_dir.path().join(secret_file);
            let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "Secret file {secret_file} must have strict 0600 permissions, got {mode:o}"
            );
        }
    }

    // 5. [C6 / D4] 2-Layer PQ Onion Routing, Ephemeral Blinded Vouchers & Uniform Shard Padding
    let raw_shard = vec![0xABu8; 1337];
    let padded_shard = pad_shard_uniform_bucket(&raw_shard, 4096);
    assert_eq!(padded_shard.len(), 4096);
    let unpadded_shard = unpad_shard_uniform_bucket(&padded_shard).unwrap();
    assert_eq!(unpadded_shard, raw_shard);

    let relay_kem = HybridKemKeypair::generate().unwrap();
    let target_kem = HybridKemKeypair::generate().unwrap();
    let blinded_id = BlindedShardId::derive(&mk, &[0x99u8; 32], 2, &padded_shard);
    let (_, cap) = BlindedShardCapability::derive_keypair(&mk, &blinded_id.locator);
    let (_, ephem_voucher_a) =
        AnonymousQuotaVoucher::mint_blinded_ephemeral(&[0x77u8; 32], &blinded_id.locator, 4096);
    let (_, ephem_voucher_b) =
        AnonymousQuotaVoucher::mint_blinded_ephemeral(&[0x77u8; 32], &[0x88u8; 32], 4096);
    assert_ne!(
        ephem_voucher_a.issuer_pubkey, ephem_voucher_b.issuer_pubkey,
        "Per-shard ephemeral vouchers must not share a static linkable issuer_pubkey across locators"
    );

    let bundle = PqOnionFinalBundle {
        blinded_id,
        shard_bytes: padded_shard.clone(),
        capability: cap,
        voucher: ephem_voucher_a.clone(),
        current_epoch: 10,
        lease_duration_epochs: 30,
        delete_verifier: [0x55u8; 32],
    };
    let outer = PqRelayedShardEnvelope::seal_layered_pq(
        &relay_kem.public_key(),
        "relay-hop-1",
        &target_kem.public_key(),
        "/ip4/10.0.0.99/tcp/4001",
        &bundle,
        15,
        5,
    )
    .unwrap();

    // Relay peels outer hop, learns only next-hop multiaddr, and cannot open inner target payload
    let hop = outer.peel_relay_hop_pq(&relay_kem).unwrap();
    assert_eq!(hop.target_peer_addr, "/ip4/10.0.0.99/tcp/4001");
    assert!(hop.inner_envelope.open_final_target_pq(&relay_kem).is_err());

    // Final target opens inner payload and recovers the full bundle
    let recovered = hop
        .inner_envelope
        .open_final_target_pq(&target_kem)
        .unwrap();
    assert_eq!(recovered.blinded_id, blinded_id);
    assert_eq!(recovered.shard_bytes, padded_shard);
    assert_eq!(recovered.voucher, ephem_voucher_a);
}
