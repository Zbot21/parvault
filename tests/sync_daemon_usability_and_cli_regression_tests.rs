//! Wave 2 & Wave 3 Comprehensive Regression Suite (`ADR-16`):
//! Verifies internet-grade sync-daemon usability, streaming 64 KiB SHA-256 hashing,
//! `.parvaultignore` filtering, dry-run `diff_folder`, deleted-file tombstones & shard pruning,
//! selective single-file restore, persistent node/PQ identity & `PARVAULT-CERT-V1:` shareable tokens,
//! bounded FIFO nonce caches, PoR range limits, token-bucket bandwidth rate limiting,
//! minimum free disk space guards, and PQ/Catalog `ZeroTrustDhtStore` enforcement.

use parvault::{
    bootstrap::{
        normalize_subnet_prefix_key, ElasticBootstrapEngine, ElasticPeerCandidate,
        PersonalDeviceCert, ZeroTrustSeedServer,
    },
    config::ErasureTier,
    crypto::{
        pqc::{
            HybridPqPublicKey, HybridPqSigningKeypair, PqSignedDhtManifestEnvelope,
            PqVaultMasterKey,
        },
        MasterKey, NodeIdentity,
    },
    network::{
        DelegationChain, InvitationHop, PeerTopologyMetrics, PlacementEngine, SlashingEvidence,
        SlashingReason, TokenBucketRateLimiter, WebOfTrustRegistry,
    },
    por::{
        compute_salted_commitment, generate_por_challenge, PorError, PorResponse,
        PorVerifierEngine, MAX_POR_RANGE_BYTES,
    },
    sharding::merkle::hash_shard_leaf,
    storage::{BlockStore, QuotaManager, ShardId, TrustLevel, ZeroTrustDhtStore},
    sync::{compute_file_sha256_streaming, FolderSyncEngine, ParvaultIgnore},
};
use sha2::{Digest, Sha256};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

/// v0.5.0 requires ring admission for storage: every process these tests start (and every
/// in-process `MeshClient`) shares one ring genesis, provisioned before the first spawn.
fn provision_ring_genesis() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| std::env::set_var("PARVAULT_GENESIS_SEED_HEX", "47".repeat(32)));
}

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "parvault-regression-{}-{}-{}",
        label,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn test_streaming_sha256_and_parvaultignore_filtering() {
    provision_ring_genesis();
    let base = unique_temp_dir("ignore-and-stream");
    let data_dir = base.join("store");
    let watched = base.join("watched_project");
    fs::create_dir_all(&watched).unwrap();

    // 1. Verify streaming 64 KiB SHA-256 over a multi-chunk 300 KiB payload
    let large_file = watched.join("dataset.bin");
    let payload: Vec<u8> = (0..(300 * 1024))
        .map(|i| ((i * 73 + 19) & 0xFF) as u8)
        .collect();
    fs::write(&large_file, &payload).unwrap();

    let (stream_len, stream_sha) = compute_file_sha256_streaming(&large_file).unwrap();
    let expected_sha: [u8; 32] = Sha256::digest(&payload).into();
    assert_eq!(stream_len, payload.len() as u64);
    assert_eq!(stream_sha, expected_sha);

    // 2. Populate watched folder with default-ignored directories/files and custom .parvaultignore rules
    fs::create_dir_all(watched.join(".git/objects")).unwrap();
    fs::write(watched.join(".git/objects/pack"), b"git-pack-object").unwrap();
    fs::create_dir_all(watched.join("node_modules/pkg")).unwrap();
    fs::write(
        watched.join("node_modules/pkg/index.js"),
        b"module.exports = {}",
    )
    .unwrap();
    fs::create_dir_all(watched.join("target/debug")).unwrap();
    fs::write(watched.join("target/debug/app"), b"binary").unwrap();
    fs::write(watched.join(".DS_Store"), b"macos").unwrap();
    fs::write(watched.join("scratch.tmp"), b"temp").unwrap();
    fs::write(
        watched.join("folder_snapshot.manifest.bin"),
        b"self-manifest",
    )
    .unwrap();

    // Custom .parvaultignore with wildcard + negation rule
    fs::write(
        watched.join(".parvaultignore"),
        "# Project ignore rules\nlogs/\n*.log\n!keep.log\n",
    )
    .unwrap();
    fs::create_dir_all(watched.join("logs")).unwrap();
    fs::write(watched.join("logs/debug.txt"), b"ignored-dir").unwrap();
    fs::write(watched.join("app.log"), b"ignored-log").unwrap();
    fs::write(watched.join("keep.log"), b"negated-important-log").unwrap();
    fs::write(watched.join("src_main.rs"), b"fn main() {}").unwrap();

    let ignore = ParvaultIgnore::from_folder(&watched);
    assert!(ignore.is_ignored(".git", true));
    assert!(ignore.is_ignored("node_modules", true));
    assert!(ignore.is_ignored("logs", true));
    assert!(ignore.is_ignored("app.log", false));
    assert!(!ignore.is_ignored("keep.log", false));
    assert!(!ignore.is_ignored("src_main.rs", false));

    let quota = QuotaManager::new(500 * 1024 * 1024, 50 * 1024 * 1024);
    let store = BlockStore::new(&data_dir, quota).unwrap();
    let master_key = MasterKey::generate();
    let owner = NodeIdentity::generate();
    let mut engine = FolderSyncEngine::new(store, master_key, owner, ErasureTier::Consumer);

    let snapshot = engine.sync_folder_once(&watched).unwrap();
    assert_eq!(snapshot.files.len(), 3);
    assert!(snapshot.files.contains_key("dataset.bin"));
    assert!(snapshot.files.contains_key("keep.log"));
    assert!(snapshot.files.contains_key("src_main.rs"));
    assert!(!snapshot.files.contains_key("app.log"));
    assert!(!snapshot.files.contains_key(".parvaultignore"));
    assert!(!snapshot.files.contains_key("folder_snapshot.manifest.bin"));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_incremental_mtime_fastpath_diff_folder_tombstones_and_single_file_restore() {
    provision_ring_genesis();
    let base = unique_temp_dir("diff-tombstone-single");
    let data_dir = base.join("store");
    let watched = base.join("docs");
    let restored_dir = base.join("restored");
    fs::create_dir_all(watched.join("sub")).unwrap();

    fs::write(watched.join("alpha.txt"), b"alpha-v1").unwrap();
    fs::write(watched.join("sub/beta.txt"), b"beta-v1").unwrap();
    fs::write(watched.join("ephemeral.txt"), b"will-be-deleted").unwrap();

    let quota = QuotaManager::new(500 * 1024 * 1024, 50 * 1024 * 1024);
    let store = BlockStore::new(&data_dir, quota).unwrap();
    let master_key = MasterKey::generate();
    let owner = NodeIdentity::generate();
    let mut engine = FolderSyncEngine::new(
        store.clone(),
        master_key.clone(),
        owner,
        ErasureTier::Consumer,
    );

    // 1. Dry-run diff before initial sync
    let diff0 = engine.diff_folder(&watched).unwrap();
    assert_eq!(diff0.added.len(), 3);
    assert!(diff0.modified.is_empty());
    assert!(diff0.deleted.is_empty());

    // 2. Initial sync (v1)
    let snap1 = engine.sync_folder_once(&watched).unwrap();
    assert_eq!(snap1.version, 1);
    assert_eq!(snap1.files.len(), 3);
    assert!(snap1.deleted_tombstones.is_empty());

    // 3. Modify alpha.txt, delete ephemeral.txt, add gamma.txt
    fs::write(watched.join("alpha.txt"), b"alpha-v2-updated").unwrap();
    fs::remove_file(watched.join("ephemeral.txt")).unwrap();
    fs::write(watched.join("gamma.txt"), b"gamma-new").unwrap();

    let diff1 = engine.diff_folder(&watched).unwrap();
    assert_eq!(diff1.added, vec!["gamma.txt".to_string()]);
    assert_eq!(diff1.modified, vec!["alpha.txt".to_string()]);
    assert_eq!(diff1.deleted, vec!["ephemeral.txt".to_string()]);
    assert_eq!(diff1.unchanged, vec!["sub/beta.txt".to_string()]);

    // 4. Sync pass v2 records tombstone for ephemeral.txt
    let snap2 = engine.sync_folder_once(&watched).unwrap();
    assert_eq!(snap2.version, 2);
    assert_eq!(snap2.files.len(), 3);
    assert!(snap2.deleted_tombstones.contains_key("ephemeral.txt"));
    assert_eq!(
        snap2.deleted_tombstones["ephemeral.txt"].deleted_at_version,
        2
    );

    // 5. Selective single-file restore of only "sub/beta.txt"
    let single_out = engine
        .restore_single_file(&snap2, "sub/beta.txt", &restored_dir)
        .unwrap();
    assert_eq!(fs::read(&single_out).unwrap(), b"beta-v1");
    assert!(!restored_dir.join("alpha.txt").exists());

    // Path traversal on restore_single_file must be rejected
    assert!(engine
        .restore_single_file(&snap2, "../escape.txt", &restored_dir)
        .is_err());

    // 6. Prune deleted file shards reclaims ephemeral.txt's 20 shards
    let pruned_shards = engine.prune_deleted_file_shards(&snap2).unwrap();
    assert_eq!(pruned_shards, 20);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_persistent_identity_and_shareable_personal_device_cert_tokens() {
    provision_ring_genesis();
    let base = unique_temp_dir("identity-and-cert");

    // 1. NodeIdentity & HybridPqSigningKeypair persistence across restarts
    let node_id_1 = NodeIdentity::load_or_generate_in_dir(&base).unwrap();
    let node_id_2 = NodeIdentity::load_or_generate_in_dir(&base).unwrap();
    assert_eq!(node_id_1.public_key_bytes(), node_id_2.public_key_bytes());
    assert_eq!(node_id_1.device_peer_id(), node_id_2.device_peer_id());
    assert!(node_id_1.device_peer_id().starts_with("parvault-peer-"));

    let pq_1 = HybridPqSigningKeypair::load_or_generate_in_dir(&base).unwrap();
    let pq_2 = HybridPqSigningKeypair::load_or_generate_in_dir(&base).unwrap();
    assert_eq!(pq_1.public_key(), pq_2.public_key());

    let pk_hex = pq_1.public_key().to_hex().unwrap();
    let pk_roundtrip = HybridPqPublicKey::from_hex(&pk_hex).unwrap();
    assert_eq!(pq_1.public_key(), pk_roundtrip);
    assert_eq!(pq_1.public_key().fingerprint_hex().len(), 16);

    // 2. PersonalDeviceCert length-prefixed signing digest & empty-field rejection
    assert!(PersonalDeviceCert::issue(&pq_1, "", "Laptop", 1_700_000_000).is_err());
    assert!(PersonalDeviceCert::issue(&pq_1, "peer-1", "   ", 1_700_000_000).is_err());

    let cert_a = PersonalDeviceCert::issue(&pq_1, "peer:A", "B", 1_700_000_000).unwrap();
    let mut forged_shift = cert_a.clone();
    forged_shift.device_peer_id = "peer".to_string();
    forged_shift.device_label = "A:B".to_string();
    assert!(
        forged_shift.verify(&pq_1.public_key()).is_err(),
        "Length-prefixed signing_digest must block variable-length boundary shift"
    );

    // 3. Shareable token (PARVAULT-CERT-V1:...) and JSON round-trip
    let cert = PersonalDeviceCert::issue(
        &pq_1,
        &node_id_1.device_peer_id(),
        "ThinkPad-X1",
        1_700_000_000,
    )
    .unwrap();
    let token = cert.to_shareable_token().unwrap();
    assert!(token.starts_with("PARVAULT-CERT-V1:"));
    let from_token = PersonalDeviceCert::from_shareable_token(&token).unwrap();
    from_token.verify(&pq_1.public_key()).unwrap();

    let json = cert.to_json_pretty().unwrap();
    let from_json = PersonalDeviceCert::from_shareable_token(&json).unwrap();
    from_json.verify(&pq_1.public_key()).unwrap();

    // Verify HomelabRedundancyVault accepts the deserialized cert with 0 quota charge
    let quota = QuotaManager::new(100 * 1024 * 1024, 10 * 1024 * 1024);
    let store = BlockStore::new(base.join("seed"), quota).unwrap();
    let mut seed_server =
        ZeroTrustSeedServer::new_homelab_vault("nas-seed", store, pq_1.public_key(), 2);
    let shard_bytes = vec![0x42u8; 1024];
    let shard_id = ShardId {
        stripe_merkle_root: [0x88; 32],
        shard_index: 0,
        shard_hash: hash_shard_leaf(0, &shard_bytes),
    };
    seed_server
        .store_personal_device_shard(&from_token, &shard_id, &shard_bytes)
        .unwrap();
    assert_eq!(
        seed_server.personal_device_quota_charged(&node_id_1.device_peer_id()),
        0
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_bounded_por_and_slashing_replay_caches_and_range_cap() {
    provision_ring_genesis();
    let base = unique_temp_dir("por-and-wot-bounds");
    let quota = QuotaManager::new(100 * 1024 * 1024, 10 * 1024 * 1024);
    let store = BlockStore::new(&base, quota).unwrap();

    let shard_bytes = vec![0x55u8; 128 * 1024]; // 128 KiB shard
    let shard_id = ShardId {
        stripe_merkle_root: [0x33; 32],
        shard_index: 0,
        shard_hash: hash_shard_leaf(0, &shard_bytes),
    };
    store.put_shard("owner-1", &shard_id, &shard_bytes).unwrap();

    let mut verifier = PorVerifierEngine::new(300);
    let session_key = [0xAB; 32];
    verifier.register_shard_session(&shard_id, session_key);

    // 1. Oversized PoR range (> 64 KiB MAX_POR_RANGE_BYTES) rejected in RAM before disk read
    let mut oversized_chal =
        generate_por_challenge(&session_key, shard_id, shard_bytes.len() as u64, 1_000_000);
    oversized_chal.offset = 0;
    oversized_chal.length = MAX_POR_RANGE_BYTES + 1;
    assert!(matches!(
        verifier.handle_incoming_challenge(&oversized_chal, 1_000_000, &store),
        Err(PorError::InvalidHmacToken)
    ));

    // 2. Valid challenge succeeds and increments seen_nonces_count
    let valid_chal =
        generate_por_challenge(&session_key, shard_id, shard_bytes.len() as u64, 1_000_000);
    let resp = verifier
        .handle_incoming_challenge(&valid_chal, 1_000_000, &store)
        .unwrap();
    assert_eq!(verifier.seen_nonces_count(), 1);

    // 3. Challenge-bound audit verification rejects mismatched nonce or shard_id
    let expected_slice =
        &shard_bytes[valid_chal.offset as usize..(valid_chal.offset + valid_chal.length) as usize];
    let expected_commit = compute_salted_commitment(&valid_chal.nonce, expected_slice);
    let outcome_ok = verifier.verify_challenge_audit_response(
        &valid_chal,
        &expected_commit,
        Some(&resp),
        50,
        ErasureTier::Homelab,
        20,
    );
    assert!(outcome_ok.passed);

    let mut wrong_nonce_resp: PorResponse = resp.clone();
    wrong_nonce_resp.nonce = [0xFF; 32];
    let outcome_bad = verifier.verify_challenge_audit_response(
        &valid_chal,
        &expected_commit,
        Some(&wrong_nonce_resp),
        50,
        ErasureTier::Homelab,
        20,
    );
    assert!(!outcome_bad.passed);

    // 4. WebOfTrustRegistry slashing nonce deduplication tracking
    let genesis = NodeIdentity::generate();
    let offender = NodeIdentity::generate();
    let reporter = NodeIdentity::generate();
    let mut wot = WebOfTrustRegistry::new(genesis.public_key_bytes(), 3);
    let hop = InvitationHop::issue(&genesis, offender.public_key_bytes(), 1, 1_700_000_000);
    wot.verify_and_admit_chain(&DelegationChain {
        hops: vec![hop.clone()],
    })
    .unwrap();
    let hop_rep = InvitationHop::issue(&genesis, reporter.public_key_bytes(), 1, 1_700_000_000);
    wot.verify_and_admit_chain(&DelegationChain {
        hops: vec![hop_rep],
    })
    .unwrap();

    let ev = SlashingEvidence::issue(
        &reporter,
        offender.public_key_bytes(),
        SlashingReason::PorAuditTimeoutOrTamper,
        42,
    );
    assert!(
        !wot.apply_slashing_evidence(&ev),
        "1st PoR timeout increments failure count to 1/3 (not yet quarantined)"
    );
    assert_eq!(wot.seen_slashing_nonces_count(), 1);
    // Replaying the exact same SlashingEvidence (nonce=42) 5 times must be ignored and never quarantine offender
    for _ in 0..5 {
        assert!(!wot.apply_slashing_evidence(&ev));
    }
    assert!(
        wot.is_peer_trusted(&offender.public_key_bytes()),
        "Replayed SlashingEvidence with duplicate nonce must not quarantine honest/single-fault peer"
    );
    assert_eq!(wot.seen_slashing_nonces_count(), 1);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_token_bucket_rate_limiter_free_disk_guard_and_pq_dht_catalog_store() {
    provision_ring_genesis();
    let base = unique_temp_dir("ratelimit-disk-dht");

    // 1. TokenBucketRateLimiter enforces burst & refill rate
    let mut limiter = TokenBucketRateLimiter::new(1_000_000, 500_000, 1_000); // 1 MB/s, 500 KB burst
    assert_eq!(limiter.available_tokens(1_000), 500_000);
    assert!(limiter.try_consume(400_000, 1_000));
    assert!(!limiter.try_consume(200_000, 1_000)); // only 100 KB left
    assert!(limiter.wait_time_ms(200_000, 1_000) >= 100);
    // Advance 500 ms -> +500 KB refilled (capped at 500 KB burst)
    assert!(limiter.try_consume(500_000, 1_500));

    // 2. QuotaManager minimum free disk reserve guard
    let mut quota = QuotaManager::new(10 * 1024 * 1024 * 1024, 100 * 1024 * 1024);
    quota.set_min_free_disk_bytes(1024 * 1024 * 1024); // 1 GiB minimum free reserve
    quota.update_observed_free_disk_bytes(1024 * 1024 * 1024 + 512 * 1024); // 1 GiB + 512 KiB free
    assert!(quota.can_accept_shard("peer-a", 256 * 1024));
    assert!(
        !quota.can_accept_shard("peer-a", 1024 * 1024),
        "Must reject shard write that would drop partition free space below min_free_disk_bytes"
    );

    // 3. ZeroTrustDhtStore PQ Manifest & Vault Catalog anti-rollback enforcement
    let mut dht = ZeroTrustDhtStore::new();
    let pq_mk = PqVaultMasterKey::generate();
    let pq_owner = HybridPqSigningKeypair::generate().unwrap();
    let pq_attacker = HybridPqSigningKeypair::generate().unwrap();
    let dht_key = [0x91; 32];

    let env_v1 =
        PqSignedDhtManifestEnvelope::seal_pq(&pq_mk, &pq_owner, dht_key, 1, &[1, 2, 3]).unwrap();
    let env_v1_replay =
        PqSignedDhtManifestEnvelope::seal_pq(&pq_mk, &pq_owner, dht_key, 1, &[4, 5, 6]).unwrap();
    let env_v2_spoof =
        PqSignedDhtManifestEnvelope::seal_pq(&pq_mk, &pq_attacker, dht_key, 2, &[9, 9]).unwrap();
    let env_v2_valid =
        PqSignedDhtManifestEnvelope::seal_pq(&pq_mk, &pq_owner, dht_key, 2, &[7, 8, 9]).unwrap();

    dht.put_pq_manifest_envelope(env_v1).unwrap();
    assert!(dht.put_pq_manifest_envelope(env_v1_replay).is_err());
    assert!(dht.put_pq_manifest_envelope(env_v2_spoof).is_err());
    dht.put_pq_manifest_envelope(env_v2_valid).unwrap();
    assert_eq!(
        dht.get_pq_manifest_envelope(&dht_key)
            .unwrap()
            .monotonic_version,
        2
    );

    // Vault Catalog Envelope in ZeroTrustDhtStore
    let seed_phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let store = BlockStore::new(
        &base,
        QuotaManager::new(100 * 1024 * 1024, 10 * 1024 * 1024),
    )
    .unwrap();
    let watched = base.join("vault");
    fs::create_dir_all(&watched).unwrap();
    fs::write(watched.join("secret.txt"), b"pq-catalog-secret").unwrap();

    let mk = MasterKey::from_recovery_seed_phrase(seed_phrase, "personal");
    let id = NodeIdentity::from_recovery_seed_phrase(seed_phrase, "personal");
    let mut sync_eng = FolderSyncEngine::new(store, mk, id, ErasureTier::Consumer);
    let snap = sync_eng.sync_folder_once(&watched).unwrap();
    let cat_v1 = sync_eng
        .export_encrypted_vault_catalog(seed_phrase, "personal", &snap)
        .unwrap();

    dht.put_vault_catalog_envelope(cat_v1.clone()).unwrap();
    assert!(dht.put_vault_catalog_envelope(cat_v1).is_err());

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_normalize_subnet_prefix_key_and_placement_ip_subnet_cap() {
    provision_ring_genesis();
    // 1. Subnet normalization collapses IPv6 /64s under the same /32 and IPv4s under /24
    let k1 = normalize_subnet_prefix_key("2001:db8:abcd:0001::1/64");
    let k2 = normalize_subnet_prefix_key("2001:db8:abcd:ffff::99/64");
    assert_eq!(k1, k2);

    // ElasticBootstrapEngine standby accrual collapses raw IPv6 /64 candidates in the same /32
    let cands = vec![
        ElasticPeerCandidate {
            peer_id: "v6-sybil-1".to_string(),
            role: parvault::bootstrap::PeerRole::OrganicCommunityPeer,
            subnet_prefix: "2001:db8:abcd:0001::1/64".to_string(),
            trust_level: TrustLevel::UntrustedProbationary,
            rtt_ms: 10,
            committed_standby_bytes: 20 * 1024 * 1024 * 1024,
        },
        ElasticPeerCandidate {
            peer_id: "v6-sybil-2".to_string(),
            role: parvault::bootstrap::PeerRole::OrganicCommunityPeer,
            subnet_prefix: "2001:db8:abcd:0002::1/64".to_string(),
            trust_level: TrustLevel::UntrustedProbationary,
            rtt_ms: 10,
            committed_standby_bytes: 20 * 1024 * 1024 * 1024,
        },
    ];
    let mut records = std::collections::BTreeMap::new();
    let mut heartbeats = std::collections::HashMap::new();
    heartbeats.insert("v6-sybil-1".to_string(), true);
    heartbeats.insert("v6-sybil-2".to_string(), true);
    let minted =
        ElasticBootstrapEngine::accrue_standby_uptime_epoch(&mut records, &cands, &heartbeats, 0.0);
    // Single node alone on /32 would earn 10% of 20 GiB = 2 GiB; two nodes on same /32 each earn 1 GiB (aggregate = 2 GiB)
    let total_v6_minted: u64 = minted.values().sum();
    assert_eq!(
        total_v6_minted,
        2 * 1024 * 1024 * 1024,
        "Aggregate standby credit across IPv6 /64s in the same /32 must be damped to 1.0x"
    );

    // 2. PlacementEngine::select_trust_weighted_peers enforces IP subnet concentration even if regions differ
    let peer_candidates = vec![
        PeerTopologyMetrics {
            peer_id: "sybil-a".to_string(),
            kad_id_hash: [0x01; 32],
            ip_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            asn: 64512,
            region: "spoofed-region-1".to_string(),
            rtt_ms: 3.0,
            available_bytes: 100 * 1024 * 1024,
            sla_score: 0.99,
        },
        PeerTopologyMetrics {
            peer_id: "sybil-b".to_string(),
            kad_id_hash: [0x02; 32],
            ip_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            asn: 64512,
            region: "spoofed-region-2".to_string(),
            rtt_ms: 3.0,
            available_bytes: 100 * 1024 * 1024,
            sla_score: 0.99,
        },
        PeerTopologyMetrics {
            peer_id: "sybil-c".to_string(),
            kad_id_hash: [0x03; 32],
            ip_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30)),
            asn: 64512,
            region: "spoofed-region-3".to_string(),
            rtt_ms: 3.0,
            available_bytes: 100 * 1024 * 1024,
            sla_score: 0.99,
        },
        PeerTopologyMetrics {
            peer_id: "honest-v6".to_string(),
            kad_id_hash: [0x04; 32],
            ip_addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x1111, 1, 0, 0, 0, 1)),
            asn: 64513,
            region: "eu-central".to_string(),
            rtt_ms: 25.0,
            available_bytes: 100 * 1024 * 1024,
            sla_score: 0.99,
        },
    ];
    let mut trust_map = std::collections::HashMap::new();
    for p in &peer_candidates {
        // UntrustedProbationary allows max 1 shard per subnet
        trust_map.insert(p.peer_id.clone(), TrustLevel::UntrustedProbationary);
    }

    let engine = PlacementEngine::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        64512,
        "us-east",
        5.0,
        0.70,
    );
    let plan =
        engine.select_trust_weighted_peers(&[0xAA; 32], 10, 20, 4096, &peer_candidates, &trust_map);
    assert_eq!(
        plan.selected_peers.len(),
        2,
        "Only 1 peer from 198.51.100.0/24 + 1 peer from 2001:db8:1111::/32 may be selected for UntrustedProbationary"
    );
}

#[test]
fn test_cli_end_to_end_parvault_and_parvault_seed_subcommands() {
    provision_ring_genesis();
    let base = unique_temp_dir("cli-e2e");
    let watched = base.join("watched");
    let single_restore_dir = base.join("single_restore");
    let fire_recovery_dir = base.join("fire_recovery");
    let seed_dir = base.join("seed_data");
    fs::create_dir_all(&watched).unwrap();

    fs::write(watched.join("readme.txt"), b"hello internet-grade parvault").unwrap();
    fs::write(watched.join("vault.txt"), b"secret vault note").unwrap();
    fs::write(watched.join(".parvaultignore"), b"*.ignoreme\n").unwrap();
    fs::write(watched.join("skip.ignoreme"), b"ignored-payload").unwrap();

    let parvault_bin = env!("CARGO_BIN_EXE_parvault");
    let seed_bin = env!("CARGO_BIN_EXE_parvault-seed");

    // 1. parvault identity
    let out_id = std::process::Command::new(parvault_bin)
        .current_dir(&base)
        .arg("identity")
        .output()
        .expect("run parvault identity");
    assert!(
        out_id.status.success(),
        "{}",
        String::from_utf8_lossy(&out_id.stderr)
    );
    let stdout_id = String::from_utf8_lossy(&out_id.stdout);
    assert!(stdout_id.contains("Device Peer ID"));
    assert!(stdout_id.contains("Owner PQ Public Key Hex"));

    // 2. parvault issue-device-cert & verify-device-cert
    let cert_path = base.join("laptop.device-cert.json");
    let out_issue = std::process::Command::new(parvault_bin)
        .current_dir(&base)
        .args([
            "issue-device-cert",
            "--device-peer-id",
            "parvault-peer-laptop01",
            "--device-label",
            "ThinkPad-X1",
            "--cert-out",
        ])
        .arg(&cert_path)
        .output()
        .expect("run parvault issue-device-cert");
    assert!(out_issue.status.success());
    assert!(String::from_utf8_lossy(&out_issue.stdout).contains("PARVAULT-CERT-V1:"));

    let out_verify = std::process::Command::new(parvault_bin)
        .current_dir(&base)
        .args(["verify-device-cert", "--cert"])
        .arg(&cert_path)
        .output()
        .expect("run parvault verify-device-cert");
    assert!(out_verify.status.success());

    // 3. parvault diff-folder
    let out_diff = std::process::Command::new(parvault_bin)
        .current_dir(&base)
        .args(["diff-folder", "--folder"])
        .arg(&watched)
        .output()
        .expect("run parvault diff-folder");
    assert!(out_diff.status.success());
    let stdout_diff = String::from_utf8_lossy(&out_diff.stdout);
    assert!(stdout_diff.contains("readme.txt"));
    assert!(stdout_diff.contains("skip.ignoreme"));

    // 4. parvault watch-folder --once --seed-phrase ... --catalog-out ...
    let snap_path = base.join("snap.manifest.bin");
    let catalog_path = base.join("catalog.envelope.bin");
    let phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let out_watch = std::process::Command::new(parvault_bin)
        .current_dir(&base)
        .args(["--no-lan-discovery", "watch-folder", "--folder"])
        .arg(&watched)
        .arg("--snapshot-out")
        .arg(&snap_path)
        .args([
            "--seed-phrase",
            phrase,
            "--vault-namespace",
            "homelab",
            "--catalog-out",
        ])
        .arg(&catalog_path)
        // No peers: the stripes stay on this machine (R3-1); this test checks the catalog path.
        .args(["--once", "--allow-local-only"])
        .output()
        .expect("run parvault watch-folder");
    assert!(
        out_watch.status.success(),
        "{}",
        String::from_utf8_lossy(&out_watch.stderr)
    );
    assert!(snap_path.exists());
    assert!(catalog_path.exists());

    // 5. parvault restore-folder --file readme.txt (selective single-file restore)
    let seed_mk = MasterKey::from_recovery_seed_phrase(phrase, "homelab");
    let out_restore_single = std::process::Command::new(parvault_bin)
        .current_dir(&base)
        .args(["--no-lan-discovery", "restore-folder", "--snapshot"])
        .arg(&snap_path)
        .arg("--out-dir")
        .arg(&single_restore_dir)
        .args(["--file", "readme.txt", "--key-hex", &seed_mk.to_hex()])
        .output()
        .expect("run parvault restore-folder --file");
    assert!(
        out_restore_single.status.success(),
        "{}",
        String::from_utf8_lossy(&out_restore_single.stderr)
    );
    assert_eq!(
        fs::read(single_restore_dir.join("readme.txt")).unwrap(),
        b"hello internet-grade parvault"
    );
    assert!(!single_restore_dir.join("vault.txt").exists());

    // 6. parvault recover-from-seed (zero-local-state "House Fire" disaster recovery)
    let out_recover = std::process::Command::new(parvault_bin)
        .current_dir(&base)
        .args([
            "--no-lan-discovery",
            "recover-from-seed",
            "--seed-phrase",
            phrase,
            "--vault-namespace",
            "homelab",
            "--catalog-envelope",
        ])
        .arg(&catalog_path)
        .arg("--out-dir")
        .arg(&fire_recovery_dir)
        .output()
        .expect("run parvault recover-from-seed");
    assert!(
        out_recover.status.success(),
        "{}",
        String::from_utf8_lossy(&out_recover.stderr)
    );
    assert_eq!(
        fs::read(fire_recovery_dir.join("readme.txt")).unwrap(),
        b"hello internet-grade parvault"
    );
    assert_eq!(
        fs::read(fire_recovery_dir.join("vault.txt")).unwrap(),
        b"secret vault note"
    );

    // 7. parvault scrub, status & zero-flag `leave`
    let out_scrub = std::process::Command::new(parvault_bin)
        .current_dir(&base)
        .arg("scrub")
        .output()
        .expect("run parvault scrub");
    assert!(out_scrub.status.success());

    let out_status = std::process::Command::new(parvault_bin)
        .current_dir(&base)
        .args(["--no-lan-discovery", "status"])
        .output()
        .expect("run parvault status");
    assert!(out_status.status.success());
    assert!(String::from_utf8_lossy(&out_status.stdout).contains("SoloPersonalVault"));

    let out_leave = std::process::Command::new(parvault_bin)
        .current_dir(&base)
        .args(["--no-lan-discovery", "leave"])
        .output()
        .expect("run parvault leave");
    assert!(out_leave.status.success());
    assert!(String::from_utf8_lossy(&out_leave.stdout)
        .contains("Earned Standing Preserved: true (zero PoR slashing penalty)"));

    // 8. parvault-seed identity, status, drain-plan, scrub, leave
    for subcmd in ["identity", "status", "drain-plan", "scrub", "leave"] {
        let out_seed = std::process::Command::new(seed_bin)
            .current_dir(&base)
            .arg(subcmd)
            .arg("--data-dir")
            .arg(&seed_dir)
            .output()
            .expect("run parvault-seed subcmd");
        assert!(
            out_seed.status.success(),
            "parvault-seed {} failed: {}",
            subcmd,
            String::from_utf8_lossy(&out_seed.stderr)
        );
    }

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_persistent_por_repair_grants_dht_store_and_libp2p_keypair_across_restarts() {
    provision_ring_genesis();
    use parvault::{
        config::ErasureTier,
        crypto::{pqc::PqVaultMasterKey, LocalFileKeystore, LocalKeystoreSealer, NodeIdentity},
        por::{PorVerifierEngine, RepairGrant},
        sharding::merkle::hash_shard_leaf,
        storage::{BlockStore, QuotaManager, ShardId, ZeroTrustDhtStore},
    };

    let base = unique_temp_dir("persist-por-dht-keypair");

    // 1. NodeIdentity::load_or_generate_in_dir produces identical libp2p PeerId across restarts
    let id1 = NodeIdentity::load_or_generate_in_dir(&base).unwrap();
    let kp1 = id1.to_libp2p_keypair().unwrap();
    let id2 = NodeIdentity::load_or_generate_in_dir(&base).unwrap();
    let kp2 = id2.to_libp2p_keypair().unwrap();
    assert_eq!(kp1.public().to_peer_id(), kp2.public().to_peer_id());

    // 2. LocalFileKeystore seals/unseals consistently from persisted CSPRNG/passphrase key
    let ks1 =
        LocalFileKeystore::from_passphrase_or_csprng_in_dir(&base, Some("vault-pass")).unwrap();
    let ks2 =
        LocalFileKeystore::from_passphrase_or_csprng_in_dir(&base, Some("vault-pass")).unwrap();
    let sealed = ks1.seal_key(&[0xAB; 32]).unwrap();
    let unsealed = ks2.unseal_key(&sealed).unwrap();
    assert_eq!(unsealed, [0xAB; 32]);

    // 3. PorVerifierEngine persists repair_grants and session_keys across restarts
    let owner = NodeIdentity::generate();
    let w1 = NodeIdentity::generate();
    let w2 = NodeIdentity::generate();
    let shard_bytes = b"persisted-owner-shard-read-verification-payload";
    let shard_id = ShardId {
        stripe_merkle_root: [0x33; 32],
        shard_index: 4,
        shard_hash: hash_shard_leaf(4, shard_bytes),
    };
    let store =
        BlockStore::new(&base, QuotaManager::new(10 * 1024 * 1024, 10 * 1024 * 1024)).unwrap();
    store
        .put_shard(&owner.device_peer_id(), &shard_id, shard_bytes)
        .unwrap();

    let grant = RepairGrant::issue(
        &owner,
        shard_id.stripe_merkle_root,
        vec![w1.public_key_bytes(), w2.public_key_bytes()],
        ErasureTier::Consumer,
    );
    {
        let mut por1 = PorVerifierEngine::with_persistence_dir(400, &base);
        // v0.5.0 (F-26): a grant authorises the shards stored with it.
        assert!(por1
            .register_repair_grant_for_stored(grant, &[shard_id])
            .is_ok());
        por1.register_shard_session(&shard_id, [0x77; 32]);
    }
    {
        let por2 = PorVerifierEngine::with_persistence_dir(400, &base);
        let (owner_pub, payload, sig) =
            PorVerifierEngine::sign_owner_shard_read_token(&owner, &shard_id, 1_700_000_000);
        let read_back = por2
            .authorize_raw_shard_read(&shard_id, Some(&(owner_pub, &payload, &sig)), None, &store)
            .expect("owner read token must verify after PorVerifierEngine reload from disk");
        assert_eq!(read_back, shard_bytes);
    }

    // 4. PqVaultMasterKey 64-byte Argon2id root & ChaCha20Poly1305 + Aes256Gcm cascaded AEAD
    let pq_key = PqVaultMasterKey::from_recovery_seed_phrase("correct horse battery staple", "ns");
    let ct = pq_key
        .encrypt_stripe_pq(&[0x55; 32], 7, b"post-quantum-cascaded-stripe")
        .unwrap();
    let pt = pq_key.decrypt_stripe_pq(&[0x55; 32], 7, &ct).unwrap();
    assert_eq!(pt, b"post-quantum-cascaded-stripe");

    let dht_dir = base.join("dht");
    fs::create_dir_all(&dht_dir).unwrap();
    let _dht = ZeroTrustDhtStore::with_persistence_dir(&dht_dir);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_live_libp2p_tcp_multi_daemon_network_backup_prune_and_seed_recovery() {
    provision_ring_genesis();
    struct ChildGuard(Vec<std::process::Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn reserve_free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener.local_addr().unwrap().port()
    }

    let base = unique_temp_dir("live-libp2p-multi-daemon");
    let parvault_bin = env!("CARGO_BIN_EXE_parvault");
    let seed_bin = env!("CARGO_BIN_EXE_parvault-seed");

    let seed_port = reserve_free_port();
    let node_ports = [
        reserve_free_port(),
        reserve_free_port(),
        reserve_free_port(),
        reserve_free_port(),
    ];
    let peers_csv = node_ports
        .iter()
        .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
        .collect::<Vec<_>>()
        .join(",");
    let seed_multiaddr = format!("/ip4/127.0.0.1/tcp/{seed_port}");

    let mut guards = ChildGuard(Vec::new());

    // 1. Spawn parvault-seed + 4 parvault daemon processes on isolated data directories
    let seed_dir = base.join("seed_node");
    fs::create_dir_all(&seed_dir).unwrap();
    let seed_child = std::process::Command::new(seed_bin)
        .args([
            "--peers",
            &peers_csv,
            "start",
            "--mode",
            "homelab-vault",
            "--no-lan-discovery",
            "--listen",
            &seed_multiaddr,
            "--data-dir",
        ])
        .arg(&seed_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn parvault-seed");
    guards.0.push(seed_child);

    let mut node_dirs = Vec::new();
    for (idx, port) in node_ports.iter().enumerate() {
        let ndir = base.join(format!("daemon_{idx}"));
        fs::create_dir_all(&ndir).unwrap();
        node_dirs.push(ndir.clone());
        let child = std::process::Command::new(parvault_bin)
            .arg("--data-dir")
            .arg(&ndir)
            .args([
                "--no-lan-discovery",
                "--peers",
                &peers_csv,
                "--seed-addr",
                &seed_multiaddr,
                "daemon",
                "start",
                "--listen",
                &format!("/ip4/127.0.0.1/tcp/{port}"),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn parvault daemon");
        guards.0.push(child);
    }

    // Wait until all TCP listeners accept connections
    for port in std::iter::once(seed_port).chain(node_ports.iter().copied()) {
        let mut connected = false;
        for _ in 0..50 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(connected, "Daemon on port {port} did not start listening");
    }

    // 2. From an isolated client directory, run watch-folder --once over libp2p
    let client_dir = base.join("client_data");
    let source_dir = base.join("source_vault");
    let snap_path = base.join("client_snap.manifest.bin");
    fs::create_dir_all(&client_dir).unwrap();
    fs::create_dir_all(source_dir.join("docs")).unwrap();
    fs::write(
        source_dir.join("docs/architecture.txt"),
        b"Real libp2p TCP + Noise XX + Yamux P2P backup payload",
    )
    .unwrap();
    fs::write(
        source_dir.join("ephemeral.txt"),
        b"Temporary file that will be deleted and pruned across remote peers",
    )
    .unwrap();

    let seed_phrase =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let out_sync1 = std::process::Command::new(parvault_bin)
        .arg("--data-dir")
        .arg(&client_dir)
        .args([
            "--peers",
            &peers_csv,
            "--seed-addr",
            &seed_multiaddr,
            "watch-folder",
            "--folder",
        ])
        .arg(&source_dir)
        .arg("--snapshot-out")
        .arg(&snap_path)
        .args([
            "--tier",
            "homelab",
            "--seed-phrase",
            seed_phrase,
            "--vault-namespace",
            "live-tcp-test",
            "--once",
        ])
        .output()
        .expect("run watch-folder v1");
    assert!(
        out_sync1.status.success(),
        "watch-folder v1 failed: {}",
        String::from_utf8_lossy(&out_sync1.stderr)
    );

    // Count remote .shard files across the 4 storage daemons after v1
    let count_remote_shards = |dirs: &[std::path::PathBuf]| -> usize {
        dirs.iter()
            .map(|d| {
                fs::read_dir(d.join("shards"))
                    .ok()
                    .map(|rd| {
                        rd.filter_map(Result::ok)
                            .filter(|e| {
                                e.path().extension().and_then(|s| s.to_str()) == Some("shard")
                            })
                            .count()
                    })
                    .unwrap_or(0)
            })
            .sum()
    };
    let remote_shards_v1 = count_remote_shards(&node_dirs);
    assert!(
        remote_shards_v1 >= 40,
        "Expected remote daemons to hold >= 40 shards for 2 files, found {remote_shards_v1}"
    );

    // 3. Delete ephemeral.txt and run watch-folder --once --prune-deleted
    fs::remove_file(source_dir.join("ephemeral.txt")).unwrap();
    let out_sync2 = std::process::Command::new(parvault_bin)
        .arg("--data-dir")
        .arg(&client_dir)
        .args([
            "--peers",
            &peers_csv,
            "--seed-addr",
            &seed_multiaddr,
            "watch-folder",
            "--folder",
        ])
        .arg(&source_dir)
        .arg("--snapshot-out")
        .arg(&snap_path)
        .args([
            "--tier",
            "homelab",
            "--seed-phrase",
            seed_phrase,
            "--vault-namespace",
            "live-tcp-test",
            "--prune-deleted",
            "--once",
        ])
        .output()
        .expect("run watch-folder v2 with prune-deleted");
    assert!(
        out_sync2.status.success(),
        "watch-folder v2 failed: {}",
        String::from_utf8_lossy(&out_sync2.stderr)
    );
    let remote_shards_v2 = count_remote_shards(&node_dirs);
    assert!(
        remote_shards_v2 < remote_shards_v1,
        "Remote shard count must decrease after --prune-deleted (before={remote_shards_v1}, after={remote_shards_v2})"
    );

    // 4. Kill 1 storage daemon (leaving 3 of 4 alive) and recover from seed phrase alone into a clean directory
    let _ = guards.0[1].kill();
    let _ = guards.0[1].wait();

    let fresh_client_dir = base.join("fresh_client_after_fire");
    let recovered_dir = base.join("recovered_vault");
    fs::create_dir_all(&fresh_client_dir).unwrap();

    let out_recover = std::process::Command::new(parvault_bin)
        .arg("--data-dir")
        .arg(&fresh_client_dir)
        .args([
            "--peers",
            &peers_csv,
            "--seed-addr",
            &seed_multiaddr,
            "recover-from-seed",
            "--seed-phrase",
            seed_phrase,
            "--vault-namespace",
            "live-tcp-test",
            "--out-dir",
        ])
        .arg(&recovered_dir)
        .output()
        .expect("run recover-from-seed over libp2p");
    assert!(
        out_recover.status.success(),
        "recover-from-seed failed: {}",
        String::from_utf8_lossy(&out_recover.stderr)
    );
    assert_eq!(
        fs::read(recovered_dir.join("docs/architecture.txt")).unwrap(),
        b"Real libp2p TCP + Noise XX + Yamux P2P backup payload"
    );
    assert!(!recovered_dir.join("ephemeral.txt").exists());

    drop(guards);
    let _ = fs::remove_dir_all(&base);
}
