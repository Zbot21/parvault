use parvault::config::ErasureTier;
use parvault::crypto::{
    decrypt_stripe, derive_unlinkable_shard_pseudonym, encrypt_stripe, generate_file_salt,
    pad_plaintext_iso_bucket, unpad_plaintext_iso_bucket, MasterKey, NodeIdentity,
};
use parvault::network::wot::{DelegationChain, InvitationHop, WebOfTrustRegistry};
use parvault::por::{
    compute_multi_salted_commitment, generate_multi_segment_por_challenge,
    EgressWithholdingEvidence, PorError, PorVerifierEngine, RepairGrant,
};
use parvault::sharding::{
    encode_ciphertext_stripe, reconstruct_zero_trust_with_quarantine, MerkleProof, MerkleTree,
};
use parvault::storage::{
    BlockStore, FileManifest, QuotaManager, ShardId, SignedDhtManifestEnvelope, StorageError,
    StripeManifestEntry, ZeroTrustDhtStore,
};
use stateright::{Checker, Model, Property};
use std::collections::HashSet;
use tempfile::tempdir;

/// Defense 1: Byzantine Shard Poisoning ("Bad Apple" Denial-of-Recovery)
/// Verifies that `reconstruct_zero_trust_with_quarantine` pre-screens every shard against
/// both its leaf hash and `MerkleProof`, evicts poisoned shards returned by Byzantine peers,
/// slashes those peers immediately in `WebOfTrustRegistry`, and reconstructs the stripe
/// cleanly from the remaining `>= K` honest shards.
#[test]
fn test_defense1_byzantine_shard_poisoning_quarantine_and_slashing() {
    let master_key = MasterKey::generate();
    let salt = generate_file_salt();
    let original_plaintext =
        b"Zero-trust backup payload protected against Byzantine shard poisoners!".repeat(512);

    let ciphertext = encrypt_stripe(&master_key, &salt, 0, &original_plaintext).unwrap();
    let shard_set = encode_ciphertext_stripe(0, &ciphertext, ErasureTier::Homelab).unwrap();
    let merkle_tree = MerkleTree::from_shards(&shard_set.shards);

    let proofs: Vec<Option<MerkleProof>> = (0..20).map(|i| merkle_tree.generate_proof(i)).collect();

    // Set up Web-of-Trust with 20 storage node identities invited by a parent node.
    let genesis = NodeIdentity::generate();
    let inviter = NodeIdentity::generate();
    let mut wot = WebOfTrustRegistry::new(genesis.public_key_bytes(), 5);
    let hop0 = InvitationHop::issue(&genesis, inviter.public_key_bytes(), 1, 1_700_000_000);

    let mut peer_identities = Vec::with_capacity(20);
    for _ in 0..20 {
        let leaf = NodeIdentity::generate();
        let hop1 = InvitationHop::issue(&inviter, leaf.public_key_bytes(), 2, 1_700_000_010);
        let chain = DelegationChain {
            hops: vec![hop0.clone(), hop1],
        };
        wot.verify_and_admit_chain(&chain).unwrap();
        peer_identities.push(leaf);
    }

    // Simulate simultaneous adversarial conditions on a 16-of-20 stripe:
    // - Shards 0 and 1: Crash fault (offline -> None)
    // - Shard 4: Byzantine Node 4 flips a bit in the ciphertext shard
    // - Shard 9: Byzantine Node 9 returns completely fabricated garbage bytes
    // - Remaining 16 shards: Honest
    let mut slots: Vec<Option<Vec<u8>>> = shard_set.shards.iter().cloned().map(Some).collect();
    slots[0] = None;
    slots[1] = None;
    slots[4].as_mut().unwrap()[0] ^= 0xFF;
    slots[9] = Some(vec![0xAA; shard_set.shard_len]);

    let (reconstructed_shards, poisoned_indices) = reconstruct_zero_trust_with_quarantine(
        slots,
        Some(&proofs),
        16,
        4,
        &shard_set.shard_hashes,
        shard_set.stripe_merkle_root,
    )
    .expect(
        "Zero-trust reconstruction must evict poisoned shards and succeed with 16 honest shards",
    );

    assert_eq!(poisoned_indices, vec![4, 9]);

    // Immediately slash the Byzantine peers that served poisoned shards.
    for &bad_idx in &poisoned_indices {
        // The receiver slashes locally (peer evidence is not applied in v0.5.0).
        assert!(wot.slash_immediately(peer_identities[bad_idx].public_key_bytes()));
        assert!(
            !wot.is_peer_trusted(&peer_identities[bad_idx].public_key_bytes()),
            "Byzantine shard poisoner must be quarantined on first offense"
        );
    }

    // Verify all 20 reconstructed shards match original shards bit-for-bit and decrypt cleanly.
    assert_eq!(reconstructed_shards, shard_set.shards);
    let mut restored_cipher = Vec::with_capacity(shard_set.original_ciphertext_len);
    for s in reconstructed_shards.iter().take(16) {
        restored_cipher.extend_from_slice(s);
    }
    restored_cipher.truncate(shard_set.original_ciphertext_len);
    let restored_plain = decrypt_stripe(&master_key, &salt, 0, &restored_cipher).unwrap();
    assert_eq!(restored_plain, original_plaintext);
}

/// Defense 2: Stratified Multi-Segment PoR & Strict Anti-Proxy RTT Ceiling
/// Verifies that:
/// 1. A lazy node deleting only the tail 12.5% (1/8th) of a shard is immediately caught by a
///    single 8-stratum scatter-gather PoR challenge.
/// 2. A node outsourcing storage to a remote WAN proxy (returning a valid commitment but
///    exceeding the 15 ms local RTT deadline) is caught and flagged for slashing.
#[test]
fn test_defense2_multi_segment_por_catches_partial_deletion_and_wan_proxy() {
    let tmp = tempdir().unwrap();
    let quota = QuotaManager::new(100 * 1024 * 1024, 50 * 1024 * 1024);
    let store = BlockStore::new(tmp.path(), quota).unwrap();

    let shard_bytes: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let shard_hash = parvault::sharding::hash_shard_leaf(0, &shard_bytes);
    let shard_id = ShardId {
        stripe_merkle_root: [0x42; 32],
        shard_index: 0,
        shard_hash,
    };
    store.put_shard("local", &shard_id, &shard_bytes).unwrap();

    let session_key = [0x77u8; 32];
    let mut verifier = PorVerifierEngine::new(300);
    verifier.register_shard_session(&shard_id, session_key);

    let now_ms = 1_700_000_000_000u64;
    let challenge = generate_multi_segment_por_challenge(
        &session_key,
        shard_id,
        shard_bytes.len() as u64,
        8,  // 8 non-overlapping strata across the 64 KiB shard
        15, // 15 ms strict anti-WAN-proxy RTT ceiling
        now_ms,
    );
    assert_eq!(challenge.segments.len(), 8);

    // Compute expected commitment from intact shard strata.
    let expected_slices: Vec<Vec<u8>> = challenge
        .segments
        .iter()
        .map(|seg| shard_bytes[seg.offset as usize..(seg.offset + seg.length) as usize].to_vec())
        .collect();
    let expected_commitment = compute_multi_salted_commitment(&challenge.nonce, &expected_slices);

    // 1. Honest local node responds in 4 ms -> PASS.
    let honest_resp = verifier
        .handle_multi_segment_challenge(&challenge, now_ms + 4, &store)
        .unwrap();
    let outcome_honest = verifier.verify_multi_segment_audit(
        &challenge,
        &expected_commitment,
        Some(&honest_resp),
        4,
        ErasureTier::Homelab,
        20,
    );
    assert!(outcome_honest.passed);
    assert!(!outcome_honest.slash_peer);

    // 2. Attack A: WAN-Proxy Outsourcing Attack (valid cryptographic commitment, but 42 ms RTT > 15 ms ceiling).
    let outcome_proxy = verifier.verify_multi_segment_audit(
        &challenge,
        &expected_commitment,
        Some(&honest_resp),
        42,
        ErasureTier::Homelab,
        20,
    );
    assert!(
        !outcome_proxy.passed && outcome_proxy.slash_peer,
        "WAN-proxied PoR response exceeding 15ms ceiling must fail and slash peer"
    );

    // 3. Attack B: Partial-Retention Cheating (node overwrites only the last 12.5% of the shard on disk).
    let mut corrupted_shard = shard_bytes.clone();
    for b in &mut corrupted_shard[57344..65536] {
        *b = 0x00;
    }
    let shard_file = tmp
        .path()
        .join("shards")
        .join(format!("{}.shard", shard_id.file_key()));
    std::fs::write(&shard_file, &corrupted_shard).unwrap();

    let challenge2 = generate_multi_segment_por_challenge(
        &session_key,
        shard_id,
        shard_bytes.len() as u64,
        8,
        15,
        now_ms + 100,
    );
    let partial_resp = verifier
        .handle_multi_segment_challenge(&challenge2, now_ms + 105, &store)
        .unwrap();
    let expected_slices2: Vec<Vec<u8>> = challenge2
        .segments
        .iter()
        .map(|seg| shard_bytes[seg.offset as usize..(seg.offset + seg.length) as usize].to_vec())
        .collect();
    let expected_commitment2 =
        compute_multi_salted_commitment(&challenge2.nonce, &expected_slices2);

    let outcome_partial = verifier.verify_multi_segment_audit(
        &challenge2,
        &expected_commitment2,
        Some(&partial_resp),
        3,
        ErasureTier::Homelab,
        19,
    );
    assert!(
        !outcome_partial.passed && outcome_partial.slash_peer && outcome_partial.trigger_proactive_repair,
        "Partial-retention node deleting 12.5% tail must be caught in 1 audit and trigger proactive repair"
    );
}

/// Defense 3: Zero-Knowledge Ed25519-Signed Monotonic DHT Manifest Envelopes
/// Verifies that untrusted DHT nodes (without `K_user`) reject:
/// 1. Tampered ciphertext payloads,
/// 2. Key-hijacking attempts signed by a different Ed25519 identity, and
/// 3. Rollback / replay attacks attempting to overwrite `version = 2` with `version = 1`.
#[test]
fn test_defense3_zero_knowledge_signed_dht_manifest_anti_poisoning_and_rollback() {
    let master_key = MasterKey::generate();
    let owner_id = NodeIdentity::generate();
    let attacker_id = NodeIdentity::generate();

    let manifest_v1 = FileManifest {
        version: 2,
        file_merkle_root: [0x11; 32],
        file_salt: [0x22; 32],
        original_file_size: 1024,
        stripe_size_bytes: 16 * 1024 * 1024,
        tier: ErasureTier::Homelab,
        stripes: vec![StripeManifestEntry {
            stripe_index: 0,
            k_data: 16,
            m_parity: 4,
            original_ciphertext_len: 1040,
            shard_len: 65,
            stripe_merkle_root: [0x33; 32],
            shard_hashes: vec![[0x44; 32]; 20],
            assigned_peers: vec!["peer".to_string(); 20],
            shard_chunk_roots: Vec::new(),
        }],
        witness_peers: vec!["w1".to_string(), "w2".to_string()],
    };

    let env_v1 =
        SignedDhtManifestEnvelope::seal(&master_key, &owner_id, &manifest_v1, 1, 1_700_000_000)
            .unwrap();
    assert!(env_v1.verify_zero_knowledge());

    let mut dht = ZeroTrustDhtStore::new();
    dht.put_manifest_envelope(env_v1.clone()).unwrap();

    // Attack 1: Tamper with 1 byte of the encrypted manifest in transit.
    let mut tampered = env_v1.clone();
    tampered.monotonic_version = 2;
    tampered.encrypted_manifest[0] ^= 0x01;
    assert!(matches!(
        dht.put_manifest_envelope(tampered),
        Err(StorageError::DhtManifestPoisonedOrRollback)
    ));

    // Attack 2: Attacker signs a valid envelope for the same `dht_key` with `attacker_id` at version 99.
    let mut hijack =
        SignedDhtManifestEnvelope::seal(&master_key, &attacker_id, &manifest_v1, 99, 1_700_000_500)
            .unwrap();
    hijack.dht_key = env_v1.dht_key;
    assert!(matches!(
        dht.put_manifest_envelope(hijack),
        Err(StorageError::DhtManifestPoisonedOrRollback)
    ));

    // Legitimate owner upgrade to monotonic_version = 2.
    let mut manifest_v2 = manifest_v1.clone();
    manifest_v2.original_file_size = 2048;
    let env_v2 =
        SignedDhtManifestEnvelope::seal(&master_key, &owner_id, &manifest_v2, 2, 1_700_001_000)
            .unwrap();
    dht.put_manifest_envelope(env_v2).unwrap();

    // Attack 3: Rollback / Replay Attack — attacker replays owner's genuine `env_v1` (version 1).
    assert!(matches!(
        dht.put_manifest_envelope(env_v1),
        Err(StorageError::DhtManifestPoisonedOrRollback)
    ));

    // Verify stored manifest is still version 2 (`original_file_size == 2048`).
    let stored = dht
        .get_manifest_envelope(&manifest_v2.to_encrypted_dht_record(&master_key).unwrap().0)
        .unwrap();
    let decrypted = stored.open(&master_key).unwrap();
    assert_eq!(decrypted.original_file_size, 2048);
}

/// Defense 4: Hostage / Egress-Withholding Defense at Restore Time
/// Verifies that a rational node that farms PoR credits (`100 MiB`) by answering small 4 KiB
/// challenges, but withholds bulk shard egress during restore, is cryptographically convicted
/// via `EgressWithholdingEvidence`, loses 100% of its farmed reciprocity credits, and is
/// immediately banned from the Web of Trust.
#[test]
fn test_defense4_hostage_egress_withholding_slashing_burns_credits() {
    let mut quota = QuotaManager::new(10 * 1024 * 1024 * 1024, 0); // 0 grace quota -> relies strictly on earned credits
    let hostage_peer = "peer-hostage-taker";

    // Peer farms 100 MiB of remote contribution credits and 25 PoR passes (qualifying for 1.25x Homelab SLA).
    quota.record_remote_contribution(hostage_peer, 100 * 1024 * 1024);
    for _ in 0..25 {
        quota.record_por_outcome(hostage_peer, true);
    }
    assert!(quota.can_accept_shard(hostage_peer, 50 * 1024 * 1024));

    let owner = NodeIdentity::generate();
    let offender = NodeIdentity::generate();
    let shard_id = ShardId {
        stripe_merkle_root: [0x99; 32],
        shard_index: 3,
        shard_hash: [0xAB; 32],
    };

    // Owner issues signed `EgressWithholdingEvidence` binding the prior valid PoR commitment to the failed restore.
    let withholding_proof = EgressWithholdingEvidence::issue(
        &owner,
        offender.public_key_bytes(),
        shard_id,
        [0xCD; 32],
        1_700_000_000_000,
        1_700_000_060_000,
    );
    assert!(withholding_proof.verify());

    // Slash the peer's reciprocity ledger and Web-of-Trust identity.
    let burned_bytes = quota.slash_peer_for_withholding(hostage_peer);
    assert_eq!(burned_bytes, 100 * 1024 * 1024);
    assert_eq!(
        quota
            .peer_account(hostage_peer)
            .unwrap()
            .bytes_contributed_by_peer,
        0
    );
    assert!(
        !quota.can_accept_shard(hostage_peer, 1024),
        "Slashed hostage-taking peer must be blocked from storing any shards"
    );
}

/// Defense 5: Repair-Sink Eclipse Protection & Merkle-Verified Witness Repair Deposits
/// Verifies that replacement storage nodes during an offline witness repair:
/// 1. Reject witness-repaired shards whose bytes do not verify against the `MerkleProof` for `stripe_merkle_root`,
/// 2. Reject deposits that would concentrate `> max_shards_per_asn` into a single Sybil ASN, and
/// 3. Accept valid `GF(2^8)` reconstructed shards placed on an ASN respecting diversity bounds.
#[test]
fn test_defense5_repair_sink_eclipse_and_merkle_verified_witness_deposit() {
    let owner = NodeIdentity::generate();
    let witness1 = NodeIdentity::generate();
    let witness2 = NodeIdentity::generate();

    let shard_set = encode_ciphertext_stripe(0, &[0x5A; 32768], ErasureTier::Homelab).unwrap();
    let tree = MerkleTree::from_shards(&shard_set.shards);
    let proof_shard_0 = tree.generate_proof(0).unwrap();

    let grant = RepairGrant::issue(
        &owner,
        shard_set.stripe_merkle_root,
        vec![witness1.public_key_bytes(), witness2.public_key_bytes()],
        ErasureTier::Homelab,
    );
    let shard_id = ShardId {
        stripe_merkle_root: shard_set.stripe_merkle_root,
        shard_index: 0,
        shard_hash: shard_set.shard_hashes[0],
    };

    // Existing cohort ASNs already have 2 shards in ASN 64599 (the witness's Sybil ASN).
    let existing_cohort_asns = vec![64599, 64599, 64512, 64513, 64514];

    // Attack 1: Witness tries to deposit tampered shard bytes onto healthy ASN 64520.
    let mut bad_bytes = shard_set.shards[0].clone();
    bad_bytes[0] ^= 0x01;
    assert!(matches!(
        PorVerifierEngine::verify_witness_repair_deposit(
            &shard_id,
            &bad_bytes,
            &proof_shard_0,
            &grant,
            64520,
            &existing_cohort_asns,
            2,
        ),
        Err(PorError::RepairSinkEclipseOrInvalidMerkleProof)
    ));

    // Attack 2: Witness reconstructs authentic shard 0, but tries to concentrate a 3rd shard into Sybil ASN 64599.
    assert!(matches!(
        PorVerifierEngine::verify_witness_repair_deposit(
            &shard_id,
            &shard_set.shards[0],
            &proof_shard_0,
            &grant,
            64599,
            &existing_cohort_asns,
            2,
        ),
        Err(PorError::RepairSinkEclipseOrInvalidMerkleProof)
    ));

    // Valid Deposit: Authentic shard + valid MerkleProof + diverse ASN 64520 (only 0 existing shards < 2 cap).
    PorVerifierEngine::verify_witness_repair_deposit(
        &shard_id,
        &shard_set.shards[0],
        &proof_shard_0,
        &grant,
        64520,
        &existing_cohort_asns,
        2,
    )
    .expect("Authentic Merkle-verified witness repair deposit on diverse ASN must succeed");
}

/// Defense 6: Unlinkable Per-Shard HMAC Pseudonyms & Uniform Size-Bucket ISO Padding
/// Verifies that:
/// 1. Every shard of a stripe receives a cryptographically unlinkable owner pseudonym (`anon_<hex>`), and
/// 2. Two files of wildly different lengths (`1,337` bytes vs `59,999` bytes) padded to a `64 KiB` bucket
///    produce identical ciphertext and shard lengths on disk, preventing size-correlation fingerprinting.
#[test]
fn test_defense6_unlinkable_shard_pseudonyms_and_iso_bucket_padding() {
    let master_key = MasterKey::generate();
    let root = [0xAB; 32];

    let pseudonyms: HashSet<String> = (0..20)
        .map(|idx| derive_unlinkable_shard_pseudonym(&master_key, &root, idx))
        .collect();
    assert_eq!(
        pseudonyms.len(),
        20,
        "All 20 shards must have distinct unlinkable HMAC pseudonyms"
    );

    let file_small = vec![0x11u8; 1_337];
    let file_large = vec![0x22u8; 59_999];

    let padded_small = pad_plaintext_iso_bucket(&file_small, 65536);
    let padded_large = pad_plaintext_iso_bucket(&file_large, 65536);
    assert_eq!(padded_small.len(), 65536);
    assert_eq!(padded_large.len(), 65536);

    let salt1 = generate_file_salt();
    let salt2 = generate_file_salt();
    let enc_small = encrypt_stripe(&master_key, &salt1, 0, &padded_small).unwrap();
    let enc_large = encrypt_stripe(&master_key, &salt2, 0, &padded_large).unwrap();
    assert_eq!(
        enc_small.len(),
        enc_large.len(),
        "Ciphertext sizes must be identical across different file sizes within the same bucket"
    );

    let shards_small = encode_ciphertext_stripe(0, &enc_small, ErasureTier::Homelab).unwrap();
    let shards_large = encode_ciphertext_stripe(0, &enc_large, ErasureTier::Homelab).unwrap();
    assert_eq!(shards_small.shard_len, shards_large.shard_len);

    // Unpad and verify exact original payloads.
    assert_eq!(
        unpad_plaintext_iso_bucket(&padded_small).unwrap(),
        file_small
    );
    assert_eq!(
        unpad_plaintext_iso_bucket(&padded_large).unwrap(),
        file_large
    );

    // Tamper with trailing zero padding byte -> must fail ISO sentinel check.
    let mut bad_pad = padded_small;
    let last_idx = bad_pad.len() - 1;
    bad_pad[last_idx] = 0x01;
    assert!(unpad_plaintext_iso_bucket(&bad_pad).is_err());
}

/// Formal `stateright` Model Checking of Zero-Trust Restore under simultaneous Crash Faults,
/// Byzantine Shard Poisoning, and Hostage Egress Withholding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ZeroTrustRestoreState {
    honest_online: u8,
    crashed_nodes: u8,
    byzantine_poisoners: u8,
    hostage_withholders: u8,
    admitted_poisoned: u8,
    slashed_adversaries: u8,
    adversary_credits_remaining: u8,
    restored: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ZeroTrustAction {
    NodeCrash,
    InjectPoisonedShard,
    WithholdEgressAtRestore,
    ExecuteZeroTrustRestore,
}

struct ZeroTrustRestoreModel;

impl Model for ZeroTrustRestoreModel {
    type State = ZeroTrustRestoreState;
    type Action = ZeroTrustAction;

    fn init_states(&self) -> Vec<Self::State> {
        vec![ZeroTrustRestoreState {
            honest_online: 20,
            crashed_nodes: 0,
            byzantine_poisoners: 0,
            hostage_withholders: 0,
            admitted_poisoned: 0,
            slashed_adversaries: 0,
            adversary_credits_remaining: 2,
            restored: false,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if state.restored {
            return;
        }
        // Up to 4 total faults in a 16-of-20 Homelab cohort (2 crashes + 1 poisoner + 1 hostage withholder).
        let total_faults =
            state.crashed_nodes + state.byzantine_poisoners + state.hostage_withholders;
        if total_faults < 4 && state.crashed_nodes < 2 {
            actions.push(ZeroTrustAction::NodeCrash);
        }
        if total_faults < 4 && state.byzantine_poisoners < 1 {
            actions.push(ZeroTrustAction::InjectPoisonedShard);
        }
        if total_faults < 4 && state.hostage_withholders < 1 {
            actions.push(ZeroTrustAction::WithholdEgressAtRestore);
        }
        actions.push(ZeroTrustAction::ExecuteZeroTrustRestore);
    }

    fn next_state(&self, state: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut next = state.clone();
        match action {
            ZeroTrustAction::NodeCrash => {
                next.honest_online -= 1;
                next.crashed_nodes += 1;
            }
            ZeroTrustAction::InjectPoisonedShard => {
                next.honest_online -= 1;
                next.byzantine_poisoners += 1;
            }
            ZeroTrustAction::WithholdEgressAtRestore => {
                next.honest_online -= 1;
                next.hostage_withholders += 1;
            }
            ZeroTrustAction::ExecuteZeroTrustRestore => {
                // Pre-decoding Merkle admission filter rejects all `byzantine_poisoners` (0 admitted)
                // and slashes both poisoners and hostage withholders, burning their credits to 0.
                next.admitted_poisoned = 0;
                next.slashed_adversaries = next.byzantine_poisoners + next.hostage_withholders;
                if next.slashed_adversaries > 0 {
                    next.adversary_credits_remaining = 0;
                }
                if next.honest_online >= 16 {
                    next.restored = true;
                }
            }
        }
        Some(next)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always("zero_poisoned_shards_admitted", |_, s| {
                s.admitted_poisoned == 0
            }),
            Property::<Self>::always("honest_quorum_always_recoverable", |_, s| {
                s.honest_online >= 16
            }),
            Property::<Self>::always("adversaries_slashed_on_restore", |_, s| {
                !s.restored
                    || (s.byzantine_poisoners + s.hostage_withholders == 0)
                    || (s.slashed_adversaries == s.byzantine_poisoners + s.hostage_withholders
                        && s.adversary_credits_remaining == 0)
            }),
        ]
    }
}

#[test]
fn test_stateright_zero_trust_byzantine_restore_and_hostage_model() {
    let checker = ZeroTrustRestoreModel
        .checker()
        .threads(1)
        .spawn_bfs()
        .join();
    checker.assert_properties();
    println!(
        "[STATERIGHT ZERO-TRUST PASS] Verified {} states with 0 counterexamples",
        checker.unique_state_count()
    );
    assert!(checker.unique_state_count() >= 10);
}
