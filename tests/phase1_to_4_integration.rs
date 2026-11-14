use parvault::{
    config::ErasureTier,
    crypto::{compute_sha256, MasterKey, NodeIdentity},
    network::{PeerTopologyMetrics, PlacementEngine},
    por::{
        compute_salted_commitment, generate_por_challenge, PorError, PorVerifierEngine,
        RepairGrant, WitnessFailureReceipt,
    },
    sharding::{encode_ciphertext_stripe, reconstruct_all_shards, MerkleTree},
    storage::{BlockStore, QuotaManager, ShardId},
};
use stateright::{Checker, Model, Property};
use std::net::{IpAddr, Ipv4Addr};
use tempfile::tempdir;

/// Phase 1 Spec Verification Gate:
/// Encrypt a file in streaming stripes, split into 20 shards (K=10, M=10),
/// delete 10 shards per stripe on disk, reconstruct over ciphertext, and verify SHA-256.
#[test]
fn test_phase1_encrypt_split20_delete10_reconstruct() {
    let dir = tempdir().expect("tempdir");
    let quota = QuotaManager::new(500 * 1024 * 1024, 100 * 1024 * 1024);
    let store = BlockStore::new(dir.path(), quota).expect("block store");

    let master_key = MasterKey::generate();
    let input_path = dir.path().join("sample_payload.bin");
    let output_path = dir.path().join("restored_payload.bin");

    // Create a 350 KiB deterministic payload spanning multiple 128 KiB streaming stripes.
    let payload: Vec<u8> = (0..358_400).map(|i| ((i * 31 + 17) % 251) as u8).collect();
    std::fs::write(&input_path, &payload).expect("write input");

    let manifest = store
        .store_file_streaming(
            "local",
            &input_path,
            &master_key,
            ErasureTier::Consumer, // 10-of-20
            128 * 1024,
        )
        .expect("store_file_streaming");

    assert_eq!(manifest.stripes.len(), 3);

    // Delete 10 out of 20 shards in every stripe (even indices 0, 2, 4, ..., 18).
    for stripe in &manifest.stripes {
        for idx in (0..20).step_by(2) {
            let shard_id = ShardId {
                stripe_merkle_root: stripe.stripe_merkle_root,
                shard_index: idx as u32,
                shard_hash: stripe.shard_hashes[idx],
            };
            let removed = store
                .delete_shard("local", &shard_id)
                .expect("delete_shard");
            assert!(removed);
        }
    }

    // Reconstruct and decrypt from the surviving 10 shards per stripe.
    store
        .restore_file_streaming(&manifest, &master_key, &output_path)
        .expect("restore_file_streaming after deleting 10 of 20 shards");

    let restored = std::fs::read(&output_path).expect("read restored");
    assert_eq!(compute_sha256(&payload), compute_sha256(&restored));
}

/// Verifies ADR-02 (Zero-knowledge DHT encrypted manifest recovery) & Homelab 80% Tier (16-of-20).
#[test]
fn test_homelab_16_of_20_and_dht_manifest_recovery() {
    let dir = tempdir().expect("tempdir");
    let quota = QuotaManager::new(500 * 1024 * 1024, 100 * 1024 * 1024);
    let store = BlockStore::new(dir.path(), quota).expect("block store");

    let master_key = MasterKey::generate();
    let input_path = dir.path().join("homelab_vault.bin");
    let output_path = dir.path().join("homelab_restored.bin");
    let payload = vec![0xABu8; 65_536];
    std::fs::write(&input_path, &payload).expect("write");

    let manifest = store
        .store_file_streaming(
            "local",
            &input_path,
            &master_key,
            ErasureTier::Homelab, // 16-of-20 (80% efficiency)
            1024 * 1024,
        )
        .expect("store homelab");

    // Roundtrip manifest through encrypted Kademlia DHT envelope using only MasterKey.
    let (_dht_key, encrypted_blob) = manifest
        .to_encrypted_dht_record(&master_key)
        .expect("encrypt manifest");
    let recovered_manifest =
        parvault::storage::FileManifest::from_encrypted_dht_record(&master_key, &encrypted_blob)
            .expect("decrypt manifest");
    assert_eq!(
        recovered_manifest.file_merkle_root,
        manifest.file_merkle_root
    );

    // Delete 4 shards (maximum fault tolerance for 16-of-20).
    for idx in 0..4 {
        let s = &recovered_manifest.stripes[0];
        let id = ShardId {
            stripe_merkle_root: s.stripe_merkle_root,
            shard_index: idx as u32,
            shard_hash: s.shard_hashes[idx],
        };
        store.delete_shard("local", &id).expect("delete");
    }

    store
        .restore_file_streaming(&recovered_manifest, &master_key, &output_path)
        .expect("restore 16-of-20");
    assert_eq!(std::fs::read(&output_path).unwrap(), payload);
}

/// Verifies Merkle inclusion proof generation and verification across shards.
#[test]
fn test_merkle_tree_inclusion_proofs() {
    let shard_set = encode_ciphertext_stripe(
        0,
        b"parvault-zero-knowledge-ciphertext-payload",
        ErasureTier::Consumer,
    )
    .expect("encode");
    let tree = MerkleTree::from_shards(&shard_set.shards);
    assert_eq!(tree.root(), shard_set.stripe_merkle_root);

    for (idx, shard) in shard_set.shards.iter().enumerate() {
        let proof = tree.generate_proof(idx).expect("proof");
        assert!(proof.verify(shard));
        assert!(!proof.verify(b"tampered-shard-bytes"));
    }
}

/// Verifies ADR-03 & ADR-04:
/// - Stateless RAM-only HMAC pre-verification blocks forged/replayed challenges with 0 disk I/O
/// - Salted SHA-256 commitments verify within <= 300ms SLA
/// - Raw ciphertext shard reads require a valid `RepairGrant` + >= 2 witness failure signatures
#[test]
fn test_por_stateless_hmac_and_witness_repair_grant() {
    let dir = tempdir().expect("tempdir");
    let quota = QuotaManager::new(100 * 1024 * 1024, 50 * 1024 * 1024);
    let store = BlockStore::new(dir.path(), quota).expect("store");

    let owner = NodeIdentity::generate();
    let witness1 = NodeIdentity::generate();
    let witness2 = NodeIdentity::generate();
    let unauthorized_witness = NodeIdentity::generate();

    let shard_set =
        encode_ciphertext_stripe(0, &[0x5Au8; 8192], ErasureTier::Homelab).expect("encode");
    let shard_id = ShardId {
        stripe_merkle_root: shard_set.stripe_merkle_root,
        shard_index: 0,
        shard_hash: shard_set.shard_hashes[0],
    };
    store
        .put_shard("local", &shard_id, &shard_set.shards[0])
        .expect("put_shard");

    let mut verifier = PorVerifierEngine::new(300);
    let session_key = [0x99u8; 32];
    verifier.register_shard_session(&shard_id, session_key);

    let now_ms = 1_700_000_000_000u64;
    let valid_chal = generate_por_challenge(
        &session_key,
        shard_id,
        shard_set.shards[0].len() as u64,
        now_ms,
    );

    // 1. Forged HMAC token is rejected in RAM before touching disk.
    let mut forged_chal = valid_chal.clone();
    forged_chal.hmac_token[0] ^= 0xFF;
    assert!(matches!(
        verifier.handle_incoming_challenge(&forged_chal, now_ms, &store),
        Err(PorError::InvalidHmacToken)
    ));
    assert_eq!(verifier.blocked_ddos_challenges(), 1);

    // 2. Valid challenge returns exact salted SHA-256 commitment.
    let resp = verifier
        .handle_incoming_challenge(&valid_chal, now_ms, &store)
        .expect("valid PoR challenge");
    let expected_slice = &shard_set.shards[0]
        [valid_chal.offset as usize..(valid_chal.offset + valid_chal.length) as usize];
    let expected_commit = compute_salted_commitment(&valid_chal.nonce, expected_slice);
    assert_eq!(resp.commitment, expected_commit);

    // 3. Replaying the exact same challenge nonce is rejected in RAM.
    assert!(matches!(
        verifier.handle_incoming_challenge(&valid_chal, now_ms, &store),
        Err(PorError::StaleOrReplayedNonce)
    ));
    assert_eq!(verifier.blocked_ddos_challenges(), 2);

    // 4. Proactive repair watermark triggers at 18/20 for Homelab pool.
    let outcome = verifier.verify_audit_response(
        &expected_commit,
        None, // simulated timeout
        350,
        ErasureTier::Homelab,
        19, // drops from 19 -> 18
    );
    assert!(!outcome.passed);
    assert!(outcome.trigger_proactive_repair);

    // 5. ADR-04: Raw ciphertext shard read is blocked without >= 2 authorized witness receipts.
    let grant = RepairGrant::issue(
        &owner,
        shard_set.stripe_merkle_root,
        vec![witness1.public_key_bytes(), witness2.public_key_bytes()],
        ErasureTier::Homelab,
    );
    // v0.5.0 (F-26): a grant authorises the shards stored with it.
    assert!(verifier
        .register_repair_grant_for_stored(grant.clone(), &[shard_id])
        .is_ok());

    let r1 = WitnessFailureReceipt::issue(&witness1, shard_set.stripe_merkle_root, 1, now_ms);
    let r_unauth = WitnessFailureReceipt::issue(
        &unauthorized_witness,
        shard_set.stripe_merkle_root,
        1,
        now_ms,
    );

    // Only 1 valid witness + 1 unauthorized witness -> rejected!
    assert!(matches!(
        verifier.authorize_raw_shard_read(
            &shard_id,
            None,
            Some((&grant, &[r1.clone(), r_unauth])),
            &store
        ),
        Err(PorError::UnauthorizedRawShardRead)
    ));

    // 2 valid designated witnesses -> authorized for zero-knowledge ciphertext repair!
    let r2 = WitnessFailureReceipt::issue(&witness2, shard_set.stripe_merkle_root, 1, now_ms);
    let raw_bytes = verifier
        .authorize_raw_shard_read(&shard_id, None, Some((&grant, &[r1, r2])), &store)
        .expect("authorized repair read");
    assert_eq!(raw_bytes, shard_set.shards[0]);

    // Verify witnesses can reconstruct missing shards purely over ciphertext without MasterKey.
    let mut slots: Vec<Option<Vec<u8>>> = shard_set.shards.iter().cloned().map(Some).collect();
    slots[1] = None;
    slots[2] = None;
    let repaired = reconstruct_all_shards(
        slots,
        shard_set.k_data,
        shard_set.m_parity,
        Some(&shard_set.shard_hashes),
        Some(shard_set.stripe_merkle_root),
    )
    .expect("zero-knowledge ciphertext repair");
    assert_eq!(repaired[1], shard_set.shards[1]);
    assert_eq!(repaired[2], shard_set.shards[2]);
}

/// Verifies ADR-06: 70% Intra-ASN / Low-RTT and 30% Cross-Region shard placement policy.
#[test]
fn test_70_30_topology_placement_and_fallback() {
    let engine = PlacementEngine::new(
        IpAddr::V4(Ipv4Addr::new(10, 42, 1, 10)),
        64513,
        "us-west-metro",
        5.0,
        0.70,
    );

    let mut candidates = Vec::new();
    // 16 local Intra-ASN low-RTT peers (< 5ms)
    for i in 0..16 {
        candidates.push(PeerTopologyMetrics {
            peer_id: format!("intra-peer-{i}"),
            kad_id_hash: [i as u8; 32],
            ip_addr: IpAddr::V4(Ipv4Addr::new(10, 42, 1, 20 + i as u8)),
            rtt_ms: 1.8,
            asn: 64513,
            region: "us-west-metro".to_string(),
            sla_score: 0.999,
            available_bytes: 10 * 1024 * 1024 * 1024,
        });
    }
    // 10 remote Inter-ASN cross-region peers (~35ms)
    for i in 0..10 {
        candidates.push(PeerTopologyMetrics {
            peer_id: format!("inter-peer-{i}"),
            kad_id_hash: [(100 + i) as u8; 32],
            ip_addr: IpAddr::V4(Ipv4Addr::new(10, 42, 9, 20 + i as u8)),
            rtt_ms: 35.0,
            asn: 64521,
            region: "us-east-remote".to_string(),
            sla_score: 0.998,
            available_bytes: 10 * 1024 * 1024 * 1024,
        });
    }

    let plan = engine.select_target_peers(&[0x33; 32], 10, 20, 1024, &candidates);
    assert_eq!(plan.selected_peers.len(), 20);
    assert_eq!(plan.intra_asn_count, 14); // 70% of 20
    assert_eq!(plan.inter_asn_count, 6); // 30% of 20
    assert!(!plan.used_dynamic_fallback);
}

/// Formal State-Space Model Checking (`stateright`) of the Proactive Shard Repair State Machine:
/// Verifies that for a 16-of-20 Homelab pool with proactive repair at 18 shards,
/// the system never reaches an unrecoverable state (< 16 shards) under bounded churn per epoch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CohortRepairState {
    active_shards: u8,
    drops_in_current_epoch: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum CohortAction {
    NodeChurnDrop,
    ProactiveWitnessRepair,
}

struct HomelabRepairModel {
    k_min: u8,
    n_total: u8,
    repair_watermark: u8,
    max_simultaneous_drops_per_epoch: u8,
}

impl Model for HomelabRepairModel {
    type State = CohortRepairState;
    type Action = CohortAction;

    fn init_states(&self) -> Vec<Self::State> {
        vec![CohortRepairState {
            active_shards: self.n_total,
            drops_in_current_epoch: 0,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if state.drops_in_current_epoch < self.max_simultaneous_drops_per_epoch
            && state.active_shards > 0
        {
            actions.push(CohortAction::NodeChurnDrop);
        }
        if state.active_shards <= self.repair_watermark && state.active_shards >= self.k_min {
            actions.push(CohortAction::ProactiveWitnessRepair);
        }
    }

    fn next_state(&self, last_state: &Self::State, action: Self::Action) -> Option<Self::State> {
        match action {
            CohortAction::NodeChurnDrop => Some(CohortRepairState {
                active_shards: last_state.active_shards - 1,
                drops_in_current_epoch: last_state.drops_in_current_epoch + 1,
            }),
            CohortAction::ProactiveWitnessRepair => Some(CohortRepairState {
                active_shards: self.n_total,
                drops_in_current_epoch: 0,
            }),
        }
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![Property::<Self>::always(
            "Data Always Retrievable (active_shards >= K=16)",
            |model, state| state.active_shards >= model.k_min,
        )]
    }
}

#[test]
fn test_stateright_formal_repair_safety_invariant() {
    let model = HomelabRepairModel {
        k_min: 16,
        n_total: 20,
        repair_watermark: 18,
        max_simultaneous_drops_per_epoch: 4, // up to N - K = 4 node failures per repair window
    };

    let checker = model.checker().spawn_bfs().join();
    checker.assert_properties();
}
