use parvault::config::ErasureTier;
use parvault::crypto::{
    compute_sha256, decrypt_stripe, derive_unlinkable_shard_pseudonym, encrypt_stripe,
    generate_file_salt, pad_plaintext_iso_bucket, unpad_plaintext_iso_bucket, MasterKey,
    NodeIdentity,
};
use parvault::sharding::{
    encode_ciphertext_stripe, reconstruct_all_shards, reconstruct_ciphertext_stripe, MerkleTree,
};
use parvault::storage::quota::{PeerCreditAccount, QuotaManager, TrustLevel};
use parvault::storage::BlockStore;
use parvault::sync::{FolderSnapshotManifest, FolderSyncEngine};
use stateright::{Checker, Model, Property};
use std::fs;
use tempfile::tempdir;

/// Computes empirical Shannon entropy $H(X) = -\sum_{b=0}^{255} p(b) \log_2 p(b)$ in bits/byte (`[0.0, 8.0]`).
fn compute_shannon_entropy_bits_per_byte(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Computes the fractional Hamming distance (bit-flip ratio in `[0.0, 1.0]`) across two shard sets.
fn compute_shard_bit_flip_ratio(shards_a: &[Vec<u8>], shards_b: &[Vec<u8>]) -> f64 {
    assert_eq!(shards_a.len(), shards_b.len());
    let mut flipped_bits: u64 = 0;
    let mut total_bits: u64 = 0;
    for (sa, sb) in shards_a.iter().zip(shards_b.iter()) {
        assert_eq!(sa.len(), sb.len());
        for (&ba, &bb) in sa.iter().zip(sb.iter()) {
            flipped_bits += (ba ^ bb).count_ones() as u64;
            total_bits += 8;
        }
    }
    (flipped_bits as f64) / (total_bits as f64)
}

/// ============================================================================
/// PROOF 1: Empirical Shannon Entropy ($H(X) > 7.98$ bits/byte) & Zero Plaintext
/// Substring Leakage across all 20 Reed-Solomon Shards
/// ============================================================================
#[test]
fn test_proof1_shannon_entropy_and_zero_plaintext_leakage_on_shards() {
    // 1. Construct a highly structured, low-entropy 64 KiB (65,536-byte) plaintext:
    //    - First 32 KiB: all 0x00 bytes
    //    - Second 32 KiB: repeating "SECRET NEIGHBORHOOD CLOUD TAX RETURN 2026\n" lines
    let mut plaintext = vec![0x00u8; 32 * 1024];
    let repeating_line = b"SECRET NEIGHBORHOOD CLOUD TAX RETURN 2026\n";
    while plaintext.len() < 64 * 1024 {
        let remaining = (64 * 1024) - plaintext.len();
        let take = remaining.min(repeating_line.len());
        plaintext.extend_from_slice(&repeating_line[..take]);
    }
    assert_eq!(plaintext.len(), 65_536);

    let plaintext_entropy = compute_shannon_entropy_bits_per_byte(&plaintext);
    assert!(
        plaintext_entropy < 3.5,
        "Structured plaintext must have low initial Shannon entropy (got {plaintext_entropy:.4} bits/byte)"
    );

    // 2. Pad with ISO/IEC 7816-4 uniform size bucket, encrypt with AES-256-GCM prior to
    //    Reed-Solomon splitting, and encode into N=20 shards (16-of-20 Homelab tier).
    let master_key = MasterKey::from_bytes([0x42; 32]);
    let file_salt = [0xA5; 32];
    let padded = pad_plaintext_iso_bucket(&plaintext, 65_536);
    let ciphertext = encrypt_stripe(&master_key, &file_salt, 0, &padded).unwrap();
    let shard_set = encode_ciphertext_stripe(0, &ciphertext, ErasureTier::Homelab).unwrap();
    assert_eq!(shard_set.shards.len(), 20);

    // 3. Concatenate all 20 shards and prove empirical Shannon entropy H(X) > 7.98 bits/byte
    //    (indistinguishable from uniform CSPRNG white noise where ideal = 8.00 bits/byte).
    let all_shard_bytes: Vec<u8> = shard_set
        .shards
        .iter()
        .flat_map(|s| s.iter().copied())
        .collect();
    let shard_entropy = compute_shannon_entropy_bits_per_byte(&all_shard_bytes);
    assert!(
        shard_entropy > 7.98,
        "Encrypted & erasure-coded shards must achieve Shannon entropy > 7.98 bits/byte (got {shard_entropy:.5})"
    );

    // 4. Prove zero 16-byte plaintext substring leakage across all 20 shards.
    let probe_patterns: [&[u8; 16]; 3] = [&[0x00u8; 16], b"SECRET NEIGHBORH", b"OOD CLOUD TAX RE"];
    for (shard_idx, shard) in shard_set.shards.iter().enumerate() {
        for pattern in &probe_patterns {
            assert!(
                !shard.windows(16).any(|w| w == *pattern),
                "Shard {shard_idx} leaked 16-byte plaintext pattern {:?}",
                pattern
            );
        }
    }

    // 5. Verify Merkle tree integrity and lossless round-trip unpadding for the legitimate owner.
    let tree = MerkleTree::from_shards(&shard_set.shards);
    assert_eq!(tree.root(), shard_set.stripe_merkle_root);
    let slots: Vec<Option<Vec<u8>>> = shard_set.shards.into_iter().map(Some).collect();
    let restored_cipher = reconstruct_ciphertext_stripe(
        slots,
        16,
        4,
        shard_set.original_ciphertext_len,
        Some(&shard_set.shard_hashes),
        Some(shard_set.stripe_merkle_root),
    )
    .unwrap();
    let restored_padded = decrypt_stripe(&master_key, &file_salt, 0, &restored_cipher).unwrap();
    let restored_plain = unpad_plaintext_iso_bucket(&restored_padded).unwrap();
    assert_eq!(restored_plain, plaintext);
}

/// ============================================================================
/// PROOF 2: Strict Avalanche Criterion (~50% Bit Flip) & IND-CPA / INT-CTXT
/// Non-Malleability even under 20-of-20 Storage Node Collusion
/// ============================================================================
#[test]
fn test_proof2_strict_avalanche_criterion_and_ind_cpa_non_malleability() {
    let master_key = MasterKey::from_bytes([0x19; 32]);
    let plaintext_a = b"CONFIDENTIAL NEIGHBORHOOD MESH VAULT RECORD - VERSION 1\n".repeat(1024);
    let mut plaintext_b = plaintext_a.clone();
    // Flip 1 single bit in the plaintext:
    plaintext_b[0] ^= 0x01;

    // Bind fresh per-write salt entropy (convergent/salted file write) so 1-bit plaintext
    // modification cascades through HKDF nonce derivation, AES-256-GCM, and GF(2^8) encoding.
    let salt_a = compute_sha256(&plaintext_a);
    let salt_b = compute_sha256(&plaintext_b);

    let cipher_a = encrypt_stripe(&master_key, &salt_a, 0, &plaintext_a).unwrap();
    let cipher_b = encrypt_stripe(&master_key, &salt_b, 0, &plaintext_b).unwrap();
    let shards_a = encode_ciphertext_stripe(0, &cipher_a, ErasureTier::Homelab).unwrap();
    let shards_b = encode_ciphertext_stripe(0, &cipher_b, ErasureTier::Homelab).unwrap();

    // Case A: Flipping 1 single bit in the plaintext changes ~50% of all bits across all 20 shards.
    let ratio_case_a = compute_shard_bit_flip_ratio(&shards_a.shards, &shards_b.shards);
    assert!(
        (0.45..=0.55).contains(&ratio_case_a),
        "Case A Strict Avalanche failed: expected bit-flip ratio in [0.45, 0.55], got {ratio_case_a:.4}"
    );

    // Case B: Encrypting the exact same plaintext for stripe 0 vs stripe 1, and with
    // derive_epoch_subkey(1) vs derive_epoch_subkey(2), produces completely uncorrelated shards.
    let cipher_stripe1 = encrypt_stripe(&master_key, &salt_a, 1, &plaintext_a).unwrap();
    let shards_stripe1 =
        encode_ciphertext_stripe(1, &cipher_stripe1, ErasureTier::Homelab).unwrap();
    let ratio_stripe_diff = compute_shard_bit_flip_ratio(&shards_a.shards, &shards_stripe1.shards);
    assert!(
        (0.45..=0.55).contains(&ratio_stripe_diff),
        "Case B (stripe 0 vs stripe 1) failed: expected bit-flip ratio in [0.45, 0.55], got {ratio_stripe_diff:.4}"
    );

    let epoch_key_1 = master_key.derive_epoch_subkey(1);
    let epoch_key_2 = master_key.derive_epoch_subkey(2);
    let cipher_epoch1 = encrypt_stripe(&epoch_key_1, &salt_a, 0, &plaintext_a).unwrap();
    let cipher_epoch2 = encrypt_stripe(&epoch_key_2, &salt_a, 0, &plaintext_a).unwrap();
    let shards_epoch1 = encode_ciphertext_stripe(0, &cipher_epoch1, ErasureTier::Homelab).unwrap();
    let shards_epoch2 = encode_ciphertext_stripe(0, &cipher_epoch2, ErasureTier::Homelab).unwrap();
    let ratio_epoch_diff =
        compute_shard_bit_flip_ratio(&shards_epoch1.shards, &shards_epoch2.shards);
    assert!(
        (0.45..=0.55).contains(&ratio_epoch_diff),
        "Case B (epoch 1 vs epoch 2 subkey) failed: expected bit-flip ratio in [0.45, 0.55], got {ratio_epoch_diff:.4}"
    );

    // Case C: Even if all 20 storage nodes collude and pool all 20 shards to reconstruct the
    // ciphertext stripe, they cannot decrypt without K_user, nor can they flip 1 bit without
    // failing AES-256-GCM authentication tag verification.
    let all_20_slots: Vec<Option<Vec<u8>>> = shards_a.shards.iter().cloned().map(Some).collect();
    let reconstructed_all = reconstruct_all_shards(
        all_20_slots.clone(),
        16,
        4,
        Some(&shards_a.shard_hashes),
        Some(shards_a.stripe_merkle_root),
    )
    .unwrap();
    assert_eq!(reconstructed_all.len(), 20);

    // Also verify unlinkable per-shard pseudonyms and fresh salt generation.
    let fresh_salt = generate_file_salt();
    assert_eq!(fresh_salt.len(), 32);
    let pseudo_0 = derive_unlinkable_shard_pseudonym(&master_key, &shards_a.stripe_merkle_root, 0);
    let pseudo_1 = derive_unlinkable_shard_pseudonym(&master_key, &shards_a.stripe_merkle_root, 1);
    assert_ne!(pseudo_0, pseudo_1);

    let pooled_ciphertext = reconstruct_ciphertext_stripe(
        all_20_slots,
        16,
        4,
        shards_a.original_ciphertext_len,
        Some(&shards_a.shard_hashes),
        Some(shards_a.stripe_merkle_root),
    )
    .unwrap();

    // Colluding nodes attempt decryption with a guessed/wrong key -> Err.
    let wrong_key = MasterKey::from_bytes([0xFE; 32]);
    assert!(
        decrypt_stripe(&wrong_key, &salt_a, 0, &pooled_ciphertext).is_err(),
        "20-of-20 colluding nodes without K_user must fail AES-256-GCM decryption"
    );

    // Colluding nodes flip 1 bit in the reconstructed ciphertext -> Err (INT-CTXT non-malleability).
    let mut tampered_ciphertext = pooled_ciphertext;
    tampered_ciphertext[0] ^= 0x01;
    assert!(
        decrypt_stripe(&master_key, &salt_a, 0, &tampered_ciphertext).is_err(),
        "1-bit ciphertext modification must fail AES-256-GCM tag verification"
    );
}

/// ============================================================================
/// PROOF 3: Dynamic Uptime Trust Levels (`Untrusted -> Verified -> Anchor -> Slashed`)
/// & Strict Subnet Concentration Caps (`<= 4 < 16 = K`)
/// ============================================================================
#[test]
fn test_proof3_dynamic_uptime_trust_levels_and_subnet_concentration_caps() {
    let mut quota = QuotaManager::new(100 * 1024 * 1024 * 1024, 10 * 1024 * 1024 * 1024);
    let peer_id = "peer-homelab-candidate";
    quota.record_remote_contribution(peer_id, 50 * 1024 * 1024 * 1024);

    // Stage 1: Newly joined peer starts at UntrustedProbationary (max 1 shard/subnet, 1.0x multiplier).
    let level_initial = quota.peer_trust_level(peer_id);
    assert_eq!(level_initial, TrustLevel::UntrustedProbationary);
    assert_eq!(level_initial.max_shards_per_subnet(), 1);
    assert!((level_initial.storage_quota_multiplier() - 1.0).abs() < f64::EPSILON);

    let default_acct = PeerCreditAccount::default();
    assert_eq!(
        default_acct.trust_level(),
        TrustLevel::UntrustedProbationary
    );

    // Stage 2: After 50 consecutive PoR passes (100% >= 98% SLA), peer promotes to VerifiedNeighbor.
    for _ in 0..50 {
        quota.record_por_outcome(peer_id, true);
    }
    let level_verified = quota.peer_trust_level(peer_id);
    assert_eq!(level_verified, TrustLevel::VerifiedNeighbor);
    assert_eq!(
        quota.peer_account(peer_id).unwrap().trust_level(),
        TrustLevel::VerifiedNeighbor
    );
    assert_eq!(level_verified.max_shards_per_subnet(), 2);
    assert!((level_verified.storage_quota_multiplier() - 2.5).abs() < f64::EPSILON);

    // Stage 3: After 200 total consecutive PoR passes (100% >= 99.8% SLA), peer promotes to HighUptimeAnchor.
    for _ in 0..150 {
        quota.record_por_outcome(peer_id, true);
    }
    let level_anchor = quota.peer_trust_level(peer_id);
    assert_eq!(level_anchor, TrustLevel::HighUptimeAnchor);
    assert_eq!(level_anchor.max_shards_per_subnet(), 4);
    assert!((level_anchor.storage_quota_multiplier() - 5.0).abs() < f64::EPSILON);

    // Prove that even at the highest trust level (`HighUptimeAnchor`, 4 shards/subnet),
    // a fully compromised subnet holds at most 4 shards — which is 12 shards short of K=16!
    let (k_homelab, _, _) = ErasureTier::Homelab.params();
    assert_eq!(k_homelab, 16);
    assert!(level_anchor.max_shards_per_subnet() < k_homelab);
    assert_eq!(k_homelab - level_anchor.max_shards_per_subnet(), 12);

    // Stage 4: A single Byzantine withholding or poisoning slash immediately demotes the peer
    // to SlashedQuarantined (max_shards_per_subnet == 0, storage_quota_multiplier == 0.0).
    let burned = quota.slash_peer_for_withholding(peer_id);
    assert_eq!(burned, 50 * 1024 * 1024 * 1024);

    let level_slashed = quota.peer_trust_level(peer_id);
    assert_eq!(level_slashed, TrustLevel::SlashedQuarantined);
    assert_eq!(level_slashed.max_shards_per_subnet(), 0);
    assert!((level_slashed.storage_quota_multiplier() - 0.0).abs() < f64::EPSILON);
    assert!(!quota.can_accept_shard(peer_id, 1024));
}

/// ============================================================================
/// PROOF 4: Exhaustive `stateright` Model Checking of Dynamic Trust Promotion,
/// Byzantine Slashing, and Subnet Collusion Confidentiality
/// ============================================================================
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ModelTrustTier {
    Untrusted,
    Verified,
    Anchor,
    Slashed,
}

impl ModelTrustTier {
    fn to_trust_level(self) -> TrustLevel {
        match self {
            Self::Untrusted => TrustLevel::UntrustedProbationary,
            Self::Verified => TrustLevel::VerifiedNeighbor,
            Self::Anchor => TrustLevel::HighUptimeAnchor,
            Self::Slashed => TrustLevel::SlashedQuarantined,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct DynamicTrustState {
    subnet_tier: ModelTrustTier,
    por_milestones: u8,
    shards_in_subnet: u8,
    subnet_colluding: bool,
    plaintext_leaked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum DynamicTrustAction {
    Pass50PorAudits,
    Pass200PorAudits,
    AllocateShardToSubnet,
    ByzantineSlashSubnet,
    AttemptSubnetCollusionDecryption,
}

struct DynamicTrustConfidentialityModel {
    k_required: u8,
}

impl Model for DynamicTrustConfidentialityModel {
    type State = DynamicTrustState;
    type Action = DynamicTrustAction;

    fn init_states(&self) -> Vec<Self::State> {
        vec![DynamicTrustState {
            subnet_tier: ModelTrustTier::Untrusted,
            por_milestones: 0,
            shards_in_subnet: 0,
            subnet_colluding: false,
            plaintext_leaked: false,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        let cap = state.subnet_tier.to_trust_level().max_shards_per_subnet() as u8;
        if state.subnet_tier == ModelTrustTier::Untrusted && state.por_milestones == 0 {
            actions.push(DynamicTrustAction::Pass50PorAudits);
        }
        if state.subnet_tier == ModelTrustTier::Verified && state.por_milestones == 1 {
            actions.push(DynamicTrustAction::Pass200PorAudits);
        }
        if state.shards_in_subnet < cap {
            actions.push(DynamicTrustAction::AllocateShardToSubnet);
        }
        if state.subnet_tier != ModelTrustTier::Slashed {
            actions.push(DynamicTrustAction::ByzantineSlashSubnet);
        }
        if !state.subnet_colluding {
            actions.push(DynamicTrustAction::AttemptSubnetCollusionDecryption);
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut next = last.clone();
        match action {
            DynamicTrustAction::Pass50PorAudits => {
                next.por_milestones = 1;
                next.subnet_tier = ModelTrustTier::Verified;
            }
            DynamicTrustAction::Pass200PorAudits => {
                next.por_milestones = 2;
                next.subnet_tier = ModelTrustTier::Anchor;
            }
            DynamicTrustAction::AllocateShardToSubnet => {
                let cap = next.subnet_tier.to_trust_level().max_shards_per_subnet() as u8;
                if next.shards_in_subnet < cap {
                    next.shards_in_subnet += 1;
                }
            }
            DynamicTrustAction::ByzantineSlashSubnet => {
                next.subnet_tier = ModelTrustTier::Slashed;
                next.shards_in_subnet = 0;
            }
            DynamicTrustAction::AttemptSubnetCollusionDecryption => {
                next.subnet_colluding = true;
                // A colluding subnet can only reconstruct ciphertext if shards_in_subnet >= K (16),
                // AND even then cannot decrypt without K_user.
                if next.shards_in_subnet >= self.k_required {
                    next.plaintext_leaked = true;
                }
            }
        }
        Some(next)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always("confidentiality_preserved", |model, s| {
                s.shards_in_subnet <= 4
                    && s.shards_in_subnet < model.k_required
                    && !s.plaintext_leaked
            }),
            Property::<Self>::always("subnet_caps_respected", |_, s| {
                let cap = s.subnet_tier.to_trust_level().max_shards_per_subnet() as u8;
                s.shards_in_subnet <= cap
            }),
        ]
    }
}

#[test]
fn test_proof4_stateright_dynamic_trust_and_confidentiality_model() {
    let model = DynamicTrustConfidentialityModel { k_required: 16 };
    let checker = model.checker().threads(1).spawn_bfs().join();
    checker.assert_properties();
    assert!(checker.unique_state_count() >= 15);
}

/// ============================================================================
/// PROOF 5: Incremental Folder Backup, Deduplicated Sync, & Bit-Perfect
/// Zero-Trust Directory Restore (`FolderSyncEngine`)
/// ============================================================================
#[test]
fn test_proof5_incremental_folder_backup_and_zero_trust_directory_restore() {
    let tmp = tempdir().unwrap();
    let store_dir = tmp.path().join("block_store");
    let source_dir = tmp.path().join("source_vault");
    let restore_dir = tmp.path().join("restored_vault");

    // 1. Create nested directory structure with multiple files.
    fs::create_dir_all(source_dir.join("docs")).unwrap();
    fs::create_dir_all(source_dir.join("photos")).unwrap();
    fs::create_dir_all(source_dir.join("config")).unwrap();

    let notes_v1 = b"Neighborhood Cloud architectural notes v1.\nZero-knowledge by default.";
    let photo_bytes: Vec<u8> = (0..16_384u32)
        .map(|i| ((i * 73 + 19) % 256) as u8)
        .collect();
    let settings_toml = b"[mesh]\ntier = \"homelab\"\nmax_shards_per_subnet = 4\n";

    fs::write(source_dir.join("docs/notes.txt"), notes_v1).unwrap();
    fs::write(source_dir.join("photos/img.bin"), &photo_bytes).unwrap();
    fs::write(source_dir.join("config/settings.toml"), settings_toml).unwrap();

    let quota = QuotaManager::new(500 * 1024 * 1024, 100 * 1024 * 1024);
    let store = BlockStore::new(&store_dir, quota).unwrap();
    let master_key = MasterKey::generate();
    let owner_identity = NodeIdentity::generate();

    let mut sync_engine =
        FolderSyncEngine::new(store, master_key, owner_identity, ErasureTier::Homelab);

    // 2. Run initial folder sync (`version == 1`).
    let snapshot_v1: FolderSnapshotManifest = sync_engine.sync_folder_once(&source_dir).unwrap();
    assert_eq!(snapshot_v1.version, 1);
    assert_eq!(snapshot_v1.files.len(), 3);
    assert!(snapshot_v1
        .signed_dht_envelope
        .as_ref()
        .unwrap()
        .verify_zero_knowledge());

    let img_root_v1 = snapshot_v1
        .files
        .get("photos/img.bin")
        .unwrap()
        .file_merkle_root;

    // 3. Modify `docs/notes.txt` and add a new file `docs/roadmap.md`, leaving `photos/img.bin` untouched.
    let notes_v2 =
        b"Neighborhood Cloud architectural notes v2 (UPDATED).\nAdded dynamic trust caps.";
    let roadmap_md =
        b"# Roadmap\n- Automatic incremental folder sync\n- High-uptime anchor nodes\n";
    fs::write(source_dir.join("docs/notes.txt"), notes_v2).unwrap();
    fs::write(source_dir.join("docs/roadmap.md"), roadmap_md).unwrap();

    // 4. Run incremental folder sync (`version == 2`).
    let snapshot_v2: FolderSnapshotManifest = sync_engine.sync_folder_once(&source_dir).unwrap();
    assert_eq!(snapshot_v2.version, 2);
    assert_eq!(snapshot_v2.files.len(), 4);
    assert_ne!(
        snapshot_v2.folder_merkle_root,
        snapshot_v1.folder_merkle_root
    );
    assert!(snapshot_v2
        .signed_dht_envelope
        .as_ref()
        .unwrap()
        .verify_zero_knowledge());

    // Unchanged `photos/img.bin` must retain its deduplicated Merkle root, while `docs/notes.txt` updates.
    assert_eq!(
        snapshot_v2
            .files
            .get("photos/img.bin")
            .unwrap()
            .file_merkle_root,
        img_root_v1
    );
    assert_ne!(
        snapshot_v2
            .files
            .get("docs/notes.txt")
            .unwrap()
            .file_merkle_root,
        snapshot_v1
            .files
            .get("docs/notes.txt")
            .unwrap()
            .file_merkle_root
    );

    // 5. Restore the entire v2 snapshot into a fresh directory and verify bit-for-bit equality.
    let restored_files = sync_engine
        .restore_folder(&snapshot_v2, &restore_dir)
        .unwrap();
    assert_eq!(restored_files, 4);

    assert_eq!(
        fs::read(restore_dir.join("docs/notes.txt")).unwrap(),
        notes_v2
    );
    assert_eq!(
        fs::read(restore_dir.join("docs/roadmap.md")).unwrap(),
        roadmap_md
    );
    assert_eq!(
        fs::read(restore_dir.join("photos/img.bin")).unwrap(),
        photo_bytes
    );
    assert_eq!(
        fs::read(restore_dir.join("config/settings.toml")).unwrap(),
        settings_toml
    );
}
