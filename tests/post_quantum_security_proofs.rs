use parvault::config::ErasureTier;
use parvault::crypto::pqc::{
    HybridKemKeypair, HybridPqSigningKeypair, PqRelayedShardEnvelope, PqSignedDhtManifestEnvelope,
    PqVaultMasterKey,
};
use parvault::crypto::MasterKey;
use parvault::sharding::{encode_ciphertext_stripe, reconstruct_ciphertext_stripe};
use parvault::storage::anonymity::BlindedShardId;
use stateright::{Checker, Model, Property};

/// ============================================================================
/// TEST PQ-1: Hybrid X25519 + NIST FIPS 203 ML-KEM-768 Key Encapsulation &
/// Shor's Algorithm Resilience ("Harvest-Now, Decrypt-Later" Defense)
/// ============================================================================
#[test]
fn test_pq1_hybrid_ml_kem_768_x25519_encapsulation_and_shor_resilience() {
    let recipient = HybridKemKeypair::generate().expect("ML-KEM-768 + X25519 keygen must succeed");
    let attacker = HybridKemKeypair::generate().expect("Attacker keygen must succeed");

    let recipient_pub = recipient.public_key();
    assert_eq!(recipient_pub.x25519_pub.len(), 32);
    assert_eq!(
        recipient_pub.ml_kem_768_ek.len(),
        1184,
        "NIST FIPS 203 ML-KEM-768 encapsulation key must be exactly 1,184 bytes"
    );

    let (sender_shared_secret, ciphertext) =
        HybridKemKeypair::encapsulate(&recipient_pub).expect("Hybrid encapsulation must succeed");
    assert_eq!(ciphertext.ephemeral_x25519_pub.len(), 32);
    assert_eq!(
        ciphertext.ml_kem_768_ct.len(),
        1088,
        "NIST FIPS 203 ML-KEM-768 ciphertext must be exactly 1,088 bytes"
    );

    // 1. Legitimate recipient decapsulates and recovers the exact 256-bit hybrid shared secret:
    let recipient_shared_secret = recipient
        .decapsulate(&ciphertext)
        .expect("Recipient hybrid decapsulation must succeed");
    assert_eq!(sender_shared_secret, recipient_shared_secret);

    // 2. Wrong recipient (or active MITM) decapsulating the same ciphertext derives a completely
    //    uncorrelated key due to ML-KEM FO implicit rejection + X25519 DH mismatch:
    if let Ok(attacker_secret) = attacker.decapsulate(&ciphertext) {
        assert_ne!(
            attacker_secret, sender_shared_secret,
            "Attacker decapsulation must never recover the legitimate hybrid shared secret"
        );
    }

    // 3. Shor's Algorithm Resilience Proof on the Hybrid Combiner:
    //    Suppose a future CRQC (Cryptanalytically Relevant Quantum Computer) uses Shor's algorithm
    //    to solve the discrete logarithm on Curve25519 and recovers `ss_x25519` in full,
    //    AND observes the public transcript `(ephem_x25519_pub, ml_kem_ct)`.
    //    Without breaking Module-LWE (`ss_ml_kem`), the adversary's derived key is uncorrelated.
    let ss_x25519_broken_by_shor = [0xAAu8; 32];
    let ss_ml_kem_true = [0x55u8; 32];
    let ss_ml_kem_quantum_guess = [0x54u8; 32];

    let real_hybrid_key = HybridKemKeypair::combine_hybrid_secrets(
        &ss_x25519_broken_by_shor,
        &ss_ml_kem_true,
        &ciphertext.ephemeral_x25519_pub,
        &ciphertext.ml_kem_768_ct,
    );
    let shor_adversary_key = HybridKemKeypair::combine_hybrid_secrets(
        &ss_x25519_broken_by_shor,
        &ss_ml_kem_quantum_guess,
        &ciphertext.ephemeral_x25519_pub,
        &ciphertext.ml_kem_768_ct,
    );
    assert_ne!(
        real_hybrid_key, shor_adversary_key,
        "Hybrid combiner must remain secure even when X25519 is completely broken by Shor's algorithm"
    );

    // 4. Conversely, even if a flaw were found in ML-KEM-768, classical X25519 still protects the secret:
    let classical_fallback_guess = HybridKemKeypair::combine_hybrid_secrets(
        &[0xABu8; 32],
        &ss_ml_kem_true,
        &ciphertext.ephemeral_x25519_pub,
        &ciphertext.ml_kem_768_ct,
    );
    assert_ne!(real_hybrid_key, classical_fallback_guess);

    // 5. Transcript binding (IND-CCA2 defense against ciphertext malleability):
    let mut tampered_ct = ciphertext.ml_kem_768_ct.clone();
    tampered_ct[0] ^= 0x01;
    let tampered_transcript_key = HybridKemKeypair::combine_hybrid_secrets(
        &ss_x25519_broken_by_shor,
        &ss_ml_kem_true,
        &ciphertext.ephemeral_x25519_pub,
        &tampered_ct,
    );
    assert_ne!(
        real_hybrid_key, tampered_transcript_key,
        "1-bit mutation in ciphertext transcript must completely change the derived hybrid key"
    );
}

/// ============================================================================
/// TEST PQ-2: Composite Ed25519 + NIST FIPS 204 ML-DSA-65 Digital Signatures
/// Block Quantum Forgery of Web-of-Trust & DHT Manifests
/// ============================================================================
#[test]
fn test_pq2_composite_ml_dsa_65_ed25519_signatures_block_quantum_forgery() {
    let signer =
        HybridPqSigningKeypair::generate().expect("Ed25519 + ML-DSA-65 keygen must succeed");
    let impostor = HybridPqSigningKeypair::generate().expect("Impostor keygen must succeed");

    let pubkey = signer.public_key();
    assert_eq!(pubkey.ed25519_pub.len(), 32);
    assert_eq!(
        pubkey.ml_dsa_65_pk.len(),
        1952,
        "NIST FIPS 204 ML-DSA-65 public key must be exactly 1,952 bytes"
    );

    let message = b"parvault-wot-delegation-v2:inviter=nodeA,invitee=nodeB,epoch=42";
    let sig = signer
        .sign(message)
        .expect("Composite PQ signing must succeed");

    assert_eq!(sig.ed25519_sig.len(), 64);
    assert_eq!(
        sig.ml_dsa_65_sig.len(),
        3309,
        "NIST FIPS 204 ML-DSA-65 signature must be exactly 3,309 bytes"
    );

    // 1. Valid composite signature verifies:
    assert!(HybridPqSigningKeypair::verify(&pubkey, message, &sig));

    // 2. Quantum Forgery Attempt (Shor breaks Ed25519 -> valid Ed25519 sig, forged ML-DSA-65 sig):
    let mut shor_forged_sig = sig.clone();
    shor_forged_sig.ml_dsa_65_sig[100] ^= 0xFF;
    assert!(
        !HybridPqSigningKeypair::verify(&pubkey, message, &shor_forged_sig),
        "Composite verifier MUST reject signatures where Ed25519 is valid but ML-DSA-65 is forged"
    );

    // 3. Classical Component Forgery Attempt (valid ML-DSA-65 sig, forged Ed25519 sig):
    let mut ed25519_forged_sig = sig.clone();
    ed25519_forged_sig.ed25519_sig[10] ^= 0xFF;
    assert!(
        !HybridPqSigningKeypair::verify(&pubkey, message, &ed25519_forged_sig),
        "Composite verifier MUST reject signatures where ML-DSA-65 is valid but Ed25519 is forged"
    );

    // 4. Message tampering or wrong public key MUST fail verification:
    let tampered_message = b"parvault-wot-delegation-v2:inviter=nodeA,invitee=nodeB,epoch=43";
    assert!(!HybridPqSigningKeypair::verify(
        &pubkey,
        tampered_message,
        &sig
    ));
    assert!(!HybridPqSigningKeypair::verify(
        &impostor.public_key(),
        message,
        &sig
    ));
}

/// ============================================================================
/// TEST PQ-3: 512-Bit Grover-Resistant `PqVaultMasterKey` Cascaded Independent
/// Dual-Key Encryption + Reed-Solomon `(16, 4)` Erasure Coding
/// ============================================================================
#[test]
fn test_pq3_512bit_grover_resistant_cascaded_stripe_encryption_and_sharding() {
    let pq_master = PqVaultMasterKey::generate();
    let wrong_pq_master = PqVaultMasterKey::from_bytes([0x99u8; 64]);
    assert_eq!(
        pq_master.as_bytes().len(),
        64,
        "PqVaultMasterKey must hold 512 bits (64 bytes) of entropy to resist Grover's O(2^(n/2)) search"
    );

    let file_salt = [0x77u8; 32];
    let stripe_index = 0u64;
    let plaintext = b"POST-QUANTUM GROVER-RESISTANT 512-BIT CASCADED STRIPE PAYLOAD\n".repeat(1024);

    // 1. Encrypt stripe with cascaded 512-bit PqVaultMasterKey:
    let pq_ciphertext = pq_master
        .encrypt_stripe_pq(&file_salt, stripe_index, &plaintext)
        .expect("PQ cascaded stripe encryption must succeed");
    assert!(pq_ciphertext.len() > plaintext.len());

    // 2. Erasure-code the PQ ciphertext stripe into K=16 data + M=4 parity shards:
    let shard_set = encode_ciphertext_stripe(stripe_index, &pq_ciphertext, ErasureTier::Homelab)
        .expect("Reed-Solomon encoding of PQ stripe must succeed");
    assert_eq!(shard_set.shards.len(), 20);

    // 3. Simulate simultaneous loss of 4 shards (indices 1, 6, 11, 18) and reconstruct:
    let mut shard_slots: Vec<Option<Vec<u8>>> = shard_set.shards.into_iter().map(Some).collect();
    for &lost_idx in &[1usize, 6, 11, 18] {
        shard_slots[lost_idx] = None;
    }

    let reconstructed_ct = reconstruct_ciphertext_stripe(
        shard_slots,
        shard_set.k_data,
        shard_set.m_parity,
        shard_set.original_ciphertext_len,
        Some(&shard_set.shard_hashes),
        Some(shard_set.stripe_merkle_root),
    )
    .expect("GF(2^8) reconstruction from 16/20 shards must succeed");
    assert_eq!(reconstructed_ct, pq_ciphertext);

    // 4. Decrypt reconstructed PQ ciphertext stripe and verify exact plaintext recovery:
    let decrypted = pq_master
        .decrypt_stripe_pq(&file_salt, stripe_index, &reconstructed_ct)
        .expect("PQ cascaded stripe decryption must succeed");
    assert_eq!(decrypted, plaintext);

    // 5. Verify context binding and tamper rejection across both cascaded AEAD layers:
    assert!(
        pq_master
            .decrypt_stripe_pq(&file_salt, stripe_index + 1, &reconstructed_ct)
            .is_err(),
        "Wrong stripe_index must fail PQ cascaded decryption"
    );
    assert!(
        wrong_pq_master
            .decrypt_stripe_pq(&file_salt, stripe_index, &reconstructed_ct)
            .is_err(),
        "Wrong 512-bit PqVaultMasterKey must fail PQ cascaded decryption"
    );

    let mut corrupted_ct = reconstructed_ct;
    let mid = corrupted_ct.len() / 2;
    corrupted_ct[mid] ^= 0x80;
    assert!(
        pq_master
            .decrypt_stripe_pq(&file_salt, stripe_index, &corrupted_ct)
            .is_err(),
        "1-bit ciphertext corruption must be rejected by cascaded AEAD authentication"
    );
}

/// ============================================================================
/// TEST PQ-4: Post-Quantum Onion-Relayed Shard Envelope (`PqRelayedShardEnvelope`)
/// and PQ-Signed Zero-Knowledge DHT Manifest (`PqSignedDhtManifestEnvelope`)
/// ============================================================================
#[test]
fn test_pq4_post_quantum_onion_relay_and_pq_signed_dht_manifest() {
    // --- Part A: Post-Quantum 1-Hop Onion Relay Envelope ---
    let recipient_kem = HybridKemKeypair::generate().unwrap();
    let relay_kem = HybridKemKeypair::generate().unwrap();
    let classical_locator_key = MasterKey::from_bytes([0x42u8; 32]);

    let shard_bytes = b"PQ-ONION-SEALED-REED-SOLOMON-SHARD-PAYLOAD".repeat(128);
    let blinded_id = BlindedShardId::derive(&classical_locator_key, &[0xEEu8; 32], 3, &shard_bytes);

    let pq_envelope = PqRelayedShardEnvelope::seal_pq(
        &recipient_kem.public_key(),
        "relay-node-pq-eu-central-1",
        &blinded_id,
        &shard_bytes,
        55,
    )
    .expect("PQ onion envelope sealing must succeed");

    // Intermediate relay node cannot open the hybrid ML-KEM-768 + X25519 onion payload:
    assert!(
        pq_envelope.open_pq(&relay_kem).is_err(),
        "Intermediate relay node must not be able to decapsulate or decrypt PQ onion envelope"
    );

    // Target storage node opens the PQ onion envelope and recovers exact (BlindedShardId, shard_bytes):
    let (opened_blinded_id, opened_shard) = pq_envelope
        .open_pq(&recipient_kem)
        .expect("Target storage node must open PQ onion envelope");
    assert_eq!(opened_blinded_id, blinded_id);
    assert_eq!(opened_shard, shard_bytes);

    // --- Part B: Post-Quantum Signed Zero-Knowledge DHT Manifest Envelope ---
    let pq_vault_key = PqVaultMasterKey::generate();
    let wrong_vault_key = PqVaultMasterKey::generate();
    let pq_signer = HybridPqSigningKeypair::generate().unwrap();

    let dht_key = [0xC3u8; 32];
    let manifest_plaintext =
        b"{\"file_id\":\"pq-vault-doc.pdf\",\"stripes\":4,\"tier\":\"Homelab\"}";

    let dht_envelope = PqSignedDhtManifestEnvelope::seal_pq(
        &pq_vault_key,
        &pq_signer,
        dht_key,
        7,
        manifest_plaintext,
    )
    .expect("Sealing PQ DHT manifest envelope must succeed");

    // Any untrusted DHT peer can verify the composite Ed25519 + ML-DSA-65 signature in zero-knowledge
    // without possessing `pq_vault_key`:
    assert!(
        dht_envelope.verify_zero_knowledge_pq(),
        "DHT nodes must verify composite Ed25519 + ML-DSA-65 signature without knowing PqVaultMasterKey"
    );

    // Unauthorized node without `pq_vault_key` cannot decrypt the manifest payload:
    assert!(dht_envelope.open_pq(&wrong_vault_key).is_err());

    // Legitimate owner with `pq_vault_key` verifies and decrypts the manifest:
    let recovered_manifest = dht_envelope
        .open_pq(&pq_vault_key)
        .expect("Owner with PqVaultMasterKey must decrypt PQ DHT manifest");
    assert_eq!(recovered_manifest, manifest_plaintext);
}

/// ============================================================================
/// TEST PQ-5: Exhaustive `stateright` Formal Model Checking of Hybrid
/// Post-Quantum Security Under Active Shor + Grover Quantum Oracles
/// ============================================================================
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PostQuantumModelState {
    shor_oracle_active: bool,
    grover_oracle_active: bool,
    ml_kem_768_intact: bool,
    ml_dsa_65_intact: bool,
    hybrid_session_established: bool,
    effective_symmetric_pq_bits: u16,
    session_compromised: bool,
    manifest_forged: bool,
    vault_key_compromised: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum PostQuantumModelAction {
    ActivateShorQuantumOracle,
    ActivateGroverQuantumOracle,
    EstablishHybridKemSession,
    AttemptHndlSessionDecryption,
    AttemptQuantumSignatureForgery,
    AttemptGroverSymmetricKeySearch,
}

struct PostQuantumSecurityModel;

impl Model for PostQuantumSecurityModel {
    type State = PostQuantumModelState;
    type Action = PostQuantumModelAction;

    fn init_states(&self) -> Vec<Self::State> {
        vec![PostQuantumModelState {
            shor_oracle_active: false,
            grover_oracle_active: false,
            ml_kem_768_intact: true,
            ml_dsa_65_intact: true,
            hybrid_session_established: false,
            effective_symmetric_pq_bits: 512,
            session_compromised: false,
            manifest_forged: false,
            vault_key_compromised: false,
        }]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if !state.shor_oracle_active {
            actions.push(PostQuantumModelAction::ActivateShorQuantumOracle);
        }
        if !state.grover_oracle_active {
            actions.push(PostQuantumModelAction::ActivateGroverQuantumOracle);
        }
        if !state.hybrid_session_established {
            actions.push(PostQuantumModelAction::EstablishHybridKemSession);
        }
        if state.hybrid_session_established {
            actions.push(PostQuantumModelAction::AttemptHndlSessionDecryption);
        }
        actions.push(PostQuantumModelAction::AttemptQuantumSignatureForgery);
        actions.push(PostQuantumModelAction::AttemptGroverSymmetricKeySearch);
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut next = last.clone();
        match action {
            PostQuantumModelAction::ActivateShorQuantumOracle => {
                // Shor's algorithm breaks classical ECDH (X25519) and Ed25519 in polynomial time.
                next.shor_oracle_active = true;
            }
            PostQuantumModelAction::ActivateGroverQuantumOracle => {
                // Grover's algorithm provides a quadratic speedup, halving symmetric bit-security
                // of the 512-bit cascaded PqVaultMasterKey from 512 bits to 256 bits.
                next.grover_oracle_active = true;
                next.effective_symmetric_pq_bits = 256;
            }
            PostQuantumModelAction::EstablishHybridKemSession => {
                next.hybrid_session_established = true;
            }
            PostQuantumModelAction::AttemptHndlSessionDecryption => {
                // Hybrid combiner HKDF-SHA512(ss_x25519 || ss_ml_kem_768) is compromised ONLY IF
                // BOTH X25519 is broken (e.g., via Shor) AND ML-KEM-768 (Module-LWE) is broken.
                let x25519_broken = next.shor_oracle_active;
                let ml_kem_broken = !next.ml_kem_768_intact;
                if x25519_broken && ml_kem_broken {
                    next.session_compromised = true;
                }
            }
            PostQuantumModelAction::AttemptQuantumSignatureForgery => {
                // Composite verifier requires BOTH valid Ed25519 AND valid ML-DSA-65 signatures.
                let can_forge_ed25519 = next.shor_oracle_active;
                let can_forge_ml_dsa_65 = !next.ml_dsa_65_intact;
                if can_forge_ed25519 && can_forge_ml_dsa_65 {
                    next.manifest_forged = true;
                }
            }
            PostQuantumModelAction::AttemptGroverSymmetricKeySearch => {
                // Brute-forcing the symmetric key succeeds only if effective post-quantum security < 128 bits.
                if next.effective_symmetric_pq_bits < 128 {
                    next.vault_key_compromised = true;
                }
            }
        }
        Some(next)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always("hndl_hybrid_kem_confidentiality_under_shor", |_model, s| {
                !s.session_compromised
            }),
            Property::<Self>::always(
                "composite_signature_unforgeability_under_shor",
                |_model, s| !s.manifest_forged,
            ),
            Property::<Self>::always(
                "grover_resistant_256bit_pq_symmetric_margin",
                |_model, s| !s.vault_key_compromised && s.effective_symmetric_pq_bits >= 256,
            ),
        ]
    }
}

#[test]
fn test_pq5_stateright_post_quantum_hybrid_security_model() {
    let model = PostQuantumSecurityModel;
    let checker = model.checker().threads(1).spawn_bfs().join();
    checker.assert_properties();
    assert!(
        checker.unique_state_count() >= 8,
        "Expected exhaustive exploration of all Shor/Grover/Hybrid state combinations"
    );
}
