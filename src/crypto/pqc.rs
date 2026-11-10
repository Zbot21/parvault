use crate::crypto::{
    compute_sha256, decrypt_manifest, decrypt_stripe, encrypt_manifest, encrypt_stripe,
    CryptoError, MasterKey, NodeIdentity,
};
use crate::storage::BlindedShardId;
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen as KemKeyGen, SerDes as KemSerDes};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes as DsaSerDes, Signer as DsaSigner, Verifier as DsaVerifier};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Domain-separation context string for NIST FIPS 204 `ML-DSA-65` signatures.
pub const ML_DSA_65_CONTEXT: &[u8] = b"parvault-pq-hybrid-dsa65-v1";
pub type PqcError = CryptoError;

/// Public key for Hybrid Post-Quantum Key Encapsulation (`X25519 + NIST FIPS 203 ML-KEM-768`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKemPublicKey {
    pub x25519_pub: [u8; 32],
    /// 1,184-byte NIST FIPS 203 `ML-KEM-768` encapsulation key.
    pub ml_kem_768_ek: Vec<u8>,
}

/// Ciphertext produced by Hybrid Post-Quantum Key Encapsulation (`X25519 + ML-KEM-768`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKemCiphertext {
    pub ephemeral_x25519_pub: [u8; 32],
    /// 1,088-byte NIST FIPS 203 `ML-KEM-768` ciphertext.
    pub ml_kem_768_ct: Vec<u8>,
}

/// Hybrid Post-Quantum Key-Encapsulation Keypair (`X25519 + NIST FIPS 203 ML-KEM-768` — ADR-12).
/// Provides IND-CCA2 security against both classical and Cryptographically Relevant Quantum
/// Computers (CRQCs) running Shor's Algorithm.
pub struct HybridKemKeypair {
    x25519_secret: X25519Secret,
    x25519_pub: [u8; 32],
    ml_kem_ek_bytes: Vec<u8>,
    ml_kem_dk_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StoredKemKeypair {
    x25519_seed: [u8; 32],
    ml_kem_ek_bytes: Vec<u8>,
    ml_kem_dk_bytes: Vec<u8>,
}

impl HybridKemKeypair {
    /// Generates a fresh hybrid `X25519 + ML-KEM-768` keypair.
    pub fn generate() -> Result<Self, CryptoError> {
        let x25519_secret = X25519Secret::random_from_rng(OsRng);
        let x25519_pub = X25519Public::from(&x25519_secret).to_bytes();

        let (ek, dk) = ml_kem_768::KG::try_keygen()
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-KEM-768 keygen: {e}")))?;

        Ok(Self {
            x25519_secret,
            x25519_pub,
            ml_kem_ek_bytes: ek.into_bytes().to_vec(),
            ml_kem_dk_bytes: dk.into_bytes().to_vec(),
        })
    }

    /// Loads or generates a persistent `HybridKemKeypair` in `data_dir/node_pq_kem.bin`.
    pub fn load_or_generate_in_dir(data_dir: &std::path::Path) -> Result<Self, CryptoError> {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        let path = data_dir.join("node_pq_kem.bin");
        if path.exists() {
            if let Ok(raw) = std::fs::read(&path) {
                if let Ok(stored) = bincode::deserialize::<StoredKemKeypair>(&raw) {
                    if stored.ml_kem_ek_bytes.len() == ml_kem_768::EK_LEN
                        && stored.ml_kem_dk_bytes.len() == ml_kem_768::DK_LEN
                    {
                        let x25519_secret = X25519Secret::from(stored.x25519_seed);
                        let x25519_pub = X25519Public::from(&x25519_secret).to_bytes();
                        return Ok(Self {
                            x25519_secret,
                            x25519_pub,
                            ml_kem_ek_bytes: stored.ml_kem_ek_bytes,
                            ml_kem_dk_bytes: stored.ml_kem_dk_bytes,
                        });
                    }
                }
            }
        }
        let mut x25519_seed = [0u8; 32];
        OsRng.fill_bytes(&mut x25519_seed);
        let x25519_secret = X25519Secret::from(x25519_seed);
        let x25519_pub = X25519Public::from(&x25519_secret).to_bytes();
        let (ek, dk) = ml_kem_768::KG::try_keygen()
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-KEM-768 keygen: {e}")))?;
        let ml_kem_ek_bytes = ek.into_bytes().to_vec();
        let ml_kem_dk_bytes = dk.into_bytes().to_vec();
        let stored = StoredKemKeypair {
            x25519_seed,
            ml_kem_ek_bytes: ml_kem_ek_bytes.clone(),
            ml_kem_dk_bytes: ml_kem_dk_bytes.clone(),
        };
        if let Ok(encoded) = bincode::serialize(&stored) {
            let _ = std::fs::write(&path, encoded);
        }
        Ok(Self {
            x25519_secret,
            x25519_pub,
            ml_kem_ek_bytes,
            ml_kem_dk_bytes,
        })
    }

    pub fn public_key(&self) -> HybridKemPublicKey {
        HybridKemPublicKey {
            x25519_pub: self.x25519_pub,
            ml_kem_768_ek: self.ml_kem_ek_bytes.clone(),
        }
    }

    /// Combines the classical `X25519` shared secret and post-quantum `ML-KEM-768` shared secret
    /// with transcript binding (`ephem_x25519_pub || SHA-256(ml_kem_ct)`) per NIST SP 800-227:
    /// Remains secure if EITHER `X25519` OR `ML-KEM-768` is unbroken.
    pub fn combine_hybrid_secrets(
        ss_x25519: &[u8; 32],
        ss_ml_kem: &[u8; 32],
        ephem_x25519_pub: &[u8; 32],
        ml_kem_ct: &[u8],
    ) -> [u8; 32] {
        let ct_hash = compute_sha256(ml_kem_ct);
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(ephem_x25519_pub);
        salt[32..].copy_from_slice(&ct_hash);

        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(ss_x25519);
        ikm[32..].copy_from_slice(ss_ml_kem);

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut hybrid_key = [0u8; 32];
        hk.expand(b"parvault-hybrid-x25519-mlkem768-v1", &mut hybrid_key)
            .expect("32-byte HKDF expansion is always valid");
        hybrid_key
    }

    /// Encapsulates a 256-bit hybrid shared secret to `recipient_pub`.
    pub fn encapsulate(
        recipient_pub: &HybridKemPublicKey,
    ) -> Result<([u8; 32], HybridKemCiphertext), CryptoError> {
        // 1. Classical X25519 ephemeral ECDH leg.
        let ephem_secret = X25519Secret::random_from_rng(OsRng);
        let ephemeral_x25519_pub = X25519Public::from(&ephem_secret).to_bytes();
        let target_x25519 = X25519Public::from(recipient_pub.x25519_pub);
        let ss_x25519 = ephem_secret.diffie_hellman(&target_x25519).to_bytes();

        // 2. Post-Quantum NIST FIPS 203 ML-KEM-768 leg.
        let ek_arr: [u8; ml_kem_768::EK_LEN] = recipient_pub
            .ml_kem_768_ek
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial("invalid ML-KEM-768 EK length".into()))?;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_arr)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-KEM-768 EK parse: {e}")))?;
        let (ss_pq, ct) = ek
            .try_encaps()
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-KEM-768 encaps: {e}")))?;
        let ss_ml_kem = ss_pq.into_bytes();
        let ml_kem_768_ct = ct.into_bytes().to_vec();

        // 3. Hybrid Key Combiner.
        let shared_secret = Self::combine_hybrid_secrets(
            &ss_x25519,
            &ss_ml_kem,
            &ephemeral_x25519_pub,
            &ml_kem_768_ct,
        );

        Ok((
            shared_secret,
            HybridKemCiphertext {
                ephemeral_x25519_pub,
                ml_kem_768_ct,
            },
        ))
    }

    /// Decapsulates a 256-bit hybrid shared secret from `ciphertext`.
    pub fn decapsulate(&self, ciphertext: &HybridKemCiphertext) -> Result<[u8; 32], CryptoError> {
        let peer_ephem = X25519Public::from(ciphertext.ephemeral_x25519_pub);
        let ss_x25519 = self.x25519_secret.diffie_hellman(&peer_ephem).to_bytes();

        let dk_arr: [u8; ml_kem_768::DK_LEN] =
            self.ml_kem_dk_bytes.as_slice().try_into().map_err(|_| {
                CryptoError::InvalidKeyMaterial("invalid ML-KEM-768 DK length".into())
            })?;
        let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_arr)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-KEM-768 DK parse: {e}")))?;

        let ct_arr: [u8; ml_kem_768::CT_LEN] = ciphertext
            .ml_kem_768_ct
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial("invalid ML-KEM-768 CT length".into()))?;
        let ct = ml_kem_768::CipherText::try_from_bytes(ct_arr)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-KEM-768 CT parse: {e}")))?;

        let ss_pq = dk
            .try_decaps(&ct)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-KEM-768 decaps: {e}")))?;
        let ss_ml_kem = ss_pq.into_bytes();

        Ok(Self::combine_hybrid_secrets(
            &ss_x25519,
            &ss_ml_kem,
            &ciphertext.ephemeral_x25519_pub,
            &ciphertext.ml_kem_768_ct,
        ))
    }
}

/// Public key for Composite Post-Quantum Digital Signatures (`Ed25519 + NIST FIPS 204 ML-DSA-65`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPqPublicKey {
    pub ed25519_pub: [u8; 32],
    /// 1,952-byte NIST FIPS 204 `ML-DSA-65` verifying key.
    pub ml_dsa_65_pk: Vec<u8>,
}

impl HybridPqPublicKey {
    /// Serializes this composite post-quantum public key to a hex string.
    pub fn to_hex(&self) -> Result<String, PqcError> {
        let bytes =
            bincode::serialize(self).map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        Ok(hex::encode(bytes))
    }

    /// Deserializes a composite post-quantum public key from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, PqcError> {
        let raw = hex::decode(hex_str.trim())
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        let pk: Self = bincode::deserialize(&raw)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        if pk.ml_dsa_65_pk.len() != ml_dsa_65::PK_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "invalid ML-DSA-65 public key length: {}",
                pk.ml_dsa_65_pk.len()
            )));
        }
        Ok(pk)
    }

    /// Returns a 16-hex-character SHA-256 fingerprint over `ed25519_pub || ml_dsa_65_pk`.
    pub fn fingerprint_hex(&self) -> String {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(self.ed25519_pub);
        hasher.update(&self.ml_dsa_65_pk);
        let digest = hasher.finalize();
        hex::encode(digest)[..16].to_string()
    }
}

#[derive(Serialize, Deserialize)]
struct StoredPqKeypair {
    ed25519_seed: [u8; 32],
    ml_dsa_65_pk: Vec<u8>,
    ml_dsa_65_sk: Vec<u8>,
}

/// Composite signature requiring BOTH `Ed25519` AND `ML-DSA-65` (Dilithium3) verification (ADR-12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPqSignature {
    pub ed25519_sig: Vec<u8>,
    /// 3,309-byte NIST FIPS 204 `ML-DSA-65` lattice signature.
    pub ml_dsa_65_sig: Vec<u8>,
}

/// Composite Post-Quantum Signing Keypair (`Ed25519 + NIST FIPS 204 ML-DSA-65`).
/// Defeats quantum signature forgery under Shor's Algorithm.
pub struct HybridPqSigningKeypair {
    classical_identity: NodeIdentity,
    ml_dsa_pk_bytes: Vec<u8>,
    ml_dsa_sk_bytes: Vec<u8>,
}

impl HybridPqSigningKeypair {
    pub fn generate() -> Result<Self, CryptoError> {
        let classical_identity = NodeIdentity::generate();
        let (pk, sk) = ml_dsa_65::try_keygen()
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-DSA-65 keygen: {e}")))?;

        Ok(Self {
            classical_identity,
            ml_dsa_pk_bytes: pk.into_bytes().to_vec(),
            ml_dsa_sk_bytes: sk.into_bytes().to_vec(),
        })
    }

    /// Loads the owner's composite `Ed25519 + ML-DSA-65` signing keypair from
    /// `data_dir/owner_pq_keypair.bin`, or generates and persists a new keypair if absent.
    pub fn load_or_generate_in_dir(data_dir: &std::path::Path) -> Result<Self, PqcError> {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        let path = data_dir.join("owner_pq_keypair.bin");
        if path.exists() {
            let raw =
                std::fs::read(&path).map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
            let stored: StoredPqKeypair = bincode::deserialize(&raw)
                .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
            let pk_arr: [u8; ml_dsa_65::PK_LEN] =
                stored.ml_dsa_65_pk.as_slice().try_into().map_err(|_| {
                    CryptoError::InvalidKeyMaterial("invalid ML-DSA-65 PK length".into())
                })?;
            let _ = ml_dsa_65::PublicKey::try_from_bytes(pk_arr)
                .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-DSA-65 PK parse: {e}")))?;
            let sk_arr: [u8; ml_dsa_65::SK_LEN] =
                stored.ml_dsa_65_sk.as_slice().try_into().map_err(|_| {
                    CryptoError::InvalidKeyMaterial("invalid ML-DSA-65 SK length".into())
                })?;
            let _ = ml_dsa_65::PrivateKey::try_from_bytes(sk_arr)
                .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-DSA-65 SK parse: {e}")))?;
            Ok(Self {
                classical_identity: NodeIdentity::from_seed(stored.ed25519_seed),
                ml_dsa_pk_bytes: stored.ml_dsa_65_pk,
                ml_dsa_sk_bytes: stored.ml_dsa_65_sk,
            })
        } else {
            let kp = Self::generate()?;
            let stored = StoredPqKeypair {
                ed25519_seed: kp.classical_identity.signing_seed_bytes(),
                ml_dsa_65_pk: kp.ml_dsa_pk_bytes.clone(),
                ml_dsa_65_sk: kp.ml_dsa_sk_bytes.clone(),
            };
            let encoded = bincode::serialize(&stored)
                .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
            std::fs::write(&path, encoded)
                .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
            Ok(kp)
        }
    }

    pub fn classical_identity(&self) -> &NodeIdentity {
        &self.classical_identity
    }

    pub fn public_key(&self) -> HybridPqPublicKey {
        HybridPqPublicKey {
            ed25519_pub: self.classical_identity.public_key_bytes(),
            ml_dsa_65_pk: self.ml_dsa_pk_bytes.clone(),
        }
    }

    /// Produces a composite `Ed25519 + ML-DSA-65` signature over `message`.
    pub fn sign(&self, message: &[u8]) -> Result<HybridPqSignature, CryptoError> {
        let ed25519_sig = self.classical_identity.sign(message).to_vec();

        let sk_arr: [u8; ml_dsa_65::SK_LEN] =
            self.ml_dsa_sk_bytes.as_slice().try_into().map_err(|_| {
                CryptoError::InvalidKeyMaterial("invalid ML-DSA-65 SK length".into())
            })?;
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_arr)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-DSA-65 SK parse: {e}")))?;
        let pq_sig = sk
            .try_sign(message, ML_DSA_65_CONTEXT)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ML-DSA-65 sign: {e}")))?;

        Ok(HybridPqSignature {
            ed25519_sig,
            ml_dsa_65_sig: pq_sig.to_vec(),
        })
    }

    /// Verifies a composite `HybridPqSignature`. Returns `true` IF AND ONLY IF both the
    /// `Ed25519` signature AND the NIST FIPS 204 `ML-DSA-65` lattice signature are valid.
    pub fn verify(
        pubkey: &HybridPqPublicKey,
        message: &[u8],
        signature: &HybridPqSignature,
    ) -> bool {
        let Ok(ed_sig): Result<[u8; 64], _> = signature.ed25519_sig.as_slice().try_into() else {
            return false;
        };
        if !NodeIdentity::verify_with_pubkey(&pubkey.ed25519_pub, message, &ed_sig) {
            return false;
        }

        let Ok(pk_arr): Result<[u8; ml_dsa_65::PK_LEN], _> =
            pubkey.ml_dsa_65_pk.as_slice().try_into()
        else {
            return false;
        };
        let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_arr) else {
            return false;
        };

        let Ok(sig_arr): Result<[u8; ml_dsa_65::SIG_LEN], _> =
            signature.ml_dsa_65_sig.as_slice().try_into()
        else {
            return false;
        };

        pk.verify(message, &sig_arr, ML_DSA_65_CONTEXT)
    }
}

/// 512-bit (64-byte) Grover-Resistant Post-Quantum Vault Master Key (`ADR-12`).
/// Provides 256 bits of Post-Quantum security against Grover's quadratic search algorithm
/// ($\sqrt{2^{512}} = 2^{256}$) via dual-key cascaded authenticated encryption.
#[derive(Clone)]
pub struct PqVaultMasterKey([u8; 64]);

impl PqVaultMasterKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Deterministically derives a 512-bit Grover-resistant `PqVaultMasterKey` from a memorized
    /// recovery seed phrase and `vault_namespace` (`ADR-15` zero-local-state disaster recovery).
    /// Directly stretches into a full 64-byte root seed via Argon2id (without bottlenecking through a 32-byte key).
    pub fn from_recovery_seed_phrase(seed_phrase: &str, vault_namespace: &str) -> Self {
        use argon2::{Algorithm, Argon2, Params, Version};
        use sha2::Digest;
        let normalized_phrase = seed_phrase.trim();
        let normalized_ns = vault_namespace.trim();
        let mut salt_hasher = Sha256::new();
        salt_hasher.update(b"parvault-dr-pq512-argon2id-salt-v1:");
        salt_hasher.update((normalized_ns.len() as u32).to_be_bytes());
        salt_hasher.update(normalized_ns.as_bytes());
        let salt: [u8; 32] = salt_hasher.finalize().into();

        let params = Params::new(4096, 2, 1, Some(64)).expect("valid 64-byte Argon2id parameters");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut root_seed_64 = [0u8; 64];
        argon2
            .hash_password_into(normalized_phrase.as_bytes(), &salt, &mut root_seed_64)
            .expect("Argon2id 64-byte password hashing succeeds");

        let mut pq_bytes = [0u8; 64];
        let hk_lo = Hkdf::<Sha256>::new(Some(normalized_ns.as_bytes()), &root_seed_64[..32]);
        let hk_hi = Hkdf::<Sha256>::new(Some(normalized_ns.as_bytes()), &root_seed_64[32..64]);
        hk_lo
            .expand(
                b"parvault-dr-pq512-vault-master-key-lo-v1",
                &mut pq_bytes[..32],
            )
            .expect("32-byte HKDF expansion is always valid");
        hk_hi
            .expand(
                b"parvault-dr-pq512-vault-master-key-hi-v1",
                &mut pq_bytes[32..64],
            )
            .expect("32-byte HKDF expansion is always valid");
        Self(pq_bytes)
    }

    fn split_subkeys(&self) -> (MasterKey, MasterKey) {
        let hk1 = Hkdf::<Sha256>::new(Some(b"parvault-pq512-key-split-k1-v1"), &self.0[..32]);
        let hk2 = Hkdf::<Sha256>::new(Some(b"parvault-pq512-key-split-k2-v1"), &self.0[32..64]);
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        hk1.expand(b"parvault-pq-layer1-aes256gcm", &mut k1)
            .expect("32-byte HKDF");
        hk2.expand(b"parvault-pq-layer2-chacha20poly1305", &mut k2)
            .expect("32-byte HKDF");
        (MasterKey::from_bytes(k1), MasterKey::from_bytes(k2))
    }

    fn derive_chacha_nonce_and_aad(
        k2: &MasterKey,
        file_salt: &[u8; 32],
        stripe_index: u64,
    ) -> ([u8; 12], [u8; 40]) {
        let mut info = [0u8; 40];
        info[..32].copy_from_slice(file_salt);
        info[32..40].copy_from_slice(&stripe_index.to_be_bytes());
        let hk = Hkdf::<Sha256>::new(Some(&info), k2.as_bytes());
        let mut nonce = [0u8; 12];
        hk.expand(b"parvault-pq-layer2-chacha20poly1305-nonce-v1", &mut nonce)
            .expect("12-byte HKDF");
        (nonce, info)
    }

    /// Dual-layer cascaded authenticated stripe encryption (`AES-256-GCM` inner + `ChaCha20-Poly1305` outer)
    /// under two independent 256-bit keys derived from the 512-bit `PqVaultMasterKey`.
    pub fn encrypt_stripe_pq(
        &self,
        file_salt: &[u8; 32],
        stripe_index: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Nonce,
        };
        let (k1, k2) = self.split_subkeys();
        let inner_ct = encrypt_stripe(&k1, file_salt, stripe_index, plaintext)?;
        let (nonce_bytes, aad) = Self::derive_chacha_nonce_and_aad(&k2, file_salt, stripe_index);
        let cipher = ChaCha20Poly1305::new(k2.as_bytes().into());
        cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &inner_ct,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    /// Decrypts and authenticates both layers (`ChaCha20-Poly1305` outer + `AES-256-GCM` inner)
    /// of a 512-bit cascaded Post-Quantum stripe.
    pub fn decrypt_stripe_pq(
        &self,
        file_salt: &[u8; 32],
        stripe_index: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Nonce,
        };
        let (k1, k2) = self.split_subkeys();
        let (nonce_bytes, aad) = Self::derive_chacha_nonce_and_aad(&k2, file_salt, stripe_index);
        let cipher = ChaCha20Poly1305::new(k2.as_bytes().into());
        let inner_ct = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?;
        decrypt_stripe(&k1, file_salt, stripe_index, &inner_ct)
    }
}

impl Drop for PqVaultMasterKey {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0u8);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Serialize, Deserialize)]
struct PqOnionInner {
    blinded_id: BlindedShardId,
    shard_bytes: Vec<u8>,
}

/// Harvest-Now, Decrypt-Later (HNDL) Immune 1-Hop Onion Relay Envelope (`X25519 + ML-KEM-768`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqRelayedShardEnvelope {
    pub relay_peer_id: String,
    pub hybrid_kem_ciphertext: HybridKemCiphertext,
    pub encrypted_payload: Vec<u8>,
    pub jitter_delay_ms: u64,
}

impl PqRelayedShardEnvelope {
    pub fn seal_pq(
        recipient_pub: &HybridKemPublicKey,
        relay_peer_id: impl Into<String>,
        blinded_id: &BlindedShardId,
        shard_bytes: &[u8],
        jitter_delay_ms: u64,
    ) -> Result<Self, CryptoError> {
        let (shared_secret, hybrid_kem_ciphertext) = HybridKemKeypair::encapsulate(recipient_pub)?;
        let session_key = MasterKey::from_bytes(shared_secret);

        let inner = PqOnionInner {
            blinded_id: *blinded_id,
            shard_bytes: shard_bytes.to_vec(),
        };
        let raw = bincode::serialize(&inner)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        let encrypted_payload = encrypt_manifest(&session_key, &raw)?;

        Ok(Self {
            relay_peer_id: relay_peer_id.into(),
            hybrid_kem_ciphertext,
            encrypted_payload,
            jitter_delay_ms,
        })
    }

    pub fn open_pq(
        &self,
        recipient_kem: &HybridKemKeypair,
    ) -> Result<(BlindedShardId, Vec<u8>), CryptoError> {
        let shared_secret = recipient_kem.decapsulate(&self.hybrid_kem_ciphertext)?;
        let session_key = MasterKey::from_bytes(shared_secret);
        let raw = decrypt_manifest(&session_key, &self.encrypted_payload)?;
        let inner: PqOnionInner =
            bincode::deserialize(&raw).map_err(|_| CryptoError::DecryptionFailed)?;
        Ok((inner.blinded_id, inner.shard_bytes))
    }
}

/// Post-Quantum Signed Monotonic Kademlia DHT Manifest Envelope (`Ed25519 + ML-DSA-65` + 512-Bit Cascaded AEAD).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignedDhtManifestEnvelope {
    pub dht_key: [u8; 32],
    pub owner_pq_pubkey: HybridPqPublicKey,
    pub monotonic_version: u64,
    pub ciphertext_sha256: [u8; 32],
    pub encrypted_manifest: Vec<u8>,
    pub hybrid_signature: HybridPqSignature,
}

impl PqSignedDhtManifestEnvelope {
    pub fn seal_pq(
        pq_master_key: &PqVaultMasterKey,
        signer: &HybridPqSigningKeypair,
        dht_key: [u8; 32],
        monotonic_version: u64,
        manifest_bytes: &[u8],
    ) -> Result<Self, CryptoError> {
        let encrypted_manifest =
            pq_master_key.encrypt_stripe_pq(&dht_key, monotonic_version, manifest_bytes)?;
        let ciphertext_sha256 = compute_sha256(&encrypted_manifest);
        let owner_pq_pubkey = signer.public_key();

        let msg = Self::canonical_bytes(
            &dht_key,
            &owner_pq_pubkey,
            monotonic_version,
            &ciphertext_sha256,
        );
        let hybrid_signature = signer.sign(&msg)?;

        Ok(Self {
            dht_key,
            owner_pq_pubkey,
            monotonic_version,
            ciphertext_sha256,
            encrypted_manifest,
            hybrid_signature,
        })
    }

    /// Verifies both the `Ed25519` and NIST FIPS 204 `ML-DSA-65` signatures and SHA-256 commitment
    /// in zero knowledge (without `pq_master_key`).
    pub fn verify_zero_knowledge_pq(&self) -> bool {
        if self.monotonic_version == 0 {
            return false;
        }
        if compute_sha256(&self.encrypted_manifest) != self.ciphertext_sha256 {
            return false;
        }
        let msg = Self::canonical_bytes(
            &self.dht_key,
            &self.owner_pq_pubkey,
            self.monotonic_version,
            &self.ciphertext_sha256,
        );
        HybridPqSigningKeypair::verify(&self.owner_pq_pubkey, &msg, &self.hybrid_signature)
    }

    pub fn open_pq(&self, pq_master_key: &PqVaultMasterKey) -> Result<Vec<u8>, CryptoError> {
        if !self.verify_zero_knowledge_pq() {
            return Err(CryptoError::DecryptionFailed);
        }
        pq_master_key.decrypt_stripe_pq(
            &self.dht_key,
            self.monotonic_version,
            &self.encrypted_manifest,
        )
    }

    fn canonical_bytes(
        dht_key: &[u8; 32],
        owner_pq_pubkey: &HybridPqPublicKey,
        monotonic_version: u64,
        ciphertext_sha256: &[u8; 32],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(132 + owner_pq_pubkey.ml_dsa_65_pk.len());
        buf.extend_from_slice(b"parvault-pq-dht-env-v1:");
        buf.extend_from_slice(dht_key);
        buf.extend_from_slice(&owner_pq_pubkey.ed25519_pub);
        buf.extend_from_slice(&(owner_pq_pubkey.ml_dsa_65_pk.len() as u32).to_be_bytes());
        buf.extend_from_slice(&owner_pq_pubkey.ml_dsa_65_pk);
        buf.extend_from_slice(&monotonic_version.to_be_bytes());
        buf.extend_from_slice(ciphertext_sha256);
        buf
    }
}
