use crate::crypto::aes::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

pub const KEY_LEN: usize = 32;
pub type KeyError = CryptoError;

/// Zero-knowledge 256-bit client master key (`K_user`).
#[derive(Clone, Serialize, Deserialize)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    /// Generates a cryptographically random 256-bit master key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let raw = hex::decode(hex_str.trim())
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        if raw.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "expected {} bytes, got {}",
                KEY_LEN,
                raw.len()
            )));
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&raw);
        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derives a cryptographically isolated 256-bit subkey for backup epoch `epoch` via HKDF-SHA256.
    pub fn derive_epoch_subkey(&self, epoch: u64) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(&epoch.to_be_bytes()), &self.0);
        let mut out = [0u8; KEY_LEN];
        hk.expand(b"parvault-epoch-subkey-v1", &mut out)
            .expect("32-byte HKDF expansion is always valid");
        Self(out)
    }

    /// Deterministically derives the 256-bit `MasterKey` from a memorized recovery seed phrase /
    /// 24-word mnemonic and `vault_namespace` ("House Fire" zero-local-state disaster recovery, ADR-15).
    /// Uses 10,000 rounds of domain-separated SHA-256 key stretching followed by HKDF-SHA256 expansion
    /// so no local `.manifest.bin` or OS salt file is needed to recover a destroyed machine.
    pub fn from_recovery_seed_phrase(seed_phrase: &str, vault_namespace: &str) -> Self {
        use sha2::Digest;
        let normalized_phrase = seed_phrase.trim();
        let normalized_ns = vault_namespace.trim();
        let mut state = [0u8; 32];
        let mut init_hasher = Sha256::new();
        init_hasher.update(b"parvault-dr-seed-init-v1:");
        init_hasher.update((normalized_ns.len() as u32).to_be_bytes());
        init_hasher.update(normalized_ns.as_bytes());
        init_hasher.update((normalized_phrase.len() as u32).to_be_bytes());
        init_hasher.update(normalized_phrase.as_bytes());
        state.copy_from_slice(&init_hasher.finalize());

        for round in 0..10_000u32 {
            let mut h = Sha256::new();
            h.update(b"parvault-dr-stretch-v1:");
            h.update(round.to_be_bytes());
            h.update(state);
            h.update(normalized_ns.as_bytes());
            state.copy_from_slice(&h.finalize());
        }

        let hk = Hkdf::<Sha256>::new(Some(normalized_ns.as_bytes()), &state);
        let mut out = [0u8; KEY_LEN];
        hk.expand(b"parvault-dr-master-key-v1", &mut out)
            .expect("32-byte HKDF expansion is always valid");
        Self(out)
    }

    /// Deterministically derives the Kademlia DHT lookup key for the user's encrypted root
    /// `FolderSnapshotManifest` superblock catalog (`ADR-15`), enabling full directory-tree
    /// discovery after total local disk loss.
    pub fn derive_vault_root_dht_key(&self, vault_namespace: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(vault_namespace.trim().as_bytes()), &self.0);
        let mut dht_key = [0u8; 32];
        hk.expand(b"parvault-vault-root-catalog-dht-v1", &mut dht_key)
            .expect("32-byte HKDF expansion is always valid");
        dht_key
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0u8);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Node cryptographic identity combining Ed25519 signing keys (for libp2p, WoT invitations,
/// and `RepairGrant` authorization) and X25519 Diffie-Hellman keys (for `K_session` PoR derivation).
#[derive(Clone)]
pub struct NodeIdentity {
    signing_key: SigningKey,
    x25519_secret: X25519Secret,
}

impl NodeIdentity {
    /// Generates a fresh node identity using OS CSPRNG.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let x25519_secret = X25519Secret::random_from_rng(OsRng);
        Self {
            signing_key,
            x25519_secret,
        }
    }

    /// Reconstructs deterministic node identity from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let x25519_secret = X25519Secret::from(seed);
        Self {
            signing_key,
            x25519_secret,
        }
    }

    /// Loads a persistent 32-byte node identity seed from `data_dir/node_identity.seed`,
    /// or generates and persists a fresh CSPRNG seed if none exists yet.
    pub fn load_or_generate_in_dir(data_dir: &Path) -> Result<Self, KeyError> {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        let seed_path = data_dir.join("node_identity.seed");
        if seed_path.exists() {
            let raw = std::fs::read(&seed_path)
                .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
            if raw.len() != 32 {
                return Err(CryptoError::InvalidKeyMaterial(format!(
                    "expected 32-byte node_identity.seed, got {} bytes",
                    raw.len()
                )));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw);
            Ok(Self::from_seed(seed))
        } else {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            std::fs::write(&seed_path, seed)
                .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
            Ok(Self::from_seed(seed))
        }
    }

    /// Returns a human-readable deterministic peer identifier derived from the node's Ed25519 public key.
    pub fn device_peer_id(&self) -> String {
        format!(
            "parvault-peer-{}",
            &hex::encode(self.public_key_bytes())[..16]
        )
    }

    /// Returns the raw 32-byte Ed25519 signing seed.
    pub fn signing_seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Deterministically derives the owner's `NodeIdentity` from a recovery seed phrase and
    /// `vault_namespace` (`ADR-15`) so the user can authenticate DHT catalog envelopes and
    /// owner shard reads on a replacement machine after a house fire.
    pub fn from_recovery_seed_phrase(seed_phrase: &str, vault_namespace: &str) -> Self {
        let mk = MasterKey::from_recovery_seed_phrase(seed_phrase, vault_namespace);
        let hk = Hkdf::<Sha256>::new(Some(vault_namespace.trim().as_bytes()), mk.as_bytes());
        let mut id_seed = [0u8; 32];
        hk.expand(b"parvault-dr-owner-node-identity-v1", &mut id_seed)
            .expect("32-byte HKDF expansion is always valid");
        Self::from_seed(id_seed)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn x25519_public(&self) -> X25519Public {
        X25519Public::from(&self.x25519_secret)
    }

    /// Signs an arbitrary message with the node's Ed25519 private key.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    /// Verifies an Ed25519 signature against a 32-byte public key.
    pub fn verify_with_pubkey(pubkey_bytes: &[u8; 32], msg: &[u8], sig_bytes: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(pubkey_bytes) else {
            return false;
        };
        let sig = Signature::from_bytes(sig_bytes);
        vk.verify(msg, &sig).is_ok()
    }

    /// Derives a shared 32-byte stateless Proof-of-Retrievability session key (`K_session`)
    /// with a peer or witness node using X25519 ECDH + HKDF-SHA256 (ADR-03).
    pub fn derive_por_session_key(
        &self,
        remote_x25519_pub: &X25519Public,
        merkle_root: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError> {
        let shared = self.x25519_secret.diffie_hellman(remote_x25519_pub);
        let hk = Hkdf::<Sha256>::new(Some(merkle_root), shared.as_bytes());
        let mut session_key = [0u8; 32];
        hk.expand(b"parvault-por-session-v1", &mut session_key)
            .map_err(|_| CryptoError::KdfFailed)?;
        Ok(session_key)
    }
}

/// Trait representing TPM 2.0 / hardware secure enclave key sealing on ISP gateways.
pub trait HardwareEnclaveSealer: Send + Sync {
    /// Seals raw key bytes to the gateway's PCR / enclave state.
    fn seal_key(&self, raw_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError>;
    /// Unseals a previously sealed blob back into a 32-byte key.
    fn unseal_key(&self, sealed_blob: &[u8]) -> Result<[u8; 32], CryptoError>;
}

/// Software sealing stub for development and non-TPM container environments (`deploy/Dockerfile.musl`).
pub struct SoftwareTpm2Stub {
    device_binding_key: MasterKey,
}

impl SoftwareTpm2Stub {
    pub fn new(device_binding_seed: [u8; 32]) -> Self {
        Self {
            device_binding_key: MasterKey::from_bytes(device_binding_seed),
        }
    }

    pub fn load_or_create_master_key(&self, sealed_path: &Path) -> anyhow::Result<MasterKey> {
        if sealed_path.exists() {
            let blob = std::fs::read(sealed_path)?;
            let raw = self.unseal_key(&blob)?;
            Ok(MasterKey::from_bytes(raw))
        } else {
            let key = MasterKey::generate();
            let blob = self.seal_key(key.as_bytes())?;
            if let Some(parent) = sealed_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(sealed_path, blob)?;
            Ok(key)
        }
    }
}

impl HardwareEnclaveSealer for SoftwareTpm2Stub {
    fn seal_key(&self, raw_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        crate::crypto::aes::encrypt_manifest(&self.device_binding_key, raw_key)
    }

    fn unseal_key(&self, sealed_blob: &[u8]) -> Result<[u8; 32], CryptoError> {
        let plain = crate::crypto::aes::decrypt_manifest(&self.device_binding_key, sealed_blob)?;
        if plain.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&plain);
        Ok(out)
    }
}
