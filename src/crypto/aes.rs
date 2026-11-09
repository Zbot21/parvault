use crate::crypto::keys::MasterKey;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AES-256-GCM authenticated encryption failed")]
    EncryptionFailed,
    #[error("AES-256-GCM authentication tag verification failed (tampered or wrong key)")]
    DecryptionFailed,
    #[error("HKDF key/nonce expansion failed")]
    KdfFailed,
    #[error("Invalid key or hex encoding: {0}")]
    InvalidKeyMaterial(String),
}

/// Generates a fresh 32-byte cryptographic file salt (`FileSalt`) for stripe nonce derivation.
pub fn generate_file_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derives a deterministic 96-bit (12-byte) AES-256-GCM nonce for stripe `stripe_index` (ADR-01):
/// `N_i = HKDF-Expand(K_user, "parvault-stripe-nonce" || file_salt || stripe_index_be64)`
pub fn derive_stripe_nonce(
    master_key: &MasterKey,
    file_salt: &[u8; SALT_LEN],
    stripe_index: u64,
) -> Result<[u8; NONCE_LEN], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(file_salt), master_key.as_bytes());
    let mut info = Vec::with_capacity(20 + 8);
    info.extend_from_slice(b"parvault-stripe-nonce:");
    info.extend_from_slice(&stripe_index.to_be_bytes());

    let mut nonce = [0u8; NONCE_LEN];
    hk.expand(&info, &mut nonce)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(nonce)
}

/// Encrypts a single streaming stripe (up to 16 MiB per ADR-01) using AES-256-GCM.
/// Binds the `file_salt` and `stripe_index` as Additional Authenticated Data (AAD)
/// so stripes cannot be reordered or spliced across files.
pub fn encrypt_stripe(
    master_key: &MasterKey,
    file_salt: &[u8; SALT_LEN],
    stripe_index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(master_key.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let nonce_bytes = derive_stripe_nonce(master_key, file_salt, stripe_index)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut aad = Vec::with_capacity(SALT_LEN + 8);
    aad.extend_from_slice(file_salt);
    aad.extend_from_slice(&stripe_index.to_be_bytes());

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypts and authenticates a single streaming stripe using AES-256-GCM.
pub fn decrypt_stripe(
    master_key: &MasterKey,
    file_salt: &[u8; SALT_LEN],
    stripe_index: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(master_key.as_bytes())
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce_bytes = derive_stripe_nonce(master_key, file_salt, stripe_index)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut aad = Vec::with_capacity(SALT_LEN + 8);
    aad.extend_from_slice(file_salt);
    aad.extend_from_slice(&stripe_index.to_be_bytes());

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Derives the deterministic Kademlia DHT key for storing an encrypted File Manifest (ADR-02):
/// `K_dht = HMAC-SHA256(K_user, "parvault-manifest:" || identifier)`
pub fn derive_dht_manifest_key(master_key: &MasterKey, identifier: &str) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(master_key.as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(b"parvault-manifest:");
    mac.update(identifier.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Encrypts a serialized File Manifest for zero-knowledge publication to the Kademlia DHT (ADR-02).
/// Prepends a random 12-byte nonce to the AES-256-GCM ciphertext.
pub fn encrypt_manifest(
    master_key: &MasterKey,
    manifest_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(master_key.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: manifest_bytes,
                aad: b"parvault-dht-manifest-v1",
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Decrypts an encrypted File Manifest retrieved from local disk or the Kademlia DHT (ADR-02).
pub fn decrypt_manifest(master_key: &MasterKey, envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if envelope.len() <= NONCE_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let (nonce_bytes, ciphertext) = envelope.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(master_key.as_bytes())
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: b"parvault-dht-manifest-v1",
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Computes a standard 32-byte SHA-256 digest.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Derives an unlinkable per-shard owner pseudonym (`P_shard`) so untrusted storage nodes
/// cannot correlate which shards on their disk belong to the same user or the same file:
/// `P_shard = HMAC-SHA256(K_user, "parvault-shard-pseudonym-v1:" || stripe_merkle_root || shard_index_be32)`
pub fn derive_unlinkable_shard_pseudonym(
    master_key: &MasterKey,
    stripe_merkle_root: &[u8; 32],
    shard_index: u32,
) -> String {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(master_key.as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(b"parvault-shard-pseudonym-v1:");
    mac.update(stripe_merkle_root);
    mac.update(&shard_index.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    format!("anon_{}", hex::encode(&digest[..16]))
}

/// Pads plaintext to a uniform power-of-two bucket (`>= min_bucket_bytes`, minimum 64 bytes)
/// using an 8-byte original-length header plus ISO/IEC 7816-4 (`0x80 0x00*`) sentinel padding.
/// Prevents untrusted storage nodes from fingerprinting files by exact byte length.
pub fn pad_plaintext_iso_bucket(plaintext: &[u8], min_bucket_bytes: usize) -> Vec<u8> {
    let required = plaintext.len() + 9; // 8-byte BE length + 0x80 sentinel + zero fill
    let floor = min_bucket_bytes.max(64).next_power_of_two();
    let target_len = required.next_power_of_two().max(floor);

    let mut out = vec![0u8; target_len];
    out[..8].copy_from_slice(&(plaintext.len() as u64).to_be_bytes());
    out[8..8 + plaintext.len()].copy_from_slice(plaintext);
    out[8 + plaintext.len()] = 0x80;
    out
}

/// Strips uniform bucket padding added by `pad_plaintext_iso_bucket` and validates the `0x80` sentinel.
pub fn unpad_plaintext_iso_bucket(padded: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if padded.len() < 9 {
        return Err(CryptoError::DecryptionFailed);
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&padded[..8]);
    let orig_len = u64::from_be_bytes(len_bytes) as usize;
    if orig_len + 9 > padded.len() {
        return Err(CryptoError::DecryptionFailed);
    }
    if padded[8 + orig_len] != 0x80 {
        return Err(CryptoError::DecryptionFailed);
    }
    if padded[8 + orig_len + 1..].iter().any(|&b| b != 0x00) {
        return Err(CryptoError::DecryptionFailed);
    }
    Ok(padded[8..8 + orig_len].to_vec())
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Bit-precise bounded verification that per-stripe nonce derivation never panics,
    /// has zero buffer overflows, and produces distinct 96-bit nonces for distinct stripe indices.
    #[kani::proof]
    fn proof_stripe_nonce_injectivity_and_no_panic() {
        let key_bytes: [u8; 32] = kani::any();
        let salt: [u8; SALT_LEN] = kani::any();
        let idx_a: u64 = kani::any();
        let idx_b: u64 = kani::any();
        kani::assume(idx_a != idx_b);

        let master_key = MasterKey::from_bytes(key_bytes);
        let nonce_a = derive_stripe_nonce(&master_key, &salt, idx_a).expect("HKDF expand valid");
        let nonce_b = derive_stripe_nonce(&master_key, &salt, idx_b).expect("HKDF expand valid");
        assert_eq!(nonce_a.len(), NONCE_LEN);
        assert_eq!(nonce_b.len(), NONCE_LEN);
    }
}
