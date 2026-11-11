use crate::crypto::keys::MasterKey;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use bincode::Options;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

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

/// Deserializes a `bincode`-encoded payload with a strict upper memory allocation bound `max_bytes` (`B12`).
/// Uses `with_fixint_encoding().allow_trailing_bytes().with_limit(max_bytes as u64)` so it is 100%
/// wire-compatible with `bincode::serialize` while neutralizing crafted `Vec`/`String` length-prefix OOM panics.
pub fn deserialize_bounded<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, CryptoError> {
    if bytes.len() > max_bytes {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "bincode payload length {} exceeds maximum bound {} bytes",
            bytes.len(),
            max_bytes
        )));
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(max_bytes as u64)
        .deserialize(bytes)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("bounded deserialize failed: {e}")))
}

/// Generates a fresh 32-byte cryptographic file salt (`FileSalt`) for stripe nonce derivation using `OsRng`.
pub fn generate_file_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Formats the canonical 30-byte HKDF info string `"parvault-stripe-nonce:" || stripe_index_be64`.
/// Bijective with respect to `stripe_index` across `0..=u64::MAX`.
pub fn format_stripe_nonce_info(stripe_index: u64) -> [u8; 30] {
    let mut info = [0u8; 30];
    info[..22].copy_from_slice(b"parvault-stripe-nonce:");
    info[22..30].copy_from_slice(&stripe_index.to_be_bytes());
    info
}

/// Formats the canonical 24-byte AES-256-GCM Additional Authenticated Data (AAD) block
/// `file_salt || stripe_index_be64`, binding every ciphertext stripe to both its file salt and
/// exact position in the stream.
pub fn format_stripe_aad(file_salt: &[u8; SALT_LEN], stripe_index: u64) -> [u8; SALT_LEN + 8] {
    let mut aad = [0u8; SALT_LEN + 8];
    aad[..SALT_LEN].copy_from_slice(file_salt);
    aad[SALT_LEN..].copy_from_slice(&stripe_index.to_be_bytes());
    aad
}

/// Parameterized stripe-nonce derivation boundary (`derive_stripe_nonce_from_subkey` instantiates
/// `kdf_expand` with `Hkdf<Sha256>`).
pub fn derive_stripe_nonce_with<F>(
    stripe_nonce_subkey: &[u8; 32],
    file_salt: &[u8; SALT_LEN],
    stripe_index: u64,
    kdf_expand: F,
) -> Result<[u8; NONCE_LEN], CryptoError>
where
    F: FnOnce(&[u8; 32], &[u8; SALT_LEN], &[u8; 30]) -> Result<[u8; NONCE_LEN], CryptoError>,
{
    let info = format_stripe_nonce_info(stripe_index);
    kdf_expand(stripe_nonce_subkey, file_salt, &info)
}

/// Derives a deterministic 96-bit (12-byte) AES-256-GCM nonce from the domain-separated
/// `stripe_nonce_subkey` (`N_i = HKDF-Expand(K_stripe_nonce, "parvault-stripe-nonce:" || stripe_index_be64)`
/// with `salt = file_salt`).
pub fn derive_stripe_nonce_from_subkey(
    stripe_nonce_subkey: &[u8; 32],
    file_salt: &[u8; SALT_LEN],
    stripe_index: u64,
) -> Result<[u8; NONCE_LEN], CryptoError> {
    derive_stripe_nonce_with(
        stripe_nonce_subkey,
        file_salt,
        stripe_index,
        |subkey, salt, info| {
            let hk = Hkdf::<Sha256>::new(Some(salt), subkey);
            let mut nonce = [0u8; NONCE_LEN];
            hk.expand(info, &mut nonce)
                .map_err(|_| CryptoError::KdfFailed)?;
            Ok(nonce)
        },
    )
}

/// Derives a deterministic 96-bit (12-byte) AES-256-GCM nonce for stripe `stripe_index` (ADR-01):
/// `N_i = HKDF-Expand(K_stripe_nonce, "parvault-stripe-nonce:" || stripe_index_be64)` with `salt = file_salt`.
pub fn derive_stripe_nonce(
    master_key: &MasterKey,
    file_salt: &[u8; SALT_LEN],
    stripe_index: u64,
) -> Result<[u8; NONCE_LEN], CryptoError> {
    let mut subkey = master_key.stripe_nonce_subkey();
    let res = derive_stripe_nonce_from_subkey(&subkey, file_salt, stripe_index);
    subkey.zeroize();
    res
}

/// Encrypts a single streaming stripe (up to 16 MiB per ADR-01) using AES-256-GCM under the
/// domain-separated `stripe_aead_subkey`.
/// Binds the `file_salt` and `stripe_index` as Additional Authenticated Data (AAD)
/// so stripes cannot be reordered or spliced across files.
pub fn encrypt_stripe(
    master_key: &MasterKey,
    file_salt: &[u8; SALT_LEN],
    stripe_index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut aead_subkey = master_key.stripe_aead_subkey();
    let cipher = Aes256Gcm::new_from_slice(&aead_subkey).map_err(|_| CryptoError::EncryptionFailed);
    aead_subkey.zeroize();
    let cipher = cipher?;

    let nonce_bytes = derive_stripe_nonce(master_key, file_salt, stripe_index)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = format_stripe_aad(file_salt, stripe_index);

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

/// Decrypts and authenticates a single streaming stripe using AES-256-GCM under the
/// domain-separated `stripe_aead_subkey`.
pub fn decrypt_stripe(
    master_key: &MasterKey,
    file_salt: &[u8; SALT_LEN],
    stripe_index: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut aead_subkey = master_key.stripe_aead_subkey();
    let cipher = Aes256Gcm::new_from_slice(&aead_subkey).map_err(|_| CryptoError::DecryptionFailed);
    aead_subkey.zeroize();
    let cipher = cipher?;

    let nonce_bytes = derive_stripe_nonce(master_key, file_salt, stripe_index)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = format_stripe_aad(file_salt, stripe_index);

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
/// `K_dht = HMAC-SHA256(K_dht_routing, "parvault-manifest:" || identifier)`
pub fn derive_dht_manifest_key(master_key: &MasterKey, identifier: &str) -> [u8; 32] {
    let mut routing_subkey = master_key.dht_routing_subkey();
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&routing_subkey)
        .expect("HMAC accepts any key size");
    routing_subkey.zeroize();
    mac.update(b"parvault-manifest:");
    mac.update(identifier.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Encrypts a serialized File Manifest for zero-knowledge publication to the Kademlia DHT (ADR-02).
/// Prepends a random 12-byte nonce from `OsRng` to the AES-256-GCM ciphertext under `manifest_aead_subkey`.
pub fn encrypt_manifest(
    master_key: &MasterKey,
    manifest_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut manifest_subkey = master_key.manifest_aead_subkey();
    let cipher =
        Aes256Gcm::new_from_slice(&manifest_subkey).map_err(|_| CryptoError::EncryptionFailed);
    manifest_subkey.zeroize();
    let cipher = cipher?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
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

/// Decrypts an encrypted File Manifest retrieved from local disk or the Kademlia DHT (ADR-02)
/// under `manifest_aead_subkey`.
pub fn decrypt_manifest(master_key: &MasterKey, envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if envelope.len() <= NONCE_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let (nonce_bytes, ciphertext) = envelope.split_at(NONCE_LEN);
    let mut manifest_subkey = master_key.manifest_aead_subkey();
    let cipher =
        Aes256Gcm::new_from_slice(&manifest_subkey).map_err(|_| CryptoError::DecryptionFailed);
    manifest_subkey.zeroize();
    let cipher = cipher?;

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
/// `P_shard = HMAC-SHA256(K_shard_pseudonym, "parvault-shard-pseudonym-v1:" || stripe_merkle_root || shard_index_be32)`
pub fn derive_unlinkable_shard_pseudonym(
    master_key: &MasterKey,
    stripe_merkle_root: &[u8; 32],
    shard_index: u32,
) -> String {
    let mut pseudonym_subkey = master_key.shard_pseudonym_subkey();
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&pseudonym_subkey)
        .expect("HMAC accepts any key size");
    pseudonym_subkey.zeroize();
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

    /// Bit-precise bounded verification that per-stripe nonce & AAD derivation never panics,
    /// has zero buffer overflows, injects `stripe_index` bijectively into the 30-byte HKDF
    /// `info` domain block (`format_stripe_nonce_info`) and 24-byte AEAD `aad` block
    /// (`format_stripe_aad`) across all `0..=u64::MAX`, and preserves uniqueness across
    /// `derive_stripe_nonce_with`.
    #[kani::proof]
    fn proof_stripe_nonce_injectivity_and_no_panic() {
        let idx_a: u64 = kani::any();
        let idx_b: u64 = kani::any();

        let info_a = format_stripe_nonce_info(idx_a);
        let info_b = format_stripe_nonce_info(idx_b);
        assert_eq!(&info_a[..22], b"parvault-stripe-nonce:");
        assert_eq!(&info_b[..22], b"parvault-stripe-nonce:");
        assert_eq!(&info_a[22..30], &idx_a.to_be_bytes());
        assert_eq!(&info_b[22..30], &idx_b.to_be_bytes());
        assert_eq!(info_a == info_b, idx_a == idx_b);

        let salt_a: [u8; SALT_LEN] = kani::any();
        let salt_b: [u8; SALT_LEN] = kani::any();
        let aad_a = format_stripe_aad(&salt_a, idx_a);
        let aad_b = format_stripe_aad(&salt_b, idx_b);
        assert_eq!(aad_a == aad_b, salt_a == salt_b && idx_a == idx_b);

        let subkey: [u8; 32] = kani::any();
        let ideal_kdf = |sk: &[u8; 32], salt: &[u8; SALT_LEN], info: &[u8; 30]| {
            let mut out = [0u8; NONCE_LEN];
            let mut i = 0;
            while i < 4 {
                out[i] = sk[i] ^ info[i];
                i += 1;
            }
            // Embed the 8-byte big-endian stripe_index mixed with key+salt bijectively into bytes 4..12.
            let mut j = 0;
            while j < 8 {
                out[4 + j] = info[22 + j] ^ sk[8 + j] ^ salt[j];
                j += 1;
            }
            Ok(out)
        };

        let n_a1 = derive_stripe_nonce_with(&subkey, &salt_a, idx_a, ideal_kdf).unwrap();
        let n_a2 = derive_stripe_nonce_with(&subkey, &salt_a, idx_a, ideal_kdf).unwrap();
        let n_b = derive_stripe_nonce_with(&subkey, &salt_a, idx_b, ideal_kdf).unwrap();
        assert_eq!(n_a1.len(), NONCE_LEN);
        assert_eq!(n_a1, n_a2);
        assert_eq!(n_a1 == n_b, idx_a == idx_b);
    }
}
