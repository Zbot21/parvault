use crate::crypto::aes::deserialize_bounded;
use crate::crypto::{
    compute_sha256, decrypt_manifest, encrypt_manifest, pad_plaintext_iso_bucket,
    unpad_plaintext_iso_bucket, MasterKey, NodeIdentity,
};
use crate::storage::StorageError;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashSet, VecDeque};
use x25519_dalek::PublicKey as X25519Public;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Maximum bounded deserialization size for persisted voucher nullifier FIFO ledgers (4 MiB).
const MAX_NULLIFIER_LEDGER_BYTES: usize = 4 * 1024 * 1024;
/// Maximum bounded deserialization size for 1-hop onion inner payloads (32 MiB).
const MAX_ONION_INNER_BYTES: usize = 32 * 1024 * 1024;

/// Pads a shard payload to a uniform power-of-two bucket size (`>= bucket_bytes`, minimum 64 bytes)
/// using ISO/IEC 7816-4 (`0x80 0x00*`) sentinel padding (`D4`) so colluding storage nodes cannot
/// group the 20 shards of an erasure-coded stripe by identical non-bucketed shard byte lengths.
pub fn pad_shard_uniform_bucket(shard_bytes: &[u8], bucket_bytes: usize) -> Vec<u8> {
    pad_plaintext_iso_bucket(shard_bytes, bucket_bytes)
}

/// Strips uniform bucket padding added by `pad_shard_uniform_bucket` (`D4`).
pub fn unpad_shard_uniform_bucket(padded: &[u8]) -> Result<Vec<u8>, StorageError> {
    unpad_plaintext_iso_bucket(padded).map_err(StorageError::from)
}

/// Layer 1 (ADR-11): Opaque Blinded Shard Identifier stored on remote nodes.
/// Conceals both `stripe_merkle_root` and the Reed-Solomon matrix coordinate `shard_index` (`0..N-1`),
/// preventing colluding storage nodes from grouping shards of the same stripe or knowing
/// which Vandermonde/Cauchy evaluation point a shard corresponds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlindedShardId {
    /// `Locator_i = HMAC-SHA256(K_blind_locator, "parvault-blind-locator-v1:" || stripe_merkle_root || shard_index_be32)`
    pub locator: [u8; 32],
    /// Keyless SHA-256 content digest `SHA-256(shard_bytes)` for disk integrity verification.
    pub content_sha256: [u8; 32],
}

impl BlindedShardId {
    /// Derives an unlinkable 256-bit `BlindedShardId` for shard `shard_index` of `stripe_merkle_root`
    /// using the domain-separated `blind_locator_subkey` (`B1`).
    pub fn derive(
        master_key: &MasterKey,
        stripe_merkle_root: &[u8; 32],
        shard_index: u32,
        shard_bytes: &[u8],
    ) -> Self {
        let mut locator_subkey = master_key.blind_locator_subkey();
        let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&locator_subkey)
            .expect("HMAC accepts 32-byte key");
        locator_subkey.zeroize();
        mac.update(b"parvault-blind-locator-v1:");
        mac.update(stripe_merkle_root);
        mac.update(&shard_index.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let mut locator = [0u8; 32];
        locator.copy_from_slice(&result);

        let content_sha256 = compute_sha256(shard_bytes);
        Self {
            locator,
            content_sha256,
        }
    }

    /// Returns a filesystem-safe opaque filename key with zero stripe or index metadata.
    pub fn file_key(&self) -> String {
        format!(
            "blind_{}_{}",
            hex::encode(&self.locator[..16]),
            hex::encode(&self.content_sha256[..8])
        )
    }
}

/// Layer 2 (ADR-11): Per-Shard Blinded Read/Repair Capability Key.
/// Replaces shared `owner_pubkey` and `stripe_merkle_root` registration with an independent,
/// deterministic per-shard Ed25519 capability keypair `(cap_signing_key_i, V_i)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedShardCapability {
    pub locator: [u8; 32],
    pub capability_pubkey: [u8; 32],
}

/// Maximum bidirectional NTP clock-skew tolerance (30 seconds) for `BlindedShardCapability` read tokens (`ADR-15`).
pub const MAX_CAPABILITY_CLOCK_SKEW_MS: u64 = 30_000;

/// Maximum single bearer `AnonymousQuotaVoucher` credit ceiling (1 GiB) to prevent `u64::MAX` overflow exploits.
pub const MAX_SINGLE_VOUCHER_BYTES: u64 = 1024 * 1024 * 1024;

impl BlindedShardCapability {
    /// Deterministically derives the shard-specific Ed25519 `NodeIdentity` and public `BlindedShardCapability`
    /// from `(K_blind_capability, Locator_i)` via HKDF-SHA256 (`B1`).
    pub fn derive_keypair(master_key: &MasterKey, locator: &[u8; 32]) -> (NodeIdentity, Self) {
        let mut cap_subkey = master_key.blind_capability_subkey();
        let hk = Hkdf::<Sha256>::new(Some(locator), &cap_subkey);
        cap_subkey.zeroize();
        let mut seed = [0u8; 32];
        hk.expand(b"parvault-blind-capability-ed25519-v1", &mut seed)
            .expect("32-byte HKDF expand is always valid");

        let cap_identity = NodeIdentity::from_seed(seed);
        seed.zeroize();
        let capability = Self {
            locator: *locator,
            capability_pubkey: cap_identity.public_key_bytes(),
        };
        (cap_identity, capability)
    }

    /// Signs a zero-linkage read/repair authorization token for `locator` at `timestamp_ms`.
    pub fn sign_read_token(
        cap_identity: &NodeIdentity,
        locator: &[u8; 32],
        timestamp_ms: u64,
    ) -> [u8; 64] {
        let msg = Self::canonical_bytes(locator, timestamp_ms);
        cap_identity.sign(&msg)
    }

    /// Verifies a read/repair token against `self.capability_pubkey` without learning `owner_pubkey`
    /// or `stripe_merkle_root`.
    pub fn verify_read_token(&self, timestamp_ms: u64, signature: &[u8; 64]) -> bool {
        let msg = Self::canonical_bytes(&self.locator, timestamp_ms);
        NodeIdentity::verify_with_pubkey(&self.capability_pubkey, &msg, signature)
    }

    /// Verifies a read/repair token while enforcing a symmetric $\pm 30\text{ s}$ NTP clock-skew
    /// window around `now_unix_ms` (`ADR-15`), rejecting both expired tokens and far-future
    /// `timestamp_ms = u64::MAX` "immortal token" exploits.
    pub fn verify_read_token_with_skew(
        &self,
        timestamp_ms: u64,
        now_unix_ms: u64,
        signature: &[u8; 64],
    ) -> bool {
        if timestamp_ms.abs_diff(now_unix_ms) > MAX_CAPABILITY_CLOCK_SKEW_MS {
            return false;
        }
        self.verify_read_token(timestamp_ms, signature)
    }

    fn canonical_bytes(locator: &[u8; 32], timestamp_ms: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"parvault-blind-read-v1:");
        buf.extend_from_slice(locator);
        buf.extend_from_slice(&timestamp_ms.to_be_bytes());
        buf
    }
}

/// Layer 3 (ADR-11): Unlinkable Bearer Storage Quota Voucher.
/// Decouples storage reciprocity accounting from static `peer_id` identities so storage nodes
/// cannot link multiple shards to the same user account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonymousQuotaVoucher {
    pub voucher_nonce: [u8; 32],
    pub max_bytes: u64,
    pub issuer_pubkey: [u8; 32],
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl AnonymousQuotaVoucher {
    /// Mints a fresh single-use bearer storage voucher for up to `max_bytes` using `OsRng` (`E4`).
    pub fn mint(issuer: &NodeIdentity, max_bytes: u64) -> Self {
        let mut voucher_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut voucher_nonce);
        let issuer_pubkey = issuer.public_key_bytes();
        let msg = Self::canonical_bytes(&voucher_nonce, max_bytes, &issuer_pubkey);
        let sig = issuer.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Self {
            voucher_nonce,
            max_bytes,
            issuer_pubkey,
            sig_r,
            sig_s,
        }
    }

    /// Mints a per-shard unlinkable bearer voucher signed by an ephemeral sub-identity derived
    /// via `HKDF-SHA256` from `(epoch_seed, shard_locator)` (`D4`).
    /// Prevents colluding storage nodes from linking the 20 shards of a stripe via a static `issuer_pubkey`.
    pub fn mint_blinded_ephemeral(
        epoch_seed: &[u8; 32],
        shard_locator: &[u8; 32],
        max_bytes: u64,
    ) -> (NodeIdentity, Self) {
        let hk = Hkdf::<Sha256>::new(Some(shard_locator), epoch_seed);
        let mut ephem_seed = [0u8; 32];
        hk.expand(b"parvault-ephemeral-voucher-issuer-v2", &mut ephem_seed)
            .expect("32-byte HKDF expansion is always valid");
        let ephem_issuer = NodeIdentity::from_seed(ephem_seed);
        ephem_seed.zeroize();
        let voucher = Self::mint(&ephem_issuer, max_bytes);
        (ephem_issuer, voucher)
    }

    /// Verifies the issuer's Ed25519 signature over the bearer voucher and enforces `MAX_SINGLE_VOUCHER_BYTES`.
    pub fn verify(&self, trusted_issuer_pubkey: &[u8; 32]) -> bool {
        if &self.issuer_pubkey != trusted_issuer_pubkey
            || self.max_bytes == 0
            || self.max_bytes > MAX_SINGLE_VOUCHER_BYTES
        {
            return false;
        }
        let msg = Self::canonical_bytes(&self.voucher_nonce, self.max_bytes, &self.issuer_pubkey);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(trusted_issuer_pubkey, &msg, &sig)
    }

    fn canonical_bytes(
        voucher_nonce: &[u8; 32],
        max_bytes: u64,
        issuer_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(b"parvault-anon-voucher-v1:");
        buf.extend_from_slice(voucher_nonce);
        buf.extend_from_slice(&max_bytes.to_be_bytes());
        buf.extend_from_slice(issuer_pubkey);
        buf
    }
}

/// Maximum number of spent voucher nullifiers retained in the bounded FIFO replay cache (`ADR-16`).
pub const MAX_VOUCHER_NULLIFIER_ENTRIES: usize = 65_536;

/// Anti-double-spend nullifier ledger tracking redeemed `AnonymousQuotaVoucher` nonces
/// with a strict 65,536-entry FIFO ceiling (`ADR-16`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherNullifierLedger {
    trusted_issuer_pubkey: [u8; 32],
    spent_nonces: HashSet<[u8; 32]>,
    #[serde(default)]
    spent_fifo: VecDeque<[u8; 32]>,
    #[serde(skip)]
    persistence_path: Option<std::path::PathBuf>,
}

impl VoucherNullifierLedger {
    pub fn new(trusted_issuer_pubkey: [u8; 32]) -> Self {
        Self {
            trusted_issuer_pubkey,
            spent_nonces: HashSet::new(),
            spent_fifo: VecDeque::new(),
            persistence_path: None,
        }
    }

    /// Loads or initializes a persistent `VoucherNullifierLedger` at `data_dir/voucher_nullifiers.bin`
    /// using bounded deserialization (`B12`).
    pub fn with_persistence_dir(
        trusted_issuer_pubkey: [u8; 32],
        data_dir: &std::path::Path,
    ) -> Self {
        let path = data_dir.join("voucher_nullifiers.bin");
        let spent_fifo: VecDeque<[u8; 32]> = if path.exists() {
            std::fs::read(&path)
                .ok()
                .and_then(|raw| {
                    deserialize_bounded::<VecDeque<[u8; 32]>>(&raw, MAX_NULLIFIER_LEDGER_BYTES).ok()
                })
                .unwrap_or_default()
        } else {
            VecDeque::new()
        };
        let spent_nonces: HashSet<[u8; 32]> = spent_fifo.iter().copied().collect();
        Self {
            trusted_issuer_pubkey,
            spent_nonces,
            spent_fifo,
            persistence_path: Some(path),
        }
    }

    pub const fn issuer_pubkey(&self) -> [u8; 32] {
        self.trusted_issuer_pubkey
    }

    pub fn set_trusted_issuer_pubkey(&mut self, pubkey: [u8; 32]) {
        self.trusted_issuer_pubkey = pubkey;
    }

    /// Verifies and atomically redeems a single-use `AnonymousQuotaVoucher`.
    /// Rejects forged, under-sized, or previously spent vouchers, and enforces a bounded
    /// `MAX_VOUCHER_NULLIFIER_ENTRIES` (65,536) FIFO cache.
    pub fn redeem_voucher(
        &mut self,
        voucher: &AnonymousQuotaVoucher,
        shard_size_bytes: u64,
    ) -> Result<(), StorageError> {
        if shard_size_bytes > voucher.max_bytes || !voucher.verify(&self.trusted_issuer_pubkey) {
            return Err(StorageError::QuotaExceeded(
                "invalid_or_undersized_voucher".into(),
            ));
        }
        if self.spent_nonces.contains(&voucher.voucher_nonce) {
            return Err(StorageError::QuotaExceeded(
                "double_spent_voucher_nullifier".into(),
            ));
        }
        while self.spent_nonces.len() >= MAX_VOUCHER_NULLIFIER_ENTRIES {
            if let Some(oldest) = self.spent_fifo.pop_front() {
                self.spent_nonces.remove(&oldest);
            } else {
                break;
            }
        }
        self.spent_nonces.insert(voucher.voucher_nonce);
        self.spent_fifo.push_back(voucher.voucher_nonce);
        if let Some(ref path) = self.persistence_path {
            if let Ok(bytes) = bincode::serialize(&self.spent_fifo) {
                let _ = crate::storage::BlockStore::atomic_write_file(path, &bytes);
            }
        }
        Ok(())
    }

    pub fn spent_count(&self) -> usize {
        self.spent_nonces.len()
    }
}

#[derive(Serialize, Deserialize)]
struct OnionInnerPayload {
    blinded_id: BlindedShardId,
    shard_bytes: Vec<u8>,
}

/// Layer 4 (ADR-11): 1-Hop Onion-Encrypted Relay Envelope with Timing Jitter.
/// Conceals the owner's IP address and `PeerId` from the destination storage node while
/// concealing the `BlindedShardId` and shard payload from the intermediate relay node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayedShardEnvelope {
    pub relay_peer_id: String,
    pub ephemeral_x25519_pub: [u8; 32],
    pub encrypted_payload: Vec<u8>,
    pub jitter_delay_ms: u64,
}

impl RelayedShardEnvelope {
    const ONION_DOMAIN_TAG: [u8; 32] = *b"parvault-onion-relay-envelope-v1";

    /// Seals `(blinded_id, shard_bytes)` using ephemeral X25519 ECDH + AES-256-GCM addressed
    /// exclusively to `target_x25519_pub`.
    pub fn seal_for_target(
        target_x25519_pub: &[u8; 32],
        relay_peer_id: impl Into<String>,
        blinded_id: &BlindedShardId,
        shard_bytes: &[u8],
        jitter_delay_ms: u64,
    ) -> Result<Self, StorageError> {
        let ephem = NodeIdentity::generate();
        let target_pub = X25519Public::from(*target_x25519_pub);
        let mut shared_key_bytes =
            ephem.derive_por_session_key(&target_pub, &Self::ONION_DOMAIN_TAG)?;
        let shared_key = MasterKey::from_bytes(shared_key_bytes);
        shared_key_bytes.zeroize();

        let inner = OnionInnerPayload {
            blinded_id: *blinded_id,
            shard_bytes: shard_bytes.to_vec(),
        };
        let serialized = bincode::serialize(&inner)?;
        let encrypted_payload = encrypt_manifest(&shared_key, &serialized)?;

        Ok(Self {
            relay_peer_id: relay_peer_id.into(),
            ephemeral_x25519_pub: ephem.x25519_public().to_bytes(),
            encrypted_payload,
            jitter_delay_ms,
        })
    }

    /// Decrypts and authenticates the onion envelope on the destination storage node
    /// with bounded deserialization (`B12`).
    pub fn open_at_target(
        &self,
        target_identity: &NodeIdentity,
    ) -> Result<(BlindedShardId, Vec<u8>), StorageError> {
        let ephem_pub = X25519Public::from(self.ephemeral_x25519_pub);
        let mut shared_key_bytes =
            target_identity.derive_por_session_key(&ephem_pub, &Self::ONION_DOMAIN_TAG)?;
        let shared_key = MasterKey::from_bytes(shared_key_bytes);
        shared_key_bytes.zeroize();

        let decrypted = decrypt_manifest(&shared_key, &self.encrypted_payload)?;
        let inner: OnionInnerPayload =
            deserialize_bounded(&decrypted, MAX_ONION_INNER_BYTES).map_err(StorageError::from)?;
        Ok((inner.blinded_id, inner.shard_bytes))
    }
}

/// Computes the exact base-2 logarithm of the combinatorial search space faced by an
/// adversary attempting to brute-force group `k_data` shards out of `total_mesh_shards` (`M`)
/// and assign their ordered Reed-Solomon evaluation coordinates (`0..n_total`):
/// `EntropyBits = log2( C(M, K) * P(N, K) ) = sum_{i=0..K-1} log2((M - i) * (N - i) / (i + 1))`
pub fn combinatorial_reconstruction_entropy_bits(
    total_mesh_shards: u64,
    k_data: usize,
    n_total: usize,
) -> f64 {
    if total_mesh_shards < k_data as u64 || n_total < k_data || k_data == 0 {
        return 0.0;
    }
    let mut bits = 0.0f64;
    for i in 0..k_data {
        let m_term = (total_mesh_shards - i as u64) as f64;
        let k_denom = (i + 1) as f64;
        let n_perm = (n_total - i) as f64;
        bits += (m_term / k_denom).log2() + n_perm.log2();
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Voucher-rollover gap (plan 2c fact 5): once `MAX_VOUCHER_NULLIFIER_ENTRIES` other vouchers
    /// are redeemed, the first spent voucher is accepted again (FIFO eviction, no expiry).
    #[test]
    fn repro_spent_voucher_redeemable_after_rollover() {
        let issuer = NodeIdentity::from_seed([0x2C; 32]);
        let mut ledger = VoucherNullifierLedger::new(issuer.public_key_bytes());
        let first = AnonymousQuotaVoucher::mint(&issuer, 4096);
        ledger.redeem_voucher(&first, 1024).unwrap();
        assert!(
            ledger.redeem_voucher(&first, 1024).is_err(),
            "double spend refused"
        );
        // Fill the ledger to capacity behind `first` (state setup only: distinct nonces, no
        // signing), then redeem one real voucher: the ledger's own FIFO evicts `first`.
        for i in 1..MAX_VOUCHER_NULLIFIER_ENTRIES {
            let mut nonce = [0xEEu8; 32];
            nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
            ledger.spent_nonces.insert(nonce);
            ledger.spent_fifo.push_back(nonce);
        }
        assert_eq!(ledger.spent_nonces.len(), MAX_VOUCHER_NULLIFIER_ENTRIES);
        let next = AnonymousQuotaVoucher::mint(&issuer, 4096);
        ledger.redeem_voucher(&next, 1024).unwrap();
        assert!(
            ledger.redeem_voucher(&first, 1024).is_ok(),
            "gap: the spent voucher is redeemable again after rollover"
        );
    }

    #[test]
    fn test_ephemeral_blinded_vouchers_and_uniform_shard_bucket_padding() {
        let epoch_seed = [0x77u8; 32];
        let loc_0 = [0x01u8; 32];
        let loc_1 = [0x02u8; 32];

        let (issuer_0, v0) =
            AnonymousQuotaVoucher::mint_blinded_ephemeral(&epoch_seed, &loc_0, 8192);
        let (issuer_1, v1) =
            AnonymousQuotaVoucher::mint_blinded_ephemeral(&epoch_seed, &loc_1, 8192);
        assert_ne!(
            v0.issuer_pubkey, v1.issuer_pubkey,
            "ephemeral per-shard voucher issuers must be unlinkable across shards of the same stripe"
        );
        assert!(v0.verify(&issuer_0.public_key_bytes()));
        assert!(v1.verify(&issuer_1.public_key_bytes()));

        let raw_shard = vec![0xABu8; 1337];
        let padded = pad_shard_uniform_bucket(&raw_shard, 4096);
        assert_eq!(padded.len(), 4096);
        let unpadded = unpad_shard_uniform_bucket(&padded).expect("unpad");
        assert_eq!(unpadded, raw_shard);
    }
}
