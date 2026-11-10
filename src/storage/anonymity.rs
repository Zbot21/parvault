use crate::crypto::{compute_sha256, decrypt_manifest, encrypt_manifest, MasterKey, NodeIdentity};
use crate::storage::StorageError;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use x25519_dalek::PublicKey as X25519Public;

type HmacSha256 = Hmac<Sha256>;

/// Layer 1 (ADR-11): Opaque Blinded Shard Identifier stored on remote nodes.
/// Conceals both `stripe_merkle_root` and the Reed-Solomon matrix coordinate `shard_index` (`0..N-1`),
/// preventing colluding storage nodes from grouping shards of the same stripe or knowing
/// which Vandermonde/Cauchy evaluation point a shard corresponds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlindedShardId {
    /// `Locator_i = HMAC-SHA256(K_user, "parvault-blind-locator-v1:" || stripe_merkle_root || shard_index_be32)`
    pub locator: [u8; 32],
    /// Keyless SHA-256 content digest `SHA-256(shard_bytes)` for disk integrity verification.
    pub content_sha256: [u8; 32],
}

impl BlindedShardId {
    /// Derives an unlinkable 256-bit `BlindedShardId` for shard `shard_index` of `stripe_merkle_root`.
    pub fn derive(
        master_key: &MasterKey,
        stripe_merkle_root: &[u8; 32],
        shard_index: u32,
        shard_bytes: &[u8],
    ) -> Self {
        let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(master_key.as_bytes())
            .expect("HMAC accepts 32-byte key");
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
    /// from `(K_user, Locator_i)` via HKDF-SHA256.
    pub fn derive_keypair(master_key: &MasterKey, locator: &[u8; 32]) -> (NodeIdentity, Self) {
        let hk = Hkdf::<Sha256>::new(Some(locator), master_key.as_bytes());
        let mut seed = [0u8; 32];
        hk.expand(b"parvault-blind-capability-ed25519-v1", &mut seed)
            .expect("32-byte HKDF expand is always valid");

        let cap_identity = NodeIdentity::from_seed(seed);
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
    /// Mints a fresh single-use bearer storage voucher for up to `max_bytes`.
    pub fn mint(issuer: &NodeIdentity, max_bytes: u64) -> Self {
        let mut voucher_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut voucher_nonce);
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

/// Anti-double-spend nullifier ledger tracking redeemed `AnonymousQuotaVoucher` nonces.
#[derive(Debug, Clone)]
pub struct VoucherNullifierLedger {
    trusted_issuer_pubkey: [u8; 32],
    spent_nonces: HashSet<[u8; 32]>,
}

impl VoucherNullifierLedger {
    pub fn new(trusted_issuer_pubkey: [u8; 32]) -> Self {
        Self {
            trusted_issuer_pubkey,
            spent_nonces: HashSet::new(),
        }
    }

    pub const fn issuer_pubkey(&self) -> [u8; 32] {
        self.trusted_issuer_pubkey
    }

    pub fn set_trusted_issuer_pubkey(&mut self, pubkey: [u8; 32]) {
        self.trusted_issuer_pubkey = pubkey;
    }

    /// Verifies and atomically redeems a single-use `AnonymousQuotaVoucher`.
    /// Rejects forged, under-sized, or previously spent vouchers.
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
        if !self.spent_nonces.insert(voucher.voucher_nonce) {
            return Err(StorageError::QuotaExceeded(
                "double_spent_voucher_nullifier".into(),
            ));
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
        let shared_key_bytes =
            ephem.derive_por_session_key(&target_pub, &Self::ONION_DOMAIN_TAG)?;
        let shared_key = MasterKey::from_bytes(shared_key_bytes);

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

    /// Decrypts and authenticates the onion envelope on the destination storage node.
    pub fn open_at_target(
        &self,
        target_identity: &NodeIdentity,
    ) -> Result<(BlindedShardId, Vec<u8>), StorageError> {
        let ephem_pub = X25519Public::from(self.ephemeral_x25519_pub);
        let shared_key_bytes =
            target_identity.derive_por_session_key(&ephem_pub, &Self::ONION_DOMAIN_TAG)?;
        let shared_key = MasterKey::from_bytes(shared_key_bytes);

        let decrypted = decrypt_manifest(&shared_key, &self.encrypted_payload)?;
        let inner: OnionInnerPayload = bincode::deserialize(&decrypted)?;
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
