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
use std::collections::HashMap;
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

/// Domain tag of a signed lease renewal (F-23).
pub const RENEW_LEASE_DOMAIN: &[u8] = b"parvault-renew-blinded-lease-v1";

/// The most epochs one renewal may extend a lease by (F-23).
pub const MAX_LEASE_EXTENSION_EPOCHS: u64 = 365;

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

    /// Signs a delete of `blinded_id` on the host whose Ed25519 key is `host_pubkey` (F-41):
    /// `"parvault-delete-blinded-v1" || host || locator || content_sha256 || timestamp_ms`. The
    /// host binding stops one host replaying the delete to other replicas.
    pub fn sign_delete(
        cap_identity: &NodeIdentity,
        host_pubkey: &[u8; 32],
        blinded_id: &BlindedShardId,
        timestamp_ms: u64,
    ) -> [u8; 64] {
        cap_identity.sign(&Self::delete_bytes(host_pubkey, blinded_id, timestamp_ms))
    }

    /// Verifies a delete signature by this capability key (F-41).
    pub fn verify_delete(
        &self,
        host_pubkey: &[u8; 32],
        blinded_id: &BlindedShardId,
        timestamp_ms: u64,
        signature: &[u8; 64],
    ) -> bool {
        let msg = Self::delete_bytes(host_pubkey, blinded_id, timestamp_ms);
        NodeIdentity::verify_with_pubkey(&self.capability_pubkey, &msg, signature)
    }

    fn delete_bytes(
        host_pubkey: &[u8; 32],
        blinded_id: &BlindedShardId,
        timestamp_ms: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(26 + 32 + 32 + 32 + 8);
        msg.extend_from_slice(b"parvault-delete-blinded-v1");
        msg.extend_from_slice(host_pubkey);
        msg.extend_from_slice(&blinded_id.locator);
        msg.extend_from_slice(&blinded_id.content_sha256);
        msg.extend_from_slice(&timestamp_ms.to_be_bytes());
        msg
    }

    /// Signs a lease renewal (F-23) with the shard's capability key.
    pub fn sign_lease_renewal(
        cap_identity: &NodeIdentity,
        locator: &[u8; 32],
        current_epoch: u64,
        extension_epochs: u64,
        timestamp_ms: u64,
    ) -> [u8; 64] {
        cap_identity.sign(&Self::renewal_bytes(
            locator,
            current_epoch,
            extension_epochs,
            timestamp_ms,
        ))
    }

    /// Verifies a lease renewal signed by `self.capability_pubkey` (F-23).
    pub fn verify_lease_renewal(
        &self,
        current_epoch: u64,
        extension_epochs: u64,
        timestamp_ms: u64,
        signature: &[u8],
    ) -> bool {
        let Ok(sig) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        let msg = Self::renewal_bytes(&self.locator, current_epoch, extension_epochs, timestamp_ms);
        NodeIdentity::verify_with_pubkey(&self.capability_pubkey, &msg, &sig)
    }

    fn renewal_bytes(
        locator: &[u8; 32],
        current_epoch: u64,
        extension_epochs: u64,
        timestamp_ms: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(RENEW_LEASE_DOMAIN.len() + 56);
        msg.extend_from_slice(RENEW_LEASE_DOMAIN);
        msg.extend_from_slice(locator);
        msg.extend_from_slice(&current_epoch.to_le_bytes());
        msg.extend_from_slice(&extension_epochs.to_le_bytes());
        msg.extend_from_slice(&timestamp_ms.to_le_bytes());
        msg
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

/// What a blinded-shard read knows about its capability and token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindedReadFacts {
    /// The lease has a registered capability key (F-42: a lease without one is unreadable).
    pub capability_known: bool,
    /// The presented capability key is the registered one.
    pub capability_registered: bool,
    pub locator_matches: bool,
    /// The read token was signed within `MAX_CAPABILITY_CLOCK_SKEW_MS` of now.
    pub fresh: bool,
    pub sig_valid: bool,
}

/// ADR-11 / ADR-15 / E-WIRE GetBlindedShard: bytes are served only to the holder of the lease's
/// capability key, for this locator, with a fresh signature (a captured token expires in 30 s).
pub fn blinded_read_decision(f: &BlindedReadFacts) -> Result<(), &'static str> {
    if !f.capability_known {
        return Err("reject.blinded_read_no_capability");
    }
    if !f.capability_registered || !f.locator_matches {
        return Err("reject.blinded_read_capability_mismatch");
    }
    if !f.fresh {
        return Err("reject.blinded_read_stale");
    }
    if !f.sig_valid {
        return Err("reject.blinded_read_sig_invalid");
    }
    Ok(())
}

/// What a blinded delete knows (F-41, L-42).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindedDeleteFacts {
    /// A signed delete (`DeleteBlindedShardSigned`); the MAC tombstone is never signed.
    pub signed: bool,
    /// The lease exists and has a registered capability key.
    pub capability_registered: bool,
    /// The request's id equals the stored `BlindedShardId` (locator and content hash).
    pub id_matches: bool,
    /// Signed within `MAX_CAPABILITY_CLOCK_SKEW_MS` of now.
    pub fresh: bool,
    /// Valid signature by the registered capability key, bound to this host.
    pub sig_valid: bool,
}

/// F-41: a blinded shard is deleted before lease expiry only on a fresh signature by the
/// lease's registered capability key, bound to this host and to the stored id.
pub fn blinded_delete_decision(f: &BlindedDeleteFacts) -> Result<(), &'static str> {
    if !f.signed {
        return Err("reject.blinded_delete_unsigned");
    }
    if !f.capability_registered {
        return Err("reject.blinded_delete_no_capability");
    }
    if !f.id_matches {
        return Err("reject.blinded_delete_id_mismatch");
    }
    if !f.fresh {
        return Err("reject.blinded_delete_stale");
    }
    if !f.sig_valid {
        return Err("reject.blinded_delete_sig_invalid");
    }
    Ok(())
}

/// F-41: the capability bound to a locator is immutable while its lease exists (first writer
/// wins; a same-key re-put by the owner or a handoff passes).
pub fn blinded_rebind_decision(
    registered: Option<[u8; 32]>,
    incoming: [u8; 32],
) -> Result<(), &'static str> {
    match registered {
        Some(pk) if pk != incoming => Err("reject.blinded_locator_bound_to_another_capability"),
        _ => Ok(()),
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
    /// Appended (F-35): the voucher is redeemable until this time (signed). A spent nonce is
    /// remembered until then, so a voucher cannot be replayed once its nullifier is dropped.
    pub expires_at_ms: u64,
}

/// Default voucher lifetime when minting (F-35).
pub const DEFAULT_VOUCHER_TTL_MS: u64 = 30 * 24 * 3600 * 1000;
/// Longest lifetime a receiver accepts (F-35).
pub const MAX_VOUCHER_TTL_MS: u64 = 90 * 24 * 3600 * 1000;

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A voucher is redeemable only before its expiry and at most 90 days ahead (F-35).
pub fn voucher_freshness_decision(expires_at_ms: u64, now_ms: u64) -> Result<(), &'static str> {
    if expires_at_ms <= now_ms {
        return Err("reject.voucher_expired");
    }
    if expires_at_ms > now_ms.saturating_add(MAX_VOUCHER_TTL_MS) {
        return Err("reject.voucher_expiry_unbounded");
    }
    Ok(())
}

/// A new nullifier is recorded only while the ledger, after dropping expired entries, has room;
/// when full the voucher is refused rather than evicting a live nullifier (F-35).
pub fn nullifier_cache_decision(live_entries: usize) -> Result<(), &'static str> {
    if live_entries >= MAX_VOUCHER_NULLIFIER_ENTRIES {
        Err("reject.voucher_cache_full")
    } else {
        Ok(())
    }
}

impl AnonymousQuotaVoucher {
    /// Mints a fresh single-use bearer storage voucher for up to `max_bytes` using `OsRng` (`E4`).
    pub fn mint(issuer: &NodeIdentity, max_bytes: u64) -> Self {
        Self::mint_expiring(
            issuer,
            max_bytes,
            now_unix_ms().saturating_add(DEFAULT_VOUCHER_TTL_MS),
        )
    }

    /// Mints a voucher that expires at `expires_at_ms` (F-35).
    pub fn mint_expiring(issuer: &NodeIdentity, max_bytes: u64, expires_at_ms: u64) -> Self {
        let mut voucher_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut voucher_nonce);
        let issuer_pubkey = issuer.public_key_bytes();
        let msg = Self::canonical_bytes(&voucher_nonce, max_bytes, &issuer_pubkey, expires_at_ms);
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
            expires_at_ms,
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
        let msg = Self::canonical_bytes(
            &self.voucher_nonce,
            self.max_bytes,
            &self.issuer_pubkey,
            self.expires_at_ms,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(trusted_issuer_pubkey, &msg, &sig)
    }

    fn canonical_bytes(
        voucher_nonce: &[u8; 32],
        max_bytes: u64,
        issuer_pubkey: &[u8; 32],
        expires_at_ms: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(104);
        buf.extend_from_slice(b"parvault-anon-voucher-v2:");
        buf.extend_from_slice(voucher_nonce);
        buf.extend_from_slice(&max_bytes.to_be_bytes());
        buf.extend_from_slice(issuer_pubkey);
        buf.extend_from_slice(&expires_at_ms.to_be_bytes());
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
    /// Spent nonce -> voucher expiry; kept until the voucher expires (F-35).
    spent: HashMap<[u8; 32], u64>,
    #[serde(skip)]
    persistence_path: Option<std::path::PathBuf>,
}

impl VoucherNullifierLedger {
    pub fn new(trusted_issuer_pubkey: [u8; 32]) -> Self {
        Self {
            trusted_issuer_pubkey,
            spent: HashMap::new(),
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
        // Format `Vec<([u8; 32], u64)>` since F-35; an older file (nonces only) does not decode
        // and starts empty, which is safe because pre-F-35 vouchers no longer verify.
        let spent: HashMap<[u8; 32], u64> = if path.exists() {
            std::fs::read(&path)
                .ok()
                .and_then(|raw| {
                    deserialize_bounded::<Vec<([u8; 32], u64)>>(&raw, MAX_NULLIFIER_LEDGER_BYTES)
                        .ok()
                })
                .map(|v| v.into_iter().collect())
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        Self {
            trusted_issuer_pubkey,
            spent,
            persistence_path: Some(path),
        }
    }

    pub const fn issuer_pubkey(&self) -> [u8; 32] {
        self.trusted_issuer_pubkey
    }

    /// Runs `f` with `issuer` as the trusted voucher issuer, then restores the configured one.
    /// The caller decides first whether `issuer` may be trusted (F-24 issuer policy); before this,
    /// the receiver permanently adopted whatever issuer a voucher named.
    pub fn with_trusted_issuer<T>(
        &mut self,
        issuer: [u8; 32],
        f: impl FnOnce(&mut Self) -> T,
    ) -> T {
        let configured = std::mem::replace(&mut self.trusted_issuer_pubkey, issuer);
        let out = f(self);
        self.trusted_issuer_pubkey = configured;
        out
    }

    #[cfg(test)]
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
        self.redeem_voucher_at(voucher, shard_size_bytes, now_unix_ms())
    }

    /// [`Self::redeem_voucher`] at an explicit time (tests and replay checks).
    pub fn redeem_voucher_at(
        &mut self,
        voucher: &AnonymousQuotaVoucher,
        shard_size_bytes: u64,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        if shard_size_bytes > voucher.max_bytes || !voucher.verify(&self.trusted_issuer_pubkey) {
            return Err(StorageError::QuotaExceeded(
                "invalid_or_undersized_voucher".into(),
            ));
        }
        if let Err(code) = voucher_freshness_decision(voucher.expires_at_ms, now_ms) {
            tracing::warn!(code, "refused a voucher outside its lifetime");
            return Err(StorageError::QuotaExceeded(code.into()));
        }
        // Drop nullifiers whose vouchers have expired: those vouchers can no longer verify as
        // fresh, so forgetting them cannot re-enable a spend.
        self.spent.retain(|_, exp| *exp > now_ms);
        if self.spent.contains_key(&voucher.voucher_nonce) {
            return Err(StorageError::QuotaExceeded(
                "double_spent_voucher_nullifier".into(),
            ));
        }
        if let Err(code) = nullifier_cache_decision(self.spent.len()) {
            tracing::warn!(code, "refused a voucher: the nullifier cache is full");
            return Err(StorageError::QuotaExceeded(code.into()));
        }
        self.spent
            .insert(voucher.voucher_nonce, voucher.expires_at_ms);
        if let Some(ref path) = self.persistence_path {
            let entries: Vec<([u8; 32], u64)> = self.spent.iter().map(|(n, e)| (*n, *e)).collect();
            if let Ok(bytes) = bincode::serialize(&entries) {
                let _ = crate::storage::fsio::atomic_write_file(path, &bytes);
            }
        }
        Ok(())
    }

    pub fn spent_count(&self) -> usize {
        self.spent.len()
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

    /// F-35 (plan 2c fact 5): a full ledger refuses a new voucher instead of evicting a live
    /// nullifier, so a spent voucher is never redeemable again while it is fresh.
    #[test]
    fn spent_voucher_never_redeemable_again_while_fresh() {
        let issuer = NodeIdentity::from_seed([0x2C; 32]);
        let mut ledger = VoucherNullifierLedger::new(issuer.public_key_bytes());
        let now = now_unix_ms();
        let first = AnonymousQuotaVoucher::mint(&issuer, 4096);
        ledger.redeem_voucher_at(&first, 1024, now).unwrap();
        assert!(
            ledger.redeem_voucher_at(&first, 1024, now).is_err(),
            "double spend refused"
        );
        // Fill the ledger to capacity with live nullifiers (state setup only).
        for i in 1..MAX_VOUCHER_NULLIFIER_ENTRIES {
            let mut nonce = [0xEEu8; 32];
            nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
            ledger.spent.insert(nonce, now + 60_000);
        }
        let next = AnonymousQuotaVoucher::mint(&issuer, 4096);
        assert!(
            matches!(ledger.redeem_voucher_at(&next, 1024, now), Err(StorageError::QuotaExceeded(c)) if c == "reject.voucher_cache_full")
        );
        assert!(
            ledger.redeem_voucher_at(&first, 1024, now).is_err(),
            "still spent"
        );
        // Once the filler vouchers expire their nullifiers are dropped and new vouchers fit.
        assert!(ledger.redeem_voucher_at(&next, 1024, now + 120_000).is_ok());
        assert!(
            ledger
                .redeem_voucher_at(&first, 1024, now + 120_000)
                .is_err(),
            "first is still spent"
        );
    }

    #[test]
    fn voucher_lifetime_is_bounded_and_signed() {
        let issuer = NodeIdentity::from_seed([0x2D; 32]);
        let mut ledger = VoucherNullifierLedger::new(issuer.public_key_bytes());
        let now = now_unix_ms();
        let expired = AnonymousQuotaVoucher::mint_expiring(&issuer, 4096, now - 1);
        assert!(ledger.redeem_voucher_at(&expired, 1024, now).is_err());
        let too_far =
            AnonymousQuotaVoucher::mint_expiring(&issuer, 4096, now + MAX_VOUCHER_TTL_MS + 1);
        assert!(ledger.redeem_voucher_at(&too_far, 1024, now).is_err());
        // The expiry is signed: extending it breaks the signature.
        let mut stretched = AnonymousQuotaVoucher::mint(&issuer, 4096);
        stretched.expires_at_ms += 1;
        assert!(!stretched.verify(&issuer.public_key_bytes()));
        assert_eq!(voucher_freshness_decision(now + 1, now), Ok(()));
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

#[cfg(test)]
mod blinded_read_decision_tests {
    use super::*;

    /// F-41: every fact must hold, in order; the rebind is first-writer-wins.
    #[test]
    fn blinded_delete_and_rebind_rules() {
        let ok = BlindedDeleteFacts {
            signed: true,
            capability_registered: true,
            id_matches: true,
            fresh: true,
            sig_valid: true,
        };
        assert_eq!(blinded_delete_decision(&ok), Ok(()));
        let with = |f: &dyn Fn(&mut BlindedDeleteFacts)| {
            let mut x = ok;
            f(&mut x);
            blinded_delete_decision(&x)
        };
        assert_eq!(
            with(&|f| f.signed = false),
            Err("reject.blinded_delete_unsigned")
        );
        assert_eq!(
            with(&|f| f.capability_registered = false),
            Err("reject.blinded_delete_no_capability")
        );
        assert_eq!(
            with(&|f| f.id_matches = false),
            Err("reject.blinded_delete_id_mismatch")
        );
        assert_eq!(
            with(&|f| f.fresh = false),
            Err("reject.blinded_delete_stale")
        );
        assert_eq!(
            with(&|f| f.sig_valid = false),
            Err("reject.blinded_delete_sig_invalid")
        );
        assert_eq!(blinded_rebind_decision(None, [1; 32]), Ok(()));
        assert_eq!(blinded_rebind_decision(Some([1; 32]), [1; 32]), Ok(()));
        assert_eq!(
            blinded_rebind_decision(Some([1; 32]), [2; 32]),
            Err("reject.blinded_locator_bound_to_another_capability")
        );
    }

    /// E-WIRE GetBlindedShard: registered capability for this locator, fresh, then the signature.
    #[test]
    fn blinded_read_decision_rules() {
        let ok = BlindedReadFacts {
            capability_known: true,
            capability_registered: true,
            locator_matches: true,
            fresh: true,
            sig_valid: true,
        };
        assert_eq!(blinded_read_decision(&ok), Ok(()));
        let with = |f: &dyn Fn(&mut BlindedReadFacts)| {
            let mut x = ok;
            f(&mut x);
            blinded_read_decision(&x)
        };
        assert_eq!(
            with(&|f| f.capability_known = false),
            Err("reject.blinded_read_no_capability")
        );
        assert_eq!(
            with(&|f| f.capability_registered = false),
            Err("reject.blinded_read_capability_mismatch")
        );
        assert_eq!(
            with(&|f| f.locator_matches = false),
            Err("reject.blinded_read_capability_mismatch")
        );
        assert_eq!(with(&|f| f.fresh = false), Err("reject.blinded_read_stale"));
        assert_eq!(
            with(&|f| f.sig_valid = false),
            Err("reject.blinded_read_sig_invalid")
        );
    }
}
