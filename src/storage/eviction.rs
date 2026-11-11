use crate::crypto::aes::{
    compute_sha256, decrypt_manifest, decrypt_stripe, encrypt_manifest, CryptoError,
};
use crate::crypto::keys::{write_secret_file_atomic_0600, MasterKey, NodeIdentity};
use crate::sharding::merkle::{compute_file_merkle_root, hash_shard_leaf, MerkleTree};
use crate::sharding::reed_solomon::reconstruct_ciphertext_stripe;
use crate::storage::anonymity::BlindedShardId;
use crate::storage::block_store::{BlockStore, FileManifest, ShardId, StorageError};
use bincode::Options;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Domain separator for `SignedBadActorEvictionOrder` Ed25519 signatures (`ADR-19`).
pub const EVICTION_ORDER_DOMAIN: &[u8] = b"parvault-bad-actor-eviction-order-v1:";
/// Domain separator for `VerifiableAbuseReport` reporter Ed25519 signatures (`ADR-19`).
pub const ABUSE_REPORT_DOMAIN: &[u8] = b"parvault-verifiable-abuse-report-v1:";
/// Maximum byte length of `SignedBadActorEvictionOrder::reason`.
pub const MAX_EVICTION_REASON_BYTES: usize = 256;
/// Maximum operator council co-signatures attached to a single `SignedBadActorEvictionOrder`.
pub const MAX_EVICTION_COSIGNATURES: usize = 64;
/// Maximum byte length of `VerifiableAbuseReport::legal_allegation`.
pub const MAX_ABUSE_ALLEGATION_BYTES: usize = 2048;
/// Bounded FIFO anti-replay capacity for `SignedBadActorEvictionOrder::order_id` (`ADR-19`).
pub const MAX_SEEN_EVICTION_ORDER_IDS: usize = 16_384;
/// Maximum bounded entries retained in `PublicTrackerTakedownQueue`.
pub const MAX_TAKEDOWN_QUEUE_ENTRIES: usize = 4_096;
/// Maximum bounded deserialization ceiling (`64 MiB`) for `<data_dir>/eviction_index.bin`
/// and `<data_dir>/admin_takedown_queue.bin`.
pub const MAX_EVICTION_INDEX_BYTES: u64 = 64 * 1024 * 1024;

const EVICT_IP_DOMAIN: &[u8] = b"parvault-evict-ip-v1:";
const EVICT_SUBNET_DOMAIN: &[u8] = b"parvault-evict-subnet-v1:";
const EVICT_PEERID_DOMAIN: &[u8] = b"parvault-evict-peerid-v1:";
const ZERO_SHRED_CHUNK_BYTES: usize = 64 * 1024;
const MAX_TARGET_STRING_BYTES: usize = 1024;

/// Loads or atomically generates (`0600`) the Public Tracker Admin `NodeIdentity` at
/// `<data_dir>/tracker_admin.seed` (`ADR-19`).
pub fn load_or_generate_tracker_admin_identity(
    data_dir: impl AsRef<Path>,
) -> Result<NodeIdentity, StorageError> {
    let data_dir = data_dir.as_ref();
    fs::create_dir_all(data_dir)?;
    let seed_path = data_dir.join("tracker_admin.seed");
    if seed_path.exists() {
        let mut raw = fs::read(&seed_path)?;
        if raw.len() != 32 {
            let actual = raw.len();
            raw.zeroize();
            return Err(StorageError::Crypto(CryptoError::InvalidKeyMaterial(
                format!("expected 32-byte tracker_admin.seed, got {actual} bytes"),
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        raw.zeroize();
        let id = NodeIdentity::from_seed(seed);
        seed.zeroize();
        Ok(id)
    } else {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        write_secret_file_atomic_0600(&seed_path, &seed)?;
        let id = NodeIdentity::from_seed(seed);
        seed.zeroize();
        Ok(id)
    }
}

/// 4-Vector eviction target selector (`ADR-19`):
/// 1. Network IP / Subnet (`IpAddress`, `IpSubnet`)
/// 2. Transport Identity (`Libp2pPeerId`)
/// 3. Cryptographic Admission / Voucher Cohort (`PeerOrIssuerPubkey`)
/// 4. Content / Shard Identifier (`StripeMerkleRoot`, `BlindedLocator`)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvictionTarget {
    IpAddress(std::net::IpAddr),
    IpSubnet(String), // canonical e.g. "203.0.113.0/24" or "2001:db8:abcd::/48"
    Libp2pPeerId(String),
    PeerOrIssuerPubkey([u8; 32]),
    StripeMerkleRoot([u8; 32]),
    BlindedLocator([u8; 32]),
}

/// Threshold co-signature affixed by an independent Federated Public Tracker Council operator
/// over `SignedBadActorEvictionOrder::canonical_sign_bytes()` (`ADR-19` `M-of-N` quorum).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerOperatorCosignature {
    pub cosigner_pubkey: [u8; 32],
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl TrackerOperatorCosignature {
    /// Verifies this co-signature against `canonical_order_msg`.
    pub fn verify(&self, canonical_order_msg: &[u8]) -> bool {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.cosigner_pubkey, canonical_order_msg, &sig)
    }
}

/// Cryptographically signed bad-actor or illegal-content eviction order (`ADR-19`)
/// propagated across `parvault-seed` anchors and `parvault` storage daemons.
/// Supports `M-of-N` Federated Public Tracker Council co-signatures via `cosignatures`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBadActorEvictionOrder {
    pub order_id: [u8; 32],
    pub target: EvictionTarget,
    pub reason: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64, // 0 = permanent tombstone
    pub issuer_pubkey: [u8; 32],
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
    #[serde(default)]
    pub cosignatures: Vec<TrackerOperatorCosignature>,
}

impl SignedBadActorEvictionOrder {
    /// Strict majority `M-of-N` quorum threshold for Federated Public Tracker Councils (`ADR-19`):
    /// `1-of-1`, `2-of-2`, `2-of-3`, `3-of-4`, `3-of-5`, etc.
    pub const fn default_tracker_quorum_threshold(council_size: usize) -> usize {
        match council_size {
            0 | 1 => 1,
            2 => 2,
            n => (n / 2) + 1,
        }
    }

    /// Issues a signed eviction order using a fresh 32-byte CSPRNG `order_id`, truncating
    /// `reason` safely at a UTF-8 character boundary to `<= 256` bytes.
    pub fn issue(
        issuer: &NodeIdentity,
        target: EvictionTarget,
        reason: impl Into<String>,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Self {
        let mut order_id = [0u8; 32];
        OsRng.fill_bytes(&mut order_id);
        let truncated_reason = truncate_utf8_bytes(reason.into(), MAX_EVICTION_REASON_BYTES);
        let issuer_pubkey = issuer.public_key_bytes();
        let msg = Self::encode_signing_payload(
            &order_id,
            &target,
            &truncated_reason,
            issued_at_ms,
            expires_at_ms,
            &issuer_pubkey,
        );
        let sig = issuer.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Self {
            order_id,
            target,
            reason: truncated_reason,
            issued_at_ms,
            expires_at_ms,
            issuer_pubkey,
            sig_r,
            sig_s,
            cosignatures: Vec::new(),
        }
    }

    /// Appends an `Ed25519` co-signature over `self.canonical_sign_bytes()` from an independent
    /// tracker council operator. Returns `false` without duplicating if `cosigner` is already the
    /// primary `issuer_pubkey`, has already co-signed, or `cosignatures.len() >= 64`.
    pub fn add_cosignature(&mut self, cosigner: &NodeIdentity) -> bool {
        if self.cosignatures.len() >= MAX_EVICTION_COSIGNATURES {
            return false;
        }
        let cosigner_pubkey = cosigner.public_key_bytes();
        if cosigner_pubkey == self.issuer_pubkey
            || self
                .cosignatures
                .iter()
                .any(|c| c.cosigner_pubkey == cosigner_pubkey)
        {
            return false;
        }
        let msg = self.canonical_sign_bytes();
        let sig = cosigner.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);
        self.cosignatures.push(TrackerOperatorCosignature {
            cosigner_pubkey,
            sig_r,
            sig_s,
        });
        true
    }

    /// Returns the deterministic domain-separated signing payload for this order.
    pub fn canonical_sign_bytes(&self) -> Vec<u8> {
        Self::encode_signing_payload(
            &self.order_id,
            &self.target,
            &self.reason,
            self.issued_at_ms,
            self.expires_at_ms,
            &self.issuer_pubkey,
        )
    }

    /// Verifies the primary Ed25519 signature and structural bounds (`reason.len() <= 256`,
    /// `cosignatures.len() <= 64`).
    pub fn verify_signature(&self) -> bool {
        self.verify_signature_with(NodeIdentity::verify_with_pubkey)
    }

    /// Verifies structural bounds (`issuer_pubkey != [0u8; 32]`, `reason.len() <= 256`,
    /// `cosignatures.len() <= 64`, bounded string targets) and checks the primary signature
    /// over `self.canonical_sign_bytes()` using `verify_fn`.
    pub fn verify_signature_with<F>(&self, verify_fn: F) -> bool
    where
        F: Fn(&[u8; 32], &[u8], &[u8; 64]) -> bool,
    {
        if self.issuer_pubkey == [0u8; 32]
            || self.reason.len() > MAX_EVICTION_REASON_BYTES
            || self.cosignatures.len() > MAX_EVICTION_COSIGNATURES
        {
            return false;
        }
        match &self.target {
            EvictionTarget::IpSubnet(s) | EvictionTarget::Libp2pPeerId(s)
                if s.is_empty() || s.len() > MAX_TARGET_STRING_BYTES =>
            {
                return false;
            }
            _ => {}
        }
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        if let Some((stack_buf, len)) = Self::encode_signing_payload_stack(
            &self.order_id,
            &self.target,
            self.reason.as_bytes(),
            self.issued_at_ms,
            self.expires_at_ms,
            &self.issuer_pubkey,
        ) {
            verify_fn(&self.issuer_pubkey, &stack_buf[..len], &sig)
        } else {
            let msg = self.canonical_sign_bytes();
            verify_fn(&self.issuer_pubkey, &msg, &sig)
        }
    }

    /// Counts how many **distinct** public keys in `trusted_council_pubkeys` have produced a
    /// cryptographically valid Ed25519 signature (primary `issuer_pubkey` + `cosignatures`) over
    /// `self.canonical_sign_bytes()`. Duplicate signatures from the same key count at most once.
    pub fn valid_council_signer_count(&self, trusted_council_pubkeys: &[[u8; 32]]) -> usize {
        self.valid_council_signer_count_with(
            trusted_council_pubkeys,
            NodeIdentity::verify_with_pubkey,
        )
    }

    /// Zero-allocation stack-capable `M-of-N` quorum tally and expiry evaluator shared by
    /// `valid_council_signer_count_with`, `verify_against_quorum_with`, and Kani symbolic harnesses.
    #[allow(clippy::too_many_arguments)]
    pub fn tally_and_verify_quorum_raw<F>(
        order_id: &[u8; 32],
        target: &EvictionTarget,
        reason_bytes: &[u8],
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_pubkey: &[u8; 32],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
        cosignatures: &[TrackerOperatorCosignature],
        trusted_council_pubkeys: &[[u8; 32]],
        min_quorum: usize,
        now_ms: u64,
        verify_fn: F,
    ) -> (usize, bool)
    where
        F: Fn(&[u8; 32], &[u8], &[u8; 64]) -> bool,
    {
        if trusted_council_pubkeys.is_empty()
            || *issuer_pubkey == [0u8; 32]
            || reason_bytes.len() > MAX_EVICTION_REASON_BYTES
            || cosignatures.len() > MAX_EVICTION_COSIGNATURES
        {
            return (0, false);
        }
        match target {
            EvictionTarget::IpSubnet(s) | EvictionTarget::Libp2pPeerId(s)
                if s.is_empty() || s.len() > MAX_TARGET_STRING_BYTES =>
            {
                return (0, false);
            }
            _ => {}
        }

        let heap_fallback;
        let stack_opt = Self::encode_signing_payload_stack(
            order_id,
            target,
            reason_bytes,
            issued_at_ms,
            expires_at_ms,
            issuer_pubkey,
        );
        let msg_slice: &[u8] = if let Some((ref arr, len)) = stack_opt {
            &arr[..len]
        } else {
            heap_fallback = Self::encode_signing_payload_bytes(
                order_id,
                target,
                reason_bytes,
                issued_at_ms,
                expires_at_ms,
                issuer_pubkey,
            );
            heap_fallback.as_slice()
        };

        let mut primary_sig = [0u8; 64];
        primary_sig[..32].copy_from_slice(sig_r);
        primary_sig[32..].copy_from_slice(sig_s);
        if !verify_fn(issuer_pubkey, msg_slice, &primary_sig) {
            return (0, false);
        }

        let is_council_member = |pk: &[u8; 32]| {
            if *pk == [0u8; 32] {
                return false;
            }
            let mut i = 0;
            while i < trusted_council_pubkeys.len() {
                if trusted_council_pubkeys[i] == *pk {
                    return true;
                }
                i += 1;
            }
            false
        };

        let issuer_in_council = is_council_member(issuer_pubkey);
        let mut count: usize = usize::from(issuer_in_council);

        let limit = cosignatures.len().min(MAX_EVICTION_COSIGNATURES);
        let mut valid_flags = [false; MAX_EVICTION_COSIGNATURES];
        let mut idx = 0;
        while idx < limit {
            let candidate_pk = &cosignatures[idx].cosigner_pubkey;
            if is_council_member(candidate_pk) {
                let mut duplicate = issuer_in_council && (*candidate_pk == *issuer_pubkey);
                let mut prev = 0;
                while prev < idx {
                    if valid_flags[prev] && cosignatures[prev].cosigner_pubkey == *candidate_pk {
                        duplicate = true;
                    }
                    prev += 1;
                }
                if !duplicate {
                    let mut sig = [0u8; 64];
                    sig[..32].copy_from_slice(&cosignatures[idx].sig_r);
                    sig[32..].copy_from_slice(&cosignatures[idx].sig_s);
                    if verify_fn(candidate_pk, msg_slice, &sig) {
                        valid_flags[idx] = true;
                        count += 1;
                    }
                }
            }
            idx += 1;
        }

        let not_expired = expires_at_ms == 0 || now_ms <= expires_at_ms;
        let quorum_ok = not_expired && count >= min_quorum.max(1);
        (count, quorum_ok)
    }

    /// Deterministic `M-of-N` quorum tally over `trusted_council_pubkeys` parameterized by
    /// signature verifier `verify_fn`. Rejects `[0u8; 32]` keys, requires a valid primary
    /// signature over `self.canonical_sign_bytes()`, and strictly deduplicates signers so
    /// repeated co-signatures from the same council key never count more than once.
    pub fn valid_council_signer_count_with<F>(
        &self,
        trusted_council_pubkeys: &[[u8; 32]],
        verify_fn: F,
    ) -> usize
    where
        F: Fn(&[u8; 32], &[u8], &[u8; 64]) -> bool,
    {
        Self::tally_and_verify_quorum_raw(
            &self.order_id,
            &self.target,
            self.reason.as_bytes(),
            self.issued_at_ms,
            self.expires_at_ms,
            &self.issuer_pubkey,
            &self.sig_r,
            &self.sig_s,
            &self.cosignatures,
            trusted_council_pubkeys,
            1,
            0,
            verify_fn,
        )
        .0
    }

    /// Verifies the primary signature, checks expiration, and requires at least `min_quorum.max(1)`
    /// distinct valid council signers from `trusted_council_pubkeys` (`ADR-19` `M-of-N` quorum).
    pub fn verify_against_quorum(
        &self,
        trusted_council_pubkeys: &[[u8; 32]],
        min_quorum: usize,
        now_ms: u64,
    ) -> bool {
        self.verify_against_quorum_with(
            trusted_council_pubkeys,
            min_quorum,
            now_ms,
            NodeIdentity::verify_with_pubkey,
        )
    }

    /// Parameterized `M-of-N` council quorum verification enforcing non-empty council, expiration
    /// window (`expires_at_ms == 0 || now_ms <= expires_at_ms`), primary signature validity, and
    /// `valid_council_signer_count_with(...) >= min_quorum.max(1)`.
    pub fn verify_against_quorum_with<F>(
        &self,
        trusted_council_pubkeys: &[[u8; 32]],
        min_quorum: usize,
        now_ms: u64,
        verify_fn: F,
    ) -> bool
    where
        F: Fn(&[u8; 32], &[u8], &[u8; 64]) -> bool,
    {
        if trusted_council_pubkeys.is_empty() {
            return false;
        }
        if self.expires_at_ms != 0 && now_ms > self.expires_at_ms {
            return false;
        }
        Self::tally_and_verify_quorum_raw(
            &self.order_id,
            &self.target,
            self.reason.as_bytes(),
            self.issued_at_ms,
            self.expires_at_ms,
            &self.issuer_pubkey,
            &self.sig_r,
            &self.sig_s,
            &self.cosignatures,
            trusted_council_pubkeys,
            min_quorum,
            now_ms,
            verify_fn,
        )
        .1
    }

    /// Verifies the Ed25519 signature, checks that `issuer_pubkey` is in `trusted_pubkeys`,
    /// and enforces expiration (`expires_at_ms == 0 || now_ms <= expires_at_ms`).
    pub fn verify_against_trusted_authorities(
        &self,
        trusted_pubkeys: &[[u8; 32]],
        now_ms: u64,
    ) -> bool {
        if !trusted_pubkeys.contains(&self.issuer_pubkey) {
            return false;
        }
        if self.expires_at_ms != 0 && now_ms > self.expires_at_ms {
            return false;
        }
        self.verify_signature()
    }

    /// Encodes the canonical `SignedBadActorEvictionOrder` preimage onto a fixed 256-byte stack
    /// buffer whenever the serialized preimage fits in `<= 256` bytes (zero heap allocations).
    pub fn encode_signing_payload_stack(
        order_id: &[u8; 32],
        target: &EvictionTarget,
        reason_bytes: &[u8],
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_pubkey: &[u8; 32],
    ) -> Option<([u8; 256], usize)> {
        let target_len = match target {
            EvictionTarget::IpAddress(IpAddr::V4(_)) => 6,
            EvictionTarget::IpAddress(IpAddr::V6(_)) => 18,
            EvictionTarget::IpSubnet(s) | EvictionTarget::Libp2pPeerId(s) => 5 + s.len(),
            EvictionTarget::PeerOrIssuerPubkey(_)
            | EvictionTarget::StripeMerkleRoot(_)
            | EvictionTarget::BlindedLocator(_) => 33,
        };
        let total = EVICTION_ORDER_DOMAIN
            .len()
            .checked_add(32)?
            .checked_add(target_len)?
            .checked_add(4)?
            .checked_add(reason_bytes.len())?
            .checked_add(8 + 8 + 32)?;
        if total > 256 {
            return None;
        }
        let mut buf = [0u8; 256];
        let mut pos = 0usize;
        let push_bytes = |dst: &mut [u8; 256], cursor: &mut usize, src: &[u8]| {
            let mut i = 0;
            while i < src.len() {
                dst[*cursor + i] = src[i];
                i += 1;
            }
            *cursor += src.len();
        };
        push_bytes(&mut buf, &mut pos, EVICTION_ORDER_DOMAIN);
        push_bytes(&mut buf, &mut pos, order_id);
        match target {
            EvictionTarget::IpAddress(IpAddr::V4(v4)) => {
                push_bytes(&mut buf, &mut pos, &[0x01, 0x04]);
                push_bytes(&mut buf, &mut pos, &v4.octets());
            }
            EvictionTarget::IpAddress(IpAddr::V6(v6)) => {
                push_bytes(&mut buf, &mut pos, &[0x01, 0x06]);
                push_bytes(&mut buf, &mut pos, &v6.octets());
            }
            EvictionTarget::IpSubnet(cidr) => {
                let b = cidr.as_bytes();
                push_bytes(&mut buf, &mut pos, &[0x02]);
                push_bytes(&mut buf, &mut pos, &(b.len() as u32).to_be_bytes());
                push_bytes(&mut buf, &mut pos, b);
            }
            EvictionTarget::Libp2pPeerId(peer_id) => {
                let b = peer_id.as_bytes();
                push_bytes(&mut buf, &mut pos, &[0x03]);
                push_bytes(&mut buf, &mut pos, &(b.len() as u32).to_be_bytes());
                push_bytes(&mut buf, &mut pos, b);
            }
            EvictionTarget::PeerOrIssuerPubkey(pk) => {
                push_bytes(&mut buf, &mut pos, &[0x04]);
                push_bytes(&mut buf, &mut pos, pk);
            }
            EvictionTarget::StripeMerkleRoot(root) => {
                push_bytes(&mut buf, &mut pos, &[0x05]);
                push_bytes(&mut buf, &mut pos, root);
            }
            EvictionTarget::BlindedLocator(loc) => {
                push_bytes(&mut buf, &mut pos, &[0x06]);
                push_bytes(&mut buf, &mut pos, loc);
            }
        }
        push_bytes(
            &mut buf,
            &mut pos,
            &(reason_bytes.len() as u32).to_be_bytes(),
        );
        push_bytes(&mut buf, &mut pos, reason_bytes);
        push_bytes(&mut buf, &mut pos, &issued_at_ms.to_be_bytes());
        push_bytes(&mut buf, &mut pos, &expires_at_ms.to_be_bytes());
        push_bytes(&mut buf, &mut pos, issuer_pubkey);
        Some((buf, pos))
    }

    fn encode_signing_payload(
        order_id: &[u8; 32],
        target: &EvictionTarget,
        reason: &str,
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        Self::encode_signing_payload_bytes(
            order_id,
            target,
            reason.as_bytes(),
            issued_at_ms,
            expires_at_ms,
            issuer_pubkey,
        )
    }

    fn encode_signing_payload_bytes(
        order_id: &[u8; 32],
        target: &EvictionTarget,
        reason_bytes: &[u8],
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        if let Some((arr, len)) = Self::encode_signing_payload_stack(
            order_id,
            target,
            reason_bytes,
            issued_at_ms,
            expires_at_ms,
            issuer_pubkey,
        ) {
            return arr[..len].to_vec();
        }
        let mut buf = Vec::with_capacity(192 + reason_bytes.len());
        buf.extend_from_slice(EVICTION_ORDER_DOMAIN);
        buf.extend_from_slice(order_id);
        match target {
            EvictionTarget::IpAddress(IpAddr::V4(v4)) => {
                buf.push(0x01);
                buf.push(0x04);
                buf.extend_from_slice(&v4.octets());
            }
            EvictionTarget::IpAddress(IpAddr::V6(v6)) => {
                buf.push(0x01);
                buf.push(0x06);
                buf.extend_from_slice(&v6.octets());
            }
            EvictionTarget::IpSubnet(cidr) => {
                buf.push(0x02);
                buf.extend_from_slice(&(cidr.len() as u32).to_be_bytes());
                buf.extend_from_slice(cidr.as_bytes());
            }
            EvictionTarget::Libp2pPeerId(peer_id) => {
                buf.push(0x03);
                buf.extend_from_slice(&(peer_id.len() as u32).to_be_bytes());
                buf.extend_from_slice(peer_id.as_bytes());
            }
            EvictionTarget::PeerOrIssuerPubkey(pk) => {
                buf.push(0x04);
                buf.extend_from_slice(pk);
            }
            EvictionTarget::StripeMerkleRoot(root) => {
                buf.push(0x05);
                buf.extend_from_slice(root);
            }
            EvictionTarget::BlindedLocator(loc) => {
                buf.push(0x06);
                buf.extend_from_slice(loc);
            }
        }
        buf.extend_from_slice(&(reason_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(reason_bytes);
        buf.extend_from_slice(&issued_at_ms.to_be_bytes());
        buf.extend_from_slice(&expires_at_ms.to_be_bytes());
        buf.extend_from_slice(issuer_pubkey);
        buf
    }
}

/// Summary of physical zero-wiping (`0x00`), shard removal, and ingress firewall installation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionPurgeReport {
    pub purged_regular_shards: usize,
    pub purged_blinded_shards: usize,
    pub zero_wiped_bytes: u64,
    pub firewall_rule_installed: bool,
}

impl EvictionPurgeReport {
    /// Accumulates counts from another `EvictionPurgeReport` (e.g., across mesh broadcast acks).
    pub fn merge(&mut self, other: &Self) {
        self.purged_regular_shards = self
            .purged_regular_shards
            .saturating_add(other.purged_regular_shards);
        self.purged_blinded_shards = self
            .purged_blinded_shards
            .saturating_add(other.purged_blinded_shards);
        self.zero_wiped_bytes = self.zero_wiped_bytes.saturating_add(other.zero_wiped_bytes);
        self.firewall_rule_installed |= other.firewall_rule_installed;
    }
}

/// Cryptographic burden-of-proof verification result produced when a reporter proves possession
/// of a valid `(FileManifest, disclosed_master_key_hex, sample_shards)` bundle (`ADR-19`).
/// Only the SHA-256 digest and byte length of the authenticated plaintext are retained; the
/// transient decrypted plaintext buffer is immediately `Zeroize`d in RAM and never written to disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedAbuseProofOutcome {
    pub file_merkle_root: [u8; 32],
    pub stripe_merkle_roots: Vec<[u8; 32]>,
    pub verified_stripe_index: u64,
    pub verified_plaintext_sha256: [u8; 32],
    pub verified_plaintext_len: usize,
}

/// Signed abuse / illegal-content report carrying cryptographic burden-of-proof (`ADR-19`).
/// Because `ParVault` storage nodes and public trackers are zero-knowledge, the reporter bears
/// the mathematical burden of proving what the encrypted network shards contain (via `AES-256-GCM`
/// authentication tag verification under `disclosed_master_key_hex`) and stating the legal
/// allegation before a Public Tracker Admin reviews the queued takedown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiableAbuseReport {
    pub report_id: [u8; 32],
    pub submitted_at_ms: u64,
    pub reporter_id_or_contact: String,
    pub legal_allegation: String,
    pub reported_uploader_ip: Option<IpAddr>,
    pub manifest: FileManifest,
    pub disclosed_master_key_hex: String,
    pub sample_stripe_index: u64,
    pub sample_shards: Vec<(u32, Vec<u8>)>,
    pub reporter_ed25519_pubkey: [u8; 32],
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl VerifiableAbuseReport {
    /// Creates and Ed25519-signs a `VerifiableAbuseReport` under `reporter_identity`.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_signed(
        reporter_identity: &NodeIdentity,
        reporter_id_or_contact: impl Into<String>,
        legal_allegation: impl Into<String>,
        reported_uploader_ip: Option<IpAddr>,
        manifest: FileManifest,
        disclosed_master_key_hex: impl Into<String>,
        sample_stripe_index: u64,
        sample_shards: Vec<(u32, Vec<u8>)>,
        submitted_at_ms: u64,
    ) -> Self {
        let mut report_id = [0u8; 32];
        OsRng.fill_bytes(&mut report_id);
        let reporter_id_or_contact =
            truncate_utf8_bytes(reporter_id_or_contact.into(), MAX_EVICTION_REASON_BYTES);
        let legal_allegation =
            truncate_utf8_bytes(legal_allegation.into(), MAX_ABUSE_ALLEGATION_BYTES);
        let disclosed_master_key_hex = disclosed_master_key_hex.into().trim().to_string();
        let reporter_ed25519_pubkey = reporter_identity.public_key_bytes();

        let msg = Self::encode_signing_payload(
            &report_id,
            submitted_at_ms,
            &reporter_id_or_contact,
            &legal_allegation,
            reported_uploader_ip,
            &manifest,
            &disclosed_master_key_hex,
            sample_stripe_index,
            &sample_shards,
            &reporter_ed25519_pubkey,
        );
        let sig = reporter_identity.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Self {
            report_id,
            submitted_at_ms,
            reporter_id_or_contact,
            legal_allegation,
            reported_uploader_ip,
            manifest,
            disclosed_master_key_hex,
            sample_stripe_index,
            sample_shards,
            reporter_ed25519_pubkey,
            sig_r,
            sig_s,
        }
    }

    /// Verifies the reporter's Ed25519 accountability signature and metadata bounds.
    pub fn verify_reporter_signature(&self) -> bool {
        if self.reporter_id_or_contact.len() > MAX_EVICTION_REASON_BYTES
            || self.legal_allegation.trim().is_empty()
            || self.legal_allegation.len() > MAX_ABUSE_ALLEGATION_BYTES
            || self.disclosed_master_key_hex.len() > 128
        {
            return false;
        }
        let msg = Self::encode_signing_payload(
            &self.report_id,
            self.submitted_at_ms,
            &self.reporter_id_or_contact,
            &self.legal_allegation,
            self.reported_uploader_ip,
            &self.manifest,
            &self.disclosed_master_key_hex,
            self.sample_stripe_index,
            &self.sample_shards,
            &self.reporter_ed25519_pubkey,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.reporter_ed25519_pubkey, &msg, &sig)
    }

    /// Verifies the complete cryptographic burden-of-proof (`ADR-19`):
    /// 1. Reporter Ed25519 signature over the allegation and evidence bundle.
    /// 2. `FileManifest` internal Merkle consistency (`shard_hashes -> stripe_merkle_root -> file_merkle_root`).
    /// 3. Sample shard leaf digests (`hash_shard_leaf`) match `stripe.shard_hashes`.
    /// 4. Reed-Solomon erasure reconstruction yields the exact stripe ciphertext.
    /// 5. `decrypt_stripe` passes 128-bit `AES-256-GCM` tag verification under `disclosed_master_key_hex`
    ///    (making it mathematically infeasible — $2^{-128}$ — for a griefer to frame an honest user's
    ///    private backup without possessing its decryption key).
    /// 6. Immediately `Zeroize`s the decrypted plaintext buffer in RAM so illegal content bytes
    ///    never touch disk.
    pub fn verify_cryptographic_burden_of_proof(
        &self,
    ) -> Result<VerifiedAbuseProofOutcome, String> {
        if !self.verify_reporter_signature() {
            return Err(
                "invalid reporter Ed25519 signature or missing legal allegation".to_string(),
            );
        }
        if self.manifest.stripes.is_empty() {
            return Err("reported FileManifest contains zero stripes".to_string());
        }

        let mut stripe_merkle_roots = Vec::with_capacity(self.manifest.stripes.len());
        for (expected_idx, s) in self.manifest.stripes.iter().enumerate() {
            if s.stripe_index != expected_idx as u64 {
                return Err(format!(
                    "non-sequential stripe_index {} at position {}",
                    s.stripe_index, expected_idx
                ));
            }
            let total = s.k_data.saturating_add(s.m_parity);
            if s.k_data == 0 || total == 0 || s.shard_hashes.len() != total {
                return Err("malformed StripeManifestEntry erasure parameters".to_string());
            }
            let computed_stripe_root = MerkleTree::from_leaf_hashes(s.shard_hashes.clone()).root();
            if computed_stripe_root != s.stripe_merkle_root {
                return Err(format!(
                    "StripeManifestEntry {} shard_hashes do not match stripe_merkle_root",
                    s.stripe_index
                ));
            }
            stripe_merkle_roots.push(s.stripe_merkle_root);
        }

        let computed_file_root = compute_file_merkle_root(&stripe_merkle_roots);
        if computed_file_root != self.manifest.file_merkle_root {
            return Err(
                "reported FileManifest stripe roots do not match file_merkle_root".to_string(),
            );
        }

        let stripe = self
            .manifest
            .stripes
            .iter()
            .find(|s| s.stripe_index == self.sample_stripe_index)
            .ok_or_else(|| {
                format!(
                    "sample_stripe_index {} not present in FileManifest",
                    self.sample_stripe_index
                )
            })?;

        let total_shards = stripe.k_data + stripe.m_parity;
        let mut shard_slots: Vec<Option<Vec<u8>>> = vec![None; total_shards];
        let mut populated_shards = 0usize;

        for (shard_idx, shard_bytes) in &self.sample_shards {
            let idx = *shard_idx as usize;
            if idx >= total_shards {
                return Err(format!(
                    "sample shard_index {} out of bounds for total_shards {}",
                    shard_idx, total_shards
                ));
            }
            if shard_bytes.len() != stripe.shard_len {
                return Err(format!(
                    "sample shard {} length {} != manifest shard_len {}",
                    shard_idx,
                    shard_bytes.len(),
                    stripe.shard_len
                ));
            }
            let leaf = hash_shard_leaf(*shard_idx, shard_bytes);
            if leaf != stripe.shard_hashes[idx] {
                return Err(format!(
                    "sample shard {} leaf SHA-256 does not match manifest shard_hashes[{}]",
                    shard_idx, idx
                ));
            }
            if shard_slots[idx].is_none() {
                populated_shards += 1;
                shard_slots[idx] = Some(shard_bytes.clone());
            }
        }

        if populated_shards < stripe.k_data {
            return Err(format!(
                "insufficient verified sample shards: got {}, need k_data = {}",
                populated_shards, stripe.k_data
            ));
        }

        let mut ciphertext = reconstruct_ciphertext_stripe(
            shard_slots,
            stripe.k_data,
            stripe.m_parity,
            stripe.original_ciphertext_len,
            Some(&stripe.shard_hashes),
            Some(stripe.stripe_merkle_root),
        )
        .map_err(|e| format!("Reed-Solomon stripe reconstruction failed: {e}"))?;

        let disclosed_key = MasterKey::from_hex(&self.disclosed_master_key_hex)
            .map_err(|e| format!("invalid disclosed_master_key_hex: {e}"))?;

        let decrypt_res = decrypt_stripe(
            &disclosed_key,
            &self.manifest.file_salt,
            stripe.stripe_index,
            &ciphertext,
        );
        ciphertext.zeroize();

        let mut plaintext = decrypt_res.map_err(|_| {
            "AES-256-GCM burden-of-proof failed: disclosed key does not authenticate reported stripe"
                .to_string()
        })?;

        let verified_plaintext_sha256 = compute_sha256(&plaintext);
        let verified_plaintext_len = plaintext.len();
        plaintext.zeroize();

        Ok(VerifiedAbuseProofOutcome {
            file_merkle_root: self.manifest.file_merkle_root,
            stripe_merkle_roots,
            verified_stripe_index: stripe.stripe_index,
            verified_plaintext_sha256,
            verified_plaintext_len,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_signing_payload(
        report_id: &[u8; 32],
        submitted_at_ms: u64,
        reporter_id_or_contact: &str,
        legal_allegation: &str,
        reported_uploader_ip: Option<IpAddr>,
        manifest: &FileManifest,
        disclosed_master_key_hex: &str,
        sample_stripe_index: u64,
        sample_shards: &[(u32, Vec<u8>)],
        reporter_ed25519_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        let manifest_digest = bincode::serialize(manifest)
            .map(|raw| compute_sha256(&raw))
            .unwrap_or([0u8; 32]);
        let mut shards_hasher = Sha256::new();
        shards_hasher.update((sample_shards.len() as u32).to_be_bytes());
        for (idx, bytes) in sample_shards {
            shards_hasher.update(idx.to_be_bytes());
            shards_hasher.update((bytes.len() as u32).to_be_bytes());
            shards_hasher.update(bytes);
        }
        let shards_digest: [u8; 32] = shards_hasher.finalize().into();

        let mut buf =
            Vec::with_capacity(256 + reporter_id_or_contact.len() + legal_allegation.len());
        buf.extend_from_slice(ABUSE_REPORT_DOMAIN);
        buf.extend_from_slice(report_id);
        buf.extend_from_slice(&submitted_at_ms.to_be_bytes());
        buf.extend_from_slice(&(reporter_id_or_contact.len() as u32).to_be_bytes());
        buf.extend_from_slice(reporter_id_or_contact.as_bytes());
        buf.extend_from_slice(&(legal_allegation.len() as u32).to_be_bytes());
        buf.extend_from_slice(legal_allegation.as_bytes());
        match reported_uploader_ip {
            None => buf.push(0x00),
            Some(IpAddr::V4(v4)) => {
                buf.push(0x04);
                buf.extend_from_slice(&v4.octets());
            }
            Some(IpAddr::V6(v6)) => {
                buf.push(0x06);
                buf.extend_from_slice(&v6.octets());
            }
        }
        buf.extend_from_slice(&manifest.file_merkle_root);
        buf.extend_from_slice(&manifest_digest);
        buf.extend_from_slice(&(disclosed_master_key_hex.len() as u32).to_be_bytes());
        buf.extend_from_slice(disclosed_master_key_hex.as_bytes());
        buf.extend_from_slice(&sample_stripe_index.to_be_bytes());
        buf.extend_from_slice(&shards_digest);
        buf.extend_from_slice(reporter_ed25519_pubkey);
        buf
    }
}

/// Governance state of a cryptographically verified abuse report on a Public Tracker (`ADR-19`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TakedownReviewStatus {
    PendingAdminReview,
    Approved {
        admin_pubkey: [u8; 32],
        approved_at_ms: u64,
        admin_note: String,
        issued_order_ids: Vec<[u8; 32]>,
    },
    Rejected {
        admin_pubkey: [u8; 32],
        rejected_at_ms: u64,
        reason: String,
    },
}

/// Persisted entry inside `PublicTrackerTakedownQueue` (`<data_dir>/admin_takedown_queue.bin`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedTakedownEntry {
    pub report: VerifiableAbuseReport,
    pub proof_outcome: VerifiedAbuseProofOutcome,
    pub status: TakedownReviewStatus,
}

/// Audit record for an emergency law-enforcement / warrant unilateral eviction action issued by
/// a Public Tracker Admin (`ADR-19`). Contains ZERO plaintext IP addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyAdminActionRecord {
    pub action_id: [u8; 32],
    pub admin_pubkey: [u8; 32],
    pub issued_at_ms: u64,
    pub warrant_or_emergency_ref: String,
    pub issued_order_ids: Vec<[u8; 32]>,
    pub local_purge: EvictionPurgeReport,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedAdminTakedownState {
    entries: Vec<QueuedTakedownEntry>,
    #[serde(default)]
    emergency_actions: Vec<EmergencyAdminActionRecord>,
}

/// Admin-governed takedown review queue for `parvault-seed` Public Trackers (`ADR-19`).
/// Enforces strict separation between **cryptographic verification** (on report submission, which
/// queues as `PendingAdminReview` and NEVER auto-deletes shards) and **centralized Public Tracker
/// Admin approval** (`approve_takedown`, which signs `SignedBadActorEvictionOrder`s under
/// `tracker_admin.seed` and executes `0x00` shard shredding), plus audited emergency law-enforcement
/// warrant evictions (`issue_emergency_admin_eviction`).
#[derive(Debug, Clone)]
pub struct PublicTrackerTakedownQueue {
    queue_path: PathBuf,
    entries: Vec<QueuedTakedownEntry>,
    emergency_actions: Vec<EmergencyAdminActionRecord>,
}

impl PublicTrackerTakedownQueue {
    /// Loads `<data_dir>/admin_takedown_queue.bin` (with bounded `64 MiB` deserialization) or
    /// initializes an empty queue.
    pub fn load_or_init(data_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let data_dir = data_dir.as_ref();
        fs::create_dir_all(data_dir)?;
        let queue_path = data_dir.join("admin_takedown_queue.bin");
        let state: PersistedAdminTakedownState = if queue_path.exists() {
            let raw = fs::read(&queue_path)?;
            if raw.len() as u64 > MAX_EVICTION_INDEX_BYTES {
                return Err(StorageError::Crypto(CryptoError::InvalidKeyMaterial(
                    "admin_takedown_queue.bin exceeds 64 MiB deserialization ceiling".into(),
                )));
            }
            bounded_bincode_options().deserialize(&raw)?
        } else {
            PersistedAdminTakedownState::default()
        };
        Ok(Self {
            queue_path,
            entries: state.entries,
            emergency_actions: state.emergency_actions,
        })
    }

    /// Initializes a strictly zero-filesystem in-memory `PublicTrackerTakedownQueue` (`--no-fs`).
    pub fn new_in_memory() -> Self {
        Self {
            queue_path: PathBuf::new(),
            entries: Vec::new(),
            emergency_actions: Vec::new(),
        }
    }

    /// Verifies `report.verify_cryptographic_burden_of_proof()` and, if valid, enqueues the report
    /// as `TakedownReviewStatus::PendingAdminReview` (`0600` atomic write). NEVER auto-evicts shards.
    pub fn enqueue_verified_report(
        &mut self,
        report: VerifiableAbuseReport,
    ) -> Result<VerifiedAbuseProofOutcome, String> {
        if self
            .entries
            .iter()
            .any(|e| e.report.report_id == report.report_id)
        {
            return Err("duplicate report_id already queued".to_string());
        }
        let proof_outcome = report.verify_cryptographic_burden_of_proof()?;

        while self.entries.len() >= MAX_TAKEDOWN_QUEUE_ENTRIES {
            // Evict oldest already-reviewed entry first; if all are pending, reject overflow.
            if let Some(pos) = self
                .entries
                .iter()
                .position(|e| !matches!(e.status, TakedownReviewStatus::PendingAdminReview))
            {
                self.entries.remove(pos);
            } else {
                return Err("admin takedown review queue is full".to_string());
            }
        }

        self.entries.push(QueuedTakedownEntry {
            report,
            proof_outcome: proof_outcome.clone(),
            status: TakedownReviewStatus::PendingAdminReview,
        });
        self.persist()
            .map_err(|e| format!("failed to persist admin takedown queue: {e}"))?;
        Ok(proof_outcome)
    }

    /// Returns a snapshot of all queued takedown entries.
    pub fn list_entries(&self) -> Vec<QueuedTakedownEntry> {
        self.entries.clone()
    }

    /// Looks up a single queued takedown entry by its 32-byte `report_id`.
    pub fn get_entry(&self, report_id: &[u8; 32]) -> Option<&QueuedTakedownEntry> {
        self.entries
            .iter()
            .find(|e| &e.report.report_id == report_id)
    }

    /// Approves a `PendingAdminReview` takedown under the Public Tracker Admin's `NodeIdentity`:
    /// 1. Signs permanent `SignedBadActorEvictionOrder`s for every verified `stripe_merkle_root`
    ///    (plus `IpAddress` and resolved `PeerOrIssuerPubkey` cohort orders if `reported_uploader_ip`
    ///    was supplied).
    /// 2. Applies all orders locally against `eviction_engine` + `block_store` (`0x00`-wiping shards
    ///    and installing persistent tombstones, including any derived `BlindedLocator`s under the
    ///    disclosed `MasterKey`).
    /// 3. Marks the entry `TakedownReviewStatus::Approved` and persists `admin_takedown_queue.bin`.
    #[allow(clippy::too_many_arguments)]
    pub fn approve_takedown(
        &mut self,
        report_id: &[u8; 32],
        admin_identity: &NodeIdentity,
        admin_note: &str,
        now_ms: u64,
        eviction_engine: &mut PrivacyPreservingEvictionEngine,
        block_store: &BlockStore,
    ) -> Result<(Vec<SignedBadActorEvictionOrder>, EvictionPurgeReport), StorageError> {
        let idx = self
            .entries
            .iter()
            .position(|e| &e.report.report_id == report_id)
            .ok_or_else(|| {
                StorageError::ShardNotFound(format!(
                    "takedown report {} not found",
                    hex::encode(report_id)
                ))
            })?;

        if !matches!(
            self.entries[idx].status,
            TakedownReviewStatus::PendingAdminReview
        ) {
            return Err(StorageError::QuotaExceeded(
                "takedown_report_already_reviewed".into(),
            ));
        }

        let clean_note =
            truncate_utf8_bytes(admin_note.trim().to_string(), MAX_EVICTION_REASON_BYTES);
        let order_reason = if clean_note.is_empty() {
            format!("tracker-admin-takedown:{}", hex::encode(&report_id[..8]))
        } else {
            clean_note.clone()
        };

        let mut orders = Vec::new();
        for stripe_root in &self.entries[idx].proof_outcome.stripe_merkle_roots {
            orders.push(SignedBadActorEvictionOrder::issue(
                admin_identity,
                EvictionTarget::StripeMerkleRoot(*stripe_root),
                order_reason.clone(),
                now_ms,
                0,
            ));
        }

        if let Some(bad_ip) = self.entries[idx].report.reported_uploader_ip {
            orders.push(SignedBadActorEvictionOrder::issue(
                admin_identity,
                EvictionTarget::IpAddress(bad_ip),
                order_reason.clone(),
                now_ms,
                0,
            ));
            for cohort_pk in eviction_engine.resolve_pubkeys_for_ip(bad_ip) {
                orders.push(SignedBadActorEvictionOrder::issue(
                    admin_identity,
                    EvictionTarget::PeerOrIssuerPubkey(cohort_pk),
                    order_reason.clone(),
                    now_ms,
                    0,
                ));
            }
        }

        let trusted = [admin_identity.public_key_bytes()];
        let mut combined_purge = EvictionPurgeReport::default();
        for order in &orders {
            let rep = eviction_engine.apply_signed_eviction_order(
                order,
                &trusted,
                now_ms,
                block_store,
            )?;
            combined_purge.merge(&rep);
        }

        // Also tombstone & purge any blinded `.bshard` locators deterministically derived from
        // the disclosed MasterKey + reported stripes on the local node.
        if let Ok(disclosed_mk) =
            MasterKey::from_hex(&self.entries[idx].report.disclosed_master_key_hex)
        {
            for stripe in &self.entries[idx].report.manifest.stripes {
                let n_shards = (stripe.k_data + stripe.m_parity) as u32;
                for shard_idx in 0..n_shards {
                    let bid = BlindedShardId::derive(
                        &disclosed_mk,
                        &stripe.stripe_merkle_root,
                        shard_idx,
                        &[],
                    );
                    let rep = eviction_engine
                        .evict_target(&EvictionTarget::BlindedLocator(bid.locator), block_store)?;
                    combined_purge.merge(&rep);
                }
            }
        }

        let issued_order_ids = orders.iter().map(|o| o.order_id).collect();
        self.entries[idx].status = TakedownReviewStatus::Approved {
            admin_pubkey: admin_identity.public_key_bytes(),
            approved_at_ms: now_ms,
            admin_note: clean_note,
            issued_order_ids,
        };
        self.persist()?;

        Ok((orders, combined_purge))
    }

    /// Marks a `PendingAdminReview` report as `TakedownReviewStatus::Rejected` without deleting shards.
    pub fn reject_takedown(
        &mut self,
        report_id: &[u8; 32],
        admin_identity: &NodeIdentity,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), StorageError> {
        let idx = self
            .entries
            .iter()
            .position(|e| &e.report.report_id == report_id)
            .ok_or_else(|| {
                StorageError::ShardNotFound(format!(
                    "takedown report {} not found",
                    hex::encode(report_id)
                ))
            })?;

        if !matches!(
            self.entries[idx].status,
            TakedownReviewStatus::PendingAdminReview
        ) {
            return Err(StorageError::QuotaExceeded(
                "takedown_report_already_reviewed".into(),
            ));
        }

        self.entries[idx].status = TakedownReviewStatus::Rejected {
            admin_pubkey: admin_identity.public_key_bytes(),
            rejected_at_ms: now_ms,
            reason: truncate_utf8_bytes(reason.trim().to_string(), MAX_EVICTION_REASON_BYTES),
        };
        self.persist()
    }

    /// Records an external governance decision (`Approved` or `Rejected`) signed/authorized by an
    /// out-of-band `parvault-control` operator (`admin_pubkey`) without requiring `tracker_admin.seed`
    /// private key material on the front-line VPS seed (`ADR-19`). Returns `Ok(true)` if the report
    /// was present on this seed and updated, or `Ok(false)` if not queued locally.
    pub fn record_external_admin_decision(
        &mut self,
        report_id: &[u8; 32],
        approved: bool,
        admin_pubkey: [u8; 32],
        note: &str,
        now_ms: u64,
    ) -> Result<bool, StorageError> {
        let Some(idx) = self
            .entries
            .iter()
            .position(|e| &e.report.report_id == report_id)
        else {
            return Ok(false);
        };
        let clean_note = truncate_utf8_bytes(note.trim().to_string(), MAX_EVICTION_REASON_BYTES);
        self.entries[idx].status = if approved {
            TakedownReviewStatus::Approved {
                admin_pubkey,
                approved_at_ms: now_ms,
                admin_note: clean_note,
                issued_order_ids: Vec::new(),
            }
        } else {
            TakedownReviewStatus::Rejected {
                admin_pubkey,
                rejected_at_ms: now_ms,
                reason: if clean_note.is_empty() {
                    "rejected-by-control-plane".to_string()
                } else {
                    clean_note
                },
            }
        };
        self.persist()?;
        Ok(true)
    }

    /// Returns a snapshot of all audited emergency law-enforcement / warrant admin eviction actions.
    pub fn list_emergency_actions(&self) -> Vec<EmergencyAdminActionRecord> {
        self.emergency_actions.clone()
    }

    /// Issues an audited emergency law-enforcement / warrant unilateral eviction under the Public
    /// Tracker Admin's `NodeIdentity` (`tracker_admin.seed`, `0600`, `ADR-19`):
    /// 1. Signs the primary `SignedBadActorEvictionOrder` for `target`.
    /// 2. If `target` is `IpAddress(ip)` (or `IpSubnet(cidr)`), also resolves any associated
    ///    `PublicCommonsTicket` / voucher Ed25519 pubkeys from `eviction_engine` and signs
    ///    additional `EvictionTarget::PeerOrIssuerPubkey(pk)` orders so relayed/blinded cohort
    ///    shards are purged across `--public` swarm nodes as well.
    /// 3. Executes `eviction_engine.apply_signed_eviction_order` locally (`0x00`-wiping shards and
    ///    installing HMAC firewall rules without writing plaintext IPs into `eviction_index.bin`)
    ///    and appends an `EmergencyAdminActionRecord` to `<data_dir>/admin_takedown_queue.bin`.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_emergency_admin_eviction(
        &mut self,
        admin_identity: &NodeIdentity,
        target: EvictionTarget,
        warrant_or_emergency_ref: &str,
        now_ms: u64,
        eviction_engine: &mut PrivacyPreservingEvictionEngine,
        block_store: &BlockStore,
    ) -> Result<(Vec<SignedBadActorEvictionOrder>, EvictionPurgeReport), StorageError> {
        let mut action_id = [0u8; 32];
        OsRng.fill_bytes(&mut action_id);

        let clean_ref = truncate_utf8_bytes(
            warrant_or_emergency_ref.trim().to_string(),
            MAX_EVICTION_REASON_BYTES,
        );
        let order_reason = if clean_ref.is_empty() {
            format!("emergency-admin-eviction:{}", hex::encode(&action_id[..8]))
        } else {
            clean_ref.clone()
        };

        let mut orders = vec![SignedBadActorEvictionOrder::issue(
            admin_identity,
            target.clone(),
            order_reason.clone(),
            now_ms,
            0,
        )];

        match &target {
            EvictionTarget::IpAddress(ip) => {
                for pk in eviction_engine.resolve_pubkeys_for_ip(*ip) {
                    orders.push(SignedBadActorEvictionOrder::issue(
                        admin_identity,
                        EvictionTarget::PeerOrIssuerPubkey(pk),
                        order_reason.clone(),
                        now_ms,
                        0,
                    ));
                }
            }
            EvictionTarget::IpSubnet(cidr) => {
                for pk in eviction_engine.resolve_pubkeys_for_subnet(cidr) {
                    orders.push(SignedBadActorEvictionOrder::issue(
                        admin_identity,
                        EvictionTarget::PeerOrIssuerPubkey(pk),
                        order_reason.clone(),
                        now_ms,
                        0,
                    ));
                }
            }
            _ => {}
        }

        let trusted = [admin_identity.public_key_bytes()];
        let mut local_purge = EvictionPurgeReport::default();
        for order in &orders {
            let rep = eviction_engine.apply_signed_eviction_order(
                order,
                &trusted,
                now_ms,
                block_store,
            )?;
            local_purge.merge(&rep);
        }

        let issued_order_ids = orders.iter().map(|o| o.order_id).collect();
        while self.emergency_actions.len() >= MAX_TAKEDOWN_QUEUE_ENTRIES {
            self.emergency_actions.remove(0);
        }
        self.emergency_actions.push(EmergencyAdminActionRecord {
            action_id,
            admin_pubkey: admin_identity.public_key_bytes(),
            issued_at_ms: now_ms,
            warrant_or_emergency_ref: clean_ref,
            issued_order_ids,
            local_purge: local_purge.clone(),
        });
        self.persist()?;

        Ok((orders, local_purge))
    }

    fn persist(&self) -> Result<(), StorageError> {
        if self.queue_path.as_os_str().is_empty() {
            return Ok(());
        }
        let state = PersistedAdminTakedownState {
            entries: self.entries.clone(),
            emergency_actions: self.emergency_actions.clone(),
        };
        let encoded = bounded_bincode_options().serialize(&state)?;
        write_secret_file_atomic_0600(&self.queue_path, &encoded)?;
        Ok(())
    }
}

/// Per-node secret HMAC key (`<data_dir>/eviction_hmac.seed`).
/// Deliberately omits `Serialize`, `Deserialize`, and raw `Debug` formatting so `K_node_evict`
/// can never be persisted inside `eviction_index.bin` or leaked over the wire (`ADR-19`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct EvictionHmacSeed([u8; 32]);

/// Zero-plaintext attribution entry for a regular `.shard` file.
/// Contains ZERO `String` or `IpAddr` fields: all network/peer identifiers are keyed HMAC-SHA256
/// tags under `K_node_evict`, and `owner_peer_id` is AEAD-sealed (`AES-256-GCM`) under an HKDF
/// subkey of `K_node_evict` solely so `BlockStore::delete_shard` can credit back quota on purge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegularShardAttribution {
    shard_id: ShardId,
    ip_hmac_tag: Option<[u8; 32]>,
    subnet_hmac_tag: Option<[u8; 32]>,
    peer_id_hmac_tag: Option<[u8; 32]>,
    owner_peer_id_hmac_tag: [u8; 32],
    uploader_pubkey: Option<[u8; 32]>,
    sealed_owner_peer_id: Vec<u8>,
}

/// Zero-plaintext attribution entry for an anonymized `.bshard` file (`ADR-11` + `ADR-19`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BlindedShardAttribution {
    blinded_id: BlindedShardId,
    ip_hmac_tag: Option<[u8; 32]>,
    subnet_hmac_tag: Option<[u8; 32]>,
    peer_id_hmac_tag: Option<[u8; 32]>,
    voucher_issuer_pubkey: [u8; 32],
}

/// On-disk persisted state (`<data_dir>/eviction_index.bin`).
/// By type-level construction, this struct graph contains ZERO `String` fields and ZERO `IpAddr`
/// octets — every persisted identifier is either a 32-byte per-node `HMAC-SHA256` digest, a
/// 32-byte cryptographic hash/pubkey, or `AES-256-GCM` ciphertext.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedEvictionIndex {
    blocked_ip_tags: HashSet<[u8; 32]>,
    blocked_subnet_tags: HashSet<[u8; 32]>,
    blocked_peer_id_tags: HashSet<[u8; 32]>,
    blocked_pubkeys: HashSet<[u8; 32]>,
    tombstoned_merkle_roots: HashSet<[u8; 32]>,
    tombstoned_blinded_locators: HashSet<[u8; 32]>,
    regular_shards: HashMap<ShardId, RegularShardAttribution>,
    blinded_shards: HashMap<[u8; 32], BlindedShardAttribution>,
    pubkeys_by_ip_tag: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    pubkeys_by_subnet_tag: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    seen_order_ids_fifo: VecDeque<[u8; 32]>,
}

/// 4-Vector Privacy-Preserving Bad-Actor & Illegal-Content Shard Eviction Engine (`ADR-19`).
pub struct PrivacyPreservingEvictionEngine {
    data_dir: PathBuf,
    index_path: PathBuf,
    hmac_seed: EvictionHmacSeed,
    index: PersistedEvictionIndex,
    seen_order_ids_set: HashSet<[u8; 32]>,
}

impl std::fmt::Debug for PrivacyPreservingEvictionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivacyPreservingEvictionEngine")
            .field("data_dir", &self.data_dir)
            .field("tracked_regular_shards", &self.index.regular_shards.len())
            .field("tracked_blinded_shards", &self.index.blinded_shards.len())
            .field("seen_orders", &self.seen_order_ids_set.len())
            .finish()
    }
}

impl PrivacyPreservingEvictionEngine {
    /// Loads `<data_dir>/eviction_hmac.seed` (or generates a fresh 32-byte `OsRng` secret with
    /// atomic `0600` permissions) and loads `<data_dir>/eviction_index.bin` using bounded
    /// `bincode::Options::with_limit(64 * 1024 * 1024)` deserialization.
    pub fn load_or_init(data_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir)?;

        let seed_path = data_dir.join("eviction_hmac.seed");
        let hmac_seed = if seed_path.exists() {
            let mut raw = fs::read(&seed_path)?;
            if raw.len() != 32 {
                let actual_len = raw.len();
                raw.zeroize();
                return Err(StorageError::Crypto(CryptoError::InvalidKeyMaterial(
                    format!("expected 32-byte eviction_hmac.seed, got {actual_len} bytes"),
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            raw.zeroize();
            let wrapped = EvictionHmacSeed(arr);
            arr.zeroize();
            wrapped
        } else {
            let mut arr = [0u8; 32];
            OsRng.fill_bytes(&mut arr);
            write_secret_file_atomic_0600(&seed_path, &arr)?;
            let wrapped = EvictionHmacSeed(arr);
            arr.zeroize();
            wrapped
        };

        let index_path = data_dir.join("eviction_index.bin");
        let index: PersistedEvictionIndex = if index_path.exists() {
            let raw = fs::read(&index_path)?;
            if raw.len() as u64 > MAX_EVICTION_INDEX_BYTES {
                return Err(StorageError::Crypto(CryptoError::InvalidKeyMaterial(
                    format!(
                        "eviction_index.bin size {} exceeds {} byte limit",
                        raw.len(),
                        MAX_EVICTION_INDEX_BYTES
                    ),
                )));
            }
            bounded_bincode_options().deserialize(&raw)?
        } else {
            PersistedEvictionIndex::default()
        };

        let seen_order_ids_set: HashSet<[u8; 32]> =
            index.seen_order_ids_fifo.iter().copied().collect();

        Ok(Self {
            data_dir,
            index_path,
            hmac_seed,
            index,
            seen_order_ids_set,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Constructs a deterministic in-memory `PrivacyPreservingEvictionEngine` from an explicit
    /// 32-byte `K_node_evict` seed without touching the filesystem or `OsRng`.
    pub fn in_memory_from_seed(seed: [u8; 32]) -> Self {
        Self {
            data_dir: PathBuf::new(),
            index_path: PathBuf::new(),
            hmac_seed: EvictionHmacSeed(seed),
            index: PersistedEvictionIndex::default(),
            seen_order_ids_set: HashSet::new(),
        }
    }

    /// Constructs an in-memory `PrivacyPreservingEvictionEngine` seeded from `OsRng` with zero
    /// filesystem directories or files created (`parvault-seed --no-fs` / `--in-memory-mb`).
    pub fn new_in_memory() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let eng = Self::in_memory_from_seed(seed);
        seed.zeroize();
        eng
    }

    /// Normalizes IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to `IpAddr::V4(a.b.c.d)` so dual-stack
    /// sockets can never bypass IPv4 HMAC tags or `/24` subnet blocks.
    pub fn normalize_ip(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => {
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    IpAddr::V4(mapped_v4)
                } else {
                    IpAddr::V6(v6)
                }
            }
        }
    }

    /// Encodes the exact domain-separated `HMAC-SHA256` input preimage for an `IpAddr`:
    /// `"parvault-evict-ip-v1:" || version_byte (0x04 | 0x06) || canonical_ip_octets`.
    pub fn encode_ip_hmac_preimage(ip: IpAddr) -> ([u8; 38], usize) {
        let normalized = Self::normalize_ip(ip);
        let mut buf = [0u8; 38];
        let pfx = EVICT_IP_DOMAIN.len();
        buf[..pfx].copy_from_slice(EVICT_IP_DOMAIN);
        match normalized {
            IpAddr::V4(v4) => {
                buf[pfx] = 0x04;
                buf[pfx + 1..pfx + 5].copy_from_slice(&v4.octets());
                (buf, pfx + 5)
            }
            IpAddr::V6(v6) => {
                buf[pfx] = 0x06;
                buf[pfx + 1..pfx + 17].copy_from_slice(&v6.octets());
                (buf, pfx + 17)
            }
        }
    }

    /// Stack-allocated domain-separated `HMAC-SHA256` input preimage for canonical subnet CIDRs up to
    /// 64 bytes: `"parvault-evict-subnet-v1:" || canonical_cidr_bytes`.
    pub fn encode_subnet_hmac_preimage_stack(
        canonical_cidr_bytes: &[u8],
    ) -> Option<([u8; 96], usize)> {
        if canonical_cidr_bytes.len() > 64 {
            return None;
        }
        let pfx = EVICT_SUBNET_DOMAIN.len();
        let total = pfx + canonical_cidr_bytes.len();
        let mut buf = [0u8; 96];
        buf[..pfx].copy_from_slice(EVICT_SUBNET_DOMAIN);
        let mut i = 0;
        while i < 64 {
            if i < canonical_cidr_bytes.len() {
                buf[pfx + i] = canonical_cidr_bytes[i];
            }
            i += 1;
        }
        Some((buf, total))
    }

    /// Encodes the exact domain-separated `HMAC-SHA256` input preimage for a canonical subnet CIDR:
    /// `"parvault-evict-subnet-v1:" || canonical_cidr.as_bytes()`.
    pub fn encode_subnet_hmac_preimage(canonical_cidr: &str) -> Vec<u8> {
        if let Some((buf, len)) = Self::encode_subnet_hmac_preimage_stack(canonical_cidr.as_bytes())
        {
            return buf[..len].to_vec();
        }
        let mut out = Vec::with_capacity(EVICT_SUBNET_DOMAIN.len() + canonical_cidr.len());
        out.extend_from_slice(EVICT_SUBNET_DOMAIN);
        out.extend_from_slice(canonical_cidr.as_bytes());
        out
    }

    /// Stack-allocated domain-separated `HMAC-SHA256` input preimage for trimmed `peer_id` bytes up to
    /// 64 bytes: `"parvault-evict-peerid-v1:" || trimmed_peer_id_bytes`.
    pub fn encode_peer_id_hmac_preimage_stack(
        trimmed_peer_id_bytes: &[u8],
    ) -> Option<([u8; 96], usize)> {
        if trimmed_peer_id_bytes.len() > 64 {
            return None;
        }
        let pfx = EVICT_PEERID_DOMAIN.len();
        let total = pfx + trimmed_peer_id_bytes.len();
        let mut buf = [0u8; 96];
        buf[..pfx].copy_from_slice(EVICT_PEERID_DOMAIN);
        let mut i = 0;
        while i < 64 {
            if i < trimmed_peer_id_bytes.len() {
                buf[pfx + i] = trimmed_peer_id_bytes[i];
            }
            i += 1;
        }
        Some((buf, total))
    }

    /// Encodes the exact domain-separated `HMAC-SHA256` input preimage for a `peer_id`:
    /// `"parvault-evict-peerid-v1:" || peer_id.trim().as_bytes()`.
    pub fn encode_peer_id_hmac_preimage(peer_id: &str) -> Vec<u8> {
        let trimmed = peer_id.trim().as_bytes();
        if let Some((buf, len)) = Self::encode_peer_id_hmac_preimage_stack(trimmed) {
            return buf[..len].to_vec();
        }
        let mut out = Vec::with_capacity(EVICT_PEERID_DOMAIN.len() + trimmed.len());
        out.extend_from_slice(EVICT_PEERID_DOMAIN);
        out.extend_from_slice(trimmed);
        out
    }

    /// Computes `HMAC-SHA256(seed, "parvault-evict-ip-v1:" || canonical_ip_bytes)` directly from a
    /// 32-byte node eviction key without allocating `HashMap` state (`getrandom`-free for Kani BMC).
    pub fn compute_ip_hmac_tag_with_seed(seed: &[u8; 32], ip: IpAddr) -> [u8; 32] {
        let (preimage, len) = Self::encode_ip_hmac_preimage(ip);
        let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(seed)
            .expect("HMAC-SHA256 accepts 32-byte key");
        mac.update(&preimage[..len]);
        let digest = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&digest);
        tag
    }

    /// Computes `HMAC-SHA256(K_node_evict, "parvault-evict-ip-v1:" || canonical_ip_bytes)`.
    /// Normalizes IPv4-mapped IPv6 `::ffff:a.b.c.d` to `IpAddr::V4(a.b.c.d)` prior to hashing.
    pub fn compute_ip_hmac_tag(&self, ip: IpAddr) -> [u8; 32] {
        Self::compute_ip_hmac_tag_with_seed(&self.hmac_seed.0, ip)
    }

    /// Canonicalizes an `IpAddr` to its privacy/routing aggregation prefix:
    /// `a.b.c.0/24` for IPv4 (and `::ffff:a.b.c.d`), or `xxxx:xxxx:xxxx::/48` for IPv6.
    pub fn canonicalize_ip_subnet(ip: IpAddr) -> String {
        match Self::normalize_ip(ip) {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                let prefix_v6 = Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0);
                format!("{prefix_v6}/48")
            }
        }
    }

    /// Computes `HMAC-SHA256(K_node_evict, "parvault-evict-subnet-v1:" || canonical_cidr)`
    /// for `ip`'s `/24` (IPv4) or `/48` (IPv6) subnet.
    pub fn compute_subnet_hmac_tag(&self, ip: IpAddr) -> [u8; 32] {
        let canonical_cidr = Self::canonicalize_ip_subnet(ip);
        self.hmac_canonical_cidr(&canonical_cidr)
    }

    /// Parses and validates an IPv4 `/24` or IPv6 `/48` CIDR string, normalizes it to canonical
    /// form (`a.b.c.0/24` or `xxxx:xxxx:xxxx::/48`), and returns its keyed subnet HMAC tag.
    pub fn compute_cidr_hmac_tag(&self, cidr: &str) -> Option<[u8; 32]> {
        let (addr_part, prefix_part) = cidr.trim().split_once('/')?;
        let parsed_ip: IpAddr = addr_part.trim().parse().ok()?;
        let prefix_len: u8 = prefix_part.trim().parse().ok()?;

        let is_mapped_v6 = matches!(parsed_ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some());
        let normalized_ip = Self::normalize_ip(parsed_ip);

        match normalized_ip {
            IpAddr::V4(_) => {
                if prefix_len != 24 && !(is_mapped_v6 && prefix_len == 120) {
                    return None;
                }
            }
            IpAddr::V6(_) => {
                if prefix_len != 48 {
                    return None;
                }
            }
        }

        let canonical = Self::canonicalize_ip_subnet(normalized_ip);
        Some(self.hmac_canonical_cidr(&canonical))
    }

    /// Computes `HMAC-SHA256(K_node_evict, "parvault-evict-peerid-v1:" || peer_id.trim())`.
    pub fn compute_peer_id_hmac_tag(&self, peer_id: &str) -> [u8; 32] {
        let preimage = Self::encode_peer_id_hmac_preimage(peer_id);
        let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&self.hmac_seed.0)
            .expect("HMAC-SHA256 accepts 32-byte key");
        mac.update(&preimage);
        let digest = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&digest);
        tag
    }

    /// Overwrites the entire existing file length on disk with `0x00` zero bytes in `64 KiB`
    /// chunks (`truncate(false)` so physical extents are wiped in place), flushes via `sync_all()`,
    /// closes the descriptor, unlinks `path`, and returns the wiped byte count (`Ok(0)` if absent).
    pub fn shred_and_unlink_file(path: &Path) -> std::io::Result<u64> {
        if !path.exists() {
            return Ok(0);
        }
        let mut file = match OpenOptions::new().write(true).truncate(false).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let total_len = file.metadata()?.len();
        file.seek(SeekFrom::Start(0))?;

        let zero_chunk = vec![0u8; ZERO_SHRED_CHUNK_BYTES];
        let mut remaining = total_len;
        while remaining > 0 {
            let chunk_len = (remaining as usize).min(ZERO_SHRED_CHUNK_BYTES);
            file.write_all(&zero_chunk[..chunk_len])?;
            remaining -= chunk_len as u64;
        }
        file.sync_all()?;
        drop(file);

        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(total_len)
    }

    /// Checks all 4 privacy-preserving blocklist / tombstone vectors before admitting an ingress
    /// RPC (`PutShard`, `PutBlindedShard`, `RenewBlindedLease`, `RelayPqOnionEnvelope`,
    /// `AdmitPublicPeer`, `RegisterWanRendezvous`). Returns `Some(reason)` if blocked.
    pub fn is_ingress_blocked(
        &self,
        remote_ip: Option<IpAddr>,
        remote_peer_id: Option<&str>,
        peer_or_issuer_pubkey: Option<&[u8; 32]>,
        stripe_merkle_root: Option<&[u8; 32]>,
        blinded_locator: Option<&[u8; 32]>,
    ) -> Option<String> {
        if let Some(ip) = remote_ip {
            let ip_tag = self.compute_ip_hmac_tag(ip);
            if self.index.blocked_ip_tags.contains(&ip_tag) {
                return Some("blocked_evicted_ip_hmac".to_string());
            }
            let subnet_tag = self.compute_subnet_hmac_tag(ip);
            if self.index.blocked_subnet_tags.contains(&subnet_tag) {
                return Some("blocked_evicted_subnet_hmac".to_string());
            }
        }

        if let Some(peer_id) = remote_peer_id {
            let trimmed = peer_id.trim();
            if !trimmed.is_empty() {
                let peer_tag = self.compute_peer_id_hmac_tag(trimmed);
                if self.index.blocked_peer_id_tags.contains(&peer_tag) {
                    return Some("blocked_evicted_peer_id_hmac".to_string());
                }
            }
        }

        if let Some(pubkey) = peer_or_issuer_pubkey {
            if self.index.blocked_pubkeys.contains(pubkey) {
                return Some("blocked_evicted_pubkey".to_string());
            }
        }

        if let Some(root) = stripe_merkle_root {
            if self.index.tombstoned_merkle_roots.contains(root) {
                return Some("tombstoned_stripe_merkle_root".to_string());
            }
        }

        if let Some(locator) = blinded_locator {
            if self.index.tombstoned_blinded_locators.contains(locator) {
                return Some("tombstoned_blinded_locator".to_string());
            }
        }

        None
    }

    /// Records privacy-preserving HMAC ingress tags for a newly stored regular `.shard` file.
    /// Never persists raw `remote_ip`, `remote_peer_id`, or plaintext `owner_peer_id` to disk.
    pub fn record_regular_shard_ingress(
        &mut self,
        remote_ip: Option<IpAddr>,
        remote_peer_id: Option<&str>,
        uploader_pubkey: Option<[u8; 32]>,
        owner_peer_id: &str,
        shard_id: ShardId,
    ) -> Result<(), StorageError> {
        let ip_hmac_tag = remote_ip.map(|ip| self.compute_ip_hmac_tag(ip));
        let subnet_hmac_tag = remote_ip.map(|ip| self.compute_subnet_hmac_tag(ip));
        let peer_id_hmac_tag = remote_peer_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|pid| self.compute_peer_id_hmac_tag(pid));
        let owner_peer_id_hmac_tag = self.compute_peer_id_hmac_tag(owner_peer_id);
        let wrap_key = self.owner_wrap_key();
        let sealed_owner_peer_id = encrypt_manifest(&wrap_key, owner_peer_id.as_bytes())?;

        self.index.regular_shards.insert(
            shard_id,
            RegularShardAttribution {
                shard_id,
                ip_hmac_tag,
                subnet_hmac_tag,
                peer_id_hmac_tag,
                owner_peer_id_hmac_tag,
                uploader_pubkey,
                sealed_owner_peer_id,
            },
        );
        self.persist_index()
    }

    /// Records privacy-preserving HMAC ingress tags and `voucher_issuer_pubkey` cohort linkage
    /// for a newly stored anonymized `.bshard` file.
    pub fn record_blinded_shard_ingress(
        &mut self,
        remote_ip: Option<IpAddr>,
        remote_peer_id: Option<&str>,
        voucher_issuer_pubkey: [u8; 32],
        blinded_id: BlindedShardId,
    ) -> Result<(), StorageError> {
        let ip_hmac_tag = remote_ip.map(|ip| self.compute_ip_hmac_tag(ip));
        let subnet_hmac_tag = remote_ip.map(|ip| self.compute_subnet_hmac_tag(ip));
        let peer_id_hmac_tag = remote_peer_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|pid| self.compute_peer_id_hmac_tag(pid));

        self.index.blinded_shards.insert(
            blinded_id.locator,
            BlindedShardAttribution {
                blinded_id,
                ip_hmac_tag,
                subnet_hmac_tag,
                peer_id_hmac_tag,
                voucher_issuer_pubkey,
            },
        );
        self.persist_index()
    }

    /// Indexes `(ip_hmac_tag -> peer_pubkey)` and `(subnet_hmac_tag -> peer_pubkey)` during
    /// tracker/seed ticket admission or voucher issuance without storing plaintext IP addresses.
    pub fn record_peer_admission_ip(
        &mut self,
        remote_ip: IpAddr,
        peer_pubkey: [u8; 32],
    ) -> Result<(), StorageError> {
        let ip_tag = self.compute_ip_hmac_tag(remote_ip);
        let subnet_tag = self.compute_subnet_hmac_tag(remote_ip);
        self.index
            .pubkeys_by_ip_tag
            .entry(ip_tag)
            .or_default()
            .insert(peer_pubkey);
        self.index
            .pubkeys_by_subnet_tag
            .entry(subnet_tag)
            .or_default()
            .insert(peer_pubkey);
        self.persist_index()
    }

    /// Resolves all Ed25519 peer/voucher pubkeys previously admitted from `ip` via its keyed
    /// `ip_hmac_tag`, enabling `parvault-seed` to broadcast mesh-wide `PeerOrIssuerPubkey`
    /// cohort eviction orders even when the bad actor uploaded shards through 1-hop relays.
    pub fn resolve_pubkeys_for_ip(&self, ip: IpAddr) -> Vec<[u8; 32]> {
        let ip_tag = self.compute_ip_hmac_tag(ip);
        let mut out: Vec<[u8; 32]> = self
            .index
            .pubkeys_by_ip_tag
            .get(&ip_tag)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        out.sort_unstable();
        out
    }

    /// Resolves all Ed25519 peer/voucher pubkeys previously admitted from a `/24` or `/48` `cidr`.
    pub fn resolve_pubkeys_for_subnet(&self, cidr: &str) -> Vec<[u8; 32]> {
        let Some(subnet_tag) = self.compute_cidr_hmac_tag(cidr) else {
            return Vec::new();
        };
        let mut out: Vec<[u8; 32]> = self
            .index
            .pubkeys_by_subnet_tag
            .get(&subnet_tag)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        out.sort_unstable();
        out
    }

    /// Returns the total number of active firewall block tags and content tombstones installed on this node.
    pub fn active_block_rules_count(&self) -> usize {
        self.index.blocked_ip_tags.len()
            + self.index.blocked_subnet_tags.len()
            + self.index.blocked_peer_id_tags.len()
            + self.index.blocked_pubkeys.len()
            + self.index.tombstoned_merkle_roots.len()
            + self.index.tombstoned_blinded_locators.len()
    }

    /// Merges any newly persisted admission/shard HMAC tags from `<data_dir>/eviction_index.bin`
    /// into in-memory tables without writing anything back to disk.
    pub fn refresh_from_disk_readonly(&mut self) {
        if !self.index_path.exists() {
            return;
        }
        let Ok(raw) = fs::read(&self.index_path) else {
            return;
        };
        if raw.len() as u64 > MAX_EVICTION_INDEX_BYTES {
            return;
        }
        let Ok(disk): Result<PersistedEvictionIndex, _> =
            bounded_bincode_options().deserialize(&raw)
        else {
            return;
        };
        for (tag, pks) in disk.pubkeys_by_ip_tag {
            self.index
                .pubkeys_by_ip_tag
                .entry(tag)
                .or_default()
                .extend(pks);
        }
        for (tag, pks) in disk.pubkeys_by_subnet_tag {
            self.index
                .pubkeys_by_subnet_tag
                .entry(tag)
                .or_default()
                .extend(pks);
        }
        for (sid, attr) in disk.regular_shards {
            self.index.regular_shards.entry(sid).or_insert(attr);
        }
        for (loc, attr) in disk.blinded_shards {
            self.index.blinded_shards.entry(loc).or_insert(attr);
        }
    }

    /// Purely read-only dry-run impact estimator for `parvault-control` (`ADR-19`):
    /// Computes `HMAC-SHA256(K_node_evict, ...)` strictly in RAM, resolves associated
    /// `PeerOrIssuerPubkey` cohorts, and counts matching local `.shard` and `.bshard` files and
    /// byte sizes **without modifying `self.index` or writing a single byte to disk**.
    pub fn count_matching_shards_dry_run(
        &self,
        target: &EvictionTarget,
        block_store: &BlockStore,
    ) -> (Vec<[u8; 32]>, usize, usize, u64) {
        let mut resolved_pks: HashSet<[u8; 32]> = HashSet::new();
        let mut matched_regular: HashSet<ShardId> = HashSet::new();
        let mut matched_bshard_paths: HashSet<PathBuf> = HashSet::new();

        match target {
            EvictionTarget::IpAddress(ip) => {
                let ip_tag = self.compute_ip_hmac_tag(*ip);
                if let Some(pks) = self.index.pubkeys_by_ip_tag.get(&ip_tag) {
                    resolved_pks.extend(pks.iter().copied());
                }
                for (sid, attr) in &self.index.regular_shards {
                    if attr.ip_hmac_tag == Some(ip_tag)
                        || attr
                            .uploader_pubkey
                            .is_some_and(|pk| resolved_pks.contains(&pk))
                    {
                        matched_regular.insert(*sid);
                        if let Some(pk) = attr.uploader_pubkey {
                            resolved_pks.insert(pk);
                        }
                    }
                }
                for attr in self.index.blinded_shards.values() {
                    if attr.ip_hmac_tag == Some(ip_tag)
                        || resolved_pks.contains(&attr.voucher_issuer_pubkey)
                    {
                        resolved_pks.insert(attr.voucher_issuer_pubkey);
                        matched_bshard_paths.insert(
                            block_store
                                .shards_dir()
                                .join(format!("{}.bshard", attr.blinded_id.file_key())),
                        );
                    }
                }
            }
            EvictionTarget::IpSubnet(cidr) => {
                if let Some(subnet_tag) = self.compute_cidr_hmac_tag(cidr) {
                    if let Some(pks) = self.index.pubkeys_by_subnet_tag.get(&subnet_tag) {
                        resolved_pks.extend(pks.iter().copied());
                    }
                    for (sid, attr) in &self.index.regular_shards {
                        if attr.subnet_hmac_tag == Some(subnet_tag)
                            || attr
                                .uploader_pubkey
                                .is_some_and(|pk| resolved_pks.contains(&pk))
                        {
                            matched_regular.insert(*sid);
                            if let Some(pk) = attr.uploader_pubkey {
                                resolved_pks.insert(pk);
                            }
                        }
                    }
                    for attr in self.index.blinded_shards.values() {
                        if attr.subnet_hmac_tag == Some(subnet_tag)
                            || resolved_pks.contains(&attr.voucher_issuer_pubkey)
                        {
                            resolved_pks.insert(attr.voucher_issuer_pubkey);
                            matched_bshard_paths.insert(
                                block_store
                                    .shards_dir()
                                    .join(format!("{}.bshard", attr.blinded_id.file_key())),
                            );
                        }
                    }
                }
            }
            EvictionTarget::Libp2pPeerId(peer_id) => {
                let trimmed = peer_id.trim();
                if !trimmed.is_empty() {
                    let peer_tag = self.compute_peer_id_hmac_tag(trimmed);
                    if let Some(pk) =
                        crate::config::NodeConfig::extract_ed25519_pubkey_from_peer_str(trimmed)
                    {
                        resolved_pks.insert(pk);
                    }
                    for (sid, attr) in &self.index.regular_shards {
                        if attr.peer_id_hmac_tag == Some(peer_tag)
                            || attr.owner_peer_id_hmac_tag == peer_tag
                        {
                            matched_regular.insert(*sid);
                            if let Some(pk) = attr.uploader_pubkey {
                                resolved_pks.insert(pk);
                            }
                        }
                    }
                    for attr in self.index.blinded_shards.values() {
                        if attr.peer_id_hmac_tag == Some(peer_tag) {
                            resolved_pks.insert(attr.voucher_issuer_pubkey);
                            matched_bshard_paths.insert(
                                block_store
                                    .shards_dir()
                                    .join(format!("{}.bshard", attr.blinded_id.file_key())),
                            );
                        }
                    }
                }
            }
            EvictionTarget::PeerOrIssuerPubkey(pubkey) => {
                resolved_pks.insert(*pubkey);
                let device_peer_tag = self.compute_peer_id_hmac_tag(&format!(
                    "parvault-peer-{}",
                    &hex::encode(pubkey)[..16]
                ));
                let libp2p_peer_tag = libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey)
                    .ok()
                    .map(|ed_pk| {
                        let pid = libp2p::identity::PublicKey::from(ed_pk)
                            .to_peer_id()
                            .to_string();
                        self.compute_peer_id_hmac_tag(&pid)
                    });
                for (sid, attr) in &self.index.regular_shards {
                    let peer_tag_match = attr.owner_peer_id_hmac_tag == device_peer_tag
                        || libp2p_peer_tag.is_some_and(|pt| {
                            attr.peer_id_hmac_tag == Some(pt) || attr.owner_peer_id_hmac_tag == pt
                        });
                    if attr.uploader_pubkey == Some(*pubkey) || peer_tag_match {
                        matched_regular.insert(*sid);
                    }
                }
                for attr in self.index.blinded_shards.values() {
                    let peer_tag_match =
                        libp2p_peer_tag.is_some_and(|pt| attr.peer_id_hmac_tag == Some(pt));
                    if attr.voucher_issuer_pubkey == *pubkey || peer_tag_match {
                        matched_bshard_paths.insert(
                            block_store
                                .shards_dir()
                                .join(format!("{}.bshard", attr.blinded_id.file_key())),
                        );
                    }
                }
            }
            EvictionTarget::StripeMerkleRoot(root) => {
                for (sid, attr) in &self.index.regular_shards {
                    if sid.stripe_merkle_root == *root {
                        matched_regular.insert(*sid);
                        if let Some(pk) = attr.uploader_pubkey {
                            resolved_pks.insert(pk);
                        }
                    }
                }
                if let Ok(stored) = block_store.list_stored_shards() {
                    for (sid, _) in stored {
                        if sid.stripe_merkle_root == *root {
                            matched_regular.insert(sid);
                        }
                    }
                }
            }
            EvictionTarget::BlindedLocator(loc) => {
                if let Some(attr) = self.index.blinded_shards.get(loc) {
                    resolved_pks.insert(attr.voucher_issuer_pubkey);
                    matched_bshard_paths.insert(
                        block_store
                            .shards_dir()
                            .join(format!("{}.bshard", attr.blinded_id.file_key())),
                    );
                }
                let direct_candidate = block_store
                    .shards_dir()
                    .join(format!("{}.bshard", hex::encode(loc)));
                if direct_candidate.exists() {
                    matched_bshard_paths.insert(direct_candidate);
                }
                let file_key_prefix = format!("blind_{}_", hex::encode(&loc[..16]));
                if let Ok(rd) = fs::read_dir(block_store.shards_dir()) {
                    for entry in rd.flatten() {
                        let path = entry.path();
                        if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                            if fname.starts_with(&file_key_prefix) && fname.ends_with(".bshard") {
                                matched_bshard_paths.insert(path);
                            }
                        }
                    }
                }
            }
        }

        let mut estimated_bytes = 0u64;
        let mut regular_on_disk = 0usize;
        for sid in &matched_regular {
            if let Some(len) = block_store.regular_shard_len(sid) {
                regular_on_disk += 1;
                estimated_bytes = estimated_bytes.saturating_add(len);
            }
        }
        let mut blinded_on_disk = 0usize;
        if block_store.is_in_memory() {
            let mut matched_locs: HashSet<[u8; 32]> = HashSet::new();
            match target {
                EvictionTarget::BlindedLocator(loc) => {
                    matched_locs.insert(*loc);
                }
                _ => {
                    for (loc, attr) in &self.index.blinded_shards {
                        let p = block_store
                            .shards_dir()
                            .join(format!("{}.bshard", attr.blinded_id.file_key()));
                        if matched_bshard_paths.contains(&p) {
                            matched_locs.insert(*loc);
                        }
                    }
                }
            }
            for loc in matched_locs {
                if let Some(len) = block_store.blinded_locator_len(&loc) {
                    blinded_on_disk += 1;
                    estimated_bytes = estimated_bytes.saturating_add(len);
                }
            }
        } else {
            for p in &matched_bshard_paths {
                if let Ok(meta) = fs::metadata(p) {
                    blinded_on_disk += 1;
                    estimated_bytes = estimated_bytes.saturating_add(meta.len());
                }
            }
        }

        let mut sorted_pks: Vec<[u8; 32]> = resolved_pks.into_iter().collect();
        sorted_pks.sort_unstable();
        (
            sorted_pks,
            regular_on_disk,
            blinded_on_disk,
            estimated_bytes,
        )
    }

    /// Executes an immediate local eviction + `0x00` file shred + persistent HMAC/digest firewall
    /// rule installation against `target`, updating `BlockStore` quota and blinded lease tables.
    pub fn evict_target(
        &mut self,
        target: &EvictionTarget,
        block_store: &BlockStore,
    ) -> Result<EvictionPurgeReport, StorageError> {
        let report = self.evict_target_unpersisted(target, block_store)?;
        self.persist_index()?;
        Ok(report)
    }

    /// Verifies `order` against `trusted_authorities` and `now_ms`, enforces the bounded
    /// 16,384-entry `seen_order_ids` anti-replay FIFO, executes `evict_target`, and atomically
    /// persists `eviction_index.bin`.
    pub fn apply_signed_eviction_order(
        &mut self,
        order: &SignedBadActorEvictionOrder,
        trusted_authorities: &[[u8; 32]],
        now_ms: u64,
        block_store: &BlockStore,
    ) -> Result<EvictionPurgeReport, StorageError> {
        if !order.verify_against_trusted_authorities(trusted_authorities, now_ms) {
            return Err(StorageError::Crypto(CryptoError::InvalidKeyMaterial(
                "rejected SignedBadActorEvictionOrder: invalid signature, untrusted issuer, or expired"
                    .into(),
            )));
        }
        if self.seen_order_ids_set.contains(&order.order_id) {
            return Err(StorageError::QuotaExceeded(
                "duplicate_replayed_eviction_order".into(),
            ));
        }

        let report = self.evict_target_unpersisted(&order.target, block_store)?;

        while self.seen_order_ids_set.len() >= MAX_SEEN_EVICTION_ORDER_IDS {
            if let Some(oldest) = self.index.seen_order_ids_fifo.pop_front() {
                self.seen_order_ids_set.remove(&oldest);
            } else {
                break;
            }
        }
        self.seen_order_ids_set.insert(order.order_id);
        self.index.seen_order_ids_fifo.push_back(order.order_id);

        self.persist_index()?;
        Ok(report)
    }

    /// Applies a `SignedBadActorEvictionOrder` enforcing **both** local hardware owner sovereignty
    /// (`1-of-1` when signed by `local_owner_pubkey`) and **`M-of-N` Federated Public Tracker
    /// Operator Council Quorum** (`min_quorum` distinct valid signers in `trusted_council_pubkeys`,
    /// `ADR-19` Part 3). Prevents both unvetted stranger trackers (`0` votes) and any single rogue
    /// council tracker (`1 < min_quorum`) from unilaterally wiping peers' shards to steal storage.
    pub fn apply_signed_eviction_order_with_quorum(
        &mut self,
        order: &SignedBadActorEvictionOrder,
        local_owner_pubkey: Option<&[u8; 32]>,
        trusted_council_pubkeys: &[[u8; 32]],
        min_quorum: usize,
        now_ms: u64,
        block_store: &BlockStore,
    ) -> Result<EvictionPurgeReport, StorageError> {
        if order.expires_at_ms != 0 && now_ms > order.expires_at_ms {
            return Err(StorageError::Crypto(CryptoError::InvalidKeyMaterial(
                "rejected SignedBadActorEvictionOrder: expired".into(),
            )));
        }

        let is_local_owner = local_owner_pubkey.is_some_and(|pk| *pk == order.issuer_pubkey)
            && order.verify_signature();
        let has_council_quorum =
            order.verify_against_quorum(trusted_council_pubkeys, min_quorum, now_ms);

        if !is_local_owner && !has_council_quorum {
            return Err(StorageError::Crypto(CryptoError::InvalidKeyMaterial(
                "rejected SignedBadActorEvictionOrder: insufficient M-of-N tracker council quorum or untrusted issuer"
                    .into(),
            )));
        }

        if self.seen_order_ids_set.contains(&order.order_id) {
            return Err(StorageError::QuotaExceeded(
                "duplicate_replayed_eviction_order".into(),
            ));
        }

        let report = self.evict_target_unpersisted(&order.target, block_store)?;

        while self.seen_order_ids_set.len() >= MAX_SEEN_EVICTION_ORDER_IDS {
            if let Some(oldest) = self.index.seen_order_ids_fifo.pop_front() {
                self.seen_order_ids_set.remove(&oldest);
            } else {
                break;
            }
        }
        self.seen_order_ids_set.insert(order.order_id);
        self.index.seen_order_ids_fifo.push_back(order.order_id);

        self.persist_index()?;
        Ok(report)
    }

    fn evict_target_unpersisted(
        &mut self,
        target: &EvictionTarget,
        block_store: &BlockStore,
    ) -> Result<EvictionPurgeReport, StorageError> {
        let wrap_key = self.owner_wrap_key();
        let mut matched_regular: HashMap<ShardId, String> = HashMap::new();
        let mut matched_blinded_locators: HashSet<[u8; 32]> = HashSet::new();
        let mut matched_bshard_paths: HashSet<PathBuf> = HashSet::new();

        match target {
            EvictionTarget::IpAddress(ip) => {
                let ip_tag = self.compute_ip_hmac_tag(*ip);
                self.index.blocked_ip_tags.insert(ip_tag);
                let cohort_pks: HashSet<[u8; 32]> = self
                    .index
                    .pubkeys_by_ip_tag
                    .get(&ip_tag)
                    .cloned()
                    .unwrap_or_default();
                for pk in &cohort_pks {
                    self.index.blocked_pubkeys.insert(*pk);
                }

                for (sid, attr) in &self.index.regular_shards {
                    if attr.ip_hmac_tag == Some(ip_tag)
                        || attr
                            .uploader_pubkey
                            .is_some_and(|pk| cohort_pks.contains(&pk))
                    {
                        matched_regular
                            .insert(*sid, unseal_owner(&wrap_key, &attr.sealed_owner_peer_id));
                    }
                }
                for (loc, attr) in &self.index.blinded_shards {
                    if attr.ip_hmac_tag == Some(ip_tag)
                        || cohort_pks.contains(&attr.voucher_issuer_pubkey)
                    {
                        matched_blinded_locators.insert(*loc);
                        matched_bshard_paths.insert(
                            block_store
                                .shards_dir()
                                .join(format!("{}.bshard", attr.blinded_id.file_key())),
                        );
                    }
                }
            }

            EvictionTarget::IpSubnet(cidr) => {
                let Some(subnet_tag) = self.compute_cidr_hmac_tag(cidr) else {
                    return Err(StorageError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid IPv4 /24 or IPv6 /48 subnet CIDR for eviction",
                    )));
                };
                self.index.blocked_subnet_tags.insert(subnet_tag);
                let cohort_pks: HashSet<[u8; 32]> = self
                    .index
                    .pubkeys_by_subnet_tag
                    .get(&subnet_tag)
                    .cloned()
                    .unwrap_or_default();
                for pk in &cohort_pks {
                    self.index.blocked_pubkeys.insert(*pk);
                }

                for (sid, attr) in &self.index.regular_shards {
                    if attr.subnet_hmac_tag == Some(subnet_tag)
                        || attr
                            .uploader_pubkey
                            .is_some_and(|pk| cohort_pks.contains(&pk))
                    {
                        matched_regular
                            .insert(*sid, unseal_owner(&wrap_key, &attr.sealed_owner_peer_id));
                    }
                }
                for (loc, attr) in &self.index.blinded_shards {
                    if attr.subnet_hmac_tag == Some(subnet_tag)
                        || cohort_pks.contains(&attr.voucher_issuer_pubkey)
                    {
                        matched_blinded_locators.insert(*loc);
                        matched_bshard_paths.insert(
                            block_store
                                .shards_dir()
                                .join(format!("{}.bshard", attr.blinded_id.file_key())),
                        );
                    }
                }
            }

            EvictionTarget::Libp2pPeerId(peer_id) => {
                let trimmed = peer_id.trim();
                if trimmed.is_empty() {
                    return Err(StorageError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "empty Libp2pPeerId eviction target",
                    )));
                }
                let peer_tag = self.compute_peer_id_hmac_tag(trimmed);
                self.index.blocked_peer_id_tags.insert(peer_tag);

                for (sid, attr) in &self.index.regular_shards {
                    if attr.peer_id_hmac_tag == Some(peer_tag)
                        || attr.owner_peer_id_hmac_tag == peer_tag
                    {
                        matched_regular
                            .insert(*sid, unseal_owner(&wrap_key, &attr.sealed_owner_peer_id));
                    }
                }
                for (loc, attr) in &self.index.blinded_shards {
                    if attr.peer_id_hmac_tag == Some(peer_tag) {
                        matched_blinded_locators.insert(*loc);
                        matched_bshard_paths.insert(
                            block_store
                                .shards_dir()
                                .join(format!("{}.bshard", attr.blinded_id.file_key())),
                        );
                    }
                }
            }

            EvictionTarget::PeerOrIssuerPubkey(pubkey) => {
                self.index.blocked_pubkeys.insert(*pubkey);

                let device_peer_tag = self.compute_peer_id_hmac_tag(&format!(
                    "parvault-peer-{}",
                    &hex::encode(pubkey)[..16]
                ));
                let libp2p_peer_tag = libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey)
                    .ok()
                    .map(|ed_pk| {
                        let pid = libp2p::identity::PublicKey::from(ed_pk)
                            .to_peer_id()
                            .to_string();
                        self.compute_peer_id_hmac_tag(&pid)
                    });
                if let Some(pid_tag) = libp2p_peer_tag {
                    self.index.blocked_peer_id_tags.insert(pid_tag);
                }

                for (sid, attr) in &self.index.regular_shards {
                    let peer_tag_match = attr.owner_peer_id_hmac_tag == device_peer_tag
                        || libp2p_peer_tag.is_some_and(|pt| {
                            attr.peer_id_hmac_tag == Some(pt) || attr.owner_peer_id_hmac_tag == pt
                        });
                    if attr.uploader_pubkey == Some(*pubkey) || peer_tag_match {
                        matched_regular
                            .insert(*sid, unseal_owner(&wrap_key, &attr.sealed_owner_peer_id));
                    }
                }
                for (loc, attr) in &self.index.blinded_shards {
                    let peer_tag_match =
                        libp2p_peer_tag.is_some_and(|pt| attr.peer_id_hmac_tag == Some(pt));
                    if attr.voucher_issuer_pubkey == *pubkey || peer_tag_match {
                        matched_blinded_locators.insert(*loc);
                        matched_bshard_paths.insert(
                            block_store
                                .shards_dir()
                                .join(format!("{}.bshard", attr.blinded_id.file_key())),
                        );
                    }
                }
            }

            EvictionTarget::StripeMerkleRoot(root) => {
                self.index.tombstoned_merkle_roots.insert(*root);
                for (sid, attr) in &self.index.regular_shards {
                    if sid.stripe_merkle_root == *root {
                        matched_regular
                            .insert(*sid, unseal_owner(&wrap_key, &attr.sealed_owner_peer_id));
                    }
                }
                for (stored_sid, _bytes) in block_store.list_stored_shards()? {
                    if stored_sid.stripe_merkle_root == *root {
                        matched_regular
                            .entry(stored_sid)
                            .or_insert_with(|| "local".to_string());
                    }
                }
            }

            EvictionTarget::BlindedLocator(loc) => {
                self.index.tombstoned_blinded_locators.insert(*loc);
                matched_blinded_locators.insert(*loc);
                if let Some(attr) = self.index.blinded_shards.get(loc) {
                    matched_bshard_paths.insert(
                        block_store
                            .shards_dir()
                            .join(format!("{}.bshard", attr.blinded_id.file_key())),
                    );
                }

                if !block_store.is_in_memory() {
                    let direct_candidate = block_store
                        .shards_dir()
                        .join(format!("{}.bshard", hex::encode(loc)));
                    if direct_candidate.exists() {
                        matched_bshard_paths.insert(direct_candidate);
                    }

                    let file_key_prefix = format!("blind_{}_", hex::encode(&loc[..16]));
                    if block_store.shards_dir().exists() {
                        for entry in fs::read_dir(block_store.shards_dir())? {
                            let path = entry?.path();
                            if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                                if fname.starts_with(&file_key_prefix) && fname.ends_with(".bshard")
                                {
                                    matched_bshard_paths.insert(path);
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut report = EvictionPurgeReport {
            purged_regular_shards: 0,
            purged_blinded_shards: 0,
            zero_wiped_bytes: 0,
            firewall_rule_installed: true,
        };

        if block_store.is_in_memory() {
            for (shard_id, owner_peer_id) in matched_regular {
                self.index.regular_shards.remove(&shard_id);
                let wiped = block_store.zero_wipe_regular_shard(&owner_peer_id, &shard_id)?;
                if wiped > 0 {
                    report.purged_regular_shards += 1;
                    report.zero_wiped_bytes = report.zero_wiped_bytes.saturating_add(wiped);
                }
            }
            for loc in matched_blinded_locators {
                self.index.blinded_shards.remove(&loc);
                let wiped = block_store.zero_wipe_blinded_locator(&loc)?;
                if wiped > 0 {
                    report.purged_blinded_shards += 1;
                    report.zero_wiped_bytes = report.zero_wiped_bytes.saturating_add(wiped);
                }
            }
            return Ok(report);
        }

        for (shard_id, owner_peer_id) in matched_regular {
            self.index.regular_shards.remove(&shard_id);
            let shard_path = block_store
                .shards_dir()
                .join(format!("{}.shard", shard_id.file_key()));
            let wiped = Self::shred_and_unlink_file(&shard_path)?;
            let deleted_by_store = block_store
                .delete_shard(&owner_peer_id, &shard_id)
                .unwrap_or(false);
            if wiped > 0 {
                report.purged_regular_shards += 1;
                report.zero_wiped_bytes = report.zero_wiped_bytes.saturating_add(wiped);
                if !deleted_by_store {
                    if let Ok(mut q) = block_store.quota().lock() {
                        q.record_shard_removed(&owner_peer_id, &shard_id.file_key(), wiped);
                    }
                }
            } else if deleted_by_store {
                report.purged_regular_shards += 1;
            }
        }

        for loc in matched_blinded_locators {
            self.index.blinded_shards.remove(&loc);
        }

        let mut any_bshard_removed = false;
        for bshard_path in matched_bshard_paths {
            let wiped = Self::shred_and_unlink_file(&bshard_path)?;
            if wiped > 0 {
                report.purged_blinded_shards += 1;
                report.zero_wiped_bytes = report.zero_wiped_bytes.saturating_add(wiped);
                any_bshard_removed = true;
            }
        }

        if any_bshard_removed {
            let _ = block_store.scrub_all_shards();
        }

        Ok(report)
    }

    fn hmac_canonical_cidr(&self, canonical_cidr: &str) -> [u8; 32] {
        let preimage = Self::encode_subnet_hmac_preimage(canonical_cidr);
        let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&self.hmac_seed.0)
            .expect("HMAC-SHA256 accepts 32-byte key");
        mac.update(&preimage);
        let digest = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&digest);
        tag
    }

    fn owner_wrap_key(&self) -> MasterKey {
        let hk = Hkdf::<Sha256>::new(
            Some(b"parvault-evict-owner-wrap-salt-v1"),
            &self.hmac_seed.0,
        );
        let mut out = [0u8; 32];
        hk.expand(b"parvault-evict-owner-wrap-aead-v1", &mut out)
            .expect("32-byte HKDF expansion is always valid");
        let mk = MasterKey::from_bytes(out);
        out.zeroize();
        mk
    }

    fn persist_index(&self) -> Result<(), StorageError> {
        if self.index_path.as_os_str().is_empty() {
            return Ok(());
        }
        let encoded = bounded_bincode_options().serialize(&self.index)?;
        BlockStore::atomic_write_file(&self.index_path, &encoded)
    }
}

fn bounded_bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_EVICTION_INDEX_BYTES)
}

fn unseal_owner(wrap_key: &MasterKey, sealed: &[u8]) -> String {
    decrypt_manifest(wrap_key, sealed)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| "local".to_string())
}

fn truncate_utf8_bytes(mut s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ErasureTier;
    use crate::sharding::merkle::hash_shard_leaf;
    use crate::storage::anonymity::{
        AnonymousQuotaVoucher, BlindedShardCapability, VoucherNullifierLedger,
    };
    use crate::storage::quota::QuotaManager;

    fn make_shard(stripe_root: [u8; 32], idx: u32, payload: &[u8]) -> ShardId {
        ShardId {
            stripe_merkle_root: stripe_root,
            shard_index: idx,
            shard_hash: hash_shard_leaf(idx, payload),
        }
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn test_zero_plaintext_ip_or_peerid_in_eviction_index_and_0600_seed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = BlockStore::new(
            dir.path(),
            QuotaManager::new(64 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .expect("store");
        let mut engine =
            PrivacyPreservingEvictionEngine::load_or_init(dir.path()).expect("engine init");

        let seed_path = dir.path().join("eviction_hmac.seed");
        let raw_seed = fs::read(&seed_path).expect("read seed");
        assert_eq!(raw_seed.len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&seed_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "eviction_hmac.seed must have 0600 permissions");
        }

        let bad_v4: IpAddr = "203.0.113.42".parse().unwrap();
        let bad_v6: IpAddr = "2001:db8:abcd:1234::99".parse().unwrap();
        let mapped_v6: IpAddr = "::ffff:198.51.100.77".parse().unwrap();
        let secret_peer_id = "12D3KooWSecretBadActorPeerId987654321";
        let secret_owner_id = "parvault-peer-deadbeefcafebabe";
        let uploader_id = NodeIdentity::generate();

        let payload = vec![0x5Au8; 4096];
        let shard_1 = make_shard([0x11u8; 32], 0, &payload);
        let shard_2 = make_shard([0x22u8; 32], 1, &payload);
        store
            .put_shard(secret_owner_id, &shard_1, &payload)
            .unwrap();
        store
            .put_shard(secret_owner_id, &shard_2, &payload)
            .unwrap();

        engine
            .record_regular_shard_ingress(
                Some(bad_v4),
                Some(secret_peer_id),
                Some(uploader_id.public_key_bytes()),
                secret_owner_id,
                shard_1,
            )
            .unwrap();
        engine
            .record_regular_shard_ingress(
                Some(bad_v6),
                Some(secret_peer_id),
                None,
                secret_owner_id,
                shard_2,
            )
            .unwrap();
        engine
            .record_peer_admission_ip(mapped_v6, uploader_id.public_key_bytes())
            .unwrap();

        // Install IP, Subnet, and PeerId eviction firewall rules so blocklists are also persisted.
        engine
            .evict_target(&EvictionTarget::IpAddress(bad_v4), &store)
            .unwrap();
        engine
            .evict_target(
                &EvictionTarget::IpSubnet("2001:db8:abcd::/48".to_string()),
                &store,
            )
            .unwrap();
        engine
            .evict_target(
                &EvictionTarget::Libp2pPeerId(secret_peer_id.to_string()),
                &store,
            )
            .unwrap();

        let index_bytes = fs::read(dir.path().join("eviction_index.bin")).expect("index file");
        assert!(
            !contains_subslice(&index_bytes, &raw_seed),
            "K_node_evict must never appear in eviction_index.bin"
        );
        assert!(!contains_subslice(&index_bytes, b"203.0.113.42"));
        assert!(!contains_subslice(&index_bytes, b"203.0.113"));
        assert!(!contains_subslice(&index_bytes, &[203, 0, 113, 42]));
        assert!(!contains_subslice(&index_bytes, b"198.51.100.77"));
        assert!(!contains_subslice(&index_bytes, &[198, 51, 100, 77]));
        assert!(!contains_subslice(&index_bytes, b"2001:db8"));
        assert!(!contains_subslice(&index_bytes, b"12D3KooW"));
        assert!(!contains_subslice(&index_bytes, secret_peer_id.as_bytes()));
        assert!(!contains_subslice(&index_bytes, secret_owner_id.as_bytes()));

        // Reload from disk and verify persistent firewall state & IP->pubkey cohort resolution survive restart.
        let reloaded =
            PrivacyPreservingEvictionEngine::load_or_init(dir.path()).expect("reload engine");
        assert!(reloaded
            .is_ingress_blocked(Some(bad_v4), None, None, None, None)
            .is_some());
        assert!(reloaded
            .is_ingress_blocked(
                Some("2001:db8:abcd:ffff::1".parse().unwrap()),
                None,
                None,
                None,
                None
            )
            .is_some());
        assert!(reloaded
            .is_ingress_blocked(None, Some(secret_peer_id), None, None, None)
            .is_some());
        assert_eq!(
            reloaded.resolve_pubkeys_for_ip("198.51.100.77".parse().unwrap()),
            vec![uploader_id.public_key_bytes()]
        );
    }

    #[test]
    fn test_cross_node_hmac_unlinkability_and_dual_stack_normalization() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let node_a = PrivacyPreservingEvictionEngine::load_or_init(dir_a.path()).unwrap();
        let node_b = PrivacyPreservingEvictionEngine::load_or_init(dir_b.path()).unwrap();

        let ip_v4: IpAddr = "203.0.113.88".parse().unwrap();
        let ip_mapped: IpAddr = "::ffff:203.0.113.88".parse().unwrap();
        let peer_id = "12D3KooWTestPeerUnlinkability";

        assert_ne!(
            node_a.compute_ip_hmac_tag(ip_v4),
            node_b.compute_ip_hmac_tag(ip_v4)
        );
        assert_ne!(
            node_a.compute_subnet_hmac_tag(ip_v4),
            node_b.compute_subnet_hmac_tag(ip_v4)
        );
        assert_ne!(
            node_a.compute_peer_id_hmac_tag(peer_id),
            node_b.compute_peer_id_hmac_tag(peer_id)
        );

        assert_eq!(
            node_a.compute_ip_hmac_tag(ip_v4),
            node_a.compute_ip_hmac_tag(ip_mapped)
        );
        assert_eq!(
            PrivacyPreservingEvictionEngine::canonicalize_ip_subnet(ip_mapped),
            "203.0.113.0/24"
        );
        assert_eq!(
            Some(node_a.compute_subnet_hmac_tag(ip_v4)),
            node_a.compute_cidr_hmac_tag("203.0.113.99/24")
        );

        let v6: IpAddr = "2001:db8:abcd:4242::7".parse().unwrap();
        assert_eq!(
            PrivacyPreservingEvictionEngine::canonicalize_ip_subnet(v6),
            "2001:db8:abcd::/48"
        );
        assert_eq!(
            Some(node_a.compute_subnet_hmac_tag(v6)),
            node_a.compute_cidr_hmac_tag("2001:0db8:abcd::1/48")
        );
        assert!(node_a.compute_cidr_hmac_tag("203.0.113.0/8").is_none());
        assert!(node_a.compute_cidr_hmac_tag("not-a-subnet").is_none());
    }

    #[test]
    fn test_shred_and_unlink_file_zero_wipes_physical_inode_before_unlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("bad_actor_payload.shard");
        let forensic_link = dir.path().join("inode_observer.hardlink");

        let size = 150 * 1024;
        fs::write(&target, vec![0xA5u8; size]).unwrap();
        fs::hard_link(&target, &forensic_link).unwrap();

        let wiped = PrivacyPreservingEvictionEngine::shred_and_unlink_file(&target).unwrap();
        assert_eq!(wiped, size as u64);
        assert!(!target.exists(), "target path must be unlinked");

        let residual = fs::read(&forensic_link).unwrap();
        assert_eq!(residual.len(), size);
        assert!(
            residual.iter().all(|&b| b == 0x00),
            "every byte of the underlying inode must be overwritten with 0x00 before unlinking"
        );

        assert_eq!(
            PrivacyPreservingEvictionEngine::shred_and_unlink_file(&target).unwrap(),
            0
        );
    }

    #[test]
    fn test_ip_eviction_purges_bad_actor_shards_and_preserves_honest_peers() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::new(
            dir.path(),
            QuotaManager::new(64 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .unwrap();
        let mut engine = PrivacyPreservingEvictionEngine::load_or_init(dir.path()).unwrap();

        let bad_ip: IpAddr = "203.0.113.66".parse().unwrap();
        let honest_ip: IpAddr = "198.51.100.10".parse().unwrap();

        let bad_bytes = vec![0xDEu8; 8192];
        let honest_bytes = vec![0x42u8; 8192];
        let bad_sid = make_shard([0xBAu8; 32], 0, &bad_bytes);
        let honest_sid = make_shard([0x99u8; 32], 0, &honest_bytes);

        let bad_path = store.put_shard("bad-peer", &bad_sid, &bad_bytes).unwrap();
        let honest_path = store
            .put_shard("honest-peer", &honest_sid, &honest_bytes)
            .unwrap();

        let bad_forensic = dir.path().join("bad_shard.hardlink");
        fs::hard_link(&bad_path, &bad_forensic).unwrap();

        engine
            .record_regular_shard_ingress(
                Some(bad_ip),
                Some("12D3KooWBad"),
                None,
                "bad-peer",
                bad_sid,
            )
            .unwrap();
        engine
            .record_regular_shard_ingress(
                Some(honest_ip),
                Some("12D3KooWHonest"),
                None,
                "honest-peer",
                honest_sid,
            )
            .unwrap();

        assert_eq!(store.quota().lock().unwrap().used_storage_bytes(), 16_384);

        let report = engine
            .evict_target(&EvictionTarget::IpAddress(bad_ip), &store)
            .unwrap();
        assert_eq!(report.purged_regular_shards, 1);
        assert_eq!(report.purged_blinded_shards, 0);
        assert_eq!(report.zero_wiped_bytes, 8192);
        assert!(report.firewall_rule_installed);

        assert!(!store.has_shard(&bad_sid));
        assert!(fs::read(&bad_forensic).unwrap().iter().all(|&b| b == 0x00));
        assert_eq!(
            store.quota().lock().unwrap().used_storage_bytes(),
            8192,
            "quota accounting must release purged bad-actor bytes while keeping honest bytes"
        );

        assert!(honest_path.exists());
        assert_eq!(store.get_shard(&honest_sid).unwrap(), honest_bytes);
        assert!(engine
            .is_ingress_blocked(Some(bad_ip), None, None, None, None)
            .is_some());
        assert!(engine
            .is_ingress_blocked(Some(honest_ip), None, None, None, None)
            .is_none());
    }

    #[test]
    fn test_blinded_voucher_issuer_cohort_and_locator_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::new(
            dir.path(),
            QuotaManager::new(64 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .unwrap();
        let mut engine = PrivacyPreservingEvictionEngine::load_or_init(dir.path()).unwrap();

        let bad_issuer = NodeIdentity::generate();
        let honest_issuer = NodeIdentity::generate();
        let bad_ip: IpAddr = "192.0.2.55".parse().unwrap();

        engine
            .record_peer_admission_ip(bad_ip, bad_issuer.public_key_bytes())
            .unwrap();
        assert_eq!(
            engine.resolve_pubkeys_for_ip(bad_ip),
            vec![bad_issuer.public_key_bytes()]
        );

        let mk_bad = MasterKey::generate();
        let mk_honest = MasterKey::generate();
        let bad_payload = vec![0xEEu8; 4096];
        let honest_payload = vec![0x77u8; 4096];
        let pre_existing_payload = vec![0x33u8; 4096];

        let bad_bid = BlindedShardId::derive(&mk_bad, &[0x01; 32], 0, &bad_payload);
        let (_, bad_cap) = BlindedShardCapability::derive_keypair(&mk_bad, &bad_bid.locator);
        let bad_voucher = AnonymousQuotaVoucher::mint(&bad_issuer, 8192);
        let mut bad_ledger = VoucherNullifierLedger::new(bad_issuer.public_key_bytes());
        let bad_bpath = store
            .put_blinded_shard(
                &bad_bid,
                &bad_payload,
                bad_cap,
                &bad_voucher,
                &mut bad_ledger,
            )
            .unwrap();
        let bad_bshard_forensic = dir.path().join("bad_bshard.hardlink");
        fs::hard_link(&bad_bpath, &bad_bshard_forensic).unwrap();

        engine
            .record_blinded_shard_ingress(
                Some("198.51.100.200".parse().unwrap()),
                Some("12D3KooWInnocentRelay"),
                bad_issuer.public_key_bytes(),
                bad_bid,
            )
            .unwrap();

        let honest_bid = BlindedShardId::derive(&mk_honest, &[0x02; 32], 0, &honest_payload);
        let (honest_cap_id, honest_cap) =
            BlindedShardCapability::derive_keypair(&mk_honest, &honest_bid.locator);
        let honest_voucher = AnonymousQuotaVoucher::mint(&honest_issuer, 8192);
        let mut honest_ledger = VoucherNullifierLedger::new(honest_issuer.public_key_bytes());
        store
            .put_blinded_shard(
                &honest_bid,
                &honest_payload,
                honest_cap,
                &honest_voucher,
                &mut honest_ledger,
            )
            .unwrap();
        engine
            .record_blinded_shard_ingress(
                Some("198.51.100.200".parse().unwrap()),
                Some("12D3KooWInnocentRelay"),
                honest_issuer.public_key_bytes(),
                honest_bid,
            )
            .unwrap();

        let pre_bid = BlindedShardId::derive(&mk_bad, &[0x03; 32], 1, &pre_existing_payload);
        let (_, pre_cap) = BlindedShardCapability::derive_keypair(&mk_bad, &pre_bid.locator);
        let pre_voucher = AnonymousQuotaVoucher::mint(&honest_issuer, 8192);
        store
            .put_blinded_shard(
                &pre_bid,
                &pre_existing_payload,
                pre_cap,
                &pre_voucher,
                &mut honest_ledger,
            )
            .unwrap();

        let report = engine
            .evict_target(
                &EvictionTarget::PeerOrIssuerPubkey(bad_issuer.public_key_bytes()),
                &store,
            )
            .unwrap();
        assert_eq!(report.purged_blinded_shards, 1);
        assert_eq!(report.zero_wiped_bytes, 4096);
        assert!(!store.has_blinded_shard_on_disk(&bad_bid));
        assert!(fs::read(&bad_bshard_forensic)
            .unwrap()
            .iter()
            .all(|&b| b == 0x00));

        assert!(engine
            .is_ingress_blocked(
                Some("198.51.100.200".parse().unwrap()),
                Some("12D3KooWInnocentRelay"),
                Some(&honest_issuer.public_key_bytes()),
                None,
                None,
            )
            .is_none());
        let read_sig =
            BlindedShardCapability::sign_read_token(&honest_cap_id, &honest_bid.locator, 1000);
        assert_eq!(
            store
                .get_blinded_shard_authorized(&honest_bid, &honest_cap, 1000, &read_sig)
                .unwrap(),
            honest_payload
        );

        let loc_report = engine
            .evict_target(&EvictionTarget::BlindedLocator(pre_bid.locator), &store)
            .unwrap();
        assert_eq!(loc_report.purged_blinded_shards, 1);
        assert!(!store.has_blinded_shard_on_disk(&pre_bid));
        assert!(engine
            .is_ingress_blocked(None, None, None, None, Some(&pre_bid.locator))
            .is_some());
    }

    #[test]
    fn test_merkle_root_takedown_signed_order_authority_and_replay_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::new(
            dir.path(),
            QuotaManager::new(64 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .unwrap();

        let illegal_root = [0x66u8; 32];
        let honest_root = [0x11u8; 32];
        let shard_data = vec![0xCCu8; 2048];
        let illegal_s0 = make_shard(illegal_root, 0, &shard_data);
        let illegal_s1 = make_shard(illegal_root, 1, &shard_data);
        let honest_s0 = make_shard(honest_root, 0, &shard_data);

        store.put_shard("local", &illegal_s0, &shard_data).unwrap();

        let mut engine = PrivacyPreservingEvictionEngine::load_or_init(dir.path()).unwrap();
        store.put_shard("peer-x", &illegal_s1, &shard_data).unwrap();
        engine
            .record_regular_shard_ingress(None, None, None, "peer-x", illegal_s1)
            .unwrap();
        store
            .put_shard("peer-good", &honest_s0, &shard_data)
            .unwrap();
        engine
            .record_regular_shard_ingress(None, None, None, "peer-good", honest_s0)
            .unwrap();

        let trusted_seed = NodeIdentity::generate();
        let rogue_actor = NodeIdentity::generate();
        let authorities = [trusted_seed.public_key_bytes()];

        let long_reason = "🚨".repeat(100);
        let valid_order = SignedBadActorEvictionOrder::issue(
            &trusted_seed,
            EvictionTarget::StripeMerkleRoot(illegal_root),
            long_reason,
            1_000_000,
            0,
        );
        assert!(valid_order.reason.len() <= MAX_EVICTION_REASON_BYTES);
        assert!(valid_order.verify_signature());
        assert!(valid_order.verify_against_trusted_authorities(&authorities, 9_999_999));

        let rogue_order = SignedBadActorEvictionOrder::issue(
            &rogue_actor,
            EvictionTarget::StripeMerkleRoot(honest_root),
            "forged takedown",
            1_000_000,
            0,
        );
        assert!(engine
            .apply_signed_eviction_order(&rogue_order, &authorities, 1_000_005, &store)
            .is_err());

        let expired_order = SignedBadActorEvictionOrder::issue(
            &trusted_seed,
            EvictionTarget::StripeMerkleRoot(honest_root),
            "expired",
            1_000,
            2_000,
        );
        assert!(engine
            .apply_signed_eviction_order(&expired_order, &authorities, 2_001, &store)
            .is_err());

        let report = engine
            .apply_signed_eviction_order(&valid_order, &authorities, 1_000_005, &store)
            .expect("apply valid eviction order");
        assert_eq!(report.purged_regular_shards, 2);
        assert_eq!(report.zero_wiped_bytes, 4096);
        assert!(!store.has_shard(&illegal_s0));
        assert!(!store.has_shard(&illegal_s1));
        assert!(store.has_shard(&honest_s0));
        assert!(engine
            .is_ingress_blocked(None, None, None, Some(&illegal_root), None)
            .is_some());

        assert!(engine
            .apply_signed_eviction_order(&valid_order, &authorities, 1_000_010, &store)
            .is_err());
    }

    #[test]
    fn test_public_tracker_burden_of_proof_anti_framing_and_admin_governance() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::new(
            dir.path(),
            QuotaManager::new(64 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .unwrap();
        let mut engine = PrivacyPreservingEvictionEngine::load_or_init(dir.path()).unwrap();
        let mut queue = PublicTrackerTakedownQueue::load_or_init(dir.path()).unwrap();

        let tracker_admin = load_or_generate_tracker_admin_identity(dir.path()).unwrap();
        let random_public_peer = NodeIdentity::generate();
        let reporter = NodeIdentity::generate();

        // 1. Store an honest user's private backup AND a bad actor's leaked illegal bundle.
        let honest_key = MasterKey::generate();
        let leaked_illegal_key = MasterKey::generate();

        let honest_input = dir.path().join("honest_family_photos.bin");
        let illegal_input = dir.path().join("leaked_contraband.bin");
        let honest_plaintext = b"honest private encrypted vault payload".repeat(256);
        let illegal_plaintext = b"publicly shared illegal payload with leaked key".repeat(256);
        fs::write(&honest_input, &honest_plaintext).unwrap();
        fs::write(&illegal_input, &illegal_plaintext).unwrap();

        let honest_manifest = store
            .store_file_streaming(
                "honest-user",
                &honest_input,
                &honest_key,
                ErasureTier::Consumer,
                65_536,
            )
            .unwrap();
        let illegal_manifest = store
            .store_file_streaming(
                "bad-actor",
                &illegal_input,
                &leaked_illegal_key,
                ErasureTier::Consumer,
                65_536,
            )
            .unwrap();

        let bad_actor_ip: IpAddr = "203.0.113.250".parse().unwrap();
        let bad_actor_ticket_id = NodeIdentity::generate();
        engine
            .record_peer_admission_ip(bad_actor_ip, bad_actor_ticket_id.public_key_bytes())
            .unwrap();

        // (a) Anti-Framing: griefer tries to frame honest user's manifest with a guessed/wrong MasterKey.
        let honest_stripe = &honest_manifest.stripes[0];
        let mut honest_sample_shards = Vec::new();
        for idx in 0..honest_stripe.k_data {
            let sid = ShardId {
                stripe_merkle_root: honest_stripe.stripe_merkle_root,
                shard_index: idx as u32,
                shard_hash: honest_stripe.shard_hashes[idx],
            };
            honest_sample_shards.push((idx as u32, store.get_shard(&sid).unwrap()));
        }
        let wrong_key = MasterKey::generate();
        let framing_report = VerifiableAbuseReport::submit_signed(
            &reporter,
            "griefer@example.invalid",
            "false framing attempt without real decryption key",
            None,
            honest_manifest.clone(),
            wrong_key.to_hex(),
            0,
            honest_sample_shards,
            5_000,
        );
        assert!(
            framing_report
                .verify_cryptographic_burden_of_proof()
                .is_err(),
            "AES-256-GCM tag verification MUST reject framing reports with wrong decryption key"
        );
        assert!(queue.enqueue_verified_report(framing_report).is_err());
        assert!(queue.list_entries().is_empty());

        // (c) Non-admin peer attempting direct SignedBadActorEvictionOrder is rejected!
        let unauth_order = SignedBadActorEvictionOrder::issue(
            &random_public_peer,
            EvictionTarget::StripeMerkleRoot(honest_stripe.stripe_merkle_root),
            "griefer peer eviction attempt",
            5_001,
            0,
        );
        assert!(engine
            .apply_signed_eviction_order(
                &unauth_order,
                &[tracker_admin.public_key_bytes()],
                5_002,
                &store,
            )
            .is_err());

        // (b) Legitimate reporter submits leaked `(FileManifest, disclosed_master_key_hex, sample_shards)`:
        // passes cryptographic burden-of-proof and queues as `PendingAdminReview` WITHOUT auto-evicting!
        let illegal_stripe = &illegal_manifest.stripes[0];
        let mut illegal_sample_shards = Vec::new();
        for idx in 0..illegal_stripe.k_data {
            let sid = ShardId {
                stripe_merkle_root: illegal_stripe.stripe_merkle_root,
                shard_index: idx as u32,
                shard_hash: illegal_stripe.shard_hashes[idx],
            };
            illegal_sample_shards.push((idx as u32, store.get_shard(&sid).unwrap()));
        }

        let valid_report = VerifiableAbuseReport::submit_signed(
            &reporter,
            "abuse-desk@org.example",
            "Verified illegal contraband distributed via public link",
            Some(bad_actor_ip),
            illegal_manifest.clone(),
            leaked_illegal_key.to_hex(),
            0,
            illegal_sample_shards,
            6_000,
        );
        let report_id = valid_report.report_id;
        let outcome = queue
            .enqueue_verified_report(valid_report)
            .expect("valid cryptographic burden-of-proof must enqueue");
        assert_eq!(
            outcome.verified_plaintext_sha256,
            compute_sha256(&illegal_plaintext)
        );
        assert_eq!(outcome.verified_plaintext_len, illegal_plaintext.len());
        assert_eq!(
            queue.get_entry(&report_id).unwrap().status,
            TakedownReviewStatus::PendingAdminReview
        );

        // Shards MUST still exist while PendingAdminReview (never auto-evict before human admin review!).
        let illegal_sid_0 = ShardId {
            stripe_merkle_root: illegal_stripe.stripe_merkle_root,
            shard_index: 0,
            shard_hash: illegal_stripe.shard_hashes[0],
        };
        assert!(store.has_shard(&illegal_sid_0));

        // (d) Public Tracker Admin approves takedown -> issues `tracker_admin`-signed orders & 0x00-wipes shards!
        let (issued_orders, purge_report) = queue
            .approve_takedown(
                &report_id,
                &tracker_admin,
                "Confirmed illegal content; approved for swarm takedown",
                7_000,
                &mut engine,
                &store,
            )
            .expect("admin approve_takedown");

        assert!(issued_orders.len() >= 3); // StripeMerkleRoot + IpAddress + resolved PeerOrIssuerPubkey
        for order in &issued_orders {
            assert!(order
                .verify_against_trusted_authorities(&[tracker_admin.public_key_bytes()], 7_001));
        }
        assert_eq!(purge_report.purged_regular_shards, 20);
        assert!(purge_report.zero_wiped_bytes > 0);
        assert!(!store.has_shard(&illegal_sid_0));
        assert!(engine
            .is_ingress_blocked(
                None,
                None,
                None,
                Some(&illegal_stripe.stripe_merkle_root),
                None,
            )
            .is_some());
        assert!(engine
            .is_ingress_blocked(
                None,
                None,
                Some(&bad_actor_ticket_id.public_key_bytes()),
                None,
                None,
            )
            .is_some());

        // Honest user's file remains 100% intact and restorable!
        let restored_honest = dir.path().join("restored_honest.bin");
        store
            .restore_file_streaming(&honest_manifest, &honest_key, &restored_honest)
            .expect("honest file must restore cleanly");
        assert_eq!(fs::read(&restored_honest).unwrap(), honest_plaintext);

        // Reload queue from disk (`0600`) and verify Approved status persisted.
        let reloaded_queue = PublicTrackerTakedownQueue::load_or_init(dir.path()).unwrap();
        assert!(matches!(
            reloaded_queue.get_entry(&report_id).unwrap().status,
            TakedownReviewStatus::Approved { .. }
        ));
    }

    #[test]
    fn test_emergency_admin_unilateral_ip_eviction_and_private_ring_isolation() {
        let seed_dir = tempfile::tempdir().unwrap();
        let pub_peer_dir = tempfile::tempdir().unwrap();
        let priv_ring_dir = tempfile::tempdir().unwrap();

        let seed_store = BlockStore::new(
            seed_dir.path(),
            QuotaManager::new(64 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .unwrap();
        let pub_store = BlockStore::new(
            pub_peer_dir.path(),
            QuotaManager::new(64 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .unwrap();
        let priv_store = BlockStore::new(
            priv_ring_dir.path(),
            QuotaManager::new(64 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .unwrap();

        let mut seed_engine =
            PrivacyPreservingEvictionEngine::load_or_init(seed_dir.path()).unwrap();
        let mut pub_engine =
            PrivacyPreservingEvictionEngine::load_or_init(pub_peer_dir.path()).unwrap();
        let mut priv_engine =
            PrivacyPreservingEvictionEngine::load_or_init(priv_ring_dir.path()).unwrap();

        let mut queue = PublicTrackerTakedownQueue::load_or_init(seed_dir.path()).unwrap();
        let tracker_admin = load_or_generate_tracker_admin_identity(seed_dir.path()).unwrap();
        let private_ring_owner = NodeIdentity::generate();
        let bad_actor_cohort_id = NodeIdentity::generate();

        let bad_ip: IpAddr = "203.0.113.66".parse().unwrap();
        seed_engine
            .record_peer_admission_ip(bad_ip, bad_actor_cohort_id.public_key_bytes())
            .unwrap();

        let shard_bytes = vec![0x9Au8; 4096];
        let bad_sid = make_shard([0x77u8; 32], 0, &shard_bytes);
        let relayed_sid = make_shard([0x88u8; 32], 0, &shard_bytes);
        let priv_sid = make_shard([0x55u8; 32], 0, &shard_bytes);

        seed_store
            .put_shard("bad-actor", &bad_sid, &shard_bytes)
            .unwrap();
        seed_engine
            .record_regular_shard_ingress(Some(bad_ip), None, None, "bad-actor", bad_sid)
            .unwrap();

        // Public swarm peer holds a shard uploaded by the bad actor's admitted pubkey from a DIFFERENT relay IP!
        pub_store
            .put_shard("bad-actor", &relayed_sid, &shard_bytes)
            .unwrap();
        pub_engine
            .record_regular_shard_ingress(
                Some("198.51.100.77".parse().unwrap()),
                None,
                Some(bad_actor_cohort_id.public_key_bytes()),
                "bad-actor",
                relayed_sid,
            )
            .unwrap();

        // Private ring node holds private family shards and trusts ONLY `private_ring_owner` (NOT `tracker_admin`).
        priv_store
            .put_shard("family", &priv_sid, &shard_bytes)
            .unwrap();
        priv_engine
            .record_regular_shard_ingress(Some(bad_ip), None, None, "family", priv_sid)
            .unwrap();

        let (emergency_orders, local_purge) = queue
            .issue_emergency_admin_eviction(
                &tracker_admin,
                EvictionTarget::IpAddress(bad_ip),
                "NCMEC-WARRANT-2026-9912",
                10_000,
                &mut seed_engine,
                &seed_store,
            )
            .expect("emergency admin eviction");

        assert_eq!(emergency_orders.len(), 2); // IpAddress + resolved PeerOrIssuerPubkey cohort
        assert_eq!(local_purge.purged_regular_shards, 1);
        assert!(!seed_store.has_shard(&bad_sid));

        // Verify zero plaintext IP strings in both eviction_index.bin AND admin_takedown_queue.bin!
        let seed_idx_raw = fs::read(seed_dir.path().join("eviction_index.bin")).unwrap();
        let queue_raw = fs::read(seed_dir.path().join("admin_takedown_queue.bin")).unwrap();
        assert!(!contains_subslice(&seed_idx_raw, b"203.0.113.66"));
        assert!(!contains_subslice(&seed_idx_raw, &[203, 0, 113, 66]));
        assert!(!contains_subslice(&queue_raw, b"203.0.113.66"));
        assert!(!contains_subslice(&queue_raw, &[203, 0, 113, 66]));
        assert_eq!(queue.list_emergency_actions().len(), 1);
        assert_eq!(
            queue.list_emergency_actions()[0].warrant_or_emergency_ref,
            "NCMEC-WARRANT-2026-9912"
        );

        // Public swarm peer accepts tracker_admin orders -> purges relayed cohort shard!
        let mut pub_purged = EvictionPurgeReport::default();
        for ord in &emergency_orders {
            let r = pub_engine
                .apply_signed_eviction_order(
                    ord,
                    &[tracker_admin.public_key_bytes()],
                    10_001,
                    &pub_store,
                )
                .unwrap();
            pub_purged.merge(&r);
        }
        assert_eq!(pub_purged.purged_regular_shards, 1);
        assert!(!pub_store.has_shard(&relayed_sid));

        // PrivateRing node strictly rejects tracker_admin orders -> family shard stays 100% untouched!
        for ord in &emergency_orders {
            assert!(priv_engine
                .apply_signed_eviction_order(
                    ord,
                    &[private_ring_owner.public_key_bytes()],
                    10_001,
                    &priv_store,
                )
                .is_err());
        }
        assert!(priv_store.has_shard(&priv_sid));
    }

    #[test]
    fn test_federated_public_tracker_m_of_n_quorum_blocks_rogue_single_tracker_wipe() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::new(
            dir.path(),
            QuotaManager::new(64 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .unwrap();
        let mut engine = PrivacyPreservingEvictionEngine::load_or_init(dir.path()).unwrap();

        let local_node_owner = NodeIdentity::generate();
        let tracker_1_honest = NodeIdentity::generate();
        let tracker_2_honest = NodeIdentity::generate();
        let tracker_3_rogue_insider = NodeIdentity::generate();
        let unvetted_stranger_tracker = NodeIdentity::generate();

        let council = [
            tracker_1_honest.public_key_bytes(),
            tracker_2_honest.public_key_bytes(),
            tracker_3_rogue_insider.public_key_bytes(),
        ];
        let min_quorum =
            SignedBadActorEvictionOrder::default_tracker_quorum_threshold(council.len());
        assert_eq!(
            min_quorum, 2,
            "3-tracker federation must default to 2-of-3 quorum"
        );
        assert_eq!(
            SignedBadActorEvictionOrder::default_tracker_quorum_threshold(1),
            1
        );
        assert_eq!(
            SignedBadActorEvictionOrder::default_tracker_quorum_threshold(5),
            3
        );

        let payload = vec![0x7Eu8; 4096];
        let honest_root = [0xAAu8; 32];
        let bad_root = [0xBBu8; 32];
        let local_root = [0xCCu8; 32];
        let honest_sid = make_shard(honest_root, 0, &payload);
        let bad_sid = make_shard(bad_root, 0, &payload);
        let local_sid = make_shard(local_root, 0, &payload);

        store.put_shard("honest", &honest_sid, &payload).unwrap();
        store.put_shard("bad", &bad_sid, &payload).unwrap();
        store.put_shard("local", &local_sid, &payload).unwrap();
        engine
            .record_regular_shard_ingress(None, None, None, "honest", honest_sid)
            .unwrap();
        engine
            .record_regular_shard_ingress(None, None, None, "bad", bad_sid)
            .unwrap();
        engine
            .record_regular_shard_ingress(None, None, None, "local", local_sid)
            .unwrap();

        // (a) Unvetted 4th rogue "public tracker" host has 0 council votes -> rejected immediately!
        let mut stranger_order = SignedBadActorEvictionOrder::issue(
            &unvetted_stranger_tracker,
            EvictionTarget::StripeMerkleRoot(honest_root),
            "stranger capacity-theft attempt",
            20_000,
            0,
        );
        // Even if stranger tries to self-cosign or duplicate!
        assert!(!stranger_order.add_cosignature(&unvetted_stranger_tracker));
        assert_eq!(stranger_order.valid_council_signer_count(&council), 0);
        assert!(engine
            .apply_signed_eviction_order_with_quorum(
                &stranger_order,
                Some(&local_node_owner.public_key_bytes()),
                &council,
                min_quorum,
                20_001,
                &store,
            )
            .is_err());
        assert!(store.has_shard(&honest_sid));

        // (b) Single compromised/rogue council member (`1-of-3`) tries to wipe honest shards to hog space -> rejected!
        let rogue_single_order = SignedBadActorEvictionOrder::issue(
            &tracker_3_rogue_insider,
            EvictionTarget::StripeMerkleRoot(honest_root),
            "unilateral rogue insider wipe",
            20_005,
            0,
        );
        assert_eq!(rogue_single_order.valid_council_signer_count(&council), 1);
        assert!(!rogue_single_order.verify_against_quorum(&council, min_quorum, 20_006));
        assert!(engine
            .apply_signed_eviction_order_with_quorum(
                &rogue_single_order,
                Some(&local_node_owner.public_key_bytes()),
                &council,
                min_quorum,
                20_006,
                &store,
            )
            .is_err());
        assert!(store.has_shard(&honest_sid));

        // (c) Legitimate takedown order starts at 1-of-3 (rejected if broadcast early), then 2nd independent
        // council operator co-signs (`2-of-3`) -> accepted and purges ONLY targeted bad_sid!
        let mut council_order = SignedBadActorEvictionOrder::issue(
            &tracker_1_honest,
            EvictionTarget::StripeMerkleRoot(bad_root),
            "verified illegal stripe takedown",
            20_010,
            0,
        );
        assert!(engine
            .apply_signed_eviction_order_with_quorum(
                &council_order,
                Some(&local_node_owner.public_key_bytes()),
                &council,
                min_quorum,
                20_011,
                &store,
            )
            .is_err());
        assert!(store.has_shard(&bad_sid));

        assert!(council_order.add_cosignature(&tracker_2_honest));
        assert!(!council_order.add_cosignature(&tracker_2_honest)); // duplicate cosigner ignored
        assert_eq!(council_order.valid_council_signer_count(&council), 2);
        assert!(council_order.verify_against_quorum(&council, min_quorum, 20_012));

        let purge = engine
            .apply_signed_eviction_order_with_quorum(
                &council_order,
                Some(&local_node_owner.public_key_bytes()),
                &council,
                min_quorum,
                20_012,
                &store,
            )
            .expect("2-of-3 council quorum must succeed");
        assert_eq!(purge.purged_regular_shards, 1);
        assert!(!store.has_shard(&bad_sid));
        assert!(store.has_shard(&honest_sid));

        // Local hardware owner (`1-of-1` local sovereignty) can always evict on their own box.
        let local_owner_order = SignedBadActorEvictionOrder::issue(
            &local_node_owner,
            EvictionTarget::StripeMerkleRoot(local_root),
            "local hardware owner cleanup",
            20_020,
            0,
        );
        let local_purge = engine
            .apply_signed_eviction_order_with_quorum(
                &local_owner_order,
                Some(&local_node_owner.public_key_bytes()),
                &council,
                min_quorum,
                20_021,
                &store,
            )
            .expect("local hardware owner 1-of-1 must succeed");
        assert_eq!(local_purge.purged_regular_shards, 1);
        assert!(!store.has_shard(&local_sid));
        assert!(store.has_shard(&honest_sid));
    }
}
