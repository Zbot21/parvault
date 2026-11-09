use crate::storage::ShardId;
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Verifier-signed stateless byte-range challenge sent to storage node `P_x` (ADR-03).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PorChallenge {
    pub shard_id: ShardId,
    pub nonce: [u8; 32],
    pub offset: u64,
    pub length: u64,
    pub issued_at_unix_ms: u64,
    /// `H_chal = HMAC-SHA256(K_session, ShardID || Nonce || Offset || Length || IssuedAt)`
    pub hmac_token: [u8; 32],
}

/// Nonce-salted SHA-256 block commitment returned by storage node `P_x`:
/// `commitment = SHA-256(Nonce || Data[Offset .. Offset + Length])`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PorResponse {
    pub shard_id: ShardId,
    pub nonce: [u8; 32],
    pub commitment: [u8; 32],
}

/// Computes `H_chal = HMAC-SHA256(K_session, ShardID || Nonce || Offset || Length || IssuedAt)`.
pub fn compute_challenge_hmac(
    session_key: &[u8; 32],
    shard_id: &ShardId,
    nonce: &[u8; 32],
    offset: u64,
    length: u64,
    issued_at_unix_ms: u64,
) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(session_key)
        .expect("HMAC accepts 32-byte key");
    mac.update(b"parvault-por-chal-v1:");
    mac.update(&shard_id.stripe_merkle_root);
    mac.update(&shard_id.shard_index.to_be_bytes());
    mac.update(&shard_id.shard_hash);
    mac.update(nonce);
    mac.update(&offset.to_be_bytes());
    mac.update(&length.to_be_bytes());
    mac.update(&issued_at_unix_ms.to_be_bytes());

    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Computes the salted hash commitment `SHA-256(Nonce || Data[Offset .. Offset + Length])`.
/// Prevents adversaries from building pre-image dictionaries or reconstructing raw shard bytes.
pub fn compute_salted_commitment(nonce: &[u8; 32], range_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(range_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Generates a random byte-range `PorChallenge` signed with `session_key` (`por::challenger`).
pub fn generate_por_challenge(
    session_key: &[u8; 32],
    shard_id: ShardId,
    shard_total_len: u64,
    issued_at_unix_ms: u64,
) -> PorChallenge {
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let max_window = shard_total_len.min(4096).max(1);
    let length = if shard_total_len <= 64 {
        shard_total_len.max(1)
    } else {
        rng.gen_range(64..=max_window)
    };
    let max_offset = shard_total_len.saturating_sub(length);
    let offset = if max_offset == 0 {
        0
    } else {
        rng.gen_range(0..=max_offset)
    };

    let hmac_token = compute_challenge_hmac(
        session_key,
        &shard_id,
        &nonce,
        offset,
        length,
        issued_at_unix_ms,
    );

    PorChallenge {
        shard_id,
        nonce,
        offset,
        length,
        issued_at_unix_ms,
        hmac_token,
    }
}

/// A single byte range `(offset, length)` inside a stratified multi-segment PoR challenge.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ByteSegment {
    pub offset: u64,
    pub length: u64,
}

/// Stratified multi-segment scatter-gather PoR challenge with an explicit anti-proxy RTT ceiling.
/// Defends against Partial-Retention attacks (keeping only part of a shard) and WAN-Proxy
/// Outsourcing attacks (forwarding PoR challenges to a remote node in real time).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiSegmentPorChallenge {
    pub shard_id: ShardId,
    pub nonce: [u8; 32],
    pub segments: Vec<ByteSegment>,
    pub max_rtt_ms: u64,
    pub issued_at_unix_ms: u64,
    pub hmac_token: [u8; 32],
}

/// Computes `HMAC-SHA256(K_session, "parvault-por-multichal-v1:" || ShardID || Nonce || Segments || MaxRtt || IssuedAt)`.
pub fn compute_multi_challenge_hmac(
    session_key: &[u8; 32],
    shard_id: &ShardId,
    nonce: &[u8; 32],
    segments: &[ByteSegment],
    max_rtt_ms: u64,
    issued_at_unix_ms: u64,
) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(session_key)
        .expect("HMAC accepts 32-byte key");
    mac.update(b"parvault-por-multichal-v1:");
    mac.update(&shard_id.stripe_merkle_root);
    mac.update(&shard_id.shard_index.to_be_bytes());
    mac.update(&shard_id.shard_hash);
    mac.update(nonce);
    mac.update(&(segments.len() as u32).to_be_bytes());
    for seg in segments {
        mac.update(&seg.offset.to_be_bytes());
        mac.update(&seg.length.to_be_bytes());
    }
    mac.update(&max_rtt_ms.to_be_bytes());
    mac.update(&issued_at_unix_ms.to_be_bytes());

    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Computes the chained salted commitment `SHA-256(Nonce || Seg_0 || Seg_1 || ... || Seg_{M-1})`.
pub fn compute_multi_salted_commitment(nonce: &[u8; 32], segment_slices: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    for slice in segment_slices {
        hasher.update(&(slice.len() as u32).to_be_bytes());
        hasher.update(slice);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Generates a stratified `MultiSegmentPorChallenge` that partitions `[0 .. shard_total_len]`
/// into `num_strata` non-overlapping strata and samples a random byte window inside every stratum.
/// Ensures any partial deletion across the shard is caught immediately.
pub fn generate_multi_segment_por_challenge(
    session_key: &[u8; 32],
    shard_id: ShardId,
    shard_total_len: u64,
    num_strata: usize,
    max_rtt_ms: u64,
    issued_at_unix_ms: u64,
) -> MultiSegmentPorChallenge {
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let strata = num_strata.max(1).min(shard_total_len.max(1) as usize);
    let stride = (shard_total_len / strata as u64).max(1);
    let mut segments = Vec::with_capacity(strata);

    for s in 0..strata {
        let start_bound = (s as u64) * stride;
        let end_bound = if s + 1 == strata {
            shard_total_len.max(1)
        } else {
            ((s as u64 + 1) * stride).min(shard_total_len.max(1))
        };
        let stratum_len = end_bound.saturating_sub(start_bound).max(1);
        let seg_len = stratum_len.min(256).max(1);
        let max_off = start_bound + stratum_len.saturating_sub(seg_len);
        let offset = if max_off <= start_bound {
            start_bound
        } else {
            rng.gen_range(start_bound..=max_off)
        };
        segments.push(ByteSegment {
            offset,
            length: seg_len,
        });
    }

    let hmac_token = compute_multi_challenge_hmac(
        session_key,
        &shard_id,
        &nonce,
        &segments,
        max_rtt_ms,
        issued_at_unix_ms,
    );

    MultiSegmentPorChallenge {
        shard_id,
        nonce,
        segments,
        max_rtt_ms,
        issued_at_unix_ms,
        hmac_token,
    }
}
