use crate::storage::ShardId;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, Rng, RngCore};
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
    let mut rng = OsRng;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let max_window = shard_total_len.clamp(1, 4096);
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
        hasher.update((slice.len() as u32).to_be_bytes());
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
    let mut rng = OsRng;
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
        let seg_len = stratum_len.clamp(1, 256);
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

/// Indices per chunk challenge by default; the host accepts `1..=MAX_CHUNK_AUDIT_WIDTH`.
pub const DEFAULT_CHUNK_AUDIT_WIDTH: u32 = 4;
/// Most indices a host proves for one chunk challenge.
pub const MAX_CHUNK_AUDIT_WIDTH: usize = 8;

/// A chunk-Merkle audit challenge (F-34, ADR-03 as amended by B-59). The indices are drawn
/// from the OS RNG, never derived from the nonce or the time: proofs are not bound to the
/// nonce, so freshness comes only from unpredictable indices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkChallenge {
    pub shard_id: ShardId,
    pub nonce: [u8; 32],
    pub chunk_indices: Vec<u32>,
    pub issued_at_unix_ms: u64,
    /// [`compute_chunk_challenge_hmac`] under the stripe's session key.
    pub hmac_token: [u8; 32],
}

/// A host's answer to a [`ChunkChallenge`]: one proof per index, in challenge order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkAuditResponse {
    pub shard_id: ShardId,
    pub nonce: [u8; 32],
    pub proofs: Vec<crate::por::chunk_merkle::ChunkProof>,
}

/// `HMAC-SHA256(K_stripe, "parvault-por-chunk-v1:" || root || u32_be(shard_index) || shard_hash
/// || nonce || u32_be(count) || u32_be(index)* || u64_be(issued_at))`. Its own domain, so a
/// `PorAudit` token is never valid as a `ChunkAudit` token or the reverse.
pub fn compute_chunk_challenge_hmac(
    session_key: &[u8; 32],
    shard_id: &ShardId,
    nonce: &[u8; 32],
    chunk_indices: &[u32],
    issued_at_unix_ms: u64,
) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(session_key)
        .expect("HMAC accepts any key length");
    mac.update(b"parvault-por-chunk-v1:");
    mac.update(&shard_id.stripe_merkle_root);
    mac.update(&shard_id.shard_index.to_be_bytes());
    mac.update(&shard_id.shard_hash);
    mac.update(nonce);
    mac.update(&(chunk_indices.len() as u32).to_be_bytes());
    for i in chunk_indices {
        mac.update(&i.to_be_bytes());
    }
    mac.update(&issued_at_unix_ms.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// `min(width, n)` distinct random indices in `0..n` from the OS RNG (verdict ruling 4).
pub fn random_chunk_indices(n: u32, width: u32) -> Vec<u32> {
    let want = width.clamp(1, MAX_CHUNK_AUDIT_WIDTH as u32).min(n.max(1)) as usize;
    let mut out: Vec<u32> = Vec::with_capacity(want);
    while out.len() < want {
        let i = OsRng.gen_range(0..n.max(1));
        if !out.contains(&i) {
            out.push(i);
        }
    }
    out
}

/// Builds a [`ChunkChallenge`] for `n` chunks with a fresh OS-random nonce and indices.
pub fn generate_chunk_challenge(
    session_key: &[u8; 32],
    shard_id: ShardId,
    n: u32,
    width: u32,
    issued_at_unix_ms: u64,
) -> ChunkChallenge {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let chunk_indices = random_chunk_indices(n, width);
    let hmac_token = compute_chunk_challenge_hmac(
        session_key,
        &shard_id,
        &nonce,
        &chunk_indices,
        issued_at_unix_ms,
    );
    ChunkChallenge {
        shard_id,
        nonce,
        chunk_indices,
        issued_at_unix_ms,
        hmac_token,
    }
}

#[cfg(test)]
mod chunk_challenge_tests {
    use super::*;

    fn sid() -> ShardId {
        ShardId {
            stripe_merkle_root: [1; 32],
            shard_index: 2,
            shard_hash: [3; 32],
        }
    }

    #[test]
    fn indices_are_distinct_and_clamped_to_n() {
        assert_eq!(random_chunk_indices(1, 4), vec![0]);
        let v = random_chunk_indices(3, 4);
        assert_eq!(v.len(), 3);
        let mut s = v.clone();
        s.sort_unstable();
        s.dedup();
        assert_eq!(s.len(), 3);
        assert_eq!(random_chunk_indices(256, 4).len(), 4);
        assert_eq!(random_chunk_indices(256, 99).len(), MAX_CHUNK_AUDIT_WIDTH);
    }

    /// Verdict change 12: a byte-range token is never a chunk token and the reverse.
    #[test]
    fn por_and_chunk_tokens_do_not_cross() {
        let k = [9u8; 32];
        let nonce = [4u8; 32];
        let chunk = compute_chunk_challenge_hmac(&k, &sid(), &nonce, &[0, 1], 7);
        let range = compute_challenge_hmac(&k, &sid(), &nonce, 0, 1, 7);
        assert_ne!(chunk, range);
        // Same numbers in the other layout still differ (domain prefix and length).
        let range2 = compute_challenge_hmac(&k, &sid(), &nonce, 2, 0, 7);
        assert_ne!(chunk, range2);
        let c = generate_chunk_challenge(&k, sid(), 16, 4, 7);
        assert_eq!(
            compute_chunk_challenge_hmac(&k, &sid(), &c.nonce, &c.chunk_indices, 7),
            c.hmac_token
        );
        assert_ne!(
            compute_chunk_challenge_hmac(&[8u8; 32], &sid(), &c.nonce, &c.chunk_indices, 7),
            c.hmac_token
        );
    }
}
