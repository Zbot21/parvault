//! Per-shard chunk Merkle roots (`ADR-03`).
//!
//! Every new `StripeManifestEntry` records one root per shard over its `4 KiB` chunks, so an
//! owner can later challenge a storer for a random chunk plus its path without keeping the
//! shard. This module fixes the commitment format, builds a chunk proof on the host
//! (`chunk_proof_streaming`) and checks one against the manifest root and `shard_len` with no
//! shard bytes (`chunk_proof_decision`, F-34). The audit loop that issues challenges is
//! `por::audit` (F-06).
//!
//! ```text
//! leaf = SHA-256(0x00 || chunk_index u32 LE || chunk_count u32 LE || chunk)
//! node = SHA-256(0x01 || left || right)        (last odd node promoted)
//! root = SHA-256(0x02 || chunk_count u32 LE || tree_root)
//! ```
//!
//! A shard of `L` bytes has `max(1, ceil(L / 4096))` chunks; the last chunk may be short and an
//! empty shard has one empty chunk. Binding the index and count into each leaf stops a storer
//! from answering for chunk `i` with chunk `j`, or from presenting a truncated tree.
//!
//! Formal model: `specs/ParVaultPorAudit.tla` (guard `chunk-proof`).

use sha2::{Digest, Sha256};

/// Chunk size the roots are computed over.
pub const CHUNK_SIZE_BYTES: usize = 4096;

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;
const ROOT_TAG: u8 = 0x02;

/// Number of chunks a shard of `shard_len` bytes is split into (at least one).
pub fn chunk_count(shard_len: usize) -> u32 {
    let n = shard_len.div_ceil(CHUNK_SIZE_BYTES).max(1);
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Leaf hash of chunk `chunk_index` out of `chunk_count`.
pub fn chunk_leaf_hash(chunk_index: u32, chunk_count: u32, chunk: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_TAG]);
    h.update(chunk_index.to_le_bytes());
    h.update(chunk_count.to_le_bytes());
    h.update(chunk);
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_TAG]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn finalize_root(chunk_count: u32, tree_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([ROOT_TAG]);
    h.update(chunk_count.to_le_bytes());
    h.update(tree_root);
    h.finalize().into()
}

/// Root over pre-computed leaves (the last odd node of a level is promoted unchanged).
fn tree_root(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [l, r] => next.push(node_hash(l, r)),
                [only] => next.push(*only),
                _ => unreachable!("chunks(2) yields one or two items"),
            }
        }
        level = next;
    }
    level[0]
}

/// [`chunk_count`] over a `u64` length, so a 32-bit host never truncates (verdict change 6).
pub fn chunk_count_u64(shard_len: u64) -> u32 {
    let n = shard_len.div_ceil(CHUNK_SIZE_BYTES as u64).max(1);
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Length chunk `index` of a `shard_len`-byte shard must have, or `None` when out of range.
pub fn expected_chunk_len(shard_len: u64, index: u32) -> Option<usize> {
    if index >= chunk_count_u64(shard_len) {
        return None;
    }
    let start = u64::from(index) * CHUNK_SIZE_BYTES as u64;
    let len = shard_len.saturating_sub(start).min(CHUNK_SIZE_BYTES as u64);
    usize::try_from(len).ok()
}

/// Most path elements a tree of `n` leaves can need: `ceil(log2 n)`.
pub fn max_path_len(n: u32) -> usize {
    (32 - n.saturating_sub(1).leading_zeros()) as usize
}

/// One chunk and its sibling hashes from leaf to tree root. There are no direction bits: the
/// verifier derives them from the index and the chunk count.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChunkProof {
    pub index: u32,
    pub chunk: Vec<u8>,
    pub path: Vec<[u8; 32]>,
}

/// Sibling path for leaf `index` over a full leaf level.
fn path_from_leaves(leaves: &[[u8; 32]], index: u32) -> Vec<[u8; 32]> {
    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut j = index as usize;
    while level.len() > 1 {
        let sib = j ^ 1;
        if sib < level.len() {
            path.push(level[sib]);
        }
        level = level
            .chunks(2)
            .map(|p| match p {
                [l, r] => node_hash(l, r),
                [only] => *only,
                _ => unreachable!("chunks(2) yields one or two items"),
            })
            .collect();
        j /= 2;
    }
    path
}

/// Host side: proofs for `indices` over a shard read one chunk at a time by `read_chunk(i)`.
/// Peak RAM is one chunk, the leaf level (32 B per chunk) and the challenged chunks. Nothing
/// here checks the shard's leaf hash, so a corrupt chunk surfaces as an invalid proof on the
/// verifier, not as a refusal on the host (verdict change 4).
pub fn chunk_proof_streaming<E>(
    shard_len: u64,
    indices: &[u32],
    mut read_chunk: impl FnMut(u32) -> Result<Vec<u8>, E>,
) -> Result<Vec<ChunkProof>, E> {
    let n = chunk_count_u64(shard_len);
    let mut leaves = Vec::with_capacity(n as usize);
    let mut kept: Vec<(u32, Vec<u8>)> = Vec::with_capacity(indices.len());
    for i in 0..n {
        let chunk = if shard_len == 0 {
            Vec::new()
        } else {
            read_chunk(i)?
        };
        leaves.push(chunk_leaf_hash(i, n, &chunk));
        if indices.contains(&i) {
            kept.push((i, chunk));
        }
    }
    Ok(indices
        .iter()
        .filter_map(|&i| {
            let chunk = kept.iter().find(|(k, _)| *k == i)?.1.clone();
            Some(ChunkProof {
                index: i,
                chunk,
                path: path_from_leaves(&leaves, i),
            })
        })
        .collect())
}

/// [`chunk_proof_streaming`] over a shard held in memory (tests and the in-memory store).
pub fn chunk_proof(shard: &[u8], index: u32) -> Option<ChunkProof> {
    let res: Result<Vec<ChunkProof>, ()> =
        chunk_proof_streaming(shard.len() as u64, &[index], |i| {
            let start = i as usize * CHUNK_SIZE_BYTES;
            Ok(shard[start..(start + CHUNK_SIZE_BYTES).min(shard.len())].to_vec())
        });
    res.ok()?.pop()
}

/// What the verifier holds when it checks one chunk proof: the manifest's root and length.
#[derive(Debug, Clone, Copy)]
pub struct ChunkProofFacts<'a> {
    pub root: &'a [u8; 32],
    pub shard_len: u64,
    pub index: u32,
    pub chunk: &'a [u8],
    pub path: &'a [[u8; 32]],
}

/// F-34: a chunk proof is valid only if the index is in range, the chunk has exactly the
/// length the manifest implies, every path element is used and none is left over, and the
/// fold ends at the manifest root. Bounds are checked before any hash (verdict change 6).
pub fn chunk_proof_decision(f: &ChunkProofFacts<'_>) -> Result<(), &'static str> {
    const INVALID: &str = "reject.por_chunk_proof_invalid";
    let n = chunk_count_u64(f.shard_len);
    let Some(want_len) = expected_chunk_len(f.shard_len, f.index) else {
        return Err(INVALID);
    };
    if f.chunk.len() != want_len || f.path.len() > max_path_len(n) {
        return Err(INVALID);
    }
    let mut acc = chunk_leaf_hash(f.index, n, f.chunk);
    let mut j = u64::from(f.index);
    let mut w = u64::from(n);
    let mut used = 0usize;
    while w > 1 {
        let promoted = j == w - 1 && w % 2 == 1;
        if !promoted {
            let Some(sib) = f.path.get(used) else {
                return Err(INVALID);
            };
            used += 1;
            acc = if j % 2 == 1 {
                node_hash(sib, &acc)
            } else {
                node_hash(&acc, sib)
            };
        }
        j /= 2;
        w = w.div_ceil(2);
    }
    if used != f.path.len() || finalize_root(n, &acc) != *f.root {
        return Err(INVALID);
    }
    Ok(())
}

/// Chunk Merkle root of one shard.
pub fn shard_chunk_root(shard: &[u8]) -> [u8; 32] {
    let count = chunk_count(shard.len());
    let leaves: Vec<[u8; 32]> = if shard.is_empty() {
        vec![chunk_leaf_hash(0, count, &[])]
    } else {
        shard
            .chunks(CHUNK_SIZE_BYTES)
            .enumerate()
            .map(|(i, c)| chunk_leaf_hash(i as u32, count, c))
            .collect()
    };
    finalize_root(count, &tree_root(leaves))
}

/// Chunk roots for every shard of a stripe, index-aligned with the shards.
pub fn stripe_chunk_roots(shards: &[Vec<u8>]) -> Vec<[u8; 32]> {
    shards.iter().map(|s| shard_chunk_root(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn chunk_count_rounds_up_and_never_zero() {
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(4096), 1);
        assert_eq!(chunk_count(4097), 2);
        assert_eq!(chunk_count(3 * 4096), 3);
    }

    #[test]
    fn single_chunk_root_matches_spec_by_hand() {
        let shard = pattern(100);
        let leaf = chunk_leaf_hash(0, 1, &shard);
        assert_eq!(shard_chunk_root(&shard), finalize_root(1, &leaf));
    }

    #[test]
    fn three_chunks_promote_the_odd_node() {
        let shard = pattern(2 * 4096 + 10);
        let l0 = chunk_leaf_hash(0, 3, &shard[..4096]);
        let l1 = chunk_leaf_hash(1, 3, &shard[4096..8192]);
        let l2 = chunk_leaf_hash(2, 3, &shard[8192..]);
        let expected = finalize_root(3, &node_hash(&node_hash(&l0, &l1), &l2));
        assert_eq!(shard_chunk_root(&shard), expected);
    }

    #[test]
    fn index_and_count_are_bound_into_the_leaf() {
        let c = pattern(4096);
        assert_ne!(chunk_leaf_hash(0, 2, &c), chunk_leaf_hash(1, 2, &c));
        assert_ne!(chunk_leaf_hash(0, 2, &c), chunk_leaf_hash(0, 3, &c));
        // Swapping two equal-length chunks changes the root.
        let mut swapped = pattern(2 * 4096);
        let orig = shard_chunk_root(&swapped);
        let (a, b) = swapped.split_at_mut(4096);
        a.swap_with_slice(b);
        assert_ne!(shard_chunk_root(&swapped), orig);
    }

    #[test]
    fn root_is_not_the_bare_tree_root() {
        let shard = pattern(4096);
        assert_ne!(shard_chunk_root(&shard), chunk_leaf_hash(0, 1, &shard));
    }

    fn check(shard: &[u8], p: &ChunkProof) -> Result<(), &'static str> {
        chunk_proof_decision(&ChunkProofFacts {
            root: &shard_chunk_root(shard),
            shard_len: shard.len() as u64,
            index: p.index,
            chunk: &p.chunk,
            path: &p.path,
        })
    }

    #[test]
    fn proof_round_trips_for_every_index() {
        for n in [1usize, 2, 3, 5, 256] {
            let shard = pattern(n * 4096 - if n > 1 { 100 } else { 0 });
            for i in 0..chunk_count(shard.len()) {
                let p = chunk_proof(&shard, i).unwrap();
                assert!(p.path.len() <= max_path_len(chunk_count(shard.len())));
                assert_eq!(check(&shard, &p), Ok(()), "n {n} i {i}");
            }
        }
        let empty = chunk_proof(&[], 0).unwrap();
        assert_eq!(check(&[], &empty), Ok(()));
    }

    #[test]
    fn forged_proofs_are_refused() {
        const BAD: Result<(), &str> = Err("reject.por_chunk_proof_invalid");
        let shard = pattern(5 * 4096 - 100);
        let p = chunk_proof(&shard, 2).unwrap();
        // Wrong index: chunk 2 presented as chunk 3, and out of range.
        let mut q = p.clone();
        q.index = 3;
        assert_eq!(check(&shard, &q), BAD);
        q.index = 5;
        assert_eq!(check(&shard, &q), BAD);
        // Swapped sibling.
        let mut q = p.clone();
        q.path.swap(0, 1);
        assert_eq!(check(&shard, &q), BAD);
        // Extra and missing path element.
        let mut q = p.clone();
        q.path.push([0u8; 32]);
        assert_eq!(check(&shard, &q), BAD);
        let mut q = p.clone();
        q.path.pop();
        assert_eq!(check(&shard, &q), BAD);
        // Short last chunk padded to full size.
        let mut q = chunk_proof(&shard, 4).unwrap();
        q.chunk.resize(4096, 0);
        assert_eq!(check(&shard, &q), BAD);
        // A chunk from another shard with its own valid path.
        let other = pattern(5 * 4096 - 99);
        let q = chunk_proof(&other, 2).unwrap();
        assert_eq!(check(&shard, &q), BAD);
        // One flipped byte.
        let mut q = p.clone();
        q.chunk[7] ^= 1;
        assert_eq!(check(&shard, &q), BAD);
    }

    #[test]
    fn path_bound_is_checked_before_hashing() {
        let shard = pattern(3 * 4096);
        let mut p = chunk_proof(&shard, 0).unwrap();
        p.path = vec![[0u8; 32]; 10_000];
        assert_eq!(check(&shard, &p), Err("reject.por_chunk_proof_invalid"));
        assert_eq!(max_path_len(1), 0);
        assert_eq!(max_path_len(2), 1);
        assert_eq!(max_path_len(3), 2);
        assert_eq!(max_path_len(256), 8);
        assert_eq!(max_path_len(257), 9);
    }

    #[test]
    fn u64_lengths_do_not_truncate() {
        let big = u64::from(u32::MAX) * 4096 + 1;
        assert_eq!(chunk_count_u64(big), u32::MAX);
        assert_eq!(expected_chunk_len(4097, 1), Some(1));
        assert_eq!(expected_chunk_len(4097, 2), None);
        assert_eq!(expected_chunk_len(0, 0), Some(0));
    }

    /// Golden path at `n = 3` (pattern `i % 251`, length `2·4096 + 10`, index 1): the path is
    /// leaf 0 then leaf 2 (the promoted node).
    #[test]
    fn golden_path_n3() {
        let shard = pattern(2 * 4096 + 10);
        let p = chunk_proof(&shard, 1).unwrap();
        assert_eq!(p.path.len(), 2);
        assert_eq!(p.path[0], chunk_leaf_hash(0, 3, &shard[..4096]));
        assert_eq!(p.path[1], chunk_leaf_hash(2, 3, &shard[8192..]));
        assert_eq!(hex::encode(p.path[0]), GOLDEN_PATH_N3_0);
        assert_eq!(hex::encode(p.path[1]), GOLDEN_PATH_N3_1);
        // The last (promoted) leaf has a single sibling: the level-1 node.
        let last = chunk_proof(&shard, 2).unwrap();
        assert_eq!(last.path.len(), 1);
        assert_eq!(check(&shard, &last), Ok(()));
    }

    /// Exhaustive over `n <= 64` (no proptest dependency): every index verifies and a flipped
    /// byte in the chunk fails.
    #[test]
    fn exhaustive_small_trees_verify_and_flips_fail() {
        for n in 1usize..=64 {
            let len = (n - 1) * 4096 + 1 + (n * 37) % 4096;
            let shard = pattern(len);
            for i in 0..chunk_count(len) {
                let p = chunk_proof(&shard, i).unwrap();
                assert_eq!(check(&shard, &p), Ok(()), "n {n} i {i}");
                let mut q = p.clone();
                let at = (i as usize * 13) % q.chunk.len();
                q.chunk[at] ^= 0x80;
                assert_eq!(check(&shard, &q), Err("reject.por_chunk_proof_invalid"));
            }
        }
    }

    /// Golden vectors (computed independently with Python `hashlib`; pattern byte `i % 251`).
    /// Any change to the format breaks every recorded manifest root.
    #[test]
    fn golden_vectors() {
        let cases: [(usize, &str); 5] = [
            (0, GOLDEN_EMPTY),
            (1, GOLDEN_1),
            (4096, GOLDEN_4096),
            (4097, GOLDEN_4097),
            (3 * 4096 + 7, GOLDEN_12295),
        ];
        for (len, want) in cases {
            assert_eq!(
                hex::encode(shard_chunk_root(&pattern(len))),
                want,
                "len {len}"
            );
        }
    }

    const GOLDEN_EMPTY: &str = "a373c03f4f9eba4893541bd348782db5c4e853acfc2b8773788ce74ea064782e";
    const GOLDEN_1: &str = "d6f24ba4d55af7a4820d7f8b2e0b32f91583b87d22fddfc4012cc30b50d09f83";
    const GOLDEN_4096: &str = "8f174de8f58996b8e43fddcb38125d92a8e370e2e2e1f3b5a62611664d5ae1a4";
    const GOLDEN_4097: &str = "71d756fdb7ff5bcf6f6a09423afc055d6e22b87cd1705a4633b5e871a6c8d9bd";
    const GOLDEN_12295: &str = "314f16676d45e76e0035794f152c2ae9e3ca8f55e883f8a9b3266fd95736b8bc";
    const GOLDEN_PATH_N3_0: &str =
        "61b1a26e2feae956ac8fd79e903d170e72e85c92a42e090b9aaba7830f1a7394";
    const GOLDEN_PATH_N3_1: &str =
        "377bf8ee1c3310d4c6e54f08dbc24d1bf4c76cf682336f77004fb10721e1c25c";
}
