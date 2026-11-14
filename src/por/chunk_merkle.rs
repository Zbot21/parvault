//! Per-shard chunk Merkle roots (`ADR-03`).
//!
//! Every new `StripeManifestEntry` records one root per shard over its `4 KiB` chunks, so an
//! owner can later challenge a storer for a random chunk plus its path without keeping the
//! shard. The audit loop that issues those challenges is not wired yet (`F-06`); this module
//! only fixes the commitment format.
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
}
