use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Hash32 = [u8; 32];

/// Computes a domain-separated SHA-256 leaf digest for a shard:
/// `H_leaf = SHA-256(0x00 || shard_index_be32 || shard_bytes)`
pub fn hash_shard_leaf(shard_index: u32, shard_bytes: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(shard_index.to_be_bytes());
    hasher.update(shard_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes a domain-separated SHA-256 internal node digest:
/// `H_node = SHA-256(0x01 || left_hash || right_hash)`
pub fn hash_internal_node(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the top-level File Merkle Root across all 16 MiB stripe Merkle roots (ADR-01).
pub fn compute_file_merkle_root(stripe_roots: &[Hash32]) -> Hash32 {
    if stripe_roots.is_empty() {
        return [0u8; 32];
    }
    let tree = MerkleTree::from_leaf_hashes(stripe_roots.to_vec());
    tree.root()
}

/// Compact Merkle inclusion proof for verifying an individual shard against its stripe Merkle root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProof {
    pub shard_index: u32,
    pub leaf_hash: Hash32,
    /// Pairs of `(sibling_hash, is_right_sibling)` from leaf level up to root.
    pub siblings: Vec<(Hash32, bool)>,
    pub root: Hash32,
}

impl MerkleProof {
    /// Verifies that `shard_bytes` at `self.shard_index` hashes to `self.root`.
    pub fn verify(&self, shard_bytes: &[u8]) -> bool {
        let computed_leaf = hash_shard_leaf(self.shard_index, shard_bytes);
        if computed_leaf != self.leaf_hash {
            return false;
        }
        self.verify_leaf_hash()
    }

    /// Verifies that `self.leaf_hash` resolves to `self.root` along `self.siblings`.
    pub fn verify_leaf_hash(&self) -> bool {
        let mut current = self.leaf_hash;
        for (sibling, is_right_sibling) in &self.siblings {
            current = if *is_right_sibling {
                hash_internal_node(&current, sibling)
            } else {
                hash_internal_node(sibling, &current)
            };
        }
        current == self.root
    }
}

/// Binary SHA-256 Merkle tree built over the `N` shards of an erasure-coded stripe.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash32>>,
}

impl MerkleTree {
    /// Constructs a Merkle tree from `N` shard byte buffers.
    pub fn from_shards(shards: &[Vec<u8>]) -> Self {
        let leaves: Vec<Hash32> = shards
            .iter()
            .enumerate()
            .map(|(i, s)| hash_shard_leaf(i as u32, s))
            .collect();
        Self::from_leaf_hashes(leaves)
    }

    /// Constructs a Merkle tree from precomputed leaf hashes.
    pub fn from_leaf_hashes(leaves: Vec<Hash32>) -> Self {
        if leaves.is_empty() {
            return Self {
                levels: vec![vec![[0u8; 32]]],
            };
        }

        let mut levels = vec![leaves];
        while levels.last().expect("non-empty").len() > 1 {
            let prev = levels.last().expect("non-empty");
            let mut next = Vec::with_capacity((prev.len() + 1) / 2);
            for chunk in prev.chunks(2) {
                let left = &chunk[0];
                let right = if chunk.len() == 2 {
                    &chunk[1]
                } else {
                    &chunk[0]
                };
                next.push(hash_internal_node(left, right));
            }
            levels.push(next);
        }

        Self { levels }
    }

    /// Returns the 32-byte Merkle root hash.
    pub fn root(&self) -> Hash32 {
        self.levels
            .last()
            .and_then(|lvl| lvl.first())
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Returns the slice of leaf shard hashes.
    pub fn leaf_hashes(&self) -> &[Hash32] {
        &self.levels[0]
    }

    /// Generates an inclusion proof for shard `index`.
    pub fn generate_proof(&self, index: usize) -> Option<MerkleProof> {
        let leaves = &self.levels[0];
        if index >= leaves.len() {
            return None;
        }
        let leaf_hash = leaves[index];
        let mut idx = index;
        let mut siblings = Vec::with_capacity(self.levels.len().saturating_sub(1));

        for level in &self.levels[..self.levels.len() - 1] {
            let is_right_child = idx % 2 == 1;
            let sibling_idx = if is_right_child {
                idx - 1
            } else if idx + 1 < level.len() {
                idx + 1
            } else {
                idx // odd tail duplicates self
            };
            siblings.push((level[sibling_idx], !is_right_child));
            idx /= 2;
        }

        Some(MerkleProof {
            shard_index: index as u32,
            leaf_hash,
            siblings,
            root: self.root(),
        })
    }
}
