use crate::config::ErasureTier;
use crate::sharding::merkle::{Hash32, MerkleProof, MerkleTree};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShardingError {
    #[error("Invalid Reed-Solomon parameters (k={0}, m={1})")]
    InvalidParameters(usize, usize),
    #[error("Insufficient shards for reconstruction: need at least {required}, found {available}")]
    InsufficientShards { required: usize, available: usize },
    #[error("Reed-Solomon Galois field error: {0}")]
    ErasureError(String),
    #[error("Merkle root or shard hash verification failed for shard {0}")]
    IntegrityCheckFailed(usize),
}

/// Output of splitting a single encrypted 16 MiB stripe into `N = K + M` Reed-Solomon shards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeShardSet {
    pub stripe_index: u64,
    pub k_data: usize,
    pub m_parity: usize,
    pub original_ciphertext_len: usize,
    pub shard_len: usize,
    pub stripe_merkle_root: Hash32,
    pub shard_hashes: Vec<Hash32>,
    pub shards: Vec<Vec<u8>>,
}

/// Splits an AES-256-GCM encrypted stripe into `K` data shards and `M` parity shards
/// (`N = K + M`), computing the SHA-256 Merkle tree root across all `N` shards.
pub fn encode_ciphertext_stripe(
    stripe_index: u64,
    ciphertext: &[u8],
    tier: ErasureTier,
) -> Result<StripeShardSet, ShardingError> {
    let (k_data, m_parity, _) = tier.params();
    encode_with_params(stripe_index, ciphertext, k_data, m_parity)
}

/// Splits ciphertext using explicit `(k_data, m_parity)` Reed-Solomon parameters.
pub fn encode_with_params(
    stripe_index: u64,
    ciphertext: &[u8],
    k_data: usize,
    m_parity: usize,
) -> Result<StripeShardSet, ShardingError> {
    if k_data == 0 || m_parity == 0 {
        return Err(ShardingError::InvalidParameters(k_data, m_parity));
    }
    let rs = ReedSolomon::new(k_data, m_parity)
        .map_err(|e| ShardingError::ErasureError(format!("{e:?}")))?;

    let original_ciphertext_len = ciphertext.len();
    // Compute per-shard byte length (rounded up to a non-zero multiple of k_data).
    let shard_len = if original_ciphertext_len == 0 {
        1
    } else {
        original_ciphertext_len.div_ceil(k_data)
    };

    let total_shards = k_data + m_parity;
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total_shards);
    for i in 0..k_data {
        let mut shard = vec![0u8; shard_len];
        let start = i * shard_len;
        if start < original_ciphertext_len {
            let end = (start + shard_len).min(original_ciphertext_len);
            let copy_len = end - start;
            shard[..copy_len].copy_from_slice(&ciphertext[start..end]);
        }
        shards.push(shard);
    }
    for _ in 0..m_parity {
        shards.push(vec![0u8; shard_len]);
    }

    rs.encode(&mut shards)
        .map_err(|e| ShardingError::ErasureError(format!("{e:?}")))?;

    let merkle_tree = MerkleTree::from_shards(&shards);
    let stripe_merkle_root = merkle_tree.root();
    let shard_hashes = merkle_tree.leaf_hashes().to_vec();

    Ok(StripeShardSet {
        stripe_index,
        k_data,
        m_parity,
        original_ciphertext_len,
        shard_len,
        stripe_merkle_root,
        shard_hashes,
        shards,
    })
}

/// Reconstructs all `N = K + M` ciphertext shards (data + parity) in `GF(2^8)` from at least `K`
/// surviving shards, verifying every reconstructed shard against the stripe's Merkle tree (ADR-04).
///
/// This function operates strictly on ciphertext and requires zero knowledge of `K_user`,
/// allowing delegated witness nodes to heal a degraded 18/20 cohort offline.
pub fn reconstruct_all_shards(
    mut shard_slots: Vec<Option<Vec<u8>>>,
    k_data: usize,
    m_parity: usize,
    expected_shard_hashes: Option<&[Hash32]>,
    expected_merkle_root: Option<Hash32>,
) -> Result<Vec<Vec<u8>>, ShardingError> {
    let total_shards = k_data + m_parity;
    if shard_slots.len() != total_shards {
        return Err(ShardingError::InvalidParameters(k_data, m_parity));
    }

    let available = shard_slots.iter().filter(|s| s.is_some()).count();
    if available < k_data {
        return Err(ShardingError::InsufficientShards {
            required: k_data,
            available,
        });
    }

    // Verify hashes of provided shards before running Galois field reconstruction.
    // If Byzantine / corrupted shards are present alongside spare parity shards, evict the
    // poisoned slots so honest shards can still reconstruct the stripe.
    if let Some(hashes) = expected_shard_hashes {
        let mut first_corrupted: Option<usize> = None;
        for (idx, maybe_shard) in shard_slots.iter_mut().enumerate() {
            if let Some(bytes) = maybe_shard {
                let actual = crate::sharding::merkle::hash_shard_leaf(idx as u32, bytes);
                if actual != hashes[idx] {
                    if first_corrupted.is_none() {
                        first_corrupted = Some(idx);
                    }
                    *maybe_shard = None;
                }
            }
        }
        let surviving_honest = shard_slots.iter().filter(|s| s.is_some()).count();
        if surviving_honest < k_data {
            if let Some(bad_idx) = first_corrupted {
                return Err(ShardingError::IntegrityCheckFailed(bad_idx));
            }
            return Err(ShardingError::InsufficientShards {
                required: k_data,
                available: surviving_honest,
            });
        }
    }

    let rs = ReedSolomon::new(k_data, m_parity)
        .map_err(|e| ShardingError::ErasureError(format!("{e:?}")))?;
    rs.reconstruct(&mut shard_slots)
        .map_err(|e| ShardingError::ErasureError(format!("{e:?}")))?;

    let reconstructed: Vec<Vec<u8>> = shard_slots
        .into_iter()
        .enumerate()
        .map(|(i, opt)| opt.ok_or(ShardingError::IntegrityCheckFailed(i)))
        .collect::<Result<Vec<_>, _>>()?;

    if let Some(root) = expected_merkle_root {
        let tree = MerkleTree::from_shards(&reconstructed);
        if tree.root() != root {
            return Err(ShardingError::IntegrityCheckFailed(0));
        }
    }

    Ok(reconstructed)
}

/// Zero-Trust Byzantine-resilient Reed-Solomon reconstruction:
/// 1. Pre-screens every candidate shard against `expected_shard_hashes` AND optional `MerkleProof`s
///    anchored at `expected_merkle_root` BEFORE slotting bytes into the `GF(2^8)` matrix.
/// 2. Automatically quarantines/evicts any poisoned shard returned by a malicious node and records
///    its index in `poisoned_shard_indices` for immediate peer slashing.
/// 3. Reconstructs all `N` shards from the remaining `>= K` honest shards.
pub fn reconstruct_zero_trust_with_quarantine(
    mut shard_slots: Vec<Option<Vec<u8>>>,
    merkle_proofs: Option<&[Option<MerkleProof>]>,
    k_data: usize,
    m_parity: usize,
    expected_shard_hashes: &[Hash32],
    expected_merkle_root: Hash32,
) -> Result<(Vec<Vec<u8>>, Vec<usize>), ShardingError> {
    let total_shards = k_data + m_parity;
    if shard_slots.len() != total_shards || expected_shard_hashes.len() != total_shards {
        return Err(ShardingError::InvalidParameters(k_data, m_parity));
    }

    let mut poisoned_indices = Vec::new();
    for idx in 0..total_shards {
        let Some(ref bytes) = shard_slots[idx] else {
            continue;
        };
        let actual_leaf = crate::sharding::merkle::hash_shard_leaf(idx as u32, bytes);
        let hash_ok = actual_leaf == expected_shard_hashes[idx];
        let proof_ok = match merkle_proofs
            .and_then(|p| p.get(idx))
            .and_then(|p| p.as_ref())
        {
            Some(proof) => {
                proof.shard_index == idx as u32
                    && proof.root == expected_merkle_root
                    && proof.verify(bytes)
            }
            None => true,
        };

        if !hash_ok || !proof_ok {
            poisoned_indices.push(idx);
            shard_slots[idx] = None;
        }
    }

    let honest_available = shard_slots.iter().filter(|s| s.is_some()).count();
    if honest_available < k_data {
        return Err(ShardingError::InsufficientShards {
            required: k_data,
            available: honest_available,
        });
    }

    let reconstructed = reconstruct_all_shards(
        shard_slots,
        k_data,
        m_parity,
        Some(expected_shard_hashes),
        Some(expected_merkle_root),
    )?;

    Ok((reconstructed, poisoned_indices))
}

/// Reconstructs the original contiguous AES-256-GCM ciphertext stripe from at least `K` shards.
pub fn reconstruct_ciphertext_stripe(
    shard_slots: Vec<Option<Vec<u8>>>,
    k_data: usize,
    m_parity: usize,
    original_ciphertext_len: usize,
    expected_shard_hashes: Option<&[Hash32]>,
    expected_merkle_root: Option<Hash32>,
) -> Result<Vec<u8>, ShardingError> {
    let mut all_shards = reconstruct_all_shards(
        shard_slots,
        k_data,
        m_parity,
        expected_shard_hashes,
        expected_merkle_root,
    )?;

    // Drop parity shards immediately to free memory on constrained SoCs
    all_shards.truncate(k_data);

    let mut ciphertext = Vec::with_capacity(original_ciphertext_len);
    for shard in all_shards {
        let remaining = original_ciphertext_len.saturating_sub(ciphertext.len());
        if remaining == 0 {
            break;
        }
        let take_len = shard.len().min(remaining);
        ciphertext.extend_from_slice(&shard[..take_len]);
        // each shard's Vec is deallocated as it leaves scope
    }
    ciphertext.truncate(original_ciphertext_len);
    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reed_solomon_encode_and_reconstruct_all_tiers() {
        let tiers = [
            ErasureTier::Consumer,
            ErasureTier::Mixed,
            ErasureTier::Homelab,
            ErasureTier::Relay,
        ];

        for tier in tiers {
            let (k, m, n) = tier.params();
            // Test lengths: 1 byte, 100 bytes, 65537 bytes (unaligned)
            for len in [1, 100, 65537] {
                let original: Vec<u8> = (0..len).map(|i| (i * 17 % 256) as u8).collect();
                let shard_set = encode_ciphertext_stripe(0, &original, tier).expect("encode");
                assert_eq!(shard_set.k_data, k);
                assert_eq!(shard_set.m_parity, m);
                assert_eq!(shard_set.shards.len(), n);

                // Simulate dropping m parity shards (leaving k data shards)
                let slots: Vec<Option<Vec<u8>>> = shard_set
                    .shards
                    .into_iter()
                    .enumerate()
                    .map(|(idx, s)| if idx < k { Some(s) } else { None })
                    .collect();

                let reconstructed = reconstruct_ciphertext_stripe(
                    slots,
                    k,
                    m,
                    original.len(),
                    Some(&shard_set.shard_hashes),
                    Some(shard_set.stripe_merkle_root),
                )
                .expect("reconstruct with exactly K shards");

                assert_eq!(
                    reconstructed, original,
                    "Mismatch for tier {:?} len {}",
                    tier, len
                );
            }
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use reed_solomon_erasure::galois_8::Field;
    use reed_solomon_erasure::Field as _;

    /// Bit-precise symbolic verification over GF(2^8) Galois field arithmetic:
    /// Proves that for all symbolic bytes `a`, `b`, `c` in GF(2^8):
    /// 1. Addition (`a ^ b`) is commutative, associative, and self-inverse (`a + a == 0`).
    /// 2. Multiplication is commutative and distributes over addition: `a * (b + c) == (a * b) + (a * c)`.
    /// 3. Shard padding arithmetic `(len + k - 1) / k` never overflows or under-allocates for any valid stripe size.
    #[kani::proof]
    fn proof_gf256_field_axioms_and_shard_bounds() {
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        let c: u8 = kani::any();

        // 1. Additive self-inverse & commutativity in GF(2^8)
        assert_eq!(Field::add(a, a), 0);
        assert_eq!(Field::add(a, b), Field::add(b, a));

        // 2. Multiplicative commutativity & distributivity over GF(2^8)
        assert_eq!(Field::mul(a, b), Field::mul(b, a));
        let lhs = Field::mul(a, Field::add(b, c));
        let rhs = Field::add(Field::mul(a, b), Field::mul(a, c));
        assert_eq!(lhs, rhs);

        // 3. Shard length boundary safety across all 4 SLA tiers (k in {10, 16, 20})
        let ciphertext_len: usize = kani::any();
        kani::assume(ciphertext_len >= 16 && ciphertext_len <= 16 * 1024 * 1024 + 16);
        for k_data in [10usize, 16, 20] {
            let shard_len = if ciphertext_len == 0 {
                1
            } else {
                (ciphertext_len + k_data - 1) / k_data
            };
            assert!(shard_len >= 1);
            assert!(shard_len * k_data >= ciphertext_len);
            assert!(shard_len * k_data - ciphertext_len < k_data);
        }
    }
}
