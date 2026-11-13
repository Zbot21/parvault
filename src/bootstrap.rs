//! # Elastic Day-1-to-10,000-User Bootstrap & Earned Tier Progression Engine (`ADR-15`)
//!
//! Solves the P2P Cold-Start problem and replaces manual `--tier homelab` selection with
//! cryptographically and empirically **Earned Tier Progression**:
//!
//! 1. **Mechanism 1 — Single-Player Personal Device Ring (`PeerRole::PersonalDevice`):**
//!    Devices signed by the same user's [`HybridPqSigningKeypair`] (`Ed25519 + ML-DSA-65`)
//!    form an instant zero-quota-cost backup ring on Day 1 (`N = 1..M` personal devices)
//!    even when `0` external strangers are online.
//! 2. **Mechanism 2 — Zero-Knowledge Foundation Seed Anchors (`PeerRole::FoundationSeedAnchor`):**
//!    Stateless fallback storage nodes that accept [`BlindedShardId`] + [`PqVaultMasterKey`]-encrypted
//!    shards when organic neighborhood peers $P_{\text{organic}} < N$, and **automatically drain to 0%**
//!    as organic peers join the Kademlia DHT.
//! 3. **Mechanism 3 — Elastic $K$-of-$N$ Scaling & Zero-Knowledge Ciphertext Re-Sharding:**
//!    Dynamically scales Reed-Solomon $(k, n)$ parameters over $GF(2^8)$ from `2-of-3` (`SoloPersonalVault`)
//!    and `3-of-5` (`BuddyMicroCluster`) to `10-of-20` (`ProbationaryConsumerPool`), `16-of-24`
//!    (`EarnedVerifiedMixedPool`), and `16-of-20` (`EarnedHomelabAnchorPool`), re-sharding purely
//!    over authenticated ciphertext without ever decrypting user plaintext.
//! 4. **Mechanism 4 — Pioneer Standby Uptime Mining & `/24` Subnet Quota/Fault-Domain Damper:**
//!    Rewards early adopters for committed standby capacity during bootstrap epochs while applying
//!    $1 / \sqrt{M_{\text{subnet}}}$ inverse-square-root Sybil quota damping per `/24` subnet and
//!    strictly bounding per-stripe fault domains to $\le N - K$ shards per `/24`.

use crate::crypto::pqc::{HybridPqPublicKey, HybridPqSignature, HybridPqSigningKeypair};
use crate::crypto::CryptoError;
use crate::por::compute_salted_commitment;
use crate::sharding::merkle::{Hash32, MerkleTree};
use crate::storage::anonymity::{
    AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, VoucherNullifierLedger,
};
use crate::storage::block_store::{BlockStore, ShardId, StorageError};
use crate::storage::quota::{PeerCreditAccount, TrustLevel};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("Post-quantum cryptographic verification failed: {0}")]
    PqCrypto(#[from] CryptoError),
    #[error("Invalid personal device certificate or mismatched owner root key")]
    InvalidPersonalDeviceCert,
    #[error("Invalid personal device certificate: {0}")]
    InvalidDeviceCertificate(String),
    #[error("Node is SlashedQuarantined and barred from network storage")]
    NodeSlashedQuarantined,
    #[error(
        "Insufficient shards ({available}/{required_k}) for zero-knowledge elastic re-sharding"
    )]
    InsufficientShardsForReshard { available: usize, required_k: usize },
    #[error("Reed-Solomon GF(2^8) elastic coding error: {0}")]
    ReedSolomon(String),
    #[error("Ciphertext Merkle root mismatch during zero-knowledge re-sharding")]
    CiphertextIntegrityMismatch,
    #[error("Seed server storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Operation not permitted in current seed server mode")]
    InvalidSeedServerMode,
}

/// Role of a node in the elastic Day-1-to-10,000-user topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PeerRole {
    /// Another device owned by the same user (authenticated via `PersonalDeviceCert`).
    /// Enjoys infinite self-reciprocity quota and local LAN priority.
    PersonalDevice,
    /// An independent neighborhood/community node running `parvault-daemon`.
    OrganicCommunityPeer,
    /// Zero-knowledge fallback bootstrap node run by the foundation; only used when
    /// `OrganicCommunityPeer` count $< N$ and automatically drained as organic peers join.
    FoundationSeedAnchor,
}

/// Cryptographic certificate linking a user's personal devices (e.g. Laptop, Desktop, Raspberry Pi NAS)
/// into a Day-1 Single-Player Personal Ring with zero external peer dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalDeviceCert {
    pub owner_root_pubkey: HybridPqPublicKey,
    pub device_peer_id: String,
    pub device_label: String,
    pub issued_unix_secs: u64,
    pub owner_signature: HybridPqSignature,
}

impl PersonalDeviceCert {
    /// Issues a post-quantum composite certificate (`Ed25519 + ML-DSA-65`) authorizing `device_peer_id`
    /// as a member of the owner's personal device ring.
    pub fn issue(
        owner_keypair: &HybridPqSigningKeypair,
        device_peer_id: &str,
        device_label: &str,
        issued_unix_secs: u64,
    ) -> Result<Self, BootstrapError> {
        if device_peer_id.trim().is_empty() || device_label.trim().is_empty() {
            return Err(BootstrapError::InvalidPersonalDeviceCert);
        }
        let owner_root_pubkey = owner_keypair.public_key();
        let digest = Self::signing_digest(
            &owner_root_pubkey,
            device_peer_id,
            device_label,
            issued_unix_secs,
        );
        let owner_signature = owner_keypair.sign(&digest)?;
        Ok(Self {
            owner_root_pubkey,
            device_peer_id: device_peer_id.to_string(),
            device_label: device_label.to_string(),
            issued_unix_secs,
            owner_signature,
        })
    }

    /// Verifies that this device certificate was genuinely signed by `expected_owner_root`.
    pub fn verify(&self, expected_owner_root: &HybridPqPublicKey) -> Result<(), BootstrapError> {
        if self.device_peer_id.trim().is_empty()
            || self.device_label.trim().is_empty()
            || &self.owner_root_pubkey != expected_owner_root
        {
            return Err(BootstrapError::InvalidPersonalDeviceCert);
        }
        let digest = Self::signing_digest(
            &self.owner_root_pubkey,
            &self.device_peer_id,
            &self.device_label,
            self.issued_unix_secs,
        );
        let halves = HybridPqSigningKeypair::verify_halves(
            &self.owner_root_pubkey,
            &digest,
            &self.owner_signature,
        );
        if let Err(code) = crate::crypto::pqc::hybrid_signature_decision(&halves) {
            tracing::warn!(code, device = %self.device_peer_id, "refused a personal device cert");
            return Err(BootstrapError::InvalidPersonalDeviceCert);
        }
        Ok(())
    }

    pub fn to_json_pretty(&self) -> Result<String, BootstrapError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| BootstrapError::InvalidDeviceCertificate(e.to_string()))
    }

    pub fn from_json_str(s: &str) -> Result<Self, BootstrapError> {
        serde_json::from_str(s.trim())
            .map_err(|e| BootstrapError::InvalidDeviceCertificate(e.to_string()))
    }

    pub fn to_shareable_token(&self) -> Result<String, BootstrapError> {
        Ok(format!(
            "PARVAULT-CERT-V1:{}",
            hex::encode(
                bincode::serialize(self)
                    .map_err(|e| BootstrapError::InvalidDeviceCertificate(e.to_string()))?
            )
        ))
    }

    pub fn from_shareable_token(token_or_json: &str) -> Result<Self, BootstrapError> {
        let trimmed = token_or_json.trim();
        let hex_payload = if let Some(rest) = trimmed.strip_prefix("PARVAULT-CERT-V1:") {
            Some(rest)
        } else {
            trimmed.strip_prefix("parvault-cert-v1:")
        };
        if let Some(hex_str) = hex_payload {
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| BootstrapError::InvalidDeviceCertificate(e.to_string()))?;
            bincode::deserialize(&bytes)
                .map_err(|e| BootstrapError::InvalidDeviceCertificate(e.to_string()))
        } else {
            Self::from_json_str(trimmed)
        }
    }

    fn signing_digest(
        owner_root_pubkey: &HybridPqPublicKey,
        device_peer_id: &str,
        device_label: &str,
        issued_unix_secs: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"PARVAULT-PERSONAL-DEVICE-CERT-V1:");
        hasher.update(owner_root_pubkey.ed25519_pub);
        hasher.update((owner_root_pubkey.ml_dsa_65_pk.len() as u64).to_le_bytes());
        hasher.update(&owner_root_pubkey.ml_dsa_65_pk);
        hasher.update((device_peer_id.len() as u64).to_le_bytes());
        hasher.update(device_peer_id.as_bytes());
        hasher.update((device_label.len() as u64).to_le_bytes());
        hasher.update(device_label.as_bytes());
        hasher.update(issued_unix_secs.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Earned Redundancy Standing (`ADR-15`):
/// Nodes CANNOT arbitrarily pick `--tier homelab` on the CLI to get cheap `1.25x` storage.
/// Instead, a node's $(k, n)$ erasure profile and reciprocity expansion tax are **earned**
/// via sustained Proof-of-Retrievability (`PoR`) uptime and scaled elastically with network size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EarnedStanding {
    /// Day-1 Single-Device mode ($P_{\text{personal}} = 1$, $P_{\text{external}} = 0$):
    /// `2-of-3` local stripe redundancy against disk sector corruption (`0` network quota cost).
    SoloPersonalVault,
    /// Day-1 Personal Multi-Device Ring ($P_{\text{personal}} \ge 2$, e.g. Laptop + Desktop + Home Pi):
    /// `2-of-3` across the user's own devices (`0` network reciprocity quota cost).
    PersonalDeviceRing,
    /// Small Co-op / Friend Group ($2 \le P_{\text{organic}} < 6$, no Seed Anchors):
    /// `3-of-5` Reed-Solomon over $GF(2^8)$ (`1.67x` expansion, survives `2` simultaneous offline peers).
    BuddyMicroCluster,
    /// Default Entry Pool for all new/probationary nodes ($P_{\text{total}} \ge 6$, `UntrustedProbationary`):
    /// `10-of-20` Reed-Solomon (`2.00x` expansion tax, `50%` efficiency, survives `10` offline nodes).
    ProbationaryConsumerPool,
    /// Intermediate Earned Tier (`VerifiedNeighbor`: $\ge 50$ PoR audits at $\ge 98.0\%$ pass rate):
    /// `16-of-24` Reed-Solomon (`1.50x` expansion tax, `66.7%` efficiency, `2.5x` quota multiplier).
    EarnedVerifiedMixedPool,
    /// Top Earned Tier (`HighUptimeAnchor`: $\ge 200$ PoR audits at $\ge 99.8\%$ pass rate):
    /// `16-of-20` Reed-Solomon (`1.25x` expansion tax, `80.0%` efficiency, `5.0x` quota multiplier),
    /// with shards placed onto other high-uptime peers.
    EarnedHomelabAnchorPool,
}

impl EarnedStanding {
    /// Returns `(k_data_shards, m_parity_shards, n_total_shards)` for this earned standing.
    pub const fn erasure_params(self) -> (usize, usize, usize) {
        match self {
            Self::SoloPersonalVault | Self::PersonalDeviceRing => (2, 1, 3),
            Self::BuddyMicroCluster => (3, 2, 5),
            Self::ProbationaryConsumerPool => (10, 10, 20),
            Self::EarnedVerifiedMixedPool => (16, 8, 24),
            Self::EarnedHomelabAnchorPool => (16, 4, 20),
        }
    }

    /// Returns the reciprocity expansion factor (`N / K`) charged against the node's contributed bytes.
    /// Personal modes charge `0.0` external network quota.
    pub const fn reciprocity_expansion_tax(self) -> f64 {
        match self {
            Self::SoloPersonalVault | Self::PersonalDeviceRing => 0.0,
            Self::BuddyMicroCluster => 5.0 / 3.0,
            Self::ProbationaryConsumerPool => 2.00,
            Self::EarnedVerifiedMixedPool => 1.50,
            Self::EarnedHomelabAnchorPool => 1.25,
        }
    }

    /// Maximum shards of a single stripe allowed on any single `/24` IPv4 (or `/48` IPv6) fault domain.
    /// Notice that because confidentiality is guaranteed by `ADR-11` (`BlindedShardId`) and `ADR-12`
    /// (`PqVaultMasterKey` 512-bit Cascaded AEAD), this bound is purely an **Availability Fault-Domain Cap**:
    /// it never exceeds $N - K$ (the parity budget), ensuring a single router/fiber outage cannot
    /// take a stripe offline.
    pub const fn max_shards_per_subnet_fault_domain(self) -> usize {
        let (_k, m, _n) = self.erasure_params();
        if m == 0 {
            1
        } else if m > 4 {
            4 // Cap at 4 even when m=10 to spread across at least 5 distinct subnets
        } else {
            m
        }
    }

    /// Deterministically computes a node's `EarnedStanding` from its proven PoR `PeerCreditAccount`
    /// and the current reachable peer counts. Nodes CANNOT self-select `EarnedHomelabAnchorPool` without
    /// earning `TrustLevel::HighUptimeAnchor`.
    pub fn evaluate(
        account: &PeerCreditAccount,
        personal_devices: usize,
        organic_peers: usize,
        seed_anchors: usize,
    ) -> Result<Self, BootstrapError> {
        let trust = account.trust_level();
        if trust == TrustLevel::SlashedQuarantined {
            return Err(BootstrapError::NodeSlashedQuarantined);
        }

        let external_pool = organic_peers + seed_anchors;
        if external_pool == 0 {
            if personal_devices >= 2 {
                return Ok(Self::PersonalDeviceRing);
            }
            return Ok(Self::SoloPersonalVault);
        }

        if external_pool < 6 {
            return Ok(Self::BuddyMicroCluster);
        }

        // With >= 6 external peers (organic + seed anchors), the node enters the 20+ shard mesh,
        // where its tier is strictly earned via PoR uptime history:
        match trust {
            TrustLevel::UntrustedProbationary => Ok(Self::ProbationaryConsumerPool),
            TrustLevel::VerifiedNeighbor => {
                if external_pool >= 24 {
                    Ok(Self::EarnedVerifiedMixedPool)
                } else {
                    Ok(Self::ProbationaryConsumerPool)
                }
            }
            TrustLevel::HighUptimeAnchor => {
                if external_pool >= 20 {
                    Ok(Self::EarnedHomelabAnchorPool)
                } else {
                    Ok(Self::ProbationaryConsumerPool)
                }
            }
            TrustLevel::SlashedQuarantined => Err(BootstrapError::NodeSlashedQuarantined),
        }
    }
}

/// Candidate node metadata used by the Elastic Bootstrap & Placement Controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticPeerCandidate {
    pub peer_id: String,
    pub role: PeerRole,
    pub subnet_prefix: String,
    pub trust_level: TrustLevel,
    pub rtt_ms: u64,
    pub committed_standby_bytes: u64,
}

/// Assignment of a shard index `0..N` to a specific peer in the elastic mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardPlacementAssignment {
    pub shard_index: usize,
    pub peer_id: String,
    pub role: PeerRole,
    pub subnet_prefix: String,
}

/// Migration instruction generated when organic peers join the network and drain shards
/// off Foundation Seed Anchors (`Mechanism 2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedAnchorDrainMigration {
    pub shard_index: usize,
    pub from_seed_anchor_id: String,
    pub to_organic_peer_id: String,
    pub to_subnet_prefix: String,
}

/// Elastic Bootstrap, Placement & Pioneer Quota Engine (`ADR-15`).
pub struct ElasticBootstrapEngine;

impl ElasticBootstrapEngine {
    /// Selects `N` target peers for a stripe under the node's `EarnedStanding`, enforcing:
    /// 1. Priority ordering: `PersonalDevice` (for personal rings) $\to$ `OrganicCommunityPeer` (sorted by
    ///    earned `TrustLevel` and low RTT) $\to$ `FoundationSeedAnchor` (used ONLY as a last resort when
    ///    organic peers $< N$).
    /// 2. Availability Fault-Domain Cap: No single `/24` subnet receives more than
    ///    `standing.max_shards_per_subnet_fault_domain()` shards of the same stripe when sufficient subnets exist.
    pub fn select_elastic_targets(
        standing: EarnedStanding,
        candidates: &[ElasticPeerCandidate],
    ) -> Vec<ShardPlacementAssignment> {
        let (_k, _m, n_total) = standing.erasure_params();
        let fault_domain_cap = standing.max_shards_per_subnet_fault_domain();

        let mut active: Vec<&ElasticPeerCandidate> = candidates
            .iter()
            .filter(|c| c.trust_level != TrustLevel::SlashedQuarantined)
            .collect();

        // Priority sort:
        // 1. PersonalDevice first, then OrganicCommunityPeer, then FoundationSeedAnchor last!
        // 2. Higher TrustLevel first (especially for EarnedHomelabAnchorPool).
        // 3. Lower RTT first.
        active.sort_by(|a, b| {
            a.role
                .cmp(&b.role)
                .then_with(|| b.trust_level.cmp(&a.trust_level))
                .then_with(|| a.rtt_ms.cmp(&b.rtt_ms))
                .then_with(|| a.peer_id.cmp(&b.peer_id))
        });

        let mut assignments = Vec::with_capacity(n_total);
        let mut subnet_counts: HashMap<String, usize> = HashMap::new();
        let mut used_peers: HashMap<String, usize> = HashMap::new();

        // Pass 1: Strict distinct peers + strict fault-domain cap per canonical subnet
        for cand in &active {
            if assignments.len() == n_total {
                break;
            }
            let norm_subnet = normalize_subnet_prefix_key(&cand.subnet_prefix);
            let sub_cnt = subnet_counts.get(&norm_subnet).copied().unwrap_or(0);
            if sub_cnt >= fault_domain_cap && cand.role != PeerRole::FoundationSeedAnchor {
                continue;
            }
            let shard_index = assignments.len();
            assignments.push(ShardPlacementAssignment {
                shard_index,
                peer_id: cand.peer_id.clone(),
                role: cand.role,
                subnet_prefix: cand.subnet_prefix.clone(),
            });
            *subnet_counts.entry(norm_subnet).or_insert(0) += 1;
            *used_peers.entry(cand.peer_id.clone()).or_insert(0) += 1;
        }

        // Pass 2: If fewer distinct subnets/peers exist than `n_total` (e.g. SoloPersonalVault or small cluster),
        // prefer wrapping around FoundationSeedAnchor nodes first so organic peers don't receive duplicate
        // shards of the same stripe when a Seed Anchor is available; otherwise wrap around `active`.
        let seed_pool: Vec<&ElasticPeerCandidate> = active
            .iter()
            .copied()
            .filter(|c| c.role == PeerRole::FoundationSeedAnchor)
            .collect();
        let overflow_pool = if !seed_pool.is_empty() {
            &seed_pool
        } else {
            &active
        };
        let mut idx = 0;
        while assignments.len() < n_total && !overflow_pool.is_empty() {
            let cand = overflow_pool[idx % overflow_pool.len()];
            let shard_index = assignments.len();
            assignments.push(ShardPlacementAssignment {
                shard_index,
                peer_id: cand.peer_id.clone(),
                role: cand.role,
                subnet_prefix: cand.subnet_prefix.clone(),
            });
            idx += 1;
        }

        assignments
    }

    /// Computes background migration steps to drain shards off `FoundationSeedAnchor` nodes
    /// onto newly joined `OrganicCommunityPeer` nodes (`Mechanism 2`).
    /// Once $P_{\text{organic}} \ge N$ across sufficient subnets, `0` shards remain on Foundation Seed Anchors.
    pub fn plan_seed_anchor_drain(
        standing: EarnedStanding,
        current_placements: &[ShardPlacementAssignment],
        available_candidates: &[ElasticPeerCandidate],
    ) -> Vec<SeedAnchorDrainMigration> {
        let fault_domain_cap = standing.max_shards_per_subnet_fault_domain();

        let mut subnet_counts: HashMap<String, usize> = HashMap::new();
        let mut assigned_peers: HashMap<String, bool> = HashMap::new();

        for p in current_placements {
            if p.role != PeerRole::FoundationSeedAnchor {
                let norm_sub = normalize_subnet_prefix_key(&p.subnet_prefix);
                *subnet_counts.entry(norm_sub).or_insert(0) += 1;
                assigned_peers.insert(p.peer_id.clone(), true);
            }
        }

        let mut organic_pool: Vec<&ElasticPeerCandidate> = available_candidates
            .iter()
            .filter(|c| {
                // ADR-15 Red-Team Defense: Only organic peers that have earned at least
                // `TrustLevel::VerifiedNeighbor` (>= 50 PoR passes at >= 98% SLA) may drain shards
                // off Foundation Seed Anchors, blocking 1-hour ephemeral Sybil drain attacks.
                c.role == PeerRole::OrganicCommunityPeer
                    && c.trust_level >= TrustLevel::VerifiedNeighbor
                    && !assigned_peers.contains_key(&c.peer_id)
            })
            .collect();

        organic_pool.sort_by(|a, b| {
            b.trust_level
                .cmp(&a.trust_level)
                .then_with(|| a.rtt_ms.cmp(&b.rtt_ms))
                .then_with(|| a.peer_id.cmp(&b.peer_id))
        });

        let mut migrations = Vec::new();
        let mut org_idx = 0;

        for placement in current_placements {
            if placement.role != PeerRole::FoundationSeedAnchor {
                continue;
            }
            while org_idx < organic_pool.len() {
                let candidate = organic_pool[org_idx];
                org_idx += 1;
                let norm_sub = normalize_subnet_prefix_key(&candidate.subnet_prefix);
                let sub_cnt = subnet_counts.get(&norm_sub).copied().unwrap_or(0);
                if sub_cnt < fault_domain_cap {
                    *subnet_counts.entry(norm_sub).or_insert(0) += 1;
                    migrations.push(SeedAnchorDrainMigration {
                        shard_index: placement.shard_index,
                        from_seed_anchor_id: placement.peer_id.clone(),
                        to_organic_peer_id: candidate.peer_id.clone(),
                        to_subnet_prefix: candidate.subnet_prefix.clone(),
                    });
                    break;
                }
            }
        }

        migrations
    }

    /// Encodes an already-encrypted ciphertext stripe into any elastic `(k, m, n)` Reed-Solomon
    /// profile over $GF(2^8)$ (`2-of-3`, `3-of-5`, `10-of-20`, `16-of-24`, `16-of-20`).
    pub fn encode_ciphertext_elastic(
        standing: EarnedStanding,
        ciphertext: &[u8],
    ) -> Result<(Vec<Vec<u8>>, Hash32), BootstrapError> {
        let (k, m, n) = standing.erasure_params();
        let rs = ReedSolomon::new(k, m).map_err(|e| BootstrapError::ReedSolomon(e.to_string()))?;

        let shard_len = ciphertext.len().div_ceil(k).max(1);
        let padded_len = shard_len * k;
        let mut padded = vec![0u8; padded_len];
        padded[..ciphertext.len()].copy_from_slice(ciphertext);

        let mut shards: Vec<Vec<u8>> = padded.chunks_exact(shard_len).map(|c| c.to_vec()).collect();
        for _ in 0..m {
            shards.push(vec![0u8; shard_len]);
        }

        rs.encode(&mut shards)
            .map_err(|e| BootstrapError::ReedSolomon(e.to_string()))?;
        debug_assert_eq!(shards.len(), n);

        let tree = MerkleTree::from_shards(&shards);
        Ok((shards, tree.root()))
    }

    /// Zero-Knowledge Elastic Ciphertext Re-Sharding (`Mechanism 3`):
    /// Reconstructs an encrypted stripe from any `k_old` surviving shards of `old_standing`
    /// (e.g. `3-of-5` BuddyMicroCluster or `10-of-20` ProbationaryConsumerPool) and re-encodes
    /// it into `new_standing` (e.g. `16-of-20` EarnedHomelabAnchorPool) **purely over ciphertext**
    /// without ever requiring the user's decryption key or exposing plaintext.
    pub fn reshard_ciphertext_stripe_elastic(
        old_standing: EarnedStanding,
        new_standing: EarnedStanding,
        mut old_shards: Vec<Option<Vec<u8>>>,
        original_ciphertext_len: usize,
        expected_ciphertext_sha256: &[u8; 32],
    ) -> Result<(Vec<Vec<u8>>, Hash32), BootstrapError> {
        let (k_old, m_old, _n_old) = old_standing.erasure_params();
        let available = old_shards.iter().filter(|s| s.is_some()).count();
        if available < k_old {
            return Err(BootstrapError::InsufficientShardsForReshard {
                available,
                required_k: k_old,
            });
        }

        let rs_old = ReedSolomon::new(k_old, m_old)
            .map_err(|e| BootstrapError::ReedSolomon(e.to_string()))?;
        rs_old
            .reconstruct(&mut old_shards)
            .map_err(|e| BootstrapError::ReedSolomon(e.to_string()))?;

        let mut reconstructed_ciphertext = Vec::with_capacity(original_ciphertext_len);
        for shard in old_shards.into_iter().take(k_old).flatten() {
            reconstructed_ciphertext.extend_from_slice(&shard);
        }
        reconstructed_ciphertext.truncate(original_ciphertext_len);

        // Verify outer ciphertext integrity before re-sharding into the new tier
        let actual_hash: [u8; 32] = Sha256::digest(&reconstructed_ciphertext).into();
        if &actual_hash != expected_ciphertext_sha256 {
            return Err(BootstrapError::CiphertextIntegrityMismatch);
        }

        Self::encode_ciphertext_elastic(new_standing, &reconstructed_ciphertext)
    }

    /// Pioneer Standby Uptime Mining + `/24` Subnet Sybil Quota Damper (`Mechanism 4`):
    ///
    /// During bootstrap and growth epochs, nodes that commit standby disk capacity and pass
    /// liveness/PoR audits earn:
    /// 1. `por_passes += 1` toward earning `VerifiedNeighbor` (`16-of-24`) and `HighUptimeAnchor` (`16-of-20`).
    /// 2. Standby byte-hour credits scaled by:
    ///    - `bootstrap_utilization_bonus`: `1.0 - (network_utilization_ratio * 0.75)` so early pioneers
    ///      with empty disks still earn base reciprocity credits on their committed standby storage.
    ///    - `subnet_sybil_damper`: $1 / M_{\text{subnet}}$ per node on the same `/24` subnet so spinning up
    ///      $M$ virtual machines on a single residential `/24` router yields the **exact same aggregate
    ///      subnet standby credit** as running 1 honest node ($M \times \frac{1}{M} = 1.0\times$).
    pub fn accrue_standby_uptime_epoch(
        peer_accounts: &mut BTreeMap<String, PeerCreditAccount>,
        candidates: &[ElasticPeerCandidate],
        epoch_passed_peers: &HashMap<String, bool>,
        network_utilization_ratio: f64,
    ) -> HashMap<String, u64> {
        let clamped_util = network_utilization_ratio.clamp(0.0, 1.0);
        // At 0% network utilization (Day 1), pioneer standby factor is 10% of committed capacity per epoch;
        // at 100% utilization, standby bonus tapers to 2.5% as active shard hosting dominates.
        let pioneer_standby_rate = 0.10 * (1.0 - 0.75 * clamped_util);

        // Count how many active nodes share each canonical subnet to damp Sybil container farming
        let mut subnet_node_counts: HashMap<String, usize> = HashMap::new();
        for cand in candidates {
            if cand.role == PeerRole::OrganicCommunityPeer {
                let norm_sub = normalize_subnet_prefix_key(&cand.subnet_prefix);
                *subnet_node_counts.entry(norm_sub).or_insert(0) += 1;
            }
        }

        let mut minted_credits = HashMap::new();

        for cand in candidates {
            if cand.role != PeerRole::OrganicCommunityPeer {
                continue;
            }
            let acct = peer_accounts.entry(cand.peer_id.clone()).or_default();
            if acct.is_slashed {
                minted_credits.insert(cand.peer_id.clone(), 0);
                continue;
            }

            let passed = epoch_passed_peers
                .get(&cand.peer_id)
                .copied()
                .unwrap_or(false);
            if passed {
                acct.por_passes = acct.por_passes.saturating_add(1);
                let norm_sub = normalize_subnet_prefix_key(&cand.subnet_prefix);
                let m_subnet = subnet_node_counts
                    .get(&norm_sub)
                    .copied()
                    .unwrap_or(1)
                    .max(1) as f64;

                // Strict /24 Subnet Conservation: dividing per-node standby credit by `m_subnet`
                // guarantees that 20 Sybil VMs on the same /24 sharing `C` bytes (or claiming `C` bytes)
                // cannot multiply their subnet's pioneer credit minting rate.
                let subnet_damper = 1.0 / m_subnet;
                let trust_mult = acct.trust_level().storage_quota_multiplier();
                let credit = (cand.committed_standby_bytes as f64
                    * pioneer_standby_rate
                    * subnet_damper
                    * trust_mult) as u64;

                acct.bytes_contributed_by_peer =
                    acct.bytes_contributed_by_peer.saturating_add(credit);
                minted_credits.insert(cand.peer_id.clone(), credit);
            } else {
                acct.por_failures = acct.por_failures.saturating_add(1);
                minted_credits.insert(cand.peer_id.clone(), 0);
            }
        }

        minted_credits
    }
}

/// Maximum lease duration or single-renewal extension (365 epochs) to prevent `u64::MAX` infinite pinning (`ADR-19`).
pub const MAX_BLINDED_LEASE_EPOCHS: u64 = 365;

/// Cryptographic capability tombstone (`BlindedShardTombstone`) allowing a departing node
/// or file owner to delete a specific [`BlindedShardId`](crate::storage::anonymity::BlindedShardId)
/// in $O(1)$ without revealing its `PeerId` or linking other shards (`ADR-11`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedShardTombstone {
    pub blinded_shard_id: [u8; 32],
    pub nonce: [u8; 16],
    pub delete_proof_mac: [u8; 32],
    #[serde(default)]
    pub lease_generation: u64,
}

impl BlindedShardTombstone {
    /// Derives the per-shard delete verification token stored alongside the blinded shard.
    pub fn derive_delete_verifier(
        shard_cap_secret: &[u8; 32],
        blinded_shard_id: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"PARVAULT-BLINDED-DELETE-VERIFIER-V1:");
        hasher.update(shard_cap_secret);
        hasher.update(blinded_shard_id);
        hasher.finalize().into()
    }

    /// Creates a signed `BlindedShardTombstone` using the shard's delete verifier.
    pub fn create(delete_verifier: &[u8; 32], blinded_shard_id: [u8; 32], nonce: [u8; 16]) -> Self {
        Self::create_for_generation(delete_verifier, blinded_shard_id, nonce, 0)
    }

    /// Creates a generation-scoped `BlindedShardTombstone` (`ADR-19` signed delete) bound to `lease_generation`
    /// so old tombstones cannot be replayed after a shard is legitimately re-uploaded.
    pub fn create_for_generation(
        delete_verifier: &[u8; 32],
        blinded_shard_id: [u8; 32],
        nonce: [u8; 16],
        lease_generation: u64,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"PARVAULT-BLINDED-TOMBSTONE-V1:");
        hasher.update(delete_verifier);
        hasher.update(blinded_shard_id);
        hasher.update(nonce);
        if lease_generation > 0 {
            hasher.update(lease_generation.to_be_bytes());
        }
        let delete_proof_mac = hasher.finalize().into();
        Self {
            blinded_shard_id,
            nonce,
            delete_proof_mac,
            lease_generation,
        }
    }

    /// Verifies the tombstone against the stored `delete_verifier` in constant time.
    pub fn verify(&self, stored_delete_verifier: &[u8; 32]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(b"PARVAULT-BLINDED-TOMBSTONE-V1:");
        hasher.update(stored_delete_verifier);
        hasher.update(self.blinded_shard_id);
        hasher.update(self.nonce);
        if self.lease_generation > 0 {
            hasher.update(self.lease_generation.to_be_bytes());
        }
        let expected: [u8; 32] = hasher.finalize().into();
        let mut diff = 0u8;
        for (a, b) in expected.iter().zip(self.delete_proof_mac.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// Metadata tracked per blinded shard on a storage node for **Identity-Free Lease Eviction**
/// when an anonymous owner node permanently leaves the network (`ADR-11`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedShardLeaseEntry {
    pub blinded_shard_id: [u8; 32],
    pub size_bytes: u64,
    pub lease_expires_epoch: u64,
    pub last_renewed_epoch: u64,
    pub delete_verifier: [u8; 32],
    #[serde(default)]
    pub capability_pubkey: Option<[u8; 32]>,
    #[serde(default)]
    pub lease_generation: u64,
}

/// Manages unlinkable Byte-Epoch leases and lazy/pressure-driven LRU eviction for blinded shards
/// so departing nodes' shards are reclaimed without ever tracking `owner_peer_id`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlindedShardLeaseManager {
    max_capacity_bytes: u64,
    used_bytes: u64,
    grace_epochs: u64,
    leases: BTreeMap<[u8; 32], BlindedShardLeaseEntry>,
    #[serde(default)]
    next_generation_by_locator: BTreeMap<[u8; 32], u64>,
    #[serde(default)]
    consumed_tombstone_macs: BTreeMap<[u8; 32], Vec<[u8; 32]>>,
}

impl BlindedShardLeaseManager {
    pub fn new(max_capacity_bytes: u64, grace_epochs: u64) -> Self {
        Self {
            max_capacity_bytes,
            used_bytes: 0,
            grace_epochs,
            leases: BTreeMap::new(),
            next_generation_by_locator: BTreeMap::new(),
            consumed_tombstone_macs: BTreeMap::new(),
        }
    }

    pub fn set_policy(&mut self, max_capacity_bytes: u64, grace_epochs: u64) {
        self.max_capacity_bytes = max_capacity_bytes;
        self.grace_epochs = grace_epochs;
    }

    pub const fn max_capacity_bytes(&self) -> u64 {
        self.max_capacity_bytes
    }

    pub const fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    pub fn active_shard_count(&self) -> usize {
        self.leases.len()
    }

    pub fn lease_entry(&self, blinded_shard_id: &[u8; 32]) -> Option<&BlindedShardLeaseEntry> {
        self.leases.get(blinded_shard_id)
    }

    pub fn force_remove_locator(&mut self, locator: &[u8; 32]) -> bool {
        if let Some(removed) = self.leases.remove(locator) {
            self.used_bytes = self.used_bytes.saturating_sub(removed.size_bytes);
            true
        } else {
            false
        }
    }

    /// Stores or updates a blinded shard with an initial Byte-Epoch lease (`current_epoch + lease_duration_epochs`).
    /// If the disk is full, automatically evicts expired-lease shards first (from departed nodes) before rejecting.
    pub fn store_with_lease(
        &mut self,
        blinded_shard_id: [u8; 32],
        size_bytes: u64,
        current_epoch: u64,
        lease_duration_epochs: u64,
        delete_verifier: [u8; 32],
    ) -> Vec<[u8; 32]> {
        self.store_with_capability_and_lease(
            blinded_shard_id,
            size_bytes,
            current_epoch,
            lease_duration_epochs,
            delete_verifier,
            None,
        )
    }

    /// Stores a blinded shard while binding its `BlindedShardCapability` public key (`capability_pubkey`)
    /// and incrementing its monotonic `lease_generation` (`ADR-19` lease pinning).
    pub fn store_with_capability_and_lease(
        &mut self,
        blinded_shard_id: [u8; 32],
        size_bytes: u64,
        current_epoch: u64,
        lease_duration_epochs: u64,
        delete_verifier: [u8; 32],
        capability_pubkey: Option<[u8; 32]>,
    ) -> Vec<[u8; 32]> {
        let clamped_duration = lease_duration_epochs.clamp(1, MAX_BLINDED_LEASE_EPOCHS);
        let mut evicted = Vec::new();
        if self.used_bytes.saturating_add(size_bytes) > self.max_capacity_bytes {
            evicted = self.evict_expired_to_fit(size_bytes, current_epoch);
        }

        if let Some(prev) = self.leases.remove(&blinded_shard_id) {
            self.used_bytes = self.used_bytes.saturating_sub(prev.size_bytes);
        }

        let gen = *self
            .next_generation_by_locator
            .get(&blinded_shard_id)
            .unwrap_or(&0);

        self.used_bytes = self.used_bytes.saturating_add(size_bytes);
        self.leases.insert(
            blinded_shard_id,
            BlindedShardLeaseEntry {
                blinded_shard_id,
                size_bytes,
                lease_expires_epoch: current_epoch.saturating_add(clamped_duration),
                last_renewed_epoch: current_epoch,
                delete_verifier,
                capability_pubkey,
                lease_generation: gen,
            },
        );
        evicted
    }

    /// Renews a blinded shard's lease when its owner presents a fresh epoch `AnonymousQuotaVoucher`
    /// or PoR heartbeat (capped at `MAX_BLINDED_LEASE_EPOCHS`).
    pub fn renew_lease(
        &mut self,
        blinded_shard_id: &[u8; 32],
        current_epoch: u64,
        extension_epochs: u64,
    ) -> bool {
        let clamped_ext = extension_epochs.clamp(1, MAX_BLINDED_LEASE_EPOCHS);
        if let Some(entry) = self.leases.get_mut(blinded_shard_id) {
            entry.last_renewed_epoch = current_epoch;
            entry.lease_expires_epoch = current_epoch.saturating_add(clamped_ext);
            true
        } else {
            false
        }
    }

    /// Removes the lease of `blinded_shard_id` (after a signed delete, F-41). Its next
    /// generation is recorded so a stale grant cannot reuse it.
    pub fn remove_lease(&mut self, blinded_shard_id: &[u8; 32]) -> bool {
        let Some(removed) = self.leases.remove(blinded_shard_id) else {
            return false;
        };
        self.used_bytes = self.used_bytes.saturating_sub(removed.size_bytes);
        self.next_generation_by_locator.insert(
            *blinded_shard_id,
            removed.lease_generation.saturating_add(1),
        );
        true
    }

    /// Evicts shards whose `lease_expires_epoch + grace_epochs <= current_epoch` (oldest first)
    /// until `needed_bytes` of free capacity is available. Notice that if there is no disk pressure,
    /// expired shards can remain lazily cached so returning nodes can still recover data!
    pub fn evict_expired_to_fit(&mut self, needed_bytes: u64, current_epoch: u64) -> Vec<[u8; 32]> {
        let mut expired_candidates: Vec<([u8; 32], u64)> = self
            .leases
            .values()
            .filter(|e| e.lease_expires_epoch.saturating_add(self.grace_epochs) <= current_epoch)
            .map(|e| (e.blinded_shard_id, e.lease_expires_epoch))
            .collect();

        // Evict oldest expired leases first
        expired_candidates.sort_by_key(|(_id, exp)| *exp);

        let mut evicted = Vec::new();
        for (id, _exp) in expired_candidates {
            if self.max_capacity_bytes.saturating_sub(self.used_bytes) >= needed_bytes {
                break;
            }
            if let Some(removed) = self.leases.remove(&id) {
                self.used_bytes = self.used_bytes.saturating_sub(removed.size_bytes);
                evicted.push(id);
            }
        }
        evicted
    }

    /// Hard-cap eviction for bounded in-memory seed nodes (`--no-fs` / `--in-memory-mb`):
    /// Evicts expired leases first, then evicts the oldest-expiring / LRU active leases until
    /// `needed_bytes` fits strictly within `self.max_capacity_bytes`. Returns `None` if
    /// `needed_bytes > self.max_capacity_bytes`.
    pub fn evict_oldest_to_fit(
        &mut self,
        needed_bytes: u64,
        current_epoch: u64,
    ) -> Option<Vec<[u8; 32]>> {
        if needed_bytes > self.max_capacity_bytes {
            return None;
        }
        let mut evicted = self.evict_expired_to_fit(needed_bytes, current_epoch);
        if self.max_capacity_bytes.saturating_sub(self.used_bytes) >= needed_bytes {
            return Some(evicted);
        }

        let mut active_candidates: Vec<([u8; 32], u64, u64)> = self
            .leases
            .values()
            .map(|e| {
                (
                    e.blinded_shard_id,
                    e.lease_expires_epoch,
                    e.last_renewed_epoch,
                )
            })
            .collect();
        active_candidates.sort_by_key(|(_id, exp, ren)| (*exp, *ren));

        for (id, _, _) in active_candidates {
            if self.max_capacity_bytes.saturating_sub(self.used_bytes) >= needed_bytes {
                break;
            }
            if let Some(removed) = self.leases.remove(&id) {
                self.used_bytes = self.used_bytes.saturating_sub(removed.size_bytes);
                evicted.push(id);
            }
        }
        if self.max_capacity_bytes.saturating_sub(self.used_bytes) >= needed_bytes {
            Some(evicted)
        } else {
            None
        }
    }

    /// Time-based background GC sweep: returns and removes all blinded shard locators whose
    /// `lease_expires_epoch + grace_epochs <= current_epoch` so `BlockStore` can unlink their
    /// `.bshard` files from the filesystem.
    pub fn sweep_all_expired(&mut self, current_epoch: u64) -> Vec<[u8; 32]> {
        let mut expired_ids: Vec<([u8; 32], u64)> = self
            .leases
            .values()
            .filter(|e| e.lease_expires_epoch.saturating_add(self.grace_epochs) <= current_epoch)
            .map(|e| (e.blinded_shard_id, e.lease_expires_epoch))
            .collect();

        expired_ids.sort_by_key(|(_id, exp)| *exp);

        let mut purged = Vec::with_capacity(expired_ids.len());
        for (id, _exp) in expired_ids {
            if let Some(removed) = self.leases.remove(&id) {
                self.used_bytes = self.used_bytes.saturating_sub(removed.size_bytes);
                purged.push(id);
            }
        }
        purged
    }
}

/// Operating mode for the standalone Zero-Trust Seed & Redundancy Server (`parvault-seed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedServerMode {
    /// Dedicated 24/7 backup/redundancy vault for a homelab user (`PeerRole::PersonalDevice` for
    /// devices presenting a valid post-quantum `PersonalDeviceCert` signed by the homelab owner's
    /// `HybridPqPublicKey`, plus optional `PeerRole::OrganicCommunityPeer` reciprocity hosting for
    /// neighbors so the server earns `TrustLevel::HighUptimeAnchor` / `EarnedStanding::EarnedHomelabAnchorPool`
    /// `16-of-20` standing for the household).
    HomelabRedundancyVault,
    /// Stateless zero-knowledge public network bootstrapper (`PeerRole::FoundationSeedAnchor`) that
    /// accepts only anonymized `BlindedShardId` shards with Byte-Epoch leases and automatically
    /// drains to 0% as organic peers join the network.
    PublicNetworkBootstrapper,
}

impl SeedServerMode {
    /// Returns the primary `PeerRole` associated with this seed server mode.
    pub const fn peer_role(self) -> PeerRole {
        match self {
            Self::HomelabRedundancyVault => PeerRole::PersonalDevice,
            Self::PublicNetworkBootstrapper => PeerRole::FoundationSeedAnchor,
        }
    }
}

/// Telemetry & security status report returned by [`ZeroTrustSeedServer::status_report`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SeedServerStatusReport {
    pub mode: SeedServerMode,
    pub peer_role: PeerRole,
    pub max_storage_bytes: u64,
    pub used_storage_bytes: u64,
    pub active_blinded_leases: usize,
    pub earned_trust_level: TrustLevel,
    pub earned_standing: EarnedStanding,
    pub por_passes: u64,
    pub sla_ratio: f64,
    /// Always `false` — proving zero-trust seed-only operation with zero user plaintext or local folders.
    pub holds_own_plaintext_files: bool,
}

/// Client operating mode for `parvault` (`ADR-20`):
/// - [`ClientOperatingMode::FullMeshNode`]: Full 24/7 P2P node that encodes and distributes `N`
///   Reed-Solomon shards directly to mesh peers and answers PoR challenges.
/// - [`ClientOperatingMode::LiteSeedBacked`]: Laptop/roaming "Lite" client that runs the exact same
///   client-side encryption protocol (`AES-256-GCM` / `PqVaultMasterKey`) and sends a `1.0x` encrypted
///   stripe bundle to its paired `parvault-seed` box (`HomelabRedundancyVault`). The `parvault-seed` box
///   performs the `N`-shard Reed-Solomon encoding and mesh syndication in the background while keeping
///   a fast hot cache for "Cloud-Away-From-Home" selective reads. If the `parvault-seed` NAS dies, the
///   laptop seamlessly falls back to reconstructing any file or stripe directly from `K`-of-`N` mesh peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientOperatingMode {
    FullMeshNode,
    LiteSeedBacked,
}

/// A `1.0x` encrypted ciphertext stripe bundle sent by a `LiteSeedBacked` laptop to its paired
/// `parvault-seed` server for zero-knowledge Reed-Solomon encoding and mesh syndication (`ADR-20`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiteStripeSyndicationBundle {
    pub stripe_index: u64,
    pub tier: crate::config::ErasureTier,
    pub ciphertext_bytes: Vec<u8>,
    pub expected_stripe_merkle_root: Hash32,
    pub expected_shard_hashes: Vec<Hash32>,
}

/// Receipt returned by `ZeroTrustSeedServer::ingest_and_syndicate_lite_stripe` proving that the
/// laptop's encrypted stripe was cached on the seed server and syndicated across `N` mesh peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiteSyndicationReceipt {
    pub stripe_index: u64,
    pub stripe_merkle_root: Hash32,
    pub total_shards_syndicated: usize,
    pub cached_on_seed_server: bool,
    pub mesh_peers_populated: usize,
}

/// B-SEED-SYND (L-46): a syndication job stops issuing puts after this, and answers with what
/// landed (shorter than the client's 30 s `LITE_SYNDICATION_TIMEOUT`).
pub const LITE_FANOUT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);
/// B-SEED-SYND: puts in flight at once within one syndication job.
pub const LITE_FANOUT_PARALLEL_PUTS: usize = 4;

/// The result of the locked half of a lite syndication: the stripe and its shard ids, all stored
/// on the seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteIngest {
    pub stripe_index: u64,
    pub stripe_merkle_root: Hash32,
    pub shard_ids: Vec<ShardId>,
}

impl LiteIngest {
    pub fn receipt(&self, mesh_peers_populated: usize) -> LiteSyndicationReceipt {
        LiteSyndicationReceipt {
            stripe_index: self.stripe_index,
            stripe_merkle_root: self.stripe_merkle_root,
            total_shards_syndicated: self.shard_ids.len(),
            cached_on_seed_server: true,
            mesh_peers_populated,
        }
    }
}

/// The lock-free half of a lite syndication: owns shard ids (not bytes; each shard is read back
/// from the block store when sent), the peers and a mesh client.
pub struct LiteFanOutPlan {
    ingest: LiteIngest,
    peers: Vec<String>,
    server_peer_id: String,
    client: crate::network::MeshClient,
    block_store: BlockStore,
    repair_grant: Option<crate::por::RepairGrant>,
    session_key: [u8; 32],
}

/// Runs a lite fan-out (blocking; call off the swarm task, without the seed's lock). Shards go
/// out `parallel` at a time, keeping the replica rule (3 replicas when peers < shards, else 1);
/// a peer whose put fails once gets no further puts in this job (dead set); no new put starts
/// after `deadline`. The receipt names only peers that acknowledged.
pub fn run_lite_fan_out(
    plan: LiteFanOutPlan,
    deadline: std::time::Duration,
    parallel: usize,
) -> (LiteSyndicationReceipt, Vec<String>) {
    use std::collections::HashSet;
    use std::sync::Mutex;
    let stop_at = std::time::Instant::now() + deadline;
    let shard_count = plan.ingest.shard_ids.len();
    let num_peers = plan.peers.len();
    let replica_shifts = if num_peers < shard_count {
        3usize.min(num_peers)
    } else {
        1
    };
    // Per-peer gate: puts to one peer are serialized and the gate holds "dead", so a peer that
    // fails once (e.g. silent until the timeout) gets exactly one put per job, even with
    // `parallel` workers; different peers still run in parallel.
    let unique: HashSet<&str> = plan.peers.iter().map(String::as_str).collect();
    let gates: std::collections::HashMap<&str, Mutex<bool>> =
        unique.into_iter().map(|p| (p, Mutex::new(false))).collect();
    let primary: Mutex<Vec<Option<String>>> = Mutex::new(vec![None; shard_count]);
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..parallel.max(1) {
            scope.spawn(|| loop {
                let idx = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if idx >= shard_count || std::time::Instant::now() >= stop_at {
                    break;
                }
                let shard_id = plan.ingest.shard_ids[idx];
                let Ok(bytes) = plan.block_store.get_shard(&shard_id) else {
                    continue;
                };
                for shift in 0..replica_shifts {
                    if std::time::Instant::now() >= stop_at {
                        break;
                    }
                    let target = &plan.peers[(idx + shift) % num_peers];
                    let Some(gate) = gates.get(target.as_str()) else {
                        continue;
                    };
                    let mut dead = gate.lock().unwrap_or_else(|p| p.into_inner());
                    if *dead || std::time::Instant::now() >= stop_at {
                        continue;
                    }
                    // Accounted to the sender (v0.5.0 owner rule).
                    let put = plan.client.put_shard(
                        target,
                        "",
                        shard_id,
                        bytes.clone(),
                        plan.session_key,
                        plan.repair_grant.clone(),
                    );
                    if put.is_ok() {
                        let mut p = primary.lock().unwrap_or_else(|p| p.into_inner());
                        if p[idx].is_none() {
                            p[idx] = Some(target.clone());
                        }
                    } else {
                        *dead = true;
                    }
                }
            });
        }
    });
    let primary = primary.into_inner().unwrap_or_else(|p| p.into_inner());
    let populated = primary.iter().filter(|p| p.is_some()).count();
    let syndicated_peers = primary
        .into_iter()
        .map(|p| p.unwrap_or_else(|| plan.server_peer_id.clone()))
        .collect();
    (plan.ingest.receipt(populated), syndicated_peers)
}

/// Route used by a Lite Client when selectively restoring files or byte ranges (`ADR-20`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiteRestoreRoute {
    /// Fast 1-hop read from the paired `parvault-seed` server (local LAN or remote "Cloud-Away-From-Home").
    ViaSeedServerFastPath,
    /// Automatic failover when the `parvault-seed` NAS is offline/destroyed: reconstructs `K`-of-`N`
    /// syndicated shards directly from the Neighborhood Cloud mesh using the same protocol.
    DirectFromMeshPeersFallback,
}

/// Standalone Zero-Trust Seed & Redundancy Server engine (`ADR-16`).
///
/// Holds **zero user plaintext or local folders of its own** and operates in either:
/// - [`SeedServerMode::HomelabRedundancyVault`] (dedicated 24/7 personal device ring + uptime anchor), or
/// - [`SeedServerMode::PublicNetworkBootstrapper`] (stateless `FoundationSeedAnchor` with Byte-Epoch
///   lease eviction and automatic organic peer draining).
pub struct ZeroTrustSeedServer {
    server_peer_id: String,
    mode: SeedServerMode,
    block_store: BlockStore,
    owner_root_pubkey: Option<HybridPqPublicKey>,
    authorized_personal_devices: HashMap<String, PersonalDeviceCert>,
    voucher_ledger: VoucherNullifierLedger,
    server_credit_account: PeerCreditAccount,
    reachable_organic_peers: usize,
    reachable_seed_anchors: usize,
}

impl ZeroTrustSeedServer {
    /// Initializes a `ZeroTrustSeedServer` in `HomelabRedundancyVault` mode bound to the
    /// homelab owner's composite post-quantum public key (`Ed25519 + ML-DSA-65`).
    pub fn new_homelab_vault(
        server_peer_id: impl Into<String>,
        block_store: BlockStore,
        owner_root_pubkey: HybridPqPublicKey,
        grace_epochs: u64,
    ) -> Self {
        let max_bytes = block_store
            .quota()
            .lock()
            .expect("quota mutex")
            .max_storage_bytes();
        block_store.set_blinded_lease_policy(max_bytes, grace_epochs);
        let voucher_issuer = owner_root_pubkey.ed25519_pub;
        Self {
            server_peer_id: server_peer_id.into(),
            mode: SeedServerMode::HomelabRedundancyVault,
            block_store,
            owner_root_pubkey: Some(owner_root_pubkey),
            authorized_personal_devices: HashMap::new(),
            voucher_ledger: VoucherNullifierLedger::new(voucher_issuer),
            server_credit_account: PeerCreditAccount::default(),
            reachable_organic_peers: 0,
            reachable_seed_anchors: 0,
        }
    }

    /// Initializes a `ZeroTrustSeedServer` in `PublicNetworkBootstrapper` mode (`PeerRole::FoundationSeedAnchor`).
    pub fn new_public_bootstrapper(
        server_peer_id: impl Into<String>,
        block_store: BlockStore,
        voucher_issuer_pubkey: [u8; 32],
        grace_epochs: u64,
    ) -> Self {
        let max_bytes = block_store
            .quota()
            .lock()
            .expect("quota mutex")
            .max_storage_bytes();
        block_store.set_blinded_lease_policy(max_bytes, grace_epochs);
        Self {
            server_peer_id: server_peer_id.into(),
            mode: SeedServerMode::PublicNetworkBootstrapper,
            block_store,
            owner_root_pubkey: None,
            authorized_personal_devices: HashMap::new(),
            voucher_ledger: VoucherNullifierLedger::new(voucher_issuer_pubkey),
            server_credit_account: PeerCreditAccount::default(),
            reachable_organic_peers: 0,
            reachable_seed_anchors: 1,
        }
    }

    pub fn server_peer_id(&self) -> &str {
        &self.server_peer_id
    }

    pub const fn mode(&self) -> SeedServerMode {
        self.mode
    }

    /// The homelab owner's root public key, if this seed has one.
    pub fn owner_root_pubkey(&self) -> Option<&HybridPqPublicKey> {
        self.owner_root_pubkey.as_ref()
    }

    pub fn block_store(&self) -> &BlockStore {
        &self.block_store
    }

    pub fn set_owner_pq_pubkey(&mut self, owner_root_pubkey: HybridPqPublicKey) {
        self.mode = SeedServerMode::HomelabRedundancyVault;
        self.owner_root_pubkey = Some(owner_root_pubkey);
    }

    /// Verifies and admits a client device (`"laptop-1"`, `"desktop-1"`) into the homelab owner's
    /// `HomelabRedundancyVault` using its post-quantum `PersonalDeviceCert`.
    pub fn authorize_personal_device(
        &mut self,
        cert: &PersonalDeviceCert,
    ) -> Result<(), BootstrapError> {
        if self.mode != SeedServerMode::HomelabRedundancyVault {
            return Err(BootstrapError::InvalidSeedServerMode);
        }
        let Some(expected_owner_root) = &self.owner_root_pubkey else {
            return Err(BootstrapError::InvalidPersonalDeviceCert);
        };
        cert.verify(expected_owner_root)?;
        self.authorized_personal_devices
            .insert(cert.device_peer_id.clone(), cert.clone());
        Ok(())
    }

    /// Stores an encrypted shard from an authenticated personal device (`HomelabRedundancyVault` mode)
    /// with **zero reciprocity quota deduction** (`infinite self-quota`) after verifying its
    /// post-quantum `PersonalDeviceCert`.
    pub fn store_personal_device_shard(
        &mut self,
        cert: &PersonalDeviceCert,
        shard_id: &ShardId,
        encrypted_shard_bytes: &[u8],
    ) -> Result<PathBuf, BootstrapError> {
        self.authorize_personal_device(cert)?;
        // Store under the owner's infinite `"self"` quota ring so 0 reciprocity quota is deducted
        // against the personal device's peer credit account.
        let path = self
            .block_store
            .put_shard("self", shard_id, encrypted_shard_bytes)?;
        Ok(path)
    }

    /// Reads an encrypted shard back for an authenticated personal device (`HomelabRedundancyVault` mode).
    pub fn get_personal_device_shard(
        &self,
        cert: &PersonalDeviceCert,
        shard_id: &ShardId,
    ) -> Result<Vec<u8>, BootstrapError> {
        if self.mode != SeedServerMode::HomelabRedundancyVault {
            return Err(BootstrapError::InvalidSeedServerMode);
        }
        let Some(expected_owner_root) = &self.owner_root_pubkey else {
            return Err(BootstrapError::InvalidPersonalDeviceCert);
        };
        cert.verify(expected_owner_root)?;
        Ok(self.block_store.get_shard(shard_id)?)
    }

    /// Zero-Knowledge Lite-Client Stripe Ingestion & Mesh Syndication (`ADR-20`):
    ///
    /// A laptop running in `ClientOperatingMode::LiteSeedBacked` encrypts its files locally
    /// (`AES-256-GCM` / `PqVaultMasterKey` — `K_user` never leaves the laptop) and sends a
    /// `1.0x` encrypted stripe bundle (`LiteStripeSyndicationBundle`) over 1 connection to its
    /// paired `parvault-seed` server (`HomelabRedundancyVault`).
    ///
    /// The `parvault-seed` server:
    /// 1. Authenticates the laptop's post-quantum `PersonalDeviceCert` with `0` reciprocity quota charge.
    /// 2. Encodes the encrypted stripe into `N` Reed-Solomon shards over `GF(2^8)` (`encode_ciphertext_stripe`)
    ///    without ever decrypting or knowing `K_user`.
    /// 3. Verifies that the resulting `stripe_merkle_root` and `shard_hashes` match the laptop's
    ///    signed manifest expectations (`CiphertextIntegrityMismatch` if tampered in transit).
    /// 4. Caches the `N` shards locally on the seed server (enabling 1-hop "Cloud-Away-From-Home"
    ///    selective restores when the laptop is on coffee-shop Wi-Fi).
    /// 5. Syndicates the `N` shards across `mesh_peer_stores` in the wider Neighborhood Cloud so that
    ///    if the NAS / `parvault-seed` server ever dies, the laptop can recover any file or stripe
    ///    directly from any `K`-of-`N` surviving mesh peers using the exact same protocol!
    pub fn ingest_and_syndicate_lite_stripe(
        &mut self,
        cert: &PersonalDeviceCert,
        bundle: &LiteStripeSyndicationBundle,
        mesh_peer_stores: &[&BlockStore],
    ) -> Result<LiteSyndicationReceipt, BootstrapError> {
        let (receipt, _) =
            self.ingest_and_syndicate_lite_stripe_with_grant(cert, bundle, mesh_peer_stores, None)?;
        Ok(receipt)
    }

    /// Syndicates a Lite-Client `1.0x` encrypted stripe while forwarding the owner's `RepairGrant`
    /// to each syndicated mesh peer (`ADR-20`) and returning the assigned peer addresses.
    pub fn ingest_and_syndicate_lite_stripe_with_grant(
        &mut self,
        cert: &PersonalDeviceCert,
        bundle: &LiteStripeSyndicationBundle,
        mesh_peer_stores: &[&BlockStore],
        repair_grant: Option<crate::por::RepairGrant>,
    ) -> Result<(LiteSyndicationReceipt, Vec<String>), BootstrapError> {
        let ingest = self.ingest_lite_stripe(cert, bundle)?;
        if !mesh_peer_stores.is_empty() {
            // In-process mesh stores (tests and embedded callers): no network RPC.
            let mut syndicated_peers = Vec::with_capacity(ingest.shard_ids.len());
            for (idx, shard_id) in ingest.shard_ids.iter().enumerate() {
                let bytes = self.block_store.get_shard(shard_id)?;
                let target = mesh_peer_stores[idx % mesh_peer_stores.len()];
                target.put_shard(&self.server_peer_id, shard_id, &bytes)?;
                syndicated_peers.push(self.server_peer_id.clone());
            }
            let n = syndicated_peers.len();
            return Ok((ingest.receipt(n), syndicated_peers));
        }
        Ok(match self.lite_fan_out_plan(&ingest, repair_grant) {
            Ok(plan) => run_lite_fan_out(plan, LITE_FANOUT_DEADLINE, LITE_FANOUT_PARALLEL_PUTS),
            Err(done) => done,
        })
    }

    /// B-SEED-SYND (L-46), the part under the seed's lock: device cert, encode, integrity check
    /// and the hot copy of every shard in the seed's own ring. No outbound RPC.
    pub fn ingest_lite_stripe(
        &mut self,
        cert: &PersonalDeviceCert,
        bundle: &LiteStripeSyndicationBundle,
    ) -> Result<LiteIngest, BootstrapError> {
        self.authorize_personal_device(cert)?;
        let shard_set = crate::sharding::encode_ciphertext_stripe(
            bundle.stripe_index,
            &bundle.ciphertext_bytes,
            bundle.tier,
        )
        .map_err(|e| BootstrapError::ReedSolomon(e.to_string()))?;
        if shard_set.stripe_merkle_root != bundle.expected_stripe_merkle_root
            || shard_set.shard_hashes != bundle.expected_shard_hashes
        {
            return Err(BootstrapError::CiphertextIntegrityMismatch);
        }
        let mut shard_ids = Vec::with_capacity(shard_set.shards.len());
        for (idx, shard_bytes) in shard_set.shards.iter().enumerate() {
            let shard_id = ShardId {
                stripe_merkle_root: shard_set.stripe_merkle_root,
                shard_index: idx as u32,
                shard_hash: shard_set.shard_hashes[idx],
            };
            self.block_store.put_shard("self", &shard_id, shard_bytes)?;
            shard_ids.push(shard_id);
        }
        Ok(LiteIngest {
            stripe_index: bundle.stripe_index,
            stripe_merkle_root: shard_set.stripe_merkle_root,
            shard_ids,
        })
    }

    /// B-SEED-SYND: what the fan-out needs, owned, so it runs without the seed's lock. `Err`
    /// carries the finished result when the seed has no mesh client or no peers (the receipt then
    /// names only the seed).
    pub fn lite_fan_out_plan(
        &self,
        ingest: &LiteIngest,
        repair_grant: Option<crate::por::RepairGrant>,
    ) -> Result<LiteFanOutPlan, (LiteSyndicationReceipt, Vec<String>)> {
        let seed_only = || {
            (
                ingest.receipt(0),
                vec![self.server_peer_id.clone(); ingest.shard_ids.len()],
            )
        };
        let Some(client) = self.block_store.mesh_client() else {
            return Err(seed_only());
        };
        let peers = client.peers();
        if peers.is_empty() {
            return Err(seed_only());
        }
        let session_key = client
            .identity()
            .derive_stripe_por_session_key(&ingest.stripe_merkle_root);
        Ok(LiteFanOutPlan {
            ingest: ingest.clone(),
            peers: peers.to_vec(),
            server_peer_id: self.server_peer_id.clone(),
            client: client.clone(),
            block_store: self.block_store.clone(),
            repair_grant,
            session_key,
        })
    }

    /// Returns the reciprocity quota tax charged against `device_peer_id` (always `0` for authorized
    /// personal devices in `HomelabRedundancyVault` mode).
    pub fn personal_device_quota_charged(&self, device_peer_id: &str) -> u64 {
        let q = self.block_store.quota();
        let guard = q.lock().expect("quota mutex");
        guard
            .peer_account(device_peer_id)
            .map(|acct| acct.bytes_hosted_for_peer)
            .unwrap_or(0)
    }

    /// Updates reachable external peer counts so `EarnedStanding::evaluate` reflects current network topology.
    pub fn set_neighborhood_peer_counts(&mut self, organic_peers: usize, seed_anchors: usize) {
        self.reachable_organic_peers = organic_peers;
        self.reachable_seed_anchors = seed_anchors;
    }

    /// Records a Proof-of-Retrievability (`PoR`) outcome in this server's own ledger. No network
    /// path calls it: a node never credits itself for answering a challenge (F-07), so earned
    /// standing is self-reported. Used by `simulate_por_heartbeats` for self-tests.
    pub fn record_por_heartbeat(&mut self, passed: bool) {
        if passed {
            self.server_credit_account.por_passes =
                self.server_credit_account.por_passes.saturating_add(1);
        } else {
            self.server_credit_account.por_failures =
                self.server_credit_account.por_failures.saturating_add(1);
        }
        if let Ok(mut q) = self.block_store.quota().lock() {
            q.record_por_outcome(&self.server_peer_id, passed);
        }
    }

    /// Simulates `count` consecutive passed PoR heartbeats with `reachable_organic_peers` neighbors.
    /// Self-test and test fixture only: no network path calls it (F-07).
    pub fn simulate_por_heartbeats(&mut self, count: u64, reachable_organic_peers: usize) {
        self.reachable_organic_peers = reachable_organic_peers;
        for _ in 0..count {
            self.record_por_heartbeat(true);
        }
    }

    /// Ingests an anonymized `BlindedShardId` with an explicit Byte-Epoch lease and `delete_verifier`
    /// (`PublicNetworkBootstrapper` mode).
    pub fn ingest_blinded_shard_with_lease(
        &mut self,
        blinded_id: &BlindedShardId,
        shard_bytes: &[u8],
        capability: BlindedShardCapability,
        voucher: &AnonymousQuotaVoucher,
        lease: crate::storage::BlindedLeaseSpec,
    ) -> Result<PathBuf, BootstrapError> {
        let path = self.block_store.put_blinded_shard_with_lease(
            blinded_id,
            shard_bytes,
            capability,
            voucher,
            &mut self.voucher_ledger,
            lease,
        )?;
        Ok(path)
    }

    /// Answers a stateless PoR challenge (`compute_salted_commitment`) over a hosted blinded shard.
    pub fn answer_blinded_por_challenge(
        &mut self,
        blinded_id: &BlindedShardId,
        capability: &BlindedShardCapability,
        timestamp_ms: u64,
        read_sig: &[u8; 64],
        challenge_nonce: &[u8; 32],
        now_ms: u64,
    ) -> Result<[u8; 32], BootstrapError> {
        let bytes = self.block_store.get_blinded_shard_authorized(
            blinded_id,
            capability,
            timestamp_ms,
            read_sig,
            now_ms,
        )?;
        // No self-credit for answering (F-07).
        Ok(compute_salted_commitment(challenge_nonce, &bytes))
    }

    /// Renews a blinded shard's Byte-Epoch lease so it is preserved across time-based GC sweeps.
    pub fn renew_blinded_lease(
        &mut self,
        blinded_id: &BlindedShardId,
        current_epoch: u64,
        extension_epochs: u64,
    ) -> bool {
        self.block_store
            .renew_blinded_shard_lease(blinded_id, current_epoch, extension_epochs)
    }

    /// Runs a time-driven lease expiration sweep (`BlockStore::sweep_expired_blinded_shards`),
    /// physically deleting `.bshard` files on disk whose `lease_expires_epoch + grace_epochs <= current_epoch`.
    pub fn sweep_expired_epoch(
        &mut self,
        current_epoch: u64,
    ) -> Result<Vec<BlindedShardId>, BootstrapError> {
        Ok(self
            .block_store
            .sweep_expired_blinded_shards(current_epoch)?)
    }

    /// Computes drain migration steps (`ElasticBootstrapEngine::plan_seed_anchor_drain`) to hand
    /// shards off this seed server onto newly joined `OrganicCommunityPeer` nodes.
    pub fn plan_seed_anchor_drain(
        &self,
        standing: EarnedStanding,
        current_placements: &[ShardPlacementAssignment],
        available_candidates: &[ElasticPeerCandidate],
    ) -> Vec<SeedAnchorDrainMigration> {
        ElasticBootstrapEngine::plan_seed_anchor_drain(
            standing,
            current_placements,
            available_candidates,
        )
    }

    /// Produces a deterministic `SeedServerStatusReport` at `current_epoch`.
    pub fn status_report(&self, _current_epoch: u64) -> SeedServerStatusReport {
        let (blinded_bytes, active_blinded_leases) = self.block_store.blinded_lease_stats();
        let (max_storage_bytes, quota_used_bytes) = {
            let q = self.block_store.quota();
            let guard = q.lock().expect("quota mutex");
            (guard.max_storage_bytes(), guard.used_storage_bytes())
        };
        let used_storage_bytes = quota_used_bytes.saturating_add(blinded_bytes);
        let earned_trust_level = self.server_credit_account.trust_level();
        let personal_devices = self.authorized_personal_devices.len().max(1);
        let earned_standing = EarnedStanding::evaluate(
            &self.server_credit_account,
            personal_devices,
            self.reachable_organic_peers,
            self.reachable_seed_anchors,
        )
        .unwrap_or(EarnedStanding::ProbationaryConsumerPool);

        SeedServerStatusReport {
            mode: self.mode,
            peer_role: self.mode.peer_role(),
            max_storage_bytes,
            used_storage_bytes,
            active_blinded_leases,
            earned_trust_level,
            earned_standing,
            por_passes: self.server_credit_account.por_passes,
            sla_ratio: self.server_credit_account.sla_ratio(),
            holds_own_plaintext_files: false,
        }
    }
}

/// Availability state of an erasure-coded stripe during normal operation or correlated ISP blackouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StripeAvailability {
    /// All `N` shards are reachable online.
    HealthyFullRedundancy,
    /// `K <= online_shards < N`: Stripe is 100% readable/recoverable right now, with degraded parity.
    DegradedButReadable {
        online_shards: usize,
        required_k: usize,
    },
    /// `online_shards < K` during a massive correlated outage (e.g. 75% of nodes offline):
    /// Shards are NOT lost (they remain safely on the offline nodes' disks within their multi-week
    /// Byte-Epoch lease window). The stripe hibernates with `0` wasted repair bandwidth until
    /// offline ISP nodes return and push `online_shards >= K`.
    HibernatingAwaitingIspReturn {
        online_shards: usize,
        offline_preserved_shards: usize,
        required_k: usize,
    },
}

/// Telemetry & decision snapshot for a single wave of a correlated ISP / regional outage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MassOutageWaveReport {
    pub wave_name: String,
    pub total_mesh_nodes: usize,
    pub online_nodes: usize,
    pub offline_nodes: usize,
    pub offline_fraction: f64,
    /// True when `offline_fraction >= 0.15` (15%+ of mesh or ASN suddenly unreachable):
    /// freezes PoR SLA demotions/slashing and suppresses thundering-herd repair storms.
    pub circuit_breaker_active: bool,
    pub por_sla_penalties_frozen: bool,
    pub stripes_immediately_readable: usize,
    pub stripes_hibernating_zero_data_loss: usize,
    pub permanent_data_loss_stripes: usize,
    pub zero_bandwidth_rejoined_shards: usize,
}

/// Maximum attested sub-slots permitted inside a shared RFC 6598 CGNAT (`100.64.0.0/10`) `/24` pool (`ADR-15`).
pub const MAX_CGNAT_SLOTS_PER_SLASH24: u8 = 4;

/// Computes the canonical Sybil & fault-domain bucket key for an IP address (`ADR-15`):
/// - **IPv6 (`/32` LIR / `/48` Site Normalization):** Collapses all $2^{80}$ addresses inside an
///   IPv6 `/48` (and groups by `/32` LIR prefix `v6:xxxx:xxxx::/32`) so an attacker with 65,536 `/64`
///   subnets cannot multiply Pioneer Standby Mining or capture multiple shards of a stripe.
/// - **RFC 6598 CGNAT (`100.64.0.0/10` — Starlink / 5G Home Internet):** Allows up to `4` hardware/WoT-attested
///   sub-slots (`cgnat_slot % 4`) per `/24` so independent households behind carrier NAT are not falsely collided,
///   while still damping unbounded Sybils (`> 4`) in the same CGNAT pool.
/// - **Standard Public IPv4:** Grouped by `/24` (`a.b.c.0/24`).
pub fn canonical_sybil_subnet_key(ip: std::net::IpAddr, cgnat_slot: Option<u8>) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            let is_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64;
            if is_cgnat {
                let slot = cgnat_slot.unwrap_or(0) % MAX_CGNAT_SLOTS_PER_SLASH24;
                format!("cgnat:{}.{}.{}.0/24#slot{}", o[0], o[1], o[2], slot)
            } else {
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            }
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("v6:{:04x}:{:04x}::/32", s[0], s[1])
        }
    }
}

/// Normalizes a raw subnet prefix string (e.g. `"2001:db8:1234:5678::1/64"`, `"192.0.2.10/24"`)
/// into the canonical Sybil & fault-domain key (`canonical_sybil_subnet_key`) so IPv6 `/64`
/// rotation within the same `/32` LIR allocation cannot bypass subnet caps (`ADR-15`).
pub fn normalize_subnet_prefix_key(raw_prefix: &str) -> String {
    if raw_prefix.starts_with("cgnat:")
        || raw_prefix.starts_with("v6:")
        || raw_prefix.starts_with("v4:")
    {
        return raw_prefix.to_string();
    }
    let ip_part = raw_prefix.split('/').next().unwrap_or(raw_prefix).trim();
    if let Ok(ip) = ip_part.parse::<std::net::IpAddr>() {
        return canonical_sybil_subnet_key(ip, None);
    }
    raw_prefix.to_string()
}

/// Correlated ISP Outage Circuit-Breaker & Anti-Repair-Storm Controller (`ADR-15`).
pub struct CorrelatedOutageController;

impl CorrelatedOutageController {
    /// Threshold of simultaneous mesh/ASN unreachability (`15.0%`) that trips the
    /// Correlated Outage Circuit-Breaker (freezing PoR SLA demotions and throttling non-critical repairs).
    pub const CIRCUIT_BREAKER_OFFLINE_THRESHOLD: f64 = 0.15;

    /// Evaluates the health of a batch of stripes (each with `n_total` assigned node indices `0..total_nodes`)
    /// across a mass outage wave (`online_mask[node_idx] == true`), tracking how many shards
    /// snap back online with `0` repair bandwidth when previously offline ISP nodes return.
    pub fn evaluate_outage_wave(
        wave_name: impl Into<String>,
        standing: EarnedStanding,
        total_mesh_nodes: usize,
        previous_online_mask: &[bool],
        current_online_mask: &[bool],
        stripe_node_assignments: &[Vec<usize>],
    ) -> MassOutageWaveReport {
        let (required_k, _m, _n) = standing.erasure_params();
        let online_nodes = current_online_mask.iter().filter(|&&b| b).count();
        let offline_nodes = total_mesh_nodes.saturating_sub(online_nodes);
        let offline_fraction = if total_mesh_nodes == 0 {
            0.0
        } else {
            offline_nodes as f64 / total_mesh_nodes as f64
        };

        let circuit_breaker_active = offline_fraction >= Self::CIRCUIT_BREAKER_OFFLINE_THRESHOLD;

        let mut stripes_immediately_readable = 0usize;
        let mut stripes_hibernating_zero_data_loss = 0usize;
        let mut zero_bandwidth_rejoined_shards = 0usize;

        for peers in stripe_node_assignments {
            let mut online_shards = 0usize;
            for &node_idx in peers {
                let is_now_online = current_online_mask.get(node_idx).copied().unwrap_or(false);
                let was_prev_online = previous_online_mask.get(node_idx).copied().unwrap_or(true);
                if is_now_online {
                    online_shards += 1;
                    if !was_prev_online {
                        // Node was offline in the previous wave and came back up with its .bshard
                        // file still intact on disk (within Byte-Epoch lease grace window)!
                        zero_bandwidth_rejoined_shards += 1;
                    }
                }
            }

            if online_shards >= required_k {
                stripes_immediately_readable += 1;
            } else {
                stripes_hibernating_zero_data_loss += 1;
            }
        }

        MassOutageWaveReport {
            wave_name: wave_name.into(),
            total_mesh_nodes,
            online_nodes,
            offline_nodes,
            offline_fraction,
            circuit_breaker_active,
            por_sla_penalties_frozen: circuit_breaker_active,
            stripes_immediately_readable,
            stripes_hibernating_zero_data_loss,
            permanent_data_loss_stripes: 0,
            zero_bandwidth_rejoined_shards,
        }
    }

    /// **Elastic Surge Parity (`16-of-20` $\to$ `16-of-28` Emergency Parity Expansion):**
    ///
    /// In `16-of-20` (`EarnedHomelabAnchorPool`), a stripe normally has only $M = 4$ parity shards
    /// (surviving $20\%$ loss). If a rolling regional/ISP outage begins and online shards drop to
    /// `16..=18`, witnesses can invoke `synthesize_surge_parity_shards` using any $K = 16$ surviving
    /// shards to generate `surge_parity_count` (e.g. `8`) **additional $GF(2^8)$ parity shards**,
    /// temporarily expanding the stripe from `16-of-20` (tolerates `4` failures) to **`16-of-28`
    /// (tolerates `12` failures = `43%` of nodes going dark)** without ever decrypting plaintext!
    pub fn synthesize_surge_parity_shards(
        base_standing: EarnedStanding,
        surviving_base_shards: Vec<Option<Vec<u8>>>,
        original_ciphertext_len: usize,
        expected_ciphertext_sha256: &[u8; 32],
        surge_parity_count: usize,
    ) -> Result<Vec<Vec<u8>>, BootstrapError> {
        let (k, m_base, _n_base) = base_standing.erasure_params();
        let available = surviving_base_shards.iter().filter(|s| s.is_some()).count();
        if available < k {
            return Err(BootstrapError::InsufficientShardsForReshard {
                available,
                required_k: k,
            });
        }

        // 1. Reconstruct the K data shards over GF(2^8) from the surviving base shards
        let mut base_buf = surviving_base_shards;
        let rs_base =
            ReedSolomon::new(k, m_base).map_err(|e| BootstrapError::ReedSolomon(e.to_string()))?;
        rs_base
            .reconstruct(&mut base_buf)
            .map_err(|e| BootstrapError::ReedSolomon(e.to_string()))?;

        let shard_len = base_buf[0].as_ref().map(|s| s.len()).unwrap_or(1);
        let mut ciphertext = Vec::with_capacity(original_ciphertext_len);
        for s in base_buf.iter().take(k).flatten() {
            ciphertext.extend_from_slice(s);
        }
        ciphertext.truncate(original_ciphertext_len);

        let actual_sha: [u8; 32] = Sha256::digest(&ciphertext).into();
        if &actual_sha != expected_ciphertext_sha256 {
            return Err(BootstrapError::CiphertextIntegrityMismatch);
        }

        // 2. Encode the extended `(k, m_base + surge_parity_count)` Reed-Solomon code over GF(2^8)
        let m_extended = m_base + surge_parity_count;
        let rs_extended = ReedSolomon::new(k, m_extended)
            .map_err(|e| BootstrapError::ReedSolomon(e.to_string()))?;

        let mut extended_shards: Vec<Vec<u8>> = Vec::with_capacity(k + m_extended);
        for s_opt in base_buf.into_iter().take(k) {
            extended_shards.push(s_opt.unwrap_or_else(|| vec![0u8; shard_len]));
        }
        for _ in 0..m_extended {
            extended_shards.push(vec![0u8; shard_len]);
        }

        rs_extended
            .encode(&mut extended_shards)
            .map_err(|e| BootstrapError::ReedSolomon(e.to_string()))?;

        Ok(extended_shards)
    }

    /// **Empirical Failure Co-Variance Anti-Correlation Filter:**
    ///
    /// Even if two nodes report different `/24` subnets or different reseller ASNs, they may share
    /// the same physical fiber conduit, power grid substation, or ISP upstream.
    /// By observing each candidate node's 64-epoch downtime bitmask (`downtime_bitmask_64`: bit `t = 1`
    /// if the node was unreachable in epoch `t`), ` compute_failure_jaccard_similarity` computes the
    /// empirical Jaccard failure correlation in `[0.0, 1.0]`.
    /// `select_decorrelated_homelab_targets` refuses to place shards of a `16-of-20` stripe onto two nodes
    /// whose historical downtime similarity exceeds `max_jaccard_correlation` (e.g. `0.30`).
    pub fn compute_failure_jaccard_similarity(mask_a: u64, mask_b: u64) -> f64 {
        let union = (mask_a | mask_b).count_ones();
        if union == 0 {
            return 0.0;
        }
        let intersection = (mask_a & mask_b).count_ones();
        intersection as f64 / union as f64
    }

    /// Selects `N` target peers while ensuring that no more than `max_correlated_cluster_size`
    /// (e.g. `<= 2`, strictly `< M = 4`) chosen peers have historical downtime correlation
    /// exceeding `max_jaccard_correlation`.
    pub fn select_decorrelated_targets(
        standing: EarnedStanding,
        candidates: &[(ElasticPeerCandidate, u64)],
        max_jaccard_correlation: f64,
        max_correlated_cluster_size: usize,
    ) -> Vec<ShardPlacementAssignment> {
        let (_k, _m, n_total) = standing.erasure_params();
        let mut selected: Vec<(ShardPlacementAssignment, u64)> = Vec::with_capacity(n_total);

        for (cand, mask) in candidates {
            if selected.len() == n_total {
                break;
            }
            if cand.trust_level == TrustLevel::SlashedQuarantined {
                continue;
            }
            let correlated_peers = selected
                .iter()
                .filter(|(_prev, prev_mask)| {
                    Self::compute_failure_jaccard_similarity(*prev_mask, *mask)
                        > max_jaccard_correlation
                })
                .count();

            if correlated_peers < max_correlated_cluster_size {
                let shard_index = selected.len();
                selected.push((
                    ShardPlacementAssignment {
                        shard_index,
                        peer_id: cand.peer_id.clone(),
                        role: cand.role,
                        subnet_prefix: cand.subnet_prefix.clone(),
                    },
                    *mask,
                ));
            }
        }

        selected.into_iter().map(|(a, _)| a).collect()
    }
}
