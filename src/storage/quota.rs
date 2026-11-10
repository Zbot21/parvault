use crate::config::ErasureTier;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Rolling SLA threshold (99.5% PoR pass rate) required to qualify for the 80% efficiency
/// Homelab / Prosumer pool (`16-of-20`, 1.25x expansion factor).
pub const HOMELAB_SLA_THRESHOLD: f64 = 0.995;

/// Default minimum free OS filesystem space (5 GiB) reserved as a safety guard against disk exhaustion.
pub const DEFAULT_MIN_FREE_DISK_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Dynamic Uptime-Based Trust Levels (ADR-10):
/// Governs how many shards of a single stripe an ASN/subnet is permitted to host and
/// scales the storage quota allowance within a heterogeneous mesh of untrusted and high-uptime nodes.
/// Even at `HighUptimeAnchor` (`4` shards/subnet), the cap remains strictly `< K / 3` (`4 < 16`),
/// guaranteeing mathematically that a fully colluding high-uptime subnet cannot reconstruct ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    SlashedQuarantined,
    UntrustedProbationary,
    VerifiedNeighbor,
    HighUptimeAnchor,
}

impl TrustLevel {
    /// Maximum shards of any single stripe permitted within a subnet/ASN at this trust level.
    pub const fn max_shards_per_subnet(&self) -> usize {
        match self {
            Self::SlashedQuarantined => 0,
            Self::UntrustedProbationary => 1,
            Self::VerifiedNeighbor => 2,
            Self::HighUptimeAnchor => 4,
        }
    }

    /// Storage capacity multiplier unlocked by sustained PoR uptime.
    pub const fn storage_quota_multiplier(&self) -> f64 {
        match self {
            Self::SlashedQuarantined => 0.0,
            Self::UntrustedProbationary => 1.0,
            Self::VerifiedNeighbor => 2.5,
            Self::HighUptimeAnchor => 5.0,
        }
    }
}

/// Per-peer storage reciprocity & SLA account (ADR-07).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerCreditAccount {
    /// Physical bytes this local node is currently hosting on behalf of the remote peer.
    pub bytes_hosted_for_peer: u64,
    /// Physical bytes the remote peer is currently hosting on behalf of this local node.
    pub bytes_contributed_by_peer: u64,
    /// Cumulative successful PoR audits (< 300 ms valid salted commitments).
    pub por_passes: u64,
    /// Cumulative failed or timed-out PoR audits.
    pub por_failures: u64,
    /// Whether this peer has been slashed for Byzantine shard poisoning or egress withholding.
    pub is_slashed: bool,
    /// Non-refundable cumulative bytes written during the current epoch (`ADR-15` anti-SSD-wear griefing).
    #[serde(default)]
    pub epoch_ingress_bytes_written: u64,
}

impl PeerCreditAccount {
    /// Computes rolling PoR SLA pass ratio in `[0.0, 1.0]`.
    /// Peers with >= 20 audits and >= 99.5% pass rate qualify for the Homelab SLA pool.
    pub fn sla_ratio(&self) -> f64 {
        let total = self.por_passes + self.por_failures;
        if total == 0 {
            return 1.0;
        }
        self.por_passes as f64 / total as f64
    }

    /// Determines the peer's qualified SLA erasure tier based on observed PoR history.
    pub fn qualified_tier(&self) -> ErasureTier {
        let total = self.por_passes + self.por_failures;
        if total >= 20 && self.sla_ratio() >= HOMELAB_SLA_THRESHOLD {
            ErasureTier::Homelab
        } else {
            ErasureTier::Consumer
        }
    }

    /// Returns the required physical contribution multiplier (`1.25x` for Homelab, `2.00x` for Consumer).
    pub fn required_reciprocity_factor(&self) -> f64 {
        self.qualified_tier().expansion_factor()
    }

    /// Computes the peer's dynamic uptime trust level based on cumulative PoR history and slash status (ADR-10).
    pub fn trust_level(&self) -> TrustLevel {
        if self.is_slashed {
            return TrustLevel::SlashedQuarantined;
        }
        let total = self.por_passes + self.por_failures;
        let ratio = self.sla_ratio();
        if total >= 200 && ratio >= 0.998 {
            TrustLevel::HighUptimeAnchor
        } else if total >= 50 && ratio >= 0.98 {
            TrustLevel::VerifiedNeighbor
        } else {
            TrustLevel::UntrustedProbationary
        }
    }
}

/// Manages local disk allocation, tier-weighted peer reciprocity credits (ADR-07),
/// and LRU cache eviction for transient shards (`storage::quota`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaManager {
    max_storage_bytes: u64,
    used_storage_bytes: u64,
    bootstrap_grace_bytes: u64,
    peer_accounts: HashMap<String, PeerCreditAccount>,
    shard_sizes: HashMap<String, u64>,
    #[serde(default)]
    shard_owners: HashMap<String, String>,
    lru_queue: VecDeque<String>,
    #[serde(default)]
    min_free_disk_bytes: u64,
    #[serde(default)]
    observed_free_disk_bytes: Option<u64>,
    #[serde(skip)]
    persistence_path: Option<std::path::PathBuf>,
}

impl QuotaManager {
    pub fn new(max_storage_bytes: u64, bootstrap_grace_bytes: u64) -> Self {
        Self {
            max_storage_bytes,
            used_storage_bytes: 0,
            bootstrap_grace_bytes,
            peer_accounts: HashMap::new(),
            shard_sizes: HashMap::new(),
            shard_owners: HashMap::new(),
            lru_queue: VecDeque::new(),
            min_free_disk_bytes: 0,
            observed_free_disk_bytes: None,
            persistence_path: None,
        }
    }

    /// Loads or binds a persistent `QuotaManager` at `data_dir/quota_state.bin`.
    pub fn with_persistence_dir(
        max_storage_bytes: u64,
        bootstrap_grace_bytes: u64,
        data_dir: &std::path::Path,
    ) -> Self {
        let path = data_dir.join("quota_state.bin");
        if path.exists() {
            if let Ok(raw) = std::fs::read(&path) {
                if let Ok(mut loaded) = bincode::deserialize::<Self>(&raw) {
                    loaded.max_storage_bytes = max_storage_bytes;
                    loaded.bootstrap_grace_bytes = bootstrap_grace_bytes;
                    loaded.persistence_path = Some(path);
                    return loaded;
                }
            }
        }
        let mut q = Self::new(max_storage_bytes, bootstrap_grace_bytes);
        q.persistence_path = Some(path);
        q
    }

    pub fn bind_persistence_dir(&mut self, data_dir: &std::path::Path) {
        let path = data_dir.join("quota_state.bin");
        if self.used_storage_bytes == 0 && self.peer_accounts.is_empty() && path.exists() {
            if let Ok(raw) = std::fs::read(&path) {
                if let Ok(mut loaded) = bincode::deserialize::<Self>(&raw) {
                    loaded.max_storage_bytes = self.max_storage_bytes;
                    loaded.bootstrap_grace_bytes = self.bootstrap_grace_bytes;
                    if self.min_free_disk_bytes > 0 {
                        loaded.min_free_disk_bytes = self.min_free_disk_bytes;
                    }
                    loaded.persistence_path = Some(path);
                    *self = loaded;
                    return;
                }
            }
        }
        self.persistence_path = Some(path);
    }

    fn persist(&self) {
        if let Some(ref path) = self.persistence_path {
            if let Ok(bytes) = bincode::serialize(self) {
                let _ = crate::storage::BlockStore::atomic_write_file(path, &bytes);
            }
        }
    }

    pub fn set_min_free_disk_bytes(&mut self, bytes: u64) {
        self.min_free_disk_bytes = bytes;
    }

    pub fn update_observed_free_disk_bytes(&mut self, free_bytes: u64) {
        self.observed_free_disk_bytes = Some(free_bytes);
    }

    pub const fn min_free_disk_bytes(&self) -> u64 {
        self.min_free_disk_bytes
    }

    pub const fn observed_free_disk_bytes(&self) -> Option<u64> {
        self.observed_free_disk_bytes
    }

    pub const fn max_storage_bytes(&self) -> u64 {
        self.max_storage_bytes
    }

    pub const fn used_storage_bytes(&self) -> u64 {
        self.used_storage_bytes
    }

    pub const fn available_storage_bytes(&self) -> u64 {
        self.max_storage_bytes
            .saturating_sub(self.used_storage_bytes)
    }

    pub fn peer_account(&self, peer_id: &str) -> Option<&PeerCreditAccount> {
        self.peer_accounts.get(peer_id)
    }

    /// Returns the current `TrustLevel` of `peer_id` (defaults to `UntrustedProbationary` for new peers).
    pub fn peer_trust_level(&self, peer_id: &str) -> TrustLevel {
        self.peer_accounts
            .get(peer_id)
            .map(PeerCreditAccount::trust_level)
            .unwrap_or(TrustLevel::UntrustedProbationary)
    }

    /// Records the bytes that a remote peer is hosting for us, unlocking proportional reciprocity credit.
    pub fn record_remote_contribution(&mut self, peer_id: &str, contributed_bytes: u64) {
        let acct = self.peer_accounts.entry(peer_id.to_string()).or_default();
        acct.bytes_contributed_by_peer = acct
            .bytes_contributed_by_peer
            .saturating_add(contributed_bytes);
        self.persist();
    }

    /// Records a PoR audit outcome for `peer_id`, updating its SLA cohort qualification.
    pub fn record_por_outcome(&mut self, peer_id: &str, passed: bool) {
        let acct = self.peer_accounts.entry(peer_id.to_string()).or_default();
        if passed {
            acct.por_passes = acct.por_passes.saturating_add(1);
        } else {
            acct.por_failures = acct.por_failures.saturating_add(1);
        }
        self.persist();
    }

    /// Checks whether `peer_id` is within both the node's physical disk ceiling and its
    /// tier-weighted reciprocity allowance (`bootstrap_grace_bytes + contributed / factor`).
    pub fn can_accept_shard(&self, peer_id: &str, shard_bytes: u64) -> bool {
        if let Some(free_bytes) = self.observed_free_disk_bytes {
            if free_bytes.saturating_sub(shard_bytes) < self.min_free_disk_bytes {
                return false;
            }
        }
        if self.used_storage_bytes.saturating_add(shard_bytes) > self.max_storage_bytes {
            return false;
        }
        if peer_id == "local" || peer_id == "self" {
            return true;
        }

        let acct = self.peer_accounts.get(peer_id).cloned().unwrap_or_default();
        if acct.is_slashed {
            return false;
        }
        let factor = acct.required_reciprocity_factor();
        let earned_allowance = (acct.bytes_contributed_by_peer as f64 / factor) as u64;
        let max_allowed_for_peer = self.bootstrap_grace_bytes.saturating_add(earned_allowance);

        // Enforce both active hosted ceiling AND per-epoch cumulative ingress write ceiling (4x allowance)
        // so an attacker cannot loop `put_shard -> delete_shard` to wear out NVMe flash at 0 net storage.
        let max_epoch_write_allowance = max_allowed_for_peer.saturating_mul(4);
        acct.bytes_hosted_for_peer.saturating_add(shard_bytes) <= max_allowed_for_peer
            && acct.epoch_ingress_bytes_written.saturating_add(shard_bytes)
                <= max_epoch_write_allowance
    }

    /// Resets per-epoch ingress write counters at the start of a new epoch.
    pub fn reset_epoch_ingress_counters(&mut self) {
        for acct in self.peer_accounts.values_mut() {
            acct.epoch_ingress_bytes_written = 0;
        }
    }

    /// Retroactively burns all accumulated reciprocity credits (`bytes_contributed_by_peer`)
    /// and permanently blocks future storage requests when a peer is caught withholding shard
    /// egress at restore time or injecting poisoned shards (Defense 4).
    /// Returns the total byte credits burned.
    pub fn slash_peer_for_withholding(&mut self, offender_peer_id: &str) -> u64 {
        let acct = self
            .peer_accounts
            .entry(offender_peer_id.to_string())
            .or_default();
        let burned = acct.bytes_contributed_by_peer;
        acct.bytes_contributed_by_peer = 0;
        acct.is_slashed = true;
        acct.por_failures = acct.por_failures.saturating_add(100);
        self.persist();
        burned
    }

    /// Commits a newly stored shard to quota accounting and pushes it to the back of the LRU queue.
    pub fn record_shard_stored(&mut self, peer_id: &str, shard_key: String, shard_bytes: u64) {
        if let Some(prev_size) = self.shard_sizes.insert(shard_key.clone(), shard_bytes) {
            self.used_storage_bytes = self.used_storage_bytes.saturating_sub(prev_size);
            if let Some(prev_owner) = self.shard_owners.get(&shard_key) {
                if let Some(acct) = self.peer_accounts.get_mut(prev_owner) {
                    acct.bytes_hosted_for_peer =
                        acct.bytes_hosted_for_peer.saturating_sub(prev_size);
                }
            }
        }
        self.shard_owners
            .insert(shard_key.clone(), peer_id.to_string());
        let acct = self.peer_accounts.entry(peer_id.to_string()).or_default();
        acct.bytes_hosted_for_peer = acct.bytes_hosted_for_peer.saturating_add(shard_bytes);
        acct.epoch_ingress_bytes_written =
            acct.epoch_ingress_bytes_written.saturating_add(shard_bytes);
        self.used_storage_bytes = self.used_storage_bytes.saturating_add(shard_bytes);
        self.touch_shard(&shard_key);
        self.persist();
    }

    /// Updates LRU recency when a shard is read or audited.
    pub fn touch_shard(&mut self, shard_key: &str) {
        self.lru_queue.retain(|k| k != shard_key);
        self.lru_queue.push_back(shard_key.to_string());
    }

    /// Removes a shard from quota accounting.
    pub fn record_shard_removed(&mut self, peer_id: &str, shard_key: &str, shard_bytes: u64) {
        self.shard_sizes.remove(shard_key);
        self.shard_owners.remove(shard_key);
        self.lru_queue.retain(|k| k != shard_key);
        self.used_storage_bytes = self.used_storage_bytes.saturating_sub(shard_bytes);
        if let Some(acct) = self.peer_accounts.get_mut(peer_id) {
            acct.bytes_hosted_for_peer = acct.bytes_hosted_for_peer.saturating_sub(shard_bytes);
        }
        self.persist();
    }

    /// Evicts least-recently-used shard keys until at least `needed_bytes` of free space is available.
    pub fn evict_lru_to_fit(&mut self, needed_bytes: u64) -> Vec<String> {
        let mut evicted = Vec::new();
        while self.available_storage_bytes() < needed_bytes {
            let Some(oldest_key) = self.lru_queue.pop_front() else {
                break;
            };
            if let Some(sz) = self.shard_sizes.remove(&oldest_key) {
                self.used_storage_bytes = self.used_storage_bytes.saturating_sub(sz);
                if let Some(owner) = self.shard_owners.remove(&oldest_key) {
                    if let Some(acct) = self.peer_accounts.get_mut(&owner) {
                        acct.bytes_hosted_for_peer = acct.bytes_hosted_for_peer.saturating_sub(sz);
                    }
                }
                evicted.push(oldest_key);
            }
        }
        evicted
    }
}
