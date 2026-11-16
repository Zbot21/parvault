//! Formal model: `specs/ParVaultConfidentialityAndTrust.tla` (guard `slashed-sticky`).
use crate::config::ErasureTier;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Rolling SLA threshold (99.5% PoR pass rate) required to qualify for the 80% efficiency
/// Homelab / Prosumer pool (`16-of-20`, 1.25x expansion factor).
pub const HOMELAB_SLA_THRESHOLD: f64 = 0.995;

pub use crate::profile::DEFAULT_MIN_FREE_DISK_BYTES;

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
    /// Chunk audits of this peer that this node ran and that verified (B-59, `por::auditor`).
    pub por_passes: u64,
    /// Chunk audits of this peer whose proof was verifiably invalid against the manifest root.
    /// An unanswered, refused or late audit is never counted here (L-27); the auditor counts
    /// those in `por_audit_state.json`. The one automatic consequence (ADR-03 decision 5): with
    /// `por_passes` this sets the peer's reciprocity factor on this node, 1.25 at >= 20 audits
    /// and >= 99.5 % passes, else 2.0, so an invalid proof narrows the peer's allowance here. No
    /// repair, quarantine or gossip follows.
    pub por_failures: u64,
    /// Whether this peer has been slashed for Byzantine shard poisoning or egress withholding.
    pub is_slashed: bool,
    /// Non-refundable cumulative bytes written during the current epoch (`ADR-19` anti-SSD-wear griefing).
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
    /// B-152 (a): the LRU order, oldest first. Persisted in the `VecDeque<String>` layout of
    /// `5943dca` (the same bytes), held in RAM as an O(log n) index; empty and inert on
    /// file-backed stores, which never evict (B-161).
    lru_queue: LruIndex,
    #[serde(default)]
    min_free_disk_bytes: u64,
    #[serde(default)]
    observed_free_disk_bytes: Option<u64>,
    #[serde(skip)]
    persistence_path: Option<std::path::PathBuf>,
    /// The refusal code while the last `quota_state.bin` write failed (B-52): the disk copy is stale, so
    /// [`Self::quota_decision`] refuses new shards until a later write succeeds.
    #[serde(skip)]
    persist_failed: std::cell::Cell<Option<&'static str>>,
    /// Set when `quota_state.bin` exists but cannot be read or decoded (B-52 QA): the recorded
    /// accounting is unknown, so [`Self::quota_decision`] refuses with this code and the file is
    /// never overwritten. Cleared only by a restart that loads the file.
    #[serde(skip)]
    load_error: Option<&'static str>,
    /// B-162: when the current write-ceiling epoch started, on the monotonic clock. RAM only:
    /// `quota_state.bin` is a bincode dump of this struct, so a new serialized field would make
    /// every existing file fail to load (`reject.quota_state_corrupt`). A restart starts a new
    /// epoch (the counters are zeroed on load).
    #[serde(skip)]
    epoch_started: Option<std::time::Instant>,
    /// B-162: the write-ceiling epoch length in ms (RAM only; 0 means
    /// [`QUOTA_WRITE_EPOCH_SECS`]; `quota_write_epoch_secs` in `config.toml`).
    #[serde(skip)]
    write_epoch_ms: u64,
    /// B-152 (a), L-130: the held-shard bound (RAM only; `None` keeps no bound, as before
    /// `v0.5.6`, until the daemon sets it at startup).
    #[serde(skip)]
    held_bound: Option<HeldShardBound>,
}

/// B-152 (a): the LRU order of held shards in O(log n): a sequence number per key and the keys
/// by sequence, sharing one allocation per key. Serialized exactly as the `VecDeque<String>`
/// it replaces (a length, then the keys oldest first), so `quota_state.bin` keeps its layout.
#[derive(Debug, Clone, Default)]
pub struct LruIndex {
    next_seq: u64,
    by_key: HashMap<Arc<str>, u64>,
    by_seq: BTreeMap<u64, Arc<str>>,
    /// File-backed stores: no order is kept (RAM only, never serialized).
    disabled: bool,
}

impl LruIndex {
    fn touch(&mut self, key: &str) {
        if self.disabled {
            return;
        }
        let k: Arc<str> = match self.by_key.get_key_value(key) {
            Some((k, seq)) => {
                let k = Arc::clone(k);
                self.by_seq.remove(seq);
                k
            }
            None => Arc::from(key),
        };
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.by_seq.insert(seq, Arc::clone(&k));
        self.by_key.insert(k, seq);
    }

    fn remove(&mut self, key: &str) {
        if let Some(seq) = self.by_key.remove(key) {
            self.by_seq.remove(&seq);
        }
    }

    fn pop_oldest(&mut self) -> Option<String> {
        let (_, k) = self.by_seq.pop_first()?;
        self.by_key.remove(&k);
        Some(k.to_string())
    }
}

impl Serialize for LruIndex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.by_seq.values().map(|k| &**k))
    }
}

impl<'de> Deserialize<'de> for LruIndex {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let keys = Vec::<String>::deserialize(deserializer)?;
        let mut idx = Self::default();
        for k in keys {
            idx.touch(&k);
        }
        Ok(idx)
    }
}

/// B-152 (a), L-130: measured anon bytes per held regular shard, the whole daemon's anon growth
/// over 2,000 held shards (`b152_two_cycles_of_2000_shards`, release build on the EVO-X2,
/// 2026-11-16: 3,252 B; heap152's heap-only figure at `5943dca` was about 2.5 kB). The
/// held-shard bound divides the index memory budget by it; `v0.5.7`'s re-key targets 300 B.
pub const BYTES_PER_HELD_SHARD: u64 = 3_252;

/// Where the held-shard bound came from (logged at startup, shown in live status).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldShardBoundSource {
    /// `max_held_shards` in `config.toml`.
    Config,
    /// The cgroup memory limit the daemon runs under.
    Cgroup,
    /// Physical RAM (no cgroup limit).
    PhysicalRam,
    /// No memory figure could be read: the profile ceiling.
    ProfileCeiling,
}

impl HeldShardBoundSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Cgroup => "cgroup",
            Self::PhysicalRam => "ram",
            Self::ProfileCeiling => "profile-ceiling",
        }
    }
}

/// The held-shard bound (L-130) and its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldShardBound {
    pub max: u64,
    pub source: HeldShardBoundSource,
    /// The memory figure it was derived from, if any (bytes).
    pub memory_bytes: Option<u64>,
}

/// L-130 per profile: the share of memory (percent) the per-shard indexes may use, and the floor
/// and ceiling of the bound. Shares and ceilings are L-130's; the floors are track B1's
/// proposal (low enough that a 64 MiB NAS container still derives from its memory).
pub const fn held_shard_profile(profile: crate::profile::HardwareProfile) -> (u64, u64, u64) {
    use crate::profile::HardwareProfile;
    match profile {
        HardwareProfile::RouterSoc => (15, 512, 4_096),
        HardwareProfile::HomelabNas => (25, 2_048, 1_048_576),
        HardwareProfile::Desktop => (25, 8_192, 4_194_304),
    }
}

/// L-130: max held shards = memory x share / [`BYTES_PER_HELD_SHARD`], clamped to the profile's
/// floor and ceiling; an explicit config value wins unclamped (at least 1). Pure; a Kani target.
pub const fn held_shard_bound_from(
    memory_bytes: Option<u64>,
    memory_is_cgroup: bool,
    share_pct: u64,
    floor: u64,
    ceiling: u64,
    config_override: Option<u64>,
) -> HeldShardBound {
    if let Some(n) = config_override {
        return HeldShardBound {
            max: if n == 0 { 1 } else { n },
            source: HeldShardBoundSource::Config,
            memory_bytes,
        };
    }
    let Some(mem) = memory_bytes else {
        return HeldShardBound {
            max: ceiling,
            source: HeldShardBoundSource::ProfileCeiling,
            memory_bytes: None,
        };
    };
    let derived = mem / 100 * share_pct / BYTES_PER_HELD_SHARD;
    let max = if derived < floor {
        floor
    } else if derived > ceiling {
        ceiling
    } else {
        derived
    };
    HeldShardBound {
        max,
        source: if memory_is_cgroup {
            HeldShardBoundSource::Cgroup
        } else {
            HeldShardBoundSource::PhysicalRam
        },
        memory_bytes: Some(mem),
    }
}

/// B-152 (a), arch152b 3.4: a new regular shard is refused once the node holds `max` (memory
/// for the per-shard indexes, L-130), before any eviction (C31): refuse, never evict.
pub const fn held_shard_decision(held: u64, max: u64) -> Result<(), &'static str> {
    if held >= max {
        Err("reject.node_shard_count")
    } else {
        Ok(())
    }
}

/// The memory limit this process runs under: the lowest cgroup v2 `memory.max` on its path
/// (`/proc/self/cgroup`, walking up to the root, as the kernel applies every ancestor's limit),
/// else the cgroup v1 `memory.limit_in_bytes`, else `MemTotal` from `/proc/meminfo`. Returns
/// the bytes and whether a cgroup limit applied.
pub fn read_memory_limit() -> Option<(u64, bool)> {
    let ram = std::fs::read_to_string("/proc/meminfo").ok().and_then(|t| {
        t.lines()
            .find_map(|l| l.strip_prefix("MemTotal:"))
            .and_then(|v| v.trim().strip_suffix("kB"))
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|kb| kb.saturating_mul(1024))
    });
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|t| cgroup_limit(&t, std::path::Path::new("/sys/fs/cgroup")));
    match (cgroup, ram) {
        (Some(c), Some(r)) if c < r => Some((c, true)),
        (Some(c), None) => Some((c, true)),
        (_, Some(r)) => Some((r, false)),
        (None, None) => None,
    }
}

/// The lowest memory limit on this process's cgroup path, given `/proc/self/cgroup` text and
/// the cgroup mount root: v2 (`0::/path`, every `memory.max` from the leaf up) or v1 (the
/// `memory` controller's `memory.limit_in_bytes`). `max` and v1's near-`u64::MAX` mean none.
pub fn cgroup_limit(proc_self_cgroup: &str, root: &std::path::Path) -> Option<u64> {
    let read = |p: std::path::PathBuf| -> Option<u64> {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v < (1u64 << 60))
    };
    for line in proc_self_cgroup.lines() {
        let mut parts = line.splitn(3, ':');
        let (_, controllers, path) = (parts.next()?, parts.next()?, parts.next()?);
        let rel = path.trim_start_matches('/');
        if controllers.is_empty() {
            let mut dir = root.join(rel);
            let mut lowest: Option<u64> = None;
            loop {
                if let Some(v) = read(dir.join("memory.max")) {
                    lowest = Some(lowest.map_or(v, |l| l.min(v)));
                }
                if dir == root || !dir.pop() || !dir.starts_with(root) {
                    break;
                }
            }
            if lowest.is_some() {
                return lowest;
            }
        } else if controllers.split(',').any(|c| c == "memory") {
            if let Some(v) = read(root.join("memory").join(rel).join("memory.limit_in_bytes")) {
                return Some(v);
            }
        }
    }
    None
}

/// [`held_shard_bound_at_startup`] without its log line, for a CLI command (its logs go to stdout,
/// where a `--json` document must be alone).
pub fn held_shard_bound_quiet(
    profile: crate::profile::HardwareProfile,
    config_override: Option<u64>,
) -> HeldShardBound {
    let (share, floor, ceiling) = held_shard_profile(profile);
    let mem = read_memory_limit();
    held_shard_bound_from(
        mem.map(|m| m.0),
        mem.is_some_and(|m| m.1),
        share,
        floor,
        ceiling,
        config_override,
    )
}

/// L-130 at startup: the held-shard bound for `profile` from the memory the daemon runs under
/// ([`read_memory_limit`]), an explicit config value winning; logged once with its source
/// (`info.held_shard_bound`).
pub fn held_shard_bound_at_startup(
    profile: crate::profile::HardwareProfile,
    config_override: Option<u64>,
) -> HeldShardBound {
    let b = held_shard_bound_quiet(profile, config_override);
    tracing::info!(
        code = "info.held_shard_bound",
        max_held_shards = b.max,
        source = b.source.as_str(),
        memory_bytes = b.memory_bytes.unwrap_or(0),
        bytes_per_shard = BYTES_PER_HELD_SHARD,
        "held-shard bound"
    );
    b
}

/// B-162: the write-ceiling epoch (24 h). The per-peer ceiling of 4x the allowance resets at
/// the start of each epoch, so it is a daily upload budget, not a lifetime cap.
pub const QUOTA_WRITE_EPOCH_SECS: u64 = 86_400;

const QUOTA_WRITE_EPOCH_MS: u64 = QUOTA_WRITE_EPOCH_SECS * 1000;

/// B-162: the info code logged when a new write-ceiling epoch starts.
pub const INFO_QUOTA_WRITE_EPOCH_ROLLED: &str = "info.quota_write_epoch_rolled";

/// B-162: a new write-ceiling epoch starts once `elapsed_ms` since the current one started
/// reaches `epoch_len_ms`, that is once a whole epoch has elapsed. A zero length (never
/// configured: [`QuotaManager::write_epoch_ms`] maps 0 to the default) always rolls over.
pub const fn epoch_rollover_decision(elapsed_ms: u64, epoch_len_ms: u64) -> bool {
    if epoch_len_ms == 0 {
        return true;
    }
    elapsed_ms / epoch_len_ms >= 1
}

/// B-159 (C16, B154-QUOTA): which account a removal credits and by how much. A shard the
/// ledger recorded credits its recorded owner its recorded size; only an unrecorded shard
/// falls back to the caller's account and the file's length.
pub fn removal_credit(
    recorded_owner: Option<String>,
    recorded_bytes: Option<u64>,
    caller: &str,
    file_bytes: u64,
) -> (String, u64) {
    (
        recorded_owner.unwrap_or_else(|| caller.to_string()),
        recorded_bytes.unwrap_or(file_bytes),
    )
}

/// Loads `quota_state.bin` (B-52 QA): an absent file is a fresh state; any other read or decode
/// failure is refused, since starting empty would forget every peer's used quota.
pub fn quota_state_load_decision(
    read: std::io::Result<Option<Vec<u8>>>,
) -> Result<Option<QuotaManager>, &'static str> {
    match read {
        Ok(None) => Ok(None),
        Ok(Some(raw)) => bincode::deserialize::<QuotaManager>(&raw)
            .map(Some)
            .map_err(|_| "reject.quota_state_corrupt"),
        Err(_) => Err("reject.quota_state_unreadable"),
    }
}

/// B-52: after a failed state write the accounting on disk is behind memory, and a restart would
/// forget the shards since; new shards are refused (by [`QuotaManager::quota_decision`]) until a
/// later write succeeds.
pub fn quota_state_persist_decision<E>(written: &Result<(), E>) -> Result<(), &'static str> {
    match written {
        Ok(()) => Ok(()),
        Err(_) => Err("reject.quota_state_not_persisted"),
    }
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
            lru_queue: LruIndex::default(),
            min_free_disk_bytes: 0,
            observed_free_disk_bytes: None,
            persistence_path: None,
            persist_failed: std::cell::Cell::new(None),
            load_error: None,
            epoch_started: None,
            write_epoch_ms: QUOTA_WRITE_EPOCH_MS,
            held_bound: None,
        }
    }

    /// B-162: sets the write-ceiling epoch length in seconds (0 keeps
    /// [`QUOTA_WRITE_EPOCH_SECS`]). Call before binding persistence; a loaded state keeps it.
    pub fn set_write_epoch_secs(&mut self, epoch_secs: u64) {
        self.write_epoch_ms = epoch_secs.saturating_mul(1000);
    }

    /// L-130: sets the held-shard bound (at startup, from [`held_shard_bound_at_startup`]).
    pub fn set_held_shard_bound(&mut self, bound: HeldShardBound) {
        self.held_bound = Some(bound);
    }

    /// The held-shard bound and the shards held now, for live status (B-148).
    pub fn held_shard_bound(&self) -> Option<(HeldShardBound, u64)> {
        self.held_bound.map(|b| (b, self.shard_sizes.len() as u64))
    }

    /// B-162: the write-ceiling epoch length in ms.
    pub const fn write_epoch_ms(&self) -> u64 {
        if self.write_epoch_ms == 0 {
            QUOTA_WRITE_EPOCH_MS
        } else {
            self.write_epoch_ms
        }
    }

    /// B-162: starts a new write-ceiling epoch when the current one has lasted
    /// [`Self::write_epoch_ms`]: zeroes every peer's epoch ingress counter, restarts the timer at
    /// `now` and persists. The first call starts the timer. Hosted bytes are never changed.
    /// Returns whether a new epoch started.
    pub fn roll_epoch_if_due(&mut self, now: std::time::Instant) -> bool {
        let started = *self.epoch_started.get_or_insert(now);
        let elapsed_ms =
            u64::try_from(now.saturating_duration_since(started).as_millis()).unwrap_or(u64::MAX);
        if !epoch_rollover_decision(elapsed_ms, self.write_epoch_ms()) {
            return false;
        }
        self.reset_epoch_ingress_counters();
        self.epoch_started = Some(now);
        self.persist();
        tracing::info!(
            code = INFO_QUOTA_WRITE_EPOCH_ROLLED,
            epoch_ms = self.write_epoch_ms(),
            "new write-ceiling epoch; per-peer write counters reset"
        );
        true
    }

    /// Loads or binds a persistent `QuotaManager` at `data_dir/quota_state.bin`.
    pub fn with_persistence_dir(
        max_storage_bytes: u64,
        bootstrap_grace_bytes: u64,
        data_dir: &std::path::Path,
    ) -> Self {
        let path = data_dir.join("quota_state.bin");
        let mut q = Self::new(max_storage_bytes, bootstrap_grace_bytes);
        q.load_from(path);
        q
    }

    /// Binds `data_dir/quota_state.bin`. An empty manager loads it; a non-empty one keeps its
    /// accounting and replaces a file that loads, but fails closed like [`Self::load_from`] on a
    /// file that exists and does not load (B-52 QA): that file is kept, never overwritten.
    pub fn bind_persistence_dir(&mut self, data_dir: &std::path::Path) {
        let path = data_dir.join("quota_state.bin");
        if self.used_storage_bytes == 0 && self.peer_accounts.is_empty() {
            self.load_from(path);
        } else {
            if let Err(code) =
                quota_state_load_decision(crate::storage::fsio::read_state_file(&path))
            {
                tracing::warn!(code, path = %path.display(), "quota state not loaded; refusing new shards");
                self.load_error = Some(code);
            }
            self.persistence_path = Some(path);
        }
    }

    /// Binds `path` and loads it, keeping this manager's limits; fails closed on a bad file.
    fn load_from(&mut self, path: std::path::PathBuf) {
        match quota_state_load_decision(crate::storage::fsio::read_state_file(&path)) {
            Ok(Some(mut loaded)) => {
                loaded.max_storage_bytes = self.max_storage_bytes;
                loaded.bootstrap_grace_bytes = self.bootstrap_grace_bytes;
                if self.min_free_disk_bytes > 0 {
                    loaded.min_free_disk_bytes = self.min_free_disk_bytes;
                }
                // B-162: the epoch is RAM only, so a loaded state starts a new one.
                loaded.write_epoch_ms = self.write_epoch_ms;
                loaded.held_bound = self.held_bound;
                loaded.reset_epoch_ingress_counters();
                loaded.epoch_started = Some(std::time::Instant::now());
                *self = loaded;
            }
            Ok(None) => {}
            Err(code) => {
                tracing::warn!(code, path = %path.display(), "quota state not loaded; refusing new shards");
                self.load_error = Some(code);
            }
        }
        self.persistence_path = Some(path);
    }

    fn persist(&self) {
        if self.load_error.is_some() {
            return; // keep the unreadable file for the operator; never replace it with a fresh state
        }
        if let Some(ref path) = self.persistence_path {
            let written = bincode::serialize(self)
                .map_err(|e| e.to_string())
                .and_then(|bytes| {
                    crate::storage::fsio::atomic_write_file(path, &bytes).map_err(|e| e.to_string())
                });
            let refused = quota_state_persist_decision(&written).err();
            if let (Some(code), Err(error)) = (refused, &written) {
                tracing::warn!(
                    code,
                    %error,
                    "quota state write failed; refusing new shards until a write succeeds"
                );
            }
            self.persist_failed.set(refused);
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

    /// B-147 (G5): sets `peer_id`'s audit counters to journalled post-values (only the given
    /// ones; the caller applies each only where it is above the current value) and persists.
    pub fn apply_por_post_values(
        &mut self,
        peer_id: &str,
        por_passes: Option<u64>,
        por_failures: Option<u64>,
    ) {
        let acct = self.peer_accounts.entry(peer_id.to_string()).or_default();
        if let Some(v) = por_passes {
            acct.por_passes = v;
        }
        if let Some(v) = por_failures {
            acct.por_failures = v;
        }
        self.persist();
    }

    /// Checks whether `peer_id` is within both the node's physical disk ceiling and its
    /// tier-weighted reciprocity allowance (`bootstrap_grace_bytes + contributed / factor`).
    pub fn can_accept_shard(&self, peer_id: &str, shard_bytes: u64) -> bool {
        self.quota_decision(peer_id, shard_bytes).is_ok()
    }

    /// ADR-07: a shard is accepted only within the disk reserve and node capacity and, for a
    /// remote peer, within its quota (bootstrap grace plus earned allowance) and its per-epoch
    /// write ceiling (4x the quota, so put/delete loops cannot wear out flash).
    /// Fails closed while the last state write failed (B-52), so no shard is accepted that a
    /// restart would forget.
    pub fn quota_decision(&self, peer_id: &str, shard_bytes: u64) -> Result<(), &'static str> {
        if let Some(code) = self.load_error {
            return Err(code);
        }
        if let Some(code) = self.persist_failed.get() {
            return Err(code);
        }
        // B-152 (a), arch152b 3.4: the held-shard bound, before any capacity or eviction rule.
        if let Some(b) = self.held_bound {
            held_shard_decision(self.shard_sizes.len() as u64, b.max)?;
        }
        if let Some(free_bytes) = self.observed_free_disk_bytes {
            if free_bytes.saturating_sub(shard_bytes) < self.min_free_disk_bytes {
                return Err("reject.disk_reserve");
            }
        }
        if self.used_storage_bytes.saturating_add(shard_bytes) > self.max_storage_bytes {
            return Err("reject.node_capacity");
        }
        if peer_id == "local" || peer_id == "self" {
            return Ok(());
        }
        let acct = self.peer_accounts.get(peer_id).cloned().unwrap_or_default();
        if acct.is_slashed {
            return Err("reject.peer_slashed");
        }
        let factor = acct.required_reciprocity_factor();
        let earned_allowance = (acct.bytes_contributed_by_peer as f64 / factor) as u64;
        let max_allowed_for_peer = self.bootstrap_grace_bytes.saturating_add(earned_allowance);
        if acct.bytes_hosted_for_peer.saturating_add(shard_bytes) > max_allowed_for_peer {
            return Err("reject.peer_quota_exceeded");
        }
        let max_epoch_write_allowance = max_allowed_for_peer.saturating_mul(4);
        if acct.epoch_ingress_bytes_written.saturating_add(shard_bytes) > max_epoch_write_allowance
        {
            return Err("reject.peer_write_amplification");
        }
        Ok(())
    }

    /// Resets per-epoch ingress write counters at the start of a new epoch (B-162: called by
    /// [`Self::roll_epoch_if_due`] and on load).
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

    /// Commits a newly stored shard to in-memory quota accounting and LRU queue without
    /// immediately rewriting `quota_state.bin` (call [`Self::flush_persistence`] after a stripe batch).
    pub fn record_shard_stored_deferred(
        &mut self,
        peer_id: &str,
        shard_key: String,
        shard_bytes: u64,
    ) {
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
    }

    /// Flushes `quota_state.bin` atomically to disk when persistence is bound.
    pub fn flush_persistence(&self) {
        self.persist();
    }

    /// Commits a newly stored shard to quota accounting and pushes it to the back of the LRU queue.
    /// The id the shard `shard_key` is accounted to, if it is stored.
    pub fn shard_owner(&self, shard_key: &str) -> Option<&str> {
        self.shard_owners.get(shard_key).map(String::as_str)
    }

    pub fn record_shard_stored(&mut self, peer_id: &str, shard_key: String, shard_bytes: u64) {
        self.record_shard_stored_deferred(peer_id, shard_key, shard_bytes);
        self.persist();
    }

    /// Updates LRU recency when a shard is read or audited: O(log n) (B-152 (a); was an O(n)
    /// retain over every held shard). Nothing on a file-backed store.
    pub fn touch_shard(&mut self, shard_key: &str) {
        self.lru_queue.touch(shard_key);
    }

    /// B-152 (a): turns the LRU off and frees it. A file-backed store never evicts (B-161), so
    /// it keeps no recency order; `quota_state.bin` then carries an empty queue, which every
    /// earlier release loads.
    pub fn disable_lru(&mut self) {
        self.lru_queue = LruIndex {
            disabled: true,
            ..LruIndex::default()
        };
    }

    /// Shard keys in LRU order, oldest first (tests and the fixture check).
    pub fn lru_order(&self) -> Vec<String> {
        self.lru_queue
            .by_seq
            .values()
            .map(|k| k.to_string())
            .collect()
    }

    /// Regular shards this ledger accounts for (B-152 (a), the held-shard bound).
    pub fn held_shard_count(&self) -> usize {
        self.shard_sizes.len()
    }

    /// Removes a shard from quota accounting (B-159, C16): the bytes recorded for it are
    /// credited back to the account it was stored for (`shard_owners`), as
    /// [`Self::evict_lru_to_fit`] does, never to whoever asked for the removal. `peer_id` and
    /// `shard_bytes` are used only for a shard this ledger never recorded.
    pub fn record_shard_removed(&mut self, peer_id: &str, shard_key: &str, shard_bytes: u64) {
        self.record_shard_removed_deferred(peer_id, shard_key, shard_bytes);
        self.persist();
    }

    /// [`Self::record_shard_removed`] without the state write (call
    /// [`Self::flush_persistence`] after the batch).
    pub fn record_shard_removed_deferred(
        &mut self,
        peer_id: &str,
        shard_key: &str,
        shard_bytes: u64,
    ) {
        let (owner, bytes) = removal_credit(
            self.shard_owners.remove(shard_key),
            self.shard_sizes.remove(shard_key),
            peer_id,
            shard_bytes,
        );
        self.lru_queue.remove(shard_key);
        self.used_storage_bytes = self.used_storage_bytes.saturating_sub(bytes);
        if let Some(acct) = self.peer_accounts.get_mut(&owner) {
            acct.bytes_hosted_for_peer = acct.bytes_hosted_for_peer.saturating_sub(bytes);
        }
    }

    /// Evicts least-recently-used shard keys until at least `needed_bytes` of free space is available.
    pub fn evict_lru_to_fit(&mut self, needed_bytes: u64) -> Vec<String> {
        let mut evicted = Vec::new();
        while self.available_storage_bytes() < needed_bytes {
            let Some(oldest_key) = self.lru_queue.pop_oldest() else {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unloadable_state_file_refuses_new_shards_and_is_kept() {
        // B-52 QA differential: the same shard against a loadable and an unloadable state file.
        let ok_dir = tempfile::tempdir().unwrap();
        let mut seed = QuotaManager::with_persistence_dir(1 << 30, 1 << 20, ok_dir.path());
        seed.record_shard_stored("peer", "a".into(), 1024);
        let ok = QuotaManager::with_persistence_dir(1 << 30, 1 << 20, ok_dir.path());
        assert!(ok.quota_decision("local", 1024).is_ok());
        let mut busy = QuotaManager::new(1 << 30, 1 << 20);
        busy.record_shard_stored("peer", "c".into(), 2048);
        busy.bind_persistence_dir(ok_dir.path());
        assert!(busy.quota_decision("local", 1024).is_ok());
        assert_eq!(
            ok.peer_accounts
                .get("peer")
                .map(|a| a.bytes_hosted_for_peer),
            Some(1024)
        );

        for (bytes, code) in [
            (vec![0xFFu8; 3], "reject.quota_state_corrupt"),
            (Vec::new(), "reject.quota_state_unreadable"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("quota_state.bin");
            if bytes.is_empty() {
                std::fs::create_dir(&path).unwrap(); // exists but cannot be read
            } else {
                std::fs::write(&path, &bytes).unwrap();
            }
            let mut q = QuotaManager::with_persistence_dir(1 << 30, 1 << 20, dir.path());
            assert_eq!(q.quota_decision("local", 1024), Err(code));
            let mut bound = QuotaManager::new(1 << 30, 1 << 20);
            bound.bind_persistence_dir(dir.path());
            assert_eq!(bound.quota_decision("local", 1024), Err(code));
            // A non-empty manager bound to the same file fails closed too, and never writes it.
            let mut busy = QuotaManager::new(1 << 30, 1 << 20);
            busy.record_shard_stored("peer", "c".into(), 2048);
            busy.bind_persistence_dir(dir.path());
            assert_eq!(busy.quota_decision("local", 1024), Err(code));
            busy.record_shard_stored("peer", "d".into(), 2048);
            busy.flush_persistence();
            q.record_shard_stored("local", "b".into(), 1024);
            q.flush_persistence();
            if !bytes.is_empty() {
                assert_eq!(std::fs::read(&path).unwrap(), bytes, "the bad file is kept");
            }
        }
    }

    #[test]
    fn failed_state_write_refuses_new_shards_until_a_write_succeeds() {
        // B-52 differential: same shard, writable then blocked then restored state file.
        let dir = tempfile::tempdir().unwrap();
        let mut q = QuotaManager::with_persistence_dir(1 << 30, 1 << 20, dir.path());
        assert!(q.quota_decision("local", 1024).is_ok());
        let path = dir.path().join("quota_state.bin");
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir(&path).unwrap();
        q.record_shard_stored("local", "a".into(), 1024);
        assert_eq!(
            q.quota_decision("local", 1024),
            Err("reject.quota_state_not_persisted")
        );
        std::fs::remove_dir(&path).unwrap();
        q.flush_persistence();
        assert!(q.quota_decision("local", 1024).is_ok());
        assert!(path.is_file());
    }

    /// B-162: the rollover boundary: not before the epoch length, from it on.
    #[test]
    fn b162_epoch_rollover_boundaries() {
        let len = QUOTA_WRITE_EPOCH_SECS * 1000;
        assert!(!epoch_rollover_decision(0, len));
        assert!(!epoch_rollover_decision(len - 1, len));
        assert!(epoch_rollover_decision(len, len));
        assert!(epoch_rollover_decision(u64::MAX, len));
        assert!(epoch_rollover_decision(u64::MAX, u64::MAX));
        assert!(!epoch_rollover_decision(u64::MAX - 1, u64::MAX));
        let q = QuotaManager::new(1 << 30, 1 << 20);
        assert_eq!(q.write_epoch_ms(), 24 * 60 * 60 * 1000);
        let mut z = QuotaManager::new(1 << 30, 1 << 20);
        z.set_write_epoch_secs(0);
        assert_eq!(z.write_epoch_ms(), QUOTA_WRITE_EPOCH_SECS * 1000);
        z.set_write_epoch_secs(6);
        assert_eq!(z.write_epoch_ms(), 6_000);
    }

    /// Fills `peer`'s write ceiling (4x a 5,000-byte grace) by put-and-delete churn, leaving
    /// it hosting one 1,000-byte shard.
    fn b162_churn_to_ceiling(q: &mut QuotaManager, peer: &str) {
        for i in 0..19 {
            let k = format!("churn-{i}");
            assert!(q.quota_decision(peer, 1_000).is_ok(), "put {i}");
            q.record_shard_stored(peer, k.clone(), 1_000);
            q.record_shard_removed(peer, &k, 1_000);
        }
        q.record_shard_stored(peer, "kept".into(), 1_000);
        assert_eq!(
            q.quota_decision(peer, 1_000),
            Err("reject.peer_write_amplification")
        );
    }

    /// B-162: a peer refused at its write ceiling is accepted after the epoch rolls; the
    /// rollover leaves hosted bytes unchanged and only happens once the epoch has lasted.
    #[test]
    fn b162_refused_peer_accepted_after_rollover() {
        let mut q = QuotaManager::new(1 << 30, 5_000);
        q.set_write_epoch_secs(60);
        let t0 = std::time::Instant::now();
        assert!(!q.roll_epoch_if_due(t0), "the first call starts the epoch");
        b162_churn_to_ceiling(&mut q, "peer-a");
        let hosted = q.peer_account("peer-a").unwrap().bytes_hosted_for_peer;
        assert_eq!(hosted, 1_000);
        let used = q.used_storage_bytes();
        assert!(!q.roll_epoch_if_due(t0 + std::time::Duration::from_millis(59_999)));
        assert_eq!(
            q.quota_decision("peer-a", 1_000),
            Err("reject.peer_write_amplification")
        );
        let t1 = t0 + std::time::Duration::from_millis(60_000);
        assert!(q.roll_epoch_if_due(t1));
        assert!(q.quota_decision("peer-a", 1_000).is_ok());
        let acct = q.peer_account("peer-a").unwrap();
        assert_eq!(acct.bytes_hosted_for_peer, hosted, "hosted bytes unchanged");
        assert_eq!(acct.epoch_ingress_bytes_written, 0);
        assert_eq!(q.used_storage_bytes(), used);
        // The timer restarted at t1: no second rollover before t1 + 60 s.
        assert!(!q.roll_epoch_if_due(t1 + std::time::Duration::from_millis(59_999)));
        assert!(q.roll_epoch_if_due(t1 + std::time::Duration::from_millis(60_000)));
    }

    /// B-162: the rollover is persisted (the zeroed counters reach `quota_state.bin`), and a
    /// restart starts a new epoch with the hosted bytes kept.
    #[test]
    fn b162_rollover_persists_and_restart_starts_new_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = QuotaManager::with_persistence_dir(1 << 30, 5_000, dir.path());
        b162_churn_to_ceiling(&mut q, "peer-a");
        drop(q);
        let mut q = QuotaManager::with_persistence_dir(1 << 30, 5_000, dir.path());
        let acct = q.peer_account("peer-a").unwrap();
        assert_eq!(acct.bytes_hosted_for_peer, 1_000);
        assert_eq!(
            acct.epoch_ingress_bytes_written, 0,
            "a restart opens a new epoch"
        );
        assert!(q.quota_decision("peer-a", 1_000).is_ok());
        b162_churn_to_ceiling(&mut q, "peer-b");
        let later =
            std::time::Instant::now() + std::time::Duration::from_secs(QUOTA_WRITE_EPOCH_SECS);
        assert!(q.roll_epoch_if_due(later));
        let raw = std::fs::read(dir.path().join("quota_state.bin")).unwrap();
        let on_disk: QuotaManager = bincode::deserialize(&raw).unwrap();
        let b = on_disk.peer_account("peer-b").unwrap();
        assert_eq!(b.epoch_ingress_bytes_written, 0);
        assert_eq!(b.bytes_hosted_for_peer, 1_000);
    }

    /// B-162 upgrade: a `quota_state.bin` written by `v0.5.3` (`a92f647`, generated by
    /// `QuotaManager::with_persistence_dir` and `record_shard_*` on that tree) loads with the same
    /// hosted bytes, its epoch counters zeroed, and is written back in the same layout.
    #[test]
    fn b162_v0_5_3_quota_state_loads() {
        const V053: &[u8] = include_bytes!("../../tests/fixtures/quota_state_v0_5_3.bin");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("quota_state.bin"), V053).unwrap();
        let q = QuotaManager::with_persistence_dir(1 << 30, 20_000, dir.path());
        assert!(q.quota_decision("owner-a", 1_000).is_ok());
        assert_eq!(q.used_storage_bytes(), 9_000);
        let a = q.peer_account("owner-a").unwrap();
        assert_eq!(a.bytes_hosted_for_peer, 5_000);
        assert_eq!(a.epoch_ingress_bytes_written, 0);
        let b = q.peer_account("owner-b").unwrap();
        assert_eq!(b.bytes_hosted_for_peer, 4_000);
        assert_eq!(b.epoch_ingress_bytes_written, 0);
        assert_eq!(q.shard_owner(&("aa".repeat(32) + "-0")), Some("owner-a"));
        assert_eq!(q.shard_owner(&("bb".repeat(32) + "-1")), Some("owner-b"));
        // The fixture really holds non-zero counters (5,000 and 5,500), so the zeroing is real.
        let raw: QuotaManager = bincode::deserialize(V053).unwrap();
        assert_eq!(
            raw.peer_account("owner-b")
                .unwrap()
                .epoch_ingress_bytes_written,
            5_500
        );
        // Same layout: re-serialized, the state has the v0.5.3 length.
        assert_eq!(bincode::serialize(&q).unwrap().len(), V053.len());
        q.flush_persistence();
        let back = std::fs::read(dir.path().join("quota_state.bin")).unwrap();
        assert_eq!(back.len(), V053.len());
    }

    /// B-152 (a), arch152 3.1, arch152b 3.2: the `v0.5.3` (`5943dca` layout) fixture loads into
    /// the O(log n) LRU with its queue order unchanged and the same hosted bytes, and writes back
    /// the same bytes; a file-backed store keeps no LRU and still loads it.
    #[test]
    fn b152_lru_keeps_the_persisted_layout_and_order() {
        const V053: &[u8] = include_bytes!("../../tests/fixtures/quota_state_v0_5_3.bin");
        #[derive(serde::Deserialize)]
        struct Old {
            _max: u64,
            _used: u64,
            _grace: u64,
            _accounts: HashMap<String, PeerCreditAccount>,
            _sizes: HashMap<String, u64>,
            _owners: HashMap<String, String>,
            lru_queue: std::collections::VecDeque<String>,
            _min_free: u64,
            _observed: Option<u64>,
        }
        let old: Old = bincode::deserialize(V053).unwrap();
        assert!(!old.lru_queue.is_empty());
        let q: QuotaManager = bincode::deserialize(V053).unwrap();
        assert_eq!(q.lru_order(), Vec::from(old.lru_queue.clone()));
        // Same layout (the maps' order varies by process, so the length is compared).
        assert_eq!(bincode::serialize(&q).unwrap().len(), V053.len());

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("quota_state.bin"), V053).unwrap();
        let store = crate::storage::BlockStore::new(dir.path(), QuotaManager::new(1 << 30, 20_000))
            .unwrap();
        let q = store.quota();
        let q = q.lock().unwrap();
        assert_eq!(
            q.peer_account("owner-a").unwrap().bytes_hosted_for_peer,
            5_000
        );
        assert_eq!(
            q.peer_account("owner-b").unwrap().bytes_hosted_for_peer,
            4_000
        );
        assert!(q.lru_order().is_empty(), "a file-backed store keeps no LRU");
    }

    /// B-152 (a): the in-memory LRU evicts oldest first, a touch moves a key to the back, a
    /// removal leaves no entry; 100,000 touches over 100,000 keys stay well under a second.
    #[test]
    fn b152_lru_order_and_touch_cost() {
        let mut q = QuotaManager::new(10_000, 1 << 20);
        for k in ["a", "b", "c", "d"] {
            q.record_shard_stored("p", k.into(), 2_000);
        }
        q.touch_shard("a");
        q.record_shard_removed("p", "c", 2_000);
        assert_eq!(q.lru_order(), vec!["b", "d", "a"]);
        assert_eq!(q.evict_lru_to_fit(5_000), vec!["b"]);
        assert_eq!(q.lru_order(), vec!["d", "a"]);

        let mut big = QuotaManager::new(u64::MAX, u64::MAX);
        for i in 0..100_000u32 {
            big.record_shard_stored_deferred("p", format!("k{i}"), 1);
        }
        let t = std::time::Instant::now();
        for i in 0..100_000u32 {
            big.touch_shard(&format!("k{}", (i * 7_919) % 100_000));
        }
        let took = t.elapsed();
        eprintln!("touch_shard x100000 at 100000 keys: {took:?}");
        assert!(took < std::time::Duration::from_secs(2), "{took:?}");
        assert_eq!(big.lru_order().len(), 100_000);
    }

    #[test]
    fn b152_held_shard_bound_derivation() {
        use crate::profile::HardwareProfile::*;
        const MIB: u64 = 1 << 20;
        let nas = held_shard_profile(HomelabNas);
        let at = |mem: u64| held_shard_bound_from(Some(mem), true, nas.0, nas.1, nas.2, None);
        // L-130 test: 64 MiB and 256 MiB derive bounds in that ratio.
        let (b64, b256) = (at(64 * MIB), at(256 * MIB));
        assert_eq!(b64.source, HeldShardBoundSource::Cgroup);
        assert_eq!(b64.max, 64 * MIB / 100 * 25 / BYTES_PER_HELD_SHARD);
        assert!(b256.max.abs_diff(4 * b64.max) <= 4, "{b64:?} {b256:?}");
        // Clamped to the floor and the ceiling; an override wins; no figure: the ceiling.
        assert_eq!(at(MIB).max, nas.1);
        assert_eq!(at(1 << 50).max, nas.2);
        let o = held_shard_bound_from(Some(64 * MIB), true, nas.0, nas.1, nas.2, Some(3));
        assert_eq!((o.max, o.source), (3, HeldShardBoundSource::Config));
        let none = held_shard_bound_from(None, false, nas.0, nas.1, nas.2, None);
        assert_eq!(
            (none.max, none.source),
            (nas.2, HeldShardBoundSource::ProfileCeiling)
        );
        let ram = held_shard_bound_from(Some(256 * MIB), false, nas.0, nas.1, nas.2, None);
        assert_eq!(ram.source, HeldShardBoundSource::PhysicalRam);
        for p in [RouterSoc, HomelabNas, Desktop] {
            let (share, floor, ceiling) = held_shard_profile(p);
            assert!(share > 0 && floor <= ceiling);
        }
    }

    /// L-130: the cgroup limit is the lowest `memory.max` on the process's v2 path (a parent's
    /// limit applies to a child), `max` is none; v1 reads the memory controller.
    #[test]
    fn b152_cgroup_limit_reads_the_path_the_process_runs_under() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        std::fs::create_dir_all(r.join("a/b/c")).unwrap();
        std::fs::write(r.join("a/memory.max"), "268435456\n").unwrap();
        std::fs::write(r.join("a/b/memory.max"), "max\n").unwrap();
        std::fs::write(r.join("a/b/c/memory.max"), "67108864\n").unwrap();
        assert_eq!(cgroup_limit("0::/a/b/c\n", r), Some(64 << 20));
        assert_eq!(cgroup_limit("0::/a/b\n", r), Some(256 << 20));
        assert_eq!(cgroup_limit("0::/\n", r), None);
        std::fs::create_dir_all(r.join("memory/svc")).unwrap();
        std::fs::write(r.join("memory/svc/memory.limit_in_bytes"), "134217728").unwrap();
        assert_eq!(
            cgroup_limit("4:cpu:/x\n3:memory:/svc\n", r),
            Some(128 << 20)
        );
        std::fs::write(
            r.join("memory/svc/memory.limit_in_bytes"),
            "9223372036854771712",
        )
        .unwrap();
        assert_eq!(cgroup_limit("3:memory:/svc\n", r), None);
    }

    /// arch152b 3.4: the bound refuses a new shard at the count, in `quota_decision`.
    #[test]
    fn b152_held_shard_bound_refuses_at_the_count() {
        let mut q = QuotaManager::new(1 << 30, 1 << 30);
        q.set_held_shard_bound(HeldShardBound {
            max: 2,
            source: HeldShardBoundSource::Config,
            memory_bytes: None,
        });
        q.record_shard_stored("p", "a".into(), 1);
        assert!(q.quota_decision("p", 1).is_ok());
        q.record_shard_stored("p", "b".into(), 1);
        assert_eq!(q.quota_decision("p", 1), Err("reject.node_shard_count"));
        q.record_shard_removed("p", "a", 1);
        assert!(q.quota_decision("p", 1).is_ok());
        assert_eq!(held_shard_decision(2, 2), Err("reject.node_shard_count"));
    }
}
