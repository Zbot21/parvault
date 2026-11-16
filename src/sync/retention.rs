//! Retention of folder versions (B-154 C25-C30, L-119 as amended, L-122): keep 3 recent plus 3
//! daily by default; client ceilings 50, 90 and 52 are refused, not clamped; an optional
//! per-folder cap on stored bytes drops the oldest retained versions first, never the newest; a
//! warning when expected stored bytes exceed 1.25x what the policy can hold (C43, C44).
//!
//! Also the version store (C1): one tagged file per retained version next to `snapshot_out`.
//! `snapshot_out` itself keeps the untagged `v0.5.5` layout, so older binaries still read it.
//!
//! Everything that decides is a pure function over small inputs (Kani: `kani_proofs::gc_owner`).

use super::engine::FolderSnapshotManifest;
use crate::storage::{BlockStore, StorageError};
use std::fmt;
use std::path::{Path, PathBuf};

/// Default recent versions kept (L-119 amended).
pub const KEEP_LAST_DEFAULT: u32 = 3;
/// Default daily versions kept (L-119 amended).
pub const KEEP_DAILY_DEFAULT: u32 = 3;
/// Default weekly versions kept.
pub const KEEP_WEEKLY_DEFAULT: u32 = 0;
/// Client ceilings (L-119 owner addition 2): refused above, never clamped.
pub const KEEP_LAST_CEILING: u32 = 50;
pub const KEEP_DAILY_CEILING: u32 = 90;
pub const KEEP_WEEKLY_CEILING: u32 = 52;
/// The shortest `watch-folder` interval (C37; at or below T1's 2 s).
pub const MIN_WATCH_INTERVAL_SECS: u64 = 2;

pub const DAY_MS: u64 = 86_400_000;
/// Weekly buckets are fixed 7-day windows from the Unix epoch (C28).
pub const WEEK_MS: u64 = 7 * DAY_MS;
/// A wall clock below this (2026-11-01 UTC, before this build) is implausible (B-154 2.1).
pub const CLOCK_FLOOR_UNIX_MS: u64 = 1_793_491_200_000;
/// Folders smaller than this warn as if they were this size (tiny folders never warn).
pub const WARN_FOLDER_FLOOR_BYTES: u64 = 1024 * 1024;

/// A folder's retention policy (L-119 tunables), already checked against the ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub keep_last: u32,
    pub keep_daily: u32,
    pub keep_weekly: u32,
    /// Cap on unique stored (pre-erasure) bytes over the retained versions.
    pub max_stored_bytes: Option<u64>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            keep_last: KEEP_LAST_DEFAULT,
            keep_daily: KEEP_DAILY_DEFAULT,
            keep_weekly: KEEP_WEEKLY_DEFAULT,
            max_stored_bytes: None,
        }
    }
}

/// Why a policy was refused; `code` is set by [`retention_policy_decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionRefusal {
    /// `--keep-last 0`: the newest version would have no floor.
    KeepLastZero { code: &'static str },
    /// A field above its client ceiling.
    AboveCeiling {
        code: &'static str,
        field: &'static str,
        value: u32,
        ceiling: u32,
    },
}

impl RetentionRefusal {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::KeepLastZero { code } | Self::AboveCeiling { code, .. } => code,
        }
    }
}

impl fmt::Display for RetentionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeepLastZero { .. } => write!(
                f,
                "{}: --keep-last must be at least 1 (the newest version is always kept)",
                self.code()
            ),
            Self::AboveCeiling {
                field,
                value,
                ceiling,
                ..
            } => write!(
                f,
                "{}: --{field} {value} is above the limit of {ceiling}; old versions use space on other members' disks",
                self.code()
            ),
        }
    }
}

impl std::error::Error for RetentionRefusal {}

/// B154-CEIL (L-119 owner addition 2): the policy, or the refusal of its first out-of-range
/// field: refused, never clamped.
pub const fn retention_policy_decision(
    keep_last: u32,
    keep_daily: u32,
    keep_weekly: u32,
    max_stored_bytes: Option<u64>,
) -> Result<RetentionPolicy, RetentionRefusal> {
    const CEIL: &str = "reject.retention_above_ceiling";
    if keep_last == 0 {
        return Err(RetentionRefusal::KeepLastZero {
            code: "reject.retention_keep_last_zero",
        });
    }
    if keep_last > KEEP_LAST_CEILING {
        return Err(RetentionRefusal::AboveCeiling {
            code: CEIL,
            field: "keep-last",
            value: keep_last,
            ceiling: KEEP_LAST_CEILING,
        });
    }
    if keep_daily > KEEP_DAILY_CEILING {
        return Err(RetentionRefusal::AboveCeiling {
            code: CEIL,
            field: "keep-daily",
            value: keep_daily,
            ceiling: KEEP_DAILY_CEILING,
        });
    }
    if keep_weekly > KEEP_WEEKLY_CEILING {
        return Err(RetentionRefusal::AboveCeiling {
            code: CEIL,
            field: "keep-weekly",
            value: keep_weekly,
            ceiling: KEEP_WEEKLY_CEILING,
        });
    }
    Ok(RetentionPolicy {
        keep_last,
        keep_daily,
        keep_weekly,
        max_stored_bytes,
    })
}

impl RetentionPolicy {
    /// [`retention_policy_decision`].
    pub const fn checked(
        keep_last: u32,
        keep_daily: u32,
        keep_weekly: u32,
        max_stored_bytes: Option<u64>,
    ) -> Result<Self, RetentionRefusal> {
        retention_policy_decision(keep_last, keep_daily, keep_weekly, max_stored_bytes)
    }

    /// The most versions this policy can retain at once (L-122 `retained_versions_max`).
    pub const fn retained_versions_max(&self) -> u64 {
        self.keep_last as u64 + self.keep_daily as u64 + self.keep_weekly as u64
    }
}

/// One retained version, as retention sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMeta {
    pub version: u64,
    pub created_unix_ms: u64,
}

/// Whether the wall clock can be trusted for time-based retention: not below the build floor
/// and not earlier than the newest version (B-154 2.1).
pub const fn clock_plausible(now_ms: u64, newest_created_ms: u64) -> bool {
    now_ms >= CLOCK_FLOOR_UNIX_MS && now_ms >= newest_created_ms
}

/// What retention knows about one version (C20: a per-version predicate over ranks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RankFacts {
    /// Versions newer than this one (0: the newest).
    pub rank: u64,
    /// The newest version of its UTC day.
    pub day_rep: bool,
    /// Whole days between its day and today (time-based; meaningful only on a plausible clock).
    pub days_ago: u64,
    /// The newest version of its 7-day window.
    pub week_rep: bool,
    pub weeks_ago: u64,
}

/// Keep one version (before any cap)?
/// - the newest, and the last `keep_last`, always (a clock jump never goes below them);
/// - the newest of each of the last `keep_daily` days and `keep_weekly` weeks;
/// - on an implausible clock, window expiry is suspended: a day or week representative is kept
///   whatever its age, so nothing is dropped on time grounds.
pub const fn keep_by_rank(facts: RankFacts, policy: &RetentionPolicy, plausible: bool) -> bool {
    if facts.rank == 0 || facts.rank < policy.keep_last as u64 {
        return true;
    }
    let daily = policy.keep_daily > 0
        && facts.day_rep
        && (!plausible || facts.days_ago < policy.keep_daily as u64);
    let weekly = policy.keep_weekly > 0
        && facts.week_rep
        && (!plausible || facts.weeks_ago < policy.keep_weekly as u64);
    daily || weekly
}

/// The rank facts of `versions[i]` at `now_ms`. Versions are distinct by `version`, in any
/// order; the representative of a bucket is its highest version.
pub fn rank_facts(versions: &[VersionMeta], i: usize, now_ms: u64) -> RankFacts {
    let me = versions[i];
    let my_day = me.created_unix_ms / DAY_MS;
    let my_week = me.created_unix_ms / WEEK_MS;
    let mut rank = 0u64;
    let mut day_rep = true;
    let mut week_rep = true;
    for other in versions {
        if other.version > me.version {
            rank += 1;
            if other.created_unix_ms / DAY_MS == my_day {
                day_rep = false;
            }
            if other.created_unix_ms / WEEK_MS == my_week {
                week_rep = false;
            }
        }
    }
    RankFacts {
        rank,
        day_rep,
        days_ago: (now_ms / DAY_MS).saturating_sub(my_day),
        week_rep,
        weeks_ago: (now_ms / WEEK_MS).saturating_sub(my_week),
    }
}

/// B154-RETAIN: which versions the policy keeps at `now_ms`, before the cap. `keep[i]` is for
/// `versions[i]`; `keep` must be as long as `versions`. The newest is always kept, at least
/// `min(keep_last, count)` are kept, keeping is monotone in each policy field, and an
/// implausible clock (below the floor, or behind any retained version's creation time) drops
/// nothing on time grounds (C25, C28). Returns whether the clock was plausible.
pub fn retention_decision(
    versions: &[VersionMeta],
    policy: &RetentionPolicy,
    now_ms: u64,
    keep: &mut [bool],
) -> bool {
    let mut latest_created = 0u64;
    for v in versions {
        if v.created_unix_ms > latest_created {
            latest_created = v.created_unix_ms;
        }
    }
    let plausible = clock_plausible(now_ms, latest_created);
    for (i, k) in keep.iter_mut().enumerate().take(versions.len()) {
        *k = keep_by_rank(rank_facts(versions, i, now_ms), policy, plausible);
    }
    #[cfg(not(kani))]
    if !plausible {
        tracing::warn!(
            code = "warn.retention_clock_implausible",
            now_ms,
            latest_created,
            "the clock is below the build floor or behind a retained version: no version is dropped for its age"
        );
    }
    plausible
}

/// What the cap did (C25, C26).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapOutcome {
    /// Versions the cap dropped.
    pub dropped: usize,
    /// Only the newest is left and it alone is above the cap (`warn.folder_cap_below_one_version`).
    pub below_one_version: bool,
}

/// The stored-bytes cap (C26): while the kept versions' unique stored bytes (`bytes_of(keep)`)
/// are above `cap`, drop the oldest kept version, never the newest. Never blocks a backup.
pub fn apply_cap(
    versions: &[VersionMeta],
    keep: &mut [bool],
    cap: Option<u64>,
    mut bytes_of: impl FnMut(&[bool]) -> u64,
) -> CapOutcome {
    let mut out = CapOutcome::default();
    let Some(cap) = cap else {
        return out;
    };
    let newest = versions
        .iter()
        .enumerate()
        .max_by_key(|(_, v)| v.version)
        .map(|(i, _)| i);
    loop {
        if bytes_of(keep) <= cap {
            return out;
        }
        let oldest = (0..versions.len())
            .filter(|&i| keep[i] && Some(i) != newest)
            .min_by_key(|&i| versions[i].version);
        match oldest {
            Some(i) => {
                keep[i] = false;
                out.dropped += 1;
            }
            None => {
                out.below_one_version = true;
                return out;
            }
        }
    }
}

/// B154-WARN (L-122): warn when the expected stored bytes exceed 1.25x what the policy can
/// legitimately hold.
pub const fn storage_warning_decision(
    expected_stored_bytes: u64,
    policy_max_bytes: u64,
) -> Option<&'static str> {
    if (expected_stored_bytes as u128) * 4 > (policy_max_bytes as u128) * 5 {
        Some("warn.folder_storage_ratio")
    } else {
        None
    }
}

/// C37: the shortest `watch-folder` interval, refused (not clamped) below the floor; `--once`
/// has no interval.
pub const fn watch_interval_decision(interval_secs: u64, once: bool) -> Result<(), &'static str> {
    if once || interval_secs >= MIN_WATCH_INTERVAL_SECS {
        Ok(())
    } else {
        Err("reject.interval_below_floor")
    }
}

/// `restore-folder --version N` (T5): only a retained version can be restored.
pub fn version_restore_decision(
    retained: &[VersionMeta],
    version: u64,
) -> Result<(), &'static str> {
    if retained.iter().any(|m| m.version == version) {
        Ok(())
    } else {
        Err("reject.version_not_retained")
    }
}

/// What the policy can legitimately hold on the ring (L-122):
/// `retained_versions_max x folder_size x tier_expansion x replica_factor`, with the folder size
/// floored at [`WARN_FOLDER_FLOOR_BYTES`] and, with a cap, the pre-erasure part at most the cap.
pub fn policy_max_bytes(
    policy: &RetentionPolicy,
    folder_size_bytes: u64,
    k_data: u64,
    n_total: u64,
    replica_factor: u64,
) -> u64 {
    let folder = folder_size_bytes.max(WARN_FOLDER_FLOOR_BYTES) as u128;
    let mut pre = policy.retained_versions_max() as u128 * folder;
    if let Some(cap) = policy.max_stored_bytes {
        pre = pre.min((cap as u128).max(folder));
    }
    let v = pre * n_total.max(1) as u128 * replica_factor.max(1) as u128 / k_data.max(1) as u128;
    v.min(u64::MAX as u128) as u64
}

/// The replica factor of a stripe of `n_total` shards on a ring of `hosts` (B-149 replica shift).
pub const fn replica_factor(n_total: u64, hosts: u64) -> u64 {
    if hosts == 0 || hosts >= n_total {
        1
    } else {
        n_total.div_ceil(hosts)
    }
}

// --- The version store (C1, C30) -------------------------------------------------------------

/// The tag of a version file.
pub const VERSION_FILE_MAGIC: &[u8; 8] = b"PVVERS01";
/// The layout of the header after the magic.
pub const VERSION_FILE_LAYOUT: u32 = 1;
const HEADER_LEN: usize = 8 + 4 + 8 + 8;

/// The retained versions of one folder: `<snapshot_out>.versions/v<NNNNNNNN>.snap`, each a
/// tagged header (magic, layout, version, creation time) and the snapshot's bincode bytes.
#[derive(Debug, Clone)]
pub struct VersionStore {
    dir: PathBuf,
}

/// Why a version file could not be used.
#[derive(Debug)]
pub enum VersionFileError {
    Io(std::io::Error),
    /// Not a version file, a newer layout, or a header that disagrees with its body.
    Format(String),
    Decode(StorageError),
}

impl fmt::Display for VersionFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "version file: {e}"),
            Self::Format(s) => write!(f, "reject.version_file_format: {s}"),
            Self::Decode(e) => write!(f, "version file snapshot: {e}"),
        }
    }
}

impl std::error::Error for VersionFileError {}

impl From<std::io::Error> for VersionFileError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<StorageError> for VersionFileError {
    fn from(e: StorageError) -> Self {
        Self::Decode(e)
    }
}

impl VersionStore {
    /// The store of the folder whose latest snapshot is `snapshot_out`.
    pub fn for_snapshot(snapshot_out: &Path) -> Self {
        let mut name = snapshot_out.as_os_str().to_owned();
        name.push(".versions");
        Self {
            dir: PathBuf::from(name),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path_of(&self, version: u64) -> PathBuf {
        self.dir.join(format!("v{version:08}.snap"))
    }

    /// The file's bytes: header then the snapshot's bincode.
    pub fn encode(snapshot: &FolderSnapshotManifest, created_unix_ms: u64) -> Vec<u8> {
        let body = bincode::serialize(snapshot).unwrap_or_default();
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(VERSION_FILE_MAGIC);
        out.extend_from_slice(&VERSION_FILE_LAYOUT.to_be_bytes());
        out.extend_from_slice(&snapshot.version.to_be_bytes());
        out.extend_from_slice(&created_unix_ms.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn parse_header(raw: &[u8]) -> Result<VersionMeta, VersionFileError> {
        if raw.len() < HEADER_LEN || &raw[..8] != VERSION_FILE_MAGIC {
            return Err(VersionFileError::Format("no version-file tag".into()));
        }
        let layout = u32::from_be_bytes(raw[8..12].try_into().expect("4 bytes"));
        if layout != VERSION_FILE_LAYOUT {
            return Err(VersionFileError::Format(format!(
                "layout {layout} (this build reads {VERSION_FILE_LAYOUT})"
            )));
        }
        Ok(VersionMeta {
            version: u64::from_be_bytes(raw[12..20].try_into().expect("8 bytes")),
            created_unix_ms: u64::from_be_bytes(raw[20..28].try_into().expect("8 bytes")),
        })
    }

    /// Decodes a version file; the header must name the body's version.
    pub fn decode(raw: &[u8]) -> Result<(VersionMeta, FolderSnapshotManifest), VersionFileError> {
        let meta = Self::parse_header(raw)?;
        let snap = FolderSnapshotManifest::decode_bytes(&raw[HEADER_LEN..])
            .map_err(VersionFileError::Decode)?;
        if snap.version != meta.version {
            return Err(VersionFileError::Format(format!(
                "header says version {}, body is version {}",
                meta.version, snap.version
            )));
        }
        Ok((meta, snap))
    }

    /// Writes one version atomically (fsync, then rename). Returns the file's size.
    pub fn write(
        &self,
        snapshot: &FolderSnapshotManifest,
        created_unix_ms: u64,
    ) -> Result<u64, VersionFileError> {
        std::fs::create_dir_all(&self.dir)?;
        let bytes = Self::encode(snapshot, created_unix_ms);
        BlockStore::atomic_write_file(&self.path_of(snapshot.version), &bytes)?;
        Ok(bytes.len() as u64)
    }

    /// Every version file's header, oldest first. A file that is not a version file is an error,
    /// so a damaged store is never read as "fewer versions".
    pub fn list(&self) -> Result<Vec<VersionMeta>, VersionFileError> {
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for ent in rd {
            let ent = ent?;
            let name = ent.file_name();
            let name = name.to_string_lossy();
            let Some(num) = name.strip_prefix('v').and_then(|s| s.strip_suffix(".snap")) else {
                continue; // atomic-write temporaries and anything else that is not ours
            };
            let Ok(num) = num.parse::<u64>() else {
                continue;
            };
            use std::io::Read;
            let mut head = [0u8; HEADER_LEN];
            let mut f = std::fs::File::open(ent.path())?;
            f.read_exact(&mut head).map_err(|_| {
                VersionFileError::Format(format!("{name}: shorter than its header"))
            })?;
            let meta = Self::parse_header(&head)?;
            if meta.version != num {
                return Err(VersionFileError::Format(format!(
                    "{name}: header says version {}",
                    meta.version
                )));
            }
            out.push(meta);
        }
        out.sort_by_key(|m| m.version);
        Ok(out)
    }

    pub fn load(&self, version: u64) -> Result<FolderSnapshotManifest, VersionFileError> {
        let raw = std::fs::read(self.path_of(version))?;
        Ok(Self::decode(&raw)?.1)
    }

    /// Removes one version file; a missing one is not an error (idempotent GC step 4).
    pub fn remove(&self, version: u64) -> std::io::Result<()> {
        match std::fs::remove_file(self.path_of(version)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// The store's bytes on this disk (C30).
    pub fn local_bytes(&self) -> u64 {
        std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.metadata().ok())
                    .filter(|m| m.is_file())
                    .map(|m| m.len())
                    .sum()
            })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = CLOCK_FLOOR_UNIX_MS + 100 * DAY_MS + 12 * 3_600_000;

    fn mask(versions: &[VersionMeta], p: &RetentionPolicy, now: u64) -> Vec<bool> {
        let mut k = vec![false; versions.len()];
        let _ = retention_decision(versions, p, now, &mut k);
        k
    }

    fn hourly(count: u64, start: u64) -> Vec<VersionMeta> {
        (1..=count)
            .map(|v| VersionMeta {
                version: v,
                created_unix_ms: start + v * 3_600_000,
            })
            .collect()
    }

    #[test]
    fn ceilings_are_refused_not_clamped() {
        assert!(RetentionPolicy::checked(50, 90, 52, None).is_ok());
        assert_eq!(
            RetentionPolicy::checked(0, 3, 0, None).unwrap_err().code(),
            "reject.retention_keep_last_zero"
        );
        for (l, d, w) in [(51, 0, 0), (3, 91, 0), (3, 3, 53)] {
            let e = RetentionPolicy::checked(l, d, w, None).unwrap_err();
            assert_eq!(e.code(), "reject.retention_above_ceiling");
            assert!(e.to_string().contains("above the limit"));
        }
        assert_eq!(RetentionPolicy::default().retained_versions_max(), 6);
    }

    #[test]
    fn default_keeps_three_recent_and_three_daily() {
        // 5 days of hourly versions ending now.
        let vs = hourly(120, NOW - 120 * 3_600_000);
        let k = mask(&vs, &RetentionPolicy::default(), NOW);
        let kept: Vec<u64> = vs
            .iter()
            .zip(&k)
            .filter(|(_, k)| **k)
            .map(|(v, _)| v.version)
            .collect();
        // The last 3, plus the newest of today (already in the last 3), yesterday and the day
        // before.
        assert!(kept.contains(&120) && kept.contains(&119) && kept.contains(&118));
        assert!(kept.len() <= 6 && kept.len() >= 5, "{kept:?}");
    }

    #[test]
    fn clock_jump_never_drops_below_last_n_and_backwards_suspends_expiry() {
        let vs = hourly(10, NOW - 30 * DAY_MS);
        let p = RetentionPolicy::default();
        // Far-future clock: dailies expire, the last 3 stay.
        let k = mask(&vs, &p, NOW + 1000 * DAY_MS);
        assert!(k[7] && k[8] && k[9]);
        // Clock below the floor: implausible, window expiry suspended (the day representative
        // of that old day is kept).
        let k_bad = mask(&vs, &p, 5);
        let k_bad2 = mask(&vs, &p, 6 * DAY_MS);
        assert_eq!(
            k_bad, k_bad2,
            "an implausible clock does not move retention"
        );
        assert!(k_bad[9] && k_bad[8] && k_bad[7]);
        for i in 0..vs.len() {
            assert!(!k[i] || k_bad[i]);
        }
    }

    #[test]
    fn cap_drops_oldest_never_newest() {
        let vs = hourly(5, NOW - DAY_MS);
        let p = RetentionPolicy::checked(5, 0, 0, Some(250)).unwrap();
        let mut k = mask(&vs, &p, NOW);
        assert!(k.iter().all(|x| *x));
        let out = apply_cap(&vs, &mut k, p.max_stored_bytes, |m| {
            m.iter().filter(|x| **x).count() as u64 * 100
        });
        assert_eq!(k, vec![false, false, false, true, true]);
        assert_eq!(out.dropped, 3);
        assert!(!out.below_one_version);
        let mut k = vec![true; 5];
        let out = apply_cap(&vs, &mut k, Some(10), |m| {
            m.iter().filter(|x| **x).count() as u64 * 100
        });
        assert_eq!(k, vec![false, false, false, false, true]);
        assert!(out.below_one_version);
    }

    #[test]
    fn warning_is_policy_relative() {
        let p = RetentionPolicy::default(); // 6 versions max
        let max = policy_max_bytes(&p, 10 << 20, 16, 20, 1);
        assert_eq!(max, 6 * (10u64 << 20) * 20 / 16);
        assert!(storage_warning_decision(max, max).is_none());
        assert!(storage_warning_decision(max * 5 / 4, max).is_none());
        assert!(storage_warning_decision(max * 5 / 4 + 1, max).is_some());
        assert!(watch_interval_decision(1, false).is_err());
        assert!(watch_interval_decision(1, true).is_ok());
        assert!(watch_interval_decision(2, false).is_ok());
        // A tiny folder is floored at 1 MiB.
        assert_eq!(
            policy_max_bytes(&p, 10, 16, 20, 1),
            policy_max_bytes(&p, WARN_FOLDER_FLOOR_BYTES, 16, 20, 1)
        );
        assert_eq!(replica_factor(20, 3), 7);
        assert_eq!(replica_factor(20, 25), 1);
    }

    #[test]
    fn version_file_roundtrip_and_tag() {
        let tmp = tempfile::tempdir().unwrap();
        let store = VersionStore::for_snapshot(&tmp.path().join("s.manifest.bin"));
        assert!(store.list().unwrap().is_empty());
        let snap = FolderSnapshotManifest {
            version: 7,
            folder_merkle_root: [1; 32],
            tier: crate::config::ErasureTier::Homelab,
            files: Default::default(),
            signed_dht_envelope: None,
            deleted_tombstones: Default::default(),
        };
        store.write(&snap, 1234).unwrap();
        assert_eq!(
            store.list().unwrap(),
            vec![VersionMeta {
                version: 7,
                created_unix_ms: 1234
            }]
        );
        assert_eq!(store.load(7).unwrap().version, 7);
        assert!(store.local_bytes() > 0);
        // A bare snapshot is not a version file.
        std::fs::write(store.path_of(8), bincode::serialize(&snap).unwrap()).unwrap();
        assert!(matches!(store.list(), Err(VersionFileError::Format(_))));
        std::fs::remove_file(store.path_of(8)).unwrap();
        // A newer layout is refused, never read as empty.
        let mut raw = VersionStore::encode(&snap, 1);
        raw[11] = 2;
        assert!(matches!(
            VersionStore::decode(&raw),
            Err(VersionFileError::Format(_))
        ));
        store.remove(7).unwrap();
        store.remove(7).unwrap();
    }
}
