//! The owner's version GC (B-154 2.2-2.4; C2-C8, C10, C11 signing half, C12 retries, C27, C35):
//! mark and sweep over the retained versions, the crash-safe free journal, and the owner-signed
//! `FreeShards` orders.
//!
//! One GC epoch, in order (B-154 2.3):
//! 1. write the pass's version file (the snapshot itself is written by the caller);
//! 2. retention, the two mark sets (C2: stripes and file roots), the garbage;
//! 3. append the garbage to the journal (atomic, fsync) and clear the in-flight log (C3);
//! 4. delete the dropped version files and the garbage's manifests;
//! 5. free local shards;
//! 6. send `FreeShards` orders; an entry leaves the journal on `freed` or `not_held` only.
//!
//! A crash anywhere is recovered by the next run: before step 3 nothing was freed and the
//! dropped version files still exist; after it the journal drives the rest, and every step is
//! idempotent. An entry whose stripe is marked again is dropped, never freed.
//!
//! Formal model: `specs/ParVaultVersionGC.tla` (guards `mark-includes-pass`, `catalog-pin`).

use super::engine::FolderSnapshotManifest;
use super::retention::{self, RetentionPolicy, VersionMeta, VersionStore, DAY_MS};
use crate::crypto::NodeIdentity;
use crate::network::behaviour::{FreeShardOutcome, MAX_FREE_ORDER_SHARDS};
use crate::network::client::{FreeShardsReply, PrePlaceHook};
use crate::network::MeshClient;
use crate::sharding::merkle::Hash32;
use crate::storage::{BlockStore, ShardId, StorageError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// After this long without a `freed` or `not_held`, an entry moves to the abandoned list (C5).
pub const ABANDON_AFTER_MS: u64 = 30 * DAY_MS;
/// Abandoned entries kept per host (C5: bounded); the rest are counted as bytes only.
pub const MAX_ABANDONED_PER_HOST: usize = 4096;
/// The longest backoff between retries, in passes (B-154 2.4).
pub const MAX_BACKOFF_PASSES: u64 = 60;
/// How long one `FreeShards` order may take (up to 1024 shards purged on the host).
pub const FREE_ORDER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// D12: the most one pass spends sending one host its frees; the rest of that host's work is
/// carried to the next pass, so a stalled host costs the others at most this (plus the order
/// in flight, [`FREE_ORDER_TIMEOUT`]).
pub const FREE_HOST_BUDGET_MS: u64 = 60_000;
/// D12: the most one pass spends on frees in all; hosts not reached in it are carried.
pub const FREE_PASS_BUDGET_MS: u64 = 300_000;
// One order in flight fits in a host's budget, and two stalled hosts leave the pass budget.
const _: () = assert!(
    FREE_ORDER_TIMEOUT.as_millis() < FREE_HOST_BUDGET_MS as u128
        && 2 * FREE_HOST_BUDGET_MS < FREE_PASS_BUDGET_MS
);
/// The retry reason of a host that did not answer.
const UNREACHABLE: &str = "unreachable";
/// The pseudo-host of the owner's own block store.
pub const LOCAL_HOST: &str = "local";

// --- Pure decisions (Kani: `kani_proofs::gc_owner`) ------------------------------------------

/// B154-MARK: free a stripe only if no retained version or the pass marks it, it is not in the
/// last acknowledged catalog (C6), and this vault's own version store produced it.
pub fn gc_free_decision(marked: bool, in_published_catalog: bool, produced_here: bool) -> bool {
    let free = !marked && !in_published_catalog && produced_here;
    // Kani locates the B154-MARK check here (a pure boolean has no other check).
    #[cfg(kani)]
    kani::cover!(!free && marked, "marked kept");
    free
}

/// C4: a `snapshot_out` older than the newest version file (an old copy put back, or a missing
/// one with a store left behind) would reuse freed stripes: refuse (`reject.gc_snapshot_stale`).
pub const fn stale_snapshot_decision(
    snapshot_version: Option<u64>,
    newest_version_file: Option<u64>,
) -> Result<(), &'static str> {
    let snap = match snapshot_version {
        Some(v) => v,
        None => 0,
    };
    match newest_version_file {
        Some(newest) if snap < newest => Err("reject.gc_snapshot_stale"),
        _ => Ok(()),
    }
}

/// C10, C11 (signing half): one epoch per order, `max(last + 1, timestamp_ms)`, so a device
/// recovered from the phrase (whose last is 0) is not refused by a host that saw the old one.
pub fn order_epoch(last_epoch: u64, timestamp_ms: u64) -> u64 {
    let next = last_epoch.saturating_add(1);
    if next > timestamp_ms {
        next
    } else {
        // Kani locates the B154-EPOCH check here.
        #[cfg(kani)]
        kani::cover!(timestamp_ms > last_epoch, "timestamp epoch");
        timestamp_ms
    }
}

/// What C35 does after a pass in which a host refused this owner for quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaRetry {
    /// No host refused for quota.
    NotNeeded,
    /// GC freed something: retry the pass once.
    Retry,
    /// The retry is spent, or GC freed nothing: the refused stripes stay local this pass.
    Spent(&'static str),
}

/// B163-RETRY (C35): after a pass some host refused for quota, run GC and retry the pass once,
/// only if GC freed something.
pub fn quota_retry_decision(
    refused_quota: bool,
    retried_once: bool,
    gc_freed_any: bool,
) -> QuotaRetry {
    if !refused_quota {
        QuotaRetry::NotNeeded
    } else if !retried_once && gc_freed_any {
        QuotaRetry::Retry
    } else {
        // Kani locates the B163-RETRY check here.
        #[cfg(kani)]
        kani::cover!(retried_once || !gc_freed_any, "retry spent");
        QuotaRetry::Spent("warn.gc_quota_retry_spent")
    }
}

/// D12: whether a pass may send one more free request (an order, or one fallback
/// `DeleteShard`) after spending `host_spent_ms` on this host and `pass_spent_ms` on frees in
/// all. Work not sent stays journalled, untouched, for the next pass.
pub const fn free_send_decision(host_spent_ms: u64, pass_spent_ms: u64) -> bool {
    host_spent_ms < FREE_HOST_BUDGET_MS && pass_spent_ms < FREE_PASS_BUDGET_MS
}

/// Milliseconds since `t`, saturating.
fn spent_ms(t: std::time::Instant) -> u64 {
    u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// What to do with a journal entry after a host's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeAction {
    /// `freed` or `not_held`: leave the journal.
    Done,
    /// No answer or a transient refusal: retry with backoff.
    Retry,
    /// `reject.delete_not_shard_owner`: straight to the abandoned list (C5).
    Abandon,
    /// `reject.free_stale`: clock skew; shown, retried, not counted toward abandonment (C5).
    ClockSkew,
}

/// The action for one refusal code (a per-shard outcome or a whole-order refusal).
/// Host codes are matched by name: their literals belong to the host's decision functions.
pub fn refusal_action(reason: &str) -> FreeAction {
    if reason.contains(".delete_not_shard_owner") {
        FreeAction::Abandon
    } else if reason.contains(".free_stale") {
        FreeAction::ClockSkew
    } else {
        FreeAction::Retry
    }
}

pub fn outcome_action(outcome: &FreeShardOutcome) -> FreeAction {
    match outcome {
        FreeShardOutcome::Freed | FreeShardOutcome::NotHeld => FreeAction::Done,
        FreeShardOutcome::Refused(code) => refusal_action(code),
    }
}

/// The pass of the next retry after `attempts` failures: 1, 2, 4 ... up to 60 passes later.
pub const fn next_retry_pass(pass: u64, attempts: u32) -> u64 {
    let shift = if attempts > 6 { 6 } else { attempts };
    let wait = 1u64 << shift;
    let wait = if wait > MAX_BACKOFF_PASSES {
        MAX_BACKOFF_PASSES
    } else {
        wait
    };
    pass.saturating_add(wait)
}

/// C5: abandoned after 30 days without an answer that clears it (clock skew does not count).
pub const fn abandon_decision(first_attempt_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(first_attempt_ms) >= ABANDON_AFTER_MS
}

/// The peer id an address names in its `/p2p/` suffix, as text.
fn addr_peer_id(addr: &str) -> Option<String> {
    let m = crate::network::parse_peer_multiaddr(addr).ok()?;
    crate::network::client::extract_expected_peer_id(&m).map(|p| p.to_string())
}

/// C8 by identity: an address naming peer id `X` in its `/p2p/` suffix is the host the owner was
/// given for `X` (`canon`: peer id -> its `--peers` or seed address) when it has one. A host
/// advertises every listen address over Identify, its loopback one included; the owner cannot
/// dial that one from another machine or container, and a free journalled for it would be
/// retried as unreachable for 30 days (T4). Other addresses are unchanged.
pub fn canonical_host(addr: &str, canon: &BTreeMap<String, String>) -> String {
    match addr_peer_id(addr).and_then(|pid| canon.get(&pid)) {
        Some(given) => given.clone(),
        None => addr.to_string(),
    }
}

/// Whether `addr` is a loopback IP address.
fn is_loopback_addr(addr: &str) -> bool {
    crate::network::client::is_loopback_peer_addr(addr)
}

/// The addresses to try for a host journalled under `host` (B-192, shared with the client's
/// read path): `host`, then the other known addresses of its peer id, non-loopback first.
pub fn send_candidates(host: &str, known: &[String]) -> Vec<String> {
    crate::network::client::peer_address_candidates(host, known)
}

/// Peer id -> address for the hosts the owner was given (`--peers`, the seed) whose peer id is
/// known: pinned by a connection this process made, or in the address. With `dial_for`, an
/// unpinned given host is dialed once (one status request) while some peer id in `dial_for` is
/// still unmapped.
fn given_hosts(client: &MeshClient, dial_for: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut given: Vec<String> = client
        .peers()
        .iter()
        .filter(|p| crate::network::is_network_peer_addr(p))
        .cloned()
        .collect();
    if let Some(seed) = client.seed_addr() {
        if crate::network::is_network_peer_addr(seed) {
            given.push(seed.to_string());
        }
    }
    let mut canon = BTreeMap::new();
    let mut unpinned = Vec::new();
    for g in given {
        match client.pinned_peer_id(&g) {
            Some(pid) => {
                canon.entry(pid.to_string()).or_insert(g);
            }
            None => unpinned.push(g),
        }
    }
    for g in unpinned {
        if dial_for.iter().all(|pid| canon.contains_key(pid)) {
            break;
        }
        if client.remote_ed25519_pubkey(&g).is_ok() {
            if let Some(pid) = client.pinned_peer_id(&g) {
                canon.entry(pid.to_string()).or_insert(g);
            }
        }
    }
    canon
}

/// C7: the catalog fetched from the ring is not the one this store last published: another
/// device writes this vault. No frees then (`reject.gc_foreign_catalog`).
/// `published` is `(version, ciphertext digest)` of this store's last acknowledged catalog, or
/// `None` when it has no record (an upgrade): then only a catalog newer than this store's
/// current version is foreign.
pub fn foreign_catalog_decision(
    published: Option<(u64, Hash32)>,
    current_version: u64,
    fetched: Option<(u64, Hash32)>,
) -> Result<(), &'static str> {
    let foreign = match (published, fetched) {
        (_, None) => false,
        (Some((pv, pd)), Some((fv, fd))) => fv > pv || (fv == pv && fd != pd),
        (None, Some((fv, _))) => fv > current_version,
    };
    if foreign {
        Err("reject.gc_foreign_catalog")
    } else {
        Ok(())
    }
}

pub use crate::por::verifier::{free_order_signing_bytes, sign_free_order};

// --- The journal -----------------------------------------------------------------------------

pub const JOURNAL_MAGIC: &[u8; 8] = b"PVGCJ001";
pub const JOURNAL_LAYOUT: u32 = 1;
pub const INFLIGHT_MAGIC: &[u8; 8] = b"PVGCI001";

type ShardKey = (Hash32, u32, Hash32);

fn key(id: &ShardId) -> ShardKey {
    (id.stripe_merkle_root, id.shard_index, id.shard_hash)
}

/// One shard to free on one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingFree {
    pub shard_id: ShardId,
    pub shard_len: u64,
    /// A network address, or [`LOCAL_HOST`].
    pub host: String,
    pub attempts: u32,
    pub first_attempt_ms: u64,
    pub next_pass: u64,
    /// `reject.free_stale` answers (clock skew; not counted toward abandonment).
    pub skew_refusals: u32,
}

/// A free that did not succeed in 30 days, or that the host refused as not the owner's (C5):
/// kept (quota stays charged), shown in status, retried daily.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbandonedFree {
    pub shard_id: ShardId,
    pub shard_len: u64,
    pub host: String,
    pub reason: String,
    pub last_retry_ms: u64,
}

/// The catalog this store last published and a host acknowledged (C6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedCatalog {
    pub version: u64,
    pub ciphertext_sha256: Hash32,
}

/// The journal: `<snapshot_out>.gc/journal.bin`, a tagged header and this body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcJournal {
    /// The last epoch signed (C10, C11).
    pub last_epoch: u64,
    /// GC runs so far (the backoff clock).
    pub pass: u64,
    pub published: Option<PublishedCatalog>,
    /// The policy of the last run, as (keep_last, keep_daily, keep_weekly, cap) (C27).
    pub policy: Option<(u32, u32, u32, Option<u64>)>,
    /// Step 4 work recorded at step 3: version files and manifests to delete.
    pub drop_versions: Vec<u64>,
    pub drop_manifests: Vec<Hash32>,
    pub pending: Vec<PendingFree>,
    pub abandoned: Vec<AbandonedFree>,
    /// Abandoned bytes beyond the bounded list.
    pub abandoned_overflow_bytes: u64,
}

/// Paths of one folder's GC state.
#[derive(Debug, Clone)]
pub struct GcPaths {
    pub dir: PathBuf,
}

impl GcPaths {
    pub fn for_snapshot(snapshot_out: &Path) -> Self {
        let mut name = snapshot_out.as_os_str().to_owned();
        name.push(".gc");
        Self {
            dir: PathBuf::from(name),
        }
    }
    pub fn journal(&self) -> PathBuf {
        self.dir.join("journal.bin")
    }
    pub fn inflight(&self) -> PathBuf {
        self.dir.join("inflight.log")
    }
    pub fn lock(&self) -> PathBuf {
        self.dir.join("pass.lock")
    }
}

/// Why GC state could not be read.
#[derive(Debug)]
pub enum GcError {
    Io(std::io::Error),
    /// A journal of another layout, or a damaged one: never read as empty.
    Format(String),
    Storage(StorageError),
    Version(retention::VersionFileError),
    /// C4, with its code from [`stale_snapshot_decision`].
    StaleSnapshot {
        code: &'static str,
        snapshot: u64,
        newest: u64,
    },
    /// `reject.gc_snapshot_locked`: another pass holds this folder.
    Locked(PathBuf),
}

impl std::fmt::Display for GcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "gc state: {e}"),
            Self::Format(s) => write!(f, "reject.gc_journal_format: {s}"),
            Self::Storage(e) => write!(f, "gc: {e}"),
            Self::Version(e) => write!(f, "{e}"),
            Self::StaleSnapshot {
                code,
                snapshot,
                newest,
            } => write!(
                f,
                "{code}: the snapshot file is version {snapshot} but the version store holds version {newest}; restore with 'restore-folder --version' instead of copying an old snapshot back"
            ),
            Self::Locked(p) => write!(
                f,
                "reject.gc_snapshot_locked: another watch-folder runs on this snapshot ({})",
                p.display()
            ),
        }
    }
}

impl std::error::Error for GcError {}

impl From<std::io::Error> for GcError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<StorageError> for GcError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}
impl From<retention::VersionFileError> for GcError {
    fn from(e: retention::VersionFileError) -> Self {
        Self::Version(e)
    }
}

impl GcJournal {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(JOURNAL_MAGIC);
        out.extend_from_slice(&JOURNAL_LAYOUT.to_be_bytes());
        out.extend_from_slice(&bincode::serialize(self).unwrap_or_default());
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self, GcError> {
        if raw.len() < 12 || &raw[..8] != JOURNAL_MAGIC {
            return Err(GcError::Format("no journal tag".into()));
        }
        let layout = u32::from_be_bytes(raw[8..12].try_into().expect("4 bytes"));
        if layout != JOURNAL_LAYOUT {
            return Err(GcError::Format(format!("layout {layout}")));
        }
        bincode::deserialize(&raw[12..]).map_err(|e| GcError::Format(e.to_string()))
    }

    /// The journal, or an empty one if there is none yet.
    pub fn load(paths: &GcPaths) -> Result<Self, GcError> {
        match std::fs::read(paths.journal()) {
            Ok(raw) => Self::decode(&raw),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Writes atomically (fsync, rename).
    pub fn save(&self, paths: &GcPaths) -> Result<(), GcError> {
        std::fs::create_dir_all(&paths.dir)?;
        BlockStore::atomic_write_file(&paths.journal(), &self.encode())?;
        Ok(())
    }

    pub fn pending_bytes(&self) -> u64 {
        self.pending
            .iter()
            .filter(|p| p.host != LOCAL_HOST)
            .map(|p| p.shard_len)
            .sum()
    }

    pub fn abandoned_bytes(&self) -> u64 {
        self.abandoned.iter().map(|a| a.shard_len).sum::<u64>() + self.abandoned_overflow_bytes
    }

    fn add_pending(&mut self, entry: PendingFree) {
        let k = (key(&entry.shard_id), entry.host.clone());
        if !self
            .pending
            .iter()
            .any(|p| (key(&p.shard_id), p.host.clone()) == k)
        {
            self.pending.push(entry);
        }
    }

    fn abandon(&mut self, p: PendingFree, reason: String, now_ms: u64) {
        let per_host = self.abandoned.iter().filter(|a| a.host == p.host).count();
        if per_host >= MAX_ABANDONED_PER_HOST {
            self.abandoned_overflow_bytes += p.shard_len;
            return;
        }
        if self
            .abandoned
            .iter()
            .any(|a| a.host == p.host && key(&a.shard_id) == key(&p.shard_id))
        {
            return;
        }
        tracing::warn!(
            code = "warn.gc_host_unreachable",
            host = %p.host,
            reason = %reason,
            "a free was abandoned; the shard stays charged to this owner on that host"
        );
        self.abandoned.push(AbandonedFree {
            shard_id: p.shard_id,
            shard_len: p.shard_len,
            host: p.host,
            reason,
            last_retry_ms: now_ms,
        });
    }
}

// --- The in-flight log (C3) ------------------------------------------------------------------

/// One stripe about to be placed: its shard ids, shard length and candidate hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InflightStripe {
    pub shard_ids: Vec<ShardId>,
    pub hosts: Vec<String>,
}

/// Appends one record and fsyncs: `u32 len || bincode`. A torn last record (a crash during the
/// append) is ignored on read; nothing of it was sent.
pub fn inflight_append(path: &Path, rec: &InflightStripe) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if f.metadata()?.len() == 0 {
        f.write_all(INFLIGHT_MAGIC)?;
    }
    let body = bincode::serialize(rec).map_err(std::io::Error::other)?;
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    f.write_all(&buf)?;
    f.sync_all()
}

/// Every whole record of the in-flight log.
pub fn inflight_read(path: &Path) -> Result<Vec<InflightStripe>, GcError> {
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if raw.len() < 8 || &raw[..8] != INFLIGHT_MAGIC {
        return Err(GcError::Format("in-flight log has no tag".into()));
    }
    let mut out = Vec::new();
    let mut at = 8usize;
    while at + 4 <= raw.len() {
        let len = u32::from_be_bytes(raw[at..at + 4].try_into().expect("4 bytes")) as usize;
        let Some(body) = raw.get(at + 4..at + 4 + len) else {
            break; // torn tail
        };
        match bincode::deserialize(body) {
            Ok(r) => out.push(r),
            Err(_) => break,
        }
        at += 4 + len;
    }
    Ok(out)
}

/// The placement hook that writes the in-flight log (C3).
pub fn inflight_hook(paths: &GcPaths) -> PrePlaceHook {
    let path = paths.inflight();
    PrePlaceHook(Arc::new(move |ids: &[ShardId], hosts: &[String]| {
        inflight_append(
            &path,
            &InflightStripe {
                shard_ids: ids.to_vec(),
                hosts: hosts.to_vec(),
            },
        )
    }))
}

/// Holds one folder's pass lock (`flock` on `<snapshot_out>.gc/pass.lock`) while alive.
#[derive(Debug)]
pub struct PassLock {
    _file: std::fs::File,
}

impl PassLock {
    /// Fails fast with `reject.gc_snapshot_locked` if another process holds it.
    pub fn acquire(paths: &GcPaths) -> Result<Self, GcError> {
        std::fs::create_dir_all(&paths.dir)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(paths.lock())?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(GcError::Locked(paths.lock())),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }
}

// --- Mark and sweep --------------------------------------------------------------------------

/// What one stripe needs for freeing and accounting.
#[derive(Debug, Clone)]
pub struct StripeRef {
    pub shard_ids: Vec<ShardId>,
    pub shard_len: u64,
    pub ciphertext_len: u64,
    pub assigned_peers: Vec<String>,
}

/// The stripes and file roots one snapshot references.
#[derive(Debug, Clone, Default)]
pub struct SnapshotRefs {
    pub stripes: BTreeMap<Hash32, StripeRef>,
    pub file_roots: BTreeSet<Hash32>,
}

impl SnapshotRefs {
    pub fn of(snap: &FolderSnapshotManifest) -> Self {
        let mut out = Self::default();
        for f in snap.files.values() {
            out.file_roots.insert(f.file_merkle_root);
            for s in &f.manifest.stripes {
                out.stripes
                    .entry(s.stripe_merkle_root)
                    .or_insert_with(|| StripeRef {
                        shard_ids: s
                            .shard_hashes
                            .iter()
                            .enumerate()
                            .map(|(i, h)| ShardId {
                                stripe_merkle_root: s.stripe_merkle_root,
                                shard_index: i as u32,
                                shard_hash: *h,
                            })
                            .collect(),
                        shard_len: s.shard_len as u64,
                        ciphertext_len: s.original_ciphertext_len as u64,
                        assigned_peers: s.assigned_peers.clone(),
                    });
            }
        }
        out
    }
}

/// The two mark sets (C2) of the kept snapshots.
#[derive(Debug, Clone, Default)]
pub struct MarkSets {
    pub stripes: BTreeSet<Hash32>,
    pub file_roots: BTreeSet<Hash32>,
}

/// Marks every stripe and file root of `kept` (the retained versions, the pass being written,
/// and the published catalog's version).
pub fn mark<'a>(kept: impl IntoIterator<Item = &'a SnapshotRefs>) -> MarkSets {
    let mut m = MarkSets::default();
    for r in kept {
        m.stripes.extend(r.stripes.keys().copied());
        m.file_roots.extend(r.file_roots.iter().copied());
    }
    m
}

/// The garbage of `dropped` against `marks`: stripes to free (C2: only unmarked stripes) and
/// manifests to delete (only unmarked file roots).
pub fn sweep<'a>(
    dropped: impl IntoIterator<Item = &'a SnapshotRefs>,
    marks: &MarkSets,
) -> (BTreeMap<Hash32, StripeRef>, BTreeSet<Hash32>) {
    let mut stripes = BTreeMap::new();
    let mut manifests = BTreeSet::new();
    for r in dropped {
        for (root, s) in &r.stripes {
            // Every stripe here came from this store's own version files: produced here.
            if gc_free_decision(marks.stripes.contains(root), false, true) {
                stripes.entry(*root).or_insert_with(|| s.clone());
            }
        }
        for fr in &r.file_roots {
            if !marks.file_roots.contains(fr) {
                manifests.insert(*fr);
            }
        }
    }
    (stripes, manifests)
}

// --- The run ---------------------------------------------------------------------------------

/// GC settings of one folder.
#[derive(Debug, Clone)]
pub struct GcSettings {
    pub snapshot_out: PathBuf,
    pub policy: RetentionPolicy,
    /// The node's data dir (the B-113 relocation map, `folders/` stats).
    pub data_dir: PathBuf,
    /// The client frees go through; `None`: local frees only.
    pub client: Option<MeshClient>,
    /// C7: the catalog fetched from the ring after this pass's publish, `(version, digest)`.
    pub fetched_catalog: Option<(u64, Hash32)>,
}

impl GcSettings {
    /// The daemon's appliance folder (`up --watch-folder`): its snapshot in `data_dir`, the
    /// default policy, frees through `client`.
    pub fn appliance(data_dir: &Path, client: Option<MeshClient>) -> Self {
        Self {
            snapshot_out: data_dir.join(super::engine::APPLIANCE_SNAPSHOT_FILE),
            policy: RetentionPolicy::default(),
            data_dir: data_dir.to_path_buf(),
            client,
            fetched_catalog: None,
        }
    }
}

/// What one GC run did, for the pass output and status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    pub versions_kept: usize,
    pub versions_dropped: usize,
    pub stripes_garbage: usize,
    pub manifests_deleted: usize,
    pub local_shards_freed: usize,
    pub orders_sent: usize,
    pub shards_freed: usize,
    pub shards_not_held: usize,
    pub pending: usize,
    pub pending_bytes: u64,
    pub abandoned: usize,
    pub abandoned_bytes: u64,
    pub clock_skew_refusals: usize,
    pub foreign_catalog: bool,
    pub cap_below_one_version: bool,
    pub fallback_deletes: usize,
    /// D12: due frees not sent this pass (a host's or the pass's time budget ran out); they
    /// stay journalled for the next pass.
    pub frees_deferred: usize,
    /// Unique pre-erasure bytes of the retained versions.
    pub stored_cipher_bytes: u64,
    /// Unique shard bytes (`shard_len x n`) of the retained versions, before the replica factor.
    pub stored_shard_bytes: u64,
    /// The version store's bytes on this disk (C30).
    pub version_store_bytes: u64,
}

impl GcReport {
    /// Whether this run freed anything anywhere (C35).
    pub fn freed_any(&self) -> bool {
        self.local_shards_freed + self.shards_freed > 0
    }
}

/// One GC run, step by step (the steps are public so the crash-prefix test can stop after any
/// of them on a real directory).
pub struct GcRun<'a> {
    pub settings: &'a GcSettings,
    store: &'a BlockStore,
    owner: &'a NodeIdentity,
    now_ms: u64,
    paths: GcPaths,
    versions: VersionStore,
    pub journal: GcJournal,
    pub report: GcReport,
    marks: MarkSets,
    current: u64,
}

impl<'a> GcRun<'a> {
    pub fn new(
        settings: &'a GcSettings,
        store: &'a BlockStore,
        owner: &'a NodeIdentity,
        now_ms: u64,
    ) -> Result<Self, GcError> {
        let paths = GcPaths::for_snapshot(&settings.snapshot_out);
        let journal = GcJournal::load(&paths)?;
        Ok(Self {
            settings,
            store,
            owner,
            now_ms,
            versions: VersionStore::for_snapshot(&settings.snapshot_out),
            paths,
            journal,
            report: GcReport::default(),
            marks: MarkSets::default(),
            current: 0,
        })
    }

    /// Step 1: the pass's version file (a no-change pass already has it).
    pub fn step1_write_version(
        &mut self,
        snapshot: &FolderSnapshotManifest,
    ) -> Result<(), GcError> {
        self.current = snapshot.version;
        if !self.versions.path_of(snapshot.version).exists() {
            self.versions.write(snapshot, self.now_ms)?;
        }
        Ok(())
    }

    /// Steps 2 and 3: retention, marks, garbage, then the journal (fsync) and the in-flight log
    /// cleared.
    pub fn step2_3_mark_and_journal(&mut self) -> Result<(), GcError> {
        let policy = self.settings.policy;
        // C27: the policy of this run is recorded with the epoch; a shrunk policy only adds
        // garbage through the journal, a grown one resurrects nothing already dropped.
        self.journal.policy = Some((
            policy.keep_last,
            policy.keep_daily,
            policy.keep_weekly,
            policy.max_stored_bytes,
        ));
        let metas: Vec<VersionMeta> = self.versions.list()?;
        let mut refs = Vec::with_capacity(metas.len());
        for m in &metas {
            refs.push(SnapshotRefs::of(&self.versions.load(m.version)?));
        }
        let mut keep = vec![false; metas.len()];
        let _ = retention::retention_decision(&metas, &policy, self.now_ms, &mut keep);
        let pinned =
            |v: u64| v == self.current || Some(v) == self.journal.published.map(|p| p.version);
        for (i, m) in metas.iter().enumerate() {
            if pinned(m.version) {
                keep[i] = true;
            }
        }
        let cap = retention::apply_cap(&metas, &mut keep, policy.max_stored_bytes, |mask| {
            let mut seen = BTreeSet::new();
            let mut bytes = 0u64;
            for (i, r) in refs.iter().enumerate() {
                if mask[i] {
                    for (root, s) in &r.stripes {
                        if seen.insert(*root) {
                            bytes += s.ciphertext_len;
                        }
                    }
                }
            }
            bytes
        });
        // The cap never drops the pass being written or the published catalog (C6).
        for (i, m) in metas.iter().enumerate() {
            if pinned(m.version) {
                keep[i] = true;
            }
        }
        if cap.below_one_version {
            self.report.cap_below_one_version = true;
            tracing::warn!(
                code = "warn.folder_cap_below_one_version",
                "the newest version alone is above --max-stored-bytes; it is kept"
            );
        }
        self.marks = mark(refs.iter().zip(&keep).filter(|(_, k)| **k).map(|(r, _)| r));
        let mut seen = BTreeSet::new();
        for (r, _) in refs.iter().zip(&keep).filter(|(_, k)| **k) {
            for (root, st) in &r.stripes {
                if seen.insert(*root) {
                    self.report.stored_cipher_bytes += st.ciphertext_len;
                    self.report.stored_shard_bytes += st.shard_len * st.shard_ids.len() as u64;
                }
            }
        }
        let dropped: Vec<&SnapshotRefs> = refs
            .iter()
            .zip(&keep)
            .filter(|(_, k)| !**k)
            .map(|(r, _)| r)
            .collect();
        let (mut garbage, manifests) = sweep(dropped, &self.marks);
        // C3: stripes a dead pass placed and no version references.
        let inflight = inflight_read(&self.paths.inflight())?;
        let mut inflight_hosts: BTreeMap<Hash32, Vec<String>> = BTreeMap::new();
        for rec in &inflight {
            let Some(root) = rec.shard_ids.first().map(|s| s.stripe_merkle_root) else {
                continue;
            };
            if self.marks.stripes.contains(&root) {
                continue;
            }
            inflight_hosts
                .entry(root)
                .or_default()
                .extend(rec.hosts.iter().cloned());
            garbage.entry(root).or_insert_with(|| StripeRef {
                shard_ids: rec.shard_ids.clone(),
                shard_len: 0,
                ciphertext_len: 0,
                assigned_peers: Vec::new(),
            });
        }
        self.report.versions_kept = keep.iter().filter(|k| **k).count();
        self.report.versions_dropped = keep.len() - self.report.versions_kept;
        self.report.stripes_garbage = garbage.len();
        let relocations = crate::por::auditor::relocation_targets(&self.settings.data_dir)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "relocation map unreadable; frees go to placed hosts only");
                Vec::new()
            });
        // Hosts by identity (C8): no dial here; step 6 maps what is still unmapped.
        let canon = match &self.settings.client {
            Some(client) => given_hosts(client, &BTreeSet::new()),
            None => BTreeMap::new(),
        };
        for (root, s) in &garbage {
            for id in &s.shard_ids {
                let mut hosts = self.targets(s, id, &relocations, &canon);
                if let Some(extra) = inflight_hosts.get(root) {
                    hosts.extend(extra.iter().map(|h| canonical_host(h, &canon)));
                }
                for host in hosts {
                    self.journal.add_pending(PendingFree {
                        shard_id: *id,
                        shard_len: s.shard_len,
                        host,
                        attempts: 0,
                        first_attempt_ms: self.now_ms,
                        next_pass: 0,
                        skew_refusals: 0,
                    });
                }
            }
        }
        for (i, m) in metas.iter().enumerate() {
            if !keep[i] && !self.journal.drop_versions.contains(&m.version) {
                self.journal.drop_versions.push(m.version);
            }
        }
        for fr in manifests {
            if !self.journal.drop_manifests.contains(&fr) {
                self.journal.drop_manifests.push(fr);
            }
        }
        // Re-check before anything is freed: an entry whose stripe is marked again is dropped.
        let marks = &self.marks;
        self.journal
            .pending
            .retain(|p| !marks.stripes.contains(&p.shard_id.stripe_merkle_root));
        self.journal
            .abandoned
            .retain(|a| !marks.stripes.contains(&a.shard_id.stripe_merkle_root));
        self.journal
            .drop_manifests
            .retain(|fr| !marks.file_roots.contains(fr));
        let current = self.current;
        self.journal.drop_versions.retain(|v| *v != current);
        self.journal.save(&self.paths)?;
        match std::fs::remove_file(self.paths.inflight()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        Ok(())
    }

    /// Hosts that may hold `id` (B-154 2.4, C8): its placed host, the seed, every ring peer when
    /// the ring has fewer peers than shards (replica shift), the B-113 relocation map, and the
    /// owner's own store.
    fn targets(
        &self,
        s: &StripeRef,
        id: &ShardId,
        relocations: &[crate::por::auditor::RelocationTarget],
        canon: &BTreeMap<String, String>,
    ) -> BTreeSet<String> {
        let mut hosts = BTreeSet::new();
        hosts.insert(LOCAL_HOST.to_string());
        if let Some(p) = s.assigned_peers.get(id.shard_index as usize) {
            if crate::network::is_network_peer_addr(p) {
                hosts.insert(p.clone());
            }
        }
        if let Some(client) = &self.settings.client {
            if let Some(seed) = client.seed_addr() {
                if crate::network::is_network_peer_addr(seed) {
                    hosts.insert(seed.to_string());
                }
            }
            let endpoints = client.all_network_endpoints();
            if endpoints.len() < s.shard_ids.len().max(1) {
                hosts.extend(
                    endpoints
                        .into_iter()
                        .filter(|p| crate::network::is_network_peer_addr(p)),
                );
            }
        }
        let fk = id.file_key();
        for r in relocations {
            if r.shard_file_key == fk && crate::network::is_network_peer_addr(&r.host_addr) {
                hosts.insert(r.host_addr.clone());
            }
        }
        hosts
            .into_iter()
            .map(|h| canonical_host(&h, canon))
            .collect()
    }

    /// Step 4: the dropped version files and the garbage's manifests (off the owner's PoR scan
    /// before any host frees a shard).
    pub fn step4_delete_versions_and_manifests(&mut self) -> Result<(), GcError> {
        if self.report.foreign_catalog {
            return Ok(());
        }
        for v in std::mem::take(&mut self.journal.drop_versions) {
            self.versions.remove(v)?;
        }
        let dir = self.store.root_dir().join("manifests");
        for fr in std::mem::take(&mut self.journal.drop_manifests) {
            match std::fs::remove_file(dir.join(format!("{}.manifest.bin", hex::encode(fr)))) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                Ok(()) => self.report.manifests_deleted += 1,
                _ => {}
            }
        }
        self.journal.save(&self.paths)
    }

    /// Step 5: the owner's own shards.
    pub fn step5_free_local(&mut self) -> Result<(), GcError> {
        if self.report.foreign_catalog {
            return Ok(());
        }
        let owner_pid = self.owner.device_peer_id();
        let mut kept = Vec::new();
        for p in std::mem::take(&mut self.journal.pending) {
            if p.host != LOCAL_HOST {
                kept.push(p);
                continue;
            }
            let a = self.store.delete_shard(&owner_pid, &p.shard_id)?;
            let b = self.store.delete_shard(LOCAL_HOST, &p.shard_id)?;
            if a || b {
                self.report.local_shards_freed += 1;
            }
        }
        self.journal.pending = kept;
        self.journal.save(&self.paths)
    }

    /// Step 6: one order per host per chunk of at most 1024 shards, each with its own epoch
    /// (C10), persisted before it is sent, and timestamped and signed when it is sent (D12).
    /// Each host gets at most [`FREE_HOST_BUDGET_MS`] and the pass [`FREE_PASS_BUDGET_MS`];
    /// work not sent in them stays journalled, untouched, for the next pass (D12).
    pub fn step6_send_orders(&mut self) -> Result<(), GcError> {
        if self.report.foreign_catalog {
            return Ok(());
        }
        self.journal.pass = self.journal.pass.saturating_add(1);
        let pass = self.journal.pass;
        let now = self.now_ms;
        let started = std::time::Instant::now();
        let Some(probe) = self.settings.client.clone() else {
            return self.journal.save(&self.paths);
        };
        // A host purges each shard of an order (shred, fsync): a full order takes seconds, far
        // over the default 1.2 s request timeout (track B1 measured 2.3 s for 666 shards).
        // Only orders and fallback deletes get the long timeout; status probes and key lookups
        // keep the short one, so a host that holds a connection without answering costs one
        // short probe, not a long timeout per probe (D12).
        let client = probe.clone().with_timeout(FREE_ORDER_TIMEOUT);
        // Every address known for a host: the client's endpoints (given and discovered) and the
        // journal's own, before entries merge under one address per peer id.
        let mut known = client.all_network_endpoints();
        known.extend(
            self.journal
                .pending
                .iter()
                .map(|p| p.host.clone())
                .chain(self.journal.abandoned.iter().map(|a| a.host.clone()))
                .filter(|h| h != LOCAL_HOST),
        );
        self.canonicalize_hosts(&client);
        // Due work per host: pending entries whose backoff has passed, and abandoned entries
        // not retried for a day.
        let mut by_host: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, p) in self.journal.pending.iter().enumerate() {
            if p.next_pass <= pass {
                by_host.entry(p.host.clone()).or_default().push(i);
            }
        }
        let mut abandoned_due: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, a) in self.journal.abandoned.iter().enumerate() {
            if now.saturating_sub(a.last_retry_ms) >= DAY_MS {
                abandoned_due.entry(a.host.clone()).or_default().push(i);
            }
        }
        let hosts: BTreeSet<String> = by_host
            .keys()
            .chain(abandoned_due.keys())
            .cloned()
            .collect();
        // Results per (shard, host): Some(action, reason).
        let mut pending_result: BTreeMap<usize, (FreeAction, String)> = BTreeMap::new();
        let mut abandoned_result: BTreeMap<usize, FreeAction> = BTreeMap::new();
        for host in hosts {
            if !free_send_decision(0, spent_ms(started)) {
                // The pass's budget is spent: this host's due work waits for the next pass.
                let n = by_host.get(&host).map_or(0, Vec::len)
                    + abandoned_due.get(&host).map_or(0, Vec::len);
                self.report.frees_deferred += n;
                continue;
            }
            let p_idx = by_host.get(&host).cloned().unwrap_or_default();
            let a_idx = abandoned_due.get(&host).cloned().unwrap_or_default();
            let mut work: Vec<(bool, usize, ShardId)> = p_idx
                .iter()
                .map(|&i| (true, i, self.journal.pending[i].shard_id))
                .chain(
                    a_idx
                        .iter()
                        .map(|&i| (false, i, self.journal.abandoned[i].shard_id)),
                )
                .collect();
            // The first known address of this host (by peer id) that answers as it; an address
            // carrying a peer id is dialed with that id expected (Noise), so another node
            // answering there is a mismatch, never a free.
            let mut send_to = host.clone();
            if addr_peer_id(&host).is_some() {
                let reachable = send_candidates(&host, &known)
                    .into_iter()
                    .find(|a| probe.is_reachable(a));
                if let Some(a) = reachable {
                    send_to = a;
                }
            }
            let host_key = match probe.remote_ed25519_pubkey(&send_to) {
                Ok(k) => Some(k),
                Err(e) => {
                    tracing::info!(host = %host, error = %e, "host unreachable; frees retried later");
                    None
                }
            };
            let Some(host_key) = host_key else {
                for (is_p, i, _) in work {
                    if is_p {
                        pending_result.insert(i, (FreeAction::Retry, UNREACHABLE.into()));
                    } else {
                        abandoned_result.insert(i, FreeAction::Retry);
                    }
                }
                continue;
            };
            let host_started = std::time::Instant::now();
            while !work.is_empty() {
                if !free_send_decision(spent_ms(host_started), spent_ms(started)) {
                    tracing::warn!(
                        host = %host,
                        deferred = work.len(),
                        "free budget spent on this host; the rest is sent next pass"
                    );
                    self.report.frees_deferred += work.len();
                    break;
                }
                let take = work.len().min(MAX_FREE_ORDER_SHARDS);
                let chunk: Vec<(bool, usize, ShardId)> = work.drain(..take).collect();
                // D12: stamped now, at send, not at the pass start: a slow host before this one
                // must not make the order stale on arrival (`reject.free_stale`).
                let ts = now.saturating_add(spent_ms(started));
                let epoch = order_epoch(self.journal.last_epoch, ts);
                self.journal.last_epoch = epoch;
                self.journal.save(&self.paths)?;
                let ids: Vec<ShardId> = chunk.iter().map(|c| c.2).collect();
                let order = sign_free_order(self.owner, host_key, ts, epoch, ids.clone());
                self.report.orders_sent += 1;
                let actions: Vec<(FreeAction, String, bool)> =
                    match client.free_shards(&send_to, order) {
                        Ok(FreeShardsReply::Outcomes(outs)) => {
                            // Per-shard refusals are retried silently otherwise: say which.
                            let mut refused: BTreeMap<&str, usize> = BTreeMap::new();
                            for o in &outs {
                                if let FreeShardOutcome::Refused(c) = o {
                                    *refused.entry(c.as_str()).or_default() += 1;
                                }
                            }
                            if !refused.is_empty() {
                                tracing::warn!(
                                    host = %host,
                                    refused = ?refused,
                                    shards = outs.len(),
                                    "free order: shards refused by the host"
                                );
                            }
                            outs.iter()
                                .map(|o| {
                                    let reason = match o {
                                        FreeShardOutcome::Refused(c) => c.clone(),
                                        _ => String::new(),
                                    };
                                    (
                                        outcome_action(o),
                                        reason,
                                        matches!(o, FreeShardOutcome::Freed),
                                    )
                                })
                                .collect()
                        }
                        Ok(FreeShardsReply::Refused(e)) => {
                            let a = refusal_action(&e);
                            tracing::warn!(host = %host, error = %e, "free order refused");
                            chunk.iter().map(|_| (a, e.clone(), false)).collect()
                        }
                        Err(_) if !probe.is_reachable(&send_to) => chunk
                            .iter()
                            .map(|_| (FreeAction::Retry, UNREACHABLE.to_string(), false))
                            .collect(),
                        Ok(FreeShardsReply::Unsupported(_)) | Err(_) => {
                            // C15: a host without `FreeShards` (never with dedup, which v0.5.6 has
                            // not): the old `DeleteShard`, per shard, within the host's budget (D12);
                            // the shards not tried get no result and stay journalled.
                            let mut acts = Vec::with_capacity(ids.len());
                            for id in &ids {
                                if !free_send_decision(spent_ms(host_started), spent_ms(started)) {
                                    self.report.frees_deferred += ids.len() - acts.len();
                                    break;
                                }
                                self.report.fallback_deletes += 1;
                                acts.push(
                                    match client.delete_shard_outcome(&send_to, *id, self.owner) {
                                        Ok(true) => (FreeAction::Done, String::new(), true),
                                        Ok(false) => (FreeAction::Done, String::new(), false),
                                        Err(e) => {
                                            let t = e.to_string();
                                            (refusal_action(&t), t, false)
                                        }
                                    },
                                );
                            }
                            acts
                        }
                    };
                for ((is_p, i, _), (action, reason, freed)) in chunk.into_iter().zip(actions) {
                    if action == FreeAction::Done {
                        if freed {
                            self.report.shards_freed += 1;
                        } else {
                            self.report.shards_not_held += 1;
                        }
                    }
                    if action == FreeAction::ClockSkew {
                        self.report.clock_skew_refusals += 1;
                    }
                    if is_p {
                        pending_result.insert(i, (action, reason));
                    } else {
                        abandoned_result.insert(i, action);
                    }
                }
            }
        }
        // Apply the results.
        let mut still = Vec::new();
        let mut to_abandon = Vec::new();
        for (i, mut p) in std::mem::take(&mut self.journal.pending)
            .into_iter()
            .enumerate()
        {
            match pending_result.remove(&i) {
                None => still.push(p),
                Some((FreeAction::Done, _)) => {}
                Some((FreeAction::Abandon, reason)) => to_abandon.push((p, reason)),
                Some((FreeAction::ClockSkew, _)) => {
                    p.skew_refusals += 1;
                    p.next_pass = pass.saturating_add(1);
                    still.push(p);
                }
                Some((FreeAction::Retry, reason)) => {
                    p.attempts = p.attempts.saturating_add(1);
                    // An unreachable host is probed every pass (one status request), so a host
                    // that comes back is freed on its next pass (T4); a host that answers and
                    // refuses backs off.
                    p.next_pass = if reason == UNREACHABLE {
                        pass.saturating_add(1)
                    } else {
                        next_retry_pass(pass, p.attempts)
                    };
                    if abandon_decision(p.first_attempt_ms, now) {
                        to_abandon.push((p, reason));
                    } else {
                        still.push(p);
                    }
                }
            }
        }
        self.journal.pending = still;
        let mut abandoned = Vec::new();
        for (i, mut a) in std::mem::take(&mut self.journal.abandoned)
            .into_iter()
            .enumerate()
        {
            match abandoned_result.get(&i) {
                Some(FreeAction::Done) => {}
                Some(_) => {
                    a.last_retry_ms = now;
                    abandoned.push(a);
                }
                None => abandoned.push(a),
            }
        }
        self.journal.abandoned = abandoned;
        for (p, reason) in to_abandon {
            self.journal.abandon(p, reason, now);
        }
        self.journal.save(&self.paths)
    }

    /// Entries journalled for another address of a given host (a listen address it advertised,
    /// or a journal from before this mapping) move to the address the owner was given for it, and
    /// merge with an entry already there (C8 by identity; T4).
    fn canonicalize_hosts(&mut self, client: &MeshClient) {
        let given: BTreeSet<&str> = client
            .peers()
            .iter()
            .map(String::as_str)
            .chain(client.seed_addr())
            .collect();
        let dial_for: BTreeSet<String> = self
            .journal
            .pending
            .iter()
            .map(|p| p.host.as_str())
            .chain(self.journal.abandoned.iter().map(|a| a.host.as_str()))
            .filter(|h| *h != LOCAL_HOST && !given.contains(h))
            .filter_map(addr_peer_id)
            .collect();
        if dial_for.is_empty() {
            return;
        }
        let mut canon = given_hosts(client, &dial_for);
        // A host the owner was not given (found by discovery): its journalled addresses merge
        // under one, a non-loopback one first; step 6 still tries every address it knows.
        let mut by_pid: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for h in self
            .journal
            .pending
            .iter()
            .map(|p| &p.host)
            .chain(self.journal.abandoned.iter().map(|a| &a.host))
        {
            if let Some(pid) = addr_peer_id(h) {
                if !canon.contains_key(&pid) {
                    by_pid.entry(pid).or_default().push(h.clone());
                }
            }
        }
        for (pid, mut addrs) in by_pid {
            addrs.sort_by(|a, b| (is_loopback_addr(a), a).cmp(&(is_loopback_addr(b), b)));
            canon.insert(pid, addrs.swap_remove(0));
        }
        let mut seen = BTreeSet::new();
        let mut pending = Vec::with_capacity(self.journal.pending.len());
        for mut p in std::mem::take(&mut self.journal.pending) {
            if p.host != LOCAL_HOST {
                p.host = canonical_host(&p.host, &canon);
            }
            if seen.insert((key(&p.shard_id), p.host.clone())) {
                pending.push(p);
            }
        }
        self.journal.pending = pending;
        let mut seen = BTreeSet::new();
        let mut abandoned = Vec::with_capacity(self.journal.abandoned.len());
        for mut a in std::mem::take(&mut self.journal.abandoned) {
            a.host = canonical_host(&a.host, &canon);
            if seen.insert((key(&a.shard_id), a.host.clone())) {
                abandoned.push(a);
            }
        }
        self.journal.abandoned = abandoned;
    }

    /// The report's journal totals.
    pub fn finish(mut self) -> GcReport {
        self.report.version_store_bytes = self.versions.local_bytes();
        self.report.pending = self.journal.pending.len();
        self.report.pending_bytes = self.journal.pending_bytes();
        self.report.abandoned = self.journal.abandoned.len();
        self.report.abandoned_bytes = self.journal.abandoned_bytes();
        self.report
    }

    /// C7: decided once per run, before step 4.
    pub fn check_foreign_catalog(&mut self) {
        let published = self
            .journal
            .published
            .map(|p| (p.version, p.ciphertext_sha256));
        if let Err(code) =
            foreign_catalog_decision(published, self.current, self.settings.fetched_catalog)
        {
            self.report.foreign_catalog = true;
            tracing::error!(
                code,
                "the ring's catalog for this vault is not the one this device published: another device writes this vault (one writer per vault folder); nothing is freed"
            );
        }
    }
}

/// Runs every step of one GC epoch.
pub fn run_gc(
    settings: &GcSettings,
    store: &BlockStore,
    owner: &NodeIdentity,
    snapshot: &FolderSnapshotManifest,
    now_ms: u64,
) -> Result<GcReport, GcError> {
    let mut run = GcRun::new(settings, store, owner, now_ms)?;
    run.step1_write_version(snapshot)?;
    run.step2_3_mark_and_journal()?;
    run.check_foreign_catalog();
    run.step4_delete_versions_and_manifests()?;
    run.step5_free_local()?;
    run.step6_send_orders()?;
    Ok(run.finish())
}

/// A folder's accounting after a pass (B-154 5, C30, C44, L-122), written to
/// `<data_dir>/folders/<id>.stats.json` (counts only, no paths) and shown by `watch-folder`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderStats {
    pub version: u64,
    pub files: usize,
    /// The folder's size on disk (the current version's files).
    pub disk_bytes: u64,
    pub versions_retained: usize,
    pub keep_last: u32,
    pub keep_daily: u32,
    pub keep_weekly: u32,
    pub max_stored_bytes: Option<u64>,
    /// Unique pre-erasure bytes of the retained versions.
    pub stored_cipher_bytes: u64,
    /// Expected on-ring bytes (labelled expected until B-149(1) measures them): unique shard
    /// bytes x replica factor, plus pending and abandoned frees (C44).
    pub expected_stored_bytes: u64,
    pub pending_free_bytes: u64,
    pub abandoned_bytes: u64,
    /// What the policy can legitimately hold (L-122).
    pub policy_max_bytes: u64,
    pub replica_factor: u64,
    /// The version store's bytes on this disk (C30).
    pub version_store_bytes: u64,
    /// Expected above 1.25x the policy maximum.
    pub warn: bool,
    /// The warning's code, from `storage_warning_decision`.
    #[serde(skip)]
    pub warn_code: Option<&'static str>,
}

/// The accounting of `snapshot` after a GC run, for a ring of `hosts` storage hosts.
pub fn folder_stats(
    snapshot: &FolderSnapshotManifest,
    policy: &RetentionPolicy,
    report: &GcReport,
    hosts: u64,
) -> FolderStats {
    let (k, _, n) = snapshot.tier.params();
    let (k, n) = (k as u64, n as u64);
    let r = retention::replica_factor(k, n, hosts);
    let disk_bytes: u64 = snapshot.files.values().map(|f| f.size_bytes).sum();
    let expected = report
        .stored_shard_bytes
        .saturating_mul(r)
        .saturating_add(report.pending_bytes)
        .saturating_add(report.abandoned_bytes);
    let max = retention::policy_max_bytes(policy, disk_bytes, k, n, r);
    let warn_code = retention::storage_warning_decision(expected, max);
    FolderStats {
        version: snapshot.version,
        files: snapshot.files.len(),
        disk_bytes,
        versions_retained: report.versions_kept,
        keep_last: policy.keep_last,
        keep_daily: policy.keep_daily,
        keep_weekly: policy.keep_weekly,
        max_stored_bytes: policy.max_stored_bytes,
        stored_cipher_bytes: report.stored_cipher_bytes,
        expected_stored_bytes: expected,
        pending_free_bytes: report.pending_bytes,
        abandoned_bytes: report.abandoned_bytes,
        policy_max_bytes: max,
        replica_factor: r,
        version_store_bytes: report.version_store_bytes,
        warn: warn_code.is_some(),
        warn_code,
    }
}

/// `<data_dir>/folders/<first 16 hex of sha256(snapshot path)>.stats.json`.
pub fn stats_path(data_dir: &Path, snapshot_out: &Path) -> PathBuf {
    let abs = std::fs::canonicalize(snapshot_out).unwrap_or_else(|_| snapshot_out.to_path_buf());
    let h = crate::crypto::compute_sha256(abs.as_os_str().as_encoded_bytes());
    data_dir
        .join("folders")
        .join(format!("{}.stats.json", &hex::encode(h)[..16]))
}

pub fn write_stats(
    data_dir: &Path,
    snapshot_out: &Path,
    stats: &FolderStats,
) -> Result<(), GcError> {
    let path = stats_path(data_dir, snapshot_out);
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let body = serde_json::to_vec_pretty(stats).map_err(std::io::Error::other)?;
    BlockStore::atomic_write_file(&path, &body)?;
    Ok(())
}

/// Records the catalog a host acknowledged (C6).
pub fn record_published_catalog(
    snapshot_out: &Path,
    version: u64,
    ciphertext_sha256: Hash32,
) -> Result<(), GcError> {
    let paths = GcPaths::for_snapshot(snapshot_out);
    let mut j = GcJournal::load(&paths)?;
    j.published = Some(PublishedCatalog {
        version,
        ciphertext_sha256,
    });
    j.save(&paths)
}

/// The version of this store's last acknowledged catalog, if any (C6: a no-change pass
/// republishes while it lags).
pub fn published_catalog_version(snapshot_out: &Path) -> Result<Option<u64>, GcError> {
    Ok(GcJournal::load(&GcPaths::for_snapshot(snapshot_out))?
        .published
        .map(|p| p.version))
}

/// C4, checked before a pass: the snapshot file is not older than the version store.
pub fn check_snapshot_fresh(
    snapshot_out: &Path,
    snapshot_version: Option<u64>,
) -> Result<(), GcError> {
    let newest = VersionStore::for_snapshot(snapshot_out)
        .list()?
        .last()
        .map(|m| m.version);
    stale_snapshot_decision(snapshot_version, newest).map_err(|code| GcError::StaleSnapshot {
        code,
        snapshot: snapshot_version.unwrap_or(0),
        newest: newest.unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_host_maps_by_peer_id() {
        let pid = "12D3KooWQ5LDnSQSq9VXdV87F4JNArnT9HocahLHynC7h7PHrKej";
        let other = "12D3KooWF34TMAzmQHG8czvSFwEua6C3cBsZ8iVWG3jsEurRKz11";
        let mut canon = BTreeMap::new();
        canon.insert(pid.to_string(), "/ip4/172.28.1.71/tcp/4001".to_string());
        // A host's loopback alias goes to its given address.
        assert_eq!(
            canonical_host(&format!("/ip4/127.0.0.1/tcp/4001/p2p/{pid}"), &canon),
            "/ip4/172.28.1.71/tcp/4001"
        );
        // Another peer id, a plain address, and the local pseudo-host are unchanged.
        let o = format!("/ip4/127.0.0.1/tcp/4001/p2p/{other}");
        assert_eq!(canonical_host(&o, &canon), o);
        assert_eq!(
            canonical_host("/ip4/172.28.1.73/tcp/4001", &canon),
            "/ip4/172.28.1.73/tcp/4001"
        );
        assert_eq!(canonical_host(LOCAL_HOST, &canon), LOCAL_HOST);
    }

    #[test]
    fn send_candidates_try_every_address_of_the_peer_id() {
        let pid = "12D3KooWQ5LDnSQSq9VXdV87F4JNArnT9HocahLHynC7h7PHrKej";
        let other = "12D3KooWF34TMAzmQHG8czvSFwEua6C3cBsZ8iVWG3jsEurRKz11";
        let alias = format!("/ip4/127.0.0.1/tcp/4001/p2p/{pid}");
        let real = format!("/ip4/172.28.1.71/tcp/4001/p2p/{pid}");
        let lo2 = format!("/ip4/127.0.0.1/tcp/5001/p2p/{pid}");
        let foreign = format!("/ip4/172.28.1.72/tcp/4001/p2p/{other}");
        let known = vec![
            lo2.clone(),
            foreign,
            real.clone(),
            alias.clone(),
            "/ip4/172.28.1.73/tcp/4001".to_string(),
        ];
        // The alias first (it is the journalled address), then the same peer's other addresses,
        // non-loopback first; never another peer id's, never a plain address.
        assert_eq!(send_candidates(&alias, &known), vec![alias, real, lo2]);
        assert_eq!(
            send_candidates("/ip4/172.28.1.73/tcp/4001", &known),
            vec!["/ip4/172.28.1.73/tcp/4001".to_string()]
        );
    }

    #[test]
    fn decisions() {
        assert!(gc_free_decision(false, false, true));
        assert!(!gc_free_decision(true, false, true));
        assert!(!gc_free_decision(false, true, true));
        assert!(!gc_free_decision(false, false, false));
        assert!(stale_snapshot_decision(Some(3), Some(4)).is_err());
        assert!(stale_snapshot_decision(None, Some(1)).is_err());
        assert!(stale_snapshot_decision(Some(4), Some(4)).is_ok());
        assert!(stale_snapshot_decision(None, None).is_ok());
        assert_eq!(order_epoch(5, 3), 6);
        assert_eq!(order_epoch(5, 100), 100);
        assert_eq!(order_epoch(u64::MAX, 0), u64::MAX);
        assert_eq!(quota_retry_decision(true, false, true), QuotaRetry::Retry);
        assert!(matches!(
            quota_retry_decision(true, true, true),
            QuotaRetry::Spent(_)
        ));
        assert!(matches!(
            quota_retry_decision(true, false, false),
            QuotaRetry::Spent(_)
        ));
        assert_eq!(
            quota_retry_decision(false, false, true),
            QuotaRetry::NotNeeded
        );
        assert_eq!(next_retry_pass(10, 0), 11);
        assert_eq!(next_retry_pass(10, 3), 18);
        assert_eq!(next_retry_pass(10, 30), 70);
        assert_eq!(
            refusal_action("x.delete_not_shard_owner"),
            FreeAction::Abandon
        );
        assert_eq!(refusal_action("x.free_stale: 31 s"), FreeAction::ClockSkew);
        assert_eq!(
            refusal_action("reject.free_epoch_replay"),
            FreeAction::Retry
        );
        assert!(foreign_catalog_decision(Some((3, [1; 32])), 3, Some((3, [1; 32]))).is_ok());
        assert!(foreign_catalog_decision(Some((3, [1; 32])), 3, Some((3, [2; 32]))).is_err());
        assert!(foreign_catalog_decision(Some((3, [1; 32])), 9, Some((4, [1; 32]))).is_err());
        assert!(foreign_catalog_decision(None, 5, Some((5, [9; 32]))).is_ok());
        assert!(foreign_catalog_decision(None, 5, Some((6, [9; 32]))).is_err());
        assert!(foreign_catalog_decision(None, 5, None).is_ok());
    }

    /// D12: a host gets at most its budget, and the pass at most its own.
    #[test]
    fn free_budgets_bound_a_host_and_the_pass() {
        assert!(free_send_decision(0, 0));
        assert!(free_send_decision(
            FREE_HOST_BUDGET_MS - 1,
            FREE_PASS_BUDGET_MS - 1
        ));
        assert!(!free_send_decision(FREE_HOST_BUDGET_MS, 0));
        assert!(!free_send_decision(0, FREE_PASS_BUDGET_MS));
    }

    #[test]
    fn order_bytes_bind_every_field() {
        let id = ShardId {
            stripe_merkle_root: [1; 32],
            shard_index: 2,
            shard_hash: [3; 32],
        };
        let a = free_order_signing_bytes(&[9; 32], 10, 11, &[id]);
        assert!(a.starts_with(b"parvault-owner-shard-free-v2:"));
        assert_eq!(a.len(), 29 + 32 + 8 + 8 + 4 + 68);
        for b in [
            free_order_signing_bytes(&[8; 32], 10, 11, &[id]),
            free_order_signing_bytes(&[9; 32], 12, 11, &[id]),
            free_order_signing_bytes(&[9; 32], 10, 12, &[id]),
            free_order_signing_bytes(&[9; 32], 10, 11, &[id, id]),
        ] {
            assert_ne!(a, b);
        }
        let owner = NodeIdentity::from_seed([4; 32]);
        let o = sign_free_order(&owner, [9; 32], 10, 11, vec![id]);
        let sig: [u8; 64] = o.signature.as_slice().try_into().unwrap();
        assert!(NodeIdentity::verify_with_pubkey(
            &o.owner_ed25519_pubkey,
            &free_order_signing_bytes(&o.host_ed25519_pubkey, 10, 11, &o.shard_ids),
            &sig
        ));
    }

    #[test]
    fn journal_tag_and_inflight_torn_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = GcPaths::for_snapshot(&tmp.path().join("s.bin"));
        assert_eq!(GcJournal::load(&paths).unwrap(), GcJournal::default());
        let j = GcJournal {
            last_epoch: 7,
            ..Default::default()
        };
        j.save(&paths).unwrap();
        assert_eq!(GcJournal::load(&paths).unwrap().last_epoch, 7);
        let mut raw = std::fs::read(paths.journal()).unwrap();
        raw[11] = 9;
        std::fs::write(paths.journal(), &raw).unwrap();
        assert!(matches!(GcJournal::load(&paths), Err(GcError::Format(_))));

        let id = ShardId {
            stripe_merkle_root: [1; 32],
            shard_index: 0,
            shard_hash: [2; 32],
        };
        let rec = InflightStripe {
            shard_ids: vec![id],
            hosts: vec!["/ip4/127.0.0.1/tcp/1".into()],
        };
        let hook = inflight_hook(&paths);
        (hook.0)(&rec.shard_ids, &rec.hosts).unwrap();
        (hook.0)(&rec.shard_ids, &rec.hosts).unwrap();
        let mut raw = std::fs::read(paths.inflight()).unwrap();
        raw.truncate(raw.len() - 3);
        std::fs::write(paths.inflight(), &raw).unwrap();
        assert_eq!(inflight_read(&paths.inflight()).unwrap(), vec![rec]);
    }

    use crate::config::ErasureTier;
    use crate::crypto::MasterKey;
    use crate::storage::QuotaManager;
    use crate::sync::FolderSyncEngine;

    type StepFn<'a> = dyn Fn(&mut GcRun) -> Result<(), GcError> + 'a;

    fn stripes_of(s: &FolderSnapshotManifest) -> Vec<ShardId> {
        SnapshotRefs::of(s)
            .stripes
            .values()
            .flat_map(|r| r.shard_ids.clone())
            .collect()
    }

    /// C24: the journal step function, crashed after every prefix of its steps on a real
    /// directory, then run again: every retained version restores byte-identically, the journal
    /// is empty, no freed stripe is referenced by a retained version, and the dropped version's
    /// shards and manifest are gone.
    #[test]
    fn crash_after_every_step_prefix_recovers() {
        for prefix in 0..=6usize {
            let tmp = tempfile::tempdir().unwrap();
            let store = BlockStore::new(
                tmp.path().join("store"),
                QuotaManager::new(1 << 30, 1 << 20),
            )
            .unwrap();
            let folder = tmp.path().join("folder");
            std::fs::create_dir_all(&folder).unwrap();
            let snap_out = tmp.path().join("s.manifest.bin");
            let mk = MasterKey::generate();
            let id = NodeIdentity::generate();
            let mut engine =
                FolderSyncEngine::new(store.clone(), mk.clone(), id.clone(), ErasureTier::Homelab);
            let settings = GcSettings {
                snapshot_out: snap_out.clone(),
                policy: RetentionPolicy::checked(1, 0, 0, None).unwrap(),
                data_dir: tmp.path().join("store"),
                client: None,
                fetched_catalog: None,
            };
            std::fs::write(folder.join("a.txt"), b"version one").unwrap();
            let v1 = engine.sync_folder_once(&folder).unwrap();
            run_gc(&settings, &store, &id, &v1, 1).unwrap();
            std::fs::write(folder.join("a.txt"), b"version two, longer").unwrap();
            let v2 = engine.sync_folder_once(&folder).unwrap();
            assert_eq!(v2.version, 2);
            let v1_shards = stripes_of(&v1);
            assert!(v1_shards.iter().all(|s| store.has_shard(s)));

            // The crashed run: only the first `prefix` steps.
            {
                let mut run = GcRun::new(&settings, &store, &id, 2).unwrap();
                let steps: [&StepFn<'_>; 6] = [
                    &|r| r.step1_write_version(&v2),
                    &|r| r.step2_3_mark_and_journal(),
                    &|r| {
                        r.check_foreign_catalog();
                        Ok(())
                    },
                    &|r| r.step4_delete_versions_and_manifests(),
                    &|r| r.step5_free_local(),
                    &|r| r.step6_send_orders(),
                ];
                for step in steps.iter().take(prefix) {
                    step(&mut run).unwrap();
                }
            }
            // The restarted pass: nothing changed, same snapshot; GC runs whole.
            let mut engine2 =
                FolderSyncEngine::new(store.clone(), mk.clone(), id.clone(), ErasureTier::Homelab);
            engine2.load_previous_snapshot(&v2);
            let again = engine2.sync_folder_once(&folder).unwrap();
            assert!(engine2.last_pass().no_change);
            assert_eq!(again.version, 2);
            let report = run_gc(&settings, &store, &id, &again, 3).unwrap();
            let paths = GcPaths::for_snapshot(&snap_out);
            let j = GcJournal::load(&paths).unwrap();
            assert!(j.pending.is_empty(), "prefix {prefix}: {:?}", j.pending);
            assert!(j.drop_versions.is_empty() && j.drop_manifests.is_empty());
            let vs = VersionStore::for_snapshot(&snap_out);
            assert_eq!(
                vs.list()
                    .unwrap()
                    .iter()
                    .map(|m| m.version)
                    .collect::<Vec<_>>(),
                vec![2],
                "prefix {prefix}"
            );
            assert!(
                v1_shards.iter().all(|s| !store.has_shard(s)),
                "prefix {prefix}: v1 shards left"
            );
            assert!(stripes_of(&v2).iter().all(|s| store.has_shard(s)));
            let out = tmp.path().join("restored");
            engine2.restore_folder(&vs.load(2).unwrap(), &out).unwrap();
            assert_eq!(
                std::fs::read(out.join("a.txt")).unwrap(),
                b"version two, longer"
            );
            assert_eq!(report.versions_kept, 1);
        }
    }

    /// C3: a stripe a dead pass placed, that no version references, is freed from the
    /// in-flight log; a logged stripe the pass did keep is not.
    #[test]
    fn inflight_stripe_of_a_dead_pass_is_freed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlockStore::new(
            tmp.path().join("store"),
            QuotaManager::new(1 << 30, 1 << 20),
        )
        .unwrap();
        let folder = tmp.path().join("folder");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("a.txt"), b"kept").unwrap();
        let snap_out = tmp.path().join("s.manifest.bin");
        let id = NodeIdentity::generate();
        let mut engine = FolderSyncEngine::new(
            store.clone(),
            MasterKey::generate(),
            id.clone(),
            ErasureTier::Homelab,
        );
        let v1 = engine.sync_folder_once(&folder).unwrap();
        let orphan = ShardId {
            stripe_merkle_root: [0xAB; 32],
            shard_index: 0,
            shard_hash: crate::sharding::merkle::hash_shard_leaf(0, b"orphan shard"),
        };
        store
            .put_shard(&id.device_peer_id(), &orphan, b"orphan shard")
            .unwrap();
        let paths = GcPaths::for_snapshot(&snap_out);
        let hook = inflight_hook(&paths);
        (hook.0)(&[orphan], &[]).unwrap();
        (hook.0)(&stripes_of(&v1), &[]).unwrap();
        let settings = GcSettings {
            snapshot_out: snap_out.clone(),
            policy: RetentionPolicy::default(),
            data_dir: tmp.path().join("store"),
            client: None,
            fetched_catalog: None,
        };
        let r = run_gc(&settings, &store, &id, &v1, 1).unwrap();
        assert_eq!(r.stripes_garbage, 1);
        assert!(!store.has_shard(&orphan));
        assert!(stripes_of(&v1).iter().all(|s| store.has_shard(s)));
        assert!(!paths.inflight().exists());
    }

    /// The mark computation (C20: its own property test): over many generated version sets,
    /// no garbage stripe or manifest is marked, and every unmarked stripe of a dropped version
    /// is garbage.
    #[test]
    fn mark_and_sweep_property() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..500 {
            let versions = 1 + (next() % 6) as usize;
            let mut refs = Vec::new();
            for _ in 0..versions {
                let mut r = SnapshotRefs::default();
                for _ in 0..(next() % 5) {
                    let root = [(next() % 8) as u8; 32];
                    let file = [(next() % 6) as u8 + 100; 32];
                    r.file_roots.insert(file);
                    r.stripes.insert(
                        root,
                        StripeRef {
                            shard_ids: vec![],
                            shard_len: 1,
                            ciphertext_len: 1,
                            assigned_peers: vec![],
                        },
                    );
                }
                refs.push(r);
            }
            let keep: Vec<bool> = (0..versions)
                .map(|i| i == versions - 1 || next() % 2 == 0)
                .collect();
            let marks = mark(refs.iter().zip(&keep).filter(|(_, k)| **k).map(|(r, _)| r));
            let (garbage, manifests) = sweep(
                refs.iter().zip(&keep).filter(|(_, k)| !**k).map(|(r, _)| r),
                &marks,
            );
            for root in garbage.keys() {
                assert!(!marks.stripes.contains(root));
            }
            for fr in &manifests {
                assert!(!marks.file_roots.contains(fr));
            }
            for (r, k) in refs.iter().zip(&keep) {
                if *k {
                    assert!(r.stripes.keys().all(|s| !garbage.contains_key(s)));
                } else {
                    for s in r.stripes.keys() {
                        assert_eq!(garbage.contains_key(s), !marks.stripes.contains(s));
                    }
                }
            }
        }
    }

    #[test]
    fn pass_lock_is_exclusive() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = GcPaths::for_snapshot(&tmp.path().join("s.bin"));
        let held = PassLock::acquire(&paths).unwrap();
        assert!(matches!(PassLock::acquire(&paths), Err(GcError::Locked(_))));
        drop(held);
        PassLock::acquire(&paths).unwrap();
    }
}
