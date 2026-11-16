//! B-59 change 9 (F-06, seed half): the seed's index of the lite stripes it fanned out, the
//! only long-running holder of their chunk roots. One [`LiteAuditRecord`] per stripe names, for
//! each shard that a mesh host acknowledged, the host, the shard id and its chunk root. The
//! seed's auditor ([`crate::por::auditor::AuditSource::LiteIndex`]) samples it as the owner
//! daemon samples its manifests.
//!
//! Bounds (verdict change 9):
//! - In bytes, [`LITE_AUDIT_INDEX_MAX_BYTES`], well under the seed's default 64 MiB memory mode.
//! - Each lite client gets a share: when the index is full, the oldest record of the client
//!   holding the most bytes is dropped, so one client cannot push everyone else's stripes out of
//!   auditing. A dropped record is dropped from auditing only (this is not a security cache);
//!   [`LiteAuditIndex::dropped`] counts them.
//! - Under `--no-fs` it lives in RAM only (ADR-30 creates no files). Otherwise it is written
//!   atomically with a version header (ADR-19) to [`LITE_AUDIT_INDEX_FILE`] in the data dir, not
//!   on every insert: an insert marks the index dirty and [`flush`] writes it, encoding under
//!   the lock and writing (with its fsync) after the lock is released. The seed flushes every
//!   minute and on shutdown, so a crash loses at most a minute of index entries (audit coverage,
//!   never a verdict). [`load`](LiteAuditIndex::load) reads at most [`LITE_AUDIT_INDEX_MAX_FILE`].
//!   A missing file starts an empty index. A file that exists but cannot be read, decoded or
//!   carries another version is refused, never treated as empty (B-52 rule): the seed then
//!   runs without lite audits and leaves the file untouched for the operator.
//!
//! The seed's audit results stay on the seed (L-29).
use crate::storage::ShardId;
use rand::{rngs::OsRng, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use tracing::warn;

/// The index's file in the seed's data dir.
pub const LITE_AUDIT_INDEX_FILE: &str = "lite_audit_index.bin";
/// The byte bound (estimated record sizes, see [`LiteAuditRecord::cost`]).
pub const LITE_AUDIT_INDEX_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Version 2 (B-113) adds [`LiteAuditRecord::unwitnessed`]; a version 1 file loads with every
/// record unwitnessed (its lite clients named no seed witness).
const LITE_AUDIT_INDEX_VERSION: u32 = 2;
const LITE_AUDIT_INDEX_VERSION_V1: u32 = 1;
/// The largest index file `load` reads (the encoding is below the charged cost; twice the byte
/// bound leaves room for the header).
pub const LITE_AUDIT_INDEX_MAX_FILE: u64 = 2 * LITE_AUDIT_INDEX_MAX_BYTES as u64;

/// One shard to audit: its host, id, length and chunk root, as a local manifest or the lite
/// index names it. Defined here, outside the `daemon-runtime` gate, because the seed's
/// fan-out records into the index in every build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTarget {
    pub host_addr: String,
    pub shard_id: ShardId,
    pub shard_len: u64,
    pub chunk_root: [u8; 32],
}

/// One shard of a lite stripe on one mesh host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiteAuditShard {
    pub shard_index: u32,
    pub shard_hash: [u8; 32],
    pub chunk_root: [u8; 32],
    pub host_addr: String,
}

/// One lite stripe the seed fanned out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiteAuditRecord {
    /// The lite client's device id (the share key).
    pub client: String,
    pub stripe_merkle_root: [u8; 32],
    pub shard_len: u64,
    pub shards: Vec<LiteAuditShard>,
    /// B-113 (A-113 §10.3): the lite client's grant does not name this seed as a witness (a
    /// pre-upgrade client), so the hosts refuse the seed's audits. The seed's auditor skips the
    /// record and counts it until a re-syndication with a witness grant replaces it.
    pub unwitnessed: bool,
}

/// A version 1 record (before B-113).
#[derive(Deserialize)]
struct LiteAuditRecordV1 {
    client: String,
    stripe_merkle_root: [u8; 32],
    shard_len: u64,
    shards: Vec<LiteAuditShard>,
}

#[derive(Deserialize)]
struct OnDiskV1 {
    /// Read from the header before decoding; bincode still needs the field for the layout.
    _version: u32,
    dropped: u64,
    records: Vec<LiteAuditRecordV1>,
}

impl LiteAuditRecord {
    /// Bytes this record is charged: its fixed fields and every shard's.
    pub fn cost(&self) -> usize {
        let shards: usize = self
            .shards
            .iter()
            .map(|s| 4 + 32 + 32 + s.host_addr.len() + 24)
            .sum();
        self.client.len() + 32 + 8 + 48 + shards
    }

    fn targets(&self) -> impl Iterator<Item = AuditTarget> + '_ {
        self.shards.iter().map(|s| AuditTarget {
            host_addr: s.host_addr.clone(),
            shard_id: ShardId {
                stripe_merkle_root: self.stripe_merkle_root,
                shard_index: s.shard_index,
                shard_hash: s.shard_hash,
            },
            shard_len: self.shard_len,
            chunk_root: s.chunk_root,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct OnDisk {
    version: u32,
    dropped: u64,
    records: Vec<LiteAuditRecord>,
}

/// The bounded index. RAM, mirrored to [`LITE_AUDIT_INDEX_FILE`] unless `--no-fs`.
#[derive(Debug, Default)]
pub struct LiteAuditIndex {
    records: VecDeque<LiteAuditRecord>,
    bytes: usize,
    per_client: BTreeMap<String, usize>,
    max_bytes: usize,
    /// Records dropped from auditing by the byte bound.
    pub dropped: u64,
    path: Option<PathBuf>,
    /// Changed since the last write.
    dirty: bool,
    /// Files written (P2: bounded by flushes, not by inserts).
    pub writes: u64,
}

impl LiteAuditIndex {
    /// An empty index held in RAM only (`--no-fs`).
    pub fn in_memory() -> Self {
        Self::with_max_bytes(LITE_AUDIT_INDEX_MAX_BYTES)
    }

    /// An empty RAM index with another byte bound (tests).
    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            ..Self::default()
        }
    }

    /// Loads the index from `data_dir` (empty when the file is missing). Later inserts are
    /// written there. A file that exists but does not read, decode, or carry this version is
    /// refused with its reject code and left as it is.
    pub fn load(data_dir: &Path) -> Result<Self, &'static str> {
        let path = data_dir.join(LITE_AUDIT_INDEX_FILE);
        let mut idx = Self::in_memory();
        match read_bounded(&path, LITE_AUDIT_INDEX_MAX_FILE) {
            Ok(None) => return Err("reject.lite_audit_index_oversized"),
            Ok(Some(raw)) => {
                let version = raw
                    .get(..4)
                    .and_then(|b| <[u8; 4]>::try_from(b).ok())
                    .map(u32::from_le_bytes)
                    .ok_or("reject.lite_audit_index_corrupt")?;
                match version {
                    LITE_AUDIT_INDEX_VERSION => {
                        let d = bincode::deserialize::<OnDisk>(&raw)
                            .map_err(|_| "reject.lite_audit_index_corrupt")?;
                        idx.dropped = d.dropped;
                        for r in d.records {
                            idx.push(r);
                        }
                    }
                    LITE_AUDIT_INDEX_VERSION_V1 => {
                        let d = bincode::deserialize::<OnDiskV1>(&raw)
                            .map_err(|_| "reject.lite_audit_index_corrupt")?;
                        idx.dropped = d.dropped;
                        for r in d.records {
                            idx.push(LiteAuditRecord {
                                client: r.client,
                                stripe_merkle_root: r.stripe_merkle_root,
                                shard_len: r.shard_len,
                                shards: r.shards,
                                unwitnessed: true,
                            });
                        }
                        // Rewritten as version 2 on the next flush.
                        idx.dirty = true;
                    }
                    _ => return Err("reject.lite_audit_index_version"),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("reject.lite_audit_index_unreadable"),
        }
        idx.path = Some(path);
        Ok(idx)
    }

    /// Stripes indexed.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Bytes charged.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    fn push(&mut self, r: LiteAuditRecord) {
        let c = r.cost();
        self.bytes += c;
        *self.per_client.entry(r.client.clone()).or_default() += c;
        self.records.push_back(r);
        while self.bytes > self.max_bytes && !self.records.is_empty() {
            self.evict_one();
        }
    }

    /// Drops the oldest record of the client holding the most bytes.
    fn evict_one(&mut self) {
        let Some(heaviest) = self
            .per_client
            .iter()
            .max_by_key(|(_, b)| **b)
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        let Some(pos) = self.records.iter().position(|r| r.client == heaviest) else {
            return;
        };
        if let Some(r) = self.records.remove(pos) {
            self.uncharge(&r);
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    fn uncharge(&mut self, r: &LiteAuditRecord) {
        let c = r.cost();
        self.bytes = self.bytes.saturating_sub(c);
        if let Some(b) = self.per_client.get_mut(&r.client) {
            *b = b.saturating_sub(c);
            if *b == 0 {
                self.per_client.remove(&r.client);
            }
        }
    }

    /// Adds (or replaces, for a re-syndicated stripe) a record, then writes the file when the
    /// index has one. A record with no shards is ignored.
    pub fn insert(&mut self, r: LiteAuditRecord) {
        if r.shards.is_empty() {
            return;
        }
        if let Some(pos) = self
            .records
            .iter()
            .position(|o| o.stripe_merkle_root == r.stripe_merkle_root && o.client == r.client)
        {
            if let Some(old) = self.records.remove(pos) {
                self.uncharge(&old);
            }
        }
        self.push(r);
        self.dirty = true;
    }

    /// C17 (B-154): removes the record of `stripe_merkle_root` fanned out for `client` (the key
    /// is root plus client, as [`Self::insert`]), when that client's owner frees the stripe on
    /// the seed. Another client's record of the same root is never touched. Returns whether a
    /// record was removed; the file is written on the next [`flush`].
    pub fn remove_stripe(&mut self, stripe_merkle_root: &[u8; 32], client: &str) -> bool {
        let Some(pos) = self
            .records
            .iter()
            .position(|o| o.stripe_merkle_root == *stripe_merkle_root && o.client == client)
        else {
            return false;
        };
        if let Some(old) = self.records.remove(pos) {
            self.uncharge(&old);
        }
        self.dirty = true;
        true
    }

    /// The encoded index and its path when it has a file and changed since the last write;
    /// clears the dirty mark (a failed write sets it again, see [`flush`]).
    fn take_snapshot(&mut self) -> Option<(PathBuf, Vec<u8>)> {
        if !self.dirty {
            return None;
        }
        let path = self.path.clone()?;
        let d = OnDisk {
            version: LITE_AUDIT_INDEX_VERSION,
            dropped: self.dropped,
            records: self.records.iter().cloned().collect(),
        };
        match bincode::serialize(&d) {
            Ok(bytes) => {
                self.dirty = false;
                self.writes = self.writes.saturating_add(1);
                Some((path, bytes))
            }
            Err(e) => {
                warn!(error = %e, "could not encode the lite audit index");
                None
            }
        }
    }

    /// Records the seed cannot audit because their grant names no seed witness (B-113).
    pub fn unwitnessed_count(&self) -> usize {
        self.records.iter().filter(|r| r.unwitnessed).count()
    }

    /// The auditable shards of up to `k` random records (the bounded scan; RAM only, no decrypt).
    /// Unwitnessed records are skipped: no challenge is sent for them (B-113).
    pub fn sample_targets(&self, k: usize) -> Vec<AuditTarget> {
        let mut picks: Vec<&LiteAuditRecord> =
            self.records.iter().filter(|r| !r.unwitnessed).collect();
        picks.shuffle(&mut OsRng);
        picks
            .into_iter()
            .take(k)
            .flat_map(LiteAuditRecord::targets)
            .collect()
    }
}

/// P2: writes the index if it changed, atomically. The lock is held only to encode; the write
/// and its fsync run after it is released, so audits and fan-outs never wait on the disk.
/// Blocking: call off the async runtime.
pub fn flush(index: &std::sync::Mutex<LiteAuditIndex>) {
    let snap = index
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take_snapshot();
    let Some((path, bytes)) = snap else {
        return;
    };
    if let Err(e) = crate::storage::fsio::atomic_write_file(&path, &bytes) {
        warn!(error = %e, "could not write the lite audit index; retrying at the next flush");
        index.lock().unwrap_or_else(|p| p.into_inner()).dirty = true;
    }
}

/// The file's bytes, `None` when it is longer than `max`, without reading past `max + 1`.
fn read_bounded(path: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::fs::File::open(path)?
        .take(max.saturating_add(1))
        .read_to_end(&mut buf)?;
    Ok((buf.len() as u64 <= max).then_some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(client: &str, root: u8, hosts: usize) -> LiteAuditRecord {
        LiteAuditRecord {
            client: client.into(),
            stripe_merkle_root: [root; 32],
            shard_len: 9_000,
            shards: (0..hosts)
                .map(|i| LiteAuditShard {
                    shard_index: i as u32,
                    shard_hash: [i as u8; 32],
                    chunk_root: [7; 32],
                    host_addr: format!("/ip4/127.0.0.1/tcp/{}", 4000 + i),
                })
                .collect(),
            unwitnessed: false,
        }
    }

    /// B-113: a version 1 file loads with every record unwitnessed, and the sampler skips
    /// unwitnessed records; a re-syndicated (witnessed) record replaces one and clears it.
    #[test]
    fn v1_records_load_unwitnessed_and_are_not_sampled() {
        #[derive(Serialize)]
        struct V1Rec {
            client: String,
            stripe_merkle_root: [u8; 32],
            shard_len: u64,
            shards: Vec<LiteAuditShard>,
        }
        #[derive(Serialize)]
        struct V1 {
            version: u32,
            dropped: u64,
            records: Vec<V1Rec>,
        }
        let r = rec("a", 1, 2);
        let raw = bincode::serialize(&V1 {
            version: 1,
            dropped: 3,
            records: vec![V1Rec {
                client: r.client.clone(),
                stripe_merkle_root: r.stripe_merkle_root,
                shard_len: r.shard_len,
                shards: r.shards.clone(),
            }],
        })
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LITE_AUDIT_INDEX_FILE), raw).unwrap();
        let mut idx = LiteAuditIndex::load(dir.path()).unwrap();
        assert_eq!((idx.len(), idx.dropped, idx.unwitnessed_count()), (1, 3, 1));
        assert!(idx.sample_targets(10).is_empty());
        idx.insert(r);
        assert_eq!(idx.unwitnessed_count(), 0);
        assert_eq!(idx.sample_targets(10).len(), 2);
    }

    #[test]
    fn round_trips_through_the_file_and_refuses_other_versions() {
        let dir = tempfile::tempdir().unwrap();
        let idx = std::sync::Mutex::new(LiteAuditIndex::load(dir.path()).unwrap());
        idx.lock().unwrap().insert(rec("a", 1, 3));
        idx.lock().unwrap().insert(rec("a", 1, 2)); // re-syndication replaces
        idx.lock().unwrap().insert(rec("b", 2, 1));
        flush(&idx);
        let idx = idx.into_inner().unwrap();
        let again = LiteAuditIndex::load(dir.path()).unwrap();
        assert_eq!(again.len(), 2);
        assert_eq!(again.bytes(), idx.bytes());
        assert_eq!(again.sample_targets(10).len(), 3);
        let bad = bincode::serialize(&OnDisk {
            version: 9,
            dropped: 0,
            records: vec![rec("a", 1, 1)],
        })
        .unwrap();
        let file = dir.path().join(LITE_AUDIT_INDEX_FILE);
        std::fs::write(&file, &bad).unwrap();
        assert_eq!(
            LiteAuditIndex::load(dir.path()).err(),
            Some("reject.lite_audit_index_version")
        );
        std::fs::write(&file, b"\x01").unwrap();
        assert_eq!(
            LiteAuditIndex::load(dir.path()).err(),
            Some("reject.lite_audit_index_corrupt")
        );
        assert_eq!(
            std::fs::read(&file).unwrap(),
            b"\x01",
            "the refused file is kept"
        );
    }

    /// P2: a burst of inserts writes nothing until a flush, and a flush writes once; a flush
    /// with nothing new writes nothing.
    #[test]
    fn a_burst_of_inserts_does_bounded_writes() {
        let dir = tempfile::tempdir().unwrap();
        let idx = std::sync::Mutex::new(LiteAuditIndex::load(dir.path()).unwrap());
        for r in 0..200u8 {
            idx.lock().unwrap().insert(rec("a", r, 4));
        }
        let file = dir.path().join(LITE_AUDIT_INDEX_FILE);
        assert!(!file.exists(), "an insert wrote the file");
        flush(&idx);
        flush(&idx);
        assert_eq!(idx.lock().unwrap().writes, 1);
        assert_eq!(LiteAuditIndex::load(dir.path()).unwrap().len(), 200);
    }

    #[test]
    fn oversized_file_is_refused_unread() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(LITE_AUDIT_INDEX_FILE);
        std::fs::write(&file, vec![0u8; LITE_AUDIT_INDEX_MAX_FILE as usize + 1]).unwrap();
        assert_eq!(
            LiteAuditIndex::load(dir.path()).err(),
            Some("reject.lite_audit_index_oversized")
        );
        assert!(file.exists(), "the refused file is kept");
    }

    #[test]
    fn in_memory_index_writes_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let idx = std::sync::Mutex::new(LiteAuditIndex::in_memory());
        idx.lock().unwrap().insert(rec("a", 1, 3));
        flush(&idx);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let idx = idx.into_inner().unwrap();
        assert_eq!(idx.len(), 1);
    }

    /// Verdict change 9: one client cannot push another's stripes out of auditing.
    #[test]
    fn a_heavy_client_evicts_only_its_own_records() {
        let one = rec("heavy", 0, 4).cost();
        let mut idx = LiteAuditIndex::with_max_bytes(one * 10);
        idx.insert(rec("light", 200, 4));
        idx.insert(rec("light", 201, 4));
        for r in 0..50u8 {
            idx.insert(rec("heavy", r, 4));
        }
        assert!(idx.bytes() <= one * 10);
        let light = idx.records.iter().filter(|r| r.client == "light").count();
        assert_eq!(light, 2, "the light client's stripes stay audited");
        assert_eq!(idx.dropped, 42);
        // The oldest heavy records went first.
        assert!(idx
            .records
            .iter()
            .filter(|r| r.client == "heavy")
            .all(|r| r.stripe_merkle_root[0] >= 42));
    }

    /// C17: a free removes only the signer's own record of the root.
    #[test]
    fn remove_stripe_is_keyed_by_root_and_client() {
        let mut idx = LiteAuditIndex::in_memory();
        idx.insert(rec("alice", 1, 2));
        idx.insert(rec("bob", 1, 2));
        let before = idx.bytes();
        assert!(!idx.remove_stripe(&[1; 32], "mallory"));
        assert!(idx.remove_stripe(&[1; 32], "alice"));
        assert!(!idx.remove_stripe(&[1; 32], "alice"));
        assert_eq!(idx.len(), 1);
        assert!(idx.bytes() < before);
        assert_eq!(idx.records[0].client, "bob");
    }
}
