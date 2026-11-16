//! The PoR audit journal (B-147, G5): `por_audit_journal.bin` (tagged, atomic) holds the absolute
//! post-values of `por_passes` and `por_failures` (`quota.rs` `PeerCreditAccount`), never deltas,
//! with the auditor's own counters after the same audit; at start a value is applied only if the
//! current one is lower ([`audit_journal_apply_decision`]).
//!
//! One audit writes, in order: the journal, the quota ledger (`quota_state.bin`), the auditor
//! state (`por_audit_state.json`, which stays the readable state). A crash between any two leaves
//! a journal that brings the later files up to it on the next start, so the state and the ledger
//! agree; a replayed delta would double-credit, an absolute value cannot. An unreadable journal
//! warns and is ignored. Nothing is written without a data dir (`parvault-seed --no-fs`).
//!
//! `v0.5.6` track B1.
use crate::por::auditor::{AuditorState, MAX_AUDIT_STATE_ENTRIES};
use crate::storage::BlockStore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::warn;

/// The journal file in the data dir.
pub const AUDIT_JOURNAL_FILE: &str = "por_audit_journal.bin";

/// Tag and layout version of [`AUDIT_JOURNAL_FILE`].
const JOURNAL_MAGIC: &[u8; 8] = b"PVAJRN01";

/// A journal larger than this is not read (one entry is well under 1 KiB).
const MAX_JOURNAL_BYTES: u64 = 4096;

/// The values after the last audit, as one record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditJournalEntry {
    /// The device id the ledger credited.
    pub prover: String,
    /// The prover's `por_passes` and `por_failures` after this audit.
    pub por_passes: u64,
    pub por_failures: u64,
    /// The auditor's `passed` and `failed` after this audit.
    pub state_passed: u64,
    pub state_failed: u64,
    /// The shard file key this audit marked degraded, if any.
    pub degraded: Option<String>,
}

/// G5: a journalled post-value is applied only when the current value is lower. A value at or
/// above it already includes that audit (or a later one), so nothing is credited twice. Pure;
/// a Kani target.
pub const fn audit_journal_apply_decision(current: u64, journalled: u64) -> bool {
    journalled > current
}

/// The journal bytes of `e` (tag, then bincode).
pub fn encode_journal(e: &AuditJournalEntry) -> Option<Vec<u8>> {
    let mut out = JOURNAL_MAGIC.to_vec();
    out.extend_from_slice(&bincode::serialize(e).ok()?);
    Some(out)
}

fn decode(raw: &[u8]) -> Option<AuditJournalEntry> {
    bincode::deserialize(raw.strip_prefix(JOURNAL_MAGIC.as_slice())?).ok()
}

/// The journal in `data_dir`: `Ok(None)` when absent, `Err` when present and unreadable.
pub fn read_journal(data_dir: &Path) -> Result<Option<AuditJournalEntry>, &'static str> {
    let path = data_dir.join(AUDIT_JOURNAL_FILE);
    match std::fs::metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("warn.audit_journal_unreadable"),
        Ok(m) if m.len() > MAX_JOURNAL_BYTES => return Err("warn.audit_journal_unreadable"),
        Ok(_) => {}
    }
    let raw = std::fs::read(&path).map_err(|_| "warn.audit_journal_unreadable")?;
    decode(&raw)
        .map(Some)
        .ok_or("warn.audit_journal_unreadable")
}

/// Records one judged audit of `prover` (`passed`, or a verifiably invalid proof marking
/// `degraded`): the journal, then the ledger, then the state counters and the state file.
pub fn credit_audit(
    data_dir: Option<&Path>,
    st: &mut AuditorState,
    block_store: &BlockStore,
    prover: &str,
    passed: bool,
    degraded: Option<String>,
) {
    let quota = block_store.quota();
    let Ok(mut q) = quota.lock() else {
        return;
    };
    let acct = q.peer_account(prover).cloned().unwrap_or_default();
    let (passed_n, failed_n) = if passed {
        (st.passed.saturating_add(1), st.failed)
    } else {
        (st.passed, st.failed.saturating_add(1))
    };
    let entry = AuditJournalEntry {
        prover: prover.to_string(),
        por_passes: acct.por_passes.saturating_add(u64::from(passed)),
        por_failures: acct.por_failures.saturating_add(u64::from(!passed)),
        state_passed: passed_n,
        state_failed: failed_n,
        degraded: degraded.clone(),
    };
    if let Some(dir) = data_dir {
        let written = encode_journal(&entry).map(|raw| {
            crate::storage::fsio::atomic_write_file(&dir.join(AUDIT_JOURNAL_FILE), &raw)
        });
        if !matches!(written, Some(Ok(()))) {
            warn!(
                code = "warn.audit_journal_not_written",
                "could not write the audit journal"
            );
        }
    }
    q.record_por_outcome(prover, passed);
    drop(q);
    st.passed = passed_n;
    st.failed = failed_n;
    if let Some(key) = degraded {
        if st.degraded.len() < MAX_AUDIT_STATE_ENTRIES {
            st.degraded.insert(key);
        }
    }
    st.save_to(data_dir);
}

/// At start (the auditor's first job): brings the ledger and the state up to the journal, each
/// value only if lower ([`audit_journal_apply_decision`]). Returns whether anything changed. An
/// unreadable journal warns and is ignored.
pub fn replay_journal(data_dir: &Path, st: &mut AuditorState, block_store: &BlockStore) -> bool {
    let entry = match read_journal(data_dir) {
        Ok(Some(e)) => e,
        Ok(None) => return false,
        Err(code) => {
            warn!(code, "audit journal unreadable; ignored");
            return false;
        }
    };
    let mut changed = false;
    if let Ok(mut q) = block_store.quota().lock() {
        let acct = q.peer_account(&entry.prover).cloned().unwrap_or_default();
        let passes = audit_journal_apply_decision(acct.por_passes, entry.por_passes)
            .then_some(entry.por_passes);
        let failures = audit_journal_apply_decision(acct.por_failures, entry.por_failures)
            .then_some(entry.por_failures);
        if passes.is_some() || failures.is_some() {
            q.apply_por_post_values(&entry.prover, passes, failures);
            changed = true;
        }
    }
    if audit_journal_apply_decision(st.passed, entry.state_passed) {
        st.passed = entry.state_passed;
        changed = true;
    }
    if audit_journal_apply_decision(st.failed, entry.state_failed) {
        st.failed = entry.state_failed;
        changed = true;
    }
    if let Some(key) = entry.degraded {
        if !st.degraded.contains(&key) && st.degraded.len() < MAX_AUDIT_STATE_ENTRIES {
            st.degraded.insert(key);
            changed = true;
        }
    }
    if changed {
        tracing::info!(
            code = "info.audit_journal_replayed",
            "audit journal applied after a restart"
        );
        st.save_to(Some(data_dir));
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::QuotaManager;

    fn store(dir: &Path) -> BlockStore {
        BlockStore::new(dir, QuotaManager::new(1 << 30, 1 << 20)).unwrap()
    }

    fn totals(bs: &BlockStore, prover: &str) -> (u64, u64) {
        let q = bs.quota();
        let q = q.lock().unwrap();
        let a = q.peer_account(prover).cloned().unwrap_or_default();
        (a.por_passes, a.por_failures)
    }

    #[test]
    fn apply_decision_only_raises() {
        assert!(audit_journal_apply_decision(3, 4));
        assert!(!audit_journal_apply_decision(4, 4));
        assert!(!audit_journal_apply_decision(5, 4));
    }

    /// Every crash prefix of the three writes (none, journal, journal + ledger, all) on a real
    /// temp dir: after a restart and the replay, the state and the ledger agree, and nothing is
    /// counted twice.
    #[test]
    fn every_crash_prefix_ends_with_state_and_ledger_agreeing() {
        for prefix in 0..=3 {
            let dir = tempfile::tempdir().unwrap();
            {
                let bs = store(dir.path());
                let mut st = AuditorState::fresh();
                credit_audit(Some(dir.path()), &mut st, &bs, "p", true, None);
                credit_audit(Some(dir.path()), &mut st, &bs, "p", false, Some("k".into()));
                // The third audit, cut after `prefix` writes.
                let acct = totals(&bs, "p");
                let entry = AuditJournalEntry {
                    prover: "p".into(),
                    por_passes: acct.0 + 1,
                    por_failures: acct.1,
                    state_passed: st.passed + 1,
                    state_failed: st.failed,
                    degraded: None,
                };
                if prefix >= 1 {
                    let raw = encode_journal(&entry).unwrap();
                    std::fs::write(dir.path().join(AUDIT_JOURNAL_FILE), raw).unwrap();
                }
                if prefix >= 2 {
                    bs.quota().lock().unwrap().record_por_outcome("p", true);
                }
                if prefix >= 3 {
                    st.passed += 1;
                    st.save_to(Some(dir.path()));
                }
            }
            let bs = store(dir.path());
            let mut st = AuditorState::load(dir.path());
            replay_journal(dir.path(), &mut st, &bs);
            let (p, f) = totals(&bs, "p");
            assert_eq!((st.passed, st.failed), (p, f), "prefix {prefix}");
            let want = if prefix >= 1 { 2 } else { 1 };
            assert_eq!(
                (p, f),
                (want, 1),
                "prefix {prefix}: each audit counted once"
            );
            assert!(st.degraded.contains("k"));
            // A second replay changes nothing.
            assert!(!replay_journal(dir.path(), &mut st, &bs));
        }
    }

    #[test]
    fn unreadable_journal_is_ignored_and_no_fs_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(AUDIT_JOURNAL_FILE), b"garbage").unwrap();
        let bs = store(dir.path());
        let mut st = AuditorState::fresh();
        assert!(!replay_journal(dir.path(), &mut st, &bs));
        assert_eq!(totals(&bs, "p"), (0, 0));

        let mem = BlockStore::new_in_memory(QuotaManager::new(1 << 30, 1 << 20));
        let mut st = AuditorState::fresh();
        credit_audit(None, &mut st, &mem, "p", true, None);
        assert_eq!(st.passed, 1);
        assert_eq!(totals(&mem, "p"), (1, 0));
    }
}
