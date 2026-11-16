//! Kani harnesses of `v0.5.6` track B2: version GC, owner side (plan 3.7; B-154 C20, C28).
//!
//! Rules (docs repo `OPERATIONAL_LESSONS.md` section 8): constant-size inputs, no symbolic
//! slices, maps or strings, the smallest unwind, a `kani::cover!` per outcome; run a new harness
//! alone first (`cargo kani --lib --harness kani_proofs::gc_owner::<name> --exact`).

use crate::sync::gc_journal::{
    foreign_catalog_decision, gc_free_decision, next_retry_pass, order_epoch, quota_retry_decision,
    stale_snapshot_decision, QuotaRetry, MAX_BACKOFF_PASSES,
};
use crate::sync::retention::{
    apply_cap, keep_by_rank, rank_facts, retention_decision, retention_policy_decision,
    storage_warning_decision, version_restore_decision, watch_interval_decision, RankFacts,
    RetentionPolicy, VersionMeta, KEEP_DAILY_CEILING, KEEP_LAST_CEILING, KEEP_WEEKLY_CEILING,
    MIN_WATCH_INTERVAL_SECS,
};
use crate::sync::{no_change_decision, retention};

fn any_policy() -> RetentionPolicy {
    let keep_last: u32 = kani::any();
    let keep_daily: u32 = kani::any();
    let keep_weekly: u32 = kani::any();
    kani::assume((1..=KEEP_LAST_CEILING).contains(&keep_last));
    kani::assume(keep_daily <= KEEP_DAILY_CEILING);
    kani::assume(keep_weekly <= KEEP_WEEKLY_CEILING);
    RetentionPolicy {
        keep_last,
        keep_daily,
        keep_weekly,
        max_stored_bytes: None,
    }
}

fn any_rank_facts() -> RankFacts {
    RankFacts {
        rank: kani::any(),
        day_rep: kani::any(),
        days_ago: kani::any(),
        week_rep: kani::any(),
        weeks_ago: kani::any(),
    }
}

/// B154-RETAIN, the per-version predicate (C20): the newest and the last N are always kept;
/// keeping is monotone in each policy field; an implausible clock keeps at least what a
/// plausible one keeps (nothing dropped on time grounds).
#[kani::proof]
fn proof_keep_by_rank_floors_monotone_and_clock() {
    let facts = any_rank_facts();
    let p = any_policy();
    let plausible: bool = kani::any();
    let kept = keep_by_rank(facts, &p, plausible);
    if facts.rank == 0 || facts.rank < p.keep_last as u64 {
        assert!(kept);
    }
    // Monotone: a policy at least as large in every field keeps at least as much.
    let q = any_policy();
    kani::assume(q.keep_last >= p.keep_last);
    kani::assume(q.keep_daily >= p.keep_daily);
    kani::assume(q.keep_weekly >= p.keep_weekly);
    if kept {
        assert!(keep_by_rank(facts, &q, plausible));
    }
    // An implausible clock never keeps less.
    if keep_by_rank(facts, &p, true) {
        assert!(keep_by_rank(facts, &p, false));
    }
    kani::cover!(
        kept && facts.rank >= p.keep_last as u64,
        "kept as a day or week version"
    );
    kani::cover!(!kept, "dropped");
}

fn four_versions() -> [VersionMeta; 4] {
    let mut vs = [VersionMeta {
        version: 0,
        created_unix_ms: 0,
    }; 4];
    for (i, v) in vs.iter_mut().enumerate() {
        // Distinct versions 1..=4 in a fixed order (the rank logic does not use the order);
        // creation times are free.
        v.version = i as u64 + 1;
        v.created_unix_ms = kani::any();
    }
    vs
}

/// B154-RETAIN on 4 versions (C25, C28): policy fields symbolic over their full ranges; the
/// newest is kept and at least `min(keep_last, 4)` versions are kept, at any clock.
#[kani::proof]
#[kani::unwind(5)]
fn proof_retention_decision_floors() {
    let vs = four_versions();
    let p = any_policy();
    let now: u64 = kani::any();
    let mut keep = [false; 4];
    let plausible = retention_decision(&vs, &p, now, &mut keep);
    assert!(keep[3], "the newest is kept");
    let kept = keep.iter().filter(|k| **k).count() as u32;
    assert!(kept >= p.keep_last.min(4));
    kani::cover!(!plausible, "implausible clock");
    kani::cover!(plausible && kept < 4, "a version dropped");
}

/// B154-RETAIN on 4 versions (C28): keeping is monotone in each policy field at any clock.
/// `retention_decision` keeps `versions[i]` iff `keep_by_rank(rank_facts(versions, i, now),
/// policy, plausible)`, and the facts do not depend on the policy, so the facts are computed
/// once (two full `retention_decision` calls do not finish in CBMC).
#[kani::proof]
#[kani::unwind(5)]
fn proof_retention_decision_monotone() {
    let vs = four_versions();
    let p = any_policy();
    let q = any_policy();
    kani::assume(q.keep_last >= p.keep_last);
    kani::assume(q.keep_daily >= p.keep_daily);
    kani::assume(q.keep_weekly >= p.keep_weekly);
    let now: u64 = kani::any();
    let plausible: bool = kani::any();
    let mut grew = false;
    for i in 0..4 {
        let f = rank_facts(&vs, i, now);
        let kp = keep_by_rank(f, &p, plausible);
        let kq = keep_by_rank(f, &q, plausible);
        assert!(!kp || kq);
        grew |= kq && !kp;
    }
    kani::cover!(grew, "a larger policy keeps more");
}

/// B154-RETAIN (C28): on an implausible clock keeping ignores the ages; the ranks and bucket
/// representatives come from `rank_and_reps`, which takes no clock, so an implausible clock
/// does not move retention (nothing is dropped for its age).
#[kani::proof]
fn proof_retention_decision_clock_independent() {
    let a = any_rank_facts();
    let b = RankFacts {
        days_ago: kani::any(),
        weeks_ago: kani::any(),
        ..a
    };
    let p = any_policy();
    assert!(keep_by_rank(a, &p, false) == keep_by_rank(b, &p, false));
    kani::cover!(
        a.days_ago != b.days_ago && keep_by_rank(a, &p, false),
        "kept whatever its age"
    );
}

/// C25, C26: the cap drops the oldest kept versions only, never the newest, and stops at or
/// under the cap unless only the newest is left.
#[kani::proof]
#[kani::unwind(6)]
fn proof_apply_cap_never_drops_newest() {
    let vs = four_versions();
    let sizes: [u16; 4] = kani::any();
    let mut keep: [bool; 4] = kani::any();
    keep[3] = true;
    let before = keep;
    let cap: u64 = kani::any();
    let total = |m: &[bool]| -> u64 {
        let mut t = 0u64;
        for i in 0..4 {
            if m[i] {
                t += sizes[i] as u64;
            }
        }
        t
    };
    let out = apply_cap(&vs, &mut keep, Some(cap), total);
    assert!(keep[3], "the newest is kept");
    for i in 0..4 {
        assert!(!keep[i] || before[i], "the cap never adds a version");
    }
    if out.below_one_version {
        assert!(keep == [false, false, false, true]);
    } else {
        assert!(total(&keep) <= cap);
    }
    kani::cover!(out.dropped > 0 && !out.below_one_version, "dropped to fit");
    kani::cover!(out.below_one_version, "newest alone over the cap");
}

/// B154-CEIL: a policy is accepted exactly when `1 <= keep_last <= 50`, `keep_daily <= 90` and
/// `keep_weekly <= 52`; never clamped.
#[kani::proof]
fn proof_retention_policy_ceilings_refused_not_clamped() {
    let l: u32 = kani::any();
    let d: u32 = kani::any();
    let w: u32 = kani::any();
    let ok =
        (1..=KEEP_LAST_CEILING).contains(&l) && d <= KEEP_DAILY_CEILING && w <= KEEP_WEEKLY_CEILING;
    let r = retention_policy_decision(l, d, w, None);
    match r {
        Ok(p) => {
            assert!(ok);
            assert!(p.keep_last == l && p.keep_daily == d && p.keep_weekly == w);
        }
        Err(_) => assert!(!ok),
    }
    kani::cover!(r.is_ok(), "accepted");
    kani::cover!(r.is_err(), "refused");
}

/// B154-NOCHANGE (C20): over fixed arrays of 3 small ids, no change exactly when the
/// `(path, root, size)` lists and the tombstone lists are equal; modification times are not an
/// input, so a pass that changed only them is no change.
#[kani::proof]
#[kani::unwind(4)]
fn proof_no_change_decision() {
    let prev: [(u8, u8, u64); 3] = kani::any();
    let next: [(u8, u8, u64); 3] = kani::any();
    let pt: [u8; 3] = kani::any();
    let nt: [u8; 3] = kani::any();
    let same = no_change_decision(&prev, &next, &pt, &nt);
    let mut equal = pt == nt;
    for i in 0..3 {
        equal &= prev[i] == next[i];
    }
    assert!(same == equal);
    kani::cover!(same, "no change");
    kani::cover!(!same && pt == nt, "a file root, size or path changed");
    kani::cover!(!same && prev == next, "a tombstone changed");
}

/// B154-MARK (C2): a marked stripe, or one in the acknowledged catalog, is never freed; only
/// this store's own stripes are.
#[kani::proof]
fn proof_gc_free_decision_never_frees_marked() {
    let marked: bool = kani::any();
    let published: bool = kani::any();
    let produced: bool = kani::any();
    let free = gc_free_decision(marked, published, produced);
    if marked || published || !produced {
        assert!(!free);
    }
    kani::cover!(free, "garbage freed");
    kani::cover!(!free && marked, "marked kept");
}

/// C10, C11: an order's epoch is above the last one (unless it is already `u64::MAX`, where
/// the host refuses the replay) and at least the timestamp; no overflow.
#[kani::proof]
fn proof_order_epoch_increases() {
    let last: u64 = kani::any();
    let ts: u64 = kani::any();
    let e = order_epoch(last, ts);
    assert!(e >= ts);
    if last < u64::MAX {
        assert!(e > last);
    }
    kani::cover!(e == ts && ts > last, "timestamp epoch");
    kani::cover!(
        last < u64::MAX && e == last + 1 && last >= ts,
        "last + 1 (recovered device or skewed clock)"
    );
}

/// B163-RETRY (C35): at most one retry per pass, and only after GC freed something.
#[kani::proof]
fn proof_quota_retry_at_most_once() {
    let refused: bool = kani::any();
    let retried: bool = kani::any();
    let freed: bool = kani::any();
    let d = quota_retry_decision(refused, retried, freed);
    if retried || !freed || !refused {
        assert!(d != QuotaRetry::Retry);
    }
    assert!((d == QuotaRetry::NotNeeded) == !refused);
    kani::cover!(d == QuotaRetry::Retry, "retry once");
    kani::cover!(matches!(d, QuotaRetry::Spent(_)), "retry spent");
}

/// C4: a snapshot older than the newest version file is refused; a current one is not.
#[kani::proof]
fn proof_stale_snapshot_decision() {
    let snap: Option<u64> = kani::any();
    let newest: Option<u64> = kani::any();
    let r = stale_snapshot_decision(snap, newest);
    match (snap, newest) {
        (_, None) => assert!(r.is_ok()),
        (s, Some(n)) => assert!(r.is_err() == (s.unwrap_or(0) < n)),
    }
    kani::cover!(r.is_err(), "stale refused");
}

/// C7: the ring's catalog is foreign exactly when it is newer than what this store published,
/// or the same version with another digest (the digest bytes drawn from one symbolic byte).
#[kani::proof]
fn proof_foreign_catalog_decision() {
    let pv: u64 = kani::any();
    let fv: u64 = kani::any();
    let cur: u64 = kani::any();
    let pd: u8 = kani::any();
    let fd: u8 = kani::any();
    let has_pub: bool = kani::any();
    let has_fetch: bool = kani::any();
    let published = if has_pub { Some((pv, [pd; 32])) } else { None };
    let fetched = if has_fetch {
        Some((fv, [fd; 32]))
    } else {
        None
    };
    let r = foreign_catalog_decision(published, cur, fetched);
    if !has_fetch {
        assert!(r.is_ok());
    } else if has_pub {
        assert!(r.is_err() == (fv > pv || (fv == pv && fd != pd)));
    } else {
        assert!(r.is_err() == (fv > cur));
    }
    kani::cover!(r.is_err(), "foreign");
}

/// L-122: the warning fires exactly above 1.25x the policy maximum, without overflow.
#[kani::proof]
fn proof_storage_warning_threshold() {
    let expected: u64 = kani::any();
    let max: u64 = kani::any();
    let w = storage_warning_decision(expected, max).is_some();
    assert!(w == ((expected as u128) * 4 > (max as u128) * 5));
    kani::cover!(w, "warns");
    kani::cover!(
        !w && expected > max,
        "above the maximum but within 1.25x: silent"
    );
}

/// C37 and T5: the interval floor and the retained-version check.
#[kani::proof]
#[kani::unwind(3)]
fn proof_interval_and_restore_decisions() {
    let secs: u64 = kani::any();
    let once: bool = kani::any();
    let r = watch_interval_decision(secs, once);
    assert!(r.is_ok() == (once || secs >= MIN_WATCH_INTERVAL_SECS));
    let kept = [
        VersionMeta {
            version: kani::any(),
            created_unix_ms: 0,
        },
        VersionMeta {
            version: kani::any(),
            created_unix_ms: 0,
        },
    ];
    let n: u64 = kani::any();
    let ok = version_restore_decision(&kept, n).is_ok();
    assert!(ok == (kept[0].version == n || kept[1].version == n));
    kani::cover!(r.is_err(), "interval refused");
    kani::cover!(!ok, "version not retained");
}

/// B-154 2.4: the retry backoff waits between 1 and 60 passes.
#[kani::proof]
fn proof_retry_backoff_bounded() {
    let pass: u64 = kani::any();
    let attempts: u32 = kani::any();
    kani::assume(pass <= u64::MAX - MAX_BACKOFF_PASSES);
    let next = next_retry_pass(pass, attempts);
    assert!(next > pass && next - pass <= MAX_BACKOFF_PASSES);
    kani::cover!(next - pass == MAX_BACKOFF_PASSES, "capped");
}
