//! Kani harnesses of `v0.5.6` track B1: version GC, host side (plan 3.7, 3.8 a).
//!
//! Rules (docs repo `OPERATIONAL_LESSONS.md` section 8): constant-size inputs, no symbolic
//! slices, maps or strings, the smallest unwind, a `kani::cover!` per outcome; run a new harness
//! alone first (`cargo kani --lib --harness kani_proofs::gc_host::<name> --exact`).

/// B154-FREE (B-158, C12): an order is admitted only when every fact holds. (The code per failed
/// fact, in check order, is the unit test `free_order_decision_needs_every_fact_in_order`; string
/// equality is kept out of the solver, `OPERATIONAL_LESSONS.md` 8.2.)
#[kani::proof]
fn proof_free_order_needs_every_fact() {
    let f = crate::por::verifier::FreeOrderFacts {
        shape_ok: kani::any(),
        host_matches: kani::any(),
        fresh: kani::any(),
        signature_valid: kani::any(),
        epoch_state_ok: kani::any(),
        epoch_advances: kani::any(),
    };
    let d = crate::por::verifier::free_order_decision(&f);
    kani::cover!(d.is_ok(), "free order admitted");
    kani::cover!(d.is_err(), "free order refused");
    let all = f.shape_ok
        && f.host_matches
        && f.fresh
        && f.signature_valid
        && f.epoch_state_ok
        && f.epoch_advances;
    assert_eq!(d.is_ok(), all);
}

/// B158-FRESH: a delete token is fresh exactly within 30 s either side of now, with no overflow
/// at the ends of the `u64` range.
#[kani::proof]
fn proof_delete_freshness_window() {
    let ts: u64 = kani::any();
    let now: u64 = kani::any();
    let d = crate::por::verifier::delete_freshness_decision(ts, now);
    kani::cover!(d.is_ok(), "delete token fresh");
    kani::cover!(d.is_err(), "delete token stale");
    let gap = if ts > now { ts - now } else { now - ts };
    assert_eq!(d.is_ok(), gap <= crate::por::verifier::DELETE_TOKEN_SKEW_MS);
}

/// B147-JOURNAL (G5): a journalled post-value is applied only when it is above the current one,
/// so a replay never lowers a counter and applying it twice is the same as once.
#[kani::proof]
fn proof_audit_journal_apply_decision() {
    let current: u8 = kani::any();
    let journalled: u8 = kani::any();
    let (c, j) = (u64::from(current), u64::from(journalled));
    let raise = crate::por::audit_journal::audit_journal_apply_decision(c, j);
    kani::cover!(raise.is_some(), "journal applied");
    kani::cover!(raise.is_none(), "journal ignored");
    let after = c + raise.unwrap_or(0);
    assert!(after >= c);
    assert!(after >= j);
    assert!(raise.is_none() || after == j);
    assert!(crate::por::audit_journal::audit_journal_apply_decision(after, j).is_none());
}

/// B152-COUNT (arch152b 3.4): a new shard is refused exactly at the held-shard bound.
#[kani::proof]
fn proof_held_shard_decision() {
    let held: u64 = kani::any();
    let max: u64 = kani::any();
    let d = crate::storage::quota::held_shard_decision(held, max);
    kani::cover!(d.is_ok(), "shard within the bound");
    kani::cover!(d.is_err(), "shard over the bound refused");
    assert_eq!(d.is_ok(), held < max);
}

/// B152-BOUND (L-130): for each profile's real share, floor and ceiling, a derived bound lies in
/// [floor, ceiling], more memory never lowers it, and an override wins. Memory is the only
/// symbolic quantity (KiB-granular up to 4 TiB); a symbolic share and bounds made the products
/// nonlinear and the run passed 15 minutes (`OPERATIONAL_LESSONS.md` 8.1, 8.2).
#[kani::proof]
fn proof_held_shard_bound_clamped_and_monotone() {
    use crate::profile::HardwareProfile;
    let profile = match kani::any::<u8>() % 3 {
        0 => HardwareProfile::RouterSoc,
        1 => HardwareProfile::HomelabNas,
        _ => HardwareProfile::Desktop,
    };
    let (share, floor, ceiling) = crate::storage::quota::held_shard_profile(profile);
    let mem = u64::from(kani::any::<u32>()) << 10;
    let more = mem + (u64::from(kani::any::<u32>()) << 10);
    let a =
        crate::storage::quota::held_shard_bound_from(Some(mem), true, share, floor, ceiling, None);
    let b =
        crate::storage::quota::held_shard_bound_from(Some(more), true, share, floor, ceiling, None);
    kani::cover!(a.max == floor, "bound at the floor");
    kani::cover!(a.max == ceiling, "bound at the ceiling");
    kani::cover!(
        a.max > floor && a.max < ceiling,
        "bound derived from memory"
    );
    assert!(a.max >= floor && a.max <= ceiling);
    assert!(b.max >= a.max);
    let o = u64::from(kani::any::<u32>());
    kani::assume(o > 0);
    let r = crate::storage::quota::held_shard_bound_from(
        Some(mem),
        true,
        share,
        floor,
        ceiling,
        Some(o),
    );
    assert_eq!(r.max, o);
}
