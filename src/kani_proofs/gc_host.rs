//! Kani harnesses of `v0.5.6` track B1: version GC, host side (plan 3.7, 3.8 a).
//!
//! Rules (docs repo `OPERATIONAL_LESSONS.md` section 8): constant-size inputs, no symbolic
//! slices, maps or strings, the smallest unwind, a `kani::cover!` per outcome; run a new harness
//! alone first (`cargo kani --lib --harness kani_proofs::gc_host::<name> --exact`).

/// B154-FREE (B-158, C12): an order is admitted only when every fact holds, and a refusal names
/// the first failed fact in the check order (shape, host, freshness, signature, epoch).
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
    if !f.shape_ok {
        assert_eq!(d, Err("reject.free_order_malformed"));
    } else if !f.host_matches {
        assert_eq!(d, Err("reject.free_wrong_host"));
    } else if !f.fresh {
        assert_eq!(d, Err("reject.free_stale"));
    } else if !f.signature_valid {
        assert_eq!(d, Err("reject.free_bad_signature"));
    }
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
    let apply = crate::por::audit_journal::audit_journal_apply_decision(c, j);
    kani::cover!(apply, "journal applied");
    kani::cover!(!apply, "journal ignored");
    let after = if apply { j } else { c };
    assert!(after >= c);
    assert!(after >= j);
    assert!(!crate::por::audit_journal::audit_journal_apply_decision(
        after, j
    ));
}
