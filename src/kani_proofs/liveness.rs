//! Kani harnesses of `v0.5.6` track D: liveness and visibility (plan 3.8 b to 3.11).
//!
//! Empty at T0. Rules (docs repo `OPERATIONAL_LESSONS.md` section 8): constant-size inputs, no
//! symbolic slices, maps or strings, the smallest unwind, a `kani::cover!` per outcome; run a new
//! harness alone first (`cargo kani --lib --harness kani_proofs::liveness::<name> --exact`).

use crate::network::redial::{backoff_ms, redial_decision, BACKOFF_BASE_MS, BACKOFF_CAP_MS};
use crate::network::server_events::{kad_record_decision, KadRecordFacts, KadStoreBudget};
use crate::profile::HardwareProfile;
use crate::storage::block_store::{dht_store_decision, DhtStoreFacts, DhtStoreLimits};

/// B157-REDIAL: only a ring member that is not connected and whose backoff elapsed is dialled.
#[kani::proof]
#[kani::unwind(40)]
fn redial_decision_only_ring_members_after_backoff() {
    let configured: bool = kani::any();
    let admitted: bool = kani::any();
    let connected: bool = kani::any();
    let attempt: u8 = kani::any();
    let since: u64 = kani::any();
    let r = redial_decision(configured, admitted, connected, attempt, since);
    if r.is_ok() {
        assert!(configured || admitted);
        assert!(!connected);
        assert!(since >= backoff_ms(attempt));
    }
    if !configured && !admitted {
        assert!(r == Err("reject.redial_not_ring_member"));
    }
    kani::cover!(r.is_ok(), "ring member dialled");
    kani::cover!(
        r == Err("reject.redial_not_ring_member"),
        "unknown peer not redialled"
    );
    kani::cover!(
        r == Err("reject.redial_connected"),
        "connected peer not redialled"
    );
    kani::cover!(
        r == Err("reject.redial_backoff"),
        "redial waits for its backoff"
    );
}

/// R1: the backoff is monotone in the attempt, starts at the base step, never exceeds the cap.
#[kani::proof]
#[kani::unwind(40)]
fn backoff_monotone_and_capped() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    kani::assume(a <= b);
    let (x, y) = (backoff_ms(a), backoff_ms(b));
    assert!(x <= y);
    assert!(BACKOFF_BASE_MS <= x && y <= BACKOFF_CAP_MS);
    assert!(backoff_ms(0) == BACKOFF_BASE_MS);
    kani::cover!(x < y, "backoff grows");
    kani::cover!(y == BACKOFF_CAP_MS, "backoff capped");
}

/// A-152 4.1-4.4 (B152-DHT-STORE): a corrupt store refuses; an accepted put keeps the store
/// within its byte budget and, for a new key, within the key count and the owner's share; an
/// update within the byte budget is never refused.
#[kani::proof]
#[kani::unwind(40)]
fn dht_store_decision_respects_budget() {
    let f: DhtStoreFacts = kani::any();
    let l = DhtStoreLimits::for_profile(HardwareProfile::RouterSoc);
    let r = dht_store_decision(&f, &l);
    if f.store_corrupt {
        assert!(r == Err("reject.dht_store_corrupt"));
    }
    if r.is_ok() {
        let removed = if f.replaces_existing { f.old_len } else { 0 };
        assert!(
            f.total_bytes
                .saturating_sub(removed)
                .saturating_add(f.new_len)
                <= l.max_bytes
        );
        if !f.replaces_existing {
            assert!(f.total_keys < l.max_keys);
            assert!(f.owner_keys < l.max_owner_keys);
            assert!(f.owner_bytes.saturating_add(f.new_len) <= l.max_owner_bytes);
        }
    }
    if !f.store_corrupt
        && f.replaces_existing
        && f.total_bytes
            .checked_sub(f.old_len)
            .and_then(|b| b.checked_add(f.new_len))
            .is_some_and(|after| after <= l.max_bytes)
    {
        assert!(r.is_ok());
    }
    kani::cover!(r.is_ok() && !f.replaces_existing, "new key stored");
    kani::cover!(r.is_ok() && f.replaces_existing, "update stored");
    kani::cover!(r == Err("reject.dht_store_full"), "full store refuses");
    kani::cover!(
        r == Err("reject.dht_owner_key_cap"),
        "owner over its share refused"
    );
    kani::cover!(
        r == Err("reject.dht_store_corrupt"),
        "corrupt store refuses"
    );
}

/// B-152 b (arch152b 2.4): an inbound Kademlia record from an admitted source, valid for its
/// key, is stored only within the record and byte budget; replacing a held key needs no free
/// slot. Owner and version are fixed (constant-size inputs); the budget is symbolic.
#[kani::proof]
#[kani::unwind(40)]
fn kad_record_budget_respected() {
    let budget: KadStoreBudget = kani::any();
    let replaces: bool = kani::any();
    let facts = KadRecordFacts {
        source_admitted: true,
        candidate: Some((vec![1u8], 2)),
        existing: if replaces { Some((vec![1u8], 1)) } else { None },
        budget,
    };
    let r = kad_record_decision(&facts);
    let removed = if replaces { budget.existing_len } else { 0 };
    let after = budget
        .bytes
        .saturating_sub(removed)
        .saturating_add(budget.candidate_len);
    let fits = after <= budget.max_bytes && (replaces || budget.records < budget.max_records);
    assert!(r.is_ok() == fits);
    if r.is_err() {
        assert!(r == Err("reject.dht_record_store_full"));
    }
    kani::cover!(
        r.is_ok() && replaces && budget.records >= budget.max_records,
        "replacing at the record cap stored"
    );
    kani::cover!(
        r == Err("reject.dht_record_store_full"),
        "full kad store refuses"
    );
}
