//! Kani harnesses of `v0.5.6` track C: the restore path and fetch scheduler (plan 3.3 to 3.5).
//!
//! Empty at T0. Rules (docs repo `OPERATIONAL_LESSONS.md` section 8): constant-size inputs, no
//! symbolic slices, maps or strings, the smallest unwind, a `kani::cover!` per outcome; run a new
//! harness alone first (`cargo kani --lib --harness kani_proofs::restore::<name> --exact`).

use crate::fetch_sched::{fetch_slot_decision, SchedState, SlotDecision, AGING_N, SLOTS};

/// A reachable scheduler state: in flight within the slots, scavengers within `SLOTS - 1`.
fn any_valid_state() -> SchedState {
    let s = SchedState {
        fg_queued: kani::any(),
        bg_queued: kani::any(),
        fg_in_flight: kani::any(),
        bg_in_flight: kani::any(),
        bg_skipped: kani::any(),
    };
    kani::assume(s.bg_in_flight < SLOTS);
    kani::assume(s.fg_in_flight <= SLOTS - s.bg_in_flight);
    kani::assume(s.bg_skipped <= AGING_N);
    s
}

/// S2/S3: one step never lets scavengers hold more than `SLOTS - 1` slots, nor overfills the
/// slots, nor grants a class with nothing queued.
#[kani::proof]
fn l72_scavenger_never_exceeds_s_minus_1() {
    let s = any_valid_state();
    let (d, n) = s.step();
    assert!(n.bg_in_flight < SLOTS);
    assert!(n.fg_in_flight as u16 + n.bg_in_flight as u16 <= SLOTS as u16);
    assert!(n.bg_skipped <= AGING_N);
    match d {
        SlotDecision::GrantForeground => assert!(s.fg_queued > 0),
        SlotDecision::GrantScavenger => assert!(s.bg_queued > 0),
        SlotDecision::Wait => {}
    }
    kani::cover!(d == SlotDecision::GrantForeground, "foreground granted");
    kani::cover!(d == SlotDecision::GrantScavenger, "scavenger granted");
    kani::cover!(d == SlotDecision::Wait, "nothing granted");
}

/// S3: a foreground is granted whenever one is queued with a slot free, except the aging step.
#[kani::proof]
fn l72_foreground_granted_when_queued_and_slot_free() {
    let (fg, bg, free, bgf, skip): (u8, u8, u8, u8, u8) = (
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
    let (d, defer) = fetch_slot_decision(fg, bg, free, bgf, skip);
    // The defer code marks exactly the foreground grants that pass a queued scavenger.
    assert!(defer.is_some() == (d == SlotDecision::GrantForeground && bg > 0));
    let aging = bg > 0 && bgf < SLOTS - 1 && skip >= AGING_N;
    if fg > 0 && free > 0 && !aging {
        assert!(d == SlotDecision::GrantForeground);
    }
    if free == 0 {
        assert!(d == SlotDecision::Wait);
    }
    if fg > 0 && d == SlotDecision::GrantScavenger {
        assert!(aging);
    }
    kani::cover!(
        aging && fg > 0 && free > 0 && d == SlotDecision::GrantScavenger,
        "aging step starts a scavenger"
    );
    kani::cover!(defer.is_some(), "scavenger deferred for a foreground read");
}

/// S3: a queued scavenger that may hold a slot starts within `AGING_N + 1` grants, whatever
/// foreground traffic arrives and whichever fetches finish between grants.
#[kani::proof]
#[kani::unwind(11)]
fn l72_queued_scavenger_starts_within_n_plus_1_grants() {
    let mut s = any_valid_state();
    kani::assume(s.bg_queued > 0);
    kani::assume(s.bg_in_flight < SLOTS - 1);
    let mut started = false;
    let mut grants: u8 = 0;
    while grants <= AGING_N {
        // Between grants: foreground arrivals and completions of either class (never new
        // scavenger slots: only a grant adds one).
        let fg_q: u8 = kani::any();
        let fg_f: u8 = kani::any();
        let bg_f: u8 = kani::any();
        kani::assume(bg_f <= s.bg_in_flight);
        kani::assume(fg_f as u16 + bg_f as u16 <= SLOTS as u16);
        s.fg_queued = fg_q;
        s.fg_in_flight = fg_f;
        s.bg_in_flight = bg_f;
        // Count only steps that grant: a slot must be free.
        kani::assume(s.slots_free() > 0);
        let (d, n) = s.step();
        assert!(
            d != SlotDecision::Wait,
            "a free slot with a scavenger queued is granted"
        );
        grants += 1;
        s = n;
        if d == SlotDecision::GrantScavenger {
            started = true;
            break;
        }
    }
    assert!(started);
    kani::cover!(grants == AGING_N + 1, "scavenger aged in at grant N+1");
    kani::cover!(grants == 1, "scavenger started at once");
}

use crate::vfs::{catalog_import_decision, CatalogImport};

/// B20-LIST: a catalog is applied only if it verifies, names this data dir's key and is newer
/// than the loaded one; the same version is a no-op and an older one a rollback.
#[kani::proof]
fn b20_catalog_import_decision() {
    let verifies: bool = kani::any();
    let key_matches: bool = kani::any();
    let env_v: u8 = kani::any();
    let loaded_v: u8 = kani::any();
    let r = catalog_import_decision(verifies, key_matches, env_v as u64, loaded_v as u64);
    if r == Ok(CatalogImport::Apply) {
        assert!(verifies && key_matches && env_v > loaded_v);
    }
    if !verifies || !key_matches {
        assert!(r.is_err());
    } else if env_v < loaded_v {
        assert!(r.is_err());
    } else if env_v == loaded_v {
        assert!(r == Ok(CatalogImport::Unchanged));
    }
    kani::cover!(r.is_err() && !verifies, "foreign catalog refused");
    kani::cover!(r.is_err() && verifies && key_matches, "rollback refused");
    kani::cover!(r == Ok(CatalogImport::Apply), "newer catalog applied");
    kani::cover!(r == Ok(CatalogImport::Unchanged), "same version unchanged");
}
