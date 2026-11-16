//! Kani harnesses of `v0.5.6` track E: setup and ops (plan 3.12 to 3.14).
//!
//! Empty at T0. Rules (docs repo `OPERATIONAL_LESSONS.md` section 8): constant-size inputs, no
//! symbolic slices, maps or strings, the smallest unwind, a `kani::cover!` per outcome; run a new
//! harness alone first (`cargo kani --lib --harness kani_proofs::setup::<name> --exact`).

use crate::datadir_lock::{init_if_absent_decision, InitIfAbsent, RingFiles, VolumeState};

fn refused_as(d: InitIfAbsent, suffix: &str) -> bool {
    matches!(d, InitIfAbsent::Refuse(code) if code.ends_with(suffix))
}

/// B146-INIT (A-146-2 to A-146-4, arch056c 2.5): over every volume state (five ring states, two
/// bools) and both flags, a configured join token never inits; nothing inits a volume that holds
/// a ring file, a chain or any other entry; seed and pin that disagree are always refused; and
/// a seed without its pin is resumed, never re-initialised.
#[kani::proof]
fn proof_init_if_absent_never_second_genesis() {
    let v: VolumeState = kani::any();
    let join: bool = kani::any();
    let flag: bool = kani::any();
    let d = init_if_absent_decision(v, join, flag);
    if join {
        assert!(d != InitIfAbsent::Init);
        assert!(d != InitIfAbsent::Skip);
    }
    if d == InitIfAbsent::Init {
        assert!(flag && !join);
        assert!(v.ring == RingFiles::Neither && !v.other_files && !v.chain_stored);
    }
    if v.ring == RingFiles::Disagree {
        assert!(refused_as(d, "partial_state"));
    }
    if v.ring == RingFiles::SeedOnly && flag && !join {
        assert!(d == InitIfAbsent::ResumePin);
    }
    if v.ring == RingFiles::Neither && v.other_files && flag && !join {
        assert!(refused_as(d, "volume_not_empty"));
    }
    if !join && !flag {
        assert!(d == InitIfAbsent::Skip || refused_as(d, "partial_state"));
    }
    kani::cover!(d == InitIfAbsent::Init, "empty volume inits");
    kani::cover!(d == InitIfAbsent::Join, "join token joins");
    kani::cover!(d == InitIfAbsent::ResumePin, "seed without pin resumes");
    kani::cover!(d == InitIfAbsent::OwnRing, "own ring is a no-op");
    kani::cover!(refused_as(d, "volume_not_empty"), "unknown volume refused");
}
