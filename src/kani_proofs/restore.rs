//! Kani harnesses of `v0.5.6` track C: the restore path and fetch scheduler (plan 3.3 to 3.5).
//!
//! Empty at T0. Rules (docs repo `OPERATIONAL_LESSONS.md` section 8): constant-size inputs, no
//! symbolic slices, maps or strings, the smallest unwind, a `kani::cover!` per outcome; run a new
//! harness alone first (`cargo kani --lib --harness kani_proofs::restore::<name> --exact`).
