//! Kani harnesses of `v0.5.6` track D: liveness and visibility (plan 3.8 b to 3.11).
//!
//! Empty at T0. Rules (docs repo `OPERATIONAL_LESSONS.md` section 8): constant-size inputs, no
//! symbolic slices, maps or strings, the smallest unwind, a `kani::cover!` per outcome; run a new
//! harness alone first (`cargo kani --lib --harness kani_proofs::liveness::<name> --exact`).
