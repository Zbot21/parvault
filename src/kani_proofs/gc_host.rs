//! Kani harnesses of `v0.5.6` track B1: version GC, host side (plan 3.7, 3.8 a).
//!
//! Empty at T0. Rules (docs repo `OPERATIONAL_LESSONS.md` section 8): constant-size inputs, no
//! symbolic slices, maps or strings, the smallest unwind, a `kani::cover!` per outcome; run a new
//! harness alone first (`cargo kani --lib --harness kani_proofs::gc_host::<name> --exact`).
