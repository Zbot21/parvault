//! `v0.5.6` track C suite: the restore path and the fetch scheduler (plan Sections 3.3 to 3.5).
//! Claims of track C put their differential pairs here;
//! `tests/trust_enforcement.rs` is frozen.
//!
//! T0 checks that each stub of track C keeps today's behaviour; track C replaces those checks.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

use std::path::Path;

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// The C-to-D seam: the scheduler counters live status reads are zero until track C fills them.
#[test]
fn fetch_sched_counters_start_at_zero() {
    assert_eq!(
        parvault::fetch_sched::counters(),
        parvault::fetch_sched::FetchSchedCounters::default()
    );
    gate_ran("trust_enforcement_restore::fetch_sched_counters_start_at_zero");
}
