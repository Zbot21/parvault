//! `v0.5.6` track B1 suite: version GC on the host, per-shard memory (plan Sections 3.7 and 3.8
//! (a)). Claims of track B1 put their differential pairs here;
//! `tests/trust_enforcement.rs` is frozen.
//!
//! T0 checks that each stub of track B1 keeps today's behaviour (the `FreeShards` refusal is in
//! `tests/wire_handler_equivalence.rs`); track B1 replaces those checks.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

use std::path::Path;

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// G2: `relocation_targets` reads the auditor's B-113 map; no state file is an empty map.
#[test]
fn relocation_targets_of_a_fresh_data_dir_is_empty() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(parvault::por::auditor::relocation_targets(tmp.path())
        .unwrap()
        .is_empty());
    std::fs::write(
        tmp.path().join(parvault::por::auditor::AUDIT_STATE_FILE),
        b"not json",
    )
    .unwrap();
    assert!(parvault::por::auditor::relocation_targets(tmp.path()).is_err());
    gate_ran("trust_enforcement_gc_host::relocation_targets_of_a_fresh_data_dir_is_empty");
}
