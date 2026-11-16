//! `v0.5.6` track D suite: liveness and visibility (plan Sections 3.8 (b) to 3.11). Claims of track
//! D put their differential pairs here;
//! `tests/trust_enforcement.rs` is frozen.
//!
//! T0 checks that each stub of track D refuses with `reject.not_built_yet`; track D replaces those
//! checks.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

use std::path::Path;

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// T0 stub of track D: `status --live` (and `live_status::snapshot`, behind `QueryLiveStatus`
/// and `GET /live`).
#[test]
fn track_d_stubs_refuse_not_built_yet() {
    let tmp = tempfile::tempdir().unwrap();
    let out = common::parvault_in(&tmp.path().join("node"), &["status", "--live"]);
    common::assert_not_built_yet(&out, "status --live");
    let e = parvault::live_status::snapshot().unwrap_err();
    assert!(e.to_string().contains("reject.not_built_yet"), "{e}");
    gate_ran("trust_enforcement_liveness::track_d_stubs_refuse_not_built_yet");
}
