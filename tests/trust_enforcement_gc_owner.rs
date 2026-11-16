//! `v0.5.6` track B2 suite: version GC on the owner (plan Section 3.7). Claims of track B2 put
//! their differential pairs here;
//! `tests/trust_enforcement.rs` is frozen.
//!
//! T0 checks that each stub of track B2 refuses with `reject.not_built_yet`; track B2 replaces
//! those checks.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

use std::path::Path;

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// T0 stub of track B2: `restore-folder --version`.
#[test]
fn track_b2_stubs_refuse_not_built_yet() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let snap = tmp.path().join("s.manifest.bin");
    let out = tmp.path().join("out");
    let out = common::parvault_in(
        &dir,
        &[
            "restore-folder",
            "--snapshot",
            snap.to_str().unwrap(),
            "--out-dir",
            out.to_str().unwrap(),
            "--version",
            "2",
        ],
    );
    common::assert_not_built_yet(&out, "restore-folder --version");
    let folder = tmp.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    for args in [
        vec![
            "watch-folder",
            "--folder",
            folder.to_str().unwrap(),
            "--once",
            "--no-gc",
        ],
        vec!["up", "--no-socket", "--no-gc"],
    ] {
        common::assert_not_built_yet(&common::parvault_in(&dir, &args), "--no-gc");
    }
    gate_ran("trust_enforcement_gc_owner::track_b2_stubs_refuse_not_built_yet");
}
