//! `v0.5.6` track E suite: setup and ops (plan Sections 3.12 to 3.14). Claims of track E put their
//! differential pairs here;
//! `tests/trust_enforcement.rs` is frozen.
//!
//! T0 checks that each stub of track E refuses with `reject.not_built_yet` and that the data-dir
//! lock passes through; track E replaces those checks.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

use std::path::Path;

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// T0 stubs of track E: `wot invite --out`, `ring backup|restore`, `up --init-if-absent`,
/// `up --join-token-file`.
#[test]
fn track_e_unbuilt_entries_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let peer = "11".repeat(32);
    let pass = tmp.path().join("pass");
    let p = pass.to_str().unwrap();
    for (args, entry) in [
        (
            vec!["wot", "invite", "--peer", &peer, "--out", "inv.tok"],
            "wot invite --out",
        ),
        (
            vec!["ring", "backup", "--out", "b", "--passphrase-file", p],
            "ring backup",
        ),
        (
            vec!["ring", "restore", "--from", "b.bin", "--passphrase-file", p],
            "ring restore",
        ),
        (
            vec!["up", "--no-socket", "--init-if-absent"],
            "up --init-if-absent / --join-token-file",
        ),
        (
            vec!["up", "--no-socket", "--join-token-file", p],
            "up --init-if-absent / --join-token-file",
        ),
    ] {
        common::assert_not_built_yet(&common::parvault_in(&dir, &args), entry);
    }
    gate_ran("trust_enforcement_setup::track_e_unbuilt_entries_refuse");
}

/// B-174 at T0: `wot init` runs under the (pass-through) lock exactly as before: one genesis,
/// a second init refused by the existing check, and no lock file yet.
#[test]
fn wot_init_under_the_pass_through_lock_is_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let first = common::parvault_in(&dir, &["wot", "init"]);
    assert!(first.status.success(), "{first:?}");
    let second = common::parvault_in(&dir, &["wot", "init"]);
    assert!(!second.status.success(), "{second:?}");
    assert!(!dir.join(".parvault.lock").exists());
    gate_ran("trust_enforcement_setup::wot_init_under_the_pass_through_lock_is_unchanged");
}
