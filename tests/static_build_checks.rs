//! Static build checks run as tests, so the full suite and the scoped local gate run the same
//! scripts CI does (plan-3 ruling: one script for CI and the local gate).

use std::process::Command;

fn run_script(script: &str) {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut cmd = Command::new("bash");
    cmd.arg(format!("{root}/scripts/{script}"));
    // doc_commands.sh takes a mode; the others take the repository root.
    if script == "doc_commands.sh" {
        cmd.arg("selftest");
    } else {
        cmd.arg(root);
    }
    let out = cmd.env("CARGO", env!("CARGO")).output().expect("run bash");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    println!("{text}");
    assert!(out.status.success(), "{script} failed:\n{text}");
}

/// L-48: the plugin feature sets (ipc-client, vfs, combined) link no tokio, libp2p, mio or quinn.
#[test]
fn plugin_feature_sets_link_no_async_runtime() {
    run_script("check_no_runtime_deps.sh");
}

/// Ruling change 5: no feature cfg inside a claimed or Kani-named function or its facts struct.
#[test]
fn claimed_functions_carry_no_feature_cfg() {
    run_script("check_claim_cfg.sh");
}

/// L-34 runner positive controls (release QA): blocks run from a file with stdin closed, a failing
/// command fails its block, unannotated non-allowlisted and indented shell fences fail the check,
/// and a background block whose process dies is not reported ready. Runs locally (no Docker).
#[test]
fn doc_commands_runner_positive_controls() {
    run_script("doc_commands.sh");
}
