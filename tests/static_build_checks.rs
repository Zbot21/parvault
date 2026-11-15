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

/// v0.5.4 (docs/METRICS.md): the release guard. The binaries this suite was built with carry no
/// insecure metrics listener: in a release-profile test run the full check (marker and
/// `--version --verbose`) passes; in a debug run, whose binaries have debug assertions on, the
/// marker scan passes and the exec check flags debug assertions. A file carrying the marker
/// is flagged by the marker scan alone, and a missing file is exit 2 (fail closed).
#[test]
fn shipped_binaries_lack_insecure_metrics() {
    let root = env!("CARGO_MANIFEST_DIR");
    let script = format!("{root}/scripts/check_no_insecure_metrics.sh");
    let run = |args: &[&str]| -> (i32, String) {
        let out = Command::new("bash")
            .arg(&script)
            .args(args)
            .output()
            .expect("run bash");
        (
            out.status.code().unwrap_or(-1),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let bins = [
        env!("CARGO_BIN_EXE_parvault"),
        env!("CARGO_BIN_EXE_parvault-seed"),
    ];
    let (code, text) = run(&["--marker-only", bins[0], bins[1]]);
    assert_eq!(code, 0, "{text}");
    let (code, text) = run(&bins);
    if cfg!(debug_assertions) {
        assert_eq!(code, 1, "{text}");
        assert!(text.contains("debug_assertions: on"), "{text}");
    } else {
        assert_eq!(code, 0, "{text}");
        assert!(
            text.contains("debug_assertions: off, features: none"),
            "{text}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let carrier = dir.path().join("carrier.bin");
    let mut bytes = vec![0u8; 4096];
    bytes.extend_from_slice(b"PARVAULT-LAB-INSECURE-METRICS-v1");
    bytes.extend_from_slice(&[0u8; 4096]);
    std::fs::write(&carrier, &bytes).unwrap();
    let (code, text) = run(&["--marker-only", carrier.to_str().unwrap()]);
    assert_eq!(code, 1, "{text}");
    let (code, _) = run(&[dir.path().join("absent").to_str().unwrap()]);
    assert_eq!(code, 2);
    let (code, _) = run(&[]);
    assert_eq!(code, 2);
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(
            std::path::Path::new(&dir)
                .join("static_build_checks::shipped_binaries_lack_insecure_metrics"),
            b"ran",
        )
        .expect("sentinel");
    }
}
