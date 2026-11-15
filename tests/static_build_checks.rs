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

fn run_script_on(script: &str, args: &[&std::path::Path]) -> (bool, String) {
    let root = env!("CARGO_MANIFEST_DIR");
    let out = Command::new("bash")
        .arg(format!("{root}/scripts/{script}"))
        .args(args)
        .output()
        .expect("run bash");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    println!("{text}");
    (out.status.success(), text)
}

fn planted_tree(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for (rel, body) in files {
        let p = dir.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    dir
}

/// L-16 S1: manifest selection is compile time only, and no compiling command uses
/// `--all-features` (G-1 C3). Passes on the tree.
#[test]
fn manifest_cfg_check_passes_on_tree() {
    run_script("check_manifest_cfg.sh");
}

/// L-16 S1 reject twin: a manifest cfg planted in `wire_handler.rs` fails the check, as does
/// `--all-features` on a compiling command; `cargo tree --all-features` and the cfg inside
/// `src/manifest/mod.rs` pass.
#[test]
fn manifest_cfg_check_fails_on_planted_cfg() {
    let ok = planted_tree(&[
        (
            "src/manifest/mod.rs",
            "#[cfg(feature = \"manifest-household-ring-v1\")]\npub mod household_ring_v1;\n",
        ),
        (
            ".github/workflows/ci.yml",
            "      run: cargo tree -e features --all-features | grep x\n      # cargo build --all-features is prose\n",
        ),
    ]);
    let (pass, text) = run_script_on("check_manifest_cfg.sh", &[ok.path()]);
    assert!(pass, "clean planted tree must pass:\n{text}");

    let bad_cfg = planted_tree(&[(
        "src/network/wire_handler.rs",
        "#[cfg(feature = \"manifest-household-ring-v1\")]\nfn f() {}\n",
    )]);
    let (pass, text) = run_script_on("check_manifest_cfg.sh", &[bad_cfg.path()]);
    assert!(!pass, "planted manifest cfg must fail:\n{text}");
    assert!(text.contains("src/network/wire_handler.rs:1: manifest feature cfg outside"));

    let bad_all = planted_tree(&[(
        ".github/workflows/ci.yml",
        "      run: cargo clippy --all-features -- -D warnings\n",
    )]);
    let (pass, text) = run_script_on("check_manifest_cfg.sh", &[bad_all.path()]);
    assert!(!pass, "--all-features on clippy must fail:\n{text}");
    assert!(text.contains("--all-features in a compiling command"));
}

/// L-16 S1: a daemon-runtime build with no manifest, and one with two, both fail with the
/// `compile_error!` text (G-1 C2: the minimal headless check must name the manifest).
#[test]
fn manifest_selection_compile_errors() {
    let root = env!("CARGO_MANIFEST_DIR");
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::Path::new(root).join("target"))
        .join("manifest-selection-check");
    for (features, expect) in [
        ("daemon-runtime", "parvault: no manifest selected"),
        (
            "daemon-runtime,manifest-household-ring-v1,manifest-test-restricted",
            "parvault: more than one manifest selected",
        ),
    ] {
        let out = Command::new(env!("CARGO"))
            .current_dir(root)
            .env("CARGO_TARGET_DIR", &target)
            .args([
                "check",
                "--lib",
                "--no-default-features",
                "--features",
                features,
            ])
            .output()
            .expect("run cargo");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{features} must not build");
        assert!(
            err.contains(expect),
            "{features}: expected '{expect}':\n{err}"
        );
    }
}

/// L-16 plan 1.3, G-1 C10 reject test: the release check refuses a binary that embeds a manifest
/// other than the default (or two), and accepts the default alone.
#[test]
fn release_manifest_check_refuses_non_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let write = |name: &str, body: &[u8]| {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    };
    let default = write(
        "default",
        b"\x00\x01parvault 0.5.5 (manifest household-ring-v1)\x00",
    );
    let restricted = write(
        "restricted",
        b"\x00parvault 0.5.5 (manifest test-restricted)\x00",
    );
    let both = write(
        "both",
        b"(manifest household-ring-v1)\x00(manifest test-restricted)",
    );
    let none = write("none", b"\x7fELF no manifest here");
    assert!(run_script_on("check_release_manifest.sh", &[&default]).0);
    for bad in [&restricted, &both, &none] {
        let (pass, text) = run_script_on("check_release_manifest.sh", &[bad]);
        assert!(!pass, "{} must be refused:\n{text}", bad.display());
        assert!(text.contains("release builds ship 'household-ring-v1' only"));
    }
}
