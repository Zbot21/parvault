//! Runs `scripts/docker_acceptance_gate.sh` (the 12-stage multi-container acceptance gate) as a
//! suite so the enforcement gates can require it (`suite`/`artifact` lines in `.enforcement.map`).
//!
//! It runs only when the enforcement runner provides `GATES_SENTINEL_DIR`, or when
//! `PARVAULT_DOCKER_GATE=1`; a plain `cargo test` prints `SKIPPED`. Under `GATES_REQUIRE_REAL=1` a
//! missing `docker` is a failure, not a skip.

use std::process::Command;

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(std::path::Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

fn require_real() -> bool {
    std::env::var("GATES_REQUIRE_REAL").as_deref() == Ok("1")
}

#[test]
fn docker_acceptance_gate() {
    let requested = std::env::var_os("GATES_SENTINEL_DIR").is_some()
        || std::env::var("PARVAULT_DOCKER_GATE").as_deref() == Ok("1");
    if !requested {
        println!("SKIPPED: set PARVAULT_DOCKER_GATE=1 (or run through the enforcement gates)");
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !docker_ok {
        assert!(!require_real(), "docker is required (GATES_REQUIRE_REAL=1)");
        println!("SKIPPED: docker is not available");
        return;
    }
    // The script builds into and copies from the repository's own build directory, so the
    // inherited build-directory override is cleared (artifact provenance, A-DOCKER).
    let status = Command::new("bash")
        .arg("scripts/docker_acceptance_gate.sh")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .expect("run docker_acceptance_gate.sh");
    assert!(status.success(), "docker acceptance gate failed: {status}");
    gate_ran("docker_acceptance_gate::docker_acceptance_gate");
}
