//! The plugins' `self-test` subcommands are client-only (item 3): they need a running daemon.
//! These tests host the gateway in-process, as the old embedded self-tests did, and run the
//! shipped plugin binaries against it.
#![cfg(unix)]

use parvault::capabilities::CapabilityMacaroon;
use parvault::config::HardwareProfile;
use parvault::crypto::MasterKey;
use parvault::gateway::ipc::{GatewayIpcServer, GatewayIpcServerHandle};
use parvault::storage::{BlockStore, QuotaManager};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ROOT_KEY: [u8; 32] = [0x5A; 32];

struct Host {
    dir: PathBuf,
    sock: PathBuf,
    srv: GatewayIpcServerHandle,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.srv.shutdown();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn host(label: &str) -> Host {
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("pv-plugin-selftest-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("gw.sock");
    let store = BlockStore::new(
        dir.join("store"),
        QuotaManager::new(512 * 1024 * 1024, 64 * 1024 * 1024),
    )
    .unwrap();
    let srv = GatewayIpcServer::new(&sock, store, MasterKey::generate())
        .with_profile(HardwareProfile::RouterSoc)
        .with_require_sealed_ingest_memfd(true)
        .with_strict_allowed_peer_uids(vec![parvault::os_sys::geteuid()])
        .with_macaroon_root_key(ROOT_KEY)
        .spawn()
        .unwrap();
    Host { dir, sock, srv }
}

fn root_token() -> String {
    CapabilityMacaroon::mint(&ROOT_KEY, [0x11; 32], [0x22; 32], Vec::new())
        .unwrap()
        .to_compact_token()
}

fn run(bin: &str, sock: &Path, token: Option<&str>, cwd: &Path) -> Output {
    let mut cmd = Command::new(bin);
    cmd.current_dir(cwd).arg("--socket").arg(sock);
    if let Some(t) = token {
        cmd.arg("--macaroon").arg(t);
    }
    cmd.arg("self-test").output().unwrap()
}

fn assert_pass(out: &Output, name: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains(&format!("{name} self-test: PASS")),
        "{name} self-test failed:\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    println!("{}", stdout.trim());
}

#[test]
fn fuse_self_test_against_hosted_gateway() {
    let h = host("fuse");
    let out = run(
        env!("CARGO_BIN_EXE_parvault-fuse"),
        &h.sock,
        Some(&root_token()),
        &h.dir,
    );
    assert_pass(&out, "parvault-fuse");
}

#[test]
fn sync_self_test_against_hosted_gateway() {
    let h = host("sync");
    let out = run(
        env!("CARGO_BIN_EXE_parvault-sync"),
        &h.sock,
        Some(&root_token()),
        &h.dir,
    );
    assert_pass(&out, "parvault-sync");
}

/// The gateway has a root key, so a self-test without `--macaroon` cannot read back.
#[test]
fn fuse_self_test_without_token_fails() {
    let h = host("fuse-notok");
    let out = run(env!("CARGO_BIN_EXE_parvault-fuse"), &h.sock, None, &h.dir);
    assert!(!out.status.success());
}

/// With no daemon on the socket the self-test says so.
#[test]
fn self_test_without_daemon_names_the_socket() {
    let dir = std::env::temp_dir().join(format!("pv-plugin-nodaemon-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = run(
        env!("CARGO_BIN_EXE_parvault-fuse"),
        &dir.join("absent.sock"),
        None,
        &dir,
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("needs a running daemon"));
}
