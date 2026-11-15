//! `parvault net probe --force-direct` against the real binary (`v0.5.4` NEW-4,
//! `docs/LAB_MODE.md`). Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

use parvault::crypto::pqc::HybridPqSigningKeypair;
use parvault::crypto::{HybridKemKeypair, NodeIdentity};
use parvault::network::node_identity_libp2p_peer_id;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ROOT_KEY: [u8; 32] = [0x33; 32];
const GENESIS_SEED: [u8; 32] = [0x47; 32];

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// A running `parvault daemon start` with its status page.
struct Daemon {
    child: Child,
    dir: PathBuf,
    mesh: String,
    status: std::net::SocketAddr,
    _root: tempfile::TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn peer_id(&self) -> libp2p::PeerId {
        node_identity_libp2p_peer_id(&NodeIdentity::load_or_generate_in_dir(&self.dir).unwrap())
            .unwrap()
    }
    fn addr(&self) -> String {
        format!("{}/p2p/{}", self.mesh, self.peer_id())
    }
    fn inbound(&self) -> u64 {
        use std::io::{Read, Write};
        let token = parvault::capabilities::CapabilityMacaroon::mint(
            &ROOT_KEY,
            [1; 32],
            [2; 32],
            vec![parvault::capabilities::Caveat::ReadOnly],
        )
        .unwrap()
        .to_compact_token();
        let mut s = std::net::TcpStream::connect(self.status).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "GET /metrics HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\n\r\n",
            self.status
        )
        .unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        String::from_utf8_lossy(&raw)
            .lines()
            .find_map(|l| {
                l.strip_prefix(
                    "parvault_traversal_inbound_total{path=\"direct\",transport=\"tcp\"} ",
                )
                .and_then(|v| v.trim().parse().ok())
            })
            .expect("inbound series")
    }
}

fn spawn_daemon(label: &str) -> Daemon {
    let root = tempfile::Builder::new()
        .prefix(&format!("pv-probe-{label}-"))
        .tempdir()
        .unwrap();
    let dir = root.path().join("data");
    std::fs::create_dir_all(&dir).unwrap();
    NodeIdentity::load_or_generate_in_dir(&dir).unwrap();
    HybridKemKeypair::load_or_generate_in_dir(&dir).unwrap();
    HybridPqSigningKeypair::load_or_generate_in_dir(&dir).unwrap();
    std::fs::write(dir.join("macaroon_root.key"), hex::encode(ROOT_KEY)).unwrap();
    let log = root.path().join("node.log");
    let f = std::fs::File::create(&log).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env_remove("PARVAULT_PEERS")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "daemon",
            "start",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
            "--no-socket",
            "--status-http",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::from(f.try_clone().unwrap()))
        .stderr(Stdio::from(f))
        .spawn()
        .unwrap();
    let mesh = common::wait_for_listen_addr(
        &mut child,
        || std::fs::read_to_string(&log).unwrap_or_default(),
        Duration::from_secs(20),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(rest) = text.split("Status Server listening on http://").nth(1) {
            break rest.split_whitespace().next().unwrap().parse().unwrap();
        }
        assert!(Instant::now() < deadline, "no status listener:\n{text}");
        std::thread::sleep(Duration::from_millis(50));
    };
    Daemon {
        child,
        dir,
        mesh,
        status,
        _root: root,
    }
}

/// Runs `parvault [global] net probe <args>` in `data_dir`; returns (exit code, JSON or null, stderr).
fn probe(data_dir: &Path, global: &[&str], args: &[&str]) -> (i32, serde_json::Value, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env_remove("PARVAULT_LAN_REGISTRY_DIR")
        .env_remove("PARVAULT_PEERS")
        .env("NO_COLOR", "1")
        .arg("--data-dir")
        .arg(data_dir)
        .args(global)
        .args(["net", "probe"])
        .args(args);
    let out = common::output_within_deadline(&mut cmd);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let doc = serde_json::from_str(stdout.trim()).unwrap_or(serde_json::Value::Null);
    (
        out.status.code().unwrap_or(-1),
        doc,
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn empty_dir(label: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("pv-probe-{label}-"))
        .tempdir()
        .unwrap()
}

fn other_pid() -> String {
    node_identity_libp2p_peer_id(&NodeIdentity::generate())
        .unwrap()
        .to_string()
}

fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// PROBE-PID, -DIRECT, -LAB accept: a probe of a live daemon connects, every timing is set, and
/// the daemon counts one more inbound connection.
#[test]
fn probe_force_direct_connects() {
    let d = spawn_daemon("ok");
    let before = d.inbound();
    let t = empty_dir("ok-c");
    let (code, doc, err) = probe(t.path(), &[], &["--peer", &d.addr(), "--force-direct"]);
    assert_eq!(code, 0, "{doc} {err}");
    assert_eq!(doc["result"], "connected");
    assert_eq!(doc["reason"], "ok");
    assert_eq!(doc["path"], "direct");
    assert_eq!(doc["transport"], "tcp");
    for k in ["established", "ping_rtt", "first_response"] {
        assert!(doc["timings_us"][k].is_u64(), "{k}: {doc}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while d.inbound() <= before && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(d.inbound(), before + 1);
    gate_ran("net_probe::probe_force_direct_connects");
}

#[test]
fn probe_refused_port_fails_stably() {
    let t = empty_dir("refused");
    let addr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", closed_port(), other_pid());
    for _ in 0..3 {
        let (code, doc, _) = probe(t.path(), &[], &["--peer", &addr, "--force-direct"]);
        assert_eq!(code, 1, "{doc}");
        assert_eq!(doc["result"], "failed");
        assert_eq!(doc["reason"], "refused");
    }
    gate_ran("net_probe::probe_refused_port_fails_stably");
}

#[test]
fn probe_wrong_peer_id_fails() {
    let d = spawn_daemon("wrong");
    let t = empty_dir("wrong-c");
    let addr = format!("{}/p2p/{}", d.mesh, other_pid());
    let (code, doc, err) = probe(t.path(), &[], &["--peer", &addr, "--force-direct"]);
    assert_eq!(code, 1, "{doc}");
    assert_eq!(doc["reason"], "peer_id_mismatch", "{err}");
    // Logs (the gate's refusal line) go to stderr; stdout is the one JSON document.
    assert!(err.contains("reject.dial_peer_id_mismatch"), "{err}");
    gate_ran("net_probe::probe_wrong_peer_id_fails");
}

#[test]
fn probe_unroutable_times_out() {
    let t = empty_dir("unroutable");
    let addr = format!("/ip4/192.0.2.1/tcp/4001/p2p/{}", other_pid());
    let start = Instant::now();
    let (code, doc, _) = probe(
        t.path(),
        &[],
        &["--peer", &addr, "--force-direct", "--timeout-ms", "500"],
    );
    let wall = start.elapsed();
    assert_eq!(code, 1, "{doc}");
    let reason = doc["reason"].as_str().unwrap();
    assert!(reason == "timeout" || reason == "unreachable", "{doc}");
    assert!(wall <= Duration::from_millis(1500), "{wall:?}");
    gate_ran("net_probe::probe_unroutable_times_out");
}

/// PROBE-PID reject: an address without `/p2p/` is refused (Noise must authenticate a named peer).
#[test]
fn probe_requires_peer_id() {
    let t = empty_dir("nopid");
    let (code, doc, err) = probe(
        t.path(),
        &[],
        &["--peer", "/ip4/127.0.0.1/tcp/4001", "--force-direct"],
    );
    assert_eq!(code, 3);
    assert_eq!(doc["result"], "error");
    assert_eq!(doc["reason"], "reject.probe_peer_id_required");
    assert!(err.contains("reject.probe_peer_id_required"));
    gate_ran("net_probe::probe_requires_peer_id");
}

/// PROBE-DIRECT reject: a relay address under `--force-direct` is refused.
#[test]
fn probe_refuses_circuit_addr() {
    let t = empty_dir("circuit");
    let addr = format!(
        "/ip4/10.0.0.1/tcp/4001/p2p/{}/p2p-circuit/p2p/{}",
        other_pid(),
        other_pid()
    );
    let (code, doc, err) = probe(t.path(), &[], &["--peer", &addr, "--force-direct"]);
    assert_eq!(code, 3, "{doc}");
    assert_eq!(doc["reason"], "reject.probe_relay_addr_forced_direct");
    assert!(err.contains("reject.probe_relay_addr_forced_direct"));
    gate_ran("net_probe::probe_refuses_circuit_addr");
}

#[test]
fn probe_requires_mode_flag() {
    let t = empty_dir("mode");
    let addr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", other_pid());
    let (code, doc, _) = probe(t.path(), &[], &["--peer", &addr]);
    assert_eq!(code, 3);
    assert_eq!(doc["reason"], "reject.probe_mode_required");
    gate_ran("net_probe::probe_requires_mode_flag");
}

#[test]
fn probe_force_relay_unknown_flag() {
    let t = empty_dir("relay");
    let addr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", other_pid());
    let (code, doc, _) = probe(t.path(), &[], &["--peer", &addr, "--force-relay"]);
    assert_eq!(code, 2);
    assert!(doc.is_null());
    gate_ran("net_probe::probe_force_relay_unknown_flag");
}

fn lab_config(dir: &Path) -> PathBuf {
    let p = dir.join("lab.toml");
    std::fs::write(&p, "[lab]\nrelays = []\n").unwrap();
    p
}

/// PROBE-LAB reject: lab mode refuses a bare PeerId (it reads no state file).
#[test]
fn probe_lab_refuses_bare_peer_id() {
    let t = empty_dir("lab-bare");
    let cfg = lab_config(t.path());
    let data = t.path().join("d");
    let (code, doc, err) = probe(
        &data,
        &["--config", cfg.to_str().unwrap(), "--lab-deterministic"],
        &["--peer", &other_pid(), "--force-direct"],
    );
    assert_eq!(code, 3, "{doc} {err}");
    assert_eq!(doc["reason"], "reject.probe_bare_peer_id_lab");
    assert!(!data.exists(), "the probe created the data dir");
    gate_ran("net_probe::probe_lab_refuses_bare_peer_id");
}

/// Lab mode refuses a name, so none is resolved.
#[test]
fn probe_lab_refuses_dns_addr() {
    let t = empty_dir("lab-dns");
    let cfg = lab_config(t.path());
    let addr = format!("/dns4/b.example/tcp/4001/p2p/{}", other_pid());
    let (code, doc, err) = probe(
        &t.path().join("d"),
        &["--config", cfg.to_str().unwrap(), "--lab-deterministic"],
        &["--peer", &addr, "--force-direct"],
    );
    assert_eq!(code, 3, "{doc} {err}");
    assert_eq!(doc["reason"], "reject.lab_dns_addr");
    gate_ran("net_probe::probe_lab_refuses_dns_addr");
}

/// Exactly one dial, never a retry: one accept on a listener that accepts and closes.
#[test]
fn probe_makes_exactly_one_dial() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    l.set_nonblocking(true).unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let a = Arc::clone(&accepts);
    std::thread::spawn(move || loop {
        match l.accept() {
            Ok((s, _)) => {
                a.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    });
    let t = empty_dir("once");
    let addr = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{}", other_pid());
    let (code, doc, _) = probe(
        t.path(),
        &[],
        &["--peer", &addr, "--force-direct", "--timeout-ms", "2000"],
    );
    assert_eq!(code, 1, "{doc}");
    assert_eq!(doc["reason"], "noise_failed", "{doc}");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    gate_ran("net_probe::probe_makes_exactly_one_dial");
}

/// Against an empty data directory the probe connects, and the directory stays empty: no key
/// file was read (none existed) or created.
#[test]
fn probe_writes_no_files() {
    let d = spawn_daemon("nofiles");
    let t = empty_dir("nofiles-c");
    let (code, doc, err) = probe(t.path(), &[], &["--peer", &d.addr(), "--force-direct"]);
    assert_eq!(code, 0, "{doc} {err}");
    let left: Vec<_> = std::fs::read_dir(t.path()).unwrap().flatten().collect();
    assert!(left.is_empty(), "{left:?}");
    gate_ran("net_probe::probe_writes_no_files");
}

fn key_set(v: &serde_json::Value, prefix: &str, out: &mut BTreeSet<String>) {
    if let serde_json::Value::Object(m) = v {
        for (k, c) in m {
            let p = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            out.insert(p.clone());
            key_set(c, &p, out);
        }
    }
}

/// The key set equals the golden file, and the document meets the schema's required keys.
#[test]
fn probe_schema_golden() {
    let t = empty_dir("golden");
    let addr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", closed_port(), other_pid());
    let (_, doc, _) = probe(t.path(), &[], &["--peer", &addr, "--force-direct"]);
    let mut keys = BTreeSet::new();
    key_set(&doc, "", &mut keys);
    let golden: BTreeSet<String> = include_str!("golden/net-probe-1.keys")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    assert_eq!(keys, golden);
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../docs/schemas/net-probe-1.json")).unwrap();
    for req in schema["required"].as_array().unwrap() {
        assert!(doc.get(req.as_str().unwrap()).is_some(), "{req}");
    }
    assert_eq!(doc["schema"], schema["properties"]["schema"]["const"]);
    gate_ran("net_probe::probe_schema_golden");
}

#[test]
fn probe_no_rpc_skips_first_response() {
    let d = spawn_daemon("norpc");
    let t = empty_dir("norpc-c");
    let (code, doc, _) = probe(
        t.path(),
        &[],
        &["--peer", &d.addr(), "--force-direct", "--no-rpc"],
    );
    assert_eq!(code, 0, "{doc}");
    assert!(doc["timings_us"]["established"].is_u64());
    assert!(doc["timings_us"]["first_response"].is_null(), "{doc}");
    gate_ran("net_probe::probe_no_rpc_skips_first_response");
}
