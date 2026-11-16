//! `v0.5.6` track D suite: liveness and visibility (plan Sections 3.8 (b) to 3.11). Claims of track
//! D put their differential pairs here;
//! `tests/trust_enforcement.rs` is frozen.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

use parvault::crypto::pqc::HybridPqSigningKeypair;
use parvault::crypto::{HybridKemKeypair, NodeIdentity};
use parvault::network::node_identity_libp2p_peer_id;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ROOT_KEY: [u8; 32] = [0x44; 32];
const GENESIS_SEED: [u8; 32] = [0x4C; 32];

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

fn token() -> String {
    parvault::capabilities::CapabilityMacaroon::mint(
        &ROOT_KEY,
        [7; 32],
        [8; 32],
        vec![parvault::capabilities::Caveat::ReadOnly],
    )
    .unwrap()
    .to_compact_token()
}

/// A test node's data directory (identity, keys, root key) under its own temp root.
struct Node {
    root: tempfile::TempDir,
    dir: PathBuf,
}

impl Node {
    fn new(label: &str) -> Self {
        let root = tempfile::Builder::new()
            .prefix(&format!("pv-d056-{label}-"))
            .tempdir()
            .unwrap();
        let dir = root.path().join("data");
        std::fs::create_dir_all(&dir).unwrap();
        NodeIdentity::load_or_generate_in_dir(&dir).unwrap();
        HybridKemKeypair::load_or_generate_in_dir(&dir).unwrap();
        HybridPqSigningKeypair::load_or_generate_in_dir(&dir).unwrap();
        std::fs::write(dir.join("macaroon_root.key"), hex::encode(ROOT_KEY)).unwrap();
        Self { root, dir }
    }

    fn peer_id(&self) -> libp2p::PeerId {
        node_identity_libp2p_peer_id(&NodeIdentity::load_or_generate_in_dir(&self.dir).unwrap())
            .unwrap()
    }

    /// Starts `parvault daemon start` on `listen`, with `peers` and a status listener.
    fn start(&self, run: &str, listen: &str, peers: &[String]) -> Daemon {
        let log = self.root.path().join(format!("{run}.log"));
        let f = std::fs::File::create(&log).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
        cmd.env("PARVAULT_LAN_REGISTRY_DIR", self.root.path().join("reg"))
            .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
            .env_remove("PARVAULT_PEERS")
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .arg("--data-dir")
            .arg(&self.dir)
            .arg("--no-lan-discovery");
        if !peers.is_empty() {
            cmd.arg("--peers").arg(peers.join(","));
        }
        cmd.args([
            "daemon",
            "start",
            "--listen",
            listen,
            "--no-socket",
            "--status-http",
            "127.0.0.1:0",
        ]);
        let mut child = cmd
            .stdout(Stdio::from(f.try_clone().unwrap()))
            .stderr(Stdio::from(f))
            .spawn()
            .unwrap();
        let read = || std::fs::read_to_string(&log).unwrap_or_default();
        let mesh = common::wait_for_listen_addr(&mut child, read, Duration::from_secs(20));
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            let text = read();
            if let Some(rest) = text.split("Status Server listening on http://").nth(1) {
                break rest.split_whitespace().next().unwrap().parse().unwrap();
            }
            assert!(Instant::now() < deadline, "no status listener:\n{text}");
            std::thread::sleep(Duration::from_millis(50));
        };
        Daemon {
            child,
            log,
            status,
            mesh,
        }
    }
}

struct Daemon {
    child: Child,
    log: PathBuf,
    status: std::net::SocketAddr,
    mesh: String,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// `GET /live` with `auth` (a bearer token or none): (status line, body).
    fn get_live(&self, auth: Option<&str>) -> (String, String) {
        http_get(self.status, "/live", auth)
    }

    /// The daemon's live status (`/live`, with the read-only token).
    fn live(&self) -> serde_json::Value {
        let (head, body) = self.get_live(Some(&token()));
        assert!(head.starts_with("HTTP/1.1 200"), "{head}\n{body}");
        serde_json::from_str(&body).unwrap()
    }

    /// Whether the daemon's swarm reports `peer` connected.
    fn connected_to(&self, peer: &libp2p::PeerId) -> bool {
        let live = self.live();
        live["peers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["peer_id"] == peer.to_string() && p["connected"] == true)
    }
}

fn http_get(addr: std::net::SocketAddr, path: &str, auth: Option<&str>) -> (String, String) {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let auth = auth
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (head.to_string(), body.to_string())
}

fn eventually(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    cond()
}

/// R1 bound: the cap, its jitter, and 10 s for the dial and the swarm to report it (E5).
const REDIAL_BOUND: Duration = Duration::from_secs(30 + 30 / 4 + 10);

/// B157-REDIAL accept (R1, R2, R4): A is configured with B. B goes down for more than 2 minutes
/// and comes back on the same address; A's swarm redials it on its own, within the cap plus
/// jitter plus 10 s, as A's live status (the swarm's connected set) and B's own show. No client
/// command and no PoR audit runs (an audit dials for itself, R4).
#[test]
fn b157_restarted_peer_redialled() {
    let b_node = Node::new("b157-b");
    let a_node = Node::new("b157-a");
    let b = b_node.start("b1", common::LOOPBACK_EPHEMERAL, &[]);
    let b_listen = b.mesh.clone();
    let b_addr = format!("{b_listen}/p2p/{}", b_node.peer_id());
    let a = a_node.start("a", common::LOOPBACK_EPHEMERAL, &[b_addr]);
    let b_pid = b_node.peer_id();
    let a_pid = a_node.peer_id();
    assert!(
        eventually(Duration::from_secs(20), || a.connected_to(&b_pid)),
        "{}",
        a.log_text()
    );
    b.stop();
    assert!(
        eventually(Duration::from_secs(20), || !a.connected_to(&b_pid)),
        "A still reports B connected"
    );
    // Down for more than 2 minutes: A's backoff reaches its cap.
    std::thread::sleep(Duration::from_secs(125));
    assert!(!a.connected_to(&b_pid));
    let back = Instant::now();
    let b = b_node.start("b2", &b_listen, &[]);
    assert!(
        eventually(REDIAL_BOUND, || a.connected_to(&b_pid)),
        "A did not redial B within {REDIAL_BOUND:?}:\n{}",
        a.log_text()
    );
    let took = back.elapsed();
    assert!(
        eventually(Duration::from_secs(10), || b.connected_to(&a_pid)),
        "B's swarm does not see A"
    );
    let log = a.log_text();
    assert!(log.contains("redialling a ring peer"), "{log}");
    // B-148 item 1: the lazy-admission line is DEBUG, so an INFO log never shows it.
    assert!(!log.contains("not yet admitted"), "{log}");
    assert!(
        !log.contains("peer not added to the Kademlia routing table"),
        "{log}"
    );
    eprintln!("b157: redialled {took:?} after B came back");
    gate_ran("trust_enforcement_liveness::b157_restarted_peer_redialled");
}

/// B157-REDIAL reject (R2): B dials A; A has no `--peers` and never admitted B. When B goes
/// away, A does not redial it: it is not a ring member A knows (`reject.redial_not_ring_member`),
/// and the address B came from is an observed, ephemeral one.
#[test]
fn b157_unknown_addr_not_redialled() {
    let a_node = Node::new("b157r-a");
    let b_node = Node::new("b157r-b");
    let a = a_node.start("a", common::LOOPBACK_EPHEMERAL, &[]);
    let a_addr = format!("{}/p2p/{}", a.mesh, a_node.peer_id());
    let b = b_node.start("b", common::LOOPBACK_EPHEMERAL, &[a_addr]);
    let b_pid = b_node.peer_id();
    assert!(
        eventually(Duration::from_secs(20), || a.connected_to(&b_pid)),
        "B never reached A:\n{}",
        b.log_text()
    );
    let live = a.live();
    let entry = live["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["peer_id"] == b_pid.to_string())
        .cloned()
        .unwrap();
    assert_eq!(entry["admitted"], false, "{entry}");
    b.stop();
    // Longer than the first three backoff steps (1 + 2 + 4 s) and the cap's jitter.
    std::thread::sleep(Duration::from_secs(15));
    let log = a.log_text();
    assert!(!log.contains("redialling a ring peer"), "{log}");
    assert!(!a.connected_to(&b_pid));
    assert_eq!(
        parvault::network::redial::redial_decision(false, false, false, 0, u64::MAX),
        Err("reject.redial_not_ring_member")
    );
    gate_ran("trust_enforcement_liveness::b157_unknown_addr_not_redialled");
}

/// B-148 item 2 accept (V1): `/live` with the read-only token returns the daemon's live state:
/// its listen address, its connected peer, its anonymous memory; every list within its caps.
#[test]
fn b148_live_status_served_with_token() {
    let b_node = Node::new("b148-b");
    let a_node = Node::new("b148-a");
    let b = b_node.start("b", common::LOOPBACK_EPHEMERAL, &[]);
    let b_addr = format!("{}/p2p/{}", b.mesh, b_node.peer_id());
    let a = a_node.start("a", common::LOOPBACK_EPHEMERAL, &[b_addr]);
    let b_pid = b_node.peer_id();
    assert!(eventually(Duration::from_secs(20), || a.connected_to(&b_pid)));
    let live = a.live();
    let listen: Vec<String> = live["listen_addrs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(listen.contains(&a.mesh), "{listen:?} vs {}", a.mesh);
    assert!(live["anon_rss_bytes"].as_u64().unwrap() > 0, "{live}");
    let snap: parvault::live_status::LiveStatusSnapshot = serde_json::from_value(live).unwrap();
    assert!(snap.within_caps());
    drop(b);
    gate_ran("trust_enforcement_liveness::b148_live_status_served_with_token");
}

/// B-148 item 2 reject: `/live` without a token is refused (`reject.status_token_missing`,
/// the status decision), and says nothing about the daemon's peers.
#[test]
fn b148_live_status_refused_without_token() {
    let a_node = Node::new("b148r-a");
    let a = a_node.start("a", common::LOOPBACK_EPHEMERAL, &[]);
    let (head, body) = a.get_live(None);
    assert!(!head.starts_with("HTTP/1.1 200"), "{head}\n{body}");
    assert!(!body.contains("peer_id"), "{body}");
    assert!(
        eventually(Duration::from_secs(5), || a
            .log_text()
            .contains("reject.status_token_missing")),
        "{}",
        a.log_text()
    );
    gate_ran("trust_enforcement_liveness::b148_live_status_refused_without_token");
}

/// T0 stub of track D still standing: the CLI half of `status --live` (it needs the daemon's
/// socket, a flag the Lead adds to the frozen `config.rs`).
#[test]
fn track_d_status_live_cli_unbuilt() {
    let tmp = tempfile::tempdir().unwrap();
    let out = common::parvault_in(&tmp.path().join("node"), &["status", "--live"]);
    common::assert_not_built_yet(&out, "status --live");
    gate_ran("trust_enforcement_liveness::track_d_status_live_cli_unbuilt");
}
