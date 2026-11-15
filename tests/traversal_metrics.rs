//! Traversal counters and `/metrics` against the real `parvault` binary (`v0.5.4` NEW-3,
//! `docs/METRICS.md`). Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

use libp2p::futures::StreamExt;
use parvault::crypto::pqc::HybridPqSigningKeypair;
use parvault::crypto::{HybridKemKeypair, NodeIdentity};
use parvault::network::node_identity_libp2p_peer_id;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ROOT_KEY: [u8; 32] = [0x31; 32];
const GENESIS_SEED: [u8; 32] = [0x47; 32];

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

struct Daemon {
    child: Child,
    dir: PathBuf,
    log: PathBuf,
    status: Option<std::net::SocketAddr>,
    mesh: String,
    _root: tempfile::TempDir,
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

    fn peer_id(&self) -> libp2p::PeerId {
        node_identity_libp2p_peer_id(&NodeIdentity::load_or_generate_in_dir(&self.dir).unwrap())
            .unwrap()
    }

    /// The full `/p2p/` address of its mesh listener.
    fn addr(&self) -> String {
        format!("{}/p2p/{}", self.mesh, self.peer_id())
    }

    fn scrape(&self) -> String {
        scrape(self.status.expect("status listener"))
    }
}

fn scrape(addr: std::net::SocketAddr) -> String {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET /metrics HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {}\r\n\r\n",
        token()
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    text[text.find("\r\n\r\n").unwrap() + 4..].to_string()
}

/// The value of one exact series line (`name{labels}`), 0 if absent.
fn series(body: &str, key: &str) -> u64 {
    body.lines()
        .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(' ')))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

fn outcome(body: &str, origin: &str, transport: &str, reason: &str) -> u64 {
    series(
        body,
        &format!(
            "parvault_traversal_outcomes_total{{origin=\"{origin}\",path=\"direct\",transport=\"{transport}\",reason=\"{reason}\"}}"
        ),
    )
}

fn attempts(body: &str, origin: &str) -> u64 {
    series(
        body,
        &format!("parvault_traversal_attempts_total{{origin=\"{origin}\"}}"),
    )
}

fn sum_outcomes(body: &str, origin: &str) -> u64 {
    let prefix = format!("parvault_traversal_outcomes_total{{origin=\"{origin}\",");
    body.lines()
        .filter(|l| l.starts_with(&prefix))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// `parvault daemon start` on ephemeral loopback ports, with the status page when `status`.
fn spawn_daemon(label: &str, peers: &[String], status: bool) -> Daemon {
    spawn_daemon_with(
        Command::new(env!("CARGO_BIN_EXE_parvault")),
        label,
        peers,
        status,
        &[],
    )
}

fn spawn_daemon_with(
    mut cmd: Command,
    label: &str,
    peers: &[String],
    status: bool,
    extra: &[String],
) -> Daemon {
    let root = tempfile::Builder::new()
        .prefix(&format!("pv-mx-{label}-"))
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
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env_remove("PARVAULT_PEERS")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .arg("--data-dir")
        .arg(&dir)
        .arg("--no-lan-discovery");
    if !peers.is_empty() {
        cmd.arg("--peers").arg(peers.join(","));
    }
    cmd.args([
        "daemon",
        "start",
        "--listen",
        common::LOOPBACK_EPHEMERAL,
        "--no-socket",
    ]);
    if status {
        cmd.args(["--status-http", "127.0.0.1:0"]);
    }
    cmd.args(extra);
    let mut child = cmd
        .stdout(Stdio::from(f.try_clone().unwrap()))
        .stderr(Stdio::from(f))
        .spawn()
        .unwrap();
    let mesh = common::wait_for_listen_addr(
        &mut child,
        || std::fs::read_to_string(&log).unwrap_or_default(),
        Duration::from_secs(20),
    );
    let mut status_addr = None;
    if status {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if let Some(rest) = text.split("Status Server listening on http://").nth(1) {
                status_addr = Some(rest.split_whitespace().next().unwrap().parse().unwrap());
                break;
            }
            assert!(Instant::now() < deadline, "no status listener:\n{text}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    Daemon {
        child,
        dir,
        log,
        status: status_addr,
        mesh,
        _root: root,
    }
}

fn eventually(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    cond()
}

/// A loopback port nothing listens on (bound, then closed: connecting is refused).
fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// The source check: in `handle_status_conn`, the only `return` above the
/// `status_auth_decision(` call is the empty-head one, and the `"/metrics"` literal appears
/// only after that call and after `method != "GET"`.
#[test]
fn metrics_arm_below_status_auth() {
    let src = include_str!("../src/router_nas.rs");
    let start = src.find("fn handle_status_conn(").expect("handler");
    let body = &src[start..];
    let end = body[1..].find("\nfn ").map(|i| i + 1).unwrap_or(body.len());
    let body = &body[..end];
    let auth = body.find("status_auth_decision(").expect("decision call");
    let get = body.find("method != \"GET\"").expect("GET check");
    let above = &body[..auth];
    let returns: Vec<_> = above.match_indices("return").collect();
    assert_eq!(returns.len(), 1, "returns above the decision: {returns:?}");
    let ret_line = above[..returns[0].0].rsplit('\n').next().unwrap_or("");
    assert!(
        above[returns[0].0..].starts_with("return Ok(());") && ret_line.trim().is_empty(),
        "the one early return is not the empty-head one"
    );
    assert!(above.contains("let Some(head) = read_request_head(stream)? else {"));
    let metrics: Vec<_> = body.match_indices("\"/metrics\"").collect();
    assert!(!metrics.is_empty(), "no /metrics arm");
    for (i, _) in metrics {
        assert!(
            i > auth && i > get,
            "\"/metrics\" above the decision or the GET check"
        );
    }
    gate_ran("traversal_metrics::metrics_arm_below_status_auth");
}

/// The line count is the constant before and after traffic, and the body is under 32 KiB.
#[test]
fn metrics_series_count_is_constant() {
    let b = spawn_daemon("card-b", &[], false);
    let a = spawn_daemon(
        "card-a",
        &[b.addr(), format!("/ip4/127.0.0.1/tcp/{}", closed_port())],
        true,
    );
    let before = a.scrape();
    assert_eq!(
        before.lines().count(),
        parvault::traversal_metrics::LINE_COUNT
    );
    assert!(eventually(Duration::from_secs(15), || sum_outcomes(
        &a.scrape(),
        "daemon"
    ) >= 2));
    let after = a.scrape();
    assert_eq!(
        after.lines().count(),
        parvault::traversal_metrics::LINE_COUNT
    );
    assert!(after.len() < 32 * 1024);
    // Every line is a comment or a series from schema 1.
    let families: Vec<String> = include_str!("../docs/schemas/traversal-metrics-1.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with("reserved ") && !l.trim().is_empty())
        .map(|l| l.split_whitespace().next().unwrap().to_string())
        .collect();
    for line in after.lines().filter(|l| !l.starts_with('#')) {
        let name = line.split(['{', ' ']).next().unwrap();
        let family = name
            .trim_end_matches("_bucket")
            .trim_end_matches("_sum")
            .trim_end_matches("_count");
        assert!(
            families.iter().any(|f| f == name || f == family),
            "series {name} not in schema 1"
        );
    }
    gate_ran("traversal_metrics::metrics_series_count_is_constant");
}

/// No PeerId, IP or node label in the body.
#[test]
fn metrics_labels_carry_no_identifiers() {
    let b = spawn_daemon("ids-b", &[], false);
    let a = spawn_daemon("ids-a", &[b.addr()], true);
    assert!(eventually(Duration::from_secs(15), || outcome(
        &a.scrape(),
        "daemon",
        "tcp",
        "ok"
    ) >= 1));
    let body = a.scrape();
    for needle in ["12D3Koo", "Qm", "127.0.0.1", "::1", "parvault-"] {
        assert!(!body.contains(needle), "{needle} in:\n{body}");
    }
    let ipv4 = body
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|t| {
            t.split('.').count() == 4
                && t.split('.')
                    .all(|o| !o.is_empty() && o.parse::<u8>().is_ok())
        });
    assert!(!ipv4, "an IPv4 literal in:\n{body}");
    assert!(!body.contains(&a.peer_id().to_string()));
    gate_ran("traversal_metrics::metrics_labels_carry_no_identifiers");
}

/// During a burst of dials, every scrape has `attempts >= Σ outcomes` for each origin.
#[test]
fn metrics_attempts_cover_outcomes() {
    let peers: Vec<String> = (0..60)
        .map(|_| format!("/ip4/127.0.0.1/tcp/{}", closed_port()))
        .collect();
    let a = spawn_daemon("cover", &peers, true);
    let mut max_outcomes = 0;
    for _ in 0..200 {
        let body = a.scrape();
        for origin in ["daemon", "client"] {
            let (at, out) = (attempts(&body, origin), sum_outcomes(&body, origin));
            assert!(at >= out, "{origin}: attempts {at} < outcomes {out}");
        }
        max_outcomes = max_outcomes.max(sum_outcomes(&body, "daemon"));
    }
    assert!(max_outcomes > 0, "no dial outcome was ever scraped");
    gate_ran("traversal_metrics::metrics_attempts_cover_outcomes");
}

/// Real daemons on loopback: an `ok` (and B's inbound), a `refused`, a `peer_id_mismatch`, and
/// TEST-NET-1 as `timeout` or `unreachable`.
#[test]
fn metrics_count_dial_outcomes() {
    let b = spawn_daemon("out-b", &[], true);
    let c = spawn_daemon("out-c", &[], false);
    let b_before = b.scrape();
    let inbound_key = "parvault_traversal_inbound_total{path=\"direct\",transport=\"tcp\"}";
    let a = spawn_daemon("out-a", &[b.addr()], true);
    assert!(eventually(Duration::from_secs(15), || outcome(
        &a.scrape(),
        "daemon",
        "tcp",
        "ok"
    ) == 1));
    let body = a.scrape();
    assert!(attempts(&body, "daemon") >= 1);
    assert!(series(&b.scrape(), inbound_key) > series(&b_before, inbound_key));

    let r = spawn_daemon(
        "out-r",
        &[format!("/ip4/127.0.0.1/tcp/{}", closed_port())],
        true,
    );
    assert!(eventually(Duration::from_secs(15), || outcome(
        &r.scrape(),
        "daemon",
        "tcp",
        "refused"
    ) == 1));

    let wrong = format!("{}/p2p/{}", b.mesh, c.peer_id());
    let m = spawn_daemon("out-m", &[wrong], true);
    assert!(
        eventually(Duration::from_secs(15), || {
            let s = m.scrape();
            outcome(&s, "daemon", "tcp", "peer_id_mismatch")
                + outcome(&s, "daemon", "none", "peer_id_mismatch")
                == 1
        }),
        "{}",
        m.scrape()
    );

    let t = spawn_daemon("out-t", &["/ip4/192.0.2.1/tcp/4001".to_string()], true);
    assert!(
        eventually(Duration::from_secs(150), || {
            let s = t.scrape();
            outcome(&s, "daemon", "tcp", "timeout") + outcome(&s, "daemon", "tcp", "unreachable")
                == 1
        }),
        "{}",
        t.scrape()
    );
    gate_ran("traversal_metrics::metrics_count_dial_outcomes");
}

/// One dial of one peer with a closed TCP address and an unroutable QUIC address: one attempt,
/// one outcome, `refused` on `tcp` (the precedence). Run on the crate's own gated client swarm
/// (with QUIC on), since the daemon dials one address per endpoint.
#[test]
fn metrics_multi_address_precedence() {
    use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
    use parvault::traversal_metrics::{BuildInfo, Origin, TraversalCounters};
    let counters = std::sync::Arc::new(TraversalCounters::new(BuildInfo {
        profile: "desktop",
        deterministic: false,
    }));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let c2 = std::sync::Arc::clone(&counters);
    rt.block_on(async move {
        let mut sw = parvault::network::build_mesh_client_swarm_gated(
            libp2p::identity::Keypair::generate_ed25519(),
            true,
            parvault::network::GateParams::open().with_counters(Some(c2), Origin::Client),
        )
        .unwrap();
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let tcp: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", closed_port())
            .parse()
            .unwrap();
        let quic: libp2p::Multiaddr = "/ip4/192.0.2.1/udp/4001/quic-v1".parse().unwrap();
        sw.dial(
            DialOpts::peer_id(peer)
                .addresses(vec![quic, tcp])
                .condition(PeerCondition::Always)
                .build(),
        )
        .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            tokio::select! {
                ev = sw.select_next_some() => {
                    if let libp2p::swarm::SwarmEvent::OutgoingConnectionError { .. } = ev {
                        break;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => panic!("dial never failed"),
            }
        }
    });
    let body = counters.render_prometheus();
    assert_eq!(attempts(&body, "client"), 1);
    assert_eq!(sum_outcomes(&body, "client"), 1, "{body}");
    assert_eq!(outcome(&body, "client", "tcp", "refused"), 1, "{body}");
    gate_ran("traversal_metrics::metrics_multi_address_precedence");
}

/// No `--status-http`, no listener: the daemon binds no TCP port but its mesh port.
#[test]
fn metrics_absent_without_status_http() {
    let a = spawn_daemon("absent", &[], false);
    let log = a.log_text();
    assert!(!log.contains("Status Server listening"), "{log}");
    assert!(a.status.is_none());
    gate_ran("traversal_metrics::metrics_absent_without_status_http");
}

/// A default build has no `--lab-insecure-metrics`: clap rejects it (exit 2).
#[test]
fn insecure_listener_refused_without_feature() {
    let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .args(["--version", "--verbose"])
        .output()
        .unwrap();
    let v = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(v.contains("\nfeatures: none"), "{v}");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.args([
        "daemon",
        "start",
        "--lab-insecure-metrics",
        "lo=127.0.0.1:9100",
    ]);
    let out = common::output_within_deadline(&mut cmd);
    assert_eq!(out.status.code(), Some(2));
    gate_ran("traversal_metrics::insecure_listener_refused_without_feature");
}

/// The `parvault` binary with `lab-insecure-metrics` (dev profile, the only shape it builds in):
/// `CARGO_BIN_EXE_parvault` if it already has the feature, else built once from this tree into
/// its own target directory.
fn insecure_bin() -> PathBuf {
    static BIN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        let default = PathBuf::from(env!("CARGO_BIN_EXE_parvault"));
        let v = Command::new(&default)
            .args(["--version", "--verbose"])
            .output()
            .unwrap();
        if String::from_utf8_lossy(&v.stdout).contains("features: lab-insecure-metrics") {
            return default;
        }
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target"))
            .join("lab-insecure-metrics");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("CARGO_TARGET_DIR", &target)
            .args([
                "build",
                "--profile",
                "dev",
                "--features",
                "lab-insecure-metrics",
                "--bin",
                "parvault",
            ])
            .status()
            .unwrap();
        assert!(status.success(), "feature build failed");
        target.join("debug").join("parvault")
    })
    .clone()
}

fn insecure_get(addr: std::net::SocketAddr, host: &str) -> String {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(s, "GET /metrics HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    String::from_utf8_lossy(&raw).to_string()
}

/// METRICS-INSEC accept (feature build): on `lo=127.0.0.1` it serves without a token, with the
/// marker header; a DNS Host gets 403; a fifth concurrent connection is dropped.
#[test]
fn insecure_listener_on_named_iface_debug_only() {
    let bin = insecure_bin();
    let port = closed_port();
    let d = spawn_daemon_with(
        Command::new(&bin),
        "insec-ok",
        &[],
        false,
        &[
            "--lab-insecure-metrics".into(),
            format!("lo=127.0.0.1:{port}"),
        ],
    );
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    assert!(eventually(Duration::from_secs(10), || d
        .log_text()
        .contains("PARVAULT-LAB-INSECURE-METRICS-v1")));
    let ok = insecure_get(addr, &addr.to_string());
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    assert!(
        ok.contains("X-Parvault-Insecure-Metrics: PARVAULT-LAB-INSECURE-METRICS-v1\r\n"),
        "{ok}"
    );
    assert!(ok.contains("parvault_build_info{"), "{ok}");
    let dns = insecure_get(addr, &format!("rebind.example:{port}"));
    assert!(dns.starts_with("HTTP/1.1 403"), "{dns}");
    // Four idle connections hold every slot (5 s head timeout); the fifth is dropped unanswered.
    let held: Vec<_> = (0..4)
        .map(|_| std::net::TcpStream::connect(addr).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    let fifth = {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let _ = write!(s, "GET /metrics HTTP/1.1\r\nHost: {addr}\r\n\r\n");
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        raw
    };
    assert!(fifth.is_empty(), "{}", String::from_utf8_lossy(&fifth));
    drop(held);
    gate_ran("traversal_metrics::insecure_listener_on_named_iface_debug_only");
}

/// METRICS-INSEC reject (feature build): an IP that `lo` does not own is refused at start.
#[test]
fn insecure_listener_iface_mismatch_refused() {
    let bin = insecure_bin();
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("data");
    std::fs::create_dir_all(&dir).unwrap();
    let mut cmd = Command::new(&bin);
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env("RUST_LOG", "info")
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "daemon",
            "start",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
            "--no-socket",
            "--lab-insecure-metrics",
            "lo=10.255.255.1:9100",
        ]);
    let out = common::output_within_deadline(&mut cmd);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{text}");
    assert!(
        text.contains("reject.metrics_insecure_iface_mismatch"),
        "{text}"
    );
    gate_ran("traversal_metrics::insecure_listener_iface_mismatch_refused");
}
