//! Deterministic lab mode against the real `parvault` binary (`v0.5.4` NEW-5,
//! `docs/LAB_MODE.md`). Every test writes its sentinel (`gate_ran`) last, after its assertions.
//!
//! Lab mode refuses port 0, so these daemons bind fixed ports. To keep two test processes from
//! co-binding one (libp2p-tcp sets `SO_REUSEPORT`), each address is a random `127.x.y.z` with a
//! random port: every address in `127.0.0.0/8` is on the loopback interface.

mod common;

use libp2p::futures::StreamExt;
use libp2p::{swarm::SwarmEvent, Multiaddr, PeerId};
use parvault::crypto::pqc::HybridPqSigningKeypair;
use parvault::crypto::{HybridKemKeypair, NodeIdentity};
use parvault::network::node_identity_libp2p_peer_id;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// A random loopback IP (`127.x.y.z`, never `127.0.0.1`).
fn lab_ip() -> String {
    let b: [u8; 3] = rand::random();
    format!(
        "127.{}.{}.{}",
        1 + b[0] % 250,
        1 + b[1] % 250,
        2 + b[2] % 250
    )
}

fn lab_port() -> u16 {
    20000 + rand::random::<u16>() % 40000
}

/// A fixed TCP listen multiaddr on a random loopback IP.
fn lab_listen() -> String {
    format!("/ip4/{}/tcp/{}", lab_ip(), lab_port())
}

/// A TCP listener the test owns, counting accepts (each accepted socket is closed at once).
struct CountingListener {
    addr: std::net::SocketAddr,
    accepts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl CountingListener {
    fn bind() -> Self {
        let l = TcpListener::bind((lab_ip().as_str(), 0)).expect("bind counting listener");
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (a, s) = (Arc::clone(&accepts), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match l.accept() {
                    Ok((sock, _)) => {
                        a.fetch_add(1, Ordering::SeqCst);
                        drop(sock);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Self {
            addr,
            accepts,
            stop,
        }
    }

    fn multiaddr(&self) -> String {
        format!("/ip4/{}/tcp/{}", self.addr.ip(), self.addr.port())
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

impl Drop for CountingListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// A spawned binary with its data directory and log; killed on drop.
struct Node {
    child: Child,
    dir: PathBuf,
    log: PathBuf,
    _root: TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn peer_id(&self) -> PeerId {
        node_identity_libp2p_peer_id(&NodeIdentity::load_or_generate_in_dir(&self.dir).unwrap())
            .unwrap()
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Waits until the log contains `needle`; panics if the process exits first.
    fn wait_for(&mut self, needle: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let text = self.log_text();
            if text.contains(needle) {
                return;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("exited ({status}) before logging {needle:?}:\n{text}");
            }
            assert!(Instant::now() < deadline, "{needle:?} not logged:\n{text}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// A test root with a data directory whose keys are pre-created (so the test knows the PeerId).
fn prepare(label: &str) -> (TempDir, PathBuf) {
    let root = tempfile::Builder::new()
        .prefix(&format!("pv-lab-{label}-"))
        .tempdir()
        .unwrap();
    let dir = root.path().join("data");
    std::fs::create_dir_all(&dir).unwrap();
    NodeIdentity::load_or_generate_in_dir(&dir).unwrap();
    HybridKemKeypair::load_or_generate_in_dir(&dir).unwrap();
    HybridPqSigningKeypair::load_or_generate_in_dir(&dir).unwrap();
    (root, dir)
}

/// Writes a lab config (`[lab] deterministic = true`, `relays = []`) with `extra` top-level keys.
fn lab_toml(root: &Path, extra: &str) -> PathBuf {
    let path = root.join("lab.toml");
    std::fs::write(
        &path,
        format!("{extra}\n[lab]\ndeterministic = true\nrelays = []\n"),
    )
    .unwrap();
    path
}

/// `parvault` with a clean environment for the variables lab mode refuses.
fn parvault() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    for v in [
        "PARVAULT_LAN_REGISTRY_DIR",
        "PARVAULT_PEERS",
        "PARVAULT_SEED_ADDR",
        "PARVAULT_WAN_SEEDS",
        "PARVAULT_TRACKERS",
        "PARVAULT_PUBLIC",
        "PARVAULT_GENESIS_PUBKEY_HEX",
    ] {
        cmd.env_remove(v);
    }
    cmd.env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED));
    cmd
}

fn spawn_logged(mut cmd: Command, root: TempDir, dir: PathBuf) -> Node {
    let log = root.path().join("node.log");
    let f = std::fs::File::create(&log).unwrap();
    let child = cmd
        .stdout(Stdio::from(f.try_clone().unwrap()))
        .stderr(Stdio::from(f))
        .spawn()
        .expect("spawn parvault");
    Node {
        child,
        dir,
        log,
        _root: root,
    }
}

/// Runs a command that must refuse to start: exit 3 with `code` on stderr.
fn assert_startup_refused(mut cmd: Command, code: &str) -> String {
    let out = common::output_within_deadline(&mut cmd);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(out.status.code(), Some(3), "{code}: stderr:\n{stderr}");
    assert!(stderr.contains(code), "{code} not in stderr:\n{stderr}");
    stderr
}

fn daemon_cmd(dir: &Path, toml: &Path, listen: &str) -> Command {
    let mut cmd = parvault();
    cmd.arg("--data-dir")
        .arg(dir)
        .arg("--config")
        .arg(toml)
        .args(["daemon", "start", "--listen", listen]);
    cmd
}

/// The socket inodes of `pid` that are UDP sockets (from `/proc/net/udp` and `udp6`), with
/// their local ports.
fn udp_sockets_of(pid: u32) -> Vec<u16> {
    let mut inodes = std::collections::HashSet::new();
    if let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
        for e in rd.flatten() {
            if let Ok(target) = std::fs::read_link(e.path()) {
                let t = target.to_string_lossy().to_string();
                if let Some(ino) = t.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
                    inodes.insert(ino.to_string());
                }
            }
        }
    }
    let mut ports = Vec::new();
    for table in ["/proc/net/udp", "/proc/net/udp6"] {
        let text = std::fs::read_to_string(table).unwrap_or_default();
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() > 9 && inodes.contains(cols[9]) {
                let port = cols[1]
                    .rsplit(':')
                    .next()
                    .and_then(|p| u16::from_str_radix(p, 16).ok())
                    .unwrap_or(0);
                ports.push(port);
            }
        }
    }
    ports
}

/// LAB-CONFLICT, LAB-PORT, LAB-DNS accept: a deterministic daemon with fixed IP-literal binds and
/// an IP-literal `/p2p/` dial set starts and binds where it was told.
#[test]
fn deterministic_daemon_starts_with_fixed_ports() {
    let (root, dir) = prepare("ok");
    let peer = NodeIdentity::generate();
    let peer_addr = format!(
        "{}/p2p/{}",
        lab_listen(),
        node_identity_libp2p_peer_id(&peer).unwrap()
    );
    let listen = lab_listen();
    let toml = lab_toml(
        root.path(),
        &format!("bootstrap_peers = [\"{peer_addr}\"]\nlan_discovery_enabled = false"),
    );
    let cmd = daemon_cmd(&dir, &toml, &listen);
    let mut node = spawn_logged(cmd, root, dir);
    node.wait_for(&listen, Duration::from_secs(20));
    let log = node.log_text();
    assert!(log.contains("deterministic=true"), "{log}");
    assert!(log.contains("config_digest="), "{log}");
    gate_ran("lab_deterministic::deterministic_daemon_starts_with_fixed_ports");
}

/// LAB-PORT reject: port 0 is refused at startup.
#[test]
fn deterministic_refuses_ephemeral_port() {
    let (root, dir) = prepare("eph");
    let toml = lab_toml(root.path(), "");
    let cmd = daemon_cmd(&dir, &toml, &format!("/ip4/{}/tcp/0", lab_ip()));
    assert_startup_refused(cmd, "reject.lab_ephemeral_port");
    gate_ran("lab_deterministic::deterministic_refuses_ephemeral_port");
}

/// The unspecified-bind rule, on the mesh TCP listener.
#[test]
fn deterministic_refuses_unspecified_bind() {
    let (root, dir) = prepare("unspec");
    let toml = lab_toml(root.path(), "");
    let cmd = daemon_cmd(&dir, &toml, "/ip4/0.0.0.0/tcp/4001");
    assert_startup_refused(cmd, "reject.lab_unspecified_bind");
    gate_ran("lab_deterministic::deterministic_refuses_unspecified_bind");
}

/// The unspecified-bind rule, on the status listener.
#[test]
fn deterministic_refuses_unspecified_status_bind() {
    let (root, dir) = prepare("unspec-st");
    let toml = lab_toml(root.path(), "");
    let mut cmd = daemon_cmd(&dir, &toml, &lab_listen());
    cmd.args(["--status-http", "0.0.0.0:4080"]);
    assert_startup_refused(cmd, "reject.lab_unspecified_bind");
    gate_ran("lab_deterministic::deterministic_refuses_unspecified_status_bind");
}

/// The unspecified-bind rule, on the built-in WebDAV listener.
#[test]
fn deterministic_refuses_unspecified_webdav_bind() {
    let (root, dir) = prepare("unspec-dav");
    let toml = lab_toml(root.path(), "");
    let mut cmd = daemon_cmd(&dir, &toml, &lab_listen());
    cmd.args(["--no-socket", "--vfs-webdav-listen", "[::]:4081"]);
    assert_startup_refused(cmd, "reject.lab_unspecified_bind");
    gate_ran("lab_deterministic::deterministic_refuses_unspecified_webdav_bind");
}

/// LAB-CONFLICT reject: an explicit `lan_discovery_enabled = true` conflicts; the message names
/// the key and its source.
#[test]
fn deterministic_refuses_explicit_lan_discovery() {
    let (root, dir) = prepare("lan");
    let toml = lab_toml(root.path(), "lan_discovery_enabled = true");
    let cmd = daemon_cmd(&dir, &toml, &lab_listen());
    let stderr = assert_startup_refused(cmd, "reject.lab_config_conflict");
    assert!(
        stderr.contains("lan_discovery_enabled (source file)"),
        "{stderr}"
    );
    gate_ran("lab_deterministic::deterministic_refuses_explicit_lan_discovery");
}

/// `PARVAULT_LAN_REGISTRY_DIR` set is a conflict.
#[test]
fn deterministic_refuses_lan_registry_env() {
    let (root, dir) = prepare("reg");
    let toml = lab_toml(root.path(), "");
    let mut cmd = daemon_cmd(&dir, &toml, &lab_listen());
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"));
    let stderr = assert_startup_refused(cmd, "reject.lab_config_conflict");
    assert!(stderr.contains("env:PARVAULT_LAN_REGISTRY_DIR"), "{stderr}");
    gate_ran("lab_deterministic::deterministic_refuses_lan_registry_env");
}

/// A dial-set address without `/p2p/` is refused.
#[test]
fn deterministic_refuses_addr_without_peer_id() {
    let (root, dir) = prepare("nopid");
    let toml = lab_toml(root.path(), "");
    let mut cmd = daemon_cmd(&dir, &toml, &lab_listen());
    cmd.args(["--peers", &lab_listen()]);
    assert_startup_refused(cmd, "reject.lab_addr_without_peer_id");
    gate_ran("lab_deterministic::deterministic_refuses_addr_without_peer_id");
}

/// LAB-DNS reject: a name in the dial set is refused, so none is ever resolved.
#[test]
fn deterministic_refuses_dns_addr() {
    let (root, dir) = prepare("dns");
    let peer = node_identity_libp2p_peer_id(&NodeIdentity::generate()).unwrap();
    let toml = lab_toml(root.path(), "");
    let mut cmd = daemon_cmd(&dir, &toml, &lab_listen());
    cmd.args(["--peers", &format!("/dns4/b.example/tcp/4001/p2p/{peer}")]);
    assert_startup_refused(cmd, "reject.lab_dns_addr");
    gate_ran("lab_deterministic::deterministic_refuses_dns_addr");
}

/// `[lab] relays` must be given (it may be empty).
#[test]
fn deterministic_refuses_missing_relays() {
    let (root, dir) = prepare("relays");
    let toml = root.path().join("lab.toml");
    std::fs::write(&toml, "[lab]\ndeterministic = true\n").unwrap();
    let cmd = daemon_cmd(&dir, &toml, &lab_listen());
    assert_startup_refused(cmd, "reject.lab_relays_missing");
    gate_ran("lab_deterministic::deterministic_refuses_missing_relays");
}

/// LAB-SIDE accept: outside lab mode `discover` runs.
#[test]
fn discover_allowed_outside_lab_mode() {
    let (root, dir) = prepare("disc-ok");
    let mut cmd = parvault();
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .arg("--data-dir")
        .arg(&dir)
        .args(["discover", "--timeout-ms", "100", "--json"]);
    let out = common::output_within_deadline(&mut cmd);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    gate_ran("lab_deterministic::discover_allowed_outside_lab_mode");
}

/// LAB-SIDE reject: `discover` is a side channel and exits 3 in lab mode (`pair` and `join` too).
#[test]
fn discover_refused_in_lab_mode() {
    let (root, dir) = prepare("disc");
    let toml = lab_toml(root.path(), "");
    for args in [
        vec!["discover", "--timeout-ms", "100"],
        vec!["pair", "--once"],
        vec!["join", "--code", "anchor-velvet-orbit-oak"],
    ] {
        let mut cmd = parvault();
        cmd.arg("--data-dir")
            .arg(&dir)
            .arg("--config")
            .arg(&toml)
            .args(&args);
        assert_startup_refused(cmd, "reject.lab_side_channel");
    }
    gate_ran("lab_deterministic::discover_refused_in_lab_mode");
}

/// No mDNS (5353), no LAN beacon (4009), no UDP socket at all without QUIC.
#[test]
fn deterministic_daemon_binds_no_discovery_udp() {
    let (root, dir) = prepare("udp");
    let listen = lab_listen();
    let toml = lab_toml(root.path(), "");
    let cmd = daemon_cmd(&dir, &toml, &listen);
    let mut node = spawn_logged(cmd, root, dir);
    node.wait_for(&listen, Duration::from_secs(20));
    std::thread::sleep(Duration::from_secs(10));
    let udp = udp_sockets_of(node.pid());
    assert!(udp.is_empty(), "UDP sockets bound: {udp:?}");
    gate_ran("lab_deterministic::deterministic_daemon_binds_no_discovery_udp");
}

/// Writes a `known_peers.json` naming `target` (a test listener) as the pinned peer `pid`.
fn pin_known_peer(dir: &Path, pid: &PeerId, target: &str) -> Vec<u8> {
    parvault::network::KnownPeersStore::update(dir, |s| {
        s.upsert_pinned_multiaddr(&pid.to_string(), target, Some("planted"), Some("node"));
    })
    .unwrap();
    std::fs::read(dir.join("known_peers.json")).unwrap()
}

/// Empty `bootstrap_peers` and a `known_peers.json` naming a test listener: in 10 s no UDP
/// socket, no accept on the listener, and the file is unchanged.
#[test]
fn deterministic_empty_bootstrap_no_scan() {
    let (root, dir) = prepare("noscan");
    let x = CountingListener::bind();
    let fake = node_identity_libp2p_peer_id(&NodeIdentity::generate()).unwrap();
    let before = pin_known_peer(&dir, &fake, &x.multiaddr());
    let listen = lab_listen();
    let toml = lab_toml(root.path(), "");
    let cmd = daemon_cmd(&dir, &toml, &listen);
    let mut node = spawn_logged(cmd, root, dir);
    node.wait_for(&listen, Duration::from_secs(20));
    std::thread::sleep(Duration::from_secs(10));
    assert!(udp_sockets_of(node.pid()).is_empty());
    assert_eq!(x.accepts(), 0, "dialled a known_peers.json entry");
    assert_eq!(
        std::fs::read(node.dir.join("known_peers.json")).unwrap(),
        before
    );
    gate_ran("lab_deterministic::deterministic_empty_bootstrap_no_scan");
}

/// A real libp2p peer B in this process (the crate's own server swarm): it listens on loopback,
/// records who connected, and names peer C' at `x` in its Kademlia routing table, so a Kademlia
/// query to B returns C' at `x`: a remote-supplied ("learned") address.
struct PeerB {
    addr: String,
    connected: Arc<Mutex<Vec<PeerId>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for PeerB {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn spawn_peer_b(x: &str) -> PeerB {
    let x: Multiaddr = x.parse().unwrap();
    let connected = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel();
    let (c, s) = (Arc::clone(&connected), Arc::clone(&stop));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let kp = libp2p::identity::Keypair::generate_ed25519();
            let pid = kp.public().to_peer_id();
            let mut sw = parvault::network::build_mesh_server_swarm(kp, false, false).unwrap();
            let c_prime = libp2p::identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id();
            sw.behaviour_mut().kademlia.add_address(&c_prime, x);
            let listen: Multiaddr = format!("/ip4/{}/tcp/0", lab_ip()).parse().unwrap();
            sw.listen_on(listen).unwrap();
            let mut tick = tokio::time::interval(Duration::from_millis(100));
            let mut tx = Some(tx);
            // Requests are held unanswered, so the client keeps its connection (and its
            // Kademlia bootstrap) going until its request timeouts.
            let mut held = Vec::new();
            loop {
                tokio::select! {
                    ev = sw.select_next_some() => match ev {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            if let Some(tx) = tx.take() {
                                let _ = tx.send(format!("{address}/p2p/{pid}"));
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            c.lock().unwrap().push(peer_id);
                        }
                        SwarmEvent::Behaviour(
                            parvault::network::behaviour::MeshNetworkBehaviourEvent::ReqResp(
                                libp2p::request_response::Event::Message {
                                    message: libp2p::request_response::Message::Request {
                                        channel, ..
                                    },
                                    ..
                                },
                            ),
                        ) => held.push(channel),
                        _ => {}
                    },
                    _ = tick.tick() => {
                        if s.load(Ordering::SeqCst) {
                            break;
                        }
                    }
                }
            }
        });
    });
    let addr = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("peer B listening");
    PeerB {
        addr,
        connected,
        stop,
    }
}

/// `parvault file store` of a small file to B (`--peers B`), optionally in lab mode. It keeps the
/// client worker busy while Kademlia bootstraps through B.
fn store_via(b: &PeerB, lab: bool, label: &str) -> Node {
    let (root, dir) = prepare(label);
    let file = root.path().join("payload.bin");
    std::fs::write(&file, vec![0x5Au8; 4096]).unwrap();
    let mut cmd = parvault();
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .arg("--data-dir")
        .arg(&dir);
    if lab {
        let toml = lab_toml(root.path(), "");
        cmd.arg("--config").arg(toml);
    } else {
        cmd.arg("--no-lan-discovery");
    }
    cmd.args(["--peers", &b.addr, "file", "store"])
        .arg(&file)
        .args([
            "--key-hex",
            &hex::encode([0x11u8; 32]),
            "--allow-local-only",
        ]);
    if lab {
        cmd.env_remove("PARVAULT_LAN_REGISTRY_DIR");
    }
    spawn_logged(cmd, root, dir)
}

/// Waits up to `timeout` for `cond`.
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

/// LAB-DIAL accept: a deterministic client connects to its dial-set peer B, and never to the
/// address B's Kademlia names (zero accepts on X).
#[test]
fn deterministic_dials_only_dial_set() {
    let x = CountingListener::bind();
    let b = spawn_peer_b(&x.multiaddr());
    let a = store_via(&b, true, "dial-ok");
    let a_pid = a.peer_id();
    assert!(
        eventually(Duration::from_secs(15), || b
            .connected
            .lock()
            .unwrap()
            .contains(&a_pid)),
        "A never connected to B:\n{}",
        a.log_text()
    );
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(x.accepts(), 0, "A dialled a learned address");
    gate_ran("lab_deterministic::deterministic_dials_only_dial_set");
}

/// LAB-DIAL reject: the learned address is refused by the gate, which logs its code; X sees no
/// connection.
#[test]
fn deterministic_refuses_learned_addr() {
    let x = CountingListener::bind();
    let b = spawn_peer_b(&x.multiaddr());
    let a = store_via(&b, true, "dial-learned");
    assert!(
        eventually(Duration::from_secs(15), || a
            .log_text()
            .contains("reject.lab_dial_outside_set")),
        "no gate refusal logged:\n{}",
        a.log_text()
    );
    assert_eq!(x.accepts(), 0);
    gate_ran("lab_deterministic::deterministic_refuses_learned_addr");
}

/// The control for the pair above: outside lab mode the same run dials X, so the tests can see
/// the leak they assert is closed.
#[test]
fn learned_addr_dialled_outside_lab_mode() {
    let x = CountingListener::bind();
    let b = spawn_peer_b(&x.multiaddr());
    let a = store_via(&b, false, "dial-control");
    assert!(
        eventually(Duration::from_secs(20), || x.accepts() > 0),
        "control: X never dialled:\n{}",
        a.log_text()
    );
    gate_ran("lab_deterministic::learned_addr_dialled_outside_lab_mode");
}

/// An onion relay request naming `x` as the next hop, from a ring member (the daemon gets the
/// test genesis).
fn relay_to(node_addr: &str, x: &str, node_dir: &Path) -> parvault::network::MeshWireResponse {
    use parvault::crypto::{MasterKey, PqRelayedShardEnvelope};
    use parvault::network::admission::AdmissionSource;
    use parvault::storage::{AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId};
    let relay = NodeIdentity::from_seed([0x5E; 32]);
    let mk = MasterKey::from_bytes([0x61; 32]);
    let bytes = vec![0x3C; 256];
    let id = BlindedShardId::derive(&mk, &[0x61; 32], 0, &bytes);
    let (_cap_ident, cap) = BlindedShardCapability::derive_keypair(&mk, &id.locator);
    let kem = HybridKemKeypair::load_or_generate_in_dir(node_dir)
        .unwrap()
        .public_key();
    let req = parvault::network::MeshWireRequest::RelayPqOnionEnvelope {
        target_peer_addr: Some(x.to_string()),
        envelope: PqRelayedShardEnvelope::seal_pq(&kem, "relay", &id, &bytes, 0).unwrap(),
        capability: cap,
        voucher: AnonymousQuotaVoucher::mint(&relay, 8192),
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: [0x62; 32],
    };
    parvault::network::MeshClient::new(relay, Vec::new(), None)
        .with_admission(AdmissionSource::from_genesis(NodeIdentity::from_seed(
            GENESIS_SEED,
        )))
        .with_timeout(Duration::from_secs(10))
        .send_request(node_addr, req)
        .expect("relay request")
}

const GENESIS_SEED: [u8; 32] = [0x47; 32];

fn relay_daemon(lab: bool, label: &str) -> (Node, String) {
    let (root, dir) = prepare(label);
    let listen = lab_listen();
    let mut cmd = parvault();
    cmd.arg("--data-dir").arg(&dir);
    if lab {
        let toml = lab_toml(root.path(), "");
        cmd.arg("--config").arg(toml);
    } else {
        cmd.env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
            .arg("--no-lan-discovery");
    }
    cmd.args(["daemon", "start", "--listen", &listen]);
    let mut node = spawn_logged(cmd, root, dir);
    node.wait_for(&listen, Duration::from_secs(20));
    let addr = format!("{listen}/p2p/{}", node.peer_id());
    (node, addr)
}

/// A remote-named next hop is never dialled in lab mode: the ack is `delivered: false`, the log
/// has `reject.lab_relay_forward`, X has no accept.
#[test]
fn deterministic_refuses_relay_forward() {
    let x = CountingListener::bind();
    let (node, addr) = relay_daemon(true, "relay");
    let resp = relay_to(&addr, &x.multiaddr(), &node.dir);
    match resp {
        parvault::network::MeshWireResponse::RelayPqOnionAck { delivered, error } => {
            assert!(!delivered);
            assert_eq!(
                error.as_deref(),
                Some(parvault::network::wire_handler::LAB_RELAY_FORWARD_OFF_TEXT)
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(eventually(Duration::from_secs(5), || node
        .log_text()
        .contains("reject.lab_relay_forward")));
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(x.accepts(), 0);
    gate_ran("lab_deterministic::deterministic_refuses_relay_forward");
}

/// The control: outside lab mode the same request makes the daemon dial X.
#[test]
fn relay_forward_dialled_outside_lab_mode() {
    let x = CountingListener::bind();
    let (node, addr) = relay_daemon(false, "relay-control");
    let _ = relay_to(&addr, &x.multiaddr(), &node.dir);
    assert!(
        eventually(Duration::from_secs(15), || x.accepts() > 0),
        "control: next hop never dialled:\n{}",
        node.log_text()
    );
    gate_ran("lab_deterministic::relay_forward_dialled_outside_lab_mode");
}

/// A2: a `folder` command in lab mode (the lite-seed network path, which builds its own clients)
/// dials neither a `known_peers.json` entry nor a seed outside the dial set.
#[test]
fn folder_command_in_lab_mode_dials_no_state_file_peer() {
    let (root, dir) = prepare("folder");
    let x = CountingListener::bind();
    let y = CountingListener::bind();
    let fake = node_identity_libp2p_peer_id(&NodeIdentity::generate()).unwrap();
    pin_known_peer(&dir, &fake, &x.multiaddr());
    let seed_pid = node_identity_libp2p_peer_id(&NodeIdentity::generate()).unwrap();
    let folder = root.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"lab").unwrap();
    let toml = lab_toml(root.path(), "");
    let mut cmd = parvault();
    cmd.arg("--data-dir")
        .arg(&dir)
        .arg("--config")
        .arg(&toml)
        .args(["watch-folder", "--folder"])
        .arg(&folder)
        .arg("--snapshot-out")
        .arg(root.path().join("snap.manifest.bin"))
        .args([
            "--once",
            "--allow-local-only",
            "--key-hex",
            &hex::encode([0x22u8; 32]),
            "--lite-seed-addr",
            &format!("{}/p2p/{seed_pid}", y.multiaddr()),
        ]);
    let out = common::output_within_deadline(&mut cmd);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!text.contains("not in a ring"), "{text}");
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(x.accepts(), 0, "dialled a known_peers.json entry:\n{text}");
    assert_eq!(
        y.accepts(),
        0,
        "dialled a seed outside the dial set:\n{text}"
    );
    let _ = root;
    gate_ran("lab_deterministic::folder_command_in_lab_mode_dials_no_state_file_peer");
}
