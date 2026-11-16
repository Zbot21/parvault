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
        let key = dir.join("macaroon_root.key");
        std::fs::write(&key, hex::encode(ROOT_KEY)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self { root, dir }
    }

    fn peer_id(&self) -> libp2p::PeerId {
        node_identity_libp2p_peer_id(&NodeIdentity::load_or_generate_in_dir(&self.dir).unwrap())
            .unwrap()
    }

    /// Starts `parvault daemon start` on `listen`, with `peers` and a status listener.
    fn start(&self, run: &str, listen: &str, peers: &[String]) -> Daemon {
        self.start_env(run, listen, peers, &[])
    }

    /// [`Self::start`] with extra environment variables.
    fn start_env(&self, run: &str, listen: &str, peers: &[String], env: &[(&str, &str)]) -> Daemon {
        self.start_full(run, listen, peers, env, None)
    }

    /// [`Self::start_env`], with the gateway socket at `socket` instead of `--no-socket`.
    fn start_full(
        &self,
        run: &str,
        listen: &str,
        peers: &[String],
        env: &[(&str, &str)],
        socket: Option<&Path>,
    ) -> Daemon {
        let log = self.root.path().join(format!("{run}.log"));
        let f = std::fs::File::create(&log).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
        cmd.env("PARVAULT_LAN_REGISTRY_DIR", self.root.path().join("reg"))
            .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
            .env_remove("PARVAULT_PEERS")
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .envs(env.iter().copied())
            .arg("--data-dir")
            .arg(&self.dir)
            .arg("--no-lan-discovery");
        if !peers.is_empty() {
            cmd.arg("--peers").arg(peers.join(","));
        }
        cmd.args(["daemon", "start", "--listen", listen]);
        match socket {
            Some(sock) => cmd.arg("--ipc-socket").arg(sock),
            None => cmd.arg("--no-socket"),
        };
        cmd.args(["--status-http", "127.0.0.1:0"]);
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

/// Runs `parvault status --live --socket <sock> [extra]` on `node`'s data directory.
fn status_live(node: &Node, sock: &Path, extra: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env_remove("PARVAULT_PEERS")
        .env("PARVAULT_LAN_REGISTRY_DIR", node.root.path().join("reg"))
        .arg("--data-dir")
        .arg(&node.dir)
        .args(["--no-lan-discovery", "status", "--live", "--socket"])
        .arg(sock)
        .args(extra);
    common::output_within_deadline(&mut cmd)
}

/// B-148 item 2 accept (CLI): `parvault status --live` asks the daemon over its socket with a
/// read-only token minted from the data directory's root key and prints its connected peer.
#[test]
fn b148_status_live_cli_shows_connected_peer() {
    let b_node = Node::new("b148c-b");
    let a_node = Node::new("b148c-a");
    let b = b_node.start("b", common::LOOPBACK_EPHEMERAL, &[]);
    let b_addr = format!("{}/p2p/{}", b.mesh, b_node.peer_id());
    let sock = a_node.root.path().join("gw.sock");
    let a = a_node.start_full("a", common::LOOPBACK_EPHEMERAL, &[b_addr], &[], Some(&sock));
    let b_pid = b_node.peer_id();
    assert!(eventually(Duration::from_secs(20), || a.connected_to(&b_pid)));
    let out = status_live(&a_node, &sock, &[]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("Live Status"), "{text}");
    assert!(text.contains(&format!("{b_pid} connected")), "{text}");
    assert!(text.contains(&a.mesh), "{text}");
    drop(b);
    gate_ran("trust_enforcement_liveness::b148_status_live_cli_shows_connected_peer");
}

/// B-148 item 2 reject (CLI): a token from another root key is refused by the daemon's status
/// decision (`reject.status_token_invalid`), and nothing about its peers is printed.
#[test]
fn b148_status_live_cli_wrong_token_refused() {
    let a_node = Node::new("b148cr-a");
    let sock = a_node.root.path().join("gw.sock");
    let _a = a_node.start_full("a", common::LOOPBACK_EPHEMERAL, &[], &[], Some(&sock));
    let other = parvault::capabilities::CapabilityMacaroon::mint(
        &[0x99; 32],
        [7; 32],
        [8; 32],
        vec![parvault::capabilities::Caveat::ReadOnly],
    )
    .unwrap()
    .to_compact_token();
    let file = a_node.root.path().join("other.token");
    std::fs::write(&file, other).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = status_live(&a_node, &sock, &["--macaroon-file", file.to_str().unwrap()]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("reject.status_token_invalid"), "{text}");
    assert!(!text.contains("Peers "), "{text}");
    gate_ran("trust_enforcement_liveness::b148_status_live_cli_wrong_token_refused");
}

/// Runs `parvault file store <file>` as a ring client (the test genesis) against `peers`.
fn store_file(client_dir: &Path, reg: &Path, peers: &[String], file: &Path) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", reg)
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env_remove("PARVAULT_PEERS")
        .arg("--data-dir")
        .arg(client_dir)
        .args([
            "--no-lan-discovery",
            "--peers",
            &peers.join(","),
            "file",
            "store",
        ])
        .arg(file)
        .args([
            "--key-hex",
            &hex::encode([0x11u8; 32]),
            "--tier",
            "consumer",
        ]);
    let out = common::output_within_deadline(&mut cmd);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "file store failed:\n{text}");
    text
}

/// arch152b 4 (measure first): how many envelope keys one owner adds per stored version. Each
/// version of a file is a new manifest key (HMAC of its Merkle root), so keys grow with
/// versions until GC removes envelopes (B-182). Prints the count; asserts one key per version.
#[test]
fn b152_envelope_keys_per_version_measured() {
    let host = Node::new("b152m-h");
    let h = host.start("h", common::LOOPBACK_EPHEMERAL, &[]);
    let peers = vec![format!("{}/p2p/{}", h.mesh, host.peer_id())];
    let client = host.root.path().join("client");
    let file = host.root.path().join("doc.bin");
    const VERSIONS: u64 = 3;
    for v in 0..VERSIONS {
        std::fs::write(&file, vec![v as u8 + 1; 64 * 1024]).unwrap();
        store_file(&client, &host.root.path().join("reg"), &peers, &file);
    }
    h.stop();
    let store = parvault::storage::ZeroTrustDhtStore::with_persistence_dir(&host.dir);
    assert!(!store.is_corrupt());
    let per_owner = store.keys_per_owner();
    let (keys, bytes) = store.usage();
    eprintln!(
        "b152: {VERSIONS} versions of one 64 KiB file -> keys per owner {per_owner:?}, \
         {keys} keys, {bytes} bytes ({} bytes per envelope)",
        bytes / keys.max(1)
    );
    assert_eq!(per_owner, vec![VERSIONS], "one manifest key per version");
    gate_ran("trust_enforcement_liveness::b152_envelope_keys_per_version_measured");
}

/// A-152 4.4: a host whose envelope store file does not decode does not start empty: it
/// refuses every envelope (`reject.dht_store_corrupt`), and the file stays byte for byte, so
/// no version floor it holds is lost.
#[test]
fn b152_corrupt_envelope_store_not_loaded_as_empty() {
    let host = Node::new("b152c-h");
    let path = host
        .dir
        .join(parvault::storage::block_store::DHT_STORE_FILE);
    let garbage = b"not a bincode envelope store \xff\xff\xff".to_vec();
    std::fs::write(&path, &garbage).unwrap();
    let h = host.start("h", common::LOOPBACK_EPHEMERAL, &[]);
    let peers = vec![format!("{}/p2p/{}", h.mesh, host.peer_id())];
    let file = host.root.path().join("doc.bin");
    std::fs::write(&file, vec![7u8; 64 * 1024]).unwrap();
    store_file(
        &host.root.path().join("client"),
        &host.root.path().join("reg"),
        &peers,
        &file,
    );
    assert!(
        eventually(Duration::from_secs(10), || h
            .log_text()
            .contains("reject.dht_store_corrupt")),
        "{}",
        h.log_text()
    );
    h.stop();
    assert_eq!(std::fs::read(&path).unwrap(), garbage);
    gate_ran("trust_enforcement_liveness::b152_corrupt_envelope_store_not_loaded_as_empty");
}

/// Stores `versions` versions of one file through a host started with `env`, and returns the
/// host's log.
fn store_versions_on_host(label: &str, env: &[(&str, &str)], versions: u8) -> String {
    let host = Node::new(label);
    let h = host.start_env("h", common::LOOPBACK_EPHEMERAL, &[], env);
    let peers = vec![format!("{}/p2p/{}", h.mesh, host.peer_id())];
    let file = host.root.path().join("doc.bin");
    for v in 0..versions {
        std::fs::write(&file, vec![v + 1; 64 * 1024]).unwrap();
        store_file(
            &host.root.path().join("client"),
            &host.root.path().join("reg"),
            &peers,
            &file,
        );
    }
    let log = h.log_text();
    h.stop();
    log
}

/// A-152 4.1-4.3 reject (store budget): a host whose envelope budget is lowered to 1 byte
/// (`PARVAULT_DHT_STORE_MAX_BYTES`, which can only lower it) refuses the first envelope with
/// `reject.dht_store_full`; nothing is evicted, because there is nothing it could take.
#[test]
fn b152_dht_store_full_refused() {
    let log = store_versions_on_host("b152f", &[("PARVAULT_DHT_STORE_MAX_BYTES", "1")], 1);
    assert!(log.contains("reject.dht_store_full"), "{log}");
    assert!(log.contains("DHT envelope store limits lowered"), "{log}");
    gate_ran("trust_enforcement_liveness::b152_dht_store_full_refused");
}

/// A-152 4.2-4.3 reject (owner share): with 4 keys in total, one owner may hold 3; its fourth
/// version is refused with `reject.dht_owner_key_cap`, and the three held keys stay.
#[test]
fn b152_dht_owner_key_cap_refused() {
    let log = store_versions_on_host("b152o", &[("PARVAULT_DHT_STORE_MAX_KEYS", "4")], 4);
    assert!(log.contains("reject.dht_owner_key_cap"), "{log}");
    assert_eq!(log.matches("refused a DHT envelope").count(), 1, "{log}");
    gate_ran("trust_enforcement_liveness::b152_dht_owner_key_cap_refused");
}

/// The store-limit knobs only lower the profile limits, refuse zero and junk, and the owner
/// shares follow the lowered totals; `set_limits` sets what `limits` reports.
#[test]
fn dht_store_limits_overrides_only_lower() {
    use parvault::profile::HardwareProfile;
    use parvault::storage::block_store::DhtStoreLimits;
    let router = DhtStoreLimits::for_profile(HardwareProfile::RouterSoc);
    assert_eq!(router.with_overrides(None, None), Ok(router));
    let raised = router
        .with_overrides(Some("999999999"), Some("999999999999"))
        .unwrap();
    assert_eq!(raised, router, "an override never raises a limit");
    let low = router.with_overrides(Some("4"), Some("1000")).unwrap();
    assert_eq!((low.max_keys, low.max_owner_keys), (4, 3));
    assert_eq!((low.max_bytes, low.max_owner_bytes), (1000, 750));
    for bad in ["0", "-1", "lots", ""] {
        assert_eq!(
            router.with_overrides(Some(bad), None),
            Err("reject.dht_store_override_invalid"),
            "{bad:?}"
        );
    }
    let mut store = parvault::storage::ZeroTrustDhtStore::new();
    store.set_limits(router);
    assert_eq!(store.limits(), router);
    assert_eq!(store.usage(), (0, 0));
    gate_ran("trust_enforcement_liveness::dht_store_limits_overrides_only_lower");
}

// --- E4 (arch152b 5.1-5.3): memory across Kademlia replication ticks -----------------------

/// A self-consistent signed vault-catalog envelope at `dht_key`, owned by `signer`.
fn catalog_record(signer: &NodeIdentity, dht_key: [u8; 32]) -> libp2p::kad::Record {
    use sha2::{Digest, Sha256};
    let envelope_salt = [0x33; 32];
    let encrypted_catalog_bytes = vec![0xAB; 256];
    let ciphertext_sha256: [u8; 32] = Sha256::digest(&encrypted_catalog_bytes).into();
    let owner_pubkey = signer.public_key_bytes();
    let version = 1u64;
    let mut msg = Vec::new();
    msg.extend_from_slice(b"parvault-vault-root-catalog-v1:");
    msg.extend_from_slice(&dht_key);
    msg.extend_from_slice(&owner_pubkey);
    msg.extend_from_slice(&version.to_be_bytes());
    msg.extend_from_slice(&envelope_salt);
    msg.extend_from_slice(&ciphertext_sha256);
    let sig = signer.sign(&msg);
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&sig[..32]);
    sig_s.copy_from_slice(&sig[32..]);
    let env = parvault::sync::EncryptedVaultCatalogEnvelope {
        dht_key,
        owner_pubkey,
        monotonic_version: version,
        envelope_salt,
        ciphertext_sha256,
        encrypted_catalog_bytes,
        sig_r,
        sig_s,
    };
    assert!(env.verify_zero_knowledge());
    let value = bincode::serialize(&parvault::network::DhtWireEnvelope::VaultCatalog(env)).unwrap();
    libp2p::kad::Record::new(dht_key.to_vec(), value)
}

/// Admits `ident` on the daemon at `addr` (a genesis-issued chain over `HandshakeWoT`).
fn admit(ident: &NodeIdentity, addr: &str) {
    use parvault::network::{DelegationChain, InvitationHop, MeshWireRequest, MeshWireResponse};
    let genesis = NodeIdentity::from_seed(GENESIS_SEED);
    let chain = DelegationChain {
        hops: vec![InvitationHop::issue(
            &genesis,
            ident.public_key_bytes(),
            1,
            100,
        )],
    };
    let client = parvault::network::MeshClient::new(ident.clone(), Vec::new(), None)
        .with_admission(parvault::network::admission::AdmissionSource::from_genesis(
            genesis,
        ));
    let resp = client
        .send_request(
            addr,
            MeshWireRequest::HandshakeWoT {
                chain,
                asn: None,
                region: None,
            },
        )
        .unwrap();
    assert!(
        matches!(resp, MeshWireResponse::HandshakeAck { accepted: true, .. }),
        "{resp:?}"
    );
}

/// Puts `records` into the daemon at `addr` over Kademlia as `ident`, at most 32 in flight.
fn kad_put_all(
    ident: &NodeIdentity,
    addr: &str,
    target: libp2p::PeerId,
    records: Vec<libp2p::kad::Record>,
) {
    use libp2p::futures::StreamExt;
    use libp2p::kad;
    use libp2p::kad::store::RecordStore;
    use libp2p::swarm::SwarmEvent;
    let addr: libp2p::Multiaddr = addr.parse().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let kp = ident.to_libp2p_keypair().unwrap();
        let mut swarm = parvault::network::build_mesh_client_swarm(kp, false).unwrap();
        swarm.behaviour_mut().kademlia.add_address(&target, addr);
        let total = records.len();
        let mut pending = records.into_iter();
        let (mut in_flight, mut done) = (0usize, 0usize);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
        while done < total {
            while in_flight < 32 {
                let Some(r) = pending.next() else { break };
                let key = r.key.clone();
                swarm
                    .behaviour_mut()
                    .kademlia
                    .put_record(r, kad::Quorum::One)
                    .unwrap();
                // put_record keeps a local copy; drop it so this client's own store never
                // fills.
                swarm.behaviour_mut().kademlia.store_mut().remove(&key);
                in_flight += 1;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{done} of {total} puts"
            );
            tokio::select! {
                ev = swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(
                        parvault::network::behaviour::MeshNetworkBehaviourEvent::Kademlia(
                            kad::Event::OutboundQueryProgressed {
                                result: kad::QueryResult::PutRecord(_),
                                step,
                                ..
                            },
                        ),
                    ) = ev
                    {
                        if step.last {
                            in_flight -= 1;
                            done += 1;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    });
}

/// The test replication interval (the shortest the knob allows).
const E4_TICK: Duration = Duration::from_secs(60);
/// Anon RSS after tick 6 within this of tick 2 (arch152b 5.1).
const E4_FLAT_MARGIN: u64 = 2 << 20;
/// Stated bound on the first step (fill to the first tick) on desktop limits.
const E4_FIRST_STEP_BOUND: u64 = 8 << 20;

/// E4 (arch152b 5.1-5.3; B-152 b): a daemon with a 60 s replication interval
/// (`PARVAULT_KAD_REPLICATION_SECS`) and its Kademlia store filled to `max_records` keeps its
/// anonymous memory flat across six replication ticks: tick 6 within 2 MiB of tick 2, the first
/// step under 8 MiB. Sampled from `/live` at the same phase of each interval. One more new
/// record is refused (`reject.dht_record_store_full`). Run on the release build for the
/// shipped allocator; about 8 minutes.
#[test]
fn e4_kad_replication_ticks_memory_flat() {
    let host = Node::new("e4-h");
    let h = host.start_env(
        "h",
        common::LOOPBACK_EPHEMERAL,
        &[],
        &[("PARVAULT_KAD_REPLICATION_SECS", "60")],
    );
    let started = Instant::now();
    assert!(
        h.log_text().contains("replication interval set by"),
        "{}",
        h.log_text()
    );
    let max = parvault::network::transport::KadParams::default().max_records;
    let writer = NodeIdentity::from_seed([0x5E; 32]);
    admit(&writer, &h.mesh);
    let anon = |d: &Daemon| d.live()["anon_rss_bytes"].as_u64().unwrap();
    let before = anon(&h);
    let records: Vec<_> = (0..=max as u32)
        .map(|i| {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            k[4] = 0xE4;
            catalog_record(&writer, k)
        })
        .collect();
    kad_put_all(&writer, &h.mesh, host.peer_id(), records);
    assert!(
        eventually(Duration::from_secs(10), || h
            .log_text()
            .contains("reject.dht_record_store_full")),
        "the store did not fill:\n{}",
        h.log_text()
    );
    let filled = anon(&h);
    // Sample at the same phase of each interval: 30 s after each tick of the swarm's clock.
    let mut samples = Vec::new();
    for tick in 1..=6u32 {
        let at = E4_TICK * tick + Duration::from_secs(30);
        if let Some(wait) = at.checked_sub(started.elapsed()) {
            std::thread::sleep(wait);
        }
        samples.push(anon(&h));
    }
    eprintln!(
        "e4: anon before fill {before}, after fill {filled}, ticks 1-6 {samples:?} \
         (tick 6 - tick 2 = {} bytes)",
        samples[5] as i64 - samples[1] as i64
    );
    assert!(
        samples[5].abs_diff(samples[1]) <= E4_FLAT_MARGIN,
        "anon not flat across ticks: {samples:?}"
    );
    assert!(
        samples[0].saturating_sub(before) <= E4_FIRST_STEP_BOUND,
        "first step over its bound: before {before}, tick 1 {}",
        samples[0]
    );
    gate_ran("trust_enforcement_liveness::e4_kad_replication_ticks_memory_flat");
}
