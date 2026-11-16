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

/// B-157 (in-flight guard): a configured address without `/p2p/` whose dial hangs (a listener
/// that accepts TCP and never answers the Noise handshake) is not dialled again while that dial
/// is in flight. Without the guard the redial task would open a new connection at 1, 3 and 7 s.
#[test]
fn b157_hanging_dial_not_doubled() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for conn in listener.incoming() {
            match conn {
                Ok(c) => {
                    counter.fetch_add(1, Ordering::SeqCst);
                    held.push(c); // never read or written: the handshake hangs
                }
                Err(_) => break,
            }
        }
    });
    let a_node = Node::new("b157h-a");
    let a = a_node.start(
        "a",
        common::LOOPBACK_EPHEMERAL,
        &[format!("/ip4/127.0.0.1/tcp/{port}")],
    );
    assert!(eventually(Duration::from_secs(10), || accepted
        .load(Ordering::SeqCst)
        >= 1));
    std::thread::sleep(Duration::from_secs(10));
    let n = accepted.load(Ordering::SeqCst);
    let log = a.log_text();
    // A dial that does fail (a handshake timeout) may be followed by one redial.
    assert!(n <= 2, "{n} parallel dials to a hanging address:\n{log}");
    gate_ran("trust_enforcement_liveness::b157_hanging_dial_not_doubled");
}

/// G-28: the folder sync engine and the daemon's wire handler write one `ZeroTrustDhtStore`
/// (the `BlockStore`'s), not two copies of `dht_store.bin`. Before the fix the engine loaded its
/// own copy at construction and rewrote the whole file from it, so an envelope a peer put after
/// that load was lost on disk. Checked first as that exact interleaving, then as two concurrent
/// writers (engine passes, each with a fresh engine as the daemon makes per pass, beside peer
/// puts): the file on disk holds every key at its highest version.
#[test]
fn g28_two_dht_writers_lose_no_envelope_or_version_floor() {
    use parvault::config::ErasureTier;
    use parvault::crypto::MasterKey;
    use parvault::storage::{
        BlockStore, FileManifest, QuotaManager, SignedDhtManifestEnvelope, ZeroTrustDhtStore,
    };
    use parvault::sync::FolderSyncEngine;
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let folder = tmp.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    let store = BlockStore::new(&data, QuotaManager::new(1 << 30, 1 << 28)).unwrap();
    let mk = MasterKey::generate();
    let owner = NodeIdentity::from_master_key(&mk);
    let peer_mks: Vec<MasterKey> = (0..4).map(|_| MasterKey::generate()).collect();
    let peer_put = |manifest: &FileManifest, p: usize, version: u64| -> [u8; 32] {
        let id = NodeIdentity::from_master_key(&peer_mks[p]);
        let env =
            SignedDhtManifestEnvelope::seal(&peer_mks[p], &id, manifest, version, version).unwrap();
        store.put_dht_manifest_envelope(env.clone()).unwrap();
        env.dht_key
    };
    let on_disk = |key: &[u8; 32]| -> Option<u64> {
        ZeroTrustDhtStore::with_persistence_dir(&data)
            .get_manifest_envelope(key)
            .map(|e| e.monotonic_version)
    };

    // 1. The interleaving: engine made, then a peer put, then the engine's pass.
    std::fs::write(folder.join("a.txt"), "first").unwrap();
    let mut engine = FolderSyncEngine::new(
        store.clone(),
        mk.clone(),
        owner.clone(),
        ErasureTier::Homelab,
    );
    let snap = engine.sync_folder_once(&folder).unwrap();
    let manifest = snap.files["a.txt"].manifest.clone();
    let mut engine = FolderSyncEngine::new(
        store.clone(),
        mk.clone(),
        owner.clone(),
        ErasureTier::Homelab,
    );
    engine.load_previous_snapshot(&snap);
    let peer_key = peer_put(&manifest, 0, 7);
    std::fs::write(folder.join("a.txt"), "second").unwrap();
    let snap = engine.sync_folder_once(&folder).unwrap();
    assert_eq!(
        on_disk(&peer_key),
        Some(7),
        "the peer's envelope was lost on disk"
    );
    let own = snap.signed_dht_envelope.clone().unwrap();
    assert_eq!(on_disk(&own.dht_key), Some(own.monotonic_version));

    // 2. Two concurrent writers.
    const ROUNDS: u64 = 40;
    let last_own = std::thread::scope(|s| {
        let syncer = s.spawn(|| {
            let mut snap = snap.clone();
            for i in 0..ROUNDS {
                let mut e = FolderSyncEngine::new(
                    store.clone(),
                    mk.clone(),
                    owner.clone(),
                    ErasureTier::Homelab,
                );
                e.load_previous_snapshot(&snap);
                std::fs::write(folder.join("a.txt"), format!("round {i}")).unwrap();
                snap = e.sync_folder_once(&folder).unwrap();
            }
            snap.signed_dht_envelope.unwrap()
        });
        let peers = s.spawn(|| {
            for v in 8..8 + ROUNDS {
                for p in 0..peer_mks.len() {
                    peer_put(&manifest, p, v);
                }
            }
        });
        peers.join().unwrap();
        syncer.join().unwrap()
    });
    // Read back without another write (a write would persist the whole store again).
    for (p, pmk) in peer_mks.iter().enumerate() {
        let id = NodeIdentity::from_master_key(pmk);
        let key = SignedDhtManifestEnvelope::seal(pmk, &id, &manifest, 1, 1)
            .unwrap()
            .dht_key;
        assert_eq!(on_disk(&key), Some(8 + ROUNDS - 1), "peer {p}");
    }
    assert_eq!(on_disk(&last_own.dht_key), Some(last_own.monotonic_version));
    gate_ran("trust_enforcement_liveness::g28_two_dht_writers_lose_no_envelope_or_version_floor");
}

/// G-28 merge rule: per key, a lower version never replaces a higher one, whichever side holds
/// it; the owner already on disk keeps the key; a key one side lacks is taken from the other.
#[test]
fn g28_merge_never_lowers_a_floor() {
    use parvault::storage::block_store::{dht_merge_pick, DhtMergePick};
    let (a, b) = ([1u8; 32], [2u8; 32]);
    assert_eq!(
        dht_merge_pick(Some((a, 5)), Some((a, 4))),
        DhtMergePick::Disk
    );
    assert_eq!(
        dht_merge_pick(Some((a, 4)), Some((a, 5))),
        DhtMergePick::Memory
    );
    assert_eq!(
        dht_merge_pick(Some((a, 5)), Some((a, 5))),
        DhtMergePick::Disk
    );
    assert_eq!(
        dht_merge_pick(Some((a, 1)), Some((b, 9))),
        DhtMergePick::Disk
    );
    assert_eq!(dht_merge_pick(None, Some((b, 1))), DhtMergePick::Memory);
    assert_eq!(dht_merge_pick(Some((a, 1)), None), DhtMergePick::Disk);
    for d in 0..6u64 {
        for m in 0..6u64 {
            let kept = match dht_merge_pick(Some((a, d)), Some((a, m))) {
                DhtMergePick::Disk => d,
                DhtMergePick::Memory => m,
            };
            assert_eq!(kept, d.max(m), "disk {d}, memory {m}");
        }
    }
    gate_ran("trust_enforcement_liveness::g28_merge_never_lowers_a_floor");
}

/// Rounds each G-28 writer process runs.
const G28_ROUNDS: u64 = 150;

/// G-28 helper: one writer process, spawned by `g28_two_processes_lose_no_envelope_or_floor`
/// (a no-op when run on its own). It keeps one store open for its whole life, as a daemon or a
/// `watch-folder` loop does, and per round puts its own key's next version and tries the shared
/// key at an interleaved version (2i + id), recording the highest one it was granted.
#[test]
fn g28_writer_child() {
    use parvault::crypto::MasterKey;
    use parvault::storage::{FileManifest, SignedDhtManifestEnvelope, ZeroTrustDhtStore};
    let Ok(dir) = std::env::var("PV_G28_CHILD_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let me: u64 = std::env::var("PV_G28_CHILD_ID").unwrap().parse().unwrap();
    let manifest =
        FileManifest::decode_bytes(&std::fs::read(dir.join("manifest.bin")).unwrap()).unwrap();
    let own = MasterKey::from_hex(&format!("{:02x}", 0x10 + me).repeat(32)).unwrap();
    let shared = MasterKey::from_hex(&"5a".repeat(32)).unwrap();
    let seal = |mk: &MasterKey, v: u64| {
        SignedDhtManifestEnvelope::seal(mk, &NodeIdentity::from_master_key(mk), &manifest, v, v)
            .unwrap()
    };
    let mut store = ZeroTrustDhtStore::with_persistence_dir(&dir.join("data"));
    let deadline = Instant::now() + Duration::from_secs(60);
    while !dir.join("go").exists() {
        assert!(Instant::now() < deadline, "no start signal");
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut granted = 0;
    for i in 1..=G28_ROUNDS {
        store.put_manifest_envelope(seal(&own, i)).unwrap();
        let v = 2 * i + me;
        if store.put_manifest_envelope(seal(&shared, v)).is_ok() {
            granted = v;
        }
    }
    std::fs::write(dir.join(format!("granted-{me}")), granted.to_string()).unwrap();
}

/// G-28 across processes (a daemon and a `watch-folder` client may share one data dir): two
/// writer processes, each with its own long-lived store on one `zero_trust_dht_store.bin`, put
/// interleaved envelopes. On disk afterwards each writer's own key is at its last version, and
/// the shared key is at the highest version either writer was granted (no floor lowered).
#[test]
fn g28_two_processes_lose_no_envelope_or_floor() {
    use parvault::config::ErasureTier;
    use parvault::crypto::MasterKey;
    use parvault::storage::{
        BlockStore, QuotaManager, SignedDhtManifestEnvelope, ZeroTrustDhtStore,
    };
    use parvault::sync::FolderSyncEngine;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    // One manifest both writers seal (any real manifest will do).
    let folder = dir.join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), "g28").unwrap();
    let mk = MasterKey::generate();
    let mut engine = FolderSyncEngine::new(
        BlockStore::new(dir.join("scratch"), QuotaManager::new(1 << 30, 1 << 28)).unwrap(),
        mk.clone(),
        NodeIdentity::from_master_key(&mk),
        ErasureTier::Homelab,
    );
    let manifest = engine.sync_folder_once(&folder).unwrap().files["a.txt"]
        .manifest
        .clone();
    std::fs::write(
        dir.join("manifest.bin"),
        bincode::serialize(&manifest).unwrap(),
    )
    .unwrap();
    let exe = std::env::current_exe().unwrap();
    let children: Vec<Child> = (0..2u64)
        .map(|id| {
            Command::new(&exe)
                .args([
                    "g28_writer_child",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("PV_G28_CHILD_DIR", dir)
                .env("PV_G28_CHILD_ID", id.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    std::fs::write(dir.join("go"), b"").unwrap();
    for c in children {
        let out = c.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let disk = ZeroTrustDhtStore::with_persistence_dir(&dir.join("data"));
    let key_of = |mk: &MasterKey| {
        SignedDhtManifestEnvelope::seal(mk, &NodeIdentity::from_master_key(mk), &manifest, 1, 1)
            .unwrap()
            .dht_key
    };
    let version = |mk: &MasterKey| {
        disk.get_manifest_envelope(&key_of(mk))
            .map(|e| e.monotonic_version)
    };
    let mut granted = Vec::new();
    for id in 0..2u64 {
        let own = MasterKey::from_hex(&format!("{:02x}", 0x10 + id).repeat(32)).unwrap();
        assert_eq!(version(&own), Some(G28_ROUNDS), "writer {id}'s own key");
        let g: u64 = std::fs::read_to_string(dir.join(format!("granted-{id}")))
            .unwrap()
            .parse()
            .unwrap();
        granted.push(g);
    }
    let shared = MasterKey::from_hex(&"5a".repeat(32)).unwrap();
    assert_eq!(
        version(&shared),
        granted.iter().copied().max(),
        "the shared key's floor (granted {granted:?})"
    );
    gate_ran("trust_enforcement_liveness::g28_two_processes_lose_no_envelope_or_floor");
}

/// G-29 (A-152 parts 2 and 4; Lead choice (b)): a `router-soc` daemon reports its profile's
/// limits at start (`info.profile_limits`): Kademlia replication 21,600 s, publication
/// 79,200 s, TTL 172,800 s, 128 records in 4 MiB, and an envelope store of 2,048 keys in
/// 8 MiB with owner shares of 1,536 keys and 6 MiB.
#[test]
fn g29_router_soc_daemon_reports_its_profile_limits() {
    let node = Node::new("g29");
    std::fs::write(
        node.dir.join("config.toml"),
        "hardware_profile = \"router-soc\"\n",
    )
    .unwrap();
    let d = node.start("g29", common::LOOPBACK_EPHEMERAL, &[]);
    let log = d.log_text();
    let line = log
        .lines()
        .find(|l| l.contains("info.profile_limits"))
        .unwrap_or_else(|| panic!("no info.profile_limits line:\n{log}"));
    for field in [
        "router-soc",
        "kad_replication_secs=21600",
        "kad_publication_secs=79200",
        "kad_record_ttl_secs=172800",
        "kad_max_records=128",
        "kad_max_total_bytes=4194304",
        "dht_store_max_keys=2048",
        "dht_store_max_bytes=8388608",
        "dht_store_max_owner_keys=1536",
        "dht_store_max_owner_bytes=6291456",
    ] {
        assert!(line.contains(field), "{field} not in: {line}");
    }
    d.stop();
    gate_ran("trust_enforcement_liveness::g29_router_soc_daemon_reports_its_profile_limits");
}
