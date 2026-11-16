//! `v0.5.6` B-182 suite (architect arch182, L-141): folder sync publishes only its vault catalog
//! to the ring, so an owner's envelope keys track its vaults, not its versions; owner-side
//! envelope refusals are never silent.
//!
//! Every test runs the real `parvault` binary on scratch data dirs (the ring tests run real
//! daemons on ephemeral loopback ports). Every test writes its sentinel (`gate_ran`) last, after
//! its assertions.

mod common;

use parvault::storage::ZeroTrustDhtStore;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The ring genesis the hosts and the owner are provisioned with.
const GENESIS_SEED_HEX: &str = "8282828282828282828282828282828282828282828282828282828282828282";
const PHRASE: &str = "b182 envelope growth ring test passphrase";
const NAMESPACE: &str = "b182-ring";
/// `PARVAULT_DHT_STORE_MAX_KEYS=32`: one owner's share is 24 keys.
const MAX_KEYS: &str = "32";
const OWNER_SHARE: u64 = 24;

/// A storage daemon on an ephemeral loopback port, with the envelope store capped.
struct Host {
    child: std::process::Child,
    dir: PathBuf,
    log: PathBuf,
    addr: String,
    _tmp: tempfile::TempDir,
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Host {
    fn spawn(label: &str, max_keys: &str) -> Self {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("pv-b182-{label}-"))
            .tempdir()
            .unwrap();
        let dir = tmp.path().join("data");
        std::fs::create_dir_all(&dir).unwrap();
        let id = parvault::crypto::NodeIdentity::load_or_generate_in_dir(&dir).unwrap();
        let log = tmp.path().join("host.log");
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
        cmd.env("PARVAULT_LAN_REGISTRY_DIR", tmp.path().join("lan-registry"))
            .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
            .env("PARVAULT_DHT_STORE_MAX_KEYS", max_keys)
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .env_remove("PARVAULT_PEERS")
            .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
            .arg("--data-dir")
            .arg(&dir)
            .args([
                "--no-lan-discovery",
                "daemon",
                "start",
                "--listen",
                common::LOOPBACK_EPHEMERAL,
            ]);
        let (child, addr) = common::spawn_on_ephemeral_port(&mut cmd, &log);
        let pid = parvault::network::node_identity_libp2p_peer_id(&id).unwrap();
        Self {
            child,
            dir,
            log,
            addr: format!("{addr}/p2p/{pid}"),
            _tmp: tmp,
        }
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The host's envelope store as its file holds it now (read only).
    fn keys_per_owner(&self) -> Vec<u64> {
        let s = ZeroTrustDhtStore::with_persistence_dir(&self.dir);
        assert!(!s.is_corrupt());
        s.keys_per_owner()
    }
}

/// One owner folder backed up with `watch-folder --once` against a ring.
struct Owner {
    _tmp: tempfile::TempDir,
    node: PathBuf,
    folder: PathBuf,
    snap: PathBuf,
}

impl Owner {
    fn new() -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("pv-b182-owner-")
            .tempdir()
            .unwrap();
        let node = tmp.path().join("node");
        let folder = tmp.path().join("folder");
        std::fs::create_dir_all(&folder).unwrap();
        let snap = tmp.path().join("s.manifest.bin");
        Self {
            node,
            folder,
            snap,
            _tmp: tmp,
        }
    }

    /// A `watch-folder --once` pass against `peers`, with the vault phrase (the catalog is
    /// published) and `env`.
    fn pass(&self, peers: &str, env: &[(&str, &str)]) -> Output {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
        cmd.env("PARVAULT_LAN_REGISTRY_DIR", self.node.join("lan-registry"))
            .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
            .env("PARVAULT_SEED_PHRASE", PHRASE)
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .env_remove("PARVAULT_PEERS")
            .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
            .envs(env.iter().copied())
            .arg("--data-dir")
            .arg(&self.node)
            .args(["--no-lan-discovery", "--peers", peers])
            .args([
                "watch-folder",
                "--folder",
                self.folder.to_str().unwrap(),
                "--snapshot-out",
                self.snap.to_str().unwrap(),
                "--vault-namespace",
                NAMESPACE,
                "--once",
            ]);
        output_within(&mut cmd, Duration::from_secs(120))
    }
}

/// Runs `cmd` to completion within `limit`.
fn output_within(cmd: &mut std::process::Command, limit: Duration) -> Output {
    use std::io::Read;
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t1 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let t2 = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("command did not exit within {}s", limit.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: t1.join().unwrap(),
        stderr: t2.join().unwrap(),
    }
}

/// Asserts every host holds at most `bound` keys for any owner (B182-3).
fn assert_hosts_bounded(hosts: &[Host], bound: u64, after: usize) {
    for (i, h) in hosts.iter().enumerate() {
        let per_owner = h.keys_per_owner();
        assert!(
            per_owner.iter().all(|&k| k <= bound),
            "after {after} changed passes host {i} holds {per_owner:?} keys per owner (bound \
             {bound}, share {OWNER_SHARE})\nhost log tail:\n{}",
            tail(&h.log_text(), 40)
        );
    }
}

fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// T1 passes: 5x the owner share of 24.
const T1_PASSES: usize = 120;

/// Runs T1's churn: three capped hosts, one owner, `passes` changed passes of one file. Returns
/// the hosts, the owner and every pass's output.
fn churn(passes: usize) -> (Vec<Host>, Owner, Vec<String>) {
    let hosts: Vec<Host> = (0..3)
        .map(|i| Host::spawn(&format!("h{i}"), MAX_KEYS))
        .collect();
    let peers = hosts
        .iter()
        .map(|h| h.addr.clone())
        .collect::<Vec<_>>()
        .join(",");
    let owner = Owner::new();
    let mut outs = Vec::with_capacity(passes);
    for n in 1..=passes {
        std::fs::write(
            owner.folder.join("a.txt"),
            format!("b182 churn pass {n}\n").repeat(64),
        )
        .unwrap();
        let out = owner.pass(&peers, &[("PARVAULT_DHT_STORE_MAX_KEYS", MAX_KEYS)]);
        let t = text(&out);
        assert!(out.status.success(), "pass {n} failed:\n{t}");
        outs.push(t);
        // Past the owner share, a per-version publish would already show (fail early).
        if n == OWNER_SHARE as usize + 6 {
            assert_hosts_bounded(&hosts, 1, n);
        }
    }
    (hosts, owner, outs)
}

/// B182-3 accept (T1): three hosts capped at 32 keys (an owner share of 24); one file rewritten
/// for 120 changed passes. Every host holds at most one key for the owner (its one vault's
/// catalog), every pass's catalog is acknowledged by all three hosts, the owner's own store
/// holds only the catalog, and no envelope refusal is logged or counted.
#[test]
fn b182_churn_past_owner_cap_keys_bounded() {
    let (hosts, owner, outs) = churn(T1_PASSES);
    assert_hosts_bounded(&hosts, 1, T1_PASSES);
    for (i, h) in hosts.iter().enumerate() {
        assert_eq!(h.keys_per_owner(), vec![1], "host {i}: one catalog key");
        let log = h.log_text();
        assert!(!log.contains("refused a DHT envelope"), "host {i}:\n{log}");
    }
    let own = ZeroTrustDhtStore::with_persistence_dir(&owner.node);
    assert_eq!(own.keys_per_owner(), vec![1], "owner's own store: the catalog");
    for (n, t) in outs.iter().enumerate() {
        assert!(
            t.contains("info.catalog_published") && t.contains("hosts_stored=3"),
            "pass {}: catalog not acknowledged by every host:\n{t}",
            n + 1
        );
        assert!(t.contains("hosts_refused=0"), "pass {}:\n{t}", n + 1);
        assert!(!t.contains("warn.dht_envelope_refused"), "pass {}:\n{t}", n + 1);
        assert!(!t.contains("envelope refusal"), "pass {}:\n{t}", n + 1);
    }
    // The last pass's catalog is the one every host holds (by version).
    let cat = std::fs::read(owner.snap.with_extension("catalog.bin")).unwrap();
    let cat: parvault::sync::EncryptedVaultCatalogEnvelope = bincode::deserialize(&cat).unwrap();
    for (i, h) in hosts.iter().enumerate() {
        let s = ZeroTrustDhtStore::with_persistence_dir(&h.dir);
        let held = s.get_vault_catalog_envelope(&cat.dht_key).cloned();
        assert_eq!(
            held.map(|e| e.monotonic_version),
            Some(cat.monotonic_version),
            "host {i} holds the last catalog"
        );
    }
    gate_ran("trust_enforcement_b182::b182_churn_past_owner_cap_keys_bounded");
}
