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
    max_keys: String,
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
        Self::spawn_prepared(label, max_keys, |_| {})
    }

    /// [`Self::spawn`], with `prep` run on the data dir before the daemon starts.
    fn spawn_prepared(label: &str, max_keys: &str, prep: impl FnOnce(&Path)) -> Self {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("pv-b182-{label}-"))
            .tempdir()
            .unwrap();
        let dir = tmp.path().join("data");
        std::fs::create_dir_all(&dir).unwrap();
        prep(&dir);
        let log = tmp.path().join("host.log");
        let (child, addr) = Self::start(tmp.path(), &dir, &log, max_keys);
        Self {
            child,
            dir,
            log,
            addr,
            max_keys: max_keys.to_string(),
            _tmp: tmp,
        }
    }

    /// Starts a daemon on `dir`; returns it and its `/p2p/` address.
    fn start(root: &Path, dir: &Path, log: &Path, max_keys: &str) -> (std::process::Child, String) {
        let id = parvault::crypto::NodeIdentity::load_or_generate_in_dir(dir).unwrap();
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
        cmd.env("PARVAULT_LAN_REGISTRY_DIR", root.join("lan-registry"))
            .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
            .env("PARVAULT_DHT_STORE_MAX_KEYS", max_keys)
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .env_remove("PARVAULT_PEERS")
            .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
            .arg("--data-dir")
            .arg(dir)
            .args([
                "--no-lan-discovery",
                "daemon",
                "start",
                "--listen",
                common::LOOPBACK_EPHEMERAL,
            ]);
        let (child, addr) = common::spawn_on_ephemeral_port(&mut cmd, log);
        let pid = parvault::network::node_identity_libp2p_peer_id(&id).unwrap();
        (child, format!("{addr}/p2p/{pid}"))
    }

    /// Stops the daemon, runs `edit` on its data dir, and starts it again (a new port; the log
    /// continues in `restart.log`).
    fn restart_with(&mut self, edit: impl FnOnce(&Path)) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        edit(&self.dir);
        let root = self.log.parent().unwrap().to_path_buf();
        self.log = root.join("restart.log");
        let (child, addr) = Self::start(&root, &self.dir, &self.log, &self.max_keys);
        self.child = child;
        self.addr = addr;
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
    let peers = peers_of(&hosts);
    let owner = Owner::new();
    let mut outs = Vec::with_capacity(passes);
    for n in 1..=passes {
        std::fs::write(owner.folder.join("a.txt"), body(n)).unwrap();
        let out = owner.pass(&peers, &[("PARVAULT_DHT_STORE_MAX_KEYS", MAX_KEYS)]);
        let t = text(&out);
        assert!(out.status.success(), "pass {n} failed:\n{t}");
        outs.push(t);
    }
    (hosts, owner, outs)
}

/// B182-3 accept (T1): three hosts capped at 32 keys (an owner share of 24); one file rewritten
/// for 120 changed passes. Every host holds at most one key for the owner (its one vault's
/// catalog), every pass's catalog is acknowledged by all three hosts, the owner's own store
/// holds only the catalog, and no envelope refusal is logged or counted. Every violation is
/// collected before the test fails, so a mutant shows each one (growth, refusal warnings).
#[test]
fn b182_churn_past_owner_cap_keys_bounded() {
    let (hosts, owner, outs) = churn(T1_PASSES);
    let mut problems: Vec<String> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let per_owner = h.keys_per_owner();
        if per_owner != vec![1] {
            problems.push(format!(
                "growth: host {i} holds {per_owner:?} keys per owner (bound 1, share {OWNER_SHARE})"
            ));
        }
        let refused = h.log_text().matches("refused a DHT envelope").count();
        if refused > 0 {
            problems.push(format!("host {i} refused {refused} envelope(s)"));
        }
    }
    let own = ZeroTrustDhtStore::with_persistence_dir(&owner.node).keys_per_owner();
    if own != vec![1] {
        problems.push(format!("growth: the owner's own store holds {own:?}"));
    }
    let mut unacked = Vec::new();
    let mut warned = Vec::new();
    for (n, t) in outs.iter().enumerate() {
        if !(t.contains("info.catalog_published")
            && t.contains("hosts_stored=3")
            && t.contains("hosts_refused=0"))
        {
            unacked.push(n + 1);
        }
        if t.contains("warn.dht_envelope_refused") || t.contains("envelope refusal") {
            warned.push(n + 1);
        }
    }
    if !unacked.is_empty() {
        problems.push(format!(
            "catalog not acknowledged by all 3 hosts on passes {unacked:?}"
        ));
    }
    if !warned.is_empty() {
        problems.push(format!(
            "warn.dht_envelope_refused on {} pass(es), first {:?}",
            warned.len(),
            warned.first()
        ));
    }
    // The last pass's catalog is the one every host holds (by version).
    let cat = std::fs::read(owner.snap.with_extension("catalog.bin")).unwrap();
    let cat: parvault::sync::EncryptedVaultCatalogEnvelope = bincode::deserialize(&cat).unwrap();
    for (i, h) in hosts.iter().enumerate() {
        let s = ZeroTrustDhtStore::with_persistence_dir(&h.dir);
        let held = s
            .get_vault_catalog_envelope(&cat.dht_key)
            .map(|e| e.monotonic_version);
        if held != Some(cat.monotonic_version) {
            problems.push(format!("host {i} holds catalog {held:?}, not the last"));
        }
    }
    assert!(
        problems.is_empty(),
        "T1 after {T1_PASSES} changed passes:\n{}\nlast pass:\n{}",
        problems.join("\n"),
        outs.last().map(|t| tail(t, 30)).unwrap_or_default()
    );
    gate_ran("trust_enforcement_b182::b182_churn_past_owner_cap_keys_bounded");
}

// --- B182-6: no owner-side envelope put is discarded -----------------------------------------

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().filter_map(Result::ok) {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The envelope put calls B182-6 covers (local store and ring).
const ENVELOPE_PUTS: &[&str] = &[
    ".put_dht_manifest_envelope(",
    ".put_dht_pq_manifest_envelope(",
    ".put_dht_vault_catalog_envelope(",
    ".put_dht_envelope(",
    ".put_dht_envelope_report(",
    // D23: the Kademlia copy of a put envelope (`store_mut().put`, `put_record`).
    ".put(",
    ".put_record(",
];

/// The call sites of the envelope puts in `src/` (file, line, the statement up to the call),
/// definitions and comments excluded.
fn envelope_put_sites() -> Vec<(String, usize, String)> {
    envelope_put_statements()
        .into_iter()
        .map(|(f, l, head, _)| (f, l, head))
        .collect()
}

/// Whether a put statement (`head`: up to the call; `whole`: to its `;`) drops the result:
/// `let _ =` / `let _:`, or an expression statement ending in `.ok()` or `.is_ok()`.
fn put_discarded(head: &str, whole: &str) -> bool {
    let bound = [
        "let ", "if ", "match ", "return", "while ", "Some(", "Ok(", "Err(",
    ];
    head.starts_with("let _ =")
        || head.starts_with("let _:")
        || ((whole.ends_with(".ok()") || whole.ends_with(".is_ok()"))
            && !bound.iter().any(|b| whole.starts_with(b)))
}

/// [`envelope_put_sites`] with each whole statement (to its `;`, or the end of its block).
fn envelope_put_statements() -> Vec<(String, usize, String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    let mut sites = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).unwrap();
        for put in ENVELOPE_PUTS {
            for (at, _) in src.match_indices(put) {
                let line_start = src[..at].rfind('\n').map_or(0, |i| i + 1);
                if src[line_start..at].trim_start().starts_with("//") {
                    continue;
                }
                // The statement: back to the previous `;`, `{` or `}`.
                let stmt_start = src[..at].rfind([';', '{', '}']).map_or(0, |i| i + 1);
                let stmt = src[stmt_start..at + put.len()]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                let end = src[at..].find([';', '}']).map_or(src.len(), |i| at + i);
                let whole = src[stmt_start..end]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                let line = src[..at].matches('\n').count() + 1;
                let rel = f.strip_prefix(root).unwrap().display().to_string();
                sites.push((rel, line, stmt, whole));
            }
        }
    }
    sites
}

/// B182-6 accept/reject: lists every envelope put call site in `src/` and fails on any whose
/// result is discarded with `let _ =` (or `.ok();` / `.is_ok()` dropped on its own line).
#[test]
fn b182_envelope_puts_never_discarded() {
    let all = envelope_put_statements();
    for (f, l, s, _) in &all {
        eprintln!("b182 envelope put: {f}:{l}: {s}");
    }
    let discarded: Vec<_> = all
        .iter()
        .filter(|(_, _, head, whole)| put_discarded(head, whole))
        .collect();
    let sites = envelope_put_sites();
    assert!(
        discarded.is_empty(),
        "envelope puts whose result is discarded: {discarded:#?}"
    );
    // The owner-side sites B182-6 names are among them, reported.
    for want in [
        "src/storage/block_store.rs",
        "src/sync/engine.rs",
        "src/network/wire_handler.rs",
    ] {
        assert!(
            sites.iter().any(|(f, _, _)| f == want),
            "{want}: {sites:#?}"
        );
    }
    // The detector bites: a discarded put is found.
    let probe = "fn x() { let _ = store.put_dht_manifest_envelope(env); }";
    let at = probe.find(".put_dht_manifest_envelope(").unwrap();
    let start = probe[..at].rfind([';', '{', '}']).unwrap() + 1;
    assert!(probe[start..at].trim_start().starts_with("let _ ="));
    // D23: the Kademlia copy is covered, and the `.ok()` / `.is_ok()` forms bite too.
    assert!(
        all.iter()
            .filter(|(f, _, _, _)| f == "src/network/client.rs")
            .any(|(_, _, h, _)| h.ends_with(".put_record(")),
        "{all:#?}"
    );
    for (head, whole, dropped) in [
        (
            "let _ = swarm.behaviour_mut().kademlia.put_record(",
            "let _ = swarm.behaviour_mut().kademlia.put_record(r, q)",
            true,
        ),
        ("store.put(", "store.put(record).ok()", true),
        (
            "c.put_dht_envelope_report(",
            "c.put_dht_envelope_report(env).is_ok()",
            true,
        ),
        (
            "if let Err(e) = store.put(",
            "if let Err(e) = store.put(record) {",
            false,
        ),
        (
            "let ok = c.put_dht_envelope_report(",
            "let ok = c.put_dht_envelope_report(env).is_ok()",
            false,
        ),
    ] {
        assert_eq!(put_discarded(head, whole), dropped, "{whole}");
    }
    gate_ran("trust_enforcement_b182::b182_envelope_puts_never_discarded");
}

/// B182-1/B182-2 reject: folder sync has no ring publish of a per-file or anchor manifest left
/// (the folder engine stores manifests `LocalOnly`; no classical manifest envelope is put from
/// `sync/engine.rs` or `cli/folder.rs`).
#[test]
fn b182_folder_paths_publish_no_manifest_envelope() {
    let sites = envelope_put_sites();
    let offending: Vec<_> = sites
        .iter()
        .filter(|(f, _, s)| {
            (f == "src/sync/engine.rs" || f == "src/cli/folder.rs")
                && (s.contains("put_dht_manifest_envelope") || s.contains("ClassicalManifest"))
        })
        .collect();
    assert!(offending.is_empty(), "{offending:#?}");
    use parvault::storage::block_store::{
        manifest_publish_decision, ManifestOrigin, ManifestPublish,
    };
    assert_eq!(
        manifest_publish_decision(ManifestOrigin::FolderSync),
        ManifestPublish::LocalOnly
    );
    assert_eq!(
        manifest_publish_decision(ManifestOrigin::LiteSeed),
        ManifestPublish::LocalOnly
    );
    assert_eq!(
        manifest_publish_decision(ManifestOrigin::FileStore),
        ManifestPublish::Ring
    );
    assert_eq!(
        manifest_publish_decision(ManifestOrigin::Gateway),
        ManifestPublish::Ring
    );
    let engine =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sync/engine.rs"))
            .unwrap();
    assert!(engine.contains("ManifestOrigin::FolderSync"));
    gate_ran("trust_enforcement_b182::b182_folder_paths_publish_no_manifest_envelope");
}

// --- T2, T3 (B182-10): restores need no per-file ring envelope -------------------------------

const KEY_SHARE_PLUS: usize = OWNER_SHARE as usize + 6;

fn body(n: usize) -> String {
    format!("b182 churn pass {n}\n").repeat(64)
}

fn run(node: &Path, args: &[&str], peers: &str) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", node.join("lan-registry"))
        .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
        .env("PARVAULT_SEED_PHRASE", PHRASE)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .arg("--data-dir")
        .arg(node)
        .args(["--no-lan-discovery", "--peers", peers])
        .args(args);
    output_within(&mut cmd, Duration::from_secs(120))
}

fn peers_of(hosts: &[Host]) -> String {
    hosts
        .iter()
        .map(|h| h.addr.clone())
        .collect::<Vec<_>>()
        .join(",")
}

/// T2 (B182-10): after churn past the owner share, the owner's data dir is lost. Recovery from
/// the seed phrase on another node restores the last pass byte for byte; a fresh node given the
/// phrase imports the catalog and continues the vault at last+1 (L-135).
#[test]
fn b182_disaster_restore_newest_version() {
    let (hosts, owner, _) = churn(KEY_SHARE_PLUS);
    let peers = peers_of(&hosts);
    std::fs::remove_dir_all(&owner.node).unwrap();
    let other = tempfile::Builder::new()
        .prefix("pv-b182-rec-")
        .tempdir()
        .unwrap();
    let out_dir = other.path().join("out");
    let out = run(
        &other.path().join("node"),
        &[
            "recover-from-seed",
            "--vault-namespace",
            NAMESPACE,
            "--out-dir",
            out_dir.to_str().unwrap(),
        ],
        &peers,
    );
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert_eq!(
        std::fs::read_to_string(out_dir.join("a.txt")).unwrap(),
        body(KEY_SHARE_PLUS),
        "{t}"
    );
    // Catalog import and resume on a fresh node.
    let fresh = Owner::new();
    std::fs::write(fresh.folder.join("a.txt"), "after resume\n").unwrap();
    let out = fresh.pass(&peers, &[]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(
        t.contains(&format!("from the ring's catalog version {KEY_SHARE_PLUS}")),
        "{t}"
    );
    assert!(
        t.contains(&format!("Snapshot Version   : {}", KEY_SHARE_PLUS + 1)),
        "{t}"
    );
    gate_ran("trust_enforcement_b182::b182_disaster_restore_newest_version");
}

/// T3 (B182-10): on the owner node, with `manifests/` and the envelope store deleted, every
/// retained version restores byte for byte from the version store and the ring's shards; a
/// version GC dropped is refused.
#[test]
fn b182_every_retained_version_restores() {
    let (hosts, owner, _) = churn(KEY_SHARE_PLUS);
    let peers = peers_of(&hosts);
    let _ = std::fs::remove_dir_all(owner.node.join("manifests"));
    let _ = std::fs::remove_file(
        owner
            .node
            .join(parvault::storage::block_store::DHT_STORE_FILE),
    );
    let retained: Vec<u64> = parvault::sync::retention::VersionStore::for_snapshot(&owner.snap)
        .list()
        .unwrap()
        .iter()
        .map(|m| m.version)
        .collect();
    assert!(!retained.is_empty());
    for &v in &retained {
        let out_dir = owner.snap.with_extension(format!("v{v}"));
        let vs = v.to_string();
        let out = run(
            &owner.node,
            &[
                "restore-folder",
                "--snapshot",
                owner.snap.to_str().unwrap(),
                "--out-dir",
                out_dir.to_str().unwrap(),
                "--vault-namespace",
                NAMESPACE,
                "--version",
                &vs,
            ],
            &peers,
        );
        let t = text(&out);
        assert!(out.status.success(), "version {v}: {t}");
        assert_eq!(
            std::fs::read_to_string(out_dir.join("a.txt")).unwrap(),
            body(v as usize),
            "version {v}"
        );
    }
    let dropped = (1..=KEY_SHARE_PLUS as u64).find(|v| !retained.contains(v));
    if let Some(v) = dropped {
        let vs = v.to_string();
        let out_dir = owner.snap.with_extension("dropped");
        let out = run(
            &owner.node,
            &[
                "restore-folder",
                "--snapshot",
                owner.snap.to_str().unwrap(),
                "--out-dir",
                out_dir.to_str().unwrap(),
                "--vault-namespace",
                NAMESPACE,
                "--version",
                &vs,
            ],
            &peers,
        );
        let t = text(&out);
        assert!(!out.status.success(), "{t}");
        assert!(t.contains("reject.version_not_retained"), "{t}");
    }
    eprintln!("b182 T3: retained {retained:?}, dropped checked: {dropped:?}");
    gate_ran("trust_enforcement_b182::b182_every_retained_version_restores");
}

// --- T4 (B182-6, B182-7): refusals surface ---------------------------------------------------

/// `parvault file store <file>` from `node` against `peers`, under the key `[key; 32]` (the
/// envelope's owner follows the key).
fn file_store(node: &Path, peers: &str, file: &Path, key: u8) -> String {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", node.join("lan-registry"))
        .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .arg("--data-dir")
        .arg(node)
        .args(["--no-lan-discovery", "--peers", peers, "file", "store"])
        .arg(file)
        .args(["--key-hex", &hex::encode([key; 32]), "--tier", "consumer"]);
    let out = output_within(&mut cmd, Duration::from_secs(120));
    let t = text(&out);
    assert!(out.status.success(), "file store failed:\n{t}");
    t
}

/// T4 accept: a host capped at 4 keys (an owner share of 3). Ten `file store` runs: the first
/// three envelopes are stored, the other seven each log `warn.dht_envelope_refused` with
/// `reject.dht_owner_key_cap` on the owner. A second node stores one file (the fourth and last
/// key). Then two changed `watch-folder` passes: a phrase vault's catalog is signed by the vault's
/// own identity (seed phrase and namespace), a new owner, and the full host refuses its new key
/// (`reject.dht_store_full`) each time; each pass prints its refusal line, and `folder-status`
/// shows a total of 2 with the last reason.
#[test]
fn b182_owner_refusals_surface() {
    let host = Host::spawn("t4", "4");
    let owner = Owner::new();
    let file = owner.node.with_extension("one.bin");
    let mut refused = 0;
    for n in 0..10u8 {
        std::fs::write(&file, vec![n + 1; 4096]).unwrap();
        let t = file_store(&owner.node, &host.addr, &file, 0x11);
        if t.contains("warn.dht_envelope_refused") {
            assert!(t.contains("reject.dht_owner_key_cap"), "{t}");
            assert!(t.contains("hosts_refused=1"), "{t}");
            refused += 1;
        }
    }
    assert_eq!(refused, 7, "{}", host.log_text());
    let second = owner.node.with_extension("second");
    let t = file_store(&second, &host.addr, &file, 0x22);
    assert!(!t.contains("warn.dht_envelope_refused"), "{t}");
    for n in 1..=2 {
        std::fs::write(owner.folder.join("a.txt"), body(n)).unwrap();
        let out = owner.pass(&host.addr, &[]);
        let t = text(&out);
        assert!(out.status.success(), "{t}");
        assert!(
            t.contains(
                "1 envelope refusal(s) this pass (last: catalog ring reject.dht_store_full)"
            ),
            "pass {n}:\n{t}"
        );
        assert!(t.contains("warn.dht_envelope_refused"), "{t}");
    }
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env_remove("PARVAULT_PEERS")
        .arg("--data-dir")
        .arg(&owner.node)
        .args(["--no-lan-discovery", "folder-status", "--snapshot"])
        .arg(&owner.snap);
    let out = output_within(&mut cmd, Duration::from_secs(60));
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(
        t.contains("Envelope Refusals  : 2 (last: catalog ring reject.dht_store_full)"),
        "{t}"
    );
    gate_ran("trust_enforcement_b182::b182_owner_refusals_surface");
}

/// T4 reject: a pass with no refusal prints no refusal line, and `folder-status` shows 0.
#[test]
fn b182_no_refusal_no_line() {
    let host = Host::spawn("t4r", MAX_KEYS);
    let owner = Owner::new();
    std::fs::write(owner.folder.join("a.txt"), body(1)).unwrap();
    let out = owner.pass(&host.addr, &[]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(!t.contains("envelope refusal"), "{t}");
    assert!(!t.contains("warn.dht_envelope_refused"), "{t}");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env_remove("PARVAULT_PEERS")
        .arg("--data-dir")
        .arg(&owner.node)
        .args(["--no-lan-discovery", "folder-status", "--snapshot"])
        .arg(&owner.snap);
    let out = output_within(&mut cmd, Duration::from_secs(60));
    let t = text(&out);
    assert!(t.contains("Envelope Refusals  : 0 (last: none)"), "{t}");
    gate_ran("trust_enforcement_b182::b182_no_refusal_no_line");
}

// --- T5 (B182-4, B182-5): host rules unchanged -----------------------------------------------

/// A self-consistent signed vault-catalog envelope at `dht_key`, owned by `signer`, at
/// `version`.
fn catalog(
    signer: &parvault::crypto::NodeIdentity,
    dht_key: [u8; 32],
    version: u64,
) -> parvault::sync::EncryptedVaultCatalogEnvelope {
    use sha2::{Digest, Sha256};
    let envelope_salt = [0x33; 32];
    let encrypted_catalog_bytes = vec![version as u8; 256];
    let ciphertext_sha256: [u8; 32] = Sha256::digest(&encrypted_catalog_bytes).into();
    let owner_pubkey = signer.public_key_bytes();
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
    env
}

fn limits(max_keys: u64) -> parvault::storage::block_store::DhtStoreLimits {
    parvault::storage::block_store::DhtStoreLimits {
        max_bytes: 1 << 20,
        max_keys,
        max_owner_bytes: 1 << 20,
        max_owner_keys: max_keys / 4 * 3,
    }
}

fn err_text(r: Result<(), parvault::storage::StorageError>) -> String {
    r.expect_err("refused").to_string()
}

/// T5 (B182-4, B182-5): a foreign owner's replacement is refused; a catalog rollback (or a
/// replay of the held version) is refused; at its key share an owner's held catalog still
/// updates in place, while its new key is refused (`reject.dht_owner_key_cap`); the G-28 merge
/// never lowers a floor; and no wire request removes a DHT record.
#[test]
fn b182_host_rules_unchanged() {
    use parvault::crypto::NodeIdentity;
    let a = NodeIdentity::from_seed([0xA1; 32]);
    let b = NodeIdentity::from_seed([0xB2; 32]);
    let mut s = ZeroTrustDhtStore::new();
    s.set_limits(limits(4)); // owner share 3
    s.put_vault_catalog_envelope(catalog(&a, [1; 32], 1))
        .unwrap();
    // Foreign replacement.
    assert!(s
        .put_vault_catalog_envelope(catalog(&b, [1; 32], 9))
        .is_err());
    // Rollback and replay.
    s.put_vault_catalog_envelope(catalog(&a, [1; 32], 5))
        .unwrap();
    assert!(s
        .put_vault_catalog_envelope(catalog(&a, [1; 32], 4))
        .is_err());
    assert!(s
        .put_vault_catalog_envelope(catalog(&a, [1; 32], 5))
        .is_err());
    // Fill A's share (3 keys).
    s.put_vault_catalog_envelope(catalog(&a, [2; 32], 1))
        .unwrap();
    s.put_vault_catalog_envelope(catalog(&a, [3; 32], 1))
        .unwrap();
    assert_eq!(s.keys_per_owner(), vec![3]);
    // B182-CATALOG-INPLACE: the held catalog updates at the cap.
    s.put_vault_catalog_envelope(catalog(&a, [1; 32], 6))
        .unwrap();
    assert_eq!(
        s.get_vault_catalog_envelope(&[1; 32])
            .map(|e| e.monotonic_version),
        Some(6)
    );
    // A new key at the cap is refused.
    let e = err_text(s.put_vault_catalog_envelope(catalog(&a, [4; 32], 1)));
    assert!(e.contains("reject.dht_owner_key_cap"), "{e}");
    assert_eq!(s.keys_per_owner(), vec![3]);
    // The store counts its refusals (foreign, rollback, replay, cap).
    assert_eq!(s.refusals(), 4);
    // G-28: the merge never lowers a floor.
    use parvault::storage::block_store::{dht_merge_pick, DhtMergePick};
    for d in 0..6u64 {
        for m in 0..6u64 {
            let kept = match dht_merge_pick(Some(([1; 32], d)), Some(([1; 32], m))) {
                DhtMergePick::Disk => d,
                DhtMergePick::Memory => m,
            };
            assert_eq!(kept, d.max(m));
        }
    }
    // No wire request removes a DHT record: the request enum names DHT envelopes only in a put
    // and a get.
    let wire = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/network/behaviour.rs"),
    )
    .unwrap();
    let start = wire.find("pub enum MeshWireRequest").unwrap();
    let end = start + wire[start..].find("\n}\n").unwrap();
    let variants: Vec<&str> = wire[start..end]
        .lines()
        .map(str::trim)
        .filter(|l| l.contains("Dht") && l.starts_with(|c: char| c.is_ascii_uppercase()))
        .collect();
    for v in &variants {
        assert!(
            v.starts_with("PutDhtEnvelope(") || v.starts_with("GetDhtEnvelope {"),
            "unexpected DHT request: {v}"
        );
    }
    gate_ran("trust_enforcement_b182::b182_host_rules_unchanged");
}

/// B182-CATALOG-INPLACE accept (B182-5): a vault's catalog is held on a host (cap 32, owner
/// share 24); the host is stopped and 24 more keys of the vault's own owner are added, so on
/// restart the owner holds 25 keys, over its share (`warn.dht_owner_over_cap_at_load`). The next
/// changed pass's catalog still updates in place on that host, with no refusal.
#[test]
fn b182_catalog_updates_in_place_over_cap() {
    let mut host = Host::spawn("t5a", MAX_KEYS);
    let owner = Owner::new();
    std::fs::write(owner.folder.join("a.txt"), body(1)).unwrap();
    let out = owner.pass(&host.addr, &[]);
    let t = text(&out);
    assert!(out.status.success() && t.contains("hosts_stored=1"), "{t}");
    let canonical = parvault::crypto::validate_recovery_seed_phrase_or_passphrase(PHRASE).unwrap();
    let vault = parvault::crypto::NodeIdentity::from_recovery_seed_phrase(&canonical, NAMESPACE);
    host.restart_with(|dir| {
        let mut s = ZeroTrustDhtStore::with_persistence_dir(dir);
        for k in 0..24u8 {
            s.put_vault_catalog_envelope(catalog(&vault, [100 + k; 32], 1))
                .unwrap();
        }
        assert_eq!(s.keys_per_owner(), vec![25]);
    });
    std::fs::write(owner.folder.join("a.txt"), body(2)).unwrap();
    let out = owner.pass(&host.addr, &[]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(
        t.contains("hosts_stored=1") && t.contains("hosts_refused=0"),
        "{t}"
    );
    assert!(!t.contains("warn.dht_envelope_refused"), "{t}");
    let log = host.log_text();
    assert!(log.contains("warn.dht_owner_over_cap_at_load"), "{log}");
    assert!(!log.contains("refused a DHT envelope"), "{log}");
    let cat = std::fs::read(owner.snap.with_extension("catalog.bin")).unwrap();
    let cat: parvault::sync::EncryptedVaultCatalogEnvelope = bincode::deserialize(&cat).unwrap();
    let s = ZeroTrustDhtStore::with_persistence_dir(&host.dir);
    assert_eq!(
        s.get_vault_catalog_envelope(&cat.dht_key)
            .map(|e| e.monotonic_version),
        Some(cat.monotonic_version)
    );
    assert_eq!(s.keys_per_owner(), vec![25]);
    gate_ran("trust_enforcement_b182::b182_catalog_updates_in_place_over_cap");
}

// --- T6 (B182-8): a legacy store over the cap ------------------------------------------------

/// Writes a store file in `dir` holding `n` catalog keys of `owner` (and loads nothing else).
fn legacy_store(dir: &Path, owner: &parvault::crypto::NodeIdentity, n: u8) {
    let mut s = ZeroTrustDhtStore::with_persistence_dir(dir);
    for k in 0..n {
        s.put_vault_catalog_envelope(catalog(owner, [k; 32], 1))
            .unwrap();
    }
    assert_eq!(s.keys_per_owner(), vec![u64::from(n)]);
}

/// T6 (B182-8): a store with 40 legacy keys of one owner, loaded under a cap of 32 (a share of
/// 24): the owner's new key is refused, its held catalog still updates, and loading changes
/// nothing in the file. A real daemon on that store logs `warn.dht_owner_over_cap_at_load` once
/// and leaves the file as it is.
#[test]
fn b182_legacy_store_over_cap_at_load() {
    use parvault::crypto::NodeIdentity;
    let owner = NodeIdentity::from_seed([0xC3; 32]);
    let tmp = tempfile::tempdir().unwrap();
    legacy_store(tmp.path(), &owner, 40);
    let path = tmp
        .path()
        .join(parvault::storage::block_store::DHT_STORE_FILE);
    let before = std::fs::read(&path).unwrap();
    let mut s = ZeroTrustDhtStore::with_persistence_dir(tmp.path());
    s.set_limits(limits(32));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "load changed the file"
    );
    assert_eq!(s.keys_per_owner(), vec![40]);
    // 40 keys are over both the total (32) and the owner's share (24): the total refuses first.
    let e = err_text(s.put_vault_catalog_envelope(catalog(&owner, [200; 32], 1)));
    assert!(e.contains("reject.dht_store_full"), "{e}");
    s.put_vault_catalog_envelope(catalog(&owner, [7; 32], 2))
        .unwrap();
    assert_eq!(s.keys_per_owner(), vec![40]);

    // A real daemon on a fresh copy of the 40-key store.
    let host = Host::spawn_prepared("t6", MAX_KEYS, |dir| legacy_store(dir, &owner, 40));
    let file = host
        .dir
        .join(parvault::storage::block_store::DHT_STORE_FILE);
    let before = std::fs::read(&file).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !host.log_text().contains("warn.dht_owner_over_cap_at_load")
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    let log = host.log_text();
    assert_eq!(
        log.matches("warn.dht_owner_over_cap_at_load").count(),
        1,
        "{log}"
    );
    assert!(log.contains("keys=40") && log.contains("share=24"), "{log}");
    assert_eq!(std::fs::read(&file).unwrap(), before);
    gate_ran("trust_enforcement_b182::b182_legacy_store_over_cap_at_load");
}

/// B182-8 reject: an owner under its share logs no over-cap warning at load.
#[test]
fn b182_store_under_cap_no_warning() {
    use parvault::crypto::NodeIdentity;
    let owner = NodeIdentity::from_seed([0xC4; 32]);
    let host = Host::spawn_prepared("t6r", MAX_KEYS, |dir| legacy_store(dir, &owner, 20));
    std::thread::sleep(Duration::from_secs(2));
    let log = host.log_text();
    assert!(log.contains("DHT envelope store limits lowered"), "{log}");
    assert!(!log.contains("warn.dht_owner_over_cap_at_load"), "{log}");
    gate_ran("trust_enforcement_b182::b182_store_under_cap_no_warning");
}

// --- T7: the wire is unchanged ---------------------------------------------------------------

/// T7 (golden): `PutDhtEnvelope` of a fixed catalog envelope serialises to the same bytes as in
/// `v0.5.5` (no wire change).
#[test]
fn b182_wire_golden_unchanged() {
    use sha2::{Digest, Sha256};
    let signer = parvault::crypto::NodeIdentity::from_seed([0x5A; 32]);
    let env = catalog(&signer, [9; 32], 7);
    let req = parvault::network::MeshWireRequest::PutDhtEnvelope(
        parvault::network::DhtWireEnvelope::VaultCatalog(env),
    );
    let raw = bincode::serialize(&req).unwrap();
    let got = hex::encode(Sha256::digest(&raw));
    assert_eq!(got, WIRE_GOLDEN_SHA256, "{} bytes", raw.len());
    gate_ran("trust_enforcement_b182::b182_wire_golden_unchanged");
}

/// Pinned at core `14a3f7d` (the B-182 base; `behaviour.rs` unchanged by B-182).
const WIRE_GOLDEN_SHA256: &str = "c12dbe3d576efd7eb43daf3dfa7f86c2bcf7535b1e6f21f5664dbba45de47918";
