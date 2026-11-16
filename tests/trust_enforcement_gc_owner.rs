//! `v0.5.6` track B2 suite: version GC on the owner (plan Section 3.7; B-154 C1-C8, C24, C30,
//! C35, C37; L-119, L-122). Claims of track B2 put their differential pairs here;
//! `tests/trust_enforcement.rs` is frozen.
//!
//! Every test runs the real `parvault` binary on scratch data dirs (and, for the ring tests,
//! real daemons on ephemeral loopback ports). Every test writes its sentinel (`gate_ran`) last,
//! after its assertions.

mod common;

use parvault::sync::retention::{VersionStore, DAY_MS};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

const KEY_HEX: &str = "6262626262626262626262626262626262626262626262626262626262626262";

/// One owner folder backed up with `watch-folder --once` on this machine only (no ring).
struct LocalFolder {
    _tmp: tempfile::TempDir,
    node: PathBuf,
    folder: PathBuf,
    snap: PathBuf,
}

impl LocalFolder {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
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

    fn write(&self, body: &str) {
        std::fs::write(self.folder.join("a.txt"), body).unwrap();
    }

    fn versions(&self) -> Vec<u64> {
        VersionStore::for_snapshot(&self.snap)
            .list()
            .unwrap()
            .iter()
            .map(|m| m.version)
            .collect()
    }

    fn shard_files(&self) -> std::collections::BTreeSet<String> {
        std::fs::read_dir(self.node.join("shards"))
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Rewrites version `v`'s creation time (fixture data: no fault hook in the binary).
    fn date_version(&self, v: u64, created_ms: u64) {
        let store = VersionStore::for_snapshot(&self.snap);
        let snap = store.load(v).unwrap();
        std::fs::write(store.path_of(v), VersionStore::encode(&snap, created_ms)).unwrap();
    }
}

/// `parvault --data-dir <node> --no-lan-discovery <args>` (the real binary), ring env cleared.
fn run_parvault(node: &Path, args: &[&str]) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env_remove("PARVAULT_GENESIS_SEED_HEX")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .env_remove("PARVAULT_PEERS")
        .env("PARVAULT_LAN_REGISTRY_DIR", node.join("lan-registry"))
        .arg("--data-dir")
        .arg(node)
        .arg("--no-lan-discovery")
        .args(args);
    common::output_within_deadline(&mut cmd)
}

/// One `watch-folder --once` pass of `f` with `extra` flags.
fn pass_with(f: &LocalFolder, extra: &[&str]) -> Output {
    let mut args = vec![
        "watch-folder",
        "--folder",
        f.folder.to_str().unwrap(),
        "--snapshot-out",
        f.snap.to_str().unwrap(),
        "--key-hex",
        KEY_HEX,
        "--once",
        "--allow-local-only",
    ];
    args.extend_from_slice(extra);
    run_parvault(&f.node, &args)
}

/// One pass that must succeed.
fn pass(f: &LocalFolder) -> String {
    let out = pass_with(f, &[]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    t
}

fn restore(f: &LocalFolder, version: Option<u64>, out: &Path) -> Output {
    let v = version.map(|n| n.to_string());
    let mut args = vec![
        "restore-folder",
        "--snapshot",
        f.snap.to_str().unwrap(),
        "--out-dir",
        out.to_str().unwrap(),
        "--key-hex",
        KEY_HEX,
    ];
    if let Some(v) = &v {
        args.extend_from_slice(&["--version", v]);
    }
    run_parvault(&f.node, &args)
}

// --- B154-NOCHANGE (B-154 3, T2) -------------------------------------------------------------

/// B154-NOCHANGE accept (T2): ten passes over an unchanged two-file folder keep version 1, say
/// "(no change)" nine times, leave the snapshot file and the version store byte-identical after
/// pass 2, and write no new shard.
#[test]
fn b154_unchanged_folder_keeps_version() {
    let f = LocalFolder::new();
    f.write("alpha");
    std::fs::write(f.folder.join("b.txt"), "bravo").unwrap();
    let first = pass(&f);
    assert!(first.contains("Snapshot Version   : 1\n"), "{first}");
    let snap_after_1 = std::fs::read(&f.snap).unwrap();
    let shards_after_1 = f.shard_files();
    let v1_file = std::fs::read(VersionStore::for_snapshot(&f.snap).path_of(1)).unwrap();
    let mut unchanged = 0;
    for _ in 0..9 {
        let t = pass(&f);
        assert!(t.contains("Snapshot Version   : 1 (no change)"), "{t}");
        assert!(t.contains("Changes            : none"), "{t}");
        unchanged += 1;
    }
    assert_eq!(unchanged, 9);
    assert_eq!(std::fs::read(&f.snap).unwrap(), snap_after_1);
    assert_eq!(f.versions(), vec![1]);
    assert_eq!(
        std::fs::read(VersionStore::for_snapshot(&f.snap).path_of(1)).unwrap(),
        v1_file
    );
    assert_eq!(f.shard_files(), shards_after_1, "no new shard");
    gate_ran("trust_enforcement_gc_owner::b154_unchanged_folder_keeps_version");
}

/// B154-NOCHANGE reject: a changed file is never a no-change pass (`info.folder_unchanged` is
/// not logged); it makes version 2 with its own version file.
#[test]
fn b154_changed_file_makes_a_version() {
    let f = LocalFolder::new();
    f.write("alpha");
    pass(&f);
    f.write("alpha, changed");
    let t = pass(&f);
    assert!(!t.contains("info.folder_unchanged"), "{t}");
    assert!(t.contains("Snapshot Version   : 2\n"), "{t}");
    assert!(
        t.contains("Changes            : 1 modified, 0 added, 0 deleted"),
        "{t}"
    );
    assert_eq!(f.versions(), vec![1, 2]);
    // The unchanged pass that follows does log the code.
    let t = pass(&f);
    assert!(t.contains("info.folder_unchanged"), "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_changed_file_makes_a_version");
}

// --- B154-STALE (C4) -------------------------------------------------------------------------

/// B154-STALE accept: the snapshot file a pass wrote runs the next pass.
#[test]
fn b154_current_snapshot_runs() {
    let f = LocalFolder::new();
    f.write("one");
    pass(&f);
    f.write("two");
    let t = pass(&f);
    assert!(t.contains("Snapshot Version   : 2"), "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_current_snapshot_runs");
}

/// B154-STALE reject (C4): an old copy of the snapshot file put back (its version below the
/// version store's newest) is refused with `reject.gc_snapshot_stale`, and nothing changes.
#[test]
fn b154_old_snapshot_copy_refused() {
    let f = LocalFolder::new();
    f.write("one");
    pass(&f);
    let old = std::fs::read(&f.snap).unwrap();
    f.write("two");
    pass(&f);
    std::fs::write(&f.snap, &old).unwrap();
    f.write("three");
    let out = pass_with(&f, &[]);
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("reject.gc_snapshot_stale"), "{t}");
    assert_eq!(f.versions(), vec![1, 2]);
    assert_eq!(std::fs::read(&f.snap).unwrap(), old);
    gate_ran("trust_enforcement_gc_owner::b154_old_snapshot_copy_refused");
}

// --- B154-RESTORE-VERSION (T5) ---------------------------------------------------------------

/// B154-RESTORE-VERSION accept: `restore-folder --version 2` restores version 2's bytes after
/// version 4 is the latest.
#[test]
fn b154_restore_retained_version() {
    let f = LocalFolder::new();
    for body in ["v1 body", "v2 body", "v3 body", "v4 body"] {
        f.write(body);
        pass(&f);
    }
    assert_eq!(f.versions(), vec![2, 3, 4]);
    let out_dir = f.node.parent().unwrap().join("restored");
    let out = restore(&f, Some(2), &out_dir);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(std::fs::read(out_dir.join("a.txt")).unwrap(), b"v2 body");
    gate_ran("trust_enforcement_gc_owner::b154_restore_retained_version");
}

/// B154-RESTORE-VERSION reject: a version retention dropped is refused with
/// `reject.version_not_retained` and nothing is written.
#[test]
fn b154_restore_dropped_version_refused() {
    let f = LocalFolder::new();
    for body in ["v1 body", "v2 body", "v3 body", "v4 body"] {
        f.write(body);
        pass(&f);
    }
    let out_dir = f.node.parent().unwrap().join("restored");
    let out = restore(&f, Some(1), &out_dir);
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("reject.version_not_retained"), "{t}");
    assert!(!out_dir.join("a.txt").exists());
    gate_ran("trust_enforcement_gc_owner::b154_restore_dropped_version_refused");
}

// --- B154-INTERVAL (C37) ---------------------------------------------------------------------

fn watch_loop(f: &LocalFolder, interval: &str) -> std::process::Child {
    std::process::Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env_remove("PARVAULT_PEERS")
        .env("PARVAULT_LAN_REGISTRY_DIR", f.node.join("lan-registry"))
        .arg("--data-dir")
        .arg(&f.node)
        .arg("--no-lan-discovery")
        .args([
            "watch-folder",
            "--folder",
            f.folder.to_str().unwrap(),
            "--snapshot-out",
            f.snap.to_str().unwrap(),
            "--key-hex",
            KEY_HEX,
            "--interval-secs",
            interval,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

/// B154-INTERVAL accept: a 2 s interval (the floor) runs passes.
#[test]
fn b154_interval_at_floor_runs() {
    let f = LocalFolder::new();
    f.write("loop");
    let mut child = watch_loop(&f, "2");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while f.versions().is_empty() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "watch-folder exited early"
        );
        assert!(std::time::Instant::now() < deadline, "no pass in 30 s");
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(f.versions(), vec![1]);
    gate_ran("trust_enforcement_gc_owner::b154_interval_at_floor_runs");
}

/// B154-INTERVAL reject (C37): `--interval-secs 1` is refused (`reject.interval_below_floor`),
/// not clamped; no pass runs.
#[test]
fn b154_interval_below_floor_refused() {
    let f = LocalFolder::new();
    f.write("loop");
    let child = watch_loop(&f, "1");
    let out = child.wait_with_output().unwrap();
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("reject.interval_below_floor"), "{t}");
    assert!(f.versions().is_empty());
    gate_ran("trust_enforcement_gc_owner::b154_interval_below_floor_refused");
}

// --- B154-RETAIN (C25, C28) ------------------------------------------------------------------

/// Three versions dated 12 and 11 days ago and `v3_created` (one per day).
fn dated_history(f: &LocalFolder, v3_created: u64) {
    for body in ["d1", "d2", "d3"] {
        f.write(body);
        pass(f);
    }
    let now = now_ms();
    f.date_version(1, now - 12 * DAY_MS);
    f.date_version(2, now - 11 * DAY_MS);
    f.date_version(3, v3_created);
}

/// B154-RETAIN accept: on a plausible clock the default policy (3 recent, 3 daily) drops the
/// day versions older than 3 days once 3 newer versions exist.
#[test]
fn b154_old_versions_dropped() {
    let f = LocalFolder::new();
    dated_history(&f, now_ms() - 10 * DAY_MS);
    let mut last = String::new();
    for body in ["t4", "t5", "t6"] {
        f.write(body);
        last = pass(&f);
    }
    assert_eq!(f.versions(), vec![4, 5, 6], "{last}");
    assert!(!last.contains("warn.retention_clock_implausible"), "{last}");
    gate_ran("trust_enforcement_gc_owner::b154_old_versions_dropped");
}

/// B154-RETAIN reject: a clock behind a retained version (version 3 dated two days ahead) is
/// implausible: `warn.retention_clock_implausible`, and no version is dropped for its age (each
/// day's newest version stays, with the last 3).
#[test]
fn b154_implausible_clock_drops_nothing() {
    let f = LocalFolder::new();
    dated_history(&f, now_ms() + 2 * DAY_MS);
    let mut last = String::new();
    for body in ["t4", "t5", "t6"] {
        f.write(body);
        last = pass(&f);
    }
    assert!(last.contains("warn.retention_clock_implausible"), "{last}");
    assert_eq!(f.versions(), vec![1, 2, 3, 4, 5, 6], "{last}");
    gate_ran("trust_enforcement_gc_owner::b154_implausible_clock_drops_nothing");
}

// --- `--no-gc` and the upgrade (C1) ----------------------------------------------------------

/// `--no-gc` keeps the `v0.5.5` behaviour for one release: no version store, no GC lines.
#[test]
fn b154_no_gc_keeps_v055_behaviour() {
    let f = LocalFolder::new();
    for body in ["v1", "v2", "v3", "v4", "v5"] {
        f.write(body);
        let out = pass_with(&f, &["--no-gc"]);
        let t = text(&out);
        assert!(out.status.success(), "{t}");
        assert!(!t.contains("Versions Retained"), "{t}");
    }
    assert!(!VersionStore::for_snapshot(&f.snap).dir().exists());
    gate_ran("trust_enforcement_gc_owner::b154_no_gc_keeps_v055_behaviour");
}

/// C1: a snapshot file written before the version store (`--no-gc`, the `v0.5.5` layout) is
/// taken over by the first GC pass (its version is stored, nothing older is freed), and the
/// snapshot file a `v0.5.6` pass writes still decodes with the frozen `v0.5.5` layout.
#[test]
fn b154_v055_snapshot_upgrades_and_stays_readable() {
    let f = LocalFolder::new();
    f.write("old");
    let out = pass_with(&f, &["--no-gc"]);
    assert!(out.status.success(), "{}", text(&out));
    let shards = f.shard_files();
    f.write("new");
    let t = pass(&f);
    assert!(t.contains("Snapshot Version   : 2"), "{t}");
    assert_eq!(f.versions(), vec![2]);
    assert!(f.shard_files().is_superset(&shards), "nothing older freed");
    let raw = std::fs::read(&f.snap).unwrap();
    let old: v055::FolderSnapshotManifest = bincode::deserialize(&raw).unwrap();
    assert_eq!(old.version, 2);
    assert_eq!(old.files.len(), 1);
    gate_ran("trust_enforcement_gc_owner::b154_v055_snapshot_upgrades_and_stays_readable");
}

/// The snapshot layout `v0.5.5` reads (`sync/engine.rs` at `1b1bad6`), frozen here.
mod v055 {
    use parvault::config::ErasureTier;
    use parvault::storage::{FileManifest, SignedDhtManifestEnvelope};
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    #[allow(dead_code)]
    pub struct SyncedFileEntry {
        pub relative_path: String,
        pub size_bytes: u64,
        pub modified_unix_ms: u64,
        pub plaintext_sha256: [u8; 32],
        pub file_merkle_root: [u8; 32],
        pub manifest: FileManifest,
        pub shard_pseudonyms: Vec<String>,
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    pub struct DeletedFileTombstone {
        pub relative_path: String,
        pub deleted_at_version: u64,
        pub previous_merkle_root: [u8; 32],
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    pub struct FolderSnapshotManifest {
        pub version: u64,
        pub folder_merkle_root: [u8; 32],
        pub tier: ErasureTier,
        pub files: BTreeMap<String, SyncedFileEntry>,
        pub signed_dht_envelope: Option<SignedDhtManifestEnvelope>,
        pub deleted_tombstones: BTreeMap<String, DeletedFileTombstone>,
    }
}

// --- Ring tests: one real storage daemon ----------------------------------------------------

/// The ring genesis the host and the owner are provisioned with.
const GENESIS_SEED_HEX: &str = "4747474747474747474747474747474747474747474747474747474747474747";
const PHRASE: &str = "b2 version gc ring test passphrase";

/// A storage daemon on an ephemeral loopback port.
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

fn spawn_host() -> Host {
    spawn_host_with("")
}

/// A host whose `config.toml` is `config`.
fn spawn_host_with(config: &str) -> Host {
    let tmp = tempfile::Builder::new()
        .prefix("pv-b2-host-")
        .tempdir()
        .unwrap();
    let dir = tmp.path().join("data");
    std::fs::create_dir_all(&dir).unwrap();
    parvault::crypto::NodeIdentity::load_or_generate_in_dir(&dir).unwrap();
    if !config.is_empty() {
        std::fs::write(dir.join("config.toml"), config).unwrap();
    }
    let log = tmp.path().join("host.log");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", tmp.path().join("lan-registry"))
        .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
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
    let id = parvault::crypto::NodeIdentity::load_or_generate_in_dir(&dir).unwrap();
    let pid = parvault::network::node_identity_libp2p_peer_id(&id).unwrap();
    Host {
        child,
        dir,
        log,
        addr: format!("{addr}/p2p/{pid}"),
        _tmp: tmp,
    }
}

impl Host {
    fn shard_names(&self) -> std::collections::BTreeSet<String> {
        std::fs::read_dir(self.dir.join("shards"))
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.ends_with(".shard"))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A `watch-folder --once` pass of `f` against `host` with the vault phrase (the catalog is
/// published to the ring).
fn ring_pass(f: &LocalFolder, host: &Host) -> Output {
    ring_pass_peers(f, &host.addr)
}

/// A `watch-folder --once` pass of `f` against the hosts in `peers` (comma-separated).
fn ring_pass_peers(f: &LocalFolder, peers: &str) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", f.node.join("lan-registry"))
        .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
        .env("PARVAULT_SEED_PHRASE", PHRASE)
        .env("RUST_LOG", "info")
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .arg("--data-dir")
        .arg(&f.node)
        .args(["--no-lan-discovery", "--peers", peers])
        .args([
            "watch-folder",
            "--folder",
            f.folder.to_str().unwrap(),
            "--snapshot-out",
            f.snap.to_str().unwrap(),
            "--vault-namespace",
            "b2-ring",
            "--once",
        ]);
    output_within(&mut cmd, Duration::from_secs(240))
}

/// `restore-folder --version` of `f` through the ring.
fn ring_restore(f: &LocalFolder, host: &Host, version: u64, out: &Path) -> Output {
    let v = version.to_string();
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", f.node.join("lan-registry"))
        .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
        .env("PARVAULT_SEED_PHRASE", PHRASE)
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .arg("--data-dir")
        .arg(&f.node)
        .args(["--no-lan-discovery", "--peers", &host.addr])
        .args([
            "restore-folder",
            "--snapshot",
            f.snap.to_str().unwrap(),
            "--out-dir",
            out.to_str().unwrap(),
            "--vault-namespace",
            "b2-ring",
            "--version",
            &v,
        ]);
    output_within(&mut cmd, Duration::from_secs(120))
}

/// Runs `cmd` to completion within `limit` (ring passes over many shards outlast
/// `common::EXIT_DEADLINE`).
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

fn ring_pass_ok(f: &LocalFolder, host: &Host) -> String {
    let out = ring_pass(f, host);
    let t = text(&out);
    assert!(
        out.status.success(),
        "{t}\nhost log:\n{}",
        std::fs::read_to_string(&host.log).unwrap_or_default()
    );
    t
}

/// The shard file names of the stripes only `version` references (not the unchanged file).
fn shard_names_of(f: &LocalFolder, version: u64, path: &str) -> Vec<String> {
    let snap = VersionStore::for_snapshot(&f.snap).load(version).unwrap();
    let entry = &snap.files[path];
    entry
        .manifest
        .stripes
        .iter()
        .flat_map(|s| {
            s.shard_hashes.iter().enumerate().map(|(i, h)| {
                format!(
                    "{}.shard",
                    parvault::storage::ShardId {
                        stripe_merkle_root: s.stripe_merkle_root,
                        shard_index: i as u32,
                        shard_hash: *h,
                    }
                    .file_key()
                )
            })
        })
        .collect()
}

/// Four changed passes of `a.txt` beside an unchanged `b.txt`; returns version 1's `a.txt` and
/// `b.txt` shard names.
fn ring_history(f: &LocalFolder, host: &Host) -> (Vec<String>, Vec<String>) {
    std::fs::write(f.folder.join("b.txt"), "unchanged in every version").unwrap();
    f.write("a v1");
    ring_pass_ok(f, host);
    let a1 = shard_names_of(f, 1, "a.txt");
    let b1 = shard_names_of(f, 1, "b.txt");
    let held = host.shard_names();
    assert!(
        a1.iter().chain(&b1).all(|n| held.contains(n)),
        "placed on the host"
    );
    for body in ["a v2", "a v3"] {
        f.write(body);
        ring_pass_ok(f, host);
    }
    (a1, b1)
}

/// B154-FOREIGN accept (C6, C7): with this device's own catalog on the ring, version 1 ages out
/// at version 4 and its shards are freed on the host; the unchanged file's shards (marked by
/// every retained version) stay.
#[test]
fn b154_own_catalog_frees_on_host() {
    let host = spawn_host();
    let f = LocalFolder::new();
    let (a1, b1) = ring_history(&f, &host);
    f.write("a v4");
    let t = ring_pass_ok(&f, &host);
    assert!(!t.contains("reject.gc_foreign_catalog"), "{t}");
    assert_eq!(f.versions(), vec![2, 3, 4], "{t}");
    let held = host.shard_names();
    assert!(
        a1.iter().all(|n| !held.contains(n)),
        "v1 freed on the host\n{t}"
    );
    assert!(
        b1.iter().all(|n| held.contains(n)),
        "a marked stripe is kept\n{t}"
    );
    let out_dir = f.node.parent().unwrap().join("restored");
    let out = ring_restore(&f, &host, 2, &out_dir);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(std::fs::read(out_dir.join("a.txt")).unwrap(), b"a v2");
    gate_ran("trust_enforcement_gc_owner::b154_own_catalog_frees_on_host");
}

/// B154-FOREIGN reject (C7): a second device continued this vault from its catalog and
/// published a newer one; this device's next pass refuses to free anything
/// (`reject.gc_foreign_catalog`): version 1's shards and version file stay.
#[test]
fn b154_foreign_catalog_frees_nothing() {
    let host = spawn_host();
    let f = LocalFolder::new();
    let (a1, _) = ring_history(&f, &host);
    // The second device: the same phrase, this vault's snapshot (as recovered from the
    // catalog), one changed pass: it publishes version 4.
    let g = LocalFolder::new();
    std::fs::copy(&f.snap, &g.snap).unwrap();
    std::fs::write(g.folder.join("b.txt"), "unchanged in every version").unwrap();
    g.write("second device");
    let tg = ring_pass_ok(&g, &host);
    assert!(tg.contains("Snapshot Version   : 4"), "{tg}");
    f.write("a v4");
    let t = ring_pass_ok(&f, &host);
    assert!(t.contains("reject.gc_foreign_catalog"), "{t}");
    assert!(f.versions().contains(&1), "{t}");
    let held = host.shard_names();
    assert!(a1.iter().all(|n| held.contains(n)), "nothing freed\n{t}");
    gate_ran("trust_enforcement_gc_owner::b154_foreign_catalog_frees_nothing");
}

/// C24 (over 1024 shards): 60 changed files of one stripe each (Homelab, 20 shards) on one
/// host; when version 1 ages out its 1,200 shards go in two orders (1024 + 176), every one
/// freed.
#[test]
fn b154_over_1024_shards_freed_in_two_orders() {
    let host = spawn_host();
    let f = LocalFolder::new();
    let names: Vec<String> = (0..60).map(|i| format!("f{i:02}.txt")).collect();
    let write_all = |tag: &str| {
        for n in &names {
            std::fs::write(f.folder.join(n), format!("{tag} {n}")).unwrap();
        }
    };
    write_all("v1");
    ring_pass_ok(&f, &host);
    let v1: Vec<String> = names
        .iter()
        .flat_map(|n| shard_names_of(&f, 1, n))
        .collect();
    assert_eq!(v1.len(), 1200);
    for tag in ["v2", "v3"] {
        write_all(tag);
        ring_pass_ok(&f, &host);
    }
    write_all("v4");
    let t = ring_pass_ok(&f, &host);
    assert!(t.contains("2 order(s)"), "{t}");
    let held = host.shard_names();
    assert!(v1.iter().all(|n| !held.contains(n)), "{t}");
    assert!(t.contains("Pending Frees      : 0 "), "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_over_1024_shards_freed_in_two_orders");
}

// --- B154-WARN (L-122, C43, C44) -------------------------------------------------------------

/// 1 MiB of incompressible bytes tagged `tag`.
fn mib_body(tag: u8) -> Vec<u8> {
    let mut x = 0x2545_F491u32 ^ ((tag as u32) << 8);
    (0..1_048_576)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Rewrites a 1 MiB file `passes` times against two hosts, stopping the second after the first
/// pass when `stop_second`; returns the last pass's output.
fn churn_two_hosts(passes: u8, stop_second: bool) -> String {
    let h1 = spawn_host();
    let mut h2 = spawn_host();
    let peers = format!("{},{}", h1.addr, h2.addr);
    let f = LocalFolder::new();
    let mut last = String::new();
    for tag in 1..=passes {
        std::fs::write(f.folder.join("a.bin"), mib_body(tag)).unwrap();
        let out = ring_pass_peers(&f, &peers);
        last = text(&out);
        assert!(out.status.success(), "pass {tag}: {last}");
        if tag == 1 && stop_second {
            let _ = h2.child.kill();
            let _ = h2.child.wait();
        }
    }
    last
}

/// B154-WARN accept (L-122): normal churn under the default policy (frees succeed) stays below
/// 1.25x what the policy can hold: no warning.
#[test]
fn b154_storage_within_policy_is_silent() {
    let t = churn_two_hosts(8, false);
    assert!(!t.contains("warn.folder_storage_ratio"), "{t}");
    assert!(t.contains("Pending Frees      : 0 "), "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_storage_within_policy_is_silent");
}

/// B154-WARN reject (C44): with one host gone, its frees stay pending; once pending and
/// retained bytes pass 1.25x the policy maximum the pass warns (`warn.folder_storage_ratio`).
#[test]
fn b154_stuck_frees_warn() {
    let t = churn_two_hosts(14, true);
    assert!(t.contains("warn.folder_storage_ratio"), "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_stuck_frees_warn");
}
