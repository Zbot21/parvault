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
    // Every field of the frozen layout decodes to what the current decoder reads.
    let cur = parvault::sync::FolderSnapshotManifest::decode_bytes(&raw).unwrap();
    assert_eq!(old.folder_merkle_root, cur.folder_merkle_root);
    assert_eq!(old.tier, cur.tier);
    assert_eq!(
        old.signed_dht_envelope.map(|e| e.monotonic_version),
        cur.signed_dht_envelope.map(|e| e.monotonic_version)
    );
    for (k, e) in &old.files {
        let c = &cur.files[k];
        assert_eq!(e.relative_path, c.relative_path);
        assert_eq!(e.size_bytes, c.size_bytes);
        assert_eq!(e.modified_unix_ms, c.modified_unix_ms);
        assert_eq!(e.plaintext_sha256, c.plaintext_sha256);
        assert_eq!(e.file_merkle_root, c.file_merkle_root);
        assert_eq!(e.manifest, c.manifest);
        assert_eq!(e.shard_pseudonyms, c.shard_pseudonyms);
    }
    for (k, t) in &old.deleted_tombstones {
        let c = &cur.deleted_tombstones[k];
        assert_eq!(t.relative_path, c.relative_path);
        assert_eq!(t.deleted_at_version, c.deleted_at_version);
        assert_eq!(t.previous_merkle_root, c.previous_merkle_root);
    }
    gate_ran("trust_enforcement_gc_owner::b154_v055_snapshot_upgrades_and_stays_readable");
}

/// The snapshot layout `v0.5.5` reads (`sync/engine.rs` at `1b1bad6`), frozen here.
mod v055 {
    use parvault::config::ErasureTier;
    use parvault::storage::{FileManifest, SignedDhtManifestEnvelope};
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
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
    pub struct DeletedFileTombstone {
        pub relative_path: String,
        pub deleted_at_version: u64,
        pub previous_merkle_root: [u8; 32],
    }

    #[derive(Deserialize)]
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
    let (child, addr) = start_host_daemon(tmp.path(), &dir, &log, common::LOOPBACK_EPHEMERAL);
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

/// Starts a storage daemon on `dir` listening on `listen`; returns it and its listen address.
fn start_host_daemon(
    tmp: &Path,
    dir: &Path,
    log: &Path,
    listen: &str,
) -> (std::process::Child, String) {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", tmp.join("lan-registry"))
        .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .arg("--data-dir")
        .arg(dir)
        .args(["--no-lan-discovery", "daemon", "start", "--listen", listen]);
    common::spawn_on_ephemeral_port(&mut cmd, log)
}

impl Host {
    /// The listen address without the `/p2p/` suffix (how the Docker gate names its peers).
    fn plain_addr(&self) -> &str {
        self.addr.split("/p2p/").next().unwrap()
    }

    /// Stops the daemon (as `docker stop` does).
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Starts the daemon again on the same data directory and port (as `docker start` does).
    fn restart(&mut self) {
        let listen = self.plain_addr().to_string();
        let log = self.log.with_extension("restart.log");
        let tmp = self.log.parent().unwrap().to_path_buf();
        let (child, addr) = start_host_daemon(&tmp, &self.dir, &log, &listen);
        assert_eq!(addr, listen, "the host came back on another port");
        self.child = child;
        self.log = log;
    }

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
    ring_pass_args(f, peers, &[], Duration::from_secs(240))
}

/// A ring pass with `extra` watch-folder flags, within `limit`.
fn ring_pass_args(f: &LocalFolder, peers: &str, extra: &[&str], limit: Duration) -> Output {
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
        ])
        .args(extra);
    output_within(&mut cmd, limit)
}

/// A ring pass with a raw `--key-hex` and no vault phrase, as the Docker gate's stage 13 runs
/// it: no catalog is published or fetched, so an unchanged pass dials a host only for GC.
fn ring_pass_key_hex(f: &LocalFolder, peers: &str) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", f.node.join("lan-registry"))
        .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
        .env("RUST_LOG", "info")
        .env_remove("PARVAULT_SEED_PHRASE")
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
            "--key-hex",
            KEY_HEX,
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
    // Freed through the host's FreeShards path (track B1), not the old DeleteShard.
    assert!(t.contains("0 DeleteShard fallback(s)"), "{t}");
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

/// C24 (over 1024 shards): 52 files of one stripe each (Homelab, 20 shards) on one host, kept
/// one version; when the next version drops them all, their 1,040 shards go in two orders
/// (1024 + 16), every one freed through the host's `FreeShards` path.
#[test]
fn b154_over_1024_shards_freed_in_two_orders() {
    let host = spawn_host();
    let f = LocalFolder::new();
    let keep_one = ["--keep-last", "1", "--keep-daily", "0"];
    let names: Vec<String> = (0..52).map(|i| format!("f{i:02}.txt")).collect();
    for n in &names {
        std::fs::write(f.folder.join(n), format!("v1 {n}")).unwrap();
    }
    let out = ring_pass_args(&f, &host.addr, &keep_one, Duration::from_secs(900));
    assert!(out.status.success(), "{}", text(&out));
    let v1: Vec<String> = names
        .iter()
        .flat_map(|n| shard_names_of(&f, 1, n))
        .collect();
    assert_eq!(v1.len(), 1040);
    for n in &names {
        std::fs::remove_file(f.folder.join(n)).unwrap();
    }
    f.write("the only file left");
    let out = ring_pass_args(&f, &host.addr, &keep_one, Duration::from_secs(900));
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("2 order(s), 0 DeleteShard fallback(s)"), "{t}");
    let held = host.shard_names();
    assert!(v1.iter().all(|n| !held.contains(n)), "{t}");
    assert!(t.contains("Pending Frees      : 0 "), "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_over_1024_shards_freed_in_two_orders");
}

// --- B163-RETRY (C35) ------------------------------------------------------------------------

/// 200 KiB of incompressible bytes tagged `tag` (one stripe: 20 shards of about 13 KiB).
fn big_body(tag: u8) -> Vec<u8> {
    let mut x = 0x9E37_79B9u32 ^ tag as u32;
    (0..204_800)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// B163-RETRY accept (C35): a host allows this owner about 3.6 versions of a 200 KiB file.
/// The fourth version is refused for quota; GC drops version 1 and frees it on the host, and the
/// pass is retried once and stored on the host.
#[test]
fn b163_full_owner_gcs_then_stores() {
    let host = spawn_host_with("bootstrap_grace_bytes = 921600\n");
    let f = LocalFolder::new();
    for tag in 1..=3u8 {
        std::fs::write(f.folder.join("a.bin"), big_body(tag)).unwrap();
        ring_pass_ok(&f, &host);
    }
    std::fs::write(f.folder.join("a.bin"), big_body(4)).unwrap();
    let t = ring_pass_ok(&f, &host);
    assert!(t.contains("retrying 1 file(s) once"), "{t}");
    assert!(!t.contains("warn.gc_quota_retry_spent"), "{t}");
    let retried = t.split("retrying 1 file(s) once").nth(1).unwrap();
    assert!(!retried.contains("NOT backed up"), "{t}");
    let newest = *f.versions().last().unwrap();
    let held = host.shard_names();
    assert!(
        shard_names_of(&f, newest, "a.bin")
            .iter()
            .all(|n| held.contains(n)),
        "the retried version is on the host\n{t}"
    );
    gate_ran("trust_enforcement_gc_owner::b163_full_owner_gcs_then_stores");
}

/// B163-RETRY reject (C35): a first pass over the owner's allowance has nothing to free; the
/// retry is spent (`warn.gc_quota_retry_spent`), nothing is retried, and the pass reports the
/// stripe not backed up (exit 3).
#[test]
fn b163_quota_retry_spent_without_frees() {
    let host = spawn_host_with("bootstrap_grace_bytes = 102400\n");
    let f = LocalFolder::new();
    std::fs::write(f.folder.join("a.bin"), big_body(1)).unwrap();
    let out = ring_pass(&f, &host);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(3), "{t}");
    assert!(t.contains("warn.gc_quota_retry_spent"), "{t}");
    assert!(!t.contains("retrying"), "{t}");
    assert!(
        std::fs::read_to_string(&host.log)
            .unwrap_or_default()
            .contains("peer_quota_exceeded"),
        "the host refused for quota"
    );
    gate_ran("trust_enforcement_gc_owner::b163_quota_retry_spent_without_frees");
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

// --- B154-CEIL (L-119 ceilings) and folder-status (C30) ----------------------------------------

/// B154-CEIL accept: the ceilings themselves (50 recent, 90 daily, 52 weekly) are accepted.
#[test]
fn b154_ceilings_accepted() {
    let f = LocalFolder::new();
    f.write("one");
    let out = pass_with(
        &f,
        &[
            "--keep-last",
            "50",
            "--keep-daily",
            "90",
            "--keep-weekly",
            "52",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("policy: last 50, daily 90, weekly 52"),
        "{}",
        text(&out)
    );
    gate_ran("trust_enforcement_gc_owner::b154_ceilings_accepted");
}

/// B154-CEIL reject (L-119): one over any ceiling is refused, never clamped
/// (`reject.retention_above_ceiling`); no pass runs.
#[test]
fn b154_above_ceiling_refused() {
    for flags in [
        ["--keep-last", "51"],
        ["--keep-daily", "91"],
        ["--keep-weekly", "53"],
    ] {
        let f = LocalFolder::new();
        f.write("one");
        let out = pass_with(&f, &flags);
        let t = text(&out);
        assert!(!out.status.success(), "{t}");
        assert!(t.contains("reject.retention_above_ceiling"), "{t}");
        assert!(f.versions().is_empty());
    }
    gate_ran("trust_enforcement_gc_owner::b154_above_ceiling_refused");
}

/// `--keep-last 1 --keep-daily 0` keeps only the newest version.
#[test]
fn b154_keep_last_one_keeps_newest_only() {
    let f = LocalFolder::new();
    for body in ["a", "b", "c"] {
        f.write(body);
        let out = pass_with(&f, &["--keep-last", "1", "--keep-daily", "0"]);
        assert!(out.status.success(), "{}", text(&out));
    }
    assert_eq!(f.versions(), vec![3]);
    gate_ran("trust_enforcement_gc_owner::b154_keep_last_one_keeps_newest_only");
}

/// C30: `folder-status` shows the retained versions, the policy, frees and the version
/// store's bytes on this disk.
#[test]
fn b154_folder_status_shows_versions_and_store() {
    let f = LocalFolder::new();
    for body in ["a", "b"] {
        f.write(body);
        pass(&f);
    }
    let out = run_parvault(
        &f.node,
        &["folder-status", "--snapshot", f.snap.to_str().unwrap()],
    );
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("Versions Retained  : 2 (1, 2)"), "{t}");
    assert!(
        t.contains("Policy             : last 3, daily 3, weekly 0"),
        "{t}"
    );
    assert!(t.contains("Version Store      : "), "{t}");
    assert!(t.contains("Folder Size        : 1 bytes"), "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_folder_status_shows_versions_and_store");
}

/// `folder-status` of a folder never backed up with GC fails and says why.
#[test]
fn b154_folder_status_without_store_fails() {
    let f = LocalFolder::new();
    let out = run_parvault(
        &f.node,
        &["folder-status", "--snapshot", f.snap.to_str().unwrap()],
    );
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("no version store"), "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_folder_status_without_store_fails");
}

/// `up --no-gc` starts and runs its folder passes without a version store (with G-17 applied).
#[test]
fn b154_up_no_gc_runs_without_versions() {
    let tmp = tempfile::tempdir().unwrap();
    let node = tmp.path().join("node");
    let folder = tmp.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), "up").unwrap();
    let log = tmp.path().join("up.log");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", node.join("lan-registry"))
        .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
        .env_remove("PARVAULT_PEERS")
        .arg("--data-dir")
        .arg(&node)
        .args([
            "--no-lan-discovery",
            "up",
            "--no-socket",
            "--no-gc",
            "--listen",
        ])
        .arg(common::LOOPBACK_EPHEMERAL)
        .arg("--folder")
        .arg(&folder);
    let (mut child, _addr) = common::spawn_on_ephemeral_port(&mut cmd, &log);
    let snap = node.join("appliance_folder_snapshot.manifest.bin");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !snap.exists() {
        assert!(std::time::Instant::now() < deadline, "no pass in 30 s");
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_secs(2));
    let _ = child.kill();
    let _ = child.wait();
    assert!(!VersionStore::for_snapshot(&snap).dir().exists());
    gate_ran("trust_enforcement_gc_owner::b154_up_no_gc_runs_without_versions");
}

// --- B154 T4 (C5): an offline host's garbage is freed within 3 passes of its return ----------

/// B154-OFFLINE accept (C5, Docker gate stage 13 T4): with one of three hosts stopped, 4 changed
/// passes leave its garbage journalled; once it is back on the same address, the journal is
/// empty within 3 passes, unchanged passes included.
#[test]
fn b154_offline_host_freed_within_three_passes_of_return() {
    let h1 = spawn_host();
    let h2 = spawn_host();
    let mut h3 = spawn_host();
    let peers = format!(
        "{},{},{}",
        h1.plain_addr(),
        h2.plain_addr(),
        h3.plain_addr()
    );
    let f = LocalFolder::new();
    let mut body = String::new();
    let changed_pass = |body: &mut String, n: usize| {
        body.push_str(&format!("line {n} {}\n", "x".repeat(4096)));
        f.write(body);
        let out = ring_pass_key_hex(&f, &peers);
        let t = text(&out);
        assert!(out.status.success(), "pass {n}: {t}");
        t
    };
    for n in 0..5 {
        changed_pass(&mut body, n);
    }
    h3.stop();
    let mut t = String::new();
    for n in 5..9 {
        t = changed_pass(&mut body, n);
    }
    assert!(
        !t.contains("Pending Frees      : 0 "),
        "no frees journalled: {t}"
    );
    h3.restart();
    std::thread::sleep(Duration::from_secs(3));
    let mut outs = Vec::new();
    let mut cleared = false;
    for _ in 0..3 {
        let out = ring_pass_key_hex(&f, &peers);
        let t = text(&out);
        assert!(out.status.success(), "{t}");
        cleared = t.contains("Pending Frees      : 0 ");
        outs.push(t);
        if cleared {
            break;
        }
    }
    assert!(
        cleared,
        "journal not empty within 3 passes of the host's return:\n{}\n--- host 3 log ---\n{}",
        outs.join("\n---\n"),
        std::fs::read_to_string(&h3.log).unwrap_or_default()
    );
    gate_ran("trust_enforcement_gc_owner::b154_offline_host_freed_within_three_passes_of_return");
}

/// B154-OFFLINE reject half (T4 root cause): a free journalled for an address of a host the
/// owner cannot dial (here: a dead loopback port under host 1's peer id, as a host's advertised
/// loopback listen address is from another container) is sent to the address the owner was given
/// for that peer id, and the journal empties; before the fix it was retried as unreachable for 30
/// days.
#[test]
fn b154_free_for_unreachable_alias_goes_to_given_host() {
    let h1 = spawn_host();
    let h2 = spawn_host();
    let peers = format!("{},{}", h1.plain_addr(), h2.plain_addr());
    let f = LocalFolder::new();
    f.write("one");
    let out = ring_pass_key_hex(&f, &peers);
    assert!(out.status.success(), "{}", text(&out));
    let dead_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let pid = h1.addr.split("/p2p/").nth(1).unwrap();
    let alias = format!("/ip4/127.0.0.1/tcp/{dead_port}/p2p/{pid}");
    let paths = parvault::sync::gc_journal::GcPaths::for_snapshot(&f.snap);
    let mut j = parvault::sync::gc_journal::GcJournal::load(&paths).unwrap();
    j.pending.push(parvault::sync::gc_journal::PendingFree {
        shard_id: parvault::storage::ShardId {
            stripe_merkle_root: [0x5a; 32],
            shard_index: 3,
            shard_hash: [0xa5; 32],
        },
        shard_len: 4096,
        host: alias.clone(),
        attempts: 0,
        first_attempt_ms: now_ms(),
        next_pass: 0,
        skew_refusals: 0,
    });
    j.save(&paths).unwrap();
    let mut outs = Vec::new();
    let mut cleared = false;
    for _ in 0..3 {
        let out = ring_pass_key_hex(&f, &peers);
        let t = text(&out);
        assert!(out.status.success(), "{t}");
        cleared = t.contains("Pending Frees      : 0 ");
        outs.push(t);
        if cleared {
            break;
        }
    }
    assert!(
        cleared,
        "the alias free stayed pending ({alias}):\n{}",
        outs.join("\n---\n")
    );
    gate_ran("trust_enforcement_gc_owner::b154_free_for_unreachable_alias_goes_to_given_host");
}

/// A shard id no host holds, distinct per `n`.
fn absent_shard(n: u8) -> parvault::storage::ShardId {
    parvault::storage::ShardId {
        stripe_merkle_root: [n; 32],
        shard_index: n as u32,
        shard_hash: [n ^ 0xff; 32],
    }
}

/// Appends pending frees `(shard, host)` to `f`'s GC journal, as an older owner would have
/// written them.
fn seed_pending(f: &LocalFolder, entries: &[(parvault::storage::ShardId, String)]) {
    let paths = parvault::sync::gc_journal::GcPaths::for_snapshot(&f.snap);
    let mut j = parvault::sync::gc_journal::GcJournal::load(&paths).unwrap();
    for (id, host) in entries {
        j.pending.push(parvault::sync::gc_journal::PendingFree {
            shard_id: *id,
            shard_len: 4096,
            host: host.clone(),
            attempts: 0,
            first_attempt_ms: now_ms(),
            next_pass: 0,
            skew_refusals: 0,
        });
    }
    j.save(&paths).unwrap();
}

/// A loopback address nothing listens on, under `host`'s peer id.
fn dead_alias_of(host: &Host) -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    format!(
        "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
        host.addr.split("/p2p/").nth(1).unwrap()
    )
}

/// The `FreeShards` orders a host applied, as `shards=` counts from its log.
fn applied_orders(host: &Host) -> Vec<String> {
    std::fs::read_to_string(&host.log)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("info.free_order_applied"))
        .filter_map(|l| l.split("shards=").nth(1))
        .map(|t| t.split_whitespace().next().unwrap_or("").to_string())
        .collect()
}

/// B154-OFFLINE migration: a journal from the old code holds one shard under both a host's
/// dead alias and its given address, and a second shard under the alias only. They merge under
/// the given address: one order of 2 shards, no double free, and the journal empties.
#[test]
fn b154_alias_journal_migrates_without_double_free() {
    let h1 = spawn_host();
    let h2 = spawn_host();
    let peers = format!("{},{}", h1.plain_addr(), h2.plain_addr());
    let f = LocalFolder::new();
    f.write("one");
    let out = ring_pass_key_hex(&f, &peers);
    assert!(out.status.success(), "{}", text(&out));
    let before = applied_orders(&h1).len();
    let alias = dead_alias_of(&h1);
    seed_pending(
        &f,
        &[
            (absent_shard(1), alias.clone()),
            (absent_shard(1), h1.plain_addr().to_string()),
            (absent_shard(2), alias),
        ],
    );
    let out = ring_pass_key_hex(&f, &peers);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("Pending Frees      : 0 "), "{t}");
    assert_eq!(applied_orders(&h1)[before..], ["2".to_string()], "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_alias_journal_migrates_without_double_free");
}

/// B154-OFFLINE discovery-only host: a host the owner was not given (no `--peers` or seed entry
/// for its peer id), journalled under a dead alias and under a reachable address of the same
/// peer id. The dead alias does not make the host unreachable: one order reaches it through the
/// address that answers, and the journal empties.
#[test]
fn b154_discovery_only_host_reached_past_dead_alias() {
    let h1 = spawn_host();
    let h2 = spawn_host();
    let peers = h2.plain_addr().to_string();
    let f = LocalFolder::new();
    f.write("one");
    let out = ring_pass_key_hex(&f, &peers);
    assert!(out.status.success(), "{}", text(&out));
    let alias = dead_alias_of(&h1);
    seed_pending(
        &f,
        &[
            (absent_shard(1), alias.clone()),
            (absent_shard(2), alias),
            (absent_shard(2), h1.addr.clone()),
        ],
    );
    let out = ring_pass_key_hex(&f, &peers);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("Pending Frees      : 0 "), "{t}");
    assert_eq!(applied_orders(&h1), ["2".to_string()], "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_discovery_only_host_reached_past_dead_alias");
}

/// B154-OFFLINE safety: an alias under host 1's peer id whose address is host 2's. The dial
/// expects host 1's id, Noise authenticates host 2: a mismatch, so no order reaches host 2, the
/// order (signed for host 1's key) is never sent, and the entry stays pending.
#[test]
fn b154_alias_answered_by_another_node_frees_nothing_there() {
    let h1 = spawn_host();
    let h2 = spawn_host();
    let peers = h2.plain_addr().to_string();
    let f = LocalFolder::new();
    f.write("one");
    let out = ring_pass_key_hex(&f, &peers);
    assert!(out.status.success(), "{}", text(&out));
    let h1_pid = h1.addr.split("/p2p/").nth(1).unwrap();
    let wrong = format!("{}/p2p/{h1_pid}", h2.plain_addr());
    let h2_before = applied_orders(&h2).len();
    seed_pending(&f, &[(absent_shard(1), wrong)]);
    for _ in 0..2 {
        let out = ring_pass_key_hex(&f, &peers);
        let t = text(&out);
        assert!(out.status.success(), "{t}");
        assert!(t.contains("Pending Frees      : 1 "), "{t}");
    }
    let h2_log = std::fs::read_to_string(&h2.log).unwrap_or_default();
    assert_eq!(applied_orders(&h2).len(), h2_before, "{h2_log}");
    assert!(!h2_log.contains("refused a free order"), "{h2_log}");
    assert!(applied_orders(&h1).is_empty());
    gate_ran("trust_enforcement_gc_owner::b154_alias_answered_by_another_node_frees_nothing_there");
}

// --- B-192: a host's advertised aliases (one entry per peer id) -------------------------------

/// B-192 (3): data written before B-192 may name a shard's host by an alias the owner cannot
/// reach. Every placement record naming host 1 is rewritten to a dead loopback alias under its
/// peer id, the owner's local shards are removed and host 2 is stopped; a cold process restores
/// the file byte-identically from host 1 alone (the alias is skipped for its known address).
/// D7 (`v0.5.6` final QA): `restore-folder --snapshot` reads the manifests embedded in the
/// snapshot file, so those are rewritten too, and the decoded snapshot is checked to name host 1
/// only by the dead alias before the restore.
#[test]
fn b192_shards_recorded_under_alias_restore_cold() {
    let h1 = spawn_host();
    let mut h2 = spawn_host();
    let peers = format!("{},{}", h1.plain_addr(), h2.plain_addr());
    let f = LocalFolder::new();
    let body = big_body(7);
    std::fs::write(f.folder.join("a.bin"), &body).unwrap();
    let out = ring_pass_key_hex(&f, &peers);
    assert!(out.status.success(), "{}", text(&out));
    let mk = parvault::crypto::MasterKey::from_hex(KEY_HEX).unwrap();
    let h1_pid = h1.addr.split("/p2p/").nth(1).unwrap().to_string();
    let alias = dead_alias_of(&h1);
    let mut rewritten = 0usize;
    for e in std::fs::read_dir(f.node.join("manifests")).unwrap() {
        let path = e.unwrap().path();
        let raw = std::fs::read(&path).unwrap();
        let Ok(mut fm) = parvault::storage::FileManifest::from_encrypted_dht_record(&mk, &raw)
        else {
            continue;
        };
        for st in &mut fm.stripes {
            for a in &mut st.assigned_peers {
                if a.as_str() == h1.plain_addr() || a.contains(&h1_pid) {
                    *a = alias.clone();
                    rewritten += 1;
                }
            }
        }
        let (_, enc) = fm.to_encrypted_dht_record(&mk).unwrap();
        std::fs::write(&path, enc).unwrap();
    }
    assert!(rewritten > 0, "no placement record named host 1");
    // D7: the snapshot the restore reads embeds its own manifests.
    let names_h1 = |a: &str| a == h1.plain_addr() || a.contains(&h1_pid);
    let raw = std::fs::read(&f.snap).unwrap();
    let mut snap = parvault::sync::FolderSnapshotManifest::decode_bytes(&raw).unwrap();
    for fe in snap.files.values_mut() {
        for st in &mut fe.manifest.stripes {
            for a in &mut st.assigned_peers {
                if names_h1(a) {
                    *a = alias.clone();
                }
            }
        }
    }
    std::fs::write(&f.snap, bincode::serialize(&snap).unwrap()).unwrap();
    let snap =
        parvault::sync::FolderSnapshotManifest::decode_bytes(&std::fs::read(&f.snap).unwrap())
            .unwrap();
    let recorded: Vec<&String> = snap
        .files
        .values()
        .flat_map(|fe| fe.manifest.stripes.iter())
        .flat_map(|st| st.assigned_peers.iter())
        .collect();
    assert!(
        recorded.iter().any(|a| **a == alias),
        "the snapshot does not name the alias: {recorded:?}"
    );
    assert!(
        recorded.iter().all(|a| **a == alias || !names_h1(a)),
        "the snapshot still names host 1 by a live address: {recorded:?}"
    );
    let _ = std::fs::remove_dir_all(f.node.join("shards"));
    // Host 1, recorded only under the dead alias, is the only source left.
    h2.stop();
    let out_dir = f.node.parent().unwrap().join("restored");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", f.node.join("lan-registry"))
        .env("PARVAULT_GENESIS_SEED_HEX", GENESIS_SEED_HEX)
        .env_remove("PARVAULT_SEED_PHRASE")
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .arg("--data-dir")
        .arg(&f.node)
        .args(["--no-lan-discovery", "--peers", &peers])
        .args([
            "restore-folder",
            "--snapshot",
            f.snap.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
            "--key-hex",
            KEY_HEX,
        ]);
    let out = output_within(&mut cmd, Duration::from_secs(240));
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        std::fs::read(out_dir.join("a.bin")).unwrap(),
        body,
        "{}",
        text(&out)
    );
    gate_ran("trust_enforcement_gc_owner::b192_shards_recorded_under_alias_restore_cold");
}

// --- v0.5.6 final QA D8, D9, D11: the client's view of hosts -----------------------------------

/// A TCP listener that accepts connections and never answers (a peer that hangs every dial);
/// returns its address and the count of connections it accepted.
fn blackhole() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("/ip4/127.0.0.1/tcp/{}", l.local_addr().unwrap().port());
    let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = std::sync::Arc::clone(&n);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in l.incoming().flatten() {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            held.push(s);
        }
    });
    (addr, n)
}

/// A loopback port nothing listens on.
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// D8: a given peer that hangs every dial (powered off behind a route that drops packets) is
/// probed for its peer id at most once, however many requests to a dead `/p2p/` alias fail, so
/// N failures cost one dial timeout, not N.
#[test]
fn d8_down_given_peer_probed_once() {
    use parvault::network::MeshWireRequest;
    let (hole, accepted) = blackhole();
    let x = parvault::network::node_identity_libp2p_peer_id(
        &parvault::crypto::NodeIdentity::from_seed([0xD8; 32]),
    )
    .unwrap();
    let alias = format!("/ip4/127.0.0.1/tcp/{}/p2p/{x}", closed_port());
    let timeout = Duration::from_secs(2);
    let client = parvault::network::MeshClient::new(
        parvault::crypto::NodeIdentity::from_seed([0xD7; 32]),
        vec![hole],
        None,
    )
    .with_timeout(timeout);
    let n = 6u32;
    let t0 = std::time::Instant::now();
    for _ in 0..n {
        assert!(client
            .send_request(&alias, MeshWireRequest::QueryNodeStatus)
            .is_err());
    }
    let elapsed = t0.elapsed();
    let dials = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert!(dials <= 1, "the down given peer was dialed {dials} times");
    assert!(
        elapsed < timeout * 3,
        "{n} failing requests took {elapsed:?} (one probe is {timeout:?})"
    );
    gate_ran("trust_enforcement_gc_owner::d8_down_given_peer_probed_once");
}

/// D9: in a cold process (no pins), a plain `--peers` address and a discovered `/p2p/X` of the
/// same host are one candidate: the endpoint list and the hosts placement journals and places
/// on name the host once.
#[test]
fn d9_cold_placement_one_candidate_per_peer_id() {
    let h1 = spawn_host();
    let disc = tempfile::tempdir().unwrap();
    let pid = h1.addr.split("/p2p/").nth(1).unwrap().to_string();
    parvault::network::KnownPeersStore::update(disc.path(), |s| {
        s.upsert_pinned_multiaddr(&pid, &h1.addr, Some("h1"), Some("node"));
    })
    .unwrap();
    let owner = parvault::crypto::NodeIdentity::from_seed([0xD9; 32]);
    let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let seen_hook = std::sync::Arc::clone(&seen);
    let client =
        parvault::network::MeshClient::new(owner.clone(), vec![h1.plain_addr().to_string()], None)
            .with_lan_discovery(false)
            .with_data_dir_discovery(disc.path().to_path_buf(), closed_port())
            .with_pre_place_hook(parvault::network::client::PrePlaceHook(
                std::sync::Arc::new(move |_ids, hosts| {
                    *seen_hook.lock().unwrap() = hosts.to_vec();
                    Err(std::io::Error::other("stop before any put"))
                }),
            ));
    assert!(client.discovered_peers().contains(&h1.addr));
    assert_eq!(
        client.all_network_endpoints(),
        vec![h1.plain_addr().to_string()]
    );
    let set = parvault::sharding::reed_solomon::encode_ciphertext_stripe(
        0,
        &[0x5A; 4096],
        parvault::config::ErasureTier::Consumer,
    )
    .unwrap();
    let r = client.distribute_stripe_shards_partial(
        &owner,
        "",
        &set,
        parvault::config::ErasureTier::Consumer,
        [0; 32],
    );
    assert!(r.is_err(), "the hook stops placement");
    assert_eq!(*seen.lock().unwrap(), vec![h1.plain_addr().to_string()]);
    assert!(h1.shard_names().is_empty());
    gate_ran("trust_enforcement_gc_owner::d9_cold_placement_one_candidate_per_peer_id");
}

/// A wire peer that refuses every vault request with the handler's own "not admitted" reply
/// (`reject_response`), as a node of another ring, or one whose manifest does not serve the
/// variant, answers. Returns its `/p2p/` address and the requests it saw.
fn spawn_refusing_peer() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use libp2p::futures::StreamExt;
    use libp2p::request_response::{self, ProtocolSupport};
    use libp2p::swarm::SwarmEvent;
    use parvault::network::behaviour::BincodeWireCodec;
    use parvault::network::wire_handler::{reject_response, NOT_ADMITTED_TEXT};
    use parvault::network::{MeshWireRequest, MeshWireResponse};
    let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let log = std::sync::Arc::clone(&seen);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let ident = parvault::crypto::NodeIdentity::from_seed([0xDB; 32]);
            let mut swarm =
                libp2p::SwarmBuilder::with_existing_identity(ident.to_libp2p_keypair().unwrap())
                    .with_tokio()
                    .with_tcp(
                        libp2p::tcp::Config::default(),
                        libp2p::noise::Config::new,
                        libp2p::yamux::Config::default,
                    )
                    .unwrap()
                    .with_behaviour(|_| {
                        request_response::Behaviour::with_codec(
                            BincodeWireCodec::default(),
                            [(
                                libp2p::StreamProtocol::new("/parvault/wire/1.0.0"),
                                ProtocolSupport::Full,
                            )],
                            request_response::Config::default(),
                        )
                    })
                    .unwrap()
                    .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
                    .build();
            swarm
                .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            let pid = *swarm.local_peer_id();
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let _ = tx.send(format!("{address}/p2p/{pid}"));
                    }
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    }) => {
                        let name = format!("{request:?}");
                        log.lock()
                            .unwrap()
                            .push(name.split([' ', '(', '{']).next().unwrap_or("").to_string());
                        let resp = match request {
                            // Accept the handshake so every refusal is the vault request's own.
                            MeshWireRequest::HandshakeWoT { .. } => {
                                MeshWireResponse::HandshakeAck {
                                    accepted: true,
                                    reason: None,
                                }
                            }
                            other => reject_response(&other, NOT_ADMITTED_TEXT.to_string()),
                        };
                        let _ = swarm.behaviour_mut().send_response(channel, resp);
                    }
                    _ => {}
                }
            }
        });
    });
    let addr = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("refusing peer listening");
    (addr, seen)
}

/// D11: a fresh owner (vault phrase, no local snapshot) whose every ring peer refuses the
/// catalog query does not read the refusals as "the ring holds no catalog": the pass is refused
/// `reject.catalog_resume_unreachable`, no version 1 is written and no catalog is published.
#[test]
fn d11_refusing_ring_rejects_resume() {
    let (peer, seen) = spawn_refusing_peer();
    let f = LocalFolder::new();
    f.write("one");
    let out = ring_pass_args(&f, &peer, &[], Duration::from_secs(120));
    let t = text(&out);
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests.iter().any(|r| r == "GetDhtEnvelope"),
        "the catalog was never asked for: {requests:?}\n{t}"
    );
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("reject.catalog_resume_unreachable"), "{t}");
    assert!(!f.snap.exists(), "a snapshot was written:\n{t}");
    assert!(f.versions().is_empty(), "a version was kept:\n{t}");
    assert!(
        !requests
            .iter()
            .any(|r| r == "PutDhtEnvelope" || r == "PutShard"),
        "{requests:?}"
    );
    gate_ran("trust_enforcement_gc_owner::d11_refusing_ring_rejects_resume");
}

/// Sends `sig` (`STOP` or `CONT`) to a host daemon.
fn signal_host(host: &Host, sig: &str) {
    let st = std::process::Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(host.child.id().to_string())
        .status()
        .unwrap();
    assert!(st.success(), "kill -{sig}");
}

/// D12 (qa056): of three hosts, the one first in send order is stopped (SIGSTOP: it holds
/// every connection without answering). In the same pass the other two still apply their
/// orders (stamped when sent, not at the pass start, so none arrives stale), and only the
/// stopped host's free stays journalled.
#[test]
fn b154_stalled_host_does_not_starve_the_others() {
    let mut hosts = [spawn_host(), spawn_host(), spawn_host()];
    hosts.sort_by(|a, b| a.addr.cmp(&b.addr));
    let peers = hosts
        .iter()
        .map(|h| h.addr.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let f = LocalFolder::new();
    f.write("one");
    let out = ring_pass_key_hex(&f, &peers);
    assert!(out.status.success(), "{}", text(&out));
    let before: Vec<usize> = hosts.iter().map(|h| applied_orders(h).len()).collect();
    let seeded: Vec<_> = hosts
        .iter()
        .enumerate()
        .map(|(i, h)| (absent_shard(0x40 + i as u8), h.addr.clone()))
        .collect();
    seed_pending(&f, &seeded);
    signal_host(&hosts[0], "STOP");
    let out = ring_pass_key_hex(&f, &peers);
    signal_host(&hosts[0], "CONT");
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    for (h, n) in hosts.iter().zip(&before).skip(1) {
        assert!(
            applied_orders(h).len() > *n,
            "host {} got no order this pass:\n{t}\n--- host log ---\n{}",
            h.addr,
            std::fs::read_to_string(&h.log).unwrap_or_default()
        );
    }
    assert!(!t.contains("free_stale"), "{t}");
    assert!(t.contains("Pending Frees      : 1 "), "{t}");
    gate_ran("trust_enforcement_gc_owner::b154_stalled_host_does_not_starve_the_others");
}

/// An in-process GC run of one owner: its block store, journal and settings in a scratch dir,
/// frees through `client`.
struct OwnerRun {
    _tmp: tempfile::TempDir,
    store: parvault::storage::BlockStore,
    owner: parvault::crypto::NodeIdentity,
    settings: parvault::sync::gc_journal::GcSettings,
}

impl OwnerRun {
    fn new(seed: u8, client: parvault::network::MeshClient) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let store = parvault::storage::BlockStore::new(
            tmp.path().join("store"),
            parvault::storage::QuotaManager::new(1 << 30, 1 << 20),
        )
        .unwrap();
        let settings = parvault::sync::gc_journal::GcSettings {
            snapshot_out: tmp.path().join("s.manifest.bin"),
            policy: Default::default(),
            data_dir: tmp.path().to_path_buf(),
            client: Some(client),
            fetched_catalog: None,
        };
        Self {
            _tmp: tmp,
            store,
            owner: parvault::crypto::NodeIdentity::from_seed([seed; 32]),
            settings,
        }
    }

    fn paths(&self) -> parvault::sync::gc_journal::GcPaths {
        parvault::sync::gc_journal::GcPaths::for_snapshot(&self.settings.snapshot_out)
    }

    /// Journals `ids` as due frees on `host`.
    fn seed(&self, ids: &[parvault::storage::ShardId], host: &str) {
        let mut j = parvault::sync::gc_journal::GcJournal::load(&self.paths()).unwrap();
        for id in ids {
            j.pending.push(parvault::sync::gc_journal::PendingFree {
                shard_id: *id,
                shard_len: 4096,
                host: host.to_string(),
                attempts: 0,
                first_attempt_ms: now_ms(),
                next_pass: 0,
                skew_refusals: 0,
            });
        }
        j.save(&self.paths()).unwrap();
    }

    fn pending(&self) -> Vec<parvault::storage::ShardId> {
        parvault::sync::gc_journal::GcJournal::load(&self.paths())
            .unwrap()
            .pending
            .iter()
            .map(|p| p.shard_id)
            .collect()
    }
}

/// D12 (qa056 re-verification): steps 1 to 5 of a run took 31 s (about 4,000 local frees),
/// longer than a host's 30 s skew. The run's clock pair is read at its start, before that
/// work; the orders of step 6 are stamped with the wall time at their send, so the host
/// applies them (`info.free_order_applied`) and none is refused `reject.free_stale`.
#[test]
fn d12_orders_after_a_slow_step5_are_fresh() {
    let host = spawn_host();
    let client = parvault::network::MeshClient::new(
        parvault::crypto::NodeIdentity::from_seed([0xE1; 32]),
        Vec::new(),
        None,
    )
    .with_lan_discovery(false)
    .with_admission(parvault::network::admission::AdmissionSource::from_genesis(
        parvault::crypto::NodeIdentity::from_seed([0x47; 32]),
    ));
    let r = OwnerRun::new(0xE1, client);
    r.seed(&[absent_shard(0x61), absent_shard(0x62)], &host.addr);
    let slow = Duration::from_secs(31);
    let started = std::time::Instant::now()
        .checked_sub(slow)
        .expect("uptime over 31 s");
    let mut run = parvault::sync::gc_journal::GcRun::new_started(
        &r.settings,
        &r.store,
        &r.owner,
        now_ms() - slow.as_millis() as u64,
        started,
    )
    .unwrap();
    run.step6_send_orders().unwrap();
    let report = run.finish();
    assert_eq!(report.clock_skew_refusals, 0, "{report:?}");
    assert_eq!(report.orders_sent, 1, "{report:?}");
    assert_eq!(report.shards_not_held, 2, "{report:?}");
    assert!(r.pending().is_empty(), "{:?}", r.pending());
    assert_eq!(applied_orders(&host), vec!["2".to_string()]);
    let log = std::fs::read_to_string(&host.log).unwrap_or_default();
    assert!(!log.contains("free_stale"), "{log}");
    gate_ran("trust_enforcement_gc_owner::d12_orders_after_a_slow_step5_are_fresh");
}

/// The shard ids of each `FreeShards` order a peer saw.
type SeenOrders = std::sync::Arc<std::sync::Mutex<Vec<Vec<parvault::storage::ShardId>>>>;

/// A wire peer that accepts every connection and status request but never answers its first
/// `FreeShards` order nor any `DeleteShard` (it holds each response open past the owner's
/// timeout); later `FreeShards` orders are answered `NotHeld` for every shard. Returns its
/// `/p2p/` address and the shard ids of each `FreeShards` order it saw.
fn spawn_stalling_free_peer() -> (String, SeenOrders) {
    use libp2p::futures::StreamExt;
    use libp2p::request_response::{self, ProtocolSupport};
    use libp2p::swarm::SwarmEvent;
    use parvault::network::behaviour::{BincodeWireCodec, FreeShardOutcome};
    use parvault::network::wire_handler::{reject_response, NOT_ADMITTED_TEXT};
    use parvault::network::{MeshWireRequest, MeshWireResponse};
    let seen: SeenOrders = Default::default();
    let log = std::sync::Arc::clone(&seen);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let ident = parvault::crypto::NodeIdentity::from_seed([0xD5; 32]);
            let mut swarm =
                libp2p::SwarmBuilder::with_existing_identity(ident.to_libp2p_keypair().unwrap())
                    .with_tokio()
                    .with_tcp(
                        libp2p::tcp::Config::default(),
                        libp2p::noise::Config::new,
                        libp2p::yamux::Config::default,
                    )
                    .unwrap()
                    .with_behaviour(|_| {
                        request_response::Behaviour::with_codec(
                            BincodeWireCodec::default(),
                            [(
                                libp2p::StreamProtocol::new("/parvault/wire/1.0.0"),
                                ProtocolSupport::Full,
                            )],
                            // Held responses outlive the owner's 30 s order timeout.
                            request_response::Config::default()
                                .with_request_timeout(Duration::from_secs(600)),
                        )
                    })
                    .unwrap()
                    .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(600)))
                    .build();
            swarm
                .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            let pid = *swarm.local_peer_id();
            let mut held = Vec::new();
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let _ = tx.send(format!("{address}/p2p/{pid}"));
                    }
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    }) => {
                        let resp = match request {
                            MeshWireRequest::HandshakeWoT { .. } => {
                                MeshWireResponse::HandshakeAck {
                                    accepted: true,
                                    reason: None,
                                }
                            }
                            MeshWireRequest::FreeShards { order } => {
                                let first = {
                                    let mut l = log.lock().unwrap();
                                    l.push(order.shard_ids.clone());
                                    l.len() == 1
                                };
                                if first {
                                    held.push(channel);
                                    continue;
                                }
                                MeshWireResponse::FreeShardsAck {
                                    outcomes: vec![
                                        FreeShardOutcome::NotHeld;
                                        order.shard_ids.len()
                                    ],
                                    error: None,
                                }
                            }
                            MeshWireRequest::DeleteShard { .. } => {
                                held.push(channel);
                                continue;
                            }
                            other => reject_response(&other, NOT_ADMITTED_TEXT.to_string()),
                        };
                        let _ = swarm.behaviour_mut().send_response(channel, resp);
                    }
                    _ => {}
                }
            }
        });
    });
    let addr = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("stalling peer listening");
    (addr, seen)
}

/// D12 (qa056 re-verification): a host that accepts the `FreeShards` order and never answers
/// (nor the per-shard `DeleteShard` fallback) costs the pass at most its host budget plus the
/// order in flight; the shards not tried are deferred, stay journalled, and the next pass sends
/// them (that host answers this time), which empties them from the journal.
#[test]
fn d12_stall_inside_free_shards_is_bounded_and_carried() {
    use parvault::sync::gc_journal::{GcRun, FREE_HOST_BUDGET_MS, FREE_ORDER_TIMEOUT};
    let (peer, seen) = spawn_stalling_free_peer();
    let client = parvault::network::MeshClient::new(
        parvault::crypto::NodeIdentity::from_seed([0xE2; 32]),
        Vec::new(),
        None,
    )
    .with_lan_discovery(false);
    let r = OwnerRun::new(0xE2, client);
    let ids = [absent_shard(0x71), absent_shard(0x72), absent_shard(0x73)];
    r.seed(&ids, &peer);

    let t0 = std::time::Instant::now();
    let mut run = GcRun::new(&r.settings, &r.store, &r.owner, now_ms()).unwrap();
    run.step6_send_orders().unwrap();
    let report = run.finish();
    let spent = t0.elapsed();
    let bound = Duration::from_millis(FREE_HOST_BUDGET_MS) + FREE_ORDER_TIMEOUT;
    assert!(
        spent >= FREE_ORDER_TIMEOUT,
        "the order did not stall: {spent:?}"
    );
    assert!(spent < bound, "the stall cost {spent:?}, over {bound:?}");
    assert_eq!(report.frees_deferred, 2, "{report:?}");
    assert_eq!(
        report.shards_freed + report.shards_not_held,
        0,
        "{report:?}"
    );
    assert_eq!(r.pending().len(), 3, "every shard stays journalled");
    assert_eq!(seen.lock().unwrap().len(), 1);

    // The next pass: the deferred shards are due and sent; the host answers and they leave the
    // journal.
    let mut run = GcRun::new(&r.settings, &r.store, &r.owner, now_ms()).unwrap();
    run.step6_send_orders().unwrap();
    let report = run.finish();
    let orders = seen.lock().unwrap().clone();
    assert_eq!(orders.len(), 2, "{orders:?}");
    for id in &ids[1..] {
        assert!(
            orders[1].contains(id),
            "deferred {id:?} not sent: {orders:?}"
        );
    }
    assert!(report.shards_not_held >= 2, "{report:?}");
    let left = r.pending();
    assert!(
        ids[1..].iter().all(|id| !left.contains(id)),
        "deferred shards still journalled: {left:?}"
    );
    gate_ran("trust_enforcement_gc_owner::d12_stall_inside_free_shards_is_bounded_and_carried");
}
