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
