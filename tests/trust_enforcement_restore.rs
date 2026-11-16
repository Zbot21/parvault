//! `v0.5.6` track C suite: the restore path and the fetch scheduler (plan Sections 3.3 to 3.5).
//! Claims of track C put their differential pairs here;
//! `tests/trust_enforcement.rs` is frozen.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

#[cfg(unix)]
use parvault::fetch_sched::{self, FetchClass, SLOTS};
#[cfg(unix)]
use parvault::gateway::ipc::GatewayBus;
#[cfg(unix)]
use parvault::gateway::GatewayEngine;
#[cfg(unix)]
use parvault::vfs::{LazyFileSpec, VirtualVaultFs};
use std::path::Path;
#[cfg(unix)]
use std::sync::atomic::AtomicBool;
#[cfg(unix)]
use std::sync::{Arc, Barrier, Mutex};
#[cfg(unix)]
use std::time::{Duration, Instant};

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// The scheduler in this test binary is the process one (`fetch_sched::global`); tests that
/// hold its slots run one at a time.
#[cfg(unix)]
static SCHED_TESTS: Mutex<()> = Mutex::new(());

/// A real in-process VFS over a local block store holding one `len`-byte file at `/f.bin`.
#[cfg(unix)]
fn vfs_with_file(dir: &Path, len: usize) -> (VirtualVaultFs, Vec<u8>) {
    use parvault::crypto::MasterKey;
    use parvault::storage::{BlockStore, QuotaManager};
    let engine = Arc::new(GatewayEngine::from_local_block_store(
        BlockStore::new(
            dir.join("store"),
            QuotaManager::new(256 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .unwrap(),
        MasterKey::generate(),
    ));
    let key = [0x6C; 32];
    engine.set_macaroon_root_key(Some(key));
    // A write token (no caveats): the ingest stores the fixture, reads present the same token.
    let tok =
        parvault::capabilities::CapabilityMacaroon::mint(&key, [0x5A; 32], [0x5B; 32], vec![])
            .unwrap();
    let vfs = VirtualVaultFs::with_bus(
        GatewayBus::in_process(engine),
        dir.join("cache"),
        64 * 1024 * 1024,
    )
    .unwrap()
    .with_default_macaroon(Some(tok));
    let seed = dir.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    let bytes: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
    std::fs::write(seed.join("f.bin"), &bytes).unwrap();
    assert_eq!(vfs.ingest_local_directory(&seed).unwrap(), 1);
    (vfs, bytes)
}

/// The same file under a new, cold inode (T1: the cache is keyed by inode and block).
#[cfg(unix)]
fn cold_copy(vfs: &VirtualVaultFs, path: &str) -> u64 {
    let n = vfs.lookup_path("/f.bin").unwrap();
    vfs.upsert_file(
        path,
        LazyFileSpec {
            manifest: n.manifest.unwrap(),
            macaroon: None,
            mtime_unix_secs: None,
        },
    )
    .unwrap()
}

/// B-24: eight concurrent cold reads of one block make one fetch (one miss), 200 times.
#[cfg(unix)]
#[test]
fn b24_concurrent_cold_reads_fetch_once() {
    let _g = SCHED_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let (vfs, bytes) = vfs_with_file(dir.path(), 300 * 1024);
    for rep in 0..200 {
        let ino = cold_copy(&vfs, &format!("/rep/{rep}.bin"));
        let before = vfs.cache_stats().misses;
        let barrier = Barrier::new(8);
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    barrier.wait();
                    let got = vfs.read_at(ino, 0, bytes.len() as u64).unwrap();
                    assert_eq!(got, bytes);
                });
            }
        });
        assert_eq!(vfs.cache_stats().misses - before, 1, "rep {rep}: one fetch");
    }
    gate_ran("trust_enforcement_restore::b24_concurrent_cold_reads_fetch_once");
}

/// S6 (B-24 with L-72): a foreground reader joining a block fetch owned by a queued scavenger
/// promotes it, so both finish while scavengers hold every slot they may hold.
#[cfg(unix)]
#[test]
fn s6_foreground_join_promotes_a_queued_scavenger_fetch() {
    let _g = SCHED_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let (vfs, bytes) = vfs_with_file(dir.path(), 200 * 1024);
    let ino = cold_copy(&vfs, "/s6.bin");
    let sched = fetch_sched::global();
    let held: Vec<_> = (0..SLOTS - 1)
        .map(|_| sched.admit_as(FetchClass::Scavenger, None))
        .collect();
    std::thread::scope(|s| {
        let scav = s.spawn(|| {
            fetch_sched::run_as_scavenger(Arc::new(AtomicBool::new(false)), || {
                vfs.read_at(ino, 0, bytes.len() as u64).unwrap()
            })
        });
        let t0 = Instant::now();
        while sched.queued() != (0, 1) {
            assert!(
                t0.elapsed() < Duration::from_secs(10),
                "the scavenger fetch queues"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let fg = vfs.read_at(ino, 0, bytes.len() as u64).unwrap();
        assert_eq!(fg, bytes);
        assert_eq!(scav.join().unwrap(), bytes);
        assert_eq!(
            sched.in_flight(),
            (0, SLOTS - 1),
            "scavenger slots still held"
        );
    });
    drop(held);
    gate_ran("trust_enforcement_restore::s6_foreground_join_promotes_a_queued_scavenger_fetch");
}

/// S6 reject side: with no foreground join, the queued scavenger fetch stays queued while
/// scavengers hold `SLOTS - 1`, and `defer.scavenger_preempted` rises while a foreground waits.
#[cfg(unix)]
#[test]
fn s6_unjoined_scavenger_fetch_stays_queued() {
    let _g = SCHED_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let (vfs, bytes) = vfs_with_file(dir.path(), 200 * 1024);
    let ino = cold_copy(&vfs, "/s6r.bin");
    let sched = fetch_sched::global();
    let held: Vec<_> = (0..SLOTS - 1)
        .map(|_| sched.admit_as(FetchClass::Scavenger, None))
        .collect();
    let fg_hold = sched.admit_as(FetchClass::Foreground, None);
    let before = fetch_sched::counters().scavenger_preempted;
    std::thread::scope(|s| {
        let scav = s.spawn(|| {
            fetch_sched::run_as_scavenger(Arc::new(AtomicBool::new(false)), || {
                vfs.read_at(ino, 0, bytes.len() as u64).unwrap()
            })
        });
        let fg_wait = s.spawn(|| sched.admit_as(FetchClass::Foreground, None).class());
        let t0 = Instant::now();
        while sched.queued() != (1, 1) {
            assert!(t0.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(sched.queued(), (1, 1), "the scavenger fetch is not started");
        drop(fg_hold);
        assert_eq!(fg_wait.join().unwrap(), FetchClass::Foreground);
        assert!(
            fetch_sched::counters().scavenger_preempted > before,
            "the foreground grant passed the queued scavenger"
        );
        drop(held);
        assert_eq!(scav.join().unwrap(), bytes);
    });
    gate_ran("trust_enforcement_restore::s6_unjoined_scavenger_fetch_stays_queued");
}

/// The upsert swap is atomic for readers (qa-t0 INFO): a reader looking up a path that is being
/// replaced always finds a file.
#[cfg(unix)]
#[test]
fn upsert_never_hides_the_path_from_readers() {
    let dir = tempfile::tempdir().unwrap();
    let (vfs, _) = vfs_with_file(dir.path(), 4096);
    cold_copy(&vfs, "/swap.bin");
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        let reader = s.spawn(|| {
            let mut seen = 0u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                assert!(
                    vfs.lookup_path("/swap.bin").is_some(),
                    "path vanished mid-swap"
                );
                seen += 1;
            }
            seen
        });
        for _ in 0..2000 {
            cold_copy(&vfs, "/swap.bin");
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(reader.join().unwrap() > 0);
    });
    gate_ran("trust_enforcement_restore::upsert_never_hides_the_path_from_readers");
}

/// T2 (glue G-26): a read of a file whose stripes version GC freed (the host removal path a
/// `FreeShards` order takes: `delete_shard_deferred`, then `flush_removals`) re-imports the
/// catalogs once; the re-import gives the path a new inode that still names the freed stripes,
/// the read is retried once on it, and it fails with an error, not a panic or a loop. The path
/// stays listed.
#[cfg(unix)]
#[test]
fn t2_freed_stripe_reimports_once_then_fails_cleanly() {
    use parvault::crypto::{MasterKey, NodeIdentity};
    use parvault::storage::{BlockStore, QuotaManager};
    use std::sync::atomic::{AtomicUsize, Ordering};
    // Reads go through the process fetch scheduler, which the S6 tests hold.
    let _sched = SCHED_TESTS.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let mk = MasterKey::generate();
    let owner = NodeIdentity::from_master_key(&mk).device_peer_id();
    let store = BlockStore::new(
        dir.path().join("store"),
        QuotaManager::new(256 * 1024 * 1024, 32 * 1024 * 1024),
    )
    .unwrap();
    let engine = Arc::new(GatewayEngine::from_local_block_store(store.clone(), mk));
    let key = [0x6C; 32];
    engine.set_macaroon_root_key(Some(key));
    let tok =
        parvault::capabilities::CapabilityMacaroon::mint(&key, [0x5A; 32], [0x5B; 32], vec![])
            .unwrap();
    let vfs = Arc::new(
        VirtualVaultFs::with_bus(
            GatewayBus::in_process(engine),
            dir.path().join("cache"),
            64 * 1024 * 1024,
        )
        .unwrap()
        .with_default_macaroon(Some(tok)),
    );
    let seed = dir.path().join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    std::fs::write(seed.join("f.bin"), vec![0x42u8; 300 * 1024]).unwrap();
    assert_eq!(vfs.ingest_local_directory(&seed).unwrap(), 1);
    // A cold inode for the same file (the ingest may have warmed the cache of `/f.bin`).
    let manifest = vfs.lookup_path("/f.bin").unwrap().manifest.unwrap();
    vfs.upsert_file(
        "/g.bin",
        LazyFileSpec {
            manifest: manifest.clone(),
            macaroon: None,
            mtime_unix_secs: None,
        },
    )
    .unwrap();
    let node = vfs.lookup_path("/g.bin").unwrap();

    // Version GC frees every stripe of this version on the host.
    let held = store.list_stored_shards().unwrap();
    assert!(!held.is_empty());
    for (id, _) in &held {
        assert!(store.delete_shard_deferred(&owner, id).unwrap());
    }
    store.flush_removals();
    assert!(store.list_stored_shards().unwrap().is_empty());

    // The re-import: the catalog still names the freed version (a new inode, same manifest).
    let calls = Arc::new(AtomicUsize::new(0));
    let weak = Arc::downgrade(&vfs);
    let (c, m) = (Arc::clone(&calls), manifest.clone());
    vfs.set_reimport_hook(Some(Arc::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
        if let Some(v) = weak.upgrade() {
            v.upsert_file(
                "/g.bin",
                LazyFileSpec {
                    manifest: m.clone(),
                    macaroon: None,
                    mtime_unix_secs: None,
                },
            )
            .unwrap();
        }
    })));
    let started = Instant::now();
    let err = vfs
        .read_range_with_ttfb(node.ino, 0, 4096)
        .expect_err("a freed stripe cannot be read");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one re-import per failed read"
    );
    assert!(started.elapsed() < Duration::from_secs(60), "{err}");
    let after = vfs.lookup_path("/g.bin").expect("the path stays listed");
    assert_ne!(after.ino, node.ino, "the re-import replaced the inode");
    gate_ran("trust_enforcement_restore::t2_freed_stripe_reimports_once_then_fails_cleanly");
}

// --- B-20: catalog listing on the real binary ---------------------------------------------------

#[cfg(unix)]
mod b20 {
    use super::*;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    pub const ROOT_KEY: [u8; 32] = [0x20; 32];

    /// A real `parvault up` with built-in WebDAV; killed on drop.
    pub struct Daemon {
        child: Child,
        log: PathBuf,
        pub webdav: String,
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Daemon {
        pub fn log_text(&self) -> String {
            std::fs::read_to_string(&self.log).unwrap_or_default()
        }

        pub fn stop(mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }

        /// Waits until the log has `code`.
        pub fn assert_logged(&self, code: &str) {
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                if self.log_text().contains(code) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            panic!("{code} not in the log:\n{}", self.log_text());
        }
    }

    /// A data dir under `root` with the tests' macaroon root key.
    pub fn data_dir(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("macaroon_root.key");
        std::fs::write(&key, hex::encode(ROOT_KEY)).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        dir
    }

    /// `parvault up --no-socket` on `dir` with WebDAV on an ephemeral port and, with `folder`,
    /// the daemon's own folder sync every 2 s, the C37 floor (a changed catalog imports within a
    /// second of the pass that wrote it).
    pub fn up(dir: &Path, folder: Option<&Path>, extra_env: &[(&str, &str)]) -> Daemon {
        up_with(dir, folder, extra_env, &[])
    }

    pub fn up_with(
        dir: &Path,
        folder: Option<&Path>,
        extra_env: &[(&str, &str)],
        extra_args: &[&str],
    ) -> Daemon {
        let log = dir.with_extension(format!("log{}", std::process::id()));
        let log = PathBuf::from(format!("{}-{}", log.display(), rand_suffix()));
        let reg = dir.with_extension("lan-registry");
        std::fs::create_dir_all(&reg).unwrap();
        let log_file = std::fs::File::create(&log).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
        cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
            .env("PARVAULT_GENESIS_SEED_HEX", hex::encode([0x47u8; 32]))
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .env_remove("PARVAULT_PEERS")
            .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
            .arg("--data-dir")
            .arg(dir)
            .args(["--no-lan-discovery", "up"]);
        if !extra_args.contains(&"--ipc-socket") {
            cmd.arg("--no-socket");
        }
        cmd.args([
            "--listen",
            common::LOOPBACK_EPHEMERAL,
            "--vfs-webdav-listen",
            "127.0.0.1:0",
            "--interval-secs",
            "2",
        ]);
        if let Some(f) = folder {
            cmd.arg("--folder").arg(f);
        }
        cmd.args(extra_args);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let child = cmd
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("spawn parvault");
        let mut d = Daemon {
            child,
            log,
            webdav: String::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let text = d.log_text();
            if let Some(addr) = text
                .lines()
                .find_map(|l| l.split("WebDAV listening on http://").nth(1))
                .and_then(|rest| rest.split_whitespace().next())
            {
                d.webdav = addr.to_string();
                return d;
            }
            if let Ok(Some(st)) = d.child.try_wait() {
                panic!("daemon exited {st}:\n{text}");
            }
            assert!(Instant::now() < deadline, "WebDAV not up:\n{text}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn rand_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    pub fn token(caveats: Vec<parvault::capabilities::Caveat>) -> String {
        parvault::capabilities::CapabilityMacaroon::mint(&ROOT_KEY, [0x11; 32], [0x22; 32], caveats)
            .unwrap()
            .to_compact_token()
    }

    pub fn read_token() -> String {
        token(vec![parvault::capabilities::Caveat::ReadOnly])
    }

    /// One HTTP/1.1 request; (status, body).
    pub fn http(addr: &str, method: &str, path: &str, tok: &str, extra: &[&str]) -> (u16, Vec<u8>) {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nAuthorization: Bearer {tok}\r\n"
        );
        for h in extra {
            req.push_str(h);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        let status = String::from_utf8_lossy(&out)
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let body = out
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| out[i + 4..].to_vec())
            .unwrap_or_default();
        (status, body)
    }

    /// Polls `GET path` until `want(status, body)` or the deadline.
    pub fn wait_get(d: &Daemon, path: &str, what: &str, want: impl Fn(u16, &[u8]) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (st, body) = http(&d.webdav, "GET", path, &read_token(), &[]);
            if want(st, &body) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: GET {path} gave {st}\n{}",
                d.log_text()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn snapshot_file(dir: &Path) -> PathBuf {
        dir.join(parvault::vfs::catalog::DEVICE_SNAPSHOT_FILE)
    }

    pub fn snapshot_version(dir: &Path) -> u64 {
        let raw = std::fs::read(snapshot_file(dir)).unwrap();
        parvault::sync::FolderSnapshotManifest::decode_bytes(&raw)
            .unwrap()
            .version
    }
}

/// B20-LIST accept: the daemon lists its catalog under `/watched/` and a read-only token reads
/// it; a changed file is re-imported with its new bytes (T1); a deleted file leaves the
/// listing (T4); a token scoped to another manifest gets 403 (F-43).
#[cfg(unix)]
#[test]
fn b20_readonly_token_lists_catalog() {
    use b20::*;
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"catalog a, first").unwrap();
    std::fs::write(folder.join("b.txt"), b"catalog b").unwrap();
    let d = up(&data_dir(root.path(), "data"), Some(&folder), &[]);
    wait_get(&d, "/watched/a.txt", "listed", |st, b| {
        st == 200 && b == b"catalog a, first"
    });
    let (st, body) = http(
        &d.webdav,
        "PROPFIND",
        "/watched/",
        &read_token(),
        &["Depth: 1"],
    );
    let listing = String::from_utf8_lossy(&body);
    assert_eq!(st, 207, "{listing}");
    assert!(
        listing.contains("a.txt") && listing.contains("b.txt"),
        "{listing}"
    );
    // F-43: a token scoped to another manifest is refused.
    let scoped = token(vec![
        parvault::capabilities::Caveat::ReadOnly,
        parvault::capabilities::Caveat::AllowedManifest([0xEE; 32]),
    ]);
    let (st, _) = http(&d.webdav, "GET", "/watched/a.txt", &scoped, &[]);
    assert_eq!(st, 403);
    // T1: change, pass, re-import, new bytes.
    std::fs::write(folder.join("a.txt"), b"catalog a, second version").unwrap();
    wait_get(&d, "/watched/a.txt", "T1 new bytes", |st, b| {
        st == 200 && b == b"catalog a, second version"
    });
    // T4: a deleted file leaves the listing.
    std::fs::remove_file(folder.join("b.txt")).unwrap();
    wait_get(&d, "/watched/b.txt", "T4 removed", |st, _| st == 404);
    let (_, body) = http(
        &d.webdav,
        "PROPFIND",
        "/watched/",
        &read_token(),
        &["Depth: 1"],
    );
    assert!(!String::from_utf8_lossy(&body).contains("b.txt"));
    gate_ran("trust_enforcement_restore::b20_readonly_token_lists_catalog");
}

/// B20-LIST reject: a catalog another data dir wrote (another owner key) is not imported.
#[cfg(unix)]
#[test]
fn b20_foreign_catalog_refused() {
    use b20::*;
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"someone else's file").unwrap();
    let a_dir = data_dir(root.path(), "a");
    let a = up(&a_dir, Some(&folder), &[]);
    wait_get(&a, "/watched/a.txt", "a lists its own", |st, _| st == 200);
    a.stop();
    let b_dir = data_dir(root.path(), "b");
    std::fs::copy(snapshot_file(&a_dir), snapshot_file(&b_dir)).unwrap();
    let b = up(&b_dir, None, &[]);
    b.assert_logged("reject.catalog_foreign");
    let (st, _) = http(&b.webdav, "GET", "/watched/a.txt", &read_token(), &[]);
    assert_eq!(st, 404, "a foreign catalog is not listed");
    gate_ran("trust_enforcement_restore::b20_foreign_catalog_refused");
}

/// B20-LIST-RB reject: an older catalog than the one loaded is not applied.
#[cfg(unix)]
#[test]
fn b20_rollback_catalog_refused() {
    use b20::*;
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"rollback v1").unwrap();
    let dir = data_dir(root.path(), "data");
    let a = up(&dir, Some(&folder), &[]);
    wait_get(&a, "/watched/a.txt", "v1", |st, b| {
        st == 200 && b == b"rollback v1"
    });
    let v1 = std::fs::read(snapshot_file(&dir)).unwrap();
    let v1_version = snapshot_version(&dir);
    std::fs::write(folder.join("a.txt"), b"rollback v2").unwrap();
    wait_get(&a, "/watched/a.txt", "v2", |st, b| {
        st == 200 && b == b"rollback v2"
    });
    a.stop();
    assert!(snapshot_version(&dir) > v1_version);
    let b = up(&dir, None, &[]);
    wait_get(&b, "/watched/a.txt", "v2 after restart", |st, b| {
        st == 200 && b == b"rollback v2"
    });
    std::fs::write(snapshot_file(&dir), &v1).unwrap();
    b.assert_logged("reject.catalog_rollback");
    let (st, body) = http(&b.webdav, "GET", "/watched/a.txt", &read_token(), &[]);
    assert_eq!((st, body.as_slice()), (200, &b"rollback v2"[..]));
    gate_ran("trust_enforcement_restore::b20_rollback_catalog_refused");
}

// --- L-72: foreground preempts the in-daemon scavenger (S1, S5, S7) ----------------------------

#[cfg(unix)]
mod l72 {
    use super::b20::*;
    use super::*;

    /// The last `fetch_sched counters` line of the log: (preempted, cache misses).
    pub fn counters(d: &Daemon) -> (u64, u64) {
        let text = d.log_text();
        let Some(line) = text
            .lines()
            .rev()
            .find(|l| l.contains("fetch_sched counters"))
        else {
            return (0, 0);
        };
        let field = |name: &str| {
            line.split_whitespace()
                .find_map(|w| w.strip_prefix(&format!("{name}=")))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        };
        (field("preempted"), field("cache_misses"))
    }

    /// What E1 step 8 measures on one daemon.
    pub struct Outcome {
        pub preempted_before: u64,
        pub preempted_after: u64,
        pub misses_before: u64,
        pub misses_after: u64,
        pub ttfb_loaded: Duration,
        pub ttfb_idle: Duration,
        pub log: String,
    }

    fn ttfb_get(d: &Daemon, path: &str) -> (Duration, u16, usize) {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(&d.webdav).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer {}\r\n\r\n",
            read_token()
        );
        let t0 = Instant::now();
        s.write_all(req.as_bytes()).unwrap();
        let mut first = [0u8; 1];
        s.read_exact(&mut first).unwrap();
        let ttfb = t0.elapsed();
        let mut rest = Vec::new();
        let _ = s.read_to_end(&mut rest);
        let text = String::from_utf8_lossy(&rest[..rest.len().min(64)]).to_string();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (ttfb, status, rest.len() + 1)
    }

    /// Step 8: the scavenger hydrates the 48 MiB file; meanwhile a foreground GET of a 3 MiB
    /// file this daemon never read runs. Then an idle GET of another never-read 3 MiB file.
    pub fn run(label: &str, extra_env: &[(&str, &str)]) -> Outcome {
        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join(label);
        std::fs::create_dir_all(&folder).unwrap();
        let fill = |n: usize, seed: u8| -> Vec<u8> {
            (0..n)
                .map(|i| (i as u8).wrapping_mul(seed).wrapping_add(seed))
                .collect()
        };
        std::fs::write(folder.join("a_big.bin"), fill(48 << 20, 7)).unwrap();
        std::fs::write(folder.join("z_small.bin"), fill(3 << 20, 11)).unwrap();
        std::fs::write(folder.join("z_idle.bin"), fill(3 << 20, 13)).unwrap();
        let d = up_with(
            &data_dir(root.path(), "data"),
            Some(&folder),
            extra_env,
            &["--vfs-cache-mib", "64"],
        );
        // Listed (PROPFIND reads no bytes), and the scavenger has started on the big file.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let (_, body) = http(
                &d.webdav,
                "PROPFIND",
                "/watched/",
                &read_token(),
                &["Depth: 1"],
            );
            if String::from_utf8_lossy(&body).contains("z_small.bin")
                && d.log_text().contains("scavenger: hydrating")
            {
                break;
            }
            assert!(Instant::now() < deadline, "not listed:\n{}", d.log_text());
            std::thread::sleep(Duration::from_millis(20));
        }
        let (preempted_before, misses_before) = counters(&d);
        let (ttfb_loaded, st, n) = ttfb_get(&d, "/watched/z_small.bin");
        assert_eq!(st, 200);
        assert!(n > 3 << 20);
        // The scavenger stops at its cache share; wait for it to go quiet.
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut last = counters(&d);
        loop {
            std::thread::sleep(Duration::from_millis(2500));
            let now = counters(&d);
            if now == last {
                break;
            }
            last = now;
            assert!(Instant::now() < deadline, "scavenger never idle");
        }
        let (ttfb_idle, st, _) = ttfb_get(&d, "/watched/z_idle.bin");
        assert_eq!(st, 200);
        std::thread::sleep(Duration::from_millis(2500));
        let (preempted_after, misses_after) = counters(&d);
        Outcome {
            preempted_before,
            preempted_after,
            misses_before,
            misses_after,
            ttfb_loaded,
            ttfb_idle,
            log: d.log_text(),
        }
    }

    /// The accept condition (S7): the never-read file missed the cache and at least one
    /// scavenger fetch was deferred for it; on the box (`PARVAULT_L72_TIMING=1`) also the
    /// TTFB bound, `2x` idle plus `100 ms`.
    pub fn accept_holds(o: &Outcome) -> Result<(), String> {
        println!(
            "L72 ttfb loaded={:?} idle={:?} preempted {}->{} misses {}->{}",
            o.ttfb_loaded,
            o.ttfb_idle,
            o.preempted_before,
            o.preempted_after,
            o.misses_before,
            o.misses_after
        );
        if o.misses_after <= o.misses_before {
            return Err("the cache-miss counter did not rise".into());
        }
        if o.preempted_after <= o.preempted_before {
            return Err("no scavenger fetch was deferred".into());
        }
        if std::env::var("PARVAULT_L72_TIMING").as_deref() == Ok("1") {
            let bound = o.ttfb_idle * 2 + Duration::from_millis(100);
            if o.ttfb_loaded > bound {
                return Err(format!("TTFB {:?} over {:?}", o.ttfb_loaded, bound));
            }
        }
        Ok(())
    }
}

/// L72-SCHED accept (E1 step 8 on one daemon; S1, S7): a foreground GET of a never-read file
/// while the scavenger hydrates is served ahead of it.
#[cfg(unix)]
#[test]
fn l72_foreground_ttfb_under_load() {
    let _g = SCHED_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let o = l72::run("l72-accept", &[]);
    if let Err(e) = l72::accept_holds(&o) {
        panic!("{e}\n{}", o.log);
    }
    gate_ran("trust_enforcement_restore::l72_foreground_ttfb_under_load");
}

/// L72-SCHED reject: while a foreground read is queued the scavenger's fetch waits; the daemon
/// logs `defer.scavenger_preempted`.
#[cfg(unix)]
#[test]
fn l72_scavenger_waits_while_foreground_queued() {
    let _g = SCHED_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let o = l72::run("l72-reject", &[]);
    assert!(
        o.log.contains("defer.scavenger_preempted"),
        "no deferral logged:\n{}",
        o.log
    );
    assert!(o.preempted_after > 0);
    gate_ran("trust_enforcement_restore::l72_scavenger_waits_while_foreground_queued");
}

/// S5: with the priority removed (the daemon's mutant switch), the accept condition fails.
#[cfg(unix)]
#[test]
fn l72_priority_mutant_fails_the_accept_test() {
    let _g = SCHED_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let o = l72::run("l72-mutant", &[("PARVAULT_TEST_SCHED_NO_PRIORITY", "1")]);
    assert!(
        l72::accept_holds(&o).is_err(),
        "the mutant passed the accept test"
    );
    gate_ran("trust_enforcement_restore::l72_priority_mutant_fails_the_accept_test");
}

/// B-20 (plan 3.3): `parvault-sync` lists its catalog and pulls with a read-only token; a
/// read-only token cannot push.
#[cfg(unix)]
#[test]
fn b20_parvault_sync_read_only_listing() {
    use b20::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    let root = tempfile::tempdir().unwrap();
    let dir = data_dir(root.path(), "data");
    let sock = root.path().join("gw.sock");
    let sock_s = sock.to_str().unwrap().to_string();
    let _d = up_with(&dir, None, &[], &["--ipc-socket", &sock_s]);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "no gateway socket");
        std::thread::sleep(Duration::from_millis(50));
    }
    let folder = root.path().join("push");
    std::fs::create_dir_all(&folder).unwrap();
    let body: Vec<u8> = (0..200_000u32).map(|i| (i % 239) as u8).collect();
    std::fs::write(folder.join("doc.bin"), &body).unwrap();
    let catalog = root.path().join("catalog.bin");
    let sync = |args: &[&str], tok: Option<&Path>| {
        let mut cmd = Command::new(common::plugin_bin(
            "parvault-sync",
            env!("CARGO_BIN_EXE_parvault-sync"),
        ));
        cmd.arg("--data-dir")
            .arg(&dir)
            .arg("--socket")
            .arg(&sock)
            .arg("--catalog")
            .arg(&catalog);
        if let Some(t) = tok {
            cmd.arg("--macaroon-file").arg(t);
        }
        cmd.args(args);
        common::output_within_deadline(&mut cmd)
    };
    let out = sync(
        &[
            "push",
            "--folder",
            folder.to_str().unwrap(),
            "--allow-local-only",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ro = root.path().join("ro.tok");
    std::fs::write(&ro, read_token()).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = sync(&["list"], Some(&ro));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && text.contains("doc.bin"), "{text}");
    let restored = root.path().join("restored");
    let out = sync(&["pull", "--output", restored.to_str().unwrap()], Some(&ro));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(restored.join("doc.bin")).unwrap(), body);
    // The same read-only token cannot store.
    std::fs::write(folder.join("new.bin"), b"not with a read token").unwrap();
    let out = sync(
        &[
            "push",
            "--folder",
            folder.to_str().unwrap(),
            "--allow-local-only",
        ],
        Some(&ro),
    );
    assert!(!out.status.success(), "a read-only token pushed");
    gate_ran("trust_enforcement_restore::b20_parvault_sync_read_only_listing");
}

// --- B-20 seed vaults (archC1, L-133) -----------------------------------------------------------

#[cfg(unix)]
mod seedvault {
    use super::*;
    use parvault::crypto::{MasterKey, NodeIdentity};
    use parvault::storage::{BlockStore, QuotaManager};
    use parvault::sync::{EncryptedVaultCatalogEnvelope, FolderSyncEngine};
    use std::collections::{BTreeMap, HashMap};

    pub const SEED_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    pub const SEED_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    pub const NS: &str = "photos";

    /// A seed vault's folder sync, writing shards and its catalog envelope into `dir` (the
    /// node's data dir) as `watch-folder --seed-phrase` does.
    pub struct Writer {
        engine: FolderSyncEngine,
        seed: &'static str,
        ns: &'static str,
    }

    impl Writer {
        pub fn new(dir: &Path, seed: &'static str) -> Self {
            Self::new_ns(dir, seed, NS)
        }

        /// The writer of the vault `ns`.
        pub fn new_ns(dir: &Path, seed: &'static str, ns: &'static str) -> Self {
            let canonical =
                parvault::crypto::validate_recovery_seed_phrase_or_passphrase(seed).unwrap();
            let mk = MasterKey::from_recovery_seed_phrase(&canonical, ns);
            let owner = NodeIdentity::from_recovery_seed_phrase(&canonical, ns);
            let store = BlockStore::new(dir, QuotaManager::new(1 << 30, 1 << 28)).unwrap();
            Self {
                engine: FolderSyncEngine::new(
                    store,
                    mk,
                    owner,
                    parvault::config::ErasureTier::Consumer,
                ),
                seed,
                ns,
            }
        }

        /// One pass over `folder` and the exported catalog envelope.
        pub fn pass(&mut self, folder: &Path) -> EncryptedVaultCatalogEnvelope {
            let snap = self.engine.sync_folder_once(folder).unwrap();
            self.engine.load_previous_snapshot(&snap);
            self.engine
                .export_encrypted_vault_catalog(self.seed, self.ns, &snap)
                .unwrap()
        }
    }

    /// `zero_trust_dht_store.bin`'s layout (`storage::block_store`), to plant an envelope the
    /// way a DHT peer could hand one back.
    #[derive(serde::Serialize, serde::Deserialize, Default)]
    struct DhtState {
        records: HashMap<[u8; 32], parvault::storage::SignedDhtManifestEnvelope>,
        pq_records: HashMap<[u8; 32], parvault::crypto::PqSignedDhtManifestEnvelope>,
        catalog_records: HashMap<[u8; 32], EncryptedVaultCatalogEnvelope>,
    }

    /// Stores `env` in `dir`'s DHT store under `key`, bypassing the store's own checks.
    pub fn plant(dir: &Path, key: [u8; 32], env: EncryptedVaultCatalogEnvelope) {
        let path = dir.join("zero_trust_dht_store.bin");
        let mut st: DhtState = std::fs::read(&path)
            .ok()
            .and_then(|b| bincode::deserialize(&b).ok())
            .unwrap_or_default();
        st.catalog_records.insert(key, env);
        std::fs::write(&path, bincode::serialize(&st).unwrap()).unwrap();
    }

    /// What a daemon could change for the vault: its shard files and the DHT store.
    pub fn fingerprint(dir: &Path) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        if let Ok(rd) = std::fs::read_dir(dir.join("shards")) {
            for e in rd.filter_map(Result::ok) {
                let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                out.insert(e.file_name().to_string_lossy().to_string(), len);
            }
        }
        let dht = std::fs::read(dir.join("zero_trust_dht_store.bin")).unwrap_or_default();
        let h = dht.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3)
        });
        out.insert("zero_trust_dht_store.bin".into(), h);
        out
    }
}

/// VAULTKEY and B20-LIST accept for a seed vault (archC1): a registered vault's catalog is
/// listed under `/<namespace>/` and read; across import, read and the scavenger the daemon
/// stores, deletes, frees and publishes nothing for it (condition 2).
#[cfg(unix)]
#[test]
fn b20_seed_vault_listed_and_read() {
    use b20::*;
    use seedvault::*;
    let root = tempfile::tempdir().unwrap();
    let dir = data_dir(root.path(), "data");
    let folder = root.path().join("src");
    std::fs::create_dir_all(&folder).unwrap();
    let body: Vec<u8> = (0..1_500_000u32).map(|i| (i % 233) as u8).collect();
    std::fs::write(folder.join("a.bin"), &body).unwrap();
    std::fs::write(folder.join("b.txt"), b"seed vault b").unwrap();
    Writer::new(&dir, SEED_A).pass(&folder);
    let kf = parvault::vfs::register_vault_keys(&dir, SEED_A, NS).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&kf).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let raw = std::fs::read(&kf).unwrap();
    let mk = parvault::crypto::MasterKey::from_recovery_seed_phrase(
        &parvault::crypto::validate_recovery_seed_phrase_or_passphrase(SEED_A).unwrap(),
        NS,
    );
    assert!(
        !raw.windows(32).any(|w| w == mk.as_bytes()),
        "the key file holds no plaintext key"
    );
    let before = fingerprint(&dir);
    let d = up(&dir, None, &[]);
    wait_get(&d, "/photos/a.bin", "seed vault listed", |st, b| {
        st == 200 && b == body.as_slice()
    });
    wait_get(&d, "/photos/b.txt", "second file", |st, b| {
        st == 200 && b == b"seed vault b"
    });
    // Let the scavenger hydrate, then compare.
    std::thread::sleep(Duration::from_secs(4));
    let log = d.log_text();
    d.stop();
    assert_eq!(
        fingerprint(&dir),
        before,
        "the daemon changed the vault's shards or DHT store"
    );
    for word in ["PutShard", "DeleteShard", "FreeShards", "put_dht_envelope"] {
        assert!(!log.contains(word), "{word} in the log:\n{log}");
    }
    assert!(!log.contains(SEED_A), "the phrase is not logged");
    gate_ran("trust_enforcement_restore::b20_seed_vault_listed_and_read");
}

/// VAULTKEY reject (archC1 condition 1): a key file renamed to another namespace is refused.
#[cfg(unix)]
#[test]
fn b20_swapped_vaultkey_refused() {
    use b20::*;
    use seedvault::*;
    let root = tempfile::tempdir().unwrap();
    let dir = data_dir(root.path(), "data");
    let folder = root.path().join("src");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"renamed key").unwrap();
    Writer::new(&dir, SEED_A).pass(&folder);
    let kf = parvault::vfs::register_vault_keys(&dir, SEED_A, NS).unwrap();
    std::fs::rename(&kf, kf.with_file_name("music.vaultkey")).unwrap();
    let d = up(&dir, None, &[]);
    d.assert_logged("reject.vaultkey_mismatch");
    for p in ["/music/a.txt", "/photos/a.txt"] {
        let (st, _) = http(&d.webdav, "GET", p, &read_token(), &[]);
        assert_eq!(st, 404, "{p}");
    }
    gate_ran("trust_enforcement_restore::b20_swapped_vaultkey_refused");
}

/// B20-LIST reject for a seed vault (archC1 condition 3): a validly signed catalog of another
/// owner at the vault's DHT key is not imported.
#[cfg(unix)]
#[test]
fn b20_seed_vault_foreign_catalog_refused() {
    use b20::*;
    use seedvault::*;
    let root = tempfile::tempdir().unwrap();
    let dir = data_dir(root.path(), "data");
    let other = root.path().join("other");
    std::fs::create_dir_all(&other).unwrap();
    let folder = root.path().join("src");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"not your vault").unwrap();
    let env_b = Writer::new(&other, SEED_B).pass(&folder);
    assert!(env_b.verify_zero_knowledge());
    parvault::vfs::register_vault_keys(&dir, SEED_A, NS).unwrap();
    let mk_a = parvault::crypto::MasterKey::from_recovery_seed_phrase(
        &parvault::crypto::validate_recovery_seed_phrase_or_passphrase(SEED_A).unwrap(),
        NS,
    );
    plant(&dir, mk_a.derive_vault_root_dht_key(NS), env_b);
    let d = up(&dir, None, &[]);
    d.assert_logged("reject.catalog_foreign");
    let (st, _) = http(&d.webdav, "GET", "/photos/a.txt", &read_token(), &[]);
    assert_eq!(st, 404);
    gate_ran("trust_enforcement_restore::b20_seed_vault_foreign_catalog_refused");
}

/// B20-LIST-RB reject for a seed vault: after version 2 was applied, version 1 is a rollback,
/// also after a restart.
#[cfg(unix)]
#[test]
fn b20_seed_vault_rollback_refused() {
    use b20::*;
    use seedvault::*;
    let root = tempfile::tempdir().unwrap();
    let dir = data_dir(root.path(), "data");
    let folder = root.path().join("src");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"vault v1").unwrap();
    let mut w = Writer::new(&dir, SEED_A);
    let env1 = w.pass(&folder);
    std::fs::write(folder.join("a.txt"), b"vault v2").unwrap();
    let env2 = w.pass(&folder);
    assert!(env2.monotonic_version > env1.monotonic_version);
    drop(w);
    parvault::vfs::register_vault_keys(&dir, SEED_A, NS).unwrap();
    let d = up(&dir, None, &[]);
    wait_get(&d, "/photos/a.txt", "v2", |st, b| {
        st == 200 && b == b"vault v2"
    });
    d.stop();
    let key = env1.dht_key;
    plant(&dir, key, env1);
    let d = up(&dir, None, &[]);
    d.assert_logged("reject.catalog_rollback");
    let (st, body) = http(&d.webdav, "GET", "/photos/a.txt", &read_token(), &[]);
    assert_ne!((st, body.as_slice()), (200, &b"vault v1"[..]));
    gate_ran("trust_enforcement_restore::b20_seed_vault_rollback_refused");
}

// --- v0.5.6 qafix (D13, D16) -------------------------------------------------------------

#[cfg(unix)]
mod qafix056 {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    pub const BACKUP_PASS: &str = "qafix056 ring backup passphrase";

    /// `parvault --data-dir <dir>` with the ring and passphrase environment cleared.
    fn pv(dir: &Path) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
        cmd.env_remove("PARVAULT_GENESIS_SEED_HEX")
            .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
            .env_remove("PARVAULT_PEERS")
            .env_remove("PARVAULT_PASSPHRASE")
            .env(
                "PARVAULT_LAN_REGISTRY_DIR",
                dir.with_extension("lan-registry"),
            )
            .arg("--data-dir")
            .arg(dir)
            .arg("--no-lan-discovery");
        cmd
    }

    fn text(o: &Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    }

    /// Makes `dir` (a `b20` daemon's data dir, ring from `PARVAULT_GENESIS_SEED_HEX`) a node a
    /// ring backup accepts: its identity and the ring's public key on disk.
    pub fn make_ring_node(dir: &Path) {
        parvault::crypto::NodeIdentity::load_or_generate_in_dir(dir).unwrap();
        let ring = parvault::crypto::NodeIdentity::from_seed([0x47; 32]).public_key_bytes();
        std::fs::write(dir.join("ring_genesis.pub"), hex::encode(ring)).unwrap();
    }

    /// `ring backup` of `dir` then `ring restore` into the new data dir `target`.
    pub fn backup_and_restore(dir: &Path, target: &Path, tmp: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let pass = tmp.join("backup.pass");
        std::fs::write(&pass, BACKUP_PASS).unwrap();
        std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o600)).unwrap();
        let out = tmp.join("bundle");
        let o = common_out(
            pv(dir)
                .args(["ring", "backup", "--out"])
                .arg(&out)
                .arg("--passphrase-file")
                .arg(&pass),
        );
        assert!(o.status.success(), "backup: {}", text(&o));
        let bundle: PathBuf = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "pvbak"))
            .unwrap();
        let o = common_out(
            pv(target)
                .args(["ring", "restore", "--from"])
                .arg(&bundle)
                .arg("--passphrase-file")
                .arg(&pass)
                .arg("--confirm-move"),
        );
        assert!(o.status.success(), "restore: {}", text(&o));
    }

    fn common_out(cmd: &mut Command) -> Output {
        super::common::output_within_deadline(cmd)
    }
}

/// D13 (VFS-LIVE-CATALOG): a running daemon lists a catalog version another process (the vault's
/// `watch-folder` writer, here this test process through the same envelope store) publishes into
/// its data dir, without a restart.
#[cfg(unix)]
#[test]
fn d13_running_daemon_lists_other_process_catalog() {
    use b20::*;
    use seedvault::*;
    let root = tempfile::tempdir().unwrap();
    let dir = data_dir(root.path(), "data");
    let folder = root.path().join("src");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"live v1").unwrap();
    let mut w = Writer::new(&dir, SEED_A);
    w.pass(&folder);
    parvault::vfs::register_vault_keys(&dir, SEED_A, NS).unwrap();
    let d = up(&dir, None, &[]);
    wait_get(&d, "/photos/a.txt", "v1 listed", |st, b| {
        st == 200 && b == b"live v1"
    });
    std::fs::write(folder.join("b.txt"), b"published while the daemon runs").unwrap();
    w.pass(&folder);
    wait_get(
        &d,
        "/photos/b.txt",
        "the new version, no restart",
        |st, b| st == 200 && b == b"published while the daemon runs",
    );
    d.stop();
    gate_ran("trust_enforcement_restore::d13_running_daemon_lists_other_process_catalog");
}

/// D16 (VAULT-FLOOR-BACKUP): a ring backup carries the version floor of every namespace a vault
/// can be registered under (here one with a space, plus a leading '.', non-ASCII and a 200-byte
/// name), so after a restore a rolled-back catalog is still refused.
#[cfg(unix)]
#[test]
fn d16_floor_of_any_registered_namespace_survives_backup() {
    use b20::*;
    use seedvault::*;
    const ODD: &str = "my photos";
    let root = tempfile::tempdir().unwrap();
    let a = data_dir(root.path(), "a");
    let folder = root.path().join("src");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"odd v1").unwrap();
    let mut w = Writer::new_ns(&a, SEED_A, ODD);
    let env1 = w.pass(&folder);
    std::fs::write(folder.join("a.txt"), b"odd v2").unwrap();
    let env2 = w.pass(&folder);
    drop(w);
    parvault::vfs::register_vault_keys(&a, SEED_A, ODD).unwrap();
    let floor = a.join("vaults").join(format!("{ODD}.floor"));
    let d = up(&a, None, &[]);
    let deadline = Instant::now() + Duration::from_secs(60);
    while std::fs::read(&floor).ok() != Some(env2.monotonic_version.to_be_bytes().to_vec()) {
        assert!(
            Instant::now() < deadline,
            "v2 never applied:\n{}",
            d.log_text()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    d.stop();
    let long = "n".repeat(200);
    let others = [".hidden", "fotos-\u{fc}", long.as_str()];
    for ns in others {
        std::fs::write(
            a.join("vaults").join(format!("{ns}.floor")),
            7u64.to_be_bytes(),
        )
        .unwrap();
    }
    qafix056::make_ring_node(&a);
    let b = root.path().join("b");
    qafix056::backup_and_restore(&a, &b, root.path());
    for ns in others.iter().copied().chain([ODD]) {
        let name = format!("{ns}.floor");
        assert_eq!(
            std::fs::read(b.join("vaults").join(&name)).ok(),
            std::fs::read(a.join("vaults").join(&name)).ok(),
            "{name} not restored"
        );
    }
    let b = data_dir(root.path(), "b");
    parvault::vfs::register_vault_keys(&b, SEED_A, ODD).unwrap();
    let key = env1.dht_key;
    plant(&b, key, env1);
    let d = up(&b, None, &[]);
    d.assert_logged("reject.catalog_rollback");
    d.stop();
    gate_ran("trust_enforcement_restore::d16_floor_of_any_registered_namespace_survives_backup");
}
