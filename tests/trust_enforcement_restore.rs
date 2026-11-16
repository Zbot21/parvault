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
        std::fs::write(dir.join("macaroon_root.key"), hex::encode(ROOT_KEY)).unwrap();
        dir
    }

    /// `parvault up --no-socket` on `dir` with WebDAV on an ephemeral port and, with `folder`,
    /// the daemon's own folder sync every second (a changed catalog imports within a second).
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
            .args([
                "--no-lan-discovery",
                "up",
                "--no-socket",
                "--listen",
                common::LOOPBACK_EPHEMERAL,
                "--vfs-webdav-listen",
                "127.0.0.1:0",
                "--interval-secs",
                "1",
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
