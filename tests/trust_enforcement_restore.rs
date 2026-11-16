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
        assert!(fetch_sched::counters().scavenger_preempted > before);
        drop(fg_hold);
        assert_eq!(fg_wait.join().unwrap(), FetchClass::Foreground);
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
