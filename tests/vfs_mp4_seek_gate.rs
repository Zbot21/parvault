//! Plan-5 (design ledger §7.2): a real H.264 MP4, stored over sealed memfd through a real gateway
//! socket, is probed and random-seeked by real `ffprobe` / `ffmpeg` straight from a real kernel
//! `/dev/fuse` mount (`fusermount3`, unprivileged) and from the WebDAV `HTTP 206` edge with a
//! ReadOnly bearer token, with an LRU cache (3 MiB) smaller than the video (≈12 MiB). Frame digests are compared with
//! the same file read from local disk, so no golden values are pinned.
//!
//! Skip rule: a missing `/dev/fuse`, `fusermount3`, `ffmpeg` or `ffprobe` prints `SKIPPED: ...`;
//! under `GATES_REQUIRE_REAL=1` it fails instead. `tc netem` needs root: that leg runs only in the
//! Docker gate (stage 12c).
#![cfg(target_os = "linux")]

use parvault::capabilities::{CapabilityMacaroon, Caveat};
use parvault::config::{ErasureTier, HardwareProfile};
use parvault::crypto::MasterKey;
use parvault::gateway::GatewayIpcServer;
use parvault::os_sys::recvmsg_scm_rights;
use parvault::storage::{BlockStore, QuotaManager};
use parvault::vfs::{VirtualVaultFs, WebdavVerifier};
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MIB: u64 = 1024 * 1024;
const CACHE_BYTES: u64 = 3 * MIB;
const SEEK_SECS: &str = "12";

fn require_real() -> bool {
    std::env::var("GATES_REQUIRE_REAL").as_deref() == Ok("1")
}

fn have_cmd(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd} >/dev/null")])
        .status()
        .is_ok_and(|s| s.success())
}

/// `None` when every prerequisite is present; else what is missing.
fn missing(needs_fuse: bool) -> Option<String> {
    let mut out = Vec::new();
    for c in ["ffmpeg", "ffprobe"] {
        if !have_cmd(c) {
            out.push(c.to_string());
        }
    }
    if needs_fuse {
        if !have_cmd("fusermount3") {
            out.push("fusermount3".into());
        }
        if !std::fs::metadata("/dev/fuse").is_ok_and(|m| m.file_type().is_char_device()) {
            out.push("/dev/fuse".into());
        }
    }
    (!out.is_empty()).then(|| out.join(", "))
}

/// Returns false (skipped) or panics under `GATES_REQUIRE_REAL=1`.
fn prerequisites(test: &str, needs_fuse: bool) -> bool {
    match missing(needs_fuse) {
        None => true,
        Some(what) => {
            assert!(
                !require_real(),
                "{test}: missing {what} (GATES_REQUIRE_REAL=1)"
            );
            eprintln!("SKIPPED: {test}: missing {what}");
            false
        }
    }
}

/// The §7.2 latency and RSS budgets are release-build numbers (a debug build decodes a 1 MiB
/// stripe ~20x slower). A debug run checks everything else and reports the measurement; under
/// `GATES_REQUIRE_REAL=1` an unasserted budget is a failure, so the gate must run `--release`.
fn assert_budget(what: &str, ok: bool, measured: String) {
    if cfg!(debug_assertions) {
        assert!(
            !require_real(),
            "{what}: budget not asserted in a debug build ({measured}); run with --release (GATES_REQUIRE_REAL=1)"
        );
        eprintln!("BUDGET-UNASSERTED (debug build): {what}: {measured}");
    } else {
        assert!(ok, "{what}: {measured}");
    }
}

/// Cold time-to-first-byte budget; the Docker gate's netem stage sets 100 (§7.2).
fn ttfb_budget() -> Duration {
    Duration::from_millis(
        std::env::var("PARVAULT_VFS_TTFB_BUDGET_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50),
    )
}

/// The plugin binary: `PARVAULT_FUSE_BIN` (the Docker gate runs this test binary in a container),
/// else the one cargo built.
fn plugin_bin() -> PathBuf {
    std::env::var_os("PARVAULT_FUSE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_parvault-fuse")))
}

fn run(cmd: &mut Command) -> std::process::Output {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// ≈12 MiB faststart H.264 (keyframe every second), size asserted 8..=16 MiB.
fn make_clip(dir: &Path) -> PathBuf {
    let seed = dir.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    let clip = seed.join("clip.mp4");
    run(Command::new("ffmpeg")
        .args([
            "-v",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=1280x720:rate=30",
            "-t",
            "24",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-b:v",
            "4M",
            "-maxrate",
            "4M",
            "-bufsize",
            "8M",
            "-g",
            "30",
            "-bf",
            "0",
            "-threads",
            "1",
            "-fflags",
            "+bitexact",
            "-movflags",
            "+faststart",
        ])
        .arg(&clip));
    let len = std::fs::metadata(&clip).unwrap().len();
    assert!(
        (8 * MIB..=16 * MIB).contains(&len),
        "clip is {len} bytes, want 8..=16 MiB"
    );
    clip
}

fn probe(target: &str, bearer: Option<&str>) -> std::process::Output {
    let mut c = Command::new("ffprobe");
    c.args(["-v", "error"]);
    if let Some(t) = bearer {
        c.args(["-headers", &format!("Authorization: Bearer {t}\r\n")]);
    }
    c.args([
        "-show_entries",
        "format=duration:stream=codec_name,width,height",
        "-of",
        "default=nw=1",
        target,
    ]);
    c.output().expect("spawn ffprobe")
}

fn assert_probe_ok(out: &std::process::Output) {
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "ffprobe failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for want in ["codec_name=h264", "width=1280", "height=720"] {
        assert!(text.contains(want), "ffprobe output lacks {want}: {text}");
    }
}

fn framemd5(target: &str, bearer: Option<&str>) -> String {
    let mut c = Command::new("ffmpeg");
    c.args(["-v", "error", "-ss", SEEK_SECS]);
    if let Some(t) = bearer {
        c.args(["-headers", &format!("Authorization: Bearer {t}\r\n")]);
    }
    c.args([
        "-i",
        target,
        "-frames:v",
        "5",
        "-fflags",
        "+bitexact",
        "-f",
        "framemd5",
        "-",
    ]);
    let out = run(&mut c);
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(
        s.lines().filter(|l| !l.starts_with('#')).count() == 5,
        "want 5 frames: {s}"
    );
    s
}

/// Byte offset of the first keyframe at or after the seek point (from the local file).
fn keyframe_offset(local: &Path) -> u64 {
    let out = run(Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-select_streams",
            "v",
            "-show_entries",
            "packet=pts_time,pos,flags",
            "-of",
            "csv=p=0",
        ])
        .arg(local));
    let seek: f64 = SEEK_SECS.parse().unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            let t: f64 = f.first()?.parse().ok()?;
            let pos: u64 = f.get(1)?.parse().ok()?;
            (t >= seek && f.get(2)?.starts_with('K')).then_some(pos)
        })
        .next()
        .expect("a keyframe after the seek point")
}

/// Cached block indices (from the LRU's `ino<I>_blk<B>.blk` files).
fn cached_blocks(cache: &Path) -> Vec<u64> {
    let mut v: Vec<u64> = std::fs::read_dir(cache)
        .map(|d| {
            d.filter_map(|e| {
                let n = e.ok()?.file_name().into_string().ok()?;
                n.strip_suffix(".blk")?.rsplit("_blk").next()?.parse().ok()
            })
            .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    v
}

struct Gateway {
    _server: parvault::gateway::GatewayIpcServerHandle,
    sock: PathBuf,
    root: [u8; 32],
}

fn token(root: &[u8; 32], caveats: Vec<Caveat>) -> CapabilityMacaroon {
    let mut nonce = [0u8; 32];
    nonce[..8].copy_from_slice(&(caveats.len() as u64 + 1).to_le_bytes());
    CapabilityMacaroon::mint(root, nonce, [0u8; 32], caveats).unwrap()
}

fn gateway(dir: &Path) -> Gateway {
    let root = [0x5Au8; 32];
    let sock = dir.join("gw.sock");
    let store = BlockStore::new(dir.join("store"), QuotaManager::new(512 * MIB, 64 * MIB)).unwrap();
    let server = GatewayIpcServer::new(&sock, store, MasterKey::generate())
        .with_profile(HardwareProfile::RouterSoc)
        .with_tier(ErasureTier::Consumer)
        .with_macaroon_root_key(root)
        .with_require_sealed_ingest_memfd(true)
        .spawn()
        .expect("spawn gateway");
    Gateway {
        _server: server,
        sock,
        root,
    }
}

/// Ingests `seed` with a write token, then serves reads with a ReadOnly token (as the daemon's
/// built-in VFS does).
fn reader_vfs(gw: &Gateway, cache: &Path, seed: &Path) -> VirtualVaultFs {
    let vfs = VirtualVaultFs::new(&gw.sock, cache, CACHE_BYTES)
        .unwrap()
        .with_default_macaroon(Some(token(&gw.root, Vec::new())));
    assert_eq!(vfs.ingest_local_directory(seed).unwrap(), 1);
    let vfs = vfs.with_default_macaroon(Some(token(&gw.root, vec![Caveat::ReadOnly])));
    assert_eq!(
        vfs.cache_stats().misses,
        0,
        "ingest must not warm the read cache"
    );
    vfs
}

/// A real kernel FUSE mount via `fusermount3`'s `_FUSE_COMMFD` handshake (no root, no unsafe).
struct Mount {
    dir: PathBuf,
}

impl Mount {
    fn new(dir: PathBuf) -> (Self, File) {
        std::fs::create_dir_all(&dir).unwrap();
        let (ours, theirs) = UnixStream::pair().unwrap();
        let status = Command::new("fusermount3")
            .args(["-o", "ro,fsname=parvault,subtype=parvault", "--"])
            .arg(&dir)
            .env("_FUSE_COMMFD", "0")
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .status()
            .expect("spawn fusermount3");
        assert!(status.success(), "fusermount3 mount failed");
        let mut b = [0u8; 1];
        let (_, fd) = recvmsg_scm_rights(ours.as_fd(), &mut b).expect("receive /dev/fuse fd");
        (
            Self { dir },
            File::from(fd.expect("fusermount3 sent no fd")),
        )
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = Command::new("fusermount3")
            .args(["-u", "-z", "--"])
            .arg(&self.dir)
            .status();
    }
}

#[test]
fn fuse_mount_mp4_probe_and_random_seek() {
    if !prerequisites("fuse_mount_mp4_probe_and_random_seek", true) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let clip = make_clip(tmp.path());
    let gw = gateway(tmp.path());
    let cache = tmp.path().join("cache");
    let vfs = reader_vfs(&gw, &cache, clip.parent().unwrap());
    let (mount, dev) = Mount::new(tmp.path().join("mnt"));
    let serving = vfs.clone();
    let server = std::thread::spawn(move || serving.serve_fuse_fd_blocking(dev));
    let on_mount = mount.dir.join("clip.mp4");
    let target = on_mount.to_str().unwrap();
    let blocks_total = std::fs::metadata(&clip).unwrap().len().div_ceil(MIB);

    // A1: probe reads only the header blocks.
    assert_probe_ok(&probe(target, None));
    let s = vfs.cache_stats();
    let fetched = cached_blocks(&cache);
    eprintln!(
        "A1 probe: misses={} hits={} blocks={fetched:?} of {blocks_total}",
        s.misses, s.hits
    );
    assert!(
        s.misses <= 2,
        "probe fetched {} blocks: {fetched:?}",
        s.misses
    );
    assert!(
        fetched.iter().all(|b| *b < 2),
        "probe hydrated a middle stripe: {fetched:?}"
    );

    // A3: cold time-to-first-byte at the mid keyframe.
    let pos = keyframe_offset(&clip);
    let f = File::open(&on_mount).unwrap();
    let mut buf = vec![0u8; 4096];
    let t0 = Instant::now();
    f.read_exact_at(&mut buf, pos).unwrap();
    let ttfb = t0.elapsed();
    let mut want = vec![0u8; 4096];
    File::open(&clip)
        .unwrap()
        .read_exact_at(&mut want, pos)
        .unwrap();
    assert_eq!(buf, want, "bytes at the keyframe differ");
    eprintln!("A3 cold TTFB at offset {pos}: {ttfb:?}");
    assert_budget(
        "cold FUSE TTFB within budget",
        ttfb < ttfb_budget(),
        format!("{ttfb:?}"),
    );

    // A2: random seek decodes the same frames as the local file, within the cache cap.
    assert_eq!(
        framemd5(target, None),
        framemd5(clip.to_str().unwrap(), None)
    );
    let s = vfs.cache_stats();
    eprintln!(
        "A2 seek: misses={} used={} cap={}",
        s.misses, s.used_bytes, s.capacity_bytes
    );
    assert!(s.used_bytes <= s.capacity_bytes);
    assert!(
        s.misses < blocks_total,
        "the seek pulled the whole file ({} misses)",
        s.misses
    );

    drop(f);
    drop(mount);
    server
        .join()
        .unwrap()
        .expect("FUSE loop ends cleanly on unmount");
}

#[test]
fn webdav_206_mp4_probe_and_random_seek() {
    if !prerequisites("webdav_206_mp4_probe_and_random_seek", false) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let clip = make_clip(tmp.path());
    let gw = gateway(tmp.path());
    let cache = tmp.path().join("cache");
    let vfs = reader_vfs(&gw, &cache, clip.parent().unwrap());
    let handle = vfs
        .spawn_webdav_server("127.0.0.1:0", WebdavVerifier::RootKey(gw.root))
        .unwrap();
    let url = format!("http://{}/clip.mp4", handle.local_addr());
    let bearer = token(&gw.root, vec![Caveat::ReadOnly]).to_compact_token();

    // B1: no token, no probe (F-43); then the ReadOnly token probes with only header blocks.
    assert!(
        !probe(&url, None).status.success(),
        "probe without a token must fail"
    );
    assert_probe_ok(&probe(&url, Some(&bearer)));
    let s = vfs.cache_stats();
    let fetched = cached_blocks(&cache);
    eprintln!("B1 probe: misses={} blocks={fetched:?}", s.misses);
    assert!(
        s.misses <= 2,
        "probe fetched {} blocks: {fetched:?}",
        s.misses
    );
    assert!(
        fetched.iter().all(|b| *b < 2),
        "probe hydrated a middle stripe: {fetched:?}"
    );

    // B3: cold time-to-first-byte of a Range request at the mid keyframe (the HTTP hop is what
    // the Docker gate's netem stage delays).
    let pos = keyframe_offset(&clip);
    let mut conn = std::net::TcpStream::connect(handle.local_addr()).unwrap();
    let t0 = Instant::now();
    std::io::Write::write_all(
        &mut conn,
        format!(
            "GET /clip.mp4 HTTP/1.1\r\nHost: gate\r\nRange: bytes={pos}-{}\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n\r\n",
            pos + 4095
        )
        .as_bytes(),
    )
    .unwrap();
    let mut first = [0u8; 1];
    std::io::Read::read_exact(&mut conn, &mut first).unwrap();
    let ttfb = t0.elapsed();
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut conn, &mut rest).unwrap();
    let mut resp = first.to_vec();
    resp.extend(rest);
    let split = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP head");
    assert!(
        resp.starts_with(b"HTTP/1.1 206"),
        "{}",
        String::from_utf8_lossy(&resp[..split])
    );
    let mut want = vec![0u8; 4096];
    File::open(&clip)
        .unwrap()
        .read_exact_at(&mut want, pos)
        .unwrap();
    assert_eq!(&resp[split + 4..], &want[..], "Range body differs");
    eprintln!("B3 cold WebDAV TTFB at offset {pos}: {ttfb:?}");
    assert_budget(
        "cold WebDAV TTFB within budget",
        ttfb < ttfb_budget(),
        format!("{ttfb:?}"),
    );

    // B2: random seek over HTTP Range.
    assert_eq!(
        framemd5(&url, Some(&bearer)),
        framemd5(clip.to_str().unwrap(), None)
    );
    let s = vfs.cache_stats();
    assert!(s.used_bytes <= s.capacity_bytes);
}

/// The standalone `parvault-fuse mount-fd` plugin process: same probe and seek, peak RSS < 16 MiB.
/// It ingests with a write token (`mount-fd` allows one; a ReadOnly plugin cannot ingest, R-3).
#[test]
fn parvault_fuse_plugin_mount_rss_under_16_mib() {
    if !prerequisites("parvault_fuse_plugin_mount_rss_under_16_mib", true) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let clip = make_clip(tmp.path());
    let gw = gateway(tmp.path());
    let (mount, dev) = Mount::new(tmp.path().join("mnt"));
    // The plugin refuses fds 0-2 as /dev/fuse, so a shell moves the fd from stdin to 3.
    let mut plugin = Command::new("sh")
        .args(["-c", "exec 3<&0 0</dev/null; exec \"$@\"", "sh"])
        .arg(plugin_bin())
        .arg("--socket")
        .arg(&gw.sock)
        .arg("--cache-dir")
        .arg(tmp.path().join("plugin-cache"))
        .args([
            "--cache-mib",
            "3",
            "--macaroon",
            &token(&gw.root, Vec::new()).to_compact_token(),
        ])
        .args(["mount-fd", "--fuse-fd", "3", "--seed-dir"])
        .arg(clip.parent().unwrap())
        .stdin(Stdio::from(OwnedFd::from(dev)))
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn parvault-fuse");
    let on_mount = mount.dir.join("clip.mp4");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !on_mount.exists() {
        assert!(
            Instant::now() < deadline,
            "the plugin never exposed clip.mp4"
        );
        if plugin.try_wait().unwrap().is_some() {
            let mut err = String::new();
            std::io::Read::read_to_string(plugin.stderr.as_mut().unwrap(), &mut err).unwrap();
            panic!("the plugin exited early: {err}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let target = on_mount.to_str().unwrap();
    assert_probe_ok(&probe(target, None));
    assert_eq!(
        framemd5(target, None),
        framemd5(clip.to_str().unwrap(), None)
    );
    let status = std::fs::read_to_string(format!("/proc/{}/status", plugin.id())).unwrap();
    let hwm_kib: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmHWM");
    eprintln!("plugin peak RSS: {hwm_kib} KiB");
    drop(mount);
    let _ = plugin.wait_timeout_or_kill();
    assert_budget(
        "plugin peak RSS < 16 MiB",
        hwm_kib < 16 * 1024,
        format!("{hwm_kib} KiB"),
    );
}

trait WaitOrKill {
    fn wait_timeout_or_kill(&mut self) -> std::io::Result<()>;
}

impl WaitOrKill for std::process::Child {
    fn wait_timeout_or_kill(&mut self) -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.try_wait()?.is_none() {
            if Instant::now() > deadline {
                self.kill()?;
                self.wait()?;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }
}
