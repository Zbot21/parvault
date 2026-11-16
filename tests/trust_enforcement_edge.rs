//! `v0.5.6` track A suite: the HTTP edge, TLS and the read-only WebDAV server (plan Section 3.1).
//! Claims of track A (`B1-PLAIN`, `B1-KEY`, `B1-PAIR`, F-43 over TLS) put their differential pairs
//! here; `tests/trust_enforcement.rs` is frozen.
//!
//! Real binaries and real sockets only: `parvault up` with its edges, `parvault-fuse webdav`, and
//! a rustls client that trusts the exported certificate (`tests/edge_common`).
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.
#![cfg(target_os = "linux")]

mod common;
mod edge_common;

use edge_common::{
    default_client, export_cert, init_node, parvault_out, pattern, req, tls_once, up, up_refused,
    write_seed, Tls,
};

use parvault::capabilities::{CapabilityMacaroon, Caveat};
use parvault::config::{ErasureTier, HardwareProfile};
use parvault::crypto::MasterKey;
use parvault::gateway::GatewayIpcServer;
use parvault::storage::{BlockStore, QuotaManager};
use parvault::vfs::{VfsWebdavServerHandle, VirtualVaultFs, WebdavVerifier};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

const MIB: u64 = 1024 * 1024;
const ROOT: [u8; 32] = [0x5C; 32];

fn token(caveats: Vec<Caveat>) -> CapabilityMacaroon {
    let mut nonce = [0u8; 32];
    nonce[0] = caveats.len() as u8 + 1;
    CapabilityMacaroon::mint(&ROOT, nonce, [0u8; 32], caveats).unwrap()
}

fn content() -> Vec<u8> {
    (0..64 * 1024u32).map(|i| (i * 7 + 3) as u8).collect()
}

/// A one-file vault behind a ReadOnly WebDAV edge (the built-in server, in-process gateway).
fn edge(
    dir: &Path,
) -> (
    parvault::gateway::GatewayIpcServerHandle,
    VirtualVaultFs,
    VfsWebdavServerHandle,
) {
    let sock = dir.join("gw.sock");
    let store = BlockStore::new(dir.join("store"), QuotaManager::new(512 * MIB, 64 * MIB)).unwrap();
    let server = GatewayIpcServer::new(&sock, store, MasterKey::generate())
        .with_profile(HardwareProfile::RouterSoc)
        .with_tier(ErasureTier::Consumer)
        .with_macaroon_root_key(ROOT)
        .with_require_sealed_ingest_memfd(true)
        .spawn()
        .unwrap();
    let seed = dir.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    std::fs::write(seed.join("f.bin"), content()).unwrap();
    let bus = parvault::gateway::GatewayBus::unix_socket(&sock).with_token_source(Some(
        std::sync::Arc::new(parvault::capabilities::GatewayTokenSource::Fixed(token(
            Vec::new(),
        ))),
    ));
    let vfs = VirtualVaultFs::with_bus(bus, dir.join("cache"), 8 * MIB)
        .unwrap()
        .with_default_macaroon(Some(token(Vec::new())));
    assert_eq!(vfs.ingest_local_directory(&seed).unwrap(), 1);
    let vfs = vfs.with_default_macaroon(Some(token(vec![Caveat::ReadOnly])));
    let handle = vfs
        .spawn_webdav_server("127.0.0.1:0", WebdavVerifier::RootKey(ROOT))
        .unwrap();
    (server, vfs, handle)
}

/// Sends `requests` in one write and reads until the server closes.
fn exchange(addr: std::net::SocketAddr, requests: &str) -> String {
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    c.write_all(requests.as_bytes()).unwrap();
    let mut resp = Vec::new();
    c.read_to_end(&mut resp)
        .expect("the server closes after the last request it has");
    String::from_utf8_lossy(&resp).into_owned()
}

/// The status codes of the responses, read in sequence by their `Content-Length` (`HEAD` is not
/// sent here, so every body is as long as its header says).
fn statuses(resp: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(end) = resp[pos..].find("\r\n\r\n").map(|e| pos + e) {
        let head = &resp[pos..end];
        out.push(&head[9..12]);
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        pos = end + 4 + len;
        if pos >= resp.len() {
            break;
        }
    }
    out
}

/// A-TLS-4: two pipelined requests in one write are both answered (the remainder of the first
/// head is no longer dropped), a request body is skipped exactly, and the connection closes when
/// no further request is buffered.
#[test]
fn pipelined_requests_in_one_write_are_all_answered() {
    let tmp = tempfile::tempdir().unwrap();
    let (_gw, _vfs, handle) = edge(tmp.path());
    let bearer = token(vec![Caveat::ReadOnly]).to_compact_token();
    let body = "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:allprop/></D:propfind>";
    let reqs = format!(
        "OPTIONS / HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {bearer}\r\n\r\n\
         PROPFIND / HTTP/1.1\r\nHost: t\r\nDepth: 1\r\nAuthorization: Bearer {bearer}\r\nContent-Length: {}\r\n\r\n{body}\
         GET /f.bin HTTP/1.1\r\nHost: t\r\nRange: bytes=0-9\r\nAuthorization: Bearer {bearer}\r\n\r\n",
        body.len()
    );
    let resp = exchange(handle.local_addr(), &reqs);
    assert_eq!(statuses(&resp), vec!["200", "207", "206"], "{resp}");
    assert!(resp.contains("DAV: 1"), "{resp}");
    assert!(resp.contains("<D:href>/f.bin</D:href>"), "{resp}");
    let tail = resp.rsplit("\r\n\r\n").next().unwrap();
    assert_eq!(tail.as_bytes(), &content()[..10], "206 body");
    gate_ran("trust_enforcement_edge::pipelined_requests_in_one_write_are_all_answered");
}

/// A refusal closes the connection (A-TLS-5): a pipelined request behind a 401 is not served;
/// `Connection: close` ends the connection after its answer.
#[test]
fn pipelining_stops_at_a_refusal_and_at_connection_close() {
    let tmp = tempfile::tempdir().unwrap();
    let (_gw, _vfs, handle) = edge(tmp.path());
    let bearer = token(vec![Caveat::ReadOnly]).to_compact_token();
    let good = format!("OPTIONS / HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {bearer}\r\n\r\n");
    let refused = exchange(
        handle.local_addr(),
        &format!("OPTIONS / HTTP/1.1\r\nHost: t\r\n\r\n{good}"),
    );
    assert_eq!(statuses(&refused), vec!["401"], "{refused}");
    let closed = exchange(
        handle.local_addr(),
        &format!(
            "OPTIONS / HTTP/1.1\r\nHost: t\r\nConnection: close\r\nAuthorization: Bearer {bearer}\r\n\r\n{good}"
        ),
    );
    assert_eq!(statuses(&closed), vec!["200"], "{closed}");
    let one = exchange(handle.local_addr(), &good);
    assert_eq!(statuses(&one), vec!["200"], "{one}");
    gate_ran("trust_enforcement_edge::pipelining_stops_at_a_refusal_and_at_connection_close");
}

// --- B1-PLAIN-FUSE (L-81, A-TLS-3): the plugin loads PEM; plain only on loopback or opt-out -----

/// An edge PEM file (certificate, key, SANs) in `dir`, mode 0600, as the daemon writes it.
fn pem_file(dir: &Path, name: &str, sans: &[&str]) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let sans: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let pem = parvault::edge_tls::generate_pem(&sans).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, pem).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn fuse_webdav(dir: &Path, listen: &str, extra: &[&str]) -> std::process::Child {
    let bin = common::plugin_bin("parvault-fuse", env!("CARGO_BIN_EXE_parvault-fuse"));
    let log = std::fs::File::create(dir.join("fuse.log")).unwrap();
    std::process::Command::new(bin)
        .arg("--socket")
        .arg(dir.join("no-daemon.sock"))
        .arg("--cache-dir")
        .arg(dir.join("cache"))
        .arg("--macaroon")
        .arg(token(vec![Caveat::ReadOnly]).to_compact_token())
        .args(["webdav", "--listen", listen])
        .args(extra)
        .stdout(std::process::Stdio::from(log.try_clone().unwrap()))
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .unwrap()
}

fn wait_log(path: &Path, marker: &str, child: &mut std::process::Child) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.contains(marker) {
            return text;
        }
        if let Ok(Some(st)) = child.try_wait() {
            return format!("EXITED {st}\n{text}");
        }
        assert!(Instant::now() < deadline, "no {marker:?} in:\n{text}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn served_port(text: &str) -> u16 {
    let rest = text.split("WebDAV VFS on ").nth(1).unwrap();
    let url = rest.split_whitespace().next().unwrap();
    url.rsplit(':').next().unwrap().parse().unwrap()
}

/// B1-PLAIN-FUSE accept: `parvault-fuse webdav` on a non-loopback bind with `--tls-pem` serves
/// TLS (it loads the PEM and generates nothing); `OPTIONS` with the pinned token answers `DAV: 1`.
#[test]
fn b1_fuse_tls_nonloopback_serves() {
    let tmp = tempfile::tempdir().unwrap();
    let pem = pem_file(tmp.path(), "edge.pem", &["127.0.0.1"]);
    let mut child = fuse_webdav(
        tmp.path(),
        "0.0.0.0:0",
        &["--tls-pem", pem.to_str().unwrap()],
    );
    let text = wait_log(
        &tmp.path().join("fuse.log"),
        "WebDAV VFS on https://",
        &mut child,
    );
    assert!(!text.starts_with("EXITED"), "{text}");
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", served_port(&text)).parse().unwrap();
    let der = edge_common::leaf_der_of(&std::fs::read(&pem).unwrap());
    let bearer = token(vec![Caveat::ReadOnly]).to_compact_token();
    let r = tls_once(
        addr,
        &default_client(&der),
        &req("OPTIONS", "/", addr, Some(&bearer), ""),
    );
    assert_eq!(r.status(), 200, "{}", r.head);
    assert!(r.head.contains("DAV: 1"), "{}", r.head);
    assert_eq!(
        std::fs::read_dir(tmp.path())
            .unwrap()
            .filter(|e| e
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("edge_tls"))
            .count(),
        0,
        "a plugin never makes a certificate"
    );
    let _ = child.kill();
    let _ = child.wait();
    gate_ran("trust_enforcement_edge::b1_fuse_tls_nonloopback_serves");
}

/// B1-PLAIN-FUSE reject: without `--tls-pem` a non-loopback bind refuses to start with
/// `reject.edge_plain_http_nonloopback`; loopback plain and the opt-out still serve.
#[test]
fn b1_fuse_plain_nonloopback_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let mut child = fuse_webdav(tmp.path(), "0.0.0.0:0", &[]);
    let status = child.wait().unwrap();
    let text = std::fs::read_to_string(tmp.path().join("fuse.log")).unwrap();
    assert!(!status.success(), "{text}");
    assert!(
        text.contains("reject.edge_plain_http_nonloopback"),
        "{text}"
    );
    for (listen, extra) in [
        ("127.0.0.1:0", &[][..]),
        ("0.0.0.0:0", &["--insecure-plain-http"][..]),
    ] {
        let sub = tmp.path().join(listen.replace([':', '.'], "_"));
        std::fs::create_dir_all(&sub).unwrap();
        let mut c = fuse_webdav(&sub, listen, extra);
        let t = wait_log(&sub.join("fuse.log"), "WebDAV VFS on http://", &mut c);
        assert!(!t.starts_with("EXITED"), "{listen}: {t}");
        let _ = c.kill();
        let _ = c.wait();
    }
    gate_ran("trust_enforcement_edge::b1_fuse_plain_nonloopback_refused");
}

// --- The daemon's TLS edge: B1-KEY, B1-PAIR, A-TLS-5 to 9 ---------------------------------------

const F_LEN: usize = 300 * 1024;

/// A daemon with WebDAV on `0.0.0.0:0` (TLS by default, L-81) and one seeded file `f.bin`.
fn tls_daemon(dir: &Path, extra: &[&str]) -> edge_common::Daemon {
    init_node(dir);
    let seed = write_seed(dir, &[("f.bin", pattern(F_LEN, 1))]);
    let mut args = vec![
        "--vfs-webdav-listen",
        "0.0.0.0:0",
        "--vfs-seed-dir",
        seed.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    // The seed dir lives in the data dir's parent-free path; leak the String into the args.
    let d = up(dir, &args);
    assert_eq!(edge_common::webdav_scheme(&d), "https");
    d
}

/// B1-KEY and B1-PAIR accept: the first `up` with a non-loopback WebDAV bind makes one owner-only
/// file holding the pair; it serves TLS with it (PROPFIND 207, a Range GET 206, `tls show` names
/// the exported certificate); a `--tls-san` name passes the Host check and an unknown name is
/// 403 (A-TLS-7); plain HTTP to the TLS port gets no HTTP answer; a second start keeps the
/// fingerprint (never auto-reissued).
#[test]
fn b1_daemon_tls_owner_only_pair_served() {
    use sha2::Digest;
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let mut d = tls_daemon(&dir, &["--tls-san", "nas.local"]);
    let meta = std::fs::metadata(dir.join("edge_tls.pem")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let (_, der) = export_cert(&dir);
    let (ok, show) = parvault_out(&dir, &["tls", "show"]);
    assert!(ok, "{show}");
    let fp = parvault::edge_tls::colon_hex(&sha2::Sha256::digest(&der));
    assert!(show.contains(&fp), "{show}");
    assert!(
        show.contains("nas.local") && show.contains("127.0.0.1"),
        "{show}"
    );
    let addr = d.webdav_lo();
    let cfg = default_client(&der);
    let t = d.read_token();
    let r = tls_once(
        addr,
        &cfg,
        &req("PROPFIND", "/", addr, Some(&t), "Depth: 1\r\n"),
    );
    assert_eq!(r.status(), 207, "{}", r.head);
    assert!(r.text().contains("<D:href>/f.bin</D:href>"), "{}", r.text());
    let r = tls_once(
        addr,
        &cfg,
        &req("GET", "/f.bin", addr, Some(&t), "Range: bytes=10-19\r\n"),
    );
    assert_eq!(r.status(), 206, "{}", r.head);
    assert_eq!(r.body, pattern(F_LEN, 1)[10..20]);
    let named = format!("nas.local:{}", addr.port());
    let r = tls_once(
        addr,
        &cfg,
        &format!("OPTIONS / HTTP/1.1\r\nHost: {named}\r\nAuthorization: Bearer {t}\r\n\r\n"),
    );
    assert_eq!(r.status(), 200, "{}", r.head);
    let r = tls_once(
        addr,
        &cfg,
        &format!(
            "OPTIONS / HTTP/1.1\r\nHost: rebind.example:{}\r\nAuthorization: Bearer {t}\r\n\r\n",
            addr.port()
        ),
    );
    assert_eq!(r.status(), 403, "{}", r.head);
    // Plain HTTP to the TLS port: no HTTP response.
    let mut plain = TcpStream::connect(addr).unwrap();
    plain
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    plain
        .write_all(req("OPTIONS", "/", addr, Some(&t), "").as_bytes())
        .unwrap();
    let mut got = Vec::new();
    let _ = plain.read_to_end(&mut got);
    assert!(
        !String::from_utf8_lossy(&got).contains("HTTP/1."),
        "{got:?}"
    );
    d.kill();
    let d2 = up(&dir, &["--vfs-webdav-listen", "0.0.0.0:0"]);
    let (_, der2) = export_cert(&dir);
    assert_eq!(der2, der, "the certificate is never re-issued on its own");
    drop(d2);
    gate_ran("trust_enforcement_edge::b1_daemon_tls_owner_only_pair_served");
}

/// B1-KEY reject (A-TLS-8): a group-readable edge file, or a symlink to one, refuses the start
/// with `reject.tls_key_mode`; the file is not replaced.
#[test]
fn b1_key_group_readable_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    init_node(&dir);
    let p = pem_file(&dir, "edge_tls.pem", &["127.0.0.1"]);
    let before = std::fs::read(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    let out = up_refused(&dir, &["--vfs-webdav-listen", "0.0.0.0:0"]);
    assert!(out.contains("reject.tls_key_mode"), "{out}");
    assert_eq!(std::fs::read(&p).unwrap(), before, "never replaced");
    std::fs::rename(&p, dir.join("real.pem")).unwrap();
    std::fs::set_permissions(dir.join("real.pem"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(dir.join("real.pem"), &p).unwrap();
    let out = up_refused(&dir, &["--vfs-webdav-listen", "0.0.0.0:0"]);
    assert!(out.contains("reject.tls_key_mode"), "{out}");
    gate_ran("trust_enforcement_edge::b1_key_group_readable_refused");
}

/// B1-PAIR reject: a file whose certificate and key come from two issues refuses the start with
/// `reject.tls_key_cert_mismatch`.
#[test]
fn b1_pair_mismatch_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    init_node(&dir);
    let a = parvault::edge_tls::generate_pem(&["127.0.0.1".into()]).unwrap();
    let b = parvault::edge_tls::generate_pem(&["127.0.0.1".into()]).unwrap();
    let cert_a = &a[..a.find("-----BEGIN PRIVATE KEY-----").unwrap()];
    let key_b = &b[b.find("-----BEGIN PRIVATE KEY-----").unwrap()..];
    let p = dir.join("edge_tls.pem");
    std::fs::write(&p, format!("{cert_a}{key_b}")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = up_refused(&dir, &["--vfs-webdav-listen", "0.0.0.0:0"]);
    assert!(out.contains("reject.tls_key_cert_mismatch"), "{out}");
    gate_ran("trust_enforcement_edge::b1_pair_mismatch_refused");
}

/// A-TLS-8: SIGKILL at any point of `tls rotate` leaves a loadable pair (the old or the new), and
/// the next start serves it.
#[test]
fn sigkill_mid_rotate_keeps_a_pair() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    init_node(&dir);
    pem_file(&dir, "edge_tls.pem", &["127.0.0.1"]);
    for i in 0..20u64 {
        let mut c = edge_common::parvault_cmd(&dir)
            .args(["tls", "rotate"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis((i * 7) % 60));
        let _ = c.kill();
        let _ = c.wait();
        let (ok, show) = parvault_out(&dir, &["tls", "show"]);
        assert!(ok, "after kill {i}: {show}");
    }
    let d = up(&dir, &["--vfs-webdav-listen", "0.0.0.0:0"]);
    assert_eq!(edge_common::webdav_scheme(&d), "https");
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp.edge_tls"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    gate_ran("trust_enforcement_edge::sigkill_mid_rotate_keeps_a_pair");
}

/// A-TLS-5: keep-alive only after auth. 50 requests on one TLS connection are all answered;
/// a bad token mid-connection gets the 401 and the close. An unauthenticated first request
/// (WebClient's `OPTIONS`) gets the 401 with the Basic challenge and the close.
#[test]
fn keepalive_after_auth_then_bad_token_closes() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let d = tls_daemon(&dir, &[]);
    let (_, der) = export_cert(&dir);
    let cfg = default_client(&der);
    let addr = d.webdav_lo();
    let t = d.read_token();
    let mut c = Tls::connect(addr, &cfg).unwrap();
    for i in 0..50 {
        let (m, path, extra) = match i % 3 {
            0 => ("OPTIONS", "/", ""),
            1 => ("PROPFIND", "/", "Depth: 1\r\n"),
            _ => ("GET", "/f.bin", "Range: bytes=0-99\r\n"),
        };
        c.send(&req(m, path, addr, Some(&t), extra)).unwrap();
        let r = c
            .response(false)
            .unwrap_or_else(|| panic!("request {i} unanswered"));
        assert!(matches!(r.status(), 200 | 206 | 207), "{i}: {}", r.head);
    }
    let forged = edge_common::mint(&[9; 32], vec![Caveat::ReadOnly]);
    c.send(&req("OPTIONS", "/", addr, Some(&forged), ""))
        .unwrap();
    let r = c.response(false).unwrap();
    assert_eq!(r.status(), 401);
    assert!(c.response(false).is_none(), "closed after the 401");
    let mut u = Tls::connect(addr, &cfg).unwrap();
    u.send(&req("OPTIONS", "/", addr, None, "")).unwrap();
    let r = u.response(false).unwrap();
    assert_eq!(r.status(), 401);
    assert!(
        r.head
            .contains("WWW-Authenticate: Basic realm=\"parvault-webdav\""),
        "{}",
        r.head
    );
    u.send(&req("OPTIONS", "/", addr, Some(&t), "")).ok();
    assert!(
        u.response(false).is_none(),
        "closed after the unauthenticated 401"
    );
    gate_ran("trust_enforcement_edge::keepalive_after_auth_then_bad_token_closes");
}

/// A-TLS-5: at most 100 requests per connection.
#[test]
fn keepalive_caps_at_100_requests() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let d = tls_daemon(&dir, &[]);
    let (_, der) = export_cert(&dir);
    let addr = d.webdav_lo();
    let t = d.read_token();
    let mut c = Tls::connect(addr, &default_client(&der)).unwrap();
    let mut answered = 0;
    for _ in 0..101 {
        if c.send(&req("OPTIONS", "/", addr, Some(&t), "")).is_err() {
            break;
        }
        match c.response(false) {
            Some(r) if r.status() == 200 => answered += 1,
            _ => break,
        }
    }
    assert_eq!(answered, 100);
    gate_ran("trust_enforcement_edge::keepalive_caps_at_100_requests");
}

/// A-TLS-5: a stalled handshake and a handshake with no request are both closed within the
/// pre-auth deadline (5 s), so an unauthenticated peer never holds a slot past it; 8 idle
/// authenticated connections from one IP take that IP's slots and the 9th is dropped, while
/// another IP is still served.
#[test]
fn slots_and_pre_auth_deadline_hold_under_tls() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    init_node(&dir);
    let seed = write_seed(&dir, &[("f.bin", pattern(1024, 2))]);
    let d = up(
        &dir,
        &[
            "--vfs-webdav-listen",
            "[::]:0",
            "--vfs-seed-dir",
            seed.to_str().unwrap(),
        ],
    );
    let (_, der) = export_cert(&dir);
    let cfg = default_client(&der);
    let port = d.webdav.unwrap().port();
    let v4: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let v6: std::net::SocketAddr = format!("[::1]:{port}").parse().unwrap();
    // Stalled handshake: closed by the deadline.
    let start = Instant::now();
    let mut stalled = TcpStream::connect(v4).unwrap();
    stalled
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut b = [0u8; 8];
    let _ = stalled.read(&mut b);
    let waited = start.elapsed();
    assert!(
        waited >= Duration::from_secs(4) && waited < Duration::from_secs(8),
        "{waited:?}"
    );
    // Handshake, then no request.
    let start = Instant::now();
    let mut idle = Tls::connect(v4, &cfg).unwrap();
    assert!(idle.response(false).is_none());
    assert!(
        start.elapsed() < Duration::from_secs(8),
        "{:?}",
        start.elapsed()
    );
    // 8 authenticated idle connections from 127.0.0.1.
    let t = d.read_token();
    let mut held = Vec::new();
    for _ in 0..8 {
        let mut c = Tls::connect(v4, &cfg).unwrap();
        c.send(&req("OPTIONS", "/", v4, Some(&t), "")).unwrap();
        assert_eq!(c.response(false).unwrap().status(), 200);
        held.push(c);
    }
    let ninth = Tls::connect(v4, &cfg).and_then(|mut c| {
        c.send(&req("OPTIONS", "/", v4, Some(&t), ""))?;
        c.response(false)
            .ok_or_else(|| std::io::ErrorKind::ConnectionReset.into())
    });
    assert!(ninth.is_err(), "the 9th connection from one IP is dropped");
    let r = tls_once(v6, &cfg, &req("OPTIONS", "/", v6, Some(&t), ""));
    assert_eq!(r.status(), 200, "another IP is served");
    drop(held);
    gate_ran("trust_enforcement_edge::slots_and_pre_auth_deadline_hold_under_tls");
}

/// A-TLS-9: TLS 1.2 is kept (an ECDHE-ECDSA suite); TLS 1.0 and 1.1 get no ServerHello.
#[test]
fn tls12_kept_and_tls10_11_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let d = tls_daemon(&dir, &[]);
    let (_, der) = export_cert(&dir);
    let addr = d.webdav_lo();
    let t = d.read_token();
    let cfg12 = edge_common::client_config(&der, &[&rustls::version::TLS12]);
    let mut c = Tls::connect(addr, &cfg12).unwrap();
    assert_eq!(
        c.s.conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    let suite = format!("{:?}", c.s.conn.negotiated_cipher_suite().unwrap().suite());
    assert!(suite.starts_with("TLS_ECDHE_ECDSA_"), "{suite}");
    c.send(&req("OPTIONS", "/", addr, Some(&t), "")).unwrap();
    assert_eq!(c.response(false).unwrap().status(), 200);
    for version in [[3u8, 1], [3, 2]] {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        s.write_all(&legacy_client_hello(version)).unwrap();
        let mut got = Vec::new();
        let _ = s.read_to_end(&mut got);
        // A handshake record (0x16) carrying a ServerHello (type 2) would mean it was accepted.
        assert!(
            !(got.len() > 5 && got[0] == 0x16 && got[5] == 0x02),
            "{version:?}: {got:?}"
        );
    }
    gate_ran("trust_enforcement_edge::tls12_kept_and_tls10_11_refused");
}

/// A minimal TLS 1.0/1.1 ClientHello (no supported_versions extension).
fn legacy_client_hello(version: [u8; 2]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version);
    body.extend_from_slice(&[0x11; 32]); // random
    body.push(0); // session id
    body.extend_from_slice(&[0, 4, 0xc0, 0x09, 0xc0, 0x13]); // ECDHE_ECDSA/RSA AES128 CBC SHA
    body.extend_from_slice(&[1, 0]); // compression: null
    let mut hs = vec![1, 0, 0, body.len() as u8];
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1, 0, hs.len() as u8];
    rec.extend_from_slice(&hs);
    rec
}

/// A-TLS-2: QUIC (libp2p's rustls) and the edge TLS listener come up in one daemon: neither
/// installs a process-wide provider.
#[test]
fn quic_and_edge_tls_in_one_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    init_node(&dir);
    let cfg = tmp.path().join("quic.toml");
    std::fs::write(
        &cfg,
        "enable_quic = true\nlisten_quic = \"/ip4/127.0.0.1/udp/0/quic-v1\"\n",
    )
    .unwrap();
    let d = edge_common::up_full(
        &dir,
        Some(&cfg),
        "/ip4/127.0.0.1/tcp/0",
        &["--vfs-webdav-listen", "0.0.0.0:0"],
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !d.log_text().contains("quic-v1") {
        assert!(
            Instant::now() < deadline,
            "no QUIC listener:\n{}",
            d.log_text()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let (_, der) = export_cert(&dir);
    let addr = d.webdav_lo();
    let r = tls_once(
        addr,
        &default_client(&der),
        &req("OPTIONS", "/", addr, Some(&d.read_token()), ""),
    );
    assert_eq!(r.status(), 200, "{}", r.head);
    gate_ran("trust_enforcement_edge::quic_and_edge_tls_in_one_daemon");
}

// --- Request smuggling (QA of T0): one framing for the reader and the handlers -----------------

/// A bare LF, a space before the colon, a repeated `Content-Length`, `Content-Length` with
/// `Transfer-Encoding`, and a signed length are refused; a chunked body never becomes a second
/// request.
#[test]
fn smuggling_heads_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (_gw, _vfs, handle) = edge(tmp.path());
    let addr = handle.local_addr();
    let bearer = token(vec![Caveat::ReadOnly]).to_compact_token();
    let next = format!("GET /f.bin HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {bearer}\r\n\r\n");
    for (label, head) in [
        ("bare LF", format!("OPTIONS / HTTP/1.1\r\nHost: t\nContent-Length: 0\r\nAuthorization: Bearer {bearer}\r\n\r\n")),
        ("space before colon", format!("OPTIONS / HTTP/1.1\r\nHost: t\r\nContent-Length : 5\r\nAuthorization: Bearer {bearer}\r\n\r\n")),
        ("two lengths", format!("OPTIONS / HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nContent-Length: 50\r\nAuthorization: Bearer {bearer}\r\n\r\n")),
        ("CL and TE", format!("OPTIONS / HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nAuthorization: Bearer {bearer}\r\n\r\n")),
        ("folded", format!("OPTIONS / HTTP/1.1\r\nHost: t\r\n Content-Length: 5\r\nAuthorization: Bearer {bearer}\r\n\r\n")),
    ] {
        let resp = exchange(addr, &format!("{head}{next}"));
        assert_eq!(statuses(&resp), vec!["400"], "{label}: {resp}");
    }
    // `+5` is not a length: the request is answered but nothing behind it is served.
    let resp = exchange(addr, &format!("OPTIONS / HTTP/1.1\r\nHost: t\r\nContent-Length: +5\r\nAuthorization: Bearer {bearer}\r\n\r\nabcde{next}"));
    assert_eq!(statuses(&resp), vec!["200"], "{resp}");
    let resp = exchange(addr, &format!("POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\nAuthorization: Bearer {bearer}\r\n\r\n0\r\n\r\n{next}"));
    assert_eq!(statuses(&resp), vec!["405"], "{resp}");
    gate_ran("trust_enforcement_edge::smuggling_heads_are_refused");
}

/// The same over TLS keep-alive: a chunked request closes the connection after its answer.
#[test]
fn smuggling_over_tls_keepalive_closes() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let d = tls_daemon(&dir, &[]);
    let (_, der) = export_cert(&dir);
    let addr = d.webdav_lo();
    let t = d.read_token();
    let mut c = Tls::connect(addr, &default_client(&der)).unwrap();
    let smuggled = req("GET", "/f.bin", addr, Some(&t), "");
    c.send(&format!(
        "PROPFIND / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {t}\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{smuggled}\r\n0\r\n\r\n",
        smuggled.len()
    ))
    .unwrap();
    assert_eq!(c.response(false).unwrap().status(), 207);
    assert!(c.response(false).is_none(), "nothing in the body is served");
    let mut c = Tls::connect(addr, &default_client(&der)).unwrap();
    c.send(&format!(
        "OPTIONS / HTTP/1.1\r\nHost: {addr}\nAuthorization: Bearer {t}\r\n\r\n"
    ))
    .unwrap();
    assert_eq!(c.response(false).unwrap().status(), 400);
    gate_ran("trust_enforcement_edge::smuggling_over_tls_keepalive_closes");
}

/// EDGE-FRAMING (daemon status edge): a head with a bare LF is answered 400 and logged as
/// `reject.edge_bare_lf`; the same head with CRLF is served.
#[test]
fn edge_framing_bare_lf_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    init_node(&dir);
    let d = up(&dir, &["--status-http", "127.0.0.1:0"]);
    let addr = d.status.unwrap();
    let t = d.read_token();
    let raw = |r: &str| {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(r.as_bytes()).unwrap();
        let mut got = Vec::new();
        let _ = s.read_to_end(&mut got);
        String::from_utf8_lossy(&got).into_owned()
    };
    let bad = raw(&format!(
        "GET /api/v1/health HTTP/1.1\r\nHost: {addr}\nAuthorization: Bearer {t}\r\n\r\n"
    ));
    assert!(bad.starts_with("HTTP/1.1 400 "), "{bad}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !d.log_text().contains("reject.edge_bare_lf") {
        assert!(Instant::now() < deadline, "{}", d.log_text());
        std::thread::sleep(Duration::from_millis(50));
    }
    gate_ran("trust_enforcement_edge::edge_framing_bare_lf_refused");
}

/// EDGE-FRAMING accept: the same request with CRLF line ends is served.
#[test]
fn edge_framing_crlf_served() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    init_node(&dir);
    let d = up(&dir, &["--status-http", "127.0.0.1:0"]);
    let addr = d.status.unwrap();
    let t = d.read_token();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(req("GET", "/api/v1/health", addr, Some(&t), "").as_bytes())
        .unwrap();
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 200 "), "{text}");
    // `/live` until track D builds it: 501 with the code in the body (QA of T0).
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(req("GET", "/live", addr, Some(&t), "").as_bytes())
        .unwrap();
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got);
    assert!(
        text.starts_with("HTTP/1.1 501 ") || text.starts_with("HTTP/1.1 200 "),
        "{text}"
    );
    if text.starts_with("HTTP/1.1 501 ") {
        assert!(text.contains("reject.not_built_yet"), "{text}");
    }
    gate_ran("trust_enforcement_edge::edge_framing_crlf_served");
}

// --- token mint --out (L-123 Q4) and B-180 ------------------------------------------------------

/// `token mint --out` writes the token `0600` and prints only the path; a read-only token with an
/// expiry is under 255 characters; a longer one gets the warning.
#[test]
fn token_mint_out_writes_owner_only_and_warns_long() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    init_node(&dir);
    let out = dir.join("webdav.token");
    let (ok, text) = parvault_out(
        &dir,
        &[
            "token",
            "mint",
            "--ttl-secs",
            "86400",
            "--out",
            out.to_str().unwrap(),
        ],
    );
    assert!(ok, "{text}");
    let tok = std::fs::read_to_string(&out).unwrap();
    let tok = tok.trim();
    assert!(tok.starts_with("PARVAULT-MAC-V1:"), "{tok}");
    assert!(!text.contains(tok), "the token is not printed: {text}");
    assert!(text.contains(out.to_str().unwrap()), "{text}");
    assert!(tok.len() < 255, "{}", tok.len());
    assert!(!text.contains("warning"), "{text}");
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let (ok, text) = parvault_out(
        &dir,
        &[
            "token",
            "mint",
            "--ttl-secs",
            "86400",
            "--manifest-hex",
            &"ab".repeat(32),
            "--byte-range",
            "0:4096",
            "--allow-peer-uid",
            "1000",
        ],
    );
    assert!(ok, "{text}");
    assert!(text.contains("warning: this token is"), "{text}");
    gate_ran("trust_enforcement_edge::token_mint_out_writes_owner_only_and_warns_long");
}

/// B-180: `--gateway-socket-group` gives the socket to that group with mode 0660; without it the
/// socket stays 0600; an unknown group refuses the start.
#[test]
fn b180_gateway_socket_group() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    init_node(&dir);
    let gid = std::fs::metadata(&dir).unwrap().gid();
    let sock = tmp.path().join("gw.sock");
    let wait_sock = |d: &edge_common::Daemon| {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !d.log_text().contains("Zero-Copy IPC Gateway listening") {
            assert!(Instant::now() < deadline, "{}", d.log_text());
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let gid_s = gid.to_string();
    let mut d = up(
        &dir,
        &[
            "--ipc-socket",
            sock.to_str().unwrap(),
            "--gateway-socket-group",
            &gid_s,
        ],
    );
    wait_sock(&d);
    let m = std::fs::metadata(&sock).unwrap();
    assert_eq!(m.permissions().mode() & 0o777, 0o660);
    assert_eq!(m.gid(), gid);
    d.kill();
    let mut d = up(&dir, &["--ipc-socket", sock.to_str().unwrap()]);
    wait_sock(&d);
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
        0o600
    );
    d.kill();
    let (ok, out) = parvault_out(
        &dir,
        &[
            "up",
            "--listen",
            "/ip4/127.0.0.1/tcp/0",
            "--ipc-socket",
            sock.to_str().unwrap(),
            "--gateway-socket-group",
            "no-such-group-pv",
        ],
    );
    assert!(!ok && out.contains("reject.socket_group_unknown"), "{out}");
    gate_ran("trust_enforcement_edge::b180_gateway_socket_group");
}
