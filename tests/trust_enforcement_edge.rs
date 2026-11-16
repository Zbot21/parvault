//! `v0.5.6` track A suite: the HTTP edge, TLS and the read-only WebDAV server (plan Section 3.1).
//! Claims of track A (`B1-PLAIN`, `B1-KEY`, `B1-PAIR`, F-43 over TLS) put their differential pairs
//! here; `tests/trust_enforcement.rs` is frozen.
//!
//! T0 holds the A-TLS-4 pipelining test (the one real fix of T0) and checks that each stub of
//! track A refuses with `reject.not_built_yet`; track A replaces those checks.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.
#![cfg(target_os = "linux")]

mod common;

use parvault::capabilities::{CapabilityMacaroon, Caveat};
use parvault::config::{ErasureTier, HardwareProfile};
use parvault::crypto::MasterKey;
use parvault::gateway::GatewayIpcServer;
use parvault::storage::{BlockStore, QuotaManager};
use parvault::vfs::{VfsWebdavServerHandle, VirtualVaultFs, WebdavVerifier};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

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

/// T0 stubs of track A: `tls show|export|rotate`, `token mint --out`, `up --tls-san`,
/// `up --insecure-plain-http`.
#[test]
fn track_a_unbuilt_entries_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    // `up` refuses a node in no ring before it reaches the edge; start one.
    let init = common::parvault_in(&dir, &["wot", "init"]);
    assert!(init.status.success(), "{init:?}");
    for (args, entry) in [
        (vec!["tls", "show"], "tls show"),
        (vec!["tls", "export", "--out", "x.pem"], "tls export"),
        (vec!["tls", "rotate"], "tls rotate"),
        (vec!["token", "mint", "--out", "t.tok"], "token mint --out"),
    ] {
        common::assert_not_built_yet(&common::parvault_in(&dir, &args), entry);
    }
    for flag in [
        &["--tls-san", "nas.local"][..],
        &["--insecure-plain-http"][..],
    ] {
        let mut args = vec!["up", "--no-socket", "--listen", common::LOOPBACK_EPHEMERAL];
        args.extend_from_slice(flag);
        common::assert_not_built_yet(
            &common::parvault_in(&dir, &args),
            "--tls-san / --insecure-plain-http",
        );
    }
    // B-180: a socket group is refused, and without a gateway socket it is a usage error.
    let sock = tmp.path().join("gw.sock");
    common::assert_not_built_yet(
        &common::parvault_in(
            &dir,
            &[
                "up",
                "--listen",
                common::LOOPBACK_EPHEMERAL,
                "--ipc-socket",
                sock.to_str().unwrap(),
                "--gateway-socket-group",
                "parvault",
            ],
        ),
        "--gateway-socket-group",
    );
    let no_sock = common::parvault_in(
        &dir,
        &["up", "--no-socket", "--gateway-socket-group", "parvault"],
    );
    assert!(!no_sock.status.success(), "{no_sock:?}");
    assert!(
        String::from_utf8_lossy(&no_sock.stderr).contains("needs --ipc-socket"),
        "{no_sock:?}"
    );
    gate_ran("trust_enforcement_edge::track_a_unbuilt_entries_refuse");
}
