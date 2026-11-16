//! `v0.5.6` track A, daemon edge tests that need integration glue G-11 (the daemon serves its
//! edges through `edge_tls::prepare_edges`), G-12 (B-180) and G-14 (t0b's early flag refusals
//! removed). Copied to `tests/edge_daemon_tls.rs` by the integrator with those patches; on
//! `v0.5.6/a` it is verified in a scratch copy with the glue applied.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.
#![cfg(target_os = "linux")]

mod edge_common;

use edge_common::{
    default_client, export_cert, gate_ran, init_node, parvault_out, pattern, req, tls_once, up,
    up_refused, write_seed,
};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

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
    gate_ran("edge_daemon_tls::b1_daemon_tls_owner_only_pair_served");
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
    gate_ran("edge_daemon_tls::quic_and_edge_tls_in_one_daemon");
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
    gate_ran("edge_daemon_tls::b180_gateway_socket_group");
}

/// QA D5: `parvault tls rotate` replaces an edge file that does not load (no key, or a key and
/// certificate from two issues) with a fresh owner-only pair, keeps the stored SANs it can still
/// read, and names what was wrong; the daemon then starts on it. A group-readable file and a
/// symlink are still refused, and left as they are.
#[test]
fn qa056_d5_tls_rotate_replaces_an_invalid_file() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    drop(tls_daemon(&dir, &["--tls-san", "nas.local"]));
    let pem = dir.join("edge_tls.pem");
    let set_mode = |p: &Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    let text = String::from_utf8(std::fs::read(&pem).unwrap()).unwrap();
    let key_at = text.find("-----BEGIN PRIVATE KEY-----").unwrap();
    let key_end = text.find("-----END PRIVATE KEY-----\n").unwrap() + 26;
    let other = parvault::edge_tls::generate_pem(&["127.0.0.1".into()]).unwrap();
    let other_key = &other[other.find("-----BEGIN PRIVATE KEY-----").unwrap()
        ..other.find("-----END PRIVATE KEY-----\n").unwrap() + 26];
    let no_key = format!("{}{}", &text[..key_at], &text[key_end..]);
    let mismatched = format!("{}{other_key}{}", &text[..key_at], &text[key_end..]);
    for (broken, code) in [
        (no_key, "reject.tls_pem_invalid"),
        (mismatched, "reject.tls_key_cert_mismatch"),
    ] {
        std::fs::write(&pem, &broken).unwrap();
        set_mode(&pem, 0o600);
        let out = up_refused(&dir, &["--vfs-webdav-listen", "0.0.0.0:0"]);
        assert!(out.contains(code) && out.contains("tls rotate"), "{out}");
        let (ok, out) = parvault_out(&dir, &["tls", "rotate"]);
        assert!(ok, "{out}");
        assert!(
            out.contains(code),
            "the warning names what was wrong: {out}"
        );
        assert!(out.contains("nas.local"), "the stored SANs are kept: {out}");
        let meta = std::fs::symlink_metadata(&pem).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let d = up(&dir, &["--vfs-webdav-listen", "0.0.0.0:0"]);
        assert_eq!(edge_common::webdav_scheme(&d), "https");
        drop(d);
    }
    // Still refused: a group-readable file (left unchanged) and a symlink to a valid pair.
    let good = std::fs::read(&pem).unwrap();
    set_mode(&pem, 0o640);
    let (ok, out) = parvault_out(&dir, &["tls", "rotate"]);
    assert!(!ok && out.contains("reject.tls_key_mode"), "{out}");
    assert_eq!(std::fs::read(&pem).unwrap(), good);
    set_mode(&pem, 0o600);
    let real = tmp.path().join("real.pem");
    std::fs::rename(&pem, &real).unwrap();
    std::os::unix::fs::symlink(&real, &pem).unwrap();
    let (ok, out) = parvault_out(&dir, &["tls", "rotate"]);
    assert!(!ok && out.contains("reject.tls_key_mode"), "{out}");
    assert!(std::fs::symlink_metadata(&pem)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read(&real).unwrap(), good);
    gate_ran("edge_daemon_tls::qa056_d5_tls_rotate_replaces_an_invalid_file");
}
