//! F-43 over TLS (B-1, plan 3.1): the WebDAV auth matrix of `tests/trust_enforcement.rs` re-run
//! against a real `parvault up` whose WebDAV edge serves TLS (a non-loopback bind, L-81), and
//! the read-only method set (L-125). The four 401s stay byte-identical to the plain edge's.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.
#![cfg(target_os = "linux")]

mod edge_common;

use edge_common::{
    default_client, export_cert, gate_ran, init_node, pattern, req, req_basic, tls_once, up,
    write_seed, Daemon,
};
use parvault::capabilities::Caveat;
use std::net::SocketAddr;
use std::sync::Arc;

const A_LEN: usize = 200 * 1024;

fn daemon(dir: &std::path::Path) -> (Daemon, Arc<rustls::ClientConfig>, SocketAddr) {
    init_node(dir);
    let seed = write_seed(
        dir,
        &[("a.bin", pattern(A_LEN, 3)), ("b.txt", b"hello\n".to_vec())],
    );
    let d = up(
        dir,
        &[
            "--vfs-webdav-listen",
            "0.0.0.0:0",
            "--vfs-seed-dir",
            seed.to_str().unwrap(),
        ],
    );
    let (_, der) = export_cert(dir);
    let addr = d.webdav_lo();
    (d, default_client(&der), addr)
}

/// The whole matrix on one daemon: each refusal over TLS answers what the plain edge answers.
#[test]
fn f43_matrix_over_tls() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let (d, cfg, addr) = daemon(&dir);
    let raw = |r: String| tls_once(addr, &cfg, &r);
    let ro = d.read_token();

    // 401s: missing, malformed, wrong root key, expired, Basic with a wrong token.
    let forged = edge_common::mint(&[0xEE; 32], vec![Caveat::ReadOnly]);
    let expired = d.token(vec![Caveat::ReadOnly, Caveat::ExpiresAtUnixMs(1)]);
    let unauthorized = [
        raw(req("GET", "/a.bin", addr, None, "")),
        raw(req("GET", "/a.bin", addr, Some("PARVAULT-MAC-V1:zz"), "")),
        raw(req("GET", "/a.bin", addr, Some(&forged), "")),
        raw(req("GET", "/a.bin", addr, Some(&expired), "")),
        raw(req_basic("GET", "/a.bin", addr, &forged, "")),
        raw(req("OPTIONS", "/", addr, None, "")),
    ];
    for r in &unauthorized {
        assert_eq!(r.status(), 401, "{}", r.head);
        assert_eq!(
            r.head.as_bytes(),
            parvault::http_edge::WEBDAV_401,
            "byte-identical 401"
        );
    }

    // 403s: no ReadOnly, a peer-UID caveat, another file's manifest, a byte range outside.
    for (label, tok, path, extra) in [
        ("not read-only", d.token(vec![]), "/a.bin", ""),
        (
            "peer uid",
            d.token(vec![Caveat::ReadOnly, Caveat::AllowedPeerUid(1000)]),
            "/a.bin",
            "",
        ),
        (
            "other manifest",
            d.token(vec![Caveat::ReadOnly, Caveat::AllowedManifest([3; 32])]),
            "/a.bin",
            "",
        ),
        (
            "missing path, scoped",
            d.token(vec![Caveat::ReadOnly, Caveat::AllowedManifest([3; 32])]),
            "/nope",
            "",
        ),
        (
            "range outside",
            d.token(vec![
                Caveat::ReadOnly,
                Caveat::ByteRange {
                    offset: 0,
                    length: 10,
                },
            ]),
            "/a.bin",
            "Range: bytes=100-199\r\n",
        ),
    ] {
        let r = raw(req("GET", path, addr, Some(&tok), extra));
        assert_eq!(r.status(), 403, "{label}: {}", r.head);
        assert_eq!(r.head.as_bytes(), parvault::http_edge::RESP_403, "{label}");
    }
    // The byte-range caveat applies to GET only.
    let ranged = d.token(vec![
        Caveat::ReadOnly,
        Caveat::ByteRange {
            offset: 0,
            length: 10,
        },
    ]);
    assert_eq!(
        raw(req("PROPFIND", "/", addr, Some(&ranged), "Depth: 1\r\n")).status(),
        207
    );

    // Accept: Bearer and Basic read the bytes; PROPFIND lists both files.
    let r = raw(req("GET", "/a.bin", addr, Some(&ro), ""));
    assert_eq!(r.status(), 200, "{}", r.head);
    assert_eq!(r.body, pattern(A_LEN, 3));
    let r = raw(req_basic("GET", "/b.txt", addr, &ro, ""));
    assert_eq!((r.status(), r.body.as_slice()), (200, &b"hello\n"[..]));
    let r = raw(req("PROPFIND", "/", addr, Some(&ro), "Depth: 1\r\n"));
    assert!(
        r.text().contains("/a.bin") && r.text().contains("/b.txt"),
        "{}",
        r.text()
    );
    let r = raw(req("HEAD", "/a.bin", addr, Some(&ro), ""));
    assert_eq!(
        edge_common::header(&r.head, "content-length"),
        Some(&*A_LEN.to_string())
    );

    // Read-only (L-125): write methods get 405 and nothing is stored.
    for (m, extra) in [
        ("PUT", "Content-Length: 5\r\n"),
        ("LOCK", "Content-Length: 0\r\n"),
        ("DELETE", ""),
        ("MKCOL", ""),
        ("PROPPATCH", "Content-Length: 0\r\n"),
    ] {
        let mut r = req(m, "/new.txt", addr, Some(&ro), extra);
        if m == "PUT" {
            r.push_str("abcde");
        }
        let resp = tls_once(addr, &cfg, &r);
        assert_eq!(resp.status(), 405, "{m}: {}", resp.head);
    }
    let r = raw(req("PROPFIND", "/", addr, Some(&ro), "Depth: 1\r\n"));
    assert!(!r.text().contains("new.txt"), "{}", r.text());
    let r = raw(req("OPTIONS", "/", addr, Some(&ro), ""));
    assert!(
        r.head.contains("DAV: 1\r\n") && r.head.contains("Allow: OPTIONS, GET, HEAD, PROPFIND\r\n"),
        "{}",
        r.head
    );

    // 431 over TLS.
    let big = format!("X-Pad: {}\r\n", "a".repeat(9000));
    let mut c = edge_common::Tls::connect(addr, &cfg).unwrap();
    c.send(&req("GET", "/a.bin", addr, Some(&ro), &big)).ok();
    assert_eq!(c.response(false).map(|r| r.status()), Some(431));

    // No token in the log, raw or as the Basic form.
    use base64::Engine as _;
    let log = d.log_text();
    for t in [&ro, &forged, &expired, &ranged] {
        assert!(!log.contains(t.as_str()), "token in the log");
        let b = base64::engine::general_purpose::STANDARD.encode(format!("token:{t}"));
        assert!(!log.contains(&b), "Basic form in the log");
    }
    gate_ran("webdav_tls::f43_matrix_over_tls");
}
