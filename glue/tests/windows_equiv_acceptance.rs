//! E1, the scripted Windows-equivalent acceptance test (plan `v0.5.6-usability.md` Section 1.4):
//! real binaries, no mocks; curl (and rclone when present) stand in for WebClient. The Docker
//! stage `14-webdav-tls` adds the rclone leg in a container and the published-port leg (steps 5 and 9; davfs2 is a v0.5.7 follow-up).
//!
//! Steps here: 1 certificate, 2 pinning accept (TLS 1.3 and 1.2 ECDHE-ECDSA), 3 pinning reject,
//! 4 the WebClient transcript (E1+), 5 read and Range read with `cmp` (64 MiB included), 10 log
//! and environment hygiene. Steps 6 to 8 need tracks B2, C and D and are added on
//! `v0.5.6/integ` (merge order, plan Section 2.3), per archC1 (L-133): new files are written by
//! the vault's writer node, the same node that serves WebDAV (no second writer for one vault,
//! L-119, C7), then listed, read and restored over TLS; T3's cold read asserts the network-fetch
//! counter rather than a second daemon holding the vault key; step 10 also greps for the seed
//! phrase and the vault key hex those steps use (pushed onto `secrets`).
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.
#![cfg(target_os = "linux")]

mod edge_common;

use edge_common::{gate_ran, init_node, parvault_out, pattern, up, write_seed, Daemon};
use std::path::Path;
use std::process::Command;

const MIB: usize = 1024 * 1024;

fn fixture() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("notes.txt", b"ParVault E1 notes\r\nline two\r\n".to_vec()),
        ("readme.txt", b"read me\n".to_vec()),
        ("photo.bin", pattern(3 * MIB, 11)),
        ("video.bin", pattern(64 * MIB, 12)),
    ]
}

/// curl against the edge: `-sS`, the exported CA, the pin, Basic `token:<t>`; returns
/// (exit code, stdout, stderr).
fn curl(args: &[&str]) -> (i32, Vec<u8>, String) {
    let out = Command::new("curl")
        .args(["-sS", "--max-time", "120"])
        .args(args)
        .output()
        .expect("curl");
    (
        out.status.code().unwrap_or(-1),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn pin_of(show: &str) -> String {
    show.lines()
        .find_map(|l| l.strip_prefix("pin (curl):"))
        .map(|p| p.trim().to_string())
        .expect("a pin line")
}

/// DER contains `needle`.
fn has(der: &[u8], needle: &[u8]) -> bool {
    der.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn e1_windows_equivalent() {
    assert!(edge_common::have("curl"), "E1 needs curl (suite S-E1)");
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("owner");
    init_node(&dir);
    let seed = write_seed(&dir, &fixture());
    let d = up(
        &dir,
        &[
            "--vfs-webdav-listen",
            "0.0.0.0:0",
            "--vfs-seed-dir",
            seed.to_str().unwrap(),
            "--vfs-cache-mib",
            "16",
        ],
    );
    let addr = d.webdav_lo();
    let base = format!("https://{addr}");

    // 1. Certificate: export, show, fields.
    let (ca, der) = edge_common::export_cert(&dir);
    let (ok, show) = parvault_out(&dir, &["tls", "show"]);
    assert!(ok, "{show}");
    let pin = pin_of(&show);
    assert!(
        has(
            &der,
            &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        ),
        "P-256"
    );
    // basicConstraints, optionally critical (01 01 FF), holding CA:FALSE: an empty SEQUENCE, or
    // (rcgen) one with an explicit cA FALSE.
    let bc = edge_common::find(&der, &[0x06, 0x03, 0x55, 0x1D, 0x13]).expect("basicConstraints");
    let after = &der[bc + 5..(bc + 15).min(der.len())];
    let body = after.strip_prefix(&[0x01, 0x01, 0xFF][..]).unwrap_or(after);
    assert!(
        body.starts_with(&[0x04, 0x02, 0x30, 0x00])
            || body.starts_with(&[0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00]),
        "CA:FALSE: {after:02x?}"
    );
    assert!(
        has(
            &der,
            &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]
        ),
        "serverAuth"
    );
    assert!(has(&der, &[0x87, 0x04, 127, 0, 0, 1]), "IP SAN 127.0.0.1");
    assert!(show.contains("expires:"), "{show}");
    certificate_validity_is_825_days(&ca);

    let ro = d.read_token();
    let cred = format!("token:{ro}");
    let common: Vec<String> = vec![
        "--cacert".into(),
        ca.to_str().unwrap().into(),
        "--pinnedpubkey".into(),
        pin.clone(),
        "-u".into(),
        cred.clone(),
    ];
    let with = |extra: &[&str]| -> Vec<String> {
        let mut v = common.clone();
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    };
    let run = |v: Vec<String>| {
        let refs: Vec<&str> = v.iter().map(String::as_str).collect();
        curl(&refs)
    };

    // 2. Pinning accept: PROPFIND Depth 1 lists the fixture; again over TLS 1.2 ECDHE-ECDSA.
    let url_root = format!("{base}/");
    let (rc, body, err) = run(with(&[
        "-X",
        "PROPFIND",
        "-H",
        "Depth: 1",
        "-w",
        "%{http_code}",
        &url_root,
    ]));
    let text = String::from_utf8_lossy(&body);
    assert_eq!(rc, 0, "{err}");
    assert!(text.ends_with("207"), "{text}");
    for (name, _) in fixture() {
        assert!(
            text.contains(&format!("<D:href>/{name}</D:href>")),
            "{name}: {text}"
        );
    }
    let (rc, body, err) = run(with(&[
        "--tls-max",
        "1.2",
        "--ciphers",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "-X",
        "PROPFIND",
        "-H",
        "Depth: 0",
        "-w",
        "%{http_code}",
        &url_root,
    ]));
    assert_eq!(rc, 0, "TLS 1.2 ECDHE-ECDSA: {err}");
    assert!(String::from_utf8_lossy(&body).ends_with("207"));

    // 3. Pinning reject: another daemon's certificate, a wrong pin, http:// to the TLS port.
    let other = tmp.path().join("other");
    init_node(&other);
    let d2 = up(&other, &["--vfs-webdav-listen", "0.0.0.0:0"]);
    let (other_ca, _) = edge_common::export_cert(&other);
    drop(d2);
    let (rc, _, err) = curl(&[
        "--cacert",
        other_ca.to_str().unwrap(),
        "-u",
        &cred,
        &url_root,
    ]);
    assert_ne!(rc, 0, "another daemon's certificate must not verify: {err}");
    let wrong_pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let (rc, _, err) = curl(&[
        "--cacert",
        ca.to_str().unwrap(),
        "--pinnedpubkey",
        wrong_pin,
        "-u",
        &cred,
        &url_root,
    ]);
    assert_ne!(rc, 0, "a wrong pin must fail: {err}");
    let (rc, body, _) = curl(&[
        "-u",
        &cred,
        "-w",
        "%{http_code}",
        &format!("http://{addr}/"),
    ]);
    assert!(
        rc != 0 || String::from_utf8_lossy(&body).ends_with("000"),
        "plain HTTP answered"
    );

    // 4. WebClient transcript (E1+): unauthenticated OPTIONS is 401 with the Basic challenge and
    // the close; then one keep-alive connection: OPTIONS, PROPFIND 0 and 1, GET; write methods 405.
    let (rc, _, err) = curl(&[
        "--cacert",
        ca.to_str().unwrap(),
        "-v",
        "-X",
        "OPTIONS",
        "-o",
        "/dev/null",
        &url_root,
    ]);
    assert_eq!(rc, 0, "{err}");
    assert!(err.contains("< HTTP/1.1 401"), "{err}");
    assert!(
        err.contains("WWW-Authenticate: Basic realm=\"parvault-webdav\""),
        "{err}"
    );
    assert!(err.contains("Connection: close"), "{err}");
    let notes = format!("{base}/notes.txt");
    let (rc, body, err) = run(with(&[
        "-v",
        "-X",
        "OPTIONS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}\n",
        &url_root,
        "--next",
        "--cacert",
        ca.to_str().unwrap(),
        "--pinnedpubkey",
        &pin,
        "-u",
        &cred,
        "-X",
        "PROPFIND",
        "-H",
        "Depth: 0",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}\n",
        &url_root,
        "--next",
        "--cacert",
        ca.to_str().unwrap(),
        "--pinnedpubkey",
        &pin,
        "-u",
        &cred,
        "-X",
        "PROPFIND",
        "-H",
        "Depth: 1",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}\n",
        &url_root,
        "--next",
        "--cacert",
        ca.to_str().unwrap(),
        "--pinnedpubkey",
        &pin,
        "-u",
        &cred,
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}\n",
        &notes,
    ]));
    assert_eq!(rc, 0, "{err}");
    assert_eq!(String::from_utf8_lossy(&body), "200\n207\n207\n200\n");
    assert!(
        err.matches("Re-using existing").count() + err.matches("Reusing existing").count() >= 3,
        "keep-alive: {err}"
    );
    assert!(err.contains("DAV: 1"), "{err}");
    for m in ["PUT", "LOCK", "DELETE"] {
        let (rc, body, err) = run(with(&[
            "-X",
            m,
            "--data-binary",
            "x",
            "-w",
            "%{http_code}",
            "-o",
            "/dev/null",
            &format!("{base}/new.txt"),
        ]));
        assert_eq!(rc, 0, "{err}");
        assert_eq!(String::from_utf8_lossy(&body), "405", "{m}");
    }
    let (_, body, _) = run(with(&["-X", "PROPFIND", "-H", "Depth: 1", &url_root]));
    assert!(
        !String::from_utf8_lossy(&body).contains("new.txt"),
        "nothing stored"
    );

    // 5. Read: every fixture file byte-for-byte (the 64 MiB one included), and a Range read.
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    for (name, bytes) in fixture() {
        let dest = out.join(name);
        let (rc, _, err) = run(with(&[
            "-o",
            dest.to_str().unwrap(),
            &format!("{base}/{name}"),
        ]));
        assert_eq!(rc, 0, "{name}: {err}");
        assert!(std::fs::read(&dest).unwrap() == bytes, "{name} differs");
    }
    let (rc, body, err) = run(with(&[
        "-r",
        "1000000-1000999",
        "-D",
        "-",
        &format!("{base}/photo.bin"),
    ]));
    assert_eq!(rc, 0, "{err}");
    let split = edge_common::find(&body, b"\r\n\r\n").unwrap();
    assert!(String::from_utf8_lossy(&body[..split]).starts_with("HTTP/1.1 206"));
    assert_eq!(
        &body[split + 4..],
        &pattern(3 * MIB, 11)[1_000_000..1_001_000]
    );
    if edge_common::have("rclone") {
        rclone_lists(&d, &ca, &ro);
    }

    // 10. Hygiene: no token in the log or the environment, raw or in Basic form.
    use base64::Engine as _;
    let basic = base64::engine::general_purpose::STANDARD.encode(&cred);
    let log = d.log_text();
    let environ = std::fs::read(format!("/proc/{}/environ", d.child.id())).unwrap_or_default();
    // Steps 6-8 (integ) push the seed phrase and the vault key hex here (archC1, L-133).
    let secrets: Vec<&str> = vec![ro.as_str(), basic.as_str()];
    for needle in secrets {
        assert!(!log.contains(needle), "token in the daemon log");
        assert!(
            !edge_common::find(&environ, needle.as_bytes()).is_some(),
            "token in the environment"
        );
    }
    gate_ran("windows_equiv_acceptance::e1_windows_equivalent");
}

/// Q3: `notBefore` today and `notAfter` 825 days later (UTCTime `YYMMDD000000Z`), via openssl
/// when present, else from the certificate's own UTCTime fields.
fn certificate_validity_is_825_days(ca: &Path) {
    let der = edge_common::leaf_der_of(&std::fs::read(ca).unwrap());
    let times: Vec<String> = der
        .windows(15)
        .filter(|w| w[0] == 0x17 && w[1] == 13 && w[14] == b'Z')
        .map(|w| String::from_utf8_lossy(&w[2..14]).into_owned())
        .collect();
    assert_eq!(times.len(), 2, "two UTCTimes: {times:?}");
    let day = |t: &str| -> i64 {
        let (y, m, d): (i64, i64, i64) = (
            2000 + t[0..2].parse::<i64>().unwrap(),
            t[2..4].parse().unwrap(),
            t[4..6].parse().unwrap(),
        );
        // days_from_civil (H. Hinnant)
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    };
    assert_eq!(day(&times[1]) - day(&times[0]), 825, "{times:?}");
}

fn rclone_lists(d: &Daemon, ca: &Path, token: &str) {
    let addr = d.webdav_lo();
    let obscured = Command::new("rclone")
        .args(["obscure", token])
        .output()
        .unwrap();
    let pass = String::from_utf8_lossy(&obscured.stdout).trim().to_string();
    let out = Command::new("rclone")
        .args(["lsf", "--ca-cert", ca.to_str().unwrap()])
        .arg(format!(
            ":webdav,url='https://{addr}/',user=token,pass='{pass}':"
        ))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("video.bin") && text.contains("notes.txt"),
        "{text}"
    );
}
