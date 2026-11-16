//! TLS on the HTTP edge (B-1 P1-P3, L-81; `v0.5.6` track A): the daemon's self-signed leaf
//! certificate, made at the first `up` that has a non-loopback edge and never at `init`
//! (A-TLS-6), and the transport each edge listener serves.
//!
//! The certificate and its key live together in one owner-only file, `<data>/edge_tls.pem`, so
//! a rotation replaces the pair with one rename (A-TLS-8: a SIGKILL mid-rotate leaves the old
//! pair). The file follows the root-key rule (`read_owner_only_file`); the server config is built
//! by [`crate::http_edge::EdgeTlsServer`] with `builder_with_provider(ring)`, never
//! `install_default` (A-TLS-2). The certificate is never re-issued on its own, so its
//! fingerprint stays stable; `parvault tls rotate` re-issues it and every client registers it
//! again.
//!
//! Generation uses `rcgen 0.11.3`, the version `libp2p-tls` already links (A-TLS-1); the plugins
//! load PEM and never generate (A-TLS-3).

use crate::http_edge::{
    pem_section, EdgeServe, EdgeTlsLoadError, EdgeTlsServer, EDGE_NAMES_PEM_LABEL,
};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

/// The edge certificate and key, in the data dir.
pub const EDGE_TLS_FILE: &str = "edge_tls.pem";
/// Prefix of the temporary file a write or rotation renames over [`EDGE_TLS_FILE`]; a leftover
/// one (a SIGKILL before the rename) is removed at the next start.
pub const EDGE_TLS_TMP_PREFIX: &str = ".tmp.edge_tls.pem.";
/// Validity of a new certificate (Q3, L-123; Apple's cap for trusted server certificates).
pub const CERT_VALIDITY_DAYS: u64 = 825;

/// The edge TLS flags of `up` and `daemon start`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EdgeTlsConfig {
    /// `--tls-san`: extra DNS names or IPs for the leaf (bridge-mode containers, A-TLS-6).
    pub extra_sans: Vec<String>,
    /// `--insecure-plain-http`: serve plain HTTP on a non-loopback bind (L-81 opt-out).
    pub insecure_plain_http: bool,
}

impl EdgeTlsConfig {
    /// Whether any edge TLS flag was given.
    pub fn any_flag(&self) -> bool {
        !self.extra_sans.is_empty() || self.insecure_plain_http
    }
}

/// The certificate the edge serves, as `tls show` and the start log print it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// SHA-256 of the leaf's SubjectPublicKeyInfo (the pin, `curl --pinnedpubkey`).
    pub spki_sha256: [u8; 32],
    /// SHA-256 of the leaf's DER (the certificate fingerprint).
    pub cert_sha256: [u8; 32],
    /// SHA-256 of the file `tls export` writes (what `certutil -hashfile <file> SHA256` prints).
    pub export_sha256: [u8; 32],
    /// Subject alternative names of the leaf, as stored with it (empty for a brought certificate).
    pub sans: Vec<String>,
    /// Expiry, Unix seconds (825 days after issue, Q3), when ParVault issued it.
    pub not_after_unix_secs: Option<u64>,
}

impl CertInfo {
    fn of(server: &EdgeTlsServer, pem: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            spki_sha256: server.spki_sha256,
            cert_sha256: server.cert_sha256,
            export_sha256: Sha256::digest(export_pem(server).as_bytes()).into(),
            sans: server.names().to_vec(),
            not_after_unix_secs: pem_not_after(pem),
        }
    }

    /// The pin in curl's form: `sha256//<base64>`.
    pub fn curl_pin(&self) -> String {
        use base64::Engine as _;
        format!(
            "sha256//{}",
            base64::engine::general_purpose::STANDARD.encode(self.spki_sha256)
        )
    }
}

/// Why the edge refused to start or to load its certificate.
#[derive(Debug)]
pub enum EdgeTlsRefusal {
    /// The certificate file exists but was not loaded (key mode, mismatch, bad PEM).
    Load(PathBuf, EdgeTlsLoadError),
    /// A `--tls-san` that is neither an IP literal nor a DNS name.
    InvalidSan(String),
    /// A bind address that does not resolve.
    Bind(String, io::Error),
    /// No certificate to show, export or rotate.
    NoCertificate(PathBuf),
    /// Generating or writing the certificate failed.
    Io(io::Error),
    /// The edge needs TLS on a platform without it.
    Unsupported,
}

impl EdgeTlsRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Load(_, e) => e.code(),
            Self::InvalidSan(_) => "reject.tls_san_invalid",
            Self::Bind(..) => "reject.edge_bind_invalid",
            Self::NoCertificate(_) => "reject.tls_no_certificate",
            Self::Io(_) => "reject.tls_cert_write",
            Self::Unsupported => "reject.tls_unsupported",
        }
    }
}

impl std::fmt::Display for EdgeTlsRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(p, e) => {
                let advice = match e {
                    // `tls rotate` replaces a file that reads but does not hold a usable pair.
                    EdgeTlsLoadError::Invalid(_) | EdgeTlsLoadError::Mismatch { .. } => {
                        "run `parvault tls rotate` to issue a new pair (every client registers it again), or fix the file"
                    }
                    // `tls rotate` refuses these too: never a link, a shared key or another owner's file.
                    EdgeTlsLoadError::KeyMode { .. } => {
                        "make it a regular file (not a symlink) owned by this user with mode 0600, or remove it"
                    }
                    EdgeTlsLoadError::Io(_) => "fix the file",
                };
                write!(
                    f,
                    "{e} ({}); the certificate is never re-issued on its own: {advice}",
                    p.display()
                )
            }
            Self::InvalidSan(s) => write!(
                f,
                "{}: --tls-san {s:?} is not an IP address or a DNS name",
                self.code()
            ),
            Self::Bind(b, e) => write!(f, "{}: edge bind {b:?}: {e}", self.code()),
            Self::NoCertificate(p) => write!(
                f,
                "{}: no edge certificate at {}; it is made by the first `up` with a non-loopback WebDAV or status bind",
                self.code(),
                p.display()
            ),
            Self::Io(e) => write!(f, "{}: {e}", self.code()),
            Self::Unsupported => write!(f, "{}: edge TLS needs a Unix host", self.code()),
        }
    }
}

impl std::error::Error for EdgeTlsRefusal {}

/// The edge listeners `up` was asked for (`--vfs-webdav-listen`, `--status-http`).
#[derive(Debug, Clone, Default)]
pub struct EdgeBinds {
    pub webdav: Option<String>,
    pub status: Option<String>,
}

/// What each edge listener serves, and the certificate when any serves TLS.
pub struct EdgeSetup {
    pub cert: Option<CertInfo>,
    pub webdav: EdgeServe,
    pub status: EdgeServe,
}

/// The edge transports for `binds` (L-81, A-TLS-6): a loopback bind serves plain HTTP; any other
/// bind serves TLS, or plain HTTP with `--insecure-plain-http`. The certificate is made here at
/// the first such start (SANs: each specific bind IP, the host's interface IPs for a wildcard
/// bind, and every `--tls-san`) and loaded at every later one; it is never re-issued on its own.
/// Logs a warning for a bind IP or `--tls-san` the certificate does not cover, and the
/// fingerprint at INFO.
pub fn prepare_edges(
    data_dir: &Path,
    cfg: &EdgeTlsConfig,
    binds: &EdgeBinds,
) -> Result<EdgeSetup, EdgeTlsRefusal> {
    for s in &cfg.extra_sans {
        validate_san(s)?;
    }
    let resolve = |b: &Option<String>| -> Result<Option<SocketAddr>, EdgeTlsRefusal> {
        match b {
            None => Ok(None),
            Some(b) => b
                .to_socket_addrs()
                .map_err(|e| EdgeTlsRefusal::Bind(b.clone(), e))?
                .next()
                .map(Some)
                .ok_or_else(|| {
                    EdgeTlsRefusal::Bind(b.clone(), io::ErrorKind::AddrNotAvailable.into())
                }),
        }
    };
    let webdav = resolve(&binds.webdav)?;
    let status = resolve(&binds.status)?;
    let non_loopback =
        |a: &Option<SocketAddr>| a.is_some_and(|a| !a.ip().to_canonical().is_loopback());
    let wants_tls = |a: &Option<SocketAddr>| non_loopback(a) && !cfg.insecure_plain_http;
    let tls_binds: Vec<SocketAddr> = [webdav, status]
        .into_iter()
        .filter(|a| wants_tls(a))
        .flatten()
        .collect();
    let plain = |a: &Option<SocketAddr>| {
        if non_loopback(a) && cfg.insecure_plain_http {
            EdgeServe::InsecurePlain
        } else {
            EdgeServe::Plain
        }
    };
    if tls_binds.is_empty() {
        if !cfg.extra_sans.is_empty() {
            tracing::warn!(
                sans = ?cfg.extra_sans,
                "--tls-san given but no edge serves TLS (loopback or --insecure-plain-http)"
            );
        }
        return Ok(EdgeSetup {
            cert: None,
            webdav: plain(&webdav),
            status: plain(&status),
        });
    }
    let sans = sans_for(&tls_binds, &cfg.extra_sans);
    let (server, info) = ensure_cert_for(data_dir, &sans)?;
    warn_uncovered(&tls_binds, &cfg.extra_sans, &info.sans);
    tracing::info!(
        spki_sha256 = %hex::encode(info.spki_sha256),
        cert_sha256 = %hex::encode(info.cert_sha256),
        pin = %info.curl_pin(),
        sans = ?info.sans,
        "edge TLS certificate"
    );
    println!(
        "[parvault] Edge TLS certificate SHA-256 {} (webdav.crt file {}; pin {}); clients register it from `parvault tls export --out webdav.crt`",
        colon_hex(&info.cert_sha256),
        hex::encode(info.export_sha256),
        info.curl_pin()
    );
    let pick = |a: &Option<SocketAddr>| {
        if wants_tls(a) {
            EdgeServe::Tls(server.clone())
        } else {
            plain(a)
        }
    };
    Ok(EdgeSetup {
        webdav: pick(&webdav),
        status: pick(&status),
        cert: Some(info),
    })
}

/// Loads the edge certificate in `data_dir`, or makes it with `sans` when there is none
/// (A-TLS-6). A file that exists but does not load refuses the start: it is never replaced on
/// its own (stable fingerprint). A leftover temporary file from a killed rotation is removed.
#[cfg(unix)]
pub fn ensure_cert_for(
    data_dir: &Path,
    sans: &[String],
) -> Result<(EdgeTlsServer, CertInfo), EdgeTlsRefusal> {
    sweep_tmp(data_dir);
    let path = data_dir.join(EDGE_TLS_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => load(&path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let pem = generate_pem(sans).map_err(EdgeTlsRefusal::Io)?;
            write_owner_only_atomic(data_dir, EDGE_TLS_FILE, pem.as_bytes())
                .map_err(EdgeTlsRefusal::Io)?;
            tracing::info!(path = %path.display(), "made the edge TLS certificate (first start)");
            load(&path)
        }
        Err(e) => Err(EdgeTlsRefusal::Io(e)),
    }
}

#[cfg(not(unix))]
pub fn ensure_cert_for(
    _data_dir: &Path,
    _sans: &[String],
) -> Result<(EdgeTlsServer, CertInfo), EdgeTlsRefusal> {
    Err(EdgeTlsRefusal::Unsupported)
}

/// Loads `path` (A-TLS-8 file rule; B1-PAIR).
#[cfg(unix)]
pub fn load(path: &Path) -> Result<(EdgeTlsServer, CertInfo), EdgeTlsRefusal> {
    let server = EdgeTlsServer::load(path).map_err(|e| {
        tracing::error!(code = e.code(), path = %path.display(), "refused the edge TLS file");
        EdgeTlsRefusal::Load(path.to_path_buf(), e)
    })?;
    // The file passed the rule above; read it again only for the stored expiry.
    let pem = crate::capabilities::read_owner_only_file(path)
        .map_err(|_| EdgeTlsRefusal::NoCertificate(path.to_path_buf()))?;
    let info = CertInfo::of(&server, &pem);
    Ok((server, info))
}

/// The certificate in `data_dir` (`tls show`).
#[cfg(unix)]
pub fn show(data_dir: &Path) -> Result<CertInfo, EdgeTlsRefusal> {
    let path = data_dir.join(EDGE_TLS_FILE);
    if std::fs::symlink_metadata(&path).is_err() {
        return Err(EdgeTlsRefusal::NoCertificate(path));
    }
    load(&path).map(|(_, i)| i)
}

/// Writes the certificate (PEM, no key) to `out`, mode `0644` (`tls export`).
#[cfg(unix)]
pub fn export(data_dir: &Path, out: &Path) -> Result<CertInfo, EdgeTlsRefusal> {
    let path = data_dir.join(EDGE_TLS_FILE);
    if std::fs::symlink_metadata(&path).is_err() {
        return Err(EdgeTlsRefusal::NoCertificate(path));
    }
    let (server, info) = load(&path)?;
    let dir = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = out
        .file_name()
        .ok_or_else(|| EdgeTlsRefusal::Io(io::ErrorKind::InvalidInput.into()))?;
    write_atomic(
        &dir,
        &name.to_string_lossy(),
        export_pem(&server).as_bytes(),
        0o644,
    )
    .map_err(EdgeTlsRefusal::Io)?;
    Ok(info)
}

/// What `tls rotate` did: the new certificate, and why the file it replaced did not load when it
/// did not (an invalid PEM or a key and certificate that do not match).
#[derive(Debug)]
pub struct Rotated {
    pub info: CertInfo,
    pub replaced_invalid: Option<EdgeTlsLoadError>,
}

/// Issues a new key and certificate in place of the current one (`tls rotate`): the stored SANs
/// plus the host's current interface IPs (a changed DHCP lease), 825 days. Key and certificate
/// are replaced together by one rename. Every client must register the new certificate.
///
/// A file that passes the key rule but does not hold a usable pair (invalid PEM, mismatched
/// key and certificate) is replaced too, keeping the SANs still stored in it, with a warning
/// naming what was wrong (QA D5). A file that fails the key rule (a symlink, another owner, a
/// mode other than `0600`) or cannot be read is refused and left as it is.
#[cfg(unix)]
pub fn rotate(data_dir: &Path) -> Result<Rotated, EdgeTlsRefusal> {
    sweep_tmp(data_dir);
    let path = data_dir.join(EDGE_TLS_FILE);
    if std::fs::symlink_metadata(&path).is_err() {
        return Err(EdgeTlsRefusal::NoCertificate(path));
    }
    // The current file must pass the key rule: rotation never follows a link or a shared key.
    let (mut sans, replaced_invalid) = match load(&path) {
        Ok((_, old)) => (old.sans, None),
        Err(EdgeTlsRefusal::Load(
            _,
            e @ (EdgeTlsLoadError::Invalid(_) | EdgeTlsLoadError::Mismatch { .. }),
        )) => {
            // The file passed the key rule (the error is after it); read it again under the same
            // rule for the SANs it still stores.
            let sans = crate::capabilities::read_owner_only_file(&path)
                .map(|pem| crate::http_edge::pem_edge_names(&pem))
                .unwrap_or_default();
            tracing::warn!(
                code = e.code(),
                path = %path.display(),
                "tls rotate: the edge TLS file did not load ({e}); replacing it with a new pair"
            );
            (sans, Some(e))
        }
        Err(e) => return Err(e),
    };
    for ip in usable_interface_ips() {
        let s = ip.to_string();
        if !sans.contains(&s) {
            sans.push(s);
        }
    }
    let pem = generate_pem(&sans).map_err(EdgeTlsRefusal::Io)?;
    write_owner_only_atomic(data_dir, EDGE_TLS_FILE, pem.as_bytes()).map_err(EdgeTlsRefusal::Io)?;
    load(&path).map(|(_, info)| Rotated {
        info,
        replaced_invalid,
    })
}

/// The leaf as `tls export` writes it: one `CERTIFICATE` section, 64 columns, LF.
pub fn export_pem(server: &EdgeTlsServer) -> String {
    pem_section("CERTIFICATE", &server.leaf_der)
}

/// `AB:CD:...`, as certificate viewers print a fingerprint.
pub fn colon_hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A `--tls-san`: an IP literal, or a DNS name of letters, digits, `-` and `.` (no wildcard).
pub fn validate_san(s: &str) -> Result<(), EdgeTlsRefusal> {
    if s.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let bare = s.strip_suffix('.').unwrap_or(s);
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if !bare.is_empty() && bare.len() <= 253 && bare.split('.').all(label_ok) {
        Ok(())
    } else {
        Err(EdgeTlsRefusal::InvalidSan(s.to_string()))
    }
}

/// The SANs of a new certificate: each specific TLS bind IP, the host's interface IPs for a
/// wildcard bind (host networking, A-TLS-6), then `extra` (`--tls-san`); in order, no repeats.
pub fn sans_for(tls_binds: &[SocketAddr], extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: String| {
        if !out.iter().any(|o| o.eq_ignore_ascii_case(&s)) {
            out.push(s);
        }
    };
    for b in tls_binds {
        let ip = b.ip().to_canonical();
        if ip.is_unspecified() {
            for i in usable_interface_ips() {
                push(i.to_string());
            }
        } else {
            push(ip.to_string());
        }
    }
    for e in extra {
        push(canonical_san(e));
    }
    out
}

fn canonical_san(s: &str) -> String {
    match s.parse::<IpAddr>() {
        Ok(ip) => ip.to_canonical().to_string(),
        Err(_) => s.to_ascii_lowercase(),
    }
}

/// The host's interface addresses that can be a SAN: every one except IPv6 link-local (those
/// need a scope id no client puts in a URL).
fn usable_interface_ips() -> Vec<IpAddr> {
    host_interface_ips()
        .unwrap_or_default()
        .into_iter()
        .filter(|ip| match ip {
            IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
            IpAddr::V4(_) => true,
        })
        .collect()
}

/// A-TLS-6: warn at start for a TLS bind IP (or, on a wildcard bind, a non-loopback interface
/// IP) or a `--tls-san` the certificate does not cover. A bridge-mode container needs `--tls-san`
/// with the host's address; a changed lease needs `tls rotate`.
fn warn_uncovered(tls_binds: &[SocketAddr], extra: &[String], sans: &[String]) {
    let covered = |s: &str| sans.iter().any(|c| c.eq_ignore_ascii_case(s));
    for b in tls_binds {
        let ip = b.ip().to_canonical();
        let ips: Vec<IpAddr> = if ip.is_unspecified() {
            usable_interface_ips()
                .into_iter()
                .filter(|i| !i.is_loopback())
                .collect()
        } else {
            vec![ip]
        };
        for i in ips {
            if !covered(&i.to_string()) {
                tracing::warn!(bind = %b, ip = %i, "no SAN of the edge certificate covers this address: clients connecting to it fail the name check (bridge mode: pass --tls-san; changed address: `parvault tls rotate`)");
            }
        }
    }
    for e in extra {
        let e = canonical_san(e);
        if !covered(&e) {
            tracing::warn!(san = %e, "--tls-san is not in the existing edge certificate (it is never re-issued on its own); run `parvault tls rotate`, then re-register clients");
        }
    }
}

/// A new self-signed leaf for `sans` with its key and SAN list, as one PEM file: ECDSA P-256,
/// `CA:FALSE`, key usage `digitalSignature`, EKU `serverAuth`, 825 days from today (UTC), a
/// random 128-bit serial. The PEM holds the private key, so it is zeroized on drop.
pub fn generate_pem(sans: &[String]) -> io::Result<zeroize::Zeroizing<String>> {
    let (pem, _) = generate(sans, unix_now_secs())?;
    Ok(pem)
}

/// [`generate_pem`] at `now_unix_secs`; also returns `notAfter` (Unix seconds).
pub fn generate(
    sans: &[String],
    now_unix_secs: u64,
) -> io::Result<(zeroize::Zeroizing<String>, u64)> {
    use rand::RngCore;
    let mut p = rcgen::CertificateParams::default();
    p.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    p.subject_alt_names = sans
        .iter()
        .map(|s| match s.parse::<IpAddr>() {
            Ok(ip) => rcgen::SanType::IpAddress(ip),
            Err(_) => rcgen::SanType::DnsName(s.clone()),
        })
        .collect();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::OrganizationName, "ParVault");
    dn.push(rcgen::DnType::CommonName, "ParVault edge");
    p.distinguished_name = dn;
    p.is_ca = rcgen::IsCa::ExplicitNoCa;
    p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let mut serial = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut serial);
    serial[0] = (serial[0] & 0x7f) | 0x40; // positive, no leading zero byte
    p.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
    let today = now_unix_secs / 86_400;
    let not_after_day = today + CERT_VALIDITY_DAYS;
    let ymd = |day: u64| {
        let (y, m, d) = civil_from_days(day as i64);
        rcgen::date_time_ymd(y as i32, m as u8, d as u8)
    };
    p.not_before = ymd(today);
    p.not_after = ymd(not_after_day);
    let cert = rcgen::Certificate::from_params(p).map_err(io::Error::other)?;
    let der = cert.serialize_der().map_err(io::Error::other)?;
    let key = zeroize::Zeroizing::new(cert.serialize_private_key_pem());
    let not_after = not_after_day * 86_400;
    let mut names = sans.join("\n");
    names.push_str(&format!("\n#not_after={not_after}\n"));
    let cert_pem = pem_section("CERTIFICATE", &der);
    let names_pem = pem_section(EDGE_NAMES_PEM_LABEL, names.as_bytes());
    // QA D4: the key is copied only into a zeroized buffer sized up front, so no growth leaves a
    // freed, unwiped copy behind.
    let mut pem = zeroize::Zeroizing::new(String::with_capacity(
        cert_pem.len() + key.len() + 1 + names_pem.len(),
    ));
    pem.push_str(&cert_pem);
    pem.push_str(&key);
    if !pem.ends_with('\n') {
        pem.push('\n');
    }
    pem.push_str(&names_pem);
    Ok((pem, not_after))
}

/// The `#not_after=` line ParVault stores with a certificate it issued.
fn pem_not_after(pem: &[u8]) -> Option<u64> {
    use base64::Engine as _;
    let text = String::from_utf8_lossy(pem);
    let begin = format!("-----BEGIN {EDGE_NAMES_PEM_LABEL}-----");
    let rest = &text[text.find(&begin)? + begin.len()..];
    let b64: String = rest[..rest.find("-----END")?].split_whitespace().collect();
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    String::from_utf8_lossy(&raw)
        .lines()
        .find_map(|l| l.strip_prefix("#not_after=")?.trim().parse().ok())
}

/// Days since 1970-01-01 to a proleptic Gregorian `(year, month, day)` (H. Hinnant's
/// `civil_from_days`).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Removes temporary files a killed write or rotation left (never the live file).
fn sweep_tmp(data_dir: &Path) {
    let Ok(rd) = std::fs::read_dir(data_dir) else {
        return;
    };
    for e in rd.flatten() {
        if e.file_name()
            .to_string_lossy()
            .starts_with(EDGE_TLS_TMP_PREFIX)
        {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Writes `bytes` to `dir/name` mode `0600` by a fsynced temporary file and one rename.
#[cfg(unix)]
pub fn write_owner_only_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    write_atomic(dir, name, bytes, 0o600)
}

#[cfg(unix)]
fn write_atomic(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
    crate::capabilities::write_file_atomic(&dir.join(name), bytes, mode)
}

/// The leaf's parameters: the SANs (IP literals become IP SANs), for [`generate`].
pub fn leaf_params(sans: &[String]) -> rcgen::CertificateParams {
    rcgen::CertificateParams::new(sans.to_vec())
}

/// The host's interface addresses: the SANs of a wildcard bind (host networking, A-TLS-6).
pub fn host_interface_ips() -> std::io::Result<Vec<IpAddr>> {
    Ok(if_addrs::get_if_addrs()?.iter().map(|i| i.ip()).collect())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// QA D4: the generated PEM (it holds the private key) is a `Zeroizing<String>` through to
    /// the write, and was built in one buffer (no reallocation left a copy).
    #[test]
    fn qa056_d4_generated_pem_is_zeroizing() {
        let (pem, _): (zeroize::Zeroizing<String>, u64) =
            generate(&["127.0.0.1".into()], 1_800_000_000).unwrap();
        assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
        // The buffer is sized for the key PEM plus an optional newline: never regrown.
        assert!(
            pem.len() <= pem.capacity() && pem.capacity() - pem.len() <= 1,
            "{} {}",
            pem.capacity(),
            pem.len()
        );
        let _: zeroize::Zeroizing<String> = generate_pem(&[]).unwrap();
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_772), (2026, 11, 15));
    }

    #[test]
    fn leaf_params_keep_ip_and_dns_sans() {
        let p = leaf_params(&["192.168.1.75".into(), "nas.local".into()]);
        assert_eq!(p.subject_alt_names.len(), 2);
    }

    #[test]
    fn san_validation() {
        for ok in ["192.168.1.75", "::1", "nas.local", "nas", "a-b.example."] {
            assert!(validate_san(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "*.example",
            "a b",
            "-a.example",
            "a..b",
            "nas.local:8443",
        ] {
            assert!(validate_san(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn loopback_binds_need_no_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let setup = prepare_edges(
            dir.path(),
            &EdgeTlsConfig::default(),
            &EdgeBinds {
                webdav: Some("127.0.0.1:0".into()),
                status: Some("[::1]:0".into()),
            },
        )
        .unwrap();
        assert!(setup.cert.is_none());
        assert!(!setup.webdav.is_tls() && !setup.status.is_tls());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_nonloopback_bind_makes_one_stable_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EdgeTlsConfig {
            extra_sans: vec!["nas.local".into()],
            insecure_plain_http: false,
        };
        let binds = EdgeBinds {
            webdav: Some("0.0.0.0:0".into()),
            status: Some("127.0.0.1:0".into()),
        };
        let a = prepare_edges(dir.path(), &cfg, &binds).unwrap();
        assert!(a.webdav.is_tls());
        assert!(!a.status.is_tls(), "loopback stays plain");
        let info = a.cert.unwrap();
        assert!(
            info.sans.contains(&"nas.local".to_string()),
            "{:?}",
            info.sans
        );
        assert!(
            info.sans.contains(&"127.0.0.1".to_string()),
            "{:?}",
            info.sans
        );
        assert!(info.not_after_unix_secs.is_some());
        let b = prepare_edges(dir.path(), &EdgeTlsConfig::default(), &binds).unwrap();
        assert_eq!(
            b.cert.unwrap().spki_sha256,
            info.spki_sha256,
            "never re-issued"
        );
        let rotated = rotate(dir.path()).unwrap();
        assert!(rotated.replaced_invalid.is_none());
        let rotated = rotated.info;
        assert_ne!(rotated.spki_sha256, info.spki_sha256);
        assert!(rotated.sans.contains(&"nas.local".to_string()));
    }

    #[test]
    fn the_opt_out_serves_plain_and_makes_no_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = EdgeTlsConfig {
            extra_sans: Vec::new(),
            insecure_plain_http: true,
        };
        let s = prepare_edges(
            dir.path(),
            &cfg,
            &EdgeBinds {
                webdav: Some("0.0.0.0:0".into()),
                status: None,
            },
        )
        .unwrap();
        assert!(matches!(s.webdav, EdgeServe::InsecurePlain));
        assert!(s.cert.is_none());
    }
}
