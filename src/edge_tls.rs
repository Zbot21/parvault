//! TLS on the HTTP edge (B-1 P1-P3, L-81; `v0.5.6` track A): the daemon's self-signed leaf
//! certificate, made at the first `up` and never at `init` (A-TLS-6), and the rustls config the
//! WebDAV and status listeners serve with (built with `builder_with_provider(ring)`, never
//! `install_default`, A-TLS-2).
//!
//! `v0.5.6` T0 seam: [`ensure_cert`] is called by the daemon before its listeners bind. With no
//! TLS flag it returns `Ok(None)` and the listeners stay plain HTTP as before; a TLS flag is
//! refused (`reject.not_built_yet`) until track A builds it.

use std::net::IpAddr;
use std::path::Path;

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
    /// Subject alternative names of the leaf.
    pub sans: Vec<String>,
    /// Expiry, Unix seconds (825 days after issue, Q3).
    pub not_after_unix_secs: u64,
}

/// Why the edge refused to start or to load its certificate.
#[derive(Debug)]
pub enum EdgeTlsRefusal {
    /// A stubbed entry point (`v0.5.6` T0, G3).
    NotBuiltYet(std::io::Error),
}

impl std::fmt::Display for EdgeTlsRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotBuiltYet(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EdgeTlsRefusal {}

/// Makes the edge certificate in `data_dir` if there is none, or loads it (A-TLS-6), and
/// returns what the edge serves; `Ok(None)` means plain HTTP. Called by the daemon at `up` and
/// `daemon start`, before the WebDAV and status listeners bind.
///
/// T0 stub: no flag gives `Ok(None)` (plain HTTP, as before `v0.5.6`); any flag is refused.
pub fn ensure_cert(
    data_dir: &Path,
    cfg: &EdgeTlsConfig,
) -> Result<Option<CertInfo>, EdgeTlsRefusal> {
    let _ = data_dir;
    if cfg.any_flag() {
        return Err(EdgeTlsRefusal::NotBuiltYet(crate::seam::not_built_yet(
            crate::seam::Unbuilt {
                track: "A",
                entry: "--tls-san / --insecure-plain-http",
            },
        )));
    }
    Ok(None)
}

/// The leaf's parameters: the SANs (IP literals become IP SANs), for [`ensure_cert`] (rcgen
/// `0.11.3`, already linked by `libp2p-tls` with `ring 0.16`, A-TLS-1).
pub fn leaf_params(sans: &[String]) -> rcgen::CertificateParams {
    rcgen::CertificateParams::new(sans.to_vec())
}

/// The host's interface addresses: the SANs of a wildcard bind (host networking, A-TLS-6).
pub fn host_interface_ips() -> std::io::Result<Vec<IpAddr>> {
    Ok(if_addrs::get_if_addrs()?.iter().map(|i| i.ip()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flag_is_plain_http_and_a_flag_is_not_built_yet() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure_cert(dir.path(), &EdgeTlsConfig::default())
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let cfg = EdgeTlsConfig {
            insecure_plain_http: true,
            ..EdgeTlsConfig::default()
        };
        let e = ensure_cert(dir.path(), &cfg).unwrap_err();
        assert!(e.to_string().contains("not_built_yet"), "{e}");
    }

    #[test]
    fn leaf_params_keep_ip_and_dns_sans() {
        let p = leaf_params(&["192.168.1.75".into(), "nas.local".into()]);
        assert_eq!(p.subject_alt_names.len(), 2);
    }
}
