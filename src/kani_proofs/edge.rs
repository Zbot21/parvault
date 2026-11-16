//! Kani harnesses of `v0.5.6` track A: the edge, TLS and read-only WebDAV (plan 3.1).
//!
//! Empty at T0. Rules (docs repo `OPERATIONAL_LESSONS.md` section 8): constant-size inputs, no
//! symbolic slices, maps or strings, the smallest unwind, a `kani::cover!` per outcome; run a new
//! harness alone first (`cargo kani --lib --harness kani_proofs::edge::<name> --exact`).

/// B1-PLAIN (L-81): plain HTTP is served only on a loopback bind or with the opt-out; TLS
/// whenever a certificate is configured; every other case refuses. Three booleans, no unwind.
#[kani::proof]
fn proof_edge_transport_never_plain_off_loopback_without_opt_out() {
    let (loopback, tls, opt_out): (bool, bool, bool) = (kani::any(), kani::any(), kani::any());
    let d = crate::http_edge::edge_transport_decision(loopback, tls, opt_out);
    kani::cover!(d.is_err(), "plain non-loopback refused");
    use crate::http_edge::EdgeTransport;
    let is_tls = matches!(d, Ok(EdgeTransport::Tls));
    let is_plain = matches!(d, Ok(EdgeTransport::Plain));
    kani::cover!(is_tls, "tls served");
    kani::cover!(is_plain && !loopback, "opt-out plain served");
    if is_plain {
        assert!(!tls && (loopback || opt_out));
    }
    if tls {
        assert!(is_tls);
    }
    if !tls && !loopback && !opt_out {
        assert!(d.is_err());
    }
}

/// B1-KEY (A-TLS-8): the key file is accepted exactly when it is a regular file of the effective
/// UID with permission bits `0600`, for every `u32` mode (setuid, sticky and type bits ignored).
#[kani::proof]
fn proof_tls_key_file_owner_only() {
    let mode: u32 = kani::any();
    let (regular, owner): (bool, bool) = (kani::any(), kani::any());
    let d = crate::http_edge::tls_key_file_decision(regular, mode, owner);
    kani::cover!(
        d.is_err() && regular && owner,
        "group or world bits refused"
    );
    kani::cover!(d.is_ok(), "owner-only key accepted");
    assert_eq!(d.is_ok(), regular && owner && mode & 0o777 == 0o600);
    if d.is_ok() {
        assert!(mode & 0o077 == 0 && mode & 0o600 == 0o600);
    }
}

/// B1-PAIR: a pair is accepted exactly when the certificate's key is the private key's.
#[kani::proof]
fn proof_tls_key_pair_must_match() {
    let m: bool = kani::any();
    let d = crate::http_edge::tls_key_pair_decision(m);
    kani::cover!(d.is_err(), "mismatched pair refused");
    kani::cover!(d.is_ok(), "matching pair accepted");
    assert_eq!(d.is_ok(), m);
}
