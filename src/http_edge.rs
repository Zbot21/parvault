//! Client-side HTTP edge decisions shared by the daemon and the plugins (`ipc-client`).
//! Item 3 adds [`status_auth_decision`]; commit 5 moves the shared HTTP edge (header caps,
//! timeouts, connection caps, Bearer/Basic extraction) here.
//!
//! Formal model: `specs/ParVaultGatewayPluginBus.tla` (guards `status-auth`).

use crate::capabilities::{CapabilityMacaroon, Caveat};

/// Where a status request arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusTransport {
    /// The gateway socket, with the peer's `SO_PEERCRED` UID when the kernel gave one.
    Socket { peer_uid: Option<u32> },
    /// A TCP connection (the status page).
    Tcp,
}

/// Facts for [`status_auth_decision`], computed by [`status_auth_facts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusAuthFacts {
    /// A root key (daemon) or pinned token (sidecar) to verify against exists.
    pub verifier_present: bool,
    /// A snapshot exists to serve.
    pub provider_present: bool,
    pub token_present: bool,
    /// The tag verifies and no `ExpiresAtUnixMs` caveat has passed.
    pub token_valid: bool,
    pub read_only: bool,
    /// The token carries `AllowedManifest` or `ByteRange`: a file-scoped token is not a status token.
    pub scoped: bool,
    /// Every `AllowedPeerUid` caveat matches the socket peer; false for any such caveat over TCP.
    pub peer_uid_ok: bool,
    /// The HTTP `Host` is allowed (always true on the socket).
    pub host_allowed: bool,
}

/// Item 3 (plan-3 ruling changes 1 and 2): no status byte leaves the daemon unless a valid,
/// read-only, unscoped token is presented to a node that can verify it and has a snapshot.
/// One decision for the socket and the HTTP edge.
pub fn status_auth_decision(f: &StatusAuthFacts) -> Result<(), &'static str> {
    if !f.verifier_present || !f.provider_present {
        return Err("reject.status_unavailable");
    }
    if !f.token_present {
        return Err("reject.status_token_missing");
    }
    if !f.token_valid {
        return Err("reject.status_token_invalid");
    }
    if !f.read_only {
        return Err("reject.status_not_readonly");
    }
    if f.scoped {
        return Err("reject.status_token_scoped");
    }
    if !f.peer_uid_ok {
        return Err("reject.status_peer_uid");
    }
    if !f.host_allowed {
        return Err("reject.status_host_mismatch");
    }
    Ok(())
}

/// Computes [`StatusAuthFacts`]. `verify` checks the token's tag (root key on the daemon,
/// pinned-parent on the sidecar); it is `None` when there is no verifier.
pub fn status_auth_facts(
    token: Option<&CapabilityMacaroon>,
    verify: Option<&dyn Fn(&CapabilityMacaroon) -> bool>,
    now_unix_ms: u64,
    transport: StatusTransport,
    host_allowed: bool,
    provider_present: bool,
) -> StatusAuthFacts {
    let caveats: &[Caveat] = token.map(|t| t.caveats.as_slice()).unwrap_or(&[]);
    let expired = caveats
        .iter()
        .any(|c| matches!(c, Caveat::ExpiresAtUnixMs(t) if now_unix_ms > *t));
    let tag_ok = match (token, verify) {
        (Some(t), Some(v)) => v(t),
        _ => false,
    };
    let peer_uid_ok = caveats.iter().all(|c| match (c, transport) {
        (Caveat::AllowedPeerUid(_), StatusTransport::Tcp) => false,
        (Caveat::AllowedPeerUid(uid), StatusTransport::Socket { peer_uid }) => {
            peer_uid == Some(*uid)
        }
        _ => true,
    });
    StatusAuthFacts {
        verifier_present: verify.is_some(),
        provider_present,
        token_present: token.is_some(),
        token_valid: tag_ok && !expired,
        read_only: caveats.iter().any(|c| matches!(c, Caveat::ReadOnly)),
        scoped: caveats
            .iter()
            .any(|c| matches!(c, Caveat::AllowedManifest(_) | Caveat::ByteRange { .. })),
        peer_uid_ok,
        host_allowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x21; 32];

    fn tok(c: Vec<Caveat>) -> CapabilityMacaroon {
        CapabilityMacaroon::mint(&KEY, [1; 32], [2; 32], c).unwrap()
    }

    fn decide(
        t: Option<&CapabilityMacaroon>,
        tr: StatusTransport,
        host: bool,
    ) -> Result<(), &'static str> {
        let v = |m: &CapabilityMacaroon| m.tag_valid(&KEY);
        status_auth_decision(&status_auth_facts(t, Some(&v), 1_000, tr, host, true))
    }

    const SOCK: StatusTransport = StatusTransport::Socket {
        peer_uid: Some(1000),
    };

    #[test]
    fn status_auth_accepts_readonly_unscoped() {
        assert_eq!(
            decide(Some(&tok(vec![Caveat::ReadOnly])), SOCK, true),
            Ok(())
        );
        assert_eq!(
            decide(
                Some(&tok(vec![Caveat::ReadOnly])),
                StatusTransport::Tcp,
                true
            ),
            Ok(())
        );
        let uid = tok(vec![Caveat::ReadOnly, Caveat::AllowedPeerUid(1000)]);
        assert_eq!(decide(Some(&uid), SOCK, true), Ok(()));
    }

    #[test]
    fn status_auth_rejects_each_case() {
        let ro = tok(vec![Caveat::ReadOnly]);
        let none: Option<&dyn Fn(&CapabilityMacaroon) -> bool> = None;
        assert_eq!(
            status_auth_decision(&status_auth_facts(Some(&ro), none, 0, SOCK, true, true)),
            Err("reject.status_unavailable")
        );
        let v = |m: &CapabilityMacaroon| m.tag_valid(&KEY);
        assert_eq!(
            status_auth_decision(&status_auth_facts(
                Some(&ro),
                Some(&v),
                0,
                SOCK,
                true,
                false
            )),
            Err("reject.status_unavailable")
        );
        assert_eq!(decide(None, SOCK, true), Err("reject.status_token_missing"));
        let forged =
            CapabilityMacaroon::mint(&[9; 32], [1; 32], [2; 32], vec![Caveat::ReadOnly]).unwrap();
        assert_eq!(
            decide(Some(&forged), SOCK, true),
            Err("reject.status_token_invalid")
        );
        let old = tok(vec![Caveat::ReadOnly, Caveat::ExpiresAtUnixMs(999)]);
        assert_eq!(
            decide(Some(&old), SOCK, true),
            Err("reject.status_token_invalid")
        );
        assert_eq!(
            decide(Some(&tok(vec![])), SOCK, true),
            Err("reject.status_not_readonly")
        );
        let man = tok(vec![Caveat::ReadOnly, Caveat::AllowedManifest([3; 32])]);
        assert_eq!(
            decide(Some(&man), SOCK, true),
            Err("reject.status_token_scoped")
        );
        let rng = tok(vec![
            Caveat::ReadOnly,
            Caveat::ByteRange {
                offset: 0,
                length: 1,
            },
        ]);
        assert_eq!(
            decide(Some(&rng), SOCK, true),
            Err("reject.status_token_scoped")
        );
        let uid = tok(vec![Caveat::ReadOnly, Caveat::AllowedPeerUid(1000)]);
        assert_eq!(
            decide(Some(&uid), StatusTransport::Tcp, true),
            Err("reject.status_peer_uid")
        );
        assert_eq!(
            decide(
                Some(&uid),
                StatusTransport::Socket { peer_uid: Some(7) },
                true
            ),
            Err("reject.status_peer_uid")
        );
        assert_eq!(
            decide(Some(&ro), StatusTransport::Tcp, false),
            Err("reject.status_host_mismatch")
        );
    }
}
