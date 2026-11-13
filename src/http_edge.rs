//! The HTTP edge shared by the WebDAV server and the status page (`ipc-client`; item 3,
//! plan-3 ruling change 7): connection slots (a global cap per server and one per-IP cap),
//! the request-head reader (8 KiB cap, one deadline), the fixed refusal responses, token
//! extraction from `Authorization: Bearer` or `Basic` (L-45), and [`status_auth_decision`].

use crate::capabilities::{CapabilityMacaroon, Caveat};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Most connections one source IP may hold on one server, so a single host cannot take every
/// slot (F-43 QA r1). One constant for WebDAV and status (the plan's 4 was a typo for this 8).
pub const EDGE_MAX_CONNECTIONS_PER_IP: usize = 8;
/// Longest request head accepted (431 beyond it).
pub const EDGE_MAX_HEAD_BYTES: usize = 8192;
/// A client must finish its whole request head within this one deadline (dropped unanswered
/// otherwise); each read's timeout shrinks to the time left, so a slow drip cannot hold a slot.
pub const EDGE_HEAD_TIMEOUT: Duration = Duration::from_secs(5);

/// The WebDAV 401: byte-identical for every reason; the reason code is only logged.
pub const WEBDAV_401: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"parvault-webdav\"\r\nWWW-Authenticate: Basic realm=\"parvault-webdav\", charset=\"UTF-8\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// The status-page 401: byte-identical for every reason. The Basic challenge lets a browser
/// prompt for the token as the password (L-45); it never goes in the URL.
pub const STATUS_401: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"parvault-status\"\r\nWWW-Authenticate: Basic realm=\"parvault-status\", charset=\"UTF-8\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
pub const RESP_403: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
pub const RESP_431: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
pub const RESP_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Connection slots of one server: a global count and a count per source IP.
pub struct EdgeSlots {
    max_connections: usize,
    active: AtomicUsize,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
}

impl EdgeSlots {
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            active: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
        }
    }

    /// Takes a slot for `ip`, or `false` when the global or per-IP cap is reached.
    pub fn acquire(&self, ip: Option<IpAddr>) -> bool {
        if self.active.fetch_add(1, Ordering::SeqCst) >= self.max_connections {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        if let Some(ip) = ip {
            let mut map = self.per_ip.lock().unwrap_or_else(|p| p.into_inner());
            let n = map.entry(ip).or_insert(0);
            if *n >= EDGE_MAX_CONNECTIONS_PER_IP {
                drop(map);
                self.active.fetch_sub(1, Ordering::SeqCst);
                return false;
            }
            *n += 1;
        }
        true
    }

    pub fn release(&self, ip: Option<IpAddr>) {
        if let Some(ip) = ip {
            let mut map = self.per_ip.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(n) = map.get_mut(&ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&ip);
                }
            }
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Runs `handle` for one connection on its own thread (256 KiB stack) within `slots`; over
/// either cap the connection is dropped unanswered.
pub fn spawn_edge_conn<F>(mut stream: TcpStream, slots: &Arc<EdgeSlots>, name: &str, handle: F)
where
    F: FnOnce(&mut TcpStream) + Send + 'static,
{
    let ip = stream.peer_addr().ok().map(|a| a.ip());
    if !slots.acquire(ip) {
        return;
    }
    let slots_cl = Arc::clone(slots);
    let spawned = std::thread::Builder::new()
        .name(name.into())
        .stack_size(256 * 1024)
        .spawn(move || {
            handle(&mut stream);
            slots_cl.release(ip);
        });
    if spawned.is_err() {
        slots.release(ip);
    }
}

/// Reads the request head (through the blank line), or `None` after writing 431, on a
/// timeout, or on EOF. Heads split across several writes are reassembled.
pub fn read_request_head(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let deadline = Instant::now() + EDGE_HEAD_TIMEOUT;
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            head.truncate(end + 4);
            return Ok(Some(head));
        }
        if head.len() >= EDGE_MAX_HEAD_BYTES {
            stream.write_all(RESP_431)?;
            return Ok(None);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            return Ok(None);
        }
        let want = (EDGE_MAX_HEAD_BYTES - head.len()).min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) | Err(_) => return Ok(None),
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Longest token text accepted from a header (`PARVAULT-MAC-V1:` plus the hex of the largest
/// compact token), checked before hex decoding.
pub const MAX_TOKEN_CHARS: usize = crate::capabilities::COMPACT_MACAROON_PREFIX.len()
    + 2 * crate::capabilities::MAX_COMPACT_MACAROON_BYTES;

/// The token a request presents.
pub enum PresentedToken {
    /// No `Authorization` header, or a scheme other than Bearer or Basic.
    Missing,
    /// Bearer or Basic, but not a well-formed token within the length cap.
    Malformed,
    Token(CapabilityMacaroon),
}

/// Extracts the token from an `Authorization` header value: `Bearer <token>`, or `Basic
/// base64(<user>:<token>)` split at the first colon (D-1). Lengths are capped before decoding.
pub fn presented_token(authorization: Option<&str>) -> PresentedToken {
    let Some(value) = authorization.map(str::trim) else {
        return PresentedToken::Missing;
    };
    let (scheme, rest) = value.split_once(' ').unwrap_or((value, ""));
    let rest = rest.trim();
    let token_text = if scheme.eq_ignore_ascii_case("bearer") {
        rest.to_string()
    } else if scheme.eq_ignore_ascii_case("basic") {
        use base64::Engine as _;
        // base64 of "<user>:<token>": allow up to 256 bytes of user name.
        if rest.len() > (MAX_TOKEN_CHARS + 257).div_ceil(3) * 4 {
            return PresentedToken::Malformed;
        }
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(rest) else {
            return PresentedToken::Malformed;
        };
        let Ok(text) = String::from_utf8(raw) else {
            return PresentedToken::Malformed;
        };
        match text.split_once(':') {
            Some((_user, password)) => password.to_string(),
            None => return PresentedToken::Malformed,
        }
    } else {
        return PresentedToken::Missing;
    };
    if token_text.len() > MAX_TOKEN_CHARS {
        return PresentedToken::Malformed;
    }
    match CapabilityMacaroon::from_compact_token(&token_text) {
        Ok(t) => PresentedToken::Token(t),
        Err(_) => PresentedToken::Malformed,
    }
}

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

    /// The 33rd connection to a 32-slot server is refused (spread over IPs so the per-IP cap
    /// does not hit first); the 9th from one IP is refused; releasing frees a slot.
    #[test]
    fn edge_slots_global_and_per_ip_caps() {
        let s = EdgeSlots::new(32);
        let ip = |i: u8| Some(IpAddr::from([10, 0, 0, i]));
        for i in 0..32u8 {
            assert!(s.acquire(ip(i / 4)));
        }
        assert!(!s.acquire(ip(200)));
        s.release(ip(0));
        assert!(s.acquire(ip(200)));
        let one = EdgeSlots::new(32);
        for _ in 0..EDGE_MAX_CONNECTIONS_PER_IP {
            assert!(one.acquire(ip(1)));
        }
        assert!(!one.acquire(ip(1)));
        assert!(one.acquire(ip(2)));
    }

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
