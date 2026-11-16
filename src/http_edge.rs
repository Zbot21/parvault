//! The HTTP edge shared by the WebDAV server and the status page (`ipc-client`; item 3,
//! plan-3 ruling change 7): connection slots (a global cap per server and one per-IP cap),
//! the request-head reader (8 KiB cap, one deadline), the fixed refusal responses, token
//! extraction from `Authorization: Bearer` or `Basic` (L-45), and [`status_auth_decision`].
//!
//! Formal model: `specs/ParVaultGatewayPluginBus.tla` (guards `status-auth`).

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
/// Each write to the client must make progress within this (QA item 3, plan-3 §2): a client
/// that stops reading cannot hold a slot. Per write call, so long transfers to a reading client
/// are not cut.
pub const EDGE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

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
pub const RESP_503: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// How an HTTP server checks a token's chain (WebDAV and status). Required by every server
/// constructor (no unauthenticated server, L-44). Deliberately not `Debug`: it holds the root
/// key or a pinned token.
#[derive(Clone)]
pub enum EdgeVerifier {
    /// The daemon's macaroon root key (built-in host).
    RootKey([u8; 32]),
    /// The plugin's pinned `--macaroon`: a request token must be it or an offline attenuation of
    /// it (`capabilities::is_attenuation_of`).
    PinnedParent(CapabilityMacaroon),
}

impl EdgeVerifier {
    pub fn chain_ok(&self, token: &CapabilityMacaroon) -> bool {
        match self {
            Self::RootKey(key) => token.tag_valid(key),
            // L-44 item 4: on a plugin block-cache hit the read never reaches the gateway, so
            // this check (plus the caveat evaluation in the decision) is the only check.
            Self::PinnedParent(parent) => crate::capabilities::is_attenuation_of(parent, token),
        }
    }
}

/// Plan-3 ruling change 8 (DNS rebinding): the `Host` must be an IP literal or `localhost`,
/// with an optional port. On a wildcard bind any IP literal passes; on a specific bind only that
/// address, plus `localhost` when it is loopback. A missing `Host` or a DNS name is refused.
pub fn status_host_allowed(host: Option<&str>, bound: std::net::SocketAddr) -> bool {
    let Some(h) = host.map(str::trim).filter(|h| !h.is_empty()) else {
        return false;
    };
    let name = if let Some(rest) = h.strip_prefix('[') {
        match rest.split_once(']') {
            Some((ip, tail)) if tail.is_empty() || tail.starts_with(':') => ip,
            _ => return false,
        }
    } else {
        match h.split_once(':') {
            Some((n, port)) if !port.contains(':') => n,
            Some(_) => return false,
            None => h,
        }
    };
    let ip = bound.ip();
    if name.eq_ignore_ascii_case("localhost") {
        return ip.is_unspecified() || ip.is_loopback();
    }
    match name.parse::<IpAddr>() {
        Ok(literal) => ip.is_unspecified() || literal == ip,
        Err(_) => false,
    }
}

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
    if stream.set_write_timeout(Some(EDGE_WRITE_TIMEOUT)).is_err() {
        slots.release(ip);
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

/// A connection the edge reads requests from and writes responses to (v0.5.6 T0, B-1 P0): the
/// WebDAV and status handlers take this, not `TcpStream`, so track A can serve them over TLS.
pub trait EdgeStream: Read + Write {
    /// Bounds the next read (the head deadline shrinks it read by read).
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// The client's address (logged with a refusal).
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr>;
}

impl EdgeStream for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        TcpStream::peer_addr(self)
    }
}

/// One request head and the bytes the client sent after it (A-TLS-4): a request body, or the
/// next pipelined request. Derefs to the head bytes.
pub struct RequestHead {
    /// The head, through the blank line.
    pub head: Vec<u8>,
    /// Bytes read past the blank line; a handler consumes these before reading the stream again.
    pub remainder: Vec<u8>,
}

impl std::ops::Deref for RequestHead {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.head
    }
}

/// Reads the request head (through the blank line), or `None` after writing 431, on a
/// timeout, or on EOF. Heads split across several writes are reassembled. Bytes past the head
/// are returned in [`RequestHead::remainder`], never dropped (A-TLS-4).
pub fn read_request_head<S: EdgeStream + ?Sized>(
    stream: &mut S,
) -> io::Result<Option<RequestHead>> {
    read_request_head_after(stream, Vec::new())
}

/// [`read_request_head`] for the next request on a connection: `carry` (the previous request's
/// remainder) is consumed first, then the stream, under one head deadline and one size cap.
pub fn read_request_head_after<S: EdgeStream + ?Sized>(
    stream: &mut S,
    carry: Vec<u8>,
) -> io::Result<Option<RequestHead>> {
    let deadline = Instant::now() + EDGE_HEAD_TIMEOUT;
    let mut head = carry;
    head.reserve(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(end) = head
            .windows(4)
            .take(EDGE_MAX_HEAD_BYTES.saturating_sub(3))
            .position(|w| w == b"\r\n\r\n")
        {
            let remainder = head.split_off(end + 4);
            return Ok(Some(RequestHead { head, remainder }));
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

/// Most requests one connection may carry (A-TLS-5's cap; until track A adds keep-alive a
/// connection carries more than one only when the client pipelined them, A-TLS-4).
pub const EDGE_MAX_REQUESTS_PER_CONN: usize = 100;

/// The `Content-Length` of a request head (0 when absent), or `None` when the body cannot be
/// skipped exactly: a `Transfer-Encoding` header, a malformed or repeated length.
pub fn request_body_len(head: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(head).ok()?;
    let mut len = None;
    for line in text.split("\r\n").skip(1) {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
        if k.trim().eq_ignore_ascii_case("content-length") {
            if len.is_some() {
                return None;
            }
            len = Some(v.trim().parse::<u64>().ok()?);
        }
    }
    Some(len.unwrap_or(0))
}

/// Whether the request asked to close the connection after its answer (`Connection: close`).
pub fn request_wants_close(head: &[u8]) -> bool {
    String::from_utf8_lossy(head)
        .split("\r\n")
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case("connection"))
        .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
}

/// The bytes after this request's body when the client already sent the next request in the
/// same read (pipelining, A-TLS-4): `Some(carry)` to serve it, `None` to close as before. A body
/// is consumed from the remainder only; the stream is never read for one, so a connection
/// carries a second request only when its bytes are already here. `Connection: close` ends it.
pub fn pipelined_next(head: &RequestHead) -> Option<Vec<u8>> {
    if request_wants_close(&head.head) {
        return None;
    }
    let body = usize::try_from(request_body_len(&head.head)?).ok()?;
    if head.remainder.len() <= body {
        return None;
    }
    Some(head.remainder[body..].to_vec())
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

    /// A-TLS-4: the bytes past a head are kept, not dropped, and the next head starts there.
    #[test]
    fn request_head_keeps_its_remainder() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client
            .write_all(b"PROPFIND /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nxyzGET /b HTTP/1.1\r\nHost: h\r\n\r\n")
            .unwrap();
        // Both requests may arrive in one read or two; the second head is complete either way.
        let first = read_request_head(&mut server).unwrap().expect("first head");
        assert!(first.head.starts_with(b"PROPFIND /a "));
        assert!(first.head.ends_with(b"\r\n\r\n"));
        assert_eq!(request_body_len(&first.head), Some(3));
        let carry = pipelined_next(&first).unwrap_or_default();
        let second = read_request_head_after(&mut server, carry)
            .unwrap()
            .expect("second head");
        assert_eq!(&second.head[..], b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n");
        assert!(second.remainder.is_empty());
    }

    #[test]
    fn pipelining_stops_at_close_chunked_or_a_short_body() {
        let rh = |h: &[u8], rest: &[u8]| RequestHead {
            head: h.to_vec(),
            remainder: rest.to_vec(),
        };
        let next = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(
            pipelined_next(&rh(b"GET / HTTP/1.1\r\n\r\n", next)).as_deref(),
            Some(&next[..])
        );
        assert_eq!(pipelined_next(&rh(b"GET / HTTP/1.1\r\n\r\n", b"")), None);
        assert_eq!(
            pipelined_next(&rh(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n", next)),
            None
        );
        assert_eq!(
            pipelined_next(&rh(
                b"PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                next
            )),
            None
        );
        assert_eq!(
            pipelined_next(&rh(
                b"PROPFIND / HTTP/1.1\r\nContent-Length: 99\r\n\r\n",
                next
            )),
            None
        );
        assert_eq!(
            pipelined_next(&rh(
                b"P / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
                next
            )),
            None
        );
        assert_eq!(
            pipelined_next(&rh(b"P / HTTP/1.1\r\nContent-Length: 2\r\n\r\n", b"abGET")).as_deref(),
            Some(&b"GET"[..])
        );
    }

    /// The head cap is unchanged by the carry: a head ending past 8 KiB is a 431.
    #[test]
    fn carried_bytes_count_toward_the_head_cap() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let mut carry = vec![b'a'; EDGE_MAX_HEAD_BYTES - 2];
        carry.extend_from_slice(b"\r\n\r\n");
        assert!(read_request_head_after(&mut server, carry)
            .unwrap()
            .is_none());
        let mut resp = vec![0u8; RESP_431.len()];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(resp, RESP_431);
    }

    /// QA item 3, defect 3: every edge connection (WebDAV and status) gets a write deadline, so
    /// a client that stops reading cannot hold a slot.
    #[test]
    fn edge_conn_has_write_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let slots = Arc::new(EdgeSlots::new(4));
        spawn_edge_conn(server, &slots, "edge-test", move |s| {
            let _ = tx.send(s.write_timeout().unwrap());
        });
        let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(got, Some(EDGE_WRITE_TIMEOUT));
    }

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
    fn status_host_check() {
        let any: std::net::SocketAddr = "0.0.0.0:4080".parse().unwrap();
        let lo: std::net::SocketAddr = "127.0.0.1:4080".parse().unwrap();
        let lan: std::net::SocketAddr = "192.168.1.5:4080".parse().unwrap();
        for ok in [
            "192.168.1.5:4080",
            "10.0.0.1",
            "[::1]:4080",
            "localhost:4080",
            "LOCALHOST",
        ] {
            assert!(status_host_allowed(Some(ok), any), "{ok}");
        }
        for bad in [
            "rebind.example:4080",
            "nas.local",
            "",
            "1.2.3.4:5:6",
            "[::1",
        ] {
            assert!(!status_host_allowed(Some(bad), any), "{bad}");
        }
        assert!(!status_host_allowed(None, any));
        assert!(status_host_allowed(Some("127.0.0.1:4080"), lo));
        assert!(status_host_allowed(Some("localhost:4080"), lo));
        assert!(!status_host_allowed(Some("10.0.0.1"), lo));
        assert!(status_host_allowed(Some("192.168.1.5"), lan));
        assert!(!status_host_allowed(Some("localhost"), lan));
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
