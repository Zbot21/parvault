//! The read-only WebDAV server (`DAV: 1`; `OPTIONS`, `GET`, `HEAD`, `PROPFIND`) over
//! [`VirtualVaultFs`](crate::vfs::VirtualVaultFs), and its F-43 decision
//! [`webdav_auth_decision`]. Moved out of `vfs.rs` in `v0.5.6` T0 (B-1 P0) with no auth change
//! (L-125: no write methods); the handlers take an [`EdgeStream`](crate::http_edge::EdgeStream)
//! so track A can serve them over TLS. Owner after T0: track A.

/// F-43 (L-43, L-44): what the WebDAV auth decision needs to know about one request. Token
/// facts are known before any path lookup; `in_scope` (manifest and per-method byte-range
/// caveats) is `true` in the pre-lookup pass and evaluated after the lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebdavAuthFacts {
    /// An `Authorization: Bearer` or `Basic` header was sent.
    pub token_present: bool,
    /// It holds a well-formed `PARVAULT-MAC-V1:` token (Basic: as the password).
    pub token_parses: bool,
    /// The token's HMAC chain is valid (root key), or it attenuates the pinned token (plugin).
    pub tag_valid: bool,
    /// An `ExpiresAtUnixMs` caveat has passed.
    pub expired: bool,
    /// The token carries `ReadOnly` (required: the root key is shared with the gateway).
    pub read_only: bool,
    /// The token carries `AllowedPeerUid`, which has no meaning over TCP.
    pub peer_uid_bound: bool,
    /// Manifest and (for `GET`) byte-range caveats allow this path and range.
    pub in_scope: bool,
}

/// A refused WebDAV request: `Unauthorized` answers 401 (byte-identical for every code),
/// `Forbidden` answers 403. The code is only logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebdavAuthRefusal {
    Unauthorized(&'static str),
    Forbidden(&'static str),
}

/// F-43: every WebDAV request needs a valid, unexpired, read-only macaroon that covers it.
pub fn webdav_auth_decision(facts: &WebdavAuthFacts) -> Result<(), WebdavAuthRefusal> {
    if !facts.token_present {
        return Err(WebdavAuthRefusal::Unauthorized(
            "reject.webdav_token_missing",
        ));
    }
    if !facts.token_parses {
        return Err(WebdavAuthRefusal::Unauthorized(
            "reject.webdav_token_malformed",
        ));
    }
    if !facts.tag_valid {
        return Err(WebdavAuthRefusal::Unauthorized(
            "reject.webdav_token_invalid",
        ));
    }
    if facts.expired {
        return Err(WebdavAuthRefusal::Unauthorized(
            "reject.webdav_token_expired",
        ));
    }
    if !facts.read_only {
        return Err(WebdavAuthRefusal::Forbidden(
            "reject.webdav_token_not_read_only",
        ));
    }
    if facts.peer_uid_bound || !facts.in_scope {
        return Err(WebdavAuthRefusal::Forbidden("reject.webdav_scope_denied"));
    }
    Ok(())
}

// Token extraction lives in `http_edge` (item 3, #codehealth: one edge for WebDAV and status).
pub use crate::http_edge::{
    presented_token as presented_webdav_token, PresentedToken,
    MAX_TOKEN_CHARS as WEBDAV_MAX_TOKEN_CHARS,
};

/// How a WebDAV server checks a token's chain (moved to `http_edge`, shared with the status
/// page; item 3).
pub use crate::http_edge::EdgeVerifier as WebdavVerifier;

#[cfg(unix)]
mod unix_webdav {
    use super::*;
    use crate::capabilities::CapabilityMacaroon;
    use crate::vfs::{VfsLazyNode, VirtualVaultFs, DEFAULT_VFS_BLOCK_BYTES, VFS_ROOT_INO};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// RAII handle controlling a background HTTP `Range` (`206 Partial Content`) + WebDAV server
    /// spawned via [`VirtualVaultFs::spawn_webdav_server`].
    pub struct VfsWebdavServerHandle {
        local_addr: SocketAddr,
        shutdown_flag: Arc<AtomicBool>,
        join_handle: Option<std::thread::JoinHandle<()>>,
    }

    impl VfsWebdavServerHandle {
        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        /// Blocks until the server thread exits (for a foreground server, e.g. `parvault-fuse`).
        pub fn wait(mut self) {
            if let Some(h) = self.join_handle.take() {
                let _ = h.join();
            }
        }

        pub fn shutdown(&mut self) {
            self.shutdown_flag.store(true, Ordering::SeqCst);
            let wake_ip = if self.local_addr.ip().is_unspecified() {
                if self.local_addr.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                }
            } else {
                self.local_addr.ip()
            };
            let wake_addr = SocketAddr::new(wake_ip, self.local_addr.port());
            // One wake connect is not enough: a lost SYN (packet loss on the listen interface)
            // fails a short connect, the accept loop never wakes and the join blocks forever
            // (B-56, netem 2% loss). Retry the wake until the accept thread has exited.
            if let Some(jh) = self.join_handle.take() {
                for _ in 0..WAKE_ATTEMPTS {
                    if jh.is_finished() {
                        break;
                    }
                    let _ = TcpStream::connect_timeout(&wake_addr, Duration::from_millis(250));
                    for _ in 0..25 {
                        if jh.is_finished() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                if jh.is_finished() {
                    let _ = jh.join();
                } else {
                    // Bounded (B-68 QA): a thread still blocked after every wake is detached, not
                    // joined; it exits at its next accept, since `shutdown_flag` is set.
                    tracing::warn!(
                        addr = %self.local_addr,
                        attempts = WAKE_ATTEMPTS,
                        "WebDAV accept thread did not exit after every wake connect; detaching it"
                    );
                }
            }
        }
    }

    /// Wake connects tried by [`VfsWebdavServerHandle::shutdown`] (about 0.5 s each, so about
    /// 20 s in all); an accept thread that has still not exited is then detached, not joined.
    const WAKE_ATTEMPTS: usize = 40;

    impl Drop for VfsWebdavServerHandle {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    impl VirtualVaultFs {
        /// Spawns a background stoppable HTTP `Range` (`206 Partial Content`) + WebDAV
        /// (`OPTIONS` / `PROPFIND`) server returning an RAII [`VfsWebdavServerHandle`]. Every
        /// request must present a token `verifier` accepts (F-43); there is no unauthenticated
        /// constructor. Plain HTTP on any bind, as before `v0.5.6` (a non-loopback bind is
        /// logged as in clear); the daemon and the plugin serve through
        /// [`Self::spawn_webdav_server_served`], which refuses it (L-81).
        pub fn spawn_webdav_server(
            &self,
            bind_addr: &str,
            verifier: WebdavVerifier,
        ) -> io::Result<VfsWebdavServerHandle> {
            self.spawn_webdav_server_served(bind_addr, verifier, EdgeServe::InsecurePlain)
        }

        /// [`Self::spawn_webdav_server`] over `serve` (B-1 P1: TLS, or plain HTTP on loopback or
        /// with the opt-out). The bind is checked by `EdgeServe::check_bind` before any accept.
        pub fn spawn_webdav_server_served(
            &self,
            bind_addr: &str,
            verifier: WebdavVerifier,
            serve: EdgeServe,
        ) -> io::Result<VfsWebdavServerHandle> {
            let listener = TcpListener::bind(bind_addr)?;
            listener.set_nonblocking(false)?;
            let local_addr = listener.local_addr()?;
            serve.check_bind(local_addr)?;
            let shutdown_flag = Arc::new(AtomicBool::new(false));
            let shutdown_cl = Arc::clone(&shutdown_flag);
            let vfs = self.clone();

            let join_handle = std::thread::Builder::new()
                .name("parvault-vfs-webdav".into())
                .spawn(move || {
                    let slots = Arc::new(EdgeSlots::new(WEBDAV_MAX_CONNECTIONS));
                    for conn in listener.incoming() {
                        if shutdown_cl.load(Ordering::SeqCst) {
                            break;
                        }
                        let Ok(stream) = conn else {
                            continue;
                        };
                        spawn_webdav_conn(stream, &vfs, &verifier, &slots, &serve, local_addr);
                    }
                })?;

            Ok(VfsWebdavServerHandle {
                local_addr,
                shutdown_flag,
                join_handle: Some(join_handle),
            })
        }

        /// Serves an unprivileged HTTP `Range` (`206 Partial Content`) + WebDAV (`OPTIONS` /
        /// `PROPFIND`) endpoint for locked-down `prplOS` / `RDK-B` LXC containers without
        /// `/dev/fuse`. Every request must present a token `verifier` accepts (F-43). Plain HTTP
        /// on any bind, as before `v0.5.6`.
        pub fn serve_webdav_blocking(
            &self,
            bind_addr: &str,
            verifier: WebdavVerifier,
        ) -> io::Result<()> {
            let listener = TcpListener::bind(bind_addr)?;
            let local_addr = listener.local_addr()?;
            let serve = EdgeServe::InsecurePlain;
            serve.check_bind(local_addr)?;
            let slots = Arc::new(EdgeSlots::new(WEBDAV_MAX_CONNECTIONS));
            for conn in listener.incoming() {
                let Ok(stream) = conn else {
                    continue;
                };
                spawn_webdav_conn(stream, self, &verifier, &slots, &serve, local_addr);
            }
            Ok(())
        }
    }

    /// Most WebDAV connections served at once; more are dropped unanswered (pre-auth bound).
    const WEBDAV_MAX_CONNECTIONS: usize = 64;
    use crate::http_edge::{
        edge_host_allowed, keep_alive_next, pipelined_next, read_request_head_until,
        spawn_edge_conn_served, EdgeServe, EdgeSlots, EdgeStream, EDGE_KEEPALIVE_IDLE,
        EDGE_MAX_REQUESTS_PER_CONN, RESP_403 as WEBDAV_403, RESP_502 as WEBDAV_502, WEBDAV_401,
    };
    use std::time::Instant;

    /// What a connection knows about its listener: the bound address and, on TLS, the
    /// certificate's names for the `Host` check (A-TLS-7).
    struct ListenerCtx {
        bound: SocketAddr,
        tls_names: Option<Arc<[String]>>,
    }

    /// Runs one connection on its own thread within the server's slots (shared edge).
    fn spawn_webdav_conn(
        stream: TcpStream,
        vfs: &VirtualVaultFs,
        verifier: &WebdavVerifier,
        slots: &Arc<EdgeSlots>,
        serve: &EdgeServe,
        bound: SocketAddr,
    ) {
        let (vfs, verifier) = (vfs.clone(), verifier.clone());
        let ctx = ListenerCtx {
            bound,
            tls_names: serve.is_tls().then(|| Arc::from(serve.san_names())),
        };
        spawn_edge_conn_served(
            stream,
            slots,
            "parvault-vfs-http",
            serve,
            move |stream, deadline| {
                let _ = handle_webdav_http_conn(stream, &vfs, &verifier, &ctx, deadline);
            },
        );
    }

    fn now_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Answers a refusal (401 or 403) and logs only its code and the peer address.
    fn refuse_webdav<S: EdgeStream + ?Sized>(
        stream: &mut S,
        refusal: WebdavAuthRefusal,
    ) -> io::Result<()> {
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let (code, body) = match refusal {
            WebdavAuthRefusal::Unauthorized(code) => (code, WEBDAV_401),
            WebdavAuthRefusal::Forbidden(code) => (code, WEBDAV_403),
        };
        tracing::warn!(code, peer = %peer, "refused a WebDAV request");
        stream.write_all(body)?;
        stream.flush()
    }

    /// Whether `token`'s manifest caveats allow `node`, and (for `GET` of a file) its byte-range
    /// caveats allow `[offset, offset + length)`. A manifest-scoped token covers only its own
    /// file, never a collection or a missing path (no existence oracle).
    fn webdav_scope_ok(
        token: &CapabilityMacaroon,
        node: Option<&VfsLazyNode>,
        get_range: Option<(u64, u64)>,
    ) -> bool {
        use crate::capabilities::{AccessRequestContext, Caveat};
        let file_root = node
            .filter(|n| !n.is_dir)
            .and_then(|n| n.manifest.as_ref())
            .map(|m| m.file_merkle_root);
        let (offset, length) = get_range.unwrap_or((0, 0));
        let ctx = AccessRequestContext {
            manifest_root: file_root.unwrap_or([0u8; 32]),
            offset,
            length,
            is_write: false,
            now_unix_ms: now_unix_ms(),
            peer_uid: None,
        };
        token.caveats.iter().all(|c| match c {
            Caveat::AllowedManifest(_) => file_root.is_some() && c.allows(&ctx),
            Caveat::ByteRange { .. } => get_range.is_none_or(|_| c.allows(&ctx)),
            _ => true,
        })
    }

    /// What a connection does after one request.
    enum Next {
        /// The request authenticated and was answered in full: the connection may carry another.
        Continue,
        /// Close: a refusal (401, 403 and 431 close, A-TLS-5), a 502, or a body cut short.
        Close,
    }

    /// One connection (A-TLS-4, A-TLS-5): its first request before the pre-auth `deadline` (on
    /// TLS the handshake shares it), then, only while every request authenticates, further
    /// requests on the same connection (TLS: keep-alive; plain: only already-pipelined ones), each within [`EDGE_KEEPALIVE_IDLE`], at most
    /// [`EDGE_MAX_REQUESTS_PER_CONN`] in all. A refusal, `Connection: close`, a body without an
    /// exact length or over the discard cap ends it. Auth runs per request: the connection
    /// holds no auth state.
    fn handle_webdav_http_conn<S: EdgeStream + ?Sized>(
        stream: &mut S,
        vfs: &VirtualVaultFs,
        verifier: &WebdavVerifier,
        ctx: &ListenerCtx,
        first_deadline: Instant,
    ) -> io::Result<()> {
        let mut carry = Vec::new();
        let mut deadline = first_deadline;
        for _ in 0..EDGE_MAX_REQUESTS_PER_CONN {
            let Some(head) = read_request_head_until(stream, std::mem::take(&mut carry), deadline)?
            else {
                return Ok(());
            };
            if let Next::Close = serve_webdav_request(stream, vfs, verifier, ctx, &head)? {
                return Ok(());
            }
            // Plain listeners (loopback, the opt-out) keep the T0 rule: only requests already
            // pipelined behind this one are served. Keep-alive is for TLS, where every new
            // connection costs a handshake.
            let next = if ctx.tls_names.is_some() {
                let body_deadline = Instant::now() + crate::http_edge::EDGE_HEAD_TIMEOUT;
                keep_alive_next(stream, &head, body_deadline)
            } else {
                pipelined_next(&head)
            };
            match next {
                Some(next) => carry = next,
                None => return Ok(()),
            }
            deadline = Instant::now() + EDGE_KEEPALIVE_IDLE;
        }
        Ok(())
    }

    fn serve_webdav_request<S: EdgeStream + ?Sized>(
        stream: &mut S,
        vfs: &VirtualVaultFs,
        verifier: &WebdavVerifier,
        ctx: &ListenerCtx,
        head: &[u8],
    ) -> io::Result<Next> {
        use crate::capabilities::Caveat;
        let req_str = String::from_utf8_lossy(head);
        let mut lines = req_str.lines();
        let Some(request_line) = lines.next() else {
            return Ok(Next::Close);
        };
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let target = parts.next().unwrap_or("/");
        // The target as the VFS names it: the query dropped, each segment percent-decoded once
        // (clients send `My%20File.txt`) and checked (`webdav_path_segments`). Lookups use only
        // those segments under the vault root; the raw target never reaches a lookup or the
        // filesystem. A target that fails the check is a 400 before auth.
        let segments = match webdav_path_segments(target.split('?').next().unwrap_or("/")) {
            Ok(s) => s,
            Err(code) => {
                let peer = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                tracing::warn!(code, peer = %peer, "refused a WebDAV request path");
                stream.write_all(crate::http_edge::RESP_400)?;
                stream.flush()?;
                return Ok(Next::Close);
            }
        };
        let normalized = format!("/{}", segments.join("/"));
        tracing::debug!(method, path = %normalized, "WebDAV request");
        let raw_path = normalized.as_str();

        let mut range_header: Option<(u64, Option<u64>)> = None;
        let mut authorization: Option<&str> = None;
        let mut host: Option<&str> = None;
        let mut depth_zero = false;
        for hdr in lines {
            if hdr.is_empty() {
                break;
            }
            if let Some((k, v)) = hdr.split_once(':') {
                if k.eq_ignore_ascii_case("host") {
                    host = Some(v.trim());
                } else if k.eq_ignore_ascii_case("depth") {
                    depth_zero = v.trim() == "0";
                } else if k.eq_ignore_ascii_case("authorization") {
                    authorization = Some(v);
                } else if k.eq_ignore_ascii_case("range") {
                    if let Some(spec) = v.trim().strip_prefix("bytes=") {
                        if let Some((s, e)) = spec.split_once('-') {
                            if let Ok(start) = s.trim().parse::<u64>() {
                                let end_opt = e.trim().parse::<u64>().ok();
                                range_header = Some((start, end_opt));
                            }
                        }
                    }
                }
            }
        }

        // A-TLS-7: on TLS the `Host` must be an IP literal for this bind or a certificate name
        // (DNS rebinding); checked before the token. Plain listeners (loopback or the opt-out)
        // keep the pre-v0.5.6 behaviour.
        if let Some(names) = &ctx.tls_names {
            if !edge_host_allowed(host, ctx.bound, names) {
                refuse_webdav(
                    stream,
                    WebdavAuthRefusal::Forbidden("reject.webdav_host_mismatch"),
                )?;
                return Ok(Next::Close);
            }
        }

        // F-43 pass 1: token checks before any lookup (no existence oracle).
        let presented = presented_webdav_token(authorization);
        let token = match &presented {
            PresentedToken::Token(t) => Some(t),
            _ => None,
        };
        let now = now_unix_ms();
        let mut facts = WebdavAuthFacts {
            token_present: !matches!(presented, PresentedToken::Missing),
            token_parses: token.is_some(),
            tag_valid: token.is_some_and(|t| verifier.chain_ok(t)),
            expired: token.is_some_and(|t| {
                t.caveats
                    .iter()
                    .any(|c| matches!(c, Caveat::ExpiresAtUnixMs(e) if now > *e))
            }),
            read_only: token.is_some_and(|t| t.caveats.contains(&Caveat::ReadOnly)),
            peer_uid_bound: token.is_some_and(|t| {
                t.caveats
                    .iter()
                    .any(|c| matches!(c, Caveat::AllowedPeerUid(_)))
            }),
            in_scope: true,
        };
        if let Err(refusal) = webdav_auth_decision(&facts) {
            refuse_webdav(stream, refusal)?;
            return Ok(Next::Close);
        }
        let Some(token) = token.cloned() else {
            return Ok(Next::Close);
        };

        // F-43 pass 2: manifest and per-method byte-range caveats against the looked-up node.
        let node = vfs.lookup_path(raw_path);
        let get_range = match (method, &node) {
            ("GET", Some(n)) if !n.is_dir => Some(match range_header {
                Some((start, end_opt)) => {
                    let end_incl = end_opt
                        .unwrap_or_else(|| n.size_bytes.saturating_sub(1))
                        .min(n.size_bytes.saturating_sub(1));
                    (start, end_incl.saturating_sub(start) + 1)
                }
                None => (0, n.size_bytes),
            }),
            _ => None,
        };
        facts.in_scope = method == "OPTIONS" || webdav_scope_ok(&token, node.as_ref(), get_range);
        if let Err(refusal) = webdav_auth_decision(&facts) {
            refuse_webdav(stream, refusal)?;
            return Ok(Next::Close);
        }

        match method {
            "OPTIONS" => {
                stream.write_all(
                    b"HTTP/1.1 200 OK\r\nDAV: 1\r\nAllow: OPTIONS, GET, HEAD, PROPFIND\r\nAccept-Ranges: bytes\r\nContent-Length: 0\r\n\r\n",
                )?;
            }
            "PROPFIND" => {
                let Some(node) = vfs.lookup_path(raw_path) else {
                    stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")?;
                    stream.flush()?;
                    return Ok(Next::Continue);
                };
                let mut xml = String::from(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">",
                );
                // RFC 4918 9.1: Depth 0 is the resource alone; 1 (and infinity, served as 1)
                // adds its members.
                let entries = if node.is_dir && !depth_zero {
                    let mut v = vec![node.clone()];
                    v.extend(vfs.readdir(node.ino));
                    v
                } else {
                    vec![node.clone()]
                };
                // RFC 4918 hrefs: the full path of each member, percent-encoded, a collection's
                // ending in `/`; and the properties davfs2 and WebClient read (a missing
                // `getlastmodified` makes davfs2 refuse the listing).
                let base = {
                    let trimmed = raw_path.trim_matches('/');
                    if trimmed.is_empty() {
                        String::from("/")
                    } else {
                        format!("/{}/", encode_path(trimmed))
                    }
                };
                for item in entries {
                    // A member href is the listed collection plus one encoded segment; a name
                    // that could step out of it (`.`, `..`, a separator) is never listed.
                    if item.ino != node.ino
                        && (item.name.is_empty()
                            || item.name == "."
                            || item.name == ".."
                            || item.name.contains(['/', '\\', '\0']))
                    {
                        continue;
                    }
                    let href = if item.ino == node.ino {
                        if item.is_dir {
                            base.clone()
                        } else {
                            base.trim_end_matches('/').to_string()
                        }
                    } else if item.is_dir {
                        format!("{base}{}/", encode_segment(&item.name))
                    } else {
                        format!("{base}{}", encode_segment(&item.name))
                    };
                    let (res_type, length, ctype) = if item.is_dir {
                        ("<D:collection/>", String::new(), "httpd/unix-directory")
                    } else {
                        (
                            "",
                            format!(
                                "<D:getcontentlength>{}</D:getcontentlength>",
                                item.size_bytes
                            ),
                            "application/octet-stream",
                        )
                    };
                    let display = if item.ino == VFS_ROOT_INO {
                        ""
                    } else {
                        item.name.as_str()
                    };
                    xml.push_str(&format!(
                        "<D:response><D:href>{href}</D:href><D:propstat><D:prop><D:resourcetype>{res_type}</D:resourcetype>{length}<D:displayname>{}</D:displayname><D:getlastmodified>{}</D:getlastmodified><D:getetag>\"{:x}-{:x}-{:x}\"</D:getetag><D:getcontenttype>{ctype}</D:getcontenttype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
                        xml_escape(display),
                        http_date(item.mtime_unix_secs),
                        item.ino,
                        item.size_bytes,
                        item.mtime_unix_secs,
                    ));
                }
                xml.push_str("</D:multistatus>");
                let hdr = format!(
                    "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
                    xml.len()
                );
                stream.write_all(hdr.as_bytes())?;
                stream.write_all(xml.as_bytes())?;
            }
            "HEAD" | "GET" => {
                let Some(node) = vfs.lookup_path(raw_path) else {
                    stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")?;
                    stream.flush()?;
                    return Ok(Next::Continue);
                };
                if node.is_dir {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
                    stream.flush()?;
                    return Ok(Next::Continue);
                }
                // `(start, len, Some(end_incl))` for a 206, `(0, size, None)` for a 200.
                let (start, len, partial) = match range_header {
                    Some((start, end_opt)) => {
                        if start >= node.size_bytes {
                            stream.write_all(
                                b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n",
                            )?;
                            stream.flush()?;
                            return Ok(Next::Continue);
                        }
                        let end_incl = end_opt
                            .unwrap_or_else(|| node.size_bytes.saturating_sub(1))
                            .min(node.size_bytes.saturating_sub(1));
                        (start, end_incl.saturating_sub(start) + 1, Some(end_incl))
                    }
                    None => (0, node.size_bytes, None),
                };
                let block = DEFAULT_VFS_BLOCK_BYTES as u64;
                // Read the first block before promising a status and a length: a failed read
                // answers 502, never a silently truncated body.
                let first = if method == "GET" && len > 0 {
                    match vfs.read_at(node.ino, start, len.min(block)) {
                        Ok(b) => b,
                        Err(_) => {
                            stream.write_all(WEBDAV_502)?;
                            stream.flush()?;
                            return Ok(Next::Close);
                        }
                    }
                } else {
                    Vec::new()
                };
                let hdr = match partial {
                    Some(end_incl) => format!(
                        "HTTP/1.1 206 Partial Content\r\nAccept-Ranges: bytes\r\nContent-Range: bytes {start}-{end_incl}/{}\r\nContent-Length: {len}\r\n\r\n",
                        node.size_bytes
                    ),
                    None => format!(
                        "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Length: {len}\r\n\r\n"
                    ),
                };
                stream.write_all(hdr.as_bytes())?;
                if method == "GET" {
                    // Stream block by block (a `Range: bytes=0-` never buffers the whole file);
                    // a mid-body failure closes the connection short of Content-Length.
                    stream.write_all(&first)?;
                    let end = start + len;
                    let mut off = start + first.len() as u64;
                    while off < end && !first.is_empty() {
                        let chunk = vfs.read_at(node.ino, off, (end - off).min(block))?;
                        if chunk.is_empty() {
                            break;
                        }
                        stream.write_all(&chunk)?;
                        off += chunk.len() as u64;
                    }
                    if off < end {
                        // Short of Content-Length: the client must see the close.
                        stream.flush()?;
                        return Ok(Next::Close);
                    }
                }
            }
            _ => {
                stream
                    .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")?;
            }
        }
        stream.flush()?;
        Ok(Next::Continue)
    }

    /// The segments of a request path (QA of the davfs2 fix, Lead security condition): each
    /// `/`-separated segment percent-decoded exactly once. Refused (`reject.webdav_path_invalid`):
    /// a malformed escape, non-UTF-8, a NUL, a `.` or `..` segment, a decoded `/` (`%2F`) or a
    /// backslash in a segment, and a segment that still holds a `%XX` escape after the decode
    /// (double encoding, `%252e`). Empty segments (`//`, a trailing `/`) are dropped.
    pub(super) fn webdav_path_segments(target: &str) -> Result<Vec<String>, &'static str> {
        const BAD: &str = "reject.webdav_path_invalid";
        if !target.starts_with('/') {
            return Err(BAD);
        }
        let mut out = Vec::new();
        for raw in target.split('/').filter(|s| !s.is_empty()) {
            let seg = percent_decode_segment(raw).ok_or(BAD)?;
            let still_encoded = seg
                .as_bytes()
                .windows(3)
                .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit());
            if seg == "." || seg == ".." || seg.contains(['/', '\\', '\0']) || still_encoded {
                return Err(BAD);
            }
            out.push(seg);
        }
        Ok(out)
    }

    /// Decodes the `%XX` escapes of one segment; `None` for a malformed escape or non-UTF-8.
    fn percent_decode_segment(p: &str) -> Option<String> {
        let b = p.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return None;
                }
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).ok()
    }

    /// Percent-encodes one path segment (RFC 3986 unreserved characters stay).
    pub(super) fn encode_segment(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for &c in s.as_bytes() {
            if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
                out.push(c as char);
            } else {
                out.push_str(&format!("%{c:02X}"));
            }
        }
        out
    }

    /// [`encode_segment`] for each segment of a `/`-separated path.
    pub(super) fn encode_path(p: &str) -> String {
        p.split('/')
            .map(encode_segment)
            .collect::<Vec<_>>()
            .join("/")
    }

    pub(super) fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    /// An RFC 1123 date (`Sun, 06 Nov 1994 08:49:37 GMT`), for `getlastmodified`.
    pub(super) fn http_date(unix_secs: u64) -> String {
        const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let days = (unix_secs / 86_400) as i64;
        let rem = unix_secs % 86_400;
        // H. Hinnant's civil_from_days.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + i64::from(m <= 2);
        format!(
            "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
            DAYS[(days.rem_euclid(7)) as usize],
            d,
            MONTHS[(m - 1) as usize],
            y,
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn dates_paths_and_escapes() {
            assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
            assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
            assert_eq!(
                webdav_path_segments("/dir/My%20File.txt"),
                Ok(vec!["dir".to_string(), "My File.txt".to_string()])
            );
            assert_eq!(webdav_path_segments("//a//"), Ok(vec!["a".to_string()]));
            assert_eq!(webdav_path_segments("/"), Ok(vec![]));
            assert_eq!(
                webdav_path_segments("/f%2Ebin"),
                Ok(vec!["f.bin".to_string()])
            );
            for bad in [
                "/%2e%2e/",
                "/a/..%2f..%2fetc",
                "/..",
                "/a/../b",
                "/./f",
                "/%2E",
                "/a%00b",
                "/%00",
                "/%252e%252e",
                "/a%2Fb",
                "/a%5Cb",
                "/a\\b",
                "/a%2",
                "/a%zz",
                "/%C3%28",
                "relative",
            ] {
                assert_eq!(
                    webdav_path_segments(bad),
                    Err("reject.webdav_path_invalid"),
                    "{bad}"
                );
            }
            assert_eq!(encode_segment("My File+ü.txt"), "My%20File%2B%C3%BC.txt");
            assert_eq!(encode_path("a b/c"), "a%20b/c");
            assert_eq!(xml_escape("<a&b>"), "&lt;a&amp;b&gt;");
        }
    }
}

#[cfg(unix)]
pub use unix_webdav::VfsWebdavServerHandle;
