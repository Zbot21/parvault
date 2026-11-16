//! Helpers of the `v0.5.6` track A suites (`trust_enforcement_edge`, `webdav_tls`,
//! `windows_equiv_acceptance`): a real `parvault up` with its WebDAV and status edges, and a
//! rustls client that trusts the daemon's exported certificate. No mocks: every request goes to
//! the real binary over a real TCP socket.

#![allow(dead_code)]

use parvault::capabilities::{CapabilityMacaroon, Caveat};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// `parvault --data-dir <dir> --no-lan-discovery <args>` with the ring environment cleared.
pub fn parvault_cmd(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env_remove("PARVAULT_GENESIS_SEED_HEX")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .env_remove("PARVAULT_PEERS")
        .env("PARVAULT_LAN_REGISTRY_DIR", dir.join("lan-registry"))
        .env("NO_COLOR", "1")
        .arg("--data-dir")
        .arg(dir)
        .arg("--no-lan-discovery");
    cmd
}

/// Runs `parvault <args>` in `dir` to completion (30 s cap) and returns (success, stdout+stderr).
pub fn parvault_out(dir: &Path, args: &[&str]) -> (bool, String) {
    let mut cmd = parvault_cmd(dir);
    cmd.args(args);
    let out = output_within(&mut cmd, Duration::from_secs(60));
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

pub fn output_within(cmd: &mut Command, limit: Duration) -> std::process::Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let a = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let b = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = se.read_to_end(&mut v);
        v
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("command did not exit within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    std::process::Output {
        status,
        stdout: a.join().unwrap(),
        stderr: b.join().unwrap(),
    }
}

/// A node in its own ring (`wot init`) at `dir`.
pub fn init_node(dir: &Path) {
    let (ok, out) = parvault_out(dir, &["wot", "init"]);
    assert!(ok, "wot init: {out}");
}

/// A running `parvault up`; killed on drop.
pub struct Daemon {
    pub dir: PathBuf,
    pub log: PathBuf,
    pub child: Child,
    pub webdav: Option<SocketAddr>,
    pub status: Option<SocketAddr>,
}

impl Daemon {
    pub fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The daemon's gateway root key (`macaroon_root.key`, hex), made at start.
    pub fn root_key(&self) -> [u8; 32] {
        let hex_text = std::fs::read_to_string(self.dir.join("macaroon_root.key")).unwrap();
        let raw = hex::decode(hex_text.trim()).unwrap();
        raw.try_into().unwrap()
    }

    pub fn token(&self, caveats: Vec<Caveat>) -> String {
        mint(&self.root_key(), caveats)
    }

    pub fn read_token(&self) -> String {
        self.token(vec![Caveat::ReadOnly])
    }

    /// The WebDAV edge as a loopback address (a wildcard bind is reached on 127.0.0.1).
    pub fn webdav_lo(&self) -> SocketAddr {
        loopback_of(self.webdav.expect("webdav edge"))
    }

    pub fn status_lo(&self) -> SocketAddr {
        loopback_of(self.status.expect("status edge"))
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill();
    }
}

pub fn loopback_of(a: SocketAddr) -> SocketAddr {
    if a.ip().is_unspecified() {
        let ip: std::net::IpAddr = if a.is_ipv4() {
            [127, 0, 0, 1].into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        };
        SocketAddr::new(ip, a.port())
    } else {
        a
    }
}

pub fn mint(key: &[u8; 32], caveats: Vec<Caveat>) -> String {
    let nonce: [u8; 32] = rand::random();
    CapabilityMacaroon::mint(key, nonce, [7; 32], caveats)
        .unwrap()
        .to_compact_token()
}

/// The fixture folder of E1 step setup (two text files and two binaries) or a smaller one.
pub fn write_seed(dir: &Path, files: &[(&str, Vec<u8>)]) -> PathBuf {
    let seed = dir.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    for (name, body) in files {
        std::fs::write(seed.join(name), body).unwrap();
    }
    seed
}

/// Deterministic test bytes.
pub fn pattern(len: usize, salt: u8) -> Vec<u8> {
    let mut x: u32 = 0x9E37_79B9 ^ salt as u32;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Starts `parvault up --no-socket --listen <loopback> <extra>` and waits for every edge `extra`
/// asks for, and for a seed ingest when `--vfs-seed-dir` is given. Panics with the log if the
/// daemon exits first.
pub fn up(dir: &Path, extra: &[&str]) -> Daemon {
    up_on(dir, "/ip4/127.0.0.1/tcp/0", extra)
}

/// [`up`] with the mesh listening on `listen` (for example QUIC).
pub fn up_on(dir: &Path, listen: &str, extra: &[&str]) -> Daemon {
    up_full(dir, None, listen, extra)
}

/// [`up_on`] with a `--config` file.
pub fn up_full(dir: &Path, config: Option<&Path>, listen: &str, extra: &[&str]) -> Daemon {
    let log = dir.join("daemon.log");
    let file = std::fs::File::create(&log).unwrap();
    let mut cmd = parvault_cmd(dir);
    if let Some(c) = config {
        cmd.arg("--config").arg(c);
    }
    let mut base = vec!["up", "--listen", listen];
    if !extra.contains(&"--ipc-socket") {
        base.push("--no-socket");
    }
    cmd.args(base)
        .args(extra)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(file.try_clone().unwrap()))
        .stderr(Stdio::from(file));
    let child = cmd.spawn().expect("spawn parvault up");
    let mut d = Daemon {
        dir: dir.to_path_buf(),
        log,
        child,
        webdav: None,
        status: None,
    };
    let want_dav = extra.contains(&"--vfs-webdav-listen");
    let want_status = extra.contains(&"--status-http");
    let want_seed = extra.contains(&"--vfs-seed-dir");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = d.log_text();
        if want_dav && d.webdav.is_none() {
            d.webdav = addr_after(&text, "Built-in VFS WebDAV listening on ");
        }
        if want_status && d.status.is_none() {
            d.status = addr_after(&text, "Embedded Status Server listening on ");
        }
        let seeded = !want_seed || text.contains("Ingested built-in VFS seed directory");
        if (!want_dav || d.webdav.is_some()) && (!want_status || d.status.is_some()) && seeded {
            return d;
        }
        if let Ok(Some(st)) = d.child.try_wait() {
            panic!("parvault up exited ({st}):\n{text}");
        }
        assert!(Instant::now() < deadline, "edges not up:\n{text}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Starts `parvault up` that must refuse; returns its output.
pub fn up_refused(dir: &Path, extra: &[&str]) -> String {
    let mut args = vec!["up", "--no-socket", "--listen", "/ip4/127.0.0.1/tcp/0"];
    args.extend_from_slice(extra);
    let (ok, out) = parvault_out(dir, &args);
    assert!(!ok, "up started: {out}");
    out
}

fn addr_after(text: &str, marker: &str) -> Option<SocketAddr> {
    let rest = text.split(marker).nth(1)?;
    let url = rest.split_whitespace().next()?;
    let hostport = url.split("://").nth(1)?;
    hostport.trim_end_matches(',').parse().ok()
}

/// The scheme the daemon printed for its WebDAV edge.
pub fn webdav_scheme(d: &Daemon) -> String {
    let text = d.log_text();
    let rest = text
        .split("Built-in VFS WebDAV listening on ")
        .nth(1)
        .unwrap();
    rest.split("://").next().unwrap().to_string()
}

/// `parvault tls export --out <dir>/webdav.crt`; returns the PEM and the leaf DER.
pub fn export_cert(dir: &Path) -> (PathBuf, Vec<u8>) {
    let out = dir.join("webdav.crt");
    let (ok, text) = parvault_out(dir, &["tls", "export", "--out", out.to_str().unwrap()]);
    assert!(ok, "tls export: {text}");
    let pem = std::fs::read(&out).unwrap();
    (out, leaf_der_of(&pem))
}

pub fn leaf_der_of(pem: &[u8]) -> Vec<u8> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::from_pem_slice(pem)
        .expect("a certificate")
        .to_vec()
}

/// A client config trusting exactly `leaf_der` (the self-signed leaf as its own anchor).
pub fn client_config(
    leaf_der: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(leaf_der.to_vec()))
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

pub fn default_client(leaf_der: &[u8]) -> Arc<rustls::ClientConfig> {
    client_config(
        leaf_der,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
    )
}

/// One TLS connection to the edge.
pub struct Tls {
    pub s: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    buf: Vec<u8>,
}

impl Tls {
    /// Connects to `addr`, checking the certificate against the IP of `addr` (no SNI is sent for
    /// an IP name).
    pub fn connect(addr: SocketAddr, cfg: &Arc<rustls::ClientConfig>) -> std::io::Result<Self> {
        let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
        Self::connect_as(addr, cfg, name)
    }

    pub fn connect_as(
        addr: SocketAddr,
        cfg: &Arc<rustls::ClientConfig>,
        name: rustls::pki_types::ServerName<'static>,
    ) -> std::io::Result<Self> {
        let sock = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        sock.set_read_timeout(Some(Duration::from_secs(30)))?;
        let conn =
            rustls::ClientConnection::new(Arc::clone(cfg), name).map_err(std::io::Error::other)?;
        let mut s = rustls::StreamOwned::new(conn, sock);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock)?;
        }
        Ok(Self { s, buf: Vec::new() })
    }

    pub fn send(&mut self, raw: &str) -> std::io::Result<()> {
        self.s.write_all(raw.as_bytes())?;
        self.s.flush()
    }

    /// Reads one response (head plus `Content-Length` body; none for a `HEAD` request when
    /// `head_only`). `None` when the server closed first.
    pub fn response(&mut self, head_only: bool) -> Option<Response> {
        let mut chunk = [0u8; 16 * 1024];
        loop {
            if let Some(end) = find(&self.buf, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&self.buf[..end + 4]).into_owned();
                let len = header(&head, "content-length")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                let len = if head_only { 0 } else { len };
                while self.buf.len() < end + 4 + len {
                    match self.s.read(&mut chunk) {
                        Ok(0) | Err(_) => return None,
                        Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let body = self.buf[end + 4..end + 4 + len].to_vec();
                self.buf.drain(..end + 4 + len);
                return Some(Response { head, body });
            }
            match self.s.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Whether the server closed the connection (EOF or reset) within `wait`.
    pub fn closed_within(&mut self, wait: Duration) -> bool {
        let _ = self.s.sock.set_read_timeout(Some(wait));
        let mut b = [0u8; 64];
        !matches!(self.s.read(&mut b), Ok(n) if n > 0)
            && !matches!(self.s.read(&mut b), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut)
    }
}

pub struct Response {
    pub head: String,
    pub body: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> u16 {
        self.head
            .get(9..12)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// A request with `Host: <addr>` and a Bearer token.
pub fn req(method: &str, path: &str, addr: SocketAddr, token: Option<&str>, extra: &str) -> String {
    let mut r = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
    if let Some(t) = token {
        r.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    r.push_str(extra);
    r.push_str("\r\n");
    r
}

/// The same with Basic auth `token:<token>` (what WebClient, Finder and davfs2 send).
pub fn req_basic(method: &str, path: &str, addr: SocketAddr, token: &str, extra: &str) -> String {
    use base64::Engine as _;
    let b = base64::engine::general_purpose::STANDARD.encode(format!("token:{token}"));
    format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic {b}\r\n{extra}\r\n")
}

/// One request on a new TLS connection; the response.
pub fn tls_once(addr: SocketAddr, cfg: &Arc<rustls::ClientConfig>, raw: &str) -> Response {
    let mut c = Tls::connect(addr, cfg).expect("tls connect");
    c.send(raw).unwrap();
    c.response(raw.starts_with("HEAD ")).expect("a response")
}

/// Whether a command is on PATH.
pub fn have(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd} >/dev/null 2>&1")])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The plugin edge (B-1 P1 on `parvault-fuse webdav --tls-pem`, A-TLS-3): a daemon serving its
/// gateway socket (plain, local), and `parvault-fuse` serving the seeded files over TLS with a PEM
/// file. Real binaries both; killed on drop.
pub struct PluginEdge {
    pub gateway: Daemon,
    pub fuse: Child,
    pub log: PathBuf,
    pub addr: SocketAddr,
    pub pem: PathBuf,
    pub leaf_der: Vec<u8>,
    pub parent: CapabilityMacaroon,
}

impl PluginEdge {
    /// A read-only attenuation of the pinned token (what a client presents).
    pub fn read_token(&self) -> String {
        self.parent
            .attenuate(Caveat::ReadOnly)
            .unwrap()
            .to_compact_token()
    }
    pub fn token_with(&self, caveats: Vec<Caveat>) -> String {
        let mut t = self.parent.attenuate(Caveat::ReadOnly).unwrap();
        for c in caveats {
            t = t.attenuate(c).unwrap();
        }
        t.to_compact_token()
    }
    pub fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
    pub fn client(&self) -> Arc<rustls::ClientConfig> {
        default_client(&self.leaf_der)
    }
}

impl Drop for PluginEdge {
    fn drop(&mut self) {
        let _ = self.fuse.kill();
        let _ = self.fuse.wait();
    }
}

/// The plugin binary (`$PARVAULT_PLUGIN_BIN_DIR` or cargo's).
pub fn fuse_bin() -> PathBuf {
    match std::env::var_os("PARVAULT_PLUGIN_BIN_DIR") {
        Some(d) => Path::new(&d).join("parvault-fuse"),
        None => PathBuf::from(env!("CARGO_BIN_EXE_parvault-fuse")),
    }
}

/// An edge PEM file (certificate, key, SAN list) at `path`, mode 0600, as the daemon writes it.
pub fn write_pem(path: &Path, sans: &[&str]) {
    use std::os::unix::fs::PermissionsExt;
    let sans: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    std::fs::write(path, parvault::edge_tls::generate_pem(&sans).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Starts the gateway daemon in `dir` and `parvault-fuse webdav --listen <listen> --tls-pem
/// <dir>/edge.pem --seed-dir <files>`; waits until it serves HTTPS.
pub fn plugin_edge(dir: &Path, listen: &str, files: &[(&str, Vec<u8>)]) -> PluginEdge {
    let pem = dir.join("edge.pem");
    std::fs::create_dir_all(dir).unwrap();
    write_pem(&pem, &["127.0.0.1", "::1", "nas.local"]);
    let (fuse, log, gateway, parent) =
        spawn_plugin(dir, listen, files, &["--tls-pem", pem.to_str().unwrap()]);
    let mut fuse = fuse;
    let text = wait_plugin(&log, &mut fuse, "WebDAV VFS on https://");
    let port: u16 = text
        .split("WebDAV VFS on https://")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(|u| u.rsplit(':').next())
        .and_then(|p| p.parse().ok())
        .expect("served port");
    let ip: std::net::IpAddr = if listen.starts_with('[') {
        std::net::Ipv6Addr::LOCALHOST.into()
    } else {
        [127, 0, 0, 1].into()
    };
    let leaf_der = leaf_der_of(&std::fs::read(&pem).unwrap());
    PluginEdge {
        gateway,
        fuse,
        log,
        addr: SocketAddr::new(ip, port),
        pem,
        leaf_der,
        parent,
    }
}

/// The daemon (gateway socket only) and a `parvault-fuse webdav` with `extra` flags; the plugin
/// may have exited (a refusal). Returns (plugin, its log, the daemon, the pinned token).
pub fn spawn_plugin(
    dir: &Path,
    listen: &str,
    files: &[(&str, Vec<u8>)],
    extra: &[&str],
) -> (Child, PathBuf, Daemon, CapabilityMacaroon) {
    init_node(dir);
    let key = [0x5D; 32];
    std::fs::write(dir.join("macaroon_root.key"), hex::encode(key)).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("macaroon_root.key"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let sock = dir.join("gw.sock");
    let gateway = up(dir, &["--ipc-socket", sock.to_str().unwrap()]);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !sock.exists() {
        assert!(
            Instant::now() < deadline,
            "no gateway socket:\n{}",
            gateway.log_text()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let parent = CapabilityMacaroon::mint(
        &key,
        [0x31; 32],
        [0x32; 32],
        vec![Caveat::ExpiresAtUnixMs(u64::MAX)],
    )
    .unwrap();
    let seed = write_seed(&dir.join("plugin"), files);
    let log = dir.join("fuse.log");
    let file = std::fs::File::create(&log).unwrap();
    let fuse = Command::new(fuse_bin())
        .arg("--socket")
        .arg(&sock)
        .arg("--cache-dir")
        .arg(dir.join("plugin-cache"))
        .arg("--macaroon")
        .arg(parent.to_compact_token())
        .args(["webdav", "--listen", listen, "--seed-dir"])
        .arg(&seed)
        .args(extra)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::from(file.try_clone().unwrap()))
        .stderr(Stdio::from(file))
        .spawn()
        .unwrap();
    (fuse, log, gateway, parent)
}

/// Waits for `marker` in the plugin log; panics with the log if the plugin exits first.
pub fn wait_plugin(log: &Path, fuse: &mut Child, marker: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if text.contains(marker) {
            return text;
        }
        if let Ok(Some(st)) = fuse.try_wait() {
            panic!("parvault-fuse exited ({st}):\n{text}");
        }
        assert!(Instant::now() < deadline, "no {marker:?}:\n{text}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Waits for the plugin to exit (a refusal); returns its log.
pub fn plugin_refusal(log: &Path, fuse: &mut Child) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(Some(st)) = fuse.try_wait() {
            assert!(!st.success(), "parvault-fuse exited 0");
            return std::fs::read_to_string(log).unwrap_or_default();
        }
        assert!(
            Instant::now() < deadline,
            "parvault-fuse did not refuse:\n{}",
            std::fs::read_to_string(log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
