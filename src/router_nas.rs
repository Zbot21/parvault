//! ParVault embedded status page (`status-ui`): the node's [`StatusSnapshot`] as JSON
//! (`/api/v1/health`, `/api/v1/peers`) and a small HTML dashboard (`/`).
//!
//! Item 3 (plan-3, L-48): a blocking `std::net::TcpListener` on the shared [`crate::http_edge`]
//! (connection slots, 8 KiB heads, one deadline, fixed refusals). Every request presents a
//! read-only token (`Authorization: Bearer`, or as the Basic password; never in the URL), and
//! [`crate::http_edge::status_auth_decision`] runs before the snapshot is fetched over a
//! [`GatewayBus`]: in-process in `parvault`, the gateway socket in `parvault-status`.
//!
//! [`StatusSnapshot`]: crate::gateway::ipc::StatusSnapshot

use crate::capabilities::CapabilityMacaroon;
use crate::gateway::ipc::GatewayBus;
use crate::http_edge::{
    presented_token, read_request_head, spawn_edge_conn, status_auth_decision, status_auth_facts,
    status_host_allowed, EdgeSlots, EdgeVerifier, PresentedToken, StatusAuthFacts, StatusTransport,
    RESP_403, RESP_502, RESP_503, STATUS_401,
};
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Moved to `gateway::ipc` (item 3) so the sidecar and `QueryStatus` share it; the old names
/// stay as aliases. `pairing_sas_code` and `watched_folder` are gone (plan-3 ruling change 3).
pub use crate::gateway::ipc::{
    StatusPeerEntry as RouterNasPeerEntry, StatusSnapshot as RouterNasLiveSnapshot,
};

impl RouterNasLiveSnapshot {
    /// Refreshes process memory telemetry and uptime.
    pub fn update_telemetry(&mut self, start_time: std::time::Instant) {
        let (rss, hwm) = read_linux_process_memory_kib();
        self.rss_kib = rss;
        self.hwm_kib = hwm;
        self.uptime_secs = start_time.elapsed().as_secs();
    }
}

/// Read resident memory (`VmRSS`) and high-water mark (`VmHWM`) from `/proc/self/status` in KiB.
/// Returns `(0, 0)` gracefully on non-Linux operating systems or if `/proc/self/status` is inaccessible.
pub fn read_linux_process_memory_kib() -> (u64, u64) {
    let mut rss = 0u64;
    let mut hwm = 0u64;
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                rss = parse_kib_field(rest);
            } else if let Some(rest) = line.strip_prefix("VmHWM:") {
                hwm = parse_kib_field(rest);
            }
        }
    }
    (rss, hwm)
}

fn parse_kib_field(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|tok| tok.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Most status connections served at once (item 3: the 33rd is dropped unanswered).
pub const STATUS_MAX_CONNECTIONS: usize = 32;

/// RAII handle of a running status server; dropping it stops the accept loop.
pub struct RouterNasServerHandle {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl RouterNasServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops accepting connections (in-flight ones finish on their own threads).
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Blocks until the accept loop exits (a foreground server, e.g. `parvault-status`).
    pub fn wait(mut self) {
        if let Some(h) = self.join_handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for RouterNasServerHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

/// The status page server. There is no constructor without a verifier (L-44).
pub struct RouterNasStatusServer;

impl RouterNasStatusServer {
    /// Binds `bind_addr` (`:0` for an ephemeral port) and serves the snapshot from `bus` to
    /// requests whose token `verifier` accepts. No default address: no flag, no listener.
    pub fn bind_and_spawn(
        bind_addr: SocketAddr,
        bus: GatewayBus,
        verifier: EdgeVerifier,
    ) -> io::Result<(SocketAddr, RouterNasServerHandle)> {
        let listener = TcpListener::bind(bind_addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let slots = Arc::new(EdgeSlots::new(STATUS_MAX_CONNECTIONS));
        let join_handle = std::thread::Builder::new()
            .name("parvault-status-accept".into())
            .spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if stream.set_nonblocking(false).is_err() {
                                continue;
                            }
                            let (bus, verifier) = (bus.clone(), verifier.clone());
                            spawn_edge_conn(stream, &slots, "parvault-status-http", move |s| {
                                let _ = handle_status_conn(s, &bus, &verifier, local_addr);
                            });
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(20)),
                    }
                }
            })?;
        Ok((
            local_addr,
            RouterNasServerHandle {
                local_addr,
                shutdown,
                join_handle: Some(join_handle),
            },
        ))
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The fixed response for a refusal, from the facts in the decision's order: 503 when the node
/// cannot verify or has no snapshot, 403 for a scoped token or a bad Host, and the one
/// byte-identical 401 otherwise. The reason code itself is only logged.
fn status_refusal(f: &StatusAuthFacts) -> &'static [u8] {
    if !f.verifier_present || !f.provider_present {
        RESP_503
    } else if !f.token_present || !f.token_valid || !f.read_only {
        STATUS_401
    } else if f.scoped {
        RESP_403
    } else if !f.peer_uid_ok {
        STATUS_401
    } else {
        RESP_403
    }
}

fn handle_status_conn(
    stream: &mut TcpStream,
    bus: &GatewayBus,
    verifier: &EdgeVerifier,
    bound: SocketAddr,
) -> io::Result<()> {
    let Some(head) = read_request_head(stream)? else {
        return Ok(());
    };
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let mut request = lines.next().unwrap_or("").split_whitespace();
    let method = request.next().unwrap_or("").to_string();
    let raw_path = request.next().unwrap_or("/");
    let path = raw_path.split('?').next().unwrap_or("/").to_string();
    let (mut host, mut authorization) = (None, None);
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                host = Some(v.trim());
            } else if k.eq_ignore_ascii_case("authorization") {
                authorization = Some(v);
            }
        }
    }

    // Item 3: the decision runs before the snapshot is fetched.
    let presented = presented_token(authorization);
    let token: Option<&CapabilityMacaroon> = match &presented {
        PresentedToken::Token(t) => Some(t),
        _ => None,
    };
    let verify = |t: &CapabilityMacaroon| verifier.chain_ok(t);
    let mut facts = status_auth_facts(
        token,
        Some(&verify),
        now_unix_ms(),
        StatusTransport::Tcp,
        status_host_allowed(host, bound),
        true,
    );
    if matches!(presented, PresentedToken::Malformed) {
        facts.token_present = true;
        facts.token_valid = false;
    }
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    if let Err(code) = status_auth_decision(&facts) {
        tracing::warn!(code, peer = %peer, "refused a status request");
        stream.write_all(status_refusal(&facts))?;
        return stream.flush();
    }
    if method != "GET" {
        return send_response(
            stream,
            "405 Method Not Allowed",
            "application/json",
            b"{\"error\":\"method not allowed\"}\n",
        );
    }
    let snap = match bus.query_status_sync(token.cloned()) {
        Ok(s) => s,
        Err(e) => {
            // The daemon's own refusal (or no daemon): 503 when it has no verifier or snapshot,
            // 502 otherwise. Its reason code is in its log, not repeated here.
            let unavailable = e.to_string().contains("status_unavailable");
            tracing::warn!(peer = %peer, unavailable, "status snapshot not served by the gateway");
            stream.write_all(if unavailable { RESP_503 } else { RESP_502 })?;
            return stream.flush();
        }
    };
    match path.as_str() {
        "/api/v1/health" => {
            let json = serde_json::to_vec_pretty(&snap).map_err(io::Error::other)?;
            send_response(stream, "200 OK", "application/json", &json)
        }
        "/api/v1/peers" => {
            let json = serde_json::to_vec_pretty(&snap.lan_peers).map_err(io::Error::other)?;
            send_response(stream, "200 OK", "application/json", &json)
        }
        "/" | "/index.html" => {
            let html = render_dashboard_html(&snap);
            send_response(
                stream,
                "200 OK",
                "text/html; charset=utf-8",
                html.as_bytes(),
            )
        }
        _ => send_response(
            stream,
            "404 Not Found",
            "application/json",
            b"{\"error\":\"not found\"}\n",
        ),
    }
}

fn send_response(stream: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.2} TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.0} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let rem_secs = secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {rem_secs}s")
    } else if minutes > 0 {
        format!("{minutes}m {rem_secs}s")
    } else {
        format!("{rem_secs}s")
    }
}

/// Renders a sleek, responsive, zero-external-asset HTML dashboard (< 6 KiB).
pub fn render_dashboard_html(snap: &RouterNasLiveSnapshot) -> String {
    let label = html_escape(&snap.node_label);
    let version = html_escape(&snap.version);
    let profile = html_escape(&snap.hardware_profile);

    let rss_mib = snap.rss_kib as f64 / 1024.0;
    let hwm_mib = snap.hwm_kib as f64 / 1024.0;
    let mem_status_cls = if hwm_mib <= 32.0 {
        "badge-green"
    } else {
        "badge-amber"
    };
    let mem_status_txt = if hwm_mib <= 32.0 {
        "PASS (&lt; 32 MiB SoC Ceiling)"
    } else {
        "EXCEEDS 32 MiB Target"
    };

    let used_fmt = format_bytes(snap.used_storage_bytes);
    let max_fmt = format_bytes(snap.max_storage_bytes);
    let storage_pct = if snap.max_storage_bytes > 0 {
        ((snap.used_storage_bytes as f64 / snap.max_storage_bytes as f64) * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };

    let stripe_str = if snap.stripe_size_bytes >= 1024 * 1024 {
        format!("{} MiB", snap.stripe_size_bytes / (1024 * 1024))
    } else {
        format!("{} KiB", snap.stripe_size_bytes / 1024)
    };

    let uptime = format_uptime(snap.uptime_secs);

    let mut peer_rows = String::new();
    if snap.lan_peers.is_empty() {
        peer_rows.push_str("<tr><td colspan=\"5\" class=\"text-center muted\">No LAN peers discovered yet (listening on 239.255.80.86:4009)...</td></tr>");
    } else {
        for peer in &snap.lan_peers {
            let p_id = html_escape(&peer.peer_id);
            let p_lbl = html_escape(&peer.label);
            let p_role = html_escape(&peer.role);
            let p_addr = html_escape(&peer.multiaddr);
            let p_avail = format_bytes(peer.available_bytes);
            peer_rows.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td><span class=\"badge-role\">{}</span></td><td class=\"code-sm\">{}</td><td>{}</td></tr>\n",
                p_id, p_lbl, p_role, p_addr, p_avail
            ));
        }
    }

    let dev_peer_id = html_escape(&snap.device_peer_id);
    let libp2p_id = html_escape(&snap.libp2p_peer_id);

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>ParVault Cloud NAS — Router Appliance Status</title>
<style>
:root{{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--cyan:#38bdf8;--green:#10b981;--amber:#f59e0b;--purple:#a855f7}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;padding:1.25rem}}
.container{{max-width:960px;margin:0 auto}}
header{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.75rem;padding-bottom:1rem;border-bottom:1px solid var(--border);margin-bottom:1.25rem}}
h1{{font-size:1.35rem;font-weight:700;display:flex;align-items:center;gap:0.5rem}}
.sub{{color:var(--muted);font-size:0.85rem}}
.badge{{font-size:0.75rem;padding:0.2rem 0.55rem;border-radius:9999px;font-weight:600;display:inline-block}}
.badge-profile{{background:#1e3a8a;color:#93c5fd;border:1px solid #3b82f6}}
.badge-green{{background:#064e3b;color:#6ee7b7;border:1px solid var(--green)}}
.badge-amber{{background:#78350f;color:#fcd34d;border:1px solid var(--amber)}}
.badge-muted{{background:#334155;color:var(--muted)}}
.badge-role{{background:#312e81;color:#c7d2fe;font-size:0.75rem;padding:0.15rem 0.45rem;border-radius:4px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem;margin-bottom:1.25rem}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem}}
.card h2{{font-size:0.9rem;text-transform:uppercase;color:var(--muted);letter-spacing:0.05em;margin-bottom:0.5rem}}
.val{{font-size:1.4rem;font-weight:700;color:var(--cyan)}}
.bar-box{{background:#0f172a;border-radius:4px;height:10px;overflow:hidden;margin:0.5rem 0}}
.bar{{background:linear-gradient(90deg,var(--cyan),var(--green));height:100%}}
table{{width:100%;border-collapse:collapse;font-size:0.85rem}}
th,td{{text-align:left;padding:0.6rem;border-bottom:1px solid var(--border)}}
th{{color:var(--muted);font-weight:600}}
code{{font-family:ui-monospace,monospace;font-size:0.82rem;background:#0f172a;padding:0.1rem 0.35rem;border-radius:3px}}
.code-sm{{font-size:0.75rem;word-break:break-all}}
.text-center{{text-align:center}}.muted{{color:var(--muted)}}
footer{{margin-top:1.25rem;font-size:0.75rem;color:var(--muted);display:flex;justify-content:space-between;flex-wrap:wrap;gap:0.5rem}}
</style>
</head>
<body>
<div class="container">
<header>
<div>
<h1>ParVault Cloud NAS <span class="badge badge-profile">{profile}</span></h1>
<div class="sub">Node: <strong>{label}</strong> &bull; v{version} &bull; Uptime: {uptime} &bull; SLA: {sla}</div>
</div>
</header>
<div class="grid">
<div class="card">
<h2>Resident RAM (VmRSS / VmHWM)</h2>
<div class="val">{rss_mib:.1} MiB <span style="font-size:0.95rem;color:var(--muted)">/ {hwm_mib:.1} MiB</span></div>
<div style="margin-top:0.4rem"><span class="badge {mem_cls}">{mem_txt}</span></div>
</div>
<div class="card">
<h2>Storage Pool ({storage_pct:.1}%)</h2>
<div class="val">{used_fmt} <span style="font-size:0.95rem;color:var(--muted)">/ {max_fmt}</span></div>
<div class="bar-box"><div class="bar" style="width:{storage_pct:.1}%;"></div></div>
</div>
<div class="card">
<h2>NAS Sync &amp; Network</h2>
<div style="font-size:0.85rem">Stripe Size: <strong>{stripe}</strong> &bull; Quota Limit: <strong>{max_fmt}</strong></div>
<div style="font-size:0.75rem;margin-top:0.4rem;color:var(--muted);word-break:break-all">Libp2p: <code>{libp2p}</code></div>
</div>
</div>
<div class="card">
<h2>Auto-Discovered LAN Peers ({peer_count})</h2>
<div style="overflow-x:auto">
<table>
<thead><tr><th>Peer ID</th><th>Label</th><th>Role</th><th>Multiaddress</th><th>Available</th></tr></thead>
<tbody>
{peers}</tbody>
</table>
</div>
</div>
<footer>
<div>Device: <code>{dev_id}</code></div>
<div>Auto-refreshes every 5s &bull; Zero-Framework Embedded HTTP Status API</div>
</footer>
</div>
</body>
</html>"##,
        profile = profile,
        label = label,
        version = version,
        uptime = uptime,
        sla = html_escape(&snap.sla_tier),
        rss_mib = rss_mib,
        hwm_mib = hwm_mib,
        mem_cls = mem_status_cls,
        mem_txt = mem_status_txt,
        storage_pct = storage_pct,
        used_fmt = used_fmt,
        max_fmt = max_fmt,
        stripe = stripe_str,
        libp2p = libp2p_id,
        peer_count = snap.lan_peers.len(),
        peers = peer_rows,
        dev_id = dev_peer_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_linux_process_memory() {
        let (rss, hwm) = read_linux_process_memory_kib();
        #[cfg(target_os = "linux")]
        {
            // On Linux systems, a running cargo test process will have non-zero RSS and HWM.
            assert!(rss > 0, "VmRSS should be > 0 on Linux");
            assert!(hwm >= rss, "VmHWM should be >= VmRSS on Linux");
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (rss, hwm);
        }
    }

    #[test]
    fn test_dashboard_html_rendering_size() {
        let snap = RouterNasLiveSnapshot {
            node_label: "openwrt-gateway".to_string(),
            rss_kib: 14 * 1024,
            hwm_kib: 18 * 1024,
            used_storage_bytes: 5 * 1024 * 1024 * 1024,
            max_storage_bytes: 64 * 1024 * 1024 * 1024,
            lan_peers: vec![RouterNasPeerEntry {
                peer_id: "12D3KooWTestPeer1".to_string(),
                label: "macbook-air".to_string(),
                role: "client".to_string(),
                multiaddr: "/ip4/192.168.1.105/tcp/4001/p2p/12D3KooWTestPeer1".to_string(),
                available_bytes: 100 * 1024 * 1024 * 1024,
            }],
            ..RouterNasLiveSnapshot::default()
        };

        let html = render_dashboard_html(&snap);
        assert!(html.contains("ParVault Cloud NAS"));
        assert!(html.contains("openwrt-gateway"));
        assert!(html.contains("12D3KooWTestPeer1"));
        assert!(
            html.len() < 6144,
            "Rendered HTML must be < 6 KiB (actual: {} bytes)",
            html.len()
        );
    }

    // The HTTP endpoints are covered end to end in tests/trust_enforcement.rs (status_http_*)
    // and tests/zero_config_lan_and_router_soc_tests.rs (test_4).
}
