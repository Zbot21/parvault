//! ParVault v0.3.0 — Embedded Router Cloud-NAS Dashboard & Control HTTP API
//!
//! Provides a zero-dependency, ultra-lightweight HTTP status server and embedded HTML dashboard
//! for hardware routers (OpenWrt LuCI, prplOS, ARM64/MIPS SoC gateways) and home users.
//!
//! Built strictly with `tokio::net::TcpListener`, `tokio::io`, and `serde_json` to eliminate
//! heavy web framework dependencies (axum/hyper/actix) and maintain a tiny binary footprint (< 32 MiB RAM).

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

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

/// Handle controlling the background HTTP server task.
#[derive(Debug)]
pub struct RouterNasServerHandle {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl RouterNasServerHandle {
    /// Signal the server to stop accepting connections and shut down cleanly.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Alias for `shutdown`.
    pub fn stop(&self) {
        self.shutdown();
    }

    /// Awaits completion of the background server task.
    pub async fn wait(mut self) {
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for RouterNasServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Zero-dependency Router Cloud-NAS HTTP Server.
pub struct RouterNasStatusServer;

impl RouterNasStatusServer {
    /// Binds to `bind_addr` and spawns the background server loop.
    ///
    /// Supports ephemeral `:0` binding for automated tests.
    pub async fn bind_and_spawn(
        bind_addr: SocketAddr,
        state: Arc<RwLock<RouterNasLiveSnapshot>>,
    ) -> anyhow::Result<(SocketAddr, RouterNasServerHandle)> {
        let listener = TcpListener::bind(bind_addr).await?;
        Self::spawn_on_listener(listener, state)
    }

    /// Binds synchronously using standard library `TcpListener` and spawns in the active Tokio runtime.
    pub fn bind_and_spawn_std(
        bind_addr: SocketAddr,
        state: Arc<RwLock<RouterNasLiveSnapshot>>,
    ) -> anyhow::Result<(SocketAddr, RouterNasServerHandle)> {
        let std_listener = std::net::TcpListener::bind(bind_addr)?;
        std_listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std_listener)?;
        Self::spawn_on_listener(listener, state)
    }

    /// Spawns the background server loop on an existing Tokio `TcpListener`.
    pub fn spawn_on_listener(
        listener: TcpListener,
        state: Arc<RwLock<RouterNasLiveSnapshot>>,
    ) -> anyhow::Result<(SocketAddr, RouterNasServerHandle)> {
        let local_addr = listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let start_time = std::time::Instant::now();
        let server_state = Arc::clone(&state);

        let join_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok((stream, _peer_addr)) => {
                                let st = Arc::clone(&server_state);
                                tokio::spawn(async move {
                                    let _ = handle_client(stream, st, start_time).await;
                                });
                            }
                            Err(e) => {
                                tracing::debug!("Router NAS status server accept error: {e}");
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        Ok((
            local_addr,
            RouterNasServerHandle {
                shutdown_tx,
                join_handle: Some(join_handle),
            },
        ))
    }
}

async fn handle_client(
    mut stream: tokio::net::TcpStream,
    state: Arc<RwLock<RouterNasLiveSnapshot>>,
    start_time: std::time::Instant,
) -> anyhow::Result<()> {
    // Strict 4 KiB request header cap
    let mut buf = [0u8; 4096];
    let mut total_read = 0;

    while total_read < buf.len() {
        let n = stream.read(&mut buf[total_read..]).await?;
        if n == 0 {
            break;
        }
        total_read += n;
        if buf[..total_read].windows(4).any(|w| w == b"\r\n\r\n")
            || buf[..total_read].windows(2).any(|w| w == b"\n\n")
        {
            break;
        }
    }

    if total_read == 0 {
        return Ok(());
    }

    let req_str = match std::str::from_utf8(&buf[..total_read]) {
        Ok(s) => s,
        Err(_) => {
            send_response(
                &mut stream,
                "400 Bad Request",
                "application/json",
                b"{\"error\":\"invalid utf-8\"}\n",
            )
            .await?;
            return Ok(());
        }
    };

    let first_line = req_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_response(
            &mut stream,
            "400 Bad Request",
            "application/json",
            b"{\"error\":\"malformed request line\"}\n",
        )
        .await?;
        return Ok(());
    }

    let method = parts[0];
    let raw_path = parts[1];
    let path = raw_path.split('?').next().unwrap_or(raw_path);

    if method != "GET" {
        let err_json = format!(
            "{{\"error\":\"method not allowed\",\"method\":\"{}\"}}\n",
            method
        );
        send_response(
            &mut stream,
            "405 Method Not Allowed",
            "application/json",
            err_json.as_bytes(),
        )
        .await?;
        return Ok(());
    }

    match path {
        "/api/v1/health" => {
            {
                let mut guard = state.write().await;
                guard.update_telemetry(start_time);
            }
            let snap = state.read().await.clone();
            let json = serde_json::to_vec_pretty(&snap)?;
            send_response(&mut stream, "200 OK", "application/json", &json).await?;
        }
        "/api/v1/peers" => {
            let peers = state.read().await.lan_peers.clone();
            let json = serde_json::to_vec_pretty(&peers)?;
            send_response(&mut stream, "200 OK", "application/json", &json).await?;
        }
        "/" | "/index.html" => {
            {
                let mut guard = state.write().await;
                guard.update_telemetry(start_time);
            }
            let snap = state.read().await.clone();
            let html = render_dashboard_html(&snap);
            send_response(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                html.as_bytes(),
            )
            .await?;
        }
        _ => {
            let not_found = format!("{{\"error\":\"not found\",\"path\":\"{}\"}}\n", path);
            send_response(
                &mut stream,
                "404 Not Found",
                "application/json",
                not_found.as_bytes(),
            )
            .await?;
        }
    }

    Ok(())
}

async fn send_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    let header = format!(
        "HTTP/1.1 {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Cache-Control: no-store\r\n\
         \r\n",
        status,
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
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
    use std::time::Duration;

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

    #[tokio::test]
    async fn test_router_nas_http_server_endpoints() -> anyhow::Result<()> {
        let initial_snap = RouterNasLiveSnapshot {
            node_label: "test-router-node".to_string(),
            lan_peers: vec![RouterNasPeerEntry {
                peer_id: "12D3KooWPeer1".to_string(),
                label: "laptop".to_string(),
                role: "client".to_string(),
                multiaddr: "/ip4/192.168.1.50/tcp/4001".to_string(),
                available_bytes: 50_000_000,
            }],
            ..RouterNasLiveSnapshot::default()
        };
        let state = Arc::new(RwLock::new(initial_snap));

        let (addr, handle) =
            RouterNasStatusServer::bind_and_spawn("127.0.0.1:0".parse()?, Arc::clone(&state))
                .await?;

        // 1. Test GET /api/v1/health
        {
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            stream
                .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await?;
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await?;
            let resp_str = String::from_utf8(resp)?;
            assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
            assert!(resp_str.contains("Content-Type: application/json"));
            assert!(resp_str.contains("X-Content-Type-Options: nosniff"));
            assert!(resp_str.contains("Cache-Control: no-store"));
            assert!(resp_str.contains("Connection: close"));
            let body = resp_str.split("\r\n\r\n").nth(1).unwrap();
            let parsed: RouterNasLiveSnapshot = serde_json::from_str(body)?;
            assert_eq!(parsed.node_label, "test-router-node");
            // Item 3: the pairing SAS code is no longer in the status snapshot.
            assert!(!body.contains("sas"));
        }

        // 2. Test GET /api/v1/peers
        {
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            stream
                .write_all(b"GET /api/v1/peers HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await?;
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await?;
            let resp_str = String::from_utf8(resp)?;
            assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
            let body = resp_str.split("\r\n\r\n").nth(1).unwrap();
            let peers: Vec<RouterNasPeerEntry> = serde_json::from_str(body)?;
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].peer_id, "12D3KooWPeer1");
            assert_eq!(peers[0].label, "laptop");
        }

        // 3. Test GET / (HTML Dashboard)
        {
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await?;
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await?;
            let resp_str = String::from_utf8(resp)?;
            assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
            assert!(resp_str.contains("Content-Type: text/html; charset=utf-8"));
            assert!(resp_str.contains("ParVault Cloud NAS"));
            // Item 3: the dashboard no longer shows the pairing SAS code.
            assert!(!resp_str.contains("sas-code"));
        }

        // 4. Test 404 for unknown route
        {
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            stream
                .write_all(b"GET /unknown/path HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await?;
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await?;
            let resp_str = String::from_utf8(resp)?;
            assert!(resp_str.starts_with("HTTP/1.1 404 Not Found"));
            assert!(resp_str.contains("\"error\":\"not found\""));
        }

        // 5. Shutdown
        handle.shutdown();
        tokio::time::sleep(Duration::from_millis(50)).await;

        Ok(())
    }
}
