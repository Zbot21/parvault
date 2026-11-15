//! The unauthenticated `--lab-insecure-metrics <IFACE>=<IP:PORT>` listener (`v0.5.4`,
//! `docs/METRICS.md`). Debug builds with the `lab-insecure-metrics` feature only: a release
//! build with the feature is a compile error (`lib.rs`), and shipped artifacts are scanned for
//! [`INSECURE_METRICS_MARKER`] (`scripts/check_no_insecure_metrics.sh`).
//!
//! It is a listener of its own, separate from the status page, so the authenticated path has no
//! "skip auth" branch in any build. It serves only `GET /metrics`, from the same renderer, after
//! `status_host_allowed` (403 otherwise), with its own 4 connection slots and the shared head and
//! write timeouts. Every response carries the marker header, and the listener logs the marker at
//! start, so the marker bytes are in every binary that has the listener.

use crate::http_edge::{read_request_head, spawn_edge_conn, status_host_allowed, EdgeSlots};
use crate::traversal_metrics::{
    build_facts, insecure_metrics_listener_decision, InsecureMetricsFacts, TraversalCounters,
};
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The marker in every response header and in the start log line.
pub const INSECURE_METRICS_MARKER: &str = "PARVAULT-LAB-INSECURE-METRICS-v1";

/// Connection slots of the insecure listener.
pub const INSECURE_METRICS_MAX_CONNECTIONS: usize = 4;

/// Parses `<IFACE>=<IP:PORT>`.
pub fn parse_spec(spec: &str) -> Result<(String, SocketAddr), &'static str> {
    let (iface, addr) = spec.split_once('=').ok_or("reject.metrics_insecure_spec")?;
    let addr: SocketAddr = addr
        .trim()
        .parse()
        .map_err(|_| "reject.metrics_insecure_spec")?;
    let iface = iface.trim();
    if iface.is_empty() {
        return Err("reject.metrics_insecure_spec");
    }
    Ok((iface.to_string(), addr))
}

/// A running insecure listener; dropping it stops the accept loop.
pub struct InsecureMetricsHandle {
    pub local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Drop for InsecureMetricsHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Checks the facts (`insecure_metrics_listener_decision`) at bind time, then binds and serves.
pub fn spawn(
    spec: &str,
    counters: Arc<TraversalCounters>,
) -> anyhow::Result<InsecureMetricsHandle> {
    let (iface, addr) = parse_spec(spec).map_err(|c| anyhow::anyhow!("{c}: {spec}"))?;
    let bf = build_facts();
    let facts = InsecureMetricsFacts {
        feature: bf.insecure_metrics_feature,
        debug_assertions: bf.debug_assertions,
        unspecified: addr.ip().to_canonical().is_unspecified(),
        iface_owns_ip: crate::os_sys::interface_has_ip(&iface, addr.ip())?,
    };
    if let Err(code) = insecure_metrics_listener_decision(&facts) {
        tracing::warn!(code, "refused the insecure metrics listener");
        anyhow::bail!("{code}: --lab-insecure-metrics {iface}=<ip:port>");
    }
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let local_addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stop);
    let slots = Arc::new(EdgeSlots::new(INSECURE_METRICS_MAX_CONNECTIONS));
    tracing::warn!(
        marker = INSECURE_METRICS_MARKER,
        %local_addr,
        iface = %iface,
        "UNAUTHENTICATED metrics listener active (debug lab build)"
    );
    println!("[parvault] {INSECURE_METRICS_MARKER} listening on http://{local_addr}/metrics");
    std::thread::Builder::new()
        .name("parvault-insecure-metrics".into())
        .spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let c = Arc::clone(&counters);
                        spawn_edge_conn(stream, &slots, "parvault-insecure-metrics", move |st| {
                            let _ = handle(st, &c, local_addr);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        })?;
    Ok(InsecureMetricsHandle { local_addr, stop })
}

fn respond(stream: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nX-Parvault-Insecure-Metrics: {INSECURE_METRICS_MARKER}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn handle(
    stream: &mut TcpStream,
    counters: &TraversalCounters,
    bound: SocketAddr,
) -> io::Result<()> {
    let Some(head) = read_request_head(stream)? else {
        return Ok(());
    };
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let mut req = lines.next().unwrap_or("").split_whitespace();
    let method = req.next().unwrap_or("");
    let path = req.next().unwrap_or("/").split('?').next().unwrap_or("/");
    let host = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.trim());
    if !status_host_allowed(host, bound) {
        return respond(stream, "403 Forbidden", "text/plain", b"forbidden\n");
    }
    if method != "GET" {
        return respond(
            stream,
            "405 Method Not Allowed",
            "text/plain",
            b"method not allowed\n",
        );
    }
    if path != crate::router_nas::METRICS_PATH {
        return respond(stream, "404 Not Found", "text/plain", b"not found\n");
    }
    respond(
        stream,
        "200 OK",
        crate::router_nas::METRICS_CONTENT_TYPE,
        counters.render_prometheus().as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_parses_iface_and_socket() {
        assert_eq!(
            parse_spec("lo=127.0.0.1:9100"),
            Ok(("lo".to_string(), "127.0.0.1:9100".parse().unwrap()))
        );
        assert!(parse_spec("127.0.0.1:9100").is_err());
        assert!(parse_spec("=127.0.0.1:9100").is_err());
        assert!(parse_spec("lo=localhost:9100").is_err());
    }
}
