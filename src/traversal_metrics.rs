//! Per-attempt traversal counters and `GET /metrics` (`v0.5.4` NEW-3, `docs/METRICS.md`).
//!
//! No tokio or libp2p: the status page (`status-ui`) renders these, and `TraversalGate`
//! (`network::traversal_gate`, `daemon-runtime`) records into them. Every label value comes from
//! a closed enum, every series is pre-registered at zero, and the arrays are fixed-size atomics:
//! no lock and no allocation on the swarm path, and a constant body size.
//!
//! The index functions ([`flat_index`] and its siblings) are the only way into the arrays; every
//! `record_*` uses them and Kani `proof_reason_index_in_bounds` proves them in bounds and
//! injective.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Which swarm made the attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Origin {
    Daemon,
    Client,
}

/// `relayed` iff the address has `/p2p-circuit` (always `direct` until `v0.5.9`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum PathKind {
    Direct,
    Relayed,
}

/// The transport of an outcome; `None` when the outcome names no address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum TransportKind {
    Tcp,
    Quic,
    None,
}

/// The transport of a connection (always known).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum ConnTransport {
    Tcp,
    Quic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Direction {
    Outbound,
    Inbound,
}

/// Why a dial ended (shared with `net probe`, NEW-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum TraversalReason {
    Ok,
    Timeout,
    Refused,
    Unreachable,
    NoiseFailed,
    PeerIdMismatch,
    TransportUnsupported,
    Denied,
    Aborted,
    Other,
}

/// The status page's refusal codes (`http_edge::status_auth_decision`), as metric labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum StatusRefusal {
    Unavailable,
    TokenMissing,
    TokenInvalid,
    NotReadonly,
    TokenScoped,
    PeerUid,
    HostMismatch,
}

pub const ORIGINS: [Origin; 2] = [Origin::Daemon, Origin::Client];
pub const PATHS: [PathKind; 2] = [PathKind::Direct, PathKind::Relayed];
pub const TRANSPORTS: [TransportKind; 3] =
    [TransportKind::Tcp, TransportKind::Quic, TransportKind::None];
pub const CONN_TRANSPORTS: [ConnTransport; 2] = [ConnTransport::Tcp, ConnTransport::Quic];
pub const DIRECTIONS: [Direction; 2] = [Direction::Outbound, Direction::Inbound];
pub const REASONS: [TraversalReason; 10] = [
    TraversalReason::Ok,
    TraversalReason::Timeout,
    TraversalReason::Refused,
    TraversalReason::Unreachable,
    TraversalReason::NoiseFailed,
    TraversalReason::PeerIdMismatch,
    TraversalReason::TransportUnsupported,
    TraversalReason::Denied,
    TraversalReason::Aborted,
    TraversalReason::Other,
];
pub const STATUS_REFUSALS: [StatusRefusal; 7] = [
    StatusRefusal::Unavailable,
    StatusRefusal::TokenMissing,
    StatusRefusal::TokenInvalid,
    StatusRefusal::NotReadonly,
    StatusRefusal::TokenScoped,
    StatusRefusal::PeerUid,
    StatusRefusal::HostMismatch,
];

/// Histogram bucket upper bounds in seconds (`+Inf` is the last bucket).
pub const BUCKETS_SECS: [f64; 12] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];
/// Buckets including `+Inf`.
pub const N_BUCKETS: usize = BUCKETS_SECS.len() + 1;

pub const N_ATTEMPTS: usize = 2;
pub const N_OUTCOMES: usize = 2 * 2 * 3 * 10;
pub const N_INBOUND: usize = 2 * 2;
pub const N_HIST_SERIES: usize = 2 * 2;
pub const N_HIST_BUCKETS: usize = N_HIST_SERIES * N_BUCKETS;
pub const N_CONNECTIONS: usize = 2 * 2 * 2;
pub const N_REFUSED: usize = 7;

/// The `pending` map of `TraversalGate` (A1): at most this many dials are timed at once; more
/// are counted in `parvault_traversal_timing_overflow_total` and not timed.
pub const MAX_TIMED_DIALS: usize = 1024;

impl Origin {
    pub const fn index(self) -> usize {
        match self {
            Self::Daemon => 0,
            Self::Client => 1,
        }
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Client => "client",
        }
    }
}

impl PathKind {
    pub const fn index(self) -> usize {
        match self {
            Self::Direct => 0,
            Self::Relayed => 1,
        }
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relayed => "relayed",
        }
    }
}

impl TransportKind {
    pub const fn index(self) -> usize {
        match self {
            Self::Tcp => 0,
            Self::Quic => 1,
            Self::None => 2,
        }
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
            Self::None => "none",
        }
    }
}

impl ConnTransport {
    pub const fn index(self) -> usize {
        match self {
            Self::Tcp => 0,
            Self::Quic => 1,
        }
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
        }
    }
}

impl Direction {
    pub const fn index(self) -> usize {
        match self {
            Self::Outbound => 0,
            Self::Inbound => 1,
        }
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
        }
    }
}

impl TraversalReason {
    pub const fn index(self) -> usize {
        match self {
            Self::Ok => 0,
            Self::Timeout => 1,
            Self::Refused => 2,
            Self::Unreachable => 3,
            Self::NoiseFailed => 4,
            Self::PeerIdMismatch => 5,
            Self::TransportUnsupported => 6,
            Self::Denied => 7,
            Self::Aborted => 8,
            Self::Other => 9,
        }
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Timeout => "timeout",
            Self::Refused => "refused",
            Self::Unreachable => "unreachable",
            Self::NoiseFailed => "noise_failed",
            Self::PeerIdMismatch => "peer_id_mismatch",
            Self::TransportUnsupported => "transport_unsupported",
            Self::Denied => "denied",
            Self::Aborted => "aborted",
            Self::Other => "other",
        }
    }
}

impl StatusRefusal {
    pub const fn index(self) -> usize {
        match self {
            Self::Unavailable => 0,
            Self::TokenMissing => 1,
            Self::TokenInvalid => 2,
            Self::NotReadonly => 3,
            Self::TokenScoped => 4,
            Self::PeerUid => 5,
            Self::HostMismatch => 6,
        }
    }
    /// The label: the reason code without its `reject.` prefix.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "status_unavailable",
            Self::TokenMissing => "status_token_missing",
            Self::TokenInvalid => "status_token_invalid",
            Self::NotReadonly => "status_not_readonly",
            Self::TokenScoped => "status_token_scoped",
            Self::PeerUid => "status_peer_uid",
            Self::HostMismatch => "status_host_mismatch",
        }
    }
    /// From a `status_auth_decision` code (`reject.<label>`); `None` for anything else.
    pub fn from_code(code: &str) -> Option<Self> {
        let label = code.strip_prefix("reject.")?;
        STATUS_REFUSALS.into_iter().find(|r| r.label() == label)
    }
}

/// The outcome index: `((origin × 2 + path) × 3 + transport) × 10 + reason`.
pub const fn flat_index(
    origin: Origin,
    path: PathKind,
    transport: TransportKind,
    reason: TraversalReason,
) -> usize {
    ((origin.index() * 2 + path.index()) * 3 + transport.index()) * 10 + reason.index()
}

/// The attempt index.
pub const fn attempt_index(origin: Origin) -> usize {
    origin.index()
}

/// The inbound and histogram-series index: `path × 2 + transport`.
pub const fn conn_series_index(path: PathKind, transport: ConnTransport) -> usize {
    path.index() * 2 + transport.index()
}

/// The histogram bucket index: `series × N_BUCKETS + bucket` (`bucket < N_BUCKETS`).
pub const fn hist_index(path: PathKind, transport: ConnTransport, bucket: usize) -> usize {
    let b = if bucket < N_BUCKETS {
        bucket
    } else {
        N_BUCKETS - 1
    };
    conn_series_index(path, transport) * N_BUCKETS + b
}

/// The connection-gauge index: `(direction × 2 + path) × 2 + transport`.
pub const fn connection_index(
    direction: Direction,
    path: PathKind,
    transport: ConnTransport,
) -> usize {
    (direction.index() * 2 + path.index()) * 2 + transport.index()
}

/// The refusal index.
pub const fn refused_index(r: StatusRefusal) -> usize {
    r.index()
}

/// The bucket a duration falls in (the first bound it does not exceed, else `+Inf`).
pub fn bucket_of(d: Duration) -> usize {
    let s = d.as_secs_f64();
    BUCKETS_SECS
        .iter()
        .position(|b| s <= *b)
        .unwrap_or(N_BUCKETS - 1)
}

/// The labels of `parvault_build_info`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildInfo {
    /// The hardware profile (`desktop`, `homelab-nas`, `router-soc`).
    pub profile: &'static str,
    pub deterministic: bool,
}

fn zeroed<const N: usize>() -> [AtomicU64; N] {
    std::array::from_fn(|_| AtomicU64::new(0))
}

/// The counters of one daemon process.
pub struct TraversalCounters {
    build: BuildInfo,
    attempts: [AtomicU64; N_ATTEMPTS],
    outcomes: [AtomicU64; N_OUTCOMES],
    inbound: [AtomicU64; N_INBOUND],
    hist_buckets: [AtomicU64; N_HIST_BUCKETS],
    hist_sum_us: [AtomicU64; N_HIST_SERIES],
    hist_count: [AtomicU64; N_HIST_SERIES],
    connections: [AtomicI64; N_CONNECTIONS],
    refused: [AtomicU64; N_REFUSED],
    timing_overflow: AtomicU64,
}

impl std::fmt::Debug for TraversalCounters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraversalCounters").finish_non_exhaustive()
    }
}

impl TraversalCounters {
    pub fn new(build: BuildInfo) -> Self {
        Self {
            build,
            attempts: zeroed(),
            outcomes: zeroed(),
            inbound: zeroed(),
            hist_buckets: zeroed(),
            hist_sum_us: zeroed(),
            hist_count: zeroed(),
            connections: std::array::from_fn(|_| AtomicI64::new(0)),
            refused: zeroed(),
            timing_overflow: AtomicU64::new(0),
        }
    }

    /// One `handle_pending_outbound_connection` call on `TraversalGate`.
    pub fn record_attempt(&self, origin: Origin) {
        self.attempts[attempt_index(origin)].fetch_add(1, Ordering::Relaxed);
    }

    /// The one outcome of an attempt. `Release`, after the attempt's increment on the same swarm
    /// task, so a scrape that sees the outcome also sees its attempt.
    pub fn record_outcome(
        &self,
        origin: Origin,
        path: PathKind,
        transport: TransportKind,
        reason: TraversalReason,
    ) {
        self.outcomes[flat_index(origin, path, transport, reason)].fetch_add(1, Ordering::Release);
    }

    /// Time from the attempt to an established outbound connection.
    pub fn record_connect_time(&self, path: PathKind, transport: ConnTransport, d: Duration) {
        let series = conn_series_index(path, transport);
        self.hist_buckets[hist_index(path, transport, bucket_of(d))]
            .fetch_add(1, Ordering::Relaxed);
        let us = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        self.hist_sum_us[series].fetch_add(us, Ordering::Relaxed);
        self.hist_count[series].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_inbound(&self, path: PathKind, transport: ConnTransport) {
        self.inbound[conn_series_index(path, transport)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_open(&self, direction: Direction, path: PathKind, transport: ConnTransport) {
        self.connections[connection_index(direction, path, transport)]
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_close(&self, direction: Direction, path: PathKind, transport: ConnTransport) {
        self.connections[connection_index(direction, path, transport)]
            .fetch_sub(1, Ordering::Relaxed);
    }

    /// A status-page refusal; codes outside the 7 are not counted.
    pub fn record_status_refused(&self, code: &str) {
        if let Some(r) = StatusRefusal::from_code(code) {
            self.refused[refused_index(r)].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A dial the gate could not time because `MAX_TIMED_DIALS` were in flight.
    pub fn record_timing_overflow(&self) {
        self.timing_overflow.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus text format 0.0.4. Outcomes are read (`Acquire`) before attempts, so every
    /// scrape has `attempts_total{origin} >= Σ outcomes_total{origin,…}`.
    pub fn render_prometheus(&self) -> String {
        use std::fmt::Write;
        let outcomes: Vec<u64> = self
            .outcomes
            .iter()
            .map(|a| a.load(Ordering::Acquire))
            .collect();
        let attempts: Vec<u64> = self
            .attempts
            .iter()
            .map(|a| a.load(Ordering::Relaxed))
            .collect();
        let mut out = String::with_capacity(32 * 1024);
        let _ = writeln!(
            out,
            "# HELP parvault_traversal_attempts_total Outbound connection attempts (one per dial that passed its peer condition)."
        );
        let _ = writeln!(out, "# TYPE parvault_traversal_attempts_total counter");
        for o in ORIGINS {
            let _ = writeln!(
                out,
                "parvault_traversal_attempts_total{{origin=\"{}\"}} {}",
                o.label(),
                attempts[attempt_index(o)]
            );
        }
        let _ = writeln!(
            out,
            "# HELP parvault_traversal_outcomes_total The one outcome of each attempt."
        );
        let _ = writeln!(out, "# TYPE parvault_traversal_outcomes_total counter");
        for o in ORIGINS {
            for p in PATHS {
                for t in TRANSPORTS {
                    for r in REASONS {
                        let _ = writeln!(
                            out,
                            "parvault_traversal_outcomes_total{{origin=\"{}\",path=\"{}\",transport=\"{}\",reason=\"{}\"}} {}",
                            o.label(),
                            p.label(),
                            t.label(),
                            r.label(),
                            outcomes[flat_index(o, p, t, r)]
                        );
                    }
                }
            }
        }
        let _ = writeln!(
            out,
            "# HELP parvault_traversal_inbound_total Inbound connections established."
        );
        let _ = writeln!(out, "# TYPE parvault_traversal_inbound_total counter");
        for p in PATHS {
            for t in CONN_TRANSPORTS {
                let _ = writeln!(
                    out,
                    "parvault_traversal_inbound_total{{path=\"{}\",transport=\"{}\"}} {}",
                    p.label(),
                    t.label(),
                    self.inbound[conn_series_index(p, t)].load(Ordering::Relaxed)
                );
            }
        }
        let _ = writeln!(
            out,
            "# HELP parvault_traversal_connect_seconds Time from an attempt to its established outbound connection."
        );
        let _ = writeln!(out, "# TYPE parvault_traversal_connect_seconds histogram");
        for p in PATHS {
            for t in CONN_TRANSPORTS {
                let mut cumulative = 0u64;
                for b in 0..N_BUCKETS {
                    cumulative = cumulative.saturating_add(
                        self.hist_buckets[hist_index(p, t, b)].load(Ordering::Relaxed),
                    );
                    let le = BUCKETS_SECS
                        .get(b)
                        .map(|v| format!("{v}"))
                        .unwrap_or_else(|| "+Inf".to_string());
                    let _ = writeln!(
                        out,
                        "parvault_traversal_connect_seconds_bucket{{path=\"{}\",transport=\"{}\",le=\"{le}\"}} {cumulative}",
                        p.label(),
                        t.label()
                    );
                }
                let s = conn_series_index(p, t);
                let sum_us = self.hist_sum_us[s].load(Ordering::Relaxed);
                let _ = writeln!(
                    out,
                    "parvault_traversal_connect_seconds_sum{{path=\"{}\",transport=\"{}\"}} {}.{:06}",
                    p.label(),
                    t.label(),
                    sum_us / 1_000_000,
                    sum_us % 1_000_000
                );
                let _ = writeln!(
                    out,
                    "parvault_traversal_connect_seconds_count{{path=\"{}\",transport=\"{}\"}} {}",
                    p.label(),
                    t.label(),
                    self.hist_count[s].load(Ordering::Relaxed)
                );
            }
        }
        let _ = writeln!(
            out,
            "# HELP parvault_traversal_connections Open connections."
        );
        let _ = writeln!(out, "# TYPE parvault_traversal_connections gauge");
        for d in DIRECTIONS {
            for p in PATHS {
                for t in CONN_TRANSPORTS {
                    let v = self.connections[connection_index(d, p, t)]
                        .load(Ordering::Relaxed)
                        .max(0);
                    let _ = writeln!(
                        out,
                        "parvault_traversal_connections{{direction=\"{}\",path=\"{}\",transport=\"{}\"}} {v}",
                        d.label(),
                        p.label(),
                        t.label()
                    );
                }
            }
        }
        let _ = writeln!(
            out,
            "# HELP parvault_traversal_timing_overflow_total Dials not timed because the timing map was full."
        );
        let _ = writeln!(
            out,
            "# TYPE parvault_traversal_timing_overflow_total counter"
        );
        let _ = writeln!(
            out,
            "parvault_traversal_timing_overflow_total {}",
            self.timing_overflow.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP parvault_status_refused_total Status-page requests refused, by reason."
        );
        let _ = writeln!(out, "# TYPE parvault_status_refused_total counter");
        for r in STATUS_REFUSALS {
            let _ = writeln!(
                out,
                "parvault_status_refused_total{{code=\"{}\"}} {}",
                r.label(),
                self.refused[refused_index(r)].load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(out, "# HELP parvault_build_info The running build.");
        let _ = writeln!(out, "# TYPE parvault_build_info gauge");
        let _ = writeln!(
            out,
            "parvault_build_info{{version=\"{}\",profile=\"{}\",deterministic=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION"),
            self.build.profile,
            u8::from(self.build.deterministic)
        );
        out
    }
}

/// Series in one scrape: 2 + 120 + 4 + 4 × 15 + 8 + 1 + 7 + 1.
pub const SERIES_COUNT: usize = N_ATTEMPTS
    + N_OUTCOMES
    + N_INBOUND
    + N_HIST_SERIES * (N_BUCKETS + 2)
    + N_CONNECTIONS
    + 1
    + N_REFUSED
    + 1;
/// Families (one `# HELP` and one `# TYPE` line each).
pub const FAMILY_COUNT: usize = 8;
/// Lines in one scrape.
pub const LINE_COUNT: usize = SERIES_COUNT + 2 * FAMILY_COUNT;

/// The process-wide counters, installed once by the daemon before any swarm or client exists;
/// every `MeshClient` built afterwards records into them (origin `client`).
static PROCESS_COUNTERS: std::sync::OnceLock<Arc<TraversalCounters>> = std::sync::OnceLock::new();

pub fn install_process_counters(c: Arc<TraversalCounters>) {
    let _ = PROCESS_COUNTERS.set(c);
}

pub fn process_counters() -> Option<Arc<TraversalCounters>> {
    PROCESS_COUNTERS.get().cloned()
}

pub use crate::build_facts::{build_facts, build_facts_lines, long_version, BuildFacts};

/// The facts the unauthenticated debug listener needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct InsecureMetricsFacts {
    /// `build_facts().insecure_metrics_feature`.
    pub feature: bool,
    /// `build_facts().debug_assertions`.
    pub debug_assertions: bool,
    /// The bind IP is unspecified (`0.0.0.0`, `::`, or the v4-mapped `::ffff:0.0.0.0`).
    pub unspecified: bool,
    /// The bind IP is assigned to the named interface (at bind time).
    pub iface_owns_ip: bool,
}

/// The `--lab-insecure-metrics` listener (`docs/METRICS.md`): allowed only in a build with the
/// feature and debug assertions, on a specified IP that the named interface owns. Compiled in
/// every build so its Kani harness runs in the default job.
pub fn insecure_metrics_listener_decision(f: &InsecureMetricsFacts) -> Result<(), &'static str> {
    if !f.feature || !f.debug_assertions {
        return Err("reject.metrics_insecure_unavailable");
    }
    if f.unspecified {
        return Err("reject.metrics_insecure_unspecified");
    }
    if !f.iface_owns_ip {
        return Err("reject.metrics_insecure_iface_mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters() -> TraversalCounters {
        TraversalCounters::new(BuildInfo {
            profile: "desktop",
            deterministic: false,
        })
    }

    #[test]
    fn series_and_lines_are_constant_and_small() {
        let c = counters();
        let body = c.render_prometheus();
        assert_eq!(body.lines().count(), LINE_COUNT);
        assert_eq!(SERIES_COUNT, 203);
        assert!(body.len() < 32 * 1024, "{}", body.len());
        c.record_attempt(Origin::Daemon);
        c.record_outcome(
            Origin::Daemon,
            PathKind::Direct,
            TransportKind::Tcp,
            TraversalReason::Refused,
        );
        c.record_connect_time(
            PathKind::Direct,
            ConnTransport::Tcp,
            Duration::from_secs(99),
        );
        c.conn_open(Direction::Inbound, PathKind::Direct, ConnTransport::Quic);
        c.record_status_refused("reject.status_token_missing");
        c.record_status_refused("reject.not_a_status_code");
        let after = c.render_prometheus();
        assert_eq!(after.lines().count(), LINE_COUNT);
        assert!(after.contains("parvault_traversal_attempts_total{origin=\"daemon\"} 1\n"));
        assert!(after.contains("parvault_traversal_outcomes_total{origin=\"daemon\",path=\"direct\",transport=\"tcp\",reason=\"refused\"} 1\n"));
        assert!(after.contains(
            "parvault_traversal_connect_seconds_bucket{path=\"direct\",transport=\"tcp\",le=\"30\"} 0\n"
        ));
        assert!(after.contains(
            "parvault_traversal_connect_seconds_bucket{path=\"direct\",transport=\"tcp\",le=\"+Inf\"} 1\n"
        ));
        assert!(after.contains(
            "parvault_traversal_connect_seconds_sum{path=\"direct\",transport=\"tcp\"} 99.000000\n"
        ));
        assert!(after.contains("parvault_status_refused_total{code=\"status_token_missing\"} 1\n"));
        assert!(after.contains("parvault_build_info{version=\"".to_string().as_str()));
    }

    #[test]
    fn index_functions_are_dense_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for o in ORIGINS {
            for p in PATHS {
                for t in TRANSPORTS {
                    for r in REASONS {
                        let i = flat_index(o, p, t, r);
                        assert!(i < N_OUTCOMES);
                        assert!(seen.insert(i));
                    }
                }
            }
        }
        assert_eq!(seen.len(), N_OUTCOMES);
        let mut h = std::collections::HashSet::new();
        for p in PATHS {
            for t in CONN_TRANSPORTS {
                for b in 0..N_BUCKETS {
                    assert!(h.insert(hist_index(p, t, b)));
                }
            }
        }
        assert_eq!(h.len(), N_HIST_BUCKETS);
        assert!(h.iter().all(|i| *i < N_HIST_BUCKETS));
    }

    #[test]
    fn buckets_are_upper_bounds() {
        assert_eq!(bucket_of(Duration::from_millis(5)), 0);
        assert_eq!(bucket_of(Duration::from_micros(5001)), 1);
        assert_eq!(bucket_of(Duration::from_secs(30)), 11);
        assert_eq!(bucket_of(Duration::from_secs(31)), 12);
    }

    #[test]
    fn status_refusal_labels_round_trip() {
        for r in STATUS_REFUSALS {
            assert_eq!(
                StatusRefusal::from_code(&format!("reject.{}", r.label())),
                Some(r)
            );
        }
        assert_eq!(StatusRefusal::from_code("status_token_missing"), None);
    }

    /// One case per build shape: this test binary's own shape is pinned; the line format is
    /// pinned for every shape.
    #[test]
    fn build_facts_pin_this_build_and_the_line_format() {
        let f = build_facts();
        assert_eq!(f.debug_assertions, cfg!(debug_assertions));
        assert_eq!(
            f.insecure_metrics_feature,
            cfg!(feature = "lab-insecure-metrics")
        );
        assert_eq!(
            build_facts_lines(BuildFacts {
                insecure_metrics_feature: false,
                debug_assertions: true
            }),
            "debug_assertions: on\nfeatures: none"
        );
        assert_eq!(
            build_facts_lines(BuildFacts {
                insecure_metrics_feature: false,
                debug_assertions: false
            }),
            "debug_assertions: off\nfeatures: none"
        );
        assert_eq!(
            build_facts_lines(BuildFacts {
                insecure_metrics_feature: true,
                debug_assertions: true
            }),
            "debug_assertions: on\nfeatures: lab-insecure-metrics"
        );
        assert!(long_version().starts_with(env!("CARGO_PKG_VERSION")));
        assert!(long_version().ends_with(&build_facts_lines(f)));
    }

    #[test]
    fn insecure_listener_needs_all_four_facts() {
        for bits in 0u8..16 {
            let f = InsecureMetricsFacts {
                feature: bits & 1 != 0,
                debug_assertions: bits & 2 != 0,
                unspecified: bits & 4 != 0,
                iface_owns_ip: bits & 8 != 0,
            };
            let ok = f.feature && f.debug_assertions && !f.unspecified && f.iface_owns_ip;
            assert_eq!(insecure_metrics_listener_decision(&f).is_ok(), ok, "{f:?}");
        }
    }
}
