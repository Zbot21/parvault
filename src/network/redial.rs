//! Redial of ring peers (B-157, R1-R4; `v0.5.6` track D): the daemon dials `--peers` once at
//! start, and a closed connection drops the address. The redial task re-dials configured peers
//! and admitted members' identify listen addresses (never observed ephemeral, mDNS or Kademlia
//! addresses, R2) with a backoff from `1 s` doubling to `30 s`, with jitter (R1); the backoff
//! resets only after a connection held `60 s` (R3, the one reset mechanism).
//!
//! The daemon owns one [`RedialTask`] and polls [`RedialTask::due`] in its event loop.
//! `server_events` feeds connection, identify and admission events into the process's
//! [`PeerBook`] ([`book`]); the task reads the book and the swarm's own connected set.

use crate::network::MeshNetworkBehaviour;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId, Swarm};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// The first backoff step (R1).
pub const BACKOFF_BASE_MS: u64 = 1_000;
/// The backoff cap (R1).
pub const BACKOFF_CAP_MS: u64 = 30_000;
/// How long a connection must hold before the backoff resets (R3).
pub const HOLD_RESET_MS: u64 = 60_000;
/// Most redial addresses per peer (R2).
pub const MAX_REDIAL_ADDRS_PER_PEER: usize = 8;
/// Most peers the book tracks per map; a peer beyond it is not tracked.
pub const MAX_BOOK_PEERS: usize = 256;
/// How often the task checks for due redials.
pub const TICK_MS: u64 = 1_000;

/// The backoff before redial attempt `attempt + 1` (attempt 0 is the first redial after a
/// close): `1 s` doubling, capped at [`BACKOFF_CAP_MS`]. Monotone, never overflows.
pub const fn backoff_ms(attempt: u8) -> u64 {
    if attempt >= 5 {
        BACKOFF_CAP_MS
    } else {
        let b = BACKOFF_BASE_MS << attempt;
        if b > BACKOFF_CAP_MS {
            BACKOFF_CAP_MS
        } else {
            b
        }
    }
}

/// The jitter added to a backoff: at most a quarter of it, from `entropy`.
pub const fn jitter_ms(backoff: u64, entropy: u64) -> u64 {
    let span = backoff / 4;
    if span == 0 {
        0
    } else {
        entropy % (span + 1)
    }
}

/// The redial rule (B-157): only a ring member (a configured peer or an admitted member) is
/// redialled, only while it is not connected, and only once its backoff has elapsed.
/// `since_last_ms` is the time since the last attempt (or since it was last seen connected),
/// less the jitter.
pub fn redial_decision(
    is_configured: bool,
    is_admitted: bool,
    connected: bool,
    attempt: u8,
    since_last_ms: u64,
) -> Result<(), &'static str> {
    if !is_configured && !is_admitted {
        return Err("reject.redial_not_ring_member");
    }
    if connected {
        return Err("reject.redial_connected");
    }
    if since_last_ms < backoff_ms(attempt) {
        return Err("reject.redial_backoff");
    }
    Ok(())
}

/// Whether `addr` may be a redial address for `peer` (R2): an IP address with a specified,
/// non-multicast IP and a non-zero TCP or UDP port, no relay hop and no `/p2p/` naming another
/// peer.
pub fn redial_addr_ok(addr: &Multiaddr, peer: Option<&PeerId>) -> bool {
    let mut has_ip = false;
    let mut has_port = false;
    for p in addr.iter() {
        match p {
            Protocol::Ip4(ip) => {
                if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                    return false;
                }
                has_ip = true;
            }
            Protocol::Ip6(ip) => {
                if ip.is_unspecified() || ip.is_multicast() {
                    return false;
                }
                has_ip = true;
            }
            Protocol::Tcp(port) | Protocol::Udp(port) => {
                if port == 0 {
                    return false;
                }
                has_port = true;
            }
            Protocol::P2pCircuit => return false,
            Protocol::P2p(id) if peer.is_some_and(|p| *p != id) => return false,
            _ => {}
        }
    }
    has_ip && has_port
}

/// What the network side of the daemon knows about ring peers: fed by `server_events`, read by
/// the redial task and by live status. In memory; a restart starts empty.
#[derive(Debug, Default)]
pub struct PeerBook {
    /// Peers whose handshake or ticket this node accepted since start.
    admitted: HashSet<PeerId>,
    /// Identify listen addresses per peer (at most [`MAX_REDIAL_ADDRS_PER_PEER`]); never the
    /// observed address of the connection.
    listen_addrs: HashMap<PeerId, Vec<Multiaddr>>,
    /// When each connected peer's first open connection was established.
    connected_since: HashMap<PeerId, Instant>,
    /// The peer an address this node dialled authenticated as (for configured addresses
    /// without `/p2p/`).
    dialled_as: HashMap<Multiaddr, PeerId>,
    /// This node's own listen addresses.
    own_listen: Vec<Multiaddr>,
    /// Outgoing dials to an address with no known PeerId that have not finished yet (the
    /// start-up dial of a configured address without `/p2p/`, or a redial of one).
    dialing_unknown: HashSet<libp2p::swarm::ConnectionId>,
}

impl PeerBook {
    /// A peer was admitted (handshake or ticket accepted). Returns whether it is new.
    pub fn on_admitted(&mut self, peer: PeerId) -> bool {
        if self.admitted.len() >= MAX_BOOK_PEERS && !self.admitted.contains(&peer) {
            return false;
        }
        self.admitted.insert(peer)
    }

    /// A connection to `peer` was established; `dialled` is the address this node dialled, if
    /// it was the dialer.
    pub fn on_established(&mut self, peer: PeerId, dialled: Option<&Multiaddr>, now: Instant) {
        if self.connected_since.len() < MAX_BOOK_PEERS || self.connected_since.contains_key(&peer) {
            self.connected_since.entry(peer).or_insert(now);
        }
        if let Some(a) = dialled {
            let base = crate::network::client::strip_p2p_protocol(a);
            if self.dialled_as.len() < MAX_BOOK_PEERS || self.dialled_as.contains_key(&base) {
                self.dialled_as.insert(base, peer);
            }
        }
    }

    /// An outgoing dial started (`SwarmEvent::Dialing`).
    pub fn on_dialing(&mut self, peer: Option<PeerId>, id: libp2p::swarm::ConnectionId) {
        if peer.is_none() && self.dialing_unknown.len() < MAX_BOOK_PEERS {
            self.dialing_unknown.insert(id);
        }
    }

    /// An outgoing dial finished (established or failed).
    pub fn on_dial_finished(&mut self, id: libp2p::swarm::ConnectionId) {
        self.dialing_unknown.remove(&id);
    }

    /// Whether a dial to an address with no known PeerId is still in flight.
    pub fn unknown_dial_in_flight(&self) -> bool {
        !self.dialing_unknown.is_empty()
    }

    /// The last connection to `peer` closed.
    pub fn on_closed(&mut self, peer: &PeerId) {
        self.connected_since.remove(peer);
    }

    /// Identify reported `addrs` as `peer`'s listen addresses.
    pub fn on_identify(&mut self, peer: PeerId, addrs: &[Multiaddr]) {
        if !self.listen_addrs.contains_key(&peer) && self.listen_addrs.len() >= MAX_BOOK_PEERS {
            return;
        }
        let kept: Vec<Multiaddr> = addrs
            .iter()
            .filter(|a| redial_addr_ok(a, Some(&peer)))
            .map(crate::network::client::strip_p2p_protocol)
            .take(MAX_REDIAL_ADDRS_PER_PEER)
            .collect();
        self.listen_addrs.insert(peer, kept);
    }

    /// This node started listening on `addr`.
    pub fn on_new_listen_addr(&mut self, addr: Multiaddr) {
        if !self.own_listen.contains(&addr) && self.own_listen.len() < MAX_BOOK_PEERS {
            self.own_listen.push(addr);
        }
    }

    /// This node stopped listening on `addr`.
    pub fn on_expired_listen_addr(&mut self, addr: &Multiaddr) {
        self.own_listen.retain(|a| a != addr);
    }

    pub fn is_admitted(&self, peer: &PeerId) -> bool {
        self.admitted.contains(peer)
    }

    /// When `peer`'s connection was established, if it is connected.
    pub fn connected_since(&self, peer: &PeerId) -> Option<Instant> {
        self.connected_since.get(peer).copied()
    }

    pub fn admitted(&self) -> impl Iterator<Item = &PeerId> {
        self.admitted.iter()
    }

    pub fn connected(&self) -> impl Iterator<Item = &PeerId> {
        self.connected_since.keys()
    }

    pub fn listen_addrs_of(&self, peer: &PeerId) -> &[Multiaddr] {
        self.listen_addrs.get(peer).map_or(&[], Vec::as_slice)
    }

    pub fn own_listen_addrs(&self) -> &[Multiaddr] {
        &self.own_listen
    }

    pub fn dialled_as(&self, addr: &Multiaddr) -> Option<PeerId> {
        self.dialled_as.get(addr).copied()
    }
}

/// The process's peer book.
pub fn book() -> MutexGuard<'static, PeerBook> {
    static BOOK: OnceLock<Mutex<PeerBook>> = OnceLock::new();
    BOOK.get_or_init(|| Mutex::new(PeerBook::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One redial target's backoff state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backoff {
    /// Redial attempts since the last reset.
    pub attempt: u8,
    /// Milliseconds (task clock) of the last attempt, or of the last tick it was connected.
    pub last_ms: u64,
    /// The jitter of the current step.
    pub jitter_ms: u64,
}

impl Backoff {
    pub const fn at(now_ms: u64) -> Self {
        Self {
            attempt: 0,
            last_ms: now_ms,
            jitter_ms: 0,
        }
    }
}

/// What the task sees of one target at one tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetView {
    pub is_configured: bool,
    pub is_admitted: bool,
    pub connected: bool,
    /// How long the current connection has held, if connected.
    pub held_ms: Option<u64>,
}

/// One tick of one target's backoff: `Ok` means dial now. A connected target that held
/// [`HOLD_RESET_MS`] resets to attempt 0; any connected target moves its clock to `now_ms`, so
/// the first redial after a close waits one step of its current backoff.
pub fn step(b: &mut Backoff, v: TargetView, now_ms: u64, entropy: u64) -> Result<(), &'static str> {
    if v.connected {
        if v.held_ms.is_some_and(|h| h >= HOLD_RESET_MS) {
            b.attempt = 0;
            b.jitter_ms = 0;
        }
        b.last_ms = now_ms;
    }
    let since = now_ms.saturating_sub(b.last_ms).saturating_sub(b.jitter_ms);
    redial_decision(
        v.is_configured,
        v.is_admitted,
        v.connected,
        b.attempt,
        since,
    )?;
    b.attempt = b.attempt.saturating_add(1);
    b.last_ms = now_ms;
    b.jitter_ms = jitter_ms(backoff_ms(b.attempt), entropy);
    Ok(())
}

/// A redial target: a peer (known PeerId) or a configured address whose peer is not yet known.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TargetKey {
    Peer(PeerId),
    Addr(Multiaddr),
}

/// The daemon's redial state.
#[derive(Debug, Default)]
pub struct RedialTask {
    /// The configured peers (`--peers`, the config file) without `/p2p/`, with the PeerId when
    /// the address names one.
    configured: Vec<(Multiaddr, Option<PeerId>)>,
    backoff: HashMap<TargetKey, Backoff>,
    started: Option<Instant>,
    tick: Option<tokio::time::Interval>,
}

impl RedialTask {
    /// A task for the configured peer addresses. Addresses that do not parse are skipped (the
    /// start-up dial reports them).
    pub fn new(configured: Vec<String>) -> Self {
        let configured = configured
            .iter()
            .filter_map(|s| crate::network::parse_peer_multiaddr(s).ok())
            .map(|a| {
                let pid = crate::network::client::extract_expected_peer_id(&a);
                (crate::network::client::strip_p2p_protocol(&a), pid)
            })
            .collect();
        Self {
            configured,
            ..Self::default()
        }
    }

    /// Resolves when the next check is due (every [`TICK_MS`]).
    pub async fn due(&mut self) {
        let tick = self.tick.get_or_insert_with(|| {
            let mut i = tokio::time::interval(Duration::from_millis(TICK_MS));
            i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            i
        });
        tick.tick().await;
    }

    /// This tick's targets: (key, addresses, configured). Configured peers first; admitted
    /// members with identify listen addresses next. Never this node.
    fn targets(&self, local: PeerId) -> Vec<(TargetKey, Vec<Multiaddr>, bool)> {
        let book = book();
        let mut out = Vec::new();
        let mut seen: HashSet<PeerId> = HashSet::new();
        for (addr, pid) in &self.configured {
            match pid.or_else(|| book.dialled_as(addr)) {
                Some(p) if p == local => {}
                Some(p) => {
                    seen.insert(p);
                    let mut addrs = vec![addr.clone()];
                    if book.is_admitted(&p) {
                        for a in book.listen_addrs_of(&p) {
                            if !addrs.contains(a) && addrs.len() < MAX_REDIAL_ADDRS_PER_PEER {
                                addrs.push(a.clone());
                            }
                        }
                    }
                    out.push((TargetKey::Peer(p), addrs, true));
                }
                None => out.push((TargetKey::Addr(addr.clone()), vec![addr.clone()], true)),
            }
        }
        for p in book.admitted() {
            if *p == local || seen.contains(p) {
                continue;
            }
            let addrs = book.listen_addrs_of(p).to_vec();
            if !addrs.is_empty() {
                out.push((TargetKey::Peer(*p), addrs, false));
            }
        }
        out
    }

    /// Dials the ring peers whose backoff has elapsed and that the swarm is not connected to.
    pub fn dial_due(&mut self, swarm: &mut Swarm<MeshNetworkBehaviour>) {
        let now = Instant::now();
        let started = *self.started.get_or_insert(now);
        let now_ms = u64::try_from(now.duration_since(started).as_millis()).unwrap_or(u64::MAX);
        let targets = self.targets(*swarm.local_peer_id());
        let live: HashSet<TargetKey> = targets.iter().map(|t| t.0.clone()).collect();
        self.backoff.retain(|k, _| live.contains(k));
        for (key, addrs, configured) in targets {
            let (connected, held_ms, admitted) = match &key {
                TargetKey::Peer(p) => {
                    let book = book();
                    let held = book.connected_since(p).map(|t| {
                        u64::try_from(now.duration_since(t).as_millis()).unwrap_or(u64::MAX)
                    });
                    (swarm.is_connected(p), held, book.is_admitted(p))
                }
                // A dial still in flight holds the clock like a connection does (no reset),
                // so an address whose connect hangs is never dialled twice at once.
                TargetKey::Addr(_) => (book().unknown_dial_in_flight(), None, false),
            };
            let b = self
                .backoff
                .entry(key.clone())
                .or_insert(Backoff::at(now_ms));
            let view = TargetView {
                is_configured: configured,
                is_admitted: admitted,
                connected,
                held_ms,
            };
            if step(b, view, now_ms, rand::random::<u64>()).is_err() {
                continue;
            }
            let attempt = b.attempt;
            let opts = match &key {
                TargetKey::Peer(p) => libp2p::swarm::dial_opts::DialOpts::peer_id(*p)
                    .addresses(addrs)
                    .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                    .build(),
                TargetKey::Addr(a) => libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
                    .address(a.clone())
                    .build(),
            };
            match swarm.dial(opts) {
                Ok(()) => tracing::info!(target = ?key, attempt, "redialling a ring peer"),
                Err(e) => {
                    tracing::debug!(target = ?key, attempt, error = %e, "redial not started")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_the_cap() {
        let got: Vec<u64> = (0..8).map(backoff_ms).collect();
        assert_eq!(
            got,
            [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000]
        );
        assert_eq!(backoff_ms(u8::MAX), BACKOFF_CAP_MS);
        for e in [0, 1, 7_500, u64::MAX] {
            assert!(jitter_ms(BACKOFF_CAP_MS, e) <= BACKOFF_CAP_MS / 4);
        }
    }

    #[test]
    fn redial_decision_rules() {
        assert_eq!(redial_decision(true, false, false, 0, 1_000), Ok(()));
        assert_eq!(redial_decision(false, true, false, 0, 1_000), Ok(()));
        assert_eq!(
            redial_decision(false, false, false, 0, u64::MAX),
            Err("reject.redial_not_ring_member")
        );
        assert_eq!(
            redial_decision(true, true, true, 0, u64::MAX),
            Err("reject.redial_connected")
        );
        assert_eq!(
            redial_decision(true, false, false, 2, 3_999),
            Err("reject.redial_backoff")
        );
    }

    fn view(connected: bool, held_ms: Option<u64>) -> TargetView {
        TargetView {
            is_configured: true,
            is_admitted: false,
            connected,
            held_ms,
        }
    }

    /// R3: a peer that drops before holding 60 s keeps its backoff growing; one that held 60 s
    /// starts again at the base step.
    #[test]
    fn flapping_peer_keeps_its_backoff() {
        let mut b = Backoff::at(0);
        let mut now = 0u64;
        let mut dial_times = Vec::new();
        // Each redial connects, holds 10 s, then drops.
        for _ in 0..6 {
            loop {
                now += TICK_MS;
                if step(&mut b, view(false, None), now, 0).is_ok() {
                    dial_times.push(now);
                    break;
                }
            }
            for h in 0..10 {
                now += TICK_MS;
                assert!(step(&mut b, view(true, Some(h * TICK_MS)), now, 0).is_err());
            }
        }
        assert_eq!(b.attempt, 6, "no reset while flapping");
        let gaps: Vec<u64> = dial_times.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(gaps.windows(2).all(|w| w[0] <= w[1]), "{gaps:?}");
        // Held 60 s: reset.
        for h in 0..=60 {
            now += TICK_MS;
            let _ = step(&mut b, view(true, Some(h * TICK_MS)), now, 0);
        }
        assert_eq!(b.attempt, 0);
        now += BACKOFF_BASE_MS;
        assert_eq!(step(&mut b, view(false, None), now, 0), Ok(()));
    }

    /// R1: a peer down for more than 2 minutes is redialled at least every cap plus jitter.
    #[test]
    fn long_outage_redials_within_cap_plus_jitter() {
        let mut b = Backoff::at(0);
        let mut last = 0;
        let mut max_gap = 0;
        for t in (TICK_MS..=180_000).step_by(TICK_MS as usize) {
            if step(&mut b, view(false, None), t, u64::MAX / 3).is_ok() {
                max_gap = max_gap.max(t - last);
                last = t;
            }
        }
        let bound = BACKOFF_CAP_MS + BACKOFF_CAP_MS / 4 + TICK_MS;
        assert!(max_gap <= bound, "{max_gap}");
        assert!(180_000 - last <= bound);
    }

    #[test]
    fn redial_addresses_exclude_unroutable_and_foreign() {
        let p = PeerId::random();
        let q = PeerId::random();
        let ok: Multiaddr = "/ip4/192.168.1.5/tcp/4001".parse().unwrap();
        assert!(redial_addr_ok(&ok, Some(&p)));
        for bad in [
            "/ip4/0.0.0.0/tcp/4001".to_string(),
            "/ip4/192.168.1.5/tcp/0".to_string(),
            "/ip4/224.0.0.251/udp/5353".to_string(),
            format!("/ip4/192.168.1.5/tcp/4001/p2p/{q}"),
            format!("/ip4/192.168.1.5/tcp/4001/p2p/{q}/p2p-circuit"),
            "/dns4/example.org/tcp/4001".to_string(),
        ] {
            let a: Multiaddr = bad.parse().unwrap();
            assert!(!redial_addr_ok(&a, Some(&p)), "{bad}");
        }
        let mut book = PeerBook::default();
        let many: Vec<Multiaddr> = (1..=20)
            .map(|i| format!("/ip4/10.0.0.{i}/tcp/4001").parse().unwrap())
            .collect();
        book.on_identify(p, &many);
        assert_eq!(book.listen_addrs_of(&p).len(), MAX_REDIAL_ADDRS_PER_PEER);
    }
}
