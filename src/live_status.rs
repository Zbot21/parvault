//! Live status (B-148 item 2, V1; `v0.5.6` track D): what `parvault status --live` and the
//! status page's `/live` show, over the IPC command `QueryLiveStatus` (appended at the end of
//! `IpcCommand`; `QueryStatus` and `StatusSnapshot` are untouched). Every list is capped.

use serde::{Deserialize, Serialize};

/// Most peers a [`LiveStatusSnapshot`] carries.
pub const MAX_LIVE_PEERS: usize = 256;
/// Most addresses per peer, and listen addresses of this node.
pub const MAX_LIVE_ADDRS_PER_PEER: usize = 16;

/// One ring peer as this daemon sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivePeer {
    pub peer_id: String,
    pub admitted: bool,
    pub connected: bool,
    /// At most [`MAX_LIVE_ADDRS_PER_PEER`].
    pub addrs: Vec<String>,
}

/// The daemon's live state (V1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveStatusSnapshot {
    /// At most [`MAX_LIVE_PEERS`].
    pub peers: Vec<LivePeer>,
    /// At most [`MAX_LIVE_ADDRS_PER_PEER`].
    pub listen_addrs: Vec<String>,
    /// The fetch scheduler's counters (track C, `fetch_sched::counters`).
    pub fetch: crate::fetch_sched::FetchSchedCounters,
    /// Regular and blinded shards this node holds (B-152).
    pub shards_held: u64,
    /// Anonymous resident memory of the daemon, bytes (B-152).
    pub anon_rss_bytes: u64,
}

impl LiveStatusSnapshot {
    /// Whether every list is within its cap.
    pub fn within_caps(&self) -> bool {
        self.peers.len() <= MAX_LIVE_PEERS
            && self.listen_addrs.len() <= MAX_LIVE_ADDRS_PER_PEER
            && self
                .peers
                .iter()
                .all(|p| p.addrs.len() <= MAX_LIVE_ADDRS_PER_PEER)
    }
}

/// The daemon's live status, after the caller authorised the request (`status_auth_decision`):
/// the ring peers this daemon's swarm admitted or is connected to (from the process's
/// [`crate::network::redial::book`], fed by `server_events`), its listen addresses, the fetch
/// scheduler's counters and its anonymous resident memory. Lists are capped
/// ([`MAX_LIVE_PEERS`], [`MAX_LIVE_ADDRS_PER_PEER`]); peers are sorted by PeerId.
pub fn snapshot() -> std::io::Result<LiveStatusSnapshot> {
    #[cfg(feature = "daemon-runtime")]
    let mut snap = network_view();
    #[cfg(not(feature = "daemon-runtime"))]
    let mut snap = LiveStatusSnapshot::default();
    snap.fetch = crate::fetch_sched::counters();
    snap.anon_rss_bytes = anon_rss_bytes();
    debug_assert!(snap.within_caps());
    Ok(snap)
}

/// The network half of [`snapshot`].
#[cfg(feature = "daemon-runtime")]
fn network_view() -> LiveStatusSnapshot {
    let book = crate::network::redial::book();
    let mut ids: Vec<libp2p::PeerId> = book.admitted().chain(book.connected()).copied().collect();
    ids.sort_unstable_by_key(|p| p.to_bytes());
    ids.dedup();
    let peers = ids
        .into_iter()
        .take(MAX_LIVE_PEERS)
        .map(|p| LivePeer {
            peer_id: p.to_string(),
            admitted: book.is_admitted(&p),
            connected: book.connected_since(&p).is_some(),
            addrs: book
                .listen_addrs_of(&p)
                .iter()
                .take(MAX_LIVE_ADDRS_PER_PEER)
                .map(ToString::to_string)
                .collect(),
        })
        .collect();
    let listen_addrs = book
        .own_listen_addrs()
        .iter()
        .take(MAX_LIVE_ADDRS_PER_PEER)
        .map(ToString::to_string)
        .collect();
    LiveStatusSnapshot {
        peers,
        listen_addrs,
        ..LiveStatusSnapshot::default()
    }
}

/// This process's anonymous resident memory (`RssAnon` in `/proc/self/status`), bytes; `0`
/// where the kernel does not report it.
pub fn anon_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_rss_anon_kib(&s))
        .map_or(0, |kib| kib.saturating_mul(1024))
}

/// The `RssAnon:` value of a `/proc/<pid>/status` text, KiB.
pub fn parse_rss_anon_kib(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("RssAnon:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_anon_parses() {
        let s = "Name:\tparvault\nRssAnon:\t   12345 kB\nRssFile:\t 1 kB\n";
        assert_eq!(parse_rss_anon_kib(s), Some(12_345));
        assert_eq!(parse_rss_anon_kib("Name: x\n"), None);
    }

    #[test]
    fn snapshot_is_within_caps() {
        let s = snapshot().unwrap();
        assert!(s.within_caps());
        #[cfg(target_os = "linux")]
        assert!(s.anon_rss_bytes > 0);
    }
}
