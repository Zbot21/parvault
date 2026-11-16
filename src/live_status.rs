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
    /// The node's held-shard bound (L-130, arch152 3.6), when known.
    pub held_shard_bound: Option<u64>,
    /// Where the bound came from (cgroup limit, physical RAM, config override); empty when
    /// the bound is not known.
    pub held_shard_bound_source: String,
}

/// The shard half of a [`LiveStatusSnapshot`], from the block store and the quota manager
/// (`BlockStore::shards_held`, `QuotaManager::held_shard_bound`; integration glue G-5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShardFacts {
    pub shards_held: u64,
    pub held_shard_bound: Option<u64>,
    pub held_shard_bound_source: String,
}

/// Longest bound-source text a snapshot carries.
pub const MAX_BOUND_SOURCE_LEN: usize = 64;

/// The reason code of a refused `/live` request, for the status edge's own log line: the
/// first `reject.` code in the refusal (the status decision's), else
/// `reject.live_status_unavailable` (no daemon, or no code in the error).
pub fn live_refusal_code(e: &dyn std::fmt::Display) -> String {
    let text = e.to_string();
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_'))
        .find(|w| w.starts_with("reject.") && w.len() > "reject.".len())
        .map_or_else(
            || "reject.live_status_unavailable".to_string(),
            str::to_string,
        )
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
            && self.held_shard_bound_source.chars().count() <= MAX_BOUND_SOURCE_LEN
    }
}

/// The daemon's live status, after the caller authorised the request (`status_auth_decision`):
/// the ring peers this daemon's swarm admitted or is connected to (from the process's
/// [`crate::network::redial::book`], fed by `server_events`), its listen addresses, the fetch
/// scheduler's counters and its anonymous resident memory. Lists are capped
/// ([`MAX_LIVE_PEERS`], [`MAX_LIVE_ADDRS_PER_PEER`]); peers are sorted by PeerId.
/// Until the shard facts are passed in (glue G-5), the shard fields are 0 and the bound is
/// unknown.
pub fn snapshot() -> std::io::Result<LiveStatusSnapshot> {
    snapshot_with(&ShardFacts::default())
}

/// [`snapshot`] with the node's shard facts.
pub fn snapshot_with(shards: &ShardFacts) -> std::io::Result<LiveStatusSnapshot> {
    #[cfg(feature = "daemon-runtime")]
    let mut snap = network_view();
    #[cfg(not(feature = "daemon-runtime"))]
    let mut snap = LiveStatusSnapshot::default();
    snap.fetch = crate::fetch_sched::counters();
    snap.anon_rss_bytes = anon_rss_bytes();
    snap.shards_held = shards.shards_held;
    snap.held_shard_bound = shards.held_shard_bound;
    snap.held_shard_bound_source = shards
        .held_shard_bound_source
        .chars()
        .take(MAX_BOUND_SOURCE_LEN)
        .collect();
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
    fn shard_facts_carried_and_refusal_codes() {
        let s = snapshot_with(&ShardFacts {
            shards_held: 7,
            held_shard_bound: Some(4_096),
            held_shard_bound_source: "x".repeat(200),
        })
        .unwrap();
        assert_eq!((s.shards_held, s.held_shard_bound), (7, Some(4_096)));
        assert!(s.within_caps());
        let e = std::io::Error::other("QueryStatus refused: reject.example_code (x)");
        assert_eq!(live_refusal_code(&e), "reject.example_code");
        assert_eq!(
            live_refusal_code(&"socket gone"),
            "reject.live_status_unavailable"
        );
    }

    #[test]
    fn snapshot_is_within_caps() {
        let s = snapshot().unwrap();
        assert!(s.within_caps());
        #[cfg(target_os = "linux")]
        assert!(s.anon_rss_bytes > 0);
    }
}
