//! Live status (B-148 item 2, V1; `v0.5.6` track D): what `parvault status --live` and the
//! status page's `/live` show, over the IPC command `QueryLiveStatus` (appended at the end of
//! `IpcCommand`; `QueryStatus` and `StatusSnapshot` are untouched). Every list is capped.
//!
//! `v0.5.6` T0 seam: the types are fixed; [`snapshot`] refuses (`reject.not_built_yet`) until
//! track D fills it in.

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

/// The daemon's live status, after the caller authorised the request (`status_auth_decision`).
/// T0 stub: refuses.
pub fn snapshot() -> std::io::Result<LiveStatusSnapshot> {
    Err(crate::seam::not_built_yet(crate::seam::Unbuilt {
        track: "D",
        entry: "status --live / QueryLiveStatus / GET /live",
    }))
}
