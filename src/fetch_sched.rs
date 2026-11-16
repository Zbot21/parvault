//! The daemon's fetch scheduler (L-72, S1-S7; `v0.5.6` track C): foreground reads (WebDAV,
//! FUSE, IPC) preempt the background scavenger at stripe admission in `gateway::engine`
//! (`fetch_stripe_network_hedged`), with S = 8 slots of which a scavenger holds at most S-1.
//!
//! `v0.5.6` T0 seam: [`counters`] is the function live status reads (track D); it reports zeros
//! until track C fills it in.

use serde::{Deserialize, Serialize};

/// Scheduler counters exported to live status (S7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchSchedCounters {
    /// `defer.scavenger_preempted`: scavenger admissions deferred for a foreground read.
    pub scavenger_preempted: u64,
    /// Block-cache misses.
    pub cache_misses: u64,
    /// Stripe fetches that went to the network.
    pub network_fetches: u64,
    /// Foreground and scavenger requests waiting now.
    pub foreground_queued: u64,
    pub scavenger_queued: u64,
}

/// The current counters. T0: no scheduler yet, so all zero.
pub fn counters() -> FetchSchedCounters {
    FetchSchedCounters::default()
}
