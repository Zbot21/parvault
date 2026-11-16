//! Redial of ring peers (B-157, R1-R4; `v0.5.6` track D): the daemon dials `--peers` once at
//! start, and a closed connection drops the address. The redial task re-dials configured peers
//! and admitted members' listen addresses (never observed ephemeral, mDNS or Kademlia
//! addresses, R2) with a backoff from `1 s` doubling to `30 s`, with jitter (R1); the backoff
//! resets only after a connection held `60 s` or the peer re-admits (R3).
//!
//! `v0.5.6` T0 seam: the daemon owns one [`RedialTask`] and polls [`RedialTask::due`] in its
//! event loop. Until track D fills it in, `due` never resolves and nothing is redialled, as
//! before `v0.5.6`. Track D feeds connection events from `server_events` through this module.

use crate::network::MeshNetworkBehaviour;
use libp2p::Swarm;

/// The daemon's redial state.
#[derive(Debug, Default)]
pub struct RedialTask {
    /// The configured peers (`--peers`, the config file), as given.
    _configured: Vec<String>,
}

impl RedialTask {
    /// A task for the configured peer addresses.
    pub fn new(configured: Vec<String>) -> Self {
        Self {
            _configured: configured,
        }
    }

    /// Resolves when a redial attempt is due. T0 stub: never.
    pub async fn due(&mut self) {
        std::future::pending::<()>().await
    }

    /// Dials the peers that are due. T0 stub: nothing.
    pub fn dial_due(&mut self, swarm: &mut Swarm<MeshNetworkBehaviour>) {
        let _ = swarm;
    }
}
