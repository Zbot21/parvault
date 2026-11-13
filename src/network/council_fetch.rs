//! Bounded background fetch of a newer council manifest (F-08/F-09).
//!
//! When an order names a council epoch above the installed one, the node refuses the order and
//! asks its admitted peers for the manifest. Bounds: only peers this node admitted, one fetch in
//! flight per scope root, one request per peer per minute, a size cap, a request timeout, and an
//! install only when [`council_manifest_decision`] accepts the chain from the current epoch
//! (never a lower or equal epoch). The swarm task never waits: the fetch runs on its own thread.
//!
//! [`council_manifest_decision`]: crate::storage::council::council_manifest_decision

use crate::network::{MeshClient, MeshWireRequest, MeshWireResponse};
use crate::storage::council::{install_council_manifest, MAX_COUNCIL_MANIFEST_BYTES};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// At most one request to the same peer per this interval.
pub const COUNCIL_FETCH_PEER_INTERVAL: Duration = Duration::from_secs(60);
/// Timeout of one `GetCouncilManifest` request.
pub const COUNCIL_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Most peers asked by one fetch.
pub const COUNCIL_FETCH_MAX_PEERS: usize = 8;

#[derive(Default)]
struct Limiter {
    in_flight: HashSet<[u8; 32]>,
    last_asked: HashMap<String, Instant>,
}

fn limiter() -> &'static Mutex<Limiter> {
    static L: OnceLock<Mutex<Limiter>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(Limiter::default()))
}

/// Whether a fetch for one scope may start: none in flight and at least one admitted peer.
pub fn council_fetch_decision(in_flight: bool, admitted_peers: usize) -> Result<(), &'static str> {
    if in_flight {
        return Err("reject.council_fetch_in_flight");
    }
    if admitted_peers == 0 {
        return Err("reject.council_fetch_no_admitted_peer");
    }
    Ok(())
}

/// Starts a background fetch of `scope_root`'s manifest from `admitted_peers` (endpoints whose
/// key this node admitted). Returns at once; `Err(code)` if the bounds refuse to start.
pub fn spawn_council_fetch(
    client: MeshClient,
    admitted_peers: Vec<String>,
    data_dir: PathBuf,
    scope_root: [u8; 32],
) -> Result<(), &'static str> {
    let peers: Vec<String> = {
        let mut l = limiter().lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let peers: Vec<String> = admitted_peers
            .into_iter()
            .filter(|p| {
                l.last_asked
                    .get(p)
                    .is_none_or(|t| now.duration_since(*t) >= COUNCIL_FETCH_PEER_INTERVAL)
            })
            .take(COUNCIL_FETCH_MAX_PEERS)
            .collect();
        council_fetch_decision(l.in_flight.contains(&scope_root), peers.len())?;
        l.in_flight.insert(scope_root);
        for p in &peers {
            l.last_asked.insert(p.clone(), now);
        }
        peers
    };
    let client = client.with_timeout(COUNCIL_FETCH_TIMEOUT);
    let spawned = std::thread::Builder::new()
        .name("council-fetch".into())
        .spawn(move || {
            for peer in &peers {
                let resp = client.send_request(peer, MeshWireRequest::GetCouncilManifest { scope_root });
                let Ok(MeshWireResponse::CouncilManifestResult { manifest: Some(m) }) = resp else {
                    continue;
                };
                if m.to_bytes().len() > MAX_COUNCIL_MANIFEST_BYTES {
                    tracing::warn!(code = "reject.council_manifest_oversized", peer = %peer, "ignored a council manifest");
                    continue;
                }
                if install_council_manifest(&data_dir, &m, scope_root).is_ok() {
                    tracing::info!(epoch = m.epoch, peer = %peer, "installed a newer council manifest");
                    break;
                }
            }
            limiter()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .in_flight
                .remove(&scope_root);
        });
    if spawned.is_err() {
        limiter()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .in_flight
            .remove(&scope_root);
        return Err("reject.council_fetch_spawn");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_bounds() {
        assert_eq!(council_fetch_decision(false, 1), Ok(()));
        assert_eq!(
            council_fetch_decision(true, 3),
            Err("reject.council_fetch_in_flight")
        );
        assert_eq!(
            council_fetch_decision(false, 0),
            Err("reject.council_fetch_no_admitted_peer")
        );
    }
}
