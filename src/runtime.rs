//! The daemon's tokio runtime, sized by hardware profile (B-53, L-96).

use crate::config::HardwareProfile;

/// The tokio runtime for `profile`: multi-thread, with the profile's worker and blocking-pool
/// bounds when it sets them.
pub fn build_runtime(profile: HardwareProfile) -> std::io::Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(workers) = profile.runtime_worker_threads() {
        builder.worker_threads(workers);
    }
    if let Some(blocking) = profile.runtime_max_blocking_threads() {
        builder.max_blocking_threads(blocking);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::server_events::{max_inflight_relays, MAX_SYNDICATIONS_IN_FLIGHT};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    /// The router runtime applies the profile's worker count.
    #[test]
    fn router_runtime_applies_profile_workers() {
        let rt = build_runtime(HardwareProfile::RouterSoc).expect("runtime");
        assert_eq!(rt.metrics().num_workers(), 2);
    }

    /// Holds `n` blocking-pool threads until the returned barrier is released.
    async fn hold_blocking(n: usize) -> (Arc<Barrier>, Vec<tokio::task::JoinHandle<()>>) {
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(Barrier::new(n + 1));
        let handles = (0..n)
            .map(|_| {
                let (tx, r) = (started_tx.clone(), release.clone());
                tokio::task::spawn_blocking(move || {
                    let _ = tx.send(());
                    r.wait();
                })
            })
            .collect();
        for _ in 0..n {
            started_rx.recv().await.expect("blocking task started");
        }
        (release, handles)
    }

    async fn release(release: Arc<Barrier>, handles: Vec<tokio::task::JoinHandle<()>>) {
        release.wait();
        for h in handles {
            h.await.expect("join");
        }
    }

    /// B-53: with every admitted relay forward and syndication fan-out holding a blocking
    /// thread (the most the admission caps allow at once), owner blocking work still runs on
    /// the router runtime. Holding the whole pool instead stalls it, so the bound is real.
    #[test]
    fn router_owner_blocking_work_runs_while_relays_saturated() {
        let profile = HardwareProfile::RouterSoc;
        let pool = profile.runtime_max_blocking_threads().expect("pool bound");
        let rt = build_runtime(profile).expect("runtime");
        rt.block_on(async {
            let (r, h) =
                hold_blocking(max_inflight_relays(profile) + MAX_SYNDICATIONS_IN_FLIGHT).await;
            let owner =
                tokio::time::timeout(Duration::from_secs(10), tokio::task::spawn_blocking(|| 7u8))
                    .await;
            assert_eq!(owner.expect("owner work ran").expect("join"), 7);
            release(r, h).await;

            // Control: holding the whole pool queues owner work behind it.
            let (r, h) = hold_blocking(pool).await;
            let owner = tokio::task::spawn_blocking(|| 7u8);
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(!owner.is_finished(), "owner work ran with the pool full");
            release(r, h).await;
            assert_eq!(owner.await.expect("join"), 7);
        });
    }
}
