//! 70/30 Intra-ASN / Cross-Region shard placement (ADR-06).

use crate::network::behaviour::{
    effective_kademlia_distance, ipv4_same_slash24, ipv6_same_slash48,
};
use crate::sharding::merkle::Hash32;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Network topology & latency profile for a candidate storage peer (ADR-06).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerTopologyMetrics {
    pub peer_id: String,
    pub kad_id_hash: Hash32,
    pub ip_addr: IpAddr,
    pub rtt_ms: f64,
    pub asn: u32,
    pub region: String,
    pub sla_score: f64,
    pub available_bytes: u64,
}

/// Result of running the 70/30 Network Topology Shard Placement Engine.
#[derive(Debug, Clone)]
pub struct ShardPlacementPlan {
    pub selected_peers: Vec<PeerTopologyMetrics>,
    pub intra_asn_count: usize,
    pub inter_asn_count: usize,
    pub used_dynamic_fallback: bool,
}

/// Shard Placement Policy Engine enforcing the 70% Intra-ASN / Low-RTT and 30% Inter-ASN /
/// Cross-Region split with automatic fallback when local peer density drops below `K` (ADR-06).
pub struct PlacementEngine {
    pub local_ip: IpAddr,
    pub local_asn: u32,
    pub local_region: String,
    pub local_rtt_ceiling_ms: f64,
    pub intra_asn_ratio: f64,
}

impl PlacementEngine {
    pub fn new(
        local_ip: IpAddr,
        local_asn: u32,
        local_region: impl Into<String>,
        local_rtt_ceiling_ms: f64,
        intra_asn_ratio: f64,
    ) -> Self {
        Self {
            local_ip,
            local_asn,
            local_region: local_region.into(),
            local_rtt_ceiling_ms,
            intra_asn_ratio: intra_asn_ratio.clamp(0.0, 1.0),
        }
    }

    /// Determines whether `peer` belongs to the Intra-ASN / Low-RTT Local Network Neighborhood.
    pub fn is_local_neighborhood(&self, peer: &PeerTopologyMetrics) -> bool {
        let same_subnet = match (self.local_ip, peer.ip_addr) {
            (IpAddr::V4(a), IpAddr::V4(b)) => ipv4_same_slash24(a, b),
            (IpAddr::V6(a), IpAddr::V6(b)) => ipv6_same_slash48(a, b),
            _ => false,
        };
        let same_asn = peer.asn == self.local_asn;
        let low_rtt = peer.rtt_ms <= self.local_rtt_ceiling_ms;

        same_subnet || (same_asn && low_rtt)
    }

    /// Selects `n_total` distinct target nodes (`k_data` minimum local density threshold)
    /// ordered by `D_effective = D_XOR * RTT_weight`.
    pub fn select_target_peers(
        &self,
        stripe_merkle_root: &Hash32,
        k_data: usize,
        n_total: usize,
        min_shard_bytes: u64,
        candidates: &[PeerTopologyMetrics],
    ) -> ShardPlacementPlan {
        let target_intra = ((n_total as f64) * self.intra_asn_ratio).round() as usize;
        let target_inter = n_total.saturating_sub(target_intra);

        let mut eligible: Vec<PeerTopologyMetrics> = candidates
            .iter()
            .filter(|p| p.available_bytes >= min_shard_bytes)
            .cloned()
            .collect();

        eligible.sort_by(|a, b| {
            let da = effective_kademlia_distance(
                stripe_merkle_root,
                &a.kad_id_hash,
                a.rtt_ms,
                self.local_rtt_ceiling_ms,
            );
            let db = effective_kademlia_distance(
                stripe_merkle_root,
                &b.kad_id_hash,
                b.rtt_ms,
                self.local_rtt_ceiling_ms,
            );
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut intra_pool = Vec::new();
        let mut inter_pool = Vec::new();
        for peer in eligible {
            if self.is_local_neighborhood(&peer) {
                intra_pool.push(peer);
            } else {
                inter_pool.push(peer);
            }
        }

        let used_dynamic_fallback = intra_pool.len() < k_data || intra_pool.len() < target_intra;

        let mut selected = Vec::with_capacity(n_total);
        let mut intra_taken = 0usize;
        let mut inter_taken = 0usize;

        for peer in intra_pool.iter().take(target_intra) {
            selected.push(peer.clone());
            intra_taken += 1;
        }
        for peer in inter_pool.iter().take(target_inter) {
            selected.push(peer.clone());
            inter_taken += 1;
        }

        // Dynamic fallback: fill remaining slots from whichever pool still has healthy nodes.
        if selected.len() < n_total {
            for peer in intra_pool.into_iter().skip(intra_taken) {
                if selected.len() >= n_total {
                    break;
                }
                selected.push(peer);
                intra_taken += 1;
            }
        }
        if selected.len() < n_total {
            for peer in inter_pool.into_iter().skip(inter_taken) {
                if selected.len() >= n_total {
                    break;
                }
                selected.push(peer);
                inter_taken += 1;
            }
        }

        ShardPlacementPlan {
            selected_peers: selected,
            intra_asn_count: intra_taken,
            inter_asn_count: inter_taken,
            used_dynamic_fallback,
        }
    }

    /// Selects target peers while enforcing Dynamic Uptime Trust Level per-subnet concentration caps (ADR-10):
    /// - `SlashedQuarantined`: 0 shards allowed
    /// - `UntrustedProbationary`: max 1 shard per subnet/region
    /// - `VerifiedNeighbor`: max 2 shards per subnet/region
    /// - `HighUptimeAnchor`: max 4 shards per subnet/region (strictly `< K / 3` so no subnet can reconstruct)
    pub fn select_trust_weighted_peers(
        &self,
        stripe_merkle_root: &Hash32,
        k_data: usize,
        n_total: usize,
        min_shard_bytes: u64,
        candidates: &[PeerTopologyMetrics],
        peer_trust: &std::collections::HashMap<String, crate::storage::TrustLevel>,
    ) -> ShardPlacementPlan {
        let hard_confidentiality_cap = (k_data / 3).max(1);
        let mut region_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut ip_subnet_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut filtered = Vec::with_capacity(candidates.len());

        for cand in candidates {
            let trust = peer_trust
                .get(&cand.peer_id)
                .copied()
                .unwrap_or(crate::storage::TrustLevel::UntrustedProbationary);
            let allowed_in_subnet = trust.max_shards_per_subnet().min(hard_confidentiality_cap);
            if allowed_in_subnet == 0 {
                continue;
            }
            let ip_subnet_key = crate::bootstrap::canonical_sybil_subnet_key(cand.ip_addr, None);
            let region_count = region_counts.get(&cand.region).copied().unwrap_or(0);
            let ip_subnet_count = ip_subnet_counts.get(&ip_subnet_key).copied().unwrap_or(0);
            if region_count < allowed_in_subnet && ip_subnet_count < allowed_in_subnet {
                *region_counts.entry(cand.region.clone()).or_insert(0) += 1;
                *ip_subnet_counts.entry(ip_subnet_key).or_insert(0) += 1;
                filtered.push(cand.clone());
            }
        }

        self.select_target_peers(
            stripe_merkle_root,
            k_data,
            n_total,
            min_shard_bytes,
            &filtered,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// B-149: placement as placed. `MeshClient::put_shard` notes every shard a host accepted (every
// replica, not only the first that `assigned_peers` keeps); `file store` runs the store inside
// [`track`] and prints [`PlacementSummary`], grouped by PeerId, never by address string (P1).

/// One shard a host accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedShard {
    /// The address the shard was sent to.
    pub peer_addr: String,
    pub stripe_merkle_root: Hash32,
    pub shard_index: u32,
}

thread_local! {
    static PLACED: std::cell::RefCell<Option<Vec<PlacedShard>>> =
        const { std::cell::RefCell::new(None) };
}

/// Most placements one [`track`] records (a 64 GiB file at 16 MiB stripes and 20 shards with a
/// double replica shift); beyond it the summary says it is incomplete.
pub const MAX_TRACKED_PLACEMENTS: usize = 200_000;

/// Notes that the host at `peer_addr` accepted `shard`, when a [`track`] is running on this
/// thread; otherwise nothing.
pub fn note_placed(peer_addr: &str, shard: &crate::storage::ShardId) {
    PLACED.with(|p| {
        if let Some(v) = p.borrow_mut().as_mut() {
            if v.len() < MAX_TRACKED_PLACEMENTS {
                v.push(PlacedShard {
                    peer_addr: peer_addr.to_string(),
                    stripe_merkle_root: shard.stripe_merkle_root,
                    shard_index: shard.shard_index,
                });
            }
        }
    });
}

/// Runs `f` and returns its result with the shards placed on this thread while it ran.
pub fn track<T>(f: impl FnOnce() -> T) -> (T, Vec<PlacedShard>) {
    let outer = PLACED.with(|p| p.borrow_mut().replace(Vec::new()));
    let out = f();
    let mine = PLACED.with(|p| std::mem::replace(&mut *p.borrow_mut(), outer));
    let mine = mine.unwrap_or_default();
    PLACED.with(|p| {
        if let Some(v) = p.borrow_mut().as_mut() {
            v.extend(mine.iter().cloned());
        }
    });
    (out, mine)
}

/// One host in a [`PlacementSummary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPlacement {
    /// The host's PeerId, or `address <addr> (PeerId not verified)` when the client never
    /// authenticated that address.
    pub host: String,
    pub shards: u64,
    pub bytes: u64,
}

/// Where one stored file's shards went, as placed.
#[derive(Debug, Clone, PartialEq)]
pub struct PlacementSummary {
    /// Hosts, most shards first, then by name.
    pub hosts: Vec<HostPlacement>,
    pub total_shards: u64,
    /// Bytes placed on hosts over the file's size.
    pub expansion: f64,
    /// Stripes that a loss of any one host leaves with fewer than `k` distinct shards.
    pub stripes_lost_to_one_host: u64,
    pub stripes: u64,
    /// The tracker hit [`MAX_TRACKED_PLACEMENTS`].
    pub truncated: bool,
}

impl PlacementSummary {
    /// Groups `placed` by host. `resolve` names an address's PeerId (from its `/p2p/` or the
    /// client's pin of it); `stripes` gives each stripe's root, `k` and shard length.
    pub fn build(
        placed: &[PlacedShard],
        resolve: impl Fn(&str) -> Option<String>,
        stripes: &[(Hash32, usize, u64)],
        original_file_size: u64,
    ) -> Self {
        use std::collections::{BTreeMap, BTreeSet, HashMap};
        let shard_len: HashMap<Hash32, (usize, u64)> =
            stripes.iter().map(|(r, k, l)| (*r, (*k, *l))).collect();
        let mut hosts: BTreeMap<String, HostPlacement> = BTreeMap::new();
        // stripe -> host -> distinct shard indices
        let mut held: HashMap<Hash32, BTreeMap<String, BTreeSet<u32>>> = HashMap::new();
        let mut total_bytes = 0u64;
        for p in placed {
            let host = resolve(&p.peer_addr)
                .unwrap_or_else(|| format!("address {} (PeerId not verified)", p.peer_addr.trim()));
            let len = shard_len.get(&p.stripe_merkle_root).map_or(0, |(_, l)| *l);
            let h = hosts.entry(host.clone()).or_insert(HostPlacement {
                host: host.clone(),
                shards: 0,
                bytes: 0,
            });
            h.shards += 1;
            h.bytes = h.bytes.saturating_add(len);
            total_bytes = total_bytes.saturating_add(len);
            held.entry(p.stripe_merkle_root)
                .or_default()
                .entry(host)
                .or_default()
                .insert(p.shard_index);
        }
        let mut lost = 0u64;
        for (root, (k, _)) in &shard_len {
            let by_host = held.get(root);
            let names: Vec<&String> = by_host.map(|m| m.keys().collect()).unwrap_or_default();
            let survives = |without: Option<&String>| {
                let mut idx = BTreeSet::new();
                if let Some(m) = by_host {
                    for (h, s) in m {
                        if Some(h) != without {
                            idx.extend(s.iter().copied());
                        }
                    }
                }
                idx.len() >= *k
            };
            let ok = if names.is_empty() {
                survives(None)
            } else {
                names.iter().all(|h| survives(Some(h)))
            };
            if !ok {
                lost += 1;
            }
        }
        let mut hosts: Vec<HostPlacement> = hosts.into_values().collect();
        hosts.sort_by(|a, b| b.shards.cmp(&a.shards).then(a.host.cmp(&b.host)));
        Self {
            total_shards: placed.len() as u64,
            hosts,
            expansion: if original_file_size == 0 {
                0.0
            } else {
                total_bytes as f64 / original_file_size as f64
            },
            stripes_lost_to_one_host: lost,
            stripes: stripes.len() as u64,
            truncated: placed.len() >= MAX_TRACKED_PLACEMENTS,
        }
    }

    /// The lines `file store` prints.
    pub fn lines(&self, tier_expansion: f64) -> Vec<String> {
        let mut out = vec![format!(
            "Placement (as placed): {} shard(s) on {} host(s){}",
            self.total_shards,
            self.hosts.len(),
            if self.truncated { " (incomplete)" } else { "" }
        )];
        for h in &self.hosts {
            out.push(format!(
                "  {:<52} : {} shard(s), {} bytes",
                h.host, h.shards, h.bytes
            ));
        }
        out.push(format!(
            "Stored on hosts   : {:.1}x the file (the tier alone is {:.1}x)",
            self.expansion, tier_expansion
        ));
        out.push(if self.stripes_lost_to_one_host == 0 {
            format!(
                "One-host loss     : every stripe ({}) survives the loss of any one host",
                self.stripes
            )
        } else {
            format!(
                "One-host loss     : {} of {} stripe(s) would NOT survive the loss of one host",
                self.stripes_lost_to_one_host, self.stripes
            )
        });
        out
    }
}

#[cfg(test)]
mod placement_summary_tests {
    use super::*;

    fn shard(root: u8, i: u32) -> crate::storage::ShardId {
        crate::storage::ShardId {
            stripe_merkle_root: [root; 32],
            shard_index: i,
            shard_hash: [0; 32],
        }
    }

    /// Notes `idx` of stripe `root` on `addr`, the way the replica shift does.
    fn place(addr: &str, root: u8, idx: impl Iterator<Item = u32>) {
        for i in idx {
            note_placed(addr, &shard(root, i));
        }
    }

    fn resolve(addr: &str) -> Option<String> {
        addr.strip_prefix("addr-").map(|s| format!("peer-{s}"))
    }

    /// B-149: 2 hosts, 10-of-20, every shard on both (the C12 replica shift): 20 per host, 4.0x,
    /// and the stripe survives either host's loss.
    #[test]
    fn two_hosts_hold_twenty_each_at_four_x() {
        let ((), placed) = track(|| {
            place("addr-a", 1, 0..20);
            place("addr-b", 1, 0..20);
        });
        // 2 MiB file: 10 data shards of 209,716 bytes.
        let s = PlacementSummary::build(&placed, resolve, &[([1; 32], 10, 209_716)], 2 << 20);
        assert_eq!(s.hosts.len(), 2);
        assert!(s.hosts.iter().all(|h| h.shards == 20), "{s:?}");
        assert_eq!(format!("{:.1}", s.expansion), "4.0");
        assert_eq!(s.stripes_lost_to_one_host, 0);
        let text = s.lines(2.0).join("\n");
        assert!(
            text.contains("as placed") && text.contains("4.0x"),
            "{text}"
        );
    }

    /// P1: two addresses of one PeerId are one host; an unverified address is labelled so.
    #[test]
    fn grouped_by_peer_id_not_address() {
        let ((), placed) = track(|| {
            place("addr-a", 1, 0..7);
            place("addr-a", 1, 7..14); // the same host
            place("unpinned", 1, 14..20);
        });
        let resolve = |a: &str| (a == "addr-a").then(|| "peer-a".to_string());
        let s = PlacementSummary::build(&placed, resolve, &[([1; 32], 10, 100)], 1_000);
        assert_eq!(s.hosts.len(), 2);
        assert_eq!(s.hosts[0].host, "peer-a");
        assert_eq!(s.hosts[0].shards, 14);
        assert!(s.hosts[1].host.contains("PeerId not verified"));
        // Losing peer-a leaves 6 < 10.
        assert_eq!(s.stripes_lost_to_one_host, 1);
    }

    /// 3 hosts print the real split; nothing is tracked outside `track`.
    #[test]
    fn three_hosts_real_split_and_no_tracking_outside() {
        note_placed("addr-x", &shard(9, 0));
        let ((), placed) = track(|| {
            place("addr-a", 1, (0..20).filter(|i| i % 3 == 0));
            place("addr-b", 1, (0..20).filter(|i| i % 3 == 1));
            place("addr-c", 1, (0..20).filter(|i| i % 3 == 2));
        });
        let s = PlacementSummary::build(&placed, resolve, &[([1; 32], 10, 10)], 100);
        let counts: Vec<u64> = s.hosts.iter().map(|h| h.shards).collect();
        assert_eq!(counts, [7, 7, 6]);
        assert_eq!(s.total_shards, 20);
    }
}
