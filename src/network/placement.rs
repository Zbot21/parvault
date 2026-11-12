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
