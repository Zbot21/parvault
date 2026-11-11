//! # Zero-Knowledge Anonymous Network Census & Extent Telemetry (`ADR-14`)
//!
//! Enables foundation operators and community dashboards to measure:
//! - Total active network population (`unique_active_nodes` + Kademlia DHT cross-check),
//! - Geographic macro-region distribution (`extent_by_region`),
//! - Earned redundancy tier progression (`nodes_by_earned_standing`),
//! - Aggregate committed and used capacity (`total_committed_capacity_gib`, `total_used_storage_gib`),
//! - **Seed Anchor drain progress (`seed_anchor_storage_share_percent` $\to 0.0\%$)**,
//!
//! **without ever collecting IP addresses, `/24` subnets, `PeerId`s, file counts, or cross-epoch node histories.**

use crate::bootstrap::{EarnedStanding, PeerRole};
use crate::crypto::{
    CryptoError, HybridKemKeypair, HybridKemPublicKey, MasterKey, PqRelayedShardEnvelope,
};
use crate::storage::BlindedShardId;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Bytes per Gibibyte (`2^30`).
pub const BYTES_PER_GIB: u64 = 1024 * 1024 * 1024;

/// Maximum plausible single-node committed storage bucket (`65,536 GiB` = `64 TiB`, `ADR-15`)
/// to block single-beacon `u64::MAX` / `4 ZiB` capacity-poisoning attacks.
pub const MAX_SINGLE_NODE_BUCKET_GIB: u64 = 65_536;

/// Maximum unique beacons retained per epoch in `NetworkCensusAggregator` to bound RAM usage (`ADR-15`).
pub const MAX_BEACONS_PER_EPOCH: usize = 250_000;

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("Beacon epoch mismatch: aggregator is tracking epoch {expected}, got {actual}")]
    EpochMismatch { expected: u64, actual: u64 },
    #[error("Beacon integrity MAC verification failed")]
    InvalidBeaconMac,
    #[error("Coarse region '{0}' is invalid or contains fine-grained IP/subnet characters")]
    InvalidCoarseRegion(String),
    #[error("Invalid or implausible storage bucket (committed={committed} GiB, used={used} GiB)")]
    InvalidCapacityBucket { committed: u64, used: u64 },
    #[error("Insufficient zero-knowledge telemetry Proof-of-Work (required {required} bits, got {actual})")]
    InsufficientProofOfWork { required: u8, actual: u8 },
    #[error("Aggregator epoch capacity ceiling ({MAX_BEACONS_PER_EPOCH}) reached")]
    AggregatorCapacityExceeded,
    #[error("Post-quantum onion telemetry envelope error: {0}")]
    PqEnvelope(#[from] CryptoError),
    #[error("Telemetry serialization error: {0}")]
    Serialization(String),
}

/// Rounds a raw byte capacity into a coarse power-of-two GiB bucket (`0`, `1`, `2`, `4`, `8`, ..., `512`, `1024`, ..., `65536`)
/// so that exact disk capacity (e.g., `476,940,021,760` bytes due to bad blocks or filesystem overhead)
/// can never fingerprint an individual host across epochs, while clamping at `MAX_SINGLE_NODE_BUCKET_GIB`.
pub const fn round_to_pow2_gib(bytes: u64) -> u64 {
    if bytes == 0 {
        return 0;
    }
    let gib = bytes.div_ceil(BYTES_PER_GIB);
    let clamped = if gib == 0 { 1 } else { gib };
    if clamped >= MAX_SINGLE_NODE_BUCKET_GIB {
        MAX_SINGLE_NODE_BUCKET_GIB
    } else {
        clamped.next_power_of_two()
    }
}

/// Validates and normalizes a coarse macro-region identifier (e.g. `"NA-WEST"`, `"EU-CENTRAL"`, `"APAC"`).
/// Strictly rejects any string containing `.`, `:`, or `/` to prevent accidental IPv4, IPv6, or `/24` CIDR leakage.
pub fn sanitize_coarse_region(region: &str) -> Result<String, TelemetryError> {
    let trimmed = region.trim().to_ascii_uppercase();
    if trimmed.is_empty() || trimmed.len() > 24 {
        return Err(TelemetryError::InvalidCoarseRegion(region.to_string()));
    }
    if trimmed.contains('.') || trimmed.contains(':') || trimmed.contains('/') {
        return Err(TelemetryError::InvalidCoarseRegion(region.to_string()));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(TelemetryError::InvalidCoarseRegion(region.to_string()));
    }
    Ok(trimmed)
}

/// Returns the canonical string label for an [`EarnedStanding`] tier in census reports.
pub const fn earned_standing_label(standing: EarnedStanding) -> &'static str {
    match standing {
        EarnedStanding::SoloPersonalVault => "SoloPersonalVault",
        EarnedStanding::PersonalDeviceRing => "PersonalDeviceRing",
        EarnedStanding::BuddyMicroCluster => "BuddyMicroCluster",
        EarnedStanding::ProbationaryConsumerPool => "ProbationaryConsumerPool",
        EarnedStanding::EarnedVerifiedMixedPool => "EarnedVerifiedMixedPool",
        EarnedStanding::EarnedHomelabAnchorPool => "EarnedHomelabAnchorPool",
    }
}

/// Zero-Knowledge Anonymous Telemetry Beacon (`ADR-14`).
///
/// Emitted once per epoch (optionally inside a 1-hop `PqRelayedShardEnvelope` onion wrapper)
/// to allow operators to compute a `NetworkCensusReport` without learning the node's `PeerId`,
/// IP address, `/24` subnet, or cross-epoch identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonymousTelemetryBeacon {
    /// Coarse time epoch index (e.g., `unix_timestamp_secs / 3600` for hourly census epochs).
    pub epoch_id: u64,
    /// `HMAC-SHA256(node_secret_seed, "PARVAULT-TELEMETRY-EPOCH-V1:" || epoch_id_le64)`.
    /// Identical within the same `epoch_id` (enabling Sybil/replay deduplication) and
    /// cryptographically unlinkable across `epoch_id` vs `epoch_id + 1`.
    pub epoch_nullifier: [u8; 32],
    /// Coarse geographic macro-region (e.g., `"NA-WEST"`, `"NA-EAST"`, `"EU-CENTRAL"`, `"APAC"`).
    pub coarse_region: String,
    /// Node role (`PersonalDevice`, `OrganicCommunityPeer`, or `FoundationSeedAnchor`).
    pub role: PeerRole,
    /// Current cryptographically earned redundancy standing (`ADR-13`).
    pub earned_standing: EarnedStanding,
    /// Committed disk capacity rounded to a power-of-two GiB bucket (`round_to_pow2_gib`).
    pub committed_capacity_bucket_gib: u64,
    /// Used shard storage rounded to a power-of-two GiB bucket (`round_to_pow2_gib`).
    pub used_storage_bucket_gib: u64,
    /// Number of live peers currently observed in the node's local Kademlia DHT routing table.
    pub observed_dht_routing_peers: u32,
    /// Integrity MAC (`HMAC-SHA256(epoch_nullifier, canonical_fields)`) protecting beacon fields in transit.
    pub beacon_mac: [u8; 32],
    /// Stateless zero-knowledge Hashcash micro-puzzle nonce (`ADR-15` anti-Sybil telemetry defense).
    #[serde(default)]
    pub pow_nonce: u64,
    /// Leading zero bits required/solved by `pow_nonce`.
    #[serde(default)]
    pub pow_difficulty_bits: u8,
}

impl AnonymousTelemetryBeacon {
    /// Counts leading zero bits in a 256-bit SHA-256 digest.
    pub fn leading_zero_bits(hash: &[u8; 32]) -> u8 {
        let mut total = 0u8;
        for &b in hash {
            if b == 0 {
                total += 8;
            } else {
                total += b.leading_zeros() as u8;
                break;
            }
        }
        total
    }

    /// Computes the domain-separated Hashcash PoW digest over `(epoch_id, epoch_nullifier, beacon_mac, pow_nonce)`.
    pub fn compute_pow_hash(
        epoch_id: u64,
        epoch_nullifier: &[u8; 32],
        beacon_mac: &[u8; 32],
        pow_nonce: u64,
    ) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(b"PARVAULT-TELEMETRY-POW-V1:");
        hasher.update(epoch_id.to_le_bytes());
        hasher.update(epoch_nullifier);
        hasher.update(beacon_mac);
        hasher.update(pow_nonce.to_le_bytes());
        hasher.finalize().into()
    }

    /// Solves a stateless Hashcash micro-puzzle with at least `difficulty_bits` leading zero bits.
    pub fn solve_pow(
        epoch_id: u64,
        epoch_nullifier: &[u8; 32],
        beacon_mac: &[u8; 32],
        difficulty_bits: u8,
    ) -> u64 {
        if difficulty_bits == 0 {
            return 0;
        }
        let mut nonce = 0u64;
        loop {
            let digest = Self::compute_pow_hash(epoch_id, epoch_nullifier, beacon_mac, nonce);
            if Self::leading_zero_bits(&digest) >= difficulty_bits {
                return nonce;
            }
            nonce = nonce.wrapping_add(1);
        }
    }
    /// Derives the per-epoch unlinkable nullifier from a node's private 32-byte telemetry seed:
    /// `epoch_nullifier = HMAC-SHA256(node_secret_seed, "PARVAULT-TELEMETRY-EPOCH-V1:" || epoch_id_le64)`
    pub fn derive_epoch_nullifier(node_secret_seed: &[u8; 32], epoch_id: u64) -> [u8; 32] {
        let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(node_secret_seed)
            .expect("32-byte HMAC key is always valid");
        mac.update(b"PARVAULT-TELEMETRY-EPOCH-V1:");
        mac.update(&epoch_id.to_le_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    /// Constructs a new privacy-preserving `AnonymousTelemetryBeacon`, automatically rounding
    /// `raw_committed_bytes` and `raw_used_bytes` to power-of-two GiB buckets and rejecting
    /// any fine-grained IP/subnet string in `coarse_region`.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        node_secret_seed: &[u8; 32],
        epoch_id: u64,
        coarse_region: &str,
        role: PeerRole,
        earned_standing: EarnedStanding,
        raw_committed_bytes: u64,
        raw_used_bytes: u64,
        observed_dht_routing_peers: u32,
    ) -> Result<Self, TelemetryError> {
        let sanitized_region = sanitize_coarse_region(coarse_region)?;
        let epoch_nullifier = Self::derive_epoch_nullifier(node_secret_seed, epoch_id);
        let committed_capacity_bucket_gib = round_to_pow2_gib(raw_committed_bytes);
        let used_storage_bucket_gib = round_to_pow2_gib(raw_used_bytes);

        let mut beacon = Self {
            epoch_id,
            epoch_nullifier,
            coarse_region: sanitized_region,
            role,
            earned_standing,
            committed_capacity_bucket_gib,
            used_storage_bucket_gib,
            observed_dht_routing_peers,
            beacon_mac: [0u8; 32],
            pow_nonce: 0,
            pow_difficulty_bits: 0,
        };
        beacon.beacon_mac = beacon.compute_beacon_mac();
        Ok(beacon)
    }

    /// Constructs a new `AnonymousTelemetryBeacon` and solves a zero-knowledge Hashcash Proof-of-Work
    /// puzzle of `pow_difficulty_bits` leading zero bits (`ADR-15` Sybil-resistant census).
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_pow(
        node_secret_seed: &[u8; 32],
        epoch_id: u64,
        coarse_region: &str,
        role: PeerRole,
        earned_standing: EarnedStanding,
        raw_committed_bytes: u64,
        raw_used_bytes: u64,
        observed_dht_routing_peers: u32,
        pow_difficulty_bits: u8,
    ) -> Result<Self, TelemetryError> {
        let mut beacon = Self::create(
            node_secret_seed,
            epoch_id,
            coarse_region,
            role,
            earned_standing,
            raw_committed_bytes,
            raw_used_bytes,
            observed_dht_routing_peers,
        )?;
        beacon.pow_difficulty_bits = pow_difficulty_bits;
        beacon.pow_nonce = Self::solve_pow(
            beacon.epoch_id,
            &beacon.epoch_nullifier,
            &beacon.beacon_mac,
            pow_difficulty_bits,
        );
        Ok(beacon)
    }

    /// Verifies that the beacon's `coarse_region` is properly sanitized, capacity buckets obey
    /// power-of-two and `MAX_SINGLE_NODE_BUCKET_GIB` physical plausibility bounds, `beacon_mac`
    /// matches all payload fields, and any declared `pow_difficulty_bits` puzzle is valid.
    pub fn verify_integrity(&self) -> Result<(), TelemetryError> {
        self.verify_integrity_with_pow(0)
    }

    pub fn verify_integrity_with_pow(&self, min_pow_bits: u8) -> Result<(), TelemetryError> {
        let sanitized = sanitize_coarse_region(&self.coarse_region)?;
        if sanitized != self.coarse_region {
            return Err(TelemetryError::InvalidCoarseRegion(
                self.coarse_region.clone(),
            ));
        }
        let valid_pow2 = |v: u64| v == 0 || v.is_power_of_two();
        if !valid_pow2(self.committed_capacity_bucket_gib)
            || !valid_pow2(self.used_storage_bucket_gib)
            || self.committed_capacity_bucket_gib > MAX_SINGLE_NODE_BUCKET_GIB
            || self.used_storage_bucket_gib > self.committed_capacity_bucket_gib
        {
            return Err(TelemetryError::InvalidCapacityBucket {
                committed: self.committed_capacity_bucket_gib,
                used: self.used_storage_bucket_gib,
            });
        }
        let expected_mac = self.compute_beacon_mac();
        if expected_mac != self.beacon_mac {
            return Err(TelemetryError::InvalidBeaconMac);
        }
        let required_bits = min_pow_bits.max(self.pow_difficulty_bits);
        if required_bits > 0 {
            let pow_hash = Self::compute_pow_hash(
                self.epoch_id,
                &self.epoch_nullifier,
                &self.beacon_mac,
                self.pow_nonce,
            );
            let actual_bits = Self::leading_zero_bits(&pow_hash);
            if actual_bits < required_bits {
                return Err(TelemetryError::InsufficientProofOfWork {
                    required: required_bits,
                    actual: actual_bits,
                });
            }
        }
        Ok(())
    }

    /// Wraps this `AnonymousTelemetryBeacon` inside a 1-hop Post-Quantum `PqRelayedShardEnvelope`
    /// (`X25519 + NIST FIPS 203 ML-KEM-768`) addressed to a Seed Anchor (`seed_anchor_kem_pub`)
    /// via `relay_peer_id` so the Seed Anchor never sees the origin node's IP address or `PeerId`.
    pub fn seal_pq_onion(
        &self,
        seed_anchor_kem_pub: &HybridKemPublicKey,
        relay_peer_id: impl Into<String>,
        jitter_delay_ms: u64,
    ) -> Result<PqRelayedShardEnvelope, TelemetryError> {
        let payload =
            bincode::serialize(self).map_err(|e| TelemetryError::Serialization(e.to_string()))?;
        let mk = MasterKey::from_bytes(self.epoch_nullifier);
        let dummy_root = *b"parvault-telemetry-onion-beacon1";
        let blinded_id = BlindedShardId::derive(&mk, &dummy_root, self.epoch_id as u32, &payload);

        PqRelayedShardEnvelope::seal_pq(
            seed_anchor_kem_pub,
            relay_peer_id,
            &blinded_id,
            &payload,
            jitter_delay_ms,
        )
        .map_err(TelemetryError::PqEnvelope)
    }

    fn compute_beacon_mac(&self) -> [u8; 32] {
        let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&self.epoch_nullifier)
            .expect("32-byte HMAC key is always valid");
        mac.update(b"PARVAULT-TELEMETRY-BEACON-MAC-V1:");
        mac.update(&self.epoch_id.to_le_bytes());
        mac.update(self.coarse_region.as_bytes());
        mac.update(b":");
        let role_tag: u8 = match self.role {
            PeerRole::PersonalDevice => 1,
            PeerRole::OrganicCommunityPeer => 2,
            PeerRole::FoundationSeedAnchor => 3,
        };
        mac.update(&[role_tag]);
        mac.update(earned_standing_label(self.earned_standing).as_bytes());
        mac.update(&self.committed_capacity_bucket_gib.to_le_bytes());
        mac.update(&self.used_storage_bucket_gib.to_le_bytes());
        mac.update(&self.observed_dht_routing_peers.to_le_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}

/// Aggregated Zero-Knowledge Network Census Report for a single epoch (`ADR-14`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkCensusReport {
    /// Epoch index covered by this census report.
    pub epoch_id: u64,
    /// Count of deduplicated active nodes that emitted a valid beacon in `epoch_id`.
    pub unique_active_nodes: usize,
    /// Count of deduplicated `PeerRole::OrganicCommunityPeer` nodes.
    pub organic_community_nodes: usize,
    /// Count of deduplicated `PeerRole::PersonalDevice` nodes.
    pub personal_ring_devices: usize,
    /// Count of deduplicated `PeerRole::FoundationSeedAnchor` nodes.
    pub foundation_seed_anchors: usize,
    /// Cross-checked total mesh population combining `unique_active_nodes` with the median
    /// `observed_dht_routing_peers + 1` reported across beacons (resistant to outlier spoofing).
    pub dht_cross_checked_population_estimate: usize,
    /// Geographic extent: count of unique active nodes per coarse macro-region.
    pub extent_by_region: BTreeMap<String, usize>,
    /// Tier progression distribution: count of unique active nodes per `EarnedStanding`.
    pub nodes_by_earned_standing: BTreeMap<String, usize>,
    /// Total committed storage capacity across all unique nodes (in GiB).
    pub total_committed_capacity_gib: u64,
    /// Total used shard storage across all unique nodes (in GiB).
    pub total_used_storage_gib: u64,
    /// Percentage (`0.0..=100.0`) of total network used storage sitting on `FoundationSeedAnchor` nodes.
    /// Drops to `0.0%` once `ElasticBootstrapEngine::plan_seed_anchor_drain` completes!
    pub seed_anchor_storage_share_percent: f64,
}

impl NetworkCensusReport {
    /// Formats this `NetworkCensusReport` in standard Prometheus / OpenMetrics text exposition format
    /// so Grafana + Prometheus can scrape `/metrics` directly from `parvault-seed`.
    pub fn to_prometheus_metrics(&self) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(2048);
        let _ = writeln!(
            out,
            "# HELP parvault_census_epoch_id Current anonymous telemetry epoch index"
        );
        let _ = writeln!(out, "# TYPE parvault_census_epoch_id gauge");
        let _ = writeln!(out, "parvault_census_epoch_id {}", self.epoch_id);

        let _ = writeln!(
            out,
            "# HELP parvault_unique_active_nodes Deduplicated active nodes in current epoch"
        );
        let _ = writeln!(out, "# TYPE parvault_unique_active_nodes gauge");
        let _ = writeln!(
            out,
            "parvault_unique_active_nodes {}",
            self.unique_active_nodes
        );

        let _ = writeln!(
            out,
            "# HELP parvault_dht_population_estimate Capture-recapture Kademlia population estimate"
        );
        let _ = writeln!(out, "# TYPE parvault_dht_population_estimate gauge");
        let _ = writeln!(
            out,
            "parvault_dht_population_estimate {}",
            self.dht_cross_checked_population_estimate
        );

        let _ = writeln!(
            out,
            "# HELP parvault_nodes_by_role Active nodes broken down by PeerRole"
        );
        let _ = writeln!(out, "# TYPE parvault_nodes_by_role gauge");
        let _ = writeln!(
            out,
            "parvault_nodes_by_role{{role=\"OrganicCommunityPeer\"}} {}",
            self.organic_community_nodes
        );
        let _ = writeln!(
            out,
            "parvault_nodes_by_role{{role=\"PersonalDevice\"}} {}",
            self.personal_ring_devices
        );
        let _ = writeln!(
            out,
            "parvault_nodes_by_role{{role=\"FoundationSeedAnchor\"}} {}",
            self.foundation_seed_anchors
        );

        let _ = writeln!(
            out,
            "# HELP parvault_nodes_by_region Active nodes per coarse macro-region"
        );
        let _ = writeln!(out, "# TYPE parvault_nodes_by_region gauge");
        for (region, count) in &self.extent_by_region {
            let _ = writeln!(
                out,
                "parvault_nodes_by_region{{region=\"{}\"}} {}",
                region, count
            );
        }

        let _ = writeln!(
            out,
            "# HELP parvault_nodes_by_standing Active nodes per earned redundancy standing"
        );
        let _ = writeln!(out, "# TYPE parvault_nodes_by_standing gauge");
        for (standing, count) in &self.nodes_by_earned_standing {
            let _ = writeln!(
                out,
                "parvault_nodes_by_standing{{standing=\"{}\"}} {}",
                standing, count
            );
        }

        let _ = writeln!(
            out,
            "# HELP parvault_total_committed_capacity_gib Aggregate committed storage in GiB"
        );
        let _ = writeln!(out, "# TYPE parvault_total_committed_capacity_gib gauge");
        let _ = writeln!(
            out,
            "parvault_total_committed_capacity_gib {}",
            self.total_committed_capacity_gib
        );

        let _ = writeln!(
            out,
            "# HELP parvault_total_used_storage_gib Aggregate used shard storage in GiB"
        );
        let _ = writeln!(out, "# TYPE parvault_total_used_storage_gib gauge");
        let _ = writeln!(
            out,
            "parvault_total_used_storage_gib {}",
            self.total_used_storage_gib
        );

        let _ = writeln!(
            out,
            "# HELP parvault_seed_anchor_storage_share_percent Percentage of storage still held by Foundation Seed Anchors"
        );
        let _ = writeln!(
            out,
            "# TYPE parvault_seed_anchor_storage_share_percent gauge"
        );
        let _ = writeln!(
            out,
            "parvault_seed_anchor_storage_share_percent {:.4}",
            self.seed_anchor_storage_share_percent
        );
        out
    }
}

/// Deduplicating Zero-Knowledge Telemetry Census Aggregator run by Seed Anchors (`ADR-14` / `ADR-15`).
#[derive(Debug, Clone, Default)]
pub struct NetworkCensusAggregator {
    epoch_id: u64,
    min_pow_bits: u8,
    beacons_by_nullifier: BTreeMap<[u8; 32], AnonymousTelemetryBeacon>,
}

impl NetworkCensusAggregator {
    /// Creates a new census aggregator for `epoch_id`.
    pub fn new(epoch_id: u64) -> Self {
        Self {
            epoch_id,
            min_pow_bits: 0,
            beacons_by_nullifier: BTreeMap::new(),
        }
    }

    /// Creates a Sybil-hardened census aggregator requiring at least `min_pow_bits` of stateless
    /// Hashcash Proof-of-Work on every ingested `AnonymousTelemetryBeacon` (`ADR-15`).
    pub fn with_min_pow_bits(epoch_id: u64, min_pow_bits: u8) -> Self {
        Self {
            epoch_id,
            min_pow_bits,
            beacons_by_nullifier: BTreeMap::new(),
        }
    }

    pub const fn epoch_id(&self) -> u64 {
        self.epoch_id
    }

    pub const fn min_pow_bits(&self) -> u8 {
        self.min_pow_bits
    }

    pub fn unique_beacon_count(&self) -> usize {
        self.beacons_by_nullifier.len()
    }

    /// Ingests a direct `AnonymousTelemetryBeacon`.
    /// Returns `Ok(true)` if the beacon is from a new unique node in this epoch, or `Ok(false)`
    /// if a beacon with the same `epoch_nullifier` was already counted in this epoch.
    pub fn ingest_beacon(
        &mut self,
        beacon: AnonymousTelemetryBeacon,
    ) -> Result<bool, TelemetryError> {
        if beacon.epoch_id != self.epoch_id {
            return Err(TelemetryError::EpochMismatch {
                expected: self.epoch_id,
                actual: beacon.epoch_id,
            });
        }
        beacon.verify_integrity_with_pow(self.min_pow_bits)?;

        if self
            .beacons_by_nullifier
            .contains_key(&beacon.epoch_nullifier)
        {
            return Ok(false);
        }
        if self.beacons_by_nullifier.len() >= MAX_BEACONS_PER_EPOCH {
            return Err(TelemetryError::AggregatorCapacityExceeded);
        }
        self.beacons_by_nullifier
            .insert(beacon.epoch_nullifier, beacon);
        Ok(true)
    }

    /// Unwraps and ingests a 1-hop Post-Quantum Onion-Relayed telemetry beacon (`PqRelayedShardEnvelope`).
    /// The aggregator learns only the relay peer's transport address, never the origin node's IP or `PeerId`.
    pub fn ingest_pq_onion_beacon(
        &mut self,
        envelope: &PqRelayedShardEnvelope,
        seed_anchor_kem_keypair: &HybridKemKeypair,
    ) -> Result<bool, TelemetryError> {
        let (_blinded_id, payload) = envelope.open_pq(seed_anchor_kem_keypair)?;
        let beacon: AnonymousTelemetryBeacon = bincode::deserialize(&payload)
            .map_err(|e| TelemetryError::Serialization(e.to_string()))?;
        self.ingest_beacon(beacon)
    }

    /// Computes the deduplicated `NetworkCensusReport` for `self.epoch_id`.
    pub fn generate_report(&self) -> NetworkCensusReport {
        let unique_active_nodes = self.beacons_by_nullifier.len();
        let mut organic_community_nodes = 0usize;
        let mut personal_ring_devices = 0usize;
        let mut foundation_seed_anchors = 0usize;

        let mut extent_by_region: BTreeMap<String, usize> = BTreeMap::new();
        let mut nodes_by_earned_standing: BTreeMap<String, usize> = BTreeMap::new();

        let mut total_committed_capacity_gib = 0u64;
        let mut total_used_storage_gib = 0u64;
        let mut seed_anchor_used_gib = 0u64;
        let mut dht_samples: Vec<usize> = Vec::with_capacity(unique_active_nodes);

        for beacon in self.beacons_by_nullifier.values() {
            match beacon.role {
                PeerRole::OrganicCommunityPeer => organic_community_nodes += 1,
                PeerRole::PersonalDevice => personal_ring_devices += 1,
                PeerRole::FoundationSeedAnchor => {
                    foundation_seed_anchors += 1;
                    seed_anchor_used_gib =
                        seed_anchor_used_gib.saturating_add(beacon.used_storage_bucket_gib);
                }
            }

            *extent_by_region
                .entry(beacon.coarse_region.clone())
                .or_insert(0) += 1;

            let standing_key = earned_standing_label(beacon.earned_standing).to_string();
            *nodes_by_earned_standing.entry(standing_key).or_insert(0) += 1;

            total_committed_capacity_gib =
                total_committed_capacity_gib.saturating_add(beacon.committed_capacity_bucket_gib);
            total_used_storage_gib =
                total_used_storage_gib.saturating_add(beacon.used_storage_bucket_gib);

            dht_samples.push(beacon.observed_dht_routing_peers as usize + 1);
        }

        dht_samples.sort_unstable();
        let median_dht_population = if dht_samples.is_empty() {
            0
        } else if dht_samples.len() >= 4 {
            // Tukey Interquartile Range (IQR) outlier trimming before computing median (`ADR-15`)
            let q1 = dht_samples[dht_samples.len() / 4];
            let q3 = dht_samples[(dht_samples.len() * 3) / 4];
            let iqr = q3.saturating_sub(q1);
            let fence_low = q1.saturating_sub(iqr + iqr / 2);
            let fence_high = q3.saturating_add(iqr + iqr / 2);
            let trimmed: Vec<usize> = dht_samples
                .iter()
                .copied()
                .filter(|&v| v >= fence_low && v <= fence_high)
                .collect();
            if trimmed.is_empty() {
                dht_samples[dht_samples.len() / 2]
            } else {
                trimmed[trimmed.len() / 2]
            }
        } else {
            dht_samples[dht_samples.len() / 2]
        };
        let dht_cross_checked_population_estimate = unique_active_nodes.max(median_dht_population);

        let seed_anchor_storage_share_percent = if total_used_storage_gib == 0 {
            0.0
        } else {
            (seed_anchor_used_gib as f64 / total_used_storage_gib as f64) * 100.0
        };

        NetworkCensusReport {
            epoch_id: self.epoch_id,
            unique_active_nodes,
            organic_community_nodes,
            personal_ring_devices,
            foundation_seed_anchors,
            dht_cross_checked_population_estimate,
            extent_by_region,
            nodes_by_earned_standing,
            total_committed_capacity_gib,
            total_used_storage_gib,
            seed_anchor_storage_share_percent,
        }
    }
}
