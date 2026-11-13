//! Stripe sizing, hardware profiles and erasure tiers (client-side: no runtime dependencies).
//! Re-exported from `config`.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Default streaming stripe size (16 MiB) per ADR-01 to cap RAM < 32 MiB on gateways.
pub const DEFAULT_STRIPE_SIZE_BYTES: usize = 16 * 1024 * 1024;

/// Balanced streaming stripe size (4 MiB) for 24/7 Homelab NAS nodes.
pub const HOMELAB_NAS_STRIPE_SIZE_BYTES: usize = 4 * 1024 * 1024;

/// Ultra-low-RAM streaming stripe size (1 MiB) for OpenWrt / prplOS / ARM64 Router SoCs (ADR-18).
pub const ROUTER_SOC_STRIPE_SIZE_BYTES: usize = 1024 * 1024;

/// Minimum streaming stripe size floor (`64 KiB`).
pub const MIN_STRIPE_SIZE_BYTES: usize = 64 * 1024;

/// Maximum logical file size supported by the streaming pipeline (`u64::MAX` bytes).
pub const MAX_FILE_BYTES: u64 = u64::MAX;

/// Strict Router-SoC peak concurrent per-stripe RAM ceiling (`32 MiB`, `ADR-01` / `ADR-18`).
pub const ROUTER_SOC_MAX_STRIPE_MEMORY_BYTES: usize = 32 * 1024 * 1024;

/// AES-256-GCM authentication tag overhead per encrypted stripe (`16` bytes).
pub const AES_GCM_TAG_OVERHEAD_BYTES: usize = 16;

/// Deterministic streaming stripe decomposition for a file of `file_size_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamingStripeLayout {
    pub stripe_size_bytes: usize,
    pub stripe_count: u64,
    pub last_stripe_plaintext_bytes: usize,
    pub max_stripe_plaintext_bytes: usize,
    pub max_stripe_ciphertext_bytes: usize,
}

/// Computes the exact overflow-free streaming stripe layout for `file_size_bytes` (`0..=u64::MAX`),
/// clamping `raw_stripe_size_bytes` into `[MIN_STRIPE_SIZE_BYTES, DEFAULT_STRIPE_SIZE_BYTES]`.
/// Empty files (`0` bytes) emit exactly `1` authenticated `0`-byte plaintext (`16`-byte GCM tag) stripe.
pub const fn compute_stripe_layout_for_size(
    file_size_bytes: u64,
    raw_stripe_size_bytes: usize,
) -> StreamingStripeLayout {
    let stripe_size_bytes = if raw_stripe_size_bytes < MIN_STRIPE_SIZE_BYTES {
        MIN_STRIPE_SIZE_BYTES
    } else if raw_stripe_size_bytes > DEFAULT_STRIPE_SIZE_BYTES {
        DEFAULT_STRIPE_SIZE_BYTES
    } else {
        raw_stripe_size_bytes
    };

    if file_size_bytes == 0 {
        StreamingStripeLayout {
            stripe_size_bytes,
            stripe_count: 1,
            last_stripe_plaintext_bytes: 0,
            max_stripe_plaintext_bytes: 0,
            max_stripe_ciphertext_bytes: AES_GCM_TAG_OVERHEAD_BYTES,
        }
    } else {
        let cap_u64 = stripe_size_bytes as u64;
        let full_stripes_before_last = (file_size_bytes - 1) / cap_u64;
        let stripe_count = full_stripes_before_last + 1;
        let last_stripe_plaintext_bytes = (((file_size_bytes - 1) % cap_u64) as usize) + 1;
        let max_stripe_plaintext_bytes = if stripe_count > 1 {
            stripe_size_bytes
        } else {
            last_stripe_plaintext_bytes
        };
        StreamingStripeLayout {
            stripe_size_bytes,
            stripe_count,
            last_stripe_plaintext_bytes,
            max_stripe_plaintext_bytes,
            max_stripe_ciphertext_bytes: max_stripe_plaintext_bytes + AES_GCM_TAG_OVERHEAD_BYTES,
        }
    }
}

/// Hardware resource profiles tuning stripe sizing, disk safety guards, and peer fanout (`ADR-18`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
pub enum HardwareProfile {
    /// Workstation / laptop profile (`16 MiB` stripes, `5 GiB` disk guard, `128` max connections)
    #[default]
    #[serde(rename = "desktop", alias = "Desktop")]
    #[value(name = "desktop")]
    Desktop,
    /// Dedicated 24/7 home NAS / mini-server profile (`4 MiB` stripes, `1 GiB` disk guard, `64` max connections)
    #[serde(rename = "homelab-nas", alias = "HomelabNas", alias = "homelab_nas")]
    #[value(name = "homelab-nas")]
    HomelabNas,
    /// Constrained OpenWrt / prplOS / ARM64 router SoC profile (`1 MiB` stripes, `64 MiB` disk guard, `24` max connections)
    #[serde(rename = "router-soc", alias = "RouterSoc", alias = "router_soc")]
    #[value(name = "router-soc")]
    RouterSoc,
}

impl HardwareProfile {
    /// Streaming ciphertext stripe size in bytes for this hardware profile.
    pub const fn stripe_size_bytes(self) -> usize {
        match self {
            Self::Desktop => DEFAULT_STRIPE_SIZE_BYTES,
            Self::HomelabNas => HOMELAB_NAS_STRIPE_SIZE_BYTES,
            Self::RouterSoc => ROUTER_SOC_STRIPE_SIZE_BYTES,
        }
    }

    /// Computes the exact overflow-free streaming stripe decomposition (`stripe_count`,
    /// `last_stripe_plaintext_bytes`, and `max_stripe_ciphertext_bytes`) for `file_size_bytes`
    /// under this hardware profile.
    pub const fn compute_streaming_stripe_layout(
        self,
        file_size_bytes: u64,
    ) -> StreamingStripeLayout {
        compute_stripe_layout_for_size(file_size_bytes, self.stripe_size_bytes())
    }

    /// Minimum free OS filesystem space reserved as a safety guard against disk exhaustion.
    pub const fn min_free_disk_bytes(self) -> u64 {
        match self {
            Self::Desktop => crate::storage::quota::DEFAULT_MIN_FREE_DISK_BYTES,
            Self::HomelabNas => 1024 * 1024 * 1024, // 1 GiB
            Self::RouterSoc => 64 * 1024 * 1024,    // 64 MiB for small USB/eMMC partitions
        }
    }

    /// Recommended concurrent peer connection ceiling.
    pub const fn max_connections(self) -> usize {
        match self {
            Self::Desktop => 128,
            Self::HomelabNas => 64,
            Self::RouterSoc => 24,
        }
    }

    /// Recommended default local storage allocation when initializing a fresh node.
    pub const fn default_max_storage_gib(self) -> u64 {
        match self {
            Self::Desktop => 100,
            Self::HomelabNas => 500,
            Self::RouterSoc => 32,
        }
    }

    /// Canonical CLI / JSON / TOML profile slug (`"desktop"`, `"homelab-nas"`, `"router-soc"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::HomelabNas => "homelab-nas",
            Self::RouterSoc => "router-soc",
        }
    }

    /// Default role advertised in signed LAN beacons and WAN peer cards.
    pub const fn beacon_role(self) -> &'static str {
        match self {
            Self::Desktop => "daemon",
            Self::HomelabNas => "router-nas",
            Self::RouterSoc => "router-nas",
        }
    }
}

impl fmt::Display for HardwareProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Comparative Erasure Coding Schemes (k-of-n) and Dynamic SLA Pools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum ErasureTier {
    /// 10-of-20 (50.0% efficiency, 2.00x expansion, tolerates 10 failures) — Unmanaged Consumer Gateways
    #[serde(alias = "consumer")]
    Consumer,
    /// 16-of-24 (66.7% efficiency, 1.50x expansion, tolerates 8 failures) — Standard Mesh / Mixed Nodes
    #[serde(alias = "mixed")]
    Mixed,
    /// 16-of-20 (80.0% efficiency, 1.25x expansion, tolerates 4 failures) — High-SLA Homelab / Prosumer Pool (>99.5% SLA)
    #[serde(alias = "homelab")]
    Homelab,
    /// 20-of-24 (83.3% efficiency, 1.20x expansion, tolerates 4 failures) — Static Infrastructure Relays
    #[serde(alias = "relay")]
    Relay,
}

impl ErasureTier {
    /// Returns `(k_data_shards, m_parity_shards, n_total_shards)`.
    pub const fn params(self) -> (usize, usize, usize) {
        match self {
            Self::Consumer => (10, 10, 20),
            Self::Mixed => (16, 8, 24),
            Self::Homelab => (16, 4, 20),
            Self::Relay => (20, 4, 24),
        }
    }

    /// Proactive repair trigger watermark (`T_repair`).
    /// For Homelab (16-of-20), proactive repair initiates as soon as active shards drop from 20 to 18.
    pub const fn repair_trigger_watermark(self) -> usize {
        match self {
            Self::Consumer => 16,
            Self::Mixed => 20,
            Self::Homelab => 18,
            Self::Relay => 22,
        }
    }

    /// Storage expansion / reciprocity multiplier required by `storage::quota` (ADR-07).
    pub const fn expansion_factor(self) -> f64 {
        match self {
            Self::Consumer => 2.00,
            Self::Mixed => 1.50,
            Self::Homelab => 1.25,
            Self::Relay => 1.20,
        }
    }
}
