# ADR-17: Zero-Knowledge Anonymous Network Census & Epoch-Nullifier Telemetry

- **Status:** Accepted
- **Subsystem:** `telemetry`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Operators need coarse visibility into active network population, macro-regional distribution, and Foundation Seed Anchor drain progress without logging peer IP addresses, persistent `PeerId`s, or exact user disk capacities—and without allowing Sybil bots to spoof petabytes of fake capacity.

## Decision

1. **PQ Onion-Relayed Rotating-Nullifier Beacons (`AnonymousTelemetryBeacon`):** Opt-in census beacons are wrapped in 1-hop post-quantum `PqRelayedShardEnvelope`s (hiding sender IP) and carry an epoch-scoped HMAC nullifier that deduplicates single-epoch resends while remaining cryptographically unlinkable across epochs `t` and `t + 1`:

```text
Nullifier_t = HMAC-SHA256(K_node_secret, "PARVAULT-TELEMETRY-EPOCH-V1:" || u64_be(t))
```

2. **Coarse Bucketing, Hashcash PoW & IQR Outlier Trimming (`NetworkCensusAggregator`):** Capacities are rounded to power-of-two GiB buckets (`round_to_pow2_gib`, capped at `MAX_SINGLE_NODE_BUCKET_GIB = 65,536 GiB`), protected by configurable stateless Hashcash Proof-of-Work (`create_with_pow`), bounded in RAM per epoch, and aggregated using Tukey Interquartile Range (IQR) outlier trimming plus Kademlia capture-recapture cross-checks.

## Consequences & Verification

- **Consequences:** Delivers Sybil-damped network health metrics with zero IP logging and zero cross-epoch node tracking.
- **Verification:** `tests/anonymous_telemetry_tests.rs` and `tests/red_team_hardening_tests.rs`.
