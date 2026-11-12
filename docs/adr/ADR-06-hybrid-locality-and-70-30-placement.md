# ADR-06: Hybrid Offline Locality Probing & 70/30 Intra-ASN / Cross-Region Placement

- **Status:** Accepted
- **Subsystem:** `network::placement` / `network::client`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Fast LAN/metro restores benefit from low-RTT intra-ASN peers, whereas surviving regional fiber cuts, floods, or power-grid blackouts requires geographic dispersion. Residential gateways must classify peer locality without external BGP feeds or paid GeoIP databases, and deterministic Docker/Shadow testbeds must work on RFC 1918 private subnets.

## Decision

1. **Offline Locality Classifier (`PlacementEngine`):** Classifies candidate peers into the **Intra-ASN / Local** cohort vs. **Cross-Region** cohort using three offline signals:
   - `/24` IPv4 or `/48` IPv6 prefix affinity (with Bogon/loopback/RFC 1918 poisoning filters on WAN tables),
   - Live `libp2p::ping` / `QueryPeerStatus` RTT measurements (`≤ 5 ms`), and
   - An embedded compact ASN prefix table (with deterministic `asn` and `region` overrides in `config.toml` for multi-container simulations).
2. **70% Intra-ASN / 30% Cross-Region Split:** Each stripe places 70% of shards on low-RTT local/intra-ASN peers for high-throughput recovery and 30% on distinct cross-region ASNs for regional disaster survival, falling back gracefully when total pool density is small.

## Consequences & Verification

- **Consequences:** Combines sub-5 ms metropolitan restore speed with correlated regional outage resilience using zero external GeoIP services.
- **Verification:** `tests/phase1_to_4_integration.rs` and `scripts/docker_acceptance_gate.sh` (10 simulated ASNs).
