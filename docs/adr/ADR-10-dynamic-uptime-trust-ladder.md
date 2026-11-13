# ADR-10: Dynamic Uptime Trust Ladder & `/24` Subnet Concentration Caps

- **Status:** Superseded by F-07 (v0.5.0: earned standing is self-reported and grants nothing; see `docs/security/TRUST_FINDINGS.md`). Note: `network/placement.rs` (`select_trust_weighted_peers`, via `max_shards_per_subnet`) defines subnet caps from that self-reported trust level, but production placement never calls it (F-48, by `v0.6.0`). Previously extended by [ADR-15](ADR-15-elastic-bootstrap-and-earned-tiers.md).
- **Formal model:** `specs/ParVaultConfidentialityAndTrust.tla`
- **Subsystem:** `storage::quota` / `network::behaviour`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

> **[Historical Evolution Note (`v0.4.0`)]:** Originally bundled with `FolderSyncEngine` in `v0.1`; split into a dedicated single-concern trust-and-placement ADR in `v0.4.0` (with folder sync in [ADR-14](ADR-14-incremental-folder-sync-engine.md)) and integrated with `EarnedStanding::evaluate` + `/32` IPv6 / CGNAT subnet normalization in [ADR-15](ADR-15-elastic-bootstrap-and-earned-tiers.md).

---

## Context

Static per-subnet shard limits create an unappealing dilemma: capping every subnet at 1 shard underutilizes proven high-uptime homelab anchors in modest clusters, whereas allowing unproven newcomers 4 shards per `/24` weakens fault-domain isolation against residential Sybil routers.

## Decision

1. **Four-State Audited Trust Ladder (`TrustLevel`):** Every peer and canonical `/24` IPv4 (or `/32` IPv6 LIR) subnet progresses strictly via audited PoR history and egress behavior:
   - `UntrustedProbationary` (`< 50` PoR passes): max **`1` shard** per `/24` subnet, `1.0×` reciprocity multiplier.
   - `VerifiedNeighbor` (`≥ 50` PoR passes, `≥ 98.0%` SLA): max **`2` shards** per `/24` subnet, `2.5×` reciprocity multiplier.
   - `HighUptimeAnchor` (`≥ 200` PoR passes, `≥ 99.5%`–`99.8%` SLA): max **`4` shards** per `/24` subnet, `5.0×` reciprocity multiplier.
   - `SlashedQuarantined` (any cryptographic fault): **`0` shards**, `0.0×` (100% credit burn), immediate Gossipsub quarantine.
2. **Collusion & Availability Margin (`4 ≪ K = 16`):** Even if an entire `HighUptimeAnchor` `/24` subnet colludes or suffers a simultaneous router failure, `4` shards neither exceed the parity budget `M = N - K` (`4` in `16-of-20`, `10` in `10-of-20`) nor approach the `K = 16` reconstruction threshold—and carry zero plaintext information without `K_user`.

## Consequences & Verification

- **Consequences:** Rewards proven 24/7 homelab anchors with higher utilization while keeping unproven subnets strictly contained at 1 shard.
- **Verification:** `specs/ParVaultConfidentialityAndTrust.tla` model-checks `Safety_SlashedNeverTrusted` (mutant-covered). `Safety_SubnetTrustCapsEnforced` is waived (`@assume placement-trust-cap`: production placement does not apply the cap, F-48), and zero-knowledge confidentiality is `@structural ciphertext-only-egress`, not model-checked. Unit checks: `tests/confidentiality_and_trust_proofs.rs`.
