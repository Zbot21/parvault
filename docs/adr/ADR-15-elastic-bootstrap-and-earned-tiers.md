# ADR-15: Day-1-to-Scale Elastic Bootstrap, Auto-Draining Seed Anchors & Earned Tier Progression

- **Status:** Accepted
- **Subsystem:** `bootstrap`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Decentralized storage networks face two cold-start hazards: (1) a rigid 20-peer Reed-Solomon requirement deadlocks on Day 1 when `0..5` organic peers exist, and (2) letting unproven nodes self-select `16-of-20` (`1.25×` tax) via a CLI flag creates adverse selection where flaky peers claim `homelab` efficiency and drop offline simultaneously.

## Decision

1. **Cryptographically Computed Earned Standing (`EarnedStanding::evaluate`):** Erasure profiles are computed deterministically from audited PoR history and reachable pool topology (`external_pool`):
   - `SoloPersonalVault` / `PersonalDeviceRing` (`external_pool == 0`, `PersonalDeviceCert`): `2-of-3`, `0.00×` external tax.
   - `BuddyMicroCluster` (`1 ≤ external_pool < 6`): `3-of-5`, `1.67×` tax.
   - `ProbationaryConsumerPool` (`external_pool ≥ 6`, `< 50` PoR passes): mandatory `10-of-20`, `2.00×` tax.
   - `EarnedVerifiedMixedPool` (`≥ 50` PoR passes at `≥ 98.0%` SLA, `≥ 24` peers): `16-of-24`, `1.50×` tax.
   - `EarnedHomelabAnchorPool` (`≥ 200` PoR passes at `≥ 99.8%` SLA, `≥ 20` peers): `16-of-20`, `1.25×` tax.
2. **Auto-Draining Foundation Seed Anchors & `VerifiedNeighbor` Gate:** When organic peers are scarce (`P_organic < N`), `FoundationSeedAnchor` nodes hold blinded `.bshard` fallback slots and automatically drain (`plan_seed_anchor_drain`) to `0` shards strictly onto `VerifiedNeighbor` (`≥ 50` PoR passes) organic subnets.
3. **Zero-Knowledge Ciphertext Re-Sharding & Sybil-Damped Standby Mining:** `reshard_ciphertext_stripe_elastic` transitions stripes across $(k, n)$ tiers purely over $GF(2^8)$ ciphertext without `MasterKey`. Pioneer standby credits divide by `/24` (and `/32` IPv6 / 4-slot RFC 6598 CGNAT) cohort counts (`M × (1/M) = 1.0×`). (An anchor-signed weather quorum for freezing SLA demotions during regional outages was specified but never wired; it was removed in `v0.5.0`, finding F-15.)

## Consequences & Verification

- **Consequences:** Seamless progression from a single-user 2-device LAN ring on Day 1 to a 10,000-user organic mesh with zero self-selected tier gaming.
- **Verification:** `specs/ParVaultBootstrapAndEarnedTier.tla` (`0` errors) and `tests/bootstrap_and_earned_tier_tests.rs`.
