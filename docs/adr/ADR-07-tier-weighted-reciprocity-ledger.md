# ADR-07: Tier-Weighted Byte-Hour Reciprocity Credit Ledger & Bootstrap Grace Quota

- **Status:** Accepted — Extended by [ADR-10](ADR-10-dynamic-uptime-trust-ladder.md) and [ADR-15](ADR-15-elastic-bootstrap-and-earned-tiers.md)
- **Subsystem:** `storage::quota`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Without symmetric storage accounting, rational users would upload terabytes of backups while unplugging their own disks (free-riding). Conversely, cryptocurrency tokenomics add speculative volatility, wallet UX friction, and consensus bloat unsuitable for `< 32 MiB` home routers.

## Decision

1. **Tokenless Byte-Hour Reciprocity (`QuotaManager`):** Tracks per-peer `bytes_contributed_by_peer` vs. `bytes_hosted_for_peer` persisted atomically at `quota_state.bin`, paired with a `10 GiB` initial bootstrap grace quota (`DEFAULT_BOOTSTRAP_GRACE_QUOTA_BYTES`) for newly invited Web-of-Trust peers.
2. **SLA-Weighted Expansion Multipliers:** High-reliability Homelab peers (`16-of-20`, `> 99.5%` 30-day PoR SLA) incur only a `1.25×` expansion tax (`80%` net storage efficiency), whereas Consumer peers (`10-of-20`) pay a `2.00×` expansion tax (`50%` efficiency).
3. **Anti-Wear-Griefing Guard:** LRU eviction releases `bytes_hosted_for_peer` accounting cleanly while capping non-refundable per-epoch write amplification at `4×` to deter rapid upload-delete SSD wear attacks.

## Consequences & Verification

- **Consequences:** Sustains fair cooperative storage ("Filecoin without the coin") with zero blockchain state and bounded flash wear.
- **Verification:** `tests/phase1_to_4_integration.rs` and `tests/red_team_hardening_tests.rs`.
