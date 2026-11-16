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

## v0.5.0 status

Items 1 and 3 (per-peer quota with bootstrap grace, the 4x per-epoch write-amplification cap) are enforced on every `PutShard` by `QuotaManager::quota_decision` (claim ADR-07). Item 2 (tier-weighted SLA multipliers) is not implemented: peers earn no credit in v0.5.0 (F-07), so every remote peer's allowance is its bootstrap grace.

v0.5.5 (B-161): a full file-backed node refuses a put with `reject.node_capacity` (`quota_decision`); it never evicts shards of any account, the putting one included, to admit one; a local (`local`/`self`) put skips the per-peer checks but not node capacity (claims B161-NO-EVICT, B161-NO-EVICT-LOCAL). The in-memory `--no-fs` store still evicts LRU shards (ADR-30; residual B-164).

v0.5.6 (B-159, C16): a removed shard credits the account it was stored for, by the size recorded at the put (`record_shard_removed`, `removal_credit`), whoever asked for the removal; a seed's fan-out is credited back when the owner frees it (suites S-B159-QUOTA, S-B159-SENDER).
