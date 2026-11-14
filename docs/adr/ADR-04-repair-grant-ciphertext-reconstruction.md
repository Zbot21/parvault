# ADR-04: Authenticated `RepairGrant` & Witness Threshold Ciphertext Reconstruction

- **Status:** Accepted
- **Formal model:** `specs/ParVaultProtocol.tla`
- **Subsystem:** `por::verifier` / `sharding::reed_solomon`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Because `AES-256-GCM` encryption precedes Reed-Solomon sharding ([ADR-01](ADR-01-streaming-stripes-and-encrypt-before-shard.md)), lost shards can be reconstructed over $GF(2^8)$ purely from surviving ciphertext shards without the owner's `MasterKey`. However, storage nodes must block arbitrary unauthenticated raw shard downloads to prevent uninvited peers from scraping ciphertext cohorts or amplifying egress.

## Decision

1. **Dual-Path Raw Shard Read Authorization (`PorVerifierEngine::authorize_raw_shard_read`):** Storage peers reject raw shard reads (`FetchShard`) unless the requester presents either:
   - An owner-signed domain-separated read token (`"parvault-owner-shard-read-v1:"` bound to `shard_id`), OR
   - An owner-signed `RepairGrant` paired with a threshold **Proof-of-Degradation** comprising `≥ 2` distinct witness-signed `WitnessFailureReceipt`s attesting to failed PoR audits on that stripe cohort (e.g., when a `16-of-20` cohort drops to `≤ 18` live shards).
2. **Merkle-Verified Ciphertext Repair (`verify_witness_repair_deposit`):** The repairing witness reconstructs missing ciphertext shards over $GF(2^8)$ and proves membership against `stripe_merkle_root` before replacement storage peers accept the deposit.

## Consequences & Verification

- **Consequences:** Self-healing shard repair operates autonomously while the vault owner is offline without ever exposing `MasterKey` or permitting unauthorized bulk shard scraping.
- **Verification:** `specs/ParVaultProtocol.tla` (`EventuallyRepaired`, `DataSecrecyInvariant`) and `tests/zero_trust_adversarial.rs`.
