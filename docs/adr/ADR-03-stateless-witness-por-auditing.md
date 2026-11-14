# ADR-03: Stateless RAM-Verified Proof-of-Retrievability (PoR) Auditing

- **Status:** Accepted — Extended by [ADR-09](ADR-09-byzantine-merkle-quarantine-and-egress-slashing.md) and [ADR-11](ADR-11-four-layer-shard-anonymization.md)
- **Subsystem:** `por::challenger` / `por::verifier`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Continuous storage auditing must verify that peers physically retain assigned ciphertext shards within interactive latency (`≤ 300 ms` SLA) even while the vault owner's laptop is offline. However, stateful challenge databases on storage nodes would exhaust gateway RAM, and unauthenticated byte-range reads would enable denial-of-service disk amplification.

## Decision

1. **Stateless RAM HMAC Pre-Screening:** Before touching disk I/O (`BlockStore::read_shard_range_verified`), `PorVerifierEngine` validates a stateless HMAC token in RAM and rejects replayed nonces via a bounded `65,536`-entry FIFO cache (`MAX_REPLAY_CACHE_ENTRIES`):

```text
Chal_MAC   = HMAC-SHA256(K_session, ShardId || ChallengeNonce || u64_be(Offset) || u64_be(Length))
Commitment = SHA-256(ChallengeNonce || ShardBytes[Offset .. Offset + Length])
```

2. **Delegated Witness Auditing:** Cohort witness nodes hold only the per-stripe challenge key (or per-shard `BlindedShardCapability` public key in anonymized mode per [ADR-11](ADR-11-four-layer-shard-anonymization.md)) so routine PoR challenges continue while the owner device sleeps, without granting witnesses decryption capability.

3. **Per-shard chunk roots (manifest version 2):** every new `StripeManifestEntry` records `shard_chunk_roots`, one root per shard over its `4 KiB` chunks (`por::chunk_merkle`): `leaf = SHA-256(0x00 || u32_le(i) || u32_le(n) || chunk)`, `node = SHA-256(0x01 || l || r)` with the last odd node promoted, `root = SHA-256(0x02 || u32_le(n) || tree_root)`. Index and count are bound into each leaf. The audit loop that challenges chunks against these roots does not issue challenges yet (`F-06`). Manifests written before version 2 decode with no roots and cannot be chunk-audited.

## Consequences & Verification

- **Consequences:** Invalid or replayed audit packets are dropped in nanoseconds with zero disk seeks, while honest storage peers prove physical byte retention in bounded RAM.
- **Verification:** `specs/ParVaultProtocol.tla`, `tests/zero_trust_adversarial.rs`, and `por::verifier` unit tests.
