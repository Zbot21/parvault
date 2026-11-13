# ADR-09: Pre-Decoding Merkle Quarantine & Byzantine Egress-Withholding Slashing

- **Status:** Accepted — Extended by [ADR-11](ADR-11-four-layer-shard-anonymization.md) and [ADR-12](ADR-12-asymmetric-post-quantum-hybrids.md)
- **Formal model:** `specs/ParVaultProtocol.tla`
- **Subsystem:** `sharding::reed_solomon` / `por::challenger` / `storage::quota`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

> **[Historical Evolution Note (`v0.4.0`)]:** Originally paired with Ed25519 `SignedDhtManifestEnvelope`s and per-owner HMAC shard pseudonyms in `v0.1`. Extended in [ADR-11](ADR-11-four-layer-shard-anonymization.md) to full 4-layer unlinkable `.bshard` anonymization (`BlindedShardId` + PQ onion relays) and in [ADR-12](ADR-12-asymmetric-post-quantum-hybrids.md) to composite post-quantum `PqSignedDhtManifestEnvelope` signatures.

---

## Context

Crash-fault erasure coding alone fails under active Byzantine adversaries who inject corrupted shards into Reed-Solomon reconstruction, retain only a tiny fraction of a shard or proxy challenges over WAN links, or pass lightweight PoR audits to farm credits while withholding bulk shard egress during user restores.

## Decision

1. **Pre-Decoding Merkle Quarantine (`reconstruct_zero_trust_with_quarantine`):** Every candidate shard is verified against its leaf SHA-256 and `MerkleProof` *before* entering $GF(2^8)$ Vandermonde matrix inversion; poisoned shards are discarded immediately and their sender is slashed (`WebOfTrustRegistry::slash_immediately`).
2. **8-Stratum Scatter-Gather PoR & Anti-Proxy RTT Ceiling (`MultiSegmentPorChallenge`):** Samples non-overlapping byte strata across the entire shard under a strict `max_rtt_ms` bound (`≤ 300 ms`) so partial-retention and remote-proxy nodes fail audits with overwhelming probability.
3. **Egress-Withholding Credit Burn (`EgressWithholdingEvidence`):** Storage peers that pass PoR challenges but refuse bulk `FetchShard` egress during restore have 100% of their accumulated `bytes_contributed_by_peer` reciprocity credits burned (`QuotaManager::slash_peer_for_withholding`).

## v0.5.0 status

- **Quarantine is local.** A node quarantines a peer only from its own checks (pre-decoding Merkle quarantine, item 1, and in a later release its own PoR audits, 2c-β). No wire input slashes a peer in v0.5.0: slashing gossip is not subscribed (F-01) and `apply_slashing_evidence` is test-only. The slash guard `slash_target_decision` (`reject.slash_protected_target`) keeps the genesis and the node's own keys unslashable (Kani `proof_slash_guard_protects_genesis_and_self`).
- **Egress slashing (item 3) is not implemented.** `EgressWithholdingEvidence` is a reporter's claim, not transferable proof; publishing proof-carrying evidence is v0.6.0.

## Consequences & Verification

- **Consequences:** Neutralizes poisoned-shard decoding corruption, partial-shard cheating, WAN proxy outsourcing, and hostage egress withholding.
- **Verification:** `tests/zero_trust_adversarial.rs` and Stage 8 (`parvault scrub` bit-rot quarantine) of `scripts/docker_acceptance_gate.sh`.
