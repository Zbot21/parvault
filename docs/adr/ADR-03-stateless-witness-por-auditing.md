# ADR-03: Stateless RAM-Verified Proof-of-Retrievability (PoR) Auditing

- **Status:** Accepted, amended by B-59 (`v0.5.2`). Extended by [ADR-09](ADR-09-byzantine-merkle-quarantine-and-egress-slashing.md) and [ADR-11](ADR-11-four-layer-shard-anonymization.md)
- **Subsystem:** `por::challenger` / `por::verifier` / `por::audit` / `por::auditor`
- **Formal model:** `specs/ParVaultPorAudit.tla`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

The owner needs evidence that the peers holding its shards still hold them. A host must not be able to pass from stored hashes alone. A storage node must keep no per-challenge database, and an unauthenticated request must never make it read disk.

Audits run only while an auditor runs: the owner's long-running daemon, or a seed for the lite stripes it fanned out (L-27, L-100). Nothing audits a full client's stripes while its owner is offline.

## Decision

1. **Stateless RAM pre-screen.** Before any disk read, `PorVerifierEngine` checks a stateless HMAC under the per-stripe session key `K_stripe`, the freshness of `issued_at` (30 s), and a bounded replay cache (`MAX_SEEN_NONCES_RAM` = 65,536 nonces). Byte-range audits then read with `BlockStore::get_shard_range`:

```text
PorAudit:   H = HMAC-SHA256(K_stripe, "parvault-por-chal-v1:" || ShardId || Nonce || u64_be(Offset) || u64_be(Length) || u64_be(issued_at))
ChunkAudit: H = HMAC-SHA256(K_stripe, "parvault-por-chunk-v1:" || root || u32_be(shard_index) || shard_hash
                            || Nonce || u32_be(count) || u32_be(index)* || u64_be(issued_at))
```

   Each kind has its own prefix, so a token of one kind is never valid as the other.

2. **Delegated witness auditing: superseded (L-27).** Witness audits while the owner sleeps are `v0.6.x+`.

3. **Chunk-Merkle proofs (F-34).** Every `StripeManifestEntry` (manifest version 2) records `shard_chunk_roots`, one root per shard over its 4 KiB chunks (`por::chunk_merkle`): `leaf = SHA-256(0x00 || u32_le(i) || u32_le(n) || chunk)`, `node = SHA-256(0x01 || l || r)` with the last odd node promoted, `root = SHA-256(0x02 || u32_le(n) || tree_root)`. The auditor challenges `min(4, n)` distinct indices (at most 8) drawn from the OS RNG. The host returns each chunk and its sibling path, and `chunk_proof_decision` checks it against the manifest root and `shard_len` alone. Proofs are not bound to the nonce, so freshness comes only from unpredictable indices: they are never derived from the nonce or the time.

4. **The host answers only the storer.** `K_stripe` is held by every host of a stripe, so the HMAC alone would let a co-host fetch another host's chunks on demand, read them without the owner signature `GetCiphertextShard` requires, or spend the owner's audit budget. A host answers `ChunkAudit` only when the Noise-authenticated sender is the peer the shard is accounted to (`por_storer_decision`, `reject.por_not_storer`), checked in RAM before the rate check and any read. Then: at most 6 chunk audits per stripe key per 10 min and 60 per minute per host (12 on `router-soc`), with a rate map that refuses when full (`reject.por_rate_limited`). The proof is built on the blocking pool, at most 2 in flight (1 on `router-soc`, `reject.por_prover_busy`). The host reads chunk by chunk without the leaf-hash check, so a corrupt chunk surfaces as an invalid proof.

5. **Detection, with one latent local consequence.** `chunk_audit_decision` gives one of three verdicts:
   - **Pass:** `record_por_outcome(prover, true)` in the auditor's own ledger.
   - **ProofInvalid:** only for a decoded answer that fails the echo check (shard, nonce, one proof per index in order) or `chunk_proof_decision`. It writes `record_por_outcome(prover, false)` and marks the shard degraded.
   - **Unanswered:** everything a host can cause by not answering: no answer, a refusal, a decode error, an unknown variant on an old host, or an answer over the RTT bound (2 s; 5 s on `router-soc`). It is counted in `por_audit_state.json` and retried once after 60 s. It is never a failure. A host refuses with `ChunkAuditResult(None)` and no reason, so a refusal for a stale clock (`issued_at` more than 30 s off) is counted unanswered like every other refusal, with no count of its own. That is deliberate: the reason would be chosen by the host, and nothing the host says about why it did not answer can change the verdict, so a reason count would only report the host's claim.

   `audit_credit_decision` credits only a prover that is not one of the auditor's own identities, keyed by its Noise-authenticated device id (`reject.por_self_credit`). A host already known to be this node is refused before any network call. A manifest address without a `/p2p/` id is resolved from the connection the audit request makes, so a self-named host at such an address is contacted once before the refusal. A prover whose id stays unknown (an offline host at an address with no `/p2p/` id) is credited nothing (`reject.por_prover_unknown`) and counted unanswered, retried once like any other; the ledger is never keyed by an address. **The one automatic consequence is local and latent (L-105):** the ledger sets that peer's reciprocity factor on this node (`quota_decision`). At least 20 audits with at least 99.5 % passes give 1.25, otherwise 2.0, so an invalid proof narrows the host's allowance on the auditing node. Unanswered audits never move the factor, so a host that has earned 1.25 keeps it by not answering: a cheating host never produces `ProofInvalid`, it simply stops answering. While `record_remote_contribution` has no caller, the earned allowance is zero at either factor and only the bootstrap grace applies; giving it a production caller needs its own decision on hosts that stop answering. Nothing quarantines, repairs, gossips or leaves the node (L-27, L-29), and ADR-09 consequences are not driven by audit results.

6. **Sampling and cost.** A tick (the interval, at most 60 s) first checks whether anything may be due: a pending retry, the hourly cap, and the next scan time. A scan decrypts at most 4 random local manifests (no table), or on a seed samples 4 records of its lite audit index; it takes the host whose last audit is oldest and audits a random shard of it once that host is due (1 h, or 6 h on `router-soc`, with ±20 % jitter). A scan that finds nothing due sets the next scan to when the oldest scanned host falls due, at least one tick and at most a quarter interval away, so an idle node scans at most about 4 times per interval. The node runs at most 30 audits per hour. Sampling is per host, so a given shard is challenged about once per `S × interval`, where `S` is the number of shards that host holds for this owner. A host that dropped a fraction `d` of a shard passes one audit of it with probability `(1 − d)^min(4, n)`. Shards with fewer than 8 chunks get weak detection.

   **Seed (F-06-SEED, L-100).** `ingest_lite_stripe` computes the chunk roots and `run_lite_fan_out` records each shard a host acknowledged in `LiteAuditIndex`: 8 MiB at most; when full, the oldest record of the lite client holding the most bytes is dropped (from auditing only), so one client cannot push out the others' stripes. It lives in RAM under `--no-fs` and otherwise in `lite_audit_index.bin`, written atomically with a version header; an unreadable file starts empty. The seed audits as its own identity, which stored the shards, through the same `run_audit_job` and verdicts. Its results stay on the seed (L-29). Flags: `--no-audit`, `--audit-interval-secs` (default 1 h), `--audit-rtt-ms` (default 2 s).

7. **Single-round challenges (PAT-04, L-106).** Every audit kind (`PorAudit`, `MultiSegmentPorAudit`, `ChunkAudit`, and any later witness audit) is one request and one response. The verifier chooses the indices or offsets and the nonce from the OS RNG; a retry draws fresh ones. A prover never derives a challenge from an earlier proof, and no audit runs a sequential proof chain.

## Consequences & Verification

- **Consequences:**
  - Invalid or replayed audits are refused in RAM with no disk read.
  - Byte-range `PorAudit` and `MultiSegmentPorAudit` stay liveness probes: answered, never issued by core, and unverifiable.
  - Blinded shards (ADR-11) and v1 manifests are counted unauditable, never failed. A stripe stored under another key is refused by its host (`reject.por_not_storer`, answered as `None`), so its audits are counted unanswered, as are audits a host refuses for a stale clock.
  - Shards handed off by a departing node are accounted to it, so the owner's audit of them is refused (`reject.por_not_storer`) and counted unanswered.
  - Colluding hosts of a stripe can still proxy for each other within the RTT bound.
  - Hosts must run `v0.5.2` before an owner's ledger means anything.
- **Verification:** `specs/ParVaultPorAudit.tla` (guards `chunk-proof`, `chunk-storer`, `audit-credit`, `verdict-classes`); reach F-06 and F-06-SEED; claims F-06-RATE, F-06-SEED, F-06-TIMEOUT, F-07, F-34, F-34-STORER and E-POR in `tests/trust_enforcement.rs`; `por::chunk_merkle`, `por::audit`, `por::auditor`, `por::lite_index` and `por::verifier` unit tests.
