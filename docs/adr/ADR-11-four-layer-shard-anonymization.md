# ADR-11: 4-Layer Cryptographic Shard Anonymization & 2-Layer Onion Relaying

- **Status:** Accepted
- **Formal model:** `specs/ParVaultAnonymity.tla`
- **Subsystem:** `storage::anonymity` / `crypto::pqc` / `network::client`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Even when shard payloads are encrypted, naive metadata (shared `stripe_merkle_root`, shard index `0..19`, shared stripe-level `K_session` PoR keys, static `uploader_peer_id` quota debits, or direct TCP source IPs) would allow a global coalition of storage peers to group shards belonging to the same file or link them to an uploader's IP address.

## Decision

1. **Layer 1 — Blinded Shard Locators (`BlindedShardId`):** Stored `.bshard` files omit `stripe_merkle_root`, `shard_index`, and sibling hashes, addressing shards solely via a 256-bit keyed PRF locator:

```text
K_blind_loc = HKDF-SHA256(ikm = K_user, info = "parvault-subkey-blind-locator-v1")
Locator_i   = HMAC-SHA256(K_blind_loc, "parvault-blinded-locator-v1:" || StripeRoot || u32_be(ShardIdx) || PayloadHash_i)
```

   Across a neighborhood pool of $M$ blinded shards, an unguided coalition faces a static combinatorial grouping search wall of:

$$
\Omega_{\mathrm{search}} = \binom{M}{K} \times \frac{N!}{(N - K)!} \approx 2^{224} \quad (M \ge 8{,}000,\; K = 16,\; N = 20)
$$

2. **Layer 2 — Per-Shard PoR Capability Keys (`BlindedShardCapability`):** Derives an unlinkable per-shard Ed25519 capability keypair $V_i$ from `(blind_capability_subkey, Locator_i)` pinned at upload time (`±30 s` NTP skew window).
3. **Layer 3 — Ephemeral-Issuer Bearer Quota Vouchers (`AnonymousQuotaVoucher`):** Mints single-use bearer tokens signed by fresh per-shard ephemeral Ed25519 keys (`mint_ephemeral`) redeemed into a disk-persisted `65,536`-entry `VoucherNullifierLedger` (`1-to-1` conservation with zero `PeerId` linkage).
4. **Layer 4 — 2-Layer Post-Quantum Onion Relay Dispatch (`PqRelayedShardEnvelope`):** Wraps `PqInnerStorageEnvelope` (sealed to destination storage peer's `HybridKemPublicKey`) inside an outer relay envelope (sealed to an intermediate relay peer's `HybridKemPublicKey` with `jitter_delay_ms`) so the relay never sees `Locator_i` or `voucher` and the storage peer never sees the uploader's IP/`PeerId`.

## `v0.5.0` Enforcement

- A voucher is honoured only if its issuer is a ring member the receiver knows or the receiver's configured issuer (F-24). Ephemeral per-shard issuers (`mint_blinded_ephemeral`) are therefore refused in `v0.5.0`; unlinkable vouchers need the anonymous credentials planned for `v0.6.0`. Because the final target only honours an issuer it trusts, an onion voucher identifies its issuer to the target: originator anonymity toward the target holds only if the issuer is not the originator (for example a relay-issued voucher) (L-39). Every hop needs an admitted sender: the originator at the entry relay, and each relay at the next hop.
- Onion routing hides the originator from the final target and the storage host, assuming the entry relay and the target do not collude. The entry relay always learns the originator's IP address and transport key, which in `v0.5.0` is its ring identity. The originator presents its ring credential at the entry relay and must be admitted there (F-33); each relay forwards under its own identity, is admitted at the next hop, and keeps at most 4 forwards in flight per sender and 64 in total (`reject.relay_budget`).
- A single-layer envelope sent straight to the target is not anonymous.
- No shipped command originates onions in `v0.5.0` (`OnionOriginator` has no production caller). Unlinkable entry (an ephemeral transport key plus an anonymous credential, or a PoW ticket in public mode) is planned for `v0.6.0`.
- A direct `PutBlindedShard` is a hand-off between ring members (graceful leave), not anonymous origination, and needs an admitted sender.

## Consequences & Verification

- **Consequences:** Eliminates static disk grouping, PoR key correlation, quota ledger linkage, and single-hop IP exposure; paired with hedged parallel $N$-shard reads across degraded WANs.
- **Verification:** `specs/ParVaultAnonymity.tla` (<!-- metric:tlc.distinct.ParVaultAnonymity -->`441`<!-- /metric --> distinct states, `0` errors) and `tests/anonymity_and_degraded_net_tests.rs` (`8/8` degraded network profiles).

## v0.5.0: deletes (F-41)

A blinded shard is deleted before lease expiry only on a fresh Ed25519 signature by the lease's registered capability key over `"parvault-delete-blinded-v1" || host_pubkey || locator || content_sha256 || timestamp_ms` (`DeleteBlindedShardSigned`, `blinded_delete_decision`). The host binding stops one host replaying a delete to other replicas. The capability bound to a locator is immutable while its lease exists (`blinded_rebind_decision`). The MAC tombstone keyed by `delete_verifier` is refused: the verifier is visible to hosts and relays. Leases stored without a capability key cannot be deleted and expire by lease. Read, renew and delete share the capability key; it is Ed25519 only in v0.5.0.
