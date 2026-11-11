# ADR-28: Stateless `HMAC-SHA256` `CapabilityMacaroon` Offline Caveat Attenuation

- **Status:** Accepted (`v0.4.0`)
- **Subsystem:** `capabilities` / `gateway`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

When local brokers (`parvault-auth-broker`, `parvault-media-daemon`, `parvault-fuse`) request stripe reads or writes through `/var/run/parvault.sock`, `parvault-gateway` must enforce fine-grained least-privilege scoping (read-only access, single manifest root, byte-range slice, short TTL) in `< 1 ms` without querying a session database or round-tripping to mint sub-tokens.

## Decision

1. **Chained `HMAC-SHA256` Macaroons (`CapabilityMacaroon`):** Root tokens are minted under a non-zero 256-bit gateway root key (`[0u8; 32]` fails closed), and any holder can attenuate permissions offline by appending canonical `Caveat`s (`AllowedManifest([u8; 32])`, `ByteRange { offset, length }`, `ExpiresAtUnixMs(u64)`, `ReadOnly`):

```text
tag_0 = HMAC-SHA256(K_macaroon_root, "parvault-macaroon-root-v1:"   || nonce_32 || gateway_id)
tag_i = HMAC-SHA256(tag_{i-1},       "parvault-macaroon-caveat-v1:" || encode_stack(caveat_i))
```

2. **Sub-Millisecond Constant-Time RAM Verification:** `GatewayIpcServer` recomputes the HMAC chain in RAM, compares the final tag via constant-time `ct_eq_32`, evaluates every caveat against `AccessRequestContext` before any `BlockStore` lookup, and anchors gateway identity via composite post-quantum `Ed25519 + ML-DSA-65` (`GatewayIdentityStatement`).

## Consequences & Verification

- **Consequences:** Offline monotonic privilege attenuation (`Allowed(Child) => Allowed(Parent)`) verified in `< 1 ms` with zero database state on `parvault-gateway`.
- **Verification:** Kani harness `proof_macaroon_caveat_attenuation_monotonic_and_zero_key_rejected` and `tests/gateway_ipc_benchmark.rs`.
