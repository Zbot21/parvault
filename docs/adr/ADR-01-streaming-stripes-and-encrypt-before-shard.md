# ADR-01: Fixed-Size Streaming Stripes & Encrypt-Before-Shard Pipeline

- **Status:** Accepted — Extended by [ADR-13](ADR-13-symmetric-pq-grover-baseline-and-cascaded-aead.md) and [ADR-21](ADR-21-router-soc-1mib-streaming-profile.md)
- **Subsystem:** `crypto::aes` / `sharding::reed_solomon` / `sharding::merkle`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

> **[Historical Evolution Note (`v0.4.0`)]:** Originally specified in `v0.1` with fixed `16 MiB` `AES-256-GCM` stripes. [ADR-13](ADR-13-symmetric-pq-grover-baseline-and-cascaded-aead.md) formalized why 256-bit `AES-256-GCM` already provides a 128-bit post-quantum Grover security floor and added optional dual-cipher cascaded sealing (`PqVaultMasterKey`), while [ADR-21](ADR-21-router-soc-1mib-streaming-profile.md) made stripe sizes profile-configurable (`1 MiB` Router-SoC, `4 MiB` Homelab-NAS, `16 MiB` Desktop) with full cross-profile manifest interoperability.

---

## Context

Target deployment hardware spans multi-terabyte homelab servers and memory-constrained residential gateways (`prplOS` / `OpenWrt` LXC containers with 128–512 MiB total system RAM and a strict `< 32 MiB` active daemon RAM budget), whereas backup workloads routinely process multi-gigabyte files. Buffering entire files in RAM before encryption or erasure coding would cause out-of-memory kills on embedded gateways, while sharding plaintext before encryption would leak data to colluding storage nodes.

## Decision

1. **Bounded Streaming Stripe Pipeline:** Files are processed sequentially in fixed-size streaming segments (`DEFAULT_STRIPE_SIZE_BYTES = 16 MiB` on Desktop, configurable down to `1 MiB` on Router-SoC per [ADR-21](ADR-21-router-soc-1mib-streaming-profile.md)) after ISO/IEC 7816-4 power-of-two bucket padding (`pad_plaintext_iso_bucket`).
2. **Domain-Separated HKDF Subkeys & Deterministic Per-Stripe Nonces:** The 256-bit client `MasterKey` never keys multiple primitives directly; it derives isolated subkeys via `HKDF-SHA256` and deterministic 96-bit per-stripe nonces:

```text
K_stripe_aead  = HKDF-SHA256(ikm = K_user, info = "parvault-subkey-stripe-aead-v1")
K_stripe_nonce = HKDF-SHA256(ikm = K_user, info = "parvault-subkey-stripe-nonce-v1")
Nonce_i        = HKDF-SHA256(ikm = K_stripe_nonce, salt = FileSalt, info = "parvault-stripe-nonce-v1:" || u64_be(i))[0..12]
AAD_i          = "parvault-stripe-aad-v1:" || u64_be(i)
```

3. **Strict Encrypt-Before-Shard Invariant:** Each stripe is authenticated and encrypted client-side with `AES-256-GCM` *before* Reed-Solomon splitting over $GF(2^8)$ (`0x11d`) into $K$ data shards and $M$ parity shards ($N = K + M$).
4. **Two-Level Merkle Integrity:** Each stripe's $N$ ciphertext shards form a domain-separated SHA-256 Merkle tree (`0x00` leaf prefix, `0x01` internal node prefix), and stripe roots roll up into `file_merkle_root`.

## Consequences & Verification

- **Consequences:** Resident memory remains strictly decoupled from total file size (<!-- metric:bench.soc.vmhwm -->`9.72–9.74 MiB`<!-- /metric --> peak `VmHWM` on `1 MiB` stripes; <!-- metric:bench.desktop.vmhwm -->`57.91 MiB`<!-- /metric --> on `16 MiB` stripes across arbitrarily large files), and storage peers never observe plaintext or unauthenticated shards.
- **Verification:** Kani harnesses `proof_streaming_stripe_layout_all_u64_file_sizes_and_profiles`, `proof_stripe_nonce_injectivity_and_no_panic`, and `proof_gf256_field_axioms_and_shard_bounds`; `specs/ParVaultProtocol.tla`; `tests/formal_verification.rs` (`16,777,216` $GF(2^8)^3$ triples).
