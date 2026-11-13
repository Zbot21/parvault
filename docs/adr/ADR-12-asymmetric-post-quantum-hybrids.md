# ADR-12: Asymmetric Post-Quantum Hybrid KEM & Signatures (`X25519 + ML-KEM-768` & `Ed25519 + ML-DSA-65`)

- **Status:** Accepted
- **Formal model:** `specs/ParVaultPostQuantum.tla`
- **Subsystem:** `crypto::pqc`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Long-lived distributed backups and 2-layer onion relay envelopes are high-value targets for **Harvest-Now, Decrypt-Later (HNDL)** adversaries who record wire traffic today to decrypt once a Cryptographically Relevant Quantum Computer (CRQC) exists. On a CRQC, **Shor's algorithm** solves the Elliptic Curve Discrete Logarithm Problem (ECDLP) in polynomial time—completely breaking standalone classical `X25519` key exchange and forging standalone `Ed25519` signatures. Conversely, pure post-quantum lattice implementations (`fips203`, `fips204`) benefit from classical defense-in-depth against implementation defects.

## Decision

1. **X-Wing Style Hybrid KEM (`HybridKemKeypair`: `X25519 + NIST FIPS 203 ML-KEM-768`):** Combines `32 B` `X25519` ECDH with Module-LWE `ML-KEM-768` (`1,184 B` encapsulation key, `1,088 B` ciphertext), binding both shared secrets, ciphertexts, and recipient public keys via `HKDF-SHA512` to prevent multi-target public-key substitution:

```text
salt     = pk_ephem_x25519 || SHA-256(ct_mlkem768)
ikm      = ss_x25519 || ss_mlkem768
info     = "parvault-hybrid-x25519-mlkem768-v2:" || pk_recip_x25519 || SHA-256(ek_recip_mlkem768)
K_hybrid = HKDF-SHA512(salt = salt, ikm = ikm, info = info)
```

   Session encapsulation (`PqRelayedShardEnvelope`, `PqInnerStorageEnvelope`) remains IND-CCA2 secure unless *both* `X25519` and `ML-KEM-768` are simultaneously broken (<!-- metric:kem.encap -->`100.4–117.8 µs`<!-- /metric --> encapsulate / <!-- metric:kem.decap -->`99.4–106.9 µs`<!-- /metric --> decapsulate).
2. **Composite Hybrid Digital Signatures (`HybridPqSigningKeypair`: `Ed25519 + NIST FIPS 204 ML-DSA-65`):** Long-lived `PersonalDeviceCert`s, `PqSignedDhtManifestEnvelope`s, and `GatewayIdentityStatement`s sign over both `Ed25519` (`64 B`) and `ML-DSA-65` (`3,309 B`, context `"parvault-pq-hybrid-dsa65-v1"`). Verification requires `Ed25519::verify` **AND** `ML-DSA-65::verify` to succeed (<!-- metric:sig.sign -->`475.6–477.3 µs`<!-- /metric --> sign / <!-- metric:sig.verify -->`152.1–159.2 µs`<!-- /metric --> verify).

## Consequences & Verification

- **Consequences:** Immunizes asymmetric key encapsulation and long-lived identity/manifest certificates against Shor's algorithm on a CRQC while retaining classical `x25519-dalek` / `ed25519-dalek` security guarantees. (For symmetric encryption under Grover's bound, see [ADR-13](ADR-13-symmetric-pq-grover-baseline-and-cascaded-aead.md).)
- **Verification:** `specs/ParVaultPostQuantum.tla` (`Safety_HNDLConfidentialityPreserved`, `Safety_QuantumSignatureUnforgeability`, <!-- metric:tlc.distinct.ParVaultPostQuantum -->`1,656`<!-- /metric --> distinct states, `0` errors) and `tests/post_quantum_security_proofs.rs`.
