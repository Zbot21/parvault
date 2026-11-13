# ADR-13: Symmetric Post-Quantum Grover Baseline (`AES-256-GCM`) & Dual-Cipher Cascaded AEAD (`PqVaultMasterKey`)

- **Status:** Accepted
- **Formal model:** `specs/ParVaultPostQuantum.tla`
- **Subsystem:** `crypto::aes` / `crypto::pqc` / `crypto::keys`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Engineers auditing a post-quantum codebase frequently ask why `parvault` continues to use `AES-256-GCM` for streaming stripes alongside NIST FIPS 203/204 post-quantum lattices ([ADR-12](ADR-12-asymmetric-post-quantum-hybrids.md)), and why `PqVaultMasterKey` cascades `AES-256-GCM` with `ChaCha20-Poly1305`. Unlike public-key elliptic curves broken exponentially by Shor's algorithm, unstructured symmetric block/stream ciphers and keyed hash PRFs face only **Grover's quantum search algorithm**, which yields at most a quadratic $\mathcal{O}(2^{n/2})$ speedup.

## Decision

1. **Single-Pass `AES-256-GCM` Already Satisfies NIST Post-Quantum Category 5 (`128-Bit PQ`):** Halving a 256-bit key space under Grover's $\mathcal{O}(2^{n/2})$ bound leaves $2^{128}$ sequential quantum oracle evaluations—matching **NIST Post-Quantum Security Category 5** (the highest NIST PQ tier). Standard `MasterKey` stripe encryption (`encrypt_stripe`, <!-- metric:aes.enc.span -->`496.5–589.2 MiB/s`<!-- /metric -->), manifest encryption (`encrypt_manifest`), `PqRelayedShardEnvelope` payload sealing, and 256-bit `HMAC-SHA256` PRFs are therefore **already post-quantum secure** without lattice overhead.
2. **Dual-Cipher Cascaded AEAD for Algebraic Cipher Diversity (`PqVaultMasterKey`):** For root vault superblocks (`EncryptedVaultCatalogEnvelope`) and maximum-assurance vault sealing (<!-- metric:pq.enc -->`248.4–261.4 MiB/s`<!-- /metric -->), `PqVaultMasterKey` derives two independent 256-bit keys $(K_1, K_2)$ via `Argon2id` + `HKDF-SHA256` and cascades two algebraically orthogonal AEAD designs:

```text
Inner Pass : C_inner = AES-256-GCM_Encrypt(key = K_1, nonce = Nonce_1, plaintext = P)
Outer Pass : C_outer = ChaCha20-Poly1305_Encrypt(key = K_2, nonce = Nonce_2, plaintext = C_inner)
```

   - `AES-256-GCM` is an `S-box` substitution-permutation network (SPN) paired with binary Galois field ($GF(2^{128})$) GHASH authentication.
   - `ChaCha20-Poly1305` is an Add-Rotate-XOR (ARX) stream cipher paired with prime-field ($2^{130} - 5$) Poly1305 authentication.
   - **Explicit Cryptanalytic Rationale:** Cascading two 256-bit ciphers does *not* square Grover resistance to $2^{512}$ (each layer maintains a $2^{128}$ quantum floor); rather, it guarantees **algebraic cipher-diversity defense-in-depth** so a catastrophic classical or quantum cryptanalytic shortcut against either AES-GCM *or* ChaCha20-Poly1305 alone never exposes plaintext.

## Consequences & Verification

- **Consequences:** Preserves `~500–589 MiB/s` single-pass `AES-256-GCM` streaming speed on constrained Router-SoC CPUs with full 128-bit post-quantum security while protecting crown-jewel catalog superblocks and cascaded vaults against single-cipher cryptanalytic breaks.
- **Verification:** `specs/ParVaultPostQuantum.tla` (`Safety_GroverBitSecurityFloor`), `tests/post_quantum_security_proofs.rs`, and `parvault-bench`.

## v0.5.0: blinded deletes (F-41)

Blinded shards are deleted only by a delete signed with the lease's capability key (ADR-11, `DeleteBlindedShardSigned`); `BlindedShardTombstone` MACs are refused. Leases stored without a registered capability key (`capability_pubkey: None`, legacy) can be neither read nor deleted (F-42, D-2: fail closed) and expire by lease.
