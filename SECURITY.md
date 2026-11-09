# Security Policy & Cryptographic Architecture (`parvault`)

## Supported Versions

| Version | Supported | Cryptographic Suite |
| :--- | :---: | :--- |
| `0.1.x` | Yes | Classical (`AES-256-GCM`, `Ed25519`, `X25519`) + Post-Quantum Hybrid (`ML-KEM-768`, `ML-DSA-65`, 512-bit Cascaded AEAD) |

## Zero-Trust & Adversarial Security Guarantees (`ADR-01` – `ADR-15`)

1. **Zero-Knowledge Storage Hosts (`ADR-01`, `ADR-10`, `ADR-12`):**
   - Plaintext files are padded to ISO/IEC 7816-4 buckets and encrypted client-side using 256-bit `MasterKey` (`AES-256-GCM`) or 512-bit Grover-resistant `PqVaultMasterKey` (`ChaCha20-Poly1305 -> AES-256-GCM`) **before** Reed-Solomon erasure coding over $GF(2^8)$.
   - Storage peers and `parvault-seed` nodes hold only high-entropy ciphertext shards ($H(X) > 7.98$ bits/byte) and never possess decryption keys.
2. **4-Layer Shard Anonymization (`ADR-11`):**
   - Remote shards use `BlindedShardId` (`HMAC-SHA256`), per-shard `BlindedShardCapability` keys, single-use `AnonymousQuotaVoucher`s, and 1-hop `PqRelayedShardEnvelope` (`X25519 + ML-KEM-768`) onion routing.
3. **Multi-Domain Red-Team Hardening (`ADR-15`):**
   - **Zero-Local-State "House Fire" Recovery:** Deterministic key stretching (`MasterKey::from_recovery_seed_phrase`) and encrypted DHT Root Catalogs (`EncryptedVaultCatalogEnvelope`) allow full directory recovery after total local disk loss.
   - **Wire Protocol & Filesystem Safety:** `BincodeWireCodec` enforces bounded allocation limits (`with_limit`), `BlockStore` enforces crash-safe write-temp-`fsync`-rename and periodic bit-rot scrubbing (`scrub_all_shards`), and `FolderSyncEngine::restore_folder` blocks path/symlink traversal (`StorageError::InvalidRestorePath`).

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected cryptographic, wire-protocol, or filesystem vulnerabilities.
Instead, use **GitHub Private Vulnerability Reporting** (`Security -> Advisories -> Report a vulnerability`) on the repository. We acknowledge reports within 48 hours and coordinate regression tests (`tests/red_team_hardening_tests.rs`) and TLA+ model updates (`specs/*.tla`) prior to disclosure.
