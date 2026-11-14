# Security Policy & Cryptographic Architecture (`parvault`)

## Supported Versions

| Version | Supported | Cryptographic & Memory-Safety Suite |
| :--- | :---: | :--- |
| `0.4.x` | Yes | Classical (`AES-256-GCM`, `ChaCha20-Poly1305`, `Argon2id`, `Ed25519`, `X25519`) + Post-Quantum Hybrid (`ML-KEM-768`, `ML-DSA-65`, Dual-Cipher `PqVaultMasterKey`) + `#![deny/forbid(unsafe_code)]` (`15` Kani + `7` TLA+ proofs) |
| `< 0.4.0` | No (Superseded by `0.4.0`) | Prior releases |

## Zero-Trust & Adversarial Security Guarantees ([ADR index](docs/ADR.md))

1. **Zero-Knowledge Storage Hosts: encrypt-before-shard, AES and post-quantum ciphers (`ADR-01`, `ADR-12`, `ADR-13`):**
   - Plaintext files are padded to ISO/IEC 7816-4 buckets and encrypted client-side using 256-bit `MasterKey` (`AES-256-GCM`, 128-bit post-quantum Grover floor) or 512-bit dual-cipher `PqVaultMasterKey` (inner `AES-256-GCM` $\to$ outer `ChaCha20-Poly1305`) **before** Reed-Solomon erasure coding over $GF(2^8)$.
   - Storage peers and `parvault-seed` nodes hold only high-entropy ciphertext shards (`H(X) > 7.98 bits/byte`) and never possess decryption keys.
2. **4-Layer Shard Anonymization (`ADR-11`):**
   - Remote shards use `BlindedShardId` (`HMAC-SHA256`), per-shard `BlindedShardCapability` keys, single-use `AnonymousQuotaVoucher`s (bounded 65,536-entry FIFO nullifier ledger), and 1-hop `PqRelayedShardEnvelope` (`X25519 + ML-KEM-768`) onion routing.
3. **Multi-Domain Red-Team Hardening: house-fire recovery and crash-safe atomic storage (`ADR-18`, `ADR-19`):**
   - **Zero-Local-State "House Fire" Recovery:** Memory-hard `Argon2id` (`m = 64 MiB`, `t = 3`, `p = 4`) + `HKDF-SHA256` key derivation (`MasterKey::from_recovery_seed_phrase` / `PqVaultMasterKey::from_recovery_seed_phrase`) and encrypted DHT Root Catalogs (`EncryptedVaultCatalogEnvelope`) allow full directory recovery over `libp2p` after total local disk loss.
   - **Wire Protocol & Filesystem Safety:** `BincodeWireCodec` enforces bounded allocation limits (`with_limit`), `BlockStore` enforces crash-safe write-temp-`fsync`-rename and periodic bit-rot scrubbing (`scrub_all_shards`), and `FolderSyncEngine::restore_folder` blocks path/symlink traversal (`StorageError::InvalidRestorePath`).

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected cryptographic, wire-protocol, or filesystem vulnerabilities.
Instead, use **GitHub Private Vulnerability Reporting** (`Security -> Advisories -> Report a vulnerability`) on the repository. We acknowledge reports within 48 hours and coordinate regression tests (`tests/red_team_hardening_tests.rs`) and TLA+ model updates (`specs/*.tla`) prior to disclosure.
