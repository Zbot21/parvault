# ADR-18: Zero-Local-State BIP-39 & `Argon2id` "House Fire" Disaster Recovery

- **Status:** Accepted
- **Subsystem:** `crypto::keys` / `sync`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

If a user's home burns down destroying every laptop, phone, and local `.manifest.bin` / key file simultaneously, they must be able to recover their complete directory tree on a brand-new machine using only a memorized 12-word or 24-word recovery mnemonic and reachable mesh peers—while resisting GPU brute-force attacks against low-entropy passphrases.

## Decision

1. **BIP-39 Checksum Validation & Memory-Hard `Argon2id` Stretching:** `MasterKey::from_recovery_seed_phrase` and `PqVaultMasterKey::from_recovery_seed_phrase` normalize mnemonics via Unicode NFKD, verify BIP-39 wordlist membership and SHA-256 checksum bits, and stretch entropy with **`Argon2id` (`m = 64 MiB [65,536 KiB], t = 3, p = 4`)** (<!-- metric:argon2.derive -->`138.77–143.65 ms`<!-- /metric -->) followed by domain-separated `HKDF-SHA256` / `HKDF-SHA512` to deterministically reconstruct `MasterKey`, `PqVaultMasterKey`, `NodeIdentity`, and `derive_vault_root_dht_key(vault_namespace)`.
2. **Dual-Sealed Root Superblock Catalog (`EncryptedVaultCatalogEnvelope`):** `FolderSyncEngine::export_encrypted_vault_catalog` seals `FolderSnapshotManifest` under both `MasterKey` and 512-bit cascaded `PqVaultMasterKey`, signed by the derived `NodeIdentity`, enabling `parvault recover-from-seed` to discover the highest-version catalog over `libp2p` and restore all files with **zero prior local state**.

## Consequences & Verification

- **Consequences:** Total physical loss of all local hardware is survivable from a memorized 12/24-word phrase alone, backed by `64 MiB` memory-hard key stretching. This covers only folders backed up with `parvault watch-folder --seed-phrase <P> --vault-namespace <NS>` (or `PARVAULT_SEED_PHRASE`) while peers holding the shards are reachable; `parvault init` prints no phrase (`parvault new-seed-phrase` generates one and stores nothing), and `parvault up --folder` vaults have no phrase recovery. Node, PQ, ring and enclave keys are never derived from the phrase.
- **Verification:** `tests/red_team_hardening_tests.rs` and Stage 9 of `scripts/docker_acceptance_gate.sh`.
