# ADR-19: Crash-Safe Atomic Storage (`fsync` + `rename`), Path-Traversal Defense & Generation-Scoped Lease Pinning

- **Status:** Accepted
- **Subsystem:** `storage::block_store` / `sync`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Power loss mid-write can leave truncated `.shard` or ledger files on flash media; malicious manifests could embed `../` or symlink paths to overwrite host `~/.ssh` files on restore; and replaying an old `BlindedShardTombstone` or unpinned capability key could delete newly re-uploaded blinded shards.

## Decision

1. **Write-Temp-`fsync`-Rename Persistence (`BlockStore::atomic_write_file`):** All `.shard`, `.bshard`, `.manifest.bin`, `blinded_leases.bin`, `wot_state.bin`, `quota_state.bin`, and `0600` secret key files (`write_secret_file_atomic_0600`) write to `.tmp.<nonce>`, call `File::sync_all()`, and atomically `fs::rename`—committing disk I/O *before* burning `AnonymousQuotaVoucher` nullifiers.
2. **Strict Restore Path Containment (`FolderSyncEngine::resolve_safe_restore_path`):** Rejects `..` (`ParentDir`), leading `/`, Windows drive/UNC prefixes, `\`, `:`, NUL bytes, and symlink components (`StorageError::InvalidRestorePath`), verifying streaming SHA-256 on a `.parvault_restore_staging` file before placement.
3. **Capability Pinning, Generation-Scoped Tombstones & Bit-Rot Scrubbing:** `BlindedShardLeaseEntry` pins `capability_pubkey` on initial upload, `BlindedShardTombstone` binds monotonic `lease_generation` (`MAX_CAPABILITY_CLOCK_SKEW_MS = 30,000`), and `BlockStore::scrub_all_shards` (`parvault scrub`) quarantines silent flash bit-rot.

## Consequences & Verification

- **Consequences:** Eliminates torn-write corruption, arbitrary file-overwrite traversal, tombstone replay, and silent media bit-rot.
- **Verification:** `tests/red_team_hardening_tests.rs` and Stage 8 of `scripts/docker_acceptance_gate.sh`.
