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
3. **Capability Pinning, Signed Deletes & Bit-Rot Scrubbing:** `BlindedShardLeaseEntry` pins `capability_pubkey` on initial upload and a re-put cannot replace it while the lease exists (`blinded_rebind_decision`, F-41); a delete is a host-bound signature by that key within `MAX_CAPABILITY_CLOCK_SKEW_MS = 30,000` (`blinded_delete_decision`); generation-scoped MAC tombstones are retired (refused); `BlockStore::scrub_all_shards` (`parvault scrub`) quarantines silent flash bit-rot.

## Consequences & Verification

- **Consequences:** Eliminates torn-write corruption, arbitrary file-overwrite traversal, forged or replayed blinded deletes, and silent media bit-rot.
- **Verification:** `tests/red_team_hardening_tests.rs` and Stage 8 of `scripts/docker_acceptance_gate.sh`.

## v0.5.5 status (B-162)

The per-peer write ceiling (4x the allowance, ADR-07 item 3; `epoch_ingress_bytes_written`) resets every 24 h (`DEFAULT_WRITE_EPOCH_MS`; `quota_write_epoch_ms` in `config.toml`), so it is a daily upload budget per peer and host. Before v0.5.5 it never reset outside tests, a lifetime cap. The epoch timer is RAM only on the monotonic clock (`roll_epoch_if_due`, `epoch_rollover_decision`; claim and Kani `B-162`): `quota_state.bin` keeps its v0.5.3 layout, and a restart starts a new epoch, so restarting a node reopens every peer's budget.
