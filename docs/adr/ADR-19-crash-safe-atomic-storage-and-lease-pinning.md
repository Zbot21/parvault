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

The per-peer write ceiling (4x the allowance, ADR-07 item 3; `epoch_ingress_bytes_written`) resets every 24 h (`QUOTA_WRITE_EPOCH_SECS = 86_400`; `quota_write_epoch_secs` in `config.toml`; each rollover logs `info.quota_write_epoch_rolled`), so it is a daily upload budget per peer and host. Before v0.5.5 it never reset outside tests, a lifetime cap. The epoch timer is RAM only on the monotonic clock (`roll_epoch_if_due`, `epoch_rollover_decision`; claim and Kani `B162-EPOCH`): `quota_state.bin` keeps its v0.5.3 layout, and a restart starts a new epoch, so restarting a node reopens every peer's budget.

## v0.5.6 status (B-158, B-147)

Owner frees (`MeshWireRequest::FreeShards`, B-154 2.4) are host-bound, 30 s fresh, signed over `free_order_signing_bytes`, and carry a per-signer epoch; the host keeps the last accepted epoch per signer in `free_order_epochs.bin` (tagged, atomic; RAM only on `--no-fs`), drops a mark 60 s after it was set, and refuses every order for 60 s after a mark file fails to load (claims B154-FREE*, Kani `proof_free_order_needs_every_fact`). `DeleteShard` v1 tokens are 30 s fresh too (B158-FRESH). Every owner removal goes through one path (`remove_held_shard`: the shard with its quota credit and shard-index entry, then the eviction attribution, then the PoR binding, cleared only after the removal succeeded). The PoR auditor writes `por_audit_journal.bin` (tagged, atomic, absolute post-values) before the quota ledger and `por_audit_state.json`; the first audit job after a start raises each to the journal where lower (`audit_journal_apply_decision`, Kani `B147-JOURNAL`), so a crash between the writes leaves them agreeing.
