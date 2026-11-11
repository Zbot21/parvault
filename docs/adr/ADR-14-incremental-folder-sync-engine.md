# ADR-14: Incremental Folder Synchronization Engine (`FolderSyncEngine`), `.parvaultignore` & 64 KiB Streaming Delta Hashing

- **Status:** Accepted
- **Subsystem:** `sync`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Users and companion appliances require continuous, deduplicated directory-tree backup (`watch-folder`, `diff-folder`, `restore-folder`) rather than manual single-file invocations. Whole-file `std::fs::read` hashing would violate the `< 32 MiB` gateway RAM ceiling on multi-gigabyte VM or media archives, and workspace junk (`.git`, `target`, `node_modules`, swap files) must be excluded deterministically.

## Decision

1. **Constant-Memory `64 KiB` Streaming SHA-256 Delta Detection (`compute_file_sha256_streaming`):** `FolderSyncEngine` scans directory trees using a fixed `64 KiB` stack buffer, re-encrypting and erasure-coding only new or modified files across polling epochs while reusing existing `FileManifest` entries for unchanged files.
2. **`.parvaultignore` Filtering & Tombstone Pruning:** `IgnoreRules` excludes `.git`, `node_modules`, `target`, `.DS_Store`, `Thumbs.db`, `*.tmp`, `*.swp`, and `.parvault_restore_staging` by default plus user `.parvaultignore` globs and `!` negations; `--prune-deleted` records `DeletedFileTombstone`s and issues authenticated local + remote `DeleteShard` garbage collection.
3. **Monotonic Encrypted Snapshot Catalogs (`FolderSnapshotManifest`):** Publishes versioned directory snapshots wrapped in signed DHT envelopes for whole-folder or single-file (`--file`) restoration.

## Consequences & Verification

- **Consequences:** Arbitrary multi-GiB directory trees synchronize incrementally within `< 32 MiB` gateway RAM with zero redundant shard uploads.
- **Verification:** `tests/sync_daemon_usability_and_cli_regression_tests.rs` and Stages 4–5 of `scripts/docker_acceptance_gate.sh`.
