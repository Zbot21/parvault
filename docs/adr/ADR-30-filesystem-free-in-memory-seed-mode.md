# ADR-30: Filesystem-Free Bounded-RAM Ephemeral Seed & Relay Mode (`parvault-seed --no-fs`)

- **Status:** Accepted (`v0.4.0`)
- **Subsystem:** `bin/parvault-seed` / `storage::block_store` / `storage::eviction`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Privacy-hardened seed operators deploying on diskless PXE/initramfs appliances, read-only container rootfs images, or high-risk jurisdictions require a guarantee that `parvault-seed` creates **zero persistent directories or files** on storage media, leaves zero forensic artifacts on reboot, and never exceeds a strict RAM ceiling.

## Decision

1. **Pure In-Memory Stores (`--no-fs --in-memory-mb <MiB>`):** Instantiates `BlockStore::new_in_memory`, `PrivacyPreservingEvictionEngine::new_in_memory`, and `PublicTrackerTakedownQueue::new_in_memory` without touching the filesystem (`0` directories or files created), loading optional static identity seeds exclusively from `--identity-env` or read-only `--identity-file`.
2. **Hard Byte-Cap & `0x00` Volatile Scrubbing:** Enforces `--in-memory-mb` across stored shards by evicting expired and oldest leases first, explicitly overwriting every evicted or dropped buffer with `0x00` bytes via `zeroize::Zeroize` before deallocation.

## Consequences & Verification

- **Consequences:** Enables zero-disk, forensically clean seed/relay operation within a deterministic RAM budget (`6.45 MiB` measured `VmHWM` on `32 MiB` cap self-test).
- **Verification:** `tests/gateway_ipc_benchmark.rs` (`--no-fs` zero-file & `0x00` wipe assertions) and `parvault-seed self-test`.
