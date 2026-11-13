# ADR-33: Dual-Mode (`=y` / `=m`) `VirtualVaultFs` Hosting & Zero-Key Sibling `GatewayFolderSync` (`parvault-sync`)

- **Status:** Accepted (`v0.5.0`)
- **Subsystem:** `gateway::ipc` / `vfs` / `sync` / `main` / `bin/parvault-sync`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)
- **Wire Specification:** [`docs/GATEWAY_SOCKET_PROTOCOL.md`](../GATEWAY_SOCKET_PROTOCOL.md)

---

## Context

`ADR-32` unified asynchronous gateway callers behind `GatewayBus { InProcess(Arc<GatewayEngine>), UnixSocket(GatewayIpcClient) }`, added mandatory `F_ADD_SEALS` `memfd` immutability checks, and enforced `SO_PEERCRED` POSIX UID isolation. Three remaining architectural gaps prevented full Linux-kernel style `=y` (built-in single-daemon) vs. `=m` (unprivileged split-plugin) parity across synchronous filesystems and folder synchronizers:

1. **Async-Only `GatewayBus` Surface:** Synchronous loops (`VirtualVaultFs` FUSE ABI `7.31` / HTTP-Range WebDAV threads and blocking CLI synchronizers) remained hardwired to `GatewayIpcClient`, forcing a Unix Domain Socket hop even when hosted inside `parvault up` and preventing `--no-socket` built-in VFS operation.
2. **Master-Key Coupling in Folder Sync:** `FolderSyncEngine` (`ADR-14`) embeds `MasterKey` and `NodeIdentity` inside the synchronization process for standalone single-host / disaster-recovery vaults, which prevented running continuous folder push/pull synchronization inside an unprivileged container or sandboxed UID isolated from vault encryption keys.
3. **Catalog Path-Traversal Surface:** A zero-key external catalog (`GatewayFolderCatalog`) persisted on untrusted disk requires a pure-safe, formally verified relative-path sanitizer rejecting traversal (`..`), empty/root paths, NUL bytes, and Windows drive/ADS colons before any restore writes or tombstone unlinks touch the filesystem.

## Decision

1. **Synchronous Blocking Surface on `GatewayBus` (`src/gateway/ipc.rs`):**
   - Extend `GatewayBus` with blocking `std::io::Result` methods (`store_memfd_sync`, `store_sealed_memfd_sync`, `fetch_into_memfd_sync`, `fetch_range_into_memfd_sync`, `fetch_range_bytes_sync`, `register_manifest_sync`, `query_health_sync`).
   - Enforce `strict_allowed_peer_uids` (`Some(geteuid())` in-process vs. kernel `SO_PEERCRED` over Unix sockets), `require_sealed_ingest_memfd` (`has_immutable_memfd_seals`), and `< 1 ms` in-RAM `CapabilityMacaroon` verification identically across `GatewayBus::InProcess` and `GatewayBus::UnixSocket`.
2. **Dual-Mode (`=y` Built-In vs. `=m` Split Plugin) `VirtualVaultFs` (`src/vfs.rs`, `src/config.rs`, `src/cli/daemon.rs`):**
   - Migrate `VirtualVaultFs` from `GatewayIpcClient` to `GatewayBus` (`VirtualVaultFs::with_bus`, `with_bus_and_block_size`, `bus()`), preserving `VirtualVaultFs::new` / `with_block_size` for `parvault-fuse` (`=m`), honoring `ParvaultIgnore::from_folder` during directory seeding, and adding RAII `VfsWebdavServerHandle` (`spawn_webdav_server`, `local_addr`, `shutdown`, `Drop`).
   - Add `--vfs-webdav-listen`, `--vfs-fuse-fd`, `--vfs-seed-dir`, and `--vfs-cache-mib` to `parvault up` and `parvault daemon start`, sharing a single `Arc<GatewayEngine>` between `GatewayIpcServer::bind` (when `--ipc-socket` is active) and `VirtualVaultFs::with_bus(GatewayBus::in_process(..))` so built-in `=y` WebDAV and FUSE work even under `--no-socket` (zero `.sock` file on disk). Fail fast with an actionable error when compiled with `--no-default-features` (`not(feature = "vfs")`).
3. **Zero-Key Sibling `GatewayFolderSync` (`src/sync.rs`) & `parvault-sync` Plugin (`src/bin/parvault-sync.rs`):**
   - Preserve `FolderSyncEngine` (`parvault up --watch` / `watch-folder`) intact while introducing `GatewayFolderSync`, `GatewayFolderCatalog` (bounded `64 MiB` `bincode` + atomic `sync_all` + `rename`), and `GatewaySyncedFileEntry` holding **zero `MasterKey` and zero `NodeIdentity` fields** and requiring **no `vfs` Cargo feature**.
   - Stream added/modified files in `64 KiB` chunks into sealed `memfd`s (`store_sealed_memfd_sync`) with metadata + SHA-256 zero-reupload fast paths, and stream `1 MiB` ranges on `restore_to_folder` (`fetch_range_into_memfd_sync` with attenuated `CapabilityMacaroon`) verifying end-to-end `SHA-256` before atomic rename.
   - Add pure-safe `sanitize_sync_relative_path` (`src/sync.rs`) and ship `#![forbid(unsafe_code)]` binary `parvault-sync` (`diff`, `push`, `watch`, `pull`, `list`, `self-test`).

## Consequences & Verification

- **F-43 (L-43, L-44):** both hosts require a read-only macaroon on every WebDAV request: the built-in host verifies it under the node's `macaroon_root.key` (created when `--vfs-webdav-listen` is set), and `parvault-fuse webdav` accepts only its pinned `--macaroon` or an offline attenuation of it. The edge check is the only client gate: the built-in VFS reads with an in-memory ReadOnly macaroon minted by the daemon, and the plugin reads with its pinned token.

- **Consequences:** Operators can choose built-in `=y` zero-socket single-daemon VFS (`parvault up --no-socket --vfs-webdav-listen ...`) or unprivileged `=m` split plugins (`parvault-fuse`, `parvault-sync`) over `/var/run/parvault.sock` with zero `MasterKey` exposure in plugin memory and zero new `unsafe` blocks (`13` audited wrappers in `src/os_sys.rs`, `#![forbid(unsafe_code)]` across all `5` binaries).
- **Verification:** Kani symbolic harness #17 (`proof_sanitize_sync_relative_path_no_traversal` in `src/kani_proofs.rs`), `parvault-sync self-test`, and integration suite `tests/m3_dual_mode_vfs_and_gateway_sync.rs`.
