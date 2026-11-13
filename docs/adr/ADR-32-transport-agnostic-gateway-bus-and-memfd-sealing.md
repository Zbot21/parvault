# ADR-32: Transport-Agnostic `GatewayBus`, Mandatory `memfd` Sealing (`F_ADD_SEALS`) & `SO_PEERCRED` Plugin Isolation

- **Status:** Accepted (`v0.5.0`)
- **Formal model:** `specs/ParVaultGatewayPluginBus.tla`
- **Subsystem:** `gateway` / `capabilities` / `os_sys` / `main` / `bin/parvault-fuse`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)
- **Wire Specification:** [`docs/GATEWAY_SOCKET_PROTOCOL.md`](../GATEWAY_SOCKET_PROTOCOL.md)

---

## Context

`v0.4.0` introduced `/var/run/parvault.sock` (`SCM_RIGHTS` `memfd` zero-copy IPC) and `CapabilityMacaroon` attenuation via a separate `parvault-gateway` binary (`ADR-27`, `ADR-28`). Production CPE and single-host appliance deployments surfaced four architectural gaps:

1. **Duplicate Daemon Footprint:** Shipping a separate `parvault-gateway` binary duplicated ~`2.2 MiB` of Rust + `libp2p` runtime when `parvault up --ipc-socket` already hosted `GatewayIpcServer` inside the primary P2P daemon, while embedded library callers wanted a zero-socket in-process path (`--no-socket`) using the exact same async API.
2. **Shared-Memory TOCTOU Window:** Passing an unsealed writable `memfd` over `SCM_RIGHTS` allowed a buggy or compromised local plugin to mutate backing pages concurrently while `GatewayEngine` streamed and encrypted stripes.
3. **Socket Peer Identity Binding:** `CapabilityMacaroon` caveats constrained manifests, byte ranges, expiry, and read-only access, but could not cryptographically bind a delegated token to the kernel-verified POSIX UID of the connecting plugin process, nor enforce a pre-read UID allowlist on `accept()`.
4. **Operator Token Ergonomics:** Minting, offline-attenuating, and inspecting `CapabilityMacaroon` tokens required writing Rust code rather than a deterministic compact string format (`PARVAULT-MAC-V1:`) and CLI (`parvault token`).

## Decision

1. **Linux-Kernel `=y` vs. `=m` Dual-Mode `GatewayBus` & Single-Daemon Consolidation:**
   - Fold `parvault-gateway` into `parvault` (`parvault up --ipc-socket` as the canonical single-daemon plugin host, plus `parvault gateway {serve, health, ipc-roundtrip, self-test}` for standalone outbound socket benchmarking) and remove the redundant `src/bin/parvault-gateway.rs` binary target.
   - Introduce `GatewayBus { InProcess(Arc<GatewayEngine>), UnixSocket(GatewayIpcClient) }` exposing one unified async surface (`store_payload_fd`, `store_sealed_payload_fd`, `fetch_payload_to_fd`, `fetch_range_to_fd`, `register_manifest`, `query_health`):
     - **Built-In Mode (`=y`, `GatewayBus::InProcess`, default `features = ["vfs"]` & `--no-socket`):** Embeds first-party components inside one binary (~`120 KiB` incremental code vs. ~`2.2 MiB` per extra binary), simplifies single-binary OTA signing, and supports `parvault up --no-socket` with zero filesystem socket exposed.
     - **Split Plugin Mode (`=m`, `GatewayBus::UnixSocket`, `parvault-fuse` reference plugin & `--no-default-features` core):** Lets plugin authors iterate/restart plugins in seconds without dropping `parvault`'s live `libp2p` WAN sessions, lets operators strip `vfs` via `--no-default-features`, and isolates LAN/FUSE frontends (`src/bin/parvault-fuse.rs`) under unprivileged UIDs.
2. **Mandatory Linux `memfd` Sealing (`F_ADD_SEALS`):** Add audited `seal_memfd_immutable` (`F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`) and `has_immutable_memfd_seals` wrappers in `src/os_sys.rs`. When `--require-sealed-memfd` (`with_require_sealed_ingest_memfd(true)`) is enabled, `StorePayload` rejects unsealed descriptors before hashing or encrypting a single byte.
3. **Kernel `SO_PEERCRED` Allowlisting & `Caveat::AllowedPeerUid(u32)`:** Add `peer_socket_ucred` (`getsockopt(SOL_SOCKET, SO_PEERCRED)`) in `src/os_sys.rs`. When `--strict-plugins --allow-peer-uid <UID>` is active, `GatewayIpcServer` inspects `SO_PEERCRED` immediately on `accept()` (both sync and async Tokio loops), closes unauthorized connections before reading any bytes, and threads `Some(ucred.uid)` (`Some(geteuid())` for `GatewayBus::InProcess`) into `AccessRequestContext.peer_uid` for `Caveat::AllowedPeerUid(u32)` (`0x05` + 4 BE bytes, zero heap allocation).
4. **Compact `PARVAULT-MAC-V1:` Token Format & `parvault token` CLI:** Add `CapabilityMacaroon::{to_compact_token, from_compact_token}` and `parvault token {mint, attenuate, inspect}` (`mint` atomically initializes `0600` `<data_dir>/macaroon_root.key`; `attenuate` runs 100% offline with zero root key), plus fast-fail startup guardrails for `--strict-plugins`, `--no-socket`, and ignored `watched_folder` on `parvault gateway serve` (documented in [`docs/GATEWAY_SOCKET_PROTOCOL.md`](../GATEWAY_SOCKET_PROTOCOL.md)).

## Consequences & Verification

- **Consequences:** Eliminates an entire ~`2.2 MiB` duplicate binary from release artifacts while preserving wire compatibility for `/var/run/parvault.sock` clients (`parvault-suite`), closes the shared-memory `memfd` TOCTOU window in kernel space, binds capabilities to kernel-verified POSIX UIDs, and keeps 100% of `unsafe` syscalls isolated inside `src/os_sys.rs` (`13` wrappers total, `0` `unsafe` in `gateway/` or `capabilities.rs`).
- **Verification:** Kani symbolic harness #16 (`proof_macaroon_peer_uid_and_compact_roundtrip`), kernel unit tests in `src/os_sys.rs` (`test_memfd_immutable_seals_and_peer_socket_ucred`), and end-to-end integration suite `tests/gateway_bus_and_plugin_security.rs`.
