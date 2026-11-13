# ADR-27: Zero-Copy Unix Socket & `SCM_RIGHTS` `memfd` Data-Plane Gateway (`parvault-gateway`)

- **Status:** Accepted (`v0.4.0`)
- **Formal model:** `specs/ParVaultGatewayPluginBus.tla`
- **Subsystem:** `gateway::engine` / `gateway::ipc` / `gateway::shm` / `bin/parvault-gateway`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Downstream companion daemons (`parvault-fuse`, `parvault-media-daemon`, `parvault-auth-broker`, `parvault-isp-agent`) need high-throughput access to encrypted erasure-coded storage without linking `libp2p` into every binary or copying multi-megabyte payloads over localhost TCP/JSON. Furthermore, under `10-of-20` or `20-of-40` erasure tiers on `15 ms` RTT / `2%` loss WAN links, a 20-thread worker pool queues shards `20..39` behind `0..19`, doubling tail Time-To-First-Byte (TTFB) past interactive `60 ms` media/VFS budgets.

## Decision

1. **Zero-Copy `memfd_create` + `SCM_RIGHTS` UDS Data Plane (`/var/run/parvault.sock`):** `GatewayIpcServer` and `GatewayIpcClient` exchange compact `bincode` control frames (`MAX_IPC_FRAME_BYTES = 16 MiB`, `64 KiB` initial reservation) over a `0600` Unix Domain Socket while passing anonymous kernel shared-memory descriptors (`memfd_create`) via `SOL_SOCKET` / `SCM_RIGHTS` ancillary messages. Stripe encryption and $GF(2^8)$ reconstruction stream via safe positional `pread_full_or_eof` / `pwrite_all` (`GATEWAY_STRIPE_BYTES = 1 MiB`) without `mmap`-pinning whole files into RSS.
2. **Single-Wave `40`-Lane Hedged Worker Pool (`MESH_POOL_CONCURRENCY = 40`):** `GatewayEngine` provisions `40` worker threads with compact `128 KiB` stacks (`.stack_size(128 * 1024)`) so all `N ≤ 40` shard RPCs fire in **one parallel wave at `t = 0`**, keeping degraded-WAN TTFB `< 60 ms` even on 2-vCPU runners while holding peak gateway `VmHWM` at **<!-- metric:gw.ipc.gateway_vmhwm -->`10.98 MiB`<!-- /metric -->** (`< 16 MiB` ceiling).
3. **Overflow-Free Pinned Shared-Memory Ring Admission (`PinnedRingBudget<SLOTS>`):** Enforces hard byte and slot caps across in-flight `memfd` descriptors using subtraction-based `max_bytes - size_bytes` admission checks immune to `u64::MAX` saturation.

## Consequences & Verification

- **Consequences:** Sustains `730.88–957.01 MiB/s` `Store` and `1,724.51–2,213.86 MiB/s` `FetchRange` over `/var/run/parvault.sock` (`0.49 ms` local TTFB, <!-- metric:gw.ipc.gateway_vmhwm -->`10.98 MiB`<!-- /metric --> peak `VmHWM`, `3.07 MiB` ARM64 / `3.80 MiB` x86_64 stripped `musl` binary).
- **Verification:** Kani harnesses `proof_pinned_ring_capacity_invariant` and `proof_gateway_ipc_frame_header_bounds`; `tests/gateway_ipc_benchmark.rs`; `parvault-gateway self-test`.
