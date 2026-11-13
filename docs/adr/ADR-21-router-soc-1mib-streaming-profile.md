# ADR-21: Tiny-SoC `1 MiB` Streaming Stripe Memory Profile & Embedded Router Status Server

- **Status:** Accepted
- **Subsystem:** `config` / `storage::block_store` / `router_nas`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

With `16 MiB` Desktop stripes, transient working-set memory during `16-of-20` Reed-Solomon encoding peaks at <!-- metric:bench.desktop.vmhwm -->`57.91 MiB`<!-- /metric --> (`VmHWM`). Consumer OpenWrt and prplOS gateways on MediaTek Filogic or Rockchip ARM64 SoCs enforce strict `32–48 MiB` LXC cgroup ceilings where a `58 MiB` spike triggers an OOM kill.

## Decision

1. **Profile-Tuned Streaming Stripes (`HardwareProfile`):** Configures `BlockStore` stripe sizing, connection fanout, and disk reserves by device class while preserving 100% manifest interoperability (`FileManifest` records exact per-stripe byte bounds so a `1 MiB` router upload restores seamlessly on a `16 MiB` desktop and vice versa):
   - `RouterSoc` (`--profile router-soc`): `ROUTER_SOC_STRIPE_SIZE_BYTES = 1 MiB` (`1,048,576 B`), `64 MiB` disk reserve, `max_connections = 24`.
   - `HomelabNas` (`--profile homelab-nas`): `HOMELAB_NAS_STRIPE_SIZE_BYTES = 4 MiB` (`4,194,304 B`), `1 GiB` disk reserve.
   - `Desktop` (`--profile desktop`): `DEFAULT_STRIPE_SIZE_BYTES = 16 MiB` (`16,777,216 B`), `5 GiB` disk reserve.
2. **Turnkey Appliance & Embedded Status HTTP (`parvault up`, `RouterNasStatusServer`):** Serves live `/proc/self/status` `VmRSS`/`VmHWM` telemetry and a `< 6 KiB` zero-dependency HTML5 status page (`GET /`, `/api/v1/health`, `/api/v1/peers`).
   - **Amended in v0.5.0 (item 3, F-46, plan-3 ruling change 11).** Every request presents a read-only, unscoped macaroon (`Authorization: Bearer`, or as the Basic password for a browser prompt; never in the URL), checked by `http_edge::status_auth_decision` before the snapshot is read, under the gateway root key (built-in) or a pinned `--macaroon` (the `parvault-status` sidecar). The same decision guards `IpcCommand::QueryStatus`. The `Host` must be an IP literal or `localhost` (DNS rebinding). The server is a blocking `std::net::TcpListener` on the shared HTTP edge (32 connections, 8 per source IP, 8 KiB heads, one 5 s deadline, fixed 401/403/431/503 bytes) and reads the snapshot over `GatewayBus`; it moved off tokio into the `status-ui` feature. The snapshot no longer carries the pairing SAS code or the watched-folder path. `--status-http` has no default: no flag, no listener.

## Consequences & Verification

- **Consequences:** Cuts streaming peak `VmHWM` 6× from <!-- metric:bench.desktop.vmhwm -->`57.91 MiB`<!-- /metric --> to **<!-- metric:bench.soc.vmhwm -->`9.72–9.74 MiB`<!-- /metric -->** (<!-- metric:bench.soc.store -->`75.9–82.1 MiB/s`<!-- /metric --> store, <!-- metric:bench.soc.restore -->`127.1–127.4 MiB/s`<!-- /metric --> restore), running comfortably inside a `32–48 MiB` router cgroup.
- **Chunk roots (manifest version 2, [ADR-03](ADR-03-stateless-witness-por-auditing.md)):** ingest hashes every shard once more to build its chunk root, about `n/k` (1.25× at 16-of-20) SHA-256 passes over each stripe's ciphertext. Not yet re-measured in the benchmarks above.
- **Verification:** Kani harnesses `proof_router_soc_and_desktop_reed_solomon_memory_ceiling`, `proof_streaming_stripe_layout_all_u64_file_sizes_and_profiles` and (status, v0.5.0) `proof_status_auth_requires_readonly_unscoped_token_and_host`; claims STATUS-AUTH, STATUS-HOST and STATUS-IPC (`tests/trust_enforcement.rs`); `tests/zero_config_lan_and_router_soc_tests.rs`; Stage 12 (`48m` cgroup) of `scripts/docker_acceptance_gate.sh`.
