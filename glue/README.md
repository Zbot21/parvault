# Track A integration glue (`v0.5.6`)

Apply on `v0.5.6/integ` with track A merged (numbers per `architecture/plans/v0.5.6-integration-glue.md`):

| Glue | File | What |
| :-- | :-- | :-- |
| G-11 | `G-11-daemon.patch` (base `dccaa6e`) | `cli/daemon.rs` calls `edge_tls::prepare_edges` and serves both edges through `*_served`. Then delete `edge_tls::ensure_cert` and `EdgeTlsRefusal::NotBuiltYet` (the last track-A Unbuilt site). |
| G-12 | `G-12-server.patch` (base `dccaa6e`) | B-180 `GatewayIpcServer::with_socket_group` (track C's file), using `capabilities::resolve_group_id`. |
| G-14 | `G-14-main.patch` (base t0b `d9d2bca`) | Removes t0b's early refusals of `--tls-san`, `--insecure-plain-http`, `--gateway-socket-group` in `main.rs`; keeps the `needs --ipc-socket` usage error. Also delete the t0b test `trust_enforcement_edge::unbuilt_start_flags_refuse_before_any_file` (and its `files_under` helper): the flags are built. |
| G-18 | `G-18-gate-stage14.patch` | Calls `scripts/docker_stage_webdav_tls.sh` as stage 14 of `docker_acceptance_gate.sh` (needs G-11). |
| G-19 | `tests/*.rs`, `enforcement.map.add` | Copy `glue/tests/*.rs` into `tests/` (they `mod edge_common;`) and append `enforcement.map.add` to `.enforcement.map`. They need G-11, G-12 and G-14. |

Each was built and tested in a scratch copy of `v0.5.6/a` with the patches applied (job ids in track A's report).
