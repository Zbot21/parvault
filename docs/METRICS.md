# Traversal metrics: `GET /metrics`

`v0.5.4`. The `parvault` daemon counts every outbound connection attempt and every inbound connection in fixed counters, and serves them in Prometheus text format `0.0.4` on its status listener. The lab and the dogfood mesh scrape them.

## 1. Where and how

- **Route.** `GET /metrics` on the status listener (`--status-http <IP:PORT>` / `status_http_bind`). There is no other port: no `--status-http`, no metrics. The router keeps its loopback default (B-54).
- **Auth.** The status page's token: `Authorization: Bearer <PARVAULT-MAC-V1 token>`, or Basic with the token as the password. It must be unscoped and `ReadOnly`, with no `AllowedPeerUid`, and the `Host` must be an IP literal. Refusals are the status page's fixed responses (the byte-identical `401`, a `403` for a scoped token or a bad `Host`); a non-GET gets `405` only after auth.
- **Edge decision only.** `/metrics` is decided by the status edge (`http_edge::status_auth_decision`) alone. Unlike the other status paths it does not fetch the snapshot over the gateway bus, so it does not get the gateway engine's second check. The counters live in the daemon process: there is no snapshot to fetch and no engine to ask, and they carry less than `/api/v1/peers` (which has PeerIds and addresses).
- **The same token reads `/api/v1/peers`.** Both are read-only, and a metrics-only caveat would change the macaroon format (D-44 Q1).
- The `parvault-status` sidecar answers `/metrics` with `404` after auth: it has no counters.

Mint a scraper token against the daemon's `<data_dir>/macaroon_root.key`. Give it a TTL, 30 days by default (D-44 Q4): a token cannot be revoked short of rotating the root key, which also kills every status token. The TTL is advice, not enforced (B-137).

```text
parvault --data-dir /var/lib/parvault token mint --read-only --ttl-secs 2592000 > scraper.token
curl -sH "Authorization: Bearer $(cat scraper.token)" http://127.0.0.1:4080/metrics
```

Prometheus:

```yaml
scrape_configs:
  - job_name: parvault
    authorization:
      credentials_file: /etc/prometheus/parvault-scraper.token
    static_configs:
      - targets: ["10.9.0.1:4080"]
```

On a router, scrape through SSH (`ssh router curl -sH "Authorization: Bearer $(cat token)" http://127.0.0.1:4080/metrics`) or bind the status page to a LAN address; keep loopback the default.

## 2. Series

Every label value comes from a closed enum and every series exists at zero from the start, so each scrape has the same `219` lines (`203` series, `8` families). No label carries a PeerId, IP, port, node label or any other remote- or user-supplied string. The schema is `docs/schemas/traversal-metrics-1.txt`.

| Series | Type | Labels |
| :-- | :-- | :-- |
| `parvault_traversal_attempts_total` | counter | `origin` (`daemon`, `client`) |
| `parvault_traversal_outcomes_total` | counter | `origin`, `path` (`direct`, `relayed`), `transport` (`tcp`, `quic`, `none`), `reason` |
| `parvault_traversal_inbound_total` | counter | `path`, `transport` (`tcp`, `quic`) |
| `parvault_traversal_connect_seconds` | histogram | `path`, `transport` (`tcp`, `quic`); buckets `0.005 0.01 0.025 0.05 0.1 0.25 0.5 1 2.5 5 10 30 +Inf` |
| `parvault_traversal_connections` | gauge | `direction` (`outbound`, `inbound`), `path`, `transport` (`tcp`, `quic`) |
| `parvault_traversal_timing_overflow_total` | counter | none |
| `parvault_status_refused_total` | counter | `code`: the status refusal codes without the `reject.` prefix (`status_unavailable`, `status_token_missing`, `status_token_invalid`, `status_not_readonly`, `status_token_scoped`, `status_peer_uid`, `status_host_mismatch`) |
| `parvault_build_info` | gauge (`1`) | `version`, `profile` (`desktop`, `homelab-nas`, `router-soc`), `deterministic` (`0`, `1`) |

`reason`: `ok`, `timeout`, `refused`, `unreachable`, `noise_failed`, `peer_id_mismatch`, `transport_unsupported`, `denied` (the lab dial gate), `aborted`, `other`. `net probe` (`docs/LAB_MODE.md`) reports the same values.

`path` is `relayed` iff the address has `/p2p-circuit`; it is always `direct` until the relay (`v0.5.9`), and the relayed series exist at zero so no name changes then. `transport` is `quic` iff the address has `/quic-v1`, `none` when the outcome names no address.

Reserved, not emitted until their release: `parvault_relay_reservations` (`v0.5.8`), `parvault_autonat_status` (`v0.5.9`).

## 3. Attempts and outcomes

- `origin=daemon` is the daemon's server swarm; `origin=client` is every `MeshClient` worker in the daemon process.
- **Attempt:** one dial that passed its peer condition: one call of the swarm into the `TraversalGate` behaviour (`handle_pending_outbound_connection`), whether the application or a behaviour (Kademlia, request-response) started it. Attempts carry only `origin`: one dial can carry several addresses of both transports.
- **Outcome:** exactly one per attempt, labelled when it happens from the address it names. An established outbound connection is `ok` (its address gives `path` and `transport`; the histogram gets the time since the attempt). A failed dial over several addresses is classified per address and one is picked by a fixed precedence, `noise_failed > refused > unreachable > timeout > transport_unsupported > denied > other`: an error that shows the remote was reached wins over one that shows it was not, and a lab refusal ranks below any real network result. On a tie `tcp` wins over `quic`, then the first address. Errors of other addresses of a dial that succeeded are not counted.
- **Consistency:** a scrape always has `attempts_total{origin} >= Σ outcomes_total{origin,…}` (outcomes are written with release ordering after their attempt, and read first). The difference is dials in flight plus dials dropped at shutdown.
- **Timing bound:** the connect-time histogram needs each attempt's start; the gate keeps at most `1024` timed dials. A dial over that is counted in `parvault_traversal_timing_overflow_total` and gets an outcome but no time.
- `inbound_total` and the `connections` gauge come from established and closed connections; they have no cross-series invariant.

## 4. Limits

- **Slot starvation (known, no change in `v0.5.4`).** The status listener serves 32 connections, 8 per source IP, with 5 s head and write timeouts. Four source addresses can hold every slot for 5 s at a time without a token; that already applies to the status page and now also causes scrape gaps.
- The counters cost `O(1)` atomics on the swarm path and a constant body size, so a flood of failed dials only increments fixed counters.
- `parvault_status_refused_total` can be driven by an unauthenticated client; it reveals only that someone is probing.

## 5. The unauthenticated debug listener

Cargo feature `lab-insecure-metrics`, off by default, for lab debugging only:

```text
parvault daemon start ... --lab-insecure-metrics <IFACE>=<IP:PORT>
```

- A listener of its own (the status listener keeps no "skip auth" branch in any build), serving only `GET /metrics` from the same renderer, without a token. It checks the `Host` like the status page and has its own 4 connection slots.
- It starts only if the build has the feature and debug assertions on, the IP is not unspecified, and `<IFACE>` owns the IP at bind time (`traversal_metrics::insecure_metrics_listener_decision`, Kani `proof_insecure_metrics_requires_debug_feature_and_iface`). Codes: `reject.metrics_insecure_unavailable`, `reject.metrics_insecure_unspecified`, `reject.metrics_insecure_iface_mismatch`.
- Without the feature the flag does not exist (clap: exit `2`).
- Every response carries `X-Parvault-Insecure-Metrics: PARVAULT-LAB-INSECURE-METRICS-v1`, and the listener logs the marker at start.

**Why release builds can never carry it:**

1. `compile_error!` when the feature is built with debug assertions off: an honest release build fails.
2. `scripts/check_release_build_env.sh` runs before every release-profile build in CI and in the release workflow. It fails on `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_TARGET_*_RUSTFLAGS`, `CARGO_PROFILE_*_DEBUG_ASSERTIONS`, a cargo config with a profile table, `rustflags` or `debug-assertions`, and a shipped `[profile.*]` with `debug-assertions = true`: the ways debug assertions can be turned on in a `soc` build without touching `Cargo.toml`.
3. `scripts/check_no_insecure_metrics.sh` runs on the release binaries and on the exact published files, before their checksums are written. It scans every file for the marker, and where a file runs on the host it checks `parvault --version --verbose`, which prints `debug_assertions: on|off` and `features: <list or none>`. It exits `1` on any finding and `2` if a file is missing or got no check.
4. Two negative controls run in CI: a dev build with the feature must be flagged, and the exact bypass in the shipped shape (`--profile soc`, static musl, stripped, `CARGO_PROFILE_SOC_DEBUG_ASSERTIONS=true`) must be flagged by the marker alone, and must also fail the build-environment check.
