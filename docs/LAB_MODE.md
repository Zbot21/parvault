# Lab mode: deterministic configuration, `config dump` and `net probe`

`v0.5.4`. Two lab boxes given the same inputs run the same network behaviour, and each can prove it with a byte-stable dump of its configuration. This page covers the `[lab]` table, the deterministic rules and their reason codes, the dial gate, the dump schema, and `parvault net probe`.

## 1. The `[lab]` table

```toml
[lab]
deterministic = true          # default false
relays = []                   # required when deterministic (it may be empty)
```

- `--lab-deterministic` (a global flag) sets `deterministic = true`. No environment variable does (D-44 Q5): the switch is always visible in the unit file or the config.
- `relays` lists IP-literal `/p2p/` multiaddrs. In `v0.5.4` it is parsed, checked, dumped and part of the dial set; the relay client (`v0.5.9`) will read it and nothing else in lab mode.

## 2. Deterministic rules

Every refusal is a startup error: the command prints `<code>: <detail>` on stderr and exits `3`, before any key, identity or data-dir file is created. The dial gate is the exception: it refuses a dial at run time and logs its code.

| Rule | Effect | Code |
| :-- | :-- | :-- |
| Fixed ports | Every listener the `parvault` daemon binds has a nonzero port and an IP literal that is not unspecified (`0.0.0.0`, `::`, or the v4-mapped `::ffff:0.0.0.0`): `listen_tcp`, `listen_quic` (if enabled), `status_http_bind`, `--vfs-webdav-listen`, and `--lab-insecure-metrics` (debug builds) | `reject.lab_ephemeral_port`, `reject.lab_unspecified_bind`, `reject.lab_bind_not_ip_literal` |
| Fixed dial set | The dial set is `bootstrap_peers` ∪ `lite_seed_addr` ∪ `lab.relays`. Each entry is an IP-literal TCP (`/ip4\|ip6/<ip>/tcp/<port>`) or QUIC (`/udp/<port>/quic-v1`) multiaddr ending in `/p2p/<id>` | `reject.lab_addr_without_peer_id`, `reject.lab_dial_shape` |
| IP literals only | A `/dns*` address or a `host:port` name in the dial set is refused, so no name is ever resolved | `reject.lab_dns_addr` |
| Relay list | `[lab] relays` must be set | `reject.lab_relays_missing` |
| No state-file peers | `known_peers.json` is never loaded, so no configured peer is rewritten to a healed address and no pinned peer is dialled. LAN discovery is off, so an empty dial set scans nothing. Zero-config resolution is skipped | — |
| No learned addresses | Kademlia is seeded with the dial set once and never fed a learned address; the identify cache is `0` | — |
| Onion forwards refused | A `RelayPqOnionEnvelope` naming a next hop is answered `delivered: false` before any forward is queued | `reject.lab_relay_forward` (logged) |
| mDNS, LAN beacon, WAN DDNS, trackers | Off | — |
| Discovery commands | `discover`, `pair` and `join` exit `3` | `reject.lab_side_channel` |
| Conflicts | An explicit setting (file, environment or flag) that turns a side channel on: `lan_discovery_enabled = true`, a public or hybrid `trust_mode` (also `--public`, `PARVAULT_PUBLIC`, `--tracker`), `public_trackers`, `wan_rendezvous_seeds` (also `PARVAULT_WAN_SEEDS`), `up --wan`, and `PARVAULT_LAN_REGISTRY_DIR` set to any value. The detail names each key and its source | `reject.lab_config_conflict` |

A default that would turn a channel on is overridden silently; the dump shows its source as `lab`. Only explicit settings conflict.

Out of scope in `v0.5.4`:
- the seed's admin RPC listener (`admin_rpc`), bound only by `parvault-seed`, and `parvault-seed` itself (its dump comes with the relay, `v0.5.8`, D-44 Q6);
- the IPC gateway, a Unix socket path (no port): the dump shows it under `effective.listeners.ipc_socket`;
- inbound connections, which lab mode never restricts; admission is unchanged.

**Tracker-admin pins (A3).** Skipping `known_peers.json` also drops the tracker-admin pin store: pins learned in a lab run stay in memory only. That is harmless while lab mode refuses `--public` and trackers. A change that allows trackers in lab mode must load the pin store on its own, or it silently loses pins.

## 3. The dial gate

One pure decision, `lab_dial::lab_dial_decision(addr, peer, set)`, in the library's default build (Kani `proof_lab_dial_only_within_fixed_set`). Outside lab mode the set is `Open` and every dial passes. Under a fixed set, an address passes iff some entry has the same `(ip, port, transport)` and every PeerId given (the dial's and the address's `/p2p/`) is that entry's.

Both swarms the `parvault` binary builds (the daemon's server swarm and every `MeshClient` worker) enforce it in two places:

1. `LabDialTransport`, wrapping the whole TCP and QUIC transport: every address the swarm dials, including addresses a behaviour adds, is checked in `Transport::dial`, so no socket is opened for an address outside the set.
2. `TraversalGate`, the first field of `MeshNetworkBehaviour`: it refuses a pending dial to a peer or address outside the set, and checks the Noise-authenticated PeerId of each established outbound connection against the entry it was dialled at.

Codes: `reject.lab_dial_outside_set`, `reject.lab_dial_peer_mismatch`, `reject.lab_dial_shape`. Each refusal logs one `warn!` with the code and no address. In a lab process every `MeshClient` starts with the fixed set (it is installed process-wide before the first client), including the clients the gateway engine, the block store and the auditor build.

## 4. `config dump`

```text
parvault [global flags] config dump
parvault [global flags] daemon start <flags> --dump-config
parvault [global flags] up <flags> --dump-config
```

Each prints the effective configuration of that command and exits `0`. It reads the config file and nothing else: it creates, opens or writes no other file (key presence comes from file metadata), binds nothing and contacts no one. Exit `3`: the configuration does not resolve; stdout is then one line, `{"error":"<code>","schema":"parvault.config-dump/1"}`. Exit `2`: a usage error.

The running daemon logs `config_digest=<hex>` at start, and `/api/v1/health` serves `config_digest`: the lowercase hex SHA-256 of the dump of the same command, taken before any file is created. A lab compares the digest of each running daemon with the dump it recorded.

Schema `parvault.config-dump/1` (`docs/schemas/config-dump-1.json`):

```json
{
  "args": {"listen": {"source": "flag:--listen", "value": "/ip4/10.9.0.1/tcp/4001"}},
  "binary": "parvault",
  "config_file": "/etc/parvault/config.toml",
  "effective": {
    "deterministic": true,
    "dial_set": ["/ip4/10.9.0.2/tcp/4001/p2p/12D3KooW..."],
    "listeners": {"ipc_socket": null, "quic": null, "status_http": "10.9.0.1:4080", "tcp": "/ip4/10.9.0.1/tcp/4001", "webdav": null},
    "metrics": {"auth": "readonly-macaroon", "insecure_listener": null, "path": "/metrics"},
    "relays": [],
    "side_channels": {"known_peers_file": false, "lan_beacon": false, "lan_registry": false, "mdns": false, "relay_forward": false, "trackers": false, "wan_rendezvous": false, "zero_config_resolution": false}
  },
  "env": {"PARVAULT_PEERS": {"set": false}},
  "schema": "parvault.config-dump/1",
  "secrets": {
    "PARVAULT_PASSPHRASE": {"set": true, "source": "env:PARVAULT_PASSPHRASE"},
    "macaroon_root.key": {"set": true, "source": "file:/var/lib/parvault/macaroon_root.key"}
  },
  "unknown_file_keys": 0,
  "values": {
    "lan_discovery_enabled": {"source": "lab", "value": false},
    "public_trackers": {"source": "file", "userinfo_removed": true, "value": ["https://tracker.example/announce"]}
  },
  "version": "0.5.4"
}
```

- `source` is `default`, `profile`, `file`, `env:<NAME>`, `flag:--<name>` or `lab`. A clap default (for example `daemon start --listen`) shows as `default`. A flag overrides the file only when given; a clap default applies only when the file does not set the key.
- Canonical output: keys sorted, arrays in config order without duplicates, two-space indent, a trailing newline, no timestamp, PID or binary path.
- `values` holds every config key, `args` every argument of the global flags and of the dumped command, `env` whether each environment variable the crate reads is set (values show up as the source of the keys they set), and `secrets` every secret as `{"set", "source"}` only: no value, length, hash or prefix. Key files show their path in `source` and their presence from metadata; they are never opened.
- URL-valued entries lose their `user:password@` part (`"userinfo_removed": true`); a value that cannot be checked prints `{"set": true, "unparsed": true, "source"}`.
- `unknown_file_keys` counts file keys that are no config key, never naming them: a mistyped secret key (`device_sealing_pasphrase`) shows only as a count.

The renderer iterates one classification table (`config_dump::DUMP_SCHEMA`) and nothing else. `tests/config_dump.rs` fails on an unclassified config key or argument, and on an environment read under `src/` that is not a table row.

## 5. `net probe --force-direct`

```text
parvault net probe --peer <MULTIADDR/p2p/ID | PEER_ID> --force-direct [--timeout-ms 10000] [--no-rpc]
```

One connection attempt against a named peer, with a JSON result: the primitive each VF-6 matrix cell runs.

- `--peer`: a multiaddr ending in `/p2p/<id>`, or (outside lab mode) a bare PeerId resolved from `known_peers.json`; zero or more than one pinned address is refused. In lab mode a bare PeerId and a name are refused, so the probe reads no state file and resolves no name.
- `--force-direct` is required in `v0.5.4` (`--force-relay` and an `auto` mode come with the relay, `v0.5.9`; today clap rejects `--force-relay`, exit `2`).
- `--timeout-ms` (`100..=60000`, default `10000`) covers the dial, the upgrade and the RPC. `--no-rpc` skips the RPC.

What it does, and nothing else: it runs before any identity, key or data-dir work, with an ephemeral Ed25519 identity (it pins nothing and writes no file). It builds a client swarm with mDNS off and no listener (under lab mode the dial gate allows only the target), dials exactly one address once (no retry, no other address, no address from a behaviour), and on success sends one ping (its RTT) and, unless `--no-rpc`, one public `QueryNodeStatus` (the first-response time). Then it exits.

Output: one JSON document on stdout (`docs/schemas/net-probe-1.json`, schema `parvault.net-probe/1`); human text goes to stderr only. No remote-supplied string appears in it.

```json
{"schema":"parvault.net-probe/1","version":"0.5.4","mode":"force-direct","peer_id":"12D3KooW...","addr":"/ip4/10.9.0.2/tcp/4001/p2p/12D3KooW...","transport":"tcp","result":"connected","path":"direct","reason":"ok","timings_us":{"established":1830,"ping_rtt":410,"first_response":2950},"local":{"nat_status":"unknown"},"relay":null,"started_unix_ms":1794787200000}
```

- `result`: `connected`, `failed` (the attempt ran and did not connect) or `error` (no attempt was made).
- `reason`: a traversal reason (`docs/METRICS.md`) for `connected` and `failed`; a reason code for `error`.
- A timing is `null` when its step did not run. An RPC failure after a connection keeps `connected` and adds `"rpc_error"`.
- `nat_status` is `unknown` and `relay` is `null` until `v0.5.9`.

Exit codes: `0` connected (RPC ok or skipped), `1` failed, `4` connected but the RPC failed, `3` error, `2` usage error (no JSON).

Refusal codes (`probe::probe_target_decision`, Kani `proof_probe_target_requires_peer_id_and_direct`): `reject.probe_mode_required`, `reject.probe_peer_id_required` (Noise must authenticate a named peer), `reject.probe_relay_addr_forced_direct`, `reject.probe_peer_unknown`, `reject.probe_ambiguous_peer`, `reject.probe_bare_peer_id_lab`, and in lab mode `reject.lab_dns_addr`.

## 6. Enforcement

`.enforcement.map` rows for this page (`docs/security/TRUST_FINDINGS.md` lists them):

| Id | Kind | What it pins |
| :-- | :-- | :-- |
| LAB-CONFLICT | claim | an explicit side-channel setting is refused (`reject.lab_config_conflict`) |
| LAB-PORT | claim | port 0 is refused (`reject.lab_ephemeral_port`) |
| LAB-UNSPEC-V4M | claim | the v4-mapped wildcard `[::ffff:0.0.0.0]` is refused like `0.0.0.0` (`reject.lab_unspecified_bind`); a v4-mapped specific address is accepted |
| LAB-DNS | claim | a name in the dial set is refused (`reject.lab_dns_addr`) |
| LAB-SIDE | claim | `discover` exits 3 in lab mode (`reject.lab_side_channel`) |
| LAB-DIAL | claim | a learned address is never dialled (`reject.lab_dial_outside_set`) |
| LAB-DIAL-K | kani | `proof_lab_dial_only_within_fixed_set` |
| LAB-DIAL-TX, LAB-DIAL-BHV | reach | the transport and the behaviour call `lab_dial_decision` |
| LAB-REACH | reach | `run_daemon` runs the lab startup rule |
| S-DUMP-SECRET, S-DUMP-CLASS, S-DUMP-NOFX | suite | no secret in the dump; every input classified; no side effects |
| DUMP-K, DUMP-REACH | kani, reach | `dump_field_repr` never renders a secret, and `render_dump` uses it |
| PROBE-PID | claim | a probe target without `/p2p/` is refused (`reject.probe_peer_id_required`) |
| PROBE-DIRECT | claim | a relay address under `--force-direct` is refused (`reject.probe_relay_addr_forced_direct`) |
| PROBE-LAB | claim | a bare PeerId is refused in lab mode (`reject.probe_bare_peer_id_lab`) |
| PROBE-K, PROBE-REACH | kani, reach | `proof_probe_target_requires_peer_id_and_direct`; `run_probe` calls the decision |
