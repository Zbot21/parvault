# Operations: is the ring healthy?

What a running daemon tells you about its peers, and the knobs that change how it keeps them (`v0.5.6`).

## Live status

`parvault status` reads the node's files: its configuration, identity and quota. To see what the running daemon is doing, ask the daemon itself:

- `GET /live` on the status listener (`daemon start --status-http <addr>`). It needs the same read-only token as the other status routes (`parvault token mint`), sent as `Authorization: Bearer <token>`. Without a valid token the listener refuses the request and logs the reason code (for example `reject.status_token_missing`).
- `parvault status --live` asks over the gateway socket.

The answer is JSON:

| Field | Meaning |
| :-- | :-- |
| `peers` | Ring peers this daemon has admitted or is connected to, sorted by PeerId, at most 256. Each has `admitted` (its handshake was accepted since this daemon started), `connected` (the daemon's own swarm has an open connection to it now) and `addrs` (the listen addresses the peer reported, at most 16). |
| `listen_addrs` | Where this daemon listens, at most 16. |
| `fetch` | The restore scheduler's counters. |
| `shards_held`, `held_shard_bound`, `held_shard_bound_source` | Shards this node holds, the most it will hold, and where that bound came from. |
| `anon_rss_bytes` | The daemon's anonymous resident memory. |

A healthy home ring shows every other node `connected: true`. `admitted` turns true when a peer first sends a request that needs ring admission, so an idle ring can show connected peers that are not yet admitted. The daemon logs that state at DEBUG ("not yet admitted (no handshake yet)") and logs the admission at INFO.

## Reconnecting after a restart

When a peer goes away, the daemon dials it again: first after 1 s, then 2, 4, 8 and 16 s, then every 30 s, each with up to a quarter of random jitter. The delay goes back to 1 s only after a connection has held for 60 s, so a peer that keeps dropping is not hammered. A peer that comes back is reconnected within about 48 s at most (30 s, its jitter, and the dial itself).

Only ring peers are dialled again: the addresses in `--peers` (or the config file), and admitted members at the listen addresses they reported themselves, at most 8 per peer. An address a connection merely came from, an mDNS sighting, or a Kademlia entry is never dialled. Each redial logs "redialling a ring peer" at INFO.

## Store limits

Each profile bounds the two stores of ring metadata:

| | `desktop` | `homelab-nas` | `router-soc` |
| :-- | --: | --: | --: |
| Kademlia replication interval | 1 h | 1 h | 6 h |
| Kademlia records | 1,024 | 512 | 128 |
| Kademlia record bytes | 64 MiB | 16 MiB | 4 MiB |
| Envelope store bytes | 256 MiB | 32 MiB | 8 MiB |
| Envelope store keys | 65,536 | 8,192 | 2,048 |

Kademlia records are republished every 22 h and expire after 48 h. One owner may hold at most three quarters of the envelope store's bytes and keys. At a limit, a new record or envelope is refused and nothing held is evicted: `reject.dht_record_store_full`, `reject.dht_store_full` or `reject.dht_owner_key_cap` in the host's log. Every stored version of a changed file adds one envelope key, and nothing removes old ones yet (planned for `v0.5.7`, B-182), so a busy folder fills the envelope store over time.

If the envelope store file (`zero_trust_dht_store.bin`) does not load, the daemon logs `error.dht_store_unreadable` and refuses every envelope (`reject.dht_store_corrupt`) instead of starting empty, which would forget every version it held. Restore the file from a backup, or remove it to start empty on purpose.

## Test and tuning knobs

Environment variables, read when the daemon starts:

| Variable | Effect |
| :-- | :-- |
| `PARVAULT_KAD_REPLICATION_SECS` | The Kademlia replication interval in whole seconds; at least 60. A smaller or unreadable value stops the daemon from starting (`reject.kad_replication_too_short`, `reject.kad_replication_invalid`). |
| `PARVAULT_DHT_STORE_MAX_KEYS` | Lowers the envelope store's key limit; never raises it. |
| `PARVAULT_DHT_STORE_MAX_BYTES` | Lowers the envelope store's byte limit; never raises it. |

A zero or unreadable store limit is ignored and logged (`reject.dht_store_override_invalid`). The owner's three-quarter share follows the lowered limits.
