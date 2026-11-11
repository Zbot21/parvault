# ParVault Zero-Copy Unix Socket & `GatewayBus` Plugin Protocol Specification (`v0.5.0`)

- **Governing ADRs:** [`ADR-27`](adr/ADR-27-zero-copy-uds-gateway-and-hedged-pool.md), [`ADR-28`](adr/ADR-28-stateless-macaroon-capability-attenuation.md), [`ADR-29`](adr/ADR-29-pure-rust-fuse-and-webdav-lazy-vfs.md), [`ADR-31`](adr/ADR-31-unsafe-remediation-and-os-sys-ffi-boundary.md), [`ADR-32`](adr/ADR-32-transport-agnostic-gateway-bus-and-memfd-sealing.md)
- **Canonical Reference Plugin:** [`src/bin/parvault-fuse.rs`](../src/bin/parvault-fuse.rs) (`parvault-fuse`)
- **Core Implementation:** [`src/gateway/`](../src/gateway/), [`src/capabilities.rs`](../src/capabilities.rs), [`src/os_sys.rs`](../src/os_sys.rs)

---

## 1. Architecture Overview: Single Core Daemon + Isolated Plugins

In `v0.5.0`, **`parvault up --ipc-socket /var/run/parvault.sock`** is the canonical single-daemon host. One `parvault` process simultaneously runs:

1. Inbound + outbound reciprocal `libp2p` (`TCP + Noise XX + Yamux`) shard storage, Proof-of-Retrievability (`PoR`) auditing, 30-second bit-rot scrubbing, and zero-IP LAN/WAN discovery;
2. Optional background POSIX folder backup (`--watch` / `FolderSyncEngine`); and
3. The hardened zero-copy Unix Domain Socket server (`GatewayIpcServer`) on `/var/run/parvault.sock` (`0600` permissions by default).

No second `parvault-gateway` daemon binary is required (`parvault gateway serve` remains available as a subcommand inside `parvault` for standalone outbound 40-lane socket benchmarking).

### Why `parvault-fuse` Ships as the Canonical Reference Plugin Binary

Even though [`src/vfs.rs`](../src/vfs.rs) implements a 100% pure-Rust Linux `/dev/fuse` (`ABI 7.31`) loop with **zero** C `libfuse3` or `fuser` dependency (preserving stripped static `musl` builds on `x86_64` and `aarch64`), [`src/bin/parvault-fuse.rs`](../src/bin/parvault-fuse.rs) is packaged as a standalone `< 215`-line plugin binary for two reasons:

1. **Copy-Paste Developer Reference:** Third-party and companion plugins (`parvault-dvr`, `parvault-s3d`, `parvault-auth-broker`, `parvault-isp-agent`) can use `src/bin/parvault-fuse.rs` as a complete, minimal reference client speaking sealed `memfd` `SCM_RIGHTS` + `PARVAULT-MAC-V1:` macaroons over `/var/run/parvault.sock`.
2. **Process & UID Privilege Separation:** Frontends that mount `/dev/fuse` (`fusermount3`) or expose LAN HTTP-Range / WebDAV / S3 ports run under a dedicated unprivileged POSIX user (for example UID `1042`) with **zero** `MasterKey` material in process memory, gated by `parvault up --ipc-socket /var/run/parvault.sock --strict-plugins --allow-peer-uid 1042 --require-sealed-memfd`.

### Dual-Mode `GatewayBus` (`=y` Built-In vs. `=m` Split Plugin)

[`parvault::gateway::GatewayBus`](../src/gateway/ipc.rs) exposes one unified async Rust API across both deployment models:

- **`GatewayBus::InProcess(Arc<GatewayEngine>)` (`--no-socket`, Linux-kernel `=y` style):** Embeds the streaming gateway directly in-process with zero filesystem socket exposed and zero serialized IPC overhead. Duplicate file descriptors are created safely via `fcntl(F_DUPFD_CLOEXEC)` (`os_sys::dup_fd_cloexec`) and verified against `Some(geteuid())`.
- **`GatewayBus::UnixSocket(GatewayIpcClient)` (`--ipc-socket /var/run/parvault.sock`, Linux-kernel `=m` style):** Connects out-of-process plugins over `AF_UNIX` `SOCK_STREAM` with `SCM_RIGHTS` `memfd` zero-copy descriptor passing and kernel `SO_PEERCRED` UID verification.

---

## 2. Control Frame Wire Layout & `Serde-Bincode` Encoding

Every request (`IpcCommand`) and response (`IpcResponse`) over `/var/run/parvault.sock` uses a deterministic length-prefixed frame:

```text
+-------------------------------+---------------------------------------------------+
| frame_len_be: u32 (4 bytes)   | bincode_payload: [u8; frame_len_be]               |
| Big-endian, 1..=16,777,216 B  | Fixed-int bincode (MAX_IPC_FRAME_BYTES = 16 MiB)  |
+-------------------------------+---------------------------------------------------+
         ^
         |-- Optional 1x RawFd attached via SOL_SOCKET / SCM_RIGHTS ancillary cmsg
             on the sendmsg(2) call that transmits the 4-byte header.
```

### Framing & Pre-Deserialization Rules

1. **Header Validation (`validate_ipc_frame_header`):**
   - `frame_len_be == 0` is rejected immediately (`IpcFrameError::ZeroLengthFrame`).
   - `frame_len_be > 16_777_216` (`MAX_IPC_FRAME_BYTES = 16 MiB`) is rejected immediately (`IpcFrameError::ExceedsMaxFrameBytes`).
   - Initial receive buffer reservation is capped at `MAX_IPC_INITIAL_ALLOC_BYTES = 65_536` (`64 KiB`) before reading bytes from the socket.
2. **Canonical `bincode` Options (`ipc_bincode()`):**
   ```rust
   bincode::DefaultOptions::new()
       .with_fixint_encoding()
       .allow_trailing_bytes()
       .with_limit(16 * 1024 * 1024)
   ```
   With `with_fixint_encoding()`, enum discriminants serialize as `u32` little-endian, `usize` / `u64` lengths serialize as `u64` little-endian, `u32` as 4-byte little-endian, and fixed byte arrays `[u8; 32]` serialize raw without length prefixes.

### `IpcCommand` & `IpcResponse` Wire Schema

| Variant | Discriminant (`u32` LE) | `SCM_RIGHTS` FD | Purpose |
| :--- | :--- | :--- | :--- |
| `IpcCommand::StorePayload { payload_fd: i32, bytes_len: u64, retention_policy: RetentionPolicy }` | `0` | **Required** (readable `memfd`, sealed when `--require-sealed-memfd` is active) | Streams `bytes_len` plaintext bytes in `1 MiB` stripes (`pread`), encrypts (`AES-256-GCM`), and shards (`GF(2^8)`). |
| `IpcCommand::FetchPayload { ephemeral_shard_ids: Vec<[u8; 32]>, output_fd: i32 }` | `1` | **Required** (writable `memfd` / file) | Reconstructs and decrypts the full file directly into `output_fd` (`pwrite`). |
| `IpcCommand::FetchRange { manifest: EphemeralShardManifest, offset: u64, len: u64, output_fd: i32, macaroon: Option<CapabilityMacaroon> }` | `2` | **Required** (writable `memfd` / file) | Verifies `macaroon` in `< 1 ms` RAM (including `SO_PEERCRED` UID) and streams `[offset .. offset + len]` into `output_fd`. |
| `IpcCommand::RegisterManifest { file_manifest: FileManifest }` | `3` | None | Indexes an existing or virtual `FileManifest` in gateway RAM and returns its `EphemeralShardManifest`. |
| `IpcCommand::QueryHealthStatus` | `4` | None | Returns live `(iops, peer_count, por_sla_score)` telemetry. |

`RetentionPolicy` discriminants (`u32` LE): `0 = Ephemeral`, `1 = Persistent`, `2 = PinnedRing`.

`IpcResponse` discriminants (`u32` LE):
- `0 = StoreSuccess { manifest: EphemeralShardManifest }`
- `1 = FetchSuccess { bytes_streamed: u64 }`
- `2 = HealthStatus { iops: u64, peer_count: u64, por_sla_score: f32 }`
- `3 = Error { message: String }`

> [!NOTE]
> The `payload_fd: i32` and `output_fd: i32` integers inside `IpcCommand` carry the sender's local descriptor number for diagnostic logging only. The gateway server **never** trusts that integer; it consumes exclusively the kernel-remapped `OwnedFd` delivered via `SCM_RIGHTS` (`MSG_CMSG_CLOEXEC`). Any surplus descriptors attached to a single `cmsg` are wrapped in `OwnedFd` and closed immediately on `recvmsg(2)` return so descriptors can never leak.

---

## 3. Mandatory `memfd` Sealing (`F_ADD_SEALS`) Anti-TOCTOU Contract

### Why Unsealed Shared Memory Is Hazardous

In a streaming `encrypt-before-shard` pipeline, if a compromised or buggy local plugin passes an unsealed writable `memfd` via `SCM_RIGHTS` and mutates underlying shared pages concurrently while `parvault` reads stripes, the plugin can create a Time-of-Check-to-Time-of-Use (TOCTOU) race between metadata/size inspection, `AES-256-GCM` encryption, and caller-side checksum accounting.

### Required Kernel Seal Mask

Producers ingesting payloads into a hardened gateway (`--require-sealed-memfd` / `GatewayIpcServer::with_require_sealed_ingest_memfd(true)`) **must** create the descriptor with `memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING)`, write all plaintext bytes via `pwrite`, and seal the file description prior to `StorePayload`:

```rust
// parvault::os_sys::seal_memfd_immutable
libc::fcntl(
    fd,
    libc::F_ADD_SEALS,
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE,
);
```

When `require_sealed_ingest_memfd` is enabled:
1. Before reading, hashing, or encrypting **a single byte**, `GatewayEngine` / `GatewayIpcServer` calls `os_sys::has_immutable_memfd_seals(fd)` (`fcntl(fd, F_GET_SEALS)`).
2. If `(seals & (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW)) != required` (or if `fd` is not a `memfd`), `StorePayload` immediately aborts with:
   ```text
   unsealed ingest memfd rejected (F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW required)
   ```
3. Rust callers using `GatewayBus::store_sealed_payload_fd`, `GatewayIpcClient::store_sealed_payload_fd`, `GatewayIpcClient::store_sealed_memfd`, `GatewayIpcClient::store_bytes`, or `parvault-fuse` apply `seal_memfd_immutable` automatically.

---

## 4. `PARVAULT-MAC-V1:` Capability Tokens & Offline Caveat Attenuation

### Deterministic Compact Binary Layout

`CapabilityMacaroon::to_compact_token()` encodes tokens as `PARVAULT-MAC-V1:<lowercase-hex>`, where the decoded byte slice (`98 ..= 1,154` bytes, `MAX_MACAROON_CAVEATS = 32`) has layout:

```text
+--------------+-------------------+------------------------+------------------+---------------+---------------+
| version (1B) | nonce_id (32B)    | issuer_fingerprint(32B)| caveat_count(1B) | caveats[...]  | hmac_tag(32B) |
| 0x01         | CSPRNG root nonce | SHA-256(key_id) or 32B | 0..=32           | variable      | HMAC-SHA256   |
+--------------+-------------------+------------------------+------------------+---------------+---------------+
```

### Caveat Wire Encodings (`Caveat::encode_stack`, Zero Heap Allocation)

Each caveat is chained into the running 32-byte tag via `tag_{i+1} = HMAC-SHA256(tag_i, "parvault-macaroon-caveat-v1:" || caveat_bytes)` using stack-only encoding:

| Tag Byte | Variant | Encoded Length | Payload Bytes (Big-Endian) | Enforcement Semantics |
| :--- | :--- | :--- | :--- | :--- |
| `0x01` | `AllowedManifest([u8; 32])` | `33 B` | `32 B` `file_merkle_root` | Constant-time `ct_eq_32` match against requested manifest. |
| `0x02` | `ByteRange { offset, length }` | `17 B` | `offset: u64 BE` + `length: u64 BE` | Overflow-free `u128` sub-interval check `[req.off, req.end] <= [off, off+len]`. |
| `0x03` | `ExpiresAtUnixMs(u64)` | `9 B` | `expires_at_ms: u64 BE` | Requires `ctx.now_unix_ms <= expires_at_ms`. |
| `0x04` | `ReadOnly` | `1 B` | *(empty)* | Rejects any write/mutating context (`!ctx.is_write`). |
| `0x05` | `AllowedPeerUid(u32)` | `5 B` | `uid: u32 BE` | Requires `ctx.peer_uid == Some(uid)` (verified via kernel `SO_PEERCRED` on Unix sockets or `Some(geteuid())` in-process). |

### `parvault token` CLI Examples (`mint`, Offline `attenuate`, `inspect`)

```bash
# 1. Mint a root token (atomically creates 0600 <data_dir>/macaroon_root.key if omitted)
ROOT_TOK="$(parvault --data-dir /var/lib/parvault token mint --key-id dvr-broker)"

# 2. Attenuate 100% OFFLINE inside an untrusted broker/container (NO root key needed!)
PLUGIN_TOK="$(parvault token attenuate \
  --token "${ROOT_TOK}" \
  --manifest-hex a3f1c9e0b4d28176a3f1c9e0b4d28176a3f1c9e0b4d28176a3f1c9e0b4d28176 \
  --byte-range 0:10485760 \
  --ttl-secs 300 \
  --read-only \
  --allow-peer-uid 1042)"

# 3. Inspect caveats and optionally verify in < 1 ms RAM against a simulated request
parvault token inspect \
  --token "${PLUGIN_TOK}" \
  --verify-key-hex "$(cat /var/lib/parvault/macaroon_root.key)" \
  --manifest-hex a3f1c9e0b4d28176a3f1c9e0b4d28176a3f1c9e0b4d28176a3f1c9e0b4d28176 \
  --offset 4096 \
  --len 65536 \
  --peer-uid 1042

# 4. Launch single-daemon ParVault hosting hardened plugin socket + mount parvault-fuse
parvault --data-dir /var/lib/parvault up \
  --ipc-socket /var/run/parvault.sock \
  --strict-plugins \
  --allow-peer-uid 1042 \
  --require-sealed-memfd

parvault-fuse --socket /var/run/parvault.sock --macaroon "${PLUGIN_TOK}" webdav --listen 127.0.0.1:4918
```

---

## 5. Security Modes, Build Features & Operational Rough Edges Matrix

Operators and firmware integrators should consult the matrix below to understand exact runtime behavior and avoid misconfiguration pitfalls:

| Mode / Build Configuration | Inbound P2P Shard Hosting & PoR Listener | Outbound Mesh Sharding & Restore | Local Folder Crawler (`FolderSyncEngine`) | Plugin Socket (`/var/run/parvault.sock`) | Key Operational Notes & Guardrails |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`parvault up --ipc-socket /var/run/parvault.sock`** *(Canonical Single-Daemon Host)* | **Active** (`PutShard`, `GetShard`, PoR, 30s bit-rot scrub, LAN/WAN pairing) | **Active** (`MeshClient` + `BlockStore`) | **Optional** (`--folder` / `watched_folder`) | **Active** (`GatewayIpcServer`) | Recommended single-process deployment for homelabs, desktops, and CPE routers. Auto-loads `<data_dir>/macaroon_root.key` if present. |
| **`parvault up --no-socket`** | **Active** | **Active** | **Optional** | **Disabled** (`0` socket files) | Eliminates local Unix socket attack surface entirely; passing both `--no-socket` and `--ipc-socket` fails fast at CLI startup. |
| **`parvault gateway serve`** *(Standalone Outbound Benchmark / Bridge)* | **Inactive** *(Rough Edge 1)* | **Active** (`40`-lane hedged `MeshClient` pool) | **Inactive** *(Rough Edge 2)* | **Active** (unless `--no-socket`) | **Rough Edge 1:** Outbound mesh client + local socket server only; a cluster composed *solely* of `gateway serve` processes has no inbound storage peers to host shards. **Rough Edge 2:** `watched_folder` in `config.toml` is ignored and emits an explicit startup `WARN` log; push backups via `/var/run/parvault.sock` or use `parvault up --watch`. |
| **`cargo build --no-default-features --bin parvault --bin parvault-seed`** | **Active** (`parvault up` / `parvault-seed`) | **Active** | **Active** (`parvault`) | **Active** (`parvault`) | Excludes `vfs` (`src/vfs.rs` and `parvault-fuse`) from compilation for minimal core footprints when FUSE/WebDAV runs in a separate plugin container or is unused. |
| **`--strict-plugins --allow-peer-uid <UID,...>`** | *(Inherits host mode)* | *(Inherits host mode)* | *(Inherits host mode)* | **UID-Allowlisted (`SO_PEERCRED`)** | Calls `getsockopt(SOL_SOCKET, SO_PEERCRED)` immediately on `accept()` (both sync and async Tokio loops) and drops unauthorized UIDs **before reading 1 byte**. Passing `--strict-plugins` with an empty `--allow-peer-uid` list fails fast at CLI startup (`anyhow::bail!`). |
| **`--require-sealed-memfd`** | *(Inherits host mode)* | *(Inherits host mode)* | *(Inherits host mode)* | **Sealed `memfd` Required** | Rejects any `StorePayload` descriptor lacking `F_SEAL_WRITE \| F_SEAL_SHRINK \| F_SEAL_GROW` before reading or encrypting any byte. Custom C/Go/Rust plugins **must** call `fcntl(F_ADD_SEALS)` prior to `sendmsg`. |
