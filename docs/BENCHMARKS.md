# Empirical Benchmarks, Memory Telemetry & Verification (`parvault` v0.5.0-M3)

All measurements below are produced directly by the repository's reproducible harnesses (`parvault-bench`, `parvault gateway`, `parvault-fuse`, `parvault-sync`, `parvault-seed`, and `scripts/docker_acceptance_gate.sh`) with zero simulated sleeps or synthetic numbers, reading live Linux kernel `/proc/self/status` (`VmRSS` & `VmHWM`), `CLOCK_PROCESS_CPUTIME_ID`, and cgroup memory counters alongside wall-clock throughput.

---

## 1. Streaming Memory Footprint & End-to-End Throughput (`64 MiB` Payload)

Measured via `cargo run --release --bin parvault-bench -- --profile router-soc run --payload-mib 64` and `cargo run --release --bin parvault-bench -- run --payload-mib 64`:

| Profile | Stripe Size | Stripes | Baseline RSS | Peak `VmHWM` | SoC `< 32 MiB` Gate | Store Speed | Restore Speed |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Router-SoC** | `1 MiB` | `64` | <!-- metric:bench.soc.baseline_rss -->`4.15–4.16 MiB`<!-- /metric --> | **<!-- metric:bench.soc.vmhwm -->`9.72–9.74 MiB`<!-- /metric -->** (<!-- metric:bench.soc.vmhwm_kib -->`9,956–9,972 KiB`<!-- /metric -->) | **PASS (`< 32 MiB`)** | **<!-- metric:bench.soc.store -->`75.9–82.1 MiB/s`<!-- /metric -->** | **<!-- metric:bench.soc.restore -->`127.1–127.4 MiB/s`<!-- /metric -->** |
| **Desktop / Homelab-NAS** | `16 MiB` | `4` | <!-- metric:bench.desktop.baseline_rss -->`9.80 MiB`<!-- /metric --> | **<!-- metric:bench.desktop.vmhwm -->`57.91 MiB`<!-- /metric -->** (<!-- metric:bench.desktop.vmhwm_kib -->`59,296 KiB`<!-- /metric -->) | Desktop Target | **<!-- metric:bench.desktop.store -->`121.7 MiB/s`<!-- /metric -->** | **<!-- metric:bench.desktop.restore -->`117.3 MiB/s`<!-- /metric -->** |

---

## 2. Zero-Copy `parvault` Socket Gateway (`SCM_RIGHTS` Sealed `memfd` + `SO_PEERCRED`), `parvault-fuse` & `parvault-sync` Telemetry

Measured against a live `parvault` Unix Domain Socket listener (`/var/run/parvault.sock`), `parvault-fuse` lazy VFS client, and zero-key `parvault-sync` incremental folder plugin:

| Harness / Pipeline | Payload / Configuration | Latency / Throughput | Measured RSS / `VmHWM` |
| :--- | :--- | :---: | :---: |
| **`parvault gateway ipc-roundtrip`** (`64 MiB`) | `1,280` shards via `memfd_create` + `SCM_RIGHTS` (`512 KiB` gateway stripes, `40`-lane `128 KiB`-stack pool) | **<!-- metric:gw.ipc.ttfb -->`12.13 ms`<!-- /metric --> TTFB** (`64 KiB` range)<br/><!-- metric:gw.ipc.upload -->`1,141.21 ms`<!-- /metric --> upload (<!-- metric:gw.ipc.upload_rate -->`56.08 MiB/s`<!-- /metric -->)<br/><!-- metric:gw.ipc.restore -->`736.03 ms`<!-- /metric --> restore (<!-- metric:gw.ipc.restore_rate -->`86.95 MiB/s`<!-- /metric -->) | Gateway `VmHWM`: **<!-- metric:gw.ipc.gateway_vmhwm -->`10.98 MiB`<!-- /metric -->** (<!-- metric:gw.ipc.gateway_vmhwm_kib -->`11,240 KiB`<!-- /metric -->)<br/>Client `VmRSS`: **<!-- metric:gw.ipc.client_rss -->`6.59 MiB`<!-- /metric -->** (<!-- metric:gw.ipc.client_rss_bytes -->`6,905,856 B`<!-- /metric -->) |
| **`parvault gateway self-test`** (`static-musl`) | `2 MiB` zero-copy sealed `memfd` (`F_ADD_SEALS`) + `SCM_RIGHTS` + `SO_PEERCRED` round-trip | Bit-for-bit SHA-256 verified | **<!-- metric:gw.selftest.rss_musl -->`10.04 MiB`<!-- /metric -->** RSS (<!-- metric:gw.selftest.rss_glibc -->`13.14 MiB`<!-- /metric --> glibc) |
| **`parvault-fuse self-test`** (client-only, vs `parvault gateway serve`; `scripts/plugin_self_test.sh`) | Lazy byte-range hydration over UDS + `2 MiB` bounded LRU block cache (`1` eviction) | **<!-- metric:fuse.ttfb -->`11.96–12.75 ms`<!-- /metric --> TTFB** (<!-- metric:fuse.ttfb_musl -->`19.45–19.73 ms`<!-- /metric --> `musl`, `< 50 ms`) | Bounded `2,097,152 B` cache |
| **`parvault-sync self-test`** (client-only, as above) | Zero-key sealed-`memfd` initial `push` + edit/add/delete `diff` + incremental `push` + attenuated `PARVAULT-MAC-V1:` `pull` + streaming SHA-256 verify | **<!-- metric:sync.selftest -->`500–512 ms`<!-- /metric -->** (<!-- metric:sync.selftest_musl -->`590–610 ms`<!-- /metric --> `musl`, `2` files, `catalog_v=2`) | **<!-- metric:sync.rss_musl -->`3.90–3.94 MiB`<!-- /metric -->** RSS `musl` (<!-- metric:sync.rss_glibc -->`5.76–5.77 MiB`<!-- /metric --> glibc) |
| **Mounted MP4 gate** (`tests/vfs_mp4_seek_gate.rs`, release; real kernel `/dev/fuse` via `fusermount3` and WebDAV `206`) | `ffprobe` and `ffmpeg -ss 12` on a 12 MiB H.264 file (12 × 1 MiB stripes), `3 MiB` LRU cache | Probe: `1` cache miss (block 0 only); cold read at the mid keyframe `12.3 ms`; seek frames match the local file | `parvault-fuse mount-fd` `VmHWM` `7.5 MiB` |
| **`parvault-seed start --no-fs`** | `--mode public-bootstrap --no-fs --in-memory-mb 16` | Live `Noise_XX + Yamux` TCP listener | **`0` files / `0` dirs** created on disk |

The plugin rows (v0.5.0, item 3) are measured with `scripts/plugin_self_test.sh`: a separate `parvault gateway serve` process with a root key, then each plugin's client-only `self-test` over the socket with a minted token. `parvault-sync`'s latency is the plugin's own wall time for initial `push`, `diff`, incremental `push` and an attenuated-token `pull` with SHA-256 checks, excluding gateway start-up; RSS is the plugin process alone. Ranges are min–max over 5 runs. Earlier versions ran the gateway inside the plugin: at `1b266f6` that took `630–705 ms` and `9.6 MiB` RSS on the same machine, so the older `94.58 ms` figure is not reproducible.

---

## 3. Cryptographic, Post-Quantum & Reed-Solomon Microbenchmarks

| Subsystem / Operation | Parameters / Construction | Measured Throughput / Latency |
| :--- | :--- | :---: |
| **`Argon2id` + `HKDF-SHA256` Seed Derivation** | `m = 64 MiB (65,536 KiB), t = 3, p = 4` (BIP-39 12/24-word) | **<!-- metric:argon2.derive -->`138.77–143.65 ms`<!-- /metric -->** |
| **`AES-256-GCM` Stripe Encryption (`Router-SoC`)** | `1 MiB` stripe + HKDF per-purpose subkey/nonce | **<!-- metric:aes.enc.soc -->`583.9–589.2 MiB/s`<!-- /metric -->** |
| **`AES-256-GCM` Stripe Decryption (`Router-SoC`)** | `1 MiB` stripe + authentication tag verification | **<!-- metric:aes.dec.soc -->`559.5–610.3 MiB/s`<!-- /metric -->** |
| **`AES-256-GCM` Stripe Encryption (`Desktop`)** | `16 MiB` stripe + HKDF per-purpose subkey/nonce | **<!-- metric:aes.enc.desktop -->`496.5–497.0 MiB/s`<!-- /metric -->** |
| **`AES-256-GCM` Stripe Decryption (`Desktop`)** | `16 MiB` stripe + authentication tag verification | **<!-- metric:aes.dec.desktop -->`488.7–497.9 MiB/s`<!-- /metric -->** |
| **`PqVaultMasterKey` Dual-Cipher Encryption** | `16 MiB` (`AES-256-GCM` inner + `ChaCha20-Poly1305` outer) | **<!-- metric:pq.enc -->`248.4–261.4 MiB/s`<!-- /metric -->** |
| **`PqVaultMasterKey` Dual-Cipher Decryption** | `16 MiB` (`ChaCha20-Poly1305` outer + `AES-256-GCM` inner) | **<!-- metric:pq.dec -->`256.8–258.1 MiB/s`<!-- /metric -->** |
| **`HybridKemKeypair` Encapsulate / Decapsulate (X-Wing)** | `X25519 + NIST FIPS 203 ML-KEM-768` (`HKDF-SHA512`) | **<!-- metric:kem.encap -->`100.4–117.8 µs`<!-- /metric --> / <!-- metric:kem.decap -->`99.4–106.9 µs`<!-- /metric -->** |
| **`HybridPqSigningKeypair` Sign / Verify** | `Ed25519 + NIST FIPS 204 ML-DSA-65` | **<!-- metric:sig.sign -->`475.6–477.3 µs`<!-- /metric --> / <!-- metric:sig.verify -->`152.1–159.2 µs`<!-- /metric -->** |
| **Reed-Solomon $GF(2^8)$ `Router-SoC (16-of-20)` Encode / Reconstruct** | `1 MiB` stripe $\to$ `20 x 64 KiB` shards + Merkle quarantine | **<!-- metric:rs.soc.encode -->`304.8–334.6 MiB/s`<!-- /metric --> / <!-- metric:rs.soc.reconstruct -->`145.2–145.3 MiB/s`<!-- /metric -->** |
| **Reed-Solomon $GF(2^8)$ `Consumer (10-of-20)` Encode / Reconstruct** | `16 MiB` stripe $\to$ `20 x 1.6 MiB` shards + Merkle quarantine | **<!-- metric:rs.consumer.encode -->`158.1–159.3 MiB/s`<!-- /metric --> / <!-- metric:rs.consumer.reconstruct -->`90.4–95.4 MiB/s`<!-- /metric -->** |
| **Reed-Solomon $GF(2^8)$ `Homelab (16-of-20)` Encode / Reconstruct** | `16 MiB` stripe $\to$ `20 x 1.0 MiB` shards + Merkle quarantine | **<!-- metric:rs.homelab.encode -->`286.3–301.3 MiB/s`<!-- /metric --> / <!-- metric:rs.homelab.reconstruct -->`142.2–143.4 MiB/s`<!-- /metric -->** |

---

## 4. Static `musl` Binary & Container Footprint (`v0.5.0-M3` Dual-Mode VFS & Sibling Plugins)

Built with `--profile soc` (`opt-level = "z"`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`). Hosting built-in `=y` `VirtualVaultFs` (`--vfs-webdav-listen` / `--vfs-fuse-fd`) inside `parvault` adds only <!-- metric:size.vfs_builtin_overhead.aarch64 -->`+64 KiB`<!-- /metric --> on ARM64, while `parvault-fuse` (<!-- metric:size.parvault-fuse.aarch64 -->`1.13 MiB`<!-- /metric --> ARM64) and zero-key `parvault-sync` (<!-- metric:size.parvault-sync.aarch64 -->`0.69 MiB`<!-- /metric --> ARM64) ship as ultra-compact out-of-process `=m` plugins:

| Artifact / Target | Profile | Exact Bytes | Stripped Size | Notes |
| :--- | :---: | :---: | :---: | :--- |
| `parvault` (`aarch64-unknown-linux-musl`) | `--profile soc` | <!-- metric:size.parvault.aarch64.bytes -->`6,575,456 B`<!-- /metric --> | **<!-- metric:size.parvault.aarch64 -->`6.27 MiB`<!-- /metric -->** | Zero dynamic deps; full ARM64 P2P daemon, built-in `=y` VFS, UDS gateway & `token` CLI |
| `parvault-seed` (`aarch64-unknown-linux-musl`) | `--profile soc` | <!-- metric:size.parvault-seed.aarch64.bytes -->`4,472,240 B`<!-- /metric --> | **<!-- metric:size.parvault-seed.aarch64 -->`4.27 MiB`<!-- /metric -->** | Headless ARM64 gateway / RPi seed server (supports `--no-fs`) |
| `parvault-fuse` (`aarch64-unknown-linux-musl`) | `--profile soc` | <!-- metric:size.parvault-fuse.aarch64.bytes -->`1,185,456 B`<!-- /metric --> | **<!-- metric:size.parvault-fuse.aarch64 -->`1.13 MiB`<!-- /metric -->** | Pure-Rust ARM64 `/dev/fuse` (`ABI 7.31`) + WebDAV reference plugin |
| `parvault-sync` (`aarch64-unknown-linux-musl`) | `--profile soc` | <!-- metric:size.parvault-sync.aarch64.bytes -->`725,264 B`<!-- /metric --> | **<!-- metric:size.parvault-sync.aarch64 -->`0.69 MiB`<!-- /metric -->** | Zero-key ARM64 incremental folder sync plugin (`diff`, `push`, `watch`, `pull`, `list`) |
| `parvault-status` (`aarch64-unknown-linux-musl`) | `--profile soc` | <!-- metric:size.parvault-status.aarch64.bytes -->`1,054,352 B`<!-- /metric --> | **<!-- metric:size.parvault-status.aarch64 -->`1.01 MiB`<!-- /metric -->** | Status page sidecar (`status-ui` only: no tokio, no libp2p); holds no key, reads status over the gateway socket. |
| `parvault` (`x86_64-unknown-linux-musl`) | `--profile soc` | <!-- metric:size.parvault.x86_64.bytes -->`8,361,864 B`<!-- /metric --> | **<!-- metric:size.parvault.x86_64 -->`7.97 MiB`<!-- /metric -->** | Static `x86_64` P2P daemon, built-in `=y` VFS, UDS gateway, `token` CLI & folder sync |
| `parvault-seed` (`x86_64-unknown-linux-musl`) | `--profile soc` | <!-- metric:size.parvault-seed.x86_64.bytes -->`5,750,760 B`<!-- /metric --> | **<!-- metric:size.parvault-seed.x86_64 -->`5.48 MiB`<!-- /metric -->** | Static `x86_64` headless seed & bootstrap server |
| `parvault-fuse` (`x86_64-unknown-linux-musl`) | `--profile soc` | <!-- metric:size.parvault-fuse.x86_64.bytes -->`1,300,672 B`<!-- /metric --> | **<!-- metric:size.parvault-fuse.x86_64 -->`1.24 MiB`<!-- /metric -->** | Static `x86_64` `/dev/fuse` + HTTP `Range` / WebDAV reference plugin |
| `parvault-sync` (`x86_64-unknown-linux-musl`) | `--profile soc` | <!-- metric:size.parvault-sync.x86_64.bytes -->`811,824 B`<!-- /metric --> | **<!-- metric:size.parvault-sync.x86_64 -->`0.77 MiB`<!-- /metric -->** | Static `x86_64` zero-key incremental folder sync plugin (`GatewayFolderSync`) |
| `parvault-status` (`x86_64-unknown-linux-musl`) | `--profile soc` | <!-- metric:size.parvault-status.x86_64.bytes -->`1,198,240 B`<!-- /metric --> | **<!-- metric:size.parvault-status.x86_64 -->`1.14 MiB`<!-- /metric -->** | Status page sidecar (`status-ui` only: no tokio, no libp2p); holds no key, reads status over the gateway socket. |
| `parvault:router-soc` (`deploy/Dockerfile.router-soc`) | `FROM scratch` | — | **<!-- metric:docker.compressed -->`6.13 MB`<!-- /metric --> compressed** (<!-- metric:docker.unpacked -->`19.6 MB`<!-- /metric --> unpacked) | Verified inside `--memory=48m --memory-swap=48m` cgroup at **<!-- metric:docker.live_rss -->`8.63 MiB`<!-- /metric -->** live RSS (`0` OOM kills) |

---

## 5. Formal Verification & Automated Test Summary (`v0.5.0-M3`)

- **Kani Rust Bounded Model Checking (`cargo kani`)**: **<!-- metric:kani_pass -->`29 / 29`<!-- /metric --> symbolic harnesses verified (`0` failures)** across `src/kani_proofs.rs` (<!-- metric:kani_harnesses_module -->`26`<!-- /metric --> harnesses including `proof_pinned_ring_capacity_invariant`, `proof_fuse_header_parser_no_panic`, and `proof_sanitize_sync_relative_path_no_traversal`), `src/capabilities.rs` (<!-- metric:kani_harnesses.capabilities -->`1`<!-- /metric -->: `proof_macaroon_peer_uid_and_compact_roundtrip`), `src/crypto/aes.rs` (<!-- metric:kani_harnesses.aes -->`1`<!-- /metric -->), and `src/sharding/reed_solomon.rs` (<!-- metric:kani_harnesses.reed_solomon -->`1`<!-- /metric -->).
- **TLA+ TLC Model Checking (`specs/*.tla`)**: **<!-- metric:tla_pass -->`7 / 7`<!-- /metric --> protocol specifications verified (`0` errors)** across <!-- metric:tlc.generated -->`81,401`<!-- /metric --> generated states (<!-- metric:tlc.distinct -->`8,088`<!-- /metric --> distinct states; per spec distinct / generated: `ParVaultProtocol` <!-- metric:tlc.distinct.ParVaultProtocol -->`3,040`<!-- /metric --> / <!-- metric:tlc.generated.ParVaultProtocol -->`61,009`<!-- /metric -->, `ParVaultConfidentialityAndTrust` <!-- metric:tlc.distinct.ParVaultConfidentialityAndTrust -->`944`<!-- /metric --> / <!-- metric:tlc.generated.ParVaultConfidentialityAndTrust -->`2,318`<!-- /metric -->, `ParVaultAnonymity` <!-- metric:tlc.distinct.ParVaultAnonymity -->`441`<!-- /metric --> / <!-- metric:tlc.generated.ParVaultAnonymity -->`2,742`<!-- /metric -->, `ParVaultPostQuantum` <!-- metric:tlc.distinct.ParVaultPostQuantum -->`1,656`<!-- /metric --> / <!-- metric:tlc.generated.ParVaultPostQuantum -->`6,979`<!-- /metric -->, `ParVaultBootstrapAndEarnedTier` <!-- metric:tlc.distinct.ParVaultBootstrapAndEarnedTier -->`136`<!-- /metric --> / <!-- metric:tlc.generated.ParVaultBootstrapAndEarnedTier -->`331`<!-- /metric -->, `ParVaultLiteClientAndSeedFailover` <!-- metric:tlc.distinct.ParVaultLiteClientAndSeedFailover -->`95`<!-- /metric --> / <!-- metric:tlc.generated.ParVaultLiteClientAndSeedFailover -->`212`<!-- /metric -->, `ParVaultZeroKeyAdminAndQuorum` <!-- metric:tlc.distinct.ParVaultZeroKeyAdminAndQuorum -->`1,776`<!-- /metric --> / <!-- metric:tlc.generated.ParVaultZeroKeyAdminAndQuorum -->`7,810`<!-- /metric -->).
- **Automated Release Test Suite (`cargo test --release`)**: **<!-- metric:tests_pass -->`429 / 429`<!-- /metric --> tests passing (`0` failures)** across <!-- metric:tests_unit -->`115`<!-- /metric --> unit tests and <!-- metric:tests_integration -->`314`<!-- /metric --> integration, live `libp2p`, Stateright, TLA+ TLC, `GatewayBus` (`InProcess` & `UnixSocket`), dual-mode `VirtualVaultFs` (`--no-socket` & WebDAV `206`), zero-key `GatewayFolderSync`, sealed `memfd` IPC, `SO_PEERCRED` UID enforcement, and Byzantine red-team tests.

---

## 6. Reproducing All Benchmarks Locally

```bash
# 1. Run the isolated Router-SoC (/proc/self/status VmHWM < 32 MiB) streaming benchmark
cargo run --release --bin parvault-bench -- --profile router-soc run --payload-mib 64

# 2. Run the full multi-profile streaming + PQC + Reed-Solomon benchmark suite
cargo run --release --bin parvault-bench -- run --payload-mib 64

# 3. Run zero-copy UDS sealed memfd gateway, lazy VFS, and zero-key folder sync self-tests
cargo run --release --bin parvault -- gateway self-test
# Plugin self-tests are client-only: this starts a standalone gateway, mints a token, runs both
bash scripts/build_bins.sh --profile release --out dist && bash scripts/plugin_self_test.sh dist/parvault dist/parvault-fuse dist/parvault-sync

# 4. Run all Kani symbolic harnesses + all TLA+ TLC formal specifications
bash scripts/verify_formal_proofs.sh

# 5. Run the 8-profile degraded network & Byzantine poisoner matrix
cargo test --release --test anonymity_and_degraded_net_tests -- --nocapture

# 6. Run the full multi-container live Docker P2P + 48 MiB cgroup Router-SoC acceptance gate
bash scripts/docker_acceptance_gate.sh
```
