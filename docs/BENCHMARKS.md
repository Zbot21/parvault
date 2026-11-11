# Empirical Benchmarks, Memory Telemetry & Verification (`parvault` v0.4.0)

All measurements below are produced directly by the repository's reproducible harnesses (`parvault-bench`, `parvault-gateway`, `parvault-fuse`, `parvault-seed`, and `scripts/docker_acceptance_gate.sh`) with zero simulated sleeps or synthetic numbers, reading live Linux kernel `/proc/self/status` (`VmRSS` & `VmHWM`), `CLOCK_PROCESS_CPUTIME_ID`, and cgroup memory counters alongside wall-clock throughput.

---

## 1. Streaming Memory Footprint & End-to-End Throughput (`64 MiB` Payload)

Measured via `cargo run --release --bin parvault-bench -- --profile router-soc run --payload-mib 64` and `cargo run --release --bin parvault-bench -- run --payload-mib 64`:

| Profile | Stripe Size | Stripes | Baseline RSS | Peak `VmHWM` | SoC `< 32 MiB` Gate | Store Speed | Restore Speed |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Router-SoC** | `1 MiB` | `64` | `4.15–4.16 MiB` | **`9.72–9.74 MiB`** (`9,956–9,972 KiB`) | **PASS (`< 32 MiB`)** | **`75.9–82.1 MiB/s`** | **`127.1–127.4 MiB/s`** |
| **Desktop / Homelab-NAS** | `16 MiB` | `4` | `9.80 MiB` | **`57.91 MiB`** (`59,296 KiB`) | Desktop Target | **`121.7 MiB/s`** | **`117.3 MiB/s`** |

---

## 2. Zero-Copy `parvault-gateway` (`SCM_RIGHTS` `memfd`) & `parvault-fuse` Telemetry

Measured against a live `parvault-gateway` Unix Domain Socket listener and `parvault-fuse` lazy VFS client:

| Harness / Pipeline | Payload / Configuration | Latency / Throughput | Measured RSS / `VmHWM` |
| :--- | :--- | :---: | :---: |
| **`parvault-gateway ipc-roundtrip`** (`64 MiB`) | `1,280` shards via `memfd_create` + `SCM_RIGHTS` (`512 KiB` gateway stripes, `40`-lane `128 KiB`-stack pool) | **`12.13 ms` TTFB** (`64 KiB` range)<br/>`1,141.21 ms` upload (`56.08 MiB/s`)<br/>`736.03 ms` restore (`86.95 MiB/s`) | Gateway `VmHWM`: **`10.98 MiB`** (`11,240 KiB`)<br/>Client `VmRSS`: **`6.59 MiB`** (`6,905,856 B`) |
| **`parvault-gateway self-test`** (`static-musl`) | `2 MiB` zero-copy `memfd` `SCM_RIGHTS` round-trip | Bit-for-bit SHA-256 verified | **`7.31 MiB`** RSS (`10.50 MiB` glibc) |
| **`parvault-fuse self-test`** | Lazy byte-range hydration over UDS + `2 MiB` bounded LRU block cache (`1` eviction) | **`14.59 ms` TTFB** (`19.04 ms` `musl`, `< 50 ms`) | Bounded `2,097,152 B` cache |
| **`parvault-seed start --no-fs`** | `--mode public-bootstrap --no-fs --in-memory-mb 16` | Live `Noise_XX + Yamux` TCP listener | **`0` files / `0` dirs** created on disk |

---

## 3. Cryptographic, Post-Quantum & Reed-Solomon Microbenchmarks

| Subsystem / Operation | Parameters / Construction | Measured Throughput / Latency |
| :--- | :--- | :---: |
| **`Argon2id` + `HKDF-SHA256` Seed Derivation** | `m = 64 MiB (65,536 KiB), t = 3, p = 4` (BIP-39 12/24-word) | **`138.77–143.65 ms`** |
| **`AES-256-GCM` Stripe Encryption (`Router-SoC`)** | `1 MiB` stripe + HKDF per-purpose subkey/nonce | **`583.9–589.2 MiB/s`** |
| **`AES-256-GCM` Stripe Decryption (`Router-SoC`)** | `1 MiB` stripe + authentication tag verification | **`559.5–610.3 MiB/s`** |
| **`AES-256-GCM` Stripe Encryption (`Desktop`)** | `16 MiB` stripe + HKDF per-purpose subkey/nonce | **`496.5–497.0 MiB/s`** |
| **`AES-256-GCM` Stripe Decryption (`Desktop`)** | `16 MiB` stripe + authentication tag verification | **`488.7–497.9 MiB/s`** |
| **`PqVaultMasterKey` Dual-Cipher Encryption** | `16 MiB` (`AES-256-GCM` inner + `ChaCha20-Poly1305` outer) | **`248.4–261.4 MiB/s`** |
| **`PqVaultMasterKey` Dual-Cipher Decryption** | `16 MiB` (`ChaCha20-Poly1305` outer + `AES-256-GCM` inner) | **`256.8–258.1 MiB/s`** |
| **`HybridKemKeypair` Encapsulate / Decapsulate (X-Wing)** | `X25519 + NIST FIPS 203 ML-KEM-768` (`HKDF-SHA512`) | **`100.4–117.8 us` / `99.4–106.9 us`** |
| **`HybridPqSigningKeypair` Sign / Verify** | `Ed25519 + NIST FIPS 204 ML-DSA-65` | **`475.6–477.3 us` / `152.1–159.2 us`** |
| **Reed-Solomon $GF(2^8)$ `Router-SoC (16-of-20)` Encode / Reconstruct** | `1 MiB` stripe $\to$ `20 x 64 KiB` shards + Merkle quarantine | **`304.8–334.6 MiB/s` / `145.2–145.3 MiB/s`** |
| **Reed-Solomon $GF(2^8)$ `Consumer (10-of-20)` Encode / Reconstruct** | `16 MiB` stripe $\to$ `20 x 1.6 MiB` shards + Merkle quarantine | **`158.1–159.3 MiB/s` / `90.4–95.4 MiB/s`** |
| **Reed-Solomon $GF(2^8)$ `Homelab (16-of-20)` Encode / Reconstruct** | `16 MiB` stripe $\to$ `20 x 1.0 MiB` shards + Merkle quarantine | **`286.3–301.3 MiB/s` / `142.2–143.4 MiB/s`** |

---

## 4. Static `musl` Binary & Container Footprint (`v0.4.0`)

Built with `--profile soc` (`opt-level = "z"`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`) and stripped via `strip` / `aarch64-linux-gnu-strip`:

| Artifact / Target | Profile | Exact Bytes | Stripped Size | Notes |
| :--- | :---: | :---: | :---: | :--- |
| `parvault` (`aarch64-unknown-linux-musl`) | `--profile soc` | `6,179,072 B` | **`5.89 MiB`** | Zero dynamic library dependencies; full ARM64 daemon & CLI |
| `parvault-seed` (`aarch64-unknown-linux-musl`) | `--profile soc` | `4,404,584 B` | **`4.20 MiB`** | Headless ARM64 gateway / RPi seed server (supports `--no-fs`) |
| `parvault-gateway` (`aarch64-unknown-linux-musl`) | `--profile soc` | `3,215,952 B` | **`3.07 MiB`** | Canonical ARM64 UDS `SCM_RIGHTS` + 40-lane `libp2p` CPE gateway |
| `parvault-fuse` (`aarch64-unknown-linux-musl`) | `--profile soc` | `3,019,280 B` | **`2.88 MiB`** | Pure-Rust ARM64 `/dev/fuse` (`ABI 7.31`) + WebDAV lazy VFS client |
| `parvault` (`x86_64-unknown-linux-musl`) | `--profile soc` | `7,887,656 B` | **`7.52 MiB`** | Static `x86_64` client & folder-sync daemon |
| `parvault-seed` (`x86_64-unknown-linux-musl`) | `--profile soc` | `5,613,480 B` | **`5.35 MiB`** | Static `x86_64` headless seed & bootstrap server |
| `parvault-gateway` (`x86_64-unknown-linux-musl`) | `--profile soc` | `3,986,536 B` | **`3.80 MiB`** | Static `x86_64` UDS `SCM_RIGHTS` + 40-lane `libp2p` gateway |
| `parvault-fuse` (`x86_64-unknown-linux-musl`) | `--profile soc` | `3,793,960 B` | **`3.62 MiB`** | Static `x86_64` `/dev/fuse` + HTTP `Range` / WebDAV lazy VFS client |
| `parvault:router-soc` (`deploy/Dockerfile.router-soc`) | `FROM scratch` | — | **`6.13 MB` compressed** (`19.6 MB` unpacked) | Verified inside `--memory=48m --memory-swap=48m` cgroup at **`8.63 MiB`** live RSS (`0` OOM kills) |

---

## 5. Formal Verification & Automated Test Summary (`v0.4.0`)

- **Kani Rust Bounded Model Checking (`cargo kani`)**: **`15 / 15` symbolic harnesses verified (`0` failures)** across `src/kani_proofs.rs` (`13` harnesses including `proof_pinned_ring_capacity_invariant` and `proof_fuse_header_parser_no_panic`), `src/crypto/aes.rs` (`1`), and `src/sharding/reed_solomon.rs` (`1`).
- **TLA+ TLC Model Checking (`specs/*.tla`)**: **`7 / 7` protocol specifications verified (`0` errors)** across `17,054` generated states (`4,467` distinct states: `ParVaultProtocol` `800`, `ParVaultConfidentialityAndTrust` `944`, `ParVaultAnonymity` `861`, `ParVaultPostQuantum` `927`, `ParVaultBootstrapAndEarnedTier` `360`, `ParVaultLiteClientAndSeedFailover` `95`, `ParVaultZeroKeyAdminAndQuorum` `480`).
- **Automated Release Test Suite (`cargo test --release`)**: **`122 / 122` tests passing (`0` failures)** across `45` unit tests and `77` integration, live `libp2p`, Stateright, TLA+ TLC, zero-copy `memfd` IPC, VFS, and Byzantine red-team tests.

---

## 6. Reproducing All Benchmarks Locally

```bash
# 1. Run the isolated Router-SoC (/proc/self/status VmHWM < 32 MiB) streaming benchmark
cargo run --release --bin parvault-bench -- --profile router-soc run --payload-mib 64

# 2. Run the full multi-profile streaming + PQC + Reed-Solomon benchmark suite
cargo run --release --bin parvault-bench -- run --payload-mib 64

# 3. Run zero-copy UDS memfd gateway and lazy VFS self-tests
cargo run --release --bin parvault-gateway -- self-test
cargo run --release --bin parvault-fuse -- self-test

# 4. Run all 15 Kani symbolic harnesses + all 7 TLA+ TLC formal specifications
bash scripts/verify_formal_proofs.sh

# 5. Run the 8-profile degraded network & Byzantine poisoner matrix
cargo test --release --test anonymity_and_degraded_net_tests -- --nocapture

# 6. Run the full 14-container live Docker P2P + 48 MiB cgroup Router-SoC acceptance gate
bash scripts/docker_acceptance_gate.sh
```
