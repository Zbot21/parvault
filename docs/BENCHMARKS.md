# Empirical Benchmarks, Memory Telemetry & Verification (`parvault-bench`)

All measurements below are produced directly by the repository's reproducible harnesses (`parvault-bench` and `scripts/docker_acceptance_gate.sh`) with zero simulated sleeps or synthetic numbers, reading live Linux kernel `/proc/self/status` (`VmRSS` & `VmHWM`) and cgroup memory counters alongside wall-clock throughput.

---

## 1. Streaming Memory Footprint & End-to-End Throughput (`64 MiB` Payload)

Measured via `cargo run --release --bin parvault-bench -- run --payload-mib 64`:

| Profile | Stripe Size | Stripes | Baseline RSS | Peak `VmHWM` | SoC `< 32 MiB` Gate | Store Speed | Restore Speed |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Router-SoC** | `1 MiB` | `64` | `3.99–4.12 MiB` | **`9.36–9.39 MiB`** (`9,580–9,616 KiB`) | **PASS (`< 32 MiB`)** | **`78.8–81.9 MiB/s`** | **`117.8–122.4 MiB/s`** |
| **Desktop / Homelab-NAS** | `16 MiB` | `4` | `5.44 MiB` | **`57.23–57.30 MiB`** (`58,604–58,676 KiB`) | Desktop Target | **`118.1–127.7 MiB/s`** | **`104.8–116.2 MiB/s`** |

---

## 2. Cryptographic, Post-Quantum & Reed-Solomon Microbenchmarks

| Subsystem / Operation | Parameters / Construction | Measured Throughput / Latency |
| :--- | :--- | :---: |
| **`Argon2id` + `HKDF-SHA256` Seed Derivation** | `m = 64 MiB (65,536 KiB), t = 3, p = 4` (BIP-39 12/24-word) | **`156.44 ms`** |
| **`AES-256-GCM` Stripe Encryption (`Router-SoC`)** | `1 MiB` stripe + HKDF per-purpose subkey/nonce | **`522.1 MiB/s`** |
| **`AES-256-GCM` Stripe Decryption (`Router-SoC`)** | `1 MiB` stripe + authentication tag verification | **`535.0 MiB/s`** |
| **`AES-256-GCM` Stripe Encryption (`Desktop`)** | `16 MiB` stripe + HKDF per-purpose subkey/nonce | **`465.9 MiB/s`** |
| **`AES-256-GCM` Stripe Decryption (`Desktop`)** | `16 MiB` stripe + authentication tag verification | **`459.0 MiB/s`** |
| **`PqVaultMasterKey` Dual-Cipher Encryption** | `16 MiB` (`AES-256-GCM` inner + `ChaCha20-Poly1305` outer) | **`247.5 MiB/s`** |
| **`PqVaultMasterKey` Dual-Cipher Decryption** | `16 MiB` (`ChaCha20-Poly1305` outer + `AES-256-GCM` inner) | **`250.4 MiB/s`** |
| **`HybridKemKeypair` Encapsulate / Decapsulate (X-Wing)** | `X25519 + NIST FIPS 203 ML-KEM-768` (`HKDF-SHA512`) | **`100.2 us` / `108.2 us`** |
| **`HybridPqSigningKeypair` Sign / Verify** | `Ed25519 + NIST FIPS 204 ML-DSA-65` | **`515.3 us` / `167.9 us`** |
| **Reed-Solomon $GF(2^8)$ `Router-SoC (16-of-20)` Encode / Reconstruct** | `1 MiB` stripe $\to$ `20 x 64 KiB` shards + Merkle quarantine | **`311.9 MiB/s` / `140.4 MiB/s`** |
| **Reed-Solomon $GF(2^8)$ `Consumer (10-of-20)` Encode / Reconstruct** | `16 MiB` stripe $\to$ `20 x 1.6 MiB` shards + Merkle quarantine | **`142.7 MiB/s` / `83.6 MiB/s`** |
| **Reed-Solomon $GF(2^8)$ `Homelab (16-of-20)` Encode / Reconstruct** | `16 MiB` stripe $\to$ `20 x 1.0 MiB` shards + Merkle quarantine | **`258.5 MiB/s` / `132.2 MiB/s`** |

---

## 3. Static `musl` Binary & Container Footprint (`v0.3.0`)

| Artifact / Target | Profile | Stripped Size | Notes |
| :--- | :---: | :---: | :--- |
| `parvault` (`aarch64-unknown-linux-musl`) | `--profile soc` | **`5.83 MiB`** | Zero dynamic library dependencies (`opt-level = "z"`, `lto = "fat"`) |
| `parvault-seed` (`aarch64-unknown-linux-musl`) | `--profile soc` | **`4.14 MiB`** | Headless ARM64 gateway / RPi seed binary |
| `parvault` (`x86_64-unknown-linux-musl`) | `--profile soc` | **`7.45 MiB`** | Static `x86_64` Router-SoC binary |
| `parvault-seed` (`x86_64-unknown-linux-musl`) | `--profile soc` | **`5.32 MiB`** | Static `x86_64` headless seed binary |
| `parvault:router-soc` (`deploy/Dockerfile.router-soc`) | `FROM scratch` | **`6.13 MB` compressed** (`19.6 MB` unpacked) | Verified inside `--memory=48m --memory-swap=48m` cgroup at **`8.63 MiB`** live RSS (`0` OOM kills) |

---

## 4. Reproducing All Benchmarks Locally

```bash
# 1. Run the streaming RAM (/proc/self/status VmHWM) and crypto/erasure benchmark suite
cargo run --release --bin parvault-bench -- run --payload-mib 64

# 2. Export machine-readable JSON telemetry
cargo run --release --bin parvault-bench -- run --payload-mib 64 --json

# 3. Run the 8-profile degraded network & Byzantine poisoner matrix
cargo test --release --test anonymity_and_degraded_net_tests -- --nocapture

# 4. Run the full 14-container live Docker P2P + 48 MiB cgroup Router-SoC acceptance gate
bash scripts/docker_acceptance_gate.sh
```
