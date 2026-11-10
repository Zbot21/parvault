# AI Agent & Systems Engineer Guide (`AGENTS.md`)

This document is the authoritative architectural, security, and verification manual for AI coding agents and human systems engineers working on **`parvault`** (library crate `parvault`, binaries `parvault`, `parvault-seed`, and `parvault-bench`).

---

## 1. System Architecture & Binary Topology

`parvault` is a zero-knowledge, post-quantum hybrid, Byzantine-resilient P2P backup and continuous folder-synchronization engine designed to run identically on high-capacity homelab servers and memory-constrained residential gateways (`prplOS` / `OpenWrt` LXC containers with a strict **`< 32 MiB` active RAM ceiling**).

### Binaries & Library Targets (`Cargo.toml`)
1. **Library Crate (`parvault` — `src/lib.rs`):**
   Embeddable Rust API exposing streaming encryption, Reed-Solomon erasure coding over $GF(2^8)$, incremental folder synchronization (`FolderSyncEngine`), `libp2p` P2P client/daemon networking (`MeshClient`), Web-of-Trust admission, Proof-of-Retrievability (`PoR`), and elastic bootstrap state machines.
2. **Client & Peer Daemon (`parvault` — `src/main.rs`):**
   Runs on user workstations, laptops, desktops, or homelab nodes that own plaintext folders (`watch-folder`, `diff-folder`, `list-snapshot`, `restore-folder`, `recover-from-seed`, `file store`, `file restore`, `identity`, `issue-device-cert`, `verify-device-cert`, `scrub`, `leave`, `status`, `daemon start`). Holds the user's client-side `MasterKey` / `PqVaultMasterKey`.
3. **Standalone Zero-Trust Seed & Redundancy Server (`parvault-seed` — `src/bin/parvault-seed.rs`):**
   Runs on headless 24/7 hardware (NAS, Raspberry Pi, Unraid/TrueNAS, VPS) in two strictly zero-plaintext modes (`holds_own_plaintext_files == false`):
   - `--mode homelab-vault` (`SeedServerMode::HomelabRedundancyVault`): Authenticates the owner's personal devices via post-quantum `PersonalDeviceCert`s (`0.0x` self-quota tax), syndicates Lite-Client `1.0x` stripes across mesh peers, and answers network PoR audits 24/7 to earn `TrustLevel::HighUptimeAnchor` (`16-of-20` `EarnedHomelabAnchorPool`, `5.0x` reciprocity multiplier).
   - `--mode public-bootstrap` (`SeedServerMode::PublicNetworkBootstrapper`): Stateless `FoundationSeedAnchor` that ingests only anonymized `.bshard` leases during cold-start (`1..19` peers) and automatically drains to `0` shards as verified organic community peers join.
4. **Empirical Benchmark & Memory Telemetry Runner (`parvault-bench` — `src/bin/parvault-bench.rs`):**
   Executes real wall-clock benchmarks (`Argon2id`, `AES-256-GCM`, `PqVaultMasterKey`, `X25519 + ML-KEM-768`, `Ed25519 + ML-DSA-65`, Reed-Solomon $GF(2^8)$) and Linux `/proc/self/status` (`VmRSS`, `VmHWM`) + `getrusage(RUSAGE_SELF)` streaming memory measurements.

---

## 2. Module-by-Module Map of `src/`

| Module Path | Core Types & Responsibilities | Governing ADRs |
| :--- | :--- | :--- |
| `src/config.rs` | `Cli`, `Commands`, `NodeConfig`, `ErasureTier` (`Consumer` `10/20`, `Mixed` `16/24`, `Homelab` `16/20`, `Relay` `20/24`), token-bucket bandwidth rate-limiting config (`max_upload_mbps`, `max_download_mbps`), and minimum free disk reserve (`min_free_disk_bytes`). | `ADR-01`, `ADR-07`, `ADR-16`, `ADR-17` |
| `src/crypto/aes.rs` | `encrypt_stripe`, `decrypt_stripe`, `encrypt_manifest`, `decrypt_manifest`, `pad_plaintext_iso_bucket`, `unpad_plaintext_iso_bucket`, `derive_unlinkable_shard_pseudonym`, `compute_sha256`, and streaming 64 KiB file SHA-256 (`compute_file_sha256_streaming`) using domain-separated HKDF-SHA256 subkeys (`stripe_aead_subkey`, `stripe_nonce_subkey`, `manifest_aead_subkey`, `dht_routing_subkey`, `shard_pseudonym_subkey`). | `ADR-01`, `ADR-09`, `ADR-16` |
| `src/crypto/keys.rs` | `MasterKey` (256-bit root key + HKDF-SHA256 subkey hierarchy + deterministic memory-hard `Argon2id` `m=64 MiB, t=3, p=4` + BIP-39 12/24-word checksum/NFKD validation in `from_recovery_seed_phrase`, `ZeroizeOnDrop`), `NodeIdentity` (domain-separated `Ed25519` + `X25519` derivation in `from_seed`, persistent `0600` `write_secret_file_atomic_0600`), and `LocalFileKeystore` (`LocalKeystoreSealer` passphrase/local key sealing). | `ADR-01`, `ADR-02`, `ADR-15` |
| `src/crypto/pqc.rs` | Post-Quantum Hybrid Cryptography suite: `HybridKemKeypair` (`X25519 + NIST FIPS 203 ML-KEM-768` with X-Wing `HKDF-SHA512` public-key & ciphertext binding), `HybridPqSigningKeypair` (`Ed25519 + NIST FIPS 204 ML-DSA-65`), `PqVaultMasterKey` (dual-cipher `AES-256-GCM` + `ChaCha20-Poly1305` cascade for cipher-diversity defense-in-depth and NIST Category 5 128-bit PQ Grover floor), and 2-layer `PqRelayedShardEnvelope` (`PqInnerStorageEnvelope` + outer relay layer). | `ADR-12`, `ADR-15` |
| `src/sharding/reed_solomon.rs` | `encode_ciphertext_stripe`, `reconstruct_ciphertext_stripe`, `reconstruct_all_shards`, and `reconstruct_zero_trust_with_quarantine` (pre-decoding leaf SHA-256 + `MerkleProof` screening over $GF(2^8)$ before Vandermonde matrix inversion). | `ADR-01`, `ADR-09` |
| `src/sharding/merkle.rs` | `MerkleTree`, `MerkleProof`, `hash_shard_leaf`, `compute_file_merkle_root`. Domain-separated leaf (`0x00`) and internal node (`0x01`) SHA-256 hashing. | `ADR-01`, `ADR-09` |
| `src/por/challenger.rs` | `PorChallenge`, `MultiSegmentPorChallenge`, `generate_por_challenge`, `generate_multi_segment_por_challenge`, `compute_salted_commitment`, `compute_multi_salted_commitment` (8-stratum scatter-gather audits + RTT ceiling). | `ADR-03`, `ADR-09` |
| `src/por/verifier.rs` | `PorVerifierEngine` (stateless RAM HMAC pre-check before disk I/O + bounded 65,536-entry FIFO replay-cache eviction + disk persistence `por_verifier_state.bin`), `RepairGrant`, `WitnessFailureReceipt`, `sign_owner_shard_read_token`, `sign_owner_shard_delete_token`, `authorize_owner_shard_delete`, and `EgressWithholdingEvidence`. | `ADR-03`, `ADR-04`, `ADR-09`, `ADR-15`, `ADR-16` |
| `src/network/transport.rs` | `build_mesh_swarm` (daemon swarm with mDNS enabled) and `build_mesh_client_swarm` (client RPC swarm with mDNS disabled) constructing the primary `libp2p` **TCP + Noise XX + Yamux** stack with optional secondary QUIC listener (`enable_quic`). | `ADR-08` |
| `src/network/behaviour.rs` | `MeshNetworkBehaviour` (`Kademlia`, `Gossipsub`, `Toggle<mDNS>`, `Identify`, `Ping`, `RequestResponse`), 14-variant `MeshWireRequest` / `MeshWireResponse` (`QueryPeerStatus` + 13 storage/DHT/relay RPCs), `BincodeWireCodec` (bounded `MAX_WIRE_FRAME_BYTES = 32 MiB`, 64 KiB initial reservation, `with_limit` pre-auth framing), `PlacementEngine` (70% Intra-ASN / 30% Cross-Region split), and `TokenBucketRateLimiter`. | `ADR-06`, `ADR-08`, `ADR-15`, `ADR-16` |
| `src/network/client.rs` | `MeshClient`, `parse_peer_multiaddr`, `is_network_peer_addr`. Maintains a persistent background `Swarm` worker connection pool, enforces `/p2p/<PeerId>` verification & TOFU `PeerId` pinning, dual Kademlia DHT + `ZeroTrustDhtStore` replication, live RTT & `QueryPeerStatus` telemetry in `PlacementEngine`, and 2-layer PQ onion relay routing. | `ADR-06`, `ADR-08`, `ADR-15`, `ADR-17` |
| `src/network/wot.rs` | `WebOfTrustRegistry` (persisted at `wot_state.bin`), `DelegationChain`, `InvitationHop`, `SlashingEvidence`, `SlashingReason`. Enforces bounded-depth Ed25519 admission and 3-strike subtree slashing. | `ADR-05`, `ADR-09`, `ADR-15` |
| `src/storage/block_store.rs` | `BlockStore`, `FileManifest`, `StripeManifestEntry`, `SignedDhtManifestEnvelope`, `ZeroTrustDhtStore` (`dht_*.bin`), `BlindedShardLeaseManager` (`blinded_leases.bin`). Handles 16 MiB streaming file I/O, network shard distribution/restoration via `MeshClient`, crash-safe atomic writes (`sync_all` + `rename`), lease sweeps, `graceful_leave_and_redistribute`, and `scrub_all_shards`. | `ADR-01`, `ADR-02`, `ADR-09`, `ADR-13`, `ADR-15`, `ADR-16` |
| `src/storage/quota.rs` | `QuotaManager` (persisted at `quota_state.bin`), `PeerCreditAccount`, `TrustLevel` (`UntrustedProbationary`, `VerifiedNeighbor`, `HighUptimeAnchor`, `SlashedQuarantined`), tiered `/24` subnet caps (`1`, `2`, `4`, `0`), LRU eviction quota release, and `4x` write-amplification cap. | `ADR-07`, `ADR-09`, `ADR-10`, `ADR-15` |
| `src/storage/anonymity.rs` | 4-Layer Shard Anonymization: `BlindedShardId` (256-bit keyed HMAC locator under `blind_locator_subkey`), `BlindedShardCapability` ($V_i$ per-shard PoR/read key under `blind_capability_subkey` with $\pm 30\text{ s}$ NTP skew tolerance), `AnonymousQuotaVoucher` (ephemeral per-shard issuer via `mint_ephemeral`), `VoucherNullifierLedger` (bounded 65,536-entry FIFO persisted at `voucher_nullifiers.bin`), and `RelayedShardEnvelope`. | `ADR-11`, `ADR-15`, `ADR-16` |
| `src/bootstrap.rs` | `EarnedStanding`, `ElasticBootstrapEngine`, `PersonalDeviceCert` (including compact `PARVAULT-CERT-V1:` token encoding), `BlindedShardTombstone` (generation-scoped), `ZeroTrustSeedServer`, `CorrelatedOutageController`, and `/32` IPv6 + RFC 6598 CGNAT Sybil subnet normalization. | `ADR-13`, `ADR-14`, `ADR-15`, `ADR-16`, `ADR-17` |
| `src/sync.rs` | `FolderSyncEngine`, `FolderSnapshotManifest`, `EncryptedVaultCatalogEnvelope`, `.parvaultignore` matcher (`ParvaultIgnore`), `FolderSyncDiff` (`diff_folder`), `prune_deleted_file_shards` (local + remote `DeleteShard` GC), selective restore (`restore_single_file`, `restore_selective_subset`), and zero-local-state seed recovery (`recover_folder_from_seed_phrase`). | `ADR-10`, `ADR-15`, `ADR-16`, `ADR-17` |
| `src/telemetry.rs` | `AnonymousTelemetryBeacon` (rotating epoch nullifier + Hashcash PoW + power-of-two GiB bucketing capped at 64 TiB) and `NetworkCensusAggregator` (Tukey IQR outlier trimming + capture-recapture population estimate). | `ADR-14`, `ADR-15` |

---

## 3. Seven Non-Negotiable Zero-Trust & Memory-Safety Rules

Every code change or PR **must** preserve these 7 invariants:

1. **Encrypt-Before-Shard Ordering (`ADR-01` / `ADR-12`):**
   Plaintext must always be padded (`pad_plaintext_iso_bucket`) and encrypted client-side with `AES-256-GCM` (`MasterKey::stripe_aead_subkey`) or dual-cipher cascaded `PqVaultMasterKey` (`AES-256-GCM` + `ChaCha20-Poly1305`) **before** Reed-Solomon encoding over $GF(2^8)$. Never pass unencrypted bytes into `sharding::reed_solomon`.
2. **Bounded `< 32 MiB` Streaming I/O — Zero Full-File `fs::read` (`ADR-01` / `ADR-16`):**
   Never call `std::fs::read` on user backup files or restored staging files. Always use `compute_file_sha256_streaming` (64 KiB buffer) and `store_file_streaming` / `restore_file_streaming` (16 MiB stripes) so multi-gigabyte VM/NAS archives never exceed the 32 MiB gateway RAM ceiling.
3. **Pre-Authentication Wire Allocation Bounds (`ADR-15` / `ADR-16`):**
   All network deserialization in `BincodeWireCodec` must use `bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_limit(buf.len() as u64)` after enforcing `MAX_WIRE_FRAME_BYTES` (`32 MiB`, with 64 KiB initial read reservation against Slowloris attacks), and all replay/nullifier caches (`PorVerifierEngine`, `VoucherNullifierLedger`) must remain strictly bounded in capacity (`65,536` entries) with FIFO eviction.
4. **Crash-Safe Atomic Persistence (`ADR-15`):**
   All writes of `.shard`, `.bshard`, `.manifest.bin`, and `blinded_leases.bin` must go through `BlockStore::atomic_write_file` (write to `.tmp.<nonce>`, call `File::sync_all()`, and atomically `fs::rename`), and disk I/O must succeed *before* consuming a `BearerQuotaVoucher` nullifier.
5. **Strict Path-Traversal & Symlink Blocking (`ADR-15`):**
   Every file restoration path in `FolderSyncEngine` must be validated through `FolderSyncEngine::resolve_safe_restore_path`, which rejects `..` (`ParentDir`), `/` (`RootDir`), Windows drive/UNC prefixes (`Prefix`), `\`, `:`, null bytes, and symlink targets, and verifies the restored file's streaming SHA-256 on a `.parvault_restore_staging` file before atomic placement.
6. **Earned Standing & `VerifiedNeighbor` Seed-Drain Gating (`ADR-13` / `ADR-15`):**
   Nodes must never bypass `EarnedStanding::evaluate` to claim `16-of-20` Homelab standing without $\ge 200$ PoR passes at $\ge 99.8\%$ SLA, and `ElasticBootstrapEngine::plan_seed_anchor_drain` must never drain Foundation Seed Anchor shards onto organic peers below `TrustLevel::VerifiedNeighbor` ($\ge 50$ PoR passes).
7. **No Unauthenticated Framing Slashes (`ADR-15`):**
   Never slash or increment failure counters on a leaf `NodeIdentity` inside an unverified `HandshakeWoT` request (`handle_wire_request`), as an attacker could otherwise forge 3 bit-flipped handshakes carrying an honest node's public key to frame and quarantine that node's Web-of-Trust branch.

---

## 4. Build, Test, Multi-Container Docker & Formal Verification Commands

### Rust Unit, Integration, Mathematical & Red-Team Suites
```bash
# Check formatting and lints
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

# Run all 67 unit, integration, Stateright, TLA+ TLC, and live localhost TCP P2P tests
cargo test --release

# Run the standalone Zero-Trust Seed Server built-in self-test
cargo run --release --bin parvault-seed -- self-test

# Run the empirical cryptography, Reed-Solomon, and /proc/self/status memory benchmark binary
cargo run --release --bin parvault-bench -- run --payload-mib 64

# Run the 13-container Docker P2P regression & disaster recovery acceptance gate
bash scripts/docker_acceptance_gate.sh
```

### Static `musl` Cross-Compilation (`x86_64` & `aarch64`)
```bash
# x86_64 static musl build (Homelab / NAS / VPS)
cargo build --release --target x86_64-unknown-linux-musl --bin parvault --bin parvault-seed

# ARM64 static musl build (Raspberry Pi / OpenWrt / prplOS LXC gateway)
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-musl --bin parvault --bin parvault-seed
```

### TLA+ TLC Formal Model Checking (`specs/`)
All 6 TLA+ specifications in `specs/` must complete with **0 errors**:
```bash
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultProtocol.cfg specs/ParVaultProtocol.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultConfidentialityAndTrust.cfg specs/ParVaultConfidentialityAndTrust.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultAnonymity.cfg specs/ParVaultAnonymity.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultPostQuantum.cfg specs/ParVaultPostQuantum.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultBootstrapAndEarnedTier.cfg specs/ParVaultBootstrapAndEarnedTier.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultLiteClientAndSeedFailover.cfg specs/ParVaultLiteClientAndSeedFailover.tla
```
- **Automatic TLA+ Execution in `cargo test` (`tests/tla_formal_proofs_integration.rs`):** Setting `TLA2TOOLS_JAR=/path/to/tla2tools.jar` (configured automatically in `.github/workflows/ci.yml`) runs all **6** TLA+ formal specifications directly inside `cargo test --release`.
