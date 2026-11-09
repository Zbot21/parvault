# Changelog

All notable architectural decisions, security hardenings, and user-facing features for `parvault` (`parvault` & `parvault-seed`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [`0.1.0`] - 2026-11-09

### Added
- **Streaming 16 MiB Zero-Knowledge Encryption & Reed-Solomon Engine (`ADR-01`, `ADR-02`):**
  - Client-side `AES-256-GCM` authenticated encryption with deterministic per-stripe HKDF-SHA256 nonces (`src/crypto/aes.rs`, `src/crypto/keys.rs`).
  - Reed-Solomon $GF(2^8)$ erasure coding (`10-of-20` Consumer, `16-of-24` Mixed, `16-of-20` Homelab, `20-of-24` Relay) with per-stripe SHA-256 Merkle trees (`src/sharding/`).
  - Encrypted Kademlia DHT manifest envelopes keyed by $\text{HMAC-SHA256}(K_{\text{user}}, \dots)$ (`src/storage/block_store.rs`).
- **Stateless Proof-of-Retrievability (`PoR`) & Offline Witness Repair (`ADR-03`, `ADR-04`):**
  - Sub-300ms stateless RAM HMAC challenge pre-screening and salted SHA-256 commitments (`src/por/`).
  - Zero-knowledge ciphertext repair in $GF(2^8)$ gated by owner-signed `RepairGrant` + $\ge 2$ co-signed `WitnessFailureReceipt`s.
- **Web-of-Trust Admission, 70/30 Locality Placement & Reciprocity Quotas (`ADR-05` – `ADR-08`):**
  - Bounded-depth Ed25519 `DelegationChain` verification with 3-strike Gossipsub subtree slashing (`src/network/wot.rs`).
  - Primary `libp2p` **TCP + Noise XX + Yamux** transport stack with optional secondary QUIC listener (`src/network/transport.rs`).
  - Hybrid 70% Intra-ASN ($\le 5\text{ ms}$ RTT) / 30% Cross-Region `PlacementEngine` and tier-weighted byte-hour reciprocity `QuotaManager`.
- **Zero-Trust Adversarial Hardening & Dynamic Uptime Trust Tiers (`ADR-09`, `ADR-10`):**
  - Pre-decoding SHA-256 + `MerkleProof` quarantine (`reconstruct_zero_trust_with_quarantine`), 8-stratum scatter-gather PoR (`MultiSegmentPorChallenge`), monotonic `SignedDhtManifestEnvelope`, egress-withholding credit slashing, and ISO power-of-two plaintext padding.
  - Dynamic Uptime Trust Ladder (`UntrustedProbationary` $\to$ `VerifiedNeighbor` $\to$ `HighUptimeAnchor` $\to$ `SlashedQuarantined`) with `/24` subnet caps (`1`, `2`, `4`, `0`) and incremental `FolderSyncEngine`.
- **4-Layer Cryptographic Shard Anonymization & Degraded-Network Hedged Recovery (`ADR-11`):**
  - Unlinkable 256-bit `BlindedShardId` locators ($\Omega_{\text{search}} \ge 2^{224}$), per-shard `BlindedShardCapability` keys ($V_i$), single-use `AnonymousQuotaVoucher`s, and 1-hop onion relay envelopes (`src/storage/anonymity.rs`).
  - Hedged parallel $K$-of-$N$ shard recovery validated across the 8-profile degradation matrix (`parvault benchmark-matrix`, `src/bench_matrix.rs`).
- **Post-Quantum Hybrid Cryptography (`ADR-12`):**
  - `HybridKemKeypair` combining classical `X25519` with **NIST FIPS 203 `ML-KEM-768`** via `HKDF-SHA512`.
  - `HybridPqSigningKeypair` combining classical `Ed25519` with **NIST FIPS 204 `ML-DSA-65`**.
  - 512-bit Grover-resistant cascaded AEAD (`PqVaultMasterKey`) and `PqRelayedShardEnvelope` (`src/crypto/pqc.rs`).
- **Elastic Day-1-to-10,000-User Bootstrap & Dedicated `parvault-seed` Server (`ADR-13`, `ADR-14`):**
  - Cryptographically earned tier progression (`EarnedStanding::evaluate`), post-quantum `PersonalDeviceCert` Day-1 rings (`2-of-3`), `FoundationSeedAnchor` auto-drain, zero-knowledge elastic ciphertext re-sharding (`reshard_ciphertext_stripe_elastic`), and `/24` Sybil-damped standby uptime mining (`src/bootstrap.rs`).
  - Standalone zero-plaintext `parvault-seed` server binary (`homelab-vault` and `public-bootstrap` modes) plus zero-knowledge `AnonymousTelemetryBeacon` and `NetworkCensusAggregator` (`src/telemetry.rs`).
- **Multi-Domain Red-Team Hardening & "House Fire" Seed-Phrase Recovery (`ADR-15`):**
  - Zero-local-state folder recovery from a 24-word recovery seed phrase + `vault_namespace` alone (`MasterKey::from_recovery_seed_phrase`, `EncryptedVaultCatalogEnvelope`, `parvault recover-from-seed`).
  - Capability pubkey pinning, $\pm 30\text{ s}$ NTP skew tolerance, generation-scoped `BlindedShardTombstone`s, `/32` IPv6 + RFC 6598 CGNAT fairness, $\ge 3$-anchor `SignedWeatherAttestation` quorum, bounded `BincodeWireCodec` (`with_limit`), Hashcash PoW + IQR telemetry trimming, crash-safe write-temp-`fsync`-rename, `resolve_safe_restore_path` traversal blocking, and `BlockStore::scrub_all_shards`.
- **Internet-Grade Sync Usability, Streaming File Hashing & Sharded Documentation (`ADR-16`):**
  - Complete identity and certificate CLI workflow (`parvault identity`, `parvault issue-device-cert`, `parvault verify-device-cert`, `parvault-seed identity`, `parvault-seed issue-device-cert`, `parvault-seed verify-device-cert`, `parvault-seed status`, `parvault-seed drain-plan`, `parvault-seed scrub`) with copy-pasteable `PARVAULT-CERT-V1:...` compact tokens.
  - `.parvaultignore` exclusion patterns (default ignores for `.git`, `node_modules`, `target`, `.DS_Store`, `Thumbs.db`, `*.tmp`, `*.swp` + custom globs/negations), dry-run folder diffing (`parvault diff-folder` / `watch-folder --dry-run`), deleted-file GC (`--prune-deleted`), and selective single-file restoration (`parvault restore-folder --file <REL_PATH>`).
  - Constant-memory 64 KiB streaming file hashing (`compute_file_sha256_streaming`) eliminating full-file `fs::read` allocations in `FolderSyncEngine`, bounded 65,536-entry FIFO replay/nullifier caches, token-bucket bandwidth rate limiting (`TokenBucketRateLimiter`), and minimum free disk reserve enforcement (`min_free_disk_bytes`).
  - Full verbatim `AGPL-3.0-only` `LICENSE` and persona-sharded documentation (`README.md`, `QUICKSTART.md`, `docs/USER_AND_CLI_GUIDE.md`, `docs/SECURITY_AND_CRYPTOGRAPHY.md`, `docs/ADR.md`, `AGENTS.md`, `CONTRIBUTING.md`).
