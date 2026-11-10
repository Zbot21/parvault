# Changelog

All notable architectural decisions, security hardenings, and user-facing features for `parvault` (`parvault` & `parvault-seed`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [`0.2.0`] - 2026-11-09

### Added
- **Empirical Benchmark & Memory Telemetry Binary (`src/bin/parvault-bench.rs`):**
  - Added `parvault-bench` (`run` / `all` subcommands, `--payload-mib <MIB>`) measuring real wall-clock throughput and latency across `Argon2id (m=64 MiB, t=3, p=4)`, `AES-256-GCM`, dual-cipher `PqVaultMasterKey`, X-Wing `X25519 + ML-KEM-768` (`HKDF-SHA512`), `Ed25519 + ML-DSA-65`, and Reed-Solomon $GF(2^8)$ encoding/reconstruction, plus Linux `/proc/self/status` (`VmRSS`, `VmHWM`) and `getrusage(RUSAGE_SELF)` streaming memory instrumentation.
- **Live `libp2p` Network Client (`MeshClient`) with Persistent Swarm Pool & Full P2P Daemon/Seed Wiring (`src/network/client.rs`, `src/main.rs`, `src/bin/parvault-seed.rs`):**
  - Replaced local-directory simulation shortcuts with a persistent background `libp2p` `TCP + Noise XX + Yamux` `Swarm` worker connection pool (`MeshClient`), enforcing `/p2p/<PeerId>` authentication and Trust-On-First-Use (`TOFU`) `PeerId` pinning, dual Kademlia DHT (`put_record` / `get_record`) + `ZeroTrustDhtStore` replication, live RTT & `QueryPeerStatus` placement telemetry, and 2-layer post-quantum onion routing.
  - Wired `parvault file store/restore`, `parvault watch-folder`, `parvault restore-folder`, `parvault recover-from-seed`, and `parvault leave` to dial configured `--peers` / `PARVAULT_PEERS` and `--seed-addr` / `PARVAULT_SEED_ADDR` `Multiaddr`s over the network.
  - Added all 14 `MeshWireRequest` / `MeshWireResponse` variants (`HandshakeWoT`, `PutShard`, `DeleteShard`, `PorAudit`, `GetCiphertextShard`, `PutBlindedShard`, `GetBlindedShard`, `RenewBlindedLease`, `DeleteBlindedShardTombstone`, `MultiSegmentPorAudit`, `RelayPqOnionEnvelope`, `SyndicateLiteStripe`, `PutDhtEnvelope`, `GetDhtEnvelope`, `QueryPeerStatus`) to both `parvault daemon` and `parvault-seed`.
- **13-Container Docker P2P Regression & Disaster Recovery Gate (`scripts/docker_acceptance_gate.sh`, `.github/workflows/ci.yml`):**
  - Automated multi-container regression suite deploying `parvault-seed-0` + 11 `parvault daemon` containers + 1 isolated `parvault-client` container (`Mounts: []`) across an isolated Docker bridge network (`172.28.0.0/24`).
  - Exercises initial folder sync (`v1`), continuous background `watch-folder --prune-deleted` (`v2`) with remote `DeleteShard` pruning, Lite-Client `1.0x` stripe syndication + `parvault-seed-0` NAS-death failover, graceful node decommission (`parvault leave --handoff-to`), bit-rot injection & `parvault scrub` quarantine, daemon container restarts, 4-container `docker kill` + zero-local-state `recover-from-seed` (full & `--filter` selective restore), and cross-machine `file store` / `file restore`.
  - Added `test_live_libp2p_tcp_multi_daemon_network_backup_prune_and_seed_recovery` to `tests/sync_daemon_usability_and_cli_regression_tests.rs` spawning real localhost TCP `parvault-seed` and `parvault daemon` child processes during `cargo test`.

### Fixed & Hardened
- **Memory-Hard `Argon2id` (`64 MiB`), HKDF Subkey Hierarchy, BIP-39 Validation, `zeroize`, `0600` Key Files & X-Wing Hybrid KEM (`src/crypto/`):**
  - Upgraded `MasterKey::from_recovery_seed_phrase`, `PqVaultMasterKey::from_recovery_seed_phrase`, and `LocalFileKeystore` (`LocalKeystoreSealer`) passphrase sealing to use memory-hard **`Argon2id`** (`m = 64 MiB (65,536 KiB)`, `t = 3`, `p = 4`), full BIP-39 12/24-word English wordlist + SHA-256 checksum + Unicode NFKD normalization, `ZeroizeOnDrop` memory scrubbing, and `0600` atomic key-file permissions (`write_secret_file_atomic_0600`).
  - Added domain-separated HKDF-SHA256 subkey derivation on `MasterKey` (`stripe_aead_subkey`, `stripe_nonce_subkey`, `manifest_aead_subkey`, `dht_routing_subkey`, `blind_locator_subkey`, `blind_capability_subkey`, `shard_pseudonym_subkey`) and separated `Ed25519` / `X25519` sub-seeds in `NodeIdentity::from_seed`.
  - Upgraded `HybridKemKeypair::combine_hybrid_secrets` to an X-Wing style `HKDF-SHA512` combiner binding `ephem_x25519_pub || recipient_x25519_pub || SHA-256(ml_kem_ct) || SHA-256(recipient_ml_kem_ek)`.
  - Upgraded `PqRelayedShardEnvelope` to a 2-layer post-quantum onion construction (`PqInnerStorageEnvelope` + outer relay envelope) and `AnonymousQuotaVoucher::mint_ephemeral` to use unlinkable per-shard ephemeral issuer keys.
- **Owner Shard Read/Delete Authorization & Full Disk Persistence Across Restarts (`src/por/verifier.rs`, `src/storage/`, `src/network/wot.rs`):**
  - Fixed `GetCiphertextShard` owner signature verification to pass `owner_pub: [u8; 32]` explicitly and verify against the pinned `RepairGrant.owner_pubkey`.
  - Added signed owner shard deletion (`DeleteShard` / `authorize_owner_shard_delete`) so `watch-folder --prune-deleted` physically unlinks deleted files' shards on remote mesh peers.
  - Persisted `node_identity.seed` into `libp2p::identity::Keypair` on daemon/seed startup, and persisted `por_verifier_state.bin`, `wot_state.bin`, `quota_state.bin`, `voucher_nullifiers.bin` (bounded 65,536-entry FIFO), and `dht_*.bin` across restarts.
  - Fixed `MeshClient::get_dht_envelope` to query both the `libp2p` Kademlia DHT and all configured peers, returning the strictly highest `monotonic_version` record.
- **Non-Vacuous Adversarial TLA+ & Stateright Models (`specs/*.tla`, `tests/formal_verification.rs`):**
  - Rewrote `specs/ParVaultPostQuantum.tla` into a multi-actor protocol and non-deterministic single-primitive break / public-key substitution state machine (927 distinct states, 0 errors) and updated `specs/ParVaultAnonymity.tla` for 2-layer PQ onion routing and ephemeral-issuer vouchers (861 distinct states, 0 errors).

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
- **4-Layer Cryptographic Shard Anonymization (`ADR-11`):**
  - Unlinkable 256-bit `BlindedShardId` locators ($\Omega_{\text{search}} \ge 2^{224}$), per-shard `BlindedShardCapability` keys ($V_i$), single-use `AnonymousQuotaVoucher`s, and 1-hop onion relay envelopes (`src/storage/anonymity.rs`).
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
- **Internet-Grade Sync Usability, Streaming File Hashing & Sharded Documentation (`ADR-16`, `ADR-17`):**
  - Complete identity and certificate CLI workflow (`parvault identity`, `parvault issue-device-cert`, `parvault verify-device-cert`, `parvault-seed identity`, `parvault-seed issue-device-cert`, `parvault-seed verify-device-cert`, `parvault-seed status`, `parvault-seed drain-plan`, `parvault-seed scrub`) with copy-pasteable `PARVAULT-CERT-V1:...` compact tokens.
  - `.parvaultignore` exclusion patterns, dry-run folder diffing (`parvault diff-folder` / `watch-folder --dry-run`), deleted-file GC (`--prune-deleted`), selective single-file restoration (`parvault restore-folder --file <REL_PATH>`), and `--filter` glob/prefix partial restore.
  - Constant-memory 64 KiB streaming file hashing (`compute_file_sha256_streaming`), bounded 65,536-entry FIFO replay/nullifier caches, token-bucket bandwidth rate limiting (`TokenBucketRateLimiter`), and minimum free disk reserve enforcement (`min_free_disk_bytes`).
