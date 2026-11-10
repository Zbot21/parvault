# Security Architecture, Cryptographic Proofs & Formal Verification (`SECURITY_AND_CRYPTOGRAPHY.md`)

This document details the mathematical, cryptographic, game-theoretic, and formal-verification foundations of **`parvault`** (`parvault` and `parvault-seed`), covering `ADR-01` through `ADR-17`.

---

## Table of Contents
1. [Zero-Knowledge Streaming Pipeline & Encrypt-Before-Shard Invariant (`ADR-01`, `ADR-16`)](#1-zero-knowledge-streaming-pipeline--encrypt-before-shard-invariant-adr-01-adr-16)
2. [Dynamic Uptime Trust Ladder & Zero-Knowledge Collusion Immunity (`ADR-10`)](#2-dynamic-uptime-trust-ladder--zero-knowledge-collusion-immunity-adr-10)
3. [4-Layer Cryptographic Shard Anonymization & $\ge 2^{224}$ Combinatorial Wall (`ADR-11`)](#3-4-layer-cryptographic-shard-anonymization--ge-2224-combinatorial-wall-adr-11)
4. [Post-Quantum Hybrid Cryptography (`ADR-12` — Harvest-Now, Decrypt-Later Immunity)](#4-post-quantum-hybrid-cryptography-adr-12--harvest-now-decrypt-later-immunity)
5. [Elastic Bootstrap, Earned Standing & Correlated Outage Survival (`ADR-13` – `ADR-15`)](#5-elastic-bootstrap-earned-standing--correlated-outage-survival-adr-13--adr-15)
6. [Multi-Domain Red-Team Hardening Summary (`ADR-15` – `ADR-17`)](#6-multi-domain-red-team-hardening-summary-adr-15--adr-17)
7. [Machine-Checked Formal Verification & Test Suite Matrix](#7-machine-checked-formal-verification--test-suite-matrix)
8. [Live Multi-Container Docker P2P Regression Report (`v0.2.0`)](#8-live-multi-container-docker-p2p-regression-report-v020)

---

## 1. Zero-Knowledge Streaming Pipeline & Encrypt-Before-Shard Invariant (`ADR-01`, `ADR-16`)

Every file or incremental folder delta is processed in bounded **16 MiB streaming stripes** (with 64 KiB streaming SHA-256 content checks in `compute_file_sha256_streaming`) to guarantee a **`< 32 MiB` resident RAM footprint** even on constrained `prplOS` / `OpenWrt` LXC gateways:

1. **ISO/IEC 7816-4 Power-of-Two Bucket Padding (`pad_plaintext_iso_bucket`):**
   Eliminates exact file-size fingerprinting prior to encryption.
2. **Client-Side Authenticated Encryption (`encrypt_stripe` & `PqVaultMasterKey::encrypt_stripe_cascaded`):**
   Derives a deterministic, unique 96-bit nonce per stripe via $\text{HKDF-SHA256}(K_{\text{user}}, \text{FileSalt} \parallel \text{StripeIdx})$ using the 256-bit client-only `MasterKey` $K_{\text{user}}$ (and 512-bit cascaded `PqVaultMasterKey` combining inner `AES-256-GCM` with outer `ChaCha20-Poly1305`).
3. **Reed-Solomon $GF(2^8)$ Erasure Coding (`encode_ciphertext_stripe`):**
   Splits authenticated ciphertext into $K$ data shards and $M$ parity shards ($N = K + M$) over the finite field $GF(2^8)$ with primitive polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (`0x11d`) and builds a domain-separated SHA-256 Merkle tree (`0x00` leaf prefix, `0x01` internal node prefix).
4. **Pre-Decoding Merkle Quarantine (`reconstruct_zero_trust_with_quarantine`):**
   Before any shard enters the $GF(2^8)$ Vandermonde matrix inversion during recovery or witness repair, its leaf SHA-256 and `MerkleProof` are verified. Poisoned shards from Byzantine peers are immediately quarantined and their senders slashed in `WebOfTrustRegistry`.

---

## 2. Dynamic Uptime Trust Ladder & Zero-Knowledge Collusion Immunity (`ADR-10`)

Rather than trusting static peer claims, `parvault` enforces a cryptographically audited **Dynamic Uptime Trust Ladder** (`TrustLevel`, `src/storage/quota.rs`):

| Dynamic Trust Tier | Promotion / Entry Criteria | Max Shards per `/24` Subnet | Reciprocity Quota Multiplier | Security & Economic Role |
| :--- | :--- | :---: | :---: | :--- |
| **`UntrustedProbationary`** | Newly invited via Ed25519 Web-of-Trust (`< 50` consecutive PoR passes) | **1 shard** | **$1.0\times$** | Strict Sybil containment for unproven residential peers |
| **`VerifiedNeighbor`** | $\ge 50$ consecutive PoR passes & $\ge 98.0\%$ rolling SLA | **2 shards** | **$2.5\times$** | Standard neighborhood gateway tier; minimum standing to receive drained seed shards |
| **`HighUptimeAnchor`** | $\ge 200$ consecutive PoR passes & $\ge 99.5\%$–$99.8\%$ 30-day Homelab SLA | **4 shards** | **$5.0\times$** | High-reliability backbone anchor ($80\%$ net efficiency pool) |
| **`SlashedQuarantined`** | Any cryptographic fault (poisoned Merkle shard, forged WoT hop, or confirmed egress withholding) | **0 shards** | **$0.0\times$ (100% Credit Burn)** | Immediate Gossipsub quarantine + parent inviter slash penalty |

### Proof of Zero-Knowledge Confidentiality Under Subnet Collusion ($4 \ll K = 16$)
1. **Bounded Algebraic Concentration:** Even if an adversary controls an entire `HighUptimeAnchor` `/24` subnet and all nodes on that subnet collude, the placement engine caps the subnet at **at most 4 shards** per stripe. Under $16\text{-of-}20$ (or $10\text{-of-}20$) Reed-Solomon erasure coding over $GF(2^8)$, any subset of $< K$ shards leaves the remaining $K - 4$ polynomial coefficients underdetermined.
2. **Encrypt-Then-Shard Ordering:** Reed-Solomon encoding operates strictly on **authenticated AES-256-GCM ciphertext**. Even a global passive adversary who intercepts all $N = 20$ shards on the wire (`adversaryShards = 20`) possesses zero knowledge of the client master key $K_{\text{user}}$ (`hasMasterKey = FALSE`), which never leaves the user's device.

---

## 3. 4-Layer Cryptographic Shard Anonymization & $\ge 2^{224}$ Combinatorial Wall (`ADR-11`)

To prevent even a global coalition of storage nodes from grouping shards into a stripe, linking PoR audit sessions, correlating reciprocity ledger debits, or observing the uploader's IP/`PeerId`, `src/storage/anonymity.rs` implements a **4-Layer Cryptographic Shard Anonymization Architecture** (formally verified in [`specs/ParVaultAnonymity.tla`](../specs/ParVaultAnonymity.tla)):

| Anonymization Layer | Cryptographic Mechanism | Correlation Vector Eliminated | Formal / Combinatorial Guarantee |
| :--- | :--- | :--- | :--- |
| **Layer 1: Blinded Shard Locators (`BlindedShardId`)** | $\text{Locator}_i = \text{HMAC-SHA256}(K_{\text{user}}, \text{"parvault-blinded-locator-v1:"} \parallel \text{StripeRoot} \parallel \text{ShardIdx} \parallel \text{PayloadHash}_i)$ | Removes `stripe_merkle_root`, `shard_index` ($0..19$), and sibling Merkle hashes from stored `.bshard` files | Combinatorial grouping wall: $\binom{M}{K} \frac{N!}{(N-K)!} \approx 2^{224}$ across a neighborhood pool ($M \ge 8,000$ shards, $K=16, N=20$) |
| **Layer 2: Per-Shard PoR Capability Keys ($V_i$)** | `BlindedShardCapability::derive_keypair(&master_key, &locator)` | Eliminates shared stripe-wide $K_{\text{session}}$ across storage peers; pins `capability_pubkey` at upload time (`ADR-15`) | Storage node $i$ holds only $(\text{Locator}_i, \text{PubKey}_i, \text{Ciphertext}_i)$; zero cross-shard PoR key linkability |
| **Layer 3: Unlinkable Bearer Quota Vouchers (`AnonymousQuotaVoucher`)** | Signed one-time bearer token (`voucher_nonce`, `max_bytes`, `issuer_signature`) redeemed into disk-persisted, bounded `VoucherNullifierLedger` | Decouples byte-hour quota authorization from `uploader_peer_id` | Strict 1-to-1 voucher conservation (`Cardinality(spentNullifiers) = anonymousShardsStored`) with zero double-spend |
| **Layer 4: 1-Hop Onion Relay Dispatch (`RelayedShardEnvelope` / `PqRelayedShardEnvelope`)** | Upload wrapped in encrypted 1-hop relay envelope (`X25519 + ML-KEM-768`) forwarded via an intermediate `RelayNode` | Hides the vault owner's IP address and `PeerId` from the destination storage node | Storage node strictly observes `observedSender = "RelayNode"` (`observedSender /= "OwnerNode"`) |

### Combinatorial Hardness of Blinded Pool Reconstruction
Without the client-only master key $K_{\text{user}}$, every 256-bit $\text{Locator}_i$ is computationally indistinguishable from a uniform random bitstring. Even if an adversary colludes across every storage node in a neighborhood pool holding $M$ total blinded shards, identifying which $K = 16$ shards belong to a single stripe and ordering them into positions $0 \dots K-1$ requires searching:

$$\Omega_{\text{search}} = \binom{M}{K} \times \frac{N!}{(N - K)!} \approx 2^{224} \quad (\text{for } M \ge 8,000,\; K = 16,\; N = 20)$$

---

## 4. Post-Quantum Hybrid Cryptography (`ADR-12` — Harvest-Now, Decrypt-Later Immunity)

To protect long-lived backup shards and P2P envelopes against **Harvest-Now, Decrypt-Later (HNDL)** adversaries equipped with a future **Cryptographically Relevant Quantum Computer (CRQC)** running **Shor's Algorithm** and **Grover's Algorithm**, `src/crypto/pqc.rs` implements a **Post-Quantum Hybrid Cryptography Suite** (formally verified in [`specs/ParVaultPostQuantum.tla`](../specs/ParVaultPostQuantum.tla)):

| Cryptographic Subsystem | Classical Primitive | Post-Quantum NIST Standard | Hybrid Combiner & Construction | Quantum Threat Mitigated |
| :--- | :--- | :--- | :--- | :--- |
| **Hybrid Key Encapsulation (`HybridKemKeypair`)** | **X25519** ECDH (`32 B` public key) | **ML-KEM-768** (`NIST FIPS 203`, Module-LWE, `1,184 B` ek, `1,088 B` ct) | $K_{\text{hybrid}} = \text{HKDF-SHA512}(\text{ss}_{\text{X25519}} \parallel \text{ss}_{\text{ML-KEM-768}}, \text{ctx})$ | **Shor's Algorithm** on ECDLP; session key remains secret unless *both* X25519 and ML-KEM-768 are broken |
| **Hybrid Digital Signatures (`HybridPqSigningKeypair`)** | **Ed25519** (`32 B` vk, `64 B` sig) | **ML-DSA-65** (`NIST FIPS 204`, Module-LWE/SIS, `1,952 B` vk, `3,309 B` sig) | Composite dual verification (`Ed25519::verify` $\wedge$ `ML-DSA-65::verify`) | **Shor's Algorithm** signature forgery on `PersonalDeviceCert`s, `RepairGrant`s, and `PqSignedDhtManifestEnvelope`s |
| **Grover-Resistant Vault Encryption (`PqVaultMasterKey`)** | **AES-256-GCM** (`256-bit` inner) + **ChaCha20-Poly1305** (`256-bit` outer) | **512-Bit Root Key** ($K_{\text{outer}} \parallel K_{\text{inner}}$) via **Argon2id + HKDF-SHA512** | Cascaded dual-cipher AEAD encryption (inner `AES-256-GCM` pass under $K_{\text{inner}}$, outer `ChaCha20-Poly1305` pass under $K_{\text{outer}}$) with independent HKDF-SHA512 nonces | **Grover's Algorithm** $\mathcal{O}(2^{n/2})$ quadratic search speedup ($512 \rightarrow 256\text{ bits}$ effective post-quantum security) + cipher diversity |
| **Post-Quantum Onion Envelopes (`PqRelayedShardEnvelope`)** | **X25519** ephemeral ECDH | **ML-KEM-768** (`1,088 B` ct) + `AES-256-GCM` | 1-hop onion relay sealed under `HybridKemCiphertext` (`X25519 + ML-KEM-768`) | Prevents HNDL quantum decryption of relay hops and telemetry beacons |

---

## 5. Elastic Bootstrap, Earned Standing & Correlated Outage Survival (`ADR-13` – `ADR-15`)

`src/bootstrap.rs` (formally verified in [`specs/ParVaultBootstrapAndEarnedTier.tla`](../specs/ParVaultBootstrapAndEarnedTier.tla)) enforces **Earned Tier Progression** (`EarnedStanding::evaluate`) and protects honest nodes during regional ISP or power blackouts:

| Earned Standing (`EarnedStanding`) | Reachable Topology & PoR SLA Requirement | Reed-Solomon $(K, M, N)$ | Reciprocity Expansion Tax | `/24` Fault-Domain Cap ($\le N - K$) |
| :--- | :--- | :---: | :---: | :---: |
| **`SoloPersonalVault` / `PersonalDeviceRing`** | Day 1 (`0` external peers; `1` or $\ge 2$ devices with `PersonalDeviceCert`) | **`2-of-3`** (`K=2, M=1`) | **`0.00x`** (Self-hosted ring) | `1 shard` |
| **`BuddyMicroCluster`** | Small friend/neighborhood co-op ($1 \le P_{\text{external}} < 6$) | **`3-of-5`** (`K=3, M=2`) | **`1.67x`** (`60.0%` efficiency) | `2 shards` |
| **`ProbationaryConsumerPool`** | Mandatory entry pool for unproven nodes ($P_{\text{external}} \ge 6$, `< 50` PoR passes) | **`10-of-20`** (`K=10, M=10`) | **`2.00x`** (`50.0%` efficiency) | `4 shards` |
| **`EarnedVerifiedMixedPool`** | Earned `VerifiedNeighbor` ($\ge 50$ PoR passes, $\ge 98.0\%$ SLA, $P \ge 24$) | **`16-of-24`** (`K=16, M=8`) | **`1.50x`** (`66.7%` efficiency) | `4 shards` |
| **`EarnedHomelabAnchorPool`** | Earned `HighUptimeAnchor` ($\ge 200$ PoR passes, $\ge 99.8\%$ SLA, $P \ge 20$) | **`16-of-20`** (`K=16, M=4`) | **`1.25x`** (`80.0%` efficiency) | `4 shards` |

### Correlated Regional ISP Outage & Weather-Quorum Protection (`CorrelatedOutageController`)
- Because **70%** of a stripe's shards are placed intra-ASN ($\le 5\text{ ms}$) and **30%** cross-region (`ADR-06`), combined with a strict $\le 4$ shards per `/24` fault-domain cap, a single `/24` router failure never exceeds the parity budget $M = N - K$.
- During a macro-regional ISP or power grid outage ($\ge 30\%$ simultaneous cohort drop across $\ge 20$ verified subnets), `CorrelatedOutageController::verify_weather_quorum` requires $\ge 3$ independent anchor-signed `SignedWeatherAttestation`s before activating a temporary SLA grace freeze—preventing both unfair mass demotions of honest homelabs and fake-outage spoofing by small colluding groups.

---

## 6. Multi-Domain Red-Team Hardening Summary (`ADR-15` – `ADR-17`)

1. **Zero-Local-State "House Fire" Recovery (`MasterKey::from_recovery_seed_phrase` & `EncryptedVaultCatalogEnvelope`):**
   Memory-hard **Argon2id** (`m=64 MiB, t=3 iterations, p=4 lanes`) + domain-separated `HKDF-SHA256` / `HKDF-SHA512` deterministically reconstruct the 256-bit `MasterKey`, full 512-bit `PqVaultMasterKey`, `NodeIdentity`, and `derive_vault_root_dht_key(vault_namespace)`, publishing and querying `SignedDhtManifestEnvelope` catalog records across all reachable `libp2p` peers and selecting the strictly highest `monotonic_version`.
2. **Capability Key Pinning, $\pm 30\text{ s}$ NTP Skew, Generation-Scoped Tombstones & Remote `DeleteShard` Auth:**
   `BlockStore` pins `capability_pubkey` at upload time, enforces `MAX_CAPABILITY_CLOCK_SKEW_MS = 30_000`, scopes `BlindedShardTombstone`s to monotonic lease generations so old tombstones cannot delete re-uploaded files, and authenticates remote unblinded shard deletions (`MeshWireRequest::DeleteShard`) via domain-separated Ed25519 owner signatures (`"parvault-owner-shard-delete-v1:"`) against persisted `RepairGrant` records (`por_verifier_state.bin`).
3. **Ephemeral Sybil Drain Gate & `/32` IPv6 + RFC 6598 CGNAT Normalization:**
   `plan_seed_anchor_drain` only migrates seed shards to `VerifiedNeighbor` ($\ge 50$ PoR passes) organic nodes; `canonical_sybil_subnet_key` buckets IPv6 by `/32` LIR prefix and grants Starlink/5G CGNAT (`100.64.0.0/10`) up to 4 attested household sub-slots per `/24`.
4. **Wire-Protocol Pre-Auth OOM Bomb Defense, Bounded Replay Caches & Crash-Persisted Security Ledgers:**
   `BincodeWireCodec::deserialize_request_bounded` enforces `with_limit(buf.len() as u64)` after capping frames at `32 MiB`, while `PorVerifierEngine`, `VoucherNullifierLedger` (`voucher_nullifiers.bin`), `WebOfTrustRegistry` (`wot_state.bin`), and `QuotaManager` (`quota_state.bin`) enforce bounded `65,536`-entry FIFO ceilings and atomic disk persistence across daemon restarts.
5. **Constant-Memory Streaming I/O, Atomic Writes & Path-Traversal Blocking:**
   `compute_file_sha256_streaming` hashes files in 64 KiB chunks (zero full-file `fs::read`), `BlockStore::atomic_write_file` enforces write-temp-`sync_all`-rename, and `FolderSyncEngine::resolve_safe_restore_path` blocks `..`, `/`, drive prefixes, and symlinks.

---

## 7. Machine-Checked Formal Verification & Test Suite Matrix

Every invariant of `parvault` is verified across **6 TLA+ TLC formal specifications** (`specs/*.tla`) and **12 automated Rust unit, integration, mathematical-proof, Stateright, live `libp2p` TCP, and Red-Team test suites** (`tests/*.rs` + `src/`):

| Verification Suite | Artifact / Location | Method & Scope | Verified Result |
| :--- | :--- | :--- | :--- |
| **TLA+ Protocol Safety, Liveness & Adversarial Guards** | [`specs/ParVaultProtocol.tla`](../specs/ParVaultProtocol.tla)<br>[`specs/ParVaultProtocol.cfg`](../specs/ParVaultProtocol.cfg) | Exhaustive TLC model checking of $16\text{-of-}20$ durability, proactive $18/20$ witness repair, explicit adversary shard/key/Sybil actions (`AdversaryCompromiseShard`, `AdversaryStealMasterKeyAttempt`, `UninvitedSybilHandshakeAttempt`), and bounded subtree slashing ($M=3$) | **0 Errors** (`DataSecrecyInvariant`, `SybilResistanceInvariant`, `DurabilitySafetyInvariant`, `EventuallyRepaired`, `EventuallyBranchPruned`) |
| **TLA+ Confidentiality & Dynamic Trust Caps** | [`specs/ParVaultConfidentialityAndTrust.tla`](../specs/ParVaultConfidentialityAndTrust.tla)<br>[`specs/ParVaultConfidentialityAndTrust.cfg`](../specs/ParVaultConfidentialityAndTrust.cfg) | Exhaustive TLC model checking of dynamic trust promotion (`Untrusted` $\rightarrow$ `Verified` $\rightarrow$ `Anchor`), subnet caps (`1`, `2`, `4`), and collusion up to 15 shards / 20 wire shards without $K_{\text{user}}$ | **0 Errors** (`Safety_ZeroKnowledgeConfidentiality`, `Safety_SubnetTrustCapsEnforced`, `Safety_SlashedNeverTrusted`, `Liveness_EventualBackupAndTrustConvergence`) |
| **TLA+ 4-Layer Shard Anonymity & Voucher Conservation** | [`specs/ParVaultAnonymity.tla`](../specs/ParVaultAnonymity.tla)<br>[`specs/ParVaultAnonymity.cfg`](../specs/ParVaultAnonymity.cfg) | Exhaustive TLC model checking of Blinded Shard Locators, Per-Shard Capability Keys ($V_i$), Bearer Quota Voucher 1-to-1 conservation, and 1-Hop Onion Relay dispatch (`ADR-11`) | **0 Errors** (`Safety_ZeroOriginLeakage`, `Safety_NoVoucherDoubleSpend`, `Safety_UnlinkableReconstructionHardness`, `Liveness_AnonymousBackupCompletes`) |
| **TLA+ Post-Quantum Hybrid Cryptography (`ADR-12`)** | [`specs/ParVaultPostQuantum.tla`](../specs/ParVaultPostQuantum.tla)<br>[`specs/ParVaultPostQuantum.cfg`](../specs/ParVaultPostQuantum.cfg) | Exhaustive TLC model checking of Shor's algorithm breaking `X25519`/`Ed25519`, Grover's algorithm halving symmetric bit security (`512 -> 256`), `X25519 + ML-KEM-768` (FIPS 203), and `Ed25519 + ML-DSA-65` (FIPS 204) | **0 Errors** (`Safety_HNDLConfidentialityPreserved`, `Safety_QuantumSignatureUnforgeability`, `Safety_GroverBitSecurityFloor`, `Liveness_PostQuantumSessionAndBackupEstablished`) |
| **TLA+ Elastic Bootstrap & Earned Tier Progression (`ADR-13`)** | [`specs/ParVaultBootstrapAndEarnedTier.tla`](../specs/ParVaultBootstrapAndEarnedTier.tla)<br>[`specs/ParVaultBootstrapAndEarnedTier.cfg`](../specs/ParVaultBootstrapAndEarnedTier.cfg) | Exhaustive TLC model checking of Day-1 Personal Ring (`2-of-3`), Foundation Seed Anchor fallback & auto-drain (`20 -> 0` shards), earned PoR tier progression, and `/24` Sybil standby quota conservation | **0 Errors** (`Safety_TierStrictlyEarnedByUptime`, `Safety_SeedAnchorsDrainAtOrganicThreshold`, `Safety_SubnetSybilQuotaConservation`, `Safety_Day1ToScaleDataAvailability`) |
| **TLA+ Lite-Client Syndication & NAS-Death Failover (`ADR-17`)** | [`specs/ParVaultLiteClientAndSeedFailover.tla`](../specs/ParVaultLiteClientAndSeedFailover.tla)<br>[`specs/ParVaultLiteClientAndSeedFailover.cfg`](../specs/ParVaultLiteClientAndSeedFailover.cfg) | Exhaustive TLC model checking of `1.0x` Lite-Client seed syndication, zero-knowledge seed/mesh invariants, NAS-death direct-mesh failover, and selective `--filter` restore bandwidth savings | **0 Errors** (`ZeroKnowledgeSeedAndMeshInvariant`, `NasDeathSurvivableInvariant`, `SelectiveBandwidthSavingInvariant`, `EventuallySelectiveRestoreComplete`) |
| **Stateright Async Actor Model & Exhaustive $GF(2^8)^3$ Field Axioms** | [`tests/formal_verification.rs`](../tests/formal_verification.rs)<br>[`tests/tla_formal_proofs_integration.rs`](../tests/tla_formal_proofs_integration.rs) | Stateright BFS model checking of non-vacuous Sybil/slashing state machine + exhaustive verification of all $256^3 = 16,777,216$ triples $(a, b, c) \in GF(2^8)^3$ + automated TLC runner for all 6 `.tla` specs | **0 Invariant Violations**; **16,777,216 / 16,777,216 field triples verified** |
| **Information-Theoretic Ciphertext Indistinguishability & Dynamic Trust Proofs** | [`tests/confidentiality_and_trust_proofs.rs`](../tests/confidentiality_and_trust_proofs.rs) | Empirical Shannon entropy $H(X) = -\sum p_i \log_2 p_i$, Strict Avalanche Criterion (SAC) bit-flip diffusion, and dynamic trust subnet cap enforcement | **Shannon Entropy $> 7.98\text{ bits/byte}$**; **SAC $\approx 50.0\%$ bit-flip ratio** |
| **Byzantine Quarantine, Multi-Stratum PoR & Egress Slashing (`ADR-09`)** | [`tests/zero_trust_adversarial.rs`](../tests/zero_trust_adversarial.rs) | Pre-decoding Merkle quarantine of poisoned shards, 8-stratum scatter-gather PoR + RTT ceiling, monotonic DHT envelopes, and egress-withholding credit burn | **All Byzantine & selfish attacks defeated** |
| **4-Layer Anonymity & 8-Profile Degraded Network Recovery (`ADR-11`)** | [`tests/anonymity_and_degraded_net_tests.rs`](../tests/anonymity_and_degraded_net_tests.rs) | Verification of $>224$-bit combinatorial locator wall, per-shard capabilities, voucher nullifiers, 1-hop onion routing, and hedged $K$-of-$N$ recovery across 8 degraded profiles | **100% PASS (`0 bytes` lost across all 8 profiles)** |
| **Post-Quantum Hybrid Cryptography Proofs (`ADR-12`)** | [`tests/post_quantum_security_proofs.rs`](../tests/post_quantum_security_proofs.rs) | NIST FIPS 203 `ML-KEM-768` + `X25519` Shor resilience, FIPS 204 `ML-DSA-65` + `Ed25519` unforgeability, and 512-bit `PqVaultMasterKey` (`AES-256-GCM` + `ChaCha20-Poly1305`) Grover resistance | **100% PASS** |
| **Elastic Bootstrap, Seed Server, Lite-Client & Anonymous Telemetry (`ADR-13`–`ADR-17`)** | [`tests/bootstrap_and_earned_tier_tests.rs`](../tests/bootstrap_and_earned_tier_tests.rs)<br>[`tests/seed_server_integration.rs`](../tests/seed_server_integration.rs)<br>[`tests/lite_client_seed_failover_and_selective_restore_tests.rs`](../tests/lite_client_seed_failover_and_selective_restore_tests.rs)<br>[`tests/anonymous_telemetry_tests.rs`](../tests/anonymous_telemetry_tests.rs) | Day-1 Personal Ring, Foundation Seed Anchor auto-drain, zero-knowledge elastic re-sharding, `ZeroTrustSeedServer`, Lite-Client `1.0x` syndication & NAS-death failover, and rotating-nullifier census beacons | **100% PASS** |
| **5-Domain Red-Team Suite (`ADR-15`) & Live `libp2p` TCP Multi-Daemon Regression (`ADR-16`–`ADR-17`)** | [`tests/red_team_hardening_tests.rs`](../tests/red_team_hardening_tests.rs)<br>[`tests/sync_daemon_usability_and_cli_regression_tests.rs`](../tests/sync_daemon_usability_and_cli_regression_tests.rs)<br>[`tests/phase1_to_4_integration.rs`](../tests/phase1_to_4_integration.rs) | House-fire seed recovery, capability pinning, NTP skew, generation-scoped tombstones, `with_limit` OOM defense, Hashcash PoW + IQR trimming, path-traversal blocking, and live `libp2p` TCP multi-daemon sync/prune/recovery | **100% PASS (67 / 67 total tests)** |

---

## 8. Live Multi-Container Docker P2P Regression Report (`v0.2.0`)

Executed end-to-end via [`scripts/docker_acceptance_gate.sh`](../scripts/docker_acceptance_gate.sh) (and enforced in GitHub Actions CI [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) using static `x86_64-unknown-linux-musl` `parvault` and `parvault-seed` binaries (`v0.2.0`) inside **13 isolated `alpine:3.20` Docker containers** on bridge subnet `172.28.0.0/24` (`parvault-seed-0` at `172.28.0.10:4002`, `parvault-node-1..11` at `172.28.0.11..21:4001`, and `parvault-client` at `172.28.0.50` verified with `docker inspect Mounts == []` so zero host or container filesystem volumes are shared):

| Regression Stage | Live P2P Network Action (`libp2p` TCP + Noise XX + Yamux) | Measured Result | Status |
| :--- | :--- | :--- | :---: |
| **Stages 1–3: 13-Container Boot, WoT Cert Issuance & Zero-Mount Audit** | Boot `parvault-seed-0` (`homelab-vault`) + 11 `parvault daemon` containers across 10 simulated ASNs; issue `PARVAULT-CERT-V1:` post-quantum hybrid device cert; verify `parvault-client` has `Mounts: []` | All 12 storage listeners ready on `:4001`/`:4002`; `Verified OK: true` (`Ed25519 + ML-DSA-65`) | **PASS** |
| **Stage 4: Initial `watch-folder --once` (`v1`) & Catalog Replication** | Stream 4 files (`.parvaultignore` excluding `.git/`, `*.tmp`, `ignored_cache/`) from `parvault-client` over `libp2p` to `parvault-node-1..10` + `parvault-seed-0` (`20-of-20` shards per stripe) | **`240` `.shard` files** across `parvault-node-1..10` (`24` per node) + **`80` shards** on `parvault-seed-0` in **`2 s`** | **PASS** |
| **Stage 5: Continuous Background `watch-folder` Daemon & Remote Tombstone Pruning** | Run `parvault watch-folder --interval-secs 1 --prune-deleted` in background; modify `docs/readme.md`, add `docs/changelog.md`, delete `src/ephemeral.rs` | Catalog advanced to **Version 4** (`Deleted Tombstones: 1`); **`20` obsolete shards pruned remotely** via `MeshWireRequest::DeleteShard` | **PASS** |
| **Stage 6: Lite-Client `1.0x` Seed Syndication & NAS-Death Direct-Mesh Failover** | Run `watch-folder --once --lite-seed-dir /ip4/172.28.0.10/tcp/4002` (`1` stripe syndicated by `parvault-seed-0` to `parvault-node-1..10`), run `docker stop parvault-seed-0`, and run `recover-from-seed` from mesh peers | `parvault-seed-0` syndicated **1 stripe (`20` shards)**; after stopping `parvault-seed-0`, `laptop_note.txt` restored directly from `parvault-node-1..10` (`SHA-256 OK`) | **PASS** |
| **Stage 7: Graceful Node Decommission (`parvault leave --handoff-to`)** | Run `parvault leave --handoff-to /ip4/172.28.0.21/tcp/4001` on `parvault-node-5` to migrate shards and persisted `RepairGrant`/`session_key` metadata to spare `parvault-node-11`, then `docker stop parvault-node-5` | **`36` shards (`24,744 bytes`)** + `RepairGrant` metadata transferred over `libp2p` to `parvault-node-11` (`0 -> 36` shards); `graceful_departure_receipt.json` written | **PASS** |
| **Stage 8: Bit-Rot Injection, `parvault scrub` Quarantine, Daemon Restart & 4 Hard Kills** | Flip 1 byte in a stored `.shard` on `parvault-node-6` and run `parvault scrub`; `docker restart parvault-node-6 parvault-node-7` (verifying persisted `node_identity.seed` + `por_verifier_state.bin`); `docker kill parvault-node-1..4` | `parvault scrub` scanned `36` shards, verified `35` healthy, **quarantined `1` corrupted shard**; 5 of original 10 nodes offline + 1 bit-rotted shard quarantined | **PASS** |
| **Stage 9: Zero-Local-State `recover-from-seed` (Full & Selective `--filter`)** | Wipe client state and run `parvault recover-from-seed` (and `--filter "docs/*"`) using only the 12-word seed phrase, `--vault-namespace`, and surviving network peers | Catalog Version 4 discovered via Kademlia DHT; **all `4` surviving `v2` files restored in `7 s` (`SHA-256 OK`)**, deleted `src/ephemeral.rs` absent; `--filter "docs/*"` restored `2` files and skipped `2` (`65,590 bytes` saved) | **PASS** |
| **Stage 10: Cross-Machine `parvault file store` & `file restore --key-hex`** | Run `parvault file store` on `/tmp/machine-a/secret.txt`, wipe `/tmp/machine-a`, and run `parvault file restore --merkle-root-hex ... --key-hex ...` into `/tmp/machine-b/secret_restored.txt` | Restored across `libp2p` from Merkle root `c5a349b529494f223af1b81ab5beee0cc812e044679c252e12725de981911dfd` (`SHA-256 OK`) | **PASS** |
