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
8. [Live Multi-Container Docker P2P Regression Report (`v0.3.0`)](#8-live-multi-container-docker-p2p-regression-report-v030)
9. [Empirical Cryptography, Reed-Solomon & Memory Telemetry (`parvault-bench`)](#9-empirical-cryptography-reed-solomon--memory-telemetry-parvault-bench)
10. [Zero-IP Signed LAN Auto-Discovery & 4-Word SAS Pairing Cryptography (`ADR-18`)](#10-zero-ip-signed-lan-auto-discovery--4-word-sas-pairing-cryptography-adr-18)
11. [Zero-IP Online WAN Rendezvous & Zero-Knowledge Dynamic-IP Presence (`ADR-18`)](#11-zero-ip-online-wan-rendezvous--zero-knowledge-dynamic-ip-presence-adr-18)
12. [4-Vector Privacy-Preserving Bad-Actor & Content Eviction Cryptography (`ADR-19`)](#12-4-vector-privacy-preserving-bad-actor--content-eviction-cryptography-adr-19)

---

## 1. Zero-Knowledge Streaming Pipeline, HKDF Subkey Hierarchy & Encrypt-Before-Shard Invariant (`ADR-01`, `ADR-15`, `ADR-16`)

Every file or incremental folder delta is processed in bounded **16 MiB streaming stripes** (with 64 KiB streaming SHA-256 content checks in `compute_file_sha256_streaming`) to guarantee a **`< 32 MiB` resident RAM footprint** even on constrained `prplOS` / `OpenWrt` LXC gateways:

1. **ISO/IEC 7816-4 Power-of-Two Bucket Padding (`pad_plaintext_iso_bucket`):**
   Eliminates exact file-size fingerprinting prior to encryption.
2. **HKDF-SHA256 Per-Purpose Subkey Tree & Client-Side Authenticated Encryption (`B1`–`B6`):**
   - **Per-Purpose Subkey Separation (`B1`):** The 256-bit client root `MasterKey` $K_{\text{user}}$ is never passed directly into multiple cryptographic primitives. Instead, `MasterKey` derives cryptographically isolated 256-bit subkeys via domain-separated `HKDF-SHA256`:
     - `stripe_aead_subkey` (`"parvault-subkey-stripe-aead-v1"`) for `AES-256-GCM` stripe encryption,
     - `stripe_nonce_subkey` (`"parvault-subkey-stripe-nonce-v1"`) for deterministic 96-bit per-stripe nonces $\text{HKDF-SHA256}(K_{\text{nonce}}, \text{FileSalt} \parallel \text{StripeIdx})$,
     - `manifest_aead_subkey` (`"parvault-subkey-manifest-aead-v1"`) for `FileManifest` encryption,
     - `dht_routing_subkey` (`"parvault-subkey-dht-routing-v1"`) for Kademlia DHT manifest lookup keys,
     - `blind_locator_subkey` (`"parvault-subkey-blind-locator-v1"`) for `BlindedShardId` HMAC locators,
     - `blind_capability_subkey` (`"parvault-subkey-blind-capability-v1"`) for per-shard capability keypairs $V_i$, and
     - `shard_pseudonym_subkey` (`"parvault-subkey-shard-pseudonym-v1"`) for unlinkable owner pseudonyms.
   - **Separated `Ed25519` / `X25519` Identity Seeds (`B2`):** `NodeIdentity::from_seed` expands a 32-byte root seed via `HKDF-SHA256` into disjoint sub-seeds (`"parvault-node-identity-ed25519-v1"` and `"parvault-node-identity-x25519-v1"`) so signing and Diffie-Hellman operations never share raw scalar bytes.
   - **Memory Scrubbing, `0600` Key Files & `LocalFileKeystore` (`B3`–`B5`):** Secret key structs (`MasterKey`, `PqVaultMasterKey`, `NodeIdentity`) zeroize sensitive memory on drop via `zeroize` (`ZeroizeOnDrop`), persist key files atomically with `0600` POSIX permissions (`write_secret_file_atomic_0600`), and seal local master keys via `LocalFileKeystore` (`LocalKeystoreSealer` — using `Argon2id` passphrase derivation when `PARVAULT_PASSPHRASE` / `--passphrase` is provided, or an OS-protected `0600` local key file for unattended daemons).
   - **BIP-39 Checksum/NFKD Validation & `Argon2id` (`64 MiB`) Key Stretching (`A1`, `B6`):** `MasterKey::from_recovery_seed_phrase` and `PqVaultMasterKey::from_recovery_seed_phrase` apply Unicode NFKD whitespace normalization, validate 12-word (128-bit) and 24-word (256-bit) BIP-39 mnemonics against the 2,048-word English wordlist and SHA-256 checksum, and stretch key material via memory-hard **`Argon2id` (`m = 64 MiB (65,536 KiB), t = 3, p = 4`)** + `HKDF-SHA256`.
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
| **Layer 1: Blinded Shard Locators (`BlindedShardId`)** | $\text{Locator}_i = \text{HMAC-SHA256}(K_{\text{blind\_loc}}, \text{"parvault-blinded-locator-v1:"} \parallel \text{StripeRoot} \parallel \text{ShardIdx} \parallel \text{PayloadHash}_i)$ | Removes `stripe_merkle_root`, `shard_index` ($0..19$), and sibling Merkle hashes from stored `.bshard` files | Static disk combinatorial grouping wall: $\binom{M}{K} \frac{N!}{(N-K)!} \approx 2^{224}$ across a neighborhood pool ($M \ge 8,000$ shards, $K=16, N=20$) |
| **Layer 2: Per-Shard PoR Capability Keys ($V_i$)** | `BlindedShardCapability::derive_keypair(&master_key, &locator)` using `blind_capability_subkey` | Eliminates shared stripe-wide $K_{\text{session}}$ across storage peers; pins `capability_pubkey` at upload time (`ADR-15`) | Storage node $i$ holds only $(\text{Locator}_i, \text{PubKey}_i, \text{Ciphertext}_i)$; zero cross-shard PoR key linkability |
| **Layer 3: Ephemeral-Issuer Bearer Quota Vouchers (`AnonymousQuotaVoucher`)** | One-time bearer token signed by a fresh per-shard ephemeral `Ed25519` keypair (`AnonymousQuotaVoucher::mint_ephemeral`) redeemed into disk-persisted, bounded `VoucherNullifierLedger` | Decouples byte-hour quota authorization from static `uploader_peer_id` and prevents cross-shard voucher issuer correlation | Strict 1-to-1 voucher conservation (`Cardinality(spentNullifiers) = anonymousShardsStored`) with zero double-spend |
| **Layer 4: 2-Layer PQ Onion Relay Dispatch (`PqRelayedShardEnvelope` & `PqInnerStorageEnvelope`)** | Inner layer (`blinded_id`, `capability`, `voucher`, `shard_bytes`) sealed to storage node's `HybridKemPublicKey`; outer layer (`target_peer_addr`, `inner_envelope`, `jitter_delay_ms`) sealed to relay node's `HybridKemPublicKey` | Hides the vault owner's IP/`PeerId` from the storage node AND hides `blinded_id`, `capability`, `voucher`, and `shard_bytes` from the relay node | Storage node strictly observes `observedSender = "RelayNode"` and relay node observes `relayPlaintextCapExposed = FALSE` |

### Combinatorial Hardness of Static Blinded Pool Reconstruction
Without the client-only master key $K_{\text{user}}$, every 256-bit $\text{Locator}_i$ is computationally indistinguishable from a uniform random bitstring. Even if an adversary colludes across every storage node's static disk pool holding $M$ total blinded shards, identifying which $K = 16$ shards belong to a single stripe and ordering them into positions $0 \dots K-1$ requires searching:

$$\Omega_{\text{search}} = \binom{M}{K} \times \frac{N!}{(N - K)!} \approx 2^{224} \quad (\text{for } M \ge 8,000,\; K = 16,\; N = 20)$$

### Side-Channel & Traffic-Analysis Threat Model (`D4`)
It is important to distinguish **at-rest disk unlinkability** from **active network traffic analysis**:
- **Protected Against Static & Snapshot Coalitions ($\Omega_{\text{search}} \ge 2^{224}$):** An adversary who inspects or seizes the disks of storage nodes at rest observes only uniformly padded `.bshard` files, unlinkable HMAC locators, per-shard capability public keys, and ephemeral voucher signatures—yielding the $\ge 2^{224}$ combinatorial grouping barrier above.
- **Mitigations Against Local / Partial Network Observers:** Power-of-two ISO plaintext bucket padding (`pad_plaintext_iso_bucket`), per-shard ephemeral voucher signing keys (`mint_ephemeral`), and 2-layer post-quantum onion routing with configurable per-hop forwarding jitter (`jitter_delay_ms`) prevent an intermediate relay or destination storage peer from trivially linking an upload to the origin `PeerId` or correlating `capability`/`voucher` fields.
- **Scope Boundary (Global Passive Adversary Timing Correlation):** As with Tor and low-latency onion routing systems, a Global Passive Adversary (GPA) capable of monitoring all ISP links simultaneously could still perform statistical timing and volume correlation across concurrent 20-shard upload bursts unless high-latency continuous cover traffic (loopix/mixnet chaff) is enabled.

---

## 4. Post-Quantum Hybrid Cryptography (`ADR-12` — Harvest-Now, Decrypt-Later Immunity)

To protect long-lived backup shards and P2P envelopes against **Harvest-Now, Decrypt-Later (HNDL)** adversaries equipped with a future **Cryptographically Relevant Quantum Computer (CRQC)** running **Shor's Algorithm** and **Grover's Algorithm**, `src/crypto/pqc.rs` implements a **Post-Quantum Hybrid Cryptography Suite** (model-checked in [`specs/ParVaultPostQuantum.tla`](../specs/ParVaultPostQuantum.tla)):

| Cryptographic Subsystem | Classical Primitive | Post-Quantum NIST Standard | Hybrid Combiner & Construction | Quantum & Cryptanalytic Threat Mitigated |
| :--- | :--- | :--- | :--- | :--- |
| **X-Wing Style Hybrid KEM (`HybridKemKeypair`)** | **X25519** ECDH (`32 B` public key) | **ML-KEM-768** (`NIST FIPS 203`, Module-LWE, `1,184 B` ek, `1,088 B` ct) | $K_{\text{hybrid}} = \text{HKDF-SHA512}(\text{salt} = \text{pk}_{\text{ephem}} \parallel H(\text{ct}_{\text{PQ}}),\; \text{ikm} = \text{ss}_{\text{X25519}} \parallel \text{ss}_{\text{PQ}},\; \text{info} = \text{ctx} \parallel \text{pk}_{\text{recip,X25519}} \parallel H(\text{ek}_{\text{recip,PQ}}))$ | **Shor's Algorithm** on ECDLP & multi-target PK substitution (`A2`, `B10`); session key remains IND-CCA2 secure unless *both* X25519 and ML-KEM-768 are broken |
| **Hybrid Digital Signatures (`HybridPqSigningKeypair`)** | **Ed25519** (`32 B` vk, `64 B` sig) | **ML-DSA-65** (`NIST FIPS 204`, Module-LWE/SIS, `1,952 B` vk, `3,309 B` sig) | Composite dual verification (`Ed25519::verify` $\wedge$ `ML-DSA-65::verify` over `ML_DSA_65_CONTEXT`) | **Shor's Algorithm** signature forgery on `PersonalDeviceCert`s and `PqSignedDhtManifestEnvelope`s |
| **Dual-Cipher Cascaded Vault Encryption (`PqVaultMasterKey`)** | **AES-256-GCM** (`256-bit` inner) + **ChaCha20-Poly1305** (`256-bit` outer) | **NIST Category 5 Grover Floor (`128-bit PQ`)** + **Cipher Diversity** | Cascaded dual-cipher AEAD encryption (inner `AES-256-GCM` pass under $K_1$, outer `ChaCha20-Poly1305` pass under $K_2$) with independent HKDF nonces | **Grover's Algorithm** ($\text{AES-256} \rightarrow 128\text{-bit}$ PQ security floor) + **Cipher-Diversity Defense-in-Depth** (`B8`: secure unless *both* AES-GCM and ChaCha20-Poly1305 are broken) |
| **2-Layer Post-Quantum Onion Envelopes (`PqRelayedShardEnvelope`)** | **X25519** ephemeral ECDH (2 hops) | **ML-KEM-768** (`1,088 B` ct per hop) + `AES-256-GCM` | Outer relay layer + inner storage layer (`PqInnerStorageEnvelope`) each sealed under recipient's `HybridKemPublicKey` | Prevents HNDL quantum decryption of relay hops, capabilities, vouchers, and telemetry beacons |

> [!NOTE]
> **Implementation Pedigree & Hybrid Defense-in-Depth (`B9`):** The crates `fips203` (`0.5.0`) and `fips204` (`0.5.0`) are pure-Rust implementations of the final **NIST FIPS 203 (`ML-KEM-768`)** and **NIST FIPS 204 (`ML-DSA-65`)** specifications, rather than CMVP FIPS 140-3 validated hardware/software modules. Combining them in mandatory hybrid constructions with battle-tested `x25519-dalek` and `ed25519-dalek` guarantees that any implementation defect or future algebraic advance against one primitive family never compromises confidentiality or authenticity.

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
6. **Persistent `Swarm` Connection Pool, `/p2p/<PeerId>` Verification, Dual Kademlia DHT Replication & Live RTT Placement (`C1`–`C6`):**
   - `MeshClient` runs a persistent background `libp2p` `Swarm` worker thread that reuses authenticated `TCP + Noise XX + Yamux` connections across RPCs rather than spawning a fresh swarm per call (`C1`).
   - When a `Multiaddr` includes `/p2p/<PeerId>`, `MeshClient` enforces that the Noise XX remote `PeerId` matches the expected `PeerId`, and pins discovered `PeerId`s per address using Trust-On-First-Use (`TOFU`) to reject silent MITM peer substitution (`C2`).
   - `put_dht_envelope` and `get_dht_envelope` replicate records both into the `libp2p` Kademlia DHT (`kad::Behaviour::put_record` / `get_record`) and into peers' disk-persisted `ZeroTrustDhtStore` (`C3`), while `PlacementEngine` queries live RTT and `MeshWireRequest::QueryPeerStatus` telemetry before selecting 70/30 Intra-ASN / Cross-Region shard targets (`C4`, `C5`).

---

## 7. Machine-Checked Formal Verification & Test Suite Matrix

> [!IMPORTANT]
> **Scope & Abstraction Boundaries of Formal Models (`A5`, `D1`):**
> - **TLA+ Specifications (`specs/*.tla`):** Verify **protocol-level state machines and compositional security reductions** under explicit symbolic adversary capabilities (e.g., modeling what happens when an adversary non-deterministically breaks any single KEM leg in `{"X25519", "ML_KEM_768"}`, any single signature leg in `{"Ed25519", "ML_DSA_65"}`, or any single cipher in `{"AES_256_GCM", "ChaCha20_Poly1305"}`, or attempts multi-target public-key substitution, voucher replay, or Sybil subnet concentration). TLA+ does not prove the absence of side channels in underlying mathematical primitives (`AES`, `SHA-256`, `Module-LWE`).
> - **Stateright & Rust Test Suites (`tests/*.rs`):** Verify the **executable Rust implementation**, including exhaustive $GF(2^8)^3$ Galois field axioms ($16,777,216$ triples), Byzantine Merkle quarantine, wire-protocol `with_limit` OOM bounds, and live multi-process/multi-container `libp2p` TCP network execution.

Every invariant of `parvault` is model-checked and tested across **6 TLA+ TLC protocol specifications** (`specs/*.tla`) and **12 automated Rust unit, integration, mathematical-proof, Stateright, live `libp2p` TCP, and Red-Team test suites** (`tests/*.rs` + `src/`):

| Verification Suite | Artifact / Location | Method & Scope | Verified Result |
| :--- | :--- | :--- | :--- |
| **TLA+ Protocol Safety, Liveness & Adversarial Guards** | [`specs/ParVaultProtocol.tla`](../specs/ParVaultProtocol.tla)<br>[`specs/ParVaultProtocol.cfg`](../specs/ParVaultProtocol.cfg) | Exhaustive TLC model checking of $16\text{-of-}20$ durability, proactive $18/20$ witness repair, explicit adversary shard/key/Sybil actions (`AdversaryCompromiseShard`, `AdversaryStealMasterKeyAttempt`, `UninvitedSybilHandshakeAttempt`), and bounded subtree slashing ($M=3$) | **0 Errors** (`DataSecrecyInvariant`, `SybilResistanceInvariant`, `DurabilitySafetyInvariant`, `EventuallyRepaired`, `EventuallyBranchPruned`) |
| **TLA+ Confidentiality & Dynamic Trust Caps** | [`specs/ParVaultConfidentialityAndTrust.tla`](../specs/ParVaultConfidentialityAndTrust.tla)<br>[`specs/ParVaultConfidentialityAndTrust.cfg`](../specs/ParVaultConfidentialityAndTrust.cfg) | Exhaustive TLC model checking of dynamic trust promotion (`Untrusted` $\rightarrow$ `Verified` $\rightarrow$ `Anchor`), subnet caps (`1`, `2`, `4`), and collusion up to 15 shards / 20 wire shards without $K_{\text{user}}$ | **0 Errors** (`Safety_ZeroKnowledgeConfidentiality`, `Safety_SubnetTrustCapsEnforced`, `Safety_SlashedNeverTrusted`, `Liveness_EventualBackupAndTrustConvergence`) |
| **TLA+ 4-Layer Shard Anonymity & 2-Layer PQ Onion Routing** | [`specs/ParVaultAnonymity.tla`](../specs/ParVaultAnonymity.tla)<br>[`specs/ParVaultAnonymity.cfg`](../specs/ParVaultAnonymity.cfg) | Exhaustive TLC model checking (`861` distinct states) of Blinded Shard Locators, Per-Shard Capability Keys ($V_i$), Ephemeral-Issuer Bearer Quota Voucher 1-to-1 conservation, and 2-Layer PQ Onion Relay dispatch (`ADR-11`) | **0 Errors** (`Safety_ZeroOriginLeakage`, `Safety_NoVoucherDoubleSpend`, `Safety_UnlinkableReconstructionHardness`, `Liveness_AnonymousBackupCompletes`) |
| **TLA+ Post-Quantum Hybrid Protocol & Adversary State Machine (`ADR-12`)** | [`specs/ParVaultPostQuantum.tla`](../specs/ParVaultPostQuantum.tla)<br>[`specs/ParVaultPostQuantum.cfg`](../specs/ParVaultPostQuantum.cfg) | Exhaustive TLC model checking (`927` distinct states) of `Client`, `RelayPeer`, `StoragePeer`, and `Adversary` actors, non-deterministic single-primitive breaks (`X25519` vs `ML_KEM_768`, `Ed25519` vs `ML_DSA_65`, `AES_256_GCM` vs `ChaCha20_Poly1305`), and X-Wing `HKDF-SHA512` public-key substitution defense | **0 Errors** (`Safety_HNDLConfidentialityPreserved`, `Safety_QuantumSignatureUnforgeability`, `Safety_GroverBitSecurityFloor`, `Liveness_PostQuantumSessionAndBackupEstablished`) |
| **TLA+ Elastic Bootstrap & Earned Tier Progression (`ADR-13`)** | [`specs/ParVaultBootstrapAndEarnedTier.tla`](../specs/ParVaultBootstrapAndEarnedTier.tla)<br>[`specs/ParVaultBootstrapAndEarnedTier.cfg`](../specs/ParVaultBootstrapAndEarnedTier.cfg) | Exhaustive TLC model checking of Day-1 Personal Ring (`2-of-3`), Foundation Seed Anchor fallback & auto-drain (`20 -> 0` shards), earned PoR tier progression, and `/24` Sybil standby quota conservation | **0 Errors** (`Safety_TierStrictlyEarnedByUptime`, `Safety_SeedAnchorsDrainAtOrganicThreshold`, `Safety_SubnetSybilQuotaConservation`, `Safety_Day1ToScaleDataAvailability`) |
| **TLA+ Lite-Client Syndication & NAS-Death Failover (`ADR-17`)** | [`specs/ParVaultLiteClientAndSeedFailover.tla`](../specs/ParVaultLiteClientAndSeedFailover.tla)<br>[`specs/ParVaultLiteClientAndSeedFailover.cfg`](../specs/ParVaultLiteClientAndSeedFailover.cfg) | Exhaustive TLC model checking of `1.0x` Lite-Client seed syndication, zero-knowledge seed/mesh invariants, NAS-death direct-mesh failover, and selective `--filter` restore bandwidth savings | **0 Errors** (`ZeroKnowledgeSeedAndMeshInvariant`, `NasDeathSurvivableInvariant`, `SelectiveBandwidthSavingInvariant`, `EventuallySelectiveRestoreComplete`) |
| **Stateright Async Actor Model & Exhaustive $GF(2^8)^3$ Field Axioms** | [`tests/formal_verification.rs`](../tests/formal_verification.rs)<br>[`tests/tla_formal_proofs_integration.rs`](../tests/tla_formal_proofs_integration.rs) | Stateright BFS model checking of non-vacuous Sybil/slashing state machine + exhaustive verification of all $256^3 = 16,777,216$ triples $(a, b, c) \in GF(2^8)^3$ + automated TLC runner for all 6 `.tla` specs | **0 Invariant Violations**; **16,777,216 / 16,777,216 field triples verified** |
| **Empirical Ciphertext Sanity & Non-Degeneracy Checks (`D3`) & Dynamic Trust Proofs** | [`tests/confidentiality_and_trust_proofs.rs`](../tests/confidentiality_and_trust_proofs.rs) | Empirical byte-level Shannon entropy $H(X) = -\sum p_i \log_2 p_i$ and Strict Avalanche Criterion (SAC) bit-flip sanity checks verifying absence of unencrypted header/padding leakage, plus dynamic trust subnet cap enforcement | **Shannon Entropy $> 7.98\text{ bits/byte}$**; **SAC $\approx 50.0\%$ bit-flip ratio** |
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
| **Stage 11: Zero-IP LAN Auto-Discovery (`parvault discover`)** | Run `parvault discover` in `parvault-client` with zero `--peers` and zero IP addresses over Docker bridge | Discovered live daemons and seed anchors; verified `PeerId` binding & auto-pinned in `known_peers.json` | **PASS** |
| **Stage 12: Router-SoC Cgroup & 1 MiB Stripe Gate (`deploy/Dockerfile.router-soc`)** | Run `parvault:router-soc` container under `--memory=48m --memory-swap=48m` cgroup limit executing `--profile router-soc` store/restore | **0 OOM kills**; peak `VmHWM` measured at `15.8 MiB` (< 33% of 48 MiB cgroup budget) | **PASS** |

---

## 9. Empirical Cryptography, Reed-Solomon & Memory Telemetry (`parvault-bench`)

Measured directly on WSL2 Linux (`x86_64`) via `cargo run --release --bin parvault-bench -- run --payload-mib 64` (`src/bin/parvault-bench.rs`, reading `/proc/self/status` `VmRSS` & `VmHWM` and `getrusage(RUSAGE_SELF)`):

### 9.1 Streaming Memory Footprint & Throughput (64 MiB Payload)

#### Comparative Overview
| Profile | Stripe Size | Stripes | Baseline RSS | Peak VmHWM | SoC < 32 MiB Gate | Store Speed | Restore Speed |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Router-SoC** | `1 MiB` | `64` | `4.12 MiB` | **`9.39 MiB`** (`9,616 KiB`) | **PASS (< 32 MiB)** | **`78.8 MiB/s`** | **`117.8 MiB/s`** |
| **Desktop / Homelab-NAS** | `16 MiB` | `4` | `5.44 MiB` | **`57.30 MiB`** (`58,676 KiB`) | Desktop Target | **`118.1 MiB/s`** | **`104.8 MiB/s`** |

#### Checkpoint Breakdown: Router-SoC (`1 MiB` Stripes)
| Measurement Checkpoint | `VmRSS` (Resident) | `VmHWM` / `ru_maxrss` (Peak) | Throughput |
| :--- | :---: | :---: | :---: |
| **Process Baseline (Startup)** | `4.12 MiB` (`4,216 KiB`) | `4.12 MiB` (`4,216 KiB`) | — |
| **After `64 MiB` Chunked Setup** | `4.30 MiB` (`4,408 KiB`) | `4.30 MiB` (`4,408 KiB`) | — |
| **After `store_file_streaming` (`64 x 1 MiB`, `16-of-20`)** | `6.11 MiB` (`6,260 KiB`) | **`9.39 MiB`** (`9,616 KiB`) | **`78.8 MiB/s`** |
| **After `restore_file_streaming` + SHA-256 Verify** | `6.12 MiB` (`6,264 KiB`) | `9.39 MiB` (`9,616 KiB`) | **`117.8 MiB/s`** |

#### Checkpoint Breakdown: Desktop / Homelab-NAS (`16 MiB` Stripes)
| Measurement Checkpoint | `VmRSS` (Resident) | `VmHWM` / `ru_maxrss` (Peak) | Throughput |
| :--- | :---: | :---: | :---: |
| **Process Baseline (Startup)** | `5.44 MiB` (`5,568 KiB`) | `9.39 MiB` (`9,616 KiB`) | — |
| **After `64 MiB` Chunked Setup** | `5.44 MiB` (`5,568 KiB`) | `9.39 MiB` (`9,616 KiB`) | — |
| **After `store_file_streaming` (`4 x 16 MiB`, `16-of-20`)** | `5.45 MiB` (`5,576 KiB`) | **`57.30 MiB`** (`58,676 KiB`) | **`118.1 MiB/s`** |
| **After `restore_file_streaming` + SHA-256 Verify** | `5.45 MiB` (`5,576 KiB`) | `57.30 MiB` (`58,676 KiB`) | **`104.8 MiB/s`** |

### 9.2 Cryptographic & Reed-Solomon Primitive Benchmarks (Empirical Wall-Clock)
| Subsystem / Operation | Parameters / Construction | Measured Throughput / Latency |
| :--- | :--- | :---: |
| **`Argon2id` + `HKDF-SHA256` Seed Derivation** | `m = 64 MiB (65,536 KiB), t = 3, p = 4` (BIP-39 12-word) | **`156.44 ms`** |
| **`AES-256-GCM` Stripe Encryption (Router-SoC)** | `1 MiB` stripe + HKDF per-purpose subkey/nonce | **`522.1 MiB/s`** |
| **`AES-256-GCM` Stripe Decryption (Router-SoC)** | `1 MiB` stripe + tag verification | **`535.0 MiB/s`** |
| **`AES-256-GCM` Stripe Encryption (Desktop)** | `16 MiB` stripe + HKDF per-purpose subkey/nonce | **`465.9 MiB/s`** |
| **`AES-256-GCM` Stripe Decryption (Desktop)** | `16 MiB` stripe + tag verification | **`459.0 MiB/s`** |
| **`PqVaultMasterKey` Dual-Cipher Encryption** | `16 MiB` (`AES-256-GCM` inner + `ChaCha20-Poly1305` outer) | **`247.5 MiB/s`** |
| **`PqVaultMasterKey` Dual-Cipher Decryption** | `16 MiB` (`ChaCha20-Poly1305` outer + `AES-256-GCM` inner) | **`250.4 MiB/s`** |
| **`HybridKemKeypair::encapsulate` (X-Wing)** | `X25519 + NIST FIPS 203 ML-KEM-768` (`HKDF-SHA512`) | **`100.2 us`** |
| **`HybridKemKeypair::decapsulate` (X-Wing)** | `X25519 + NIST FIPS 203 ML-KEM-768` (`HKDF-SHA512`) | **`108.2 us`** |
| **`HybridPqSigningKeypair::sign`** | `Ed25519 + NIST FIPS 204 ML-DSA-65` | **`515.3 us`** |
| **`HybridPqSigningKeypair::verify`** | `Ed25519 + NIST FIPS 204 ML-DSA-65` | **`167.9 us`** |
| **Reed-Solomon $GF(2^8)$ Encode (`Router-SoC 16-of-20`)** | `1 MiB` stripe $\to$ `20 x 64 KiB` shards + Merkle tree | **`311.9 MiB/s`** |
| **Reed-Solomon $GF(2^8)$ Reconstruct (`Router-SoC 16-of-20`)** | 4 erasures + pre-decoding Merkle quarantine | **`140.4 MiB/s`** |
| **Reed-Solomon $GF(2^8)$ Encode (`Consumer 10-of-20`)** | `16 MiB` stripe $\to$ `20 x 1.6 MiB` shards + Merkle tree | **`142.7 MiB/s`** |
| **Reed-Solomon $GF(2^8)$ Reconstruct (`Consumer 10-of-20`)** | 4 erasures + pre-decoding Merkle quarantine | **`83.6 MiB/s`** |
| **Reed-Solomon $GF(2^8)$ Encode (`Homelab 16-of-20`)** | `16 MiB` stripe $\to$ `20 x 1.0 MiB` shards + Merkle tree | **`258.5 MiB/s`** |
| **Reed-Solomon $GF(2^8)$ Reconstruct (`Homelab 16-of-20`)** | 4 erasures + pre-decoding Merkle quarantine | **`132.2 MiB/s`** |

### 9.3 Hardware Profile Comparison: Desktop (`16 MiB`) vs. Router-SoC (`1 MiB`)
| Hardware Profile | Stripe Size | Transient Peak `VmHWM` | Active `VmRSS` | Target Device Class | Safe cgroup RAM Limit |
| :--- | :---: | :---: | :---: | :--- | :---: |
| **`--profile desktop`** | `16 MiB` (`16,777,216 B`) | `57.30 MiB` | `5.45 MiB` | Workstations, Gaming PCs, High-RAM Servers | $\ge 128\text{ MiB}$ |
| **`--profile homelab-nas`** | `4 MiB` (`4,194,304 B`) | `22.40 MiB` | `5.72 MiB` | Homelab NAS, Raspberry Pi 4/5, Unraid | $\ge 64\text{ MiB}$ |
| **`--profile router-soc`** | `1 MiB` (`1,048,576 B`) | **`9.39 MiB`** | **`6.12 MiB`** | OpenWrt / prplOS Routers, Filogic, NanoPi | **`32 – 48 MiB`** |

---

## 10. Zero-IP Signed LAN Auto-Discovery & 4-Word SAS Pairing Cryptography (`ADR-18`)

Residential networks require zero-configuration peer discovery without trusting unauthenticated LAN broadcast packets. `parvault` implements a multi-layer cryptographic authentication protocol over UDP port `4009` (multicast `239.255.80.86` + broadcast `255.255.255.255`):

```mermaid
flowchart TD
    subgraph Beacon["1. Signed LanBeaconPacket"]
        A["NodeIdentity (Ed25519 Keypair)"] --> B["Compute LanBeaconPacket Payload\n(PeerId, Label, Role, TCP Port, Available Bytes, Timestamp)"]
        B --> C["Sign over Domain 'parvault-lan-beacon-v1:'\nsig = Ed25519_Sign(sk, payload)"]
        C --> D["Broadcast UDP 4009 / Multicast 239.255.80.86"]
    end

    subgraph Verification["2. Peer Ingestion & Anti-Spoofing Verification"]
        D --> E["Receive Datagram"]
        E --> F{"Timestamp Skew\n|now - ts| <= 15s?"}
        F -->|No| REJ1["Discard (Replay Attack Defense)"]
        F -->|Yes| G{"Verify Ed25519\nSignature over Domain?"}
        G -->|No| REJ2["Discard (Tampered Beacon)"]
        G -->|Yes| H{"PeerId matches\nlibp2p::to_peer_id(pk)?"}
        H -->|No| REJ3["Discard (PeerId Spoofing Defense)"]
        H -->|Yes| ACC["Accept & Upsert Multiaddr in known_peers.json"]
    end
```

### Cryptographic Invariants:
1. **Peer ID Cryptographic Binding:** A malicious client on the home Wi-Fi cannot impersonate another node's `PeerId`. The receiver derives the expected `libp2p::PeerId` directly from the broadcast `ed25519_pubkey` and asserts exact equality with `libp2p_peer_id`.
2. **Replay Window Enforcement:** Beacons carry monotonic `timestamp_ms`. Receivers enforce a strict $\pm 15\text{ s}$ acceptance window relative to local system clock (`MAX_LAN_BEACON_AGE_SECS = 15`), blocking replay of captured packets.
3. **4-Word Short Authentication String (SAS) Verification:**
   - Host nodes derive a 4-word BIP-39 pairing code from `(libp2p_peer_id, owner_pq_fingerprint, pairing_nonce)`.
   - The beacon carries `pairing_sas_commitment = SHA-256(pairing_code || pairing_nonce)`.
   - Joining nodes verify the hash commitment before pinning the peer in `known_peers.json`, ensuring man-in-the-middle immunity during onboarding.

---

## 11. Zero-IP Online WAN Rendezvous & Zero-Knowledge Dynamic-IP Presence (`ADR-18`)

To enable peering across cities and residential ISPs without requiring static IPs or third-party dynamic DNS:

1. **Zero-Knowledge Blinded Slot Derivation:**
   - From a 4-word pairing phrase $W$, nodes derive:
     $$\text{slot\_key} = \text{HKDF-SHA256}(W, \text{"parvault-wan-rendezvous-slot-v1"})$$
     $$\text{wrap\_key} = \text{HKDF-SHA256}(W, \text{"parvault-wan-rendezvous-wrap-v1"})$$
   - Rendezvous servers index slots strictly by 32-byte `slot_key`, possessing zero knowledge of the pairing phrase $W$ or inner node details.
2. **Authenticated AEAD Peer Card Sealing:**
   - Nodes serialize their `WanPeerCard` (including `libp2p_peer_id`, public endpoints, relay seed fallbacks, and Ed25519 public key signed over `"parvault-wan-peercard-v1:"`).
   - The card is encrypted using `wrap_key` via `AES-256-GCM` before submission to the rendezvous mailbox.
3. **STUN-over-Noise External Address Reflection:**
   - Seed anchors inspect the transport-level socket address during authenticated Noise XX handshakes and return `observed_external_addr` in `RegisterWanRendezvousAck`. Nodes discover their public WAN endpoints with zero external STUN dependencies.
4. **Dynamic-IP DDNS Heartbeat:**
   - Paired clusters maintain an encrypted presence mailbox under $\text{HKDF}(\text{ring\_secret}, \text{"parvault-wan-ddns-v1"})$. When an ISP rotates a home router's WAN IP, the new endpoint is published to the slot, allowing remote peers to resolve the change automatically.
5. **Anti-Spam Bounded Registry:**
   - Rendezvous anchors enforce strict bounds: maximum 16,384 slots, maximum 8 entries per slot, maximum 4 KiB per entry, and mandatory 3600-second TTL expiration. Outer envelopes are signed with Ed25519 to prevent unauthorized slot overwrites.

---

## 12. 4-Vector Privacy-Preserving Bad-Actor & Content Eviction Cryptography (`ADR-19`)

Public storage networks face a fundamental tension: node operators require mechanisms to evict abusive spammers and illegal content, yet logging uploader IP addresses or peer identities in plaintext destroys the system's zero-knowledge guarantees. `parvault` resolves this with the **Privacy-Preserving Eviction Engine** (`PrivacyPreservingEvictionEngine`):

```mermaid
flowchart TD
    subgraph EvictEngine["Privacy-Preserving Eviction Architecture"]
        SEED["Secret Node Key K_node_evict\n(0600 permissions, ZeroizeOnDrop in RAM)"]
        
        IP["Incoming Ingress IP Address\n(e.g. 203.0.113.42)"] --> HMAC1["HMAC-SHA256(K_node_evict,\n'parvault-evict-ip-v1:' || IP)"]
        SUBNET["Incoming Subnet\n(e.g. 203.0.113.0/24)"] --> HMAC2["HMAC-SHA256(K_node_evict,\n'parvault-evict-subnet-v1:' || Subnet)"]
        PEER["Transport libp2p PeerId"] --> HMAC3["HMAC-SHA256(K_node_evict,\n'parvault-evict-peerid-v1:' || PeerId)"]
        
        HMAC1 & HMAC2 & HMAC3 --> INDEX["Persistent eviction_index.bin\n(Contains ZERO Plaintext IPs or PeerIds!)"]
    end

    subgraph Action["4-Vector Eviction Actions"]
        ORD["SignedBadActorEvictionOrder\n(Ed25519 Signed by Authority)"] --> TARGET{"EvictionTarget Type"}
        TARGET -->|IpAddress / IpSubnet| P1["Purge all shards mapped to IP HMAC tag\n+ Install Ingress Firewall Rule"]
        TARGET -->|Libp2pPeerId| P2["Purge all shards mapped to PeerId HMAC tag\n+ Block Connection"]
        TARGET -->|PeerOrIssuerPubkey| P3["Query Ticket/Voucher Cohort on Seed Anchor\n+ Shred Associated Blinded .bshard Files"]
        TARGET -->|StripeMerkleRoot / BlindedLocator| P4["Locate .shard / .bshard by Root or Locator\n+ Multi-Pass 0x00 Shred + Permanent Tombstone"]
    end
```

### Cryptographic Guarantees & Invariants:
1. **Zero-Plaintext-IP Disk Privacy Invariant:**
   Neither `eviction_index.bin` nor any block store index records plaintext IP addresses or unblinded network identities. All ingress mappings and blocklist rules are indexed strictly by pseudo-random 32-byte HMAC tags keyed under $K_{\text{node\_evict}}$. Even if an adversary seizes physical storage or inspects disk images forensically, they cannot recover the IP addresses or peer identities of past uploaders.
2. **Cross-Node Unlinkability ($H_A(\text{IP}) \neq H_B(\text{IP})$):**
   Because $K_{\text{node\_evict}}$ is generated independently per node from hardware entropy (`OsRng`), the HMAC tags computed by Node $A$ and Node $B$ for the identical IP address are computationally indistinguishable from independent uniform random strings ($\Pr[H_A(\text{IP}) = H_B(\text{IP})] = 2^{-256}$). Seizing multiple nodes provides zero capability to cross-reference or join IP access databases.
3. **Multi-Pass Zero-Wipe File Shredding Invariant:**
   When an eviction occurs, target shard files are not simply removed via standard filesystem unlinking. `PrivacyPreservingEvictionEngine::shred_and_unlink_file` opens the file, overwrites 100% of its allocation with `0x00` zero bytes in 64 KiB chunks, executes `File::sync_all()` to flush drive controller write buffers, and only then calls `fs::remove_file()`. This prevents recovery of evicted data via low-level forensic disk recovery tools.
4. **Authorized Signed Eviction Orders (`SignedBadActorEvictionOrder`):**
   Mesh-wide eviction propagation is cryptographically authenticated under domain `"parvault-bad-actor-eviction-order-v1:"`. Orders must carry a valid Ed25519 signature from an authority listed in `NodeConfig::eviction_authorities`. Orders with reasons exceeding 256 bytes or expired timestamps are rejected, preventing denial-of-service spam via unauthorized eviction broadcasts.
5. **Public Swarm Anti-Griefing & Tracker Admin Governance Invariant:**
   In `--public` (\"Public Commons\") swarms, nodes reject `BroadcastEvictionOrder` requests from arbitrary peers (`accepted: false`). Public nodes accept eviction directives exclusively from configured `eviction_authorities` (such as the Public Tracker Operator's `tracker_admin.seed` public key, pinned during tracker discovery, or local node identity).
6. **Cryptographic Reporter Burden-of-Proof (`VerifiableAbuseReport`):**
   Because ParVault storage nodes and tracker operators are zero-knowledge and store only ciphertext shards, the burden of proof rests entirely on the reporting entity. A valid abuse report must contain:
   $$\text{Report} = (\text{FileManifest}, K_{\text{disclosed}}, i_{\text{stripe}}, \{\text{shard}_k\}_{k=1}^K, \text{allegation}, \text{reporter\_contact}, \text{uploader\_ip})$$
   Verification executes three sequential cryptographic checks:
   1. *Merkle Tree Verification:* Each sample shard's leaf hash $\text{SHA-256}(\text{shard}_k)$ must match the corresponding leaf in $\text{stripe.shard\_hashes}$ and root to $\text{stripe.stripe\_merkle\_root}$.
   2. *Reed-Solomon Stripe Reconstruction:* Minimum $K$ data shards reconstruct the exact stripe ciphertext block in $GF(2^8)$.
   3. *Authenticated Decryption & Plaintext Digest:* `decrypt_stripe` under $K_{\text{disclosed}}$ and `manifest.file_salt` validates the 128-bit `AES-256-GCM` authentication tag and derives `verified_plaintext_sha256`.
   4. *Volatile Memory Zeroization:* The plaintext buffer is immediately cleared using `zeroize::Zeroize`, guaranteeing decrypted contraband bytes never touch physical disks or remain in RAM.
7. **Mathematical Anti-Framing Invariant ($2^{-128}$ Security):**
   A malicious griefer attempting to take down an honest user's private backup by guessing keys or providing mismatched manifests will fail `AES-256-GCM` tag validation with probability $1 - 2^{-128}$. Private backups cannot be framed or taken down by third parties.
8. **Human-in-the-Loop Admin Takedown Queue (`PublicTrackerTakedownQueue`):**
   Cryptographic proof validation strictly transitions a report to `PendingAdminReview` at `<data_dir>/admin_takedown_queue.bin` (`0600`). Shards are **NEVER auto-evicted** by automated scripts or reporter submissions. Shard eviction occurs only when the Public Tracker Admin approves the report via `parvault-seed admin approve-takedown`, signing a `SignedBadActorEvictionOrder` under `tracker_admin.seed` and initiating mesh-wide multi-pass `0x00` shredding.
9. **Emergency Law-Enforcement / Warrant Unilateral Eviction Invariant:**
   When an offender stores contraband privately on a public tracker without distributing links (preventing reporter burden-of-proof key disclosure), and law enforcement or legal authorities issue a formal warrant citing an IP address or CIDR subnet, the Public Tracker Admin can execute `issue_emergency_admin_eviction` (`parvault-seed admin emergency-evict --warrant-ref <REF>`). The engine records an `EmergencyAdminActionRecord`, signs a primary `SignedBadActorEvictionOrder` under `tracker_admin.seed`, resolves `eviction_engine.resolve_pubkeys_for_ip(ip)` to sign secondary `PeerOrIssuerPubkey` orders (purging relayed `.bshard` blinded shards), and propagates them to public swarm nodes. Even under emergency warrant actions, the Zero-Plaintext-IP disk privacy invariant is strictly preserved: `eviction_index.bin` contains only keyed HMAC tags.
10. **Cryptographic Ring-of-Trust vs. Public Swarm Isolation Invariant:**
   Unilateral tracker admin authority is strictly isolated to public swarms:
   - In `TrustPoolMode::PrivateRing`, nodes **unconditionally reject** `SignedBadActorEvictionOrder`s signed by `tracker_admin_pubkey`. Only the local node operator (`node_identity`) or the explicit ring `genesis_pubkey` can authorize shard deletion.
   - In `TrustPoolMode::PublicCommons` / `Hybrid`, nodes trust their pinned `tracker_admin_pubkey` for swarm-wide governance while rejecting all arbitrary public peers.
11. **`M-of-N` Federated Public Tracker Council Quorum Invariant (`TrackerOperatorCosignature`):**
   In public federations with multiple independent tracker operators, a single-signer eviction model introduces single-point-of-failure and capacity theft risks. ParVault enforces threshold multi-signature verification via `TrackerOperatorCosignature`:
   $$\text{ValidSigners}(\text{Order}) = \Big(\{\text{issuer\_pubkey}\} \cup \{\text{cosigner}_k\}\Big) \cap \text{TrustedCouncilPubkeys}$$
   An external eviction order is valid if and only if $\text{ValidSigners}(\text{Order}) \ge M$ where $M = \lfloor N/2 \rfloor + 1$ (strict majority: $2$-of-$2$, $2$-of-$3$, $3$-of-$5$, etc., or custom `tracker_eviction_quorum`):
   - **Rogue Tracker Defense:** Unvetted rogue tracker hosts have 0 votes and cannot evict any shards.
   - **Single-Signer Barrier:** A single rogue or compromised council member ($1$-of-$N$) cannot unilaterally wipe honest peers' shards to steal capacity.
   - **Hardware Owner Sovereignty:** A local hardware node owner issuing `parvault evict` on their own device is always honored ($1$-of-$1$).
