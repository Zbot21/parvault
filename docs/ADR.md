# ParVault Daemon (`parvault`) — Architectural Decision Records (ADR)

- **Status:** Approved for Implementation (`/grill-me` Session)
- **Target Build & Verification Environment:** Option B — WSL2 Linux-First + Static `musl` (`x86_64-unknown-linux-musl` & `aarch64-unknown-linux-musl`)
- **Source Specification:** [Neighborhood Cloud / Project ParVault — Technical Architectural Brief](https://docs.google.com/document/d/19LJjcNFVoAyE-TvuVt6HCg-h7AU90CiI-ZyCsXbba_Q/edit?tab=t.0)
- **Google Doc ADR Tab:** [Architectural Decisions (ADR)](https://docs.google.com/document/d/19LJjcNFVoAyE-TvuVt6HCg-h7AU90CiI-ZyCsXbba_Q/edit?tab=t.hmtpb356or1e)

---

## 1. Executive Summary of Resolved Protocol Decisions

| ADR ID | Subsystem | Decision Summary | Primary Guarantee |
| :--- | :--- | :--- | :--- |
| **ADR-01** | `crypto` / `sharding` | Fixed-size **16 MB streaming stripes** with per-stripe derived AES-256-GCM nonces and independent $k$-of-$n$ Reed-Solomon shard sets | Caps daemon RAM footprint $< 32\text{ MB}$ on constrained prplOS/OpenWrt gateways even during 1 GB+ vault transfers |
| **ADR-02** | `storage` / `kad` | Local manifest index backed by **encrypted Manifest records in the Kademlia DHT** (keyed by HMAC of master key) | Full zero-knowledge vault recovery from any node using only the user's master key / seed phrase |
| **ADR-03** | `por` / `verifier` | **Owner + delegated witness nodes** sharing derived $K_{\text{session}}$ tokens for continuous stateless HMAC PoR challenges | Sustains $\le 300\text{ ms}$ SLA auditing and proactive 18/20 repair even when the uploading node is offline |
| **ADR-04** | `por` / `sharding` | **Signed `RepairGrant` tokens + $\ge 2$ co-signed failed-PoR witness proofs** required to unlock raw ciphertext shard reads | Enables zero-knowledge ciphertext Reed-Solomon repair while preserving reconstruction-attack immunity |
| **ADR-05** | `network` / `wot` | **Signed Ed25519 delegation chains** (`Genesis -> Inviter -> Invitee`) with Gossipsub slashing propagation | Isolates malicious or failing subtrees within $\le 3$ invalid handshakes or audit failures |
| **ADR-06** | `network` / `behaviour` | **Hybrid offline locality engine**: `/24` IPv4 & `/48` IPv6 prefix affinity + live RTT probing ($\le 5\text{ ms}$) + compact ASN table | Enforces 70% Intra-ASN / Low-RTT and 30% Cross-Region shard placement without BGP router feeds |
| **ADR-07** | `storage` / `quota` | **Tier-weighted byte-hour credit ledger** ($1.25\times$ Homelab SLA vs. $2.0\times$ Consumer SLA) with bootstrap grace quota | Prevents free-riding while rewarding $>99.5\%$ uptime homelab nodes with 80% net storage efficiency |
| **ADR-08** | `network` / `transport` | **TCP + Noise XX + Yamux** primary transport stack with optional config-enabled QUIC listener | Strictly enforces stateless Noise handshakes while minimizing static `musl` binary size |
| **ADR-09** | `sharding` / `por` / `storage` | **Zero-Trust Adversarial Hardening** (Pre-Decoding Merkle Quarantine, Stratified PoR + RTT Bound, Signed Monotonic DHT Envelopes, Egress-Withholding Credit Slashing, Unlinkable Pseudonyms & ISO Padding) | Defeats Byzantine shard poisoning, proxy outsourcing, manifest rollback, hostage withholding, and metadata correlation |
| **ADR-10** | `network` / `storage` / `sync` | **Dynamic Uptime Trust Levels** (`UntrustedProbationary` $\rightarrow$ `VerifiedNeighbor` $\rightarrow$ `HighUptimeAnchor` $\rightarrow$ `SlashedQuarantined`), **Tiered Subnet Concentration Caps** (`1` / `2` / `4` / `0` shards), and **Continuous Folder-Sync Daemon** (`FolderSyncEngine`) | Eliminates static node-count fragile bottlenecks while preserving information-theoretic zero-knowledge secrecy ($4 < K = 16$) and providing incremental encrypted directory backup |
| **ADR-11** | `crypto` / `por` / `storage` / `network` | **4-Layer Cryptographic Shard Anonymization** (Blinded Locators, Per-Shard Capability Keys $V_i$, Ephemeral-Issuer Bearer Quota Vouchers, 2-Layer PQ Onion Relaying) & **Degraded-Network Hedged Parallel Recovery** (`tests/anonymity_and_degraded_net_tests.rs`) | Eliminates structural stripe/index, PoR key, reciprocity ledger, and network-origin correlation ($\ge 2^{224}$ static disk combinatorial wall) while sustaining zero-data-loss recovery across 8 degraded WAN/hardware profiles |
| **ADR-12** | `crypto` / `por` / `network` / `storage` | **Post-Quantum Hybrid Cryptography**: `X25519 + ML-KEM-768` (NIST FIPS 203, X-Wing `HKDF-SHA512`), `Ed25519 + ML-DSA-65` (NIST FIPS 204), and **Dual-Cipher Cascaded AEAD (`AES-256-GCM` + `ChaCha20-Poly1305`)** (`PqVaultMasterKey`) | Immunizes long-lived backup shards, 2-layer onion relay envelopes, DHT manifests, and Web-of-Trust certificates against **Harvest-Now, Decrypt-Later (HNDL)** and quantum forgery attacks under Shor's algorithm while maintaining NIST Category 5 128-bit post-quantum Grover security and cipher-diversity defense-in-depth |
| **ADR-13** | `bootstrap` / `sharding` / `storage` | **Day-1-to-10,000-User Elastic Bootstrap & Earned Tier Progression** (`EarnedStanding::evaluate`, `PersonalDeviceCert`, `FoundationSeedAnchor` auto-drain, zero-knowledge `reshard_ciphertext_stripe_elastic`, and `/24` Sybil-damped Pioneer Standby Mining) | Solves P2P cold-start from `0` organic peers to `10,000+` users while enforcing that `16-of-20` Homelab efficiency (`1.25x` tax) is strictly **earned** via sustained PoR uptime rather than manually selected |
| **ADR-14** | `parvault-seed` / `telemetry` | **Dedicated Zero-Trust Seed Server (`parvault-seed`)** (`HomelabRedundancyVault` & `PublicNetworkBootstrapper` modes) & **Zero-Knowledge Anonymous Network Census Telemetry** (`AnonymousTelemetryBeacon`, `NetworkCensusAggregator`) | Packages a headless zero-plaintext seed/redundancy server binary with inverted-bell-curve cloud bootstrap economics (`~$95/mo` at 10,000+ users) and measures network size/regional extent via rotating epoch nullifiers and PQ onion beacons without IP or `PeerId` tracking |
| **ADR-15** | `crypto` / `storage` / `network` / `sync` | **Multi-Domain Red-Team Hardening & Zero-Local-State "House Fire" Recovery** (`MasterKey::from_recovery_seed_phrase` via `Argon2id`, `EncryptedVaultCatalogEnvelope`, capability pinning, $\pm 30\text{ s}$ NTP skew, generation-scoped tombstones, `with_limit` OOM defense, and atomic `fsync` + `rename`) | Enables full directory recovery from a 24-word seed phrase alone after total local disk loss while neutralizing 18 adversarial crypto, Sybil, wire-OOM, and path-traversal attack vectors |
| **ADR-16** | `cli` / `sync` / `por` / `storage` / `docs` | **Internet-Grade Sync Usability, Constant-Memory 64 KiB Streaming Hashing, Bounded Replay Caches & Sharded Documentation** (`identity`, `issue-device-cert`, `PARVAULT-CERT-V1:` tokens, `.parvaultignore`, `diff-folder`, `--prune-deleted`, `--file` selective restore, `recover-from-seed`, `scrub`, and 65,536-entry FIFO caches) | Eliminates CLI/documentation mismatches, guarantees `< 32 MiB` RAM during multi-GiB folder syncs, prevents long-running replay-cache RAM growth, and shards documentation by user persona |
| **ADR-17** | `network` / `sync` / `parvault-seed` / `ci` | **Live `libp2p` Mesh Client, Lite-Client `1.0x` Seed Syndication, NAS-Death Direct-Mesh Failover, Selective `--filter` Restore & 13-Container Docker CI Gate** (`MeshClient`, `MeshWireRequest` Phase 1–4 RPCs, `DeleteShard`, `SyndicateLiteStripe`, `scripts/docker_acceptance_gate.sh`) | Wires all CLI & daemon workflows over real `libp2p` TCP + Noise XX + Yamux, enables `1.0x` laptop-to-seed syndication with automatic NAS-death mesh failover, and verifies every capability across 13 isolated Docker containers in CI |

---

## 2. Detailed Protocol Specifications

### ADR-01: 16 MB Streaming Stripes for Bounded Gateway Memory
- **Context:** Target hardware includes prplOS/OpenWrt LXC containers with 128–512 MB system RAM, whereas the validation workload processes 1 GB+ vault payloads.
- **Decision:** Large files are processed via an async streaming pipeline in fixed **16 MB segments**. Each stripe $i$ derives a deterministic 96-bit nonce $N_i = \text{HKDF-Expand}(K_{\text{user}}, \text{FileSalt} \parallel i)$, is encrypted with AES-256-GCM, and is striped into $K$ data shards + $M$ parity shards (e.g., $10 \times 1.6\text{ MB}$ data shards + $10 \times 1.6\text{ MB}$ parity shards). Each stripe forms a shard-level Merkle tree whose roots roll up into the top-level File Merkle Root.

### ADR-02: Zero-Knowledge Disaster Recovery via DHT-Backed Encrypted Manifests
- **Context:** If a user's home node suffers catastrophic disk loss, local manifest mappings (Merkle root $\rightarrow$ shard hashes, target `PeerId`s, nonces, and $k$-of-$n$ parameters) would be lost unless replicated.
- **Decision:** Every File Manifest is serialized with `bincode`, encrypted under $K_{\text{user}}$ via AES-256-GCM, cached locally, and published to the Kademlia DHT under key $K_{\text{dht}} = \text{HMAC-SHA256}(K_{\text{user}}, \text{"parvault-manifest"} \parallel \text{VaultPath})$. A root vault catalog record at $\text{HMAC-SHA256}(K_{\text{user}}, \text{"parvault-vault-root"})$ indexes all active manifest keys so a user can restore their entire vault on a fresh node using only their master key/seed phrase.

### ADR-03 & ADR-04: Delegated Witness Auditing & `RepairGrant` Ciphertext Reconstruction
- **Context:** Because AES-256-GCM encryption occurs *before* Reed-Solomon splitting, missing shards can be reconstructed purely over ciphertext in $GF(2^8)$ without $K_{\text{user}}$. However, `por::verifier` blocks arbitrary raw byte reads to prevent pre-image and reconstruction attacks.
- **Decision:**
  1. **Stateless PoR Audits:** On upload, the owner provisions designated cohort Witness Nodes with derived $K_{\text{session}}$ challenge keys and a signed `RepairGrant` descriptor. Routine audits strictly use stateless RAM-verified HMAC tokens (`H_chal = HMAC(K_session, ShardID || Nonce || Offset || Length)`) and return salted commitments (`SHA-256(Nonce || Data[Offset..Offset+Length])`).
  2. **Authenticated Offline Repair:** Storage nodes refuse raw ciphertext shard reads unless the requester presents either (a) an owner-signed read token, or (b) the file's signed `RepairGrant` accompanied by a threshold **Proof-of-Degradation** co-signed by $\ge 2$ designated witnesses attesting to PoR timeouts/failures (e.g., when a $16$-of-$20$ Homelab cohort drops from 20 to 18 active shards). Reconstructed shards are verified against the stripe's Merkle tree before re-replication.

### ADR-05: Recursive Ed25519 Web-of-Trust & Subtree Slashing
- **Context:** Uninvited Sybil nodes must be rejected at handshake time, and dishonest/failing branches must be isolated within $\le 3$ failures.
- **Decision:** Peers authenticate with a bounded-depth Ed25519 certificate chain (`Genesis -> ... -> Inviter -> Invitee`) verified during the Noise XX handshake. Accumulating $\ge 3$ invalid handshakes or unexcused PoR failures produces a signed `SlashingEvidence` payload gossiped via `gossipsub`, immediately quarantining the leaf node and incrementing its parent inviter's slash counter until the parent branch is pruned at threshold $M$.

### ADR-06: Hybrid Offline Network Proximity & 70/30 Shard Placement
- **Context:** Daemons must enforce a 70% Intra-ASN / Low-RTT and 30% Cross-Region shard placement split without requiring external BGP feeds, while working deterministically in private IP (`10.42.0.0/16`) Docker/Shadow testbeds.
- **Decision:** Kademlia distance is weighted by live RTT probing ($D_{\text{effective}} = D_{\text{XOR}} \times \text{RTT}_{\text{weight}}$). Nodes classify peers into the Local/Intra-ASN cohort using:
  1. `/24` IPv4 or `/48` IPv6 subnet prefix affinity,
  2. Active RTT probe latency $\le 5\text{ ms}$, and
  3. An embedded compact IP-to-ASN lookup table (with deterministic `asn` / `region` override fields in `config.toml` for multi-container and Shadow simulations).

### ADR-07: Tier-Weighted Reciprocity Ledger & Bootstrap Grace Quota
- **Context:** Homelab nodes ($>99.5\%$ 30-day PoR SLA) operate at 80% efficiency ($16$-of-$20$, $1.25\times$ expansion), while Consumer gateways operate at 50% efficiency ($10$-of-$20$, $2.0\times$ expansion).
- **Decision:** `storage::quota` tracks per-peer byte-hours hosted and rolling PoR pass rates, enforcing a $1.25\times$ reciprocity multiplier for verified Homelab SLA peers and a $2.0\times$ multiplier for Consumer peers, plus a configurable initial bootstrap grace quota for newly invited nodes.

### ADR-08: Primary TCP + Noise XX + Yamux Transport, Versioned `bincode` Wire Framing & WSL2 Build Pipeline
- **Context:** `libp2p` QUIC uses TLS 1.3 whereas TCP uses Noise XX + Yamux. In addition, the P2P request-response codec requires compact binary framing with strict pre-authentication allocation bounds and protocol version isolation.
- **Decision:**
  1. `network::transport` standardizes on **TCP + Noise XX + Yamux** as the primary transport (satisfying strict Noise handshake semantics and minimizing `musl` binary size), with an optional config flag to enable a secondary QUIC listener.
  2. **Wire Protocol Versioning & Bounded `bincode 1.3` Serialization (`E2`):** `BincodeWireCodec` negotiates the explicit protocol identifier `/parvault/wire/1.0.0` via `libp2p::request_response`, isolating the wire framing layer so future protocol versions (`/parvault/wire/2.0.0`) can evolve without breaking backwards compatibility. Every frame is capped at `MAX_WIRE_FRAME_BYTES = 32 MiB` (with a 64 KiB initial read reservation against Slowloris attacks) and deserialized via `bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_limit(buf.len() as u64)`.

---

## ADR-09: Zero-Trust Adversarial Hardening (Byzantine, Proxy, Hostage & Metadata Defenses)
- **Context:** In a strict zero-trust backup deployment where no storage, witness, or DHT node is trusted beyond cryptographically verifiable behavior, passive encryption (AES-256-GCM) and crash-fault erasure coding (`k-of-n`) must be augmented against active Byzantine and rational/selfish attacks.
- **Decision:**
  1. **Pre-Decoding Merkle Quarantine (`reconstruct_zero_trust_with_quarantine`):** Every shard is verified against its leaf SHA-256 and `MerkleProof` before entering the $GF(2^8)$ matrix; poisoned shards are evicted and their senders are immediately quarantined (`WebOfTrustRegistry::slash_immediately`).
  2. **Stratified Multi-Segment PoR + Anti-Proxy RTT Bound (`MultiSegmentPorChallenge`):** Challenges sample $M$ non-overlapping strata across the full shard with a per-challenge `max_rtt_ms` bound to defeat partial-retention and WAN-proxy outsourcing attacks.
  3. **Zero-Knowledge Signed Monotonic DHT Envelopes (`SignedDhtManifestEnvelope`):** DHT nodes verify the owner's Ed25519 signature and enforce strict version monotonicity (`new.monotonic_version > existing.monotonic_version`) without `K_user`.
  4. **Egress-Withholding Credit Slashing (`EgressWithholdingEvidence`):** Nodes that pass lightweight PoR challenges to farm credits but withhold bulk shard egress at restore time have 100% of their accumulated `bytes_contributed_by_peer` credits burned (`QuotaManager::slash_peer_for_withholding`).
  5. **Repair-Sink Eclipse Defense (`verify_witness_repair_deposit`):** Replacement storage nodes verify the `MerkleProof` of witness-reconstructed shards and enforce a strict per-ASN concentration cap (`max_shards_per_asn`).
  6. **Unlinkable Per-Shard Pseudonyms & ISO Bucket Padding:** Storage nodes index shards under `HMAC-SHA256(K_user, "parvault-shard-pseudonym-v1:" || root || idx)` and plaintexts are padded to power-of-two buckets (`pad_plaintext_iso_bucket`) to prevent metadata correlation and file-size fingerprinting.

---

## ADR-10: Dynamic Uptime Trust Levels, Tiered Subnet Quotas & Continuous Folder-Sync Daemon
- **Context:** In real-world neighborhood deployments, static per-subnet shard caps create a trade-off between small-cluster utilization and Sybil/collusion safety, while parent applications (`Neighborhood Cloud`) require continuous, deduplicated folder-level backup and restoration rather than one-off single-file invocations.
- **Decision:**
  1. **Dynamic Uptime Trust Ladder (`DynamicTrustLevel`):** Every peer and `/24` IPv4 (or `/48` IPv6) subnet progresses through four cryptographically audited trust states based on rolling Proof-of-Retrievability (PoR) pass history and egress reliability:
     - **`UntrustedProbationary`** (Newly invited / `< 50` consecutive PoR passes): Max **1 shard per `/24` subnet**, **$1.0\times$** reciprocity quota multiplier.
     - **`VerifiedNeighbor`** ($\ge 50$ consecutive PoR passes, $\ge 98.0\%$ SLA): Max **2 shards per `/24` subnet**, **$2.5\times$** reciprocity quota multiplier.
     - **`HighUptimeAnchor`** ($\ge 200$ consecutive PoR passes, $\ge 99.5\%$ 30-day Homelab SLA): Max **4 shards per `/24` subnet**, **$5.0\times$** reciprocity quota multiplier.
     - **`SlashedQuarantined`** (Any cryptographic fault: poisoned shard Merkle proof, forged handshake, or confirmed egress withholding): **0 shards allowed**, **100% accumulated byte-hour credit burn**, and immediate Gossipsub subtree quarantine.
  2. **Zero-Knowledge Collusion Immunity under Anchor Concentration (`4 < K = 16`):** Even if an entire `HighUptimeAnchor` subnet colludes, it holds at most $4$ ciphertext shards out of the $K = 16$ required for Reed-Solomon reconstruction ($4 \ll 16$), and possesses zero knowledge of the client-only master key $K_{\text{user}}$ or the per-stripe HKDF nonces. Consequently, subnet-level collusion yields identically **zero bits of plaintext information** (formally verified in `specs/ParVaultConfidentialityAndTrust.tla`).
  3. **Continuous Folder-Sync Engine (`FolderSyncEngine` & `FolderVaultCatalog`):** `storage::sync` provides an embeddable and CLI-driven (`parvault watch-folder` / `parvault restore-folder`) directory synchronization engine. It computes per-file SHA-256 content digests, skips unchanged files across polling epochs (incremental delta sync), removes deleted entries, encrypts and erasure-codes only modified files via the 16 MiB streaming pipeline, and publishes a monotonic, AES-256-GCM encrypted `FolderVaultCatalog` wrapped in a `SignedDhtManifestEnvelope` for zero-knowledge whole-folder disaster recovery.

---

## ADR-11: 4-Layer Cryptographic Shard Anonymization & Degraded-Network Hedged Recovery
- **Context:** Even when shards are encrypted with AES-256-GCM (`ADR-01`) and distributed across trust-capped `/24` subnets (`ADR-10`), a global or multi-subnet coalition of storage nodes could attempt to correlate which shards belong to the same stripe or owner by observing (1) shared stripe Merkle roots or explicit shard indices `0..19`, (2) shared stripe-wide PoR session keys, (3) direct per-peer reciprocity quota accounting tied to `uploader_peer_id`, or (4) direct source IP / `PeerId` transport connections during upload bursts. Furthermore, residential and mobile mesh deployments experience severe network and hardware degradation (high jitter, packet loss, CGNAT relay paths, slow USB/SD I/O, and low-RAM LXC containers) that can stall sequential $K$-shard retrieval.
- **Decision:**
  1. **Layer 1 — Blinded Shard Locators & Zero-Metadata Storage Envelopes (`AnonymousShardEnvelope`):** Storage nodes never receive `stripe_merkle_root`, `shard_index`, or sibling Merkle hashes. Each shard is addressed exclusively by an unlinkable 256-bit blinded locator:
     $$\text{Locator}_i = \text{HMAC-SHA256}(K_{\text{user}}, \text{"parvault-blinded-locator-v2"} \parallel \text{StripeRoot} \parallel \text{ShardIdx} \parallel \text{PerShardSalt}_i)$$
     Because $\text{HMAC-SHA256}$ keyed by the client-only master key $K_{\text{user}}$ is a pseudorandom function (PRF), any coalition of storage nodes holding a pool of $M$ total shards across the neighborhood faces an unguided combinatorial search space of:
     $$\Omega_{\text{search}} = \binom{M}{K} \times \frac{N!}{(N - K)!}$$
     Even for a modest pool of $M = 1,000$ shards with Homelab $16\text{-of-}20$ parameters, $\binom{1000}{16} \times \frac{20!}{4!} \approx 2^{115.6} \times 2^{59.8} \approx 2^{175.4}$ (and $\ge 2^{224}$ at $M \ge 8,000$), before still hitting the 256-bit AES-256-GCM authentication wall without $K_{\text{user}}$.
  2. **Layer 2 — Per-Shard Blinded PoR Capability Keys ($V_i$):** Instead of provisioning a shared stripe-level `K_session` to storage nodes, the owner derives an independent per-shard PoR capability key:
     $$V_i = \text{HMAC-SHA256}(K_{\text{session}}, \text{"parvault-shard-por-cap-v1"} \parallel \text{Locator}_i)$$
     Storage node $i$ stores only $(\text{Locator}_i, V_i, \text{Ciphertext}_i)$ and verifies stateless HMAC challenges against $V_i$, ensuring zero cross-shard cryptographic linkability across storage peers.
  3. **Layer 3 — Unlinkable Ephemeral-Issuer Bearer Quota Vouchers (`AnonymousQuotaVoucher` & `VoucherNullifierLedger`):** To decouple storage authorization from the uploader's identity, nodes mint one-time bearer quota vouchers (`AnonymousQuotaVoucher::mint_ephemeral`) signed by a fresh per-shard ephemeral `Ed25519` keypair (`ephemeral_issuer_pubkey`) rather than a static node identity. Storage nodes verify the signature and atomically record `voucher_nonce` in a disk-persisted, bounded 65,536-entry `VoucherNullifierLedger`, enforcing strict 1-to-1 byte-hour conservation without recording which `PeerId` owns the stored shard or linking shards across an upload batch.
  4. **Layer 4 — 2-Layer Post-Quantum Onion Relay Dispatch (`PqRelayedShardEnvelope` & `PqInnerStorageEnvelope`):** Shard uploads are wrapped in a **2-layer post-quantum onion envelope**:
     - **Inner Layer (`PqInnerStorageEnvelope`):** Sealed under the destination storage node's `HybridKemPublicKey` (`X25519 + ML-KEM-768`), encrypting `(blinded_id, shard_bytes, capability, voucher, current_epoch, lease_duration_epochs, delete_verifier)`.
     - **Outer Layer (`PqRelayedShardEnvelope`):** Sealed under the intermediate relay node's `HybridKemPublicKey`, encrypting `(target_peer_addr, inner_envelope, jitter_delay_ms)`.
     - The relay node peels only the outer layer to learn `target_peer_addr` and `jitter_delay_ms`—never observing `blinded_id`, `capability`, `voucher`, or `shard_bytes` in plaintext—while the destination storage node observes `"RelayNode"` as the transport sender and never `"OwnerNode"` (formally verified in `specs/ParVaultAnonymity.tla`).
  5. **Hedged Parallel $N$-Shard Recovery & 8-Profile Degradation Verification (`tests/anonymity_and_degraded_net_tests.rs`):** During restoration or witness repair under degraded network/hardware conditions, the client dispatches parallel requests across all $N = 20$ cohort peers (hedged requests) and resolves each stripe as soon as the fastest $K = 16$ Merkle-verified shards arrive, cutting tail latency caused by packet loss, CGNAT relays, or slow flash I/O. The `tests/anonymity_and_degraded_net_tests.rs` integration suite systematically validates all 8 canonical degradation profiles (Fiber/LAN Baseline, Cable/DSL Asymmetric WAN, Lossy Wi-Fi Mesh, Double-NAT/CGNAT Relay, High-Churn 40% Drop, Constrained Gateway 32 MiB RAM, Slow SD/USB Flash I/O, and Combined Worst-Case Storm).

---

## ADR-12: Post-Quantum Hybrid Cryptography (NIST FIPS 203 ML-KEM-768, FIPS 204 ML-DSA-65 & Dual-Cipher Cascaded AEAD)
- **Context:** Long-lived distributed backups are prime targets for **Harvest-Now, Decrypt-Later (HNDL)** adversaries who record encrypted P2P traffic, onion relay envelopes, and erasure-coded shards today to decrypt them once a Cryptographically Relevant Quantum Computer (CRQC) becomes available. On a CRQC:
  - **Shor's Algorithm** solves the Elliptic Curve Discrete Logarithm Problem (ECDLP) in polynomial time, completely breaking classical `X25519` key exchange and `Ed25519` digital signatures.
  - **Grover's Algorithm** provides a quadratic $\mathcal{O}(2^{n/2})$ speedup against unstructured symmetric key search, halving the effective security of 256-bit symmetric keys to 128 post-quantum bits (NIST Category 5).
- **Decision:**
  1. **X-Wing Style Hybrid Post-Quantum Key Encapsulation (`HybridKemKeypair`: `X25519 + ML-KEM-768`, NIST FIPS 203):**
     - Ephemeral session establishment and 2-layer `PqRelayedShardEnvelope` relay dispatch combine classical **X25519** ECDH (`32-byte` public key) with lattice-based **ML-KEM-768** (`1,184-byte` encapsulation key, `1,088-byte` ciphertext, Module-LWE security category 3).
     - Both shared secrets and **both recipient public keys** are bound via an X-Wing style **HKDF-SHA512** combiner (`B10`, `A2`):
       $$K_{\text{hybrid}} = \text{HKDF-SHA512}\!\left(\text{salt} = \text{pk}_{\text{ephem,X25519}} \parallel \text{SHA256}(\text{ct}_{\text{ML-KEM-768}}),\; \text{ikm} = \text{ss}_{\text{X25519}} \parallel \text{ss}_{\text{ML-KEM-768}},\; \text{info} = \text{"parvault-hybrid-x25519-mlkem768-v2:"} \parallel \text{pk}_{\text{recip,X25519}} \parallel \text{SHA256}(\text{ek}_{\text{recip,ML-KEM-768}})\right)$$
     - **IND-CCA2 Combiner Security Property:** Binding both the ephemeral/ciphertext transcript and the recipient's classical and post-quantum public keys prevents active multi-target public-key substitution attacks, ensuring $K_{\text{hybrid}}$ remains pseudorandom and secret as long as *at least one* of X25519 or ML-KEM-768 remains unbroken ($\neg(\text{x25519Broken} \wedge \text{mlKem768Broken})$).
  2. **Hybrid Post-Quantum Digital Signatures (`HybridPqSigningKeypair` & `HybridPqSignature`: `Ed25519 + ML-DSA-65`, NIST FIPS 204):**
     - Node identities, Web-of-Trust delegation certificates, `PersonalDeviceCert`s, and `PqSignedDhtManifestEnvelope`s support composite dual signatures combining **Ed25519** (`64-byte` signature) with lattice-based **ML-DSA-65** (`1,952-byte` verifying key, `3,309-byte` signature, Module-LWE / Module-SIS, context `ML_DSA_65_CONTEXT = b"parvault-pq-hybrid-dsa65-v1"`).
     - Verification strictly requires **both** `Ed25519::verify` **and** `ML-DSA-65::verify` to succeed, ensuring an adversary with a CRQC running Shor's algorithm still cannot forge signatures unless Module-LWE/SIS is also broken ($\text{ed25519Broken} \wedge \text{mlDsa65Broken}$).
  3. **Dual-Cipher Cascaded Symmetric Encryption (`PqVaultMasterKey` — Cipher Diversity & NIST Category 5 Grover Floor):**
     - A single 256-bit symmetric cipher (`AES-256-GCM`) already provides **128-bit post-quantum security** against Grover's $\mathcal{O}(2^{n/2})$ search algorithm (meeting NIST Post-Quantum Category 5). Note that sequential encryption under two independent 256-bit keys does not square the Grover keyspace to $2^{512}$ (since each layer can be attacked or distinguished independently at $\sim 2^{128}$ quantum evaluations); rather, `PqVaultMasterKey` derives two independent 256-bit subkeys $(K_1, K_2)$ via `Argon2id` (`m=64 MiB (65,536 KiB), t=3, p=4`) + `HKDF-SHA256` to provide **cipher-diversity defense-in-depth**:
       - Inner pass: **`AES-256-GCM`** (substitution-permutation network + Galois field polynomial MAC) keyed by $K_1$.
       - Outer pass: **`ChaCha20-Poly1305`** (ARX stream cipher + prime-field polynomial MAC) keyed by $K_2$ with independent HKDF nonces.
     - Consequently, a cryptanalytic break of either `AES-256-GCM` *or* `ChaCha20-Poly1305` alone never exposes vault plaintext.
     - This Post-Quantum Hybrid architecture is formally specified and model-checked in [`specs/ParVaultPostQuantum.tla`](../specs/ParVaultPostQuantum.tla).

---

## ADR-13: Day-1-to-10,000-User Elastic Bootstrap & Earned Tier Progression
- **Context:** Two structural failure modes threaten real-world decentralized storage networks between Day 1 (`1` user, `0` organic peers) and scale (`10,000+` users):
  1. **Adverse Selection from Manual Tier Choice:** If a CLI flag (`--tier homelab`) allows any unproven node to self-select the `16-of-20` Homelab erasure profile (`1.25x` reciprocity expansion tax, `80%` storage efficiency) over the `10-of-20` Consumer profile (`2.00x` tax, `50%` efficiency), rational or flaky nodes will universally claim `homelab` for cheap storage while churning offline—causing rapid stripe loss when more than $N - K = 4$ peers drop simultaneously.
  2. **The P2P Cold-Start Deadlock:** A rigid $20$-peer Reed-Solomon placement requirement fails on Day 1 when a pioneer user boots the first node (`0` external peers) or forms a small 3–5 friend micro-cluster, and leaves early adopters unable to earn reciprocity credits while waiting for uploads.
- **Decision:**
  1. **Cryptographically Earned Tier Progression (`EarnedStanding::evaluate`):**
     - Erasure coding tiers and reciprocity expansion taxes are **never manually selected** by the user; they are deterministically computed by `EarnedStanding::evaluate(account, personal_devices, organic_peers, seed_anchors)` from the node's cryptographically audited `PeerCreditAccount` PoR history and reachable topology:
       - **`SoloPersonalVault` / `PersonalDeviceRing` (`2-of-3`, `0.0x` network quota tax):** Active on Day 1 when `external_pool == 0` across `1` or $\ge 2$ personal devices linked via `PersonalDeviceCert`.
       - **`BuddyMicroCluster` (`3-of-5`, `1.67x` expansion tax):** Active for small friend/neighborhood co-ops ($1 \le \text{external\_pool} < 6$).
       - **`ProbationaryConsumerPool` (`10-of-20`, `2.00x` expansion tax, `50%` efficiency):** Mandatory entry pool for all newly joined or `UntrustedProbationary` nodes (`< 50` PoR passes) once $\text{external\_pool} \ge 6$. Survives up to $10$ simultaneous node failures ($50\%$ cohort loss).
       - **`EarnedVerifiedMixedPool` (`16-of-24`, `1.50x` expansion tax, `66.7%` efficiency, `2.5x` quota multiplier):** Unlocked only after earning `TrustLevel::VerifiedNeighbor` ($\ge 50$ PoR audits at $\ge 98.0\%$ SLA) with $\ge 24$ reachable peers.
       - **`EarnedHomelabAnchorPool` (`16-of-20`, `1.25x` expansion tax, `80.0%` efficiency, `5.0x` quota multiplier):** Unlocked strictly after earning `TrustLevel::HighUptimeAnchor` ($\ge 200$ PoR audits at $\ge 99.8\%$ SLA) with $\ge 20$ reachable peers, placing shards onto peers prioritized by high-uptime trust standing. Any `SlashedQuarantined` node is immediately rejected (`BootstrapError::NodeSlashedQuarantined`).
  2. **Mechanism 1 — Day-1 Single-Player Personal Device Ring (`PersonalDeviceCert`):**
     - A user's own devices (e.g., laptop, desktop, home NAS/Raspberry Pi) issue and verify post-quantum composite certificates (`PersonalDeviceCert` signed via `HybridPqSigningKeypair`: `Ed25519 + ML-DSA-65` over domain `"PARVAULT-PERSONAL-DEVICE-CERT-V1:"`).
     - Authenticated personal devices (`PeerRole::PersonalDevice`) form an instant Day-1 LAN/WAN backup ring with infinite self-reciprocity (`0.0x` external quota tax) even when `0` strangers exist on the network.
  3. **Mechanism 2 — Zero-Knowledge Foundation Seed Anchors & Automatic Drain (`PeerRole::FoundationSeedAnchor`):**
     - When a node joins the wider mesh while organic community peers $P_{\text{organic}} < N$, `ElasticBootstrapEngine::select_elastic_targets` fills the remaining $N - P_{\text{organic}}$ shard slots using stateless `FoundationSeedAnchor` fallback nodes. Seed anchors receive only `ADR-11` blinded shard locators and `ADR-12` 512-bit `PqVaultMasterKey` cascaded ciphertext—learning zero plaintext or file correlation.
     - As organic peers (`PeerRole::OrganicCommunityPeer`) join the Kademlia DHT, `ElasticBootstrapEngine::plan_seed_anchor_drain` generates deterministic `SeedAnchorDrainMigration` steps that evacuate shards off seed anchors onto organic subnets until Foundation Seed Anchors hold **0 shards** at $P_{\text{organic}} \ge 20$.
  4. **Mechanism 3 — Elastic $(k, n)$ Scaling & Zero-Knowledge Ciphertext Re-Sharding (`reshard_ciphertext_stripe_elastic`):**
     - When a node's `EarnedStanding` promotes (e.g., `3-of-5` $\to$ `10-of-20` $\to$ `16-of-24` $\to$ `16-of-20`), `ElasticBootstrapEngine::reshard_ciphertext_stripe_elastic` reconstructs the outer encrypted stripe from any $k_{\text{old}}$ surviving shards over $GF(2^8)$, verifies its SHA-256 digest (`expected_ciphertext_sha256`), and re-encodes it into $(k_{\text{new}}, n_{\text{new}})$ shards with a fresh `MerkleTree` root **purely over ciphertext**—without ever requiring `PqVaultMasterKey` or exposing user plaintext.
  5. **Mechanism 4 — Pioneer Standby Uptime Mining, `/24` Inverse-Count Sybil Damping & $\le N - K$ Fault-Domain Cap:**
     - During bootstrap and growth epochs, `ElasticBootstrapEngine::accrue_standby_uptime_epoch` rewards online nodes for committed standby capacity via a utilization-tapered rate $\text{rate} = 0.10 \times (1 - 0.75 \cdot u_{\text{net}})$ so early pioneers earn reciprocity credits and increment `por_passes` even before heavy upload traffic arrives.
     - **Strict `/24` Subnet Sybil Conservation:** Each node on a `/24` subnet is weighted by $1 / M_{\text{subnet}}$ (where $M_{\text{subnet}}$ is the count of organic nodes sharing that `/24`). Spinning up $M$ virtual machines on a single residential `/24` router yields $M \times \frac{1}{M} = 1.0\times$ the standby credit of a single honest node.
     - **Availability Fault-Domain Cap ($\le N - K$):** Because confidentiality is already unconditionally protected by `ADR-11` (`BlindedShardId`) and `ADR-12` (`PqVaultMasterKey`), per-subnet shard limits in `max_shards_per_subnet_fault_domain()` serve purely as an **Availability Fault-Domain Cap** bounded by $\min(4, N - K)$, guaranteeing that a single `/24` router or fiber cut can never destroy more than the parity budget $M = N - K$.
     - Formally specified and verified with `0` errors in [`specs/ParVaultBootstrapAndEarnedTier.tla`](../specs/ParVaultBootstrapAndEarnedTier.tla) and integration-tested in [`tests/bootstrap_and_earned_tier_tests.rs`](../tests/bootstrap_and_earned_tier_tests.rs).

### ADR-14: Dedicated Zero-Trust Seed Server (`parvault-seed`) & Zero-Knowledge Anonymous Network Telemetry
- **Context:**
  1. Homelab users want to run `parvault` on their daily-use machines (laptops, desktops) while running a dedicated, headless 24/7 redundancy server on a NAS/Raspberry Pi/VPS (`--mode homelab-vault`), and network operators need a standalone binary to run the 20 Foundation Seed Anchors (`--mode public-bootstrap`) that holds **zero plaintext files of its own**.
  2. Network operators need a way to measure active network population, regional extent, earned-tier distribution, and Seed Anchor storage load percent without tracking user IP addresses, static `PeerId`s, or exact disk/file sizes.
- **Decision:**
  1. **Standalone `parvault-seed` Binary (`src/bin/parvault-seed.rs` & `ZeroTrustSeedServer`):**
     - **`SeedServerMode::HomelabRedundancyVault`:** Verifies post-quantum `PersonalDeviceCert`s from the homelabber's personal machines (`0.0x` self-quota tax) while answering network PoR challenges 24/7 to earn `TrustLevel::HighUptimeAnchor` (`16-of-20` `EarnedHomelabAnchorPool`, `5.0x` quota multiplier) for the household.
     - **`SeedServerMode::PublicNetworkBootstrapper`:** Runs on 20 low-cost, zero-egress cloud micro-instances (`Hetzner` / `OVH` / `Netcup` across 5+ ASNs and 20 `/24` subnets), ingesting blinded `.bshard` leases during cold-start (`1..19` users) and automatically draining to `0 bytes` (`~$95/mo` flat cost) as organic peers scale past `20..10,000+` users.
  2. **Zero-Knowledge Anonymous Network Census (`src/telemetry.rs`):**
     - Nodes emit `AnonymousTelemetryBeacon`s wrapped inside 1-hop post-quantum [`PqRelayedShardEnvelope`](../src/crypto/pqc.rs)s (`ML-KEM-768 + X25519`) so the seed aggregator never observes the sender's IP address.
     - Each beacon carries an unlinkable rotating epoch nullifier $\text{Nullifier}_t = \text{HMAC-SHA256}(K_{\text{node}}, \text{"PARVAULT-TELEMETRY-EPOCH-V1:"} \parallel t)$ for exact single-epoch deduplication (preventing spam inflation while remaining cryptographically unlinkable across epochs $t$ and $t+1$), a macro-region tag (`NA-WEST`, `NA-EAST`, `EU-CENTRAL`, `EU-WEST`, `APAC`), power-of-two GiB capacity buckets (`round_to_pow2_gib`), and observed Kademlia routing peers for capture-recapture cross-checking.
     - Verified in [`tests/seed_server_integration.rs`](../tests/seed_server_integration.rs) (`4/4` PASS) and [`tests/anonymous_telemetry_tests.rs`](../tests/anonymous_telemetry_tests.rs) (`4/4` PASS).





---

### ADR-15: Multi-Domain Adversarial Red-Team Hardening & Zero-Local-State "House Fire" Recovery
- **Context:** A 5-domain adversarial Red-Team audit (Cryptography & Disaster Recovery, Economic & Game Theory, Wire Protocol & Telemetry Sybils, Storage Crash-Consistency & Path Security, and Supply-Chain & Control-Plane DevOps) probed the codebase for subtle edge cases and operational blind spots prior to public launch.
- **Decision:**
  1. **Zero-Local-State "House Fire" Disaster Recovery (`MasterKey::from_recovery_seed_phrase` & `EncryptedVaultCatalogEnvelope`):**
     - If a user's house burns down and every local disk (`.manifest.bin`) is destroyed, `MasterKey::from_recovery_seed_phrase(seed_phrase, vault_namespace)` and `PqVaultMasterKey::from_recovery_seed_phrase` apply memory-hard `Argon2id` (`m=64 MiB, t=3 iterations, p=4 lanes`) + domain-separated `HKDF-SHA256` / `HKDF-SHA512` to deterministically reconstruct the user's 256-bit `MasterKey`, full 512-bit `PqVaultMasterKey`, `NodeIdentity`, and deterministic Kademlia root catalog key `derive_vault_root_dht_key(vault_namespace)`.
     - `FolderSyncEngine::export_encrypted_vault_catalog` seals the complete `FolderSnapshotManifest` inside a dual-encrypted (`AES-256-GCM` + 512-bit cascaded `PqVaultMasterKey`) and signed `EncryptedVaultCatalogEnvelope`, allowing `FolderSyncEngine::recover_folder_from_seed_phrase` (and `FolderSyncEngine::recover_folder_from_seed_phrase_network` over `libp2p`) to recover the entire directory tree on a brand-new laptop with **zero prior local files**.
  2. **Capability Key Pinning, Bidirectional NTP Clock-Skew Tolerance & Tombstone Generation Scoping:**
     - `BlockStore::put_blinded_shard_with_lease` binds the uploader's `capability.capability_pubkey` into `BlindedShardLeaseEntry` so an attacker who knows `locator` cannot present a self-signed capability (`[CRITICAL-CRYPTO-01]`).
     - `BlindedShardCapability::verify_read_token_with_skew` enforces a symmetric $\pm 30\text{ s}$ NTP clock-skew window (`MAX_CAPABILITY_CLOCK_SKEW_MS = 30_000`), tolerating normal residential clock drift while blocking far-future `timestamp_ms = u64::MAX` "immortal capability" exploits (`[HIGH-CRYPTO-02]`).
     - `BlindedShardLeaseManager` tracks `next_generation_by_locator` and `consumed_tombstone_macs` (`BlindedShardTombstone::create_for_generation`), preventing an adversary from replaying an old `BlindedShardTombstone` if a user legitimately re-uploads a previously deleted file (`[CRITICAL-CRYPTO-03]`).
  3. **Game-Theoretic & Sybil Defenses (`VerifiedNeighbor` Seed Drain Gate, CGNAT Sub-Slots & Signed Weather Quorum):**
     - `ElasticBootstrapEngine::plan_seed_anchor_drain` strictly requires replacement organic peers to hold `trust_level >= TrustLevel::VerifiedNeighbor` ($\ge 50$ PoR passes at $\ge 98\%$ SLA), blocking 1-hour ephemeral `UntrustedProbationary` Sybil waves from prematurely draining Foundation Seed Anchors.
     - `canonical_sybil_subnet_key` normalizes IPv6 addresses to their `/32` LIR allocation prefix (`v6:xxxx:xxxx::/32`, collapsing all 65,536 `/64` subnets inside a `/48` into 1 Sybil bucket) while granting RFC 6598 CGNAT (`100.64.0.0/10` — Starlink / 5G Home Internet) up to `4` attested household sub-slots per `/24`.
     - `CorrelatedOutageController::verify_weather_quorum` requires $\ge 3$ independent trusted anchor signatures (`SignedWeatherAttestation`) across $\ge 20$ verified subnets before freezing PoR SLA demotions.
  4. **Wire-Protocol Pre-Auth OOM Bomb Defense, PoR Domain Separation & Telemetry Hashcash PoW:**
     - `BincodeWireCodec::deserialize_request_bounded` uses `bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_limit(buf.len() as u64)` and bounded `io.take(len)` streaming so a crafted 16-byte frame with a `u64::MAX` `Vec` length prefix is rejected immediately without heap OOM.
     - `PorVerifierEngine::authorize_raw_shard_read` enforces `"parvault-owner-shard-read-v1:"` domain-tag and `shard_id` binding (`sign_owner_shard_read_token`), blocking cross-protocol replay of public `RepairGrant` signatures.
     - `AnonymousTelemetryBeacon` and `NetworkCensusAggregator` enforce `MAX_SINGLE_NODE_BUCKET_GIB = 65_536` (`64 TiB`), configurable zero-knowledge Hashcash Proof-of-Work (`create_with_pow`, `with_min_pow_bits`), and Tukey Interquartile Range (IQR) outlier trimming.
  5. **Crash-Safe Atomic Storage (`fsync` + `rename`), Path-Traversal Blocking & Local Bit-Rot Scrubbing:**
     - `BlockStore::atomic_write_file` writes `.shard`, `.bshard`, `.manifest.bin`, and `blinded_leases.bin` to a sibling `.tmp.<nonce>` file, calls `File::sync_all()`, and atomically renames over the destination path; `put_blinded_shard_with_lease` commits disk I/O *before* burning `AnonymousQuotaVoucher`s.
     - `FolderSyncEngine::resolve_safe_restore_path` rejects `..` (`ParentDir`), `/` (`RootDir`), Windows drive/UNC prefixes (`Prefix`), backslashes, colons, null bytes, and symlinks (`StorageError::InvalidRestorePath`), and verifies SHA-256 on a staging file before atomic placement.
     - `BlockStore::scrub_all_shards` proactively scans and quarantines silent disk bit-rot on `.shard` and `.bshard` files, while `QuotaManager` releases `bytes_hosted_for_peer` on LRU eviction and caps per-epoch write amplification at `4x` to block rapid upload-delete SSD wear griefing.
     - All 5 Red-Team domains are regression-tested in [`tests/red_team_hardening_tests.rs`](../tests/red_team_hardening_tests.rs) (`5/5` PASS).

---

### ADR-16: Internet-Grade Sync Daemon Usability, Streaming I/O, Bounded Replay Caches, and Sharded Documentation
- **Context:** Prior to public open-source release, an end-to-end usability and systems engineering review identified five practical gaps for everyday homelabbers and long-running gateway deployments:
  1. Users needed first-class CLI commands to inspect their `device-peer-id` and `owner-pq-pubkey-hex` (`identity`), issue and verify post-quantum `PersonalDeviceCert`s using copy-pasteable single-line tokens (`PARVAULT-CERT-V1:<hex>`), run local bit-rot scrubbing (`scrub`), and execute zero-local-state seed-phrase disaster recovery (`recover-from-seed`).
  2. `FolderSyncEngine` needed `.parvaultignore` exclusion patterns (so `.git`, `node_modules`, `target`, and temporary swap files are not backed up), dry-run folder diffing (`diff-folder` / `--dry-run`), deleted-file tombstone pruning (`--prune-deleted`), and selective single-file restoration (`restore-folder --file <REL_PATH>`).
  3. `FolderSyncEngine::sync_folder_once` and `restore_folder` previously called `fs::read` to compute whole-file SHA-256 digests, which could spike memory above the 32 MiB gateway ceiling on multi-gigabyte VM/NAS archives; similarly, `PorVerifierEngine` and `VoucherNullifierLedger` needed bounded FIFO eviction to prevent unbounded RAM growth over months of uptime.
  4. Residential gateways required configurable token-bucket upload/download bandwidth rate limits (`max_upload_mbps`, `max_download_mbps`) and a minimum free disk reserve (`min_free_disk_bytes`).
  5. Documentation needed to be sharded by persona (`README.md`, `QUICKSTART.md`, `docs/USER_AND_CLI_GUIDE.md`, `docs/SECURITY_AND_CRYPTOGRAPHY.md`, `AGENTS.md`, `CONTRIBUTING.md`, `CHANGELOG.md`) with the full verbatim `AGPL-3.0-only` license in `LICENSE`.
- **Decision:**
  1. **Complete Identity, Certificate & Recovery CLI Parity (`parvault` & `parvault-seed`):**
     - Added `parvault identity`, `parvault issue-device-cert`, `parvault verify-device-cert`, `parvault diff-folder`, `parvault recover-from-seed`, and `parvault scrub`, alongside `parvault-seed identity`, `parvault-seed issue-device-cert`, `parvault-seed verify-device-cert`, `parvault-seed status`, `parvault-seed drain-plan`, and `parvault-seed scrub`.
     - Added `PersonalDeviceCert::to_compact_token()` and `from_compact_token()` (`PARVAULT-CERT-V1:<hex>`) so homelabbers can copy-paste device certificates over SSH without transferring `.json` files.
  2. **`.parvaultignore`, Dry-Run Diffs, Tombstone GC & Selective Single-File Restore (`src/sync.rs`):**
     - Implemented `IgnoreRules` with default exclusions (`.git`, `node_modules`, `target`, `.DS_Store`, `Thumbs.db`, `*.tmp`, `*.swp`, `*.parvault_restore_staging`) plus `.parvaultignore` glob, directory-prefix, and `!` negation rules.
     - Added `FolderSyncEngine::diff_folder`, `sync_folder_with_options(folder, dry_run, prune_deleted)`, `DeletedFileTombstone` tracking in `FolderSnapshotManifest::deleted_files`, and `FolderSyncEngine::restore_single_file`.
  3. **Constant-Memory 64 KiB Streaming File Hashing & Bounded 65,536-Entry FIFO Caches:**
     - Replaced full-file `fs::read` SHA-256 computations in `src/sync.rs` with `compute_file_sha256_streaming` (`64 KiB` stack buffer) and `std::io::copy` + `sync_all()` + `fs::rename` on staging files, strictly preserving the `< 32 MiB` RAM ceiling on arbitrarily large files.
     - Bounded `PorVerifierEngine::seen_challenge_macs` and `VoucherNullifierLedger::consumed_nonces` at `65,536` entries (`MAX_REPLAY_CACHE_ENTRIES` / `MAX_VOUCHER_NULLIFIER_ENTRIES`) with deterministic `VecDeque` FIFO eviction.
  4. **Token-Bucket Bandwidth Rate Limiter & Minimum Free Disk Reserve:**
     - Added `TokenBucketRateLimiter` (`src/network/behaviour.rs`) and `NodeConfig::{max_upload_mbps, max_download_mbps, min_free_disk_bytes}` (`5 GiB` default reserve).
  5. **Persona-Sharded Documentation & Verbatim `AGPL-3.0-only` `LICENSE`:**
     - Replaced the `LICENSE` stub with the full verbatim GNU Affero General Public License v3.0 text and sharded documentation across `README.md`, `QUICKSTART.md`, `docs/USER_AND_CLI_GUIDE.md`, `docs/SECURITY_AND_CRYPTOGRAPHY.md`, `AGENTS.md`, `CONTRIBUTING.md`, and `CHANGELOG.md`.

---

## ADR-17: Lite-Client Zero-Knowledge Seed Syndication, NAS-Death Direct-Mesh Failover, Selective Partial Restore, and TLA+ CI Integration Tests

- **Status:** Accepted & Verified (`specs/ParVaultLiteClientAndSeedFailover.tla`, `tests/tla_formal_proofs_integration.rs`)
- **Context:**
  1. **Laptop Battery, Disk & Uplink Conservation ("Cloud Away From Home"):** Users with a laptop and a home NAS/Raspberry Pi running `parvault-seed` want their laptop to run a lightweight `LiteSeedBacked` mode (`ClientOperatingMode::LiteSeedBacked`) that backs up `1.0x` encrypted ciphertext to their `parvault-seed` box without hosting foreign mesh shards or uploading `1.25x-2.0x` Reed-Solomon shards directly to 20 peers over mobile/Wi-Fi connections, while still accessing their vault like a cloud when away from home.
  2. **NAS-Death Survivability (Unified Protocol Guarantee):** If the home NAS (`parvault-seed`) suffers a hardware failure, theft, or house fire, the laptop must be able to fail over seamlessly to the Neighborhood Cloud mesh and recover files directly from any $K$-of-$N$ surviving mesh peers (`LiteRestoreRoute::DirectFromMeshPeersFallback`), because both laptop and seed speak the identical `FileManifest` / `FolderSnapshotManifest` / `ShardId` / $GF(2^8)$ Reed-Solomon protocol.
  3. **Selective Partial Sync & Byte-Range Restore:** A laptop with a 512 GiB SSD cannot restore an entire 10 TiB NAS backup after a NAS failure; users need catalog browsing (`list-snapshot`), path/glob filtering (`--filter`), and stripe-granular byte-range restore (`restore_file_byte_range`).
  4. **Formal Verification in GitHub CI:** All TLA+ specifications (`specs/*.tla`) must run automatically both as a standalone CI job and inside `cargo test --release` (`tests/tla_formal_proofs_integration.rs`).
- **Decision:**
  1. **Zero-Knowledge Lite-Client Syndication (`ZeroTrustSeedServer::ingest_and_syndicate_lite_stripe`):**
     - The laptop encrypts each 16 MiB stripe locally with `AES-256-GCM` under `K_file = HKDF(K_user, file_id)` (`K_user` never leaves the laptop) and sends a `LiteStripeSyndicationBundle` (`1.0x` ciphertext + `PersonalDeviceCert`) to `parvault-seed`.
     - Because `encode_ciphertext_stripe` operates purely over `AES-256-GCM` ciphertext in $GF(2^8)$, `parvault-seed` performs the `K-of-N` Reed-Solomon encoding, caches a local copy for instant 1-hop "Cloud Away From Home" reads (`LiteRestoreRoute::ViaSeedServerFastPath`), and syndicates all $N$ shards across external mesh peers (`mesh_peer_stores`), returning a `LiteSyndicationReceipt` with the exact `ShardId`s and `stripe_merkle_root`.
  2. **Automatic NAS-Death Direct-Mesh Failover (`FolderSyncEngine::restore_selective_with_seed_fallback`):**
     - During restore, the laptop checks whether its `parvault-seed` server is reachable. If `seed_server` is offline or destroyed (`None`), the laptop uses its `FolderSnapshotManifest` (or seed-phrase-recovered `EncryptedVaultCatalogEnvelope`) to fetch any $K$ surviving shards directly from `mesh_peer_stores`, verify `stripe_merkle_root`, reconstruct the ciphertext stripe in $GF(2^8)$, and decrypt with `K_user`.
  3. **Selective Partial Restore & Byte-Range Streaming (`list-snapshot`, `--filter`, `restore_file_byte_range`):**
     - Added `FolderSyncEngine::list_snapshot_catalog` (`parvault list-snapshot`) to inspect all file paths, sizes, Stripe counts, and timestamps with **zero shard downloads**.
     - Added `FolderSyncEngine::restore_selective_subset` (`parvault restore-folder --filter "..."` and `parvault recover-from-seed --filter "..."`) supporting comma-separated directory prefixes, exact paths, and `*`/`?` globs so only matching files' stripes are downloaded and reconstructed.
     - Added `FolderSyncEngine::restore_file_byte_range` to reconstruct and decrypt only the 16 MiB stripe(s) overlapping `[offset, offset + length)`.
  4. **TLA+ Formal Proof & `cargo test` Integration (`specs/ParVaultLiteClientAndSeedFailover.tla` & `tests/tla_formal_proofs_integration.rs`):**
     - Authored `specs/ParVaultLiteClientAndSeedFailover.tla` verifying `ZeroKnowledgeSeedAndMeshInvariant`, `NasDeathSurvivableInvariant`, `SelectiveBandwidthSavingInvariant`, and `EventuallySelectiveRestoreComplete` across all reachable states (`0` errors).
     - Added `tests/tla_formal_proofs_integration.rs` which invokes `tlc2.TLC` on all 6 `.tla` specifications during `cargo test --release` and updated `.github/workflows/ci.yml` to provision Java 21 + `tla2tools.jar` in `rust-tests`.

---

## ADR-18: Zero-IP Signed LAN Discovery, 4-Word SAS Pairing, Online WAN Rendezvous, and Tiny-SoC 1 MiB Streaming Profile

- **Status:** Accepted & Implemented (`v0.3.0`)
- **Context:**
  1. **Zero-Configuration Usability on Home Networks:** In `v0.2.0`, linking peers required users to discover each other's IP addresses and manually pass `/ip4/<ip>/tcp/<port>/p2p/<PeerId>` flags to CLI commands or populate `config.toml`. Non-technical household users and homelabbers deploying across laptops, phones, and home router Cloud-NAS boxes cannot be expected to inspect router DHCP lease tables or type 60-character multiaddr strings.
  2. **DHCP IP Churn & Self-Healing:** Residential routers routinely reassign internal IPv4 addresses when devices reconnect to Wi-Fi. Static IP multiaddr configurations break upon DHCP lease renegotiation unless nodes can dynamically advertise and re-verify their cryptographic `PeerId` on the LAN.
  3. **Router SoC Memory Constraints & 1 MiB Streaming Profile:** With `16 MiB` Reed-Solomon stripes, transient memory during erasure coding and reconstruction peaks at `~74.6 MiB` (`VmHWM`). Residential gateway routers (OpenWrt, prplOS) running on MediaTek Filogic or Rockchip SoCs with 512 MiB–1 GiB total system RAM impose strict `< 32 MiB` active resident set (`VmRSS`) and `< 48 MiB` peak memory cgroup ceilings. To operate safely as a background appliance without OOM risk, the streaming stripe size must be configurable down to `1 MiB` (`SOC_ROUTER_STRIPE_SIZE_BYTES = 1,048,576`), reducing peak `VmHWM` below `16 MiB` while retaining 100% wire and manifest interoperability with desktop nodes.
  4. **Zero-IP Online WAN Peering & ISP Dynamic-IP Resiliency:** Beyond local LANs, peers need to connect across cities and ISPs without public static IPs, third-party DynDNS subscriptions, or manual port forwarding. Nodes need STUN-over-Noise external address reflection to discover their public WAN endpoints and a zero-knowledge rendezvous mailbox on seed anchors to trade encrypted `WanPeerCard`s via human-friendly 4-word codes.
  5. **Zero-Pairing Public Commons ("Public BitTorrent Tracker" WoT Mode):** Private join codes and invitation chains provide high isolation for closed friend rings, but create initial onboarding friction for users trying `parvault` on the open internet. Because `parvault` already enforces end-to-end client-side post-quantum AEAD encryption, `10-of-20` Reed-Solomon erasure coding, pre-decoding Byzantine Merkle quarantine, and `/24` subnet caps, an open **Public Commons Mode** (`--public --tracker <MULTIADDR>`) can safely admit stranger peers without manual pairing codes while using Hashcash Proof-of-Work (`PublicCommonsTicket`) to deter Sybil flood attacks.
- **Decision:**
  1. **Cryptographically Signed Zero-IP LAN Discovery (`LanBeaconPacket` & `LanBeaconResponder`):**
     - Nodes broadcast periodic signed UDP beacons (default UDP port `4009`, multicast group `239.255.80.86`, broadcast `255.255.255.255`, and localhost fallback).
     - Each `LanBeaconPacket` contains `libp2p_peer_id`, `device_peer_id`, `node_label`, `role`, `tcp_listen_port`, `available_bytes`, `timestamp_ms`, `ed25519_pubkey`, and an Ed25519 signature over domain `"parvault-lan-beacon-v1:"`.
     - Recipients strictly verify the signature and ensure that `libp2p_peer_id` matches `ed25519_pubkey` to prevent rogue Wi-Fi clients from spoofing peer identities. Beacons older than 15 seconds are discarded.
  2. **DHCP-Resilient Persistent Peer Registry (`KnownPeersStore` at `known_peers.json`):**
     - Peer addresses are indexed by cryptographic `libp2p_peer_id`.
     - When a node's IP address changes due to DHCP lease renewal, `KnownPeersStore::upsert_discovered` dynamically updates the node's `/ip4/.../tcp/...` Multiaddr while keeping its trusted identity pinned.
     - All high-level CLI commands (`watch-folder`, `restore-folder`, `file store`, `file restore`, `leave`, `status`) automatically call `resolve_zero_config_peers` when no `--peers` flags are specified.
  3. **4-Word BIP-39 SAS Pairing (`parvault pair` / `parvault join`):**
     - A human-friendly 4-word Short Authentication String (SAS) code (e.g., `shield-copper-alpine-matrix`) is deterministically derived from `(libp2p_peer_id, owner_pq_fingerprint, pairing_nonce)` using `BIP39_ENGLISH_WORDLIST`.
     - The hosting node broadcasts a commitment in its beacon; the joining node verifies the SAS match and pins the trusted peer in `known_peers.json` without passwords or manual key exchanges.
  4. **Configurable Streaming Stripe Sizing (`HardwareProfile` & `BlockStore`):**
     - Introduced `HardwareProfile`:
       - `RouterSoc`: `1 MiB` stripe size (`1,048,576` bytes), `64 MiB` minimum disk reserve, `max_connections = 24`.
       - `HomelabNas`: `4 MiB` stripe size (`4,194,304` bytes), `1 GiB` minimum disk reserve.
       - `Desktop`: `16 MiB` stripe size (`16,777,216` bytes), `5 GiB` minimum disk reserve.
     - `FileManifest` structures record stripe counts and boundaries independently of node stripe profiles; a file stored with `1 MiB` stripes by a router can be restored by a `16 MiB` desktop node, and vice-versa.
  5. **Turnkey Appliance Mode (`parvault up`):**
     - Combines P2P storage daemon, signed UDP beacon responder, embedded `RouterNasStatusServer` (`:4080`), and background folder sync into a single command for OpenWrt `procd` and prplOS LXC container deployments.
  6. **Zero-Knowledge Online WAN Rendezvous & STUN-over-Noise Reflection:**
     - Added `RegisterWanRendezvous` and `LookupWanRendezvous` to `MeshWireRequest` / `MeshWireResponse`.
     - 4-word WAN codes derive a blinded rendezvous slot key `slot_key = HKDF(code, "parvault-wan-rendezvous-slot-v1")` and AEAD wrapping key `wrap_key = HKDF(code, "parvault-wan-rendezvous-wrap-v1")`. Seed anchors store opaque encrypted `WanPeerCard`s without learning pairing codes or metadata.
     - Noise handshake metadata reflects the observed public WAN socket address back to nodes (`observed_external_addr`), eliminating external STUN dependencies.
     - Dynamic-IP presence publishes encrypted endpoint updates to a blinded DDNS slot, surviving residential ISP address rotations without manual intervention.
  7. **Open Public WoT & Zero-Pairing BitTorrent-Style Public Swarm Mode (`--public --tracker`):**
     - Added `TrustPoolMode` (`PrivateRing`, `PublicCommons`, `Hybrid`) in `WebOfTrustRegistry` (`src/network/wot.rs`).
     - Added self-signed Hashcash Proof-of-Work ticket `PublicCommonsTicket` (`DEFAULT_PUBLIC_WOT_POW_BITS = 12`) allowing stranger nodes to join public swarms without invitations.
     - `parvault-seed --mode public-bootstrap` serves as a public tracker anchor indexing active swarm peers under `PUBLIC_COMMONS_SWARM_SLOT`.
     - Nodes in `--public` mode enforce mandatory `10-of-20` `Consumer` Reed-Solomon redundancy and pre-decoding Merkle quarantine, surviving 10 offline or malicious peers out of 20 with zero data loss.
- **Consequences:**
  - Zero IP addresses required for home LAN onboarding or remote 4-word WAN pairing.
  - Zero-friction public swarm onboarding (`--public --tracker ...`) with zero join codes or pairing setup.
  - Full DHCP and ISP dynamic IP self-healing.
  - Peak memory usage during erasure coding drops from `74.6 MiB` to `< 16 MiB` under `--profile router-soc`, guaranteeing safe operation inside a 32–48 MiB cgroup.
  - Backward compatible: all v0.2.0 configs, tests, and CLI flags continue to work unchanged.

---

## ADR-19: 4-Vector Privacy-Preserving Bad-Actor & Illegal-Content Shard Eviction Engine

- **Status:** Accepted & Implemented (`v0.3.0`)
- **Context:**
  1. **Legal Compliance & Node Sovereignty on Public Networks:** As `parvault` enables residential router Cloud-NAS appliances and open Public Commons swarms (`ADR-18`), home users and seed operators require unambiguous administrative mechanisms to evict abusive peers, spam flooders, or known illegal content stripes from their physical storage.
  2. **The Forensic Privacy Dilemma:** In traditional storage systems, administrators maintain server logs containing plaintext IP addresses, file paths, and user account IDs. In ParVault, storing plaintext IP addresses or cross-node correlatable identifiers on disk would destroy the system's core zero-knowledge privacy guarantees: anyone gaining physical access to a confiscated disk, stolen NAS drive, or filesystem backup could correlate and deanonymize innocent uploaders.
  3. **Multi-Vector Eviction Needs:** Eviction must function across four distinct vectors:
     - *Vector 1 (Network Origin):* Eviction by IP address or canonical CIDR subnet (`/24` IPv4, `/48` IPv6).
     - *Vector 2 (Transport Identity):* Eviction by `libp2p` `PeerId`.
     - *Vector 3 (Cryptographic Public Key Cohort):* Eviction by peer or voucher-issuer `ed25519_pubkey`, allowing seed anchors to purge all anonymous `.bshard` blinded shards uploaded by that bad actor's tickets or vouchers.
     - *Vector 4 (Content Hash):* Eviction by `stripe_merkle_root` or `BlindedLocator`, permanently blocking illegal content stripes regardless of which peer or IP uploads them.
  4. **Forensic File Shredding vs. Metadata-Only Deletion:** Simply unlinking a file from a filesystem leaves data blocks intact on flash or magnetic media until overwritten. To ensure complete legal purge, evicted shards must be overwritten with `0x00` zero bytes across their entire allocation prior to unlinking.
- **Decision:**
  1. **Zero-Plaintext-IP Disk Privacy Architecture (`PrivacyPreservingEvictionEngine`):**
     - Each node generates a local random 32-byte secret seed `K_node_evict` persisted at `<data_dir>/eviction_hmac.seed` with strict `0600` permissions (`write_secret_file_atomic`), held in memory with `ZeroizeOnDrop`, and never transmitted over the wire or stored in data indices.
     - The persistent index `<data_dir>/eviction_index.bin` stores **ZERO plaintext IP addresses and ZERO plaintext PeerIds**:
       $$\text{tag}_{\text{ip}} = \text{HMAC-SHA256}(K_{\text{node\_evict}}, \text{"parvault-evict-ip-v1:"} \parallel \text{canonical\_ip\_bytes})$$
       $$\text{tag}_{\text{subnet}} = \text{HMAC-SHA256}(K_{\text{node\_evict}}, \text{"parvault-evict-subnet-v1:"} \parallel \text{canonical\_cidr})$$
       $$\text{tag}_{\text{peer\_id}} = \text{HMAC-SHA256}(K_{\text{node\_evict}}, \text{"parvault-evict-peerid-v1:"} \parallel \text{peer\_id})$$
     - Because $K_{\text{node\_evict}}$ is unique per node, two honest nodes compute completely uncorrelated HMAC tags for the same IP ($H_A(\text{IP}) \neq H_B(\text{IP})$), preventing cross-node database joining attacks on seized media.
  2. **4 Eviction Vectors (`EvictionTarget`):**
     - `IpAddress(IpAddr)` & `IpSubnet(String)`: Purges all shards stored during sessions from that IP/subnet and installs an ingress blocklist rule.
     - `Libp2pPeerId(String)`: Purges regular shards associated with that transport identity and blocks future connections.
     - `PeerOrIssuerPubkey([u8; 32])`: Queries peer admission and voucher issuance mappings on seed anchors to identify and shred all associated anonymous `.bshard` blinded shards across the storage pool.
     - `StripeMerkleRoot([u8; 32])` & `BlindedLocator([u8; 32])`: Locates matching `.shard` or `.bshard` files by content root or locator, shreds them immediately, and records a permanent tombstone blocking re-upload.
  3. **Cryptographically Signed Eviction Orders (`SignedBadActorEvictionOrder`):**
     - Eviction orders are signed by authorized entities under domain `"parvault-bad-actor-eviction-order-v1:"` binding `(order_id, target, reason, issued_at_ms, expires_at_ms)`.
     - Nodes verify signatures against `NodeConfig::eviction_authorities` (defaulting to local node identity, Genesis Root, and configured seed/tracker anchors).
     - Propagated across the mesh via `MeshWireRequest::BroadcastEvictionOrder` and `MeshWireResponse::EvictionOrderAck`.
  4. **Multi-Pass Zero-Wipe File Shredding (`shred_and_unlink_file`):**
     - Before calling `fs::remove_file`, the engine overwrites every byte of the target `.shard` or `.bshard` file with `0x00` zero bytes in 64 KiB chunks, invokes `File::sync_all()` to flush controller write buffers, and only then unlinks the path. The purged byte count is returned in `EvictionPurgeReport::zero_wiped_bytes`.
  5. **Persistent Ingress Firewall:**
     - `is_ingress_blocked(remote_ip, remote_peer_id)` is evaluated in memory prior to accepting `PutShard`, `PutBlindedShard`, `RenewBlindedLease`, `RelayPqOnionEnvelope`, or public ticket admission, terminating abusive requests with zero disk allocation.
  6. **Public Tracker Anti-Griefing Governance & Pinned Authority:**
     - In `--public` (\"Public Commons / Public Tracker\") mode, random public peers MUST NEVER be able to evict anyone else's shards.
     - Public nodes reject `BroadcastEvictionOrder` from arbitrary peers (`accepted: false`). They enforce external eviction orders **only** when signed by a pinned/configured `eviction_authorities` public key (such as their public tracker's official `tracker_admin_pubkey` or their own local `NodeIdentity`).
     - Trackers maintain an isolated `tracker_admin.seed` (`0600`) as the sovereign authority for public swarm governance.
  7. **Cryptographic Reporter Burden-of-Proof (`VerifiableAbuseReport`):**
     - Because storage nodes and tracker operators are zero-knowledge and cannot inspect encrypted shards, the legal and cryptographic burden of proof is strictly on the reporter.
     - Anyone alleging illegal distribution of content must submit a `VerifiableAbuseReport` containing `(FileManifest, disclosed_master_key_hex, sample_stripe_index, sample_shards, legal_allegation, reporter_id_or_contact, reported_uploader_ip)`.
     - The tracker operator / node cryptographically verifies:
       1. Shard hashes match `stripe.shard_hashes` and `stripe.stripe_merkle_root` in the manifest.
       2. Reed-Solomon reconstructs the stripe ciphertext.
       3. `decrypt_stripe` under `disclosed_master_key` and `manifest.file_salt` passes 128-bit `AES-256-GCM` authentication tag verification.
       4. The verified plaintext buffer is immediately zeroized in RAM via `zeroize::Zeroize`, ensuring decrypted illegal bytes never touch disk or persist in memory.
     - **Mathematical Anti-Framing:** Malicious actors cannot frame honest users' private backups because guessing or forging a 256-bit `MasterKey` results in `AES-256-GCM` authentication failure with probability $1 - 2^{-128}$.
  8. **Human-in-the-Loop Admin Takedown Queue & 2-Lane Public Tracker Governance (`PublicTrackerTakedownQueue`):**
     - Even when cryptographic proof passes, submission **ONLY queues the report (`PendingAdminReview`)** at `<data_dir>/admin_takedown_queue.bin` (`0600`).
     - Shards are **NEVER auto-evicted** without human Public Tracker Admin review, eliminating algorithmic censorship and false positives.
     - **Lane 1 (Reporter Proof Review):** The Public Tracker Admin reviews proofs via `parvault-seed admin {list-takedowns, inspect-takedown}`. Upon approval (`parvault-seed admin approve-takedown`), the tracker signs `SignedBadActorEvictionOrder` under `tracker_admin.seed` and broadcasts to the swarm with `--propagate`.
     - **Lane 2 (Emergency Law-Enforcement / Warrant Eviction):** If an offender stores illegal content privately without sharing keys, and law enforcement or legal authorities issue a formal warrant against a specific uploader IP or CIDR, the Public Tracker Admin invokes `parvault-seed admin emergency-evict --warrant-ref <REF> --ip <IP> --propagate`. The tracker records an `EmergencyAdminActionRecord`, signs orders under `tracker_admin.seed`, resolves and evicts associated `PeerOrIssuerPubkey` voucher cohorts, purges local shards with multi-pass `0x00` shredding, and broadcasts to public swarm nodes. Raw IP strings are still **never** written into `eviction_index.bin`!
  9. **Strict Mode Isolation (Private Ring-of-Trust vs. Public Commons):**
     - In `TrustPoolMode::PrivateRing` (default private/family/co-op mode), external `tracker_admin_pubkey` authorities are **unconditionally ignored and rejected**. Private rings answer exclusively to the local node operator (`node_identity`) or explicit ring `genesis_pubkey`. Unilateral tracker admin powers cannot reach into private vaults.
     - In `TrustPoolMode::PublicCommons` / `Hybrid` (`--public --tracker <ADDR>`), storage nodes trust their pinned `tracker_admin_pubkey` (plus local operator) and **reject 100% of non-admin public peers**, preventing griefing while maintaining central public swarm governance.
  10. **`M-of-N` Federated Public Tracker Operator Council Quorum (`TrackerOperatorCosignature`):**
     - In federations with multiple independent `parvault-seed` public tracker operators, a single-signer model would allow one rogue or compromised tracker operator to broadcast unilateral eviction orders to wipe honest shards and steal storage capacity.
     - ParVault implements threshold co-signing: `SignedBadActorEvictionOrder` carries `cosignatures: Vec<TrackerOperatorCosignature>` where each cosigner signs the identical canonical order payload.
     - **Majority Quorum Threshold:** `default_tracker_quorum_threshold(N)` enforces strict majority: $1$-of-$1$, $2$-of-$2$, $2$-of-$3$, $3$-of-$5$, etc. Configurable via `tracker_eviction_quorum`.
     - **Anti-Rogue Invariant:** An unvetted rogue tracker host has 0 votes and is rejected immediately. Even an admitted council operator cannot unilaterally purge shards when $N \ge 2$ until $M$-of-$N$ distinct council operators co-sign via `parvault-seed admin cosign-eviction`.
     - **Local Sovereignty Guarantee:** A node operator running `parvault evict` on their own local hardware is always honored ($1$-of-$1$).
  11. **CLI Subcommands:**
     - Reporters submit abuse via `parvault report-abuse --tracker <MULTIADDR> --manifest <PATH> --disclosed-key-hex <HEX> --allegation <TEXT>`.
     - Tracker admins manage takedowns via `parvault-seed admin {show-authority, list-takedowns, inspect-takedown, approve-takedown, reject-takedown, emergency-evict, cosign-eviction}` with optional `--export-order <PATH>` and `--propagate`.
     - Direct local operator purges via `parvault evict` and `parvault-seed evict`.
- **Consequences:**
  - Complete operational sovereignty: node operators and tracker administrators can legally comply with abuse takedown requests and repel network attacks.
  - Zero degradation of uploader privacy: forensic inspection of disk images reveals no uploader IP addresses or cross-node correlatable identifiers.
  - Cryptographically ironclad anti-griefing: honest backups cannot be taken down or framed without possession of the owner's 256-bit MasterKey ($2^{-128}$ security), and rogue public trackers cannot unilaterally wipe data without $M$-of-$N$ council quorum.
  - High-performance non-blocking ingress filtering using in-memory HMAC tag lookups.
