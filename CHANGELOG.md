# Changelog

All notable architectural decisions, security hardenings, and user-facing features for `parvault` (`parvault`, `parvault-seed`, `parvault-gateway`, `parvault-fuse`, and `parvault-bench`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security
- **F-37 (critical, pre-release):** a public-commons node outside any ring used the all-zero key as a placeholder genesis, and signatures were checked non-strictly, so a stranger could forge a one-hop chain and be admitted as a ring member. A node with no ring now has no genesis and refuses every `HandshakeWoT`; all Ed25519 checks use strict verification.
- **Ring admission is enforced (item 2b, `docs/security/TRUST_FINDINGS.md`).** Storage requests (`PutShard`, `SyndicateLiteStripe`, `PutDhtEnvelope`, `PutBlindedShard`, onion final delivery) need an admitted sender; others get `peer not admitted; v0.5.0 requires ring admission`. Start a ring with `parvault wot init` and add devices with `parvault wot invite` / `parvault wot install-chain`. No node creates a genesis on its own any more: a private-mode daemon outside any ring, or with conflicting genesis sources, refuses to start. `v0.4.0` peers are refused.
- Onion originators (`OnionOriginator`) never present a ring credential to the entry relay; only the relay's forward to the final target is admitted.
- Public-commons tickets are bound to the verifier and fresh for 10 minutes, rate-limited per subnet, and never evict a live admission; admissions are written in batches.
- The handshake returns one fixed refusal text; members may sub-invite at most 64 keys; inbound Kademlia records need an admitted source; repair grants are keyed by owner and bound to the shards stored with them; only a shard's owner can delete it.
- `HandshakeWoT` admits only the sender's own chain; the accounted shard owner is always the sender (foreign owner claims are refused); a syndication device cert must name the sender.
- Repair grants register only after a stored shard, for its stripe, without replacing another owner's grant; witness repair reads need the registered grant.
- The DHT reader ignores envelopes not sealed by the reading identity; inbound Kademlia records must be valid signed envelopes.
- Slashing gossip is no longer applied (until proof-carrying evidence, 2c); the genesis and the node's own key are never slashed.
- `--no-lan-discovery` turns mDNS off; mDNS never feeds Kademlia, admission does.

### Added
- `MeshWireRequest::AdmitPublicTicket` / `MeshWireResponse::AdmitPublicTicketAck` (appended; existing indices unchanged) and `parvault wot init` / `invite` / `install-chain`.

### Removed
- `CorrelatedOutageController::verify_weather_quorum` and `SignedWeatherAttestation` (never called; F-15).

### Changed
- Stripes that no ring peer accepted (or stored with no peers) are no longer reported as a finished backup. `watch-folder --once`, `file store` and `parvault-sync push` print `N stripe(s) kept only on this machine: NOT backed up` and exit with code `3` unless given `--allow-local-only`; `up --folder`, `--vfs-seed-dir` and the `watch-folder` loop log it as an error each pass; `parvault status` shows `Local-Only Stripes`. **Protocol change:** gateway IPC appends `IpcResponse::StoreSuccessLocalOnly` (discriminant 4); a plugin built against the old enum fails to decode it rather than reporting success (parvault-suite re-pins in item 7). Async `GatewayBus` callers get the count from `store_payload_fd_counted`. When some shards reach peers, they stay there and only the rest are stored locally; `parvault status` counts only listed stripes that still have local shards.
- `list-snapshot` prints each file's full stripe roots, the value `evict --merkle-root` takes.
- The gateway engine's 40 mesh lanes send as the owner identity (one `PeerId`).
- The seed's syndication puts carry an empty owner claim (accounted to the seed).
- **Shared wire handler (`#codehealth`):** the daemon and `parvault-seed` now serve every `MeshWireRequest` through one `handle_mesh_wire_request` in `src/network/wire_handler.rs`; the nine role differences are explicit `WireRolePolicy` hooks. Behaviour and wire format are unchanged (pinned by `tests/wire_handler_equivalence.rs`).
- **Log targets:** the seed's wire-handler warnings now log under `parvault::network::wire_handler` instead of `parvault_seed`, and the daemon's mDNS discovery line under `parvault::network::server_events`. The default filters (`parvault=info`) still print them; a custom `RUST_LOG` that names `parvault_seed` will not.
- `parvault` command implementations moved from `src/main.rs` into `src/cli/`; `PlacementEngine` and `TokenBucketRateLimiter` moved to `network::placement` / `network::rate_limit` (re-exported at their old paths).
- Crate version `0.5.0`; `deploy/Dockerfile.musl` builds `--profile soc` like the release workflow.

---

## [`0.4.0`] - 2026-11-11

### Added
- **Canonical Zero-Copy UDS Data-Plane Gateway (`parvault-gateway`, `src/gateway/`, [`ADR-27`](docs/adr/ADR-27-zero-copy-uds-gateway-and-hedged-pool.md)):**
  - Unified `GatewayEngine`, `GatewayIpcServer`, `GatewayIpcClient`, `PinnedRingBudget<SLOTS>`, and `SharedPayloadFd` over `/var/run/parvault.sock` (`0600`) passing Linux `memfd_create` descriptors via `SCM_RIGHTS` (`730.88–957.01 MiB/s` `Store`, `1,724.51–2,213.86 MiB/s` `FetchRange`, `0.49 ms` local TTFB, `10.98 MiB` peak `VmHWM` `< 16 MiB`).
  - Provisioned a `40`-lane (`MESH_POOL_CONCURRENCY = 40`, `128 KiB` stack per worker thread) single-wave `libp2p` shard pool so all `N <= 40` shards fire concurrently at `t = 0` (`< 60 ms` degraded-WAN TTFB).
  - Added CLI subcommands `serve` (`--peers`, `--tier`, `--stripe-bytes`, `--macaroon-root-key-hex`), `ipc-roundtrip` (`--size-mib`, `--net-iface`), `health`, and `self-test`.
- **Stateless `HMAC-SHA256` `CapabilityMacaroon` Attenuation (`src/capabilities.rs`, [`ADR-28`](docs/adr/ADR-28-stateless-macaroon-capability-attenuation.md)):**
  - Implemented offline monotonic caveat attenuation (`AllowedManifest`, `ByteRange`, `ExpiresAtUnixMs`, `ReadOnly`), `< 1 ms` zero-DB constant-time RAM verification (`ct_eq_32`), and composite post-quantum `GatewayIdentityStatement` (`Ed25519 + ML-DSA-65`).
- **Pure-Rust Userspace `/dev/fuse` (`ABI 7.31`) & WebDAV Lazy Virtual Filesystem (`parvault-fuse`, `src/vfs.rs`, [`ADR-29`](docs/adr/ADR-29-pure-rust-fuse-and-webdav-lazy-vfs.md)):**
  - Implemented feature-gated (`--features vfs`) zero-`unsafe` Linux `/dev/fuse` (`parse_fuse_in_header`, `parse_fuse_read_in`), `VirtualVaultFs`, `VfsStubNode` lazy metadata inodes, `LruBlockCache`, and unprivileged HTTP `206 Partial Content` / WebDAV `PROPFIND` (`14.59 ms` TTFB `< 50 ms` on `10 GiB` sparse vaults).
- **Filesystem-Free Bounded-RAM Ephemeral Seed Mode (`parvault-seed --no-fs --in-memory-mb`, [`ADR-30`](docs/adr/ADR-30-filesystem-free-in-memory-seed-mode.md)):**
  - Added `--no-fs --in-memory-mb <MiB>` (`--identity-env` / `--identity-file`) creating zero persistent directories or files on disk and scrubbing evicted/dropped buffers with `0x00` via `zeroize::Zeroize`.
- **Crate-Wide `#![deny/forbid(unsafe_code)]`, `src/os_sys.rs` Isolation & Formal Verification Expansion ([`ADR-31`](docs/adr/ADR-31-unsafe-remediation-and-os-sys-ffi-boundary.md), [`docs/SAFETY_AND_LINT_AUDIT.md`](docs/SAFETY_AND_LINT_AUDIT.md)):**
  - Enforced `#![deny(unsafe_code)]` on `src/lib.rs` and `#![forbid(unsafe_code)]` across `src/main.rs` and all 4 binaries (`parvault-seed`, `parvault-gateway`, `parvault-fuse`, `parvault-bench`); isolated all `9` POSIX syscalls inside `src/os_sys.rs` and implemented `pread_full_or_eof` / `pwrite_all` using 100% safe `FileExt::{read_at, write_at}`.
  - Expanded formal verification to **`15/15` Kani symbolic harnesses** (adding `proof_pinned_ring_capacity_invariant`, `proof_fuse_header_parser_no_panic`, `proof_gateway_ipc_frame_header_bounds`, `proof_vfs_block_window_power_of_two_and_zero_bounds`, `proof_macaroon_caveat_attenuation_monotonic_and_zero_key_rejected`) + **`7/7` TLA+ TLC specifications** (`ParVaultZeroKeyAdminAndQuorum.tla`) and **`122/122` release tests**.
  - Sharded `docs/ADR.md` into **31 strictly single-concern ADR files** under [`docs/adr/`](docs/adr/) with a complete `AES-256-GCM` vs. Post-Quantum Cryptography suite guide and a standalone GitHub Flavored Markdown math/currency CI gate.

---

## [`0.3.0`] - 2026-11-11

### Added
- **Zero-IP Home LAN Auto-Discovery, Persistent Peer Registry & 4-Word SAS Pairing (`ADR-18`, `src/network/discovery.rs`):**
  - Added cryptographically signed `LanBeaconPacket` broadcasting on UDP port `4009` (multicast group `239.255.80.86`, broadcast `255.255.255.255`, and ephemeral localhost fallback) signed under domain `"parvault-lan-beacon-v1:"`.
  - Enforced strict cryptographic binding between `ed25519_pubkey` and `libp2p_peer_id` so rogue clients on Wi-Fi cannot spoof peer identities.
  - Implemented 4-word BIP-39 SAS pairing code derivation (`derive_4word_pairing_sas`, `verify_lan_pairing_code`) allowing devices to mutually authenticate and pair with zero IP configuration.
  - Added DHCP-resilient persistent peer store `KnownPeersStore` (`known_peers.json`) updating socket addresses dynamically when home routers renegotiate DHCP leases without invalidating pinned `PeerId`s.
  - Added automatic zero-IP fallback across all high-level CLI commands (`watch-folder`, `restore-folder`, `file store`, `file restore`, `leave`, `status`) via `resolve_zero_config_peers`.
- **Tiny-SoC 1 MiB Streaming Stripe Profile, Allocation Diet & Turnkey Router Packaging (`ADR-18`, `src/storage/block_store.rs`, `Cargo.toml`, `deploy/`):**
  - Introduced configurable streaming stripe sizes in `BlockStore` (`BlockStore::with_stripe_size_bytes`) and `HardwareProfile` (`RouterSoc` `1 MiB`, `HomelabNas` `4 MiB`, `Desktop` `16 MiB`).
  - Reduced transient peak working set memory (`VmHWM`) during Reed-Solomon $GF(2^8)$ encoding/reconstruction from `57.30 MiB` down to **`9.39 MiB`** (6.1x reduction), enabling safe execution within a strict 32–48 MiB cgroup.
  - Authored `deploy/Dockerfile.router-soc` (`FROM scratch` container image), OpenWrt `/etc/init.d/parvault-nas` `procd` service script, and updated `deploy/prplos-lxc-manifest.json` for prplOS gateway integration.
  - Authored comprehensive integration manual [`docs/ROUTER_SOC_HARDWARE_GUIDE.md`](docs/ROUTER_SOC_HARDWARE_GUIDE.md).
- **Embedded Zero-Dependency Router Cloud-NAS Status HTTP Server (`ADR-18`, `src/router_nas.rs`):**
  - Implemented lightweight HTTP server using `tokio::net::TcpListener` serving `GET /api/v1/health` (live `VmRSS`/`VmHWM`, uptime, quotas, pairing code), `GET /api/v1/peers` (LAN peers), and `GET /` (embedded HTML5 dashboard `< 6 KiB`).
  - Added turnkey single-command appliance mode `parvault up` combining P2P storage daemon, UDP discovery responder, embedded web status server, and background folder synchronization.
- **Zero-IP Online WAN Rendezvous, STUN-over-Noise Reflection & Dynamic-IP Presence (`ADR-18`, `src/network/wan_rendezvous.rs`, `src/network/behaviour.rs`):**
  - Added `RegisterWanRendezvous` and `LookupWanRendezvous` wire RPCs to `MeshWireRequest` / `MeshWireResponse`.
  - Implemented blinded WAN rendezvous mailbox deriving `slot_key = HKDF(code, "slot-v1")` and AEAD wrapping key `wrap_key = HKDF(code, "wrap-v1")` for zero-knowledge 4-word pairing across cities.
  - Implemented STUN-over-Noise external address reflection extracting observed socket addresses from authenticated `libp2p` Noise XX connection metadata.
  - Added zero-knowledge dynamic-IP presence publishing encrypted endpoint heartbeats to blinded DDNS slots, surviving residential ISP address rotations.
- **Open Public Commons / BitTorrent-Style Public Swarm Mode (`ADR-18`, `src/network/wot.rs`, `src/network/wan_rendezvous.rs`):**
  - Added `TrustPoolMode` (`PrivateRing`, `PublicCommons`, `Hybrid`) in `WebOfTrustRegistry`.
  - Added self-signed Hashcash Proof-of-Work admission ticket `PublicCommonsTicket` (`DEFAULT_PUBLIC_WOT_POW_BITS = 12`) allowing stranger nodes to join public swarms without invitations.
  - Enabled zero-pairing public swarms (`--public --tracker <MULTIADDR>`) where `parvault-seed --mode public-bootstrap` serves as a public tracker anchor indexing active swarm peers under `PUBLIC_COMMONS_SWARM_SLOT`.
- **4-Vector Privacy-Preserving Bad-Actor & Content Eviction Engine (`ADR-19`, `src/storage/eviction.rs`):**
  - Implemented `PrivacyPreservingEvictionEngine` supporting 4 eviction vectors: IP address / CIDR subnet (`/24`, `/48`), `libp2p` `PeerId`, peer/voucher-issuer public key cohorts (purging associated anonymous `.bshard` blinded shards), and content identifiers (`stripe_merkle_root`, `BlindedLocator`).
  - Enforced zero-plaintext-IP disk privacy: all ingress records and blocklist rules in `eviction_index.bin` are stored as keyed HMAC-SHA256 tags under a local random `0600` secret key (`eviction_hmac.seed`), ensuring zero IP addresses or cross-node correlatable identifiers exist on disk.
  - Implemented multi-pass `0x00` zero-wipe file shredding in 64 KiB chunks (`shred_and_unlink_file`) with explicit `sync_all()` flushes prior to unlinking.
  - Added cryptographically authenticated eviction orders (`SignedBadActorEvictionOrder`) domain-separated under `"parvault-bad-actor-eviction-order-v1:"` with mesh-wide propagation (`BroadcastEvictionOrder` / `EvictionOrderAck`).
  - Added Public Swarm Anti-Griefing Governance: nodes in `--public` swarms reject unauthenticated peer eviction orders, accepting orders exclusively from configured `eviction_authorities` (including the Public Tracker Operator's `tracker_admin.seed` authority, advertised in tracker discovery responses).
  - Implemented Cryptographic Reporter Burden-of-Proof (`VerifiableAbuseReport`): reporters alleging illegal distribution must submit the leaked `FileManifest` and `MasterKey`; nodes verify shard Merkle proofs, Reed-Solomon stripe reconstruction, and `AES-256-GCM` authentication tags, computing `verified_plaintext_sha256` and zeroizing the plaintext memory buffer immediately.
  - Added Mathematical Anti-Framing: private backups cannot be framed because guessing or forging a 256-bit `MasterKey` results in `AES-256-GCM` authentication tag failure ($2^{-128}$).
  - Added Human-in-the-Loop Admin Takedown Queue (`PublicTrackerTakedownQueue`, `<data_dir>/admin_takedown_queue.bin` `0600`): reports remain in `PendingAdminReview` with zero automatic deletion until the Public Tracker Admin approves them.
  - Implemented 2-Lane Public Swarm Governance: Lane 1 reviews reporter cryptographic proofs (`approve-takedown`), while Lane 2 enables unilateral emergency law-enforcement / warrant evictions (`emergency-evict --warrant-ref <TEXT>`) for private contraband, recording `EmergencyAdminActionRecord`s and purging voucher cohorts without compromising disk IP privacy.
  - Enforced Strict Ring-of-Trust vs. Public Commons Isolation: `PrivateRing` nodes unconditionally reject external `tracker_admin_pubkey` orders, guaranteeing tracker admin powers cannot reach private homelab or family vaults.
  - Added `M-of-N` Federated Public Tracker Council Quorum (`TrackerOperatorCosignature`): prevents rogue public tracker operators from unilaterally broadcasting fraudulent eviction orders or stealing storage capacity; requires strict majority co-signatures (`default_tracker_quorum_threshold(N)`) across trusted council operators via `parvault-seed admin cosign-eviction`.
  - Added new commands: `parvault report-abuse`, `parvault evict`, `parvault-seed evict`, and `parvault-seed admin {show-authority, list-takedowns, inspect-takedown, approve-takedown, reject-takedown, emergency-evict, cosign-eviction}`.
- **New User-Friendly Subcommands & CLI Flags (`src/config.rs`, `src/main.rs`, `src/bin/parvault-seed.rs`):**
  - Added `parvault init`, `parvault discover`, `parvault pair`, `parvault join`, `parvault up`, `parvault evict`, `parvault report-abuse`, `parvault-seed evict`, and `parvault-seed admin`.
  - Added global `--profile <router-soc|homelab-nas|desktop>`, `--lan-discovery-port <PORT>`, `--no-lan-discovery`, `--public`, and `--tracker <MULTIADDR>` flags on `parvault`.
  - Added opt-in `--admin-rpc-listen <SOCKET_ADDR>` and `--admin-rpc-pubkey <HEX>` on `parvault-seed` for forward-secret multi-tracker fleet management via `parvault-control` (`src/admin_rpc.rs`).

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
