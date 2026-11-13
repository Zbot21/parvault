# AI Agent & Systems Engineer Guide (`AGENTS.md`)

This document is the authoritative architectural, security, and verification manual for AI coding agents and human systems engineers working on **`parvault`** (<!-- metric:crate_version_tag -->`v0.5.0`<!-- /metric -->, library crate `parvault`, binaries `parvault`, `parvault-seed`, `parvault-fuse`, `parvault-sync`, and `parvault-bench`).

---

## 1. System Architecture & Binary Topology

`parvault` is a zero-knowledge, post-quantum hybrid, Byzantine-resilient P2P backup, transport-agnostic `GatewayBus` plugin host, and lazy-streaming virtual filesystem engine designed to run identically on high-capacity homelab servers and memory-constrained residential gateways (`prplOS` / `OpenWrt` LXC containers with a strict **`< 32 MiB` active RAM ceiling**).

### Binaries & Library Targets (`Cargo.toml`)
1. **Library Crate (`parvault` — `src/lib.rs`, `#![deny(unsafe_code)]`):**
   Embeddable Rust API exposing streaming encryption, Reed-Solomon erasure coding over $GF(2^8)$, incremental folder synchronization (`FolderSyncEngine` + zero-key `GatewayFolderSync`), `libp2p` P2P client/daemon networking (`MeshClient`), transport-agnostic `GatewayBus` (`InProcess` vs. `UnixSocket` `SCM_RIGHTS` `memfd` IPC in `gateway`, async + synchronous `*_sync` surface), stateless `CapabilityMacaroon` attenuation & `PARVAULT-MAC-V1:` compact tokens (`capabilities`), dual-mode `/dev/fuse` + WebDAV lazy VFS (`vfs`), audited Unix kernel wrappers (`os_sys`), Web-of-Trust admission, Proof-of-Retrievability (`PoR`), and elastic bootstrap state machines.
2. **Consolidated Client, Peer Daemon, Built-In `=y` VFS & Plugin Host (`parvault` — `src/main.rs` + per-command modules in `src/cli/`, `#![forbid(unsafe_code)]`):**
   Runs on user workstations, laptops, desktops, routers, or homelab nodes (`init`, `up`, `discover`, `pair`, `join`, `watch-folder`, `diff-folder`, `list-snapshot`, `restore-folder`, `recover-from-seed`, `file store`, `file restore`, `evict`, `report-abuse`, `cosign-eviction`, `identity`, `issue-device-cert`, `verify-device-cert`, `scrub`, `leave`, `status`, `daemon start`, `token {mint,attenuate,inspect}`, `gateway {serve,health,ipc-roundtrip,self-test}`). Supports both built-in `=y` mode (`--no-socket` + optional `--vfs-webdav-listen` / `--vfs-fuse-fd` / `--vfs-seed-dir` / `--vfs-cache-mib` over `GatewayBus::InProcess`) and hardened split-plugin `=m` host mode (`--ipc-socket /var/run/parvault.sock --strict-plugins --allow-peer-uid <UID> --require-sealed-memfd`; see [`docs/GATEWAY_SOCKET_PROTOCOL.md`](docs/GATEWAY_SOCKET_PROTOCOL.md), [`ADR-32`](docs/adr/ADR-32-transport-agnostic-gateway-bus-and-memfd-sealing.md), and [`ADR-33`](docs/adr/ADR-33-dual-mode-vfs-and-sibling-gateway-sync.md)).
3. **Standalone Zero-Trust Seed & Redundancy Server (`parvault-seed` — `src/bin/parvault-seed.rs`, `#![forbid(unsafe_code)]`):**
   Runs on headless 24/7 hardware (NAS, Raspberry Pi, Unraid/TrueNAS, VPS, or pure RAM `--no-fs --in-memory-mb <MiB>`) in two strictly zero-plaintext modes (`holds_own_plaintext_files == false`):
   - `--mode homelab-vault` (`SeedServerMode::HomelabRedundancyVault`): Authenticates the owner's personal devices via post-quantum `PersonalDeviceCert`s (`0.0x` self-quota tax), syndicates Lite-Client `1.0x` stripes across mesh peers, and answers network PoR audits 24/7 to earn `TrustLevel::HighUptimeAnchor` (`16-of-20` `EarnedHomelabAnchorPool`, `5.0x` reciprocity multiplier).
   - `--mode public-bootstrap` (`SeedServerMode::PublicNetworkBootstrapper`): Stateless `FoundationSeedAnchor` (supporting `--no-fs` zero-filesystem mode and zero-private-key-on-VPS `admin_rpc` governance) that ingests only anonymized `.bshard` leases during cold-start (`1..19` peers) and automatically drains to `0` shards as verified organic community peers join.
4. **Canonical Lazy-Streaming VFS Reference Plugin (`parvault-fuse` — `src/bin/parvault-fuse.rs`, `#![forbid(unsafe_code)]`):**
   Standalone out-of-process reference plugin (`--features vfs`, zero C `libfuse3`, zero `unsafe`) speaking [`docs/GATEWAY_SOCKET_PROTOCOL.md`](docs/GATEWAY_SOCKET_PROTOCOL.md) over `/var/run/parvault.sock` (`mount-fd` Linux `/dev/fuse` `ABI 7.31`, unprivileged HTTP `206` / WebDAV `PROPFIND`, and sealed-`memfd` folder `sync` with `--macaroon <PARVAULT-MAC-V1:...>` and bounded `LruBlockCache` `< 50 ms` TTFB).
5. **Zero-Key Incremental Folder Sync Sibling Plugin (`parvault-sync` — `src/bin/parvault-sync.rs`, `#![forbid(unsafe_code)]`):**
   Standalone out-of-process folder synchronization plugin (`diff`, `push`, `watch`, `pull`, `list`, `self-test`; builds with `--no-default-features --features ipc-client`, no tokio or libp2p, from item 3) backed by `GatewayFolderSync` (`src/sync/gateway.rs`). Holds **zero** `MasterKey` and **zero** `NodeIdentity` secrets in process memory or `GatewayFolderCatalog` state, seals ingested `memfd`s (`F_ADD_SEALS`), enforces `sanitize_sync_relative_path` path-traversal rejection, and verifies streaming `SHA-256` digests on `1 MiB` chunked `--macaroon` restores (`ADR-33`).
6. **Empirical Benchmark & Memory Telemetry Runner (`parvault-bench` — `src/bin/parvault-bench.rs`, `#![forbid(unsafe_code)]`):**
   Executes real wall-clock benchmarks (`Argon2id`, `AES-256-GCM`, `PqVaultMasterKey`, `X25519 + ML-KEM-768`, `Ed25519 + ML-DSA-65`, Reed-Solomon $GF(2^8)$) and Linux `/proc/self/status` (`VmRSS`, `VmHWM`) + `CLOCK_PROCESS_CPUTIME_ID` (`parvault::os_sys::process_cpu_time_ns`) streaming memory measurements.

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
| `src/network/transport.rs` | `build_mesh_server_swarm` (server swarm: Kademlia server mode with manual routing inserts, mDNS only when LAN discovery is on), `build_mesh_swarm` (the same with mDNS on) and `build_mesh_client_swarm` (client RPC swarm, no mDNS) constructing the primary `libp2p` **TCP + Noise XX + Yamux** stack with optional secondary QUIC listener (`enable_quic`). | `ADR-08` |
| `src/network/discovery.rs` | `LanBeaconPacket`, `LanBeaconResponder`, `LanBeaconHandle`, `discover_lan_peers`, `KnownPeersStore` (`known_peers.json`), `derive_4word_pairing_sas`, and `verify_lan_pairing_code`. Cryptographically signed UDP 4009 beacons with Ed25519 PeerId anti-spoofing and DHCP self-healing. | `ADR-18` |
| `src/network/wan_rendezvous.rs` | `WanPeerCard`, `SignedWanRendezvousEntry`, `WanRendezvousRegistry`, `derive_slot_key_from_code`, `derive_peer_ddns_slot_key`, `seal_wan_peer_card`, `open_wan_peer_card`, `reflect_observed_wan_multiaddr` (STUN-over-Noise), and `PUBLIC_COMMONS_SWARM_SLOT` public tracker indexing. | `ADR-18` |
| `src/router_nas.rs` | `RouterNasStatusServer`, `RouterNasLiveSnapshot`, `RouterNasPeerEntry`, `read_linux_process_memory_kib` (`VmRSS`/`VmHWM`). Zero-dependency embedded HTTP server serving `/api/v1/health`, `/api/v1/peers`, and responsive `< 6 KiB` HTML dashboard. | `ADR-18` |
| `src/network/behaviour.rs` | `MeshNetworkBehaviour` (`Kademlia`, `Gossipsub`, `Toggle<mDNS>`, `Identify`, `Ping`, `RequestResponse`), <!-- metric:wire_request_variants -->23<!-- /metric -->-variant `MeshWireRequest` / `MeshWireResponse` (`RegisterWanRendezvous`, `LookupWanRendezvous`, `QueryNodeStatus`, and the storage, PoR, DHT, relay and governance RPCs), `BincodeWireCodec` (bounded `MAX_WIRE_FRAME_BYTES = 32 MiB`, 64 KiB initial reservation, `with_limit` pre-auth framing); re-exports `PlacementEngine` and `TokenBucketRateLimiter` from their own modules. | `ADR-06`, `ADR-08`, `ADR-15`, `ADR-16`, `ADR-18` |
| `src/network/placement.rs` / `src/network/rate_limit.rs` | `PeerTopologyMetrics`, `ShardPlacementPlan`, `PlacementEngine` (70% Intra-ASN / 30% Cross-Region split); `TokenBucketRateLimiter`. | `ADR-06` |
| `src/network/wire_handler.rs` | `handle_mesh_wire_request`: every inbound `MeshWireRequest` for both the daemon and `parvault-seed`. Role differences are the `WireRolePolicy` hooks (`DaemonWirePolicy`, `SeedWirePolicy`); `admission_class` / `admit` and `shard_owner` are the single admission and shard-owner seams. Entry points `handle_daemon_wire_request` / `handle_seed_wire_request`. | `ADR-08`, `ADR-15`, `ADR-26` |
| `src/network/server_events.rs` | `ServerSwarmEvents`: swarm event arms shared by the daemon and seed loops (connection bookkeeping, mDNS, request dispatch). | `ADR-08` |
| `src/network/client.rs` | `MeshClient`, `parse_peer_multiaddr`, `is_network_peer_addr`, `resolve_zero_config_peers`, `register_wan_rendezvous`, `lookup_wan_rendezvous`. Maintains a persistent background `Swarm` worker connection pool, enforces `/p2p/<PeerId>` verification & TOFU `PeerId` pinning, dual Kademlia DHT + `ZeroTrustDhtStore` replication, live RTT & `QueryPeerStatus` telemetry in `PlacementEngine`, and 2-layer PQ onion relay routing. | `ADR-06`, `ADR-08`, `ADR-15`, `ADR-17`, `ADR-18` |
| `src/network/wot.rs` | `WebOfTrustRegistry` (persisted at `wot_state.bin`), `TrustPoolMode` (`PrivateRing`, `PublicCommons`, `Hybrid`), `PublicCommonsTicket` (self-signed Hashcash PoW ticket, `DEFAULT_PUBLIC_WOT_POW_BITS = 12`), `DelegationChain`, `InvitationHop`, `SlashingEvidence`, `SlashingReason`. Enforces bounded-depth Ed25519 admission (leaf bound to the sender, sub-invites capped), verifier-bound public-commons tickets, and local 3-strike subtree slashing that never targets the genesis or the node's own key. | `ADR-05`, `ADR-09`, `ADR-15`, `ADR-18` |
| `src/storage/block_store.rs` | `BlockStore`, `FileManifest`, `StripeManifestEntry`, `SignedDhtManifestEnvelope`, `ZeroTrustDhtStore` (`dht_*.bin`), `BlindedShardLeaseManager` (`blinded_leases.bin`), `BlindedLeaseSpec`. Configurable streaming stripe size (`ROUTER_SOC_STRIPE_SIZE_BYTES = 1 MiB`, `HOMELAB_NAS_STRIPE_SIZE_BYTES = 4 MiB`, `DEFAULT_STRIPE_SIZE_BYTES = 16 MiB`), `--no-fs` in-memory mode (`BlockStore::new_in_memory`), network shard distribution/restoration via `MeshClient`, crash-safe atomic writes (`sync_all` + `rename`), lease sweeps, `graceful_leave_and_redistribute`, and `scrub_all_shards`. | `ADR-01`, `ADR-02`, `ADR-09`, `ADR-13`, `ADR-15`, `ADR-16`, `ADR-18`, `v0.4.0` |
| `src/storage/quota.rs` | `QuotaManager` (persisted at `quota_state.bin`), `PeerCreditAccount`, `TrustLevel` (`UntrustedProbationary`, `VerifiedNeighbor`, `HighUptimeAnchor`, `SlashedQuarantined`), tiered `/24` subnet caps (`1`, `2`, `4`, `0`), LRU eviction quota release, and `4x` write-amplification cap. | `ADR-07`, `ADR-09`, `ADR-10`, `ADR-15` |
| `src/storage/council.rs` | `CouncilManifest` (signed, epoch-versioned eviction council), `council_manifest_decision` (strict majority, epoch chain), `council_from_manifest` (the single council resolver), `council_chain_after` / `install_council_chain` (chain fetch), `council_scope_root` (scope root by mode). | `ADR-26` |
| `src/network/council_fetch.rs` | Bounded background fetch of a newer council chain from admitted peers (`spawn_council_fetch`). | `ADR-26` |
| `src/storage/eviction.rs` | `PrivacyPreservingEvictionEngine`, `EvictionTarget` (IP, subnet, PeerId, pubkey, Merkle root, locator), `SignedBadActorEvictionOrder`, `EvictionOrderSliceView`, `EvictionPurgeReport`, `shred_and_unlink_file` (`0x00` wipe). Keyed HMAC-SHA256 indexing with ZERO plaintext IPs stored on disk. | `ADR-19` |
| `src/storage/anonymity.rs` | 4-Layer Shard Anonymization: `BlindedShardId` (256-bit keyed HMAC locator under `blind_locator_subkey`), `BlindedShardCapability` ($V_i$ per-shard PoR/read key under `blind_capability_subkey` with $\pm 30\text{ s}$ NTP skew tolerance), `AnonymousQuotaVoucher` (ephemeral per-shard issuer via `mint_ephemeral`), `VoucherNullifierLedger` (bounded 65,536-entry FIFO persisted at `voucher_nullifiers.bin`), and `RelayedShardEnvelope`. | `ADR-11`, `ADR-15`, `ADR-16` |
| `src/os_sys.rs` | Audited Unix/Linux kernel boundary (`#[cfg(unix)]`): 100% safe `pread_full_or_eof` & `pwrite_all` (`FileExt`), `/proc/self/status` RSS/HWM & `/proc/net/dev` readers, and all 13 narrowly scoped `#[allow(unsafe_code)]` POSIX syscall wrappers (`clock_gettime`, `geteuid`/`getegid`, `memfd_create`, `adopt_fuse_dev_fd`, `SCM_RIGHTS` `sendmsg`/`recvmsg`, `bind_reusable_udp_v4`, `peer_socket_ucred`, `seal_memfd_immutable`, `has_immutable_memfd_seals`, `dup_fd_cloexec`). | [`ADR-31`](docs/adr/ADR-31-unsafe-remediation-and-os-sys-ffi-boundary.md), [`ADR-32`](docs/adr/ADR-32-transport-agnostic-gateway-bus-and-memfd-sealing.md) |
| `src/gateway/` | `engine.rs` (`GatewayEngine` `40`-lane `128 KiB`-stack single-wave mesh pool, `strict_allowed_peer_uids`, `require_sealed_ingest_memfd`), `ipc.rs` (`GatewayBus` async + blocking `*_sync` surface, `GatewayIpcServer`, `GatewayIpcClient`, `store_sealed_payload_fd`, `SO_PEERCRED` & `F_ADD_SEALS` enforcement), `cli_runner.rs` (`parvault token` & `parvault gateway` runners), and `shm.rs` (`SharedPayloadFd`, `0` `unsafe`). | [`ADR-27`](docs/adr/ADR-27-zero-copy-uds-gateway-and-hedged-pool.md), [`ADR-32`](docs/adr/ADR-32-transport-agnostic-gateway-bus-and-memfd-sealing.md), [`ADR-33`](docs/adr/ADR-33-dual-mode-vfs-and-sibling-gateway-sync.md) |
| `src/capabilities.rs` | Stateless `HMAC-SHA256` `CapabilityMacaroon` minting, offline caveat attenuation (`AllowedManifest`, `ByteRange`, `ExpiresAtUnixMs`, `ReadOnly`, `AllowedPeerUid`), `PARVAULT-MAC-V1:` compact binary/hex encoding, `MacaroonSliceView`, and `< 1 ms` zero-DB RAM verification (`ct_eq_32`). | [`ADR-28`](docs/adr/ADR-28-stateless-macaroon-capability-attenuation.md), [`ADR-32`](docs/adr/ADR-32-transport-agnostic-gateway-bus-and-memfd-sealing.md) |
| `src/vfs.rs` | Pure-Rust Linux `/dev/fuse` (`ABI 7.31`, `0` `unsafe` `parse_fuse_in_header` / `parse_fuse_read_in`), dual-mode `VirtualVaultFs` (`with_bus` / `with_bus_and_block_size`, `.parvaultignore`-aware `ingest_local_directory`), `VfsStubNode`, `LruBlockCache`, `--macaroon` attenuation pass-through, and RAII `VfsWebdavServerHandle` (`spawn_webdav_server`) + blocking HTTP `206` / WebDAV `PROPFIND` server. | [`ADR-29`](docs/adr/ADR-29-pure-rust-fuse-and-webdav-lazy-vfs.md), [`ADR-32`](docs/adr/ADR-32-transport-agnostic-gateway-bus-and-memfd-sealing.md), [`ADR-33`](docs/adr/ADR-33-dual-mode-vfs-and-sibling-gateway-sync.md) |
| `src/admin_rpc.rs` | Forward-secret `X25519 + ChaCha20-Poly1305` + `Ed25519` challenge-authenticated TCP control channel for zero-private-key-on-VPS seed administration (`MAX_ADMIN_RPC_FRAME_BYTES`, `±60s` anti-replay window). | [`ADR-26`](docs/adr/ADR-26-verifiable-abuse-and-council-quorum-governance.md) |
| `src/kani_proofs.rs` | <!-- metric:kani_harnesses_module -->`22`<!-- /metric --> Kani Rust Bounded Model Checking symbolic harnesses (`#[cfg(kani)]`; <!-- metric:kani_harnesses -->`25`<!-- /metric --> total across the crate including `capabilities`, `crypto::aes`, and `sharding::reed_solomon`). | [`ADR-01`–<!-- metric:adr_last -->`ADR-33`<!-- /metric -->](docs/ADR.md) |
| `src/bootstrap.rs` | `EarnedStanding`, `ElasticBootstrapEngine`, `PersonalDeviceCert` (including compact `PARVAULT-CERT-V1:` token encoding), `BlindedShardTombstone` (generation-scoped), `ZeroTrustSeedServer`, `CorrelatedOutageController`, and `/32` IPv6 + RFC 6598 CGNAT Sybil subnet normalization. | `ADR-13`, `ADR-14`, `ADR-15`, `ADR-16`, `ADR-17` |
| `src/sync.rs` | Key-bearing `FolderSyncEngine`, zero-key `GatewayFolderSync` & `GatewayFolderCatalog` (`ADR-33`), `sanitize_sync_relative_path` (`sanitize_sync_relative_path_into`), `FolderSnapshotManifest`, `EncryptedVaultCatalogEnvelope`, `.parvaultignore` matcher (`ParvaultIgnore`), `FolderSyncDiff` (`diff_folder`), `prune_deleted_file_shards` (local + remote `DeleteShard` GC), selective restore (`restore_single_file`, `restore_selective_subset`), and zero-local-state seed recovery (`recover_folder_from_seed_phrase`). | `ADR-10`, `ADR-15`, `ADR-16`, `ADR-17`, [`ADR-33`](docs/adr/ADR-33-dual-mode-vfs-and-sibling-gateway-sync.md) |
| `src/network/admission.rs` | Client-side ring admission (`v0.5.0`): `AdmissionSource` (self-issue from a held genesis, installed chains in `wot_chains/`, public-commons tickets), `requires_admitted_sender`. Server-side decisions live next to their checks (`wire_handler::admission_decision`, `shard_owner_decision`, `device_cert_decision`; `wot::chain_leaf_decision`, `public_ticket_decision`, `slash_target_decision`; `por::verifier::grant_registration_decision`, `repair_read_decision`; `server_events::kad_record_decision`, `kad_routing_decision`; `client::dht_candidate_decision`). Each logs a `reject.*` code; `.enforcement.map` holds the claims. |
| `src/telemetry.rs` | `AnonymousTelemetryBeacon` (rotating epoch nullifier + Hashcash PoW + power-of-two GiB bucketing capped at 64 TiB) and `NetworkCensusAggregator` (Tukey IQR outlier trimming + capture-recapture population estimate). | `ADR-14`, `ADR-15` |

---

## 3. Seven Non-Negotiable Zero-Trust & Memory-Safety Rules

Every code change or PR **must** preserve these 7 invariants:

1. **Encrypt-Before-Shard Ordering (`ADR-01` / `ADR-12`):**
   Plaintext must always be padded (`pad_plaintext_iso_bucket`) and encrypted client-side with `AES-256-GCM` (`MasterKey::stripe_aead_subkey`) or dual-cipher cascaded `PqVaultMasterKey` (`AES-256-GCM` + `ChaCha20-Poly1305`) **before** Reed-Solomon encoding over $GF(2^8)$. Never pass unencrypted bytes into `sharding::reed_solomon`.
2. **Bounded `< 32 MiB` Streaming I/O & Tiny-SoC 1 MiB Profile (`ADR-01`, `ADR-16`, `ADR-18`):**
   Never call `std::fs::read` on user backup files or restored staging files. Always use `compute_file_sha256_streaming` (64 KiB buffer) and `store_file_streaming` / `restore_file_streaming`. With `--profile router-soc` (`1 MiB` stripes), peak working set `VmHWM` is guaranteed `< 16 MiB` (<!-- metric:bench.soc.vmhwm -->`9.72–9.74 MiB`<!-- /metric --> measured) inside a 32–48 MiB cgroup. All stripe profiles (`1 MiB`, `4 MiB`, `16 MiB`) are 100% wire- and manifest-interoperable.
3. **Pre-Authentication Wire Allocation Bounds (`ADR-15` / `ADR-16`):**
   All network deserialization in `BincodeWireCodec` must use `bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_limit(buf.len() as u64)` after enforcing `MAX_WIRE_FRAME_BYTES` (`32 MiB`, with 64 KiB initial read reservation against Slowloris attacks), and all replay/nullifier caches (`PorVerifierEngine`, `VoucherNullifierLedger`) must remain strictly bounded in capacity (`65,536` entries) with FIFO eviction.
4. **Crash-Safe Atomic Persistence (`ADR-15`):**
   All writes of `.shard`, `.bshard`, `.manifest.bin`, and `blinded_leases.bin` must go through `BlockStore::atomic_write_file` (write to `.tmp.<nonce>`, call `File::sync_all()`, and atomically `fs::rename`), and disk I/O must succeed *before* consuming a `BearerQuotaVoucher` nullifier.
5. **Strict Path-Traversal & Symlink Blocking (`ADR-15`):**
   Every file restoration path in `FolderSyncEngine` must be validated through `FolderSyncEngine::resolve_safe_restore_path`, which rejects `..` (`ParentDir`), `/` (`RootDir`), Windows drive/UNC prefixes (`Prefix`), `\`, `:`, null bytes, and symlink targets, and verifies the restored file's streaming SHA-256 on a `.parvault_restore_staging` file before atomic placement.
6. **Earned Standing & `VerifiedNeighbor` Seed-Drain Gating (`ADR-13` / `ADR-15`):**
   Nodes must never bypass `EarnedStanding::evaluate` to claim `16-of-20` Homelab standing without $\ge 200$ PoR passes at $\ge 99.8\%$ SLA, and `ElasticBootstrapEngine::plan_seed_anchor_drain` must never drain Foundation Seed Anchor shards onto organic peers below `TrustLevel::VerifiedNeighbor` ($\ge 50$ PoR passes).
7. **No Unauthenticated Framing Slashes (`ADR-15`):**
   Never slash or increment failure counters on a leaf `NodeIdentity` inside an unverified `HandshakeWoT` request (`handle_mesh_wire_request` in `src/network/wire_handler.rs`), as an attacker could otherwise forge 3 bit-flipped handshakes carrying an honest node's public key to frame and quarantine that node's Web-of-Trust branch.

---

## 4. Build, Test, Multi-Container Docker & Formal Verification Commands

### Rust Unit, Integration, Mathematical & Red-Team Suites
```bash
# Check formatting, lints, and --no-default-features compilation
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo check --no-default-features --features daemon-runtime --bin parvault --bin parvault-seed --bin parvault-sync

# Run all unit, integration, Stateright, TLA+ TLC, GatewayBus, VFS, GatewayFolderSync, and live localhost TCP P2P tests
TLA2TOOLS_JAR=/root/tla2tools.jar cargo test --release

# Run built-in self-tests for seed, zero-copy IPC gateway, lazy VFS, and zero-key folder sync
cargo run --release --bin parvault-seed -- self-test
cargo run --release --bin parvault -- gateway self-test
# Plugin self-tests are client-only: this starts a standalone gateway, mints a token, runs both
bash scripts/build_bins.sh --profile release --out dist && bash scripts/plugin_self_test.sh dist/parvault dist/parvault-fuse dist/parvault-sync

# Run the empirical cryptography, Reed-Solomon, and /proc/self/status memory benchmark binary
cargo run --release --bin parvault-bench -- run --payload-mib 64

# Run the multi-container Docker P2P & 48 MiB Router-SoC regression acceptance gate
bash scripts/docker_acceptance_gate.sh
```

- **Numbers in docs:** marked values (`<!-- metric:KEY -->…<!-- /metric -->`) come from `docs/metrics.txt`; never hand-edit them. Change the metrics file (measured keys only after re-measuring; `scripts/gen_metrics.sh --measured` covers sizes and TLC states), then run `bash scripts/sync_doc_metrics.sh --generate .`.
- **Change-scoped gates during iteration:** `.scoped-gates.map` maps each path to its `--lib` filter, test suites, Kani harnesses, TLA+ specs, and docs; run it with the swarm skill's `run_scoped_gates.sh` (unmapped paths escalate to the full gate run).

### Static `musl` Cross-Compilation (`x86_64` & `aarch64`, `--profile soc`)
```bash
# x86_64 static musl build (stripped sizes: docs/BENCHMARKS.md section 4)
# (build_bins.sh builds each binary with its own features, so the plugins link no tokio or libp2p)
bash scripts/build_bins.sh --profile soc --target x86_64-unknown-linux-musl --out dist

# ARM64 static musl build (OpenWrt / prplOS LXC / RPi; sizes: docs/BENCHMARKS.md section 4)
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  bash scripts/build_bins.sh --profile soc --target aarch64-unknown-linux-musl --out dist
```

### Kani Bounded Model Checking (<!-- metric:kani_harnesses -->`25`<!-- /metric --> Harnesses) & TLA+ TLC Formal Model Checking (<!-- metric:tla_specs -->`7`<!-- /metric --> Specs)
All **<!-- metric:kani_harnesses -->25<!-- /metric -->** Kani symbolic harnesses (`cargo kani`) and all **<!-- metric:tla_specs -->7<!-- /metric -->** TLA+ specifications in `specs/` must complete with **0 errors** (see [`docs/SAFETY_AND_LINT_AUDIT.md`](docs/SAFETY_AND_LINT_AUDIT.md)):
```bash
bash scripts/verify_formal_proofs.sh

# Individual TLA+ TLC runs:
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultProtocol.cfg specs/ParVaultProtocol.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultConfidentialityAndTrust.cfg specs/ParVaultConfidentialityAndTrust.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultAnonymity.cfg specs/ParVaultAnonymity.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultPostQuantum.cfg specs/ParVaultPostQuantum.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultBootstrapAndEarnedTier.cfg specs/ParVaultBootstrapAndEarnedTier.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultLiteClientAndSeedFailover.cfg specs/ParVaultLiteClientAndSeedFailover.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultZeroKeyAdminAndQuorum.cfg specs/ParVaultZeroKeyAdminAndQuorum.tla
```
- **Automatic TLA+ Execution in `cargo test` (`tests/tla_formal_proofs_integration.rs`):** Setting `TLA2TOOLS_JAR=/path/to/tla2tools.jar` (configured automatically in `.github/workflows/ci.yml`) runs all **<!-- metric:tla_specs -->7<!-- /metric -->** TLA+ formal specifications directly inside `cargo test --release`.
