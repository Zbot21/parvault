# Embedding `parvault` as a Rust Library (<!-- metric:crate_version_tag -->`v0.5.0`<!-- /metric -->)

`parvault` is architected as a dual-purpose crate: every subsystem powering the `parvault`, `parvault-seed`, `parvault-fuse`, and `parvault-sync` binaries is exposed through a clean, memory-bounded Rust library API (`src/lib.rs`, `#![deny(unsafe_code)]`) suitable for embedding inside backup agents, NAS appliances, ISP gateway daemons, and zero-key quorum control planes.

---

## 1. Adding `parvault` to `Cargo.toml`

Pin the latest published release tag, <!-- metric:released_version_tag -->`v0.4.0`<!-- /metric -->:

```toml
[dependencies]
parvault = { git = "https://github.com/Zbot21/parvault.git", tag = "v0.4.0" }
anyhow = "1"
```

---

## 2. Quickstart: Incremental Sync & Zero-Local-State Recovery

Parent applications can embed `parvault` directly for incremental folder synchronization, post-quantum catalog sealing, and zero-local-state ("house fire") disaster recovery:

```rust
use parvault::{
    config::ErasureTier,
    crypto::{MasterKey, NodeIdentity},
    storage::{BlockStore, QuotaManager},
    sync::FolderSyncEngine,
};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    // 1. Derive deterministic keys from a checksummed BIP-39 recovery seed phrase (or use MasterKey::generate())
    let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let namespace = "my-homelab-vault";
    let master_key = MasterKey::from_recovery_seed_phrase(seed, namespace);
    let owner_identity = NodeIdentity::from_recovery_seed_phrase(seed, namespace);

    // 2. Initialize crash-safe local BlockStore and incremental FolderSyncEngine
    let quota = QuotaManager::new(100 * 1024 * 1024 * 1024, 10 * 1024 * 1024 * 1024);
    let store = BlockStore::new(Path::new("./.parvault-data"), quota)?;
    let mut engine = FolderSyncEngine::new(
        store.clone(),
        master_key,
        owner_identity,
        ErasureTier::Homelab, // 16-of-20 Reed-Solomon over GF(2^8)
    );

    // 3. Incrementally encrypt & erasure-code new/modified files (respecting .parvaultignore)
    let snapshot = engine.sync_folder_once(Path::new("./my-folder"))?;
    let catalog = engine.export_encrypted_vault_catalog(seed, namespace, &snapshot)?;

    // 4. Zero-Local-State "House Fire" Recovery using only the seed phrase + encrypted catalog
    let restored_files = FolderSyncEngine::recover_folder_from_seed_phrase(
        store,
        seed,
        namespace,
        &catalog,
        Path::new("./restored-folder"),
    )?;
    println!("Verified and restored {restored_files} files!");
    Ok(())
}
```

---

## 3. Selecting a Memory Profile (`Router-SoC` vs. `Desktop`)

When embedding `parvault` inside constrained Linux containers, residential routers (`OpenWrt` / `prplOS`), or embedded ARM64 SBCs, select the `HardwareProfile::RouterSoc` profile (`1 MiB` streaming stripes instead of `16 MiB` desktop stripes) to keep transient heap and `VmHWM` strictly bounded below `16 MiB`:

```rust
use parvault::config::{
    HardwareProfile, DEFAULT_STRIPE_SIZE_BYTES, ROUTER_SOC_STRIPE_SIZE_BYTES,
};

let profile = HardwareProfile::RouterSoc;
assert_eq!(profile.stripe_size_bytes(), ROUTER_SOC_STRIPE_SIZE_BYTES); // 1 MiB (1,048,576 bytes)
assert_eq!(HardwareProfile::Desktop.stripe_size_bytes(), DEFAULT_STRIPE_SIZE_BYTES); // 16 MiB
```

---

## 4. Dual-Mode `GatewayBus`, Built-In `VirtualVaultFs` & Zero-Key `GatewayFolderSync` (`ADR-33`)

Multi-tenant services and language-agnostic frontends can embed `GatewayBus::InProcess` directly (`--no-socket`) or speak to `parvault up --ipc-socket /var/run/parvault.sock` via `GatewayBus::UnixSocket` (`SCM_RIGHTS` + sealed Linux `memfd_create` + `SO_PEERCRED` UID binding) using identical async or synchronous (`*_sync`) APIs, `VirtualVaultFs::with_bus`, and zero-key `GatewayFolderSync` (see [`GATEWAY_SOCKET_PROTOCOL.md`](GATEWAY_SOCKET_PROTOCOL.md)):

```rust
use parvault::{
    capabilities::{CapabilityMacaroon, Caveat},
    gateway::{GatewayBus, RetentionPolicy, DEFAULT_IPC_SOCKET_PATH},
    sync::{sanitize_sync_relative_path, GatewayFolderSync},
    vfs::VirtualVaultFs,
};
use std::path::Path;

fn plugin_sync_and_vfs(root_key: &[u8; 32]) -> anyhow::Result<()> {
    // 1. Connect over /var/run/parvault.sock (or swap in GatewayBus::in_process(Arc::clone(&engine)))
    let bus = GatewayBus::unix_socket(DEFAULT_IPC_SOCKET_PATH);
    assert_eq!(
        sanitize_sync_relative_path("docs\\guide//intro.md").as_deref(),
        Some("docs/guide/intro.md")
    );

    // 2. Zero-key incremental push (holds ZERO MasterKey and ZERO NodeIdentity in struct!)
    let mut sync = GatewayFolderSync::new(bus.clone());
    let catalog = sync.sync_folder_once(Path::new("./my-folder"), RetentionPolicy::Persistent)?;
    catalog.save_to_file(Path::new("./.parvault_gateway_catalog.bin"))?;

    // 3. Attenuate a read-only macaroon and selectively pull docs/* with streaming SHA-256 verification
    let read_token = CapabilityMacaroon::mint(root_key, [0x11; 32], [0x22; 32], vec![Caveat::ReadOnly])?;
    let reader = GatewayFolderSync::with_catalog(bus.clone(), catalog)
        .with_default_macaroon(Some(read_token.clone()));
    reader.restore_to_folder(Path::new("./restored-docs"), &["docs/*".to_string()])?;

    // 4. Spawn an RAII background HTTP Range / WebDAV lazy VFS server over the same GatewayBus
    let vfs = VirtualVaultFs::with_bus(bus, Path::new("/tmp/pv-vfs-cache"), 64 * 1024 * 1024)?
        .with_default_macaroon(Some(read_token));
    let mut webdav = vfs.spawn_webdav_server("127.0.0.1:0")?;
    println!("WebDAV listening on http://{}", webdav.local_addr());
    webdav.shutdown();
    Ok(())
}
```

---

## 5. Key Public Modules (`src/lib.rs`)

| Module | Purpose |
| :--- | :--- |
| `parvault::crypto` | `MasterKey`, BIP-39 deterministic derivation, HKDF subkey isolation, `NodeIdentity` (`Ed25519`), and `crypto::pqc` hybrid post-quantum `X-Wing` (`X25519 + ML-KEM-768`), `Ed25519 + ML-DSA-65`, and cascaded `AES-256-GCM + ChaCha20-Poly1305` sealing. |
| `parvault::sharding` | Streaming `GF(2^8)` Reed-Solomon encoder/reconstructor (`4-of-6`, `16-of-20`, `20-of-40`) with pre-decoding SHA-256 Merkle shard quarantine. |
| `parvault::storage` | Crash-safe `BlockStore` (`fsync` + atomic `rename`), `QuotaManager`, `.bshard` blinded shard leases (`BlindedLeaseSpec`), and `storage::eviction` 4-vector keyed-HMAC privacy-preserving quorum takedowns (`ADR-19`). |
| `parvault::gateway` | Canonical `GatewayEngine` (`40`-lane `128 KiB`-stack single-wave TTFB pool, `PinnedRingBudget<SLOTS>`), unified `GatewayBus` (`InProcess` & `UnixSocket`, async + blocking `*_sync` surface), `GatewayIpcServer` / `GatewayIpcClient` (`SCM_RIGHTS` + sealed `memfd` + `SO_PEERCRED`), and `EphemeralShardManifest` (`RetentionPolicy`). |
| `parvault::capabilities` | Stateless `HMAC-SHA256` `CapabilityMacaroon` (`PARVAULT-MAC-V1:`) minting, caveat attenuation (`AllowedManifest`, `ByteRange`, `ExpiresAtUnixMs`, `ReadOnly`, `AllowedPeerUid`), and `< 1 ms` zero-DB RAM verification. |
| `parvault::vfs` | Dual-mode `VirtualVaultFs` (`with_bus` / `with_bus_and_block_size`, RAII `VfsWebdavServerHandle` via `spawn_webdav_server`, `.parvaultignore`-aware `ingest_local_directory`), `VfsStubNode`, `LruBlockCache`, and pure-Rust Linux FUSE `ABI 7.31` parsers (`parse_fuse_in_header`, `parse_fuse_read_in`) with zero C `libfuse` dependency and zero `unsafe` blocks. |
| `parvault::os_sys` | Audited Unix/Linux kernel boundary (`pread_full_or_eof`, `pwrite_all`, `create_memfd`, `seal_memfd_immutable`, `has_immutable_memfd_seals`, `peer_socket_ucred`, `dup_fd_cloexec`, `sendmsg_scm_rights`, `recvmsg_scm_rights`, `adopt_fuse_dev_fd`, `process_cpu_time_ns`, `bind_reusable_udp_v4`). |
| `parvault::sync` | Key-bearing `FolderSyncEngine`, zero-key `GatewayFolderSync` & `GatewayFolderCatalog` (`ADR-33`), `sanitize_sync_relative_path` (`sanitize_sync_relative_path_into`), `.parvaultignore` filtering (`ParvaultIgnore`), byte-range hydration, and encrypted catalog export/recovery. |
| `parvault::network` | `libp2p` `Noise_XX + Yamux` Kademlia/RPC swarm, signed LAN UDP beacons (`UDP 4009`), 4-word BIP-39 SAS pairing, and STUN-over-Noise WAN rendezvous (`WanPeerCard`). |
| `parvault::admin_rpc` | Forward-secret `X25519 + ChaCha20-Poly1305` + `Ed25519` challenge-authenticated wire protocol for zero-private-key-on-VPS seed administration. |
| `parvault::telemetry` | Opt-in privacy-preserving `AnonymousTelemetryBeacon` (`ADR-15` coarse region, power-of-two GiB bucketing, epoch nullifiers, and Hashcash PoW). |
