# Embedding `parvault` as a Rust Library (`v0.5.0`)

`parvault` is architected as a dual-purpose crate: every subsystem powering the `parvault`, `parvault-seed`, and `parvault-fuse` binaries is exposed through a clean, memory-bounded Rust library API (`src/lib.rs`, `#![deny(unsafe_code)]`) suitable for embedding inside backup agents, NAS appliances, ISP gateway daemons, and zero-key quorum control planes.

---

## 1. Adding `parvault` to `Cargo.toml`

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

## 4. Zero-Copy Shared-Memory IPC & `GatewayBus` (`parvault::gateway`)

Multi-tenant services and language-agnostic frontends can embed `GatewayBus::InProcess` directly (`--no-socket`) or speak to `parvault up --ipc-socket /var/run/parvault.sock` via `GatewayBus::UnixSocket` (`SCM_RIGHTS` + sealed Linux `memfd_create` + `SO_PEERCRED` UID binding) with attenuated `CapabilityMacaroon` (`PARVAULT-MAC-V1:`) tokens (see [`GATEWAY_SOCKET_PROTOCOL.md`](GATEWAY_SOCKET_PROTOCOL.md)):

```rust
use parvault::{
    capabilities::{CapabilityMacaroon, Caveat},
    gateway::{
        create_memfd_sized, GatewayIpcClient, RetentionPolicy, DEFAULT_IPC_SOCKET_PATH,
    },
    os_sys::pread_full_or_eof,
};
use std::{fs::File, os::fd::AsRawFd};

async fn gateway_roundtrip(root_key: &[u8; 32], payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let client = GatewayIpcClient::new(DEFAULT_IPC_SOCKET_PATH);
    let manifest = client
        .store_bytes(payload, RetentionPolicy::Persistent)
        .await?;

    let root_token = CapabilityMacaroon::mint(
        root_key,
        [0x11; 32],
        [0x22; 32],
        vec![Caveat::AllowedManifest(manifest.file_merkle_root)],
    )?;
    let read_token = root_token.attenuate(Caveat::ReadOnly)?;

    let out_fd = create_memfd_sized("parvault-fetch", payload.len() as u64)?;
    let out_file = File::from(out_fd);
    client
        .fetch_range_to_fd(
            manifest,
            0,
            payload.len() as u64,
            out_file.as_raw_fd(),
            Some(read_token),
        )
        .await?;

    let mut hydrated = vec![0u8; payload.len()];
    let n = pread_full_or_eof(&out_file, 0, &mut hydrated)?;
    hydrated.truncate(n);
    Ok(hydrated)
}
```

---

## 5. Key Public Modules (`src/lib.rs`)

| Module | Purpose |
| :--- | :--- |
| `parvault::crypto` | `MasterKey`, BIP-39 deterministic derivation, HKDF subkey isolation, `NodeIdentity` (`Ed25519`), and `crypto::pqc` hybrid post-quantum `X-Wing` (`X25519 + ML-KEM-768`), `Ed25519 + ML-DSA-65`, and cascaded `AES-256-GCM + ChaCha20-Poly1305` sealing. |
| `parvault::sharding` | Streaming `GF(2^8)` Reed-Solomon encoder/reconstructor (`4-of-6`, `16-of-20`, `20-of-40`) with pre-decoding BLAKE3 Merkle shard quarantine. |
| `parvault::storage` | Crash-safe `BlockStore` (`fsync` + atomic `rename`), `QuotaManager`, `.bshard` blinded shard leases (`BlindedLeaseSpec`), and `storage::eviction` 4-vector keyed-HMAC privacy-preserving quorum takedowns (`ADR-19`). |
| `parvault::gateway` | Canonical `GatewayEngine` (`40`-lane `128 KiB`-stack single-wave TTFB pool, `PinnedRingBudget<SLOTS>`), unified `GatewayBus` (`InProcess` & `UnixSocket`), `GatewayIpcServer` / `GatewayIpcClient` (`SCM_RIGHTS` + sealed `memfd` + `SO_PEERCRED`), and `EphemeralShardManifest` (`RetentionPolicy`). |
| `parvault::capabilities` | Stateless `HMAC-SHA256` `CapabilityMacaroon` (`PARVAULT-MAC-V1:`) minting, caveat attenuation (`AllowedManifest`, `ByteRange`, `ExpiresAtUnixMs`, `ReadOnly`, `AllowedPeerUid`), and `< 1 ms` zero-DB RAM verification. |
| `parvault::vfs` | Pure-Rust Linux FUSE `ABI 7.31` VFS inode table (`VirtualVaultFs`, `VfsStubNode`, `parse_fuse_in_header`, `parse_fuse_read_in`) with zero C `libfuse` dependency and zero `unsafe` blocks. |
| `parvault::os_sys` | Audited Unix/Linux kernel boundary (`pread_full_or_eof`, `pwrite_all`, `create_memfd`, `seal_memfd_immutable`, `has_immutable_memfd_seals`, `peer_socket_ucred`, `dup_fd_cloexec`, `sendmsg_scm_rights`, `recvmsg_scm_rights`, `adopt_fuse_dev_fd`, `process_cpu_time_ns`, `bind_reusable_udp_v4`). |
| `parvault::sync` | `FolderSyncEngine` incremental directory delta scanner, `.parvaultignore` filtering, byte-range hydration, and encrypted catalog export/recovery. |
| `parvault::network` | `libp2p` `Noise_XX + Yamux` Kademlia/RPC swarm, signed LAN UDP beacons (`UDP 4009`), 4-word BIP-39 SAS pairing, and STUN-over-Noise WAN rendezvous (`WanPeerCard`). |
| `parvault::admin_rpc` | Forward-secret `X25519 + ChaCha20-Poly1305` + `Ed25519` challenge-authenticated wire protocol for zero-private-key-on-VPS seed administration. |
| `parvault::telemetry` | Opt-in privacy-preserving `AnonymousTelemetryBeacon` (`ADR-15` coarse region, power-of-two GiB bucketing, epoch nullifiers, and Hashcash PoW). |
