# Embedding `parvault` as a Rust Library

`parvault` is architected as a dual-purpose crate: every subsystem powering the `parvault` and `parvault-seed` binaries is exposed through a clean, memory-bounded Rust library API (`src/lib.rs`) suitable for embedding inside backup agents, NAS appliances, ISP gateway daemons, and custom control planes.

---

## 1. Adding `parvault` to `Cargo.toml`

```toml
[dependencies]
parvault = { git = "https://github.com/Zbot21/parvault.git", tag = "v0.3.0" }
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

When embedding `parvault` inside constrained Linux containers, residential routers (`OpenWrt` / `prplOS`), or embedded ARM64 SBCs, select the `RouterSoc` hardware profile (`1 MiB` streaming stripes instead of `16 MiB` desktop stripes) to keep transient heap and `VmHWM` below `16 MiB`:

```rust
use parvault::config::{HardwareProfile, SOC_ROUTER_STRIPE_SIZE_BYTES, STREAMING_STRIPE_SIZE_BYTES};

let profile = HardwareProfile::RouterSoc;
assert_eq!(profile.stripe_size_bytes(), SOC_ROUTER_STRIPE_SIZE_BYTES); // 1 MiB (1,048,576 bytes)
assert_eq!(HardwareProfile::Desktop.stripe_size_bytes(), STREAMING_STRIPE_SIZE_BYTES); // 16 MiB
```

---

## 4. Key Public Modules

| Module | Purpose |
| :--- | :--- |
| `parvault::crypto` | `MasterKey`, BIP-39 deterministic derivation, HKDF subkey isolation, and `NodeIdentity` (`Ed25519`). |
| `parvault::pq_crypto` | Post-quantum hybrid `HybridKemKeypair` (`X25519 + ML-KEM-768`), `HybridPqSigningKeypair` (`Ed25519 + ML-DSA-65`), and `PqVaultMasterKey` (`AES-256-GCM` + `ChaCha20-Poly1305` cascaded AEAD). |
| `parvault::erasure` | Streaming `GF(2^8)` Reed-Solomon encoder/reconstructor with pre-decoding Merkle shard quarantine. |
| `parvault::storage` | Crash-safe `BlockStore` (`fsync` + atomic `rename`), `QuotaManager`, and `.bshard` blinded shard persistence. |
| `parvault::sync` | `FolderSyncEngine` incremental directory delta scanner, `.parvaultignore` filtering, and encrypted catalog export/recovery. |
| `parvault::discovery` | Signed LAN UDP beacons (`UDP 4009`), 4-word BIP-39 SAS pairing, and STUN-over-Noise WAN rendezvous. |
| `parvault::eviction` | 4-vector keyed-HMAC privacy-preserving eviction (`eviction_index.bin`), `M-of-N` quorum verification, and multi-pass `0x00` shard wiping (`ADR-19`). |
| `parvault::admin_rpc` | Forward-secret `X25519 + ChaCha20-Poly1305` + `Ed25519` challenge-authenticated wire protocol for zero-private-key-on-VPS seed administration. |
