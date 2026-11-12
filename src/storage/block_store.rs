use crate::bootstrap::{BlindedShardLeaseManager, BlindedShardTombstone};
use crate::config::ErasureTier;
use crate::crypto::aes::{
    compute_sha256, decrypt_manifest, decrypt_stripe, derive_dht_manifest_key, encrypt_manifest,
    encrypt_stripe, generate_file_salt, SALT_LEN,
};
use crate::crypto::keys::{MasterKey, NodeIdentity};
use crate::sharding::merkle::{compute_file_merkle_root, hash_shard_leaf, Hash32};
use crate::sharding::reed_solomon::{encode_ciphertext_stripe, reconstruct_ciphertext_stripe};
use crate::storage::anonymity::{
    AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, VoucherNullifierLedger,
};
use crate::storage::quota::QuotaManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::aes::CryptoError),
    #[error("Sharding error: {0}")]
    Sharding(#[from] crate::sharding::reed_solomon::ShardingError),
    #[error("Shard not found: {0}")]
    ShardNotFound(String),
    #[error("Invalid byte range (offset={offset}, length={length}, size={size})")]
    InvalidRange { offset: u64, length: u64, size: u64 },
    #[error("Storage quota or reciprocity limit exceeded for peer {0}")]
    QuotaExceeded(String),
    #[error("Shard integrity hash mismatch")]
    CorruptedShard,
    #[error("Rejected DHT manifest update: invalid owner Ed25519 signature or version rollback")]
    DhtManifestPoisonedOrRollback,
    #[error("Rejected unsafe or path-traversal restore path: {0}")]
    InvalidRestorePath(String),
}

/// Summary report returned by `BlockStore::scrub_all_shards` (`ADR-15` background bit-rot scrubber).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubReport {
    pub verified_healthy_shards: usize,
    pub verified_healthy_blinded_shards: usize,
    pub quarantined_corrupted_shards: Vec<String>,
    pub quarantined_corrupted_blinded_locators: Vec<[u8; 32]>,
}

/// Cryptographically signed receipt issued by `BlockStore::graceful_leave_and_redistribute`
/// (`parvault leave` & `parvault-seed leave`), proving that the node cleanly verified and evacuated
/// 100% of its hosted `.shard` and `.bshard` files (`1.0x` direct transfer instead of `16.0x`
/// Reed-Solomon lazy repair) and freezing its Earned Uptime Standing without PoR slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GracefulDepartureReceipt {
    pub departing_peer_id: String,
    pub departing_pubkey: [u8; 32],
    pub migrated_shards_count: usize,
    pub migrated_blinded_shards_count: usize,
    pub total_bytes_handed_off: u64,
    pub handoff_manifest_sha256: [u8; 32],
    pub earned_standing_preserved: bool,
    pub departure_timestamp_ms: u64,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl GracefulDepartureReceipt {
    pub fn issue(
        identity: &NodeIdentity,
        migrated_shards_count: usize,
        migrated_blinded_shards_count: usize,
        total_bytes_handed_off: u64,
        handoff_manifest_sha256: [u8; 32],
        departure_timestamp_ms: u64,
    ) -> Self {
        let departing_peer_id = identity.device_peer_id();
        let departing_pubkey = identity.public_key_bytes();
        let mut receipt = Self {
            departing_peer_id,
            departing_pubkey,
            migrated_shards_count,
            migrated_blinded_shards_count,
            total_bytes_handed_off,
            handoff_manifest_sha256,
            earned_standing_preserved: true,
            departure_timestamp_ms,
            sig_r: [0u8; 32],
            sig_s: [0u8; 32],
        };
        let msg = receipt.canonical_bytes();
        let sig = identity.sign(&msg);
        receipt.sig_r.copy_from_slice(&sig[..32]);
        receipt.sig_s.copy_from_slice(&sig[32..]);
        receipt
    }

    pub fn verify_signature(&self) -> bool {
        let msg = self.canonical_bytes();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.departing_pubkey, &msg, &sig)
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(b"parvault-graceful-departure-v1:");
        buf.extend_from_slice(self.departing_peer_id.as_bytes());
        buf.extend_from_slice(&self.departing_pubkey);
        buf.extend_from_slice(&(self.migrated_shards_count as u64).to_be_bytes());
        buf.extend_from_slice(&(self.migrated_blinded_shards_count as u64).to_be_bytes());
        buf.extend_from_slice(&self.total_bytes_handed_off.to_be_bytes());
        buf.extend_from_slice(&self.handoff_manifest_sha256);
        buf.push(u8::from(self.earned_standing_preserved));
        buf.extend_from_slice(&self.departure_timestamp_ms.to_be_bytes());
        buf
    }
}

/// Byte-Epoch lease and deletion-verifier parameters attached to an anonymized `.bshard` upload
/// (`ADR-11` + `ADR-13`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindedLeaseSpec {
    pub current_epoch: u64,
    pub lease_duration_epochs: u64,
    pub delete_verifier: [u8; 32],
}

impl BlindedLeaseSpec {
    #[inline]
    pub const fn new(
        current_epoch: u64,
        lease_duration_epochs: u64,
        delete_verifier: [u8; 32],
    ) -> Self {
        Self {
            current_epoch,
            lease_duration_epochs,
            delete_verifier,
        }
    }
}

///Unique content-addressed identifier for an individual Reed-Solomon shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShardId {
    pub stripe_merkle_root: Hash32,
    pub shard_index: u32,
    pub shard_hash: Hash32,
}

impl ShardId {
    pub fn file_key(&self) -> String {
        format!(
            "{}_{:02}_{}",
            hex::encode(&self.stripe_merkle_root[..8]),
            self.shard_index,
            hex::encode(&self.shard_hash[..16])
        )
    }
}

/// Metadata for a single 16 MiB encrypted & erasure-coded stripe inside a `FileManifest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StripeManifestEntry {
    pub stripe_index: u64,
    pub k_data: usize,
    pub m_parity: usize,
    pub original_ciphertext_len: usize,
    pub shard_len: usize,
    pub stripe_merkle_root: Hash32,
    pub shard_hashes: Vec<Hash32>,
    /// Target PeerIDs assigned by the 70/30 network topology placement engine (index-aligned with `shard_hashes`).
    pub assigned_peers: Vec<String>,
}

/// Complete File Manifest required to verify, audit, and reconstruct an encrypted vault file (ADR-02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileManifest {
    pub version: u32,
    pub file_merkle_root: Hash32,
    pub file_salt: [u8; SALT_LEN],
    pub original_file_size: u64,
    pub stripe_size_bytes: usize,
    pub tier: ErasureTier,
    pub stripes: Vec<StripeManifestEntry>,
    /// Designated witness peer IDs authorized to co-sign `ProofOfDegradation` during offline repair (ADR-03/04).
    pub witness_peers: Vec<String>,
}

impl FileManifest {
    /// Serializes and encrypts this manifest under `master_key` for publication to the Kademlia DHT (ADR-02).
    pub fn to_encrypted_dht_record(
        &self,
        master_key: &MasterKey,
    ) -> Result<([u8; 32], Vec<u8>), StorageError> {
        let raw = bincode::serialize(self)?;
        let encrypted = encrypt_manifest(master_key, &raw)?;
        let root_hex = hex::encode(self.file_merkle_root);
        let dht_key = derive_dht_manifest_key(master_key, &root_hex);
        Ok((dht_key, encrypted))
    }

    /// Decrypts and deserializes a `FileManifest` fetched from the Kademlia DHT using only `master_key` (ADR-02).
    pub fn from_encrypted_dht_record(
        master_key: &MasterKey,
        encrypted_record: &[u8],
    ) -> Result<Self, StorageError> {
        let raw = decrypt_manifest(master_key, encrypted_record)?;
        let manifest: Self = bincode::deserialize(&raw)?;
        Ok(manifest)
    }
}

pub const SOC_ROUTER_STRIPE_SIZE_BYTES: usize = 1024 * 1024; // 1 MiB for <=48 MiB cgroup tiny-SoC
pub const NAS_BALANCED_STRIPE_SIZE_BYTES: usize = 4 * 1024 * 1024; // 4 MiB for mid-range NAS
pub const DEFAULT_STRIPE_SIZE_BYTES: usize = crate::config::DEFAULT_STRIPE_SIZE_BYTES; // 16 MiB per ADR-01

#[derive(Default)]
struct InMemoryShardBacking {
    regular_shards: HashMap<String, Vec<u8>>,
    blinded_shards: HashMap<String, Vec<u8>>,
    manifests: HashMap<Hash32, Vec<u8>>,
}

impl InMemoryShardBacking {
    fn zero_wipe_vec(mut buf: Vec<u8>) -> u64 {
        let len = buf.len() as u64;
        zeroize::Zeroize::zeroize(&mut buf);
        len
    }

    fn total_bytes(&self) -> u64 {
        let reg: u64 = self.regular_shards.values().map(|v| v.len() as u64).sum();
        let bln: u64 = self.blinded_shards.values().map(|v| v.len() as u64).sum();
        let man: u64 = self.manifests.values().map(|v| v.len() as u64).sum();
        reg.saturating_add(bln).saturating_add(man)
    }
}

impl Drop for InMemoryShardBacking {
    fn drop(&mut self) {
        for (_, mut buf) in self.regular_shards.drain() {
            zeroize::Zeroize::zeroize(&mut buf);
        }
        for (_, mut buf) in self.blinded_shards.drain() {
            zeroize::Zeroize::zeroize(&mut buf);
        }
        for (_, mut buf) in self.manifests.drain() {
            zeroize::Zeroize::zeroize(&mut buf);
        }
    }
}

/// Local NVMe / USB / bounded-RAM sharded block storage engine (`storage::block_store`).
#[derive(Clone)]
pub struct BlockStore {
    root_dir: PathBuf,
    shards_dir: PathBuf,
    manifests_dir: PathBuf,
    in_memory: Option<Arc<Mutex<InMemoryShardBacking>>>,
    quota: Arc<Mutex<QuotaManager>>,
    blinded_leases: Arc<Mutex<BlindedShardLeaseManager>>,
    blinded_id_by_locator: Arc<Mutex<HashMap<[u8; 32], BlindedShardId>>>,
    shard_id_by_file_key: Arc<Mutex<HashMap<String, ShardId>>>,
    dht_store: Arc<Mutex<ZeroTrustDhtStore>>,
    mesh_client: Option<crate::network::MeshClient>,
    stripe_size_bytes: usize,
}

impl BlockStore {
    pub const SOC_ROUTER_STRIPE_SIZE_BYTES: usize = SOC_ROUTER_STRIPE_SIZE_BYTES;
    pub const NAS_BALANCED_STRIPE_SIZE_BYTES: usize = NAS_BALANCED_STRIPE_SIZE_BYTES;
    pub const DEFAULT_STRIPE_SIZE_BYTES: usize = DEFAULT_STRIPE_SIZE_BYTES;

    pub fn new(root_dir: impl AsRef<Path>, mut quota: QuotaManager) -> Result<Self, StorageError> {
        let root_dir = root_dir.as_ref().to_path_buf();
        let shards_dir = root_dir.join("shards");
        let manifests_dir = root_dir.join("manifests");
        fs::create_dir_all(&shards_dir)?;
        fs::create_dir_all(&manifests_dir)?;
        quota.bind_persistence_dir(&root_dir);
        if quota.used_storage_bytes() == 0 {
            if let Ok(entries) = fs::read_dir(&shards_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if let Some(fname) = p.file_name().and_then(|n| n.to_str()) {
                        if let Some(stem) = fname.strip_suffix(".shard") {
                            if let Ok(meta) = p.metadata() {
                                quota.record_shard_stored("local", stem.to_string(), meta.len());
                            }
                        }
                    }
                }
            }
        }
        let max_bytes = quota.max_storage_bytes();
        let leases_file = root_dir.join("blinded_leases.bin");
        let (initial_leases, initial_id_map) = if leases_file.exists() {
            fs::read(&leases_file)
                .ok()
                .and_then(|raw| {
                    bincode::deserialize::<(
                        BlindedShardLeaseManager,
                        HashMap<[u8; 32], BlindedShardId>,
                    )>(&raw)
                    .ok()
                })
                .unwrap_or_else(|| (BlindedShardLeaseManager::new(max_bytes, 2), HashMap::new()))
        } else {
            (BlindedShardLeaseManager::new(max_bytes, 2), HashMap::new())
        };

        let shard_index_file = root_dir.join("shard_index.bin");
        let initial_shard_index = if shard_index_file.exists() {
            fs::read(&shard_index_file)
                .ok()
                .and_then(|raw| bincode::deserialize::<HashMap<String, ShardId>>(&raw).ok())
                .unwrap_or_default()
        } else {
            HashMap::new()
        };

        let dht_store = ZeroTrustDhtStore::with_persistence_dir(&root_dir);

        Ok(Self {
            root_dir,
            shards_dir,
            manifests_dir,
            in_memory: None,
            quota: Arc::new(Mutex::new(quota)),
            blinded_leases: Arc::new(Mutex::new(initial_leases)),
            blinded_id_by_locator: Arc::new(Mutex::new(initial_id_map)),
            shard_id_by_file_key: Arc::new(Mutex::new(initial_shard_index)),
            dht_store: Arc::new(Mutex::new(dht_store)),
            mesh_client: None,
            stripe_size_bytes: DEFAULT_STRIPE_SIZE_BYTES,
        })
    }

    /// Initializes a strictly zero-filesystem bounded-RAM `BlockStore` (`parvault-seed --no-fs` /
    /// `--in-memory-mb`). Creates **zero** directories or files on disk, enforces `quota`'s hard
    /// byte ceiling across regular and blinded shards, and `0x00`-wipes (`Zeroize`) every evicted
    /// or deleted buffer in RAM.
    pub fn new_in_memory(mut quota: QuotaManager) -> Self {
        quota.set_min_free_disk_bytes(0);
        let max_bytes = quota.max_storage_bytes();
        Self {
            root_dir: PathBuf::new(),
            shards_dir: PathBuf::new(),
            manifests_dir: PathBuf::new(),
            in_memory: Some(Arc::new(Mutex::new(InMemoryShardBacking::default()))),
            quota: Arc::new(Mutex::new(quota)),
            blinded_leases: Arc::new(Mutex::new(BlindedShardLeaseManager::new(max_bytes, 2))),
            blinded_id_by_locator: Arc::new(Mutex::new(HashMap::new())),
            shard_id_by_file_key: Arc::new(Mutex::new(HashMap::new())),
            dht_store: Arc::new(Mutex::new(ZeroTrustDhtStore::new())),
            mesh_client: None,
            stripe_size_bytes: SOC_ROUTER_STRIPE_SIZE_BYTES,
        }
    }

    /// Returns `true` when operating in zero-filesystem bounded RAM mode (`--no-fs` / `--in-memory-mb`).
    pub fn is_in_memory(&self) -> bool {
        self.in_memory.is_some()
    }

    /// Returns exact total bytes currently held in `InMemoryShardBacking` (`0` when disk-backed).
    pub fn in_memory_used_bytes(&self) -> u64 {
        self.in_memory
            .as_ref()
            .and_then(|m| m.lock().ok().map(|g| g.total_bytes()))
            .unwrap_or(0)
    }

    /// Returns the stored byte length of a regular shard (in RAM or on disk), if present.
    pub fn regular_shard_len(&self, id: &ShardId) -> Option<u64> {
        if let Some(ref mem) = self.in_memory {
            return mem
                .lock()
                .ok()
                .and_then(|g| g.regular_shards.get(&id.file_key()).map(|v| v.len() as u64));
        }
        fs::metadata(self.shard_path(id)).ok().map(|m| m.len())
    }

    /// Returns the stored byte length of a blinded shard locator (in RAM or on disk), if present.
    pub fn blinded_locator_len(&self, loc: &[u8; 32]) -> Option<u64> {
        let fkey = self
            .blinded_id_by_locator
            .lock()
            .ok()
            .and_then(|m| m.get(loc).map(|b| b.file_key()));
        if let Some(ref mem) = self.in_memory {
            let key = fkey?;
            return mem
                .lock()
                .ok()
                .and_then(|g| g.blinded_shards.get(&key).map(|v| v.len() as u64));
        }
        if let Some(key) = fkey {
            let p = self.shards_dir.join(format!("{key}.bshard"));
            if let Ok(meta) = fs::metadata(p) {
                return Some(meta.len());
            }
        }
        None
    }

    /// Zero-wipes (`0x00` `zeroize()`) an in-memory regular shard and updates quota + index tables.
    pub fn zero_wipe_regular_shard(
        &self,
        owner_peer_id: &str,
        id: &ShardId,
    ) -> Result<u64, StorageError> {
        if let Some(ref mem) = self.in_memory {
            let removed = mem
                .lock()
                .expect("in_memory mutex poisoned")
                .regular_shards
                .remove(&id.file_key());
            if let Ok(mut idx_map) = self.shard_id_by_file_key.lock() {
                idx_map.remove(&id.file_key());
            }
            if let Some(buf) = removed {
                let wiped = InMemoryShardBacking::zero_wipe_vec(buf);
                if let Ok(mut q) = self.quota.lock() {
                    q.record_shard_removed(owner_peer_id, &id.file_key(), wiped);
                }
                return Ok(wiped);
            }
            return Ok(0);
        }
        let path = self.shard_path(id);
        let wiped =
            crate::storage::eviction::PrivacyPreservingEvictionEngine::shred_and_unlink_file(
                &path,
            )?;
        if wiped > 0 {
            if let Ok(mut idx_map) = self.shard_id_by_file_key.lock() {
                idx_map.remove(&id.file_key());
            }
            if let Ok(mut q) = self.quota.lock() {
                q.record_shard_removed(owner_peer_id, &id.file_key(), wiped);
            }
        }
        Ok(wiped)
    }

    /// Zero-wipes (`0x00` `zeroize()`) an in-memory blinded shard locator and removes its lease.
    pub fn zero_wipe_blinded_locator(&self, loc: &[u8; 32]) -> Result<u64, StorageError> {
        let removed_bid = self
            .blinded_id_by_locator
            .lock()
            .ok()
            .and_then(|mut m| m.remove(loc));
        if let Some(ref mem) = self.in_memory {
            if let Ok(mut mgr) = self.blinded_leases.lock() {
                let _ = mgr.force_remove_locator(loc);
            }
            if let Some(bid) = removed_bid {
                let removed = mem
                    .lock()
                    .expect("in_memory mutex poisoned")
                    .blinded_shards
                    .remove(&bid.file_key());
                if let Some(buf) = removed {
                    return Ok(InMemoryShardBacking::zero_wipe_vec(buf));
                }
            }
            return Ok(0);
        }
        if let Some(bid) = removed_bid {
            let p = self.shards_dir.join(format!("{}.bshard", bid.file_key()));
            return Ok(
                crate::storage::eviction::PrivacyPreservingEvictionEngine::shred_and_unlink_file(
                    &p,
                )?,
            );
        }
        Ok(0)
    }

    pub fn with_stripe_size_bytes(mut self, stripe_size_bytes: usize) -> Self {
        self.set_stripe_size_bytes(stripe_size_bytes);
        self
    }

    pub fn set_stripe_size_bytes(&mut self, stripe_size_bytes: usize) {
        self.stripe_size_bytes =
            stripe_size_bytes.clamp(64 * 1024, Self::DEFAULT_STRIPE_SIZE_BYTES);
    }

    pub fn stripe_size_bytes(&self) -> usize {
        self.stripe_size_bytes
    }

    pub fn with_mesh_client(mut self, client: crate::network::MeshClient) -> Self {
        self.mesh_client = Some(client);
        self
    }

    pub fn set_mesh_client(&mut self, client: Option<crate::network::MeshClient>) {
        self.mesh_client = client;
    }

    pub fn mesh_client(&self) -> Option<&crate::network::MeshClient> {
        self.mesh_client.as_ref()
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn shards_dir(&self) -> &Path {
        &self.shards_dir
    }

    pub fn manifests_dir(&self) -> &Path {
        &self.manifests_dir
    }

    fn persist_shard_index(&self) {
        if self.is_in_memory() {
            return;
        }
        if let Ok(idx_map) = self.shard_id_by_file_key.lock() {
            if let Ok(raw) = bincode::serialize(&*idx_map) {
                let _ = Self::atomic_write_file(&self.root_dir.join("shard_index.bin"), &raw);
            }
        }
    }

    /// Returns all active unblinded `(ShardId, Vec<u8>)` entries stored on disk.
    pub fn list_stored_shards(&self) -> Result<Vec<(ShardId, Vec<u8>)>, StorageError> {
        let snapshot: Vec<(String, ShardId)> = {
            let map = self
                .shard_id_by_file_key
                .lock()
                .expect("shard_id_by_file_key mutex poisoned");
            map.iter().map(|(k, v)| (k.clone(), *v)).collect()
        };
        let mut out = Vec::new();
        for (_key, shard_id) in snapshot {
            if let Ok(bytes) = self.get_shard(&shard_id) {
                out.push((shard_id, bytes));
            }
        }
        Ok(out)
    }

    pub fn put_dht_manifest_envelope(
        &self,
        envelope: SignedDhtManifestEnvelope,
    ) -> Result<(), StorageError> {
        self.dht_store
            .lock()
            .expect("dht_store mutex poisoned")
            .put_manifest_envelope(envelope)
    }

    pub fn get_dht_manifest_envelope(
        &self,
        dht_key: &[u8; 32],
    ) -> Option<SignedDhtManifestEnvelope> {
        self.dht_store
            .lock()
            .expect("dht_store mutex poisoned")
            .get_manifest_envelope(dht_key)
            .cloned()
    }

    pub fn put_dht_pq_manifest_envelope(
        &self,
        envelope: crate::crypto::PqSignedDhtManifestEnvelope,
    ) -> Result<(), StorageError> {
        self.dht_store
            .lock()
            .expect("dht_store mutex poisoned")
            .put_pq_manifest_envelope(envelope)
    }

    pub fn get_dht_pq_manifest_envelope(
        &self,
        dht_key: &[u8; 32],
    ) -> Option<crate::crypto::PqSignedDhtManifestEnvelope> {
        self.dht_store
            .lock()
            .expect("dht_store mutex poisoned")
            .get_pq_manifest_envelope(dht_key)
            .cloned()
    }

    pub fn put_dht_vault_catalog_envelope(
        &self,
        envelope: crate::sync::EncryptedVaultCatalogEnvelope,
    ) -> Result<(), StorageError> {
        self.dht_store
            .lock()
            .expect("dht_store mutex poisoned")
            .put_vault_catalog_envelope(envelope)
    }

    pub fn get_dht_vault_catalog_envelope(
        &self,
        dht_key: &[u8; 32],
    ) -> Option<crate::sync::EncryptedVaultCatalogEnvelope> {
        self.dht_store
            .lock()
            .expect("dht_store mutex poisoned")
            .get_vault_catalog_envelope(dht_key)
            .cloned()
    }

    /// Crash-safe atomic file persistence (`ADR-15`):
    /// Writes `bytes` to a sibling `.tmp.<nonce>` staging file in the same directory,
    /// flushes kernel buffers to physical storage via `File::sync_all()`, and atomically
    /// renames (`fs::rename`) over `target_path` so power loss mid-write can never truncate
    /// or corrupt `.shard`, `.bshard`, `.manifest.bin`, or `blinded_leases.bin`.
    pub fn atomic_write_file(target_path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
        let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
        let mut rnd = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
        let file_name = target_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("parvault_blob");
        let tmp_path = parent.join(format!(".{file_name}.tmp.{}", hex::encode(rnd)));
        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        if let Err(e) = fs::rename(&tmp_path, target_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(StorageError::Io(e));
        }
        Ok(())
    }

    fn persist_blinded_lease_state(&self) {
        if self.is_in_memory() {
            return;
        }
        if let (Ok(mgr), Ok(id_map)) = (
            self.blinded_leases.lock(),
            self.blinded_id_by_locator.lock(),
        ) {
            if let Ok(raw) = bincode::serialize(&(&*mgr, &*id_map)) {
                let _ = Self::atomic_write_file(&self.root_dir.join("blinded_leases.bin"), &raw);
            }
        }
    }

    /// Configures the grace window (in epochs) before un-renewed blinded shards are physically
    /// deleted from disk by time-based sweeps or disk-pressure eviction.
    pub fn set_blinded_lease_policy(&self, max_capacity_bytes: u64, grace_epochs: u64) {
        if let Ok(mut mgr) = self.blinded_leases.lock() {
            mgr.set_policy(max_capacity_bytes, grace_epochs);
        }
        self.persist_blinded_lease_state();
    }

    /// Returns `(used_blinded_bytes, active_blinded_leases)` tracked by the blinded shard lease manager.
    pub fn blinded_lease_stats(&self) -> (u64, usize) {
        if let Ok(mgr) = self.blinded_leases.lock() {
            (mgr.used_bytes(), mgr.active_shard_count())
        } else {
            (0, 0)
        }
    }

    pub fn quota(&self) -> Arc<Mutex<QuotaManager>> {
        Arc::clone(&self.quota)
    }

    fn shard_path(&self, id: &ShardId) -> PathBuf {
        self.shards_dir.join(format!("{}.shard", id.file_key()))
    }

    fn manifest_path(&self, file_merkle_root: &Hash32) -> PathBuf {
        self.manifests_dir
            .join(format!("{}.manifest.bin", hex::encode(file_merkle_root)))
    }

    /// Persists a single verified shard to disk, updating quota accounting and LRU state.
    pub fn put_shard(
        &self,
        owner_peer_id: &str,
        id: &ShardId,
        bytes: &[u8],
    ) -> Result<PathBuf, StorageError> {
        let computed = hash_shard_leaf(id.shard_index, bytes);
        if computed != id.shard_hash {
            return Err(StorageError::CorruptedShard);
        }

        let shard_size = bytes.len() as u64;
        if let Some(ref mem) = self.in_memory {
            let max_cap = {
                let mut q = self.quota.lock().expect("quota mutex poisoned");
                if !q.can_accept_shard(owner_peer_id, shard_size) {
                    let evicted = q.evict_lru_to_fit(shard_size);
                    {
                        let mut m = mem.lock().expect("in_memory mutex poisoned");
                        let mut idx_map = self
                            .shard_id_by_file_key
                            .lock()
                            .expect("shard_id_by_file_key mutex poisoned");
                        for evicted_key in evicted {
                            idx_map.remove(&evicted_key);
                            if let Some(buf) = m.regular_shards.remove(&evicted_key) {
                                InMemoryShardBacking::zero_wipe_vec(buf);
                            }
                        }
                    }
                    if !q.can_accept_shard(owner_peer_id, shard_size) {
                        return Err(StorageError::QuotaExceeded(owner_peer_id.to_string()));
                    }
                }
                q.max_storage_bytes()
            };
            // Ensure combined regular + blinded RAM stays strictly <= max_cap.
            let cur_mem = self.in_memory_used_bytes();
            if cur_mem.saturating_add(shard_size) > max_cap {
                let needed_blinded_free =
                    cur_mem.saturating_add(shard_size).saturating_sub(max_cap);
                let evicted_locs = {
                    let mut mgr = self
                        .blinded_leases
                        .lock()
                        .expect("blinded_leases mutex poisoned");
                    let bl_free = mgr.max_capacity_bytes().saturating_sub(mgr.used_bytes());
                    mgr.evict_oldest_to_fit(bl_free.saturating_add(needed_blinded_free), 1)
                        .unwrap_or_default()
                };
                for loc in evicted_locs {
                    let _ = self.zero_wipe_blinded_locator(&loc);
                }
                if self.in_memory_used_bytes().saturating_add(shard_size) > max_cap {
                    return Err(StorageError::QuotaExceeded(owner_peer_id.to_string()));
                }
            }
            {
                let mut m = mem.lock().expect("in_memory mutex poisoned");
                if let Some(prev) = m.regular_shards.insert(id.file_key(), bytes.to_vec()) {
                    InMemoryShardBacking::zero_wipe_vec(prev);
                }
            }
            {
                let mut q = self.quota.lock().expect("quota mutex poisoned");
                q.record_shard_stored(owner_peer_id, id.file_key(), shard_size);
            }
            if let Ok(mut idx_map) = self.shard_id_by_file_key.lock() {
                idx_map.insert(id.file_key(), *id);
            }
            return Ok(PathBuf::from(format!("mem://{}.shard", id.file_key())));
        }

        {
            let mut q = self.quota.lock().expect("quota mutex poisoned");
            if !q.can_accept_shard(owner_peer_id, shard_size) {
                // Attempt LRU garbage collection of evictable cached shards first.
                let evicted = q.evict_lru_to_fit(shard_size);
                for evicted_key in evicted {
                    let p = self.shards_dir.join(format!("{evicted_key}.shard"));
                    let _ = fs::remove_file(p);
                }
                if !q.can_accept_shard(owner_peer_id, shard_size) {
                    return Err(StorageError::QuotaExceeded(owner_peer_id.to_string()));
                }
            }
        }

        let path = self.shard_path(id);
        Self::atomic_write_file(&path, bytes)?;

        {
            let mut q = self.quota.lock().expect("quota mutex poisoned");
            q.record_shard_stored(owner_peer_id, id.file_key(), shard_size);
        }
        if let Ok(mut idx_map) = self.shard_id_by_file_key.lock() {
            idx_map.insert(id.file_key(), *id);
        }
        self.persist_shard_index();

        Ok(path)
    }

    /// Reads an entire shard from disk (or RAM in `--no-fs` mode) and verifies its SHA-256 leaf digest.
    /// Note: For remote requests, callers MUST verify a valid `RepairGrant` or owner token first (ADR-04).
    pub fn get_shard(&self, id: &ShardId) -> Result<Vec<u8>, StorageError> {
        if let Some(ref mem) = self.in_memory {
            let bytes = mem
                .lock()
                .expect("in_memory mutex poisoned")
                .regular_shards
                .get(&id.file_key())
                .cloned()
                .ok_or_else(|| StorageError::ShardNotFound(id.file_key()))?;
            let computed = hash_shard_leaf(id.shard_index, &bytes);
            if computed != id.shard_hash {
                return Err(StorageError::CorruptedShard);
            }
            if let Ok(mut q) = self.quota.lock() {
                q.touch_shard(&id.file_key());
            }
            return Ok(bytes);
        }
        let path = self.shard_path(id);
        if !path.exists() {
            return Err(StorageError::ShardNotFound(id.file_key()));
        }
        let bytes = fs::read(&path)?;
        let computed = hash_shard_leaf(id.shard_index, &bytes);
        if computed != id.shard_hash {
            return Err(StorageError::CorruptedShard);
        }
        if let Ok(mut q) = self.quota.lock() {
            q.touch_shard(&id.file_key());
        }
        Ok(bytes)
    }

    /// Reads a bounded byte sub-range `[offset .. offset + length]` from a shard on disk or RAM.
    /// Used exclusively by `por::verifier` AFTER stateless RAM-only HMAC pre-verification passes (ADR-03).
    pub fn get_shard_range(
        &self,
        id: &ShardId,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StorageError> {
        if let Some(ref mem) = self.in_memory {
            let m = mem.lock().expect("in_memory mutex poisoned");
            let bytes = m
                .regular_shards
                .get(&id.file_key())
                .ok_or_else(|| StorageError::ShardNotFound(id.file_key()))?;
            let file_len = bytes.len() as u64;
            if length == 0 || offset.saturating_add(length) > file_len {
                return Err(StorageError::InvalidRange {
                    offset,
                    length,
                    size: file_len,
                });
            }
            let slice = bytes[offset as usize..(offset + length) as usize].to_vec();
            drop(m);
            if let Ok(mut q) = self.quota.lock() {
                q.touch_shard(&id.file_key());
            }
            return Ok(slice);
        }
        let path = self.shard_path(id);
        if !path.exists() {
            return Err(StorageError::ShardNotFound(id.file_key()));
        }
        let mut file = File::open(&path)?;
        let file_len = file.metadata()?.len();
        if length == 0 || offset.saturating_add(length) > file_len {
            return Err(StorageError::InvalidRange {
                offset,
                length,
                size: file_len,
            });
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; length as usize];
        file.read_exact(&mut buf)?;
        if let Ok(mut q) = self.quota.lock() {
            q.touch_shard(&id.file_key());
        }
        Ok(buf)
    }

    /// Deletes a shard from local disk or bounded RAM storage.
    pub fn delete_shard(&self, owner_peer_id: &str, id: &ShardId) -> Result<bool, StorageError> {
        if self.is_in_memory() {
            let wiped = self.zero_wipe_regular_shard(owner_peer_id, id)?;
            return Ok(wiped > 0);
        }
        let path = self.shard_path(id);
        if path.exists() {
            let len = fs::metadata(&path)?.len();
            fs::remove_file(&path)?;
            if let Ok(mut q) = self.quota.lock() {
                q.record_shard_removed(owner_peer_id, &id.file_key(), len);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn has_shard(&self, id: &ShardId) -> bool {
        if let Some(ref mem) = self.in_memory {
            return mem
                .lock()
                .map(|m| m.regular_shards.contains_key(&id.file_key()))
                .unwrap_or(false);
        }
        self.shard_path(id).exists()
    }

    /// Persists an anonymized shard addressed solely by `BlindedShardId` (with zero `stripe_merkle_root`,
    /// zero `shard_index`, and zero `owner_peer_id` metadata) after redeeming a single-use
    /// `AnonymousQuotaVoucher` (ADR-11). Registers a default Byte-Epoch lease in `blinded_leases`.
    pub fn put_blinded_shard(
        &self,
        blinded_id: &BlindedShardId,
        shard_bytes: &[u8],
        capability: BlindedShardCapability,
        voucher: &AnonymousQuotaVoucher,
        nullifier_ledger: &mut VoucherNullifierLedger,
    ) -> Result<PathBuf, StorageError> {
        self.put_blinded_shard_with_lease(
            blinded_id,
            shard_bytes,
            capability,
            voucher,
            nullifier_ledger,
            BlindedLeaseSpec::new(1, 30, [0u8; 32]),
        )
    }

    /// Persists an anonymized `BlindedShardId` to `{locator}.bshard` on disk with an explicit
    /// Byte-Epoch lease (`lease.current_epoch + lease.lease_duration_epochs`) and `delete_verifier` (`ADR-11` + `ADR-13`).
    /// If disk capacity is reached, automatically evicts and physically unlinks expired `.bshard` files on disk.
    pub fn put_blinded_shard_with_lease(
        &self,
        blinded_id: &BlindedShardId,
        shard_bytes: &[u8],
        capability: BlindedShardCapability,
        voucher: &AnonymousQuotaVoucher,
        nullifier_ledger: &mut VoucherNullifierLedger,
        lease: BlindedLeaseSpec,
    ) -> Result<PathBuf, StorageError> {
        let BlindedLeaseSpec {
            current_epoch,
            lease_duration_epochs,
            delete_verifier,
        } = lease;
        if capability.locator != blinded_id.locator {
            return Err(StorageError::QuotaExceeded(
                "mismatched_blinded_capability_locator".into(),
            ));
        }
        let actual_sha = compute_sha256(shard_bytes);
        if actual_sha != blinded_id.content_sha256 {
            return Err(StorageError::CorruptedShard);
        }

        if let Some(ref mem) = self.in_memory {
            let shard_size = shard_bytes.len() as u64;
            let max_cap = self
                .quota
                .lock()
                .map(|q| q.max_storage_bytes())
                .unwrap_or(0);
            if shard_size > max_cap {
                return Err(StorageError::QuotaExceeded(
                    "in_memory_capacity_exceeded".into(),
                ));
            }
            // Enforce hard RAM ceiling BEFORE burning the caller's single-use voucher.
            let pre_evicted = {
                let mut mgr = self
                    .blinded_leases
                    .lock()
                    .expect("blinded_leases mutex poisoned");
                mgr.evict_oldest_to_fit(shard_size, current_epoch)
                    .ok_or_else(|| {
                        StorageError::QuotaExceeded("in_memory_capacity_exceeded".into())
                    })?
            };
            for loc in pre_evicted {
                let _ = self.zero_wipe_blinded_locator(&loc);
            }
            // If regular cached shards also share the RAM budget, evict LRU regular shards if needed.
            if self.in_memory_used_bytes().saturating_add(shard_size) > max_cap {
                let needed_reg = self
                    .in_memory_used_bytes()
                    .saturating_add(shard_size)
                    .saturating_sub(max_cap);
                let evicted_reg = {
                    let mut q = self.quota.lock().expect("quota mutex poisoned");
                    q.evict_lru_to_fit(needed_reg)
                };
                {
                    let mut m = mem.lock().expect("in_memory mutex poisoned");
                    let mut idx_map = self
                        .shard_id_by_file_key
                        .lock()
                        .expect("shard_id_by_file_key mutex poisoned");
                    for ek in evicted_reg {
                        idx_map.remove(&ek);
                        if let Some(buf) = m.regular_shards.remove(&ek) {
                            InMemoryShardBacking::zero_wipe_vec(buf);
                        }
                    }
                }
                while self.in_memory_used_bytes().saturating_add(shard_size) > max_cap {
                    let next_loc = self.blinded_leases.lock().ok().and_then(|mut mgr| {
                        let free = mgr.max_capacity_bytes().saturating_sub(mgr.used_bytes());
                        mgr.evict_oldest_to_fit(free.saturating_add(1), current_epoch)
                            .and_then(|v| v.into_iter().next())
                    });
                    if let Some(loc) = next_loc {
                        let _ = self.zero_wipe_blinded_locator(&loc);
                    } else {
                        return Err(StorageError::QuotaExceeded(
                            "in_memory_capacity_exceeded".into(),
                        ));
                    }
                }
            }

            nullifier_ledger.redeem_voucher(voucher, shard_size)?;

            let evicted_locators = {
                let mut mgr = self
                    .blinded_leases
                    .lock()
                    .expect("blinded_leases mutex poisoned");
                mgr.store_with_capability_and_lease(
                    blinded_id.locator,
                    shard_size,
                    current_epoch,
                    lease_duration_epochs,
                    delete_verifier,
                    Some(capability.capability_pubkey),
                )
            };
            for loc in evicted_locators {
                let _ = self.zero_wipe_blinded_locator(&loc);
            }
            {
                let mut m = mem.lock().expect("in_memory mutex poisoned");
                if let Some(prev) = m
                    .blinded_shards
                    .insert(blinded_id.file_key(), shard_bytes.to_vec())
                {
                    InMemoryShardBacking::zero_wipe_vec(prev);
                }
            }
            {
                let mut id_map = self
                    .blinded_id_by_locator
                    .lock()
                    .expect("blinded_id_by_locator mutex poisoned");
                id_map.insert(blinded_id.locator, *blinded_id);
            }
            return Ok(PathBuf::from(format!(
                "mem://{}.bshard",
                blinded_id.file_key()
            )));
        }

        // Write and fsync the `.bshard` file atomically BEFORE burning the single-use voucher
        // so an I/O error never burns a user's AnonymousQuotaVoucher without storing their shard.
        let path = self
            .shards_dir
            .join(format!("{}.bshard", blinded_id.file_key()));
        Self::atomic_write_file(&path, shard_bytes)?;

        if let Err(e) = nullifier_ledger.redeem_voucher(voucher, shard_bytes.len() as u64) {
            let _ = fs::remove_file(&path);
            return Err(e);
        }

        let evicted_locators = {
            let mut mgr = self
                .blinded_leases
                .lock()
                .expect("blinded_leases mutex poisoned");
            mgr.store_with_capability_and_lease(
                blinded_id.locator,
                shard_bytes.len() as u64,
                current_epoch,
                lease_duration_epochs,
                delete_verifier,
                Some(capability.capability_pubkey),
            )
        };

        // Physically delete any expired .bshard files evicted by disk pressure
        if !evicted_locators.is_empty() {
            let mut id_map = self
                .blinded_id_by_locator
                .lock()
                .expect("blinded_id_by_locator mutex poisoned");
            for loc in evicted_locators {
                if let Some(evicted_id) = id_map.remove(&loc) {
                    let p = self
                        .shards_dir
                        .join(format!("{}.bshard", evicted_id.file_key()));
                    let _ = fs::remove_file(p);
                }
            }
        }

        {
            let mut id_map = self
                .blinded_id_by_locator
                .lock()
                .expect("blinded_id_by_locator mutex poisoned");
            id_map.insert(blinded_id.locator, *blinded_id);
        }

        self.persist_blinded_lease_state();
        Ok(path)
    }

    /// Renews a blinded shard's Byte-Epoch lease on disk so it is not evicted over time.
    pub fn renew_blinded_shard_lease(
        &self,
        blinded_id: &BlindedShardId,
        current_epoch: u64,
        extension_epochs: u64,
    ) -> bool {
        let renewed = if let Ok(mut mgr) = self.blinded_leases.lock() {
            mgr.renew_lease(&blinded_id.locator, current_epoch, extension_epochs)
        } else {
            false
        };
        if renewed {
            self.persist_blinded_lease_state();
        }
        renewed
    }

    /// Time-driven eviction sweep: physically deletes all `.bshard` files on disk (or zero-wipes
    /// in RAM) whose `lease_expires_epoch + grace_epochs <= current_epoch` and returns the list
    /// of deleted `BlindedShardId`s.
    pub fn sweep_expired_blinded_shards(
        &self,
        current_epoch: u64,
    ) -> Result<Vec<BlindedShardId>, StorageError> {
        let expired_locators = {
            let mut mgr = self
                .blinded_leases
                .lock()
                .expect("blinded_leases mutex poisoned");
            mgr.sweep_all_expired(current_epoch)
        };

        let mut deleted_ids = Vec::with_capacity(expired_locators.len());
        {
            let mut id_map = self
                .blinded_id_by_locator
                .lock()
                .expect("blinded_id_by_locator mutex poisoned");
            for loc in expired_locators {
                if let Some(bid) = id_map.remove(&loc) {
                    if let Some(ref mem) = self.in_memory {
                        if let Some(buf) = mem
                            .lock()
                            .expect("in_memory mutex poisoned")
                            .blinded_shards
                            .remove(&bid.file_key())
                        {
                            InMemoryShardBacking::zero_wipe_vec(buf);
                        }
                    } else {
                        let p = self.shards_dir.join(format!("{}.bshard", bid.file_key()));
                        if p.exists() {
                            fs::remove_file(&p)?;
                        }
                    }
                    deleted_ids.push(bid);
                }
            }
        }
        self.persist_blinded_lease_state();
        Ok(deleted_ids)
    }

    /// Immediately verifies a `BlindedShardTombstone` and physically deletes `{locator}.bshard`
    /// from disk (or zero-wipes in RAM).
    pub fn delete_blinded_shard_with_tombstone(
        &self,
        blinded_id: &BlindedShardId,
        tombstone: &BlindedShardTombstone,
    ) -> Result<bool, StorageError> {
        let authorized = {
            let mut mgr = self
                .blinded_leases
                .lock()
                .expect("blinded_leases mutex poisoned");
            mgr.execute_tombstone(tombstone)
        };
        if !authorized {
            return Ok(false);
        }
        if let Ok(mut id_map) = self.blinded_id_by_locator.lock() {
            id_map.remove(&blinded_id.locator);
        }
        if let Some(ref mem) = self.in_memory {
            if let Some(buf) = mem
                .lock()
                .expect("in_memory mutex poisoned")
                .blinded_shards
                .remove(&blinded_id.file_key())
            {
                InMemoryShardBacking::zero_wipe_vec(buf);
            }
            return Ok(true);
        }
        let path = self
            .shards_dir
            .join(format!("{}.bshard", blinded_id.file_key()));
        if path.exists() {
            fs::remove_file(&path)?;
        }
        self.persist_blinded_lease_state();
        Ok(true)
    }

    /// Checks whether a `.bshard` file exists on the storage node's filesystem (or in RAM when `--no-fs`).
    pub fn has_blinded_shard_on_disk(&self, blinded_id: &BlindedShardId) -> bool {
        if let Some(ref mem) = self.in_memory {
            return mem
                .lock()
                .map(|m| m.blinded_shards.contains_key(&blinded_id.file_key()))
                .unwrap_or(false);
        }
        self.shards_dir
            .join(format!("{}.bshard", blinded_id.file_key()))
            .exists()
    }

    /// Reads an anonymized `BlindedShardId` from disk (or RAM) if and only if the caller presents a valid
    /// Ed25519 signature under the shard's registered `BlindedShardCapability` key (ADR-11 / ADR-15).
    pub fn get_blinded_shard_authorized(
        &self,
        blinded_id: &BlindedShardId,
        capability: &BlindedShardCapability,
        timestamp_ms: u64,
        read_sig: &[u8; 64],
    ) -> Result<Vec<u8>, StorageError> {
        // ADR-15 Red-Team Fix: Verify `capability.capability_pubkey` matches the capability key
        // registered when the shard lease was created (preventing caller-supplied key substitution).
        if let Ok(mgr) = self.blinded_leases.lock() {
            if let Some(entry) = mgr.lease_entry(&blinded_id.locator) {
                if let Some(registered_pubkey) = entry.capability_pubkey {
                    if capability.capability_pubkey != registered_pubkey {
                        return Err(StorageError::QuotaExceeded(
                            "unauthorized_blinded_shard_capability".into(),
                        ));
                    }
                }
            }
        }
        if capability.locator != blinded_id.locator
            || !capability.verify_read_token(timestamp_ms, read_sig)
        {
            return Err(StorageError::QuotaExceeded(
                "unauthorized_blinded_shard_capability".into(),
            ));
        }
        if let Some(ref mem) = self.in_memory {
            let bytes = mem
                .lock()
                .expect("in_memory mutex poisoned")
                .blinded_shards
                .get(&blinded_id.file_key())
                .cloned()
                .ok_or_else(|| StorageError::ShardNotFound(blinded_id.file_key()))?;
            if compute_sha256(&bytes) != blinded_id.content_sha256 {
                return Err(StorageError::CorruptedShard);
            }
            return Ok(bytes);
        }
        let path = self
            .shards_dir
            .join(format!("{}.bshard", blinded_id.file_key()));
        if !path.exists() {
            return Err(StorageError::ShardNotFound(blinded_id.file_key()));
        }
        let bytes = fs::read(&path)?;
        if compute_sha256(&bytes) != blinded_id.content_sha256 {
            return Err(StorageError::CorruptedShard);
        }
        Ok(bytes)
    }

    /// Background Local Bit-Rot Scrubber (`ADR-15`):
    /// Scans all `.shard` and `.bshard` files on disk, recomputes their cryptographic leaf/content
    /// hashes, and automatically unlinks and quarantines any silently corrupted files before a remote
    /// PoR challenge or restore egress request can trigger a slashing penalty.
    pub fn scrub_all_shards(&self) -> Result<ScrubReport, StorageError> {
        let mut report = ScrubReport::default();

        if let Some(ref mem) = self.in_memory {
            let reg_snapshot: Vec<(String, Vec<u8>)> = mem
                .lock()
                .expect("in_memory mutex poisoned")
                .regular_shards
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (stem, bytes) in reg_snapshot {
                let parts: Vec<&str> = stem.split('_').collect();
                if parts.len() == 3 {
                    if let Ok(shard_idx) = parts[1].parse::<u32>() {
                        let computed = hash_shard_leaf(shard_idx, &bytes);
                        if hex::encode(&computed[..16]) == parts[2] {
                            report.verified_healthy_shards += 1;
                        } else {
                            if let Some(buf) = mem
                                .lock()
                                .expect("in_memory mutex poisoned")
                                .regular_shards
                                .remove(&stem)
                            {
                                InMemoryShardBacking::zero_wipe_vec(buf);
                            }
                            if let Ok(mut q) = self.quota.lock() {
                                q.record_shard_removed("local", &stem, bytes.len() as u64);
                            }
                            report.quarantined_corrupted_shards.push(stem);
                        }
                    }
                }
            }
            let blinded_snapshot: Vec<([u8; 32], BlindedShardId)> = self
                .blinded_id_by_locator
                .lock()
                .expect("blinded_id_by_locator mutex poisoned")
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect();
            let mut corrupted_locators = Vec::new();
            for (locator, bid) in blinded_snapshot {
                let is_valid = mem
                    .lock()
                    .expect("in_memory mutex poisoned")
                    .blinded_shards
                    .get(&bid.file_key())
                    .is_some_and(|b| compute_sha256(b) == bid.content_sha256);
                if is_valid {
                    report.verified_healthy_blinded_shards += 1;
                } else {
                    let _ = self.zero_wipe_blinded_locator(&locator);
                    corrupted_locators.push(locator);
                }
            }
            report.quarantined_corrupted_blinded_locators = corrupted_locators;
            return Ok(report);
        }

        // 1. Scrub all regular `.shard` files (`{root8}_{shard_idx:02}_{hash16}.shard`)
        if self.shards_dir.exists() {
            for entry in fs::read_dir(&self.shards_dir)? {
                let entry = entry?;
                let path = entry.path();
                let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if let Some(stem) = fname.strip_suffix(".shard") {
                    let parts: Vec<&str> = stem.split('_').collect();
                    if parts.len() == 3 {
                        if let Ok(shard_idx) = parts[1].parse::<u32>() {
                            let bytes = fs::read(&path)?;
                            let computed = hash_shard_leaf(shard_idx, &bytes);
                            let expected_prefix = parts[2];
                            let actual_prefix = hex::encode(&computed[..16]);
                            if actual_prefix == expected_prefix {
                                report.verified_healthy_shards += 1;
                            } else {
                                let _ = fs::remove_file(&path);
                                if let Ok(mut q) = self.quota.lock() {
                                    q.record_shard_removed("local", stem, bytes.len() as u64);
                                }
                                report.quarantined_corrupted_shards.push(stem.to_string());
                            }
                        }
                    }
                }
            }
        }

        // 2. Scrub all active `.bshard` files registered in `blinded_id_by_locator`
        let blinded_snapshot: Vec<([u8; 32], BlindedShardId)> = {
            let id_map = self
                .blinded_id_by_locator
                .lock()
                .expect("blinded_id_by_locator mutex poisoned");
            id_map.iter().map(|(k, v)| (*k, *v)).collect()
        };

        let mut corrupted_locators = Vec::new();
        for (locator, bid) in blinded_snapshot {
            let path = self.shards_dir.join(format!("{}.bshard", bid.file_key()));
            let is_valid = match fs::read(&path) {
                Ok(bytes) => compute_sha256(&bytes) == bid.content_sha256,
                Err(_) => false,
            };
            if is_valid {
                report.verified_healthy_blinded_shards += 1;
            } else {
                let _ = fs::remove_file(&path);
                corrupted_locators.push(locator);
            }
        }

        if !corrupted_locators.is_empty() {
            {
                let mut id_map = self
                    .blinded_id_by_locator
                    .lock()
                    .expect("blinded_id_by_locator mutex poisoned");
                for loc in &corrupted_locators {
                    id_map.remove(loc);
                }
            }
            report.quarantined_corrupted_blinded_locators = corrupted_locators;
            self.persist_blinded_lease_state();
        }

        Ok(report)
    }

    /// Gracefully decommissions this node (`parvault leave` / `parvault-seed leave`), directly handing off
    /// all healthy `.shard` and `.bshard` files at `1.0x` bandwidth to `target_handoff_dirs` (instead
    /// of forcing the mesh to wait for PoR timeouts and perform `16.0x` Reed-Solomon reconstruction)
    /// and issuing a signed [`GracefulDepartureReceipt`] that preserves the node's Earned Uptime Standing.
    pub fn graceful_leave_and_redistribute(
        &self,
        departing_identity: &NodeIdentity,
        target_handoff_dirs: &[PathBuf],
        remove_local_after_handoff: bool,
    ) -> Result<GracefulDepartureReceipt, StorageError> {
        // First run a local bit-rot scrub so we never hand off silently corrupted sectors
        let _ = self.scrub_all_shards()?;

        let mut shard_files: Vec<PathBuf> = Vec::new();
        if self.shards_dir.exists() {
            for entry in fs::read_dir(&self.shards_dir)? {
                let path = entry?.path();
                if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                    if fname.ends_with(".shard") || fname.ends_with(".bshard") {
                        shard_files.push(path);
                    }
                }
            }
        }
        shard_files.sort();

        let mut migrated_shards_count = 0usize;
        let mut migrated_blinded_shards_count = 0usize;
        let mut total_bytes_handed_off = 0u64;
        let mut manifest_entries: Vec<u8> = Vec::new();

        let default_mesh_pool = self.root_dir.join("mesh_evacuated_pool");
        let effective_targets: Vec<PathBuf> = if target_handoff_dirs.is_empty() {
            if let Some(ref client) = self.mesh_client {
                let net_eps = client.all_network_endpoints();
                if !net_eps.is_empty() {
                    net_eps.into_iter().map(PathBuf::from).collect()
                } else {
                    vec![default_mesh_pool]
                }
            } else {
                vec![default_mesh_pool]
            }
        } else {
            target_handoff_dirs.to_vec()
        };

        let shard_idx_snapshot: HashMap<String, ShardId> = self
            .shard_id_by_file_key
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        let blinded_idx_snapshot: HashMap<String, BlindedShardId> = self
            .blinded_id_by_locator
            .lock()
            .map(|m| m.values().map(|b| (b.file_key(), *b)).collect())
            .unwrap_or_default();
        let por_verifier = crate::por::PorVerifierEngine::with_persistence_dir(300, &self.root_dir);

        for (idx, path) in shard_files.iter().enumerate() {
            let fname = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            let bytes = fs::read(path)?;
            let content_sha = compute_sha256(&bytes);

            manifest_entries.extend_from_slice(fname.as_bytes());
            manifest_entries.extend_from_slice(&content_sha);

            let target_root = &effective_targets[idx % effective_targets.len()];
            let target_str = target_root.to_string_lossy().to_string();

            if crate::network::is_network_peer_addr(&target_str) {
                // Hand-off puts claim the departing identity, so they are sent as it (v0.5.0
                // owner rule: the accounted owner is the sender).
                let client = match self.mesh_client.clone() {
                    Some(c) => c.with_identity(departing_identity.clone()),
                    None => crate::network::MeshClient::new(
                        departing_identity.clone(),
                        vec![target_str.clone()],
                        None,
                    ),
                };
                if let Some(stem) = fname.strip_suffix(".shard") {
                    let shard_id = shard_idx_snapshot.get(stem).copied().unwrap_or(ShardId {
                        stripe_merkle_root: content_sha,
                        shard_index: idx as u32,
                        shard_hash: crate::sharding::hash_shard_leaf(idx as u32, &bytes),
                    });
                    let (maybe_session_key, maybe_grant) =
                        por_verifier.get_shard_session_and_grant(&shard_id);
                    let session_key = maybe_session_key.unwrap_or_else(|| {
                        departing_identity
                            .derive_stripe_por_session_key(&shard_id.stripe_merkle_root)
                    });
                    client
                        .put_shard(
                            &target_str,
                            &departing_identity.device_peer_id(),
                            shard_id,
                            bytes.clone(),
                            session_key,
                            maybe_grant,
                        )
                        .map_err(|e| StorageError::Io(std::io::Error::other(e.to_string())))?;
                } else if let Some(stem) = fname.strip_suffix(".bshard") {
                    let blinded_id =
                        blinded_idx_snapshot
                            .get(stem)
                            .copied()
                            .unwrap_or(BlindedShardId {
                                locator: content_sha,
                                content_sha256: content_sha,
                            });
                    let (capability, delete_verifier) = if let Ok(mgr) = self.blinded_leases.lock()
                    {
                        if let Some(entry) = mgr.lease_entry(&blinded_id.locator) {
                            let cap_pub = entry.capability_pubkey.unwrap_or_else(|| {
                                let mk =
                                    MasterKey::from_bytes(departing_identity.signing_seed_bytes());
                                BlindedShardCapability::derive_keypair(&mk, &blinded_id.locator)
                                    .1
                                    .capability_pubkey
                            });
                            (
                                BlindedShardCapability {
                                    locator: blinded_id.locator,
                                    capability_pubkey: cap_pub,
                                },
                                entry.delete_verifier,
                            )
                        } else {
                            let mk = MasterKey::from_bytes(departing_identity.signing_seed_bytes());
                            let (_, cap) =
                                BlindedShardCapability::derive_keypair(&mk, &blinded_id.locator);
                            (cap, [0u8; 32])
                        }
                    } else {
                        let mk = MasterKey::from_bytes(departing_identity.signing_seed_bytes());
                        let (_, cap) =
                            BlindedShardCapability::derive_keypair(&mk, &blinded_id.locator);
                        (cap, [0u8; 32])
                    };
                    let voucher =
                        AnonymousQuotaVoucher::mint(departing_identity, (bytes.len() * 2) as u64);
                    client
                        .put_blinded_shard(
                            &target_str,
                            blinded_id,
                            bytes.clone(),
                            capability,
                            voucher,
                            BlindedLeaseSpec::new(1, 30, delete_verifier),
                        )
                        .map_err(|e| StorageError::Io(std::io::Error::other(e.to_string())))?;
                }
            } else {
                let target_shards_dir = target_root.join("shards");
                fs::create_dir_all(&target_shards_dir)?;
                let dest_path = target_shards_dir.join(&fname);
                Self::atomic_write_file(&dest_path, &bytes)?;
            }

            if fname.ends_with(".bshard") {
                migrated_blinded_shards_count += 1;
            } else {
                migrated_shards_count += 1;
            }
            total_bytes_handed_off = total_bytes_handed_off.saturating_add(bytes.len() as u64);

            if remove_local_after_handoff {
                let _ = fs::remove_file(path);
                if let Some(stem) = fname.strip_suffix(".shard") {
                    if let Ok(mut q) = self.quota.lock() {
                        q.record_shard_removed("local", stem, bytes.len() as u64);
                    }
                }
            }
        }

        let handoff_manifest_sha256 = compute_sha256(&manifest_entries);
        let departure_timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let receipt = GracefulDepartureReceipt::issue(
            departing_identity,
            migrated_shards_count,
            migrated_blinded_shards_count,
            total_bytes_handed_off,
            handoff_manifest_sha256,
            departure_timestamp_ms,
        );

        if let Ok(json_bytes) = serde_json::to_vec_pretty(&receipt) {
            let receipt_path = self.root_dir.join("graceful_departure_receipt.json");
            let _ = Self::atomic_write_file(&receipt_path, &json_bytes);
        }

        Ok(receipt)
    }

    /// Saves a `FileManifest` to local disk (encrypted under `master_key`) and, when a
    /// `MeshClient` is configured with network peers, publishes a `SignedDhtManifestEnvelope`
    /// to the Kademlia DHT over `libp2p`.
    pub fn save_manifest(
        &self,
        master_key: &MasterKey,
        manifest: &FileManifest,
    ) -> Result<PathBuf, StorageError> {
        let (_, encrypted) = manifest.to_encrypted_dht_record(master_key)?;
        let path = if let Some(ref mem) = self.in_memory {
            let mut m = mem.lock().expect("in_memory mutex poisoned");
            if let Some(prev) = m.manifests.insert(manifest.file_merkle_root, encrypted) {
                InMemoryShardBacking::zero_wipe_vec(prev);
            }
            PathBuf::from(format!(
                "mem://{}.manifest.bin",
                hex::encode(manifest.file_merkle_root)
            ))
        } else {
            let p = self.manifest_path(&manifest.file_merkle_root);
            Self::atomic_write_file(&p, &encrypted)?;
            p
        };

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if let Some(ref client) = self.mesh_client {
            if !client.all_network_endpoints().is_empty() {
                if let Ok(env) = SignedDhtManifestEnvelope::seal(
                    master_key,
                    client.identity(),
                    manifest,
                    now_ms.max(1),
                    now_ms,
                ) {
                    let _ = self.put_dht_manifest_envelope(env.clone());
                    let _ = client
                        .put_dht_envelope(crate::network::DhtWireEnvelope::ClassicalManifest(env));
                }
            }
        }
        Ok(path)
    }

    /// Loads and decrypts a `FileManifest` by its 32-byte File Merkle Root from local disk/RAM
    /// or over `libp2p` Kademlia DHT when `mesh_client` is configured.
    pub fn load_manifest(
        &self,
        master_key: &MasterKey,
        file_merkle_root: &Hash32,
    ) -> Result<FileManifest, StorageError> {
        if let Some(ref mem) = self.in_memory {
            if let Some(encrypted) = mem
                .lock()
                .expect("in_memory mutex poisoned")
                .manifests
                .get(file_merkle_root)
                .cloned()
            {
                return FileManifest::from_encrypted_dht_record(master_key, &encrypted);
            }
        }
        let path = self.manifest_path(file_merkle_root);
        if !self.is_in_memory() && path.exists() {
            let encrypted = fs::read(path)?;
            return FileManifest::from_encrypted_dht_record(master_key, &encrypted);
        }
        let root_hex = hex::encode(file_merkle_root);
        let dht_key = derive_dht_manifest_key(master_key, &root_hex);
        if let Some(env) = self.get_dht_manifest_envelope(&dht_key) {
            return env.open(master_key);
        }
        if let Some(ref client) = self.mesh_client {
            if !client.all_network_endpoints().is_empty() {
                if let Ok(crate::network::DhtWireEnvelope::ClassicalManifest(env)) = client
                    .get_dht_envelope(&dht_key, crate::network::DhtEnvelopeKind::ClassicalManifest)
                {
                    return env.open(master_key);
                }
            }
        }
        let encrypted = fs::read(path)?;
        FileManifest::from_encrypted_dht_record(master_key, &encrypted)
    }

    /// Streams a file from `input_path` in fixed `stripe_size_bytes` segments (16 MiB default per ADR-01),
    /// encrypts each stripe with AES-256-GCM prior to Reed-Solomon splitting, distributes all `N` shards
    /// across `libp2p` peers when `mesh_client` has network endpoints (or persists locally when in local mode),
    /// and writes the encrypted `FileManifest`.
    pub fn store_file_streaming(
        &self,
        owner_peer_id: &str,
        input_path: &Path,
        master_key: &MasterKey,
        tier: ErasureTier,
        stripe_size_bytes: usize,
    ) -> Result<FileManifest, StorageError> {
        let mut file = File::open(input_path)?;
        let original_file_size = file.metadata()?.len();
        let file_salt = generate_file_salt();
        let raw_cap =
            if stripe_size_bytes == 0 || stripe_size_bytes == Self::DEFAULT_STRIPE_SIZE_BYTES {
                self.stripe_size_bytes
            } else {
                stripe_size_bytes
            };
        let layout = crate::config::compute_stripe_layout_for_size(original_file_size, raw_cap);
        let (_shard_len, peak_stripe_ram) =
            crate::sharding::reed_solomon::compute_stripe_memory_footprint_bytes(
                layout.max_stripe_plaintext_bytes,
                tier,
            )?;
        if layout.stripe_size_bytes <= crate::config::ROUTER_SOC_STRIPE_SIZE_BYTES
            && peak_stripe_ram >= crate::config::ROUTER_SOC_MAX_STRIPE_MEMORY_BYTES
        {
            return Err(StorageError::Sharding(
                crate::sharding::reed_solomon::ShardingError::ErasureError(
                    "RouterSoC stripe memory ceiling exceeded".to_string(),
                ),
            ));
        }
        let stripe_cap = layout.stripe_size_bytes;
        let prealloc_stripes = usize::try_from(layout.stripe_count)
            .unwrap_or(1024)
            .min(1024);

        let mut stripes = Vec::with_capacity(prealloc_stripes);
        let mut stripe_roots = Vec::with_capacity(prealloc_stripes);
        let mut stripe_index: u64 = 0;

        let use_network = self
            .mesh_client
            .as_ref()
            .is_some_and(|c| !c.all_network_endpoints().is_empty());

        loop {
            let mut buf = vec![0u8; stripe_cap];
            let mut read_total = 0usize;
            while read_total < stripe_cap {
                let n = file.read(&mut buf[read_total..])?;
                if n == 0 {
                    break;
                }
                read_total += n;
            }
            if read_total == 0 && stripe_index > 0 {
                break;
            }
            buf.truncate(read_total);

            // 1. Client-side zero-knowledge encryption (AES-256-GCM) BEFORE Reed-Solomon splitting.
            let ciphertext = encrypt_stripe(master_key, &file_salt, stripe_index, &buf)?;

            // 2. Reed-Solomon k-of-n erasure coding + stripe Merkle tree calculation.
            let shard_set = encode_ciphertext_stripe(stripe_index, &ciphertext, tier)?;
            stripe_roots.push(shard_set.stripe_merkle_root);

            // 3. Distribute shards over libp2p via MeshClient if network peers are configured, else local BlockStore.
            let (assigned_peers, _) =
                self.place_stripe(owner_peer_id, &shard_set, tier, use_network, false)?;

            stripes.push(StripeManifestEntry {
                stripe_index,
                k_data: shard_set.k_data,
                m_parity: shard_set.m_parity,
                original_ciphertext_len: shard_set.original_ciphertext_len,
                shard_len: shard_set.shard_len,
                stripe_merkle_root: shard_set.stripe_merkle_root,
                shard_hashes: shard_set.shard_hashes,
                assigned_peers,
            });

            stripe_index += 1;
            if read_total < stripe_cap {
                break;
            }
        }

        let file_merkle_root = compute_file_merkle_root(&stripe_roots);
        let manifest = FileManifest {
            version: 1,
            file_merkle_root,
            file_salt,
            original_file_size,
            stripe_size_bytes: stripe_cap,
            tier,
            stripes,
            witness_peers: Vec::new(),
        };

        self.save_manifest(master_key, &manifest)?;
        Ok(manifest)
    }

    /// Streams `expected_len` bytes from an arbitrary `Read` source (such as a zero-copy Linux
    /// `memfd` passed over `SCM_RIGHTS`) using a single reusable `stripe_size_bytes` buffer so RSS
    /// stays strictly bounded (`< 16 MiB` under `HardwareProfile::RouterSoc` `1 MiB` stripes).
    pub fn store_reader_streaming<R: Read>(
        &self,
        owner_peer_id: &str,
        reader: &mut R,
        expected_len: u64,
        master_key: &MasterKey,
        tier: ErasureTier,
        stripe_size_bytes: usize,
    ) -> Result<FileManifest, StorageError> {
        let file_salt = generate_file_salt();
        let raw_cap =
            if stripe_size_bytes == 0 || stripe_size_bytes == Self::DEFAULT_STRIPE_SIZE_BYTES {
                self.stripe_size_bytes
            } else {
                stripe_size_bytes
            };
        let layout = crate::config::compute_stripe_layout_for_size(expected_len, raw_cap);
        let stripe_cap = layout.stripe_size_bytes;
        let prealloc_stripes = usize::try_from(layout.stripe_count)
            .unwrap_or(1024)
            .min(1024);

        let mut stripes = Vec::with_capacity(prealloc_stripes);
        let mut stripe_roots = Vec::with_capacity(prealloc_stripes);
        let mut stripe_index: u64 = 0;
        let mut total_read_bytes: u64 = 0;

        let use_network = self
            .mesh_client
            .as_ref()
            .is_some_and(|c| !c.all_network_endpoints().is_empty());

        let mut reusable_buf = vec![0u8; stripe_cap];
        let mut wrote_local_batch = false;

        loop {
            let remaining = expected_len.saturating_sub(total_read_bytes);
            let target_chunk = (remaining as usize).min(stripe_cap);
            let mut read_total = 0usize;
            while read_total < target_chunk {
                let n = reader.read(&mut reusable_buf[read_total..target_chunk])?;
                if n == 0 {
                    break;
                }
                read_total += n;
            }
            if read_total == 0 && stripe_index > 0 {
                break;
            }
            total_read_bytes = total_read_bytes.saturating_add(read_total as u64);

            let ciphertext = encrypt_stripe(
                master_key,
                &file_salt,
                stripe_index,
                &reusable_buf[..read_total],
            )?;
            let shard_set = encode_ciphertext_stripe(stripe_index, &ciphertext, tier)?;
            stripe_roots.push(shard_set.stripe_merkle_root);

            let (assigned_peers, local) =
                self.place_stripe(owner_peer_id, &shard_set, tier, use_network, true)?;
            wrote_local_batch |= local;

            stripes.push(StripeManifestEntry {
                stripe_index,
                k_data: shard_set.k_data,
                m_parity: shard_set.m_parity,
                original_ciphertext_len: shard_set.original_ciphertext_len,
                shard_len: shard_set.shard_len,
                stripe_merkle_root: shard_set.stripe_merkle_root,
                shard_hashes: shard_set.shard_hashes,
                assigned_peers,
            });

            stripe_index += 1;
            if total_read_bytes >= expected_len || read_total < stripe_cap {
                break;
            }
        }

        if wrote_local_batch {
            if let Ok(q) = self.quota.lock() {
                q.flush_persistence();
            }
            self.persist_shard_index();
        }

        let file_merkle_root = compute_file_merkle_root(&stripe_roots);
        let manifest = FileManifest {
            version: 1,
            file_merkle_root,
            file_salt,
            original_file_size: total_read_bytes,
            stripe_size_bytes: stripe_cap,
            tier,
            stripes,
            witness_peers: Vec::new(),
        };

        self.save_manifest(master_key, &manifest)?;
        Ok(manifest)
    }

    /// Places one stripe's shards (the one placement path for file and folder stores): on ring
    /// peers through the mesh client, skipping peers that refuse or are unreachable; or locally
    /// when there is no mesh client or no peer accepts (for example only nodes of other rings are
    /// pinned, D1). Returns the assigned hosts and whether anything was written locally.
    fn place_stripe(
        &self,
        owner_peer_id: &str,
        shard_set: &crate::sharding::StripeShardSet,
        tier: ErasureTier,
        use_network: bool,
        deferred_flush: bool,
    ) -> Result<(Vec<String>, bool), StorageError> {
        if use_network {
            let client = self.mesh_client.as_ref().expect("checked use_network");
            let session_key = client
                .identity()
                .derive_stripe_por_session_key(&shard_set.stripe_merkle_root);
            match client.distribute_stripe_shards(
                client.identity(),
                owner_peer_id,
                shard_set,
                tier,
                session_key,
            ) {
                Ok(assigned) => return Ok((assigned, false)),
                // R3-1: this stripe is not backed up; the store path reports it.
                Err(e) => tracing::warn!(
                    error = %e,
                    "no ring peer accepted the stripe; storing it locally"
                ),
            }
        }
        for (idx, shard_bytes) in shard_set.shards.iter().enumerate() {
            let shard_id = ShardId {
                stripe_merkle_root: shard_set.stripe_merkle_root,
                shard_index: idx as u32,
                shard_hash: shard_set.shard_hashes[idx],
            };
            if deferred_flush {
                self.put_shard_deferred_flush(owner_peer_id, &shard_id, shard_bytes)?;
            } else {
                self.put_shard(owner_peer_id, &shard_id, shard_bytes)?;
            }
        }
        self.record_local_only_stripe(&shard_set.stripe_merkle_root);
        let (_, _, n_total) = tier.params();
        Ok((vec![owner_peer_id.to_string(); n_total], true))
    }

    /// Records a stripe whose shards are all on this machine (not backed up, R3-1): counted on
    /// the calling thread for the command summary and listed in the data directory for
    /// `parvault status`.
    pub fn record_local_only_stripe(&self, stripe_root: &Hash32) {
        crate::storage::local_only::note(1);
        if self.is_in_memory() {
            return;
        }
        let path = self
            .root_dir
            .join(crate::storage::local_only::LOCAL_ONLY_STRIPES_FILE);
        let line = hex::encode(stripe_root);
        let mut text = fs::read_to_string(&path).unwrap_or_default();
        if text.lines().any(|l| l == line) {
            return;
        }
        text.push_str(&line);
        text.push('\n');
        if let Err(e) = Self::atomic_write_file(&path, text.as_bytes()) {
            tracing::error!(error = %e, "could not record a local-only stripe");
        }
    }

    /// Number of stripes stored on this node that never reached a ring peer (R3-1).
    pub fn local_only_stripe_count(&self) -> usize {
        fs::read_to_string(
            self.root_dir
                .join(crate::storage::local_only::LOCAL_ONLY_STRIPES_FILE),
        )
        .map(|t| t.lines().filter(|l| !l.is_empty()).count())
        .unwrap_or(0)
    }

    fn put_shard_deferred_flush(
        &self,
        owner_peer_id: &str,
        id: &ShardId,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        if self.is_in_memory() {
            let _ = self.put_shard(owner_peer_id, id, bytes)?;
            return Ok(());
        }
        let computed = hash_shard_leaf(id.shard_index, bytes);
        if computed != id.shard_hash {
            return Err(StorageError::CorruptedShard);
        }
        let shard_size = bytes.len() as u64;
        {
            let mut q = self.quota.lock().expect("quota mutex poisoned");
            if !q.can_accept_shard(owner_peer_id, shard_size) {
                let evicted = q.evict_lru_to_fit(shard_size);
                for evicted_key in evicted {
                    let p = self.shards_dir.join(format!("{evicted_key}.shard"));
                    let _ = fs::remove_file(p);
                }
                if !q.can_accept_shard(owner_peer_id, shard_size) {
                    return Err(StorageError::QuotaExceeded(owner_peer_id.to_string()));
                }
            }
        }
        let path = self.shard_path(id);
        fs::write(&path, bytes)?;
        {
            let mut q = self.quota.lock().expect("quota mutex poisoned");
            q.record_shard_stored_deferred(owner_peer_id, id.file_key(), shard_size);
        }
        if let Ok(mut idx_map) = self.shard_id_by_file_key.lock() {
            idx_map.insert(id.file_key(), *id);
        }
        Ok(())
    }

    /// Reconstructs and authenticates a single plaintext stripe from `>= K` shards
    /// (or materializes a zero-filled sparse extent when `stripe.original_ciphertext_len == 0`).
    pub fn reconstruct_and_decrypt_stripe(
        &self,
        manifest: &FileManifest,
        stripe: &StripeManifestEntry,
        master_key: &MasterKey,
    ) -> Result<Vec<u8>, StorageError> {
        if stripe.original_ciphertext_len == 0 {
            let stripe_cap = manifest.stripe_size_bytes.max(1);
            let stripe_start = stripe.stripe_index.saturating_mul(stripe_cap as u64);
            let rem = manifest.original_file_size.saturating_sub(stripe_start);
            let plain_len = (rem as usize).min(stripe_cap);
            return Ok(vec![0u8; plain_len]);
        }
        let total_shards = stripe.k_data + stripe.m_parity;
        let mut shard_slots: Vec<Option<Vec<u8>>> = Vec::with_capacity(total_shards);
        let mut local_found = 0usize;

        for idx in 0..total_shards {
            let id = ShardId {
                stripe_merkle_root: stripe.stripe_merkle_root,
                shard_index: idx as u32,
                shard_hash: stripe.shard_hashes[idx],
            };
            match self.get_shard(&id) {
                Ok(bytes) => {
                    local_found += 1;
                    shard_slots.push(Some(bytes));
                }
                Err(_) => shard_slots.push(None),
            }
        }

        if local_found < stripe.k_data {
            let has_net_assigned = stripe
                .assigned_peers
                .iter()
                .any(|p| crate::network::is_network_peer_addr(p));
            let net_client = if let Some(ref c) = self.mesh_client {
                if !c.all_network_endpoints().is_empty() || has_net_assigned {
                    Some(c.clone())
                } else {
                    None
                }
            } else if has_net_assigned {
                let id = NodeIdentity::from_master_key(master_key);
                Some(crate::network::MeshClient::new(
                    id,
                    stripe.assigned_peers.clone(),
                    None,
                ))
            } else {
                None
            };

            if let Some(client) = net_client {
                let remote_slots = client.fetch_stripe_shards(stripe, client.identity());
                for (slot, rem) in shard_slots.iter_mut().zip(remote_slots) {
                    if slot.is_none() && rem.is_some() {
                        *slot = rem;
                    }
                }
            }
        }

        let ciphertext = reconstruct_ciphertext_stripe(
            shard_slots,
            stripe.k_data,
            stripe.m_parity,
            stripe.original_ciphertext_len,
            Some(&stripe.shard_hashes),
            Some(stripe.stripe_merkle_root),
        )?;

        Ok(decrypt_stripe(
            master_key,
            &manifest.file_salt,
            stripe.stripe_index,
            &ciphertext,
        )?)
    }

    /// Streams reconstructed, authenticated plaintext stripes directly into `writer` (such as a
    /// Linux `memfd` passed over `SCM_RIGHTS`), bounding RAM to a single stripe.
    pub fn restore_to_writer_streaming<W: Write>(
        &self,
        manifest: &FileManifest,
        master_key: &MasterKey,
        writer: &mut W,
    ) -> Result<u64, StorageError> {
        let mut streamed = 0u64;
        for stripe in &manifest.stripes {
            let plaintext = self.reconstruct_and_decrypt_stripe(manifest, stripe, master_key)?;
            streamed = streamed.saturating_add(plaintext.len() as u64);
            writer.write_all(&plaintext)?;
        }
        writer.flush()?;
        Ok(streamed)
    }

    /// Lazily reconstructs and decrypts **only** the minimal intersecting stripe window covering
    /// `[offset .. offset + length]` (e.g. `O(1)` stripes for a `5 MiB` slice inside a `10 GiB`
    /// vault), writing exact verified plaintext bytes to `writer`.
    pub fn read_plaintext_range<W: Write>(
        &self,
        manifest: &FileManifest,
        master_key: &MasterKey,
        offset: u64,
        length: u64,
        writer: &mut W,
    ) -> Result<u64, StorageError> {
        if offset > manifest.original_file_size {
            return Err(StorageError::InvalidRange {
                offset,
                length,
                size: manifest.original_file_size,
            });
        }
        if length == 0 || offset == manifest.original_file_size {
            return Ok(0);
        }
        let end_offset = offset
            .saturating_add(length)
            .min(manifest.original_file_size);
        let stripe_cap = (manifest.stripe_size_bytes.max(1)) as u64;
        let first_stripe_idx = offset / stripe_cap;
        let last_stripe_idx = (end_offset - 1) / stripe_cap;

        let mut streamed = 0u64;
        for target_idx in first_stripe_idx..=last_stripe_idx {
            let stripe = manifest
                .stripes
                .get(target_idx as usize)
                .filter(|s| s.stripe_index == target_idx)
                .or_else(|| {
                    manifest
                        .stripes
                        .iter()
                        .find(|s| s.stripe_index == target_idx)
                })
                .ok_or_else(|| {
                    StorageError::ShardNotFound(format!("missing stripe index {target_idx}"))
                })?;

            let plaintext = self.reconstruct_and_decrypt_stripe(manifest, stripe, master_key)?;
            let stripe_start = target_idx.saturating_mul(stripe_cap);
            let local_start = offset.saturating_sub(stripe_start) as usize;
            let local_end = ((end_offset - stripe_start) as usize).min(plaintext.len());
            if local_start < local_end {
                let slice = &plaintext[local_start..local_end];
                writer.write_all(slice)?;
                streamed = streamed.saturating_add(slice.len() as u64);
            }
        }
        writer.flush()?;
        Ok(streamed)
    }

    /// Reconstructs and decrypts a file from its `FileManifest` using at least `K` surviving
    /// shards per stripe (fetched over `libp2p` via `MeshClient` or from local disk),
    /// writing the verified plaintext to `output_path`.
    pub fn restore_file_streaming(
        &self,
        manifest: &FileManifest,
        master_key: &MasterKey,
        output_path: &Path,
    ) -> Result<(), StorageError> {
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut out_file = File::create(output_path)?;
        self.restore_to_writer_streaming(manifest, master_key, &mut out_file)?;
        Ok(())
    }
}

/// Zero-Knowledge Ed25519-Signed Monotonic DHT Manifest Envelope (Defense 3).
/// Allows untrusted Kademlia DHT nodes to authenticate the owner's public key and enforce
/// strict version monotonicity (`new.monotonic_version > old.monotonic_version`) without
/// possessing `K_user` or learning any plaintext metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedDhtManifestEnvelope {
    pub dht_key: [u8; 32],
    pub owner_pubkey: [u8; 32],
    pub monotonic_version: u64,
    pub updated_at_unix_ms: u64,
    pub ciphertext_sha256: [u8; 32],
    pub encrypted_manifest: Vec<u8>,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl SignedDhtManifestEnvelope {
    /// Encrypts `manifest` under `master_key` and signs the outer envelope with `owner_identity`.
    pub fn seal(
        master_key: &MasterKey,
        owner_identity: &NodeIdentity,
        manifest: &FileManifest,
        monotonic_version: u64,
        updated_at_unix_ms: u64,
    ) -> Result<Self, StorageError> {
        let (dht_key, encrypted_manifest) = manifest.to_encrypted_dht_record(master_key)?;
        let ciphertext_sha256 = compute_sha256(&encrypted_manifest);
        let owner_pubkey = owner_identity.public_key_bytes();

        let msg = Self::canonical_bytes(
            &dht_key,
            &owner_pubkey,
            monotonic_version,
            updated_at_unix_ms,
            &ciphertext_sha256,
        );
        let sig = owner_identity.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Ok(Self {
            dht_key,
            owner_pubkey,
            monotonic_version,
            updated_at_unix_ms,
            ciphertext_sha256,
            encrypted_manifest,
            sig_r,
            sig_s,
        })
    }

    /// Verifies ciphertext integrity and the owner's Ed25519 signature in zero knowledge
    /// (requires NO access to `K_user`).
    pub fn verify_zero_knowledge(&self) -> bool {
        if self.monotonic_version == 0 {
            return false;
        }
        let actual_sha = compute_sha256(&self.encrypted_manifest);
        if actual_sha != self.ciphertext_sha256 {
            return false;
        }
        let msg = Self::canonical_bytes(
            &self.dht_key,
            &self.owner_pubkey,
            self.monotonic_version,
            self.updated_at_unix_ms,
            &self.ciphertext_sha256,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.owner_pubkey, &msg, &sig)
    }

    /// Verifies the envelope and decrypts the inner `FileManifest` using `master_key`.
    pub fn open(&self, master_key: &MasterKey) -> Result<FileManifest, StorageError> {
        if !self.verify_zero_knowledge() {
            return Err(StorageError::DhtManifestPoisonedOrRollback);
        }
        FileManifest::from_encrypted_dht_record(master_key, &self.encrypted_manifest)
    }

    fn canonical_bytes(
        dht_key: &[u8; 32],
        owner_pubkey: &[u8; 32],
        monotonic_version: u64,
        updated_at_unix_ms: u64,
        ciphertext_sha256: &[u8; 32],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(140);
        buf.extend_from_slice(b"parvault-dht-envelope-v1:");
        buf.extend_from_slice(dht_key);
        buf.extend_from_slice(owner_pubkey);
        buf.extend_from_slice(&monotonic_version.to_be_bytes());
        buf.extend_from_slice(&updated_at_unix_ms.to_be_bytes());
        buf.extend_from_slice(ciphertext_sha256);
        buf
    }
}

#[derive(Serialize, Deserialize, Default)]
struct PersistedZeroTrustDhtState {
    records: HashMap<[u8; 32], SignedDhtManifestEnvelope>,
    pq_records: HashMap<[u8; 32], crate::crypto::PqSignedDhtManifestEnvelope>,
    catalog_records: HashMap<[u8; 32], crate::sync::EncryptedVaultCatalogEnvelope>,
}

/// Zero-Trust Kademlia DHT Manifest Table enforcing Ed25519 key ownership and strict version
/// monotonicity (`new.monotonic_version > existing.monotonic_version`) to block poisoning and rollbacks.
#[derive(Debug, Default, Clone)]
pub struct ZeroTrustDhtStore {
    records: HashMap<[u8; 32], SignedDhtManifestEnvelope>,
    pq_records: HashMap<[u8; 32], crate::crypto::PqSignedDhtManifestEnvelope>,
    catalog_records: HashMap<[u8; 32], crate::sync::EncryptedVaultCatalogEnvelope>,
    persistence_path: Option<PathBuf>,
}

impl ZeroTrustDhtStore {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            pq_records: HashMap::new(),
            catalog_records: HashMap::new(),
            persistence_path: None,
        }
    }

    /// Initializes `ZeroTrustDhtStore` backed by `data_dir/zero_trust_dht_store.bin` so
    /// DHT manifest and vault catalog envelopes survive process and daemon restarts.
    pub fn with_persistence_dir(data_dir: &Path) -> Self {
        let _ = fs::create_dir_all(data_dir);
        let path = data_dir.join("zero_trust_dht_store.bin");
        let (records, pq_records, catalog_records) = if path.exists() {
            fs::read(&path)
                .ok()
                .and_then(|bytes| bincode::deserialize::<PersistedZeroTrustDhtState>(&bytes).ok())
                .map(|s| (s.records, s.pq_records, s.catalog_records))
                .unwrap_or_default()
        } else {
            (HashMap::new(), HashMap::new(), HashMap::new())
        };
        Self {
            records,
            pq_records,
            catalog_records,
            persistence_path: Some(path),
        }
    }

    fn persist_if_configured(&self) {
        if let Some(ref path) = self.persistence_path {
            let state = PersistedZeroTrustDhtState {
                records: self.records.clone(),
                pq_records: self.pq_records.clone(),
                catalog_records: self.catalog_records.clone(),
            };
            if let Ok(raw) = bincode::serialize(&state) {
                let _ = BlockStore::atomic_write_file(path, &raw);
            }
        }
    }

    /// Validates and stores a `SignedDhtManifestEnvelope` if and only if:
    /// 1. Its zero-knowledge Ed25519 signature and SHA-256 commitment are valid.
    /// 2. If `dht_key` already exists, `owner_pubkey` matches the original owner AND
    ///    `monotonic_version` is strictly greater than the stored version.
    pub fn put_manifest_envelope(
        &mut self,
        envelope: SignedDhtManifestEnvelope,
    ) -> Result<(), StorageError> {
        if !envelope.verify_zero_knowledge() {
            return Err(StorageError::DhtManifestPoisonedOrRollback);
        }
        if let Some(existing) = self.records.get(&envelope.dht_key) {
            if existing.owner_pubkey != envelope.owner_pubkey
                || envelope.monotonic_version <= existing.monotonic_version
            {
                return Err(StorageError::DhtManifestPoisonedOrRollback);
            }
        }
        self.records.insert(envelope.dht_key, envelope);
        self.persist_if_configured();
        Ok(())
    }

    pub fn get_manifest_envelope(&self, dht_key: &[u8; 32]) -> Option<&SignedDhtManifestEnvelope> {
        self.records.get(dht_key)
    }

    /// Validates and stores a post-quantum `PqSignedDhtManifestEnvelope` (`Ed25519 + ML-DSA-65`)
    /// enforcing composite signature validity, owner key immutability, and strict version monotonicity.
    pub fn put_pq_manifest_envelope(
        &mut self,
        envelope: crate::crypto::PqSignedDhtManifestEnvelope,
    ) -> Result<(), StorageError> {
        if !envelope.verify_zero_knowledge_pq() {
            return Err(StorageError::DhtManifestPoisonedOrRollback);
        }
        if let Some(existing) = self.pq_records.get(&envelope.dht_key) {
            if existing.owner_pq_pubkey != envelope.owner_pq_pubkey
                || envelope.monotonic_version <= existing.monotonic_version
            {
                return Err(StorageError::DhtManifestPoisonedOrRollback);
            }
        }
        self.pq_records.insert(envelope.dht_key, envelope);
        self.persist_if_configured();
        Ok(())
    }

    pub fn get_pq_manifest_envelope(
        &self,
        dht_key: &[u8; 32],
    ) -> Option<&crate::crypto::PqSignedDhtManifestEnvelope> {
        self.pq_records.get(dht_key)
    }

    /// Validates and stores an `EncryptedVaultCatalogEnvelope` (`ADR-15` disaster recovery root catalog)
    /// enforcing Ed25519 signature validity, owner key immutability, and strict version monotonicity.
    pub fn put_vault_catalog_envelope(
        &mut self,
        envelope: crate::sync::EncryptedVaultCatalogEnvelope,
    ) -> Result<(), StorageError> {
        if !envelope.verify_zero_knowledge() {
            return Err(StorageError::DhtManifestPoisonedOrRollback);
        }
        if let Some(existing) = self.catalog_records.get(&envelope.dht_key) {
            if existing.owner_pubkey != envelope.owner_pubkey
                || envelope.monotonic_version <= existing.monotonic_version
            {
                return Err(StorageError::DhtManifestPoisonedOrRollback);
            }
        }
        self.catalog_records.insert(envelope.dht_key, envelope);
        self.persist_if_configured();
        Ok(())
    }

    pub fn get_vault_catalog_envelope(
        &self,
        dht_key: &[u8; 32],
    ) -> Option<&crate::sync::EncryptedVaultCatalogEnvelope> {
        self.catalog_records.get(dht_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_configurable_stripe_sizing_and_interoperable_restore() {
        let dir = tempdir().expect("tempdir");
        let quota = QuotaManager::new(100 * 1024 * 1024, 10 * 1024 * 1024);
        let mut store = BlockStore::new(dir.path(), quota).expect("create BlockStore");

        // Defaults to 16 MiB
        assert_eq!(
            store.stripe_size_bytes(),
            BlockStore::DEFAULT_STRIPE_SIZE_BYTES
        );

        // with_stripe_size_bytes
        store = store.with_stripe_size_bytes(BlockStore::SOC_ROUTER_STRIPE_SIZE_BYTES);
        assert_eq!(store.stripe_size_bytes(), 1024 * 1024);

        // Clamping bounds: min 64 KiB, max 16 MiB
        store.set_stripe_size_bytes(1024);
        assert_eq!(store.stripe_size_bytes(), 64 * 1024);

        store.set_stripe_size_bytes(64 * 1024 * 1024);
        assert_eq!(
            store.stripe_size_bytes(),
            BlockStore::DEFAULT_STRIPE_SIZE_BYTES
        );

        // Set to 1 MiB for tiny-SoC test
        store.set_stripe_size_bytes(BlockStore::SOC_ROUTER_STRIPE_SIZE_BYTES);

        // Create 2.5 MiB payload -> exactly 3 stripes of 1 MiB max
        let payload_len = (2.5 * 1024.0 * 1024.0) as usize;
        let mut original_data = vec![0u8; payload_len];
        for (i, byte) in original_data.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }

        let input_path = dir.path().join("input.bin");
        fs::write(&input_path, &original_data).expect("write input");

        let master_key = MasterKey::generate();
        let manifest = store
            .store_file_streaming(
                "test-owner",
                &input_path,
                &master_key,
                ErasureTier::Consumer,
                0, // passes 0 so store's configured stripe_size_bytes (1 MiB) is used
            )
            .expect("store_file_streaming with 1 MiB stripes");

        assert_eq!(manifest.stripe_size_bytes, 1024 * 1024);
        assert_eq!(manifest.stripes.len(), 3);
        assert_eq!(manifest.original_file_size, payload_len as u64);

        // Restore using a store with default (16 MiB) configuration — must be 100% interoperable
        let restore_dir = tempdir().expect("restore tempdir");
        let restore_store = BlockStore::new(
            restore_dir.path(),
            QuotaManager::new(100 * 1024 * 1024, 10 * 1024 * 1024),
        )
        .expect("restore store");

        // Copy shards from store to restore_store for local retrieval
        for entry in fs::read_dir(store.shards_dir())
            .expect("read shards dir")
            .flatten()
        {
            fs::copy(
                entry.path(),
                restore_store.shards_dir().join(entry.file_name()),
            )
            .expect("copy shard");
        }

        let output_path = restore_dir.path().join("restored.bin");
        restore_store
            .restore_file_streaming(&manifest, &master_key, &output_path)
            .expect("restore_file_streaming");

        let restored_data = fs::read(&output_path).expect("read restored");
        assert_eq!(restored_data.len(), original_data.len());
        assert_eq!(restored_data, original_data);
    }
}
