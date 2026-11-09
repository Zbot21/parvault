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
        let msg = Self::canonical_bytes(
            &departing_peer_id,
            &departing_pubkey,
            migrated_shards_count,
            migrated_blinded_shards_count,
            total_bytes_handed_off,
            &handoff_manifest_sha256,
            true,
            departure_timestamp_ms,
        );
        let sig = identity.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);
        Self {
            departing_peer_id,
            departing_pubkey,
            migrated_shards_count,
            migrated_blinded_shards_count,
            total_bytes_handed_off,
            handoff_manifest_sha256,
            earned_standing_preserved: true,
            departure_timestamp_ms,
            sig_r,
            sig_s,
        }
    }

    pub fn verify_signature(&self) -> bool {
        let msg = Self::canonical_bytes(
            &self.departing_peer_id,
            &self.departing_pubkey,
            self.migrated_shards_count,
            self.migrated_blinded_shards_count,
            self.total_bytes_handed_off,
            &self.handoff_manifest_sha256,
            self.earned_standing_preserved,
            self.departure_timestamp_ms,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.departing_pubkey, &msg, &sig)
    }

    #[allow(clippy::too_many_arguments)]
    fn canonical_bytes(
        departing_peer_id: &str,
        departing_pubkey: &[u8; 32],
        migrated_shards_count: usize,
        migrated_blinded_shards_count: usize,
        total_bytes_handed_off: u64,
        handoff_manifest_sha256: &[u8; 32],
        earned_standing_preserved: bool,
        departure_timestamp_ms: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(b"parvault-graceful-departure-v1:");
        buf.extend_from_slice(departing_peer_id.as_bytes());
        buf.extend_from_slice(departing_pubkey);
        buf.extend_from_slice(&(migrated_shards_count as u64).to_be_bytes());
        buf.extend_from_slice(&(migrated_blinded_shards_count as u64).to_be_bytes());
        buf.extend_from_slice(&total_bytes_handed_off.to_be_bytes());
        buf.extend_from_slice(handoff_manifest_sha256);
        buf.push(u8::from(earned_standing_preserved));
        buf.extend_from_slice(&departure_timestamp_ms.to_be_bytes());
        buf
    }
}

/// Unique content-addressed identifier for an individual Reed-Solomon shard.
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

/// Local NVMe / USB sharded block storage engine (`storage::block_store`).
#[derive(Clone)]
pub struct BlockStore {
    root_dir: PathBuf,
    shards_dir: PathBuf,
    manifests_dir: PathBuf,
    quota: Arc<Mutex<QuotaManager>>,
    blinded_leases: Arc<Mutex<BlindedShardLeaseManager>>,
    blinded_id_by_locator: Arc<Mutex<HashMap<[u8; 32], BlindedShardId>>>,
}

impl BlockStore {
    pub fn new(root_dir: impl AsRef<Path>, quota: QuotaManager) -> Result<Self, StorageError> {
        let root_dir = root_dir.as_ref().to_path_buf();
        let shards_dir = root_dir.join("shards");
        let manifests_dir = root_dir.join("manifests");
        fs::create_dir_all(&shards_dir)?;
        fs::create_dir_all(&manifests_dir)?;
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

        Ok(Self {
            root_dir,
            shards_dir,
            manifests_dir,
            quota: Arc::new(Mutex::new(quota)),
            blinded_leases: Arc::new(Mutex::new(initial_leases)),
            blinded_id_by_locator: Arc::new(Mutex::new(initial_id_map)),
        })
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
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rnd);
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

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
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

        Ok(path)
    }

    /// Reads an entire shard from disk and verifies its SHA-256 leaf digest.
    /// Note: For remote requests, callers MUST verify a valid `RepairGrant` or owner token first (ADR-04).
    pub fn get_shard(&self, id: &ShardId) -> Result<Vec<u8>, StorageError> {
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

    /// Reads a bounded byte sub-range `[offset .. offset + length]` from a shard on disk.
    /// Used exclusively by `por::verifier` AFTER stateless RAM-only HMAC pre-verification passes (ADR-03).
    pub fn get_shard_range(
        &self,
        id: &ShardId,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StorageError> {
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

    /// Deletes a shard from local disk storage.
    pub fn delete_shard(&self, owner_peer_id: &str, id: &ShardId) -> Result<bool, StorageError> {
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
            1,
            30,
            [0u8; 32],
        )
    }

    /// Persists an anonymized `BlindedShardId` to `{locator}.bshard` on disk with an explicit
    /// Byte-Epoch lease (`current_epoch + lease_duration_epochs`) and `delete_verifier` (`ADR-11` + `ADR-13`).
    /// If disk capacity is reached, automatically evicts and physically unlinks expired `.bshard` files on disk.
    #[allow(clippy::too_many_arguments)]
    pub fn put_blinded_shard_with_lease(
        &self,
        blinded_id: &BlindedShardId,
        shard_bytes: &[u8],
        capability: BlindedShardCapability,
        voucher: &AnonymousQuotaVoucher,
        nullifier_ledger: &mut VoucherNullifierLedger,
        current_epoch: u64,
        lease_duration_epochs: u64,
        delete_verifier: [u8; 32],
    ) -> Result<PathBuf, StorageError> {
        if capability.locator != blinded_id.locator {
            return Err(StorageError::QuotaExceeded(
                "mismatched_blinded_capability_locator".into(),
            ));
        }
        let actual_sha = compute_sha256(shard_bytes);
        if actual_sha != blinded_id.content_sha256 {
            return Err(StorageError::CorruptedShard);
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

    /// Time-driven eviction sweep: physically deletes all `.bshard` files on disk whose
    /// `lease_expires_epoch + grace_epochs <= current_epoch` (belonging to nodes that left the network)
    /// and returns the list of deleted `BlindedShardId`s.
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
                    let p = self.shards_dir.join(format!("{}.bshard", bid.file_key()));
                    if p.exists() {
                        fs::remove_file(&p)?;
                    }
                    deleted_ids.push(bid);
                }
            }
        }
        self.persist_blinded_lease_state();
        Ok(deleted_ids)
    }

    /// Immediately verifies a `BlindedShardTombstone` and physically deletes `{locator}.bshard` from disk.
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
        let path = self
            .shards_dir
            .join(format!("{}.bshard", blinded_id.file_key()));
        if path.exists() {
            fs::remove_file(&path)?;
        }
        self.persist_blinded_lease_state();
        Ok(true)
    }

    /// Checks whether a `.bshard` file physically exists on the storage node's filesystem.
    pub fn has_blinded_shard_on_disk(&self, blinded_id: &BlindedShardId) -> bool {
        self.shards_dir
            .join(format!("{}.bshard", blinded_id.file_key()))
            .exists()
    }

    /// Reads an anonymized `BlindedShardId` from disk if and only if the caller presents a valid
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
            vec![default_mesh_pool]
        } else {
            target_handoff_dirs.to_vec()
        };

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
            let target_shards_dir = target_root.join("shards");
            fs::create_dir_all(&target_shards_dir)?;
            let dest_path = target_shards_dir.join(&fname);
            Self::atomic_write_file(&dest_path, &bytes)?;

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

    /// Saves a `FileManifest` to local disk (encrypted under `master_key`).
    pub fn save_manifest(
        &self,
        master_key: &MasterKey,
        manifest: &FileManifest,
    ) -> Result<PathBuf, StorageError> {
        let (_, encrypted) = manifest.to_encrypted_dht_record(master_key)?;
        let path = self.manifest_path(&manifest.file_merkle_root);
        Self::atomic_write_file(&path, &encrypted)?;
        Ok(path)
    }

    /// Loads and decrypts a `FileManifest` by its 32-byte File Merkle Root.
    pub fn load_manifest(
        &self,
        master_key: &MasterKey,
        file_merkle_root: &Hash32,
    ) -> Result<FileManifest, StorageError> {
        let path = self.manifest_path(file_merkle_root);
        let encrypted = fs::read(path)?;
        FileManifest::from_encrypted_dht_record(master_key, &encrypted)
    }

    /// Streams a file from `input_path` in fixed `stripe_size_bytes` segments (16 MiB default per ADR-01),
    /// encrypts each stripe with AES-256-GCM prior to Reed-Solomon splitting, persists all `N` shards,
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
        let stripe_cap = stripe_size_bytes.max(1024);

        let mut stripes = Vec::new();
        let mut stripe_roots = Vec::new();
        let mut stripe_index: u64 = 0;

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

            // 3. Persist shards into BlockStore.
            for (idx, shard_bytes) in shard_set.shards.iter().enumerate() {
                let shard_id = ShardId {
                    stripe_merkle_root: shard_set.stripe_merkle_root,
                    shard_index: idx as u32,
                    shard_hash: shard_set.shard_hashes[idx],
                };
                self.put_shard(owner_peer_id, &shard_id, shard_bytes)?;
            }

            let (_, _, n_total) = tier.params();
            stripes.push(StripeManifestEntry {
                stripe_index,
                k_data: shard_set.k_data,
                m_parity: shard_set.m_parity,
                original_ciphertext_len: shard_set.original_ciphertext_len,
                shard_len: shard_set.shard_len,
                stripe_merkle_root: shard_set.stripe_merkle_root,
                shard_hashes: shard_set.shard_hashes,
                assigned_peers: vec![owner_peer_id.to_string(); n_total],
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

    /// Reconstructs and decrypts a file from its `FileManifest` using at least `K` surviving
    /// shards per stripe, writing the verified plaintext to `output_path`.
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

        for stripe in &manifest.stripes {
            let total_shards = stripe.k_data + stripe.m_parity;
            let mut shard_slots: Vec<Option<Vec<u8>>> = Vec::with_capacity(total_shards);

            for idx in 0..total_shards {
                let id = ShardId {
                    stripe_merkle_root: stripe.stripe_merkle_root,
                    shard_index: idx as u32,
                    shard_hash: stripe.shard_hashes[idx],
                };
                match self.get_shard(&id) {
                    Ok(bytes) => shard_slots.push(Some(bytes)),
                    Err(_) => shard_slots.push(None),
                }
            }

            // Reconstruct ciphertext in GF(2^8) from >= K surviving shards and verify Merkle root.
            let ciphertext = reconstruct_ciphertext_stripe(
                shard_slots,
                stripe.k_data,
                stripe.m_parity,
                stripe.original_ciphertext_len,
                Some(&stripe.shard_hashes),
                Some(stripe.stripe_merkle_root),
            )?;

            // Authenticate and decrypt AES-256-GCM stripe.
            let plaintext = decrypt_stripe(
                master_key,
                &manifest.file_salt,
                stripe.stripe_index,
                &ciphertext,
            )?;

            out_file.write_all(&plaintext)?;
        }

        out_file.flush()?;
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

/// Zero-Trust Kademlia DHT Manifest Table enforcing Ed25519 key ownership and strict version
/// monotonicity (`new.monotonic_version > existing.monotonic_version`) to block poisoning and rollbacks.
#[derive(Debug, Default, Clone)]
pub struct ZeroTrustDhtStore {
    records: HashMap<[u8; 32], SignedDhtManifestEnvelope>,
    pq_records: HashMap<[u8; 32], crate::crypto::PqSignedDhtManifestEnvelope>,
    catalog_records: HashMap<[u8; 32], crate::sync::EncryptedVaultCatalogEnvelope>,
}

impl ZeroTrustDhtStore {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            pq_records: HashMap::new(),
            catalog_records: HashMap::new(),
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
        Ok(())
    }

    pub fn get_vault_catalog_envelope(
        &self,
        dht_key: &[u8; 32],
    ) -> Option<&crate::sync::EncryptedVaultCatalogEnvelope> {
        self.catalog_records.get(dht_key)
    }
}
