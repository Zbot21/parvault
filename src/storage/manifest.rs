//! File and stripe manifests and shard ids (client-side: no runtime dependencies).

use crate::crypto::aes::{decrypt_manifest, derive_dht_manifest_key, encrypt_manifest, SALT_LEN};
use crate::crypto::keys::MasterKey;
use crate::profile::ErasureTier;
use crate::sharding::merkle::Hash32;
use crate::storage::error::StorageError;
use serde::{Deserialize, Serialize};

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
    /// Per-shard chunk Merkle roots (`por::chunk_merkle`), index-aligned with `shard_hashes`.
    /// Empty for manifests written before version 2: those shards cannot be chunk-audited.
    #[serde(default)]
    pub shard_chunk_roots: Vec<Hash32>,
}

impl StripeManifestEntry {
    /// Builds the entry for a freshly encoded stripe, computing the chunk roots from its shards.
    pub fn from_shard_set(
        shard_set: crate::sharding::reed_solomon::StripeShardSet,
        assigned_peers: Vec<String>,
    ) -> Self {
        let shard_chunk_roots = crate::por::chunk_merkle::stripe_chunk_roots(&shard_set.shards);
        Self {
            stripe_index: shard_set.stripe_index,
            k_data: shard_set.k_data,
            m_parity: shard_set.m_parity,
            original_ciphertext_len: shard_set.original_ciphertext_len,
            shard_len: shard_set.shard_len,
            stripe_merkle_root: shard_set.stripe_merkle_root,
            shard_hashes: shard_set.shard_hashes,
            assigned_peers,
            shard_chunk_roots,
        }
    }

    /// True when every shard has a chunk root, so the stripe can be chunk-audited.
    pub fn is_chunk_auditable(&self) -> bool {
        !self.shard_hashes.is_empty() && self.shard_chunk_roots.len() == self.shard_hashes.len()
    }
}

/// Current `FileManifest` encoding layout. Version 2 appended `StripeManifestEntry::shard_chunk_roots`.
pub const FILE_MANIFEST_VERSION: u32 = 2;

/// Frozen version-1 layouts, kept only to decode manifests written before chunk roots existed.
/// Never change these structs.
pub mod manifest_v1 {
    use super::{FileManifest, Hash32, StripeManifestEntry, FILE_MANIFEST_VERSION, SALT_LEN};
    use crate::profile::ErasureTier;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct StripeManifestEntryV1 {
        pub stripe_index: u64,
        pub k_data: usize,
        pub m_parity: usize,
        pub original_ciphertext_len: usize,
        pub shard_len: usize,
        pub stripe_merkle_root: Hash32,
        pub shard_hashes: Vec<Hash32>,
        pub assigned_peers: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct FileManifestV1 {
        pub version: u32,
        pub file_merkle_root: Hash32,
        pub file_salt: [u8; SALT_LEN],
        pub original_file_size: u64,
        pub stripe_size_bytes: usize,
        pub tier: ErasureTier,
        pub stripes: Vec<StripeManifestEntryV1>,
        pub witness_peers: Vec<String>,
    }

    impl From<FileManifestV1> for FileManifest {
        /// Converts to the current layout with empty chunk roots (unauditable). The version is
        /// the current one because `version` names the encoding layout, not the audit state.
        fn from(v1: FileManifestV1) -> Self {
            FileManifest {
                version: FILE_MANIFEST_VERSION,
                file_merkle_root: v1.file_merkle_root,
                file_salt: v1.file_salt,
                original_file_size: v1.original_file_size,
                stripe_size_bytes: v1.stripe_size_bytes,
                tier: v1.tier,
                stripes: v1
                    .stripes
                    .into_iter()
                    .map(|e| StripeManifestEntry {
                        stripe_index: e.stripe_index,
                        k_data: e.k_data,
                        m_parity: e.m_parity,
                        original_ciphertext_len: e.original_ciphertext_len,
                        shard_len: e.shard_len,
                        stripe_merkle_root: e.stripe_merkle_root,
                        shard_hashes: e.shard_hashes,
                        assigned_peers: e.assigned_peers,
                        shard_chunk_roots: Vec::new(),
                    })
                    .collect(),
                witness_peers: v1.witness_peers,
            }
        }
    }
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
        if self.version != FILE_MANIFEST_VERSION {
            return Err(StorageError::ManifestFormat(format!(
                "refusing to encode FileManifest version {} in the version {} layout",
                self.version, FILE_MANIFEST_VERSION
            )));
        }
        self.check_chunk_roots_aligned()?;
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
        Self::decode_bytes(&raw)
    }

    /// Decodes a bincode `FileManifest` of any known version. The leading `u32` version selects
    /// the layout: version 1 decodes through the frozen [`manifest_v1`] structs with empty chunk
    /// roots; version 2 must carry either no chunk roots or one per shard in every stripe.
    pub fn decode_bytes(raw: &[u8]) -> Result<Self, StorageError> {
        let version = raw
            .get(..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| {
                StorageError::ManifestFormat("FileManifest shorter than its version".into())
            })?;
        match version {
            1 => Ok(bincode::deserialize::<manifest_v1::FileManifestV1>(raw)?.into()),
            FILE_MANIFEST_VERSION => {
                let manifest: Self = bincode::deserialize(raw)?;
                manifest.check_chunk_roots_aligned()?;
                Ok(manifest)
            }
            other => Err(StorageError::ManifestFormat(format!(
                "unknown FileManifest version {other}"
            ))),
        }
    }

    /// Every stripe carries either no chunk roots (written before version 2) or one per shard.
    pub fn check_chunk_roots_aligned(&self) -> Result<(), StorageError> {
        for e in &self.stripes {
            if !e.shard_chunk_roots.is_empty() && e.shard_chunk_roots.len() != e.shard_hashes.len()
            {
                return Err(StorageError::ManifestFormat(format!(
                    "stripe {} has {} chunk roots for {} shards",
                    e.stripe_index,
                    e.shard_chunk_roots.len(),
                    e.shard_hashes.len()
                )));
            }
        }
        Ok(())
    }
}
