//! Storage error type (client-side: no runtime dependencies).

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
    /// A blinded-shard read, delete or re-put that its capability does not authorise. One
    /// variant and one text for every cause (rebind, no capability, key mismatch, stale, bad
    /// signature), so a refusal never tells a stranger whether a legacy entry exists (QA 2c).
    #[error("unauthorized")]
    Unauthorized,
    #[error("Shard integrity hash mismatch")]
    CorruptedShard,
    #[error("Rejected DHT manifest update: invalid owner Ed25519 signature or version rollback")]
    DhtManifestPoisonedOrRollback,
    #[error("Rejected unsafe or path-traversal restore path: {0}")]
    InvalidRestorePath(String),
    #[error("Malformed or unknown FileManifest encoding: {0}")]
    ManifestFormat(String),
}
