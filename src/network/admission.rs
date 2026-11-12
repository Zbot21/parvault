//! Client-side ring admission (v0.5.0, bootstrap option A).
//!
//! A ring is one Web-of-Trust genesis. A process that holds the genesis seed
//! (`PARVAULT_GENESIS_SEED_HEX`, or `data_dir/genesis_root.seed`) self-issues a one-hop
//! `DelegationChain` for any identity it sends as. Every other process installs a chain
//! issued for it (`parvault wot invite` on a seed holder, `parvault wot install-chain` on the
//! invitee); installed chains live in `data_dir/wot_chains/<leaf-pubkey-hex>.bin`.
//!
//! `MeshClient` presents the chain in a `HandshakeWoT` once per (identity, peer address) before
//! the first request that needs an admitted sender ([`requires_admitted_sender`]). The same chain
//! format is what a later pairing exchange would issue, so a pairing flow only has to call
//! [`AdmissionSource::store_chain`] with the chain it receives.

use crate::crypto::NodeIdentity;
use crate::network::behaviour::MeshWireRequest;
use crate::network::wot::{
    DelegationChain, InvitationHop, PublicCommonsTicket, DEFAULT_PUBLIC_WOT_POW_BITS,
};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Directory (under the data directory) holding installed chains, one file per leaf key.
pub const CHAIN_DIR_NAME: &str = "wot_chains";

/// Where this process finds admission credentials.
#[derive(Clone, Default)]
pub struct AdmissionSource {
    chain_dir: Option<PathBuf>,
    genesis: Option<NodeIdentity>,
    /// In public-commons or hybrid mode, the PoW bits of a ticket minted when no chain exists.
    public_ticket_bits: Option<u8>,
}

/// What a client presents to be admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionCredential {
    /// A ring member's delegation chain (`HandshakeWoT`).
    Chain(DelegationChain),
    /// A probationary public-commons ticket (`AdmitPublicTicket`).
    Ticket(PublicCommonsTicket),
}

impl std::fmt::Debug for AdmissionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionSource")
            .field("chain_dir", &self.chain_dir)
            .field("holds_genesis", &self.genesis.is_some())
            .field("public_ticket_bits", &self.public_ticket_bits)
            .finish()
    }
}

static PROCESS_SOURCE: OnceLock<AdmissionSource> = OnceLock::new();

/// Sets the process-wide source from `data_dir` (first call wins). Binaries call this once at
/// startup; every `MeshClient` without an explicit source uses it. `public_commons` lets the
/// process fall back to a public-commons ticket when it holds no chain.
pub fn install_process_source(data_dir: &Path, public_commons: bool) {
    let mut source = AdmissionSource::from_data_dir(data_dir);
    if public_commons {
        source = source.with_public_tickets(DEFAULT_PUBLIC_WOT_POW_BITS);
    }
    let _ = PROCESS_SOURCE.set(source);
}

/// The process-wide source: the one a binary installed, else (first use) a source that only
/// self-issues from `PARVAULT_GENESIS_SEED_HEX`.
pub fn process_source() -> Option<&'static AdmissionSource> {
    Some(PROCESS_SOURCE.get_or_init(|| AdmissionSource {
        chain_dir: None,
        genesis: held_genesis(None),
        public_ticket_bits: None,
    }))
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Loads the genesis identity without generating one: `PARVAULT_GENESIS_SEED_HEX`, else an
/// existing `data_dir/genesis_root.seed`.
fn held_genesis(data_dir: Option<&Path>) -> Option<NodeIdentity> {
    let env_seed = std::env::var("PARVAULT_GENESIS_SEED_HEX")
        .ok()
        .filter(|s| !s.trim().is_empty());
    if env_seed.is_none() {
        let dir = data_dir?;
        if !dir.join("genesis_root.seed").exists() {
            return None;
        }
        return NodeIdentity::load_or_generate_genesis_identity_in_dir(dir, None).ok();
    }
    let dir = data_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    NodeIdentity::load_or_generate_genesis_identity_in_dir(&dir, None).ok()
}

impl AdmissionSource {
    /// Chains under `data_dir/wot_chains`, genesis from the environment or `data_dir`.
    pub fn from_data_dir(data_dir: &Path) -> Self {
        Self {
            chain_dir: Some(data_dir.join(CHAIN_DIR_NAME)),
            genesis: held_genesis(Some(data_dir)),
            public_ticket_bits: None,
        }
    }

    /// A source that self-issues from `genesis` and stores nothing.
    pub fn from_genesis(genesis: NodeIdentity) -> Self {
        Self {
            chain_dir: None,
            genesis: Some(genesis),
            public_ticket_bits: None,
        }
    }

    /// A source with one fixed chain directory and no genesis.
    pub fn from_chain_dir(dir: PathBuf) -> Self {
        Self {
            chain_dir: Some(dir),
            genesis: None,
            public_ticket_bits: None,
        }
    }

    /// Falls back to a public-commons ticket of `pow_bits` when no chain is available.
    pub fn with_public_tickets(mut self, pow_bits: u8) -> Self {
        self.public_ticket_bits = Some(pow_bits);
        self
    }

    /// The one place a client chooses how to be admitted: a chain when it has one, else a
    /// public-commons ticket when the process runs in public or hybrid mode.
    pub fn credential(&self, identity: &NodeIdentity) -> Option<AdmissionCredential> {
        if let Some(chain) = self.credential_for(identity) {
            return Some(AdmissionCredential::Chain(chain));
        }
        let bits = self.public_ticket_bits?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Some(AdmissionCredential::Ticket(PublicCommonsTicket::mint(
            identity, now_ms, bits,
        )))
    }

    /// Whether this source holds the ring genesis (can self-issue and invite).
    pub fn holds_genesis(&self) -> bool {
        self.genesis.is_some()
    }

    fn chain_path(&self, leaf: &[u8; 32]) -> Option<PathBuf> {
        self.chain_dir
            .as_ref()
            .map(|d| d.join(format!("{}.bin", hex::encode(leaf))))
    }

    /// The chain `identity` presents: an installed one, else a self-issued one-hop chain.
    pub fn credential_for(&self, identity: &NodeIdentity) -> Option<DelegationChain> {
        let leaf = identity.public_key_bytes();
        if let Some(path) = self.chain_path(&leaf) {
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(chain) = decode_chain(&bytes) {
                    if chain.leaf_pubkey() == Some(leaf) {
                        return Some(chain);
                    }
                }
            }
        }
        self.genesis.as_ref().map(|g| issue_invitation(g, leaf))
    }

    /// Installs `chain` (its leaf names the file). Returns the leaf key.
    pub fn store_chain(&self, chain: &DelegationChain) -> anyhow::Result<[u8; 32]> {
        let leaf = chain
            .leaf_pubkey()
            .ok_or_else(|| anyhow::anyhow!("empty delegation chain"))?;
        for (idx, hop) in chain.hops.iter().enumerate() {
            anyhow::ensure!(hop.verify_signature(), "invalid hop signature at {idx}");
            if idx > 0 {
                anyhow::ensure!(
                    hop.inviter_pubkey == chain.hops[idx - 1].invitee_pubkey,
                    "broken chain link at {idx}"
                );
            }
        }
        let path = self
            .chain_path(&leaf)
            .ok_or_else(|| anyhow::anyhow!("no chain directory configured"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::storage::BlockStore::atomic_write_file(&path, &encode_chain(chain)?)?;
        Ok(leaf)
    }
}

/// A one-hop chain from `genesis` to `invitee`.
pub fn issue_invitation(genesis: &NodeIdentity, invitee: [u8; 32]) -> DelegationChain {
    DelegationChain {
        hops: vec![InvitationHop::issue(genesis, invitee, 1, unix_secs())],
    }
}

pub fn encode_chain(chain: &DelegationChain) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::serialize(chain)?)
}

pub fn decode_chain(bytes: &[u8]) -> anyhow::Result<DelegationChain> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(64 * 1024)
        .deserialize(bytes)?)
}

/// Requests whose sender must be admitted (v0.5.0). Mirrors the server's admission classes;
/// an onion relay request may be a final delivery, which the receiver checks.
pub const fn requires_admitted_sender(request: &MeshWireRequest) -> bool {
    matches!(
        request,
        MeshWireRequest::PutShard { .. }
            | MeshWireRequest::SyndicateLiteStripe { .. }
            | MeshWireRequest::PutDhtEnvelope(_)
            | MeshWireRequest::PutBlindedShard { .. }
            | MeshWireRequest::RelayPqOnionEnvelope { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_issue_and_install_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = NodeIdentity::from_seed([7; 32]);
        let me = NodeIdentity::from_seed([8; 32]);
        let issuer = AdmissionSource::from_genesis(genesis.clone());
        let chain = issuer.credential_for(&me).unwrap();
        assert_eq!(chain.leaf_pubkey(), Some(me.public_key_bytes()));
        assert_eq!(chain.hops[0].inviter_pubkey, genesis.public_key_bytes());

        let holder = AdmissionSource::from_chain_dir(dir.path().join(CHAIN_DIR_NAME));
        assert!(holder.credential_for(&me).is_none());
        assert_eq!(holder.store_chain(&chain).unwrap(), me.public_key_bytes());
        assert_eq!(holder.credential_for(&me), Some(chain));
        let other = NodeIdentity::from_seed([9; 32]);
        assert!(holder.credential_for(&other).is_none());
    }

    #[test]
    fn store_rejects_a_forged_hop() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = NodeIdentity::from_seed([7; 32]);
        let mut chain = issue_invitation(&genesis, [1; 32]);
        chain.hops[0].invitee_pubkey = [2; 32];
        let holder = AdmissionSource::from_chain_dir(dir.path().to_path_buf());
        assert!(holder.store_chain(&chain).is_err());
    }
}
