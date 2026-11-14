//! Client-side ring admission (v0.5.0, bootstrap option A).
//!
//! A ring is one Web-of-Trust genesis, created by an explicit `parvault wot init` (or provided as
//! `PARVAULT_GENESIS_SEED_HEX`). A process that holds the genesis secret self-issues a one-hop
//! `DelegationChain` for any identity it sends as. Every other node installs a ring invitation
//! (`parvault wot invite` on a holder, `parvault wot install-chain` on the invitee): the chain for
//! its node key, stored in `data_dir/wot_chains/<leaf-pubkey-hex>.bin`, and the ring's genesis
//! public key, pinned in `data_dir/ring_genesis.pub`. Its other keys (the owner key) get a
//! one-hop extension signed by the node key.
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
    /// The node key, which extends its installed chain by one hop for the node's other keys.
    node: Option<NodeIdentity>,
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
        node: None,
        public_ticket_bits: None,
    }))
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The genesis secret this process holds, if any (never generated).
fn held_genesis(data_dir: Option<&Path>) -> Option<NodeIdentity> {
    let dir = data_dir.map(Path::to_path_buf).unwrap_or_else(|| {
        // No data directory: only the environment can provide the secret.
        std::env::temp_dir().join("parvault-no-data-dir")
    });
    NodeIdentity::load_ring_genesis_identity_in_dir(&dir)
        .ok()
        .flatten()
}

/// The node identity in `data_dir`, if one exists (never generated here).
fn existing_node_identity(data_dir: &Path) -> Option<NodeIdentity> {
    data_dir
        .join("node_identity.seed")
        .exists()
        .then(|| NodeIdentity::load_or_generate_in_dir(data_dir).ok())
        .flatten()
}

/// Trusted voucher issuer of a node outside any ring. The all-zero key is a small-order point;
/// strict verification accepts no signature under it, so no voucher verifies (F-37). It is never
/// used as a genesis.
pub const NO_RING_ISSUER: [u8; 32] = [0u8; 32];

/// The ring genesis a server runs with, or `None` for a node outside any ring (F-37: there is
/// no placeholder genesis). Conflicting sources are always an error; a node with no source runs
/// ticket-only in public-commons mode (it admits no chain) and otherwise refuses to start.
pub fn server_ring_genesis(
    data_dir: &Path,
    configured_pubkey_hex: Option<&str>,
    public_commons: bool,
) -> anyhow::Result<Option<[u8; 32]>> {
    match NodeIdentity::resolve_genesis_root_pubkey_in_dir(data_dir, configured_pubkey_hex) {
        Ok(pk) => Ok(Some(pk)),
        Err(e) => {
            let msg = e.to_string();
            if public_commons && msg.contains(crate::crypto::keys::NOT_IN_RING_MESSAGE) {
                tracing::info!(
                    "not in a private ring: admitting peers by public-commons ticket only"
                );
                Ok(None)
            } else {
                anyhow::bail!("{msg}")
            }
        }
    }
}

/// What `parvault wot invite` hands to an invitee: the ring's genesis public key and the chain
/// for the invitee's key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RingInvitation {
    pub genesis_pubkey: [u8; 32],
    pub chain: DelegationChain,
}

impl RingInvitation {
    pub fn encode_hex(&self) -> anyhow::Result<String> {
        Ok(hex::encode(bincode::serialize(self)?))
    }

    pub fn decode_hex(token: &str) -> anyhow::Result<Self> {
        use bincode::Options;
        let bytes = hex::decode(token.trim())?;
        Ok(bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(64 * 1024)
            .deserialize(&bytes)?)
    }
}

impl AdmissionSource {
    /// Chains under `data_dir/wot_chains`, genesis from the environment or `data_dir`.
    pub fn from_data_dir(data_dir: &Path) -> Self {
        Self {
            chain_dir: Some(data_dir.join(CHAIN_DIR_NAME)),
            genesis: held_genesis(Some(data_dir)),
            node: existing_node_identity(data_dir),
            public_ticket_bits: None,
        }
    }

    /// A source that self-issues from `genesis` and stores nothing.
    pub fn from_genesis(genesis: NodeIdentity) -> Self {
        Self {
            chain_dir: None,
            genesis: Some(genesis),
            node: None,
            public_ticket_bits: None,
        }
    }

    /// A source with one fixed chain directory and no genesis.
    pub fn from_chain_dir(dir: PathBuf) -> Self {
        Self {
            chain_dir: Some(dir),
            genesis: None,
            node: None,
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
    ///
    /// A ticket is bound to `verifier` (the peer's Ed25519 key) and minted at `required_bits`
    /// when the peer stated them, else at this source's default.
    pub fn credential(
        &self,
        identity: &NodeIdentity,
        verifier: [u8; 32],
        required_bits: Option<u8>,
    ) -> Option<AdmissionCredential> {
        if let Some(chain) = self.credential_for(identity) {
            return Some(AdmissionCredential::Chain(chain));
        }
        let bits = required_bits.or(self.public_ticket_bits)?;
        self.public_ticket_bits?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Some(AdmissionCredential::Ticket(PublicCommonsTicket::mint(
            identity, verifier, now_ms, bits,
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
        if let Some(g) = self.genesis.as_ref() {
            return Some(issue_invitation(g, leaf));
        }
        // A member node extends its own chain by one hop for its other keys (the owner key).
        let node = self.node.as_ref()?;
        if node.public_key_bytes() == leaf {
            return None;
        }
        let mut chain = self.installed_chain(&node.public_key_bytes())?;
        let depth = chain.hops.len() as u32 + 1;
        chain
            .hops
            .push(InvitationHop::issue(node, leaf, depth, unix_secs()));
        Some(chain)
    }

    fn installed_chain(&self, leaf: &[u8; 32]) -> Option<DelegationChain> {
        let bytes = std::fs::read(self.chain_path(leaf)?).ok()?;
        let chain = decode_chain(&bytes).ok()?;
        (chain.leaf_pubkey() == Some(*leaf)).then_some(chain)
    }

    /// Checks a chain's links and signatures; returns its leaf key.
    pub fn check_chain(&self, chain: &DelegationChain) -> anyhow::Result<[u8; 32]> {
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
        Ok(leaf)
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

    /// F-38 (QA r3): a member holding no genesis extends its installed chain one hop for its
    /// vault key (genesis -> member -> vault), and the chain checks out.
    #[test]
    fn member_extends_its_chain_for_the_vault_key() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = NodeIdentity::from_seed([0x47; 32]);
        let member = NodeIdentity::from_seed([0xCD; 32]);
        let vault = NodeIdentity::from_seed([0xCE; 32]);
        let source = AdmissionSource {
            chain_dir: Some(dir.path().to_path_buf()),
            genesis: None,
            node: Some(member.clone()),
            public_ticket_bits: None,
        };
        source
            .store_chain(&issue_invitation(&genesis, member.public_key_bytes()))
            .unwrap();
        assert!(source
            .credential_for(&member)
            .is_some_and(|c| c.hops.len() == 1));
        let chain = source.credential_for(&vault).expect("one-hop extension");
        assert_eq!(chain.hops.len(), 2);
        assert_eq!(chain.hops[1].inviter_pubkey, member.public_key_bytes());
        assert_eq!(chain.leaf_pubkey(), Some(vault.public_key_bytes()));
        assert_eq!(
            source.check_chain(&chain).unwrap(),
            vault.public_key_bytes()
        );
    }
}
