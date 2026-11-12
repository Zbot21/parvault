use crate::crypto::keys::NodeIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Maximum invalid handshakes or unexcused PoR audit failures before immediate leaf isolation.
pub const MAX_LEAF_FAILURES: u32 = 3;

/// Default parent branch slash threshold (`M`) before pruning an entire delegated subtree.
pub const DEFAULT_SUBTREE_SLASH_LIMIT: u32 = 5;

/// Maximum delegation depth from Genesis Root key.
pub const MAX_DELEGATION_DEPTH: u32 = 8;

/// Maximum number of seen slashing evidence tuples retained in the bounded RAM anti-replay FIFO.
pub const MAX_SEEN_SLASHING_NONCES: usize = 65_536;

/// Maximum number of probationary Public Commons peer tickets retained in bounded RAM.
pub const MAX_PUBLIC_COMMONS_PEERS: usize = 65_536;

/// Default Hashcash Proof-of-Work difficulty (in leading zero bits) for `PublicCommonsTicket`
/// zero-pairing admission (~0.5–2 ms on tiny router SoCs).
pub const DEFAULT_PUBLIC_WOT_POW_BITS: u8 = 12;

/// Domain separator for `PublicCommonsTicket` Hashcash PoW and Ed25519 self-attestation.
pub const PUBLIC_COMMONS_POW_DOMAIN: &[u8] = b"parvault-public-wot-pow-v1:";

/// Canonical deterministic seed domain for open Public Commons trackers (`ADR-18`).
pub const PUBLIC_COMMONS_GENESIS_SEED_DOMAIN: &[u8] = b"parvault-public-commons-open-wot-v1";

const fn default_public_wot_pow_bits() -> u8 {
    DEFAULT_PUBLIC_WOT_POW_BITS
}

/// Trust admission mode for a `WebOfTrustRegistry` pool (`ADR-18`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TrustPoolMode {
    /// Strict Private Ring-of-Trust: only peers presenting a valid `DelegationChain`
    /// anchored at `genesis_pubkey` are admitted; `PublicCommonsTicket` is rejected.
    #[default]
    #[serde(alias = "private", alias = "private-ring", alias = "private_ring")]
    PrivateRing,
    /// Open BitTorrent-Tracker-style Public Commons: admits strangers presenting a valid
    /// self-signed Hashcash PoW `PublicCommonsTicket` (`>= min_public_pow_bits`).
    #[serde(
        alias = "public",
        alias = "public-commons",
        alias = "public_commons",
        alias = "public-tracker",
        alias = "public_tracker"
    )]
    PublicCommons,
    /// Hybrid mode: admits both `PrivateRing` `DelegationChain` peers and `PublicCommonsTicket`
    /// probationary public peers while tracking their admission origin separately.
    #[serde(alias = "hybrid")]
    Hybrid,
}

impl TrustPoolMode {
    /// Returns `true` when `PublicCommonsTicket` zero-pairing admission is enabled.
    pub const fn allows_public_commons(self) -> bool {
        matches!(self, Self::PublicCommons | Self::Hybrid)
    }

    /// Canonical lowercase configuration string (`"private"`, `"public"`, or `"hybrid"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateRing => "private",
            Self::PublicCommons => "public",
            Self::Hybrid => "hybrid",
        }
    }
}

impl fmt::Display for TrustPoolMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TrustPoolMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "private" | "private-ring" | "private_ring" | "privatering" => Ok(Self::PrivateRing),
            "public" | "public-commons" | "public_commons" | "publiccommons" | "public-tracker"
            | "public_tracker" => Ok(Self::PublicCommons),
            "hybrid" => Ok(Self::Hybrid),
            other => Err(format!(
                "invalid trust pool mode '{other}' (expected 'private', 'public', or 'hybrid')"
            )),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebOfTrustError {
    #[error("Empty delegation chain")]
    EmptyChain,
    #[error("Delegation chain root does not match trusted Genesis public key")]
    UntrustedGenesisRoot,
    #[error("Delegation chain depth {0} exceeds maximum {MAX_DELEGATION_DEPTH}")]
    MaxDepthExceeded(u32),
    #[error("Broken invitation link at hop {0}")]
    BrokenChainLink(usize),
    #[error("Invalid Ed25519 signature at hop {0}")]
    InvalidHopSignature(usize),
    #[error("Peer or parent branch is quarantined / slashed")]
    QuarantinedSubtree,
    #[error("Public Commons admission is disabled in PrivateRing trust mode")]
    PublicCommonsDisabled,
    #[error("Peer public key has been slashed or quarantined")]
    RevokedPeer,
    #[error("Public Commons ticket failed signature or Hashcash PoW verification")]
    InsufficientPublicPow,
}

/// Alias for [`WebOfTrustError`] used by Public Commons WoT admission APIs.
pub type WotError = WebOfTrustError;

/// Self-signed Hashcash Proof-of-Work admission ticket allowing any stranger node to join a
/// `PublicCommons` or `Hybrid` pool without pre-pairing or join codes (`ADR-18`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PublicCommonsTicket {
    pub peer_pubkey: [u8; 32],
    pub timestamp_ms: u64,
    pub pow_bits: u8,
    pub pow_nonce: u64,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl PublicCommonsTicket {
    /// Computes `SHA-256("parvault-public-wot-pow-v1:" || peer_pubkey || timestamp_ms.to_be_bytes() || pow_nonce.to_be_bytes())`.
    pub fn pow_digest(peer_pubkey: &[u8; 32], timestamp_ms: u64, pow_nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PUBLIC_COMMONS_POW_DOMAIN);
        hasher.update(peer_pubkey);
        hasher.update(timestamp_ms.to_be_bytes());
        hasher.update(pow_nonce.to_be_bytes());
        hasher.finalize().into()
    }

    /// Counts leading zero bits in a 256-bit SHA-256 digest.
    pub fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
        let mut total = 0u32;
        for &byte in digest {
            if byte == 0 {
                total += 8;
            } else {
                total += byte.leading_zeros();
                break;
            }
        }
        total
    }

    /// Canonical domain-separated signing payload covering all ticket fields.
    pub fn canonical_sign_bytes(
        peer_pubkey: &[u8; 32],
        timestamp_ms: u64,
        pow_bits: u8,
        pow_nonce: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PUBLIC_COMMONS_POW_DOMAIN.len() + 32 + 8 + 1 + 8);
        buf.extend_from_slice(PUBLIC_COMMONS_POW_DOMAIN);
        buf.extend_from_slice(peer_pubkey);
        buf.extend_from_slice(&timestamp_ms.to_be_bytes());
        buf.push(pow_bits);
        buf.extend_from_slice(&pow_nonce.to_be_bytes());
        buf
    }

    /// Mints a self-signed Hashcash PoW admission ticket by iterating `pow_nonce` until
    /// `SHA-256("parvault-public-wot-pow-v1:" || peer_pubkey || timestamp_ms.to_be_bytes() || pow_nonce.to_be_bytes())`
    /// has `>= min_pow_bits` leading zero bits, then signing with `identity`.
    pub fn mint(identity: &NodeIdentity, timestamp_ms: u64, min_pow_bits: u8) -> Self {
        let peer_pubkey = identity.public_key_bytes();
        let target_bits = u32::from(min_pow_bits);

        let mut prefix_hasher = Sha256::new();
        prefix_hasher.update(PUBLIC_COMMONS_POW_DOMAIN);
        prefix_hasher.update(peer_pubkey);
        prefix_hasher.update(timestamp_ms.to_be_bytes());

        let mut pow_nonce: u64 = 0;
        loop {
            let mut hasher = prefix_hasher.clone();
            hasher.update(pow_nonce.to_be_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            if Self::leading_zero_bits(&digest) >= target_bits {
                break;
            }
            pow_nonce = pow_nonce.wrapping_add(1);
        }

        let msg = Self::canonical_sign_bytes(&peer_pubkey, timestamp_ms, min_pow_bits, pow_nonce);
        let sig = identity.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Self {
            peer_pubkey,
            timestamp_ms,
            pow_bits: min_pow_bits,
            pow_nonce,
            sig_r,
            sig_s,
        }
    }

    /// Verifies that the ticket satisfies `>= required_pow_bits` leading zero bits on its
    /// domain-separated SHA-256 digest AND carries a valid `Ed25519` signature by `peer_pubkey`.
    pub fn verify(&self, required_pow_bits: u8) -> bool {
        if self.pow_bits < required_pow_bits {
            return false;
        }
        let effective_bits = u32::from(required_pow_bits.max(self.pow_bits));
        let digest = Self::pow_digest(&self.peer_pubkey, self.timestamp_ms, self.pow_nonce);
        if Self::leading_zero_bits(&digest) < effective_bits {
            return false;
        }
        let msg = Self::canonical_sign_bytes(
            &self.peer_pubkey,
            self.timestamp_ms,
            self.pow_bits,
            self.pow_nonce,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.peer_pubkey, &msg, &sig)
    }
}

/// Single signed delegation hop (`Inviter -> Invitee`) in the Web-of-Trust tree (ADR-05).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvitationHop {
    pub inviter_pubkey: [u8; 32],
    pub invitee_pubkey: [u8; 32],
    pub depth: u32,
    pub issued_at_unix_secs: u64,
    /// Ed25519 signature (split into two 32-byte arrays for serde compatibility).
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl InvitationHop {
    pub fn canonical_sign_bytes(
        inviter_pubkey: &[u8; 32],
        invitee_pubkey: &[u8; 32],
        depth: u32,
        issued_at_unix_secs: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(18 + 32 + 32 + 4 + 8);
        buf.extend_from_slice(b"parvault-wot-invite:");
        buf.extend_from_slice(inviter_pubkey);
        buf.extend_from_slice(invitee_pubkey);
        buf.extend_from_slice(&depth.to_be_bytes());
        buf.extend_from_slice(&issued_at_unix_secs.to_be_bytes());
        buf
    }

    pub fn issue(
        inviter: &NodeIdentity,
        invitee_pubkey: [u8; 32],
        depth: u32,
        issued_at_unix_secs: u64,
    ) -> Self {
        let inviter_pubkey = inviter.public_key_bytes();
        let msg = Self::canonical_sign_bytes(
            &inviter_pubkey,
            &invitee_pubkey,
            depth,
            issued_at_unix_secs,
        );
        let sig = inviter.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Self {
            inviter_pubkey,
            invitee_pubkey,
            depth,
            issued_at_unix_secs,
            sig_r,
            sig_s,
        }
    }

    pub fn verify_signature(&self) -> bool {
        let msg = Self::canonical_sign_bytes(
            &self.inviter_pubkey,
            &self.invitee_pubkey,
            self.depth,
            self.issued_at_unix_secs,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.inviter_pubkey, &msg, &sig)
    }
}

/// What [`WebOfTrustRegistry::public_ticket_decision`] needs to know about one ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketFacts {
    /// The node runs in public-commons or hybrid mode.
    pub public_commons_allowed: bool,
    /// The ticket's key is the sender's transport key.
    pub ticket_is_sender: bool,
    /// The ticket meets the node's PoW bits and its signature verifies.
    pub ticket_valid: bool,
}

/// Complete certificate chain (`Genesis -> ... -> Inviter -> Leaf Peer`) exchanged on handshake.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationChain {
    pub hops: Vec<InvitationHop>,
}

impl DelegationChain {
    pub fn leaf_pubkey(&self) -> Option<[u8; 32]> {
        self.hops.last().map(|h| h.invitee_pubkey)
    }

    pub fn genesis_pubkey(&self) -> Option<[u8; 32]> {
        self.hops.first().map(|h| h.inviter_pubkey)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashingReason {
    InvalidHandshake,
    PorAuditTimeoutOrTamper,
    ByzantineShardPoisoning,
    EgressWithholdingAtRestore,
    ProxyOrPartialRetentionCheating,
}

/// Signed slashing evidence broadcast over Gossipsub when a peer fails audits or handshakes (ADR-05).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingEvidence {
    pub offender_pubkey: [u8; 32],
    pub reporter_pubkey: [u8; 32],
    pub reason: SlashingReason,
    pub nonce: u64,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl SlashingEvidence {
    pub fn issue(
        reporter: &NodeIdentity,
        offender_pubkey: [u8; 32],
        reason: SlashingReason,
        nonce: u64,
    ) -> Self {
        let reporter_pubkey = reporter.public_key_bytes();
        let msg = Self::canonical_bytes(&offender_pubkey, &reporter_pubkey, reason, nonce);
        let sig = reporter.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Self {
            offender_pubkey,
            reporter_pubkey,
            reason,
            nonce,
            sig_r,
            sig_s,
        }
    }

    pub fn verify(&self) -> bool {
        let msg = Self::canonical_bytes(
            &self.offender_pubkey,
            &self.reporter_pubkey,
            self.reason,
            self.nonce,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.reporter_pubkey, &msg, &sig)
    }

    fn canonical_bytes(
        offender: &[u8; 32],
        reporter: &[u8; 32],
        reason: SlashingReason,
        nonce: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(b"parvault-slash-v1:");
        buf.extend_from_slice(offender);
        buf.extend_from_slice(reporter);
        buf.push(match reason {
            SlashingReason::InvalidHandshake => 1,
            SlashingReason::PorAuditTimeoutOrTamper => 2,
            SlashingReason::ByzantineShardPoisoning => 3,
            SlashingReason::EgressWithholdingAtRestore => 4,
            SlashingReason::ProxyOrPartialRetentionCheating => 5,
        });
        buf.extend_from_slice(&nonce.to_be_bytes());
        buf
    }
}

/// Stateful Web-of-Trust registry tracking verified delegation trees, failure counters,
/// recursive parent branch pruning, and optional Public Commons PoW zero-pairing admission (`network::wot`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebOfTrustRegistry {
    genesis_pubkey: [u8; 32],
    max_subtree_slashes: u32,
    /// Verified chain per admitted PrivateRing peer public key.
    admitted_chains: HashMap<[u8; 32], DelegationChain>,
    /// Failure counter per leaf node (quarantined once `>= MAX_LEAF_FAILURES` = 3).
    leaf_failures: HashMap<[u8; 32], u32>,
    /// Cumulative slashed descendants per parent inviter branch.
    branch_slash_counts: HashMap<[u8; 32], u32>,
    /// Explicitly quarantined leaf or branch public keys.
    quarantined_keys: HashSet<[u8; 32]>,
    /// Anti-replay ledger of processed `(reporter_pubkey, offender_pubkey, nonce)` slashing tuples (`ADR-15`).
    seen_slashing_nonces: HashSet<([u8; 32], [u8; 32], u64)>,
    /// Bounded FIFO queue ordering `seen_slashing_nonces` so RAM usage never exceeds `MAX_SEEN_SLASHING_NONCES`.
    seen_slashing_fifo: VecDeque<([u8; 32], [u8; 32], u64)>,
    /// Operating trust pool mode (`PrivateRing` by default so existing callers behave identically).
    #[serde(default)]
    trust_pool_mode: TrustPoolMode,
    /// Minimum Hashcash PoW leading zero bits required to admit a `PublicCommonsTicket`.
    #[serde(default = "default_public_wot_pow_bits")]
    min_public_pow_bits: u8,
    /// Admitted probationary Public Commons peers (`peer_pubkey -> verified ticket`).
    #[serde(default)]
    public_commons_peers: HashMap<[u8; 32], PublicCommonsTicket>,
    /// Bounded FIFO queue ordering `public_commons_peers` so RAM usage never exceeds `MAX_PUBLIC_COMMONS_PEERS`.
    #[serde(default)]
    public_commons_fifo: VecDeque<[u8; 32]>,
    #[serde(skip)]
    persistence_path: Option<std::path::PathBuf>,
}

impl WebOfTrustRegistry {
    /// Canonical deterministic seed domain for open Public Commons trackers (`ADR-18`).
    pub const PUBLIC_COMMONS_GENESIS_SEED_DOMAIN: &[u8] = PUBLIC_COMMONS_GENESIS_SEED_DOMAIN;

    /// Derives the deterministic Ed25519 Genesis public key shared across Public Commons trackers.
    pub fn public_commons_genesis_pubkey() -> [u8; 32] {
        let seed: [u8; 32] = Sha256::digest(PUBLIC_COMMONS_GENESIS_SEED_DOMAIN).into();
        NodeIdentity::from_seed(seed).public_key_bytes()
    }

    pub fn new(genesis_pubkey: [u8; 32], max_subtree_slashes: u32) -> Self {
        Self {
            genesis_pubkey,
            max_subtree_slashes: max_subtree_slashes.max(1),
            admitted_chains: HashMap::new(),
            leaf_failures: HashMap::new(),
            branch_slash_counts: HashMap::new(),
            quarantined_keys: HashSet::new(),
            seen_slashing_nonces: HashSet::new(),
            seen_slashing_fifo: VecDeque::new(),
            trust_pool_mode: TrustPoolMode::PrivateRing,
            min_public_pow_bits: DEFAULT_PUBLIC_WOT_POW_BITS,
            public_commons_peers: HashMap::new(),
            public_commons_fifo: VecDeque::new(),
            persistence_path: None,
        }
    }

    /// Initializes a `WebOfTrustRegistry` configured for open `PublicCommons` zero-pairing admission
    /// anchored at [`Self::public_commons_genesis_pubkey`].
    pub fn new_public_commons(min_pow_bits: u8) -> Self {
        let mut reg = Self::new(
            Self::public_commons_genesis_pubkey(),
            DEFAULT_SUBTREE_SLASH_LIMIT,
        );
        reg.trust_pool_mode = TrustPoolMode::PublicCommons;
        reg.min_public_pow_bits = min_pow_bits;
        reg
    }

    /// Loads or initializes a persistent `WebOfTrustRegistry` at `data_dir/wot_state.bin`.
    pub fn with_persistence_dir(
        genesis_pubkey: [u8; 32],
        max_subtree_slashes: u32,
        data_dir: &std::path::Path,
    ) -> Self {
        let path = data_dir.join("wot_state.bin");
        if path.exists() {
            if let Ok(raw) = std::fs::read(&path) {
                if let Ok(mut loaded) = bincode::deserialize::<Self>(&raw) {
                    if loaded.genesis_pubkey == genesis_pubkey {
                        loaded.persistence_path = Some(path);
                        return loaded;
                    }
                }
            }
        }
        let mut reg = Self::new(genesis_pubkey, max_subtree_slashes);
        reg.persistence_path = Some(path);
        reg
    }

    /// Loads or initializes a persistent `PublicCommons` `WebOfTrustRegistry` at `data_dir/wot_state.bin`.
    pub fn with_public_commons_persistence_dir(
        min_pow_bits: u8,
        data_dir: &std::path::Path,
    ) -> Self {
        let mut reg = Self::with_persistence_dir(
            Self::public_commons_genesis_pubkey(),
            DEFAULT_SUBTREE_SLASH_LIMIT,
            data_dir,
        );
        reg.set_trust_pool_mode(TrustPoolMode::PublicCommons, min_pow_bits);
        reg
    }

    /// Updates the pool's `TrustPoolMode` and minimum required `PublicCommonsTicket` PoW difficulty.
    pub fn set_trust_pool_mode(&mut self, mode: TrustPoolMode, min_pow_bits: u8) {
        self.trust_pool_mode = mode;
        self.min_public_pow_bits = min_pow_bits;
        self.persist();
    }

    /// Returns the active `TrustPoolMode` (`PrivateRing`, `PublicCommons`, or `Hybrid`).
    pub fn trust_pool_mode(&self) -> TrustPoolMode {
        self.trust_pool_mode
    }

    /// Returns the minimum Hashcash PoW bits required for `PublicCommonsTicket` admission.
    pub fn min_public_pow_bits(&self) -> u8 {
        self.min_public_pow_bits
    }

    /// Returns the Genesis Root Ed25519 public key configured for this registry.
    pub fn genesis_pubkey(&self) -> [u8; 32] {
        self.genesis_pubkey
    }

    fn persist(&self) {
        if let Some(ref path) = self.persistence_path {
            if let Ok(bytes) = bincode::serialize(self) {
                let _ = crate::storage::BlockStore::atomic_write_file(path, &bytes);
            }
        }
    }

    pub fn seen_slashing_nonces_count(&self) -> usize {
        self.seen_slashing_nonces.len()
    }

    /// The public-commons admission decision (F-05) for a ticket presented on the wire.
    pub fn public_ticket_decision(facts: &TicketFacts) -> Result<(), &'static str> {
        if !facts.public_commons_allowed {
            return Err("reject.public_commons_disabled");
        }
        if !facts.ticket_is_sender {
            return Err("reject.ticket_not_sender");
        }
        if !facts.ticket_valid {
            // PoW below the node's required bits, or a bad ticket signature.
            return Err("reject.ticket_insufficient_pow");
        }
        Ok(())
    }

    /// Facts for [`Self::public_ticket_decision`] about `ticket` sent by `sender_pubkey`.
    pub fn ticket_facts(
        &self,
        ticket: &PublicCommonsTicket,
        sender_pubkey: Option<[u8; 32]>,
    ) -> TicketFacts {
        TicketFacts {
            public_commons_allowed: self.trust_pool_mode.allows_public_commons(),
            ticket_is_sender: sender_pubkey == Some(ticket.peer_pubkey),
            ticket_valid: ticket.verify(self.min_public_pow_bits),
        }
    }

    /// The handshake binding (F-21): a chain admits only the key at its leaf, so the sender's
    /// transport key must be that leaf. Fails closed when the sender has no Ed25519 key.
    pub fn chain_leaf_decision(
        chain_leaf: Option<[u8; 32]>,
        sender_pubkey: Option<[u8; 32]>,
    ) -> Result<(), &'static str> {
        match (chain_leaf, sender_pubkey) {
            (Some(leaf), Some(sender)) if leaf == sender => Ok(()),
            _ => Err("reject.chain_leaf_not_sender"),
        }
    }

    /// Validates and admits a peer's `DelegationChain` if anchored at `genesis_pubkey`
    /// and free of quarantined ancestors.
    pub fn verify_and_admit_chain(
        &mut self,
        chain: &DelegationChain,
    ) -> Result<[u8; 32], WebOfTrustError> {
        if chain.hops.is_empty() {
            return Err(WebOfTrustError::EmptyChain);
        }
        if chain.hops.len() as u32 > MAX_DELEGATION_DEPTH {
            return Err(WebOfTrustError::MaxDepthExceeded(chain.hops.len() as u32));
        }
        if chain.hops[0].inviter_pubkey != self.genesis_pubkey {
            return Err(WebOfTrustError::UntrustedGenesisRoot);
        }

        for (idx, hop) in chain.hops.iter().enumerate() {
            if self.quarantined_keys.contains(&hop.inviter_pubkey)
                || self.quarantined_keys.contains(&hop.invitee_pubkey)
            {
                return Err(WebOfTrustError::QuarantinedSubtree);
            }
            if idx > 0 && hop.inviter_pubkey != chain.hops[idx - 1].invitee_pubkey {
                return Err(WebOfTrustError::BrokenChainLink(idx));
            }
            if !hop.verify_signature() {
                return Err(WebOfTrustError::InvalidHopSignature(idx));
            }
        }

        let leaf = chain.leaf_pubkey().expect("checked non-empty");
        // Upgrading to a full PrivateRing chain supersedes any probationary PublicCommons ticket.
        self.public_commons_peers.remove(&leaf);
        self.admitted_chains.insert(leaf, chain.clone());
        self.persist();
        Ok(leaf)
    }

    /// Verifies and admits a stranger peer's self-signed Hashcash `PublicCommonsTicket` when
    /// operating in `PublicCommons` or `Hybrid` mode (`ADR-18`).
    pub fn verify_and_admit_public_ticket(
        &mut self,
        ticket: &PublicCommonsTicket,
    ) -> Result<(), WotError> {
        if self.trust_pool_mode == TrustPoolMode::PrivateRing {
            return Err(WotError::PublicCommonsDisabled);
        }
        if self.quarantined_keys.contains(&ticket.peer_pubkey) {
            return Err(WotError::RevokedPeer);
        }
        if !ticket.verify(self.min_public_pow_bits) {
            return Err(WotError::InsufficientPublicPow);
        }

        // Preserve PrivateRing standing if this peer already holds an unquarantined DelegationChain.
        if !self.is_private_ring_peer(&ticket.peer_pubkey) {
            if !self.public_commons_peers.contains_key(&ticket.peer_pubkey) {
                while self.public_commons_peers.len() >= MAX_PUBLIC_COMMONS_PEERS {
                    if let Some(oldest) = self.public_commons_fifo.pop_front() {
                        if self.public_commons_peers.remove(&oldest).is_some() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                self.public_commons_fifo.push_back(ticket.peer_pubkey);
            }
            self.public_commons_peers
                .insert(ticket.peer_pubkey, ticket.clone());
        }
        self.persist();
        Ok(())
    }

    /// Returns `true` if `pubkey` is currently admitted via a `PrivateRing` `DelegationChain`
    /// with no quarantined ancestor hops.
    pub fn is_private_ring_peer(&self, pubkey: &[u8; 32]) -> bool {
        if self.quarantined_keys.contains(pubkey) {
            return false;
        }
        let Some(chain) = self.admitted_chains.get(pubkey) else {
            return false;
        };
        for hop in &chain.hops {
            if self.quarantined_keys.contains(&hop.inviter_pubkey)
                || self.quarantined_keys.contains(&hop.invitee_pubkey)
            {
                return false;
            }
        }
        true
    }

    /// Returns `true` if `pubkey` entered as a probationary `PublicCommons` peer (and has not
    /// been quarantined or superseded by a `PrivateRing` `DelegationChain`).
    pub fn is_public_commons_peer(&self, pubkey: &[u8; 32]) -> bool {
        self.trust_pool_mode.allows_public_commons()
            && !self.quarantined_keys.contains(pubkey)
            && !self.is_private_ring_peer(pubkey)
            && self.public_commons_peers.contains_key(pubkey)
    }

    /// Returns `true` if `pubkey` has been explicitly slashed or quarantined.
    pub fn is_peer_quarantined(&self, pubkey: &[u8; 32]) -> bool {
        self.quarantined_keys.contains(pubkey)
    }

    /// Checks whether a peer is currently admitted (via `genesis_pubkey`, unquarantined
    /// `PrivateRing` `DelegationChain`, or active `PublicCommonsTicket`) and not slashed.
    pub fn is_peer_trusted(&self, peer_pubkey: &[u8; 32]) -> bool {
        if *peer_pubkey == self.genesis_pubkey {
            return !self.quarantined_keys.contains(peer_pubkey);
        }
        if self.quarantined_keys.contains(peer_pubkey) {
            return false;
        }
        if self.is_private_ring_peer(peer_pubkey) {
            return true;
        }
        self.is_public_commons_peer(peer_pubkey)
    }

    /// Records a handshake or PoR failure for `offender_pubkey`.
    /// When `leaf_failures >= 3` (`MAX_LEAF_FAILURES`), immediately isolates the node and propagates
    /// a slash penalty up its parent inviter chain, pruning ancestor branches that hit `max_subtree_slashes`.
    pub fn record_failure(&mut self, offender_pubkey: [u8; 32]) -> bool {
        if self.quarantined_keys.contains(&offender_pubkey) {
            return true;
        }
        let count = self.leaf_failures.entry(offender_pubkey).or_insert(0);
        *count += 1;

        if *count >= MAX_LEAF_FAILURES {
            self.quarantined_keys.insert(offender_pubkey);
            self.public_commons_peers.remove(&offender_pubkey);

            // Propagate slash up the ancestor branch in finite steps <= M (ADR-05).
            if let Some(chain) = self.admitted_chains.get(&offender_pubkey).cloned() {
                for hop in &chain.hops {
                    let parent = hop.inviter_pubkey;
                    if parent == self.genesis_pubkey {
                        continue;
                    }
                    let branch_slashes = self.branch_slash_counts.entry(parent).or_insert(0);
                    *branch_slashes += 1;
                    if *branch_slashes >= self.max_subtree_slashes {
                        self.quarantined_keys.insert(parent);
                    }
                }
            }
            self.persist();
            return true;
        }
        self.persist();
        false
    }

    /// Immediately quarantines an offender leaf node on the first provable Byzantine offense
    /// (shard poisoning, egress withholding, or proxy cheating) and propagates a slash penalty
    /// up its parent inviter chain.
    pub fn slash_immediately(&mut self, offender_pubkey: [u8; 32]) -> bool {
        if self.quarantined_keys.contains(&offender_pubkey) {
            return true;
        }
        self.leaf_failures
            .insert(offender_pubkey, MAX_LEAF_FAILURES);
        self.quarantined_keys.insert(offender_pubkey);
        self.public_commons_peers.remove(&offender_pubkey);

        if let Some(chain) = self.admitted_chains.get(&offender_pubkey).cloned() {
            for hop in &chain.hops {
                let parent = hop.inviter_pubkey;
                if parent == self.genesis_pubkey {
                    continue;
                }
                let branch_slashes = self.branch_slash_counts.entry(parent).or_insert(0);
                *branch_slashes += 1;
                if *branch_slashes >= self.max_subtree_slashes {
                    self.quarantined_keys.insert(parent);
                }
            }
        }
        self.persist();
        true
    }

    /// Processes a signed `SlashingEvidence` message received via Gossipsub.
    /// Deduplicates `(reporter_pubkey, offender_pubkey, nonce)` so replayed evidence cannot
    /// repeatedly increment `record_failure` (`ADR-15`).
    pub fn apply_slashing_evidence(&mut self, evidence: &SlashingEvidence) -> bool {
        if !evidence.verify() {
            return false;
        }
        if !self.is_peer_trusted(&evidence.reporter_pubkey) {
            return false;
        }
        let replay_key = (
            evidence.reporter_pubkey,
            evidence.offender_pubkey,
            evidence.nonce,
        );
        if self.seen_slashing_nonces.contains(&replay_key) {
            return false;
        }
        while self.seen_slashing_nonces.len() >= MAX_SEEN_SLASHING_NONCES {
            if let Some(oldest) = self.seen_slashing_fifo.pop_front() {
                self.seen_slashing_nonces.remove(&oldest);
            } else {
                break;
            }
        }
        self.seen_slashing_nonces.insert(replay_key);
        self.seen_slashing_fifo.push_back(replay_key);
        match evidence.reason {
            SlashingReason::ByzantineShardPoisoning
            | SlashingReason::EgressWithholdingAtRestore
            | SlashingReason::ProxyOrPartialRetentionCheating => {
                self.slash_immediately(evidence.offender_pubkey)
            }
            SlashingReason::InvalidHandshake | SlashingReason::PorAuditTimeoutOrTamper => {
                self.record_failure(evidence.offender_pubkey)
            }
        }
    }

    pub fn admitted_peer_count(&self) -> usize {
        let ring_count = self
            .admitted_chains
            .keys()
            .filter(|k| self.is_private_ring_peer(k))
            .count();
        let public_count = if self.trust_pool_mode.allows_public_commons() {
            self.public_commons_peers
                .keys()
                .filter(|k| self.is_public_commons_peer(k))
                .count()
        } else {
            0
        };
        ring_count + public_count
    }

    pub fn public_commons_peer_count(&self) -> usize {
        if self.trust_pool_mode.allows_public_commons() {
            self.public_commons_peers
                .keys()
                .filter(|k| self.is_public_commons_peer(k))
                .count()
        } else {
            0
        }
    }

    pub fn quarantined_count(&self) -> usize {
        self.quarantined_keys.len()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn chain_leaf_decision_binds_the_sender() {
        let leaf = Some([1u8; 32]);
        assert_eq!(WebOfTrustRegistry::chain_leaf_decision(leaf, leaf), Ok(()));
        assert_eq!(
            WebOfTrustRegistry::chain_leaf_decision(leaf, Some([2; 32])),
            Err("reject.chain_leaf_not_sender")
        );
        assert_eq!(
            WebOfTrustRegistry::chain_leaf_decision(leaf, None),
            Err("reject.chain_leaf_not_sender"),
            "a sender without an Ed25519 key fails closed"
        );
        assert_eq!(
            WebOfTrustRegistry::chain_leaf_decision(None, leaf),
            Err("reject.chain_leaf_not_sender")
        );
    }

    use super::*;

    #[test]
    fn test_public_commons_ticket_mint_verify_and_tamper_rejection() {
        let stranger = NodeIdentity::from_seed([0x31u8; 32]);
        let now_ms = 1_762_848_000_000u64;

        let ticket = PublicCommonsTicket::mint(&stranger, now_ms, DEFAULT_PUBLIC_WOT_POW_BITS);
        assert_eq!(ticket.peer_pubkey, stranger.public_key_bytes());
        assert_eq!(ticket.pow_bits, DEFAULT_PUBLIC_WOT_POW_BITS);

        let digest = PublicCommonsTicket::pow_digest(
            &ticket.peer_pubkey,
            ticket.timestamp_ms,
            ticket.pow_nonce,
        );
        assert!(
            PublicCommonsTicket::leading_zero_bits(&digest)
                >= u32::from(DEFAULT_PUBLIC_WOT_POW_BITS),
            "minted 12-bit ticket must satisfy >= 12 leading zero bits"
        );
        assert!(ticket.verify(DEFAULT_PUBLIC_WOT_POW_BITS));
        assert!(ticket.verify(8));

        // 1. Reject forged pow_nonce
        let mut forged_nonce = ticket.clone();
        forged_nonce.pow_nonce = forged_nonce.pow_nonce.wrapping_add(1);
        assert!(
            !forged_nonce.verify(DEFAULT_PUBLIC_WOT_POW_BITS),
            "forged pow_nonce must fail verification"
        );

        // 2. Reject low-PoW self-signed ticket when 12 bits are required
        let low_pow_ticket = PublicCommonsTicket::mint(&stranger, now_ms, 4);
        assert!(low_pow_ticket.verify(4));
        assert!(
            !low_pow_ticket.verify(DEFAULT_PUBLIC_WOT_POW_BITS),
            "4-bit ticket must be rejected when 12 bits are required"
        );

        // 3. Reject tampered Ed25519 signature bytes (sig_r and sig_s)
        let mut tampered_sig_r = ticket.clone();
        tampered_sig_r.sig_r[0] ^= 0xFF;
        assert!(!tampered_sig_r.verify(DEFAULT_PUBLIC_WOT_POW_BITS));

        let mut tampered_sig_s = ticket.clone();
        tampered_sig_s.sig_s[31] ^= 0x01;
        assert!(!tampered_sig_s.verify(DEFAULT_PUBLIC_WOT_POW_BITS));

        // 4. Reject impersonated peer_pubkey with another identity's valid PoW signature
        let attacker = NodeIdentity::from_seed([0x77u8; 32]);
        let mut spoofed_peer =
            PublicCommonsTicket::mint(&attacker, now_ms, DEFAULT_PUBLIC_WOT_POW_BITS);
        spoofed_peer.peer_pubkey = stranger.public_key_bytes();
        assert!(!spoofed_peer.verify(DEFAULT_PUBLIC_WOT_POW_BITS));
    }

    #[test]
    fn test_trust_pool_modes_and_three_strike_public_peer_quarantine() {
        let genesis = NodeIdentity::from_seed([0x01u8; 32]);
        let private_member = NodeIdentity::from_seed([0x02u8; 32]);
        let stranger = NodeIdentity::from_seed([0x03u8; 32]);
        let reporter1 = NodeIdentity::from_seed([0x11u8; 32]);
        let reporter2 = NodeIdentity::from_seed([0x12u8; 32]);
        let reporter3 = NodeIdentity::from_seed([0x13u8; 32]);
        let now_ms = 1_762_848_123_000u64;

        let stranger_ticket =
            PublicCommonsTicket::mint(&stranger, now_ms, DEFAULT_PUBLIC_WOT_POW_BITS);

        // 1. Default PrivateRing mode strictly rejects PublicCommonsTicket
        let mut private_wot = WebOfTrustRegistry::new(genesis.public_key_bytes(), 5);
        assert_eq!(private_wot.trust_pool_mode(), TrustPoolMode::PrivateRing);
        assert_eq!(
            private_wot.verify_and_admit_public_ticket(&stranger_ticket),
            Err(WotError::PublicCommonsDisabled)
        );
        assert!(!private_wot.is_peer_trusted(&stranger.public_key_bytes()));
        assert!(!private_wot.is_public_commons_peer(&stranger.public_key_bytes()));

        // 2. PublicCommons mode admits valid ticket, rejects weak PoW, and quarantines after 3 strikes
        let mut public_wot = WebOfTrustRegistry::new_public_commons(DEFAULT_PUBLIC_WOT_POW_BITS);
        assert_eq!(public_wot.trust_pool_mode(), TrustPoolMode::PublicCommons);
        assert_eq!(
            public_wot.genesis_pubkey(),
            WebOfTrustRegistry::public_commons_genesis_pubkey()
        );

        let weak_ticket = PublicCommonsTicket::mint(&stranger, now_ms, 4);
        assert_eq!(
            public_wot.verify_and_admit_public_ticket(&weak_ticket),
            Err(WotError::InsufficientPublicPow)
        );

        public_wot
            .verify_and_admit_public_ticket(&stranger_ticket)
            .expect("valid 12-bit ticket must be admitted in PublicCommons mode");
        for rep in [&reporter1, &reporter2, &reporter3] {
            let rep_ticket = PublicCommonsTicket::mint(rep, now_ms, DEFAULT_PUBLIC_WOT_POW_BITS);
            public_wot
                .verify_and_admit_public_ticket(&rep_ticket)
                .expect("admit public reporter");
        }

        assert!(public_wot.is_public_commons_peer(&stranger.public_key_bytes()));
        assert!(public_wot.is_peer_trusted(&stranger.public_key_bytes()));
        assert_eq!(public_wot.admitted_peer_count(), 4);

        let ev1 = SlashingEvidence::issue(
            &reporter1,
            stranger.public_key_bytes(),
            SlashingReason::PorAuditTimeoutOrTamper,
            101,
        );
        let ev2 = SlashingEvidence::issue(
            &reporter2,
            stranger.public_key_bytes(),
            SlashingReason::PorAuditTimeoutOrTamper,
            102,
        );
        let ev3 = SlashingEvidence::issue(
            &reporter3,
            stranger.public_key_bytes(),
            SlashingReason::PorAuditTimeoutOrTamper,
            103,
        );

        assert!(!public_wot.apply_slashing_evidence(&ev1));
        assert!(public_wot.is_peer_trusted(&stranger.public_key_bytes()));
        assert!(!public_wot.apply_slashing_evidence(&ev2));
        assert!(public_wot.is_peer_trusted(&stranger.public_key_bytes()));
        assert!(
            public_wot.apply_slashing_evidence(&ev3),
            "3rd distinct SlashingEvidence strike must quarantine the public peer"
        );
        assert!(!public_wot.is_peer_trusted(&stranger.public_key_bytes()));
        assert!(!public_wot.is_public_commons_peer(&stranger.public_key_bytes()));
        assert!(public_wot.is_peer_quarantined(&stranger.public_key_bytes()));
        assert_eq!(
            public_wot.verify_and_admit_public_ticket(&stranger_ticket),
            Err(WotError::RevokedPeer),
            "quarantined peer must not be able to re-admit itself with a PublicCommonsTicket"
        );

        // 3. Hybrid mode admits both PrivateRing chains and PublicCommons tickets and honors 3-strike quarantine
        let mut hybrid_wot = WebOfTrustRegistry::new(genesis.public_key_bytes(), 5);
        hybrid_wot.set_trust_pool_mode(TrustPoolMode::Hybrid, DEFAULT_PUBLIC_WOT_POW_BITS);
        assert_eq!(hybrid_wot.trust_pool_mode(), TrustPoolMode::Hybrid);

        let hop = InvitationHop::issue(
            &genesis,
            private_member.public_key_bytes(),
            1,
            1_762_848_000,
        );
        hybrid_wot
            .verify_and_admit_chain(&DelegationChain { hops: vec![hop] })
            .expect("admit private ring member");
        hybrid_wot
            .verify_and_admit_public_ticket(&stranger_ticket)
            .expect("admit public stranger in Hybrid mode");
        for rep in [&reporter1, &reporter2, &reporter3] {
            let rep_ticket = PublicCommonsTicket::mint(rep, now_ms, DEFAULT_PUBLIC_WOT_POW_BITS);
            hybrid_wot
                .verify_and_admit_public_ticket(&rep_ticket)
                .unwrap();
        }

        assert!(hybrid_wot.is_peer_trusted(&private_member.public_key_bytes()));
        assert!(!hybrid_wot.is_public_commons_peer(&private_member.public_key_bytes()));
        assert!(hybrid_wot.is_peer_trusted(&stranger.public_key_bytes()));
        assert!(hybrid_wot.is_public_commons_peer(&stranger.public_key_bytes()));

        assert!(!hybrid_wot.apply_slashing_evidence(&ev1));
        assert!(!hybrid_wot.apply_slashing_evidence(&ev2));
        assert!(hybrid_wot.apply_slashing_evidence(&ev3));

        assert!(!hybrid_wot.is_peer_trusted(&stranger.public_key_bytes()));
        assert!(!hybrid_wot.is_public_commons_peer(&stranger.public_key_bytes()));
        assert!(
            hybrid_wot.is_peer_trusted(&private_member.public_key_bytes()),
            "PrivateRing member must remain trusted when public peer is quarantined"
        );
        assert_eq!(
            hybrid_wot.verify_and_admit_public_ticket(&stranger_ticket),
            Err(WotError::RevokedPeer)
        );
    }

    #[test]
    fn test_trust_pool_mode_serde_and_persistence_roundtrip() {
        assert_eq!(
            serde_json::from_str::<TrustPoolMode>("\"public\"").unwrap(),
            TrustPoolMode::PublicCommons
        );
        assert_eq!(
            serde_json::from_str::<TrustPoolMode>("\"private\"").unwrap(),
            TrustPoolMode::PrivateRing
        );
        assert_eq!(
            serde_json::from_str::<TrustPoolMode>("\"hybrid\"").unwrap(),
            TrustPoolMode::Hybrid
        );
        assert_eq!(
            "public".parse::<TrustPoolMode>().unwrap(),
            TrustPoolMode::PublicCommons
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let stranger = NodeIdentity::from_seed([0x55u8; 32]);
        let ticket =
            PublicCommonsTicket::mint(&stranger, 1_762_848_000_000, DEFAULT_PUBLIC_WOT_POW_BITS);
        {
            let mut wot = WebOfTrustRegistry::with_public_commons_persistence_dir(
                DEFAULT_PUBLIC_WOT_POW_BITS,
                dir.path(),
            );
            wot.verify_and_admit_public_ticket(&ticket).unwrap();
        }
        let reloaded = WebOfTrustRegistry::with_public_commons_persistence_dir(
            DEFAULT_PUBLIC_WOT_POW_BITS,
            dir.path(),
        );
        assert!(reloaded.is_public_commons_peer(&stranger.public_key_bytes()));
        assert!(reloaded.is_peer_trusted(&stranger.public_key_bytes()));
    }
}
