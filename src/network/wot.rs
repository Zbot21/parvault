//! Formal model: `specs/ParVaultProtocol.tla` (guard `wot-admission`).
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

/// How many keys one member (not the genesis) may sub-invite (F-32).
pub const MAX_SUBINVITES_PER_INVITER: usize = 64;

/// How many delegation chains a node keeps (F-32).
pub const MAX_ADMITTED_CHAINS: usize = 65_536;

/// How long a public-commons ticket admission lasts (F-29): 24 hours from the ticket's timestamp.
pub const PUBLIC_COMMONS_ADMISSION_TTL_MS: u64 = 24 * 3600 * 1000;

/// How far a ticket's timestamp may be from the verifier's clock (F-29).
pub const TICKET_FRESHNESS_WINDOW_MS: u64 = 10 * 60 * 1000;

/// Ticket admissions allowed per source subnet: a burst of 8, then 8 per minute (F-29).
pub const TICKET_ADMISSIONS_PER_SUBNET_BURST: u64 = 8;

/// The number of source subnets whose ticket rate is tracked at once.
const MAX_TRACKED_TICKET_SUBNETS: usize = 4096;

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Default Hashcash Proof-of-Work difficulty (in leading zero bits) for `PublicCommonsTicket`
/// zero-pairing admission (~0.5–2 ms on tiny router SoCs).
pub const DEFAULT_PUBLIC_WOT_POW_BITS: u8 = 12;

/// Most PoW bits a node may require of tickets (QA 2c R2): what a default client still re-mints
/// (`DEFAULT_PUBLIC_WOT_POW_BITS + 4`, see `ticket_pow_demand_decision`).
pub const MAX_REQUIRED_PUBLIC_POW_BITS: u8 = DEFAULT_PUBLIC_WOT_POW_BITS + 4;

/// QA 2c R2: an operator may not require more ticket PoW than clients will mint, or every new
/// public client is locked out.
pub fn required_pow_bits_decision(bits: u8) -> Result<(), &'static str> {
    if bits > MAX_REQUIRED_PUBLIC_POW_BITS {
        Err("reject.required_pow_bits_excessive")
    } else {
        Ok(())
    }
}

/// Hard ceiling on ticket PoW a client will mint (QA 2c D1): about a million hashes.
pub const MAX_TICKET_POW_BITS: u8 = 20;

/// QA 2c D1: a client re-mints at a peer's stated `required_pow_bits` only if the demand is at
/// most 4 bits above its own (or the default) level and never above `MAX_TICKET_POW_BITS`; a
/// larger demand would hang the client minting.
pub fn ticket_pow_demand_decision(demanded: u8, own_bits: u8) -> Result<(), &'static str> {
    let limit = own_bits
        .max(DEFAULT_PUBLIC_WOT_POW_BITS)
        .saturating_add(4)
        .min(MAX_TICKET_POW_BITS);
    if demanded > limit {
        Err("reject.ticket_pow_demand_excessive")
    } else {
        Ok(())
    }
}

/// Domain separator for `PublicCommonsTicket` Hashcash PoW and Ed25519 self-attestation.
pub const PUBLIC_COMMONS_POW_DOMAIN: &[u8] = b"parvault-public-wot-pow-v1:";

/// Canonical deterministic seed domain for open Public Commons trackers (`ADR-24`).
pub const PUBLIC_COMMONS_GENESIS_SEED_DOMAIN: &[u8] = b"parvault-public-commons-open-wot-v1";

const fn default_public_wot_pow_bits() -> u8 {
    DEFAULT_PUBLIC_WOT_POW_BITS
}

/// Trust admission mode for a `WebOfTrustRegistry` pool (`ADR-24`).
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
    #[error("Public Commons admissions are full")]
    PublicCommonsFull,
    #[error("Chain admission limit reached")]
    ChainAdmissionLimit,
    /// Appended (F-37): this node is in no ring, so it admits no chain.
    #[error("This node is not in a ring and admits no delegation chain")]
    NoRing,
}

/// Alias for [`WebOfTrustError`] used by Public Commons WoT admission APIs.
pub type WotError = WebOfTrustError;

/// Self-signed Hashcash Proof-of-Work admission ticket allowing any stranger node to join a
/// `PublicCommons` or `Hybrid` pool without pre-pairing or join codes (`ADR-24`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PublicCommonsTicket {
    pub peer_pubkey: [u8; 32],
    /// The node this ticket is for (F-29): a ticket admits its key at one verifier only.
    pub verifier_pubkey: [u8; 32],
    pub timestamp_ms: u64,
    pub pow_bits: u8,
    pub pow_nonce: u64,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl PublicCommonsTicket {
    /// Computes `SHA-256("parvault-public-wot-pow-v1:" || peer_pubkey || timestamp_ms.to_be_bytes() || pow_nonce.to_be_bytes())`.
    pub fn pow_digest(
        peer_pubkey: &[u8; 32],
        verifier_pubkey: &[u8; 32],
        timestamp_ms: u64,
        pow_nonce: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PUBLIC_COMMONS_POW_DOMAIN);
        hasher.update(peer_pubkey);
        hasher.update(verifier_pubkey);
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
        verifier_pubkey: &[u8; 32],
        timestamp_ms: u64,
        pow_bits: u8,
        pow_nonce: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PUBLIC_COMMONS_POW_DOMAIN.len() + 64 + 8 + 1 + 8);
        buf.extend_from_slice(PUBLIC_COMMONS_POW_DOMAIN);
        buf.extend_from_slice(peer_pubkey);
        buf.extend_from_slice(verifier_pubkey);
        buf.extend_from_slice(&timestamp_ms.to_be_bytes());
        buf.push(pow_bits);
        buf.extend_from_slice(&pow_nonce.to_be_bytes());
        buf
    }

    /// Mints a self-signed Hashcash PoW admission ticket by iterating `pow_nonce` until
    /// `SHA-256("parvault-public-wot-pow-v1:" || peer_pubkey || timestamp_ms.to_be_bytes() || pow_nonce.to_be_bytes())`
    /// has `>= min_pow_bits` leading zero bits, then signing with `identity`.
    pub fn mint(
        identity: &NodeIdentity,
        verifier_pubkey: [u8; 32],
        timestamp_ms: u64,
        min_pow_bits: u8,
    ) -> Self {
        let peer_pubkey = identity.public_key_bytes();
        // Defence in depth (QA 2c D1): the search never runs past MAX_TICKET_POW_BITS; a ticket
        // declaring more is then simply invalid, never an endless loop.
        let target_bits = u32::from(min_pow_bits.min(MAX_TICKET_POW_BITS));

        let mut prefix_hasher = Sha256::new();
        prefix_hasher.update(PUBLIC_COMMONS_POW_DOMAIN);
        prefix_hasher.update(peer_pubkey);
        prefix_hasher.update(verifier_pubkey);
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

        let msg = Self::canonical_sign_bytes(
            &peer_pubkey,
            &verifier_pubkey,
            timestamp_ms,
            min_pow_bits,
            pow_nonce,
        );
        let sig = identity.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Self {
            peer_pubkey,
            verifier_pubkey,
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
        let digest = Self::pow_digest(
            &self.peer_pubkey,
            &self.verifier_pubkey,
            self.timestamp_ms,
            self.pow_nonce,
        );
        if Self::leading_zero_bits(&digest) < effective_bits {
            return false;
        }
        let msg = Self::canonical_sign_bytes(
            &self.peer_pubkey,
            &self.verifier_pubkey,
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

/// A source subnet's ticket-admission budget: a burst of `TICKET_ADMISSIONS_PER_SUBNET_BURST`,
/// refilled at the same number per minute.
#[derive(Debug, Clone)]
struct SubnetTicketBudget {
    tokens: f64,
    last_ms: u64,
}

impl SubnetTicketBudget {
    fn new(now_ms: u64) -> Self {
        Self {
            tokens: TICKET_ADMISSIONS_PER_SUBNET_BURST as f64,
            last_ms: now_ms,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_ms) as f64;
        let per_ms = TICKET_ADMISSIONS_PER_SUBNET_BURST as f64 / 60_000.0;
        self.tokens =
            (self.tokens + elapsed * per_ms).min(TICKET_ADMISSIONS_PER_SUBNET_BURST as f64);
        self.last_ms = self.last_ms.max(now_ms);
    }

    fn try_spend(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn is_full(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        self.tokens >= TICKET_ADMISSIONS_PER_SUBNET_BURST as f64
    }
}

/// What [`WebOfTrustRegistry::chain_admission_decision`] needs to know (F-32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAdmissionFacts {
    /// The leaf's inviter (the last hop's signer) is the genesis.
    pub inviter_is_genesis: bool,
    /// Other keys that inviter has already sub-invited here.
    pub inviter_subinvites: usize,
    /// The leaf has no chain on record yet.
    pub new_leaf: bool,
    pub admitted_total: usize,
    pub capacity: usize,
}

/// What [`WebOfTrustRegistry::slash_target_decision`] needs to know about one slash target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlashTargetFacts {
    pub is_genesis: bool,
    /// One of the local node's own keys.
    pub is_protected: bool,
}

/// What [`WebOfTrustRegistry::public_ticket_decision`] needs to know about one ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketFacts {
    /// The node runs in public-commons or hybrid mode.
    pub public_commons_allowed: bool,
    /// The ticket's key is the sender's transport key.
    pub ticket_is_sender: bool,
    /// The sender is already admitted (a re-sent ticket is a no-op).
    pub already_admitted: bool,
    /// The ticket's timestamp is within `TICKET_FRESHNESS_WINDOW_MS` of this node's clock.
    pub ticket_fresh: bool,
    /// The ticket names this node as its verifier.
    pub ticket_for_this_verifier: bool,
    /// The sender's subnet is within its ticket-admission budget.
    pub within_rate: bool,
    /// The ticket meets the node's PoW bits and its signature verifies.
    pub ticket_valid: bool,
    /// Public-commons admissions are not full (after pruning expired ones).
    pub capacity_available: bool,
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
    /// The ring genesis; `None` on a node outside any ring, which admits no chain (F-37).
    genesis_pubkey: Option<[u8; 32]>,
    max_subtree_slashes: u32,
    /// Verified chain per admitted PrivateRing peer public key.
    admitted_chains: HashMap<[u8; 32], DelegationChain>,
    /// Failure counter per leaf node (quarantined once `>= MAX_LEAF_FAILURES` = 3).
    leaf_failures: HashMap<[u8; 32], u32>,
    /// Cumulative slashed descendants per parent inviter branch.
    branch_slash_counts: HashMap<[u8; 32], u32>,
    /// Explicitly quarantined leaf or branch public keys.
    quarantined_keys: HashSet<[u8; 32]>,
    /// Anti-replay ledger of processed `(reporter_pubkey, offender_pubkey, nonce)` slashing tuples (`ADR-05`).
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
    /// Keys that can never be slashed besides the genesis: the local node's own keys, set at
    /// startup (not persisted).
    #[serde(skip)]
    protected_keys: HashSet<[u8; 32]>,
    /// Admission changes not yet written (F-29, F-32): admissions are flushed in batches.
    #[serde(skip)]
    dirty: bool,
    /// Ticket admissions per source subnet (F-29), not persisted.
    #[serde(skip)]
    ticket_rate: HashMap<String, SubnetTicketBudget>,
    /// Capacity of `public_commons_peers` (defaults to `MAX_PUBLIC_COMMONS_PEERS`).
    #[serde(skip)]
    public_commons_capacity: Option<usize>,
    /// Capacity of `admitted_chains` (defaults to `MAX_ADMITTED_CHAINS`).
    #[serde(skip)]
    admitted_chains_capacity: Option<usize>,
}

impl WebOfTrustRegistry {
    /// Canonical deterministic seed domain for open Public Commons trackers (`ADR-24`).
    pub const PUBLIC_COMMONS_GENESIS_SEED_DOMAIN: &[u8] = PUBLIC_COMMONS_GENESIS_SEED_DOMAIN;

    /// Derives the deterministic Ed25519 Genesis public key shared across Public Commons trackers.
    /// Its seed is public, so anyone can sign chains for it: test fixtures only (F-37).
    #[cfg(test)]
    pub fn public_commons_genesis_pubkey() -> [u8; 32] {
        let seed: [u8; 32] = Sha256::digest(PUBLIC_COMMONS_GENESIS_SEED_DOMAIN).into();
        NodeIdentity::from_seed(seed).public_key_bytes()
    }

    pub fn new(genesis_pubkey: [u8; 32], max_subtree_slashes: u32) -> Self {
        Self::with_genesis(Some(genesis_pubkey), max_subtree_slashes)
    }

    /// A registry for a node outside any ring: every chain is refused (F-37).
    pub fn without_ring(max_subtree_slashes: u32) -> Self {
        Self::with_genesis(None, max_subtree_slashes)
    }

    fn with_genesis(genesis_pubkey: Option<[u8; 32]>, max_subtree_slashes: u32) -> Self {
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
            protected_keys: HashSet::new(),
            dirty: false,
            ticket_rate: HashMap::new(),
            public_commons_capacity: None,
            admitted_chains_capacity: None,
        }
    }

    /// Initializes a `WebOfTrustRegistry` configured for open `PublicCommons` zero-pairing admission
    /// anchored at [`Self::public_commons_genesis_pubkey`].
    #[cfg(test)]
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
        genesis_pubkey: Option<[u8; 32]>,
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
        let mut reg = Self::with_genesis(genesis_pubkey, max_subtree_slashes);
        reg.persistence_path = Some(path);
        reg
    }

    /// Loads or initializes a persistent `PublicCommons` `WebOfTrustRegistry` at `data_dir/wot_state.bin`.
    #[cfg(test)]
    pub fn with_public_commons_persistence_dir(
        min_pow_bits: u8,
        data_dir: &std::path::Path,
    ) -> Self {
        let mut reg = Self::with_persistence_dir(
            Some(Self::public_commons_genesis_pubkey()),
            DEFAULT_SUBTREE_SLASH_LIMIT,
            data_dir,
        );
        reg.set_trust_pool_mode(TrustPoolMode::PublicCommons, min_pow_bits);
        reg
    }

    /// Updates the pool's `TrustPoolMode` and minimum required `PublicCommonsTicket` PoW difficulty.
    pub fn set_trust_pool_mode(&mut self, mode: TrustPoolMode, min_pow_bits: u8) {
        self.trust_pool_mode = mode;
        // Backstop for R2: never require more than clients will mint.
        self.min_public_pow_bits = min_pow_bits.min(MAX_REQUIRED_PUBLIC_POW_BITS);
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

    /// Returns the ring genesis public key, or `None` outside any ring.
    pub fn genesis_pubkey(&self) -> Option<[u8; 32]> {
        self.genesis_pubkey
    }

    fn persist(&self) {
        if let Some(ref path) = self.persistence_path {
            if let Ok(bytes) = bincode::serialize(self) {
                let _ = crate::storage::BlockStore::atomic_write_file(path, &bytes);
            }
        }
    }

    /// Records an admission change to be written by the next [`Self::flush`] (batched; a lost
    /// admission is recovered by the client's re-handshake).
    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Writes pending admission changes. The server loops call this on a timer.
    pub fn flush(&mut self) {
        if self.dirty {
            self.persist();
            self.dirty = false;
        }
    }

    /// Whether admission changes are waiting for [`Self::flush`].
    pub fn has_pending_writes(&self) -> bool {
        self.dirty
    }

    /// Sets the public-commons capacity (tests and small devices).
    pub fn set_public_commons_capacity(&mut self, capacity: usize) {
        self.public_commons_capacity = Some(capacity);
    }

    pub fn seen_slashing_nonces_count(&self) -> usize {
        self.seen_slashing_nonces.len()
    }

    /// The public-commons admission decision (F-05, F-29) for a ticket presented on the wire.
    pub fn public_ticket_decision(facts: &TicketFacts) -> Result<(), &'static str> {
        if !facts.public_commons_allowed {
            return Err("reject.public_commons_disabled");
        }
        if !facts.ticket_is_sender {
            return Err("reject.ticket_not_sender");
        }
        if facts.already_admitted {
            return Ok(());
        }
        if !facts.ticket_fresh {
            return Err("reject.ticket_stale");
        }
        if !facts.ticket_for_this_verifier {
            return Err("reject.ticket_wrong_verifier");
        }
        if !facts.within_rate {
            return Err("reject.ticket_rate_limited");
        }
        if !facts.ticket_valid {
            // PoW below the node's required bits, or a bad ticket signature.
            return Err("reject.ticket_insufficient_pow");
        }
        if !facts.capacity_available {
            return Err("reject.public_commons_full");
        }
        Ok(())
    }

    /// The PoW bits this node requires of a ticket.
    pub fn required_public_pow_bits(&self) -> u8 {
        self.min_public_pow_bits
    }

    /// Facts for [`Self::public_ticket_decision`] about `ticket` sent by `sender_pubkey`.
    ///
    /// `source_subnet` is the sender's `/24` or `/48`; one rate token is spent per new ticket.
    pub fn ticket_facts(
        &mut self,
        ticket: &PublicCommonsTicket,
        sender_pubkey: Option<[u8; 32]>,
        verifier_pubkey: [u8; 32],
        source_subnet: &str,
        now_ms: u64,
    ) -> TicketFacts {
        let ticket_is_sender = sender_pubkey == Some(ticket.peer_pubkey);
        let already_admitted = ticket_is_sender
            && !self.quarantined_keys.contains(&ticket.peer_pubkey)
            && (self.is_private_ring_peer(&ticket.peer_pubkey)
                || self.public_commons_peers.contains_key(&ticket.peer_pubkey));
        let ticket_fresh = now_ms.abs_diff(ticket.timestamp_ms) <= TICKET_FRESHNESS_WINDOW_MS;
        let ticket_for_this_verifier = ticket.verifier_pubkey == verifier_pubkey;
        let within_rate = already_admitted || self.spend_ticket_token(source_subnet, now_ms);
        if self.public_commons_peers.len() >= self.public_commons_capacity() {
            self.prune_expired_public_commons(now_ms);
        }
        TicketFacts {
            public_commons_allowed: self.trust_pool_mode.allows_public_commons(),
            ticket_is_sender,
            already_admitted,
            ticket_fresh,
            ticket_for_this_verifier,
            within_rate,
            ticket_valid: ticket.verify(self.min_public_pow_bits),
            capacity_available: self.public_commons_peers.len() < self.public_commons_capacity(),
        }
    }

    fn spend_ticket_token(&mut self, subnet: &str, now_ms: u64) -> bool {
        if !self.ticket_rate.contains_key(subnet)
            && self.ticket_rate.len() >= MAX_TRACKED_TICKET_SUBNETS
        {
            // Forget idle subnets (full buckets) before tracking a new one; if none is idle,
            // refuse rather than reset an active subnet's budget.
            self.ticket_rate.retain(|_, b| !b.is_full(now_ms));
            if self.ticket_rate.len() >= MAX_TRACKED_TICKET_SUBNETS {
                return false;
            }
        }
        self.ticket_rate
            .entry(subnet.to_string())
            .or_insert_with(|| SubnetTicketBudget::new(now_ms))
            .try_spend(now_ms)
    }

    /// Marks `pubkey` (the local node's own key) as never slashable.
    pub fn protect_key(&mut self, pubkey: [u8; 32]) {
        self.protected_keys.insert(pubkey);
    }

    /// The slash guard (F-01): the genesis and the node's own keys are never slash targets.
    pub fn slash_target_decision(facts: &SlashTargetFacts) -> Result<(), &'static str> {
        if facts.is_genesis || facts.is_protected {
            return Err("reject.slash_protected_target");
        }
        Ok(())
    }

    /// Runs the slash guard for `target`; logs and returns `false` for a protected key.
    #[cfg(test)]
    fn may_slash(&self, target: [u8; 32]) -> bool {
        let facts = SlashTargetFacts {
            is_genesis: self.genesis_pubkey == Some(target),
            is_protected: self.protected_keys.contains(&target),
        };
        match Self::slash_target_decision(&facts) {
            Ok(()) => true,
            Err(code) => {
                tracing::warn!(code, target = %hex::encode(target), "refused to slash a protected key");
                false
            }
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
    /// A node outside any ring (no genesis) admits no chain (F-37). Before this, ticket-only
    /// nodes used the all-zero key as a placeholder genesis, a small-order point for which a
    /// stranger could forge a hop.
    pub fn ring_handshake_decision(genesis: Option<[u8; 32]>) -> Result<[u8; 32], &'static str> {
        genesis.ok_or("reject.handshake_no_ring")
    }

    /// P-01: a delegation chain's shape: not empty, at most `MAX_DELEGATION_DEPTH` hops, and
    /// rooted at the ring genesis (`root_is_genesis`). Signatures and links are checked separately.
    pub fn verify_and_admit_chain_shape_decision(
        hops_len: usize,
        root_is_genesis: bool,
    ) -> Result<(), &'static str> {
        if hops_len == 0 {
            return Err("reject.chain_empty");
        }
        if hops_len as u64 > MAX_DELEGATION_DEPTH as u64 {
            return Err("reject.chain_too_deep");
        }
        if !root_is_genesis {
            return Err("reject.chain_untrusted_root");
        }
        Ok(())
    }

    pub fn verify_and_admit_chain(
        &mut self,
        chain: &DelegationChain,
    ) -> Result<[u8; 32], WebOfTrustError> {
        let len = chain.hops.len();
        let shape = |root_ok| {
            Self::verify_and_admit_chain_shape_decision(len, root_ok).map_err(|code| match code {
                "reject.chain_empty" => WebOfTrustError::EmptyChain,
                "reject.chain_too_deep" => WebOfTrustError::MaxDepthExceeded(len as u32),
                _ => WebOfTrustError::UntrustedGenesisRoot,
            })
        };
        // P-01: shape first (empty, depth), then the ring, then the root, as before.
        shape(true)?;
        let genesis = Self::ring_handshake_decision(self.genesis_pubkey)
            .map_err(|_| WebOfTrustError::NoRing)?;
        shape(chain.hops[0].inviter_pubkey == genesis)?;

        // Links and signatures first: quarantine state is consulted only for a chain that is
        // otherwise valid, so a forged probe cannot learn whether a key is quarantined (F-30).
        for (idx, hop) in chain.hops.iter().enumerate() {
            if idx > 0 && hop.inviter_pubkey != chain.hops[idx - 1].invitee_pubkey {
                return Err(WebOfTrustError::BrokenChainLink(idx));
            }
            if !hop.verify_signature() {
                return Err(WebOfTrustError::InvalidHopSignature(idx));
            }
        }
        if chain.hops.iter().any(|hop| {
            self.quarantined_keys.contains(&hop.inviter_pubkey)
                || self.quarantined_keys.contains(&hop.invitee_pubkey)
        }) {
            return Err(WebOfTrustError::QuarantinedSubtree);
        }

        let leaf = chain.leaf_pubkey().expect("checked non-empty");
        // Re-sending the chain already on record is a no-op that writes nothing (F-32).
        if self.admitted_chains.get(&leaf) == Some(chain) {
            return Ok(leaf);
        }
        let inviter = chain.hops.last().expect("checked non-empty").inviter_pubkey;
        let facts = ChainAdmissionFacts {
            inviter_is_genesis: inviter == genesis,
            inviter_subinvites: self
                .admitted_chains
                .values()
                .filter(|c| c.hops.last().map(|h| h.inviter_pubkey) == Some(inviter))
                .filter(|c| c.leaf_pubkey() != Some(leaf))
                .count(),
            new_leaf: !self.admitted_chains.contains_key(&leaf),
            admitted_total: self.admitted_chains.len(),
            capacity: self.admitted_chains_capacity.unwrap_or(MAX_ADMITTED_CHAINS),
        };
        if let Err(code) = Self::chain_admission_decision(&facts) {
            tracing::warn!(code, leaf = %hex::encode(leaf), "refused a chain admission");
            return Err(WebOfTrustError::ChainAdmissionLimit);
        }
        // Upgrading to a full PrivateRing chain supersedes any probationary PublicCommons ticket.
        self.public_commons_peers.remove(&leaf);
        self.admitted_chains.insert(leaf, chain.clone());
        self.mark_dirty();
        Ok(leaf)
    }

    /// Bounds chain admissions (F-32): a member (not the genesis) may sub-invite at most
    /// `MAX_SUBINVITES_PER_INVITER` keys, and the store holds at most `capacity` chains. When
    /// full, new leaves are refused; admitted chains are never evicted.
    pub fn chain_admission_decision(facts: &ChainAdmissionFacts) -> Result<(), &'static str> {
        if !facts.inviter_is_genesis && facts.inviter_subinvites >= MAX_SUBINVITES_PER_INVITER {
            return Err("reject.subinvite_limit");
        }
        if facts.new_leaf && facts.admitted_total >= facts.capacity {
            return Err("reject.admitted_chains_full");
        }
        Ok(())
    }

    /// Sets the chain-store capacity (tests and small devices).
    pub fn set_admitted_chains_capacity(&mut self, capacity: usize) {
        self.admitted_chains_capacity = Some(capacity);
    }

    /// Verifies and admits a stranger peer's self-signed Hashcash `PublicCommonsTicket` when
    /// operating in `PublicCommons` or `Hybrid` mode (`ADR-24`).
    /// P-01: a public-commons ticket is admitted only outside private-ring mode, for a key that
    /// is not quarantined, with valid proof of work.
    pub fn verify_and_admit_public_ticket_decision(
        private_ring_mode: bool,
        quarantined: bool,
        pow_ok: bool,
    ) -> Result<(), &'static str> {
        if private_ring_mode {
            return Err("reject.public_commons_disabled");
        }
        if quarantined {
            return Err("reject.public_peer_revoked");
        }
        if !pow_ok {
            return Err("reject.public_pow_insufficient");
        }
        Ok(())
    }

    pub fn verify_and_admit_public_ticket(
        &mut self,
        ticket: &PublicCommonsTicket,
    ) -> Result<(), WotError> {
        let private_ring = self.trust_pool_mode == TrustPoolMode::PrivateRing;
        let quarantined = self.quarantined_keys.contains(&ticket.peer_pubkey);
        let to_err = |code| match code {
            "reject.public_commons_disabled" => WotError::PublicCommonsDisabled,
            "reject.public_peer_revoked" => WotError::RevokedPeer,
            _ => WotError::InsufficientPublicPow,
        };
        // P-01: mode and revocation first, so a refused ticket costs no PoW verification.
        Self::verify_and_admit_public_ticket_decision(private_ring, quarantined, true)
            .map_err(to_err)?;
        let pow_ok = ticket.verify(self.min_public_pow_bits);
        Self::verify_and_admit_public_ticket_decision(private_ring, quarantined, pow_ok)
            .map_err(to_err)?;

        // Already admitted: a cheap no-op that writes nothing (F-29).
        if self.is_private_ring_peer(&ticket.peer_pubkey)
            || self.public_commons_peers.contains_key(&ticket.peer_pubkey)
        {
            return Ok(());
        }
        // Full: expired admissions make room; a live admission is never evicted (F-29).
        if self.public_commons_peers.len() >= self.public_commons_capacity() {
            self.prune_expired_public_commons(now_unix_ms());
        }
        if self.public_commons_peers.len() >= self.public_commons_capacity() {
            return Err(WotError::PublicCommonsFull);
        }
        self.public_commons_fifo.push_back(ticket.peer_pubkey);
        self.public_commons_peers
            .insert(ticket.peer_pubkey, ticket.clone());
        self.mark_dirty();
        Ok(())
    }

    fn public_commons_capacity(&self) -> usize {
        self.public_commons_capacity
            .unwrap_or(MAX_PUBLIC_COMMONS_PEERS)
    }

    /// Drops public-commons admissions older than `PUBLIC_COMMONS_ADMISSION_TTL_MS`.
    fn prune_expired_public_commons(&mut self, now_ms: u64) {
        let before = self.public_commons_peers.len();
        self.public_commons_peers.retain(|_, t| {
            t.timestamp_ms
                .saturating_add(PUBLIC_COMMONS_ADMISSION_TTL_MS)
                > now_ms
        });
        let peers = &self.public_commons_peers;
        self.public_commons_fifo.retain(|k| peers.contains_key(k));
        if self.public_commons_peers.len() != before {
            self.mark_dirty();
        }
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
    /// P-01: a quarantined key is never trusted (not even the genesis); otherwise the genesis,
    /// a private-ring member or a public-commons member is.
    pub fn is_peer_trust_decision(
        is_genesis: bool,
        quarantined: bool,
        private_member: bool,
        public_member: bool,
    ) -> Result<(), &'static str> {
        if quarantined {
            return Err("reject.peer_quarantined");
        }
        if !(is_genesis || private_member || public_member) {
            return Err("reject.peer_not_member");
        }
        Ok(())
    }

    pub fn is_peer_trusted(&self, peer_pubkey: &[u8; 32]) -> bool {
        let quarantined = self.quarantined_keys.contains(peer_pubkey);
        let is_genesis = self.genesis_pubkey == Some(*peer_pubkey);
        Self::is_peer_trust_decision(
            is_genesis,
            quarantined,
            !quarantined && !is_genesis && self.is_private_ring_peer(peer_pubkey),
            !quarantined && !is_genesis && self.is_public_commons_peer(peer_pubkey),
        )
        .is_ok()
    }

    /// Records a handshake or PoR failure for `offender_pubkey`.
    /// When `leaf_failures >= 3` (`MAX_LEAF_FAILURES`), immediately isolates the node and propagates
    /// a slash penalty up its parent inviter chain, pruning ancestor branches that hit `max_subtree_slashes`.
    #[cfg(test)] // P-01: no production caller since F-01 (slashing is local and test-only in v0.5.0).
    pub fn record_failure(&mut self, offender_pubkey: [u8; 32]) -> bool {
        if !self.may_slash(offender_pubkey) {
            return false;
        }
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
                    if self.genesis_pubkey == Some(parent) {
                        continue;
                    }
                    let branch_slashes = self.branch_slash_counts.entry(parent).or_insert(0);
                    *branch_slashes += 1;
                    let branch_hit = *branch_slashes >= self.max_subtree_slashes;
                    if branch_hit && self.may_slash(parent) {
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
    #[cfg(test)] // P-01: no production caller since F-01.
    pub fn slash_immediately(&mut self, offender_pubkey: [u8; 32]) -> bool {
        if !self.may_slash(offender_pubkey) {
            return false;
        }
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
                if self.genesis_pubkey == Some(parent) {
                    continue;
                }
                let branch_slashes = self.branch_slash_counts.entry(parent).or_insert(0);
                *branch_slashes += 1;
                let branch_hit = *branch_slashes >= self.max_subtree_slashes;
                if branch_hit && self.may_slash(parent) {
                    self.quarantined_keys.insert(parent);
                }
            }
        }
        self.persist();
        true
    }

    /// Processes a signed `SlashingEvidence` message received via Gossipsub.
    /// Deduplicates `(reporter_pubkey, offender_pubkey, nonce)` so replayed evidence cannot
    /// repeatedly increment `record_failure` (`ADR-05`). Test-only: nothing applies peer evidence
    /// in `v0.5.0` (slashing is local; architect 2b sign-off).
    #[cfg(test)]
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
    /// Moved from tests/phase1_to_4_integration.rs (P-01: record_failure is test-only). Verifies ADR-05: Web-of-Trust recursive delegation chains and subtree slashing within <= 3 failures.
    #[test]
    fn test_wot_delegation_and_subtree_slashing() {
        let genesis = NodeIdentity::generate();
        let inviter = NodeIdentity::generate();
        let honest_leaf = NodeIdentity::generate();
        let bad_leaf_1 = NodeIdentity::generate();
        let bad_leaf_2 = NodeIdentity::generate();

        let mut wot = WebOfTrustRegistry::new(genesis.public_key_bytes(), 2);

        let hop0 = InvitationHop::issue(&genesis, inviter.public_key_bytes(), 1, 100);
        let chain_honest = DelegationChain {
            hops: vec![
                hop0.clone(),
                InvitationHop::issue(&inviter, honest_leaf.public_key_bytes(), 2, 101),
            ],
        };
        let chain_bad1 = DelegationChain {
            hops: vec![
                hop0.clone(),
                InvitationHop::issue(&inviter, bad_leaf_1.public_key_bytes(), 2, 102),
            ],
        };
        let chain_bad2 = DelegationChain {
            hops: vec![
                hop0,
                InvitationHop::issue(&inviter, bad_leaf_2.public_key_bytes(), 2, 103),
            ],
        };

        wot.verify_and_admit_chain(&chain_honest).unwrap();
        wot.verify_and_admit_chain(&chain_bad1).unwrap();
        wot.verify_and_admit_chain(&chain_bad2).unwrap();

        // 3 failures isolate bad_leaf_1.
        assert!(!wot.record_failure(bad_leaf_1.public_key_bytes()));
        assert!(!wot.record_failure(bad_leaf_1.public_key_bytes()));
        assert!(wot.record_failure(bad_leaf_1.public_key_bytes()));
        assert!(!wot.is_peer_trusted(&bad_leaf_1.public_key_bytes()));
        // Honest sibling is still trusted after 1 slashed sibling (subtree limit = 2).
        assert!(wot.is_peer_trusted(&honest_leaf.public_key_bytes()));

        // 3 failures on bad_leaf_2 crosses inviter's subtree slash threshold (M=2), pruning the entire branch!
        wot.record_failure(bad_leaf_2.public_key_bytes());
        wot.record_failure(bad_leaf_2.public_key_bytes());
        wot.record_failure(bad_leaf_2.public_key_bytes());
        assert!(!wot.is_peer_trusted(&inviter.public_key_bytes()));
        assert!(!wot.is_peer_trusted(&honest_leaf.public_key_bytes()));
    }

    /// F-30 at the registry (moved from wire_handler_equivalence, P-01): a forged hop for a
    /// quarantined key and for an ordinary key are refused with the same error, so the handshake
    /// is not a quarantine oracle.
    #[test]
    fn f30_forged_hop_is_not_a_quarantine_oracle() {
        let genesis = NodeIdentity::generate();
        let rogue = NodeIdentity::generate();
        let quarantined = NodeIdentity::generate();
        let ordinary = NodeIdentity::generate();
        let mut wot = WebOfTrustRegistry::new(genesis.public_key_bytes(), 3);
        assert!(wot.slash_immediately(quarantined.public_key_bytes()));
        let forged = |leaf: &NodeIdentity| {
            let mut hop = InvitationHop::issue(&rogue, leaf.public_key_bytes(), 1, 100);
            hop.inviter_pubkey = genesis.public_key_bytes();
            DelegationChain { hops: vec![hop] }
        };
        let eq = wot.verify_and_admit_chain(&forged(&quarantined));
        let eo = wot.verify_and_admit_chain(&forged(&ordinary));
        assert!(eq.is_err());
        assert_eq!(format!("{eq:?}"), format!("{eo:?}"));
    }

    /// QA 2c R2: a node may require at most what a default client re-mints (16 bits).
    #[test]
    fn required_pow_bits_are_capped() {
        use super::*;

        assert_eq!(required_pow_bits_decision(16), Ok(()));
        assert_eq!(
            required_pow_bits_decision(17),
            Err("reject.required_pow_bits_excessive")
        );
        assert_eq!(
            ticket_pow_demand_decision(MAX_REQUIRED_PUBLIC_POW_BITS, DEFAULT_PUBLIC_WOT_POW_BITS),
            Ok(()),
            "every requirement a node may set is one a default client accepts"
        );
        let mut wot = WebOfTrustRegistry::new([1; 32], 3);
        wot.set_trust_pool_mode(TrustPoolMode::PublicCommons, 30);
        assert_eq!(wot.min_public_pow_bits(), MAX_REQUIRED_PUBLIC_POW_BITS);
    }

    /// QA 2c D1: a peer's PoW demand is capped, and mint never searches past the ceiling.
    #[test]
    fn ticket_pow_demand_is_bounded() {
        use super::*;
        assert_eq!(ticket_pow_demand_decision(12, 12), Ok(()));
        assert_eq!(ticket_pow_demand_decision(16, 12), Ok(()));
        assert_eq!(
            ticket_pow_demand_decision(17, 12),
            Err("reject.ticket_pow_demand_excessive")
        );
        assert_eq!(
            ticket_pow_demand_decision(255, 30),
            Err("reject.ticket_pow_demand_excessive")
        );
        assert_eq!(ticket_pow_demand_decision(20, 18), Ok(()));
        let started = std::time::Instant::now();
        let t = PublicCommonsTicket::mint(&NodeIdentity::from_seed([3; 32]), [4; 32], 1, 255);
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
        assert!(!t.verify(255), "a ticket declaring 255 bits never verifies");
    }

    #[test]
    fn f32_subinvites_and_chain_store_are_bounded() {
        let genesis = NodeIdentity::from_seed([0x47; 32]);
        let member = NodeIdentity::from_seed([0x48; 32]);
        let mut reg = WebOfTrustRegistry::new(genesis.public_key_bytes(), 3);
        let base = DelegationChain {
            hops: vec![InvitationHop::issue(
                &genesis,
                member.public_key_bytes(),
                1,
                1,
            )],
        };
        reg.verify_and_admit_chain(&base).unwrap();
        reg.flush();
        // Re-sending the same chain writes nothing.
        reg.verify_and_admit_chain(&base).unwrap();
        assert!(!reg.has_pending_writes());
        let sub = |n: u32| {
            let leaf = NodeIdentity::from_seed([(n % 250) as u8 + 1; 32]);
            let mut hops = base.hops.clone();
            hops.push(InvitationHop::issue(
                &member,
                {
                    let mut k = leaf.public_key_bytes();
                    k[31] = (n / 250) as u8;
                    k
                },
                2,
                1,
            ));
            DelegationChain { hops }
        };
        for n in 0..MAX_SUBINVITES_PER_INVITER as u32 {
            reg.verify_and_admit_chain(&sub(n)).unwrap();
        }
        assert_eq!(
            reg.verify_and_admit_chain(&sub(MAX_SUBINVITES_PER_INVITER as u32)),
            Err(WebOfTrustError::ChainAdmissionLimit)
        );
        assert_eq!(
            WebOfTrustRegistry::chain_admission_decision(&ChainAdmissionFacts {
                inviter_is_genesis: false,
                inviter_subinvites: MAX_SUBINVITES_PER_INVITER,
                new_leaf: true,
                admitted_total: 1,
                capacity: 10,
            }),
            Err("reject.subinvite_limit")
        );
        // A full store refuses new leaves and keeps the admitted ones.
        let mut reg = WebOfTrustRegistry::new(genesis.public_key_bytes(), 3);
        reg.set_admitted_chains_capacity(1);
        reg.verify_and_admit_chain(&base).unwrap();
        let other = NodeIdentity::from_seed([0x49; 32]);
        let second = DelegationChain {
            hops: vec![InvitationHop::issue(
                &genesis,
                other.public_key_bytes(),
                1,
                1,
            )],
        };
        assert_eq!(
            reg.verify_and_admit_chain(&second),
            Err(WebOfTrustError::ChainAdmissionLimit)
        );
        assert!(reg.is_private_ring_peer(&member.public_key_bytes()));
        assert_eq!(
            WebOfTrustRegistry::chain_admission_decision(&ChainAdmissionFacts {
                inviter_is_genesis: true,
                inviter_subinvites: 0,
                new_leaf: true,
                admitted_total: 1,
                capacity: 1,
            }),
            Err("reject.admitted_chains_full")
        );
    }

    fn public_registry(capacity: usize) -> WebOfTrustRegistry {
        let mut reg = WebOfTrustRegistry::new([0u8; 32], 3);
        reg.set_trust_pool_mode(TrustPoolMode::PublicCommons, 8);
        reg.set_public_commons_capacity(capacity);
        reg
    }

    #[test]
    fn f29_resent_ticket_is_a_no_op_that_writes_nothing() {
        let mut reg = public_registry(10);
        let me = NodeIdentity::from_seed([0x61; 32]);
        let verifier = [0x22; 32];
        let now = 1_800_000_000_000;
        let t = PublicCommonsTicket::mint(&me, verifier, now, 8);
        let f = reg.ticket_facts(
            &t,
            Some(me.public_key_bytes()),
            verifier,
            "198.51.100.0/24",
            now,
        );
        assert_eq!(WebOfTrustRegistry::public_ticket_decision(&f), Ok(()));
        reg.verify_and_admit_public_ticket(&t).unwrap();
        reg.flush();
        assert!(!reg.has_pending_writes());
        let f = reg.ticket_facts(
            &t,
            Some(me.public_key_bytes()),
            verifier,
            "198.51.100.0/24",
            now,
        );
        assert!(f.already_admitted);
        reg.verify_and_admit_public_ticket(&t).unwrap();
        assert!(!reg.has_pending_writes(), "a re-sent ticket writes nothing");
    }

    #[test]
    fn f29_ticket_rules() {
        let verifier = [0x22; 32];
        let now = 1_800_000_000_000;
        let facts = |reg: &mut WebOfTrustRegistry, seed: u8, ts: u64, v: [u8; 32], subnet: &str| {
            let id = NodeIdentity::from_seed([seed; 32]);
            let t = PublicCommonsTicket::mint(&id, v, ts, 8);
            reg.ticket_facts(&t, Some(id.public_key_bytes()), verifier, subnet, now)
        };
        let mut reg = public_registry(10);
        // Freshness: 11 minutes old is stale.
        let stale = facts(&mut reg, 1, now - 11 * 60_000, verifier, "a");
        assert_eq!(
            WebOfTrustRegistry::public_ticket_decision(&stale),
            Err("reject.ticket_stale")
        );
        // Bound to the verifier: a ticket for another node is refused.
        let other = facts(&mut reg, 2, now, [0x33; 32], "b");
        assert_eq!(
            WebOfTrustRegistry::public_ticket_decision(&other),
            Err("reject.ticket_wrong_verifier")
        );
        // Rate: a burst of 8 new tickets per subnet, the 9th is refused.
        let mut reg = public_registry(100);
        for seed in 10..18u8 {
            let f = facts(&mut reg, seed, now, verifier, "198.51.100.0/24");
            assert_eq!(WebOfTrustRegistry::public_ticket_decision(&f), Ok(()));
        }
        let ninth = facts(&mut reg, 18, now, verifier, "198.51.100.0/24");
        assert_eq!(
            WebOfTrustRegistry::public_ticket_decision(&ninth),
            Err("reject.ticket_rate_limited")
        );
        let elsewhere = facts(&mut reg, 19, now, verifier, "203.0.113.0/24");
        assert_eq!(
            WebOfTrustRegistry::public_ticket_decision(&elsewhere),
            Ok(())
        );
    }

    #[test]
    fn f29_full_registry_refuses_and_never_evicts_a_live_admission() {
        let mut reg = public_registry(2);
        let now = now_unix_ms();
        let verifier = [0x22; 32];
        let mut admitted = Vec::new();
        for seed in [0x71u8, 0x72] {
            let id = NodeIdentity::from_seed([seed; 32]);
            reg.verify_and_admit_public_ticket(&PublicCommonsTicket::mint(&id, verifier, now, 8))
                .unwrap();
            admitted.push(id.public_key_bytes());
        }
        let sybil = NodeIdentity::from_seed([0x73; 32]);
        let t = PublicCommonsTicket::mint(&sybil, verifier, now, 8);
        let f = reg.ticket_facts(&t, Some(sybil.public_key_bytes()), verifier, "x", now);
        assert_eq!(
            WebOfTrustRegistry::public_ticket_decision(&f),
            Err("reject.public_commons_full")
        );
        assert_eq!(
            reg.verify_and_admit_public_ticket(&t),
            Err(WotError::PublicCommonsFull)
        );
        for pk in admitted {
            assert!(reg.is_public_commons_peer(&pk), "live admissions stay");
        }
        // An expired admission makes room.
        let mut reg = public_registry(1);
        let old = NodeIdentity::from_seed([0x74; 32]);
        reg.verify_and_admit_public_ticket(&PublicCommonsTicket::mint(
            &old,
            verifier,
            now - PUBLIC_COMMONS_ADMISSION_TTL_MS - 1,
            8,
        ))
        .unwrap();
        assert!(reg.verify_and_admit_public_ticket(&t).is_ok());
    }

    #[test]
    fn genesis_and_own_keys_are_never_slashed() {
        let genesis = NodeIdentity::from_seed([0x47; 32]);
        let own = [0x0A; 32];
        let mut reg = WebOfTrustRegistry::new(genesis.public_key_bytes(), 3);
        reg.protect_key(own);
        for target in [genesis.public_key_bytes(), own] {
            assert!(!reg.slash_immediately(target));
            for _ in 0..MAX_LEAF_FAILURES {
                assert!(!reg.record_failure(target));
            }
            assert!(!reg.is_peer_quarantined(&target));
        }
        assert_eq!(
            WebOfTrustRegistry::slash_target_decision(&SlashTargetFacts {
                is_genesis: true,
                is_protected: false,
            }),
            Err("reject.slash_protected_target")
        );
        // An ordinary key is still slashable.
        assert!(reg.slash_immediately([0x0B; 32]));
        // A genesis chain stays valid after evidence names the genesis.
        let reporter = NodeIdentity::from_seed([0x81; 32]);
        reg.verify_and_admit_chain(&DelegationChain {
            hops: vec![InvitationHop::issue(
                &genesis,
                reporter.public_key_bytes(),
                1,
                1,
            )],
        })
        .unwrap();
        let evidence = SlashingEvidence::issue(
            &reporter,
            genesis.public_key_bytes(),
            SlashingReason::ByzantineShardPoisoning,
            1,
        );
        assert!(!reg.apply_slashing_evidence(&evidence));
        let newcomer = NodeIdentity::from_seed([0x83; 32]);
        assert!(reg
            .verify_and_admit_chain(&DelegationChain {
                hops: vec![InvitationHop::issue(
                    &genesis,
                    newcomer.public_key_bytes(),
                    1,
                    1
                )],
            })
            .is_ok());
    }

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

        let ticket =
            PublicCommonsTicket::mint(&stranger, [0u8; 32], now_ms, DEFAULT_PUBLIC_WOT_POW_BITS);
        assert_eq!(ticket.peer_pubkey, stranger.public_key_bytes());
        assert_eq!(ticket.pow_bits, DEFAULT_PUBLIC_WOT_POW_BITS);

        let digest = PublicCommonsTicket::pow_digest(
            &ticket.peer_pubkey,
            &ticket.verifier_pubkey,
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
        let low_pow_ticket = PublicCommonsTicket::mint(&stranger, [0u8; 32], now_ms, 4);
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
            PublicCommonsTicket::mint(&attacker, [0u8; 32], now_ms, DEFAULT_PUBLIC_WOT_POW_BITS);
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
            PublicCommonsTicket::mint(&stranger, [0u8; 32], now_ms, DEFAULT_PUBLIC_WOT_POW_BITS);

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
            Some(WebOfTrustRegistry::public_commons_genesis_pubkey())
        );

        let weak_ticket = PublicCommonsTicket::mint(&stranger, [0u8; 32], now_ms, 4);
        assert_eq!(
            public_wot.verify_and_admit_public_ticket(&weak_ticket),
            Err(WotError::InsufficientPublicPow)
        );

        public_wot
            .verify_and_admit_public_ticket(&stranger_ticket)
            .expect("valid 12-bit ticket must be admitted in PublicCommons mode");
        for rep in [&reporter1, &reporter2, &reporter3] {
            let rep_ticket =
                PublicCommonsTicket::mint(rep, [0u8; 32], now_ms, DEFAULT_PUBLIC_WOT_POW_BITS);
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
            let rep_ticket =
                PublicCommonsTicket::mint(rep, [0u8; 32], now_ms, DEFAULT_PUBLIC_WOT_POW_BITS);
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
        let ticket = PublicCommonsTicket::mint(
            &stranger,
            [0u8; 32],
            1_762_848_000_000,
            DEFAULT_PUBLIC_WOT_POW_BITS,
        );
        {
            let mut wot = WebOfTrustRegistry::with_public_commons_persistence_dir(
                DEFAULT_PUBLIC_WOT_POW_BITS,
                dir.path(),
            );
            wot.verify_and_admit_public_ticket(&ticket).unwrap();
            // Admissions are written in batches (F-29): nothing is on disk until a flush.
            assert!(wot.has_pending_writes());
            wot.flush();
        }
        let reloaded = WebOfTrustRegistry::with_public_commons_persistence_dir(
            DEFAULT_PUBLIC_WOT_POW_BITS,
            dir.path(),
        );
        assert!(reloaded.is_public_commons_peer(&stranger.public_key_bytes()));
        assert!(reloaded.is_peer_trusted(&stranger.public_key_bytes()));
    }
}
