use crate::crypto::keys::NodeIdentity;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;

/// Maximum invalid handshakes or unexcused PoR audit failures before immediate leaf isolation.
pub const MAX_LEAF_FAILURES: u32 = 3;

/// Default parent branch slash threshold (`M`) before pruning an entire delegated subtree.
pub const DEFAULT_SUBTREE_SLASH_LIMIT: u32 = 5;

/// Maximum delegation depth from Genesis Root key.
pub const MAX_DELEGATION_DEPTH: u32 = 8;

/// Maximum number of seen slashing evidence tuples retained in the bounded RAM anti-replay FIFO.
pub const MAX_SEEN_SLASHING_NONCES: usize = 65_536;

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
/// and recursive parent branch pruning (`network::wot`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebOfTrustRegistry {
    genesis_pubkey: [u8; 32],
    max_subtree_slashes: u32,
    /// Verified chain per admitted peer public key.
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
    #[serde(skip)]
    persistence_path: Option<std::path::PathBuf>,
}

impl WebOfTrustRegistry {
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
            persistence_path: None,
        }
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
        self.admitted_chains.insert(leaf, chain.clone());
        self.persist();
        Ok(leaf)
    }

    /// Checks whether a peer is currently admitted and none of its ancestor branches have been pruned.
    pub fn is_peer_trusted(&self, peer_pubkey: &[u8; 32]) -> bool {
        if *peer_pubkey == self.genesis_pubkey {
            return true;
        }
        if self.quarantined_keys.contains(peer_pubkey) {
            return false;
        }
        let Some(chain) = self.admitted_chains.get(peer_pubkey) else {
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
        self.admitted_chains
            .keys()
            .filter(|k| self.is_peer_trusted(k))
            .count()
    }

    pub fn quarantined_count(&self) -> usize {
        self.quarantined_keys.len()
    }
}
