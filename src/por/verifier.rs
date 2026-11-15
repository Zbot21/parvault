//! Formal model: `specs/ParVaultProtocol.tla` (guards `read-auth-owner`, `read-auth-repair`).
//! Formal model: `specs/ParVaultPorAudit.tla` (guard `chunk-storer`).
use crate::config::ErasureTier;
use crate::crypto::keys::NodeIdentity;
use crate::por::challenger::{
    compute_challenge_hmac, compute_multi_challenge_hmac, compute_multi_salted_commitment,
    compute_salted_commitment, MultiSegmentPorChallenge, PorChallenge, PorResponse,
};
use crate::sharding::merkle::{Hash32, MerkleProof};
use crate::storage::{BlockStore, ShardId, StorageError};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;

/// Minimum co-signed witness failure receipts required to unlock raw ciphertext shard reads
/// during an offline cohort repair (ADR-04).
pub const MIN_WITNESS_SIGNATURES_FOR_REPAIR: usize = 2;

/// Witness keys a registered grant may name (B-113, A-113 C1): one seed plus repair witnesses.
/// A grant naming more registers nothing, so the storer check scans at most this many keys.
pub const MAX_GRANT_WITNESSES: usize = 8;

/// What the grant-registration decision needs to know (F-02a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantRegFacts {
    /// The grant's owner signature verifies.
    pub grant_valid: bool,
    /// The grant names the stripe of the shard that was just stored (`true` when no shard is
    /// involved).
    pub root_matches: bool,
    /// How many witness keys the grant names (B59-WITNESS-BOUND).
    pub witnesses_len: usize,
}

/// Registers a grant only if it is valid, names at most [`MAX_GRANT_WITNESSES`] witnesses and
/// names the stripe of the shard stored with it. Grants are keyed by (stripe root, owner), so
/// one owner's grant never replaces another's (F-26); which grant authorises a shard is decided
/// per shard (`grant_owner_decision`).
pub fn grant_registration_decision(facts: &GrantRegFacts) -> Result<(), &'static str> {
    if !facts.grant_valid {
        return Err("reject.repair_grant_invalid");
    }
    if facts.witnesses_len > MAX_GRANT_WITNESSES {
        return Err("reject.repair_grant_too_many_witnesses");
    }
    if !facts.root_matches {
        return Err("reject.repair_grant_root_mismatch");
    }
    Ok(())
}

/// B-113 (A-113 C9): a same-owner grant replaces the registered one for its stripe only if it
/// names every witness the registered one names. Otherwise the registered grant stays (the put
/// is still stored), so a host holding an older grant with fewer witnesses cannot strip a
/// witness's audit arm. Keys compare on all 32 bytes.
pub fn grant_replace_decision(
    registered: Option<&[[u8; 32]]>,
    incoming: &[[u8; 32]],
) -> Result<(), &'static str> {
    match registered {
        Some(old) if !old.iter().all(|w| incoming.contains(w)) => {
            Err("reject.repair_grant_witness_downgrade")
        }
        _ => Ok(()),
    }
}

/// What the PoR pre-screen knows about a challenge, all from RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PorPrescreenFacts {
    pub range_ok: bool,
    pub session_known: bool,
    pub fresh: bool,
    pub nonce_unseen: bool,
    pub hmac_valid: bool,
}

/// ADR-03 / E-WIRE: a host answers a PoR challenge (and reads disk) only if the challenge names a
/// bounded range of a shard it holds a session key for, is fresh and unseen, and carries that
/// key's HMAC. Only the key holder can make the host read disk.
pub fn por_prescreen_decision(f: &PorPrescreenFacts) -> Result<(), &'static str> {
    if !f.range_ok {
        return Err("reject.por_range_invalid");
    }
    if !f.session_known {
        return Err("reject.por_session_unknown");
    }
    if !f.fresh || !f.nonce_unseen {
        return Err("reject.por_stale_or_replayed");
    }
    if !f.hmac_valid {
        return Err("reject.por_hmac_invalid");
    }
    Ok(())
}

/// The keys a registered grant lets audit its shard: the owner and the witnesses it signed
/// over (ADR-04). `witnesses.len() <= MAX_GRANT_WITNESSES`, enforced at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantStorers<'a> {
    pub owner: [u8; 32],
    pub witnesses: &'a [[u8; 32]],
}

/// What the chunk-audit storer decision knows, all from RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PorStorerFacts<'a> {
    /// The Noise-authenticated sender's device id.
    pub sender_device_id: Option<&'a str>,
    /// The same peer's Ed25519 key (`WirePeer::pubkey`).
    pub sender_key: Option<[u8; 32]>,
    /// The quota's shard owner (F-04: the key that stored the shard here).
    pub accounted_owner: Option<&'a str>,
    /// The grant registered for this shard (F-38-GRANT binding), if any.
    pub grant: Option<GrantStorers<'a>>,
}

/// L-101 / verdict change 1, B-113: a host answers a chunk audit only to the storer of the
/// shard. With a grant registered for the shard, the storer is the grant's owner or a witness
/// it names, and nothing else is read (no fall-through: the accounted owner of a handed-off
/// shard is refused). With no grant, it is the peer the shard is accounted to (F-34-STORER).
/// The per-stripe session key is held by every host of the stripe, so the HMAC alone would let
/// a co-host fetch this shard's chunks or spend the owner's audit budget. Checked in RAM before
/// the rate check and any read.
pub fn por_storer_decision(f: &PorStorerFacts<'_>) -> Result<(), &'static str> {
    match (&f.grant, f.sender_key) {
        (Some(g), Some(k)) if k == g.owner || g.witnesses.contains(&k) => Ok(()),
        (Some(_), _) => Err("reject.por_not_storer"),
        (None, _) => match (f.sender_device_id, f.accounted_owner) {
            (Some(s), Some(o)) if s == o => Ok(()),
            _ => Err("reject.por_not_storer"),
        },
    }
}

/// Chunk audits one session key may ask for per window (the owner's budget per stripe).
pub const CHUNK_AUDITS_PER_SESSION_WINDOW: usize = 6;
/// The per-session window: 10 minutes.
pub const CHUNK_AUDIT_SESSION_WINDOW_MS: u64 = 600_000;
/// Chunk audits a host proves per minute in all (desktop and NAS).
pub const CHUNK_AUDITS_PER_MINUTE_HOST: usize = 60;
/// The same on `router-soc` (verdict change 8, ADR-21): 12 per minute of 1 MiB shards is
/// about 1.2 s CPU per minute on a MIPS 24Kc at the plan's inferred rate.
pub const CHUNK_AUDITS_PER_MINUTE_ROUTER: usize = 12;
/// Session keys the rate map tracks; when full it refuses new keys, it never evicts.
pub const MAX_CHUNK_RATE_KEYS: usize = 4096;

/// What the chunk-audit rate decision knows, all from RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PorRateFacts {
    pub session_in_window: usize,
    pub host_last_minute: usize,
    pub host_per_minute_cap: usize,
    /// Audits this owner (the authenticated storer) had proved in the last minute.
    pub owner_last_minute: usize,
    /// This owner's share of the host cap ([`owner_minute_share`]).
    pub owner_per_minute_cap: usize,
    /// P1: this owner had no audit proved here in the last session window (10 min). Only a
    /// quiet owner may take the host's last slot of the minute.
    pub owner_quiet: bool,
    /// The key is new and the map already holds `MAX_CHUNK_RATE_KEYS` live keys.
    pub map_full_for_new_key: bool,
}

/// D2 (fairness): an owner's share of the per-host minute cap when `other_owners` other owners
/// had audits proved in the last minute: the cap split across the active owners plus one free
/// share, with a floor of 1. The floor alone does not protect a quiet owner once the active
/// owners number the cap, so [`por_rate_decision`] also keeps the host's last slot of each
/// minute for an owner with no audit here in the last 10 minutes (P1).
pub fn owner_minute_share(host_cap: usize, other_owners: usize) -> usize {
    (host_cap / other_owners.saturating_add(2)).max(1)
}

/// F-06-RATE: at most 6 chunk audits per session key per 10 minutes, a per-host cap per
/// minute and each owner's share of it (D2); a full rate map refuses (no eviction an attacker
/// could drive).
pub fn por_rate_decision(f: &PorRateFacts) -> Result<(), &'static str> {
    if f.map_full_for_new_key
        || f.session_in_window >= CHUNK_AUDITS_PER_SESSION_WINDOW
        || f.host_last_minute >= f.host_per_minute_cap
        || (!f.owner_quiet && f.host_last_minute.saturating_add(1) >= f.host_per_minute_cap)
        || f.owner_last_minute >= f.owner_per_minute_cap
    {
        return Err("reject.por_rate_limited");
    }
    Ok(())
}

/// RAM-only counters behind [`por_rate_decision`].
#[derive(Debug, Default)]
struct ChunkRateState {
    per_session: HashMap<[u8; 32], VecDeque<u64>>,
    /// Proved audits in the last minute and their owner (bounded by the host cap).
    host_minute: VecDeque<(u64, String)>,
    /// P1: owner -> time of its last proved audit, for the last session window. Bounded by
    /// `MAX_CHUNK_RATE_KEYS`; an owner not in a full map counts as not quiet.
    owner_last_proved: HashMap<String, u64>,
    host_per_minute_cap: Option<usize>,
}

impl ChunkRateState {
    fn prune(&mut self, now: u64) {
        while self
            .host_minute
            .front()
            .is_some_and(|(t, _)| now.saturating_sub(*t) >= 60_000)
        {
            self.host_minute.pop_front();
        }
        self.owner_last_proved
            .retain(|_, t| now.saturating_sub(*t) < CHUNK_AUDIT_SESSION_WINDOW_MS);
        self.per_session.retain(|_, q| {
            while q
                .front()
                .is_some_and(|t| now.saturating_sub(*t) >= CHUNK_AUDIT_SESSION_WINDOW_MS)
            {
                q.pop_front();
            }
            !q.is_empty()
        });
    }

    fn facts(&self, key: &[u8; 32], owner: &str) -> PorRateFacts {
        let session = self.per_session.get(key);
        let host_cap = self
            .host_per_minute_cap
            .unwrap_or(CHUNK_AUDITS_PER_MINUTE_HOST);
        let others: std::collections::BTreeSet<&str> = self
            .host_minute
            .iter()
            .map(|(_, o)| o.as_str())
            .filter(|o| *o != owner)
            .collect();
        PorRateFacts {
            session_in_window: session.map_or(0, VecDeque::len),
            host_last_minute: self.host_minute.len(),
            host_per_minute_cap: host_cap,
            owner_last_minute: self.host_minute.iter().filter(|(_, o)| o == owner).count(),
            owner_per_minute_cap: owner_minute_share(host_cap, others.len()),
            owner_quiet: !self.owner_last_proved.contains_key(owner)
                && self.owner_last_proved.len() < MAX_CHUNK_RATE_KEYS,
            map_full_for_new_key: session.is_none()
                && self.per_session.len() >= MAX_CHUNK_RATE_KEYS,
        }
    }

    fn record(&mut self, key: [u8; 32], owner: &str, now: u64) {
        self.per_session.entry(key).or_default().push_back(now);
        self.host_minute.push_back((now, owner.to_string()));
        if self.owner_last_proved.contains_key(owner)
            || self.owner_last_proved.len() < MAX_CHUNK_RATE_KEYS
        {
            self.owner_last_proved.insert(owner.to_string(), now);
        }
    }
}

/// What a host needs to build the proofs off the swarm task once a challenge is admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkProveSpec {
    pub shard_id: ShardId,
    pub nonce: [u8; 32],
    pub chunk_indices: Vec<u32>,
    pub shard_len: u64,
}

/// What the shard-rebind decision needs to know (F-38-GRANT, L-41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardRebindFacts {
    /// The shard is in the block store now (not merely remembered by the verifier).
    pub stored: bool,
    /// The owner of the grant the stored shard is bound to, if any.
    pub existing_grant_owner: Option<[u8; 32]>,
    /// The owner of the grant this put carries, if any.
    pub incoming_grant_owner: Option<[u8; 32]>,
    /// The sender is the key the stored shard is accounted to.
    pub sender_is_accounted_owner: bool,
}

/// How a permitted put treats the shard's binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardBinding {
    /// Store and (re)register: the shard is new, or its owner re-puts it.
    Bind,
    /// Already stored for the same grant owner by another sender (repair, handoff, seed
    /// re-forward, replay): ack as stored and change nothing.
    Keep,
}

/// First writer wins (F-38-GRANT, L-41): while a shard is stored, its accounted owner, grant
/// owner and PoR session commit never change hands. Grant owners compare on all 32 bytes.
pub fn shard_rebind_decision(facts: &ShardRebindFacts) -> Result<ShardBinding, &'static str> {
    if !facts.stored {
        return Ok(ShardBinding::Bind);
    }
    let grant_unchanged = match (facts.existing_grant_owner, facts.incoming_grant_owner) {
        (Some(existing), Some(incoming)) => existing == incoming,
        _ => true,
    };
    if facts.sender_is_accounted_owner && grant_unchanged {
        return Ok(ShardBinding::Bind);
    }
    match (facts.existing_grant_owner, facts.incoming_grant_owner) {
        (Some(existing), Some(incoming))
            if !facts.sender_is_accounted_owner && existing == incoming =>
        {
            Ok(ShardBinding::Keep)
        }
        _ => Err("reject.shard_bound_to_another_owner"),
    }
}

/// The refusal code of `shard_rebind_decision`, taken from the decision itself so the code has
/// one source (a grant naming another owner for a stored shard).
pub fn shard_bound_to_another_owner_code() -> &'static str {
    let facts = ShardRebindFacts {
        stored: true,
        existing_grant_owner: Some([0; 32]),
        incoming_grant_owner: Some([1; 32]),
        sender_is_accounted_owner: false,
    };
    shard_rebind_decision(&facts).err().unwrap_or_default()
}

/// A read or delete authorised by a grant owner applies only to shards that were stored with
/// that owner's grant (F-26): an owner who registered a grant for the same stripe root first
/// gains nothing over another owner's shards.
pub fn grant_owner_decision(
    grant_owner: &[u8; 32],
    shard_grant_owner: Option<&[u8; 32]>,
) -> Result<(), &'static str> {
    if shard_grant_owner == Some(grant_owner) {
        Ok(())
    } else {
        Err("reject.grant_owner_not_shard_owner")
    }
}

/// What the shard-delete decision needs to know (F-36).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardDeleteFacts {
    /// The owner of the grant the shard was stored with, if any.
    pub grant_owner: Option<[u8; 32]>,
    /// The key that signed the delete token.
    pub signer: [u8; 32],
    /// The signer's device id is the one the shard is accounted to (it stored the shard).
    pub signer_is_accounted_owner: bool,
}

/// A shard may be deleted by the owner of the grant it was stored with, or, without a grant, by
/// the key that stored it (F-36).
pub fn shard_delete_decision(facts: &ShardDeleteFacts) -> Result<(), &'static str> {
    let allowed = match facts.grant_owner {
        Some(owner) => owner == facts.signer,
        None => facts.signer_is_accounted_owner,
    };
    if allowed {
        Ok(())
    } else {
        Err("reject.delete_not_shard_owner")
    }
}

/// What the repair-read decision needs to know (F-02b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairReadFacts {
    /// The presented grant equals the grant registered for the stripe (owner, witnesses, tier).
    pub grant_is_registered: bool,
    /// Distinct witnesses named by that grant who signed a valid failure receipt.
    pub valid_witness_receipts: usize,
}

/// A witness-cohort repair read needs the registered grant and enough of its witnesses.
pub fn repair_read_decision(facts: &RepairReadFacts) -> Result<(), &'static str> {
    if !facts.grant_is_registered {
        return Err("reject.repair_grant_unregistered");
    }
    if facts.valid_witness_receipts < MIN_WITNESS_SIGNATURES_FOR_REPAIR {
        return Err("reject.repair_witness_quorum");
    }
    Ok(())
}

/// Maximum clock skew / expiration window for stateless PoR challenges (30 seconds).
pub const CHALLENGE_FRESHNESS_WINDOW_MS: u64 = 30_000;

/// Maximum number of seen PoR challenge nonces retained in the bounded RAM FIFO ring buffer.
pub const MAX_SEEN_NONCES_RAM: usize = 65_536;

/// Maximum byte length allowed for a single PoR range read challenge (64 KiB) to prevent disk I/O amplification.
pub const MAX_POR_RANGE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum PorError {
    #[error("No registered session key in RAM for shard {0}")]
    UnknownSessionKey(String),
    #[error("Stateless HMAC pre-verification failed (dropped with 0 disk I/O)")]
    InvalidHmacToken,
    #[error("Expired or replayed challenge nonce (dropped with 0 disk I/O)")]
    StaleOrReplayedNonce,
    #[error("Storage error during verified range read: {0}")]
    Storage(#[from] StorageError),
    #[error("Unauthorized raw ciphertext shard read: missing valid owner token or threshold RepairGrant")]
    UnauthorizedRawShardRead,
    #[error("Rejected witness repair deposit: invalid Merkle inclusion proof or ASN eclipse concentration")]
    RepairSinkEclipseOrInvalidMerkleProof,
}

/// Owner-signed capability delegating offline audit & repair coordination to designated
/// cohort Witness Nodes for a specific stripe Merkle root (ADR-04).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepairGrant {
    pub stripe_merkle_root: Hash32,
    pub owner_pubkey: [u8; 32],
    pub authorized_witness_pubkeys: Vec<[u8; 32]>,
    pub tier: ErasureTier,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl RepairGrant {
    pub fn issue(
        owner: &NodeIdentity,
        stripe_merkle_root: Hash32,
        authorized_witness_pubkeys: Vec<[u8; 32]>,
        tier: ErasureTier,
    ) -> Self {
        let owner_pubkey = owner.public_key_bytes();
        let msg = Self::canonical_bytes(
            &stripe_merkle_root,
            &owner_pubkey,
            &authorized_witness_pubkeys,
            tier,
        );
        let sig = owner.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Self {
            stripe_merkle_root,
            owner_pubkey,
            authorized_witness_pubkeys,
            tier,
            sig_r,
            sig_s,
        }
    }

    pub fn verify(&self) -> bool {
        let msg = Self::canonical_bytes(
            &self.stripe_merkle_root,
            &self.owner_pubkey,
            &self.authorized_witness_pubkeys,
            self.tier,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.owner_pubkey, &msg, &sig)
    }

    fn canonical_bytes(
        stripe_merkle_root: &Hash32,
        owner_pubkey: &[u8; 32],
        witnesses: &[[u8; 32]],
        tier: ErasureTier,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + witnesses.len() * 32);
        buf.extend_from_slice(b"parvault-repair-grant-v1:");
        buf.extend_from_slice(stripe_merkle_root);
        buf.extend_from_slice(owner_pubkey);
        let (k, m, _) = tier.params();
        buf.push(k as u8);
        buf.push(m as u8);
        for w in witnesses {
            buf.extend_from_slice(w);
        }
        buf
    }
}

/// Signed attestation by a designated Witness Node certifying that a shard host failed PoR (ADR-04).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessFailureReceipt {
    pub stripe_merkle_root: Hash32,
    pub failed_shard_index: u32,
    pub witness_pubkey: [u8; 32],
    pub observed_at_unix_ms: u64,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl WitnessFailureReceipt {
    pub fn issue(
        witness: &NodeIdentity,
        stripe_merkle_root: Hash32,
        failed_shard_index: u32,
        observed_at_unix_ms: u64,
    ) -> Self {
        let witness_pubkey = witness.public_key_bytes();
        let msg = Self::canonical_bytes(
            &stripe_merkle_root,
            failed_shard_index,
            &witness_pubkey,
            observed_at_unix_ms,
        );
        let sig = witness.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Self {
            stripe_merkle_root,
            failed_shard_index,
            witness_pubkey,
            observed_at_unix_ms,
            sig_r,
            sig_s,
        }
    }

    pub fn verify(&self) -> bool {
        let msg = Self::canonical_bytes(
            &self.stripe_merkle_root,
            self.failed_shard_index,
            &self.witness_pubkey,
            self.observed_at_unix_ms,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.witness_pubkey, &msg, &sig)
    }

    fn canonical_bytes(
        stripe_merkle_root: &Hash32,
        failed_shard_index: u32,
        witness_pubkey: &[u8; 32],
        observed_at_unix_ms: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(b"parvault-witness-fail-v1:");
        buf.extend_from_slice(stripe_merkle_root);
        buf.extend_from_slice(&failed_shard_index.to_be_bytes());
        buf.extend_from_slice(witness_pubkey);
        buf.extend_from_slice(&observed_at_unix_ms.to_be_bytes());
        buf
    }
}

/// Result of evaluating a peer's PoR response on the challenger/verifier side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditOutcome {
    pub passed: bool,
    pub rtt_ms: u64,
    pub trigger_proactive_repair: bool,
    pub slash_peer: bool,
}

/// The persisted state before F-26 (grants keyed by stripe root only), read on upgrade.
#[derive(Serialize, Deserialize, Default)]
struct PersistedPorStateV1 {
    session_keys: HashMap<String, [u8; 32]>,
    repair_grants: HashMap<Hash32, RepairGrant>,
}

/// The persisted state since F-26: grants keyed by (stripe root, owner) and the grant owner each
/// stored shard was stored with.
#[derive(Serialize, Deserialize, Default)]
struct PersistedPorState {
    version: u32,
    session_keys: HashMap<String, [u8; 32]>,
    repair_grants: HashMap<(Hash32, [u8; 32]), RepairGrant>,
    shard_grant_owners: HashMap<String, [u8; 32]>,
}

const POR_STATE_VERSION: u32 = 2;

/// Stateless PoR verification, DDoS pre-filtering, and `RepairGrant` authorization engine (`por::verifier`).
pub struct PorVerifierEngine {
    /// Latency ceiling in milliseconds (default 300 ms).
    pub max_latency_ms: u64,
    /// In-memory map of `shard_file_key -> K_session` for zero-disk-I/O challenge authentication.
    session_keys_ram: HashMap<String, [u8; 32]>,
    /// In-memory set of recently seen challenge nonces to block replay attacks in RAM.
    seen_nonces_ram: HashSet<[u8; 32]>,
    /// Bounded FIFO queue ordering `seen_nonces_ram` so RAM usage never exceeds `MAX_SEEN_NONCES_RAM`.
    seen_nonces_fifo: VecDeque<[u8; 32]>,
    /// Registered `RepairGrant` descriptors indexed by (`stripe_merkle_root`, owner key).
    repair_grants_ram: HashMap<(Hash32, [u8; 32]), RepairGrant>,
    /// The owner of the grant each stored shard (file key) was stored with (F-26).
    shard_grant_owners: HashMap<String, [u8; 32]>,
    /// Counter of disk reads prevented by RAM-only stateless HMAC/nonce rejection.
    blocked_ddos_challenges: u64,
    /// Chunk-audit rate state, RAM only (B-59).
    chunk_rate: ChunkRateState,
    /// Optional path to persist `session_keys_ram` and `repair_grants_ram` across daemon restarts.
    persistence_path: Option<std::path::PathBuf>,
}

impl PorVerifierEngine {
    pub fn new(max_latency_ms: u64) -> Self {
        Self {
            max_latency_ms,
            session_keys_ram: HashMap::new(),
            seen_nonces_ram: HashSet::new(),
            seen_nonces_fifo: VecDeque::new(),
            repair_grants_ram: HashMap::new(),
            shard_grant_owners: HashMap::new(),
            blocked_ddos_challenges: 0,
            chunk_rate: ChunkRateState::default(),
            persistence_path: None,
        }
    }

    /// Initializes `PorVerifierEngine` backed by `data_dir/por_verifier_state.bin` so
    /// `repair_grants` and `session_keys` survive daemon restarts.
    pub fn with_persistence_dir(max_latency_ms: u64, data_dir: &std::path::Path) -> Self {
        let _ = std::fs::create_dir_all(data_dir);
        let path = data_dir.join("por_verifier_state.bin");
        let state = std::fs::read(&path)
            .ok()
            .and_then(|bytes| {
                bincode::deserialize::<PersistedPorState>(&bytes)
                    .ok()
                    .filter(|s| s.version == POR_STATE_VERSION)
                    .or_else(|| {
                        // Upgrade: re-key v1 grants by owner; shard owners are unknown, so old
                        // shards are readable again after their owner's next put.
                        bincode::deserialize::<PersistedPorStateV1>(&bytes)
                            .ok()
                            .map(|v1| PersistedPorState {
                                version: POR_STATE_VERSION,
                                session_keys: v1.session_keys,
                                repair_grants: v1
                                    .repair_grants
                                    .into_values()
                                    .map(|g| ((g.stripe_merkle_root, g.owner_pubkey), g))
                                    .collect(),
                                shard_grant_owners: HashMap::new(),
                            })
                    })
            })
            .unwrap_or_default();
        let (session_keys_ram, repair_grants_ram, shard_grant_owners) = (
            state.session_keys,
            state.repair_grants,
            state.shard_grant_owners,
        );
        Self {
            max_latency_ms,
            session_keys_ram,
            seen_nonces_ram: HashSet::new(),
            seen_nonces_fifo: VecDeque::new(),
            repair_grants_ram,
            shard_grant_owners,
            blocked_ddos_challenges: 0,
            chunk_rate: ChunkRateState::default(),
            persistence_path: Some(path),
        }
    }

    fn persist_state_if_configured(&self) {
        if let Some(ref path) = self.persistence_path {
            let state = PersistedPorState {
                version: POR_STATE_VERSION,
                session_keys: self.session_keys_ram.clone(),
                repair_grants: self.repair_grants_ram.clone(),
                shard_grant_owners: self.shard_grant_owners.clone(),
            };
            if let Ok(encoded) = bincode::serialize(&state) {
                let _ = std::fs::write(path, encoded);
            }
        }
    }

    pub const fn blocked_ddos_challenges(&self) -> u64 {
        self.blocked_ddos_challenges
    }

    pub fn seen_nonces_count(&self) -> usize {
        self.seen_nonces_ram.len()
    }

    fn record_seen_nonce(&mut self, nonce: [u8; 32]) {
        while self.seen_nonces_ram.len() >= MAX_SEEN_NONCES_RAM {
            if let Some(oldest) = self.seen_nonces_fifo.pop_front() {
                self.seen_nonces_ram.remove(&oldest);
            } else {
                break;
            }
        }
        if self.seen_nonces_ram.insert(nonce) {
            self.seen_nonces_fifo.push_back(nonce);
        }
    }

    /// Registers a 32-byte `K_session` key in RAM when a shard is stored.
    pub fn register_shard_session(&mut self, shard_id: &ShardId, session_key: [u8; 32]) {
        self.session_keys_ram
            .insert(shard_id.file_key(), session_key);
        self.persist_state_if_configured();
    }

    /// Registers an owner-signed `RepairGrant` for a stripe in RAM (ADR-04).
    pub fn register_repair_grant(&mut self, grant: RepairGrant) -> bool {
        let root = grant.stripe_merkle_root;
        self.register_grant(grant, &root, &[]).is_ok()
    }

    /// Registers `grant` after `stored` shards were stored with it (F-02a, F-26); `Err` carries
    /// the reason code. Each of those shards records the grant's owner.
    pub fn register_repair_grant_for_stored(
        &mut self,
        grant: RepairGrant,
        stored: &[ShardId],
    ) -> Result<(), &'static str> {
        let root = stored
            .first()
            .map(|s| s.stripe_merkle_root)
            .unwrap_or(grant.stripe_merkle_root);
        self.register_grant(grant, &root, stored)
    }

    fn register_grant(
        &mut self,
        grant: RepairGrant,
        stored_root: &Hash32,
        stored: &[ShardId],
    ) -> Result<(), &'static str> {
        let facts = GrantRegFacts {
            grant_valid: grant.verify(),
            root_matches: grant.stripe_merkle_root == *stored_root
                && stored.iter().all(|s| s.stripe_merkle_root == *stored_root),
            witnesses_len: grant.authorized_witness_pubkeys.len(),
        };
        grant_registration_decision(&facts)?;
        // F-38-GRANT: never replace a different owner a shard is already bound to.
        if stored.iter().any(|shard| {
            self.shard_grant_owners
                .get(&shard.file_key())
                .is_some_and(|o| *o != grant.owner_pubkey)
        }) {
            return Err(shard_bound_to_another_owner_code());
        }
        for shard in stored {
            self.shard_grant_owners
                .insert(shard.file_key(), grant.owner_pubkey);
        }
        let key = (grant.stripe_merkle_root, grant.owner_pubkey);
        let registered = self
            .repair_grants_ram
            .get(&key)
            .map(|g| g.authorized_witness_pubkeys.as_slice());
        // C9: the shards bind to this owner either way; only a witness superset replaces
        // the registered grant.
        if let Err(code) = grant_replace_decision(registered, &grant.authorized_witness_pubkeys) {
            tracing::warn!(
                code,
                "kept the registered grant (its witnesses are not all named)"
            );
        } else {
            self.repair_grants_ram.insert(key, grant);
        }
        self.persist_state_if_configured();
        Ok(())
    }

    /// The owner of the grant `shard_id` is bound to, if any (F-38-GRANT).
    pub fn shard_grant_owner(&self, shard_id: &ShardId) -> Option<[u8; 32]> {
        self.shard_grant_owners.get(&shard_id.file_key()).copied()
    }

    /// Forgets `shard_id`'s binding (session commit and grant owner): on delete, and before a
    /// fresh `Bind` of a shard no longer stored (e.g. LRU-evicted), so a stale owner keeps
    /// nothing over the new owner's shard (F-38-GRANT).
    pub fn clear_shard_binding(&mut self, shard_id: &ShardId) {
        let key = shard_id.file_key();
        let had_session = self.session_keys_ram.remove(&key).is_some();
        if self.shard_grant_owners.remove(&key).is_some() || had_session {
            self.persist_state_if_configured();
        }
    }

    /// The grant `shard_id` was stored with, if any.
    fn grant_for_shard(&self, shard_id: &ShardId) -> Option<&RepairGrant> {
        let owner = self.shard_grant_owners.get(&shard_id.file_key())?;
        self.repair_grants_ram
            .get(&(shard_id.stripe_merkle_root, *owner))
    }

    /// Retrieves the registered `K_session` and `RepairGrant` for `shard_id` (used during graceful node handoff).
    pub fn get_shard_session_and_grant(
        &self,
        shard_id: &ShardId,
    ) -> (Option<[u8; 32]>, Option<RepairGrant>) {
        (
            self.session_keys_ram.get(&shard_id.file_key()).copied(),
            self.grant_for_shard(shard_id).cloned(),
        )
    }

    /// Constructs and signs a domain-separated owner shard-delete token.
    /// A signed delete as in `ADR-19` (no ADR covers owner deletes of unblinded shards).
    pub fn sign_owner_shard_delete_token(
        owner: &NodeIdentity,
        shard_id: &ShardId,
        timestamp_ms: u64,
    ) -> ([u8; 32], Vec<u8>, [u8; 64]) {
        let owner_pub = owner.public_key_bytes();
        let mut payload = Vec::with_capacity(74);
        payload.extend_from_slice(b"parvault-owner-shard-delete-v1:");
        payload.extend_from_slice(&shard_id.stripe_merkle_root);
        payload.extend_from_slice(&shard_id.shard_index.to_be_bytes());
        payload.extend_from_slice(&timestamp_ms.to_be_bytes());
        let sig = owner.sign(&payload);
        (owner_pub, payload, sig)
    }

    /// Verifies an owner-signed unblinded shard deletion request against the stripe's `RepairGrant.owner_pubkey`.
    ///
    /// `accounted_owner` is the device id the shard is accounted to (the key that stored it).
    pub fn authorize_owner_shard_delete(
        &mut self,
        shard_id: &ShardId,
        owner_pub: &[u8; 32],
        signed_payload: &[u8],
        sig: &[u8; 64],
        accounted_owner: Option<&str>,
    ) -> bool {
        const DOMAIN_PREFIX: &[u8] = b"parvault-owner-shard-delete-v1:";
        let expected_min_len = DOMAIN_PREFIX.len() + 32 + 4 + 8;
        if signed_payload.len() < expected_min_len
            || !signed_payload.starts_with(DOMAIN_PREFIX)
            || &signed_payload[DOMAIN_PREFIX.len()..DOMAIN_PREFIX.len() + 32]
                != shard_id.stripe_merkle_root.as_slice()
            || &signed_payload[DOMAIN_PREFIX.len() + 32..DOMAIN_PREFIX.len() + 36]
                != shard_id.shard_index.to_be_bytes().as_slice()
        {
            return false;
        }
        if !NodeIdentity::verify_with_pubkey(owner_pub, signed_payload, sig) {
            return false;
        }
        let facts = ShardDeleteFacts {
            grant_owner: self.grant_for_shard(shard_id).map(|g| g.owner_pubkey),
            signer: *owner_pub,
            signer_is_accounted_owner: accounted_owner
                == Some(NodeIdentity::device_peer_id_for_pubkey(owner_pub).as_str()),
        };
        let authorized = match shard_delete_decision(&facts) {
            Ok(()) => true,
            Err(code) => {
                tracing::warn!(code, "refused a shard delete signed by another key");
                false
            }
        };
        if authorized {
            self.clear_shard_binding(shard_id);
        }
        authorized
    }

    /// Runs [`por_prescreen_decision`] for one challenge; a refusal is logged with its code,
    /// counted, and mapped to the existing `PorError`.
    #[allow(clippy::too_many_arguments)]
    fn prescreen(
        &mut self,
        range_ok: bool,
        session_known: bool,
        issued_at_unix_ms: u64,
        nonce: &[u8; 32],
        hmac_valid: bool,
        now_unix_ms: u64,
        shard_id: &ShardId,
    ) -> Result<(), PorError> {
        let facts = PorPrescreenFacts {
            range_ok,
            session_known,
            fresh: now_unix_ms.abs_diff(issued_at_unix_ms) <= CHALLENGE_FRESHNESS_WINDOW_MS,
            nonce_unseen: !self.seen_nonces_ram.contains(nonce),
            hmac_valid,
        };
        por_prescreen_decision(&facts).map_err(|code| {
            self.blocked_ddos_challenges += 1;
            tracing::warn!(code, "refused a PoR challenge before any disk read");
            if facts.range_ok && !facts.session_known {
                PorError::UnknownSessionKey(shard_id.file_key())
            } else if facts.range_ok && (!facts.fresh || !facts.nonce_unseen) {
                PorError::StaleOrReplayedNonce
            } else {
                PorError::InvalidHmacToken
            }
        })
    }

    /// Sets the per-host chunk-audit cap per minute (`router-soc` uses
    /// [`CHUNK_AUDITS_PER_MINUTE_ROUTER`]).
    pub fn set_chunk_audit_host_cap(&mut self, per_minute: usize) {
        self.chunk_rate.host_per_minute_cap = Some(per_minute);
    }

    /// Admits a [`ChunkChallenge`] on the host, all in RAM until the last step: the storer
    /// binding ([`por_storer_decision`]), then the pre-screen (width `1..=8`, distinct indices,
    /// session key, freshness, nonce, HMAC under `parvault-por-chunk-v1:`), then the rate
    /// ([`por_rate_decision`]), then index bounds from the shard length (`stat_len`, a stat,
    /// no read). Returns what the prover needs; the read happens off the swarm task.
    pub fn admit_chunk_challenge(
        &mut self,
        ch: &crate::por::ChunkChallenge,
        sender_key: Option<[u8; 32]>,
        accounted_owner: Option<&str>,
        now_unix_ms: u64,
        stat_len: impl FnOnce() -> Option<u64>,
    ) -> Result<ChunkProveSpec, &'static str> {
        let sender_id = sender_key.map(|pk| NodeIdentity::device_peer_id_for_pubkey(&pk));
        let sender_device_id = sender_id.as_deref();
        let storer = por_storer_decision(&PorStorerFacts {
            sender_device_id,
            sender_key,
            accounted_owner,
            grant: self.grant_for_shard(&ch.shard_id).map(|g| GrantStorers {
                owner: g.owner_pubkey,
                witnesses: &g.authorized_witness_pubkeys,
            }),
        });
        if let Err(code) = storer {
            self.blocked_ddos_challenges += 1;
            return Err(code);
        }
        let n = ch.chunk_indices.len();
        let distinct = ch
            .chunk_indices
            .iter()
            .enumerate()
            .all(|(k, i)| !ch.chunk_indices[..k].contains(i));
        let range_ok = (1..=crate::por::MAX_CHUNK_AUDIT_WIDTH).contains(&n) && distinct;
        let session_key = self.session_keys_ram.get(&ch.shard_id.file_key()).copied();
        let hmac_valid = session_key.is_some_and(|k| {
            crate::por::compute_chunk_challenge_hmac(
                &k,
                &ch.shard_id,
                &ch.nonce,
                &ch.chunk_indices,
                ch.issued_at_unix_ms,
            ) == ch.hmac_token
        });
        let facts = PorPrescreenFacts {
            range_ok,
            session_known: session_key.is_some(),
            fresh: now_unix_ms.abs_diff(ch.issued_at_unix_ms) <= CHALLENGE_FRESHNESS_WINDOW_MS,
            nonce_unseen: !self.seen_nonces_ram.contains(&ch.nonce),
            hmac_valid,
        };
        if let Err(code) = por_prescreen_decision(&facts) {
            self.blocked_ddos_challenges += 1;
            return Err(code);
        }
        let key = session_key.expect("prescreen passed, so the key is known");
        // The storer check passed, so the sender is the authenticated storer.
        let owner = sender_device_id.unwrap_or_default();
        self.chunk_rate.prune(now_unix_ms);
        if let Err(code) = por_rate_decision(&self.chunk_rate.facts(&key, owner)) {
            self.blocked_ddos_challenges += 1;
            return Err(code);
        }
        self.record_seen_nonce(ch.nonce);
        self.chunk_rate.record(key, owner, now_unix_ms);
        let Some(shard_len) = stat_len() else {
            return Err("reject.por_shard_missing");
        };
        let count = crate::por::chunk_merkle::chunk_count_u64(shard_len);
        if ch.chunk_indices.iter().any(|&i| i >= count) {
            return Err("reject.por_range_invalid");
        }
        Ok(ChunkProveSpec {
            shard_id: ch.shard_id,
            nonce: ch.nonce,
            chunk_indices: ch.chunk_indices.clone(),
            shard_len,
        })
    }

    /// Handles an incoming `PorChallenge` on the storage host node (`P_x`):
    /// 1. Validates `H_chal` and nonce freshness **strictly in RAM** before any disk access.
    /// 2. If valid, reads the requested byte range from `BlockStore` and returns `SHA-256(Nonce || Data)`.
    pub fn handle_incoming_challenge(
        &mut self,
        challenge: &PorChallenge,
        now_unix_ms: u64,
        block_store: &BlockStore,
    ) -> Result<PorResponse, PorError> {
        let range_ok = challenge.length != 0 && challenge.length <= MAX_POR_RANGE_BYTES;
        let session_key = self
            .session_keys_ram
            .get(&challenge.shard_id.file_key())
            .copied();
        // 1. Range, session key, freshness, nonce and HMAC, all in RAM (0 disk I/O).
        let hmac_valid = session_key.is_some_and(|k| {
            compute_challenge_hmac(
                &k,
                &challenge.shard_id,
                &challenge.nonce,
                challenge.offset,
                challenge.length,
                challenge.issued_at_unix_ms,
            ) == challenge.hmac_token
        });
        self.prescreen(
            range_ok,
            session_key.is_some(),
            challenge.issued_at_unix_ms,
            &challenge.nonce,
            hmac_valid,
            now_unix_ms,
            &challenge.shard_id,
        )?;

        // Record nonce in bounded RAM replay filter.
        self.record_seen_nonce(challenge.nonce);

        // 2. Pre-verification succeeded: perform bounded disk read and compute salted commitment.
        let data_slice =
            block_store.get_shard_range(&challenge.shard_id, challenge.offset, challenge.length)?;
        let commitment = compute_salted_commitment(&challenge.nonce, &data_slice);

        Ok(PorResponse {
            shard_id: challenge.shard_id,
            nonce: challenge.nonce,
            commitment,
        })
    }

    /// Constructs and signs a domain-separated owner shard-read token (`ADR-04`), preventing
    /// cross-protocol signature replay of public `RepairGrant` or DHT manifest signatures.
    pub fn sign_owner_shard_read_token(
        owner: &NodeIdentity,
        shard_id: &ShardId,
        timestamp_ms: u64,
    ) -> ([u8; 32], Vec<u8>, [u8; 64]) {
        let owner_pub = owner.public_key_bytes();
        let mut payload = Vec::with_capacity(72);
        payload.extend_from_slice(b"parvault-owner-shard-read-v1:");
        payload.extend_from_slice(&shard_id.stripe_merkle_root);
        payload.extend_from_slice(&shard_id.shard_index.to_be_bytes());
        payload.extend_from_slice(&timestamp_ms.to_be_bytes());
        let sig = owner.sign(&payload);
        (owner_pub, payload, sig)
    }

    /// Authorizes a raw ciphertext shard read request for restore or offline witness repair (ADR-04).
    /// Raw bytes are NEVER served unless either:
    /// - The file owner signs a domain-separated `"parvault-owner-shard-read-v1:"` token bound to `shard_id`, OR
    /// - A valid `RepairGrant` is presented along with `>= 2` distinct witness-signed failure receipts.
    pub fn authorize_raw_shard_read(
        &self,
        shard_id: &ShardId,
        owner_sig: Option<&([u8; 32], &[u8], &[u8; 64])>,
        repair_bundle: Option<(&RepairGrant, &[WitnessFailureReceipt])>,
        block_store: &BlockStore,
    ) -> Result<Vec<u8>, PorError> {
        // Case A: Direct owner-signed read request (with strict domain-tag & shard_id binding).
        if let Some((owner_pub, signed_payload, sig)) = owner_sig {
            const DOMAIN_PREFIX: &[u8] = b"parvault-owner-shard-read-v1:";
            let expected_min_len = DOMAIN_PREFIX.len() + 32 + 4 + 8;
            if signed_payload.len() >= expected_min_len
                && signed_payload.starts_with(DOMAIN_PREFIX)
                && &signed_payload[DOMAIN_PREFIX.len()..DOMAIN_PREFIX.len() + 32]
                    == shard_id.stripe_merkle_root.as_slice()
                && &signed_payload[DOMAIN_PREFIX.len() + 32..DOMAIN_PREFIX.len() + 36]
                    == shard_id.shard_index.to_be_bytes().as_slice()
                && NodeIdentity::verify_with_pubkey(owner_pub, signed_payload, sig)
            {
                let registered = self
                    .repair_grants_ram
                    .contains_key(&(shard_id.stripe_merkle_root, *owner_pub));
                match grant_owner_decision(
                    owner_pub,
                    self.shard_grant_owners.get(&shard_id.file_key()),
                ) {
                    Ok(()) if registered => return Ok(block_store.get_shard(shard_id)?),
                    Ok(()) => {}
                    Err(code) => {
                        tracing::warn!(code, "refused an owner read of another owner's shard")
                    }
                }
            }
        }

        // Case B: Offline Witness Cohort Repair (`RepairGrant` + >= 2 distinct witness signatures).
        if let Some((grant, receipts)) = repair_bundle {
            if grant.stripe_merkle_root == shard_id.stripe_merkle_root && grant.verify() {
                let registered = self
                    .repair_grants_ram
                    .get(&(shard_id.stripe_merkle_root, grant.owner_pubkey))
                    .filter(|_| {
                        grant_owner_decision(
                            &grant.owner_pubkey,
                            self.shard_grant_owners.get(&shard_id.file_key()),
                        )
                        .is_ok()
                    });
                let authorized_set: HashSet<[u8; 32]> =
                    grant.authorized_witness_pubkeys.iter().copied().collect();
                let mut valid_signers: HashSet<[u8; 32]> = HashSet::new();

                for receipt in receipts {
                    if receipt.stripe_merkle_root == shard_id.stripe_merkle_root
                        && authorized_set.contains(&receipt.witness_pubkey)
                        && receipt.verify()
                    {
                        valid_signers.insert(receipt.witness_pubkey);
                    }
                }

                let facts = RepairReadFacts {
                    grant_is_registered: registered == Some(grant),
                    valid_witness_receipts: valid_signers.len(),
                };
                match repair_read_decision(&facts) {
                    Ok(()) => return Ok(block_store.get_shard(shard_id)?),
                    Err(code) => tracing::warn!(code, "refused a witness-cohort repair read"),
                }
            }
        }

        Err(PorError::UnauthorizedRawShardRead)
    }

    /// Evaluates a storage peer's `PorResponse` against expected commitment, 300 ms SLA latency,
    /// and the stripe's proactive repair watermark (`18/20` for Homelab, `16/20` for Consumer).
    pub fn verify_audit_response(
        &self,
        expected_commitment: &[u8; 32],
        response: Option<&PorResponse>,
        rtt_ms: u64,
        tier: ErasureTier,
        currently_healthy_shards: usize,
    ) -> AuditOutcome {
        let passed = match response {
            Some(resp) => rtt_ms <= self.max_latency_ms && &resp.commitment == expected_commitment,
            None => false,
        };

        let effective_healthy = if passed {
            currently_healthy_shards
        } else {
            currently_healthy_shards.saturating_sub(1)
        };

        let trigger_proactive_repair = effective_healthy <= tier.repair_trigger_watermark();

        AuditOutcome {
            passed,
            rtt_ms,
            trigger_proactive_repair,
            slash_peer: !passed,
        }
    }

    /// Evaluates a storage peer's `PorResponse` while also enforcing exact `shard_id` and `nonce`
    /// binding against the issued `PorChallenge`.
    pub fn verify_challenge_audit_response(
        &self,
        challenge: &PorChallenge,
        expected_commitment: &[u8; 32],
        response: Option<&PorResponse>,
        rtt_ms: u64,
        tier: ErasureTier,
        currently_healthy_shards: usize,
    ) -> AuditOutcome {
        let passed = match response {
            Some(resp) => {
                rtt_ms <= self.max_latency_ms
                    && resp.shard_id == challenge.shard_id
                    && resp.nonce == challenge.nonce
                    && &resp.commitment == expected_commitment
            }
            None => false,
        };

        let effective_healthy = if passed {
            currently_healthy_shards
        } else {
            currently_healthy_shards.saturating_sub(1)
        };

        let trigger_proactive_repair = effective_healthy <= tier.repair_trigger_watermark();

        AuditOutcome {
            passed,
            rtt_ms,
            trigger_proactive_repair,
            slash_peer: !passed,
        }
    }

    /// Handles a stratified `MultiSegmentPorChallenge` on the storage host (`P_x`):
    /// 1. Validates `hmac_token` and nonce freshness in RAM (0 disk I/O).
    /// 2. Reads all `M` non-contiguous strata and computes the chained salted commitment.
    pub fn handle_multi_segment_challenge(
        &mut self,
        challenge: &MultiSegmentPorChallenge,
        now_unix_ms: u64,
        block_store: &BlockStore,
    ) -> Result<PorResponse, PorError> {
        let range_ok = !challenge.segments.is_empty()
            && challenge.segments.len() <= 64
            && challenge
                .segments
                .iter()
                .all(|seg| seg.length != 0 && seg.length <= MAX_POR_RANGE_BYTES);
        let session_key = self
            .session_keys_ram
            .get(&challenge.shard_id.file_key())
            .copied();
        let hmac_valid = session_key.is_some_and(|k| {
            compute_multi_challenge_hmac(
                &k,
                &challenge.shard_id,
                &challenge.nonce,
                &challenge.segments,
                challenge.max_rtt_ms,
                challenge.issued_at_unix_ms,
            ) == challenge.hmac_token
        });
        self.prescreen(
            range_ok,
            session_key.is_some(),
            challenge.issued_at_unix_ms,
            &challenge.nonce,
            hmac_valid,
            now_unix_ms,
            &challenge.shard_id,
        )?;

        self.record_seen_nonce(challenge.nonce);

        let mut slices = Vec::with_capacity(challenge.segments.len());
        for seg in &challenge.segments {
            let bytes = block_store.get_shard_range(&challenge.shard_id, seg.offset, seg.length)?;
            slices.push(bytes);
        }
        let commitment = compute_multi_salted_commitment(&challenge.nonce, &slices);

        Ok(PorResponse {
            shard_id: challenge.shard_id,
            nonce: challenge.nonce,
            commitment,
        })
    }

    /// Evaluates a peer's response to a `MultiSegmentPorChallenge`, enforcing both the
    /// chained multi-segment commitment (anti-partial-retention) AND the per-challenge
    /// `max_rtt_ms` bound (anti-WAN-proxy outsourcing).
    pub fn verify_multi_segment_audit(
        &self,
        challenge: &MultiSegmentPorChallenge,
        expected_commitment: &[u8; 32],
        response: Option<&PorResponse>,
        rtt_ms: u64,
        tier: ErasureTier,
        currently_healthy_shards: usize,
    ) -> AuditOutcome {
        let rtt_limit = challenge.max_rtt_ms.min(self.max_latency_ms);
        let passed = match response {
            Some(resp) => {
                rtt_ms <= rtt_limit
                    && resp.shard_id == challenge.shard_id
                    && resp.nonce == challenge.nonce
                    && &resp.commitment == expected_commitment
            }
            None => false,
        };

        let effective_healthy = if passed {
            currently_healthy_shards
        } else {
            currently_healthy_shards.saturating_sub(1)
        };

        AuditOutcome {
            passed,
            rtt_ms,
            trigger_proactive_repair: effective_healthy <= tier.repair_trigger_watermark(),
            slash_peer: !passed,
        }
    }

    /// Zero-Trust Repair-Sink Eclipse Defense:
    /// Validates a witness-reconstructed shard before a replacement storage node accepts it:
    /// 1. Verifies the owner's `RepairGrant` signature.
    /// 2. Verifies the `MerkleProof` inclusion path of `shard_bytes` against `stripe_merkle_root`
    ///    (proving the witness reconstructed the exact authentic shard in `GF(2^8)` without `K_user`).
    /// 3. Verifies that placing the shard on `candidate_asn` does not violate `max_shards_per_asn`
    ///    across `existing_cohort_asns`, preventing colluding witnesses from concentrating repaired
    ///    shards into a single Sybil ASN ("Repair-Sink Eclipse Attack").
    pub fn verify_witness_repair_deposit(
        shard_id: &ShardId,
        shard_bytes: &[u8],
        merkle_proof: &MerkleProof,
        repair_grant: &RepairGrant,
        candidate_asn: u32,
        existing_cohort_asns: &[u32],
        max_shards_per_asn: usize,
    ) -> Result<(), PorError> {
        if !repair_grant.verify() || repair_grant.stripe_merkle_root != shard_id.stripe_merkle_root
        {
            return Err(PorError::RepairSinkEclipseOrInvalidMerkleProof);
        }
        if merkle_proof.root != shard_id.stripe_merkle_root
            || merkle_proof.shard_index != shard_id.shard_index
            || !merkle_proof.verify(shard_bytes)
        {
            return Err(PorError::RepairSinkEclipseOrInvalidMerkleProof);
        }

        let current_asn_count = existing_cohort_asns
            .iter()
            .filter(|&&asn| asn == candidate_asn)
            .count();
        if current_asn_count >= max_shards_per_asn {
            return Err(PorError::RepairSinkEclipseOrInvalidMerkleProof);
        }

        Ok(())
    }
}

/// Signed cryptographic evidence that a storage node passed lightweight PoR audits for `shard_id`
/// (farming reciprocity credits) but withheld or refused bulk shard egress at restore time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressWithholdingEvidence {
    pub offender_pubkey: [u8; 32],
    pub reporter_pubkey: [u8; 32],
    pub shard_id: ShardId,
    pub prior_por_commitment: [u8; 32],
    pub por_passed_at_unix_ms: u64,
    pub restore_failed_at_unix_ms: u64,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl EgressWithholdingEvidence {
    pub fn issue(
        reporter: &NodeIdentity,
        offender_pubkey: [u8; 32],
        shard_id: ShardId,
        prior_por_commitment: [u8; 32],
        por_passed_at_unix_ms: u64,
        restore_failed_at_unix_ms: u64,
    ) -> Self {
        let reporter_pubkey = reporter.public_key_bytes();
        let msg = Self::canonical_bytes(
            &offender_pubkey,
            &reporter_pubkey,
            &shard_id,
            &prior_por_commitment,
            por_passed_at_unix_ms,
            restore_failed_at_unix_ms,
        );
        let sig = reporter.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);

        Self {
            offender_pubkey,
            reporter_pubkey,
            shard_id,
            prior_por_commitment,
            por_passed_at_unix_ms,
            restore_failed_at_unix_ms,
            sig_r,
            sig_s,
        }
    }

    pub fn verify(&self) -> bool {
        if self.restore_failed_at_unix_ms < self.por_passed_at_unix_ms {
            return false;
        }
        let msg = Self::canonical_bytes(
            &self.offender_pubkey,
            &self.reporter_pubkey,
            &self.shard_id,
            &self.prior_por_commitment,
            self.por_passed_at_unix_ms,
            self.restore_failed_at_unix_ms,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.reporter_pubkey, &msg, &sig)
    }

    fn canonical_bytes(
        offender_pubkey: &[u8; 32],
        reporter_pubkey: &[u8; 32],
        shard_id: &ShardId,
        prior_por_commitment: &[u8; 32],
        por_passed_at_unix_ms: u64,
        restore_failed_at_unix_ms: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(180);
        buf.extend_from_slice(b"parvault-withhold-v1:");
        buf.extend_from_slice(offender_pubkey);
        buf.extend_from_slice(reporter_pubkey);
        buf.extend_from_slice(&shard_id.stripe_merkle_root);
        buf.extend_from_slice(&shard_id.shard_index.to_be_bytes());
        buf.extend_from_slice(&shard_id.shard_hash);
        buf.extend_from_slice(prior_por_commitment);
        buf.extend_from_slice(&por_passed_at_unix_ms.to_be_bytes());
        buf.extend_from_slice(&restore_failed_at_unix_ms.to_be_bytes());
        buf
    }
}

#[cfg(test)]
mod decision_tests {
    use super::*;

    /// E-WIRE PorAudit / MultiSegmentPorAudit: range, session, freshness, then the HMAC.
    #[test]
    fn por_prescreen_decision_rules() {
        let ok = PorPrescreenFacts {
            range_ok: true,
            session_known: true,
            fresh: true,
            nonce_unseen: true,
            hmac_valid: true,
        };
        assert_eq!(por_prescreen_decision(&ok), Ok(()));
        let with = |f: &dyn Fn(&mut PorPrescreenFacts)| {
            let mut x = ok;
            f(&mut x);
            por_prescreen_decision(&x)
        };
        assert_eq!(
            with(&|f| f.range_ok = false),
            Err("reject.por_range_invalid")
        );
        assert_eq!(
            with(&|f| f.session_known = false),
            Err("reject.por_session_unknown")
        );
        assert_eq!(
            with(&|f| f.fresh = false),
            Err("reject.por_stale_or_replayed")
        );
        assert_eq!(
            with(&|f| f.nonce_unseen = false),
            Err("reject.por_stale_or_replayed")
        );
        assert_eq!(
            with(&|f| f.hmac_valid = false),
            Err("reject.por_hmac_invalid")
        );
    }

    #[test]
    fn grant_and_repair_read_decisions() {
        let base = GrantRegFacts {
            grant_valid: true,
            root_matches: true,
            witnesses_len: MAX_GRANT_WITNESSES,
        };
        assert_eq!(grant_registration_decision(&base), Ok(()));
        assert_eq!(grant_owner_decision(&[1; 32], Some(&[1; 32])), Ok(()));
        assert_eq!(
            grant_owner_decision(&[1; 32], Some(&[2; 32])),
            Err("reject.grant_owner_not_shard_owner")
        );
        assert_eq!(
            grant_owner_decision(&[1; 32], None),
            Err("reject.grant_owner_not_shard_owner")
        );
        let cases = [
            (
                GrantRegFacts {
                    grant_valid: false,
                    ..base
                },
                "reject.repair_grant_invalid",
            ),
            (
                GrantRegFacts {
                    root_matches: false,
                    ..base
                },
                "reject.repair_grant_root_mismatch",
            ),
        ];
        for (facts, code) in cases {
            assert_eq!(grant_registration_decision(&facts), Err(code));
        }
        let read = |grant_is_registered, valid_witness_receipts| {
            repair_read_decision(&RepairReadFacts {
                grant_is_registered,
                valid_witness_receipts,
            })
        };
        assert_eq!(read(true, 2), Ok(()));
        let del = |grant_owner, signer_is_accounted_owner| {
            shard_delete_decision(&ShardDeleteFacts {
                grant_owner,
                signer: [1; 32],
                signer_is_accounted_owner,
            })
        };
        assert_eq!(del(Some([1; 32]), false), Ok(()));
        assert_eq!(
            del(Some([2; 32]), true),
            Err("reject.delete_not_shard_owner")
        );
        assert_eq!(del(None, true), Ok(()));
        assert_eq!(del(None, false), Err("reject.delete_not_shard_owner"));
        assert_eq!(read(false, 2), Err("reject.repair_grant_unregistered"));
        assert_eq!(read(true, 1), Err("reject.repair_witness_quorum"));
    }
}

#[cfg(test)]
mod chunk_admit_tests {
    use super::*;
    use crate::por::{generate_chunk_challenge, ChunkChallenge};

    const OWNER_K: [u8; 32] = [0x0A; 32];
    const CO_HOST_K: [u8; 32] = [0x0B; 32];
    const WITNESS_K: [u8; 32] = [0x0C; 32];

    fn id(k: &[u8; 32]) -> String {
        NodeIdentity::device_peer_id_for_pubkey(k)
    }
    const KEY: [u8; 32] = [7; 32];
    const NOW: u64 = 1_800_000_000_000;

    fn sid(i: u32) -> ShardId {
        ShardId {
            stripe_merkle_root: [1; 32],
            shard_index: i,
            shard_hash: [i as u8; 32],
        }
    }

    fn engine() -> PorVerifierEngine {
        let mut e = PorVerifierEngine::new(300);
        for i in 0..4 {
            e.register_shard_session(&sid(i), KEY);
        }
        e
    }

    fn admit(
        e: &mut PorVerifierEngine,
        ch: &ChunkChallenge,
        sender: [u8; 32],
        now: u64,
    ) -> Result<ChunkProveSpec, &'static str> {
        // 3 chunks: 8193 bytes.
        e.admit_chunk_challenge(ch, Some(sender), Some(&id(&OWNER_K)), now, || Some(8193))
    }

    #[test]
    fn storer_decision_needs_the_accounted_owner() {
        let owner = id(&OWNER_K);
        let no_grant = |sender: Option<&str>, accounted: Option<&str>| {
            por_storer_decision(&PorStorerFacts {
                sender_device_id: sender,
                sender_key: None,
                accounted_owner: accounted,
                grant: None,
            })
        };
        assert_eq!(no_grant(Some(&owner), Some(&owner)), Ok(()));
        assert_eq!(
            no_grant(Some("co-host"), Some(&owner)),
            Err("reject.por_not_storer")
        );
        assert_eq!(no_grant(None, Some(&owner)), Err("reject.por_not_storer"));
        assert_eq!(no_grant(Some(&owner), None), Err("reject.por_not_storer"));
    }

    /// B-113: every arm of the storer decision. With a grant, only the grant owner and its
    /// witnesses pass, on all 32 bytes, and the accounted owner is not read (no fall-through).
    #[test]
    fn storer_decision_grant_arms() {
        let departed = [0x0D; 32];
        let witnesses = [WITNESS_K];
        let grant = Some(GrantStorers {
            owner: OWNER_K,
            witnesses: &witnesses,
        });
        let with = |key: Option<[u8; 32]>, accounted: &[u8; 32]| {
            let sender = key.map(|k| id(&k));
            por_storer_decision(&PorStorerFacts {
                sender_device_id: sender.as_deref(),
                sender_key: key,
                accounted_owner: Some(&id(accounted)),
                grant,
            })
        };
        assert_eq!(with(Some(OWNER_K), &departed), Ok(()));
        assert_eq!(with(Some(WITNESS_K), &departed), Ok(()));
        // The departing node, the accounted owner, is refused once a grant is registered.
        assert_eq!(
            with(Some(departed), &departed),
            Err("reject.por_not_storer")
        );
        assert_eq!(
            with(Some(CO_HOST_K), &departed),
            Err("reject.por_not_storer")
        );
        assert_eq!(with(None, &departed), Err("reject.por_not_storer"));
        // One byte off the owner key (same device-id prefix) is refused.
        let mut near = OWNER_K;
        near[31] ^= 1;
        assert_eq!(id(&near), id(&OWNER_K));
        assert_eq!(with(Some(near), &OWNER_K), Err("reject.por_not_storer"));
    }

    /// B59-WITNESS-BOUND and C9 (unit): nine witnesses register nothing; a same-owner grant
    /// with fewer witnesses keeps the registered one, a superset replaces it.
    /// B59-WITNESS-BOUND at the full bound, on the real functions: 8 witnesses register, 9 are
    /// refused and bind nothing; over 8 keys, a 7-key subset is a downgrade and the 8 replace 7.
    #[test]
    fn grant_witness_bound_at_eight() {
        let owner = NodeIdentity::from_seed([0x41; 32]);
        let keys: Vec<[u8; 32]> = (0..9u8)
            .map(|i| NodeIdentity::from_seed([0x50 + i; 32]).public_key_bytes())
            .collect();
        let eight = keys[..MAX_GRANT_WITNESSES].to_vec();
        let seven = keys[..MAX_GRANT_WITNESSES - 1].to_vec();
        assert_eq!(MAX_GRANT_WITNESSES, 8);
        let mut e = PorVerifierEngine::new(300);
        let g9 = RepairGrant::issue(&owner, [1; 32], keys.clone(), ErasureTier::Consumer);
        assert_eq!(
            e.register_repair_grant_for_stored(g9, &[sid(0)]),
            Err("reject.repair_grant_too_many_witnesses")
        );
        assert_eq!(e.shard_grant_owner(&sid(0)), None);
        let g7 = RepairGrant::issue(&owner, [1; 32], seven.clone(), ErasureTier::Consumer);
        assert_eq!(e.register_repair_grant_for_stored(g7, &[sid(0)]), Ok(()));
        let g8 = RepairGrant::issue(&owner, [1; 32], eight.clone(), ErasureTier::Consumer);
        assert_eq!(e.register_repair_grant_for_stored(g8, &[sid(1)]), Ok(()));
        let (_, g) = e.get_shard_session_and_grant(&sid(0));
        assert_eq!(g.unwrap().authorized_witness_pubkeys, eight, "8 replace 7");
        assert_eq!(grant_replace_decision(Some(&seven), &eight), Ok(()));
        assert_eq!(
            grant_replace_decision(Some(&eight), &seven),
            Err("reject.repair_grant_witness_downgrade")
        );
        let g7b = RepairGrant::issue(&owner, [1; 32], seven, ErasureTier::Consumer);
        assert_eq!(e.register_repair_grant_for_stored(g7b, &[sid(2)]), Ok(()));
        let (_, g) = e.get_shard_session_and_grant(&sid(2));
        assert_eq!(g.unwrap().authorized_witness_pubkeys, eight, "7 kept out");
    }

    #[test]
    fn grant_witness_bound_and_superset() {
        assert_eq!(
            grant_registration_decision(&GrantRegFacts {
                grant_valid: true,
                root_matches: true,
                witnesses_len: MAX_GRANT_WITNESSES + 1,
            }),
            Err("reject.repair_grant_too_many_witnesses")
        );
        let a = [[1u8; 32]];
        let ab = [[1u8; 32], [2u8; 32]];
        assert_eq!(grant_replace_decision(None, &[]), Ok(()));
        assert_eq!(grant_replace_decision(Some(&[]), &a), Ok(()));
        assert_eq!(grant_replace_decision(Some(&a), &ab), Ok(()));
        assert_eq!(grant_replace_decision(Some(&ab), &ab), Ok(()));
        assert_eq!(
            grant_replace_decision(Some(&a), &[]),
            Err("reject.repair_grant_witness_downgrade")
        );
        assert_eq!(
            grant_replace_decision(Some(&ab), &[[2u8; 32], [3u8; 32]]),
            Err("reject.repair_grant_witness_downgrade")
        );
        // On the engine: the downgrade keeps the registered witnesses; the shard still binds.
        let owner = NodeIdentity::from_seed([0x21; 32]);
        let seed = NodeIdentity::from_seed([0x22; 32]).public_key_bytes();
        let mut e = PorVerifierEngine::new(300);
        let up = RepairGrant::issue(&owner, [1; 32], vec![seed], ErasureTier::Consumer);
        let old = RepairGrant::issue(&owner, [1; 32], vec![], ErasureTier::Consumer);
        assert_eq!(e.register_repair_grant_for_stored(up, &[sid(0)]), Ok(()));
        assert_eq!(e.register_repair_grant_for_stored(old, &[sid(1)]), Ok(()));
        for i in 0..2 {
            let (_, g) = e.get_shard_session_and_grant(&sid(i));
            assert_eq!(g.unwrap().authorized_witness_pubkeys, vec![seed], "{i}");
        }
        let nine = RepairGrant::issue(&owner, [1; 32], vec![seed; 9], ErasureTier::Consumer);
        assert_eq!(
            e.register_repair_grant_for_stored(nine, &[sid(2)]),
            Err("reject.repair_grant_too_many_witnesses")
        );
        assert_eq!(e.shard_grant_owner(&sid(2)), None);
    }

    #[test]
    fn rate_decision_rules() {
        let ok = PorRateFacts {
            session_in_window: 5,
            host_last_minute: 58,
            host_per_minute_cap: 60,
            owner_last_minute: 29,
            owner_per_minute_cap: 30,
            owner_quiet: false,
            map_full_for_new_key: false,
        };
        assert_eq!(por_rate_decision(&ok), Ok(()));
        // A quiet owner may take the last slot.
        let quiet_last = PorRateFacts {
            host_last_minute: 59,
            owner_last_minute: 0,
            owner_quiet: true,
            ..ok
        };
        assert_eq!(por_rate_decision(&quiet_last), Ok(()));
        for bad in [
            PorRateFacts {
                session_in_window: 6,
                ..ok
            },
            PorRateFacts {
                host_last_minute: 60,
                ..ok
            },
            PorRateFacts {
                map_full_for_new_key: true,
                ..ok
            },
            PorRateFacts {
                owner_last_minute: 30,
                ..ok
            },
            // P1: the last slot is only for a quiet owner.
            PorRateFacts {
                host_last_minute: 59,
                owner_quiet: false,
                ..ok
            },
        ] {
            assert_eq!(por_rate_decision(&bad), Err("reject.por_rate_limited"));
        }
    }

    /// D2: owner B saturating its share of a host never starves owner A of that host: A is
    /// still admitted while B is refused, on desktop and router caps.
    #[test]
    fn one_owner_cannot_starve_another() {
        assert_eq!(owner_minute_share(60, 0), 30);
        assert_eq!(owner_minute_share(60, 1), 20);
        assert_eq!(owner_minute_share(12, 0), 6);
        assert_eq!(owner_minute_share(12, 20), 1);
        for cap in [CHUNK_AUDITS_PER_MINUTE_HOST, CHUNK_AUDITS_PER_MINUTE_ROUTER] {
            let mut r = ChunkRateState {
                host_per_minute_cap: Some(cap),
                ..ChunkRateState::default()
            };
            // B asks with a fresh stripe key each time (its per-stripe budget never binds).
            let mut b_admitted = 0;
            for i in 0..cap * 4 {
                let key = [i as u8; 32];
                if por_rate_decision(&r.facts(&key, "owner-b")).is_ok() {
                    r.record(key, "owner-b", NOW);
                    b_admitted += 1;
                }
            }
            assert_eq!(b_admitted, cap / 2, "B alone gets half the host cap");
            for j in 0..owner_minute_share(cap, 1) {
                let a_key = [250 - j as u8; 32];
                assert_eq!(por_rate_decision(&r.facts(&a_key, "owner-a")), Ok(()));
                r.record(a_key, "owner-a", NOW);
            }
            assert_eq!(
                por_rate_decision(&r.facts(&[0xBB; 32], "owner-b")),
                Err("reject.por_rate_limited")
            );
            assert!(r.host_minute.len() <= cap);
        }
    }

    /// P1: cap-many Sybil owners saturating a router host minute after minute never starve a
    /// quiet owner A: from the minute after their first burst they are no longer quiet, so the
    /// host's last slot of every minute stays for A.
    #[test]
    fn cap_many_sybils_cannot_starve_a_quiet_owner() {
        let cap = CHUNK_AUDITS_PER_MINUTE_ROUTER;
        let mut r = ChunkRateState {
            host_per_minute_cap: Some(cap),
            ..ChunkRateState::default()
        };
        let sybils: Vec<String> = (0..cap).map(|i| format!("sybil-{i}")).collect();
        let mut key_n = 0u32;
        let mut fresh_key = || {
            key_n += 1;
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&key_n.to_be_bytes());
            k
        };
        for minute in 0..8u64 {
            let t = NOW + minute * 60_000;
            r.prune(t);
            // Every Sybil asks until refused, with fresh stripe keys.
            for _ in 0..4 {
                for s in &sybils {
                    let k = fresh_key();
                    if por_rate_decision(&r.facts(&k, s)).is_ok() {
                        r.record(k, s, t);
                    }
                }
            }
            assert!(r.host_minute.len() <= cap);
            if minute == 0 {
                continue; // the first burst: every Sybil was quiet too
            }
            let owner_a = format!("owner-a-{minute}");
            let k = fresh_key();
            assert_eq!(
                por_rate_decision(&r.facts(&k, &owner_a)),
                Ok(()),
                "minute {minute}: the quiet owner is starved"
            );
            r.record(k, &owner_a, t);
        }
    }

    /// Verdict change 1: a co-host holding the stripe key is refused before anything else,
    /// and its attempt spends none of the owner's budget.
    #[test]
    fn co_host_refused_before_rate_and_read() {
        let mut e = engine();
        let ch = generate_chunk_challenge(&KEY, sid(0), 3, 2, NOW);
        let read = std::cell::Cell::new(false);
        let r = e.admit_chunk_challenge(&ch, Some(CO_HOST_K), Some(&id(&OWNER_K)), NOW, || {
            read.set(true);
            Some(8193)
        });
        assert_eq!(r, Err("reject.por_not_storer"));
        assert!(!read.get());
        assert_eq!(e.blocked_ddos_challenges, 1);
        // The same challenge from the owner still passes (nonce not burned).
        let spec = admit(&mut e, &ch, OWNER_K, NOW).expect("owner admitted");
        assert_eq!(spec.chunk_indices, ch.chunk_indices);
        assert_eq!(spec.shard_len, 8193);
    }

    #[test]
    fn prescreen_and_bounds() {
        let mut e = engine();
        let good = generate_chunk_challenge(&KEY, sid(0), 3, 2, NOW);
        // Wrong key: HMAC refused, no stat.
        let wrong = generate_chunk_challenge(&[8; 32], sid(0), 3, 2, NOW);
        assert_eq!(
            e.admit_chunk_challenge(&wrong, Some(OWNER_K), Some(&id(&OWNER_K)), NOW, || {
                panic!("stat")
            }),
            Err("reject.por_hmac_invalid")
        );
        // A PorAudit token does not pass as a chunk token.
        let mut cross = good.clone();
        cross.hmac_token = compute_challenge_hmac(&KEY, &sid(0), &good.nonce, 0, 1, NOW);
        assert_eq!(
            admit(&mut e, &cross, OWNER_K, NOW),
            Err("reject.por_hmac_invalid")
        );
        // Stale.
        assert_eq!(
            admit(
                &mut e,
                &good,
                OWNER_K,
                NOW + CHALLENGE_FRESHNESS_WINDOW_MS + 1
            ),
            Err("reject.por_stale_or_replayed")
        );
        // Unknown session.
        let unknown = generate_chunk_challenge(&KEY, sid(9), 3, 2, NOW);
        assert_eq!(
            admit(&mut e, &unknown, OWNER_K, NOW),
            Err("reject.por_session_unknown")
        );
        // Width 0, 9, or repeated indices.
        for idx in [vec![], (0..9).collect(), vec![1, 1]] {
            let mut c = good.clone();
            c.chunk_indices = idx;
            c.hmac_token = crate::por::compute_chunk_challenge_hmac(
                &KEY,
                &c.shard_id,
                &c.nonce,
                &c.chunk_indices,
                NOW,
            );
            assert_eq!(
                admit(&mut e, &c, OWNER_K, NOW),
                Err("reject.por_range_invalid")
            );
        }
        // Index past the chunk count (3 chunks at 8193 bytes).
        let mut past = good.clone();
        past.nonce = [0xAB; 32];
        past.chunk_indices = vec![3];
        past.hmac_token =
            crate::por::compute_chunk_challenge_hmac(&KEY, &past.shard_id, &past.nonce, &[3], NOW);
        assert_eq!(
            admit(&mut e, &past, OWNER_K, NOW),
            Err("reject.por_range_invalid")
        );
        // Good, then replay.
        assert!(admit(&mut e, &good, OWNER_K, NOW).is_ok());
        assert_eq!(
            admit(&mut e, &good, OWNER_K, NOW),
            Err("reject.por_stale_or_replayed")
        );
        // Missing shard file.
        let g2 = generate_chunk_challenge(&KEY, sid(1), 3, 2, NOW);
        assert_eq!(
            e.admit_chunk_challenge(&g2, Some(OWNER_K), Some(&id(&OWNER_K)), NOW, || None),
            Err("reject.por_shard_missing")
        );
    }

    /// F-06-RATE: the 7th challenge for one session key in 10 minutes is refused; the window
    /// slides; the router cap is per host per minute.
    #[test]
    fn seventh_challenge_in_window_refused() {
        let mut e = engine();
        for k in 0..6 {
            let ch = generate_chunk_challenge(&KEY, sid(k % 4), 3, 1, NOW + k as u64);
            assert!(admit(&mut e, &ch, OWNER_K, NOW + k as u64).is_ok(), "{k}");
        }
        let ch = generate_chunk_challenge(&KEY, sid(0), 3, 1, NOW + 10);
        assert_eq!(
            admit(&mut e, &ch, OWNER_K, NOW + 10),
            Err("reject.por_rate_limited")
        );
        let later = NOW + CHUNK_AUDIT_SESSION_WINDOW_MS + 10;
        let ch = generate_chunk_challenge(&KEY, sid(0), 3, 1, later);
        assert!(admit(&mut e, &ch, OWNER_K, later).is_ok());

        // Host cap 2: one owner gets its share (1, D2), a second owner the other slot, and then
        // the host cap refuses everyone for the rest of the minute.
        let mut r = engine();
        r.set_chunk_audit_host_cap(2);
        let ch = generate_chunk_challenge(&KEY, sid(0), 3, 1, NOW);
        assert!(admit(&mut r, &ch, OWNER_K, NOW).is_ok());
        let ch = generate_chunk_challenge(&KEY, sid(0), 3, 1, NOW + 1);
        assert_eq!(
            admit(&mut r, &ch, OWNER_K, NOW + 1),
            Err("reject.por_rate_limited")
        );
        let ch = generate_chunk_challenge(&KEY, sid(1), 3, 1, NOW + 2);
        assert!(r
            .admit_chunk_challenge(&ch, Some([2; 32]), Some(&id(&[2; 32])), NOW + 2, || Some(
                8193
            ))
            .is_ok());
        let ch = generate_chunk_challenge(&KEY, sid(2), 3, 1, NOW + 3);
        assert_eq!(
            r.admit_chunk_challenge(&ch, Some([3; 32]), Some(&id(&[3; 32])), NOW + 3, || Some(
                8193
            )),
            Err("reject.por_rate_limited")
        );
    }
}
