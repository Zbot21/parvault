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
    /// Registered `RepairGrant` descriptors indexed by `stripe_merkle_root`.
    repair_grants_ram: HashMap<Hash32, RepairGrant>,
    /// Counter of disk reads prevented by RAM-only stateless HMAC/nonce rejection.
    blocked_ddos_challenges: u64,
}

impl PorVerifierEngine {
    pub fn new(max_latency_ms: u64) -> Self {
        Self {
            max_latency_ms,
            session_keys_ram: HashMap::new(),
            seen_nonces_ram: HashSet::new(),
            seen_nonces_fifo: VecDeque::new(),
            repair_grants_ram: HashMap::new(),
            blocked_ddos_challenges: 0,
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
    }

    /// Registers an owner-signed `RepairGrant` for a stripe in RAM (ADR-04).
    pub fn register_repair_grant(&mut self, grant: RepairGrant) -> bool {
        if !grant.verify() {
            return false;
        }
        self.repair_grants_ram
            .insert(grant.stripe_merkle_root, grant);
        true
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
        if challenge.length == 0 || challenge.length > MAX_POR_RANGE_BYTES {
            self.blocked_ddos_challenges += 1;
            return Err(PorError::InvalidHmacToken);
        }
        let key_id = challenge.shard_id.file_key();
        let Some(&session_key) = self.session_keys_ram.get(&key_id) else {
            self.blocked_ddos_challenges += 1;
            return Err(PorError::UnknownSessionKey(key_id));
        };

        // 1a. Verify timestamp freshness & nonce uniqueness in RAM (0 disk I/O).
        if now_unix_ms.abs_diff(challenge.issued_at_unix_ms) > CHALLENGE_FRESHNESS_WINDOW_MS
            || self.seen_nonces_ram.contains(&challenge.nonce)
        {
            self.blocked_ddos_challenges += 1;
            return Err(PorError::StaleOrReplayedNonce);
        }

        // 1b. Constant-time HMAC verification in RAM (0 disk I/O).
        let expected_hmac = compute_challenge_hmac(
            &session_key,
            &challenge.shard_id,
            &challenge.nonce,
            challenge.offset,
            challenge.length,
            challenge.issued_at_unix_ms,
        );
        if expected_hmac != challenge.hmac_token {
            self.blocked_ddos_challenges += 1;
            return Err(PorError::InvalidHmacToken);
        }

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

    /// Constructs and signs a domain-separated owner shard-read token (`ADR-15`), preventing
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

    /// Authorizes a raw ciphertext shard read request for restore or offline witness repair (ADR-04 / ADR-15).
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
            {
                if let Some(grant) = self.repair_grants_ram.get(&shard_id.stripe_merkle_root) {
                    if grant.owner_pubkey == *owner_pub
                        && NodeIdentity::verify_with_pubkey(owner_pub, signed_payload, sig)
                    {
                        return Ok(block_store.get_shard(shard_id)?);
                    }
                }
            }
        }

        // Case B: Offline Witness Cohort Repair (`RepairGrant` + >= 2 distinct witness signatures).
        if let Some((grant, receipts)) = repair_bundle {
            if grant.stripe_merkle_root == shard_id.stripe_merkle_root && grant.verify() {
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

                if valid_signers.len() >= MIN_WITNESS_SIGNATURES_FOR_REPAIR {
                    return Ok(block_store.get_shard(shard_id)?);
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
        if challenge.segments.is_empty()
            || challenge.segments.len() > 64
            || challenge
                .segments
                .iter()
                .any(|seg| seg.length == 0 || seg.length > MAX_POR_RANGE_BYTES)
        {
            self.blocked_ddos_challenges += 1;
            return Err(PorError::InvalidHmacToken);
        }
        let key_id = challenge.shard_id.file_key();
        let Some(&session_key) = self.session_keys_ram.get(&key_id) else {
            self.blocked_ddos_challenges += 1;
            return Err(PorError::UnknownSessionKey(key_id));
        };

        if now_unix_ms.abs_diff(challenge.issued_at_unix_ms) > CHALLENGE_FRESHNESS_WINDOW_MS
            || self.seen_nonces_ram.contains(&challenge.nonce)
        {
            self.blocked_ddos_challenges += 1;
            return Err(PorError::StaleOrReplayedNonce);
        }

        let expected_hmac = compute_multi_challenge_hmac(
            &session_key,
            &challenge.shard_id,
            &challenge.nonce,
            &challenge.segments,
            challenge.max_rtt_ms,
            challenge.issued_at_unix_ms,
        );
        if expected_hmac != challenge.hmac_token {
            self.blocked_ddos_challenges += 1;
            return Err(PorError::InvalidHmacToken);
        }

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
