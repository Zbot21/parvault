//! B-59 auditor decisions: what one chunk-audit answer means, and what it may credit.
//!
//! Three verdict classes (verdict change 3). Only a decoded answer that fails the echo check or
//! [`chunk_proof_decision`] is [`AuditVerdict::ProofInvalid`]. Everything a host can cause by not
//! answering (no answer, a refusal, a decode error, a late answer) is
//! [`AuditVerdict::Unanswered`] and never a ledger failure (L-27).
use crate::por::chunk_merkle::{chunk_proof_decision, ChunkProofFacts};
use crate::por::{ChunkAuditResponse, ChunkChallenge};

/// What one chunk audit came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVerdict {
    Pass,
    /// A decoded answer that does not prove the challenged chunks.
    ProofInvalid(&'static str),
    /// No usable answer in time: a timeout, a refusal, or a host that does not know the variant.
    Unanswered(&'static str),
}

/// What the auditor knows when it judges one answer: its own challenge, the manifest's chunk
/// root and length for that shard, and the answer with its round-trip time.
#[derive(Debug, Clone, Copy)]
pub struct AuditFacts<'a> {
    pub challenge: &'a ChunkChallenge,
    pub root: &'a [u8; 32],
    pub shard_len: u64,
    /// `None` for no answer, any refusal (`ChunkAuditResult(None)`) or a transport error.
    pub response: Option<&'a ChunkAuditResponse>,
    pub rtt_ms: u64,
    /// The pass bound (`por_audit_rtt_ms`: 2,000 by default, 5,000 on `router-soc`).
    pub rtt_bound_ms: u64,
}

/// F-06 / F-34: judges one answer. The echo (shard, nonce, one proof per index in challenge
/// order) is checked before any hash; then each proof against the manifest root.
pub fn chunk_audit_decision(f: &AuditFacts<'_>) -> AuditVerdict {
    let Some(r) = f.response else {
        return AuditVerdict::Unanswered("reject.audit_unanswered");
    };
    if f.rtt_ms > f.rtt_bound_ms {
        return AuditVerdict::Unanswered("reject.audit_timeout");
    }
    let ch = f.challenge;
    let echo_ok = r.shard_id == ch.shard_id
        && r.nonce == ch.nonce
        && r.proofs.len() == ch.chunk_indices.len()
        && r.proofs
            .iter()
            .zip(&ch.chunk_indices)
            .all(|(p, &i)| p.index == i);
    if !echo_ok {
        return AuditVerdict::ProofInvalid("reject.por_echo_mismatch");
    }
    for p in &r.proofs {
        if let Err(code) = chunk_proof_decision(&ChunkProofFacts {
            root: f.root,
            shard_len: f.shard_len,
            index: p.index,
            chunk: &p.chunk,
            path: &p.path,
        }) {
            return AuditVerdict::ProofInvalid(code);
        }
    }
    AuditVerdict::Pass
}

/// What a verdict may write to the auditor's own ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditCredit {
    /// `record_por_outcome(prover, true)`.
    Pass,
    /// `record_por_outcome(prover, false)` and the shard marked degraded.
    Fail,
    /// The timeout counter only; never a failure.
    Unanswered,
}

/// F-07: a verdict credits only a prover other than the auditor. `self_device_ids` are every
/// identity of the auditing node (the owner key and the node key differ on a daemon). A
/// self-named host is refused here, before any network call, so a manifest that names the
/// auditor earns it nothing.
pub fn audit_credit_decision(
    self_device_ids: &[&str],
    prover_device_id: &str,
    verdict: AuditVerdict,
) -> Result<AuditCredit, &'static str> {
    if self_device_ids.contains(&prover_device_id) {
        return Err("reject.por_self_credit");
    }
    Ok(match verdict {
        AuditVerdict::Pass => AuditCredit::Pass,
        AuditVerdict::ProofInvalid(_) => AuditCredit::Fail,
        AuditVerdict::Unanswered(_) => AuditCredit::Unanswered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::por::chunk_merkle::{chunk_proof, shard_chunk_root};
    use crate::por::generate_chunk_challenge;
    use crate::storage::ShardId;

    fn setup() -> (Vec<u8>, [u8; 32], ChunkChallenge, ChunkAuditResponse) {
        let shard: Vec<u8> = (0..(5 * 4096 + 3)).map(|i| (i * 7) as u8).collect();
        let root = shard_chunk_root(&shard);
        let sid = ShardId {
            stripe_merkle_root: [1; 32],
            shard_index: 0,
            shard_hash: [2; 32],
        };
        let ch = generate_chunk_challenge(&[3; 32], sid, 6, 4, 0);
        let resp = ChunkAuditResponse {
            shard_id: sid,
            nonce: ch.nonce,
            proofs: ch
                .chunk_indices
                .iter()
                .map(|&i| chunk_proof(&shard, i).unwrap())
                .collect(),
        };
        (shard, root, ch, resp)
    }

    fn judge(
        root: &[u8; 32],
        len: u64,
        ch: &ChunkChallenge,
        r: Option<&ChunkAuditResponse>,
        rtt: u64,
    ) -> AuditVerdict {
        chunk_audit_decision(&AuditFacts {
            challenge: ch,
            root,
            shard_len: len,
            response: r,
            rtt_ms: rtt,
            rtt_bound_ms: 2_000,
        })
    }

    #[test]
    fn verdict_classes() {
        let (shard, root, ch, resp) = setup();
        let len = shard.len() as u64;
        assert_eq!(judge(&root, len, &ch, Some(&resp), 10), AuditVerdict::Pass);
        // Not answering is never a failed proof.
        assert_eq!(
            judge(&root, len, &ch, None, 10),
            AuditVerdict::Unanswered("reject.audit_unanswered")
        );
        assert_eq!(
            judge(&root, len, &ch, Some(&resp), 2_001),
            AuditVerdict::Unanswered("reject.audit_timeout")
        );
        // Echo: other nonce, a dropped proof, reordered proofs.
        let mut r = resp.clone();
        r.nonce[0] ^= 1;
        assert!(matches!(
            judge(&root, len, &ch, Some(&r), 10),
            AuditVerdict::ProofInvalid(_)
        ));
        let mut r = resp.clone();
        r.proofs.pop();
        assert!(matches!(
            judge(&root, len, &ch, Some(&r), 10),
            AuditVerdict::ProofInvalid(_)
        ));
        let mut r = resp.clone();
        r.proofs.swap(0, 1);
        assert!(matches!(
            judge(&root, len, &ch, Some(&r), 10),
            AuditVerdict::ProofInvalid(_)
        ));
        // One flipped byte in a challenged chunk.
        let mut r = resp.clone();
        r.proofs[2].chunk[0] ^= 0xFF;
        assert_eq!(
            judge(&root, len, &ch, Some(&r), 10),
            AuditVerdict::ProofInvalid("reject.por_chunk_proof_invalid")
        );
        // Another shard's root.
        assert!(matches!(
            judge(&[9; 32], len, &ch, Some(&resp), 10),
            AuditVerdict::ProofInvalid(_)
        ));
    }

    #[test]
    fn credit_only_another_prover() {
        assert_eq!(
            audit_credit_decision(&["a", "n"], "b", AuditVerdict::Pass),
            Ok(AuditCredit::Pass)
        );
        assert_eq!(
            audit_credit_decision(&["a", "n"], "b", AuditVerdict::ProofInvalid("x")),
            Ok(AuditCredit::Fail)
        );
        assert_eq!(
            audit_credit_decision(&["a", "n"], "b", AuditVerdict::Unanswered("x")),
            Ok(AuditCredit::Unanswered)
        );
        for v in [
            AuditVerdict::Pass,
            AuditVerdict::ProofInvalid("x"),
            AuditVerdict::Unanswered("x"),
        ] {
            assert_eq!(
                audit_credit_decision(&["a", "n"], "a", v),
                Err("reject.por_self_credit")
            );
            assert_eq!(
                audit_credit_decision(&["a", "n"], "n", v),
                Err("reject.por_self_credit")
            );
        }
    }
}
