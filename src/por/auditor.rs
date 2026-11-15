//! B-59 auditor (F-06): the owner daemon's chunk-audit job, run on the blocking pool from the
//! daemon loop. One job audits at most one shard: it picks the host whose last audit is oldest,
//! finds a shard of it in a bounded number of local manifests (no table), sends one
//! [`crate::por::ChunkChallenge`] as the owner identity, judges the answer with
//! [`chunk_audit_decision`] and records only what [`audit_credit_decision`] allows.
//!
//! Detection, with one latent local consequence (L-27, L-105): a pass or a failed proof goes to the owner's own ledger
//! (`QuotaManager::record_por_outcome`) and a failed proof marks the shard degraded; an
//! unanswered audit is counted here and never recorded as a failure. Nothing quarantines,
//! repairs, gossips or leaves the node (L-29).
//!
//! Detection time: sampling is per host, so a given shard is challenged about once per
//! `S x interval`, where `S` is the number of shards that host holds for this owner (verdict
//! change 7), within the node cap of [`DEFAULT_MAX_AUDITS_PER_HOUR`].
use crate::config::NodeConfig;
use crate::crypto::{MasterKey, NodeIdentity};
use crate::network::MeshClient;
use crate::por::audit::{
    audit_credit_decision, chunk_audit_decision, AuditCredit, AuditFacts, AuditVerdict,
};
use crate::por::chunk_merkle::chunk_count_u64;
use crate::por::lite_index::LiteAuditIndex;
use crate::por::{generate_chunk_challenge, DEFAULT_CHUNK_AUDIT_WIDTH};
use crate::storage::{BlockStore, FileManifest, ShardId};
use rand::{rngs::OsRng, seq::SliceRandom, Rng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Audits per node per hour, in all.
pub const DEFAULT_MAX_AUDITS_PER_HOUR: usize = 30;
/// The pass bound on the round trip (`por_audit_rtt_ms`), desktop and NAS.
pub const DEFAULT_AUDIT_RTT_MS: u64 = 2_000;
/// The same on `router-soc`.
pub const ROUTER_AUDIT_RTT_MS: u64 = 5_000;
/// Default audit interval per host: 1 h (desktop and NAS).
pub const DEFAULT_AUDIT_INTERVAL_SECS: u64 = 3_600;
/// The same on `router-soc`: 6 h.
pub const ROUTER_AUDIT_INTERVAL_SECS: u64 = 6 * 3_600;
/// Local manifests one job decrypts at most (the bounded scan, verdict change 7).
pub const MANIFESTS_PER_TICK: usize = 4;
/// Hosts and degraded shards the state keeps (bounded; a full map refuses new entries).
pub const MAX_AUDIT_STATE_ENTRIES: usize = 4_096;
/// Delay before an unanswered audit is retried once.
pub const AUDIT_RETRY_DELAY_MS: u64 = 60_000;
/// The auditor's state file in the data dir (JSON with a version header, written atomically).
pub const AUDIT_STATE_FILE: &str = "por_audit_state.json";
const AUDIT_STATE_VERSION: u32 = 1;

/// What the loop is configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditorConfig {
    pub interval_ms: u64,
    pub rtt_bound_ms: u64,
    pub width: u32,
    pub max_per_hour: usize,
}

impl AuditorConfig {
    /// The daemon loop's tick: the interval, at most one minute (so a retry fires on time).
    pub fn tick_ms(&self) -> u64 {
        self.interval_ms.clamp(1_000, 60_000)
    }

    /// The first tick: ten minutes after start, or the interval when it is shorter.
    pub fn first_delay_ms(&self) -> u64 {
        self.interval_ms.min(600_000)
    }

    /// From the node config (`por_audit_interval_secs`, `por_audit_rtt_ms`; `0` takes the
    /// hardware profile's default).
    pub fn from_node_config(cfg: &NodeConfig) -> Self {
        let router = cfg.hardware_profile == crate::profile::HardwareProfile::RouterSoc;
        let interval_secs = match (cfg.por_audit_interval_secs, router) {
            (0, true) => ROUTER_AUDIT_INTERVAL_SECS,
            (0, false) => DEFAULT_AUDIT_INTERVAL_SECS,
            (s, _) => s,
        };
        let rtt = match (cfg.por_audit_rtt_ms, router) {
            (0, true) => ROUTER_AUDIT_RTT_MS,
            (0, false) => DEFAULT_AUDIT_RTT_MS,
            (r, _) => r,
        };
        Self {
            interval_ms: interval_secs.saturating_mul(1_000),
            rtt_bound_ms: rtt,
            width: DEFAULT_CHUNK_AUDIT_WIDTH,
            max_per_hour: DEFAULT_MAX_AUDITS_PER_HOUR,
        }
    }
}

pub use crate::por::lite_index::AuditTarget;

/// Counts shown by `parvault status` (`audits`) and the state the sampler needs. RAM, mirrored
/// to [`AUDIT_STATE_FILE`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditorState {
    pub version: u32,
    pub last_run_unix_ms: u64,
    pub passed: u64,
    pub failed: u64,
    pub unanswered: u64,
    /// Unanswered because the answer came back over the RTT bound.
    pub timed_out: u64,
    /// Stripes skipped because their manifest has no chunk roots (v1).
    pub unauditable: u64,
    /// Audits refused before sending because the manifest names this node (F-07).
    pub self_refused: u64,
    /// Host address -> last audit time (ms).
    pub host_last_audit: BTreeMap<String, u64>,
    /// Shard file keys whose proof failed.
    pub degraded: BTreeSet<String>,
    /// Times of the audits in the last hour (the node cap).
    pub recent: Vec<u64>,
    /// One unanswered target waiting for its single retry, with its due time.
    pub retry: Option<(AuditTarget, u64)>,
    /// Verdict C4: no scan runs before this time (ms). Set after a scan that found nothing due,
    /// so an idle node does not list and decrypt manifests every tick.
    #[serde(default)]
    pub next_scan_unix_ms: u64,
}

impl AuditorState {
    /// An empty state (RAM only under `parvault-seed --no-fs`).
    pub fn fresh() -> Self {
        Self {
            version: AUDIT_STATE_VERSION,
            ..Self::default()
        }
    }

    /// Loads the state file, or a fresh state when it is missing, unreadable or another version.
    pub fn load(data_dir: &Path) -> Self {
        let fresh = Self::fresh();
        std::fs::read(data_dir.join(AUDIT_STATE_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Self>(&b).ok())
            .filter(|s| s.version == AUDIT_STATE_VERSION)
            .unwrap_or(fresh)
    }

    fn save(&self, data_dir: Option<&Path>) {
        let Some(data_dir) = data_dir else {
            return;
        };
        if let Ok(bytes) = serde_json::to_vec(self) {
            if let Err(e) =
                crate::storage::fsio::atomic_write_file(&data_dir.join(AUDIT_STATE_FILE), &bytes)
            {
                warn!(error = %e, "could not write the audit state");
            }
        }
    }

    fn note_host(&mut self, addr: &str, at: u64) {
        if self.host_last_audit.contains_key(addr)
            || self.host_last_audit.len() < MAX_AUDIT_STATE_ENTRIES
        {
            self.host_last_audit.insert(addr.to_string(), at);
        }
    }
}

/// Where the auditor finds what to audit.
#[derive(Clone)]
pub enum AuditSource {
    /// The owner daemon: its local manifests, decrypted with the master key.
    OwnerManifests(MasterKey),
    /// The seed: the lite stripes it fanned out (change 9).
    LiteIndex(Arc<Mutex<LiteAuditIndex>>),
}

/// Everything one job needs; cheap to clone into the blocking pool.
#[derive(Clone)]
pub struct AuditJobCtx {
    /// The node's block store; its quota manager is the ledger the outcome goes to.
    pub block_store: BlockStore,
    pub source: AuditSource,
    /// Sends as the storer of the audited stripes: the owner identity on a daemon (the writer of
    /// every stripe, B-59 commit 1), the seed identity on a seed (the writer of its fan-out).
    pub client: MeshClient,
    /// Every identity of this node: the owner's and the node's device ids.
    pub self_device_ids: Vec<String>,
    pub cfg: AuditorConfig,
    pub state: Arc<Mutex<AuditorState>>,
    /// Where the state file goes; `None` keeps it in RAM (`parvault-seed --no-fs`).
    pub data_dir: Option<PathBuf>,
}

/// What one job did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditJobOutcome {
    /// Nothing due, the hourly cap is reached, or no auditable shard was found.
    Idle,
    /// Refused before sending (`reject.por_self_credit`).
    SelfRefused,
    /// Sent, but the prover stayed unknown (no `/p2p/` id and no connection): counted
    /// unanswered, credited nothing (verdict C5).
    Unanswered(&'static str),
    Judged {
        prover: String,
        verdict: AuditVerdict,
    },
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What the verdict may look at: only a decoded answer. A transport or decode error, a refusal
/// (`ChunkAuditResult(None)`: not storer, rate, busy, or a read error on the host) is no answer,
/// so it can only ever be Unanswered, never a failed proof (Lead condition 2).
pub fn usable_answer(
    sent: anyhow::Result<Option<crate::por::ChunkAuditResponse>>,
) -> Option<crate::por::ChunkAuditResponse> {
    sent.ok().flatten()
}

/// The device id behind a host address (its `/p2p/` peer id or the client's pinned one).
pub fn host_device_id(client: &MeshClient, addr: &str) -> Option<String> {
    let pid = client.pinned_peer_id(addr)?;
    NodeConfig::extract_ed25519_pubkey_from_peer_str(&pid.to_string())
        .map(|pk| NodeIdentity::device_peer_id_for_pubkey(&pk))
}

/// The bounded scan: the auditable shards of up to [`MANIFESTS_PER_TICK`] random local
/// manifests (decrypted) or lite-index records. Returns the targets and the number of v1
/// stripes seen.
fn scan_targets(ctx: &AuditJobCtx) -> (Vec<AuditTarget>, u64) {
    match &ctx.source {
        AuditSource::OwnerManifests(mk) => scan_manifests(&ctx.block_store, mk),
        AuditSource::LiteIndex(idx) => match idx.lock() {
            Ok(i) => (i.sample_targets(MANIFESTS_PER_TICK), 0),
            Err(_) => (Vec::new(), 0),
        },
    }
}

fn scan_manifests(block_store: &BlockStore, master_key: &MasterKey) -> (Vec<AuditTarget>, u64) {
    let Ok(rd) = std::fs::read_dir(block_store.manifests_dir()) else {
        return (Vec::new(), 0);
    };
    let mut files: Vec<PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".manifest.bin"))
        })
        .collect();
    files.shuffle(&mut OsRng);
    let mut out = Vec::new();
    let mut unauditable = 0;
    for path in files.into_iter().take(MANIFESTS_PER_TICK) {
        let Ok(raw) = std::fs::read(&path) else {
            continue;
        };
        let Ok(fm) = FileManifest::from_encrypted_dht_record(master_key, &raw) else {
            continue;
        };
        for st in &fm.stripes {
            if !st.is_chunk_auditable() {
                unauditable += 1;
                continue;
            }
            for (i, addr) in st.assigned_peers.iter().enumerate() {
                let (Some(h), Some(root)) = (st.shard_hashes.get(i), st.shard_chunk_roots.get(i))
                else {
                    continue;
                };
                if addr.is_empty() {
                    continue;
                }
                out.push(AuditTarget {
                    host_addr: addr.clone(),
                    shard_id: ShardId {
                        stripe_merkle_root: st.stripe_merkle_root,
                        shard_index: i as u32,
                        shard_hash: *h,
                    },
                    shard_len: st.shard_len as u64,
                    chunk_root: *root,
                });
            }
        }
    }
    (out, unauditable)
}

/// When the next scan may run after one that found nothing due (verdict C4): when the oldest
/// scanned host falls due, at least one tick and at most a quarter interval away (the scan
/// samples, so an unscanned host may fall due sooner). With nothing scanned: a quarter interval.
pub fn next_scan_after_idle(cfg: &AuditorConfig, now: u64, oldest_due_at: Option<u64>) -> u64 {
    let wait = oldest_due_at
        .map_or(u64::MAX, |d| d.saturating_sub(now))
        .clamp(cfg.tick_ms(), (cfg.interval_ms / 4).max(cfg.tick_ms()));
    now.saturating_add(wait)
}

/// Picks the target: a due retry first, else a random shard of the host whose last audit is
/// oldest among the scanned ones, if that host is due. Due-ness is checked before the scan
/// (verdict C4): after a scan that found nothing due, no scan runs until
/// [`next_scan_after_idle`], so an idle node scans at most about 4 times per interval, plus once
/// after each audit.
fn pick_target(ctx: &AuditJobCtx, now: u64) -> Option<AuditTarget> {
    {
        let mut st = ctx.state.lock().ok()?;
        st.recent.retain(|t| now.saturating_sub(*t) < 3_600_000);
        if st.recent.len() >= ctx.cfg.max_per_hour {
            return None;
        }
        if let Some((t, due)) = st.retry.clone() {
            if due <= now {
                st.retry = None;
                return Some(t);
            }
        }
        if now < st.next_scan_unix_ms {
            return None;
        }
    }
    let (targets, unauditable) = scan_targets(ctx);
    let mut st = ctx.state.lock().ok()?;
    st.unauditable = st.unauditable.saturating_add(unauditable);
    let last = |a: &str| st.host_last_audit.get(a).copied().unwrap_or(0);
    let oldest = targets.iter().map(|t| last(&t.host_addr)).min();
    // ±20 % jitter on the per-host interval, so audits of one host do not land on a fixed grid.
    let due_after = ctx.cfg.interval_ms / 100 * OsRng.gen_range(80..=120);
    let Some(oldest) = oldest.filter(|o| now.saturating_sub(*o) >= due_after) else {
        let due_at = oldest.map(|o| o.saturating_add(due_after));
        st.next_scan_unix_ms = next_scan_after_idle(&ctx.cfg, now, due_at);
        return None;
    };
    let of_host: Vec<&AuditTarget> = targets
        .iter()
        .filter(|t| last(&t.host_addr) == oldest)
        .collect();
    let first = of_host.first()?.host_addr.clone();
    let same: Vec<&&AuditTarget> = of_host.iter().filter(|t| t.host_addr == first).collect();
    Some((*same[OsRng.gen_range(0..same.len())]).clone())
}

/// F-06: runs one audit (blocking: one request with the client's timeout). Called from the
/// daemon loop on the blocking pool, at most one in flight.
pub fn run_audit_job(ctx: &AuditJobCtx) -> AuditJobOutcome {
    let now = now_ms();
    let Some(target) = pick_target(ctx, now) else {
        return AuditJobOutcome::Idle;
    };
    let self_ids: Vec<&str> = ctx.self_device_ids.iter().map(String::as_str).collect();
    let file_key = target.shard_id.file_key();
    let short = &file_key[..16.min(file_key.len())];
    let self_refused = |code: &'static str, prover: &str| {
        warn!(code, prover = %prover, shard = %short, "por.audit");
        if let Ok(mut st) = ctx.state.lock() {
            st.self_refused = st.self_refused.saturating_add(1);
            st.note_host(&target.host_addr, now);
            st.save(ctx.data_dir.as_deref());
        }
        AuditJobOutcome::SelfRefused
    };
    // F-07 (verdict change 11): a host already known to be this node is refused here, before
    // any network call.
    if let Some(known) = host_device_id(&ctx.client, &target.host_addr) {
        if let Err(code) = audit_credit_decision(&self_ids, &known, AuditVerdict::Pass) {
            return self_refused(code, &known);
        }
    }
    let session_key = ctx
        .client
        .identity()
        .derive_stripe_por_session_key(&target.shard_id.stripe_merkle_root);
    let n = chunk_count_u64(target.shard_len);
    let challenge = generate_chunk_challenge(&session_key, target.shard_id, n, ctx.cfg.width, now);
    let t0 = Instant::now();
    let answer = usable_answer(ctx.client.chunk_audit(&target.host_addr, challenge.clone()));
    let rtt_ms = t0.elapsed().as_millis() as u64;
    // The ledger is keyed by the Noise-authenticated device id, never by the address: an
    // address without a `/p2p/` id is resolved from the connection the request just made, and a
    // prover that stays unknown is credited nothing (it could be this node). It is counted
    // unanswered and retried once, like any other host that did not answer (verdict C5): an
    // offline host is never hidden in the unauditable count.
    let Some(prover) = host_device_id(&ctx.client, &target.host_addr) else {
        let code = "reject.por_prover_unknown";
        warn!(code, host = %target.host_addr, shard = %short, "por.audit");
        if let Ok(mut st) = ctx.state.lock() {
            st.last_run_unix_ms = now;
            st.recent.push(now);
            st.unanswered = st.unanswered.saturating_add(1);
            st.note_host(&target.host_addr, now);
            if st.retry.is_none() {
                st.retry = Some((target, now + AUDIT_RETRY_DELAY_MS));
            }
            st.save(ctx.data_dir.as_deref());
        }
        return AuditJobOutcome::Unanswered(code);
    };
    if let Err(code) = audit_credit_decision(&self_ids, &prover, AuditVerdict::Pass) {
        return self_refused(code, &prover);
    }
    let verdict = chunk_audit_decision(&AuditFacts {
        challenge: &challenge,
        root: &target.chunk_root,
        shard_len: target.shard_len,
        response: answer.as_ref(),
        rtt_ms,
        rtt_bound_ms: ctx.cfg.rtt_bound_ms,
    });
    let code = match verdict {
        AuditVerdict::Pass => "pass",
        AuditVerdict::ProofInvalid(c) | AuditVerdict::Unanswered(c) => c,
    };
    info!(code, prover = %prover, shard = %short, rtt_ms, "por.audit");
    let credit = audit_credit_decision(&self_ids, &prover, verdict);
    let mut st = match ctx.state.lock() {
        Ok(s) => s,
        Err(_) => return AuditJobOutcome::Idle,
    };
    st.last_run_unix_ms = now;
    st.recent.push(now);
    st.note_host(&target.host_addr, now);
    match credit {
        Ok(AuditCredit::Pass) => {
            st.passed = st.passed.saturating_add(1);
            if let Ok(mut q) = ctx.block_store.quota().lock() {
                q.record_por_outcome(&prover, true);
            }
        }
        Ok(AuditCredit::Fail) => {
            st.failed = st.failed.saturating_add(1);
            if st.degraded.len() < MAX_AUDIT_STATE_ENTRIES {
                st.degraded.insert(file_key);
            }
            if let Ok(mut q) = ctx.block_store.quota().lock() {
                q.record_por_outcome(&prover, false);
            }
        }
        Ok(AuditCredit::Unanswered) => {
            st.unanswered = st.unanswered.saturating_add(1);
            // A decoded answer that came back Unanswered was late (the only such case).
            if answer.is_some() {
                st.timed_out = st.timed_out.saturating_add(1);
            }
            if st.retry.is_none() {
                st.retry = Some((target, now + AUDIT_RETRY_DELAY_MS));
            }
        }
        // Unreachable: the prover was checked against `self_ids` above.
        Err(_) => st.self_refused = st.self_refused.saturating_add(1),
    }
    st.save(ctx.data_dir.as_deref());
    AuditJobOutcome::Judged { prover, verdict }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_and_refuses_other_versions() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = AuditorState::load(dir.path());
        assert_eq!(s.version, AUDIT_STATE_VERSION);
        s.passed = 3;
        s.degraded.insert("k".into());
        s.save(Some(dir.path()));
        assert_eq!(AuditorState::load(dir.path()), s);
        std::fs::write(dir.path().join(AUDIT_STATE_FILE), br#"{"version":9}"#).unwrap();
        assert_eq!(AuditorState::load(dir.path()).passed, 0);
    }

    fn judge(answer: Option<&crate::por::ChunkAuditResponse>, rtt_ms: u64) -> AuditVerdict {
        let ch = generate_chunk_challenge(&[1; 32], sid(), 2, 2, 0);
        chunk_audit_decision(&AuditFacts {
            challenge: &ch,
            root: &[0; 32],
            shard_len: 5_000,
            response: answer,
            rtt_ms,
            rtt_bound_ms: DEFAULT_AUDIT_RTT_MS,
        })
    }

    fn sid() -> ShardId {
        ShardId {
            stripe_merkle_root: [4; 32],
            shard_index: 0,
            shard_hash: [5; 32],
        }
    }

    /// Lead condition 2: every way of not proving that is not a verifiably wrong proof is
    /// Unanswered: a transport or decode error, a host refusal (not storer, rate, prover busy,
    /// a host read error all answer `ChunkAuditResult(None)`), and a late answer.
    #[test]
    fn no_answer_is_never_a_failed_proof() {
        let transport: anyhow::Result<Option<crate::por::ChunkAuditResponse>> =
            Err(anyhow::anyhow!("connection reset"));
        assert_eq!(usable_answer(transport), None);
        assert_eq!(usable_answer(Ok(None)), None);
        assert_eq!(
            judge(None, 5),
            AuditVerdict::Unanswered("reject.audit_unanswered")
        );
        // A late answer is Unanswered whatever it contains, even a wrong proof.
        let wrong = crate::por::ChunkAuditResponse {
            shard_id: sid(),
            nonce: [0; 32],
            proofs: Vec::new(),
        };
        assert_eq!(
            judge(Some(&wrong), DEFAULT_AUDIT_RTT_MS + 1),
            AuditVerdict::Unanswered("reject.audit_timeout")
        );
        for v in [
            judge(None, 5),
            judge(Some(&wrong), DEFAULT_AUDIT_RTT_MS + 1),
        ] {
            assert_eq!(
                audit_credit_decision(&["self"], "host", v),
                Ok(AuditCredit::Unanswered)
            );
        }
    }

    /// Lead condition 2, auditor side: a local manifest that does not read or decrypt is no
    /// audit at all, and writes nothing to the ledger.
    #[test]
    fn unreadable_local_manifest_is_no_audit() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::new(
            dir.path(),
            crate::storage::QuotaManager::new(1 << 30, 1 << 20),
        )
        .unwrap();
        std::fs::create_dir_all(store.manifests_dir()).unwrap();
        std::fs::write(
            store.manifests_dir().join("ab.manifest.bin"),
            b"not a manifest",
        )
        .unwrap();
        let owner = NodeIdentity::from_seed([9; 32]);
        let ctx = AuditJobCtx {
            block_store: store.clone(),
            source: AuditSource::OwnerManifests(MasterKey::from_bytes([3; 32])),
            client: MeshClient::new(owner.clone(), Vec::new(), None),
            self_device_ids: vec![owner.device_peer_id()],
            cfg: AuditorConfig {
                interval_ms: 1,
                rtt_bound_ms: DEFAULT_AUDIT_RTT_MS,
                width: 4,
                max_per_hour: 30,
            },
            state: Arc::new(Mutex::new(AuditorState::default())),
            data_dir: Some(dir.path().to_path_buf()),
        };
        assert_eq!(run_audit_job(&ctx), AuditJobOutcome::Idle);
        let st = ctx.state.lock().unwrap();
        assert_eq!((st.passed, st.failed, st.unanswered), (0, 0, 0));
    }

    /// Lead condition 3 (the one automatic local consequence of an audit, ADR-03 decision 5): passes raise a
    /// host's reciprocity factor on this node to 1.25, one invalid proof drops it to 2.0, and
    /// unanswered audits change nothing.
    #[test]
    fn passes_raise_the_factor_and_one_invalid_proof_drops_it() {
        let mut q = crate::storage::QuotaManager::new(1 << 30, 1 << 20);
        let record =
            |q: &mut crate::storage::QuotaManager, v: AuditVerdict| match audit_credit_decision(
                &["self"],
                "host",
                v,
            ) {
                Ok(AuditCredit::Pass) => q.record_por_outcome("host", true),
                Ok(AuditCredit::Fail) => q.record_por_outcome("host", false),
                Ok(AuditCredit::Unanswered) | Err(_) => {}
            };
        let factor = |q: &crate::storage::QuotaManager| {
            q.peer_account("host")
                .map_or(crate::storage::PeerCreditAccount::default(), Clone::clone)
                .required_reciprocity_factor()
        };
        assert_eq!(factor(&q), 2.0);
        for _ in 0..20 {
            record(&mut q, AuditVerdict::Pass);
        }
        assert_eq!(factor(&q), 1.25);
        for _ in 0..5 {
            record(&mut q, AuditVerdict::Unanswered("reject.audit_timeout"));
        }
        assert_eq!(factor(&q), 1.25, "unanswered audits change nothing");
        record(
            &mut q,
            AuditVerdict::ProofInvalid("reject.por_chunk_proof_invalid"),
        );
        assert_eq!(factor(&q), 2.0);
    }

    fn lite_ctx(dir: &Path, index: LiteAuditIndex, interval_ms: u64) -> AuditJobCtx {
        let store =
            BlockStore::new(dir, crate::storage::QuotaManager::new(1 << 30, 1 << 20)).unwrap();
        let seed = NodeIdentity::from_seed([8; 32]);
        AuditJobCtx {
            block_store: store,
            source: AuditSource::LiteIndex(Arc::new(Mutex::new(index))),
            client: MeshClient::new(seed.clone(), Vec::new(), None)
                .with_timeout(std::time::Duration::from_secs(2)),
            self_device_ids: vec![seed.device_peer_id()],
            cfg: AuditorConfig {
                interval_ms,
                rtt_bound_ms: DEFAULT_AUDIT_RTT_MS,
                width: 4,
                max_per_hour: 30,
            },
            state: Arc::new(Mutex::new(AuditorState::default())),
            data_dir: None,
        }
    }

    fn one_host_index(host_addr: &str) -> LiteAuditIndex {
        let mut idx = LiteAuditIndex::in_memory();
        idx.insert(crate::por::lite_index::LiteAuditRecord {
            client: "laptop".into(),
            stripe_merkle_root: [4; 32],
            shard_len: 9_000,
            shards: vec![crate::por::lite_index::LiteAuditShard {
                shard_index: 0,
                shard_hash: [5; 32],
                chunk_root: [6; 32],
                host_addr: host_addr.into(),
            }],
        });
        idx
    }

    /// An address nothing listens on, with no `/p2p/` id.
    fn dead_addr() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        format!("/ip4/127.0.0.1/tcp/{port}")
    }

    /// Verdict C5: an offline host whose address has no `/p2p/` id stays an unknown prover. It
    /// is counted unanswered (never unauditable), credited nothing, and retried once.
    #[test]
    fn offline_host_without_peer_id_is_unanswered_and_retried() {
        let dir = tempfile::tempdir().unwrap();
        let host = dead_addr();
        let ctx = lite_ctx(dir.path(), one_host_index(&host), 1);
        assert_eq!(
            run_audit_job(&ctx),
            AuditJobOutcome::Unanswered("reject.por_prover_unknown")
        );
        let st = ctx.state.lock().unwrap().clone();
        assert_eq!((st.passed, st.failed, st.unanswered), (0, 0, 1));
        assert_eq!(st.unauditable, 0);
        assert_eq!(
            st.retry.as_ref().map(|(t, _)| t.host_addr.as_str()),
            Some(host.as_str())
        );
        assert!(ctx
            .block_store
            .quota()
            .lock()
            .unwrap()
            .peer_account(&host)
            .is_none());
        // `--no-fs`: nothing written.
        assert!(!dir.path().join(AUDIT_STATE_FILE).exists());
    }

    /// Verdict C4: with nothing due, a job does not scan again until `next_scan_unix_ms`, even
    /// when a host that was never audited appears meanwhile.
    #[test]
    fn idle_job_does_not_rescan_until_something_may_be_due() {
        let dir = tempfile::tempdir().unwrap();
        let audited = dead_addr();
        let ctx = lite_ctx(dir.path(), one_host_index(&audited), 3_600_000);
        let now = now_ms();
        ctx.state
            .lock()
            .unwrap()
            .host_last_audit
            .insert(audited.clone(), now);
        assert_eq!(run_audit_job(&ctx), AuditJobOutcome::Idle);
        let next = ctx.state.lock().unwrap().next_scan_unix_ms;
        assert!(next >= now + ctx.cfg.tick_ms(), "{next} vs {now}");
        assert!(next <= now_ms() + 900_000, "at most a quarter interval");
        // A never-audited host is due at once, but no scan runs before `next`.
        if let AuditSource::LiteIndex(idx) = &ctx.source {
            *idx.lock().unwrap() = one_host_index(&dead_addr());
        }
        assert_eq!(run_audit_job(&ctx), AuditJobOutcome::Idle);
        let st = ctx.state.lock().unwrap();
        assert_eq!((st.unanswered, st.recent.len()), (0, 0));
    }

    #[test]
    fn idle_rescan_wait_is_clamped() {
        let cfg = AuditorConfig {
            interval_ms: 3_600_000,
            rtt_bound_ms: 1,
            width: 4,
            max_per_hour: 30,
        };
        assert_eq!(next_scan_after_idle(&cfg, 1_000, None), 1_000 + 900_000);
        assert_eq!(next_scan_after_idle(&cfg, 1_000, Some(500)), 1_000 + 60_000);
        assert_eq!(next_scan_after_idle(&cfg, 1_000, Some(301_000)), 301_000);
    }

    #[test]
    fn host_map_is_bounded() {
        let mut s = AuditorState::default();
        for i in 0..MAX_AUDIT_STATE_ENTRIES + 5 {
            s.note_host(&format!("h{i}"), 1);
        }
        assert_eq!(s.host_last_audit.len(), MAX_AUDIT_STATE_ENTRIES);
        s.note_host("h0", 9);
        assert_eq!(s.host_last_audit["h0"], 9);
    }
}
