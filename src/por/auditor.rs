//! B-59 auditor (F-06): the owner daemon's chunk-audit job, run on the blocking pool from the
//! daemon loop. One job audits at most one shard: it picks the host whose last audit is oldest,
//! finds a shard of it in a bounded number of local manifests (no table), sends one
//! [`crate::por::ChunkChallenge`] as the owner identity, judges the answer with
//! [`chunk_audit_decision`] and records only what [`audit_credit_decision`] allows.
//!
//! Detection only (L-27): a pass or a failed proof goes to the owner's own ledger
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

/// One shard to audit, as a local manifest names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTarget {
    pub host_addr: String,
    pub shard_id: ShardId,
    pub shard_len: u64,
    pub chunk_root: [u8; 32],
}

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
}

impl AuditorState {
    /// Loads the state file, or a fresh state when it is missing, unreadable or another version.
    pub fn load(data_dir: &Path) -> Self {
        let fresh = Self {
            version: AUDIT_STATE_VERSION,
            ..Self::default()
        };
        std::fs::read(data_dir.join(AUDIT_STATE_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Self>(&b).ok())
            .filter(|s| s.version == AUDIT_STATE_VERSION)
            .unwrap_or(fresh)
    }

    fn save(&self, data_dir: &Path) {
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

/// Everything one job needs; cheap to clone into the blocking pool.
#[derive(Clone)]
pub struct AuditJobCtx {
    pub block_store: BlockStore,
    pub master_key: MasterKey,
    /// Sends as the owner identity (the writer of every stripe, B-59 commit 1).
    pub client: MeshClient,
    /// Every identity of this node: the owner's and the node's device ids.
    pub self_device_ids: Vec<String>,
    pub cfg: AuditorConfig,
    pub state: Arc<Mutex<AuditorState>>,
    pub data_dir: PathBuf,
}

/// What one job did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditJobOutcome {
    /// Nothing due, the hourly cap is reached, or no auditable shard was found.
    Idle,
    /// Refused before sending (`reject.por_self_credit`).
    SelfRefused,
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

/// The device id behind a host address (its `/p2p/` peer id or the client's pinned one).
pub fn host_device_id(client: &MeshClient, addr: &str) -> Option<String> {
    let pid = client.pinned_peer_id(addr)?;
    NodeConfig::extract_ed25519_pubkey_from_peer_str(&pid.to_string())
        .map(|pk| NodeIdentity::device_peer_id_for_pubkey(&pk))
}

/// Up to [`MANIFESTS_PER_TICK`] random local manifests, decrypted; their auditable shards.
/// Returns the targets and the number of v1 stripes seen.
fn scan_targets(ctx: &AuditJobCtx) -> (Vec<AuditTarget>, u64) {
    let Ok(rd) = std::fs::read_dir(ctx.block_store.manifests_dir()) else {
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
        let Ok(fm) = FileManifest::from_encrypted_dht_record(&ctx.master_key, &raw) else {
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

/// Picks the target: a due retry first, else a random shard of the host whose last audit is
/// oldest among the scanned ones, if that host is due.
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
    }
    let (targets, unauditable) = scan_targets(ctx);
    let mut st = ctx.state.lock().ok()?;
    st.unauditable = st.unauditable.saturating_add(unauditable);
    let last = |a: &str| st.host_last_audit.get(a).copied().unwrap_or(0);
    let oldest = targets.iter().map(|t| last(&t.host_addr)).min()?;
    // ±20 % jitter on the per-host interval, so audits of one host do not land on a fixed grid.
    let due_after = ctx.cfg.interval_ms / 100 * OsRng.gen_range(80..=120);
    if now.saturating_sub(oldest) < due_after {
        return None;
    }
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
            st.save(&ctx.data_dir);
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
    let answer = ctx
        .client
        .chunk_audit(&target.host_addr, challenge.clone())
        .ok()
        .flatten();
    let rtt_ms = t0.elapsed().as_millis() as u64;
    // The ledger is keyed by the Noise-authenticated device id, never by the address: an
    // address without a `/p2p/` id is resolved from the connection the request just made, and a
    // prover that stays unknown is credited nothing (it could be this node).
    let Some(prover) = host_device_id(&ctx.client, &target.host_addr) else {
        warn!(code = "reject.por_prover_unknown", host = %target.host_addr, shard = %short, "por.audit");
        if let Ok(mut st) = ctx.state.lock() {
            st.unauditable = st.unauditable.saturating_add(1);
            st.note_host(&target.host_addr, now);
            st.save(&ctx.data_dir);
        }
        return AuditJobOutcome::Idle;
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
            if matches!(verdict, AuditVerdict::Unanswered("reject.audit_timeout")) {
                st.timed_out = st.timed_out.saturating_add(1);
            }
            if st.retry.is_none() {
                st.retry = Some((target, now + AUDIT_RETRY_DELAY_MS));
            }
        }
        // Unreachable: the prover was checked against `self_ids` above.
        Err(_) => st.self_refused = st.self_refused.saturating_add(1),
    }
    st.save(&ctx.data_dir);
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
        s.save(dir.path());
        assert_eq!(AuditorState::load(dir.path()), s);
        std::fs::write(dir.path().join(AUDIT_STATE_FILE), br#"{"version":9}"#).unwrap();
        assert_eq!(AuditorState::load(dir.path()).passed, 0);
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
