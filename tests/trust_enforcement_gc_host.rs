//! `v0.5.6` track B1 suite: version GC on the host, per-shard memory (plan Sections 3.7 and 3.8
//! (a)). Claims of track B1 put their differential pairs here;
//! `tests/trust_enforcement.rs` is frozen.
//!
//! Real `parvault` daemons on loopback with scratch data dirs; requests go over the wire from
//! in-process ring members. Every test writes its sentinel (`gate_ran`) last, after its
//! assertions.

mod common;

use parvault::config::ErasureTier;
use parvault::crypto::NodeIdentity;
use parvault::network::admission::AdmissionSource;
use parvault::network::{
    FreeShardOutcome, FreeShardsOrder, MeshClient, MeshWireRequest, MeshWireResponse,
};
use parvault::por::{PorVerifierEngine, RepairGrant};
use parvault::storage::{QuotaManager, ShardId};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

// --- Harness (as `tests/trust_enforcement.rs`, which is frozen) --------------------------------

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

const GENESIS_SEED: [u8; 32] = [0x47; 32];

fn genesis() -> NodeIdentity {
    NodeIdentity::from_seed(GENESIS_SEED)
}

/// A spawned daemon with its data directory and captured log; killed on drop.
struct Node {
    child: Child,
    dir: PathBuf,
    reg: PathBuf,
    log: PathBuf,
    addr: String,
    /// A command the daemon is started through (a cgroup scope), or empty.
    wrap: Vec<String>,
    _root: TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn daemon_command(dir: &Path, reg: &Path, wrap: &[String]) -> Command {
    let mut cmd = match wrap.split_first() {
        Some((prog, args)) => {
            let mut c = Command::new(prog);
            c.args(args).arg(env!("CARGO_BIN_EXE_parvault"));
            c
        }
        None => Command::new(env!("CARGO_BIN_EXE_parvault")),
    };
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", reg)
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .arg("--data-dir")
        .arg(dir)
        .args([
            "--no-lan-discovery",
            "daemon",
            "start",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
        ]);
    cmd
}

/// A daemon with default config (see [`spawn_node_with`]).
fn spawn_node(label: &str) -> Node {
    spawn_node_with(label, None, &[])
}

/// A daemon with `config` as its `config.toml`, started through `wrap` (for example
/// `systemd-run --user --scope -p MemoryMax=64M --`) when given.
fn spawn_node_with(label: &str, config: Option<&str>, wrap: &[&str]) -> Node {
    let root = tempfile::Builder::new()
        .prefix(&format!("pv-b1-{label}-"))
        .tempdir()
        .unwrap();
    let dir = root.path().join("data");
    let reg = root.path().join("lan-registry");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&reg).unwrap();
    NodeIdentity::load_or_generate_in_dir(&dir).unwrap();
    if let Some(cfg) = config {
        std::fs::write(dir.join("config.toml"), cfg).unwrap();
    }
    let log = root.path().join("node.log");
    std::fs::File::create(&log).unwrap();
    let wrap: Vec<String> = wrap.iter().map(|s| s.to_string()).collect();
    let child = daemon_command(&dir, &reg, &wrap)
        .stdout(Stdio::from(std::fs::File::create(&log).unwrap()))
        .stderr(Stdio::from(
            std::fs::OpenOptions::new().append(true).open(&log).unwrap(),
        ))
        .spawn()
        .expect("spawn parvault");
    let mut node = Node {
        child,
        dir,
        reg,
        log,
        addr: String::new(),
        wrap,
        _root: root,
    };
    node.wait_listening(0);
    node
}

impl Node {
    fn start(&mut self) {
        let offset = self.log_text().len();
        let log_file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.log)
            .unwrap();
        self.child = daemon_command(&self.dir, &self.reg, &self.wrap)
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("spawn parvault");
        self.wait_listening(offset);
    }

    /// Waits for the listen address the daemon logs after `offset`, then for its port.
    fn wait_listening(&mut self, offset: usize) {
        let log = self.log.clone();
        self.addr = common::wait_for_listen_addr(
            &mut self.child,
            || {
                let t = std::fs::read_to_string(&log).unwrap_or_default();
                t.get(offset..).unwrap_or_default().to_string()
            },
            Duration::from_secs(20),
        );
        let port = common::tcp_port_of(&self.addr);
        let deadline = Instant::now() + Duration::from_secs(20);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "no listener on {port}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Kills the daemon (SIGKILL) and starts it again on the same data directory.
    fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.start();
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn host_key(&self) -> [u8; 32] {
        NodeIdentity::load_or_generate_in_dir(&self.dir)
            .unwrap()
            .public_key_bytes()
    }

    fn shard_file(&self, sid: &ShardId) -> PathBuf {
        self.dir
            .join("shards")
            .join(format!("{}.shard", sid.file_key()))
    }

    /// The bytes `account` has hosted here, from `quota_state.bin` (written atomically per put
    /// and removal).
    fn hosted(&self, account: &str) -> u64 {
        QuotaManager::with_persistence_dir(1 << 40, 0, &self.dir)
            .peer_account(account)
            .map_or(0, |a| a.bytes_hosted_for_peer)
    }

    fn shard_index_names(&self, sid: &ShardId) -> bool {
        std::fs::read(self.dir.join("shard_index.bin"))
            .ok()
            .and_then(|raw| bincode::deserialize::<HashMap<String, ShardId>>(&raw).ok())
            .is_some_and(|m| m.contains_key(&sid.file_key()))
    }

    fn assert_logged(&self, code: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.log_text().contains(code) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("{code} not in the node log:\n{}", self.log_text());
    }
}

fn send(ident: &NodeIdentity, node: &Node, req: MeshWireRequest) -> MeshWireResponse {
    let c = MeshClient::new(ident.clone(), Vec::new(), None)
        .with_admission(AdmissionSource::from_genesis(genesis()));
    match c.send_request(&node.addr, req) {
        Ok(r) => r,
        Err(e) => panic!("wire request: {e}\nnode log:\n{}", node.log_text()),
    }
}

fn key(seed: u8) -> NodeIdentity {
    NodeIdentity::from_seed([seed; 32])
}

fn shard(seed: u8, len: usize) -> (ShardId, Vec<u8>) {
    let bytes = vec![seed; len];
    let h = parvault::sharding::merkle::hash_shard_leaf(0, &bytes);
    (
        ShardId {
            stripe_merkle_root: [seed; 32],
            shard_index: 0,
            shard_hash: h,
        },
        bytes,
    )
}

fn put(
    sender: &NodeIdentity,
    node: &Node,
    sid: ShardId,
    bytes: Vec<u8>,
    grant: Option<RepairGrant>,
) -> MeshWireResponse {
    send(
        sender,
        node,
        MeshWireRequest::PutShard {
            owner_peer_id: String::new(),
            shard_id: sid,
            shard_bytes: bytes,
            session_key_commit: [0x5E; 32],
            repair_grant: grant,
        },
    )
}

fn stored(r: &MeshWireResponse) -> bool {
    matches!(r, MeshWireResponse::PutShardAck { stored: true, .. })
}

fn grant(owner: &NodeIdentity, sid: &ShardId) -> RepairGrant {
    RepairGrant::issue(
        owner,
        sid.stripe_merkle_root,
        Vec::new(),
        ErasureTier::Homelab,
    )
}

fn order(
    signer: &NodeIdentity,
    host: [u8; 32],
    ts: u64,
    epoch: u64,
    ids: Vec<ShardId>,
) -> FreeShardsOrder {
    parvault::por::verifier::sign_free_order(signer, host, ts, epoch, ids)
}

fn free(
    signer: &NodeIdentity,
    node: &Node,
    o: FreeShardsOrder,
) -> (Vec<FreeShardOutcome>, Option<String>) {
    match send(signer, node, MeshWireRequest::FreeShards { order: o }) {
        MeshWireResponse::FreeShardsAck { outcomes, error } => (outcomes, error),
        other => panic!("not a FreeShardsAck: {other:?}"),
    }
}

fn delete_at(signer: &NodeIdentity, sid: ShardId, ts: u64) -> MeshWireRequest {
    let (pub_, payload, sig) = PorVerifierEngine::sign_owner_shard_delete_token(signer, &sid, ts);
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..]);
    MeshWireRequest::DeleteShard {
        shard_id: sid,
        owner_signature: (pub_, payload, r, s),
    }
}

fn deleted(r: &MeshWireResponse) -> bool {
    matches!(r, MeshWireResponse::DeleteShardAck { deleted: true, .. })
}

// --- G2 ---------------------------------------------------------------------------------------

/// G2: `relocation_targets` reads the auditor's B-113 map; no state file is an empty map.
#[test]
fn relocation_targets_of_a_fresh_data_dir_is_empty() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(parvault::por::auditor::relocation_targets(tmp.path())
        .unwrap()
        .is_empty());
    std::fs::write(
        tmp.path().join(parvault::por::auditor::AUDIT_STATE_FILE),
        b"not json",
    )
    .unwrap();
    assert!(parvault::por::auditor::relocation_targets(tmp.path()).is_err());
    gate_ran("trust_enforcement_gc_host::relocation_targets_of_a_fresh_data_dir_is_empty");
}

// --- B154-FREE (B-158): the FreeShards host path ----------------------------------------------

/// B154-FREE accept, C19: the owner's order to this host frees its shard: `Freed`, the file and
/// its shard-index entry are gone, its account is credited, and a shard not held is `NotHeld`.
#[test]
fn b154_owner_order_frees_its_shard() {
    let node = spawn_node("free-a");
    let owner = key(0xB1);
    let (sid, bytes) = shard(0x51, 1024);
    let (absent, _) = shard(0x52, 1024);
    assert!(stored(&put(&owner, &node, sid, bytes, None)));
    assert!(node.shard_index_names(&sid));
    let o = order(&owner, node.host_key(), now_ms(), 1, vec![sid, absent]);
    let (outcomes, error) = free(&owner, &node, o);
    assert_eq!(error, None);
    assert_eq!(
        outcomes,
        vec![FreeShardOutcome::Freed, FreeShardOutcome::NotHeld]
    );
    assert!(!node.shard_file(&sid).exists());
    assert!(
        !node.shard_index_names(&sid),
        "C19: the freed shard left the shard index"
    );
    assert_eq!(node.hosted(&owner.device_peer_id()), 0);
    node.assert_logged("info.free_order_applied");
    gate_ran("trust_enforcement_gc_host::b154_owner_order_frees_its_shard");
}

/// B154-FREE reject (T5): a valid order for another host frees nothing here.
#[test]
fn b154_order_for_another_host_refused() {
    let node = spawn_node("free-host");
    let owner = key(0xB2);
    let (sid, bytes) = shard(0x53, 1024);
    assert!(stored(&put(&owner, &node, sid, bytes, None)));
    let o = order(&owner, key(0x99).public_key_bytes(), now_ms(), 1, vec![sid]);
    let (outcomes, error) = free(&owner, &node, o);
    assert!(outcomes.is_empty());
    assert_eq!(error.as_deref(), Some("reject.free_wrong_host"));
    assert!(node.shard_file(&sid).exists());
    node.assert_logged("reject.free_wrong_host");
    gate_ran("trust_enforcement_gc_host::b154_order_for_another_host_refused");
}

/// B154-FREE reject (T5): an order signed 31 s ago is stale.
#[test]
fn b154_stale_order_refused() {
    let node = spawn_node("free-stale");
    let owner = key(0xB3);
    let (sid, bytes) = shard(0x54, 1024);
    assert!(stored(&put(&owner, &node, sid, bytes, None)));
    let o = order(&owner, node.host_key(), now_ms() - 31_000, 1, vec![sid]);
    let (_, error) = free(&owner, &node, o);
    assert_eq!(error.as_deref(), Some("reject.free_stale"));
    assert!(node.shard_file(&sid).exists());
    node.assert_logged("reject.free_stale");
    gate_ran("trust_enforcement_gc_host::b154_stale_order_refused");
}

/// C24: a future-dated order (31 s ahead of the host's clock) is stale too.
#[test]
fn b154_future_dated_order_refused() {
    let node = spawn_node("free-future");
    let owner = key(0xB4);
    let (sid, bytes) = shard(0x55, 1024);
    assert!(stored(&put(&owner, &node, sid, bytes, None)));
    let o = order(&owner, node.host_key(), now_ms() + 31_000, 1, vec![sid]);
    let (_, error) = free(&owner, &node, o);
    assert_eq!(error.as_deref(), Some("reject.free_stale"));
    assert!(node.shard_file(&sid).exists());
    gate_ran("trust_enforcement_gc_host::b154_future_dated_order_refused");
}

/// B154-FREE reject (T5): the same order resent is a replay, and stays one across a restart
/// (the epoch marks are persisted).
#[test]
fn b154_resent_order_is_a_replay_across_restart() {
    let mut node = spawn_node("free-replay");
    let owner = key(0xB5);
    let (sid, bytes) = shard(0x56, 1024);
    let (sid2, bytes2) = shard(0x57, 1024);
    assert!(stored(&put(&owner, &node, sid, bytes, None)));
    let o = order(&owner, node.host_key(), now_ms(), 5, vec![sid, sid2]);
    let (outcomes, _) = free(&owner, &node, o.clone());
    assert_eq!(outcomes[0], FreeShardOutcome::Freed);
    // The owner stores the second shard after the free; the replayed order must not free it.
    assert!(stored(&put(&owner, &node, sid2, bytes2, None)));
    let (_, error) = free(&owner, &node, o.clone());
    assert_eq!(error.as_deref(), Some("reject.free_epoch_replay"));
    node.restart();
    let (_, error) = free(&owner, &node, o);
    assert_eq!(error.as_deref(), Some("reject.free_epoch_replay"));
    assert!(node.shard_file(&sid2).exists());
    node.assert_logged("reject.free_epoch_replay");
    gate_ran("trust_enforcement_gc_host::b154_resent_order_is_a_replay_across_restart");
}

/// F-36 / B154-FREE reject (T5): a ring peer's order for the owner's shard is refused per shard
/// (`reject.delete_not_shard_owner`), and does not advance its epoch.
#[test]
fn b154_ring_peer_cannot_free_owner_shard() {
    let node = spawn_node("free-peer");
    let owner = key(0xB6);
    let peer = key(0xB7);
    let (sid, bytes) = shard(0x58, 1024);
    assert!(stored(&put(
        &owner,
        &node,
        sid,
        bytes,
        Some(grant(&owner, &sid))
    )));
    let o = order(&peer, node.host_key(), now_ms(), 1, vec![sid]);
    let (outcomes, error) = free(&peer, &node, o);
    assert_eq!(error, None);
    assert_eq!(
        outcomes,
        vec![FreeShardOutcome::Refused(
            "reject.delete_not_shard_owner".into()
        )]
    );
    assert!(node.shard_file(&sid).exists());
    node.assert_logged("reject.delete_not_shard_owner");
    gate_ran("trust_enforcement_gc_host::b154_ring_peer_cannot_free_owner_shard");
}

/// F-36 accept for `FreeShards`: the grant owner frees a shard another key stored with its grant
/// (a seed's fan-out), which `DeleteShard`'s storer rule alone would not allow.
#[test]
fn b154_grant_owner_frees_a_shard_stored_by_another_key() {
    let node = spawn_node("free-grant");
    let owner = key(0xB8);
    let seed = key(0xB9);
    let (sid, bytes) = shard(0x59, 2048);
    assert!(stored(&put(
        &seed,
        &node,
        sid,
        bytes,
        Some(grant(&owner, &sid))
    )));
    let o = order(&owner, node.host_key(), now_ms(), 1, vec![sid]);
    let (outcomes, _) = free(&owner, &node, o);
    assert_eq!(outcomes, vec![FreeShardOutcome::Freed]);
    assert!(!node.shard_file(&sid).exists());
    gate_ran("trust_enforcement_gc_host::b154_grant_owner_frees_a_shard_stored_by_another_key");
}

// --- B154-QUOTA (B-159, C16, T6): a removal credits the accounted owner -----------------------

/// A seed (`seed`) stores a shard with the owner's grant; the owner, which also holds a 1 KiB
/// shard of its own, frees it. Returns the node and the seed's and the owner's hosted bytes
/// before and after the free.
fn seed_fanout_then_owner_free(label: &str) -> (Node, [u64; 4]) {
    let node = spawn_node(label);
    let owner = key(0xC1);
    let seed = key(0xC2);
    let (own, own_bytes) = shard(0x61, 1024);
    let (fanned, fanned_bytes) = shard(0x62, 2048);
    assert!(stored(&put(&owner, &node, own, own_bytes, None)));
    let seed_before = node.hosted(&seed.device_peer_id());
    let fan = Some(grant(&owner, &fanned));
    assert!(stored(&put(&seed, &node, fanned, fanned_bytes, fan)));
    assert_eq!(node.hosted(&seed.device_peer_id()), seed_before + 2048);
    let owner_before = node.hosted(&owner.device_peer_id());
    let o = order(&owner, node.host_key(), now_ms(), 1, vec![fanned]);
    let (outcomes, _) = free(&owner, &node, o);
    assert_eq!(outcomes, vec![FreeShardOutcome::Freed]);
    let seed_after = node.hosted(&seed.device_peer_id());
    let owner_after = node.hosted(&owner.device_peer_id());
    (node, [seed_before, seed_after, owner_before, owner_after])
}

/// B154-QUOTA accept (T6): the seed's `bytes_hosted_for_peer` returns to its value before the put.
#[test]
fn b159_free_credits_the_account_that_stored_it() {
    let (_node, [seed_before, seed_after, _, _]) = seed_fanout_then_owner_free("quota-a");
    assert_eq!(
        seed_after, seed_before,
        "the seed's account is credited back"
    );
    gate_ran("trust_enforcement_gc_host::b159_free_credits_the_account_that_stored_it");
}

/// B154-QUOTA reject: the sender of the free (the owner) is not credited for a shard it did
/// not store; its own shard stays charged.
#[test]
fn b159_free_does_not_credit_the_sender() {
    let (_node, [_, _, owner_before, owner_after]) = seed_fanout_then_owner_free("quota-r");
    assert_eq!(owner_before, 1024);
    assert_eq!(owner_after, 1024, "the sender's account is unchanged");
    gate_ran("trust_enforcement_gc_host::b159_free_does_not_credit_the_sender");
}

// --- B158-FRESH: DeleteShard tokens are fresh --------------------------------------------------

/// B158-FRESH accept: a delete token signed now deletes the storer's shard.
#[test]
fn b158_fresh_delete_token_accepted() {
    let node = spawn_node("del-fresh");
    let storer = key(0xC3);
    let (sid, bytes) = shard(0x63, 512);
    assert!(stored(&put(&storer, &node, sid, bytes, None)));
    let r = send(&storer, &node, delete_at(&storer, sid, now_ms()));
    assert!(deleted(&r), "{r:?}");
    assert!(!node.shard_index_names(&sid));
    gate_ran("trust_enforcement_gc_host::b158_fresh_delete_token_accepted");
}

/// B158-FRESH reject (T5): an old `DeleteShard` token (31 s) is refused, the shard kept.
#[test]
fn b158_stale_delete_token_refused() {
    let node = spawn_node("del-stale");
    let storer = key(0xC4);
    let (sid, bytes) = shard(0x64, 512);
    assert!(stored(&put(&storer, &node, sid, bytes, None)));
    let r = send(&storer, &node, delete_at(&storer, sid, now_ms() - 31_000));
    assert!(!deleted(&r), "{r:?}");
    assert!(node.shard_file(&sid).exists());
    node.assert_logged("reject.delete_stale");
    gate_ran("trust_enforcement_gc_host::b158_stale_delete_token_refused");
}

// --- B-178 (C13): the binding is cleared only after a successful removal ----------------------

/// B-178: a delete that fails after authorization (the shards directory is read-only) leaves
/// the shard and its owner binding: another owner still cannot take the shard over, and the
/// owner's retry succeeds once the directory is writable.
#[test]
fn b178_failed_delete_keeps_shard_and_binding() {
    use std::os::unix::fs::PermissionsExt;
    let node = spawn_node("b178");
    let owner = key(0xC5);
    let thief = key(0xC6);
    let (sid, bytes) = shard(0x65, 512);
    let g = Some(grant(&owner, &sid));
    assert!(stored(&put(&owner, &node, sid, bytes.clone(), g)));
    let shards = node.dir.join("shards");
    std::fs::set_permissions(&shards, std::fs::Permissions::from_mode(0o555)).unwrap();
    let r = send(&owner, &node, delete_at(&owner, sid, now_ms()));
    std::fs::set_permissions(&shards, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!deleted(&r), "the removal failed: {r:?}");
    assert!(node.shard_file(&sid).exists());
    let r = put(&thief, &node, sid, bytes, Some(grant(&thief, &sid)));
    assert!(!stored(&r), "the binding survived the failed delete: {r:?}");
    let r = send(&owner, &node, delete_at(&owner, sid, now_ms()));
    assert!(deleted(&r), "the retry succeeds: {r:?}");
    gate_ran("trust_enforcement_gc_host::b178_failed_delete_keeps_shard_and_binding");
}

// --- C19: no host path re-puts a freed root ---------------------------------------------------

/// C19 (B-160 until L-27): `place_stripe`, the only function that puts a stripe's shards to
/// hosts, is called only from the owner's own store functions; no host-side path (wire handler,
/// auditor, handoff, eviction, GC) can re-put a root it freed. A new caller fails this test and
/// must show it never re-puts a root absent from `manifests/`. The freed shard also leaves the
/// shard index, so handoff never re-sends it (`b154_owner_order_frees_its_shard`).
#[test]
fn c19_place_stripe_has_only_owner_store_callers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(root.join("src/storage/block_store.rs")).unwrap();
    let mut callers = Vec::new();
    let mut current = String::new();
    for line in src.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("pub fn ").or_else(|| t.strip_prefix("fn ")) {
            current = rest
                .split(['(', '<'])
                .next()
                .unwrap_or_default()
                .to_string();
        }
        if t.contains("place_stripe(") && !t.starts_with("fn place_stripe") && !t.starts_with("//")
        {
            callers.push(current.clone());
        }
    }
    callers.sort();
    callers.dedup();
    assert_eq!(
        callers,
        vec!["store_file_streaming", "store_reader_streaming"]
    );
    let mut others = Vec::new();
    let mut stack = vec![root.join("src")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs")
                && !p.ends_with("block_store.rs")
                && std::fs::read_to_string(&p)
                    .unwrap()
                    .contains("place_stripe(")
            {
                others.push(p);
            }
        }
    }
    assert!(
        others.is_empty(),
        "place_stripe called outside block_store.rs: {others:?}"
    );
    gate_ran("trust_enforcement_gc_host::c19_place_stripe_has_only_owner_store_callers");
}

// --- B-147 (G5): SIGKILL between the audit writes ---------------------------------------------

const B147_CHILD_ENV: &str = "PV_B147_CHILD_DIR";

/// The child side of `b147_sigkill_between_writes_state_and_ledger_agree` (the test binary
/// re-run with [`B147_CHILD_ENV`] set): replays the journal as a starting auditor does, then
/// credits audits until it is killed.
fn b147_child_loop(dir: &Path) -> ! {
    let quota = QuotaManager::new(1 << 30, 1 << 20);
    let bs = parvault::storage::BlockStore::new(dir, quota).unwrap();
    let mut st = parvault::por::auditor::AuditorState::load(dir);
    parvault::por::audit_journal::replay_journal(dir, &mut st, &bs);
    let mut i = 0u64;
    loop {
        let degraded = i.is_multiple_of(3).then(|| format!("shard-{i}"));
        let passed = degraded.is_none();
        parvault::por::audit_journal::credit_audit(
            Some(dir),
            &mut st,
            &bs,
            "prover",
            passed,
            degraded,
        );
        i += 1;
    }
}

fn ledger_totals(dir: &Path) -> (u64, u64) {
    QuotaManager::with_persistence_dir(1 << 30, 1 << 20, dir)
        .peer_account("prover")
        .map_or((0, 0), |a| (a.por_passes, a.por_failures))
}

/// B-147 (G5): an auditing process is SIGKILLed at a random point 20 times; after each kill a
/// restart's replay leaves the auditor state and the quota ledger agreeing, and no audit is
/// counted twice (the totals never fall).
#[test]
fn b147_sigkill_between_writes_state_and_ledger_agree() {
    if let Ok(dir) = std::env::var(B147_CHILD_ENV) {
        b147_child_loop(Path::new(&dir));
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let exe = std::env::current_exe().unwrap();
    let journal = dir.join(parvault::por::audit_journal::AUDIT_JOURNAL_FILE);
    let mut last = (0u64, 0u64);
    let mut replays = 0;
    for round in 0..20u64 {
        let before = std::fs::read(&journal).ok();
        let mut child = Command::new(&exe)
            .args([
                "--exact",
                "b147_sigkill_between_writes_state_and_ledger_agree",
                "--test-threads=1",
            ])
            .env(B147_CHILD_ENV, dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while std::fs::read(&journal).ok() == before {
            assert!(
                Instant::now() < deadline,
                "the child never wrote the journal"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(3 + (round * 7) % 40));
        child.kill().unwrap();
        child.wait().unwrap();

        let quota = QuotaManager::new(1 << 30, 1 << 20);
        let bs = parvault::storage::BlockStore::new(dir, quota).unwrap();
        let mut st = parvault::por::auditor::AuditorState::load(dir);
        if parvault::por::audit_journal::replay_journal(dir, &mut st, &bs) {
            replays += 1;
        }
        drop(bs);
        let ledger = ledger_totals(dir);
        assert_eq!(
            (st.passed, st.failed),
            ledger,
            "round {round}: state and ledger agree"
        );
        assert!(
            ledger.0 >= last.0 && ledger.1 >= last.1,
            "round {round}: totals never fall"
        );
        last = ledger;
    }
    assert!(last.0 > 0 && last.1 > 0);
    eprintln!("b147: 20 kills, {replays} needed the journal; totals {last:?}");
    gate_ran("trust_enforcement_gc_host::b147_sigkill_between_writes_state_and_ledger_agree");
}

// --- B-152 (a): per-shard indexes return to their start; the held-shard bound ------------------

/// A shard of stripe (`salt`, `i`), 256 bytes, distinct per pair.
fn shard_n(salt: u8, i: u32) -> (ShardId, Vec<u8>) {
    let mut bytes = vec![salt; 256];
    bytes[..4].copy_from_slice(&i.to_le_bytes());
    let mut root = [salt; 32];
    root[..4].copy_from_slice(&i.to_be_bytes());
    let h = parvault::sharding::merkle::hash_shard_leaf(0, &bytes);
    (
        ShardId {
            stripe_merkle_root: root,
            shard_index: 0,
            shard_hash: h,
        },
        bytes,
    )
}

/// A ring member's client with a 30 s request timeout: a 1,024-shard free or a 667-shard
/// eviction purge outlasts the 1.2 s default (each purged file is shredded and fsynced); the
/// test bounds and reports the time separately.
fn member_client(ident: &NodeIdentity) -> MeshClient {
    MeshClient::new(ident.clone(), Vec::new(), None)
        .with_admission(AdmissionSource::from_genesis(genesis()))
        .with_timeout(Duration::from_secs(30))
}

fn rss_anon_kb(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("RssAnon:"))
                .and_then(|v| v.trim().strip_suffix("kB"))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0)
}

/// Every per-shard index of a data dir, counted from disk: shard files, `shard_index.bin`,
/// quota-held shards, eviction attribution records, PoR session keys, grant owners, repair grants.
fn disk_counts(dir: &Path) -> [usize; 7] {
    let files = std::fs::read_dir(dir.join("shards"))
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".shard"))
                .count()
        })
        .unwrap_or(0);
    let index = std::fs::read(dir.join("shard_index.bin"))
        .ok()
        .and_then(|raw| bincode::deserialize::<HashMap<String, ShardId>>(&raw).ok())
        .map_or(0, |m| m.len());
    let held = QuotaManager::with_persistence_dir(1 << 40, 0, dir).held_shard_count();
    let attribution =
        parvault::storage::eviction::indexed_regular_shard_ids(dir).map_or(0, |v| v.len());
    let (sessions, owners, grants) =
        PorVerifierEngine::with_persistence_dir(300, dir).index_counts();
    [files, index, held, attribution, sessions, owners, grants]
}

/// One cycle: 2,000 shards stored with grants by three keys, then freed through all three
/// paths (`DeleteShard`, `FreeShards`, an eviction order). Returns (peak anon kB while holding,
/// seconds the `FreeShards` orders took).
fn b152_cycle(node: &Node, cycle: u8) -> (u64, f64) {
    const N: u32 = 2_000;
    let pid = node.child.id();
    let (a, b, e) = (
        key(0xD0 + cycle * 3),
        key(0xD1 + cycle * 3),
        key(0xD2 + cycle * 3),
    );
    let clients = [member_client(&a), member_client(&b), member_client(&e)];
    let owners = [&a, &b, &e];
    let mut ids: [Vec<ShardId>; 3] = Default::default();
    let mut peak = 0;
    for i in 0..N {
        let who = (i % 3) as usize;
        let (sid, bytes) = shard_n(0x40 + cycle, i);
        let req = MeshWireRequest::PutShard {
            owner_peer_id: String::new(),
            shard_id: sid,
            shard_bytes: bytes,
            session_key_commit: [0x5E; 32],
            repair_grant: Some(grant(owners[who], &sid)),
        };
        let r = clients[who].send_request(&node.addr, req).unwrap();
        assert!(stored(&r), "put {i}: {r:?}");
        ids[who].push(sid);
        if i % 100 == 0 {
            peak = peak.max(rss_anon_kb(pid));
        }
    }
    peak = peak.max(rss_anon_kb(pid));
    // 1. DeleteShard, one by one.
    let t = Instant::now();
    for sid in &ids[0] {
        let r = clients[0]
            .send_request(&node.addr, delete_at(&a, *sid, now_ms()))
            .unwrap();
        assert!(deleted(&r), "{r:?}");
    }
    let delete_secs = t.elapsed().as_secs_f64();
    // 2. FreeShards, at most 1,024 per order (arch056c 1.7: one flush per order, bounded time).
    let t = Instant::now();
    for (n, chunk) in ids[1].chunks(1_024).enumerate() {
        let o = order(
            &b,
            node.host_key(),
            now_ms(),
            now_ms() + n as u64,
            chunk.to_vec(),
        );
        match clients[1]
            .send_request(&node.addr, MeshWireRequest::FreeShards { order: o })
            .unwrap()
        {
            MeshWireResponse::FreeShardsAck {
                outcomes,
                error: None,
            } => {
                assert!(outcomes.iter().all(|x| *x == FreeShardOutcome::Freed));
            }
            other => panic!("{other:?}"),
        }
    }
    let free_secs = t.elapsed().as_secs_f64();
    // 3. Eviction: a local-owner order (signed by the node's own key) for the third key.
    let node_key = NodeIdentity::load_or_generate_in_dir(&node.dir).unwrap();
    let t = Instant::now();
    let ev = parvault::storage::SignedBadActorEvictionOrder::issue(
        &node_key,
        parvault::storage::EvictionTarget::PeerOrIssuerPubkey(e.public_key_bytes()),
        "b152 cycle",
        now_ms(),
        now_ms() + 3_600_000,
        0,
    );
    match clients[0]
        .send_request(&node.addr, MeshWireRequest::BroadcastEvictionOrder(ev))
        .unwrap()
    {
        MeshWireResponse::EvictionOrderAck {
            accepted: true,
            purged_regular_shards,
            ..
        } => {
            assert_eq!(purged_regular_shards, ids[2].len());
        }
        other => panic!("{other:?}\n{}", node.log_text()),
    }
    eprintln!(
        "b152 cycle {cycle}: {} deletes {delete_secs:.2} s, FreeShards of {} {free_secs:.2} s, \
         eviction of {} {:.2} s",
        ids[0].len(),
        ids[1].len(),
        ids[2].len(),
        t.elapsed().as_secs_f64()
    );
    (peak, free_secs)
}

/// B-152 (a), arch056c 1.8: 2,000 shards stored and freed through all three paths
/// (`DeleteShard`, `FreeShards`, eviction) leave every per-shard index at its start count, also
/// recounted from disk after each restart; later cycles peak no higher than the first plus
/// 2 MiB (about 1 kB per held shard, so a per-shard leak of that size fails; the allocator's
/// run-to-run spread measured 1.6 MiB). Three cycles, a restart before each later one. Prints
/// the per-shard anon bytes for `docs/BENCHMARKS.md`.
#[test]
fn b152_two_cycles_of_2000_shards() {
    const MARGIN_KB: u64 = 2_048;
    let mut node = spawn_node("b152-cycles");
    std::thread::sleep(Duration::from_secs(2));
    let start = disk_counts(&node.dir);
    assert_eq!(start, [0; 7], "a fresh node holds no shard");
    let mut growth = Vec::new();
    for cycle in 0..3u8 {
        if cycle > 0 {
            node.restart();
            assert_eq!(
                disk_counts(&node.dir),
                start,
                "recounted from disk after a restart"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
        let base = rss_anon_kb(node.child.id());
        let (peak, free_secs) = b152_cycle(&node, cycle);
        assert_eq!(
            disk_counts(&node.dir),
            start,
            "cycle {cycle}: every index back to its start"
        );
        assert!(free_secs < 10.0, "the free is bounded in time");
        eprintln!(
            "b152 cycle {cycle}: base {base} kB, peak {peak} kB, about {} anon bytes per held shard",
            peak.saturating_sub(base) * 1024 / 2_000
        );
        growth.push(peak.saturating_sub(base));
    }
    for (i, g) in growth.iter().enumerate().skip(1) {
        assert!(
            *g <= growth[0] + MARGIN_KB,
            "cycle {i} grew {g} kB, more than cycle 0's {} kB plus {MARGIN_KB} kB",
            growth[0]
        );
    }
    gate_ran("trust_enforcement_gc_host::b152_two_cycles_of_2000_shards");
}

/// B152-COUNT accept: under the held-shard bound (`max_held_shards = 2` in `config.toml`) a
/// node stores up to the bound.
#[test]
fn b152_put_within_held_shard_bound_accepted() {
    let node = spawn_node_with("count-a", Some("max_held_shards = 2\n"), &[]);
    node.assert_logged("info.held_shard_bound");
    let owner = key(0xE1);
    for i in 0..2 {
        let (sid, bytes) = shard_n(0x71, i);
        assert!(stored(&put(&owner, &node, sid, bytes, None)));
    }
    gate_ran("trust_enforcement_gc_host::b152_put_within_held_shard_bound_accepted");
}

/// B152-COUNT reject: at the bound a new shard is refused (`reject.node_shard_count`) and not
/// written; a freed slot is usable again.
#[test]
fn b152_put_over_held_shard_bound_refused() {
    let node = spawn_node_with("count-r", Some("max_held_shards = 2\n"), &[]);
    let owner = key(0xE2);
    let mut held = Vec::new();
    for i in 0..2 {
        let (sid, bytes) = shard_n(0x72, i);
        assert!(stored(&put(&owner, &node, sid, bytes, None)));
        held.push(sid);
    }
    let (sid, bytes) = shard_n(0x72, 9);
    assert!(!stored(&put(&owner, &node, sid, bytes.clone(), None)));
    assert!(!node.shard_file(&sid).exists());
    node.assert_logged("reject.node_shard_count");
    let r = send(&owner, &node, delete_at(&owner, held[0], now_ms()));
    assert!(deleted(&r));
    assert!(stored(&put(&owner, &node, sid, bytes, None)));
    gate_ran("trust_enforcement_gc_host::b152_put_over_held_shard_bound_refused");
}

/// The bound and source the daemon logged at startup (`info.held_shard_bound`).
fn logged_bound(node: &Node) -> (u64, String) {
    node.assert_logged("info.held_shard_bound");
    let text = node.log_text();
    let line = text
        .lines()
        .find(|l| l.contains("info.held_shard_bound"))
        .unwrap();
    let field = |name: &str| -> String {
        let at = line.find(&format!("{name}=")).unwrap() + name.len() + 1;
        line[at..]
            .trim_start_matches('"')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect()
    };
    (field("max_held_shards").parse().unwrap(), field("source"))
}

/// L-130: a homelab-nas daemon under a 64 MiB and a 256 MiB cgroup limit (`systemd-run --scope
/// -p MemoryMax`, the limit it actually runs under) derives bounds in that ratio from the
/// cgroup; a config value wins under the same limit.
#[test]
fn l130_bound_follows_the_cgroup_limit() {
    let scope = |mem: &'static str| -> Vec<&'static str> {
        vec![
            "systemd-run",
            "--user",
            "--scope",
            "--quiet",
            "-p",
            mem,
            "--",
        ]
    };
    let nas = "hardware_profile = \"homelab-nas\"\n";
    let n64 = spawn_node_with("l130-64", Some(nas), &scope("MemoryMax=64M"));
    let n256 = spawn_node_with("l130-256", Some(nas), &scope("MemoryMax=256M"));
    let over = format!("{nas}max_held_shards = 7\n");
    let n_over = spawn_node_with("l130-cfg", Some(&over), &scope("MemoryMax=64M"));
    let (b64, s64) = logged_bound(&n64);
    let (b256, s256) = logged_bound(&n256);
    assert_eq!((s64.as_str(), s256.as_str()), ("cgroup", "cgroup"));
    assert!(b256.abs_diff(4 * b64) <= 4, "{b64} vs {b256}");
    assert_eq!(logged_bound(&n_over), (7, "config".to_string()));
    gate_ran("trust_enforcement_gc_host::l130_bound_follows_the_cgroup_limit");
}
