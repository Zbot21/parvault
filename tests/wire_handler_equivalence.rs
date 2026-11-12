//! Characterisation suite for the inbound wire handlers (`network::wire_handler`).
//!
//! Pins today's behaviour of the `parvault` daemon handler and the `parvault-seed` handler
//! (homelab-vault and public-bootstrapper modes) for every `MeshWireRequest` variant and branch,
//! so the handlers can be merged into one shared implementation without a behaviour change.
//!
//! Each case runs the same request on three fixtures built from one template directory (same
//! keys and secrets) and compares the full response, the full data-directory tree (path, length,
//! SHA-256), quota usage, seed-server PoR counters and rendezvous contents. Rows that are
//! identical across roles must produce identical outcomes; divergent rows assert the exact
//! difference.
//!
//! Cross-role comparison alone misses a change that hits every role equally, so each variant
//! also asserts its absolute effect (response fields and the state change, read through the
//! store, quota, eviction, rendezvous and takedown APIs).
//!
//! Mutation record (each mutant is a one-line change in `src/network/wire_handler.rs`; run with
//! a dedicated `CARGO_TARGET_DIR` so a mutated library is never reused by another run):
//!
//! | Mutant | Kind | Failing test(s) |
//! | :-- | :-- | :-- |
//! | `record_put_shard_admission_ip`: seed returns `false` | hook | `put_shard` |
//! | `on_por_pass`: seed does nothing | hook | `por_audit`, `multi_segment_por_audit` |
//! | `on_por_pass`: daemon records a heartbeat | hook | `por_audit`, `multi_segment_por_audit` |
//! | `max_probationary_lease_bytes`: seed returns `0` | hook | `put_blinded_shard`, `relay_pq_onion_over_seed_lease_limit` |
//! | `tombstone_via_seed_server`: seed returns `false` | hook | `delete_blinded_tombstone` |
//! | `status_region`: seed returns the daemon text | hook | `query_node_status` |
//! | `tracker_admin_pubkey`: seed returns `None` | hook | `register_wan_rendezvous`, `lookup_wan_rendezvous` |
//! | `record_public_card_ips`: seed returns `false` | hook | `register_wan_rendezvous` |
//! | `takedown_gate`: seed always open | hook | `submit_abuse_takedown` |
//! | `eviction_council`: seed drops its local tracker admin | hook | `broadcast_eviction_order` |
//! | `shard_owner` ignores the claimed owner | symmetric | `put_shard`, `delete_shard` |
//! | `PutBlindedShard` drops `record_peer_admission_ip` | symmetric | `put_blinded_shard` |
//! | `RenewBlindedLease` ignores `extension_epochs` | symmetric | `renew_blinded_lease` |
//! | `PutShard` skips `register_repair_grant` | symmetric | `get_ciphertext_shard` |
//!
//! The four symmetric mutants passed the suite before the absolute assertions were added.

use libp2p::Multiaddr;
use parvault::bootstrap::{
    BlindedShardTombstone, LiteStripeSyndicationBundle, PersonalDeviceCert, ZeroTrustSeedServer,
};
use parvault::config::{ErasureTier, NodeConfig};
use parvault::crypto::pqc::{HybridPqSigningKeypair, PqOnionFinalBundle};
use parvault::crypto::{HybridKemKeypair, MasterKey, NodeIdentity, PqRelayedShardEnvelope};
use parvault::network::wire_handler::{
    handle_daemon_wire_request, handle_seed_wire_request, DaemonWireHandlerCtx, SeedWireHandlerCtx,
};
use parvault::network::{
    derive_slot_key_from_code, node_identity_libp2p_peer_id, seal_public_tracker_card,
    seal_wan_peer_card, DelegationChain, DhtEnvelopeKind, DhtWireEnvelope, InvitationHop,
    KnownPeersStore, MeshWireRequest, MeshWireResponse, PublicCommonsTicket, TrustPoolMode,
    WanPeerCard, WanRendezvousRegistry, WebOfTrustRegistry, DEFAULT_PUBLIC_WOT_POW_BITS,
    PUBLIC_COMMONS_SWARM_SLOT,
};
use parvault::por::{
    generate_multi_segment_por_challenge, generate_por_challenge, PorVerifierEngine, RepairGrant,
};
use parvault::sharding::encode_ciphertext_stripe;
use parvault::storage::{
    AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, BlockStore, EvictionTarget,
    FileManifest, PrivacyPreservingEvictionEngine, PublicTrackerTakedownQueue, QuotaManager,
    ShardId, SignedBadActorEvictionOrder, SignedDhtManifestEnvelope, StripeManifestEntry,
    VerifiableAbuseReport, VoucherNullifierLedger,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

/// Serialises cases that read or set the eviction-council environment variables.
static ENV_LOCK: Mutex<()> = Mutex::new(());
const ENV_VARS: [&str; 2] = [
    "PARVAULT_EVICTION_AUTHORITIES",
    "PARVAULT_TRACKER_EVICTION_QUORUM",
];
const SEED_DEFAULT_LEASE_LIMIT: u64 = 64 * 1024 * 1024; // run_seed_listener_loop's value

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    let g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    for v in ENV_VARS {
        std::env::remove_var(v);
    }
    g
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Daemon,
    SeedHomelab,
    SeedPublic,
}
const ROLES: [Role; 3] = [Role::Daemon, Role::SeedHomelab, Role::SeedPublic];

/// Key material shared by all three fixtures of one case.
struct Keys {
    node: NodeIdentity,
    genesis: NodeIdentity,
    admin: NodeIdentity,
    owner_pq: HybridPqSigningKeypair,
    voucher_issuer: NodeIdentity,
}

impl Keys {
    fn new() -> Self {
        Self {
            node: NodeIdentity::from_seed([0x11; 32]),
            genesis: NodeIdentity::from_seed([0x22; 32]),
            admin: NodeIdentity::from_seed([0x33; 32]),
            owner_pq: HybridPqSigningKeypair::generate().unwrap(),
            voucher_issuer: NodeIdentity::from_seed([0x44; 32]),
        }
    }
}

struct Peer {
    ident: NodeIdentity,
    id: String,
    addr: Multiaddr,
    ip: std::net::IpAddr,
}

impl Peer {
    fn new(seed: u8, ip: &str) -> Self {
        let ident = NodeIdentity::from_seed([seed; 32]);
        let id = node_identity_libp2p_peer_id(&ident).unwrap().to_string();
        let addr: Multiaddr = format!("/ip4/{ip}/tcp/4001").parse().unwrap();
        let ip = ip.parse().unwrap();
        Self {
            ident,
            id,
            addr,
            ip,
        }
    }
}

/// A fresh temp root, removed when the returned guard drops (on success and on panic).
fn unique_dir(label: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("parvault-wire-eq-{label}-"))
        .tempdir()
        .unwrap()
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap().flatten() {
        let p = e.path();
        let t = dst.join(e.file_name());
        if p.is_dir() {
            copy_dir(&p, &t);
        } else {
            std::fs::copy(&p, &t).unwrap();
        }
    }
}

/// Builds every persisted secret once, so each role loads identical state from its copy.
fn template(keys: &Keys) -> TempDir {
    let root = unique_dir("template");
    let dir = root.path().to_path_buf();
    let genesis = keys.genesis.public_key_bytes();
    let _ = BlockStore::new(&dir, QuotaManager::new(512 * 1024 * 1024, 64 * 1024 * 1024)).unwrap();
    let _ = WebOfTrustRegistry::with_persistence_dir(genesis, 3, &dir);
    let _ = PorVerifierEngine::with_persistence_dir(300, &dir);
    let _ = VoucherNullifierLedger::with_persistence_dir(genesis, &dir);
    let _ = HybridKemKeypair::load_or_generate_in_dir(&dir).unwrap();
    let _ = PrivacyPreservingEvictionEngine::load_or_init(&dir).unwrap();
    let _ = PublicTrackerTakedownQueue::load_or_init(&dir).unwrap();
    root
}

struct Fx {
    role: Role,
    dir: PathBuf,
    cfg: NodeConfig,
    node: NodeIdentity,
    genesis: [u8; 32],
    public_mode: bool,
    store: BlockStore,
    server: ZeroTrustSeedServer,
    wot: WebOfTrustRegistry,
    por: PorVerifierEngine,
    nullifiers: VoucherNullifierLedger,
    kem: HybridKemKeypair,
    wan: WanRendezvousRegistry,
    eviction: PrivacyPreservingEvictionEngine,
    takedown: PublicTrackerTakedownQueue,
    admin_pk: [u8; 32],
    max_lease: u64,
    /// Owns `dir`; declared last so the fixture's state drops before the directory is removed.
    _root: TempDir,
}

impl Fx {
    fn new(role: Role, keys: &Keys, tpl: &Path, label: &str) -> Self {
        let root = unique_dir(&format!("{label}-{role:?}"));
        let dir = root.path().to_path_buf();
        copy_dir(tpl, &dir);
        let genesis = keys.genesis.public_key_bytes();
        let store =
            BlockStore::new(&dir, QuotaManager::new(512 * 1024 * 1024, 64 * 1024 * 1024)).unwrap();
        let server = match role {
            Role::Daemon | Role::SeedHomelab => ZeroTrustSeedServer::new_homelab_vault(
                "server-peer",
                store.clone(),
                keys.owner_pq.public_key(),
                2,
            ),
            Role::SeedPublic => ZeroTrustSeedServer::new_public_bootstrapper(
                "server-peer",
                store.clone(),
                keys.voucher_issuer.public_key_bytes(),
                2,
            ),
        };
        let cfg = NodeConfig {
            data_dir: dir.clone(),
            ..NodeConfig::default()
        };
        Self {
            role,
            cfg,
            node: NodeIdentity::from_seed([0x11; 32]),
            genesis,
            public_mode: false,
            wot: WebOfTrustRegistry::with_persistence_dir(genesis, 3, &dir),
            por: PorVerifierEngine::with_persistence_dir(300, &dir),
            nullifiers: VoucherNullifierLedger::with_persistence_dir(genesis, &dir),
            kem: HybridKemKeypair::load_or_generate_in_dir(&dir).unwrap(),
            wan: WanRendezvousRegistry::load_or_new(Some(&dir.join("wan_rendezvous.bin"))),
            eviction: PrivacyPreservingEvictionEngine::load_or_init(&dir).unwrap(),
            takedown: PublicTrackerTakedownQueue::load_or_init(&dir).unwrap(),
            admin_pk: keys.admin.public_key_bytes(),
            max_lease: SEED_DEFAULT_LEASE_LIMIT,
            _root: root,
            store,
            server,
            dir,
        }
    }

    fn call(&mut self, peer: &Peer, req: MeshWireRequest) -> MeshWireResponse {
        match self.role {
            Role::Daemon => handle_daemon_wire_request(
                &peer.id,
                Some(&peer.addr),
                req,
                DaemonWireHandlerCtx {
                    cfg: &self.cfg,
                    node_identity: &self.node,
                    genesis_pubkey: self.genesis,
                    public_mode: self.public_mode,
                    block_store: &self.store,
                    wot: &mut self.wot,
                    por_verifier: &mut self.por,
                    nullifier_ledger: &mut self.nullifiers,
                    pq_kem: &self.kem,
                    lite_seed_server: &mut self.server,
                    wan_registry: &mut self.wan,
                    eviction: &mut self.eviction,
                    takedown_queue: &mut self.takedown,
                },
            ),
            Role::SeedHomelab | Role::SeedPublic => {
                // Mirrors run_seed_listener_loop: the local tracker admin key is always loaded on a
                // disk-backed seed, and only a public bootstrapper advertises it.
                let advertised = (self.role == Role::SeedPublic).then_some(self.admin_pk);
                handle_seed_wire_request(
                    &peer.id,
                    Some(&peer.addr),
                    req,
                    SeedWireHandlerCtx {
                        data_dir: &self.dir,
                        node_identity: &self.node,
                        advertised_admin_pk: advertised,
                        local_tracker_admin_pk: Some(self.admin_pk),
                        extra_council_pks: &[],
                        council_quorum: None,
                        max_probationary_lease_bytes: self.max_lease,
                        genesis_pubkey: self.genesis,
                        block_store: &self.store,
                        server: &mut self.server,
                        wot: &mut self.wot,
                        por_verifier: &mut self.por,
                        nullifier_ledger: &mut self.nullifiers,
                        pq_kem: &self.kem,
                        wan_registry: &mut self.wan,
                        eviction: &mut self.eviction,
                        takedown_queue: &mut self.takedown,
                    },
                )
            }
        }
    }

    /// Bans `target` directly in the eviction engine (setup only; not a handler call).
    fn ban(&mut self, keys: &Keys, target: EvictionTarget) {
        let order =
            SignedBadActorEvictionOrder::issue(&keys.admin, target, "fixture-ban", now_ms(), 0);
        self.eviction
            .apply_signed_eviction_order(
                &order,
                &[keys.admin.public_key_bytes()],
                now_ms(),
                &self.store,
            )
            .unwrap();
    }

    /// Bytes the quota manager charges to `owner` (absolute, per account).
    fn hosted(&self, owner: &str) -> u64 {
        self.store
            .quota()
            .lock()
            .unwrap()
            .peer_account(owner)
            .map(|a| a.bytes_hosted_for_peer)
            .unwrap_or(0)
    }

    /// Public keys the eviction engine has recorded as admitted from `ip`.
    fn admitted_at(&self, ip: std::net::IpAddr) -> Vec<[u8; 32]> {
        self.eviction.resolve_pubkeys_for_ip(ip)
    }

    /// Whether ingress from `ip` is blocked by the eviction engine.
    fn blocked(&self, ip: std::net::IpAddr) -> bool {
        self.eviction
            .is_ingress_blocked(Some(ip), None, None, None, None)
            .is_some()
    }

    fn tree(&self) -> BTreeMap<String, (u64, String)> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, (u64, String)>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(root, &p, out);
                } else {
                    let bytes = std::fs::read(&p).unwrap();
                    let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                    // Index files persist HashMaps (per-instance iteration order) or wall-clock
                    // times, so only raw shard / manifest data is compared byte for byte.
                    let raw = rel.starts_with("shards") || rel.starts_with("manifests");
                    let digest = if raw {
                        hex::encode(Sha256::digest(&bytes))
                    } else {
                        String::new()
                    };
                    out.insert(rel, (bytes.len() as u64, digest));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.dir, &self.dir, &mut out);
        out
    }

    fn snapshot(&mut self) -> Snap {
        let quota_used = self.store.quota().lock().unwrap().used_storage_bytes();
        let rep = self.server.status_report(1);
        Snap {
            tree: self.tree(),
            quota_used,
            por_passes: rep.por_passes,
            server_used: rep.used_storage_bytes,
            leases: rep.active_blinded_leases,
            public_swarm: format!("{:?}", self.wan.lookup_public_swarm(64, now_ms())),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Snap {
    tree: BTreeMap<String, (u64, String)>,
    quota_used: u64,
    por_passes: u64,
    server_used: u64,
    leases: usize,
    public_swarm: String,
}

/// Outcome of one request: the response and every state change it caused (path, length, and
/// SHA-256 for raw data files).
#[derive(Debug, PartialEq)]
struct Outcome {
    resp: String,
    changed: BTreeMap<String, Option<(u64, String)>>,
    quota_delta: i128,
    por_delta: i128,
    leases_delta: i128,
    public_swarm_changed: Option<String>,
}

fn diff(before: &Snap, after: &Snap) -> BTreeMap<String, Option<(u64, String)>> {
    let mut out = BTreeMap::new();
    for (k, v) in &after.tree {
        if before.tree.get(k) != Some(v) {
            out.insert(k.clone(), Some(v.clone()));
        }
    }
    for k in before.tree.keys() {
        if !after.tree.contains_key(k) {
            out.insert(k.clone(), None);
        }
    }
    out
}

impl Fx {
    fn run(&mut self, peer: &Peer, req: MeshWireRequest) -> Outcome {
        let before = self.snapshot();
        let resp = self.call(peer, req);
        let after = self.snapshot();
        Outcome {
            resp: format!("{resp:?}"),
            changed: diff(&before, &after),
            quota_delta: after.quota_used as i128 - before.quota_used as i128,
            por_delta: after.por_passes as i128 - before.por_passes as i128,
            leases_delta: after.leases as i128 - before.leases as i128,
            public_swarm_changed: (after.public_swarm != before.public_swarm)
                .then_some(after.public_swarm),
        }
    }
}

/// Three fixtures (daemon, seed homelab, seed public) for one case.
struct Trio {
    keys: Keys,
    fx: Vec<Fx>,
}

impl Trio {
    fn new(label: &str) -> Self {
        let keys = Keys::new();
        let tpl = template(&keys);
        let fx = ROLES
            .iter()
            .map(|r| Fx::new(*r, &keys, tpl.path(), label))
            .collect();
        Self { keys, fx }
    }
    /// Admits `peer` into every fixture's ring (a genesis-issued chain), as a v0.5.0 handshake
    /// would. Requests that need an admitted sender are refused without it.
    fn admit(&mut self, peer: &Peer) {
        let chain = DelegationChain {
            hops: vec![InvitationHop::issue(
                &self.keys.genesis,
                peer.ident.public_key_bytes(),
                1,
                100,
            )],
        };
        for fx in &mut self.fx {
            fx.wot.verify_and_admit_chain(&chain).unwrap();
        }
    }
    /// Applies `f` to every fixture (setup).
    fn each(&mut self, mut f: impl FnMut(&mut Fx, &Keys)) {
        for fx in &mut self.fx {
            f(fx, &self.keys);
        }
    }
    /// Like `run`, also returning the typed responses for absolute checks.
    fn run_resp(
        &mut self,
        peer: &Peer,
        req: &MeshWireRequest,
    ) -> ([Outcome; 3], Vec<MeshWireResponse>) {
        let mut outs = Vec::new();
        let mut resps = Vec::new();
        for f in &mut self.fx {
            let before = f.snapshot();
            let resp = f.call(peer, req.clone());
            let after = f.snapshot();
            outs.push(Outcome {
                resp: format!("{resp:?}"),
                changed: diff(&before, &after),
                quota_delta: after.quota_used as i128 - before.quota_used as i128,
                por_delta: after.por_passes as i128 - before.por_passes as i128,
                leases_delta: after.leases as i128 - before.leases as i128,
                public_swarm_changed: (after.public_swarm != before.public_swarm)
                    .then_some(after.public_swarm),
            });
            resps.push(resp);
        }
        let [a, b, c]: [Outcome; 3] = outs.try_into().unwrap();
        ([a, b, c], resps)
    }
    /// Runs the same request (built once, cloned) on all three roles.
    fn run(&mut self, peer: &Peer, req: &MeshWireRequest) -> [Outcome; 3] {
        let mut out = self.fx.iter_mut().map(|f| f.run(peer, req.clone()));
        [
            out.next().unwrap(),
            out.next().unwrap(),
            out.next().unwrap(),
        ]
    }
}

fn assert_identical(o: &[Outcome; 3]) {
    assert_eq!(o[0], o[1], "daemon vs seed-homelab outcome differs");
    assert_eq!(o[1], o[2], "seed-homelab vs seed-public outcome differs");
}

/// Files whose content the seed's extra eviction admission records change.
fn eviction_files(changed: &BTreeMap<String, Option<(u64, String)>>) -> Vec<String> {
    changed
        .keys()
        .filter(|k| k.contains("eviction"))
        .cloned()
        .collect()
}

/// Asserts the two outcomes agree everywhere except in eviction-index files.
fn assert_same_except_eviction(a: &Outcome, b: &Outcome) {
    let strip = |o: &Outcome| {
        let mut c = o.changed.clone();
        c.retain(|k, _| !k.contains("eviction"));
        (
            o.resp.clone(),
            c,
            o.quota_delta,
            o.por_delta,
            o.leases_delta,
            o.public_swarm_changed.clone(),
        )
    };
    assert_eq!(strip(a), strip(b));
}

// --- request builders ---------------------------------------------------------------------------

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

fn put_shard_req(
    owner: &str,
    shard_id: ShardId,
    bytes: Vec<u8>,
    session: [u8; 32],
) -> MeshWireRequest {
    MeshWireRequest::PutShard {
        owner_peer_id: owner.to_string(),
        shard_id,
        shard_bytes: bytes,
        session_key_commit: session,
        repair_grant: None,
    }
}

struct Blinded {
    id: BlindedShardId,
    cap_ident: NodeIdentity,
    cap: BlindedShardCapability,
    bytes: Vec<u8>,
    delete_verifier: [u8; 32],
    delete_secret: [u8; 32],
}

fn blinded(seed: u8, len: usize) -> Blinded {
    let mk = MasterKey::from_bytes([seed; 32]);
    let bytes = vec![seed ^ 0x5A; len];
    let id = BlindedShardId::derive(&mk, &[seed; 32], 0, &bytes);
    let (cap_ident, cap) = BlindedShardCapability::derive_keypair(&mk, &id.locator);
    let delete_secret = [seed ^ 0x77; 32];
    let delete_verifier =
        BlindedShardTombstone::derive_delete_verifier(&delete_secret, &id.locator);
    Blinded {
        id,
        cap_ident,
        cap,
        bytes,
        delete_verifier,
        delete_secret,
    }
}

fn put_blinded(b: &Blinded, voucher: AnonymousQuotaVoucher) -> MeshWireRequest {
    MeshWireRequest::PutBlindedShard {
        blinded_id: b.id,
        shard_bytes: b.bytes.clone(),
        capability: b.cap,
        voucher,
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: b.delete_verifier,
    }
}

fn wan_card(id: &NodeIdentity, addrs: &[&str]) -> WanPeerCard {
    WanPeerCard::new(
        id,
        "probe",
        "daemon",
        addrs.iter().map(|s| s.to_string()).collect(),
        None,
        None,
        3600,
        now_ms(),
    )
    .unwrap()
}

// --- the exhaustive variant guard ---------------------------------------------------------------

/// Names the case that covers each variant. No wildcard: a new variant fails to compile here.
fn covering_case(req: &MeshWireRequest) -> &'static str {
    match req {
        MeshWireRequest::HandshakeWoT { .. } => "handshake_wot",
        MeshWireRequest::PutShard { .. } => "put_shard",
        MeshWireRequest::PorAudit(_) => "por_audit",
        MeshWireRequest::GetCiphertextShard { .. } => "get_ciphertext_shard",
        MeshWireRequest::PutBlindedShard { .. } => "put_blinded_shard",
        MeshWireRequest::GetBlindedShard { .. } => "get_blinded_shard",
        MeshWireRequest::RenewBlindedLease { .. } => "renew_blinded_lease",
        MeshWireRequest::DeleteBlindedShardTombstone { .. } => "delete_blinded_tombstone",
        MeshWireRequest::MultiSegmentPorAudit(_) => "multi_segment_por_audit",
        MeshWireRequest::RelayPqOnionEnvelope { .. } => "relay_pq_onion",
        MeshWireRequest::SyndicateLiteStripe { .. } => "syndicate_lite_stripe",
        MeshWireRequest::PutDhtEnvelope(_) => "dht_envelopes",
        MeshWireRequest::GetDhtEnvelope { .. } => "dht_envelopes",
        MeshWireRequest::DeleteShard { .. } => "delete_shard",
        MeshWireRequest::QueryNodeStatus => "query_node_status",
        MeshWireRequest::RegisterWanRendezvous { .. } => "register_wan_rendezvous",
        MeshWireRequest::LookupWanRendezvous { .. } => "lookup_wan_rendezvous",
        MeshWireRequest::SubmitAbuseTakedownReport(_) => "submit_abuse_takedown",
        MeshWireRequest::BroadcastEvictionOrder(_) => "broadcast_eviction_order",
        MeshWireRequest::AdmitPublicTicket(_) => "admit_public_ticket",
    }
}

#[test]
fn every_variant_has_a_covering_case() {
    assert_eq!(
        covering_case(&MeshWireRequest::QueryNodeStatus),
        "query_node_status"
    );
}

// --- 1. HandshakeWoT (identical) ----------------------------------------------------------------

#[test]
fn handshake_wot() {
    let _g = env_guard();
    let mut t = Trio::new("hs");
    let peer = Peer::new(0x51, "198.51.100.1");
    let hop = InvitationHop::issue(&t.keys.genesis, peer.ident.public_key_bytes(), 1, 100);
    let good = MeshWireRequest::HandshakeWoT {
        chain: DelegationChain { hops: vec![hop] },
        asn: None,
        region: None,
    };
    let o = t.run(&peer, &good);
    assert!(o[0].resp.contains("accepted: true"), "{}", o[0].resp);
    assert_identical(&o);
    let pk0 = peer.ident.public_key_bytes();
    for fx in &t.fx {
        assert!(
            fx.wot.is_private_ring_peer(&pk0),
            "{:?}: leaf admitted",
            fx.role
        );
        assert!(
            fx.admitted_at(peer.ip).contains(&pk0),
            "{:?}: admission IP recorded",
            fx.role
        );
    }

    let rogue = NodeIdentity::from_seed([0x52; 32]);
    let bad_hop = InvitationHop::issue(&rogue, peer.ident.public_key_bytes(), 1, 100);
    let bad = MeshWireRequest::HandshakeWoT {
        chain: DelegationChain {
            hops: vec![bad_hop],
        },
        asn: None,
        region: None,
    };
    let o = t.run(&peer, &bad);
    assert!(o[0].resp.contains("accepted: false"));
    assert_identical(&o);
    let rogue_leaf_peer = Peer::new(0x53, "198.51.100.31");
    let bad_only = MeshWireRequest::HandshakeWoT {
        chain: DelegationChain {
            hops: vec![InvitationHop::issue(
                &rogue,
                rogue_leaf_peer.ident.public_key_bytes(),
                1,
                100,
            )],
        },
        asn: None,
        region: None,
    };
    t.run(&rogue_leaf_peer, &bad_only);
    for fx in &t.fx {
        let k = rogue_leaf_peer.ident.public_key_bytes();
        assert!(
            !fx.wot.is_private_ring_peer(&k),
            "{:?}: bad chain not admitted",
            fx.role
        );
        assert!(
            fx.admitted_at(rogue_leaf_peer.ip).is_empty(),
            "{:?}: no admission IP",
            fx.role
        );
    }

    let pk = peer.ident.public_key_bytes();
    t.each(|fx, k| fx.ban(k, EvictionTarget::PeerOrIssuerPubkey(pk)));
    let o = t.run(&peer, &good);
    // F-28: a blocked peer gets the same fixed text as any other refused handshake.
    assert!(
        o[0].resp.contains("accepted: false") && o[0].resp.contains("handshake refused"),
        "{}",
        o[0].resp
    );
    assert_identical(&o);
    // F-28: the handshake is not a quarantine oracle. A forged hop (rogue inviter) for a
    // quarantined key and for an ordinary key gets the same response on every role.
    let quarantined = Peer::new(0x54, "198.51.100.32");
    let ordinary = Peer::new(0x55, "198.51.100.33");
    let qk = quarantined.ident.public_key_bytes();
    t.each(|fx, _| {
        fx.wot.slash_immediately(qk);
    });
    // The probe names the genesis as inviter but carries a rogue signature.
    let genesis_pk = t.keys.genesis.public_key_bytes();
    let forged = |p: &Peer| {
        let mut hop = InvitationHop::issue(&rogue, p.ident.public_key_bytes(), 1, 100);
        hop.inviter_pubkey = genesis_pk;
        MeshWireRequest::HandshakeWoT {
            chain: DelegationChain { hops: vec![hop] },
            asn: None,
            region: None,
        }
    };
    let oq = t.run(&quarantined, &forged(&quarantined));
    let oo = t.run(&ordinary, &forged(&ordinary));
    assert_eq!(
        oq[0].resp, oo[0].resp,
        "quarantine state must not show on the wire"
    );
    assert!(oq[0].resp.contains("handshake refused"), "{}", oq[0].resp);
    assert_identical(&oq);
}

// --- 2. PutShard (seed also records the admission IP) -------------------------------------------

#[test]
fn put_shard() {
    let _g = env_guard();
    let mut t = Trio::new("put");
    let peer = Peer::new(0x61, "198.51.100.2");
    t.admit(&peer);
    // v0.5.0 owner rule: an empty claim and the sender's own device id both account the shard to
    // the sender's device id.
    let device = peer.ident.device_peer_id();
    for (owner, seed) in [("", 1u8), (device.as_str(), 2u8)] {
        let (sid, bytes) = shard(seed, 2048);
        let before: Vec<u64> = t.fx.iter().map(|f| f.hosted(&device)).collect();
        let o = t.run(&peer, &put_shard_req(owner, sid, bytes, [seed; 32]));
        assert!(o[0].resp.contains("stored: true"), "{}", o[0].resp);
        assert!(o[0].quota_delta > 0);
        // Absolute: the shard is stored and charged to the sender's device id on every role.
        for (fx, before) in t.fx.iter().zip(before) {
            assert!(fx.store.has_shard(&sid), "{:?}: shard stored", fx.role);
            assert_eq!(
                fx.hosted(&device) - before,
                2048,
                "{:?}: quota charged to the sender for claim {owner:?}",
                fx.role
            );
            assert_eq!(
                fx.hosted(&peer.id),
                0,
                "{:?}: nothing under the PeerId",
                fx.role
            );
        }
        // Hook record_put_shard_admission_ip, checked through the eviction API.
        let pk = peer.ident.public_key_bytes();
        assert!(
            !t.fx[0].admitted_at(peer.ip).contains(&pk),
            "daemon records no admission IP"
        );
        assert!(
            t.fx[1].admitted_at(peer.ip).contains(&pk),
            "seed records the admission IP"
        );
        assert!(
            t.fx[2].admitted_at(peer.ip).contains(&pk),
            "seed records the admission IP"
        );
        assert_eq!(o[1], o[2]);
        assert_same_except_eviction(&o[0], &o[1]);
        // Hook record_put_shard_admission_ip: the seed's eviction index records the peer IP.
        assert_ne!(
            o[0].changed
                .iter()
                .filter(|(k, _)| k.contains("eviction"))
                .collect::<Vec<_>>(),
            o[1].changed
                .iter()
                .filter(|(k, _)| k.contains("eviction"))
                .collect::<Vec<_>>(),
            "seed must persist an extra admission record on PutShard"
        );
        assert!(!eviction_files(&o[1].changed).is_empty());
    }
    // A claim naming anyone else is refused identically, with nothing stored or charged.
    let (sid, bytes) = shard(28, 1024);
    let o = t.run(&peer, &put_shard_req("alice-owner", sid, bytes, [28; 32]));
    assert!(
        o[0].resp.contains("owner claim does not match the sender"),
        "{}",
        o[0].resp
    );
    assert_identical(&o);
    for fx in &t.fx {
        assert!(!fx.store.has_shard(&sid));
        assert_eq!(fx.hosted("alice-owner"), 0);
    }
    // Error path: shard hash mismatch.
    let (mut sid, bytes) = shard(3, 1024);
    sid.shard_hash = [0xEE; 32];
    let o = t.run(&peer, &put_shard_req("", sid, bytes, [3; 32]));
    assert!(o[0].resp.contains("stored: false"), "{}", o[0].resp);
    assert_identical(&o);
    assert!(t.fx.iter().all(|f| !f.store.has_shard(&sid)));
    // Ingress-blocked by stripe root.
    let (sid, bytes) = shard(4, 1024);
    t.each(|fx, k| fx.ban(k, EvictionTarget::StripeMerkleRoot(sid.stripe_merkle_root)));
    let o = t.run(&peer, &put_shard_req("", sid, bytes, [4; 32]));
    assert!(
        o[0].resp.contains("stored: false") && o[0].resp.contains("tombstoned_stripe_merkle_root"),
        "{}",
        o[0].resp
    );
    assert_identical(&o);
    assert!(t.fx.iter().all(|f| !f.store.has_shard(&sid)));
    // v0.5.0 admission: a sender without a ring chain is refused identically by every role,
    // with no state change.
    let stranger = Peer::new(0x60, "198.51.100.40");
    let (sid, bytes) = shard(27, 1024);
    let o = t.run(&stranger, &put_shard_req("", sid, bytes, [27; 32]));
    assert!(
        o[0].resp
            .contains("peer not admitted; v0.5.0 requires ring admission"),
        "{}",
        o[0].resp
    );
    assert_identical(&o);
    assert!(o[0].changed.is_empty() && o[0].quota_delta == 0);
}

// --- 3. DeleteShard (identical) -----------------------------------------------------------------

#[test]
fn delete_shard() {
    let _g = env_guard();
    let mut t = Trio::new("del");
    let peer = Peer::new(0x62, "198.51.100.3");
    t.admit(&peer);
    let device = peer.ident.device_peer_id();
    let (sid, bytes) = shard(5, 1024);
    t.run(&peer, &put_shard_req("", sid, bytes, [5; 32]));
    let (pub_, payload, sig) =
        PorVerifierEngine::sign_owner_shard_delete_token(&peer.ident, &sid, now_ms());
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..]);
    let mut bad_payload = payload.clone();
    bad_payload[0] ^= 1;
    let o = t.run(
        &peer,
        &MeshWireRequest::DeleteShard {
            shard_id: sid,
            owner_signature: (pub_, bad_payload, r, s),
        },
    );
    assert!(o[0].resp.contains("unauthorized"), "{}", o[0].resp);
    assert_identical(&o);
    assert!(t
        .fx
        .iter()
        .all(|f| f.store.has_shard(&sid) && f.hosted(&device) == 1024));
    let o = t.run(
        &peer,
        &MeshWireRequest::DeleteShard {
            shard_id: sid,
            owner_signature: (pub_, payload, r, s),
        },
    );
    assert!(o[0].resp.contains("deleted: true"), "{}", o[0].resp);
    assert_identical(&o);
    // Absolute: the shard is gone and its quota is released under the sender's device id.
    for fx in &t.fx {
        assert!(!fx.store.has_shard(&sid), "{:?}: shard deleted", fx.role);
        assert_eq!(fx.hosted(&device), 0, "{:?}: quota released", fx.role);
    }
    // Explicit claim of the sender's own device id: put and delete account to the same key, so
    // the release empties the account (2a pinned a split here: a claim of another owner kept
    // that owner charged after the sender's delete; the v0.5.0 owner rule refuses such claims).
    let (sid2, bytes2) = shard(26, 1024);
    t.run(&peer, &put_shard_req(&device, sid2, bytes2, [26; 32]));
    assert!(t.fx.iter().all(|f| f.hosted(&device) == 1024));
    let (pub2, payload2, sig2) =
        PorVerifierEngine::sign_owner_shard_delete_token(&peer.ident, &sid2, now_ms());
    let mut r2 = [0u8; 32];
    let mut s2 = [0u8; 32];
    r2.copy_from_slice(&sig2[..32]);
    s2.copy_from_slice(&sig2[32..]);
    let o = t.run(
        &peer,
        &MeshWireRequest::DeleteShard {
            shard_id: sid2,
            owner_signature: (pub2, payload2, r2, s2),
        },
    );
    assert!(o[0].resp.contains("deleted: true"), "{}", o[0].resp);
    assert_identical(&o);
    for fx in &t.fx {
        assert!(!fx.store.has_shard(&sid2), "{:?}: shard deleted", fx.role);
        assert_eq!(fx.hosted(&device), 0, "{:?}: released in full", fx.role);
    }
}

// --- 4 / 10. PoR audits (seed records a heartbeat on success) ------------------------------------

#[test]
fn por_audit() {
    let _g = env_guard();
    let mut t = Trio::new("por");
    let peer = Peer::new(0x63, "198.51.100.4");
    t.admit(&peer);
    let (sid, bytes) = shard(6, 4096);
    let session = [0x99; 32];
    t.run(&peer, &put_shard_req("", sid, bytes.clone(), session));
    let chal = generate_por_challenge(&session, sid, bytes.len() as u64, now_ms());
    let o = t.run(&peer, &MeshWireRequest::PorAudit(chal.clone()));
    assert!(o[0].resp.contains("PorAuditResult(Some"), "{}", o[0].resp);
    // Hook on_por_pass: seed counts the pass, daemon does not.
    assert_eq!((o[0].por_delta, o[1].por_delta, o[2].por_delta), (0, 1, 1));
    // Replay: rejected in RAM, no heartbeat anywhere.
    let o = t.run(&peer, &MeshWireRequest::PorAudit(chal));
    assert!(o[0].resp.contains("PorAuditResult(None)"));
    assert_eq!((o[0].por_delta, o[1].por_delta, o[2].por_delta), (0, 0, 0));
}

#[test]
fn multi_segment_por_audit() {
    let _g = env_guard();
    let mut t = Trio::new("mpor");
    let peer = Peer::new(0x64, "198.51.100.5");
    t.admit(&peer);
    let (sid, bytes) = shard(7, 64 * 1024);
    let session = [0x98; 32];
    t.run(&peer, &put_shard_req("", sid, bytes.clone(), session));
    let chal =
        generate_multi_segment_por_challenge(&session, sid, bytes.len() as u64, 8, 5_000, now_ms());
    let o = t.run(&peer, &MeshWireRequest::MultiSegmentPorAudit(chal.clone()));
    assert!(
        o[0].resp.contains("MultiSegmentPorAuditResult(Some"),
        "{}",
        o[0].resp
    );
    assert_eq!((o[0].por_delta, o[1].por_delta, o[2].por_delta), (0, 1, 1));
    let o = t.run(&peer, &MeshWireRequest::MultiSegmentPorAudit(chal));
    assert!(o[0].resp.contains("MultiSegmentPorAuditResult(None)"));
    assert_eq!((o[0].por_delta, o[1].por_delta, o[2].por_delta), (0, 0, 0));
}

// --- 5. GetCiphertextShard (identical) ----------------------------------------------------------

#[test]
fn get_ciphertext_shard() {
    let _g = env_guard();
    let mut t = Trio::new("getct");
    let peer = Peer::new(0x65, "198.51.100.6");
    t.admit(&peer);
    let (sid, bytes) = shard(8, 1024);
    t.run(&peer, &put_shard_req("", sid, bytes, [8; 32]));
    let o = t.run(
        &peer,
        &MeshWireRequest::GetCiphertextShard {
            shard_id: sid,
            owner_signature: None,
            repair_proof: None,
        },
    );
    assert!(o[0].resp.contains("shard_bytes: None"), "{}", o[0].resp);
    assert_identical(&o);
    let (pub_, payload, sig) =
        PorVerifierEngine::sign_owner_shard_read_token(&peer.ident, &sid, now_ms());
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..]);
    let o = t.run(
        &peer,
        &MeshWireRequest::GetCiphertextShard {
            shard_id: sid,
            owner_signature: Some((pub_, payload, r, s)),
            repair_proof: None,
        },
    );
    assert!(
        o[0].resp.contains("shard_bytes: None"),
        "no grant registered: {}",
        o[0].resp
    );
    assert_identical(&o);

    // Owner-signed read of a shard stored with the owner's RepairGrant returns the exact bytes.
    let (sid2, bytes2) = shard(9, 1024);
    let grant = RepairGrant::issue(
        &peer.ident,
        sid2.stripe_merkle_root,
        vec![],
        ErasureTier::Homelab,
    );
    t.run(
        &peer,
        &MeshWireRequest::PutShard {
            owner_peer_id: String::new(),
            shard_id: sid2,
            shard_bytes: bytes2.clone(),
            session_key_commit: [9; 32],
            repair_grant: Some(grant),
        },
    );
    let (pub2, payload2, sig2) =
        PorVerifierEngine::sign_owner_shard_read_token(&peer.ident, &sid2, now_ms());
    let mut r2 = [0u8; 32];
    let mut s2 = [0u8; 32];
    r2.copy_from_slice(&sig2[..32]);
    s2.copy_from_slice(&sig2[32..]);
    let (o, resps) = t.run_resp(
        &peer,
        &MeshWireRequest::GetCiphertextShard {
            shard_id: sid2,
            owner_signature: Some((pub2, payload2, r2, s2)),
            repair_proof: None,
        },
    );
    assert_identical(&o);
    for r in resps {
        match r {
            MeshWireResponse::CiphertextShardResult {
                shard_bytes: Some(b),
                error: None,
            } => assert_eq!(b, bytes2),
            other => panic!("expected the shard bytes, got {other:?}"),
        }
    }
}

// --- 6. PutBlindedShard (seed enforces the probationary lease limit) -----------------------------

#[test]
fn put_blinded_shard() {
    let _g = env_guard();
    let mut t = Trio::new("pb");
    let issuer = t.keys.voucher_issuer.clone();
    let peer = Peer::new(0x66, "198.51.100.7");
    t.admit(&peer);
    let b = blinded(9, 4096);
    let v = AnonymousQuotaVoucher::mint(&issuer, 8192);
    let o = t.run(&peer, &put_blinded(&b, v.clone()));
    assert!(o[0].resp.contains("stored: true"), "{}", o[0].resp);
    assert_identical(&o);
    // Absolute: stored on disk, one lease, and the voucher issuer recorded as admitted from the
    // sender's IP (checked through the eviction API, not file length).
    let issuer_pk = issuer.public_key_bytes();
    assert_eq!(o[0].leases_delta, 1);
    for fx in &t.fx {
        assert!(
            fx.store.has_blinded_shard_on_disk(&b.id),
            "{:?}: stored",
            fx.role
        );
        assert!(
            fx.admitted_at(peer.ip).contains(&issuer_pk),
            "{:?}: issuer admitted at IP",
            fx.role
        );
    }
    // Absolute: a spent voucher cannot be redeemed again (nullifier).
    let b_replay = blinded(24, 1024);
    let o = t.run(&peer, &put_blinded(&b_replay, v));
    assert!(o[0].resp.contains("stored: false"), "{}", o[0].resp);
    assert_identical(&o);
    assert!(t
        .fx
        .iter()
        .all(|f| !f.store.has_blinded_shard_on_disk(&b_replay.id)));

    // Hook max_probationary_lease_bytes, read per request: lowering the limit (as the admin RPC
    // does) makes the seed reject the next PutBlindedShard; the daemon has no limit.
    t.each(|fx, _| fx.max_lease = 1024);
    let b2 = blinded(10, 4096);
    let v2 = AnonymousQuotaVoucher::mint(&issuer, 8192);
    let o = t.run(&peer, &put_blinded(&b2, v2));
    assert!(o[0].resp.contains("stored: true"), "{}", o[0].resp);
    for s in &o[1..] {
        assert!(
            s.resp.contains("exceeds max_probationary_lease_bytes 1024"),
            "{}",
            s.resp
        );
        assert!(s.changed.is_empty() && s.quota_delta == 0);
    }
    // A zero limit disables the check (the seed's `> 0` guard).
    t.each(|fx, _| fx.max_lease = 0);
    let b3 = blinded(11, 4096);
    let o = t.run(
        &peer,
        &put_blinded(&b3, AnonymousQuotaVoucher::mint(&issuer, 8192)),
    );
    assert!(o.iter().all(|x| x.resp.contains("stored: true")), "{o:?}");
    t.each(|fx, _| fx.max_lease = SEED_DEFAULT_LEASE_LIMIT);

    // Ingress-blocked by voucher issuer.
    let issuer_pk = t.keys.voucher_issuer.public_key_bytes();
    t.each(|fx, k| fx.ban(k, EvictionTarget::PeerOrIssuerPubkey(issuer_pk)));
    let b4 = blinded(12, 1024);
    let o = t.run(
        &peer,
        &put_blinded(&b4, AnonymousQuotaVoucher::mint(&issuer, 8192)),
    );
    assert!(o[0].resp.contains("stored: false"));
    assert_identical(&o);
    assert!(t
        .fx
        .iter()
        .all(|f| !f.store.has_blinded_shard_on_disk(&b4.id)));
}

// --- 7. GetBlindedShard (identical) -------------------------------------------------------------

#[test]
fn get_blinded_shard() {
    let _g = env_guard();
    let mut t = Trio::new("gb");
    let issuer = t.keys.voucher_issuer.clone();
    let peer = Peer::new(0x67, "198.51.100.8");
    t.admit(&peer);
    let b = blinded(13, 2048);
    t.run(
        &peer,
        &put_blinded(&b, AnonymousQuotaVoucher::mint(&issuer, 8192)),
    );
    let o = t.run(
        &peer,
        &MeshWireRequest::GetBlindedShard {
            blinded_id: b.id,
            capability: b.cap,
            timestamp_ms: now_ms(),
            read_sig: vec![0; 10],
        },
    );
    assert!(o[0].resp.contains("invalid 64-byte"));
    assert_identical(&o);
    let ts = now_ms();
    let sig = BlindedShardCapability::sign_read_token(&b.cap_ident, &b.id.locator, ts);
    let (o, resps) = t.run_resp(
        &peer,
        &MeshWireRequest::GetBlindedShard {
            blinded_id: b.id,
            capability: b.cap,
            timestamp_ms: ts,
            read_sig: sig.to_vec(),
        },
    );
    assert_identical(&o);
    for r in resps {
        match r {
            MeshWireResponse::BlindedShardResult {
                shard_bytes: Some(bytes),
                error: None,
            } => assert_eq!(bytes, b.bytes),
            other => panic!("expected the blinded shard bytes, got {other:?}"),
        }
    }
}

// --- 8. RenewBlindedLease (same effect via the seed server's shared store) -----------------------

#[test]
fn renew_blinded_lease() {
    let _g = env_guard();
    let mut t = Trio::new("renew");
    let issuer = t.keys.voucher_issuer.clone();
    let peer = Peer::new(0x68, "198.51.100.9");
    t.admit(&peer);
    let b = blinded(14, 2048);
    t.run(
        &peer,
        &put_blinded(&b, AnonymousQuotaVoucher::mint(&issuer, 8192)),
    );
    let req = MeshWireRequest::RenewBlindedLease {
        blinded_id: b.id,
        current_epoch: 2,
        extension_epochs: 10,
    };
    let o = t.run(&peer, &req);
    assert!(o[0].resp.contains("renewed: true"), "{}", o[0].resp);
    assert_identical(&o);
    let unknown = blinded(15, 16);
    let o = t.run(
        &peer,
        &MeshWireRequest::RenewBlindedLease {
            blinded_id: unknown.id,
            current_epoch: 2,
            extension_epochs: 10,
        },
    );
    assert!(o[0].resp.contains("renewed: false"));
    assert_identical(&o);
    let loc = b.id.locator;
    t.each(|fx, k| fx.ban(k, EvictionTarget::BlindedLocator(loc)));
    let o = t.run(&peer, &req);
    assert!(o[0].resp.contains("renewed: false"));
    assert_identical(&o);
    // Absolute (on an unbanned shard): renewal sets the expiry to current + extension
    // (2 + 10 = 12, shortening the original 1 + 30), so with the store's 2-epoch grace the shard
    // survives a sweep at 13 and is removed at 14; without the renewal it would survive until 33.
    let b2 = blinded(25, 1024);
    t.run(
        &peer,
        &put_blinded(&b2, AnonymousQuotaVoucher::mint(&issuer, 8192)),
    );
    let o = t.run(
        &peer,
        &MeshWireRequest::RenewBlindedLease {
            blinded_id: b2.id,
            current_epoch: 2,
            extension_epochs: 10,
        },
    );
    assert!(o[0].resp.contains("renewed: true"), "{}", o[0].resp);
    for fx in &t.fx {
        let _ = fx.store.sweep_expired_blinded_shards(13);
        assert!(
            fx.store.has_blinded_shard_on_disk(&b2.id),
            "{:?}: kept at 13",
            fx.role
        );
        let _ = fx.store.sweep_expired_blinded_shards(14);
        assert!(
            !fx.store.has_blinded_shard_on_disk(&b2.id),
            "{:?}: swept at 14",
            fx.role
        );
    }
}

// --- 9. DeleteBlindedShardTombstone (seed error text carries a prefix) ---------------------------

#[test]
fn delete_blinded_tombstone() {
    let _g = env_guard();
    let mut t = Trio::new("tomb");
    let issuer = t.keys.voucher_issuer.clone();
    let peer = Peer::new(0x69, "198.51.100.10");
    t.admit(&peer);
    let b = blinded(16, 2048);
    t.run(
        &peer,
        &put_blinded(&b, AnonymousQuotaVoucher::mint(&issuer, 8192)),
    );
    // Forged tombstone (wrong verifier): Ok(false) everywhere.
    let forged = BlindedShardTombstone::create(&[0xAB; 32], b.id.locator, [1; 16]);
    let o = t.run(
        &peer,
        &MeshWireRequest::DeleteBlindedShardTombstone {
            blinded_id: b.id,
            tombstone: forged,
        },
    );
    assert!(
        o[0].resp.contains("deleted: false, error: None"),
        "{}",
        o[0].resp
    );
    assert_identical(&o);
    // Storage error: a directory where the .bshard file should be makes remove_file fail.
    let b_err = blinded(23, 512);
    t.run(
        &peer,
        &put_blinded(
            &b_err,
            AnonymousQuotaVoucher::mint(&t.keys.voucher_issuer.clone(), 8192),
        ),
    );
    t.each(|fx, _| {
        let f = fx
            .dir
            .join("shards")
            .join(format!("{}.bshard", b_err.id.file_key()));
        std::fs::remove_file(&f).unwrap();
        std::fs::create_dir(&f).unwrap();
    });
    let tomb_err = BlindedShardTombstone::create(&b_err.delete_verifier, b_err.id.locator, [4; 16]);
    let o = t.run(
        &peer,
        &MeshWireRequest::DeleteBlindedShardTombstone {
            blinded_id: b_err.id,
            tombstone: tomb_err,
        },
    );
    assert!(o[0].resp.contains("deleted: false"), "{}", o[0].resp);
    // Hook tombstone_via_seed_server: identical state, seed error string gains a prefix.
    assert_eq!(o[1], o[2]);
    assert_eq!(o[0].changed, o[1].changed);
    let prefixed = o[0].resp.replace(
        "error: Some(\"",
        "error: Some(\"Seed server storage error: ",
    );
    assert!(o[0].resp.contains("error: Some(\""), "{}", o[0].resp);
    assert_eq!(prefixed, o[1].resp);
    let _ = b.delete_secret;
    let good = BlindedShardTombstone::create(&b.delete_verifier, b.id.locator, [2; 16]);
    let o = t.run(
        &peer,
        &MeshWireRequest::DeleteBlindedShardTombstone {
            blinded_id: b.id,
            tombstone: good,
        },
    );
    assert!(o[0].resp.contains("deleted: true"), "{}", o[0].resp);
    assert_identical(&o);
    assert_eq!(o[0].leases_delta, -1);
    assert!(t
        .fx
        .iter()
        .all(|f| !f.store.has_blinded_shard_on_disk(&b.id)));
}

// --- 11. RelayPqOnionEnvelope (seed enforces the lease limit on final delivery) ------------------

fn relay_req(
    env: PqRelayedShardEnvelope,
    target: Option<String>,
    b: &Blinded,
    v: AnonymousQuotaVoucher,
) -> MeshWireRequest {
    MeshWireRequest::RelayPqOnionEnvelope {
        target_peer_addr: target,
        envelope: env,
        capability: b.cap,
        voucher: v,
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: b.delete_verifier,
    }
}

fn final_bundle(fb: &Blinded, issuer: &NodeIdentity) -> PqOnionFinalBundle {
    PqOnionFinalBundle {
        blinded_id: fb.id,
        shard_bytes: fb.bytes.clone(),
        capability: fb.cap,
        voucher: AnonymousQuotaVoucher::mint(issuer, 8192),
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: fb.delete_verifier,
    }
}

#[test]
fn relay_pq_onion() {
    let _g = env_guard();
    let mut t = Trio::new("onion");
    let issuer = t.keys.voucher_issuer.clone();
    let peer = Peer::new(0x6A, "198.51.100.11");
    t.admit(&peer);
    let our_kem_pub = t.fx[0].kem.public_key();
    let v = || AnonymousQuotaVoucher::mint(&issuer, 8192);

    // (a) Forward branch with no MeshClient.
    let b = blinded(17, 1024);
    let env = PqRelayedShardEnvelope::seal_pq(&our_kem_pub, "relay", &b.id, &b.bytes, 0).unwrap();
    let o = t.run(
        &peer,
        &relay_req(env, Some("/ip4/192.0.2.1/tcp/4001".into()), &b, v()),
    );
    assert!(
        o[0].resp
            .contains("no MeshClient available for onion forwarding"),
        "{}",
        o[0].resp
    );
    assert_identical(&o);

    // (b) 1-hop delivery (open_pq).
    let env = PqRelayedShardEnvelope::seal_pq(&our_kem_pub, "relay", &b.id, &b.bytes, 0).unwrap();
    let o = t.run(&peer, &relay_req(env, None, &b, v()));
    assert!(o[0].resp.contains("delivered: true"), "{}", o[0].resp);
    assert_identical(&o);
    assert!(t
        .fx
        .iter()
        .all(|f| f.store.has_blinded_shard_on_disk(&b.id)));

    // (c) Layered final-target delivery (open_final_target_pq).
    let relay_kem = HybridKemKeypair::generate().unwrap();
    let fb = blinded(19, 256);
    let layered = PqRelayedShardEnvelope::seal_layered_pq(
        &relay_kem.public_key(),
        "relay",
        &our_kem_pub,
        "/ip4/192.0.2.9/tcp/4001",
        &final_bundle(&fb, &issuer),
        0,
        0,
    )
    .unwrap();
    let inner = layered
        .peel_relay_hop_pq(&relay_kem)
        .unwrap()
        .inner_envelope;
    let o = t.run(&peer, &relay_req(inner, None, &fb, v()));
    assert!(o[0].resp.contains("delivered: true"), "{}", o[0].resp);
    assert_identical(&o);
    assert!(t
        .fx
        .iter()
        .all(|f| f.store.has_blinded_shard_on_disk(&fb.id)));

    // (d) We are the relay hop: peeled, then no MeshClient for the second hop.
    let fb = blinded(21, 256);
    let other = HybridKemKeypair::generate().unwrap();
    let layered = PqRelayedShardEnvelope::seal_layered_pq(
        &our_kem_pub,
        "relay",
        &other.public_key(),
        "/ip4/192.0.2.9/tcp/4001",
        &final_bundle(&fb, &issuer),
        0,
        0,
    )
    .unwrap();
    let o = t.run(&peer, &relay_req(layered, None, &fb, v()));
    assert!(
        o[0].resp.contains("2-layer onion forwarding"),
        "{}",
        o[0].resp
    );
    assert_identical(&o);
    assert!(t
        .fx
        .iter()
        .all(|f| !f.store.has_blinded_shard_on_disk(&fb.id)));

    // (e) Undecryptable envelope.
    let env = PqRelayedShardEnvelope::seal_pq(&other.public_key(), "relay", &fb.id, &fb.bytes, 0)
        .unwrap();
    let o = t.run(&peer, &relay_req(env, None, &fb, v()));
    assert!(o[0].resp.contains("delivered: false"));
    assert_identical(&o);
    assert!(t
        .fx
        .iter()
        .all(|f| !f.store.has_blinded_shard_on_disk(&fb.id)));

    // (f) Ingress-blocked remote peer.
    let pk = peer.ident.public_key_bytes();
    t.each(|fx, k| fx.ban(k, EvictionTarget::PeerOrIssuerPubkey(pk)));
    let env = PqRelayedShardEnvelope::seal_pq(&our_kem_pub, "relay", &fb.id, &fb.bytes, 0).unwrap();
    let o = t.run(&peer, &relay_req(env, None, &fb, v()));
    assert!(
        o[0].resp.contains("delivered: false") && o[0].resp.contains("blocked"),
        "{}",
        o[0].resp
    );
    assert_identical(&o);
}

/// Hook max_probationary_lease_bytes on both final-delivery branches (fresh fixtures, so the
/// divergence cannot leak into identical-row comparisons).
#[test]
fn relay_pq_onion_over_seed_lease_limit() {
    let _g = env_guard();
    let peer = Peer::new(0x6B, "198.51.100.21");
    for layered_case in [false, true] {
        let mut t = Trio::new("onion-limit");
        t.admit(&peer);
        let issuer = t.keys.voucher_issuer.clone();
        let our_kem_pub = t.fx[0].kem.public_key();
        t.each(|fx, _| fx.max_lease = 512);
        let fb = blinded(if layered_case { 20 } else { 18 }, 1024);
        let env = if layered_case {
            let relay_kem = HybridKemKeypair::generate().unwrap();
            let layered = PqRelayedShardEnvelope::seal_layered_pq(
                &relay_kem.public_key(),
                "relay",
                &our_kem_pub,
                "/ip4/192.0.2.9/tcp/4001",
                &final_bundle(&fb, &issuer),
                0,
                0,
            )
            .unwrap();
            layered
                .peel_relay_hop_pq(&relay_kem)
                .unwrap()
                .inner_envelope
        } else {
            PqRelayedShardEnvelope::seal_pq(&our_kem_pub, "relay", &fb.id, &fb.bytes, 0).unwrap()
        };
        let o = t.run(
            &peer,
            &relay_req(env, None, &fb, AnonymousQuotaVoucher::mint(&issuer, 8192)),
        );
        assert!(o[0].resp.contains("delivered: true"), "{}", o[0].resp);
        for s in &o[1..] {
            assert!(
                s.resp.contains("exceeds max_probationary_lease_bytes 512"),
                "{}",
                s.resp
            );
            assert!(s.changed.is_empty() && s.quota_delta == 0, "{s:?}");
        }
    }
}

// --- 12. SyndicateLiteStripe (identical code; result depends on the server's mode) ---------------

#[test]
fn syndicate_lite_stripe() {
    let _g = env_guard();
    let mut t = Trio::new("synd");
    let peer = Peer::new(0x6B, "198.51.100.12");
    t.admit(&peer);
    // v0.5.0: a cert authorises only the device it names, so the sender is that device.
    let laptop = peer.ident.clone();
    let cert = PersonalDeviceCert::issue(
        &t.keys.owner_pq,
        &laptop.device_peer_id(),
        "laptop",
        1_700_000_000,
    )
    .unwrap();
    let ct = vec![0x3C; 32 * 1024];
    let set = encode_ciphertext_stripe(0, &ct, ErasureTier::Homelab).unwrap();
    let bundle = LiteStripeSyndicationBundle {
        stripe_index: 0,
        tier: ErasureTier::Homelab,
        ciphertext_bytes: ct,
        expected_stripe_merkle_root: set.stripe_merkle_root,
        expected_shard_hashes: set.shard_hashes.clone(),
    };
    let req = MeshWireRequest::SyndicateLiteStripe {
        cert,
        bundle,
        repair_grant: None,
    };
    let o = t.run(&peer, &req);
    assert!(o[0].resp.contains("receipt: Some"), "{}", o[0].resp);
    assert_eq!(o[0], o[1], "daemon and seed homelab vault behave the same");
    // Absolute: all 20 Reed-Solomon shards are stored on the homelab-vault roles, none on the
    // public bootstrapper.
    let shard_ids: Vec<ShardId> = (0..set.shard_hashes.len())
        .map(|i| ShardId {
            stripe_merkle_root: set.stripe_merkle_root,
            shard_index: i as u32,
            shard_hash: set.shard_hashes[i],
        })
        .collect();
    assert_eq!(shard_ids.len(), 20);
    for (fx, expect) in t.fx.iter().zip([true, true, false]) {
        assert!(
            shard_ids.iter().all(|id| fx.store.has_shard(id) == expect),
            "{:?}: shards stored = {expect}",
            fx.role
        );
    }
    assert!(
        o[2].resp.contains("receipt: None"),
        "public bootstrapper has no owner: {}",
        o[2].resp
    );
    let root = set.stripe_merkle_root;
    t.each(|fx, k| fx.ban(k, EvictionTarget::StripeMerkleRoot(root)));
    let o = t.run(&peer, &req);
    assert!(
        o[0].resp.contains("tombstoned_stripe_merkle_root"),
        "{}",
        o[0].resp
    );
    assert_identical(&o);
}

// --- 13 / 14. DHT envelopes (identical) ---------------------------------------------------------

#[test]
fn dht_envelopes() {
    let _g = env_guard();
    let mut t = Trio::new("dht");
    let peer = Peer::new(0x6D, "198.51.100.13");
    t.admit(&peer);
    let owner = NodeIdentity::from_seed([0x6E; 32]);
    let mk = MasterKey::from_bytes([0x6F; 32]);
    let manifest = FileManifest {
        version: 1,
        file_merkle_root: [0x11; 32],
        file_salt: [0x22; 32],
        original_file_size: 1024,
        stripe_size_bytes: 16 * 1024 * 1024,
        tier: ErasureTier::Homelab,
        stripes: vec![StripeManifestEntry {
            stripe_index: 0,
            k_data: 16,
            m_parity: 4,
            original_ciphertext_len: 1040,
            shard_len: 65,
            stripe_merkle_root: [0x33; 32],
            shard_hashes: vec![[0x44; 32]; 20],
            assigned_peers: vec!["peer".to_string(); 20],
        }],
        witness_peers: vec!["w1".to_string()],
    };
    let env = SignedDhtManifestEnvelope::seal(&mk, &owner, &manifest, 1, 1_700_000_000).unwrap();
    let key = env.dht_key;
    let o = t.run(
        &peer,
        &MeshWireRequest::PutDhtEnvelope(DhtWireEnvelope::ClassicalManifest(env)),
    );
    assert!(o[0].resp.contains("stored: true"), "{}", o[0].resp);
    assert_identical(&o);
    for fx in &t.fx {
        let stored = fx
            .store
            .get_dht_manifest_envelope(&key)
            .expect("stored envelope");
        assert_eq!(
            (stored.owner_pubkey, stored.monotonic_version),
            (owner.public_key_bytes(), 1)
        );
    }
    let o = t.run(
        &peer,
        &MeshWireRequest::GetDhtEnvelope {
            dht_key: key,
            kind: DhtEnvelopeKind::ClassicalManifest,
        },
    );
    assert!(o[0].resp.contains("envelope: Some"), "{}", o[0].resp);
    assert_identical(&o);
    for kind in [
        DhtEnvelopeKind::ClassicalManifest,
        DhtEnvelopeKind::PostQuantumManifest,
        DhtEnvelopeKind::VaultCatalog,
    ] {
        let o = t.run(
            &peer,
            &MeshWireRequest::GetDhtEnvelope {
                dht_key: [0xEE; 32],
                kind,
            },
        );
        assert!(o[0].resp.contains("DHT envelope not found"));
        assert_identical(&o);
    }
}

// --- 15. QueryNodeStatus (region string differs) -------------------------------------------------

#[test]
fn query_node_status() {
    let _g = env_guard();
    let mut t = Trio::new("status");
    let peer = Peer::new(0x70, "198.51.100.14");
    let (o, resps) = t.run_resp(&peer, &MeshWireRequest::QueryNodeStatus);
    // Absolute fields on every role.
    for (fx, r) in t.fx.iter().zip(resps) {
        match r {
            MeshWireResponse::NodeStatusResult {
                peer_id,
                asn,
                pq_kem_pubkey,
                ..
            } => {
                assert_eq!((peer_id.as_str(), asn), ("server-peer", 64512));
                assert_eq!(
                    format!("{:?}", pq_kem_pubkey),
                    format!("{:?}", Some(fx.kem.public_key()))
                );
            }
            other => panic!("expected NodeStatusResult, got {other:?}"),
        }
    }
    // Hook status_region.
    assert!(
        o[0].resp.contains("region: \"local-neighborhood\""),
        "{}",
        o[0].resp
    );
    assert!(
        o[1].resp.contains("region: \"seed-anchor\""),
        "{}",
        o[1].resp
    );
    assert_eq!(
        o[0].resp.replace("local-neighborhood", "seed-anchor"),
        o[1].resp
    );
    assert_eq!(o[0].changed, o[1].changed);
    assert!(o[2].resp.contains("region: \"seed-anchor\""));
}

// --- 16. RegisterWanRendezvous (tracker key and public-card IPs differ) -------------------------

#[test]
fn register_wan_rendezvous() {
    let _g = env_guard();
    let mut t = Trio::new("reg");
    let peer = Peer::new(0x71, "198.51.100.15");
    let admin = hex::encode(t.keys.admin.public_key_bytes());
    let admin_bytes: Vec<String> = t
        .keys
        .admin
        .public_key_bytes()
        .iter()
        .map(|b| b.to_string())
        .collect();
    let admin_dbg = format!("Some([{}])", admin_bytes.join(", "));
    let _ = admin;

    // Private slot.
    let code = "apple-banana-cherry-delta";
    let entry = seal_wan_peer_card(
        code,
        &wan_card(&peer.ident, &["/ip4/203.0.113.5/tcp/4001"]),
        &peer.ident,
    )
    .unwrap();
    let slot = derive_slot_key_from_code(code);
    let o = t.run(
        &peer,
        &MeshWireRequest::RegisterWanRendezvous {
            slot_key: slot,
            entry: entry.clone(),
        },
    );
    assert!(o[0].resp.contains("stored: true"), "{}", o[0].resp);
    // Hook tracker_admin_pubkey: only a public bootstrapper advertises its tracker admin key.
    assert!(o[0].resp.contains("tracker_admin_pubkey: None"));
    assert_eq!(o[0], o[1]);
    assert_eq!(
        o[2].resp,
        o[0].resp.replace(
            "tracker_admin_pubkey: None",
            &format!("tracker_admin_pubkey: {admin_dbg}")
        )
    );
    assert_eq!(o[2].changed, o[0].changed);
    // Absolute: the entry is retrievable and the signer is admitted at the sender's IP.
    let pk_priv = peer.ident.public_key_bytes();
    for fx in &mut t.fx {
        assert_eq!(
            fx.wan.lookup(&slot, now_ms()).len(),
            1,
            "{:?}: entry stored",
            fx.role
        );
        assert!(
            fx.admitted_at(peer.ip).contains(&pk_priv),
            "{:?}: signer admitted",
            fx.role
        );
    }

    // Slot mismatch -> registry error.
    let o = t.run(
        &peer,
        &MeshWireRequest::RegisterWanRendezvous {
            slot_key: [0x01; 32],
            entry,
        },
    );
    assert!(o[0].resp.contains("stored: false"), "{}", o[0].resp);
    assert_eq!(o[0], o[1]);

    // Public commons slot with advertised IPs: the seed records each card IP as an admission IP.
    let pub_peer = Peer::new(0x72, "198.51.100.16");
    let entry = seal_public_tracker_card(
        &wan_card(
            &pub_peer.ident,
            &["/ip4/203.0.113.77/tcp/4001", "/ip4/203.0.113.78/tcp/4001"],
        ),
        &pub_peer.ident,
    )
    .unwrap();
    let o = t.run(
        &pub_peer,
        &MeshWireRequest::RegisterWanRendezvous {
            slot_key: PUBLIC_COMMONS_SWARM_SLOT,
            entry,
        },
    );
    assert!(o[0].resp.contains("stored: true"), "{}", o[0].resp);
    // Hook record_public_card_ips: seed eviction state differs from the daemon's.
    assert_ne!(
        o[0].changed
            .iter()
            .filter(|(k, _)| k.contains("eviction"))
            .collect::<Vec<_>>(),
        o[1].changed
            .iter()
            .filter(|(k, _)| k.contains("eviction"))
            .collect::<Vec<_>>()
    );
    assert_same_except_eviction(&o[0], &o[1]);
    assert_eq!(o[1].changed, o[2].changed);
    // Absolute (through the eviction API): every role records the sender's IP; only the seed
    // roles also record the IPs advertised in the card.
    let pk_pub = pub_peer.ident.public_key_bytes();
    let card_ip: std::net::IpAddr = "203.0.113.77".parse().unwrap();
    for (fx, seed) in t.fx.iter().zip([false, true, true]) {
        assert!(
            fx.admitted_at(pub_peer.ip).contains(&pk_pub),
            "{:?}: sender IP",
            fx.role
        );
        assert_eq!(
            fx.admitted_at(card_ip).contains(&pk_pub),
            seed,
            "{:?}: card IP",
            fx.role
        );
    }

    // Ingress-blocked signer.
    let pk = peer.ident.public_key_bytes();
    t.each(|fx, k| fx.ban(k, EvictionTarget::PeerOrIssuerPubkey(pk)));
    let entry = seal_wan_peer_card(code, &wan_card(&peer.ident, &[]), &peer.ident).unwrap();
    let o = t.run(
        &peer,
        &MeshWireRequest::RegisterWanRendezvous {
            slot_key: slot,
            entry,
        },
    );
    assert!(
        o[0].resp.contains("stored: false") && o[0].resp.contains("blocked"),
        "{}",
        o[0].resp
    );
    assert_eq!(o[0], o[1]);
    assert!(o[2].resp.contains(&admin_dbg));
}

// --- 17. LookupWanRendezvous (tracker key differs) ----------------------------------------------

#[test]
fn lookup_wan_rendezvous() {
    let _g = env_guard();
    let mut t = Trio::new("lookup");
    let peer = Peer::new(0x73, "198.51.100.17");
    let admin_bytes: Vec<String> = t
        .keys
        .admin
        .public_key_bytes()
        .iter()
        .map(|b| b.to_string())
        .collect();
    let admin_dbg = format!("Some([{}])", admin_bytes.join(", "));
    for slot in [
        PUBLIC_COMMONS_SWARM_SLOT,
        derive_slot_key_from_code("x-y-z-w"),
    ] {
        let o = t.run(
            &peer,
            &MeshWireRequest::LookupWanRendezvous { slot_key: slot },
        );
        assert!(
            o[0].resp.contains("tracker_admin_pubkey: None"),
            "{}",
            o[0].resp
        );
        assert!(o[0].resp.contains("entries: []"), "{}", o[0].resp);
        assert_eq!(o[0], o[1]);
        assert_eq!(
            o[2].resp,
            o[0].resp.replace(
                "tracker_admin_pubkey: None",
                &format!("tracker_admin_pubkey: {admin_dbg}")
            )
        );
    }
    // Absolute: a registered entry is returned by lookup on every role.
    let code = "lookup-alpha-bravo-charlie";
    let entry = seal_wan_peer_card(code, &wan_card(&peer.ident, &[]), &peer.ident).unwrap();
    let slot = derive_slot_key_from_code(code);
    t.run(
        &peer,
        &MeshWireRequest::RegisterWanRendezvous {
            slot_key: slot,
            entry: entry.clone(),
        },
    );
    let (_, resps) = t.run_resp(
        &peer,
        &MeshWireRequest::LookupWanRendezvous { slot_key: slot },
    );
    for r in resps {
        match r {
            MeshWireResponse::LookupWanRendezvousResult { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].ed25519_pubkey, entry.ed25519_pubkey);
            }
            other => panic!("expected LookupWanRendezvousResult, got {other:?}"),
        }
    }
}

// --- 18. SubmitAbuseTakedownReport (homelab seed refuses) ---------------------------------------

#[test]
fn submit_abuse_takedown() {
    let _g = env_guard();
    let mut t = Trio::new("abuse");
    let peer = Peer::new(0x74, "198.51.100.18");
    let manifest = FileManifest {
        version: 1,
        file_merkle_root: [0x11; 32],
        file_salt: [0x22; 32],
        original_file_size: 16,
        stripe_size_bytes: 1024 * 1024,
        tier: ErasureTier::Homelab,
        stripes: vec![],
        witness_peers: vec![],
    };
    let report = VerifiableAbuseReport::submit_signed(
        &peer.ident,
        "r@example.org",
        "test",
        None,
        manifest,
        MasterKey::generate().to_hex(),
        0,
        vec![],
        now_ms(),
    );
    let o = t.run(&peer, &MeshWireRequest::SubmitAbuseTakedownReport(report));
    assert!(
        o[0].resp.contains("queued_for_admin_review: false"),
        "{}",
        o[0].resp
    );
    // Hook takedown_gate: daemon and public seed reach the queue; homelab seed refuses first.
    assert_eq!(o[0], o[2]);
    assert!(
        o[1].resp
            .contains("abuse takedown queue disabled in homelab-vault private mode"),
        "{}",
        o[1].resp
    );
    assert!(!o[0].resp.contains("homelab-vault private mode"));
    // Absolute: an unverifiable report is never queued, on any role.
    assert!(t.fx.iter().all(|f| f.takedown.list_entries().is_empty()));
}

// --- 19. BroadcastEvictionOrder (council sources differ) ----------------------------------------

fn accepted(o: &Outcome) -> bool {
    o.resp.contains("accepted: true")
}

#[test]
fn broadcast_eviction_order() {
    let _g = env_guard();
    let peer = Peer::new(0x75, "198.51.100.19");
    let target = || EvictionTarget::IpAddress("192.0.2.200".parse().unwrap());

    // Local owner (the node's own key) is accepted by every role.
    let mut t = Trio::new("evict-local");
    let order =
        SignedBadActorEvictionOrder::issue(&t.keys.node, target(), "local-owner", now_ms(), 0);
    let o = t.run(
        &peer,
        &MeshWireRequest::BroadcastEvictionOrder(order.clone()),
    );
    assert!(o.iter().all(accepted), "{o:?}");
    assert_identical(&o);
    // Absolute: the accepted order blocks the target IP.
    let target_ip: std::net::IpAddr = "192.0.2.200".parse().unwrap();
    assert!(
        t.fx.iter().all(|f| f.blocked(target_ip)),
        "IP blocked after the order"
    );
    // Replay is rejected everywhere.
    let o = t.run(&peer, &MeshWireRequest::BroadcastEvictionOrder(order));
    assert!(!o.iter().any(accepted));
    assert_identical(&o);

    // Tracker admin key: only the public seed trusts its local tracker admin.
    let mut t = Trio::new("evict-admin");
    let order =
        SignedBadActorEvictionOrder::issue(&t.keys.admin, target(), "tracker-admin", now_ms(), 0);
    let o = t.run(&peer, &MeshWireRequest::BroadcastEvictionOrder(order));
    assert_eq!(
        o.iter().map(accepted).collect::<Vec<_>>(),
        vec![false, false, true],
        "{o:?}"
    );
    let target_ip: std::net::IpAddr = "192.0.2.200".parse().unwrap();
    assert_eq!(
        t.fx.iter()
            .map(|f| f.blocked(target_ip))
            .collect::<Vec<_>>(),
        vec![false, false, true],
        "only an accepted order blocks"
    );

    // Genesis key: trusted by the homelab seed (and by the daemon's own council resolver).
    let mut t = Trio::new("evict-genesis");
    let order =
        SignedBadActorEvictionOrder::issue(&t.keys.genesis, target(), "genesis", now_ms(), 0);
    let o = t.run(&peer, &MeshWireRequest::BroadcastEvictionOrder(order));
    let genesis_pattern: Vec<bool> = o.iter().map(accepted).collect();
    assert!(genesis_pattern[1], "homelab seed trusts genesis: {o:?}");
    assert!(
        !genesis_pattern[2],
        "public seed does not trust genesis: {o:?}"
    );
    let daemon_trusts_genesis = genesis_pattern[0];

    // Authority from the environment (read per request by both resolvers).
    let env_auth = NodeIdentity::from_seed([0x76; 32]);
    let mut t = Trio::new("evict-env");
    std::env::set_var(
        "PARVAULT_EVICTION_AUTHORITIES",
        hex::encode(env_auth.public_key_bytes()),
    );
    std::env::set_var("PARVAULT_TRACKER_EVICTION_QUORUM", "1");
    let order = SignedBadActorEvictionOrder::issue(&env_auth, target(), "env", now_ms(), 0);
    let o = t.run(&peer, &MeshWireRequest::BroadcastEvictionOrder(order));
    for v in ENV_VARS {
        std::env::remove_var(v);
    }
    let env_pattern: Vec<bool> = o.iter().map(accepted).collect();

    // Pinned tracker admin in known_peers.json: the public daemon trusts it alone; the public seed
    // adds it to its local admin (council of 2, default quorum 2), so one signature is not enough.
    let pinned = NodeIdentity::from_seed([0x77; 32]);
    let mut t = Trio::new("evict-pinned");
    t.each(|fx, _| {
        let mut kp = KnownPeersStore::load(&fx.dir);
        kp.pin_tracker_admin_pubkey("tracker.example:4001", pinned.public_key_bytes());
        kp.save(&fx.dir).unwrap();
    });
    let order = SignedBadActorEvictionOrder::issue(&pinned, target(), "pinned", now_ms(), 0);
    let o = t.run(
        &peer,
        &MeshWireRequest::BroadcastEvictionOrder(order.clone()),
    );
    let pinned_private: Vec<bool> = o.iter().map(accepted).collect();
    t.each(|fx, _| fx.public_mode = true);
    let o2 = t.run(&peer, &MeshWireRequest::BroadcastEvictionOrder(order));
    let daemon_public_pinned = accepted(&o2[0]);

    // pinned_tracker_admins.json: read only by the daemon resolver, and only in public mode.
    let file_admin = NodeIdentity::from_seed([0x79; 32]);
    let mut t = Trio::new("evict-pinned-file");
    t.each(|fx, _| {
        let list = vec![hex::encode(file_admin.public_key_bytes())];
        std::fs::write(
            fx.dir.join("pinned_tracker_admins.json"),
            serde_json::to_string(&list).unwrap(),
        )
        .unwrap();
        fx.public_mode = true;
    });
    let order =
        SignedBadActorEvictionOrder::issue(&file_admin, target(), "pinned-file", now_ms(), 0);
    let o = t.run(&peer, &MeshWireRequest::BroadcastEvictionOrder(order));
    let pinned_file: Vec<bool> = o.iter().map(accepted).collect();

    // Pinned characterisation of today's council resolution, per role
    // (hook eviction_council): [daemon, seed homelab, seed public].
    assert_eq!(
        (
            daemon_trusts_genesis,
            env_pattern,
            pinned_private,
            daemon_public_pinned,
            pinned_file
        ),
        (
            DAEMON_TRUSTS_GENESIS,
            vec![true, true, true],
            vec![false, false, false],
            true,
            vec![true, false, false]
        ),
        "council resolution changed"
    );
}

/// Today's daemon resolver trusts the genesis key in private mode.
const DAEMON_TRUSTS_GENESIS: bool = true;

// --- the seed's shared-store assumption --------------------------------------------------------

/// `run_seed_listener_loop` gives the handler `&block_store` and a `ZeroTrustSeedServer` built from
/// `block_store.clone()`. Rows 8 and 9 rely on both acting on the same store.
#[test]
fn seed_server_shares_the_handler_store() {
    let root = unique_dir("shared");
    let dir = root.path().to_path_buf();
    let store =
        BlockStore::new(&dir, QuotaManager::new(64 * 1024 * 1024, 8 * 1024 * 1024)).unwrap();
    let owner = HybridPqSigningKeypair::generate().unwrap();
    let mut server =
        ZeroTrustSeedServer::new_homelab_vault("s", store.clone(), owner.public_key(), 2);
    let issuer = NodeIdentity::from_seed([0x78; 32]);
    let mut ledger = VoucherNullifierLedger::new(issuer.public_key_bytes());
    let b = blinded(22, 2048);
    let v = AnonymousQuotaVoucher::mint(&issuer, 8192);
    store
        .put_blinded_shard_with_lease(
            &b.id,
            &b.bytes,
            b.cap,
            &v,
            &mut ledger,
            parvault::storage::BlindedLeaseSpec::new(1, 5, b.delete_verifier),
        )
        .unwrap();
    assert!(
        server.renew_blinded_lease(&b.id, 2, 10),
        "server must see the handler store's lease"
    );
    assert_eq!(server.status_report(1).active_blinded_leases, 1);
    let tomb = BlindedShardTombstone::create(&b.delete_verifier, b.id.locator, [3; 16]);
    assert!(server.execute_blinded_tombstone(&b.id, &tomb).unwrap());
    assert!(
        !store.renew_blinded_shard_lease(&b.id, 3, 1),
        "deletion via the server is visible in the store"
    );
}

// --- 20. AdmitPublicTicket (appended in v0.5.0; identical) ---------------------------------------

#[test]
fn admit_public_ticket() {
    let _g = env_guard();
    let mut t = Trio::new("ticket");
    let peer = Peer::new(0x77, "198.51.100.22");
    let ticket = PublicCommonsTicket::mint(&peer.ident, now_ms(), DEFAULT_PUBLIC_WOT_POW_BITS);
    // Private ring (the fixtures' mode): refused by every role, no state change.
    let o = t.run(&peer, &MeshWireRequest::AdmitPublicTicket(ticket.clone()));
    assert!(o[0].resp.contains("admitted: false"), "{}", o[0].resp);
    assert_identical(&o);
    assert!(o[0].changed.is_empty());
    // Public commons: admitted by every role.
    t.each(|fx, _| {
        fx.wot
            .set_trust_pool_mode(TrustPoolMode::PublicCommons, DEFAULT_PUBLIC_WOT_POW_BITS)
    });
    let o = t.run(&peer, &MeshWireRequest::AdmitPublicTicket(ticket));
    assert!(o[0].resp.contains("admitted: true"), "{}", o[0].resp);
    assert_identical(&o);
    let pk = peer.ident.public_key_bytes();
    for fx in &t.fx {
        assert!(
            fx.wot.is_public_commons_peer(&pk),
            "{:?}: admitted",
            fx.role
        );
        assert!(
            fx.admitted_at(peer.ip).contains(&pk),
            "{:?}: admission IP",
            fx.role
        );
    }
    // A ticket for another key is refused even in public commons.
    let other = Peer::new(0x78, "198.51.100.23");
    let foreign = PublicCommonsTicket::mint(&peer.ident, now_ms(), DEFAULT_PUBLIC_WOT_POW_BITS);
    let o = t.run(&other, &MeshWireRequest::AdmitPublicTicket(foreign));
    assert!(o[0].resp.contains("admitted: false"), "{}", o[0].resp);
    assert_identical(&o);
}
