//! Trust-layer enforcement against the real binaries (`parvault`, `parvault-seed`).
//!
//! Item 2b, step 2: every test here REPRODUCES a finding from `docs/security/TRUST_FINDINGS.md`
//! by asserting today's gap over the wire. Each fix rewrites its reproduction into a differential
//! pair (accept and reject differ in one credential; the reject asserts the reason code in the
//! binary's log) and deletes the finding's `open` line in `.enforcement.map`.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.

use libp2p::futures::StreamExt;
use libp2p::{gossipsub, kad, swarm::SwarmEvent, Multiaddr, PeerId};
use parvault::bootstrap::{LiteStripeSyndicationBundle, PersonalDeviceCert};
use parvault::config::ErasureTier;
use parvault::crypto::pqc::HybridPqSigningKeypair;
use parvault::crypto::{
    HybridKemKeypair, MasterKey, NodeIdentity, PqRelayedShardEnvelope, PqVaultMasterKey,
};
use parvault::network::admission::AdmissionSource;
use parvault::network::{
    build_mesh_client_swarm, derive_slot_key_from_code, node_identity_libp2p_peer_id,
    seal_wan_peer_card, DelegationChain, DhtWireEnvelope, InvitationHop, MeshClient,
    MeshNetworkBehaviour, MeshWireRequest, MeshWireResponse, PublicCommonsTicket, SlashingEvidence,
    SlashingReason, WanPeerCard, DEFAULT_PUBLIC_WOT_POW_BITS,
};
use parvault::por::{RepairGrant, WitnessFailureReceipt};
use parvault::sharding::encode_ciphertext_stripe;
use parvault::storage::{AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, ShardId};
use parvault::sync::{EncryptedVaultCatalogEnvelope, FolderSnapshotManifest};
use sha2::{Digest, Sha256};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

// --- Harness --------------------------------------------------------------------------------------

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

fn temp_root(label: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("pv-trust-{label}-"))
        .tempdir()
        .expect("temp root")
}

/// Ports handed out in this process; parallel tests never get the same one.
static USED_PORTS: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());

fn free_port() -> u16 {
    let mut used = USED_PORTS.lock().unwrap();
    loop {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if !used.contains(&port) {
            used.push(port);
            return port;
        }
    }
}

fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("no listener on 127.0.0.1:{port}");
}

/// The ring genesis every node in a test is provisioned with (`PARVAULT_GENESIS_SEED_HEX`).
const GENESIS_SEED: [u8; 32] = [0x47; 32];

fn genesis() -> NodeIdentity {
    NodeIdentity::from_seed(GENESIS_SEED)
}

/// A spawned binary with its data directory and captured log; killed on drop.
struct Node {
    child: Child,
    dir: PathBuf,
    log: PathBuf,
    addr: String,
    _root: TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
    fn identity(&self) -> NodeIdentity {
        NodeIdentity::load_or_generate_in_dir(&self.dir).unwrap()
    }
    fn peer_id(&self) -> PeerId {
        node_identity_libp2p_peer_id(&self.identity()).unwrap()
    }
    fn kem_public(&self) -> parvault::crypto::HybridKemPublicKey {
        HybridKemKeypair::load_or_generate_in_dir(&self.dir)
            .unwrap()
            .public_key()
    }
    fn owner_pq(&self) -> HybridPqSigningKeypair {
        HybridPqSigningKeypair::load_or_generate_in_dir(&self.dir).unwrap()
    }
}

fn prepare(label: &str) -> (TempDir, PathBuf, PathBuf, PathBuf) {
    let root = temp_root(label);
    let dir = root.path().join("data");
    let reg = root.path().join("lan-registry");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&reg).unwrap();
    // Pre-create the keys the binary loads, so the test knows its identity and KEM key.
    NodeIdentity::load_or_generate_in_dir(&dir).unwrap();
    HybridKemKeypair::load_or_generate_in_dir(&dir).unwrap();
    HybridPqSigningKeypair::load_or_generate_in_dir(&dir).unwrap();
    let log = root.path().join("node.log");
    (root, dir, reg, log)
}

fn spawn(mut cmd: Command, root: TempDir, dir: PathBuf, log: PathBuf, port: u16) -> Node {
    let log_file = std::fs::File::create(&log).unwrap();
    let child = cmd
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .stdout(Stdio::from(log_file.try_clone().unwrap()))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("spawn binary");
    let mut node = Node {
        child,
        dir,
        log,
        addr: format!("/ip4/127.0.0.1/tcp/{port}"),
        _root: root,
    };
    // Ready when the binary itself reports listening on its address (an open port alone may
    // belong to another process).
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let log = node.log_text();
        if log.contains("istening on") && log.contains(&node.addr) {
            break;
        }
        if let Ok(Some(status)) = node.child.try_wait() {
            panic!("binary exited ({status}) before listening:\n{log}");
        }
        assert!(
            Instant::now() < deadline,
            "binary not listening on {}:\n{log}",
            node.addr
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    wait_for_port(port);
    node
}

/// `parvault daemon start` on loopback with LAN discovery off, provisioned with the ring genesis.
fn spawn_daemon(label: &str) -> Node {
    let (root, dir, reg, log) = prepare(label);
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "daemon",
            "start",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{port}"),
        ]);
    spawn(cmd, root, dir, log, port)
}

/// `parvault --public daemon start`: public-commons mode (tickets admit strangers).
fn spawn_public_daemon(label: &str) -> Node {
    let (root, dir, reg, log) = prepare(label);
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "daemon",
            "start",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{port}"),
        ]);
    spawn(cmd, root, dir, log, port)
}

/// `parvault-seed start --mode homelab-vault` on loopback, provisioned with the ring genesis. Its
/// owner key is the PQ keypair in its data directory (pre-created by `prepare`).
fn spawn_seed(label: &str) -> Node {
    spawn_seed_with_peers(label, &[])
}

/// `spawn_seed` with `--peers` (the mesh peers it syndicates to).
fn spawn_seed_with_peers(label: &str, peers: &[&str]) -> Node {
    let (root, dir, reg, log) = prepare(label);
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault-seed"));
    if !peers.is_empty() {
        cmd.arg("--peers").arg(peers.join(","));
    }
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .args([
            "start",
            "--mode",
            "homelab-vault",
            "--no-lan-discovery",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{port}"),
            "--data-dir",
        ])
        .arg(&dir);
    spawn(cmd, root, dir, log, port)
}

/// An in-process wire client speaking as `ident`, a ring member: it self-issues its chain from
/// the ring genesis and handshakes before requests that need an admitted sender.
fn client(ident: &NodeIdentity) -> MeshClient {
    MeshClient::new(ident.clone(), Vec::new(), None)
        .with_admission(AdmissionSource::from_genesis(genesis()))
}

/// A client with no admission credential (a stranger to the ring).
fn stranger_client(ident: &NodeIdentity) -> MeshClient {
    MeshClient::new(ident.clone(), Vec::new(), None).with_admission(AdmissionSource::default())
}

fn send(ident: &NodeIdentity, node: &Node, req: MeshWireRequest) -> MeshWireResponse {
    send_with(client(ident), node, req)
}

fn send_as_stranger(ident: &NodeIdentity, node: &Node, req: MeshWireRequest) -> MeshWireResponse {
    send_with(stranger_client(ident), node, req)
}

/// Waits until the node's log contains `code` (the reason code of a refusal).
fn assert_logged(node: &Node, code: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if node.log_text().contains(code) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{code} not in the node log:\n{}", node.log_text());
}

/// The refusal text a sender that is not admitted receives.
const NOT_ADMITTED: &str = "peer not admitted; v0.5.0 requires ring admission";

fn refusal_text(resp: &MeshWireResponse) -> Option<String> {
    match resp {
        MeshWireResponse::PutShardAck {
            stored: false,
            error,
        }
        | MeshWireResponse::PutBlindedShardAck {
            stored: false,
            error,
        }
        | MeshWireResponse::RelayPqOnionAck {
            delivered: false,
            error,
        }
        | MeshWireResponse::PutDhtEnvelopeAck {
            stored: false,
            error,
        }
        | MeshWireResponse::SyndicateLiteStripeAck {
            receipt: None,
            error,
            ..
        } => error.clone(),
        _ => None,
    }
}

fn send_with(c: MeshClient, node: &Node, req: MeshWireRequest) -> MeshWireResponse {
    match c.send_request(&node.addr, req) {
        Ok(resp) => resp,
        Err(e) => panic!(
            "wire request to {}: {e}\nnode log:\n{}",
            node.addr,
            node.log_text()
        ),
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

fn put_shard(
    owner: &str,
    sid: ShardId,
    bytes: Vec<u8>,
    grant: Option<RepairGrant>,
) -> MeshWireRequest {
    MeshWireRequest::PutShard {
        owner_peer_id: owner.to_string(),
        shard_id: sid,
        shard_bytes: bytes,
        session_key_commit: [0x5E; 32],
        repair_grant: grant,
    }
}

fn stored(resp: &MeshWireResponse) -> bool {
    matches!(resp, MeshWireResponse::PutShardAck { stored: true, .. })
}

fn owner_read(owner: &NodeIdentity, sid: ShardId) -> MeshWireRequest {
    let (pub_, payload, sig) =
        parvault::por::PorVerifierEngine::sign_owner_shard_read_token(owner, &sid, now_ms());
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..]);
    MeshWireRequest::GetCiphertextShard {
        shard_id: sid,
        owner_signature: Some((pub_, payload, r, s)),
        repair_proof: None,
    }
}

fn read_bytes(resp: &MeshWireResponse) -> Option<Vec<u8>> {
    match resp {
        MeshWireResponse::CiphertextShardResult { shard_bytes, .. } => shard_bytes.clone(),
        other => panic!("unexpected response {other:?}"),
    }
}

fn chain_for(leaf: &NodeIdentity) -> DelegationChain {
    DelegationChain {
        hops: vec![InvitationHop::issue(
            &genesis(),
            leaf.public_key_bytes(),
            1,
            100,
        )],
    }
}

fn handshake(sender: &NodeIdentity, node: &Node, chain: DelegationChain) -> MeshWireResponse {
    send(
        sender,
        node,
        MeshWireRequest::HandshakeWoT {
            chain,
            asn: None,
            region: None,
        },
    )
}

fn accepted(resp: &MeshWireResponse) -> bool {
    matches!(resp, MeshWireResponse::HandshakeAck { accepted: true, .. })
}

struct Blinded {
    id: BlindedShardId,
    cap: BlindedShardCapability,
    bytes: Vec<u8>,
    delete_verifier: [u8; 32],
}

fn blinded(seed: u8, len: usize) -> Blinded {
    let mk = MasterKey::from_bytes([seed; 32]);
    let bytes = vec![seed ^ 0x5A; len];
    let id = BlindedShardId::derive(&mk, &[seed; 32], 0, &bytes);
    let (_cap_ident, cap) = BlindedShardCapability::derive_keypair(&mk, &id.locator);
    let delete_verifier = parvault::bootstrap::BlindedShardTombstone::derive_delete_verifier(
        &[seed ^ 0x77; 32],
        &id.locator,
    );
    Blinded {
        id,
        cap,
        bytes,
        delete_verifier,
    }
}

// --- F-03 / F-20: no admission on the wire request path --------------------------------------------

/// F-03 accept (daemon): an admitted ring member stores a shard.
#[test]
fn f03_admitted_put_shard_stored_daemon() {
    let node = spawn_daemon("f03d-a");
    let member = key(0xA1);
    let (sid, bytes) = shard(0x11, 1024);
    let resp = send(&member, &node, put_shard("", sid, bytes, None));
    assert!(stored(&resp), "{resp:?}");
    gate_ran("trust_enforcement::f03_admitted_put_shard_stored_daemon");
}

/// F-03 reject (daemon): the same put from a key without a chain is refused.
#[test]
fn f03_unadmitted_put_shard_refused_daemon() {
    let node = spawn_daemon("f03d-r");
    let stranger = key(0xA1);
    let (sid, bytes) = shard(0x11, 1024);
    let resp = send_as_stranger(&stranger, &node, put_shard("", sid, bytes, None));
    assert_eq!(
        refusal_text(&resp).as_deref(),
        Some(NOT_ADMITTED),
        "{resp:?}"
    );
    assert_logged(&node, "reject.peer_not_admitted");
    gate_ran("trust_enforcement::f03_unadmitted_put_shard_refused_daemon");
}

/// F-03 accept (seed).
#[test]
fn f03_admitted_put_shard_stored_seed() {
    let node = spawn_seed("f03s-a");
    let member = key(0xA2);
    let (sid, bytes) = shard(0x12, 1024);
    let resp = send(&member, &node, put_shard("", sid, bytes, None));
    assert!(stored(&resp), "{resp:?}");
    gate_ran("trust_enforcement::f03_admitted_put_shard_stored_seed");
}

/// F-03 reject (seed).
#[test]
fn f03_unadmitted_put_shard_refused_seed() {
    let node = spawn_seed("f03s-r");
    let stranger = key(0xA2);
    let (sid, bytes) = shard(0x12, 1024);
    let resp = send_as_stranger(&stranger, &node, put_shard("", sid, bytes, None));
    assert_eq!(
        refusal_text(&resp).as_deref(),
        Some(NOT_ADMITTED),
        "{resp:?}"
    );
    assert_logged(&node, "reject.peer_not_admitted");
    gate_ran("trust_enforcement::f03_unadmitted_put_shard_refused_seed");
}

// --- F-05: public-commons tickets on the wire ---------------------------------------------------------

fn admit_ticket(node: &Node, sender: &NodeIdentity, bits: u8) -> MeshWireResponse {
    send_as_stranger(
        sender,
        node,
        MeshWireRequest::AdmitPublicTicket(PublicCommonsTicket::mint(sender, now_ms(), bits)),
    )
}

/// F-05 accept: in public-commons mode a ticket at the required bits admits a stranger, whose
/// shard is then stored.
#[test]
fn f05_public_ticket_at_required_bits_admits() {
    let node = spawn_public_daemon("f05-a");
    let stranger = key(0xA5);
    let resp = admit_ticket(&node, &stranger, DEFAULT_PUBLIC_WOT_POW_BITS);
    assert!(
        matches!(
            resp,
            MeshWireResponse::AdmitPublicTicketAck { admitted: true, .. }
        ),
        "{resp:?}"
    );
    let (sid, bytes) = shard(0x15, 1024);
    let put = send_as_stranger(&stranger, &node, put_shard("", sid, bytes, None));
    assert!(stored(&put), "{put:?}");
    gate_ran("trust_enforcement::f05_public_ticket_at_required_bits_admits");
}

/// F-05 reject: a ticket one bit short is refused, and the stranger's shard with it.
#[test]
fn f05_public_ticket_one_bit_short_refused() {
    let node = spawn_public_daemon("f05-r");
    let stranger = key(0xA5);
    let resp = admit_ticket(&node, &stranger, DEFAULT_PUBLIC_WOT_POW_BITS - 1);
    assert!(
        matches!(
            resp,
            MeshWireResponse::AdmitPublicTicketAck {
                admitted: false,
                ..
            }
        ),
        "{resp:?}"
    );
    assert_logged(&node, "reject.ticket_insufficient_pow");
    let (sid, bytes) = shard(0x15, 1024);
    let put = send_as_stranger(&stranger, &node, put_shard("", sid, bytes, None));
    assert_eq!(refusal_text(&put).as_deref(), Some(NOT_ADMITTED), "{put:?}");
    gate_ran("trust_enforcement::f05_public_ticket_one_bit_short_refused");
}

/// F-05 (CLI): a client without any chain stores a file on a public-commons daemon through
/// `parvault --public file store`, which mints and presents a ticket on its own.
#[test]
fn f05_public_cli_store_via_ticket() {
    let node = spawn_public_daemon("f05-cli");
    let root = temp_root("f05-cli-client");
    let file = root.path().join("doc.txt");
    std::fs::write(&file, b"public commons ticket admission").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env_remove("PARVAULT_GENESIS_SEED_HEX")
        .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .env("PARVAULT_PEERS", &node.addr)
        .arg("--data-dir")
        .arg(root.path().join("client"))
        .args(["--no-lan-discovery", "--public", "file", "store", "--path"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}\nnode log:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        node.log_text()
    );
    // Admitted by ticket: the client holds no ring genesis and installed no chain.
    let client_dir = root.path().join("client");
    assert!(!client_dir.join("genesis_root.seed").exists());
    assert!(!client_dir.join("wot_chains").exists());
    gate_ran("trust_enforcement::f05_public_cli_store_via_ticket");
}

// --- F-21: the handshake does not bind the chain leaf to the sender --------------------------------

/// F-21 accept: a chain whose leaf is the sender admits it.
#[test]
fn f21_handshake_own_chain_accepted() {
    let node = spawn_daemon("f21-a");
    let leaf = key(0xB1);
    let resp = handshake(&leaf, &node, chain_for(&leaf));
    assert!(accepted(&resp), "{resp:?}");
    gate_ran("trust_enforcement::f21_handshake_own_chain_accepted");
}

/// F-21 reject: the same chain sent by another key is refused.
#[test]
fn f21_handshake_chain_leaf_not_sender_refused() {
    let node = spawn_daemon("f21-r");
    let leaf = key(0xB1);
    let other_sender = key(0xB2);
    let resp = handshake(&other_sender, &node, chain_for(&leaf));
    assert!(!accepted(&resp), "{resp:?}");
    assert_logged(&node, "reject.chain_leaf_not_sender");
    gate_ran("trust_enforcement::f21_handshake_chain_leaf_not_sender_refused");
}

// --- F-04: the claimed owner is not bound to the sender --------------------------------------------

/// F-04 accept: a put claiming the sender's own device id is stored.
#[test]
fn f04_owner_claim_of_sender_stored() {
    let node = spawn_daemon("f04-a");
    let sender = key(0xC1);
    let (sid, bytes) = shard(0x20, 1024);
    let resp = send(
        &sender,
        &node,
        put_shard(&sender.device_peer_id(), sid, bytes, None),
    );
    assert!(stored(&resp), "{resp:?}");
    gate_ran("trust_enforcement::f04_owner_claim_of_sender_stored");
}

/// F-04 reject: the same put claiming an invented owner is refused.
#[test]
fn f04_invented_owner_claim_refused() {
    let node = spawn_daemon("f04-r");
    let sender = key(0xC1);
    let (sid, bytes) = shard(0x20, 1024);
    let resp = send(
        &sender,
        &node,
        put_shard("invented-owner-1", sid, bytes, None),
    );
    assert_eq!(
        refusal_text(&resp).as_deref(),
        Some("owner claim does not match the sender"),
        "{resp:?}"
    );
    assert_logged(&node, "reject.owner_not_sender");
    gate_ran("trust_enforcement::f04_invented_owner_claim_refused");
}

fn shard_files(dir: &Path) -> usize {
    std::fs::read_dir(dir.join("shards"))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "shard"))
                .count()
        })
        .unwrap_or(0)
}

/// F-04 (graceful leave): a departing node hands its shards to a ring peer under its own device
/// id, sent as its own key, and the peer accepts them.
#[test]
fn f04_graceful_leave_handoff_accepted() {
    let target = spawn_daemon("f04-leave-target");
    let root = temp_root("f04-leave");
    let dir = root.path().join("departing");
    let file = root.path().join("doc.bin");
    std::fs::write(&file, vec![0x42; 64 * 1024]).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
            .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
            .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
            .env_remove("PARVAULT_PEERS")
            .arg("--data-dir")
            .arg(&dir)
            .arg("--no-lan-discovery")
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: stdout={}\nstderr={}\ntarget log:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            target.log_text()
        );
    };
    run(&["file", "store", "--path", file.to_str().unwrap()]);
    let local = shard_files(&dir);
    assert!(local > 0, "the departing node holds shards");
    run(&["leave", "--handoff-to", &target.addr]);
    assert!(
        shard_files(&target.dir) >= local,
        "every shard handed off: target log:\n{}",
        target.log_text()
    );
    assert!(
        !target.log_text().contains("reject."),
        "{}",
        target.log_text()
    );
    gate_ran("trust_enforcement::f04_graceful_leave_handoff_accepted");
}

/// F-04 (syndication): a seed syndicates a device's stripe to its mesh peer with an empty owner
/// claim (accounted to the seed), and the peer accepts every shard.
#[test]
fn f04_seed_syndication_accounted_to_seed() {
    let peer = spawn_daemon("f04-synd-peer");
    let seed = spawn_seed_with_peers("f04-synd-seed", &[&peer.addr]);
    let device = key(0xC8);
    let cert =
        PersonalDeviceCert::issue(&seed.owner_pq(), &device.device_peer_id(), "laptop", 1).unwrap();
    let ct = vec![0x3D; 32 * 1024];
    let set = encode_ciphertext_stripe(0, &ct, ErasureTier::Homelab).unwrap();
    let bundle = LiteStripeSyndicationBundle {
        stripe_index: 0,
        tier: ErasureTier::Homelab,
        ciphertext_bytes: ct,
        expected_stripe_merkle_root: set.stripe_merkle_root,
        expected_shard_hashes: set.shard_hashes.clone(),
    };
    let resp = send(
        &device,
        &seed,
        MeshWireRequest::SyndicateLiteStripe {
            cert,
            bundle,
            repair_grant: None,
        },
    );
    match resp {
        MeshWireResponse::SyndicateLiteStripeAck {
            receipt: Some(r), ..
        } => assert_eq!(
            r.mesh_peers_populated,
            set.shard_hashes.len(),
            "every shard reached the peer: peer log:\n{}",
            peer.log_text()
        ),
        other => panic!("{other:?}\nseed log:\n{}", seed.log_text()),
    }
    assert!(!peer.log_text().contains("reject."), "{}", peer.log_text());
    gate_ran("trust_enforcement::f04_seed_syndication_accounted_to_seed");
}

/// F-04 (gateway): the gateway engine's 40 lanes all send as the owner identity, so one PeerId
/// holds 40 connections to the storage peer, which accepts every shard.
#[test]
fn f04_gateway_lanes_send_as_owner() {
    // In-process lanes take their credential from the process-wide source (the ring genesis).
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| std::env::set_var("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED)));
    let peer = spawn_daemon("f04-lanes-peer");
    let root = temp_root("f04-lanes");
    let engine = parvault::gateway::GatewayEngine::new(
        root.path().join("gw"),
        MasterKey::from_bytes([0x61; 32]),
        parvault::gateway::GatewayConfig {
            stripe_size_bytes: 1024 * 1024,
            tier: ErasureTier::Homelab,
            peers: vec![peer.addr.clone()],
            macaroon_root_key: None,
            strict_allowed_peer_uids: None,
            require_sealed_ingest_memfd: false,
        },
    )
    .unwrap();
    let payload = vec![0x5C; 3 * 1024 * 1024];
    let path = root.path().join("payload.bin");
    std::fs::write(&path, &payload).unwrap();
    let fd: std::os::fd::OwnedFd = std::fs::File::open(&path).unwrap().into();
    let manifest = engine
        .store_from_owned_fd(
            fd,
            payload.len() as u64,
            parvault::gateway::RetentionPolicy::Persistent,
        )
        .unwrap_or_else(|e| panic!("{e}\npeer log:\n{}", peer.log_text()));
    assert_eq!(manifest.total_size, payload.len() as u64);
    assert!(shard_files(&peer.dir) >= 20, "{}", peer.log_text());
    assert!(!peer.log_text().contains("reject."), "{}", peer.log_text());
    gate_ran("trust_enforcement::f04_gateway_lanes_send_as_owner");
}

// --- F-02: repair grants -----------------------------------------------------------------------------

/// Stores a shard of stripe `root` (index 0) with a grant by `owner` naming `witnesses`.
fn store_with_grant(
    node: &Node,
    owner: &NodeIdentity,
    witnesses: &[&NodeIdentity],
) -> (ShardId, Vec<u8>) {
    let (sid, bytes) = shard(0x31, 2048);
    let grant = RepairGrant::issue(
        owner,
        sid.stripe_merkle_root,
        witnesses.iter().map(|w| w.public_key_bytes()).collect(),
        ErasureTier::Homelab,
    );
    let resp = send(owner, node, put_shard("", sid, bytes.clone(), Some(grant)));
    assert!(stored(&resp), "{resp:?}");
    (sid, bytes)
}

fn repair_read(sid: ShardId, grant: RepairGrant, witnesses: &[&NodeIdentity]) -> MeshWireRequest {
    let receipts = witnesses
        .iter()
        .map(|w| WitnessFailureReceipt::issue(w, sid.stripe_merkle_root, sid.shard_index, now_ms()))
        .collect();
    MeshWireRequest::GetCiphertextShard {
        shard_id: sid,
        owner_signature: None,
        repair_proof: Some((grant, receipts)),
    }
}

/// F-02b accept: the registered grant plus receipts from two of its witnesses reads the shard.
#[test]
fn f02b_registered_grant_repair_read() {
    let node = spawn_daemon("f02b-a");
    let owner = key(0xD1);
    let (w1, w2) = (key(0xD2), key(0xD3));
    let (sid, bytes) = store_with_grant(&node, &owner, &[&w1, &w2]);
    let grant = RepairGrant::issue(
        &owner,
        sid.stripe_merkle_root,
        vec![w1.public_key_bytes(), w2.public_key_bytes()],
        ErasureTier::Homelab,
    );
    let resp = send(&w1, &node, repair_read(sid, grant, &[&w1, &w2]));
    assert_eq!(read_bytes(&resp), Some(bytes));
    gate_ran("trust_enforcement::f02b_registered_grant_repair_read");
}

/// F-02b reject: a foreign self-signed grant plus receipts from its own witnesses is refused.
#[test]
fn f02b_foreign_grant_repair_read_refused() {
    let node = spawn_daemon("f02b-r");
    let owner = key(0xD1);
    let (w1, w2) = (key(0xD2), key(0xD3));
    let (sid, _) = store_with_grant(&node, &owner, &[&w1, &w2]);
    let attacker = key(0xD4);
    let (a1, a2) = (key(0xD5), key(0xD6));
    let foreign = RepairGrant::issue(
        &attacker,
        sid.stripe_merkle_root,
        vec![a1.public_key_bytes(), a2.public_key_bytes()],
        ErasureTier::Homelab,
    );
    let resp = send(&attacker, &node, repair_read(sid, foreign, &[&a1, &a2]));
    assert_eq!(
        read_bytes(&resp),
        None,
        "a foreign grant must not read the shard"
    );
    assert_logged(&node, "reject.repair_grant_unregistered");
    gate_ran("trust_enforcement::f02b_foreign_grant_repair_read_refused");
}

/// A second shard (index 1) of the stripe of `sid`, with a grant by `granter`.
fn second_shard_put(sid: ShardId, granter: &NodeIdentity) -> MeshWireRequest {
    let bytes = vec![0x77; 1024];
    let sid1 = ShardId {
        stripe_merkle_root: sid.stripe_merkle_root,
        shard_index: 1,
        shard_hash: parvault::sharding::merkle::hash_shard_leaf(1, &bytes),
    };
    let grant = RepairGrant::issue(
        granter,
        sid.stripe_merkle_root,
        vec![],
        ErasureTier::Homelab,
    );
    put_shard("", sid1, bytes, Some(grant))
}

/// F-02a accept: the owner's own grant for a further shard of its stripe is registered (a
/// same-owner update) and the owner's signed read keeps working.
#[test]
fn f02a_owner_grant_update_registered() {
    let node = spawn_daemon("f02a-a");
    let owner = key(0xE1);
    let (sid, bytes) = store_with_grant(&node, &owner, &[]);
    let resp = send(&owner, &node, second_shard_put(sid, &owner));
    assert!(stored(&resp), "{resp:?}");
    assert_eq!(
        read_bytes(&send(&owner, &node, owner_read(&owner, sid))),
        Some(bytes)
    );
    assert!(
        !node.log_text().contains("reject.repair_grant"),
        "{}",
        node.log_text()
    );
    gate_ran("trust_enforcement::f02a_owner_grant_update_registered");
}

/// F-02a reject: another admitted key storing a shard of the same stripe with its own grant does
/// not replace the owner's grant; the owner's signed read keeps working.
#[test]
fn f02a_foreign_grant_not_registered() {
    let node = spawn_daemon("f02a-r");
    let owner = key(0xE1);
    let (sid, bytes) = store_with_grant(&node, &owner, &[]);
    let attacker = key(0xE2);
    let resp = send(&attacker, &node, second_shard_put(sid, &attacker));
    assert!(stored(&resp), "the shard itself is stored: {resp:?}");
    assert_logged(&node, "reject.repair_grant_owner_conflict");
    assert_eq!(
        read_bytes(&send(&owner, &node, owner_read(&owner, sid))),
        Some(bytes)
    );
    gate_ran("trust_enforcement::f02a_foreign_grant_not_registered");
}

/// F-02a (failed put): a rejected put registers nothing, so the owner's read keeps working.
#[test]
fn f02a_rejected_put_registers_nothing() {
    let node = spawn_daemon("f02a-f");
    let owner = key(0xE3);
    let (sid, bytes) = store_with_grant(&node, &owner, &[]);
    let attacker = key(0xE4);
    let mut bad = sid;
    bad.shard_index = 1;
    bad.shard_hash = [0xEE; 32];
    let foreign = RepairGrant::issue(
        &attacker,
        sid.stripe_merkle_root,
        vec![],
        ErasureTier::Homelab,
    );
    let resp = send(
        &attacker,
        &node,
        put_shard("", bad, vec![1; 64], Some(foreign)),
    );
    assert!(!stored(&resp), "{resp:?}");
    assert_eq!(
        read_bytes(&send(&owner, &node, owner_read(&owner, sid))),
        Some(bytes)
    );
    gate_ran("trust_enforcement::f02a_rejected_put_registers_nothing");
}

// --- F-24: self-certifying vouchers --------------------------------------------------------------------

fn blinded_put(b: &Blinded, voucher_issuer: &NodeIdentity) -> MeshWireRequest {
    MeshWireRequest::PutBlindedShard {
        blinded_id: b.id,
        shard_bytes: b.bytes.clone(),
        capability: b.cap,
        voucher: AnonymousQuotaVoucher::mint(voucher_issuer, 8192),
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: b.delete_verifier,
    }
}

fn onion_final(node: &Node, b: &Blinded, voucher_issuer: &NodeIdentity) -> MeshWireRequest {
    MeshWireRequest::RelayPqOnionEnvelope {
        target_peer_addr: None,
        envelope: PqRelayedShardEnvelope::seal_pq(&node.kem_public(), "relay", &b.id, &b.bytes, 0)
            .unwrap(),
        capability: b.cap,
        voucher: AnonymousQuotaVoucher::mint(voucher_issuer, 8192),
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: b.delete_verifier,
    }
}

/// F-24 accept (blinded put): an admitted sender with a voucher stores a blinded shard. The
/// voucher is still self-certifying (issuer policy: 2c).
#[test]
fn f24_admitted_blinded_put_stored() {
    let node = spawn_daemon("f24-a");
    let member = key(0xF1);
    let resp = send(&member, &node, blinded_put(&blinded(0x51, 1024), &member));
    assert!(
        matches!(
            resp,
            MeshWireResponse::PutBlindedShardAck { stored: true, .. }
        ),
        "{resp:?}"
    );
    gate_ran("trust_enforcement::f24_admitted_blinded_put_stored");
}

/// F-24 reject (blinded put): the same from a sender without a chain is refused.
#[test]
fn f24_unadmitted_blinded_put_refused() {
    let node = spawn_daemon("f24-r");
    let stranger = key(0xF1);
    let resp = send_as_stranger(
        &stranger,
        &node,
        blinded_put(&blinded(0x51, 1024), &stranger),
    );
    assert_eq!(
        refusal_text(&resp).as_deref(),
        Some(NOT_ADMITTED),
        "{resp:?}"
    );
    assert_logged(&node, "reject.peer_not_admitted");
    gate_ran("trust_enforcement::f24_unadmitted_blinded_put_refused");
}

/// F-24 accept (onion final delivery): an admitted last hop delivers.
#[test]
fn f24_admitted_onion_final_delivered() {
    let node = spawn_daemon("f24o-a");
    let relay = key(0xF2);
    let resp = send(
        &relay,
        &node,
        onion_final(&node, &blinded(0x52, 512), &relay),
    );
    assert!(
        matches!(
            resp,
            MeshWireResponse::RelayPqOnionAck {
                delivered: true,
                ..
            }
        ),
        "{resp:?}"
    );
    gate_ran("trust_enforcement::f24_admitted_onion_final_delivered");
}

/// F-24 reject (onion final delivery): a last hop without a chain is refused at final delivery.
#[test]
fn f24_unadmitted_onion_final_refused() {
    let node = spawn_daemon("f24o-r");
    let relay = key(0xF2);
    let resp = send_as_stranger(
        &relay,
        &node,
        onion_final(&node, &blinded(0x52, 512), &relay),
    );
    assert_eq!(
        refusal_text(&resp).as_deref(),
        Some(NOT_ADMITTED),
        "{resp:?}"
    );
    assert_logged(&node, "reject.peer_not_admitted");
    gate_ran("trust_enforcement::f24_unadmitted_onion_final_refused");
}

/// F-24 (relay): an originator without a chain sends a 2-layer onion through an admitted relay;
/// the relay peels its layer and forwards under its own identity, and the target delivers. Only
/// the last hop's sender is checked, so the originator is never asked to identify itself.
#[test]
fn f24_onion_relay_forwards_for_unadmitted_originator() {
    let relay = spawn_daemon("f24-relay");
    let target = spawn_daemon("f24-target");
    let originator = key(0xF3);
    let b = blinded(0x54, 512);
    let bundle = parvault::crypto::pqc::PqOnionFinalBundle {
        blinded_id: b.id,
        shard_bytes: b.bytes.clone(),
        capability: b.cap,
        voucher: AnonymousQuotaVoucher::mint(&originator, 8192),
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: b.delete_verifier,
    };
    let layered = PqRelayedShardEnvelope::seal_layered_pq(
        &relay.kem_public(),
        "relay",
        &target.kem_public(),
        target.addr.clone(),
        &bundle,
        0,
        0,
    )
    .unwrap();
    let resp = send_as_stranger(
        &originator,
        &relay,
        MeshWireRequest::RelayPqOnionEnvelope {
            target_peer_addr: None,
            envelope: layered,
            capability: b.cap,
            voucher: AnonymousQuotaVoucher::mint(&originator, 8192),
            current_epoch: 1,
            lease_duration_epochs: 30,
            delete_verifier: b.delete_verifier,
        },
    );
    assert!(
        matches!(
            resp,
            MeshWireResponse::RelayPqOnionAck {
                delivered: true,
                ..
            }
        ),
        "{resp:?}\nrelay log:\n{}\ntarget log:\n{}",
        relay.log_text(),
        target.log_text()
    );
    assert!(!target.log_text().contains("reject.peer_not_admitted"));
    gate_ran("trust_enforcement::f24_onion_relay_forwards_for_unadmitted_originator");
}

// --- F-23: lease renewal carries no credential -----------------------------------------------------------

#[test]
fn repro_f23_renew_without_credential() {
    let node = spawn_daemon("f23");
    let uploader = key(0xF3);
    let b = blinded(0x53, 512);
    send(
        &uploader,
        &node,
        MeshWireRequest::PutBlindedShard {
            blinded_id: b.id,
            shard_bytes: b.bytes.clone(),
            capability: b.cap,
            voucher: AnonymousQuotaVoucher::mint(&uploader, 8192),
            current_epoch: 1,
            lease_duration_epochs: 30,
            delete_verifier: b.delete_verifier,
        },
    );
    let stranger = key(0xF4);
    let resp = send(
        &stranger,
        &node,
        MeshWireRequest::RenewBlindedLease {
            blinded_id: b.id,
            current_epoch: 2,
            extension_epochs: 10,
        },
    );
    assert!(
        matches!(
            resp,
            MeshWireResponse::RenewBlindedLeaseAck { renewed: true, .. }
        ),
        "gap: an unrelated key renews the lease: {resp:?}"
    );
    gate_ran("trust_enforcement::repro_f23_renew_without_credential");
}

// --- F-22: rendezvous registration before admission -------------------------------------------------------

#[test]
fn repro_f22_unadmitted_rendezvous_register_stored() {
    let node = spawn_daemon("f22");
    let stranger = key(0xF5);
    let code = "quiet-river-stone-lamp";
    let card = WanPeerCard::new(
        &stranger,
        "probe",
        "daemon",
        vec!["/ip4/203.0.113.9/tcp/4001".into()],
        None,
        None,
        3600,
        now_ms(),
    )
    .unwrap();
    let entry = seal_wan_peer_card(code, &card, &stranger).unwrap();
    let resp = send(
        &stranger,
        &node,
        MeshWireRequest::RegisterWanRendezvous {
            slot_key: derive_slot_key_from_code(code),
            entry,
        },
    );
    assert!(
        matches!(
            resp,
            MeshWireResponse::RegisterWanRendezvousAck { stored: true, .. }
        ),
        "gap: unadmitted rendezvous registration stored: {resp:?}"
    );
    gate_ran("trust_enforcement::repro_f22_unadmitted_rendezvous_register_stored");
}

// --- F-25: syndication cert not bound to the sender; self-signed DHT records from strangers -------------

/// F-25 (cert): a device cert issued by the seed's owner for one device is replayed by an
/// unrelated key and the seed syndicates the stripe.
#[test]
fn repro_f25_device_cert_replayed_by_other_key() {
    let node = spawn_seed("f25c");
    let device = key(0xC5);
    let cert = PersonalDeviceCert::issue(
        &node.owner_pq(),
        &device.device_peer_id(),
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
    let replayer = key(0xC6);
    let resp = send(
        &replayer,
        &node,
        MeshWireRequest::SyndicateLiteStripe {
            cert,
            bundle,
            repair_grant: None,
        },
    );
    assert!(
        matches!(
            resp,
            MeshWireResponse::SyndicateLiteStripeAck {
                receipt: Some(_),
                ..
            }
        ),
        "gap: another key's cert is accepted: {resp:?}"
    );
    gate_ran("trust_enforcement::repro_f25_device_cert_replayed_by_other_key");
}

/// F-25 accept (DHT put): an admitted sender stores a self-signed envelope.
#[test]
fn f25_admitted_dht_put_stored() {
    let node = spawn_daemon("f25d-a");
    let member = key(0xC7);
    let env = squat_catalog(&member, [0x77; 32], 1);
    let resp = send(
        &member,
        &node,
        MeshWireRequest::PutDhtEnvelope(DhtWireEnvelope::VaultCatalog(env)),
    );
    assert!(
        matches!(
            resp,
            MeshWireResponse::PutDhtEnvelopeAck { stored: true, .. }
        ),
        "{resp:?}"
    );
    gate_ran("trust_enforcement::f25_admitted_dht_put_stored");
}

/// F-25 reject (DHT put): the same from a sender without a chain is refused.
#[test]
fn f25_unadmitted_dht_put_refused() {
    let node = spawn_daemon("f25d-r");
    let stranger = key(0xC7);
    let env = squat_catalog(&stranger, [0x77; 32], 1);
    let resp = send_as_stranger(
        &stranger,
        &node,
        MeshWireRequest::PutDhtEnvelope(DhtWireEnvelope::VaultCatalog(env)),
    );
    assert_eq!(
        refusal_text(&resp).as_deref(),
        Some(NOT_ADMITTED),
        "{resp:?}"
    );
    assert_logged(&node, "reject.peer_not_admitted");
    gate_ran("trust_enforcement::f25_unadmitted_dht_put_refused");
}

// --- F-10: DHT readers and raw Kademlia --------------------------------------------------------------------

/// A self-consistent vault-catalog envelope at `dht_key`, signed by `signer` (not the vault owner).
fn squat_catalog(
    signer: &NodeIdentity,
    dht_key: [u8; 32],
    version: u64,
) -> EncryptedVaultCatalogEnvelope {
    let envelope_salt = [0x33; 32];
    let encrypted_catalog_bytes = vec![0xAB; 64];
    let ciphertext_sha256: [u8; 32] = Sha256::digest(&encrypted_catalog_bytes).into();
    let owner_pubkey = signer.public_key_bytes();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"parvault-vault-root-catalog-v1:");
    msg.extend_from_slice(&dht_key);
    msg.extend_from_slice(&owner_pubkey);
    msg.extend_from_slice(&version.to_be_bytes());
    msg.extend_from_slice(&envelope_salt);
    msg.extend_from_slice(&ciphertext_sha256);
    let sig = signer.sign(&msg);
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&sig[..32]);
    sig_s.copy_from_slice(&sig[32..]);
    let env = EncryptedVaultCatalogEnvelope {
        dht_key,
        owner_pubkey,
        monotonic_version: version,
        envelope_salt,
        ciphertext_sha256,
        encrypted_catalog_bytes,
        sig_r,
        sig_s,
    };
    assert!(
        env.verify_zero_knowledge(),
        "test envelope is self-consistent"
    );
    env
}

const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// F-10a: with the owner's catalog on one seed and a squatter's `u64::MAX` envelope at the same
/// key on another, `recover-from-seed` picks the squatter and fails.
#[test]
fn repro_f10a_squatted_catalog_wins_recover() {
    let honest_seed = spawn_seed("f10a-h");
    let squat_seed = spawn_seed("f10a-s");
    let canonical = parvault::crypto::validate_recovery_seed_phrase_or_passphrase(PHRASE).unwrap();
    let mk = MasterKey::from_recovery_seed_phrase(&canonical, "default");
    let pq = PqVaultMasterKey::from_recovery_seed_phrase(&canonical, "default");
    let owner = NodeIdentity::from_recovery_seed_phrase(&canonical, "default");
    let honest = EncryptedVaultCatalogEnvelope::seal(
        &mk,
        &pq,
        &owner,
        "default",
        &FolderSnapshotManifest {
            version: 1,
            folder_merkle_root: [0x10; 32],
            tier: ErasureTier::Homelab,
            files: Default::default(),
            signed_dht_envelope: None,
            deleted_tombstones: Default::default(),
        },
    )
    .unwrap();
    let dht_key = honest.dht_key;
    let put = |n: &Node, who: &NodeIdentity, env: EncryptedVaultCatalogEnvelope| {
        let r = send(
            who,
            n,
            MeshWireRequest::PutDhtEnvelope(DhtWireEnvelope::VaultCatalog(env)),
        );
        assert!(
            matches!(r, MeshWireResponse::PutDhtEnvelopeAck { stored: true, .. }),
            "{r:?}"
        );
    };
    put(&honest_seed, &owner, honest);
    let squatter = key(0x9A);
    put(
        &squat_seed,
        &squatter,
        squat_catalog(&squatter, dht_key, u64::MAX),
    );

    let root = temp_root("f10a-client");
    let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .env(
            "PARVAULT_PEERS",
            format!("{},{}", honest_seed.addr, squat_seed.addr),
        )
        .arg("--data-dir")
        .arg(root.path().join("client"))
        .args([
            "--no-lan-discovery",
            "recover-from-seed",
            "--seed-phrase",
            PHRASE,
            "--out-dir",
        ])
        .arg(root.path().join("out"))
        .output()
        .expect("run recover-from-seed");
    assert!(
        !out.status.success(),
        "gap: the squatted envelope wins and recovery fails; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    gate_ran("trust_enforcement::repro_f10a_squatted_catalog_wins_recover");
}

/// F-10b: a raw Kademlia PUT of arbitrary bytes is stored by the daemon's DHT store.
#[test]
fn repro_f10b_raw_kad_put_stored() {
    let node = spawn_daemon("f10b");
    let target = node.peer_id();
    let addr: Multiaddr = node.addr.parse().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ok = rt.block_on(async move {
        let kp = key(0x9B).to_libp2p_keypair().unwrap();
        let mut swarm: libp2p::Swarm<MeshNetworkBehaviour> =
            build_mesh_client_swarm(kp, false).unwrap();
        swarm.behaviour_mut().kademlia.add_address(&target, addr);
        let record = kad::Record::new(b"junk-key".to_vec(), b"unsigned junk".to_vec());
        swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, kad::Quorum::One)
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut outcome = None;
        while outcome.is_none() {
            tokio::select! {
                ev = swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(parvault::network::behaviour::MeshNetworkBehaviourEvent::Kademlia(
                        kad::Event::OutboundQueryProgressed { result: kad::QueryResult::PutRecord(r), .. },
                    )) = ev {
                        outcome = Some(r.is_ok());
                    }
                }
                _ = tokio::time::sleep_until(deadline) => outcome = Some(false),
            }
        }
        outcome.unwrap()
    });
    assert!(ok, "gap: the daemon stores a raw unsigned Kademlia record");
    gate_ran("trust_enforcement::repro_f10b_raw_kad_put_stored");
}

// --- F-01: gossip slashing quarantines the genesis ----------------------------------------------------------

/// F-01: an admitted reporter gossips `SlashingEvidence` naming the genesis. The daemon does not
/// subscribe to the slashing topic (gossip evidence is not applied until it is proof-carrying, 2c),
/// so the evidence has no effect and a valid chain for a new peer is still accepted.
#[test]
fn f01_gossip_evidence_has_no_effect() {
    let node = spawn_daemon("f01");
    let reporter = key(0x81);
    assert!(accepted(&handshake(&reporter, &node, chain_for(&reporter))));

    let target = node.peer_id();
    let addr: Multiaddr = node.addr.parse().unwrap();
    let evidence = SlashingEvidence::issue(
        &reporter,
        genesis().public_key_bytes(),
        SlashingReason::ByzantineShardPoisoning,
        7,
    );
    let data = bincode::serialize(&evidence).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let daemon_subscribed = rt.block_on(async move {
        let kp = reporter.to_libp2p_keypair().unwrap();
        let mut swarm: libp2p::Swarm<MeshNetworkBehaviour> =
            build_mesh_client_swarm(kp, false).unwrap();
        let topic = gossipsub::IdentTopic::new("parvault-wot-slashing");
        swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
        swarm.dial(addr).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        let mut subscribed = false;
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                ev = swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(parvault::network::behaviour::MeshNetworkBehaviourEvent::Gossipsub(
                        gossipsub::Event::Subscribed { peer_id, .. },
                    )) = ev {
                        subscribed |= peer_id == target;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
        // Publishing anyway reaches no subscriber.
        let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
        subscribed
    });
    assert!(
        !daemon_subscribed,
        "the daemon must not subscribe to slashing gossip"
    );
    let after = key(0x83);
    let resp = handshake(&after, &node, chain_for(&after));
    assert!(accepted(&resp), "the genesis is not quarantined: {resp:?}");
    gate_ran("trust_enforcement::f01_gossip_evidence_has_no_effect");
}

// --- Admission plumbing (bootstrap option A) ------------------------------------------------------

/// `parvault wot invite` on a genesis holder prints a token; `parvault wot install-chain` on a
/// node without the genesis stores it, and that node's client then holds a chain for its key.
#[test]
fn wot_invite_and_install_chain() {
    let root = temp_root("wot-cli");
    let holder = root.path().join("holder");
    let invitee = root.path().join("invitee");
    std::fs::create_dir_all(&invitee).unwrap();
    let invitee_key = NodeIdentity::load_or_generate_in_dir(&invitee).unwrap();
    let invite = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .arg("--data-dir")
        .arg(&holder)
        .args(["--no-lan-discovery", "wot", "invite", "--peer"])
        .arg(hex::encode(invitee_key.public_key_bytes()))
        .output()
        .unwrap();
    assert!(invite.status.success(), "{invite:?}");
    let token = String::from_utf8(invite.stdout).unwrap().trim().to_string();
    let install = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env_remove("PARVAULT_GENESIS_SEED_HEX")
        .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .arg("--data-dir")
        .arg(&invitee)
        .args([
            "--no-lan-discovery",
            "wot",
            "install-chain",
            "--token",
            &token,
        ])
        .output()
        .unwrap();
    assert!(install.status.success(), "{install:?}");
    assert!(String::from_utf8_lossy(&install.stdout).contains("this node's key"));
    let source = parvault::network::admission::AdmissionSource::from_data_dir(&invitee);
    let chain = source
        .credential_for(&invitee_key)
        .expect("installed chain");
    assert_eq!(chain.hops[0].inviter_pubkey, genesis().public_key_bytes());
    gate_ran("trust_enforcement::wot_invite_and_install_chain");
}
