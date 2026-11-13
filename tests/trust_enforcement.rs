//! Trust-layer enforcement against the real binaries (`parvault`, `parvault-seed`).
//!
//! Item 2b, step 2: every test here REPRODUCES a finding from `docs/security/TRUST_FINDINGS.md`
//! by asserting today's gap over the wire. Each fix rewrites its reproduction into a differential
//! pair (accept and reject differ in one credential; the reject asserts the reason code in the
//! binary's log) and deletes the finding's `open` line in `.enforcement.map`.
//!
//! Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

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
    cmd.env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED));
    spawn_as_is(cmd, root, dir, log, port)
}

/// Like `spawn`, but the binary gets no ring genesis from the environment.
fn spawn_without_ring_env(
    mut cmd: Command,
    root: TempDir,
    dir: PathBuf,
    log: PathBuf,
    port: u16,
) -> Node {
    cmd.env_remove("PARVAULT_GENESIS_SEED_HEX");
    spawn_as_is(cmd, root, dir, log, port)
}

fn spawn_as_is(mut cmd: Command, root: TempDir, dir: PathBuf, log: PathBuf, port: u16) -> Node {
    let log_file = std::fs::File::create(&log).unwrap();
    let child = cmd
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
fn daemon_command(dir: &Path, reg: &Path, port: u16) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", reg)
        .arg("--data-dir")
        .arg(dir)
        .args([
            "--no-lan-discovery",
            "daemon",
            "start",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{port}"),
        ]);
    cmd
}

fn spawn_daemon(label: &str) -> Node {
    let (root, dir, reg, log) = prepare(label);
    let port = free_port();
    let cmd = daemon_command(&dir, &reg, port);
    spawn(cmd, root, dir, log, port)
}

impl Node {
    /// Restarts this daemon on the same data directory and port, first deleting its persisted
    /// Web-of-Trust state (as if its admissions were lost).
    fn restart_daemon_without_wot_state(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(self.dir.join("wot_state.bin"));
        let port: u16 = self.addr.rsplit('/').next().unwrap().parse().unwrap();
        let reg = self.dir.parent().unwrap().join("lan-registry");
        let log_file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.log)
            .unwrap();
        self.child = daemon_command(&self.dir, &reg, port)
            .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "daemon did not come back");
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
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
        MeshWireRequest::AdmitPublicTicket(PublicCommonsTicket::mint(
            sender,
            node.identity().public_key_bytes(),
            now_ms(),
            bits,
        )),
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

/// F-29 reject: a ticket at the required bits but 20 minutes old is refused (freshness window).
#[test]
fn f29_stale_ticket_refused() {
    let node = spawn_public_daemon("f27-stale");
    let stranger = key(0xA6);
    let resp = send_as_stranger(
        &stranger,
        &node,
        MeshWireRequest::AdmitPublicTicket(PublicCommonsTicket::mint(
            &stranger,
            node.identity().public_key_bytes(),
            now_ms() - 20 * 60_000,
            DEFAULT_PUBLIC_WOT_POW_BITS,
        )),
    );
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
    assert_logged(&node, "reject.ticket_stale");
    gate_ran("trust_enforcement::f29_stale_ticket_refused");
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
    assert!(!client_dir.join("ring_genesis.seed").exists());
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
    run(&[
        "file",
        "store",
        "--allow-local-only",
        "--path",
        file.to_str().unwrap(),
    ]);
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
    provision_process_genesis();
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

// --- PoR session commits ---------------------------------------------------------------------------------

/// A refused put of an existing shard id (foreign owner claim) must not replace the owner's PoR
/// session key: the owner's audit with its own key is still answered.
#[test]
fn refused_put_keeps_por_session_key() {
    let node = spawn_daemon("por-session");
    let owner = key(0xA7);
    let (sid, bytes) = shard(0x17, 2048);
    let session = [0x5E; 32];
    assert!(stored(&send(
        &owner,
        &node,
        put_shard("", sid, bytes.clone(), None)
    )));
    let attacker = key(0xA8);
    let refused = send(
        &attacker,
        &node,
        MeshWireRequest::PutShard {
            owner_peer_id: "invented-owner".into(),
            shard_id: sid,
            shard_bytes: bytes.clone(),
            session_key_commit: [0x66; 32],
            repair_grant: None,
        },
    );
    assert!(!stored(&refused), "{refused:?}");
    let chal = parvault::por::generate_por_challenge(&session, sid, bytes.len() as u64, now_ms());
    let resp = send(&owner, &node, MeshWireRequest::PorAudit(chal));
    assert!(
        matches!(resp, MeshWireResponse::PorAuditResult(Some(_))),
        "the owner's session key survives a refused put: {resp:?}"
    );
    gate_ran("trust_enforcement::refused_put_keeps_por_session_key");
}

// --- F-36: owner-signed deletes ----------------------------------------------------------------------

fn delete_req(signer: &NodeIdentity, sid: ShardId) -> MeshWireRequest {
    let (pub_, payload, sig) =
        parvault::por::PorVerifierEngine::sign_owner_shard_delete_token(signer, &sid, now_ms());
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..]);
    MeshWireRequest::DeleteShard {
        shard_id: sid,
        owner_signature: (pub_, payload, r, s),
    }
}

fn deleted(resp: &MeshWireResponse) -> bool {
    matches!(resp, MeshWireResponse::DeleteShardAck { deleted: true, .. })
}

/// F-36 accept: the key that stored a shard (no grant) deletes it.
#[test]
fn f36_storer_deletes_its_shard() {
    let node = spawn_daemon("f32-a");
    let storer = key(0xE7);
    let (sid, bytes) = shard(0x47, 512);
    assert!(stored(&send(
        &storer,
        &node,
        put_shard("", sid, bytes, None)
    )));
    let resp = send(&storer, &node, delete_req(&storer, sid));
    assert!(deleted(&resp), "{resp:?}");
    gate_ran("trust_enforcement::f36_storer_deletes_its_shard");
}

/// F-36 reject: another admitted key's signed delete of that shard is refused.
#[test]
fn f36_other_key_cannot_delete_shard() {
    let node = spawn_daemon("f32-r");
    let storer = key(0xE7);
    let other = key(0xE8);
    let (sid, bytes) = shard(0x47, 512);
    assert!(stored(&send(
        &storer,
        &node,
        put_shard("", sid, bytes, None)
    )));
    let resp = send(&other, &node, delete_req(&other, sid));
    assert!(!deleted(&resp), "{resp:?}");
    assert_logged(&node, "reject.delete_not_shard_owner");
    gate_ran("trust_enforcement::f36_other_key_cannot_delete_shard");
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

/// F-02a reject: a grant naming another stripe is not registered with the shard it came with;
/// the owner's signed read keeps working.
#[test]
fn f02a_grant_for_other_stripe_not_registered() {
    let node = spawn_daemon("f02a-r");
    let owner = key(0xE1);
    let (sid, bytes) = store_with_grant(&node, &owner, &[]);
    let bytes1 = vec![0x77; 1024];
    let sid1 = ShardId {
        stripe_merkle_root: sid.stripe_merkle_root,
        shard_index: 1,
        shard_hash: parvault::sharding::merkle::hash_shard_leaf(1, &bytes1),
    };
    let wrong_root = RepairGrant::issue(&owner, [0x99; 32], vec![], ErasureTier::Homelab);
    let resp = send(&owner, &node, put_shard("", sid1, bytes1, Some(wrong_root)));
    assert!(stored(&resp), "the shard itself is stored: {resp:?}");
    assert_logged(&node, "reject.repair_grant_root_mismatch");
    assert_eq!(
        read_bytes(&send(&owner, &node, owner_read(&owner, sid))),
        Some(bytes)
    );
    gate_ran("trust_enforcement::f02a_grant_for_other_stripe_not_registered");
}

/// An attacker registers a grant for the owner's stripe root first, by storing its own shard
/// (index 1) of that root; then the owner stores its shard (index 0) with its grant.
fn squat_then_store(node: &Node) -> (NodeIdentity, NodeIdentity, ShardId, Vec<u8>) {
    let owner = key(0xE5);
    let attacker = key(0xE6);
    let (sid, bytes) = shard(0x45, 2048);
    let junk = vec![0x13; 1024];
    let squat = ShardId {
        stripe_merkle_root: sid.stripe_merkle_root,
        shard_index: 1,
        shard_hash: parvault::sharding::merkle::hash_shard_leaf(1, &junk),
    };
    let attacker_grant = RepairGrant::issue(
        &attacker,
        sid.stripe_merkle_root,
        vec![],
        ErasureTier::Homelab,
    );
    assert!(stored(&send(
        &attacker,
        node,
        put_shard("", squat, junk, Some(attacker_grant))
    )));
    let owner_grant =
        RepairGrant::issue(&owner, sid.stripe_merkle_root, vec![], ErasureTier::Homelab);
    assert!(stored(&send(
        &owner,
        node,
        put_shard("", sid, bytes.clone(), Some(owner_grant))
    )));
    (owner, attacker, sid, bytes)
}

/// F-26 accept: the owner reads its shard although an attacker registered the root first.
#[test]
fn f26_owner_reads_after_root_squat() {
    let node = spawn_daemon("f26-a");
    let (owner, _attacker, sid, bytes) = squat_then_store(&node);
    assert_eq!(
        read_bytes(&send(&owner, &node, owner_read(&owner, sid))),
        Some(bytes)
    );
    gate_ran("trust_enforcement::f26_owner_reads_after_root_squat");
}

/// F-26 reject: the squatter's own signed read of the owner's shard is refused.
#[test]
fn f26_squatter_cannot_read_owner_shard() {
    let node = spawn_daemon("f26-r");
    let (_owner, attacker, sid, _bytes) = squat_then_store(&node);
    assert_eq!(
        read_bytes(&send(&attacker, &node, owner_read(&attacker, sid))),
        None
    );
    assert_logged(&node, "reject.grant_owner_not_shard_owner");
    gate_ran("trust_enforcement::f26_squatter_cannot_read_owner_shard");
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

/// A layered onion's inner envelope for `node` (the final-target branch, `open_final_target_pq`):
/// sealed for a test relay, peeled here, and sent to `node` as the relay would.
fn onion_layered_final(node: &Node, b: &Blinded, voucher_issuer: &NodeIdentity) -> MeshWireRequest {
    let relay_kem = HybridKemKeypair::generate().unwrap();
    let bundle = parvault::crypto::pqc::PqOnionFinalBundle {
        blinded_id: b.id,
        shard_bytes: b.bytes.clone(),
        capability: b.cap,
        voucher: AnonymousQuotaVoucher::mint(voucher_issuer, 8192),
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: b.delete_verifier,
    };
    let layered = PqRelayedShardEnvelope::seal_layered_pq(
        &relay_kem.public_key(),
        "relay",
        &node.kem_public(),
        node.addr.clone(),
        &bundle,
        0,
        0,
    )
    .unwrap();
    let inner = layered
        .peel_relay_hop_pq(&relay_kem)
        .unwrap()
        .inner_envelope;
    MeshWireRequest::RelayPqOnionEnvelope {
        target_peer_addr: None,
        envelope: inner,
        capability: b.cap,
        voucher: AnonymousQuotaVoucher::mint(voucher_issuer, 8192),
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: b.delete_verifier,
    }
}

/// F-24 accept (layered final delivery): an admitted last hop delivers a layered onion.
#[test]
fn f24_admitted_layered_final_delivered() {
    let node = spawn_daemon("f24l-a");
    let relay = key(0xF6);
    let resp = send(
        &relay,
        &node,
        onion_layered_final(&node, &blinded(0x56, 512), &relay),
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
    gate_ran("trust_enforcement::f24_admitted_layered_final_delivered");
}

/// F-24 reject (layered final delivery): the same from a last hop without a chain is refused.
#[test]
fn f24_unadmitted_layered_final_refused() {
    let node = spawn_daemon("f24l-r");
    let relay = key(0xF6);
    let resp = send_as_stranger(
        &relay,
        &node,
        onion_layered_final(&node, &blinded(0x56, 512), &relay),
    );
    assert_eq!(
        refusal_text(&resp).as_deref(),
        Some(NOT_ADMITTED),
        "{resp:?}"
    );
    assert_logged(&node, "reject.peer_not_admitted");
    gate_ran("trust_enforcement::f24_unadmitted_layered_final_refused");
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

/// Sets the ring genesis in this test process, so in-process clients can reach a credential
/// through the process-wide admission source.
fn provision_process_genesis() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| std::env::set_var("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED)));
}

/// F-27 (ADR-11): a ring member that originates a layered onion through a relay is neither
/// admitted at nor identified to the relay (the originator path cannot present a credential,
/// although one is reachable in this process); the relay's last hop to the target is admitted.
#[test]
fn ring_member_originator_stays_anonymous_at_the_relay() {
    provision_process_genesis();
    let relay = spawn_daemon("b1-relay");
    let target = spawn_daemon("b1-target");
    let originator = key(0xF7);
    let originator_id = node_identity_libp2p_peer_id(&originator).unwrap();
    let b = blinded(0x57, 512);
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
    parvault::network::OnionOriginator::new(originator.clone(), Vec::new())
        .send_layered_onion(&relay.addr, layered)
        .unwrap_or_else(|e| panic!("{e}\nrelay log:\n{}", relay.log_text()));
    let relay_log = relay.log_text();
    assert!(
        !relay_log
            .lines()
            .any(|l| l.contains("routing table updated") && l.contains(&originator_id.to_string())),
        "{relay_log}"
    );
    // The last hop (relay -> target) is admitted: the target routes the relay.
    let relay_id = relay.peer_id().to_string();
    assert!(
        target
            .log_text()
            .lines()
            .any(|l| l.contains("routing table updated") && l.contains(&relay_id)),
        "{}",
        target.log_text()
    );
    gate_ran("trust_enforcement::ring_member_originator_stays_anonymous_at_the_relay");
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

fn syndicate(seed: &Node, cert_device: &NodeIdentity) -> MeshWireRequest {
    let cert = PersonalDeviceCert::issue(
        &seed.owner_pq(),
        &cert_device.device_peer_id(),
        "laptop",
        1_700_000_000,
    )
    .unwrap();
    let ct = vec![0x3C; 32 * 1024];
    let set = encode_ciphertext_stripe(0, &ct, ErasureTier::Homelab).unwrap();
    MeshWireRequest::SyndicateLiteStripe {
        cert,
        bundle: LiteStripeSyndicationBundle {
            stripe_index: 0,
            tier: ErasureTier::Homelab,
            ciphertext_bytes: ct,
            expected_stripe_merkle_root: set.stripe_merkle_root,
            expected_shard_hashes: set.shard_hashes.clone(),
        },
        repair_grant: None,
    }
}

/// F-25 accept: the device a cert names syndicates its stripe.
#[test]
fn f25_device_cert_of_sender_accepted() {
    let node = spawn_seed("f25c-a");
    let device = key(0xC5);
    let resp = send(&device, &node, syndicate(&node, &device));
    assert!(
        matches!(
            resp,
            MeshWireResponse::SyndicateLiteStripeAck {
                receipt: Some(_),
                ..
            }
        ),
        "{resp:?}"
    );
    gate_ran("trust_enforcement::f25_device_cert_of_sender_accepted");
}

/// F-25 reject: the same cert replayed by another admitted key is refused.
#[test]
fn f25_device_cert_replayed_by_other_key_refused() {
    let node = spawn_seed("f25c-r");
    let device = key(0xC5);
    let replayer = key(0xC6);
    let resp = send(&replayer, &node, syndicate(&node, &device));
    assert_eq!(
        refusal_text(&resp).as_deref(),
        Some("device cert does not name the sender"),
        "{resp:?}"
    );
    assert_logged(&node, "reject.device_cert_not_sender");
    gate_ran("trust_enforcement::f25_device_cert_replayed_by_other_key_refused");
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

/// Publishes the owner's vault catalog on one seed and, if `squat`, a squatter's `u64::MAX`
/// envelope at the same key on another, then runs `parvault recover-from-seed` against both.
fn recover_with(label: &str, squat: bool) -> std::process::Output {
    let honest_seed = spawn_seed(&format!("{label}-h"));
    let other_seed = spawn_seed(&format!("{label}-s"));
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
    if squat {
        let squatter = key(0x9A);
        put(
            &other_seed,
            &squatter,
            squat_catalog(&squatter, dht_key, u64::MAX),
        );
    }
    let root = temp_root(&format!("{label}-client"));
    Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .env(
            "PARVAULT_PEERS",
            format!("{},{}", honest_seed.addr, other_seed.addr),
        )
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
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
        .expect("run recover-from-seed")
}

fn combined(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// F-10a accept: the owner's catalog is recovered.
#[test]
fn f10a_owner_catalog_recovered() {
    let out = recover_with("f10a-a", false);
    assert!(out.status.success(), "{}", combined(&out));
    gate_ran("trust_enforcement::f10a_owner_catalog_recovered");
}

/// F-10a reject: a squatter's `u64::MAX` envelope at the same key is ignored (logged) and the
/// owner's catalog is still recovered.
#[test]
fn f10a_squatted_catalog_ignored() {
    let out = recover_with("f10a-r", true);
    let log = combined(&out);
    assert!(out.status.success(), "{log}");
    assert!(log.contains("reject.dht_owner_mismatch"), "{log}");
    gate_ran("trust_enforcement::f10a_squatted_catalog_ignored");
}

/// Runs one Kademlia query from a fresh client swarm against `node` and returns its result.
fn kad_query(
    node: &Node,
    seed: u8,
    start: impl FnOnce(&mut libp2p::Swarm<MeshNetworkBehaviour>) + Send + 'static,
) -> Option<kad::QueryResult> {
    let target = node.peer_id();
    let addr: Multiaddr = node.addr.parse().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let kp = key(seed).to_libp2p_keypair().unwrap();
        let mut swarm: libp2p::Swarm<MeshNetworkBehaviour> =
            build_mesh_client_swarm(kp, false).unwrap();
        swarm.behaviour_mut().kademlia.add_address(&target, addr);
        start(&mut swarm);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut outcome = None;
        while outcome.is_none() && tokio::time::Instant::now() < deadline {
            tokio::select! {
                ev = swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(parvault::network::behaviour::MeshNetworkBehaviourEvent::Kademlia(
                        kad::Event::OutboundQueryProgressed { result, .. },
                    )) = ev {
                        outcome = Some(result);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
        outcome
    })
}

/// Raw Kademlia PUT from the key `seed`; `admitted` first handshakes that key with the node.
fn kad_put_as(node: &Node, seed: u8, admitted: bool, record: kad::Record) {
    if admitted {
        assert!(accepted(&handshake(
            &key(seed),
            node,
            chain_for(&key(seed))
        )));
    }
    let result = kad_query(node, seed, move |sw| {
        sw.behaviour_mut()
            .kademlia
            .put_record(record, kad::Quorum::One)
            .unwrap();
    });
    assert!(
        matches!(result, Some(kad::QueryResult::PutRecord(_))),
        "{result:?}"
    );
}

fn kad_get(node: &Node, key: Vec<u8>) -> Option<Vec<u8>> {
    match kad_query(node, 0x9C, move |sw| {
        sw.behaviour_mut()
            .kademlia
            .get_record(kad::RecordKey::new(&key));
    }) {
        Some(kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(r)))) => {
            Some(r.record.value)
        }
        _ => None,
    }
}

fn signed_record(dht_key: [u8; 32]) -> (kad::Record, Vec<u8>) {
    let signer = key(0x9D);
    let env = DhtWireEnvelope::VaultCatalog(squat_catalog(&signer, dht_key, 3));
    let value = bincode::serialize(&env).unwrap();
    (kad::Record::new(dht_key.to_vec(), value.clone()), value)
}

/// F-10b accept: an admitted source's raw Kademlia PUT of a valid signed envelope is stored.
#[test]
fn f10b_signed_envelope_record_stored() {
    let node = spawn_daemon("f10b-a");
    let dht_key = [0x5A; 32];
    let (record, value) = signed_record(dht_key);
    kad_put_as(&node, 0x9B, true, record);
    assert_eq!(
        kad_get(&node, dht_key.to_vec()),
        Some(value),
        "{}",
        node.log_text()
    );
    gate_ran("trust_enforcement::f10b_signed_envelope_record_stored");
}

/// F-10b reject: a raw Kademlia PUT of unsigned bytes is refused and cannot be read back.
#[test]
fn f10b_unsigned_record_refused() {
    let node = spawn_daemon("f10b-r");
    let dht_key = [0x5A; 32];
    kad_put_as(
        &node,
        0x9B,
        true,
        kad::Record::new(dht_key.to_vec(), b"unsigned junk".to_vec()),
    );
    assert_logged(&node, "reject.dht_record_invalid");
    assert_eq!(kad_get(&node, dht_key.to_vec()), None);
    gate_ran("trust_enforcement::f10b_unsigned_record_refused");
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

// --- F-11: mDNS never feeds Kademlia; admission does ---------------------------------------------------

/// Keeps a server-mode swarm for `ident` connected to `node` for a few seconds (long enough for
/// protocol negotiation and Kademlia's routing decision).
fn connect_server_peer(node: &Node, ident: &NodeIdentity) {
    let addr: Multiaddr = node.addr.parse().unwrap();
    let kp = ident.to_libp2p_keypair().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let mut sw = parvault::network::build_mesh_server_swarm(kp, false, false).unwrap();
        sw.dial(addr).unwrap();
        let until = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < until {
            tokio::select! {
                _ = sw.select_next_some() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    });
}

fn routing_updated(node: &Node, peer: &PeerId) -> bool {
    node.log_text()
        .lines()
        .any(|l| l.contains("Kademlia routing table updated") && l.contains(&peer.to_string()))
}

/// F-11 accept: a server-mode peer that is admitted enters the node's Kademlia routing table.
#[test]
fn f11_admitted_peer_enters_routing_table() {
    let node = spawn_daemon("f11-a");
    let member = key(0xB5);
    let member_id = node_identity_libp2p_peer_id(&member).unwrap();
    connect_server_peer(&node, &member);
    assert!(accepted(&handshake(&member, &node, chain_for(&member))));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !routing_updated(&node, &member_id) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(routing_updated(&node, &member_id), "{}", node.log_text());
    gate_ran("trust_enforcement::f11_admitted_peer_enters_routing_table");
}

/// F-11 reject: the same server-mode peer, never admitted, is not added.
#[test]
fn f11_unadmitted_peer_not_routed() {
    let node = spawn_daemon("f11-r");
    let stranger = key(0xB5);
    let stranger_id = node_identity_libp2p_peer_id(&stranger).unwrap();
    connect_server_peer(&node, &stranger);
    assert_logged(&node, "reject.kad_peer_not_admitted");
    assert!(!routing_updated(&node, &stranger_id), "{}", node.log_text());
    gate_ran("trust_enforcement::f11_unadmitted_peer_not_routed");
}

// --- F-31: inbound Kademlia records need an admitted source ----------------------------------------

/// F-31 reject: the same valid signed record from a source that never handshook is refused.
#[test]
fn f31_unadmitted_source_record_refused() {
    let node = spawn_daemon("f29-r");
    let dht_key = [0x5A; 32];
    let (record, _) = signed_record(dht_key);
    kad_put_as(&node, 0x9B, false, record);
    assert_logged(&node, "reject.dht_record_source_not_admitted");
    assert_eq!(kad_get(&node, dht_key.to_vec()), None);
    gate_ran("trust_enforcement::f31_unadmitted_source_record_refused");
}

// --- Client admission: backoff and re-handshake ----------------------------------------------------

/// A client whose credential a node refuses presents it once, not before every request.
#[test]
fn refused_credential_is_not_presented_on_every_request() {
    let node = spawn_daemon("backoff");
    let outsider_genesis = NodeIdentity::from_seed([0x48; 32]);
    let c = MeshClient::new(key(0xAB), Vec::new(), None)
        .with_admission(AdmissionSource::from_genesis(outsider_genesis));
    for i in 0..3u8 {
        let (sid, bytes) = shard(0x30 + i, 512);
        let resp = c
            .send_request(&node.addr, put_shard("", sid, bytes, None))
            .unwrap();
        assert_eq!(
            refusal_text(&resp).as_deref(),
            Some(NOT_ADMITTED),
            "{resp:?}"
        );
    }
    let handshakes = node
        .log_text()
        .lines()
        .filter(|l| l.contains("refused a handshake"))
        .count();
    assert_eq!(handshakes, 1, "{}", node.log_text());
    gate_ran("trust_enforcement::refused_credential_is_not_presented_on_every_request");
}

/// A node that lost a member's admission (restart without its WoT state) answers "not admitted";
/// the client handshakes once more and the put is stored.
#[test]
fn client_rehandshakes_after_lost_admission() {
    let mut node = spawn_daemon("rehandshake");
    let c = client(&key(0xAC));
    let (sid, bytes) = shard(0x34, 512);
    assert!(stored(
        &c.send_request(&node.addr, put_shard("", sid, bytes, None))
            .unwrap()
    ));
    node.restart_daemon_without_wot_state();
    let (sid, bytes) = shard(0x35, 512);
    let resp = c
        .send_request(&node.addr, put_shard("", sid, bytes, None))
        .unwrap();
    assert!(stored(&resp), "{resp:?}\n{}", node.log_text());
    gate_ran("trust_enforcement::client_rehandshakes_after_lost_admission");
}

// --- F-28: joining a ring by invitation; no silent genesis ------------------------------------------

/// Runs `parvault --data-dir <dir> --no-lan-discovery <args>` with no ring genesis in the
/// environment (unless `ring_env`).
fn parvault_cli(dir: &Path, ring_env: bool, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    if ring_env {
        cmd.env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED));
    } else {
        cmd.env_remove("PARVAULT_GENESIS_SEED_HEX");
    }
    cmd.env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .env("PARVAULT_LAN_REGISTRY_DIR", dir.join("lan-registry"))
        .arg("--data-dir")
        .arg(dir)
        .arg("--no-lan-discovery")
        .args(args)
        .output()
        .unwrap()
}

fn out_text(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// An invitee joins by `wot invite` / `wot install-chain` (it never holds the genesis secret),
/// runs as a server, stores a ring member's shard and refuses a stranger's.
#[test]
fn invitee_serves_the_ring() {
    let root = temp_root("b2-invitee");
    let holder = root.path().join("holder");
    let (inv_root, inv_dir, reg, log) = prepare("b2-invitee-node");
    let inv_key = NodeIdentity::load_or_generate_in_dir(&inv_dir).unwrap();
    let invite = parvault_cli(
        &holder,
        true,
        &[
            "wot",
            "invite",
            "--peer",
            &hex::encode(inv_key.public_key_bytes()),
        ],
    );
    assert!(invite.status.success(), "{}", out_text(&invite));
    let token = String::from_utf8_lossy(&invite.stdout).trim().to_string();
    let install = parvault_cli(
        &inv_dir,
        false,
        &["wot", "install-chain", "--token", &token],
    );
    assert!(install.status.success(), "{}", out_text(&install));
    assert!(inv_dir.join("ring_genesis.pub").exists());
    assert!(!inv_dir.join("ring_genesis.seed").exists());
    let port = free_port();
    let node = spawn_without_ring_env(
        daemon_command(&inv_dir, &reg, port),
        inv_root,
        inv_dir,
        log,
        port,
    );
    let (sid, bytes) = shard(0x41, 512);
    let member = send(&key(0xD8), &node, put_shard("", sid, bytes, None));
    assert!(stored(&member), "{member:?}\n{}", node.log_text());
    let (sid, bytes) = shard(0x42, 512);
    let stranger = send_as_stranger(&key(0xD9), &node, put_shard("", sid, bytes, None));
    assert_eq!(
        refusal_text(&stranger).as_deref(),
        Some(NOT_ADMITTED),
        "{stranger:?}"
    );
    assert!(
        !node.dir.join("ring_genesis.seed").exists(),
        "no genesis was generated"
    );
    gate_ran("trust_enforcement::invitee_serves_the_ring");
}

/// A node with no ring refuses to start its daemon, with the message that says what to do.
#[test]
fn daemon_without_ring_refuses_to_start() {
    let root = temp_root("b2-fresh-daemon");
    let out = common::output_within_deadline(
        Command::new(env!("CARGO_BIN_EXE_parvault"))
            .env_remove("PARVAULT_GENESIS_SEED_HEX")
            .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
            .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
            .arg("--data-dir")
            .arg(root.path().join("d"))
            .args(["--no-lan-discovery", "daemon", "start", "--listen"])
            .arg(format!("/ip4/127.0.0.1/tcp/{}", free_port())),
    );
    let text = out_text(&out);
    assert!(!out.status.success(), "{text}");
    assert!(
        text.contains("not in a ring") && text.contains("parvault wot init"),
        "{text}"
    );
    assert!(!root.path().join("d/ring_genesis.seed").exists());
    gate_ran("trust_enforcement::daemon_without_ring_refuses_to_start");
}

/// `file store` on a node with no ring credential stops with the same message instead of
/// failing on every shard.
#[test]
fn file_store_without_ring_says_so() {
    let node = spawn_daemon("b2-fresh-client-target");
    let root = temp_root("b2-fresh-client");
    let file = root.path().join("doc.txt");
    std::fs::write(&file, b"no ring yet").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env_remove("PARVAULT_GENESIS_SEED_HEX")
        .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .env("PARVAULT_PEERS", &node.addr)
        .arg("--data-dir")
        .arg(root.path().join("client"))
        .args(["--no-lan-discovery", "file", "store", "--path"])
        .arg(&file)
        .output()
        .unwrap();
    let text = out_text(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("not in a ring"), "{text}");
    gate_ran("trust_enforcement::file_store_without_ring_says_so");
}

/// `wot invite` needs a genesis from an explicit `wot init`; `wot init` runs once.
#[test]
fn wot_invite_needs_an_initialised_ring() {
    let root = temp_root("b2-init");
    let dir = root.path().join("n");
    let peer = hex::encode(key(0xDA).public_key_bytes());
    let no_ring = parvault_cli(&dir, false, &["wot", "invite", "--peer", &peer]);
    assert!(!no_ring.status.success(), "{}", out_text(&no_ring));
    assert!(out_text(&no_ring).contains("does not hold a ring genesis"));
    let init = parvault_cli(&dir, false, &["wot", "init"]);
    assert!(init.status.success(), "{}", out_text(&init));
    let again = parvault_cli(&dir, false, &["wot", "init"]);
    assert!(!again.status.success(), "{}", out_text(&again));
    let invite = parvault_cli(&dir, false, &["wot", "invite", "--peer", &peer]);
    assert!(invite.status.success(), "{}", out_text(&invite));
    gate_ran("trust_enforcement::wot_invite_needs_an_initialised_ring");
}

/// A daemon whose genesis sources disagree (a pinned ring and another key in the environment)
/// refuses to start.
#[test]
fn conflicting_genesis_sources_refuse_to_start() {
    let root = temp_root("b2-conflict");
    let dir = root.path().join("n");
    assert!(parvault_cli(&dir, false, &["wot", "init"]).status.success());
    let out = common::output_within_deadline(
        Command::new(env!("CARGO_BIN_EXE_parvault"))
            .env("PARVAULT_GENESIS_PUBKEY_HEX", hex::encode([0x11u8; 32]))
            .env_remove("PARVAULT_GENESIS_SEED_HEX")
            .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
            .arg("--data-dir")
            .arg(&dir)
            .args(["--no-lan-discovery", "daemon", "start", "--listen"])
            .arg(format!("/ip4/127.0.0.1/tcp/{}", free_port())),
    );
    let text = out_text(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("conflicting ring genesis sources"), "{text}");
    gate_ran("trust_enforcement::conflicting_genesis_sources_refuse_to_start");
}

// --- W-01: the recovery phrase is opt-in at backup time ---------------------------------------

/// A ring-member client on `dir` (working directory `cwd`) that reaches only `peers`.
fn phrase_client(dir: &Path, cwd: &Path, peers: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.current_dir(cwd)
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .env_remove("PARVAULT_SEED_PHRASE")
        .env("PARVAULT_LAN_REGISTRY_DIR", cwd.join("lan-registry"))
        .env_remove("PARVAULT_PEERS")
        .arg("--data-dir")
        .arg(dir)
        .arg("--no-lan-discovery");
    if !peers.is_empty() {
        cmd.env("PARVAULT_PEERS", peers);
    }
    cmd
}

const W01_NS: &str = "laptop";

fn w01_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("notes.txt", b"house fire drill".to_vec()),
        (
            "docs/plan.bin",
            (0..70_000u32).map(|i| (i % 251) as u8).collect(),
        ),
    ]
}

/// Backs up a folder from a fresh client into `node`, with the phrase in `PARVAULT_SEED_PHRASE`
/// if `phrase` is set (the documented commands). Returns the client's root directory.
fn w01_backup(node: &Node, label: &str, phrase: Option<&str>) -> TempDir {
    let root = temp_root(label);
    let folder = root.path().join("Documents");
    for (rel, bytes) in w01_files() {
        let p = folder.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    let mut cmd = phrase_client(&root.path().join("data"), root.path(), &node.addr);
    if let Some(p) = phrase {
        cmd.env("PARVAULT_SEED_PHRASE", p);
    }
    let out = cmd
        .arg("watch-folder")
        .arg("--folder")
        .arg(&folder)
        .args(["--once", "--vault-namespace", W01_NS])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", out_text(&out));
    root
}

/// Runs `recover-from-seed` from a fresh data directory into `<root>/Recovered`.
fn w01_recover(
    node: &Node,
    label: &str,
    phrase: &str,
    ns: &str,
) -> (TempDir, std::process::Output) {
    let root = temp_root(label);
    let out = phrase_client(&root.path().join("data"), root.path(), &node.addr)
        .env("PARVAULT_SEED_PHRASE", phrase)
        .args(["recover-from-seed", "--vault-namespace", ns, "--out-dir"])
        .arg(root.path().join("Recovered"))
        .output()
        .unwrap();
    (root, out)
}

fn assert_nothing_recovered(root: &TempDir) {
    let out_dir = root.path().join("Recovered");
    let empty = !out_dir.exists() || std::fs::read_dir(&out_dir).unwrap().next().is_none();
    assert!(empty, "files were written to {}", out_dir.display());
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// W-01 test 1: `init` prints no phrase and no recovery line, and a second `init` leaves the
/// sealed master key unchanged.
#[test]
fn w01_init_prints_no_phrase() {
    let root = temp_root("w01-init");
    let dir = root.path().join("n");
    let first = parvault_cli(&dir, false, &["init"]);
    assert!(first.status.success(), "{}", out_text(&first));
    let sealed = std::fs::read(dir.join("master_key.sealed")).unwrap();
    let second = parvault_cli(&dir, false, &["init"]);
    assert!(second.status.success(), "{}", out_text(&second));
    for out in [&first, &second] {
        let text = out_text(out);
        assert!(
            !text.contains("Recovery") && !text.contains("Mnemonic"),
            "{text}"
        );
        for line in text.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            let phrase_like = words.len() >= 12
                && words
                    .iter()
                    .all(|w| w.chars().all(|c| c.is_ascii_lowercase()));
            assert!(!phrase_like, "init printed a phrase: {line}");
        }
    }
    assert_eq!(
        std::fs::read(dir.join("master_key.sealed")).unwrap(),
        sealed
    );
}

/// W-01 test 2: a folder backed up with the phrase is recovered byte for byte into a fresh
/// data directory with the documented commands.
#[test]
fn w01_phrase_backup_recovers_byte_identical() {
    let node = spawn_daemon("w01-rec");
    let _backup = w01_backup(&node, "w01-rec-a", Some(PHRASE));
    let (root, out) = w01_recover(&node, "w01-rec-b", PHRASE, W01_NS);
    assert!(out.status.success(), "{}", out_text(&out));
    for (rel, bytes) in w01_files() {
        assert_eq!(
            std::fs::read(root.path().join("Recovered").join(rel)).unwrap(),
            bytes,
            "{rel}"
        );
    }
}

/// W-01: a folder backed up with the phrase restores with `restore-folder` and the same phrase
/// and namespace (the QUICKSTART step 4 commands).
#[test]
fn w01_restore_folder_with_phrase() {
    let node = spawn_daemon("w01-restore");
    let backup = w01_backup(&node, "w01-restore-a", Some(PHRASE));
    let out = phrase_client(&backup.path().join("data"), backup.path(), &node.addr)
        .env("PARVAULT_SEED_PHRASE", PHRASE)
        .args([
            "restore-folder",
            "--snapshot",
            "./folder_snapshot.manifest.bin",
            "--vault-namespace",
            W01_NS,
            "--out-dir",
            "./restored-docs",
            "--file",
            "notes.txt",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", out_text(&out));
    assert_eq!(
        std::fs::read(backup.path().join("restored-docs/notes.txt")).unwrap(),
        b"house fire drill"
    );
}

/// W-01 test 3: a wrong phrase or namespace fails and writes nothing.
#[test]
fn w01_wrong_phrase_or_namespace_recovers_nothing() {
    let node = spawn_daemon("w01-wrong");
    let _backup = w01_backup(&node, "w01-wrong-a", Some(PHRASE));
    let other = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    for (label, phrase, ns) in [
        ("w01-wrong-p", other, W01_NS),
        ("w01-wrong-n", PHRASE, "desktop"),
    ] {
        let (root, out) = w01_recover(&node, label, phrase, ns);
        assert!(!out.status.success(), "{label}: {}", out_text(&out));
        assert_nothing_recovered(&root);
    }
}

/// W-01 test 4: a vault backed up without a phrase cannot be recovered from one, and the
/// command fails cleanly.
#[test]
fn w01_vault_without_phrase_is_not_recoverable() {
    let node = spawn_daemon("w01-nophrase");
    let _backup = w01_backup(&node, "w01-nophrase-a", None);
    let (root, out) = w01_recover(&node, "w01-nophrase-b", PHRASE, W01_NS);
    let text = out_text(&out);
    assert!(!out.status.success(), "{text}");
    assert!(!text.contains("panicked"), "{text}");
    assert_nothing_recovered(&root);
}

/// W-01 test 5: the phrase is written nowhere: not in the data directory, the snapshot, the
/// catalog or `config.toml`.
#[test]
fn w01_phrase_is_never_stored() {
    let node = spawn_daemon("w01-store");
    let backup = w01_backup(&node, "w01-store-a", Some(PHRASE));
    let files = files_under(backup.path());
    assert!(
        files
            .iter()
            .any(|p| p.to_string_lossy().ends_with(".manifest.bin")),
        "{files:?}"
    );
    for p in files.iter().chain(files_under(&node.dir).iter()) {
        let bytes = std::fs::read(p).unwrap();
        let found = bytes.windows(PHRASE.len()).any(|w| w == PHRASE.as_bytes());
        assert!(!found, "the phrase is stored in {}", p.display());
    }
}

/// W-01 test 6 (W-02): `watch-folder` and `file store` never print the master key.
#[test]
fn w01_master_key_is_never_printed() {
    let node = spawn_daemon("w01-mk");
    let root = temp_root("w01-mk-a");
    let key_hex = hex::encode([0x5Au8; 32]);
    let folder = root.path().join("Documents");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"master key must stay secret").unwrap();
    let dir = root.path().join("data");
    let watch = phrase_client(&dir, root.path(), &node.addr)
        .arg("watch-folder")
        .arg("--folder")
        .arg(&folder)
        .args(["--once", "--key-hex", &key_hex])
        .output()
        .unwrap();
    let store = phrase_client(&dir, root.path(), &node.addr)
        .args(["file", "store", "--key-hex", &key_hex])
        .arg(folder.join("a.txt"))
        .output()
        .unwrap();
    for out in [&watch, &store] {
        let text = out_text(out);
        assert!(out.status.success(), "{text}");
        assert!(!text.to_lowercase().contains(&key_hex), "{text}");
        assert!(!text.contains("Master Key (hex)"), "{text}");
    }
}

/// W-01: `--catalog-out` without a phrase is an error (it used to seal under a public constant).
#[test]
fn w01_catalog_out_needs_a_phrase() {
    let root = temp_root("w01-cat");
    let folder = root.path().join("Documents");
    std::fs::create_dir_all(&folder).unwrap();
    let out = phrase_client(&root.path().join("data"), root.path(), "")
        .arg("watch-folder")
        .arg("--folder")
        .arg(&folder)
        .arg("--once")
        .arg("--catalog-out")
        .arg(root.path().join("c.catalog.bin"))
        .output()
        .unwrap();
    let text = out_text(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("--catalog-out needs --seed-phrase"), "{text}");
    assert!(!root.path().join("c.catalog.bin").exists());
}

/// W-03: `watch-folder` on a missing folder exits non-zero.
#[test]
fn w03_missing_folder_fails() {
    let root = temp_root("w03");
    let out = phrase_client(&root.path().join("data"), root.path(), "")
        .arg("watch-folder")
        .arg("--folder")
        .arg(root.path().join("no-such-folder"))
        .arg("--once")
        .output()
        .unwrap();
    let text = out_text(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("does not exist"), "{text}");
}

// --- D1 (2e round 2): gateway stores with a non-ring peer configured ------------------------------

fn other_ring_daemon(label: &str) -> Node {
    let (root, dir, reg, log) = prepare(label);
    let port = free_port();
    let mut cmd = daemon_command(&dir, &reg, port);
    cmd.env("PARVAULT_GENESIS_SEED_HEX", hex::encode([0x99u8; 32]));
    spawn_as_is(cmd, root, dir, log, port)
}

/// Runs a ring node's `up --no-socket --vfs-seed-dir` with `pins` pinned (in that order, as LAN
/// discovery pins them) and waits until the seed folder is ingested.
fn d1_up_with_pins(label: &str, pins: &[&Node]) -> Node {
    let (root, dir, reg, log) = prepare(label);
    let seed_dir = root.path().join("shared");
    std::fs::create_dir_all(&seed_dir).unwrap();
    std::fs::write(
        seed_dir.join("a.txt"),
        b"gateway store with a non-ring peer",
    )
    .unwrap();
    let mut store = parvault::network::KnownPeersStore::load(&dir);
    for n in pins {
        let pid = n.peer_id().to_string();
        store.upsert_pinned_multiaddr(&pid, &format!("{}/p2p/{pid}", n.addr), None, Some("daemon"));
    }
    store.save(&dir).unwrap();
    let port = free_port();
    let webdav = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "up",
            "--no-socket",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{port}"),
            "--vfs-webdav-listen",
            &format!("127.0.0.1:{webdav}"),
            "--vfs-seed-dir",
        ])
        .arg(&seed_dir);
    let node = spawn(cmd, root, dir, log, port);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let text = node.log_text();
        if text.contains("Ingested built-in VFS seed directory") {
            return node;
        }
        assert!(
            !text.contains("not ingested") && Instant::now() < deadline,
            "seed folder not stored:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// D1: with one pinned non-ring peer (first) and one admitted ring peer, the gateway path stores
/// on the ring peer: the refusal means "try the next peer".
#[test]
fn d1_gateway_store_skips_non_ring_peer() {
    let ring_peer = spawn_daemon("d1-ring");
    let other = other_ring_daemon("d1-other");
    let _node = d1_up_with_pins("d1-node", &[&other, &ring_peer]);
    assert!(
        shard_files(&ring_peer.dir) > 0,
        "shards on the admitted ring peer"
    );
    assert_eq!(shard_files(&other.dir), 0, "nothing on the non-ring peer");
}

/// D1: with only a non-ring peer pinned (a fresh ring node on a LAN with other rings), the
/// gateway path keeps the stripe locally instead of failing.
#[test]
fn d1_gateway_store_with_only_non_ring_peers_stays_local() {
    let other = other_ring_daemon("d1-only-other");
    let node = d1_up_with_pins("d1-only-node", &[&other]);
    assert!(shard_files(&node.dir) > 0, "stored locally");
    assert_eq!(shard_files(&other.dir), 0, "nothing on the non-ring peer");
    // R3-1: the long-running mode says the data is not backed up and records the stripes.
    let log = node.log_text();
    assert!(
        log.contains("kept only on this machine: NOT backed up"),
        "{log}"
    );
    let listed = std::fs::read_to_string(
        node.dir
            .join(parvault::storage::local_only::LOCAL_ONLY_STRIPES_FILE),
    )
    .unwrap_or_default();
    assert!(
        listed.lines().any(|l| l.len() == 64),
        "local-only list: {listed:?}"
    );
}

/// R3-1: runs `watch-folder --once` on a ring node whose only pinned peer belongs to another
/// ring, so every stripe stays on this machine. Returns (exit code, stdout).
fn r3_watch_once_with_only_non_ring_peer(label: &str, extra: &[&str]) -> (Option<i32>, String) {
    let other = other_ring_daemon(&format!("{label}-other"));
    let (root, dir, reg, _log) = prepare(label);
    let folder = root.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"never left this machine").unwrap();
    let mut store = parvault::network::KnownPeersStore::load(&dir);
    let pid = other.peer_id().to_string();
    store.upsert_pinned_multiaddr(
        &pid,
        &format!("{}/p2p/{pid}", other.addr),
        None,
        Some("daemon"),
    );
    store.save(&dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .arg("--data-dir")
        .arg(&dir)
        .args(["--no-lan-discovery", "watch-folder", "--once", "--folder"])
        .arg(&folder)
        .arg("--snapshot-out")
        .arg(root.path().join("snap.bin"))
        .args(extra)
        .output()
        .expect("run watch-folder");
    assert_eq!(shard_files(&other.dir), 0, "nothing on the non-ring peer");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// R3-1: a pass that backed nothing up says so and exits with the documented code.
#[test]
fn r3_watch_once_local_only_exits_with_code() {
    let (code, stdout) = r3_watch_once_with_only_non_ring_peer("r3-local-only", &[]);
    assert_eq!(
        code,
        Some(parvault::storage::local_only::EXIT_CODE_LOCAL_ONLY),
        "{stdout}"
    );
    assert!(
        stdout.contains("stripe(s) kept only on this machine: NOT backed up"),
        "{stdout}"
    );
}

/// R3-1: `--allow-local-only` prints the same line and exits 0.
#[test]
fn r3_watch_once_allow_local_only_exits_zero() {
    let (code, stdout) =
        r3_watch_once_with_only_non_ring_peer("r3-allow-local-only", &["--allow-local-only"]);
    assert_eq!(code, Some(0), "{stdout}");
    assert!(
        stdout.contains("kept only on this machine: NOT backed up"),
        "{stdout}"
    );
}

/// A public-commons daemon with no ring: no genesis from the environment or the data dir.
fn spawn_ticket_only_daemon(label: &str) -> Node {
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
    spawn_without_ring_env(cmd, root, dir, log, port)
}

/// F-37: a one-hop chain "signed" by the all-zero key, a small-order Ed25519 point. With
/// `R` = identity and `s` = 0, a non-strict verifier accepts it whenever the challenge hash is
/// 0 mod 4, so the forger varies `issued_at` until its own verifier accepts (about 4 tries).
/// Under strict verification no attempt verifies; the last one is sent anyway.
fn f37_zero_rooted_chain(leaf: &NodeIdentity) -> DelegationChain {
    let zero = [0u8; 32];
    let mut sig_r = [0u8; 32];
    sig_r[0] = 1;
    let sig_s = [0u8; 32];
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&sig_r);
    let base = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut hop = None;
    for t in 0..256u64 {
        let issued = base - t;
        let msg = InvitationHop::canonical_sign_bytes(&zero, &leaf.public_key_bytes(), 1, issued);
        hop = Some(InvitationHop {
            inviter_pubkey: zero,
            invitee_pubkey: leaf.public_key_bytes(),
            depth: 1,
            issued_at_unix_secs: issued,
            sig_r,
            sig_s,
        });
        if NodeIdentity::verify_with_pubkey(&zero, &msg, &sig) {
            break;
        }
    }
    DelegationChain {
        hops: vec![hop.expect("one attempt")],
    }
}

/// F-37: a node outside any ring refuses every chain, including one rooted at the zero key.
#[test]
fn f37_ticket_only_node_refuses_zero_rooted_chain() {
    let node = spawn_ticket_only_daemon("f37-ticket-only");
    let stranger = NodeIdentity::generate();
    let resp = handshake(&stranger, &node, f37_zero_rooted_chain(&stranger));
    assert!(
        !accepted(&resp),
        "forged zero-rooted chain admitted: {resp:?}"
    );
    assert!(
        node.log_text().contains("reject.handshake_no_ring"),
        "{}",
        node.log_text()
    );
}

/// F-37: a ring node still admits a real chain.
#[test]
fn f37_ring_node_admits_real_chain() {
    let node = spawn_daemon("f37-ring");
    let member = NodeIdentity::generate();
    let resp = handshake(&member, &node, chain_for(&member));
    assert!(accepted(&resp), "{resp:?}");
}

/// R3-1: `file store` on a ring node whose only pinned peer belongs to another ring.
#[test]
fn r3_file_store_local_only_exits_with_code() {
    let other = other_ring_daemon("r3-file-other");
    let (root, dir, reg, _log) = prepare("r3-file");
    let file = root.path().join("doc.txt");
    std::fs::write(&file, b"never left this machine").unwrap();
    let mut store = parvault::network::KnownPeersStore::load(&dir);
    let pid = other.peer_id().to_string();
    store.upsert_pinned_multiaddr(
        &pid,
        &format!("{}/p2p/{pid}", other.addr),
        None,
        Some("daemon"),
    );
    store.save(&dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .arg("--data-dir")
        .arg(&dir)
        .args(["--no-lan-discovery", "file", "store", "--path"])
        .arg(&file)
        .output()
        .expect("run file store");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(parvault::storage::local_only::EXIT_CODE_LOCAL_ONLY),
        "{stdout}"
    );
    assert!(
        stdout.contains("kept only on this machine: NOT backed up"),
        "{stdout}"
    );
    assert_eq!(shard_files(&other.dir), 0, "nothing on the non-ring peer");
}

/// R3-1: `parvault-sync push` through a gateway with no ring peer exits with the code, and the
/// count crosses the socket (`IpcResponse::StoreSuccessLocalOnly`).
#[test]
fn r3_sync_push_local_only_exits_with_code() {
    let (root, dir, reg, log) = prepare("r3-push");
    let sock = root.path().join("gw.sock");
    let folder = root.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"pushed but not backed up").unwrap();
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "up",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{port}"),
            "--ipc-socket",
        ])
        .arg(&sock);
    let _node = spawn(cmd, root, dir, log, port);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "gateway socket never appeared");
        std::thread::sleep(Duration::from_millis(100));
    }
    let push = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_parvault-sync"))
            .arg("--socket")
            .arg(&sock)
            .arg("--catalog")
            .arg(sock.with_file_name(format!("catalog{}.bin", extra.len())))
            .args(["push", "--folder"])
            .arg(&folder)
            .args(extra)
            .output()
            .expect("run parvault-sync push")
    };
    let out = push(&[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(parvault::storage::local_only::EXIT_CODE_LOCAL_ONLY),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("kept only on this machine: NOT backed up"),
        "{stdout}"
    );
    let out = push(&["--allow-local-only"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
