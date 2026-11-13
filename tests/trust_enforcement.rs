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

fn spawn(mut cmd: Command, root: TempDir, dir: PathBuf, log: PathBuf) -> Node {
    cmd.env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED));
    spawn_as_is(cmd, root, dir, log)
}

/// Like `spawn`, but the binary gets no ring genesis from the environment.
fn spawn_without_ring_env(mut cmd: Command, root: TempDir, dir: PathBuf, log: PathBuf) -> Node {
    cmd.env_remove("PARVAULT_GENESIS_SEED_HEX");
    spawn_as_is(cmd, root, dir, log)
}

/// Spawns a daemon told to listen on `common::LOOPBACK_EPHEMERAL`; `addr` is the address it
/// reports binding (never a port reserved and released first: see `common::LOOPBACK_EPHEMERAL`).
fn spawn_as_is(mut cmd: Command, root: TempDir, dir: PathBuf, log: PathBuf) -> Node {
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
        addr: String::new(),
        _root: root,
    };
    let log_path = node.log.clone();
    node.addr = common::wait_for_listen_addr(
        &mut node.child,
        || std::fs::read_to_string(&log_path).unwrap_or_default(),
        Duration::from_secs(20),
    );
    wait_for_port(common::tcp_port_of(&node.addr));
    node
}

/// `parvault daemon start` on loopback with LAN discovery off, provisioned with the ring genesis.
fn daemon_command(dir: &Path, reg: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", reg)
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

fn spawn_daemon(label: &str) -> Node {
    let (root, dir, reg, log) = prepare(label);
    let cmd = daemon_command(&dir, &reg);
    spawn(cmd, root, dir, log)
}

impl Node {
    /// Restarts this daemon on the same data directory (on a new ephemeral port, which `addr`
    /// then names), first deleting its persisted Web-of-Trust state (as if its admissions were
    /// lost).
    fn restart_daemon_without_wot_state(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(self.dir.join("wot_state.bin"));
        let reg = self.dir.parent().unwrap().join("lan-registry");
        let offset = self.log_text().len();
        let log_file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.log)
            .unwrap();
        self.child = daemon_command(&self.dir, &reg)
            .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
            .env("RUST_LOG", "info")
            .env("NO_COLOR", "1")
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file))
            .spawn()
            .unwrap();
        let log = self.log.clone();
        self.addr = common::wait_for_listen_addr(
            &mut self.child,
            || {
                let text = std::fs::read_to_string(&log).unwrap_or_default();
                text.get(offset..).unwrap_or_default().to_string()
            },
            Duration::from_secs(20),
        );
        wait_for_port(common::tcp_port_of(&self.addr));
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// `parvault --public daemon start`: public-commons mode (tickets admit strangers).
fn spawn_public_daemon(label: &str) -> Node {
    let (root, dir, reg, log) = prepare(label);
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
            common::LOOPBACK_EPHEMERAL,
        ]);
    spawn(cmd, root, dir, log)
}

/// `parvault-seed start --mode homelab-vault` on loopback, provisioned with the ring genesis. Its
/// owner key is the PQ keypair in its data directory (pre-created by `prepare`).
fn spawn_seed(label: &str) -> Node {
    spawn_seed_with_peers(label, &[])
}

/// `spawn_seed` with `--peers` (the mesh peers it syndicates to).
fn spawn_seed_with_peers(label: &str, peers: &[&str]) -> Node {
    let (root, dir, reg, log) = prepare(label);
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
            common::LOOPBACK_EPHEMERAL,
            "--data-dir",
        ])
        .arg(&dir);
    spawn(cmd, root, dir, log)
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

/// Ticket bits: a client whose default ticket is below the node's bits learns
/// `required_pow_bits` from the refusal, re-mints once, and is admitted (its shard is stored).
/// The refusal is deterministic: the node compares the ticket's declared `pow_bits` with its own
/// before it checks the hash (`PublicCommonsTicket::verify`), so a ticket declaring one bit less
/// is always refused, however many leading zeros its digest happens to have.
#[test]
fn ticket_client_remints_at_required_bits() {
    let node = spawn_public_daemon("tbits-a");
    let stranger = key(0xA6);
    let c = MeshClient::new(stranger.clone(), Vec::new(), None)
        .with_admission(AdmissionSource::default().with_public_tickets(0));
    // A `/p2p/` address states the verifier key, so the only refusal is for the bits.
    let addr = format!("{}/p2p/{}", node.addr, node.peer_id());
    let (sid, bytes) = shard(0x16, 1024);
    let put = c
        .send_request(&addr, put_shard("", sid, bytes, None))
        .unwrap();
    assert!(stored(&put), "{put:?}\n{}", node.log_text());
    assert_logged(&node, "reject.ticket_insufficient_pow");
    gate_ran("trust_enforcement::ticket_client_remints_at_required_bits");
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
    // The seed re-uploads all n shards to its peer inside the request before it answers, which
    // can exceed the client's default 1.2 s under a loaded gate run: allow 10 s.
    let resp = send_with(
        client(&device).with_timeout(Duration::from_secs(10)),
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

/// A 2-layer onion through `relay_kem` to a target, with `relay_jitter_ms` at the relay.
fn f33_layered(
    relay: &Node,
    target_kem: &parvault::crypto::HybridKemPublicKey,
    target_addr: String,
    _originator: &NodeIdentity,
    seed: u8,
    relay_jitter_ms: u64,
) -> PqRelayedShardEnvelope {
    let b = blinded(seed, 512);
    let bundle = parvault::crypto::pqc::PqOnionFinalBundle {
        blinded_id: b.id,
        shard_bytes: b.bytes.clone(),
        capability: b.cap,
        // F-24: the target honours only issuers it knows. It knows the relay (admitted at
        // the last hop), not the originator, so the relay issues the voucher here. A voucher
        // the originator issued would name it to the target (L-39; unlinkable vouchers: v0.6.0).
        voucher: AnonymousQuotaVoucher::mint(
            &NodeIdentity::load_or_generate_in_dir(&relay.dir).unwrap(),
            8192,
        ),
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: b.delete_verifier,
    };
    PqRelayedShardEnvelope::seal_layered_pq(
        &relay.kem_public(),
        "relay",
        target_kem,
        target_addr,
        &bundle,
        relay_jitter_ms,
        0,
    )
    .unwrap()
}

fn f33_relay_request(
    envelope: PqRelayedShardEnvelope,
    originator: &NodeIdentity,
) -> MeshWireRequest {
    let b = blinded(0x58, 512);
    MeshWireRequest::RelayPqOnionEnvelope {
        target_peer_addr: None,
        envelope,
        capability: b.cap,
        voucher: AnonymousQuotaVoucher::mint(originator, 8192),
        current_epoch: 1,
        lease_duration_epochs: 30,
        delete_verifier: b.delete_verifier,
    }
}

/// F-33 accept (L-38): a ring member originates a layered onion through `OnionOriginator`; it is
/// admitted at the entry relay (so the relay knows its ring key, as ADR-11 now says), the relay
/// forwards under its own identity, and the target delivers.
#[test]
fn f33_admitted_originator_relayed() {
    provision_process_genesis();
    let relay = spawn_daemon("f33-relay");
    let target = spawn_daemon("f33-target");
    let originator = key(0xF7);
    let layered = f33_layered(
        &relay,
        &target.kem_public(),
        target.addr.clone(),
        &originator,
        0x57,
        0,
    );
    parvault::network::OnionOriginator::new(originator.clone(), Vec::new())
        .send_layered_onion(&relay.addr, layered)
        .unwrap_or_else(|e| panic!("{e}\nrelay log:\n{}", relay.log_text()));
    assert!(
        !relay.log_text().contains("reject.peer_not_admitted"),
        "{}",
        relay.log_text()
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
    gate_ran("trust_enforcement::f33_admitted_originator_relayed");
}

/// F-33 reject (L-38): an originator without a chain is refused at the entry relay; nothing is
/// forwarded (no open relay).
#[test]
fn f33_unadmitted_originator_refused() {
    let relay = spawn_daemon("f33-relay-r");
    let target = spawn_daemon("f33-target-r");
    let originator = key(0xF3);
    let layered = f33_layered(
        &relay,
        &target.kem_public(),
        target.addr.clone(),
        &originator,
        0x54,
        0,
    );
    let resp = send_as_stranger(&originator, &relay, f33_relay_request(layered, &originator));
    assert_eq!(
        refusal_text(&resp).as_deref(),
        Some(NOT_ADMITTED),
        "{resp:?}"
    );
    assert_logged(&relay, "reject.peer_not_admitted");
    let relay_id = relay.peer_id().to_string();
    assert!(
        !target.log_text().contains(&relay_id),
        "the relay forwarded:\n{}",
        target.log_text()
    );
    gate_ran("trust_enforcement::f33_unadmitted_originator_refused");
}

/// F-33 budget accept: one forward from an admitted originator is within budget and delivered.
#[test]
fn f33_relay_within_budget_forwarded() {
    let relay = spawn_daemon("f33-budget-a");
    let target = spawn_daemon("f33-budget-target");
    let originator = key(0xF8);
    let layered = f33_layered(
        &relay,
        &target.kem_public(),
        target.addr.clone(),
        &originator,
        0x59,
        0,
    );
    let resp = send(&originator, &relay, f33_relay_request(layered, &originator));
    assert!(
        matches!(
            resp,
            MeshWireResponse::RelayPqOnionAck {
                delivered: true,
                ..
            }
        ),
        "{resp:?}\nrelay log:\n{}",
        relay.log_text()
    );
    assert!(!relay.log_text().contains("reject.relay_budget"));
    gate_ran("trust_enforcement::f33_relay_within_budget_forwarded");
}

/// F-33 budget reject: an admitted originator with more forwards in flight than the per-sender
/// budget is refused, not queued. The forwards wait on a 250 ms jitter and a next hop that never
/// answers (a blackhole address), so they stay in flight while the extra requests arrive.
#[test]
fn f33_relay_over_budget_refused() {
    let relay = spawn_daemon("f33-budget-r");
    let originator = key(0xF9);
    let blackhole_target = key(0xFA);
    let target_kem = HybridKemKeypair::generate().unwrap().public_key();
    let target_addr = format!(
        "/ip4/10.255.255.1/tcp/9/p2p/{}",
        node_identity_libp2p_peer_id(&blackhole_target).unwrap()
    );
    // Admit the originator first, so every concurrent request goes straight to the relay arm.
    let warm = f33_layered(
        &relay,
        &target_kem,
        target_addr.clone(),
        &originator,
        0x60,
        0,
    );
    let _ = client(&originator).send_request(&relay.addr, f33_relay_request(warm, &originator));
    let n = parvault::network::server_events::MAX_INFLIGHT_RELAYS_PER_PEER + 4;
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let req = f33_relay_request(
                f33_layered(
                    &relay,
                    &target_kem,
                    target_addr.clone(),
                    &originator,
                    0x61 + i as u8,
                    250,
                ),
                &originator,
            );
            let c = client(&originator);
            let addr = relay.addr.clone();
            std::thread::spawn(move || c.send_request(&addr, req).ok())
        })
        .collect();
    let busy = handles
        .into_iter()
        .filter_map(|h| h.join().unwrap())
        .filter(|r| {
            refusal_text(r).as_deref() == Some(parvault::network::server_events::RELAY_BUSY_TEXT)
        })
        .count();
    assert!(
        busy > 0,
        "no forward was refused\nrelay log:\n{}",
        relay.log_text()
    );
    assert_logged(&relay, "reject.relay_budget");
    gate_ran("trust_enforcement::f33_relay_over_budget_refused");
}

// --- F-23: lease renewal needs the capability key -----------------------------------------------------

fn put_for_renew(label: &str) -> (Node, Blinded, NodeIdentity) {
    let node = spawn_daemon(label);
    let uploader = key(0xF3);
    let b = blinded(0x53, 512);
    let resp = send(&uploader, &node, blinded_put(&b, &uploader));
    assert!(format!("{resp:?}").contains("stored: true"), "{resp:?}");
    let mk = MasterKey::from_bytes([0x53; 32]);
    let (cap_ident, _) = BlindedShardCapability::derive_keypair(&mk, &b.id.locator);
    (node, b, cap_ident)
}

fn renew_signed_by(b: &Blinded, signer: &NodeIdentity) -> MeshWireRequest {
    let ts = now_ms();
    MeshWireRequest::RenewBlindedLeaseSigned {
        blinded_id: b.id,
        current_epoch: 2,
        extension_epochs: 10,
        timestamp_ms: ts,
        sig: BlindedShardCapability::sign_lease_renewal(signer, &b.id.locator, 2, 10, ts).to_vec(),
    }
}

fn renewed(resp: &MeshWireResponse) -> bool {
    matches!(
        resp,
        MeshWireResponse::RenewBlindedLeaseAck { renewed: true }
    )
}

/// F-23 accept: the capability holder's signed renewal is applied.
#[test]
fn f23_capability_holder_renews() {
    let (node, b, cap_ident) = put_for_renew("f23-a");
    let resp = send(&key(0xF4), &node, renew_signed_by(&b, &cap_ident));
    assert!(renewed(&resp), "{resp:?}");
    gate_ran("trust_enforcement::f23_capability_holder_renews");
}

/// F-23 reject: a renewal signed by any other key is refused, and so is the unsigned variant.
#[test]
fn f23_stranger_renew_refused() {
    let (node, b, _) = put_for_renew("f23-r");
    let stranger = key(0xF4);
    let resp = send(&stranger, &node, renew_signed_by(&b, &stranger));
    assert!(!renewed(&resp), "{resp:?}");
    let legacy = send(
        &stranger,
        &node,
        MeshWireRequest::RenewBlindedLease {
            blinded_id: b.id,
            current_epoch: 2,
            extension_epochs: 10,
        },
    );
    assert!(!renewed(&legacy), "{legacy:?}");
    assert_logged(&node, "reject.renew_capability_invalid");
    gate_ran("trust_enforcement::f23_stranger_renew_refused");
}

// --- F-22: rendezvous registration before admission -------------------------------------------------------

/// A signed rendezvous registration for `signer` under `code`.
fn f22_register(signer: &NodeIdentity, code: &str) -> MeshWireRequest {
    let card = WanPeerCard::new(
        signer,
        "probe",
        "daemon",
        vec!["/ip4/203.0.113.9/tcp/4001".into()],
        None,
        None,
        3600,
        now_ms(),
    )
    .unwrap();
    MeshWireRequest::RegisterWanRendezvous {
        slot_key: derive_slot_key_from_code(code),
        entry: seal_wan_peer_card(code, &card, signer).unwrap(),
    }
}

/// F-22 accept: registration stays pre-admission (pairing needs it), so a stranger's entry
/// within quota is stored.
#[test]
fn f22_rendezvous_within_quota_stored() {
    let node = spawn_daemon("f22-a");
    let stranger = key(0xF5);
    let resp = send(
        &stranger,
        &node,
        f22_register(&stranger, "quiet-river-stone-lamp"),
    );
    assert!(
        matches!(
            resp,
            MeshWireResponse::RegisterWanRendezvousAck { stored: true, .. }
        ),
        "{resp:?}"
    );
    gate_ran("trust_enforcement::f22_rendezvous_within_quota_stored");
}

/// F-22 reject: a signer holding 8 slots cannot register a 9th.
#[test]
fn f22_rendezvous_over_quota_refused() {
    let node = spawn_daemon("f22-r");
    let stranger = key(0xF5);
    for i in 0..parvault::network::wan_rendezvous::MAX_RENDEZVOUS_SLOTS_PER_SIGNER {
        let resp = send(
            &stranger,
            &node,
            f22_register(&stranger, &format!("slot-{i}-code")),
        );
        assert!(
            matches!(
                resp,
                MeshWireResponse::RegisterWanRendezvousAck { stored: true, .. }
            ),
            "slot {i}: {resp:?}"
        );
    }
    let resp = send(
        &stranger,
        &node,
        f22_register(&stranger, "one-slot-too-many"),
    );
    assert!(
        matches!(
            resp,
            MeshWireResponse::RegisterWanRendezvousAck { stored: false, .. }
        ),
        "{resp:?}"
    );
    assert_logged(&node, "reject.rendezvous_quota");
    gate_ran("trust_enforcement::f22_rendezvous_over_quota_refused");
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

/// PQ-DHT reject: a post-quantum manifest cannot be bound to the reading owner (no owner PQ key
/// is bound to an identity yet), so the reader refuses it even when it is self-consistent and an
/// admitted peer serves it.
#[test]
fn pqdht_unbindable_pq_manifest_refused() {
    let node = spawn_daemon("pqdht-r");
    let member = key(0xC8);
    let canonical = parvault::crypto::validate_recovery_seed_phrase_or_passphrase(PHRASE).unwrap();
    let pq = PqVaultMasterKey::from_recovery_seed_phrase(&canonical, "default");
    let signer = HybridPqSigningKeypair::generate().unwrap();
    let dht_key = [0x78; 32];
    let env = parvault::crypto::pqc::PqSignedDhtManifestEnvelope::seal_pq(
        &pq,
        &signer,
        dht_key,
        1,
        b"manifest",
    )
    .unwrap();
    let put = send(
        &member,
        &node,
        MeshWireRequest::PutDhtEnvelope(DhtWireEnvelope::PostQuantumManifest(env)),
    );
    assert!(
        matches!(
            put,
            MeshWireResponse::PutDhtEnvelopeAck { stored: true, .. }
        ),
        "{put:?}"
    );
    let reader = MeshClient::new(member.clone(), vec![node.addr.clone()], None)
        .with_admission(AdmissionSource::from_genesis(genesis()));
    let got = reader.get_dht_envelope(
        &dht_key,
        parvault::network::DhtEnvelopeKind::PostQuantumManifest,
    );
    assert!(got.is_err(), "a PQ manifest was accepted");
    gate_ran("trust_enforcement::pqdht_unbindable_pq_manifest_refused");
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
    let node = spawn_without_ring_env(daemon_command(&inv_dir, &reg), inv_root, inv_dir, log);
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
            .arg(common::LOOPBACK_EPHEMERAL),
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
            .arg(common::LOOPBACK_EPHEMERAL),
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

// --- 2c reproductions: each asserts today's gap; its fix rewrites it into a claim pair ----------

fn order_accepted(resp: &MeshWireResponse) -> bool {
    matches!(
        resp,
        MeshWireResponse::EvictionOrderAck { accepted: true, .. }
    )
}

fn ban_ip(last: u8) -> parvault::storage::EvictionTarget {
    parvault::storage::EvictionTarget::IpAddress(format!("192.0.2.{last}").parse().unwrap())
}

/// F-09 accept: a fresh, bounded order for the installed council epoch is applied once.
#[test]
fn f09_fresh_order_applied() {
    let node = spawn_daemon("f09-a");
    let out = council_cli(&node, &council_init_args(&[genesis()], 1));
    assert!(out.status.success(), "{}", combined(&out));
    let order = council_order(&[&genesis()], ban_ip(91), 1);
    let resp = send(
        &key(0x91),
        &node,
        MeshWireRequest::BroadcastEvictionOrder(order),
    );
    assert!(order_accepted(&resp), "{resp:?}\n{}", node.log_text());
    gate_ran("trust_enforcement::f09_fresh_order_applied");
}

/// F-09 reject: the same council refuses an order issued 400 days ago with no expiry, and a
/// replay of an applied order.
#[test]
fn f09_stale_or_replayed_order_refused() {
    let node = spawn_daemon("f09-r");
    let out = council_cli(&node, &council_init_args(&[genesis()], 1));
    assert!(out.status.success(), "{}", combined(&out));
    let issued = now_ms() - 400 * 24 * 3600 * 1000;
    let stale = parvault::storage::SignedBadActorEvictionOrder::issue(
        &genesis(),
        ban_ip(92),
        "stale",
        issued,
        0,
        1,
    );
    let resp = send(
        &key(0x91),
        &node,
        MeshWireRequest::BroadcastEvictionOrder(stale),
    );
    assert!(!order_accepted(&resp), "{resp:?}");
    assert_logged(&node, "reject.order_stale");
    let fresh = council_order(&[&genesis()], ban_ip(93), 1);
    let first = send(
        &key(0x91),
        &node,
        MeshWireRequest::BroadcastEvictionOrder(fresh.clone()),
    );
    assert!(order_accepted(&first), "{first:?}");
    let replay = send(
        &key(0x91),
        &node,
        MeshWireRequest::BroadcastEvictionOrder(fresh),
    );
    assert!(!order_accepted(&replay), "{replay:?}");
    assert_logged(&node, "reject.order_replayed");
    gate_ran("trust_enforcement::f09_stale_or_replayed_order_refused");
}

/// Runs `parvault council <args>` on `node`'s data directory as the ring genesis holder.
fn council_cli(node: &Node, args: &[String]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env(
            "PARVAULT_LAN_REGISTRY_DIR",
            node.dir.parent().unwrap().join("lan-registry"),
        )
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .arg("--data-dir")
        .arg(&node.dir)
        .args(["--no-lan-discovery", "council"])
        .args(args)
        .output()
        .expect("run parvault council")
}

/// `council init` arguments for `members` at `quorum`.
fn council_init_args(members: &[NodeIdentity], quorum: usize) -> Vec<String> {
    let mut args = vec!["init".to_string()];
    for m in members {
        args.push("--member".into());
        args.push(hex::encode(m.public_key_bytes()));
    }
    args.push("--quorum".into());
    args.push(quorum.to_string());
    args
}

/// An order against `target` signed by `signers[0]` and co-signed by the rest, for the node's
/// current council epoch.
fn council_order(
    signers: &[&NodeIdentity],
    target: parvault::storage::EvictionTarget,
    council_epoch: u64,
) -> parvault::storage::SignedBadActorEvictionOrder {
    let mut order = parvault::storage::SignedBadActorEvictionOrder::issue(
        signers[0],
        target,
        "council",
        now_ms(),
        now_ms() + 3_600_000,
        council_epoch,
    );
    for s in &signers[1..] {
        assert!(order.add_cosignature(s));
    }
    order
}

/// F-08 accept: with a genesis-signed 2-of-3 council manifest installed, an order signed by two
/// members is applied.
#[test]
fn f08_majority_council_order_applied() {
    let node = spawn_daemon("f08-a");
    let members = [key(0x81), key(0x82), key(0x83)];
    let out = council_cli(&node, &council_init_args(&members, 2));
    assert!(out.status.success(), "{}", combined(&out));
    let order = council_order(&[&members[0], &members[1]], ban_ip(81), 1);
    let resp = send(
        &key(0x84),
        &node,
        MeshWireRequest::BroadcastEvictionOrder(order),
    );
    assert!(order_accepted(&resp), "{resp:?}\n{}", node.log_text());
    gate_ran("trust_enforcement::f08_majority_council_order_applied");
}

/// F-08 reject: a 1-of-3 council (below a majority) is refused at init, so no manifest exists and
/// an order signed by one member alone is refused.
#[test]
fn f08_below_majority_quorum_refused() {
    let node = spawn_daemon("f08-r");
    let members = [key(0x81), key(0x82), key(0x83)];
    let out = council_cli(&node, &council_init_args(&members, 1));
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(
        text.contains("reject.council_quorum_below_majority"),
        "{text}"
    );
    let order = council_order(&[&members[0]], ban_ip(81), 1);
    let resp = send(
        &key(0x84),
        &node,
        MeshWireRequest::BroadcastEvictionOrder(order),
    );
    assert!(!order_accepted(&resp), "{resp:?}");
    gate_ran("trust_enforcement::f08_below_majority_quorum_refused");
}

/// Local owner (1-of-1) applies only on the signing node: a peer with a 2-of-3 council refuses an
/// order signed by the sender's own key, like any order without a manifest quorum.
#[test]
fn council_peer_refuses_another_nodes_local_owner_order() {
    let node = spawn_daemon("f08-lo");
    let members = [key(0x81), key(0x82), key(0x83)];
    let out = council_cli(&node, &council_init_args(&members, 2));
    assert!(out.status.success(), "{}", combined(&out));
    let sender = key(0x85);
    let order = council_order(&[&sender], ban_ip(85), 1);
    let resp = send(
        &sender,
        &node,
        MeshWireRequest::BroadcastEvictionOrder(order),
    );
    assert!(!order_accepted(&resp), "{resp:?}");
    assert_logged(&node, "reject.order_quorum");
}

/// Two daemons of one ring, both at council epoch 1; `ahead` also holds epoch 2 (or, if
/// `forged`, an epoch-2 manifest written to disk that does not chain). `behind` has `ahead` as
/// its peer and has admitted it. Returns `(behind, ahead, members)`.
fn council_pair(label: &str, forged: bool) -> (Node, Node, Vec<NodeIdentity>) {
    use parvault::storage::council::CouncilManifest;
    let members = vec![key(0x81), key(0x82), key(0x83)];
    let ahead = spawn_daemon(&format!("{label}-ahead"));
    let out = council_cli(&ahead, &council_init_args(&members, 2));
    assert!(out.status.success(), "{}", combined(&out));
    let epoch1_hex = String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap()
        .trim()
        .to_string();
    let root = genesis().public_key_bytes();
    let mut next = CouncilManifest::new(
        root,
        2,
        members.iter().map(|m| m.public_key_bytes()).collect(),
        2,
        now_ms(),
    );
    if forged {
        next.sign(&key(0x99));
        next.sign(&key(0x98));
        std::fs::write(ahead.dir.join("council_manifest.bin"), next.to_bytes()).unwrap();
    } else {
        next.sign(&members[0]);
        next.sign(&members[1]);
        let out = council_cli(
            &ahead,
            &[
                "install".into(),
                "--manifest".into(),
                hex::encode(next.to_bytes()),
            ],
        );
        assert!(out.status.success(), "{}", combined(&out));
    }
    let (root_dir, dir, reg, log) = prepare(&format!("{label}-behind"));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "--peers",
            &format!("{}/p2p/{}", ahead.addr, ahead.peer_id()),
            "daemon",
            "start",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
        ]);
    let behind = spawn(cmd, root_dir, dir, log);
    let out = council_cli(
        &behind,
        &["install".into(), "--manifest".into(), epoch1_hex],
    );
    assert!(out.status.success(), "{}", combined(&out));
    // `behind` admits `ahead` when `ahead`'s key handshakes with it.
    let r = send(
        &ahead.identity(),
        &behind,
        MeshWireRequest::GetCouncilManifest {
            scope_root: root,
            from_epoch: 0,
        },
    );
    assert!(
        matches!(&r, MeshWireResponse::CouncilManifestResult { manifests } if !manifests.is_empty()),
        "{r:?}"
    );
    (behind, ahead, members)
}

fn council_epoch_of(node: &Node) -> u64 {
    parvault::storage::council::load_council_manifest(&node.dir).map_or(0, |m| m.epoch)
}

/// An order from council epoch 2 reaching a node at epoch 1 is refused, the node fetches epoch 2
/// from its admitted peer in the background, and the same order is then accepted.
#[test]
fn council_epoch_ahead_order_fetches_and_then_applies() {
    let (behind, _ahead, members) = council_pair("cfetch", false);
    let order = council_order(&[&members[0], &members[1]], ban_ip(86), 2);
    let r = send(
        &key(0x86),
        &behind,
        MeshWireRequest::BroadcastEvictionOrder(order.clone()),
    );
    assert!(!order_accepted(&r), "{r:?}");
    assert_logged(&behind, "reject.order_council_epoch_ahead");
    let deadline = Instant::now() + Duration::from_secs(15);
    while council_epoch_of(&behind) < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(council_epoch_of(&behind), 2, "{}", behind.log_text());
    let r = send(
        &key(0x86),
        &behind,
        MeshWireRequest::BroadcastEvictionOrder(order),
    );
    assert!(order_accepted(&r), "{r:?}\n{}", behind.log_text());
}

/// A fetched manifest that does not chain from the installed epoch is not installed.
#[test]
fn council_fetch_refuses_a_forged_chain() {
    let (behind, _ahead, members) = council_pair("cforge", true);
    let order = council_order(&[&members[0], &members[1]], ban_ip(87), 2);
    let r = send(
        &key(0x87),
        &behind,
        MeshWireRequest::BroadcastEvictionOrder(order),
    );
    assert!(!order_accepted(&r), "{r:?}");
    assert_logged(&behind, "reject.council_epoch_chain");
    assert_eq!(council_epoch_of(&behind), 1);
}

/// F-24 issuer policy accept: an admitted sender's blinded put with a voucher issued by a ring
/// member this node knows (here the sender itself) is stored.
#[test]
fn f24_ring_issuer_voucher_redeemed() {
    let node = spawn_daemon("f24-issuer-a");
    let sender = key(0xA8);
    let b = blinded(0x5A, 512);
    let resp = send(&sender, &node, blinded_put(&b, &sender));
    assert!(format!("{resp:?}").contains("stored: true"), "{resp:?}");
    gate_ran("trust_enforcement::f24_ring_issuer_voucher_redeemed");
}

/// F-24 issuer policy reject: the same admitted sender with a voucher minted by a key this node
/// does not know is refused (a voucher no longer certifies its own issuer).
#[test]
fn f24_stranger_issuer_voucher_refused() {
    let node = spawn_daemon("f24-issuer-r");
    let sender = key(0xA8);
    let stranger_issuer = key(0xA9);
    let b = blinded(0x5A, 512);
    let resp = send(&sender, &node, blinded_put(&b, &stranger_issuer));
    assert!(format!("{resp:?}").contains("stored: false"), "{resp:?}");
    assert_logged(&node, "reject.voucher_issuer_untrusted");
    gate_ran("trust_enforcement::f24_stranger_issuer_voucher_refused");
}

// --- D1 (2e round 2): gateway stores with a non-ring peer configured ------------------------------

fn other_ring_daemon(label: &str) -> Node {
    let (root, dir, reg, log) = prepare(label);
    let mut cmd = daemon_command(&dir, &reg);
    cmd.env("PARVAULT_GENESIS_SEED_HEX", hex::encode([0x99u8; 32]));
    spawn_as_is(cmd, root, dir, log)
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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "up",
            "--no-socket",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
            "--vfs-webdav-listen",
            "127.0.0.1:0",
            "--vfs-seed-dir",
        ])
        .arg(&seed_dir);
    let node = spawn(cmd, root, dir, log);
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
        stdout.contains("Files Synced       : 1"),
        "nothing was stored:\n{stdout}"
    );
    assert!(
        stdout.contains("kept only on this machine: NOT backed up"),
        "{stdout}"
    );
}

/// A public-commons daemon with no ring: no genesis from the environment or the data dir.
fn spawn_ticket_only_daemon(label: &str) -> Node {
    let (root, dir, reg, log) = prepare(label);
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
            common::LOOPBACK_EPHEMERAL,
        ]);
    spawn_without_ring_env(cmd, root, dir, log)
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
    gate_ran("trust_enforcement::f37_ticket_only_node_refuses_zero_rooted_chain");
}

/// F-37: a ring node still admits a real chain.
#[test]
fn f37_ring_node_admits_real_chain() {
    let node = spawn_daemon("f37-ring");
    let member = NodeIdentity::generate();
    let resp = handshake(&member, &node, chain_for(&member));
    assert!(accepted(&resp), "{resp:?}");
    gate_ran("trust_enforcement::f37_ring_node_admits_real_chain");
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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .arg("--data-dir")
        .arg(&dir)
        .args(["--no-lan-discovery", "file", "store", "--path"])
        .arg(&file);
    let out = common::output_within_deadline(&mut cmd);
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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "up",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
            "--ipc-socket",
        ])
        .arg(&sock);
    let _node = spawn(cmd, root, dir, log);
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

/// QA 2e M2: a ring peer whose per-owner grace quota fits only a few shards. The store keeps the
/// shards that reached the peer, writes only the rest locally, lists the stripe (fewer than k
/// remote), exits 3, and restores byte-for-byte. A second store with a roomy peer pinned first
/// places every shard remotely and adds no entry.
#[test]
fn r3_partial_placement_keeps_remote_shards() {
    const TIER_K: usize = 10; // consumer: 10-of-20
    const TIER_N: usize = 20;
    let peer = {
        let (root, dir, reg, log) = prepare("r3-partial-peer");
        std::fs::write(
            dir.join("config.toml"),
            "max_storage_bytes = 1073741824\nbootstrap_grace_bytes = 20000\n",
        )
        .unwrap();
        let cmd = daemon_command(&dir, &reg);
        spawn(cmd, root, dir, log)
    };
    let (root, dir, reg, _log) = prepare("r3-partial-client");
    let file = root.path().join("doc.bin");
    let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&file, &data).unwrap();
    let mut store = parvault::network::KnownPeersStore::load(&dir);
    let pid = peer.peer_id().to_string();
    store.upsert_pinned_multiaddr(
        &pid,
        &format!("{}/p2p/{pid}", peer.addr),
        None,
        Some("daemon"),
    );
    store.save(&dir).unwrap();
    let key_hex = hex::encode([0x4Bu8; 32]);
    let run = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
        cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
            .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
            .arg("--data-dir")
            .arg(&dir)
            .arg("--no-lan-discovery")
            .args(args);
        common::output_within_deadline(&mut cmd)
    };
    let out = run(&[
        "file",
        "store",
        "--tier",
        "consumer",
        "--key-hex",
        &key_hex,
        "--path",
        file.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let remote = shard_files(&peer.dir);
    let local = shard_files(&dir);
    assert!(
        remote > 0 && remote < TIER_K,
        "remote={remote}\n{stdout}\npeer log:\n{}",
        peer.log_text()
    );
    assert_eq!(local, TIER_N - remote, "only the missing shards are local");
    assert_eq!(
        out.status.code(),
        Some(parvault::storage::local_only::EXIT_CODE_LOCAL_ONLY),
        "{stdout}"
    );
    let listed =
        std::fs::read_to_string(dir.join(parvault::storage::local_only::LOCAL_ONLY_STRIPES_FILE))
            .unwrap_or_default();
    assert_eq!(listed.lines().count(), 1, "{listed:?}");
    let root_hex = stdout
        .lines()
        .find_map(|l| l.strip_prefix("File Merkle Root : "))
        .expect("root printed")
        .trim()
        .to_string();
    // The manifest names the peer for each remote shard and this node for each local one.
    let mk = MasterKey::from_hex(&key_hex).unwrap();
    let file_root: [u8; 32] = hex::decode(&root_hex).unwrap().try_into().unwrap();
    let manifest = parvault::storage::BlockStore::new(
        &dir,
        parvault::storage::QuotaManager::new(1 << 30, 1 << 30),
    )
    .unwrap()
    .load_manifest(&mk, &file_root)
    .unwrap();
    assert_eq!(manifest.stripes.len(), 1);
    let assigned = &manifest.stripes[0].assigned_peers;
    let on_peer = assigned.iter().filter(|p| p.contains(&pid)).count();
    assert_eq!(on_peer, remote, "{assigned:?}");
    // Leave fewer than k local shards, so the restore must fetch the remote ones.
    let mut local_files: Vec<_> = std::fs::read_dir(dir.join("shards"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "shard"))
        .collect();
    local_files.sort();
    while local_files.len() >= TIER_K {
        std::fs::remove_file(local_files.pop().unwrap()).unwrap();
    }
    assert!(shard_files(&dir) < TIER_K);
    let restored = root.path().join("restored.bin");
    let out = run(&[
        "file",
        "restore",
        &root_hex,
        "--output",
        restored.to_str().unwrap(),
        "--key-hex",
        &key_hex,
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(&restored).unwrap(),
        data,
        "restore byte-for-byte"
    );

    // A roomy ring peer pinned first takes every shard: no new entry, exit 0.
    let roomy = spawn_daemon("r3-partial-roomy");
    let mut store = parvault::network::KnownPeersStore::load(&dir);
    let rid = roomy.peer_id().to_string();
    store.upsert_pinned_multiaddr(
        &rid,
        &format!("{}/p2p/{rid}", roomy.addr),
        None,
        Some("daemon"),
    );
    store.save(&dir).unwrap();
    let out = run(&[
        "file",
        "store",
        "--tier",
        "consumer",
        "--key-hex",
        &key_hex,
        "--path",
        file.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let listed =
        std::fs::read_to_string(dir.join(parvault::storage::local_only::LOCAL_ONLY_STRIPES_FILE))
            .unwrap_or_default();
    assert_eq!(listed.lines().count(), 1, "no new entry: {listed:?}");
}

/// A syndication of one stripe whose cert names `cert_device` and whose repair grant, if any, is
/// self-signed by `grant_owner`. Returns the request and the stripe's shard 0.
fn f38_syndicate(
    seed: &Node,
    cert_device: &NodeIdentity,
    grant_owner: Option<&NodeIdentity>,
) -> (MeshWireRequest, ShardId) {
    let mut req = syndicate(seed, cert_device);
    let MeshWireRequest::SyndicateLiteStripe {
        bundle,
        repair_grant,
        ..
    } = &mut req
    else {
        unreachable!()
    };
    let root = bundle.expected_stripe_merkle_root;
    let sid = ShardId {
        stripe_merkle_root: root,
        shard_index: 0,
        shard_hash: bundle.expected_shard_hashes[0],
    };
    *repair_grant = grant_owner
        .map(|o| parvault::por::RepairGrant::issue(o, root, Vec::new(), ErasureTier::Homelab));
    (req, sid)
}

fn synd_stored(resp: &MeshWireResponse) -> bool {
    matches!(
        resp,
        MeshWireResponse::SyndicateLiteStripeAck {
            receipt: Some(_),
            ..
        }
    )
}

/// F-38 accept (L-40): the vault identity sends, the cert names it and it signs the grant; it
/// then reads the shard as its owner.
#[test]
fn f38_sender_owned_grant_accepted() {
    let node = spawn_seed("f38-a");
    let vault = key(0xC9);
    let (req, sid) = f38_syndicate(&node, &vault, Some(&vault));
    let resp = send(&vault, &node, req);
    assert!(synd_stored(&resp), "{resp:?}");
    assert!(read_bytes(&send(&vault, &node, owner_read(&vault, sid))).is_some());
    gate_ran("trust_enforcement::f38_sender_owned_grant_accepted");
}

/// F-38 reject (reproduced before the fix: the foreign key was registered and read the shard):
/// a certified device attaching a grant self-signed by another key is refused outright; nothing
/// is stored and the foreign key reads nothing.
#[test]
fn f38_foreign_owner_grant_refused() {
    let node = spawn_seed("f38-r");
    let device = key(0xC7);
    let stranger = key(0xC8);
    let (req, sid) = f38_syndicate(&node, &device, Some(&stranger));
    let resp = send(&device, &node, req);
    assert!(!synd_stored(&resp), "{resp:?}");
    assert_logged(&node, "reject.syndication_grant_not_sender");
    assert!(read_bytes(&send(&stranger, &node, owner_read(&stranger, sid))).is_none());
    gate_ran("trust_enforcement::f38_foreign_owner_grant_refused");
}

/// F-38: the node identity sending a vault-signed grant (the 5f330a1 shape) is refused with the
/// new code, even though its cert names it.
#[test]
fn f38_node_sending_vault_grant_refused() {
    let node = spawn_seed("f38-n");
    let device = key(0xCA);
    let vault = key(0xCB);
    let (req, _) = f38_syndicate(&node, &device, Some(&vault));
    let resp = send(&device, &node, req);
    assert!(!synd_stored(&resp), "{resp:?}");
    assert_logged(&node, "reject.syndication_grant_not_sender");
}

/// F-38: a syndication without a repair grant is still accepted.
#[test]
fn f38_no_grant_still_accepted() {
    let node = spawn_seed("f38-none");
    let device = key(0xCC);
    let (req, _) = f38_syndicate(&node, &device, None);
    assert!(synd_stored(&send(&device, &node, req)));
}

/// F-38: an invited, non-genesis lite client syndicates as its vault key. The seed admits a
/// genesis -> member -> vault chain and accepts the vault-owned grant. The chain is the shape
/// `AdmissionSource::credential_for` extends for a member's vault key; that extension is
/// unit-tested in `admission::tests::member_extends_its_chain_for_the_vault_key` (this process
/// sets `PARVAULT_GENESIS_SEED_HEX`, so a data-dir source here would hold the genesis).
#[test]
fn f38_invited_client_syndicates_as_vault_key() {
    let node = spawn_seed("f38-invited");
    let member = key(0xCD);
    let vault = key(0xCE);
    let to_member = InvitationHop::issue(&genesis(), member.public_key_bytes(), 1, 100);
    let to_vault = InvitationHop::issue(&member, vault.public_key_bytes(), 2, 100);
    let chain = DelegationChain {
        hops: vec![to_member, to_vault],
    };
    assert!(accepted(&handshake(&vault, &node, chain)));
    let (req, sid) = f38_syndicate(&node, &vault, Some(&vault));
    let resp = send_as_stranger(&vault, &node, req);
    assert!(synd_stored(&resp), "{resp:?}");
    assert!(read_bytes(&send_as_stranger(&vault, &node, owner_read(&vault, sid))).is_some());
}

/// F-35 accept: a fresh voucher from a trusted issuer is redeemed.
#[test]
fn f35_fresh_voucher_redeemed() {
    let node = spawn_daemon("f35-a");
    let sender = key(0xB5);
    let b = blinded(0x5B, 512);
    let resp = send(&sender, &node, blinded_put(&b, &sender));
    assert!(format!("{resp:?}").contains("stored: true"), "{resp:?}");
    gate_ran("trust_enforcement::f35_fresh_voucher_redeemed");
}

/// F-35 reject: the same sender and issuer with an expired voucher is refused (a voucher no
/// longer outlives its nullifier).
#[test]
fn f35_expired_voucher_refused() {
    let node = spawn_daemon("f35-r");
    let sender = key(0xB5);
    let b = blinded(0x5B, 512);
    let mut req = blinded_put(&b, &sender);
    if let MeshWireRequest::PutBlindedShard { voucher, .. } = &mut req {
        *voucher = AnonymousQuotaVoucher::mint_expiring(&sender, 8192, now_ms() - 1);
    }
    let resp = send(&sender, &node, req);
    assert!(format!("{resp:?}").contains("stored: false"), "{resp:?}");
    assert_logged(&node, "reject.voucher_expired");
    gate_ran("trust_enforcement::f35_expired_voucher_refused");
}

/// `evict --propagate` refuses when this node is not a member of its installed council (it has
/// none here); the local eviction still applies.
#[test]
fn evict_propagate_needs_council_membership() {
    let root = temp_root("evict-prop");
    let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .arg("--data-dir")
        .arg(root.path().join("data"))
        .args([
            "--no-lan-discovery",
            "evict",
            "--ip",
            "192.0.2.77",
            "--propagate",
        ])
        .output()
        .expect("run parvault evict");
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("member of the installed council"), "{text}");
}

// --- E-WIRE (2c item 5): claims for the remaining wire variants ---------------------------------

/// E-WIRE PorAudit accept: the session key holder's audit is answered from disk.
#[test]
fn ewire_por_audit_with_session_key_answered() {
    let node = spawn_daemon("ew-por-a");
    let owner = key(0xB1);
    let (sid, bytes) = shard(0x31, 2048);
    assert!(stored(&send(
        &owner,
        &node,
        put_shard("", sid, bytes.clone(), None)
    )));
    let chal =
        parvault::por::generate_por_challenge(&[0x5E; 32], sid, bytes.len() as u64, now_ms());
    let resp = send(&owner, &node, MeshWireRequest::PorAudit(chal));
    assert!(
        matches!(resp, MeshWireResponse::PorAuditResult(Some(_))),
        "{resp:?}"
    );
    gate_ran("trust_enforcement::ewire_por_audit_with_session_key_answered");
}

/// E-WIRE PorAudit reject: an audit keyed with another key is refused before any disk read.
#[test]
fn ewire_por_audit_wrong_key_refused() {
    let node = spawn_daemon("ew-por-r");
    let owner = key(0xB1);
    let (sid, bytes) = shard(0x31, 2048);
    assert!(stored(&send(
        &owner,
        &node,
        put_shard("", sid, bytes.clone(), None)
    )));
    let chal =
        parvault::por::generate_por_challenge(&[0x11; 32], sid, bytes.len() as u64, now_ms());
    let resp = send(&key(0xB2), &node, MeshWireRequest::PorAudit(chal));
    assert!(
        matches!(resp, MeshWireResponse::PorAuditResult(None)),
        "{resp:?}"
    );
    assert_logged(&node, "reject.por_hmac_invalid");
    gate_ran("trust_enforcement::ewire_por_audit_wrong_key_refused");
}

/// A fresh read of blinded shard `b` signed by `signer` (the capability key, or another).
fn blinded_read(b: &Blinded, signer: &NodeIdentity) -> MeshWireRequest {
    let ts = now_ms();
    MeshWireRequest::GetBlindedShard {
        blinded_id: b.id,
        capability: b.cap,
        timestamp_ms: ts,
        read_sig: BlindedShardCapability::sign_read_token(signer, &b.id.locator, ts).to_vec(),
    }
}

fn blinded_cap_identity(seed: u8, b: &Blinded) -> NodeIdentity {
    BlindedShardCapability::derive_keypair(&MasterKey::from_bytes([seed; 32]), &b.id.locator).0
}

/// E-WIRE GetBlindedShard accept: the capability key holder reads its shard.
#[test]
fn ewire_blinded_read_by_capability_holder_served() {
    let node = spawn_daemon("ew-bread-a");
    let sender = key(0xB3);
    let b = blinded(0x5B, 512);
    let put = send(&sender, &node, blinded_put(&b, &sender));
    assert!(format!("{put:?}").contains("stored: true"), "{put:?}");
    let resp = send(
        &sender,
        &node,
        blinded_read(&b, &blinded_cap_identity(0x5B, &b)),
    );
    assert!(
        format!("{resp:?}").contains("shard_bytes: Some"),
        "{resp:?}"
    );
    gate_ran("trust_enforcement::ewire_blinded_read_by_capability_holder_served");
}

/// E-WIRE GetBlindedShard reject: a read signed by another key is refused.
#[test]
fn ewire_blinded_read_by_other_key_refused() {
    let node = spawn_daemon("ew-bread-r");
    let sender = key(0xB3);
    let b = blinded(0x5B, 512);
    let put = send(&sender, &node, blinded_put(&b, &sender));
    assert!(format!("{put:?}").contains("stored: true"), "{put:?}");
    let resp = send(&sender, &node, blinded_read(&b, &key(0xB4)));
    assert!(
        format!("{resp:?}").contains("shard_bytes: None"),
        "{resp:?}"
    );
    assert_logged(&node, "reject.blinded_read_sig_invalid");
    gate_ran("trust_enforcement::ewire_blinded_read_by_other_key_refused");
}

/// A signed abuse report with a working burden of proof (a file stored with a key the reporter
/// discloses, and its first stripe's data shards).
fn abuse_report(reporter: &NodeIdentity) -> parvault::storage::VerifiableAbuseReport {
    let dir = tempfile::tempdir().unwrap();
    let store = parvault::storage::BlockStore::new(
        dir.path(),
        parvault::storage::QuotaManager::new(64 * 1024 * 1024, 32 * 1024 * 1024),
    )
    .unwrap();
    let key = MasterKey::generate();
    let input = dir.path().join("leaked.bin");
    std::fs::write(
        &input,
        b"publicly shared payload with a leaked key".repeat(256),
    )
    .unwrap();
    let manifest = store
        .store_file_streaming("uploader", &input, &key, ErasureTier::Consumer, 65_536)
        .unwrap();
    let stripe = &manifest.stripes[0];
    let samples = (0..stripe.k_data)
        .map(|i| {
            let sid = ShardId {
                stripe_merkle_root: stripe.stripe_merkle_root,
                shard_index: i as u32,
                shard_hash: stripe.shard_hashes[i],
            };
            (i as u32, store.get_shard(&sid).unwrap())
        })
        .collect();
    parvault::storage::VerifiableAbuseReport::submit_signed(
        reporter,
        "abuse@example.org",
        "publicly shared illegal content",
        None,
        manifest.clone(),
        key.to_hex(),
        0,
        samples,
        now_ms(),
    )
}

/// E-WIRE SubmitAbuseTakedownReport accept: a signed report with a working proof is queued.
#[test]
fn ewire_signed_abuse_report_queued() {
    let node = spawn_daemon("ew-abuse-a");
    let reporter = key(0xB5);
    let resp = send(
        &reporter,
        &node,
        MeshWireRequest::SubmitAbuseTakedownReport(abuse_report(&reporter)),
    );
    assert!(
        format!("{resp:?}").contains("queued_for_admin_review: true"),
        "{resp:?}"
    );
    gate_ran("trust_enforcement::ewire_signed_abuse_report_queued");
}

/// E-WIRE SubmitAbuseTakedownReport reject: the same report with a forged signature is refused.
#[test]
fn ewire_forged_abuse_report_refused() {
    let node = spawn_daemon("ew-abuse-r");
    let reporter = key(0xB5);
    let mut report = abuse_report(&reporter);
    report.sig_r[0] ^= 0xFF;
    let resp = send(
        &reporter,
        &node,
        MeshWireRequest::SubmitAbuseTakedownReport(report),
    );
    assert!(
        format!("{resp:?}").contains("queued_for_admin_review: false"),
        "{resp:?}"
    );
    assert_logged(&node, "reject.abuse_report_sig_invalid");
    gate_ran("trust_enforcement::ewire_forged_abuse_report_refused");
}

/// A node holding a genesis-signed 1-of-1 council (epoch 1).
fn node_with_council(label: &str) -> Node {
    let node = spawn_daemon(label);
    let out = council_cli(&node, &council_init_args(&[genesis()], 1));
    assert!(out.status.success(), "{}", combined(&out));
    node
}

fn council_ask() -> MeshWireRequest {
    MeshWireRequest::GetCouncilManifest {
        scope_root: genesis().public_key_bytes(),
        from_epoch: 0,
    }
}

/// E-WIRE GetCouncilManifest accept: an admitted peer gets the council chain.
#[test]
fn ewire_admitted_peer_gets_council_manifest() {
    let node = node_with_council("ew-council-a");
    let resp = send(&key(0xB6), &node, council_ask());
    assert!(
        matches!(&resp, MeshWireResponse::CouncilManifestResult { manifests } if manifests.len() == 1),
        "{resp:?}"
    );
    gate_ran("trust_enforcement::ewire_admitted_peer_gets_council_manifest");
}

/// E-WIRE GetCouncilManifest reject: a peer that is not admitted gets nothing.
#[test]
fn ewire_unadmitted_peer_council_manifest_refused() {
    let node = node_with_council("ew-council-r");
    let resp = send_as_stranger(&key(0xB6), &node, council_ask());
    assert!(
        matches!(&resp, MeshWireResponse::CouncilManifestResult { manifests } if manifests.is_empty()),
        "{resp:?}"
    );
    assert_logged(&node, "reject.peer_not_admitted");
    gate_ran("trust_enforcement::ewire_unadmitted_peer_council_manifest_refused");
}

/// F-40 reject: a blinded-read token signed by the capability key but 60 s old (outside the
/// +/-30 s window) is refused; the same holder's fresh token is served
/// (`ewire_blinded_read_by_capability_holder_served`).
#[test]
fn f40_stale_blinded_read_token_refused() {
    let node = spawn_daemon("f40-stale");
    let sender = key(0xB3);
    let b = blinded(0x5B, 512);
    let put = send(&sender, &node, blinded_put(&b, &sender));
    assert!(format!("{put:?}").contains("stored: true"), "{put:?}");
    let ts = now_ms() - 60_000;
    let cap = blinded_cap_identity(0x5B, &b);
    let stale = MeshWireRequest::GetBlindedShard {
        blinded_id: b.id,
        capability: b.cap,
        timestamp_ms: ts,
        read_sig: BlindedShardCapability::sign_read_token(&cap, &b.id.locator, ts).to_vec(),
    };
    let resp = send(&sender, &node, stale);
    assert!(
        format!("{resp:?}").contains("shard_bytes: None"),
        "{resp:?}"
    );
    assert_logged(&node, "reject.blinded_read_stale");
    let fresh = send(&sender, &node, blinded_read(&b, &cap));
    assert!(
        format!("{fresh:?}").contains("shard_bytes: Some"),
        "{fresh:?}"
    );
}

/// F-38 (QA r3): with no `--device-cert`, `watch-folder` self-issues its cert for the identity
/// it sends as, the vault key. The client holds the seed's owner key, so the seed accepts the
/// stripe, and the vault key then reads its shard back as owner.
#[test]
fn f38_lite_client_without_device_cert_syndicates() {
    let seed = spawn_seed("f38-nocert");
    let root = temp_root("f38-nocert-client");
    let client_dir = root.path().join("data");
    let folder = root.path().join("folder");
    std::fs::create_dir_all(&client_dir).unwrap();
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::copy(
        seed.dir.join("owner_pq_keypair.bin"),
        client_dir.join("owner_pq_keypair.bin"),
    )
    .unwrap();
    std::fs::write(folder.join("a.txt"), vec![0x5A; 4096]).unwrap();
    let snap = root.path().join("snap.bin");
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let ns = "f38-nocert";
    let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env("PARVAULT_LAN_REGISTRY_DIR", root.path().join("reg"))
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_SEED_PHRASE")
        .arg("--data-dir")
        .arg(&client_dir)
        .args(["--no-lan-discovery", "watch-folder", "--folder"])
        .arg(&folder)
        .arg("--snapshot-out")
        .arg(&snap)
        .args([
            "--tier",
            "homelab",
            "--seed-phrase",
            phrase,
            "--vault-namespace",
            ns,
        ])
        .args(["--lite-seed-dir", &seed.addr, "--once"])
        .output()
        .unwrap();
    let client_log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{client_log}");
    assert!(
        !seed.log_text().contains("reject.device_cert_not_sender"),
        "seed refused the self-issued cert:\n{}",
        seed.log_text()
    );
    let snapshot: FolderSnapshotManifest =
        bincode::deserialize(&std::fs::read(&snap).unwrap()).unwrap();
    let stripe = &snapshot.files.values().next().unwrap().manifest.stripes[0];
    let sid = ShardId {
        stripe_merkle_root: stripe.stripe_merkle_root,
        shard_index: 0,
        shard_hash: stripe.shard_hashes[0],
    };
    let canonical = parvault::crypto::validate_recovery_seed_phrase_or_passphrase(phrase).unwrap();
    let vault = NodeIdentity::from_recovery_seed_phrase(&canonical, ns);
    assert!(
        read_bytes(&send(&vault, &seed, owner_read(&vault, sid))).is_some(),
        "owner read failed; client:\n{client_log}\nseed:\n{}",
        seed.log_text()
    );
    gate_ran("trust_enforcement::f38_lite_client_without_device_cert_syndicates");
}

// --- F-38-GRANT (L-41): first-writer-wins shard binding -----------------------------------------

fn put_with_commit(
    sid: ShardId,
    bytes: Vec<u8>,
    commit: u8,
    grant: Option<RepairGrant>,
) -> MeshWireRequest {
    MeshWireRequest::PutShard {
        owner_peer_id: String::new(),
        shard_id: sid,
        shard_bytes: bytes,
        session_key_commit: [commit; 32],
        repair_grant: grant,
    }
}

fn self_grant(owner: &NodeIdentity, sid: &ShardId) -> RepairGrant {
    RepairGrant::issue(owner, sid.stripe_merkle_root, vec![], ErasureTier::Homelab)
}

/// The PoR audit under the session commit `put_shard` registers (`[0x5E; 32]`) is answered.
fn audit_ok(asker: &NodeIdentity, node: &Node, sid: ShardId, len: usize) -> bool {
    let chal = parvault::por::generate_por_challenge(&[0x5E; 32], sid, len as u64, now_ms());
    matches!(
        send(asker, node, MeshWireRequest::PorAudit(chal)),
        MeshWireResponse::PorAuditResult(Some(_))
    )
}

/// F-38-GRANT reject (reproduced before the fix: M became the grant and accounted owner): an
/// admitted peer holding a shard's bytes re-puts it with its own grant. Refused; the victim
/// keeps read, delete and its session commit; M can neither read nor delete.
#[test]
fn f38g_takeover_with_own_grant_refused() {
    let node = spawn_daemon("f38g-grant");
    let victim = key(0xD1);
    let m = key(0xD2);
    let (sid, bytes) = shard(0x61, 2048);
    let ok = send(
        &victim,
        &node,
        put_shard("", sid, bytes.clone(), Some(self_grant(&victim, &sid))),
    );
    assert!(stored(&ok), "{ok:?}");
    let resp = send(
        &m,
        &node,
        put_with_commit(sid, bytes.clone(), 0x66, Some(self_grant(&m, &sid))),
    );
    assert!(!stored(&resp), "{resp:?}");
    assert_logged(&node, "reject.shard_bound_to_another_owner");
    assert!(read_bytes(&send(&m, &node, owner_read(&m, sid))).is_none());
    assert!(!deleted(&send(&m, &node, delete_req(&m, sid))));
    assert!(
        audit_ok(&victim, &node, sid, bytes.len()),
        "session commit replaced"
    );
    assert_eq!(
        read_bytes(&send(&victim, &node, owner_read(&victim, sid))),
        Some(bytes)
    );
    assert!(deleted(&send(&victim, &node, delete_req(&victim, sid))));
    gate_ran("trust_enforcement::f38g_takeover_with_own_grant_refused");
}

/// F-38-GRANT reject: a re-put with no grant onto an ungranted shard (accounted-owner takeover)
/// is refused; M cannot delete, the storer still can.
#[test]
fn f38g_takeover_without_grant_refused() {
    let node = spawn_daemon("f38g-nogrant");
    let victim = key(0xD3);
    let m = key(0xD4);
    let (sid, bytes) = shard(0x62, 1024);
    assert!(stored(&send(
        &victim,
        &node,
        put_shard("", sid, bytes.clone(), None)
    )));
    let resp = send(&m, &node, put_with_commit(sid, bytes.clone(), 0x66, None));
    assert!(!stored(&resp), "{resp:?}");
    assert_logged(&node, "reject.shard_bound_to_another_owner");
    assert!(!deleted(&send(&m, &node, delete_req(&m, sid))));
    assert!(
        audit_ok(&victim, &node, sid, bytes.len()),
        "session commit replaced"
    );
    assert!(deleted(&send(&victim, &node, delete_req(&victim, sid))));
}

/// F-38-GRANT accept: the owner re-puts its own shard with its grant (idempotent `Bind`).
#[test]
fn f38g_same_owner_reput_accepted() {
    let node = spawn_daemon("f38g-same");
    let owner = key(0xD5);
    let (sid, bytes) = shard(0x63, 1024);
    for _ in 0..2 {
        let r = send(
            &owner,
            &node,
            put_shard("", sid, bytes.clone(), Some(self_grant(&owner, &sid))),
        );
        assert!(stored(&r), "{r:?}");
    }
    assert_eq!(
        read_bytes(&send(&owner, &node, owner_read(&owner, sid))),
        Some(bytes)
    );
    gate_ran("trust_enforcement::f38g_same_owner_reput_accepted");
}

/// F-38-GRANT accept (`Keep`): a third party re-puts with the owner's grant (repair, handoff,
/// seed re-forward). Acked as stored; nothing changes: session commit, read and delete stay
/// the owner's.
#[test]
fn f38g_third_party_with_owner_grant_kept() {
    let node = spawn_daemon("f38g-keep");
    let owner = key(0xD6);
    let third = key(0xD7);
    let (sid, bytes) = shard(0x64, 1024);
    let grant = self_grant(&owner, &sid);
    assert!(stored(&send(
        &owner,
        &node,
        put_shard("", sid, bytes.clone(), Some(grant.clone()))
    )));
    let r = send(
        &third,
        &node,
        put_with_commit(sid, bytes.clone(), 0x66, Some(grant)),
    );
    assert!(stored(&r), "{r:?}");
    assert!(
        audit_ok(&owner, &node, sid, bytes.len()),
        "session commit replaced"
    );
    assert!(!deleted(&send(&third, &node, delete_req(&third, sid))));
    assert!(deleted(&send(&owner, &node, delete_req(&owner, sid))));
}

/// F-38-GRANT accept: after the owner deletes its shard, a new owner may store it; the old
/// owner's stale grant binding gives it nothing over the new owner's shard.
#[test]
fn f38g_delete_then_new_owner_rebinds() {
    let node = spawn_daemon("f38g-rebind");
    let old = key(0xD8);
    let new = key(0xD9);
    let (sid, bytes) = shard(0x65, 1024);
    assert!(stored(&send(
        &old,
        &node,
        put_shard("", sid, bytes.clone(), Some(self_grant(&old, &sid)))
    )));
    assert!(deleted(&send(&old, &node, delete_req(&old, sid))));
    let r = send(
        &new,
        &node,
        put_shard("", sid, bytes.clone(), Some(self_grant(&new, &sid))),
    );
    assert!(stored(&r), "{r:?}");
    assert_eq!(
        read_bytes(&send(&new, &node, owner_read(&new, sid))),
        Some(bytes)
    );
    assert!(read_bytes(&send(&old, &node, owner_read(&old, sid))).is_none());
    assert!(!deleted(&send(&old, &node, delete_req(&old, sid))));
}

/// F-38-GRANT seed accept: the vault key re-syndicates the same stripe (rule 2).
#[test]
fn f38g_seed_vault_resyndication_accepted() {
    let node = spawn_seed("f38g-resynd");
    let vault = key(0xDA);
    for _ in 0..2 {
        let (req, _) = f38_syndicate(&node, &vault, Some(&vault));
        let resp = send(&vault, &node, req);
        assert!(synd_stored(&resp), "{resp:?}");
    }
    gate_ran("trust_enforcement::f38g_seed_vault_resyndication_accepted");
}

/// F-38-GRANT seed reject: a second key syndicating the identical bundle under its own cert
/// and grant is refused; nothing is re-registered, so it reads nothing.
#[test]
fn f38g_seed_second_key_same_bundle_refused() {
    let node = spawn_seed("f38g-second");
    let vault = key(0xDB);
    let other = key(0xDC);
    let (req, sid) = f38_syndicate(&node, &vault, Some(&vault));
    assert!(synd_stored(&send(&vault, &node, req)));
    let (req2, _) = f38_syndicate(&node, &other, Some(&other));
    let resp = send(&other, &node, req2);
    assert!(!synd_stored(&resp), "{resp:?}");
    assert_logged(&node, "reject.shard_bound_to_another_owner");
    assert!(read_bytes(&send(&other, &node, owner_read(&other, sid))).is_none());
    assert!(read_bytes(&send(&vault, &node, owner_read(&vault, sid))).is_some());
    gate_ran("trust_enforcement::f38g_seed_second_key_same_bundle_refused");
}

/// F-38-GRANT accept: after a shard is LRU-evicted (its file removed, as `put_shard`'s eviction
/// does, with no verifier cleanup), a new owner may store it; the old owner's stale grant
/// binding is dropped on that fresh bind, so the old owner can neither read nor delete it.
#[test]
fn f38g_evicted_then_new_owner_rebinds() {
    let node = spawn_daemon("f38g-evict");
    let old = key(0xDD);
    let new = key(0xDE);
    let (sid, bytes) = shard(0x66, 1024);
    let r = send(
        &old,
        &node,
        put_shard("", sid, bytes.clone(), Some(self_grant(&old, &sid))),
    );
    assert!(stored(&r), "{r:?}");
    let file = node
        .dir
        .join("shards")
        .join(format!("{}.shard", sid.file_key()));
    assert!(file.exists(), "{}", file.display());
    std::fs::remove_file(&file).unwrap();
    let r = send(
        &new,
        &node,
        put_shard("", sid, bytes.clone(), Some(self_grant(&new, &sid))),
    );
    assert!(stored(&r), "{r:?}");
    assert_eq!(
        read_bytes(&send(&new, &node, owner_read(&new, sid))),
        Some(bytes)
    );
    assert!(read_bytes(&send(&old, &node, owner_read(&old, sid))).is_none());
    assert!(!deleted(&send(&old, &node, delete_req(&old, sid))));
    assert!(deleted(&send(&new, &node, delete_req(&new, sid))));
}

/// F-38-GRANT `Keep` with the wrong bytes: a third party carrying the owner's grant but bytes
/// that do not match the shard hash is acked `stored: false`, and nothing changes: the owner
/// still reads its original bytes and its session commit still answers audits.
#[test]
fn f38g_keep_with_mismatched_bytes_refused() {
    let node = spawn_daemon("f38g-keep-bad");
    let owner = key(0xDF);
    let third = key(0xE0);
    let (sid, bytes) = shard(0x67, 1024);
    let grant = self_grant(&owner, &sid);
    assert!(stored(&send(
        &owner,
        &node,
        put_shard("", sid, bytes.clone(), Some(grant.clone()))
    )));
    let forged = vec![0x99; bytes.len()];
    let r = send(
        &third,
        &node,
        put_with_commit(sid, forged, 0x66, Some(grant)),
    );
    assert!(!stored(&r), "{r:?}");
    assert_eq!(
        read_bytes(&send(&owner, &node, owner_read(&owner, sid))),
        Some(bytes.clone())
    );
    assert!(
        audit_ok(&owner, &node, sid, bytes.len()),
        "session commit replaced"
    );
    assert!(!deleted(&send(&third, &node, delete_req(&third, sid))));
}

// --- F-41 (L-42): blinded deletes are signed by the shard's capability key ----------------------

/// A delete of `b` signed by `signer` for the host whose Ed25519 key is `host`, at `ts`.
fn blinded_delete(b: &Blinded, signer: &NodeIdentity, host: [u8; 32], ts: u64) -> MeshWireRequest {
    MeshWireRequest::DeleteBlindedShardSigned {
        blinded_id: b.id,
        timestamp_ms: ts,
        sig: BlindedShardCapability::sign_delete(signer, &host, &b.id, ts).to_vec(),
    }
}

fn blinded_deleted(resp: &MeshWireResponse) -> bool {
    matches!(
        resp,
        MeshWireResponse::DeleteBlindedShardAck { deleted: true, .. }
    )
}

/// Stores blinded shard `b` (seed byte `seed`) on `node` from an admitted sender.
fn put_blinded_ok(node: &Node, sender: &NodeIdentity, b: &Blinded) {
    let put = send(sender, node, blinded_put(b, sender));
    assert!(format!("{put:?}").contains("stored: true"), "{put:?}");
}

fn still_served(node: &Node, sender: &NodeIdentity, b: &Blinded, cap: &NodeIdentity) -> bool {
    format!("{:?}", send(sender, node, blinded_read(b, cap))).contains("shard_bytes: Some")
}

/// F-41 accept: the capability key holder deletes its blinded shard on this host.
#[test]
fn f41_capability_holder_deletes_blinded_shard() {
    let node = spawn_daemon("f41-a");
    let sender = key(0xC1);
    let b = blinded(0x61, 512);
    let cap = blinded_cap_identity(0x61, &b);
    put_blinded_ok(&node, &sender, &b);
    let host = node.identity().public_key_bytes();
    let resp = send(&sender, &node, blinded_delete(&b, &cap, host, now_ms()));
    assert!(blinded_deleted(&resp), "{resp:?}\n{}", node.log_text());
    assert!(!still_served(&node, &sender, &b, &cap));
    gate_ran("trust_enforcement::f41_capability_holder_deletes_blinded_shard");
}

/// F-41 reject: a relay that saw the delete verifier builds the old MAC tombstone; the host
/// refuses every unsigned tombstone and the shard is still served.
#[test]
fn f41_relay_holding_verifier_cannot_delete() {
    let node = spawn_daemon("f41-r");
    let sender = key(0xC1);
    let b = blinded(0x61, 512);
    let cap = blinded_cap_identity(0x61, &b);
    put_blinded_ok(&node, &sender, &b);
    let tombstone = parvault::bootstrap::BlindedShardTombstone::create(
        &b.delete_verifier,
        b.id.locator,
        [0x41; 16],
    );
    let resp = send(
        &key(0xC2),
        &node,
        MeshWireRequest::DeleteBlindedShardTombstone {
            blinded_id: b.id,
            tombstone,
        },
    );
    assert!(!blinded_deleted(&resp), "{resp:?}");
    assert_logged(&node, "reject.blinded_delete_unsigned");
    assert!(still_served(&node, &sender, &b, &cap));
    gate_ran("trust_enforcement::f41_relay_holding_verifier_cannot_delete");
}

/// F-41: a delete signed for another host (replayed by host A to host B) is refused.
#[test]
fn f41_delete_for_another_host_refused() {
    let node = spawn_daemon("f41-host");
    let sender = key(0xC1);
    let b = blinded(0x61, 512);
    let cap = blinded_cap_identity(0x61, &b);
    put_blinded_ok(&node, &sender, &b);
    let other_host = key(0xC9).public_key_bytes();
    let resp = send(
        &sender,
        &node,
        blinded_delete(&b, &cap, other_host, now_ms()),
    );
    assert!(!blinded_deleted(&resp), "{resp:?}");
    assert_logged(&node, "reject.blinded_delete_sig_invalid");
    assert!(still_served(&node, &sender, &b, &cap));
}

/// F-41: a delete signed 60 s ago is refused.
#[test]
fn f41_stale_delete_refused() {
    let node = spawn_daemon("f41-stale");
    let sender = key(0xC1);
    let b = blinded(0x61, 512);
    let cap = blinded_cap_identity(0x61, &b);
    put_blinded_ok(&node, &sender, &b);
    let host = node.identity().public_key_bytes();
    let resp = send(
        &sender,
        &node,
        blinded_delete(&b, &cap, host, now_ms() - 60_000),
    );
    assert!(!blinded_deleted(&resp), "{resp:?}");
    assert_logged(&node, "reject.blinded_delete_stale");
    assert!(still_served(&node, &sender, &b, &cap));
}

/// F-41 (cross-shard delete): a valid signature for shard X sent with `blinded_id` Y deletes
/// nothing; Y's shard survives.
#[test]
fn f41_signature_for_x_with_id_y_refused() {
    let node = spawn_daemon("f41-xy");
    let sender = key(0xC1);
    let x = blinded(0x61, 512);
    let y = blinded(0x62, 512);
    put_blinded_ok(&node, &sender, &x);
    put_blinded_ok(&node, &sender, &y);
    let cap_x = blinded_cap_identity(0x61, &x);
    let host = node.identity().public_key_bytes();
    let ts = now_ms();
    let req = MeshWireRequest::DeleteBlindedShardSigned {
        blinded_id: y.id,
        timestamp_ms: ts,
        sig: BlindedShardCapability::sign_delete(&cap_x, &host, &x.id, ts).to_vec(),
    };
    let resp = send(&sender, &node, req);
    assert!(!blinded_deleted(&resp), "{resp:?}");
    assert!(still_served(
        &node,
        &sender,
        &y,
        &blinded_cap_identity(0x62, &y)
    ));
    assert!(still_served(&node, &sender, &x, &cap_x));
}

/// F-41 (rebind): a re-put of a stored locator with another capability is refused, and that
/// key's delete then fails; the first capability still owns the shard.
#[test]
fn f41_rebind_with_another_capability_refused() {
    let node = spawn_daemon("f41-rebind");
    let sender = key(0xC1);
    let b = blinded(0x61, 512);
    let cap = blinded_cap_identity(0x61, &b);
    put_blinded_ok(&node, &sender, &b);
    let (thief, thief_cap) =
        BlindedShardCapability::derive_keypair(&MasterKey::from_bytes([0x99; 32]), &b.id.locator);
    let squat = Blinded {
        id: b.id,
        cap: thief_cap,
        bytes: b.bytes.clone(),
        delete_verifier: [0x01; 32],
    };
    let resp = send(&sender, &node, blinded_put(&squat, &sender));
    assert!(format!("{resp:?}").contains("stored: false"), "{resp:?}");
    assert_logged(&node, "reject.blinded_locator_bound_to_another_capability");
    let host = node.identity().public_key_bytes();
    let del = send(&sender, &node, blinded_delete(&b, &thief, host, now_ms()));
    assert!(!blinded_deleted(&del), "{del:?}");
    assert!(still_served(&node, &sender, &b, &cap));
    gate_ran("trust_enforcement::f41_rebind_with_another_capability_refused");
}

/// F-41 accept on the seed: the capability holder deletes on a homelab seed too.
#[test]
fn f41_seed_capability_holder_deletes_blinded_shard() {
    let node = spawn_seed("f41-seed");
    let sender = key(0xC1);
    let b = blinded(0x63, 512);
    let cap = blinded_cap_identity(0x63, &b);
    put_blinded_ok(&node, &sender, &b);
    let host = node.identity().public_key_bytes();
    let resp = send(&sender, &node, blinded_delete(&b, &cap, host, now_ms()));
    assert!(blinded_deleted(&resp), "{resp:?}\n{}", node.log_text());
    gate_ran("trust_enforcement::f41_seed_capability_holder_deletes_blinded_shard");
}

/// F-41 reject on the seed: the old MAC tombstone from the real verifier is refused.
#[test]
fn f41_seed_mac_tombstone_refused() {
    let node = spawn_seed("f41-seed-r");
    let sender = key(0xC1);
    let b = blinded(0x63, 512);
    let cap = blinded_cap_identity(0x63, &b);
    put_blinded_ok(&node, &sender, &b);
    let tombstone = parvault::bootstrap::BlindedShardTombstone::create(
        &b.delete_verifier,
        b.id.locator,
        [0x42; 16],
    );
    let resp = send(
        &sender,
        &node,
        MeshWireRequest::DeleteBlindedShardTombstone {
            blinded_id: b.id,
            tombstone,
        },
    );
    assert!(!blinded_deleted(&resp), "{resp:?}");
    assert_logged(&node, "reject.blinded_delete_unsigned");
    assert!(still_served(&node, &sender, &b, &cap));
    gate_ran("trust_enforcement::f41_seed_mac_tombstone_refused");
}

/// F-41 rebind accept: the same capability re-puts its locator (owner retry or handoff).
#[test]
fn f41_same_capability_reput_accepted() {
    let node = spawn_daemon("f41-reput");
    let sender = key(0xC1);
    let b = blinded(0x61, 512);
    put_blinded_ok(&node, &sender, &b);
    put_blinded_ok(&node, &sender, &b);
    gate_ran("trust_enforcement::f41_same_capability_reput_accepted");
}

/// F-42 reject (D-2, fail closed): a lease stored before capability keys were registered (a
/// legacy `blinded_leases.bin` entry with no key) is unreadable, even with a valid-looking
/// capability; the registered case is `ewire_blinded_read_by_capability_holder_served`.
#[test]
fn f42_unregistered_lease_read_refused() {
    let (root, dir, reg, log) = prepare("f42-legacy");
    let b = blinded(0x64, 512);
    let mut mgr = parvault::bootstrap::BlindedShardLeaseManager::new(1 << 30, 2);
    let evicted = mgr.store_with_lease(b.id.locator, b.bytes.len() as u64, 1, 30, [0; 32]);
    assert!(evicted.is_empty());
    let mut ids = std::collections::HashMap::new();
    ids.insert(b.id.locator, b.id);
    std::fs::create_dir_all(dir.join("shards")).unwrap();
    std::fs::write(
        dir.join("shards")
            .join(format!("{}.bshard", b.id.file_key())),
        &b.bytes,
    )
    .unwrap();
    std::fs::write(
        dir.join("blinded_leases.bin"),
        bincode::serialize(&(&mgr, &ids)).unwrap(),
    )
    .unwrap();
    let node = spawn(daemon_command(&dir, &reg), root, dir, log);
    let resp = send(
        &key(0xC3),
        &node,
        blinded_read(&b, &blinded_cap_identity(0x64, &b)),
    );
    assert!(
        format!("{resp:?}").contains("shard_bytes: None"),
        "{resp:?}"
    );
    assert_logged(&node, "reject.blinded_read_no_capability");
    gate_ran("trust_enforcement::f42_unregistered_lease_read_refused");
}

/// F-44: public status reports free space rounded down to whole MiB, used space in power-of-two
/// GiB buckets, and SLA to one decimal.
#[test]
fn f44_public_status_is_bucketed() {
    let node = spawn_daemon("f44");
    let resp = send_as_stranger(&key(0xC4), &node, MeshWireRequest::QueryNodeStatus);
    let MeshWireResponse::NodeStatusResult {
        available_bytes,
        used_bytes,
        sla_score,
        ..
    } = resp
    else {
        panic!("{resp:?}");
    };
    const GIB: u64 = 1 << 30;
    assert_eq!(available_bytes % (1 << 20), 0, "{available_bytes}");
    assert!(
        used_bytes % GIB == 0 && (used_bytes / GIB == 0 || (used_bytes / GIB).is_power_of_two()),
        "{used_bytes}"
    );
    assert_eq!((sla_score * 10.0).round() / 10.0, sla_score);
}

// --- ADR-08: oversized wire frames are refused in the codec ---------------------------------------

/// Sends `req` to `node` over a real libp2p connection from a test swarm whose own codec allows
/// frames up to 64 MiB (so the node's 32 MiB limit is what decides). `Some(response)` or `None`
/// if the request failed (stream reset, timeout).
fn raw_wire_request(node: &Node, req: MeshWireRequest) -> Option<MeshWireResponse> {
    use libp2p::request_response::{self, ProtocolSupport};
    use parvault::network::behaviour::BincodeWireCodec;
    let target = node.peer_id();
    let addr: Multiaddr = node.addr.parse().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let mut swarm =
            libp2p::SwarmBuilder::with_existing_identity(key(0xD8).to_libp2p_keypair().unwrap())
                .with_tokio()
                .with_tcp(
                    libp2p::tcp::Config::default(),
                    libp2p::noise::Config::new,
                    libp2p::yamux::Config::default,
                )
                .unwrap()
                .with_behaviour(|_| {
                    request_response::Behaviour::with_codec(
                        BincodeWireCodec {
                            max_frame_bytes: 64 * 1024 * 1024,
                        },
                        [(
                            libp2p::StreamProtocol::new("/parvault/wire/1.0.0"),
                            ProtocolSupport::Full,
                        )],
                        request_response::Config::default()
                            .with_request_timeout(Duration::from_secs(20)),
                    )
                })
                .unwrap()
                .build();
        swarm.add_peer_address(target, addr);
        swarm.behaviour_mut().send_request(&target, req);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                ev = swarm.select_next_some() => match ev {
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Response { response, .. },
                        ..
                    }) => return Some(response),
                    SwarmEvent::Behaviour(request_response::Event::OutboundFailure { .. }) => {
                        return None
                    }
                    _ => {}
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
        None
    })
}

/// ADR-08 accept: a frame within the limit is read and answered over a real connection.
#[test]
fn adr08_frame_within_limit_answered() {
    let node = spawn_daemon("adr08-a");
    let resp = raw_wire_request(&node, MeshWireRequest::QueryNodeStatus);
    assert!(
        matches!(resp, Some(MeshWireResponse::NodeStatusResult { .. })),
        "{resp:?}"
    );
    gate_ran("trust_enforcement::adr08_frame_within_limit_answered");
}

/// ADR-08 reject: a 33 MiB frame is refused from its length prefix; no response is produced.
#[test]
fn adr08_oversized_frame_refused() {
    let node = spawn_daemon("adr08-r");
    let (sid, _) = shard(0x38, 16);
    let req = put_shard("", sid, vec![0u8; 33 * 1024 * 1024], None);
    let resp = raw_wire_request(&node, req);
    assert!(resp.is_none(), "{resp:?}");
    assert_logged(&node, "reject.wire_frame_oversized");
    gate_ran("trust_enforcement::adr08_oversized_frame_refused");
}

// --- ADR-22: signed LAN beacons --------------------------------------------------------------------

/// Writes a beacon signed by `signer` into `reg` (`forge` flips a signature bit) and returns its
/// peer id.
fn plant_beacon(reg: &Path, signer: &NodeIdentity, forge: bool) -> String {
    let mut pkt = parvault::network::LanBeaconPacket::sign_new(
        signer,
        "test-node",
        "daemon",
        4555,
        1 << 30,
        now_ms(),
        parvault::network::discovery::LanBeaconOptions {
            explicit_listen_ip: Some("127.0.0.1"),
            owner_pq_fingerprint: None,
            pairing_sas_commitment: None,
        },
    )
    .unwrap();
    if forge {
        pkt.sig_r[0] ^= 1;
    }
    std::fs::create_dir_all(reg).unwrap();
    let id = pkt.libp2p_peer_id.clone();
    std::fs::write(
        reg.join(format!("{id}.beacon")),
        pkt.to_wire_bytes().unwrap(),
    )
    .unwrap();
    id
}

/// Runs `parvault discover` reading `reg`; returns its combined output.
fn discover_with_registry(reg: &Path, data: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_LAN_REGISTRY_DIR", reg)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .arg("--data-dir")
        .arg(data)
        .args(["discover", "--timeout-ms", "300", "--port", "0"])
        .output()
        .expect("run parvault discover");
    combined(&out)
}

/// ADR-22 accept: a beacon signed by its own key is discovered.
#[test]
fn adr22_signed_beacon_discovered() {
    let root = temp_root("adr22-a");
    let reg = root.path().join("reg");
    let id = plant_beacon(&reg, &key(0xD1), false);
    let text = discover_with_registry(&reg, &root.path().join("data"));
    let listed = text.split("DISCOVERED PARVAULT PEERS").nth(1).unwrap_or("");
    assert!(listed.contains(&id), "{text}");
    gate_ran("trust_enforcement::adr22_signed_beacon_discovered");
}

/// ADR-22 reject: a beacon with a forged signature is ignored with a reason code.
#[test]
fn adr22_forged_beacon_ignored() {
    let root = temp_root("adr22-r");
    let reg = root.path().join("reg");
    let id = plant_beacon(&reg, &key(0xD2), true);
    let text = discover_with_registry(&reg, &root.path().join("data"));
    let listed = text.split("DISCOVERED PARVAULT PEERS").nth(1).unwrap_or("");
    assert!(!listed.contains(&id), "{text}");
    assert!(text.contains("reject.beacon_sig_invalid"), "{text}");
    gate_ran("trust_enforcement::adr22_forged_beacon_ignored");
}

// --- ADR-07: per-peer quota (bootstrap grace) on PutShard ------------------------------------------

/// A daemon whose per-peer bootstrap grace is 4 KiB (`config.toml`).
fn spawn_daemon_with_grace(label: &str) -> Node {
    let (root, dir, reg, log) = prepare(label);
    let cfg = parvault::config::NodeConfig {
        data_dir: dir.clone(),
        bootstrap_grace_bytes: 4096,
        ..parvault::config::NodeConfig::default()
    };
    let cfg_path = root.path().join("config.toml");
    std::fs::write(&cfg_path, toml::to_string_pretty(&cfg).unwrap()).unwrap();
    let mut cmd = daemon_command(&dir, &reg);
    cmd.arg("--config").arg(&cfg_path);
    spawn(cmd, root, dir, log)
}

/// ADR-07 accept: a peer's shard within its 4 KiB grace is stored.
#[test]
fn adr07_shard_within_peer_quota_stored() {
    let node = spawn_daemon_with_grace("adr07-a");
    let member = key(0xD3);
    let (sid, bytes) = shard(0x41, 3000);
    assert!(stored(&send(
        &member,
        &node,
        put_shard("", sid, bytes, None)
    )));
    gate_ran("trust_enforcement::adr07_shard_within_peer_quota_stored");
}

/// ADR-07 reject: the same peer's second 3000-byte shard exceeds its grace and is refused.
#[test]
fn adr07_shard_over_peer_quota_refused() {
    let node = spawn_daemon_with_grace("adr07-r");
    let member = key(0xD3);
    let (a, ab) = shard(0x41, 3000);
    let (b, bb) = shard(0x42, 3000);
    assert!(stored(&send(&member, &node, put_shard("", a, ab, None))));
    let resp = send(&member, &node, put_shard("", b, bb, None));
    assert!(!stored(&resp), "{resp:?}");
    assert_logged(&node, "reject.peer_quota_exceeded");
    gate_ran("trust_enforcement::adr07_shard_over_peer_quota_refused");
}

// --- ADR-12: hybrid signatures need both halves ------------------------------------------------------

/// ADR-12 reject: a device cert whose Ed25519 half is valid but whose ML-DSA-65 half is broken is
/// refused by the seed (accept: `f25_device_cert_of_sender_accepted`).
#[test]
fn adr12_cert_with_bad_ml_dsa_half_refused() {
    let node = spawn_seed("adr12-r");
    let device = key(0xC5);
    let mut req = syndicate(&node, &device);
    if let MeshWireRequest::SyndicateLiteStripe { cert, .. } = &mut req {
        cert.owner_signature.ml_dsa_65_sig[100] ^= 0x01;
    }
    let resp = send(&device, &node, req);
    assert!(
        !matches!(
            resp,
            MeshWireResponse::SyndicateLiteStripeAck {
                receipt: Some(_),
                ..
            }
        ),
        "{resp:?}"
    );
    assert_logged(&node, "reject.hybrid_sig_ml_dsa_invalid");
    gate_ran("trust_enforcement::adr12_cert_with_bad_ml_dsa_half_refused");
}

// --- F-43 (L-43): every built-in WebDAV request needs a macaroon token --------------------------

const F43_ROOT_KEY: [u8; 32] = [0x43; 32];
const F43_BODY: &[u8] = b"f43 webdav content, only for token holders";

/// `parvault up --no-socket` with built-in WebDAV on an ephemeral port, its macaroon root key
/// pinned to `F43_ROOT_KEY` (`<data_dir>/macaroon_root.key`) and `a.txt` in the seed folder.
/// Returns the node and the WebDAV `host:port`.
fn f43_up(label: &str) -> (Node, String) {
    let (root, dir, reg, log) = prepare(label);
    std::fs::write(dir.join("macaroon_root.key"), hex::encode(F43_ROOT_KEY)).unwrap();
    let seed_dir = root.path().join("shared");
    std::fs::create_dir_all(&seed_dir).unwrap();
    std::fs::write(seed_dir.join("a.txt"), F43_BODY).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "up",
            "--no-socket",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
            "--vfs-webdav-listen",
            "127.0.0.1:0",
            "--vfs-seed-dir",
        ])
        .arg(&seed_dir);
    let node = spawn(cmd, root, dir, log);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let text = node.log_text();
        let addr = text
            .lines()
            .find_map(|l| l.split("WebDAV listening on http://").nth(1))
            .and_then(|rest| rest.split_whitespace().next())
            .map(str::to_string);
        if let (Some(addr), true) = (addr, text.contains("Ingested built-in VFS seed directory")) {
            return (node, addr);
        }
        assert!(Instant::now() < deadline, "WebDAV not up:\n{text}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn f43_token(root_key: &[u8; 32], caveats: Vec<parvault::capabilities::Caveat>) -> String {
    parvault::capabilities::CapabilityMacaroon::mint(root_key, [0x11; 32], [0x22; 32], caveats)
        .unwrap()
        .to_compact_token()
}

/// One raw HTTP/1.1 request; returns (status code, full response bytes).
fn f43_http(addr: &str, method: &str, path: &str, headers: &[String]) -> (u16, Vec<u8>) {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for h in headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let status = String::from_utf8_lossy(&out)
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, out)
}

fn f43_bearer(token: &str) -> String {
    format!("Authorization: Bearer {token}")
}

/// Standard base64 (RFC 4648, padded), for the Basic-auth test only.
fn f43_base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn f43_assert_unauthorized(node: &Node, resp: &(u16, Vec<u8>), code: &str) {
    let text = String::from_utf8_lossy(&resp.1);
    assert_eq!(resp.0, 401, "{text}");
    assert!(text.contains("WWW-Authenticate: Bearer"), "{text}");
    assert!(
        !text.contains(std::str::from_utf8(F43_BODY).unwrap()),
        "{text}"
    );
    assert_logged(node, code);
}

/// F-43 reject: a request with no token is refused with 401 and a Bearer challenge.
#[test]
fn f43_no_token_unauthorized() {
    let (node, addr) = f43_up("f43-none");
    let resp = f43_http(&addr, "GET", "/a.txt", &[]);
    f43_assert_unauthorized(&node, &resp, "reject.webdav_token_missing");
    gate_ran("trust_enforcement::f43_no_token_unauthorized");
}

/// F-43 reject: a token minted under another root key is refused with 401.
#[test]
fn f43_wrong_root_key_unauthorized() {
    let (node, addr) = f43_up("f43-wrong");
    let token = f43_token(&[0x99; 32], vec![]);
    let resp = f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&token)]);
    f43_assert_unauthorized(&node, &resp, "reject.webdav_token_invalid");
}

/// F-43 reject: an expired token is refused with 401 (not 403).
#[test]
fn f43_expired_token_unauthorized() {
    let (node, addr) = f43_up("f43-expired");
    let token = f43_token(
        &F43_ROOT_KEY,
        vec![parvault::capabilities::Caveat::ExpiresAtUnixMs(1)],
    );
    let resp = f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&token)]);
    f43_assert_unauthorized(&node, &resp, "reject.webdav_token_expired");
}

/// F-43 accept: a valid Bearer token reads the file (200) and a byte range of it (206).
#[test]
fn f43_valid_bearer_reads() {
    let (_node, addr) = f43_up("f43-bearer");
    let token = f43_token(
        &F43_ROOT_KEY,
        vec![parvault::capabilities::Caveat::ReadOnly],
    );
    let (status, body) = f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&token)]);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(
        body.ends_with(F43_BODY),
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (status, body) = f43_http(
        &addr,
        "GET",
        "/a.txt",
        &[f43_bearer(&token), "Range: bytes=4-9".to_string()],
    );
    assert_eq!(status, 206, "{}", String::from_utf8_lossy(&body));
    assert!(
        body.ends_with(&F43_BODY[4..10]),
        "{}",
        String::from_utf8_lossy(&body)
    );
    gate_ran("trust_enforcement::f43_valid_bearer_reads");
}

/// F-43 accept (D-1 fallback): the token as the Basic-auth password, any user name, reads the
/// file (200).
#[test]
fn f43_valid_basic_password_reads() {
    let (_node, addr) = f43_up("f43-basic");
    let token = f43_token(
        &F43_ROOT_KEY,
        vec![parvault::capabilities::Caveat::ReadOnly],
    );
    let basic = format!(
        "Authorization: Basic {}",
        f43_base64(format!("anyone:{token}").as_bytes())
    );
    let (status, body) = f43_http(&addr, "GET", "/a.txt", &[basic]);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(
        body.ends_with(F43_BODY),
        "{}",
        String::from_utf8_lossy(&body)
    );
}

fn f43_ro(extra: Vec<parvault::capabilities::Caveat>) -> String {
    let mut c = vec![parvault::capabilities::Caveat::ReadOnly];
    c.extend(extra);
    f43_token(&F43_ROOT_KEY, c)
}

fn f43_status(resp: &(u16, Vec<u8>)) -> String {
    String::from_utf8_lossy(&resp.1).into_owned()
}

/// F-43: the four 401s (missing, malformed, wrong key, expired) are byte-identical, carry the
/// Bearer and Basic challenges, and no response carries CORS headers.
#[test]
fn f43_unauthorized_responses_identical() {
    let (_node, addr) = f43_up("f43-ident");
    let expired = f43_ro(vec![parvault::capabilities::Caveat::ExpiresAtUnixMs(1)]);
    let wrong = f43_token(&[0x99; 32], vec![parvault::capabilities::Caveat::ReadOnly]);
    let responses = [
        f43_http(&addr, "GET", "/a.txt", &[]),
        f43_http(
            &addr,
            "GET",
            "/a.txt",
            &["Authorization: Bearer PARVAULT-MAC-V1:zz".into()],
        ),
        f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&wrong)]),
        f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&expired)]),
    ];
    for r in &responses {
        assert_eq!(r.0, 401, "{}", f43_status(r));
        assert_eq!(r.1, responses[0].1, "401s differ");
    }
    let text = f43_status(&responses[0]);
    assert!(text.contains("WWW-Authenticate: Basic"), "{text}");
    let ok = f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&f43_ro(vec![]))]);
    assert!(
        !f43_status(&ok).contains("Access-Control-"),
        "{}",
        f43_status(&ok)
    );
}

/// F-43 reject: OPTIONS also needs a token.
#[test]
fn f43_options_requires_token() {
    let (node, addr) = f43_up("f43-options");
    let resp = f43_http(&addr, "OPTIONS", "/", &[]);
    f43_assert_unauthorized(&node, &resp, "reject.webdav_token_missing");
}

/// F-43 reject: Basic auth carrying a token minted under another key is refused with 401.
#[test]
fn f43_basic_wrong_token_unauthorized() {
    let (node, addr) = f43_up("f43-basic-bad");
    let token = f43_token(&[0x98; 32], vec![parvault::capabilities::Caveat::ReadOnly]);
    let basic = format!(
        "Authorization: Basic {}",
        f43_base64(format!("u:{token}").as_bytes())
    );
    let resp = f43_http(&addr, "GET", "/a.txt", &[basic]);
    f43_assert_unauthorized(&node, &resp, "reject.webdav_token_invalid");
}

/// F-43 reject (L-44 item 3): a valid token without the ReadOnly caveat is refused with 403.
#[test]
fn f43_token_without_read_only_forbidden() {
    let (node, addr) = f43_up("f43-rw");
    let token = f43_token(&F43_ROOT_KEY, vec![]);
    let resp = f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&token)]);
    assert_eq!(resp.0, 403, "{}", f43_status(&resp));
    assert_logged(&node, "reject.webdav_token_not_read_only");
}

/// F-43 reject: a peer-UID-bound token has no meaning over TCP and is refused with 403.
#[test]
fn f43_peer_uid_token_forbidden() {
    let (node, addr) = f43_up("f43-uid");
    let token = f43_ro(vec![parvault::capabilities::Caveat::AllowedPeerUid(0)]);
    let resp = f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&token)]);
    assert_eq!(resp.0, 403, "{}", f43_status(&resp));
    assert_logged(&node, "reject.webdav_scope_denied");
}

/// F-43 reject: a token scoped to another manifest gets 403 for this file.
#[test]
fn f43_other_manifest_forbidden() {
    let (node, addr) = f43_up("f43-other");
    let token = f43_ro(vec![parvault::capabilities::Caveat::AllowedManifest(
        [0x55; 32],
    )]);
    let resp = f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&token)]);
    assert_eq!(resp.0, 403, "{}", f43_status(&resp));
    assert_logged(&node, "reject.webdav_scope_denied");
    gate_ran("trust_enforcement::f43_other_manifest_forbidden");
}

/// F-43 (no existence oracle): a manifest-scoped token gets 403, never 404, for a path that does
/// not exist, and 403 for a collection listing.
#[test]
fn f43_manifest_token_no_existence_oracle() {
    let (_node, addr) = f43_up("f43-oracle");
    let token = f43_ro(vec![parvault::capabilities::Caveat::AllowedManifest(
        [0x55; 32],
    )]);
    let missing = f43_http(&addr, "GET", "/no-such-file.txt", &[f43_bearer(&token)]);
    assert_eq!(missing.0, 403, "{}", f43_status(&missing));
    let listing = f43_http(
        &addr,
        "PROPFIND",
        "/",
        &[f43_bearer(&token), "Depth: 1".into()],
    );
    assert_eq!(listing.0, 403, "{}", f43_status(&listing));
}

/// F-43 reject: a ByteRange token reading outside its window with GET is refused with 403;
/// HEAD is not range-checked (L-44 item 5) and succeeds.
#[test]
fn f43_byte_range_caveat_applies_to_get_only() {
    let (_node, addr) = f43_up("f43-range");
    let token = f43_ro(vec![parvault::capabilities::Caveat::ByteRange {
        offset: 0,
        length: 4,
    }]);
    let outside = f43_http(
        &addr,
        "GET",
        "/a.txt",
        &[f43_bearer(&token), "Range: bytes=10-20".into()],
    );
    assert_eq!(outside.0, 403, "{}", f43_status(&outside));
    let whole = f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&token)]);
    assert_eq!(
        whole.0,
        403,
        "no Range means the whole file: {}",
        f43_status(&whole)
    );
    let head = f43_http(&addr, "HEAD", "/a.txt", &[f43_bearer(&token)]);
    assert_eq!(head.0, 200, "{}", f43_status(&head));
    // Inside the window: 206 with those bytes. The edge is the only client gate; the built-in
    // VFS reads whole blocks with its own in-memory token (Addendum A ruling).
    let inside = f43_http(
        &addr,
        "GET",
        "/a.txt",
        &[f43_bearer(&token), "Range: bytes=0-3".into()],
    );
    assert_eq!(inside.0, 206, "{}", f43_status(&inside));
    assert!(
        inside.1.ends_with(&F43_BODY[..4]),
        "{}",
        f43_status(&inside)
    );
}

/// F-43 accept: a full-vault read-only token lists the root collection (207).
#[test]
fn f43_valid_token_lists_collection() {
    let (_node, addr) = f43_up("f43-list");
    let resp = f43_http(
        &addr,
        "PROPFIND",
        "/",
        &[f43_bearer(&f43_ro(vec![])), "Depth: 1".into()],
    );
    assert_eq!(resp.0, 207, "{}", f43_status(&resp));
    assert!(f43_status(&resp).contains("a.txt"), "{}", f43_status(&resp));
}

/// F-43 pre-auth bound: headers over 8 KiB get 431 and no content.
#[test]
fn f43_oversized_headers_431() {
    let (_node, addr) = f43_up("f43-431");
    let pad = format!("X-Pad: {}", "a".repeat(9000));
    let resp = f43_http(&addr, "GET", "/a.txt", &[pad, f43_bearer(&f43_ro(vec![]))]);
    assert_eq!(resp.0, 431, "{}", f43_status(&resp));
    assert!(!resp.1.ends_with(F43_BODY));
}

/// F-43 pre-auth bound: a client that never finishes its headers is dropped with no response.
#[test]
fn f43_stalled_headers_dropped() {
    use std::io::{Read, Write};
    let (_node, addr) = f43_up("f43-stall");
    let mut s = std::net::TcpStream::connect(&addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(b"GET /a.txt HTTP/1.1\r\nHost: x\r\n").unwrap();
    let t0 = Instant::now();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
    assert!(
        t0.elapsed() < Duration::from_secs(15),
        "not dropped: {:?}",
        t0.elapsed()
    );
}

/// F-43 accept: headers split across two TCP writes are reassembled.
#[test]
fn f43_split_headers_accepted() {
    use std::io::{Read, Write};
    let (_node, addr) = f43_up("f43-split");
    let token = f43_ro(vec![]);
    let req = format!(
        "GET /a.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    let (a, b) = req.as_bytes().split_at(40);
    let mut s = std::net::TcpStream::connect(&addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(a).unwrap();
    s.flush().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    s.write_all(b).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    assert!(out.ends_with(F43_BODY), "{}", String::from_utf8_lossy(&out));
}

/// F-43 (L-44 item 8): neither a refused nor an accepted request puts the token, or its tag,
/// in the daemon log.
#[test]
fn f43_token_never_logged() {
    let (node, addr) = f43_up("f43-log");
    let good = f43_ro(vec![]);
    let bad = f43_token(&[0x97; 32], vec![parvault::capabilities::Caveat::ReadOnly]);
    let _ = f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&bad)]);
    let _ = f43_http(&addr, "GET", "/a.txt", &[f43_bearer(&good)]);
    assert_logged(&node, "reject.webdav_token_invalid");
    let log = node.log_text();
    for t in [&good, &bad] {
        let body = t.trim_start_matches("PARVAULT-MAC-V1:");
        assert!(!log.contains(body), "token in log");
        assert!(!log.contains(&body[body.len() - 64..]), "tag in log");
    }
}

// --- F-43-PLUGIN: `parvault-fuse webdav` accepts only its pinned token or attenuations of it ----

/// A gateway (`parvault up --ipc-socket`, root key `F43_ROOT_KEY`) and `parvault-fuse webdav`
/// pinned to `pinned`, serving `a.txt`. Killed on drop.
struct F43Plugin {
    _gateway: Node,
    fuse: Child,
    log: PathBuf,
    addr: String,
}

impl Drop for F43Plugin {
    fn drop(&mut self) {
        let _ = self.fuse.kill();
        let _ = self.fuse.wait();
    }
}

/// The pinned plugin token: full rights (ingest writes through the gateway) until far future.
fn f43_plugin_parent() -> parvault::capabilities::CapabilityMacaroon {
    parvault::capabilities::CapabilityMacaroon::mint(
        &F43_ROOT_KEY,
        [0x31; 32],
        [0x32; 32],
        vec![parvault::capabilities::Caveat::ExpiresAtUnixMs(u64::MAX)],
    )
    .unwrap()
}

fn f43_plugin_up(label: &str) -> F43Plugin {
    let (root, dir, reg, log) = prepare(label);
    std::fs::write(dir.join("macaroon_root.key"), hex::encode(F43_ROOT_KEY)).unwrap();
    let sock = dir.join("parvault.sock");
    let seed = dir.join("plugin-seed");
    std::fs::create_dir_all(&seed).unwrap();
    std::fs::write(seed.join("a.txt"), F43_BODY).unwrap();
    let cache = dir.join("plugin-cache");
    let fuse_log = dir.join("fuse.log");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "up",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
        ])
        .arg("--ipc-socket")
        .arg(&sock);
    let gateway = spawn(cmd, root, dir, log);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !sock.exists() {
        assert!(
            Instant::now() < deadline,
            "no gateway socket:\n{}",
            gateway.log_text()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let file = std::fs::File::create(&fuse_log).unwrap();
    let mut fuse = Command::new(env!("CARGO_BIN_EXE_parvault-fuse"))
        .arg("--socket")
        .arg(&sock)
        .arg("--cache-dir")
        .arg(&cache)
        .arg("--macaroon")
        .arg(f43_plugin_parent().to_compact_token())
        .args(["webdav", "--listen", "127.0.0.1:0", "--seed-dir"])
        .arg(&seed)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::from(file.try_clone().unwrap()))
        .stderr(Stdio::from(file))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let text = std::fs::read_to_string(&fuse_log).unwrap_or_default();
        if let Some(addr) = text
            .lines()
            .find_map(|l| l.split("WebDAV VFS on http://").nth(1))
            .and_then(|r| r.split_whitespace().next())
        {
            return F43Plugin {
                _gateway: gateway,
                fuse,
                log: fuse_log,
                addr: addr.to_string(),
            };
        }
        if let Ok(Some(status)) = fuse.try_wait() {
            panic!(
                "parvault-fuse exited ({status}):\n{text}\ngateway:\n{}",
                gateway.log_text()
            );
        }
        assert!(
            Instant::now() < deadline,
            "parvault-fuse not serving:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// F-43-PLUGIN accept: a read-only attenuation of the pinned token reads the file.
#[test]
fn f43_plugin_attenuated_child_reads() {
    let p = f43_plugin_up("f43-plugin-ok");
    let child = f43_plugin_parent()
        .attenuate(parvault::capabilities::Caveat::ReadOnly)
        .unwrap()
        .to_compact_token();
    let (status, body) = f43_http(&p.addr, "GET", "/a.txt", &[f43_bearer(&child)]);
    assert_eq!(
        status,
        200,
        "{}\nfuse:\n{}",
        String::from_utf8_lossy(&body),
        std::fs::read_to_string(&p.log).unwrap_or_default()
    );
    assert!(
        body.ends_with(F43_BODY),
        "{}",
        String::from_utf8_lossy(&body)
    );
    gate_ran("trust_enforcement::f43_plugin_attenuated_child_reads");
}

/// F-43-PLUGIN reject: a sibling token under the same root key (another nonce) is not an
/// attenuation of the pinned token: 401.
#[test]
fn f43_plugin_sibling_token_unauthorized() {
    let p = f43_plugin_up("f43-plugin-sib");
    let sibling = f43_ro(vec![]);
    let (status, body) = f43_http(&p.addr, "GET", "/a.txt", &[f43_bearer(&sibling)]);
    assert_eq!(status, 401, "{}", String::from_utf8_lossy(&body));
    assert!(!body.ends_with(F43_BODY));
    let log = std::fs::read_to_string(&p.log).unwrap_or_default();
    assert!(log.contains("reject.webdav_token_invalid"), "{log}");
    gate_ran("trust_enforcement::f43_plugin_sibling_token_unauthorized");
}

/// F-43-PLUGIN reject: same nonce and issuer but missing the pinned token's caveat: 401.
#[test]
fn f43_plugin_child_missing_parent_caveat_unauthorized() {
    let p = f43_plugin_up("f43-plugin-missing");
    let missing = parvault::capabilities::CapabilityMacaroon::mint(
        &F43_ROOT_KEY,
        [0x31; 32],
        [0x32; 32],
        vec![parvault::capabilities::Caveat::ReadOnly],
    )
    .unwrap()
    .to_compact_token();
    let (status, body) = f43_http(&p.addr, "GET", "/a.txt", &[f43_bearer(&missing)]);
    assert_eq!(status, 401, "{}", String::from_utf8_lossy(&body));
}

/// F-43-PLUGIN: `parvault-fuse webdav` refuses to start without a pinned `--macaroon`.
#[test]
fn f43_plugin_requires_macaroon() {
    let root = temp_root("f43-plugin-nomac");
    let out = common::output_within_deadline(
        Command::new(env!("CARGO_BIN_EXE_parvault-fuse"))
            .arg("--socket")
            .arg(root.path().join("none.sock"))
            .arg("--cache-dir")
            .arg(root.path().join("c"))
            .args(["webdav", "--listen", "127.0.0.1:0"]),
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("webdav needs --macaroon"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- D-ADR gateway pairs: ADR-28 (per-frame macaroons) and ADR-32 (sealing, UID allowlist) ------

/// `parvault up --ipc-socket` with `extra` flags; a pinned `macaroon_root.key` when `key` is set.
fn gw_up(label: &str, extra: &[&str], key: Option<[u8; 32]>) -> (Node, PathBuf) {
    let (root, dir, reg, log) = prepare(label);
    if let Some(k) = key {
        std::fs::write(dir.join("macaroon_root.key"), hex::encode(k)).unwrap();
    }
    let sock = dir.join("gw.sock");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "up",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
        ])
        .arg("--ipc-socket")
        .arg(&sock)
        .args(extra);
    let node = spawn(cmd, root, dir, log);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "no socket:\n{}", node.log_text());
        std::thread::sleep(Duration::from_millis(50));
    }
    (node, sock)
}

/// Stores `data` over the socket from a memfd, sealed when `seal` is set.
fn gw_store(
    sock: &Path,
    data: &[u8],
    seal: bool,
) -> std::io::Result<parvault::gateway::ipc::EphemeralShardManifest> {
    use std::os::fd::{AsFd, AsRawFd};
    let file = std::fs::File::from(
        parvault::gateway::create_memfd_sized("gw-test", data.len() as u64).unwrap(),
    );
    parvault::gateway::pwrite_all(&file, 0, data).unwrap();
    if seal {
        parvault::os_sys::seal_memfd_immutable(file.as_fd()).unwrap();
    }
    parvault::gateway::GatewayBus::unix_socket(sock).store_memfd_sync(
        file.as_raw_fd(),
        data.len() as u64,
        parvault::gateway::RetentionPolicy::Persistent,
    )
}

const GW_KEY: [u8; 32] = [0x28; 32];

fn gw_token(
    caveats: Vec<parvault::capabilities::Caveat>,
) -> parvault::capabilities::CapabilityMacaroon {
    parvault::capabilities::CapabilityMacaroon::mint(&GW_KEY, [5; 32], [6; 32], caveats).unwrap()
}

fn gw_window() -> parvault::capabilities::CapabilityMacaroon {
    gw_token(vec![
        parvault::capabilities::Caveat::ReadOnly,
        parvault::capabilities::Caveat::ByteRange {
            offset: 0,
            length: 4096,
        },
    ])
}

/// ADR-28 accept: a frame inside its attenuated macaroon's byte window is served.
#[test]
fn gmac_frame_inside_caveat_served() {
    let (_node, sock) = gw_up("gmac-ok", &[], Some(GW_KEY));
    let data = vec![0x5C; 64 * 1024];
    let manifest = gw_store(&sock, &data, false).unwrap();
    let bus = parvault::gateway::GatewayBus::unix_socket(&sock);
    let got = bus
        .fetch_range_bytes_sync(&manifest, 0, 4096, Some(gw_window()))
        .unwrap();
    assert_eq!(got, data[..4096]);
    gate_ran("trust_enforcement::gmac_frame_inside_caveat_served");
}

/// ADR-28 reject: the same token on a frame outside its byte window is refused, per frame.
#[test]
fn gmac_frame_outside_caveat_refused() {
    let (node, sock) = gw_up("gmac-out", &[], Some(GW_KEY));
    let data = vec![0x5D; 64 * 1024];
    let manifest = gw_store(&sock, &data, false).unwrap();
    let bus = parvault::gateway::GatewayBus::unix_socket(&sock);
    assert!(bus
        .fetch_range_bytes_sync(&manifest, 8192, 4096, Some(gw_window()))
        .is_err());
    assert_logged(&node, "reject.gateway_macaroon_caveat");
    gate_ran("trust_enforcement::gmac_frame_outside_caveat_refused");
}

/// ADR-32 accept: under --require-sealed-memfd a sealed memfd is stored.
#[test]
fn gseal_sealed_memfd_stored() {
    let (_node, sock) = gw_up("gseal-ok", &["--require-sealed-memfd"], None);
    gw_store(&sock, &[0x32; 8192], true).unwrap();
    gate_ran("trust_enforcement::gseal_sealed_memfd_stored");
}

/// ADR-32 reject: under --require-sealed-memfd an unsealed memfd is refused with its own code.
#[test]
fn gseal_unsealed_memfd_refused() {
    let (node, sock) = gw_up("gseal-bad", &["--require-sealed-memfd"], None);
    assert!(gw_store(&sock, &[0x33; 8192], false).is_err());
    assert_logged(&node, "reject.gateway_memfd_unsealed");
    gate_ran("trust_enforcement::gseal_unsealed_memfd_refused");
}

/// ADR-32 accept: a client whose UID is on --allow-peer-uid is served.
#[test]
fn guid_allowed_peer_uid_served() {
    let uid = parvault::os_sys::geteuid().to_string();
    let (_node, sock) = gw_up(
        "guid-ok",
        &["--strict-plugins", "--allow-peer-uid", &uid],
        None,
    );
    gw_store(&sock, &[0x34; 8192], false).unwrap();
    gate_ran("trust_enforcement::guid_allowed_peer_uid_served");
}

/// ADR-32 reject: a client whose UID is not on --allow-peer-uid is refused with its own code.
#[test]
fn guid_peer_uid_not_allowed_refused() {
    let other = (parvault::os_sys::geteuid() + 1).to_string();
    let (node, sock) = gw_up(
        "guid-bad",
        &["--strict-plugins", "--allow-peer-uid", &other],
        None,
    );
    assert!(gw_store(&sock, &[0x35; 8192], false).is_err());
    assert_logged(&node, "reject.gateway_peer_uid_not_allowed");
    gate_ran("trust_enforcement::guid_peer_uid_not_allowed_refused");
}

/// Opens a WebDAV connection and starts its request head without finishing it.
fn f43_partial_head(addr: &str) -> std::net::TcpStream {
    use std::io::Write;
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    s.write_all(b"GET /a.txt HTTP/1.1\r\n").unwrap();
    s
}

/// Whether the server has closed `s` (EOF or a reset), without waiting.
fn f43_closed(s: &mut std::net::TcpStream) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(0) => true,
        Ok(n) => panic!("answered: {}", String::from_utf8_lossy(&buf[..n])),
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    }
}

/// F-43 (QA r1, slowloris): the request head has one absolute deadline, not a per-read timeout.
/// A client trickling one byte every 2 s is cut off within about the deadline (5 s),
/// unanswered, and a fresh client is then served (401 without a token).
#[test]
fn f43_slow_drip_headers_cut_off() {
    use std::io::Write;
    let (_node, addr) = f43_up("f43-drip");
    let mut s = f43_partial_head(&addr);
    let t0 = Instant::now();
    let mut closed_after = None;
    for b in b"Host: x\r\nX-Slow: aaaaaaaaaaaa".iter() {
        std::thread::sleep(Duration::from_millis(2000));
        if f43_closed(&mut s) || s.write_all(&[*b]).is_err() {
            closed_after = Some(t0.elapsed());
            break;
        }
    }
    let closed_after = closed_after.expect("a 1 byte / 2 s trickle was never cut off");
    assert!(
        closed_after < Duration::from_secs(9),
        "cut off only after {closed_after:?}"
    );
    let fresh = f43_http(&addr, "GET", "/a.txt", &[]);
    assert_eq!(fresh.0, 401, "{}", f43_status(&fresh));
}

/// F-43 (QA r1, connection cap): one source IP holds at most 8 connections; a 9th is dropped
/// unanswered at once, and the IP is served again once its stalled heads are cut off.
#[test]
fn f43_per_ip_connection_cap() {
    let (_node, addr) = f43_up("f43-perip");
    let mut held: Vec<_> = (0..8).map(|_| f43_partial_head(&addr)).collect();
    std::thread::sleep(Duration::from_millis(300));
    let mut ninth = f43_partial_head(&addr);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !f43_closed(&mut ninth) {
        assert!(
            Instant::now() < deadline,
            "9th connection from one IP was not dropped"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        held.iter_mut().all(|s| !f43_closed(s)),
        "the first 8 are still open"
    );
    std::thread::sleep(Duration::from_secs(6));
    let fresh = f43_http(&addr, "GET", "/a.txt", &[]);
    assert_eq!(fresh.0, 401, "{}", f43_status(&fresh));
}

// --- QA 2c D1: a peer demanding excessive ticket PoW cannot hang a public client --------------------

/// A fake public peer: answers every request with a refused `AdmitPublicTicketAck` demanding
/// `bits` of PoW. Returns its `/p2p/` address; the swarm runs on its own thread.
fn spawn_pow_demanding_peer(bits: u8) -> String {
    use libp2p::request_response::{self, ProtocolSupport};
    use parvault::network::behaviour::BincodeWireCodec;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let ident = key(0xD9);
            let verifier = ident.public_key_bytes();
            let mut swarm =
                libp2p::SwarmBuilder::with_existing_identity(ident.to_libp2p_keypair().unwrap())
                    .with_tokio()
                    .with_tcp(
                        libp2p::tcp::Config::default(),
                        libp2p::noise::Config::new,
                        libp2p::yamux::Config::default,
                    )
                    .unwrap()
                    .with_behaviour(|_| {
                        request_response::Behaviour::with_codec(
                            BincodeWireCodec::default(),
                            [(
                                libp2p::StreamProtocol::new("/parvault/wire/1.0.0"),
                                ProtocolSupport::Full,
                            )],
                            request_response::Config::default(),
                        )
                    })
                    .unwrap()
                    .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
                    .build();
            swarm
                .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            let pid = *swarm.local_peer_id();
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let _ = tx.send(format!("{address}/p2p/{pid}"));
                    }
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Request { channel, .. },
                        ..
                    }) => {
                        let _ = swarm.behaviour_mut().send_response(
                            channel,
                            MeshWireResponse::AdmitPublicTicketAck {
                                admitted: false,
                                reason: Some("more work".into()),
                                verifier_pubkey: verifier,
                                required_pow_bits: bits,
                            },
                        );
                    }
                    _ => {}
                }
            }
        });
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("fake peer listening")
}

/// D1: a public-commons client facing a peer that demands 255 bits of PoW refuses the demand
/// and returns quickly instead of minting forever.
#[test]
fn ticket_excessive_pow_demand_refused_fast() {
    let addr = spawn_pow_demanding_peer(255);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let c = MeshClient::new(key(0xDA), Vec::new(), None).with_admission(
            AdmissionSource::default().with_public_tickets(DEFAULT_PUBLIC_WOT_POW_BITS),
        );
        let (sid, bytes) = shard(0x51, 64);
        let r = c.send_request(&addr, put_shard("", sid, bytes, None));
        let _ = done_tx.send(format!("{r:?}"));
    });
    let out = done_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the client must not hang minting a 255-bit ticket");
    assert!(!out.contains("stored: true"), "{out}");
}

/// QA 2c D3: under a council quorum above 1, `evict --propagate` refuses up front (a single
/// signature would be refused by every peer); cosigning arrives with parvault-control.
#[test]
fn evict_propagate_refused_when_quorum_needs_cosigners() {
    let node = spawn_daemon("evict-q2");
    let me = node.identity();
    let out = council_cli(
        &node,
        &council_init_args(&[me.clone(), key(0x82), key(0x83)], 2),
    );
    assert!(out.status.success(), "{}", combined(&out));
    let out = Command::new(env!("CARGO_BIN_EXE_parvault"))
        .env("PARVAULT_GENESIS_SEED_HEX", hex::encode(GENESIS_SEED))
        .env(
            "PARVAULT_LAN_REGISTRY_DIR",
            node.dir.parent().unwrap().join("lan-registry"),
        )
        .env("RUST_LOG", "info")
        .arg("--data-dir")
        .arg(&node.dir)
        .args([
            "--no-lan-discovery",
            "evict",
            "--ip",
            "192.0.2.79",
            "--propagate",
        ])
        .output()
        .expect("run parvault evict");
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("reject.evict_needs_cosignatures"), "{text}");
}

/// QA 2c D6: a node with no council manifest that sees a council order fetches epoch 1 from an
/// admitted peer (verified against its own ring genesis), then applies the same order.
#[test]
fn council_first_epoch_fetched_when_none_installed() {
    let members = vec![key(0x81), key(0x82), key(0x83)];
    let ahead = spawn_daemon("cfirst-ahead");
    let out = council_cli(&ahead, &council_init_args(&members, 2));
    assert!(out.status.success(), "{}", combined(&out));
    let (root_dir, dir, reg, log) = prepare("cfirst-behind");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "--peers",
            &format!("{}/p2p/{}", ahead.addr, ahead.peer_id()),
            "daemon",
            "start",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
        ]);
    let behind = spawn(cmd, root_dir, dir, log);
    // `behind` admits `ahead` when `ahead`'s key handshakes with it.
    let _ = send(
        &ahead.identity(),
        &behind,
        MeshWireRequest::GetCouncilManifest {
            scope_root: genesis().public_key_bytes(),
            from_epoch: 0,
        },
    );
    let order = council_order(&[&members[0], &members[1]], ban_ip(88), 1);
    let r = send(
        &key(0x88),
        &behind,
        MeshWireRequest::BroadcastEvictionOrder(order.clone()),
    );
    assert!(!order_accepted(&r), "{r:?}");
    let deadline = Instant::now() + Duration::from_secs(15);
    while council_epoch_of(&behind) < 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(council_epoch_of(&behind), 1, "{}", behind.log_text());
    let r = send(
        &key(0x88),
        &behind,
        MeshWireRequest::BroadcastEvictionOrder(order),
    );
    assert!(order_accepted(&r), "{r:?}\n{}", behind.log_text());
}

/// F-41 (QA 2c part B item 4): a delete validly signed by the capability key for the stored
/// locator but naming a different content hash does not match the stored id and is refused.
#[test]
fn f41_delete_with_other_content_hash_refused() {
    let node = spawn_daemon("f41-idmm");
    let sender = key(0xC1);
    let b = blinded(0x61, 512);
    let cap = blinded_cap_identity(0x61, &b);
    put_blinded_ok(&node, &sender, &b);
    let other = BlindedShardId {
        locator: b.id.locator,
        content_sha256: [0xEE; 32],
    };
    let host = node.identity().public_key_bytes();
    let ts = now_ms();
    let req = MeshWireRequest::DeleteBlindedShardSigned {
        blinded_id: other,
        timestamp_ms: ts,
        sig: BlindedShardCapability::sign_delete(&cap, &host, &other, ts).to_vec(),
    };
    let resp = send(&sender, &node, req);
    assert!(!blinded_deleted(&resp), "{resp:?}");
    assert_logged(&node, "reject.blinded_delete_id_mismatch");
    assert!(still_served(&node, &sender, &b, &cap));
}

// --- B-SEED-SYND (L-46): the seed's syndication fan-out never blocks other requests ------------

/// A TCP listener that accepts connections and never answers (a silent mesh peer). Returns its
/// multiaddr and the number of connections it accepted.
fn bseed_silent_peer() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("/ip4/127.0.0.1/tcp/{}", l.local_addr().unwrap().port());
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = std::sync::Arc::clone(&count);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in l.incoming().flatten() {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            held.push(s);
        }
    });
    (addr, count)
}

/// `parvault-seed` (homelab vault) with `--peers` and an admin RPC for `admin`.
fn bseed_seed(label: &str, peers: &[&str], admin: &NodeIdentity) -> (Node, String) {
    let (root, dir, reg, log) = prepare(label);
    let admin_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let admin_addr = format!("127.0.0.1:{admin_port}");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault-seed"));
    cmd.arg("--peers").arg(peers.join(","));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .args([
            "start",
            "--mode",
            "homelab-vault",
            "--no-lan-discovery",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
            "--admin-rpc-listen",
            &admin_addr,
            "--admin-rpc-pubkey",
            &hex::encode(admin.public_key_bytes()),
            "--data-dir",
        ])
        .arg(&dir);
    (spawn(cmd, root, dir, log), admin_addr)
}

/// A syndication of a distinct stripe (filled with `fill`) by `device`, certified by the seed.
fn bseed_synd(seed: &Node, device: &NodeIdentity, fill: u8) -> (MeshWireRequest, [u8; 32]) {
    let cert = PersonalDeviceCert::issue(
        &seed.owner_pq(),
        &device.device_peer_id(),
        "laptop",
        1_700_000_000,
    )
    .unwrap();
    let ct = vec![fill; 32 * 1024];
    let set = encode_ciphertext_stripe(0, &ct, ErasureTier::Homelab).unwrap();
    let root = set.stripe_merkle_root;
    let req = MeshWireRequest::SyndicateLiteStripe {
        cert,
        bundle: LiteStripeSyndicationBundle {
            stripe_index: 0,
            tier: ErasureTier::Homelab,
            ciphertext_bytes: ct,
            expected_stripe_merkle_root: root,
            expected_shard_hashes: set.shard_hashes.clone(),
        },
        repair_grant: None,
    };
    (req, root)
}

/// Runs a syndication on a thread with a 40 s client timeout; returns (response, elapsed).
fn bseed_spawn_synd(
    seed: &Node,
    device: NodeIdentity,
    req: MeshWireRequest,
) -> std::thread::JoinHandle<(Result<MeshWireResponse, String>, Duration)> {
    let addr = seed.addr.clone();
    std::thread::spawn(move || {
        let t0 = Instant::now();
        let r = client(&device)
            .with_timeout(Duration::from_secs(40))
            .send_request(&addr, req)
            .map_err(|e| e.to_string());
        (r, t0.elapsed())
    })
}

fn bseed_shard_on_seed(seed: &Node, root: [u8; 32]) -> bool {
    std::fs::read_dir(seed.dir.join("shards"))
        .map(|rd| {
            let prefix = hex::encode(&root[..8]);
            rd.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        })
        .unwrap_or(false)
}

/// B-SEED-SYND (L-46): with every mesh peer silent, a syndication is in flight while another
/// peer's request is answered within 1 s and an admin RPC returns; the syndication answers within
/// its 20 s deadline with a receipt naming no mesh peer.
#[test]
fn bseed_silent_peers_do_not_block_other_requests() {
    let silent: Vec<_> = (0..3).map(|_| bseed_silent_peer()).collect();
    let addrs: Vec<&str> = silent.iter().map(|(a, _)| a.as_str()).collect();
    let admin = key(0xB1);
    let (seed, admin_addr) = bseed_seed("bseed-block", &addrs, &admin);
    let device = key(0xB2);
    let (req, _) = bseed_synd(&seed, &device, 0x41);
    let job = bseed_spawn_synd(&seed, device, req);
    std::thread::sleep(Duration::from_millis(1500));

    let t0 = Instant::now();
    let status = send(&key(0xB3), &seed, MeshWireRequest::QueryNodeStatus);
    assert!(
        t0.elapsed() < Duration::from_secs(1),
        "status took {:?}: {status:?}",
        t0.elapsed()
    );
    let t1 = Instant::now();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let admin_resp = rt.block_on(parvault::admin_rpc::send_admin_rpc_with_identity(
        &admin_addr,
        None,
        &admin,
        &parvault::admin_rpc::SeedAdminRequest::GetSeedTelemetry,
    ));
    assert!(admin_resp.is_ok(), "{:?}", admin_resp.err());
    assert!(
        t1.elapsed() < Duration::from_secs(2),
        "admin RPC took {:?}",
        t1.elapsed()
    );

    let (resp, elapsed) = job.join().unwrap();
    assert!(
        elapsed < Duration::from_secs(22),
        "syndication took {elapsed:?}"
    );
    match resp.unwrap() {
        MeshWireResponse::SyndicateLiteStripeAck {
            receipt: Some(r),
            syndicated_peers,
            ..
        } => {
            assert_eq!(r.mesh_peers_populated, 0);
            assert!(
                syndicated_peers.iter().all(|p| !p.contains("/ip4/")),
                "{syndicated_peers:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    gate_ran("trust_enforcement::bseed_silent_peers_do_not_block_other_requests");
}

/// B-SEED-SYND accept: while one sender's syndication runs, a second sender's is accepted.
#[test]
fn bseed_second_sender_accepted_while_one_job_runs() {
    let (silent, _) = bseed_silent_peer();
    let admin = key(0xB4);
    let (seed, _) = bseed_seed("bseed-two", &[&silent], &admin);
    let (a, b) = (key(0xB5), key(0xB6));
    let (ra, _) = bseed_synd(&seed, &a, 0x42);
    let ja = bseed_spawn_synd(&seed, a, ra);
    std::thread::sleep(Duration::from_millis(800));
    let (rb, root_b) = bseed_synd(&seed, &b, 0x43);
    let jb = bseed_spawn_synd(&seed, b, rb);
    let (resp_b, _) = jb.join().unwrap();
    assert!(
        matches!(
            resp_b,
            Ok(MeshWireResponse::SyndicateLiteStripeAck {
                receipt: Some(_),
                ..
            })
        ),
        "{resp_b:?}"
    );
    assert!(bseed_shard_on_seed(&seed, root_b));
    let _ = ja.join();
    gate_ran("trust_enforcement::bseed_second_sender_accepted_while_one_job_runs");
}

/// B-SEED-SYND reject: with two jobs in flight (the seed's budget), a third sender is refused at
/// once with `reject.syndication_busy`, and nothing of its stripe is written.
#[test]
fn bseed_third_job_refused_busy() {
    let (silent, _) = bseed_silent_peer();
    let admin = key(0xB7);
    let (seed, _) = bseed_seed("bseed-busy", &[&silent], &admin);
    let (a, b, c) = (key(0xB8), key(0xB9), key(0xBA));
    let (ra, _) = bseed_synd(&seed, &a, 0x44);
    let ja = bseed_spawn_synd(&seed, a, ra);
    let (rb, _) = bseed_synd(&seed, &b, 0x45);
    let jb = bseed_spawn_synd(&seed, b, rb);
    std::thread::sleep(Duration::from_millis(1500));
    let (rc, root_c) = bseed_synd(&seed, &c, 0x46);
    let t0 = Instant::now();
    let resp_c = send_with(client(&c).with_timeout(Duration::from_secs(40)), &seed, rc);
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "busy refusal took {:?}",
        t0.elapsed()
    );
    assert!(
        matches!(
            resp_c,
            MeshWireResponse::SyndicateLiteStripeAck { receipt: None, .. }
        ),
        "{resp_c:?}"
    );
    assert_logged(&seed, "reject.syndication_busy");
    assert!(
        !bseed_shard_on_seed(&seed, root_c),
        "a refused stripe was written"
    );
    let _ = (ja.join(), jb.join());
    gate_ran("trust_enforcement::bseed_third_job_refused_busy");
}

/// B-SEED-SYND: one silent peer among healthy ones receives exactly one put per job (the job's
/// dead set), and the healthy peers get the shards.
#[test]
fn bseed_silent_peer_gets_one_put_per_job() {
    let (silent, count) = bseed_silent_peer();
    let d1 = spawn_daemon("bseed-h1");
    let d2 = spawn_daemon("bseed-h2");
    let admin = key(0xBB);
    let (seed, _) = bseed_seed("bseed-dead", &[&d1.addr, &silent, &d2.addr], &admin);
    let device = key(0xBC);
    let (req, _) = bseed_synd(&seed, &device, 0x47);
    let (resp, elapsed) = bseed_spawn_synd(&seed, device, req).join().unwrap();
    match resp.unwrap() {
        MeshWireResponse::SyndicateLiteStripeAck {
            receipt: Some(r), ..
        } => assert!(r.mesh_peers_populated > 0, "{r:?}"),
        other => panic!("{other:?}"),
    }
    assert!(elapsed < Duration::from_secs(22), "{elapsed:?}");
    // One `put_shard` dials twice: the admission handshake (`ensure_admitted`) and the put.
    // Without the per-job dead set the silent peer got about 20 puts (8 connections measured
    // with 4 parallel workers racing it).
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the silent peer received more than one put in one job"
    );
}

/// QA 2c R1: a public-mode node with no council manifest never auto-installs epoch 1 (its root
/// is a TOFU-pinned tracker key, not the ring genesis). A peer serving a manifest signed by that
/// root is ignored; the order is refused and nothing is installed.
#[test]
fn council_public_first_epoch_not_auto_installed() {
    use parvault::storage::council::{install_council_manifest, CouncilManifest};
    let tracker = key(0x7A);
    let members = [key(0x81)];
    let mut m = CouncilManifest::new(
        tracker.public_key_bytes(),
        1,
        members.iter().map(|k| k.public_key_bytes()).collect(),
        1,
        now_ms(),
    );
    m.sign(&tracker);
    // The serving peer holds the manifest (it reads it per request).
    let ahead = spawn_daemon("cpub-ahead");
    install_council_manifest(&ahead.dir, &m, tracker.public_key_bytes()).unwrap();
    // The public node pins the tracker key and has `ahead` as its peer.
    let (root_dir, dir, reg, log) = prepare("cpub-behind");
    std::fs::write(
        dir.join("pinned_tracker_admins.json"),
        format!("[\"{}\"]", hex::encode(tracker.public_key_bytes())),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "--peers",
            &format!("{}/p2p/{}", ahead.addr, ahead.peer_id()),
            "daemon",
            "start",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
        ]);
    let behind = spawn(cmd, root_dir, dir, log);
    // `behind` admits `ahead` (public-commons ticket).
    let c = MeshClient::new(ahead.identity(), Vec::new(), None).with_admission(
        AdmissionSource::default().with_public_tickets(DEFAULT_PUBLIC_WOT_POW_BITS),
    );
    let _ = c.send_request(
        &behind.addr,
        MeshWireRequest::GetCouncilManifest {
            scope_root: tracker.public_key_bytes(),
            from_epoch: 0,
        },
    );
    let order = council_order(&[&members[0]], ban_ip(89), 1);
    let r = send(
        &key(0x89),
        &behind,
        MeshWireRequest::BroadcastEvictionOrder(order.clone()),
    );
    assert!(!order_accepted(&r), "{r:?}");
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(council_epoch_of(&behind), 0, "{}", behind.log_text());
    let r = send(
        &key(0x89),
        &behind,
        MeshWireRequest::BroadcastEvictionOrder(order),
    );
    assert!(!order_accepted(&r), "{r:?}");
}

/// Architect 2c sign-off check: the blinded id map survives a daemon restart, so a signed delete
/// works afterwards (no re-put needed).
#[test]
fn f41_signed_delete_after_restart() {
    let mut node = spawn_daemon("f41-restart");
    let sender = key(0xC1);
    let b = blinded(0x65, 512);
    let cap = blinded_cap_identity(0x65, &b);
    put_blinded_ok(&node, &sender, &b);
    node.restart_daemon_without_wot_state();
    let host = node.identity().public_key_bytes();
    let resp = send(&sender, &node, blinded_delete(&b, &cap, host, now_ms()));
    assert!(blinded_deleted(&resp), "{resp:?}\n{}", node.log_text());
}

// --- F-47 (item 3): FetchPayload carries a macaroon, checked like FetchRange ---------------------

fn gw_manifest_token(root: [u8; 32]) -> parvault::capabilities::CapabilityMacaroon {
    gw_token(vec![
        parvault::capabilities::Caveat::ReadOnly,
        parvault::capabilities::Caveat::AllowedManifest(root),
    ])
}

/// F-47 accept: a token scoped to this file's manifest fetches the whole file.
#[test]
fn gpay_in_scope_token_fetches_file() {
    let (_node, sock) = gw_up("gpay-ok", &[], Some(GW_KEY));
    let data = vec![0x47; 64 * 1024];
    let manifest = gw_store(&sock, &data, false).unwrap();
    let bus = parvault::gateway::GatewayBus::unix_socket(&sock);
    let got = bus
        .fetch_payload_bytes_sync(
            manifest.shard_hashes.clone(),
            Some(gw_manifest_token(manifest.file_merkle_root)),
        )
        .unwrap();
    assert_eq!(got, data);
    gate_ran("trust_enforcement::gpay_in_scope_token_fetches_file");
}

/// F-47 reject: a token scoped to another manifest cannot fetch this file in full.
#[test]
fn gpay_other_manifest_token_refused() {
    let (node, sock) = gw_up("gpay-out", &[], Some(GW_KEY));
    let data = vec![0x48; 64 * 1024];
    let manifest = gw_store(&sock, &data, false).unwrap();
    let bus = parvault::gateway::GatewayBus::unix_socket(&sock);
    assert!(bus
        .fetch_payload_bytes_sync(
            manifest.shard_hashes.clone(),
            Some(gw_manifest_token([0xEE; 32]))
        )
        .is_err());
    assert_logged(&node, "reject.gateway_macaroon_caveat");
    gate_ran("trust_enforcement::gpay_other_manifest_token_refused");
}

/// F-47: with a root key set, a FetchPayload with no token is refused.
#[test]
fn gpay_missing_token_refused() {
    let (node, sock) = gw_up("gpay-none", &[], Some(GW_KEY));
    let data = vec![0x49; 64 * 1024];
    let manifest = gw_store(&sock, &data, false).unwrap();
    let bus = parvault::gateway::GatewayBus::unix_socket(&sock);
    assert!(bus
        .fetch_payload_bytes_sync(manifest.shard_hashes.clone(), None)
        .is_err());
    assert_logged(&node, "reject.gateway_macaroon_missing");
}

// --- Item 3: QueryStatus over the gateway socket (status_auth_decision) --------------------------

fn status_client(sock: &Path) -> parvault::gateway::ipc::GatewayIpcClient {
    parvault::gateway::ipc::GatewayIpcClient::new(sock)
}

/// STATUS-IPC accept: a ReadOnly, unscoped token gets the node's snapshot over the socket.
#[test]
fn status_ipc_readonly_token_served() {
    let (_node, sock) = gw_up("st-ok", &[], Some(GW_KEY));
    let snap = status_client(&sock)
        .query_status(Some(gw_token(vec![
            parvault::capabilities::Caveat::ReadOnly,
        ])))
        .unwrap();
    assert_eq!(snap.version, env!("CARGO_PKG_VERSION"));
    assert!(snap.within_caps());
    gate_ran("trust_enforcement::status_ipc_readonly_token_served");
}

/// STATUS-IPC reject: no token, no status.
#[test]
fn status_ipc_missing_token_refused() {
    let (node, sock) = gw_up("st-none", &[], Some(GW_KEY));
    let err = status_client(&sock).query_status(None).unwrap_err();
    assert!(
        err.to_string().contains("reject.status_token_missing"),
        "{err}"
    );
    assert_logged(&node, "reject.status_token_missing");
    gate_ran("trust_enforcement::status_ipc_missing_token_refused");
}

/// A token scoped to one file is not a status token.
#[test]
fn status_ipc_manifest_scoped_token_refused() {
    let (node, sock) = gw_up("st-scoped", &[], Some(GW_KEY));
    let tok = gw_token(vec![
        parvault::capabilities::Caveat::ReadOnly,
        parvault::capabilities::Caveat::AllowedManifest([7; 32]),
    ]);
    assert!(status_client(&sock).query_status(Some(tok)).is_err());
    assert_logged(&node, "reject.status_token_scoped");
}

/// With no gateway root key there is no verifier, so QueryStatus is refused even with a token.
#[test]
fn status_ipc_without_root_key_refused() {
    let (node, sock) = gw_up("st-nokey", &[], None);
    let tok = gw_token(vec![parvault::capabilities::Caveat::ReadOnly]);
    assert!(status_client(&sock).query_status(Some(tok)).is_err());
    assert_logged(&node, "reject.status_unavailable");
}

// --- Item 3: the status page over HTTP (status_auth_decision at the shared edge) ----------------

/// Starts `parvault up` with the status page on an ephemeral loopback port.
fn status_up(label: &str, key: Option<[u8; 32]>) -> (Node, std::net::SocketAddr) {
    let (root, dir, reg, log) = prepare(label);
    if let Some(k) = key {
        std::fs::write(dir.join("macaroon_root.key"), hex::encode(k)).unwrap();
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", &reg)
        .arg("--data-dir")
        .arg(&dir)
        .args([
            "--no-lan-discovery",
            "up",
            "--listen",
            common::LOOPBACK_EPHEMERAL,
            "--status-http",
            "127.0.0.1:0",
        ]);
    let node = spawn(cmd, root, dir, log);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let text = node.log_text();
        if let Some(rest) = text.split("Status Server listening on http://").nth(1) {
            let addr = rest.split_whitespace().next().unwrap().parse().unwrap();
            return (node, addr);
        }
        assert!(Instant::now() < deadline, "no status listener:\n{text}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn status_token(caveats: Vec<parvault::capabilities::Caveat>) -> String {
    gw_token(caveats).to_compact_token()
}

fn ro_token() -> String {
    status_token(vec![parvault::capabilities::Caveat::ReadOnly])
}

/// Sends `parts` as separate writes (50 ms apart) and returns the raw response.
fn http_raw(addr: std::net::SocketAddr, parts: &[&[u8]]) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(50));
        }
        s.write_all(p).unwrap();
    }
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

fn status_get(addr: std::net::SocketAddr, host: &str, auth: Option<String>) -> (u16, Vec<u8>) {
    let mut req = format!("GET /api/v1/health HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    let raw = http_raw(addr, &[req.as_bytes()]);
    let code = String::from_utf8_lossy(&raw)
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (code, raw)
}

fn host_of(addr: std::net::SocketAddr) -> String {
    addr.to_string()
}

/// STATUS-AUTH accept: a ReadOnly, unscoped Bearer token reads the status JSON.
#[test]
fn status_http_readonly_bearer_served() {
    let (_node, addr) = status_up("sh-ok", Some(GW_KEY));
    let (code, raw) = status_get(addr, &host_of(addr), Some(format!("Bearer {}", ro_token())));
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&raw));
    assert!(String::from_utf8_lossy(&raw).contains(env!("CARGO_PKG_VERSION")));
    gate_ran("trust_enforcement::status_http_readonly_bearer_served");
}

/// STATUS-AUTH reject: no token, the fixed 401 (F-46: the page was open to anyone who could reach it).
#[test]
fn status_http_no_token_unauthorized() {
    let (node, addr) = status_up("sh-none", Some(GW_KEY));
    let (code, raw) = status_get(addr, &host_of(addr), None);
    assert_eq!(code, 401);
    assert_eq!(raw, parvault::http_edge::STATUS_401);
    assert_logged(&node, "reject.status_token_missing");
    gate_ran("trust_enforcement::status_http_no_token_unauthorized");
}

/// STATUS-HOST accept: an IP-literal Host with a valid token is served.
#[test]
fn status_http_ip_literal_host_served() {
    let (_node, addr) = status_up("sh-host-ok", Some(GW_KEY));
    let host = format!("localhost:{}", addr.port());
    let (code, _) = status_get(addr, &host, Some(format!("Bearer {}", ro_token())));
    assert_eq!(code, 200);
    let (code, _) = status_get(addr, &host_of(addr), Some(format!("Bearer {}", ro_token())));
    assert_eq!(code, 200);
    gate_ran("trust_enforcement::status_http_ip_literal_host_served");
}

/// STATUS-HOST reject: a DNS-name Host (DNS rebinding) is refused even with a valid token.
#[test]
fn status_http_dns_host_refused() {
    let (node, addr) = status_up("sh-host-bad", Some(GW_KEY));
    let host = format!("rebind.example:{}", addr.port());
    let (code, _) = status_get(addr, &host, Some(format!("Bearer {}", ro_token())));
    assert_eq!(code, 403);
    assert_logged(&node, "reject.status_host_mismatch");
    gate_ran("trust_enforcement::status_http_dns_host_refused");
}

/// L-45: the token as the Basic password works (a browser prompt), and never in the URL.
#[test]
fn status_http_basic_password_served() {
    use base64::Engine as _;
    let (_node, addr) = status_up("sh-basic", Some(GW_KEY));
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("status:{}", ro_token()));
    let (code, _) = status_get(addr, &host_of(addr), Some(format!("Basic {basic}")));
    assert_eq!(code, 200);
}

/// The other refusals: scoped (403), not ReadOnly and AllowedPeerUid over TCP (the same 401);
/// the token text never reaches the log.
#[test]
fn status_http_token_refusals_and_no_token_in_log() {
    use parvault::capabilities::Caveat;
    let (node, addr) = status_up("sh-refuse", Some(GW_KEY));
    let h = host_of(addr);
    let scoped = status_token(vec![Caveat::ReadOnly, Caveat::AllowedManifest([3; 32])]);
    assert_eq!(
        status_get(addr, &h, Some(format!("Bearer {scoped}"))).0,
        403
    );
    assert_logged(&node, "reject.status_token_scoped");
    let rw = status_token(vec![]);
    let (code, raw) = status_get(addr, &h, Some(format!("Bearer {rw}")));
    assert_eq!(
        (code, raw.as_slice()),
        (401, parvault::http_edge::STATUS_401)
    );
    assert_logged(&node, "reject.status_not_readonly");
    let uid = status_token(vec![Caveat::ReadOnly, Caveat::AllowedPeerUid(0)]);
    let (code, raw) = status_get(addr, &h, Some(format!("Bearer {uid}")));
    assert_eq!(
        (code, raw.as_slice()),
        (401, parvault::http_edge::STATUS_401)
    );
    assert_logged(&node, "reject.status_peer_uid");
    let log = node.log_text();
    for t in [&scoped, &rw, &uid, &ro_token()] {
        assert!(!log.contains(t.as_str()), "token text in the node log");
    }
}

/// The shared edge on the status port: 431 over 8 KiB, a head split across writes is served,
/// a stalled head is dropped unanswered, and the 9th connection from one IP is dropped.
#[test]
fn status_http_edge_limits() {
    let (_node, addr) = status_up("sh-edge", Some(GW_KEY));
    let big = format!(
        "GET /api/v1/health HTTP/1.1\r\nHost: {}\r\nX-Pad: {}\r\n\r\n",
        host_of(addr),
        "a".repeat(9000)
    );
    assert!(String::from_utf8_lossy(&http_raw(addr, &[big.as_bytes()])).starts_with("HTTP/1.1 431"));
    let head = format!(
        "GET /api/v1/health HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n\r\n",
        host_of(addr),
        ro_token()
    );
    let (a, b) = head.as_bytes().split_at(20);
    assert!(String::from_utf8_lossy(&http_raw(addr, &[a, b])).starts_with("HTTP/1.1 200"));
    // Stalled: half a head, then nothing; the 5 s head deadline closes it with no bytes.
    let t0 = Instant::now();
    let stalled = http_raw(addr, &[b"GET / HTTP/1.1\r\n"]);
    assert!(stalled.is_empty() && t0.elapsed() < Duration::from_secs(9));
    // Eight idle connections hold every per-IP slot; the 9th is closed unanswered at once.
    let held: Vec<_> = (0..8)
        .map(|_| std::net::TcpStream::connect(addr).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    let t0 = Instant::now();
    let ninth = http_raw(addr, &[head.as_bytes()]);
    assert!(ninth.is_empty() && t0.elapsed() < Duration::from_secs(2));
    drop(held);
}

/// No server without a verifier (L-44): with --status-http and no key, the daemon creates the
/// gateway root key, verifies under it, and still refuses a request without a token.
#[test]
fn status_http_creates_root_key_and_verifies() {
    let (node, addr) = status_up("sh-nokey", None);
    let key_hex = std::fs::read_to_string(node.dir.join("macaroon_root.key")).unwrap();
    let key: [u8; 32] = hex::decode(key_hex.trim()).unwrap().try_into().unwrap();
    let tok = parvault::capabilities::CapabilityMacaroon::mint(
        &key,
        [5; 32],
        [6; 32],
        vec![parvault::capabilities::Caveat::ReadOnly],
    )
    .unwrap()
    .to_compact_token();
    assert_eq!(status_get(addr, &host_of(addr), None).0, 401);
    assert_eq!(
        status_get(addr, &host_of(addr), Some(format!("Bearer {tok}"))).0,
        200
    );
}

/// L-52: the token goes only in the Authorization header. A token in the query string (or
/// path) is ignored, so the request gets the fixed 401, and the URL token is not logged.
#[test]
fn status_http_query_string_token_refused() {
    let (node, addr) = status_up("sh-query", Some(GW_KEY));
    let tok = ro_token();
    for path in [
        format!("/api/v1/health?token={tok}"),
        format!("/?macaroon={tok}"),
    ] {
        let req = format!("GET {path} HTTP/1.1\r\nHost: {}\r\n\r\n", host_of(addr));
        let raw = http_raw(addr, &[req.as_bytes()]);
        assert_eq!(raw, parvault::http_edge::STATUS_401);
    }
    assert_logged(&node, "reject.status_token_missing");
    assert!(
        !node.log_text().contains(tok.as_str()),
        "URL token in the node log"
    );
}
