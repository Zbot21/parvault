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
use parvault::network::{
    build_mesh_client_swarm, derive_slot_key_from_code, node_identity_libp2p_peer_id,
    seal_wan_peer_card, DelegationChain, DhtWireEnvelope, InvitationHop, MeshClient,
    MeshNetworkBehaviour, MeshWireRequest, MeshWireResponse, SlashingEvidence, SlashingReason,
    WanPeerCard,
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
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .stdout(Stdio::null())
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("spawn binary");
    wait_for_port(port);
    Node {
        child,
        dir,
        log,
        addr: format!("/ip4/127.0.0.1/tcp/{port}"),
        _root: root,
    }
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

/// `parvault-seed start --mode homelab-vault` on loopback, provisioned with the ring genesis. Its
/// owner key is the PQ keypair in its data directory (pre-created by `prepare`).
fn spawn_seed(label: &str) -> Node {
    let (root, dir, reg, log) = prepare(label);
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault-seed"));
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

/// An in-process wire client speaking as `ident` (one Noise connection per request).
fn client(ident: &NodeIdentity) -> MeshClient {
    MeshClient::new(ident.clone(), Vec::new(), None)
}

fn send(ident: &NodeIdentity, node: &Node, req: MeshWireRequest) -> MeshWireResponse {
    match client(ident).send_request(&node.addr, req) {
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

/// F-03 (daemon): a peer that never handshook stores a shard.
#[test]
fn repro_f03_unadmitted_put_shard_stored_daemon() {
    let node = spawn_daemon("f03d");
    let stranger = key(0xA1);
    let (sid, bytes) = shard(0x11, 1024);
    let resp = send(&stranger, &node, put_shard("", sid, bytes, None));
    assert!(
        stored(&resp),
        "gap: unadmitted PutShard is stored: {resp:?}"
    );
    gate_ran("trust_enforcement::repro_f03_unadmitted_put_shard_stored_daemon");
}

/// F-03 (seed): the same on `parvault-seed`.
#[test]
fn repro_f03_unadmitted_put_shard_stored_seed() {
    let node = spawn_seed("f03s");
    let stranger = key(0xA2);
    let (sid, bytes) = shard(0x12, 1024);
    let resp = send(&stranger, &node, put_shard("", sid, bytes, None));
    assert!(
        stored(&resp),
        "gap: unadmitted PutShard is stored: {resp:?}"
    );
    gate_ran("trust_enforcement::repro_f03_unadmitted_put_shard_stored_seed");
}

// --- F-21: the handshake does not bind the chain leaf to the sender --------------------------------

#[test]
fn repro_f21_handshake_chain_leaf_not_sender_accepted() {
    let node = spawn_daemon("f21");
    let leaf = key(0xB1);
    let other_sender = key(0xB2);
    let resp = handshake(&other_sender, &node, chain_for(&leaf));
    assert!(
        accepted(&resp),
        "gap: a chain for another key is accepted: {resp:?}"
    );
    gate_ran("trust_enforcement::repro_f21_handshake_chain_leaf_not_sender_accepted");
}

// --- F-04: the claimed owner is not bound to the sender --------------------------------------------

#[test]
fn repro_f04_invented_owner_claim_accepted() {
    let node = spawn_daemon("f04");
    let sender = key(0xC1);
    for (i, owner) in ["invented-owner-1", "invented-owner-2"].iter().enumerate() {
        let (sid, bytes) = shard(0x20 + i as u8, 1024);
        let resp = send(&sender, &node, put_shard(owner, sid, bytes, None));
        assert!(
            stored(&resp),
            "gap: a PutShard claiming {owner} is stored: {resp:?}"
        );
    }
    gate_ran("trust_enforcement::repro_f04_invented_owner_claim_accepted");
}

// --- F-02: repair grants -----------------------------------------------------------------------------

/// F-02b: a foreign self-signed grant plus receipts from witnesses it names reads another owner's
/// shard (Case B is not bound to the registered grant).
#[test]
fn repro_f02b_foreign_grant_reads_shard() {
    let node = spawn_daemon("f02b");
    let owner = key(0xD1);
    let (w1, w2) = (key(0xD2), key(0xD3));
    let (sid, bytes) = shard(0x31, 2048);
    let grant = RepairGrant::issue(
        &owner,
        sid.stripe_merkle_root,
        vec![w1.public_key_bytes(), w2.public_key_bytes()],
        ErasureTier::Homelab,
    );
    assert!(stored(&send(
        &owner,
        &node,
        put_shard("", sid, bytes.clone(), Some(grant))
    )));

    let attacker = key(0xD4);
    let (a1, a2) = (key(0xD5), key(0xD6));
    let foreign = RepairGrant::issue(
        &attacker,
        sid.stripe_merkle_root,
        vec![a1.public_key_bytes(), a2.public_key_bytes()],
        ErasureTier::Homelab,
    );
    let receipts = vec![
        WitnessFailureReceipt::issue(&a1, sid.stripe_merkle_root, 0, now_ms()),
        WitnessFailureReceipt::issue(&a2, sid.stripe_merkle_root, 0, now_ms()),
    ];
    let resp = send(
        &attacker,
        &node,
        MeshWireRequest::GetCiphertextShard {
            shard_id: sid,
            owner_signature: None,
            repair_proof: Some((foreign, receipts)),
        },
    );
    assert_eq!(
        read_bytes(&resp),
        Some(bytes),
        "gap: a foreign grant reads the owner's shard"
    );
    gate_ran("trust_enforcement::repro_f02b_foreign_grant_reads_shard");
}

/// F-02a: a rejected PutShard still registers its grant, replacing the owner's, so the owner's own
/// signed read stops working.
#[test]
fn repro_f02a_rejected_put_replaces_owner_grant() {
    let node = spawn_daemon("f02a");
    let owner = key(0xE1);
    let (sid, bytes) = shard(0x41, 2048);
    let grant = RepairGrant::issue(&owner, sid.stripe_merkle_root, vec![], ErasureTier::Homelab);
    assert!(stored(&send(
        &owner,
        &node,
        put_shard("", sid, bytes.clone(), Some(grant))
    )));
    assert_eq!(
        read_bytes(&send(&owner, &node, owner_read(&owner, sid))),
        Some(bytes)
    );

    let attacker = key(0xE2);
    let mut bad = sid;
    bad.shard_index = 1;
    bad.shard_hash = [0xEE; 32]; // hash mismatch: the put itself is rejected
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
    assert!(!stored(&resp), "the attacker's put itself fails: {resp:?}");
    assert_eq!(
        read_bytes(&send(&owner, &node, owner_read(&owner, sid))),
        None,
        "gap: the rejected put replaced the owner's grant"
    );
    gate_ran("trust_enforcement::repro_f02a_rejected_put_replaces_owner_grant");
}

// --- F-24: self-certifying vouchers --------------------------------------------------------------------

/// F-24: a voucher minted by an arbitrary key stores a blinded shard from an unadmitted sender.
#[test]
fn repro_f24_self_minted_voucher_stores_blinded_shard() {
    let node = spawn_daemon("f24");
    let stranger = key(0xF1);
    let b = blinded(0x51, 1024);
    let resp = send(
        &stranger,
        &node,
        MeshWireRequest::PutBlindedShard {
            blinded_id: b.id,
            shard_bytes: b.bytes.clone(),
            capability: b.cap,
            voucher: AnonymousQuotaVoucher::mint(&stranger, 8192),
            current_epoch: 1,
            lease_duration_epochs: 30,
            delete_verifier: b.delete_verifier,
        },
    );
    assert!(
        matches!(
            resp,
            MeshWireResponse::PutBlindedShardAck { stored: true, .. }
        ),
        "gap: self-minted voucher accepted: {resp:?}"
    );
    gate_ran("trust_enforcement::repro_f24_self_minted_voucher_stores_blinded_shard");
}

/// F-24 (onion final delivery): the same through a 1-hop `RelayPqOnionEnvelope`.
#[test]
fn repro_f24_self_minted_voucher_onion_delivered() {
    let node = spawn_daemon("f24o");
    let stranger = key(0xF2);
    let b = blinded(0x52, 512);
    let env =
        PqRelayedShardEnvelope::seal_pq(&node.kem_public(), "relay", &b.id, &b.bytes, 0).unwrap();
    let resp = send(
        &stranger,
        &node,
        MeshWireRequest::RelayPqOnionEnvelope {
            target_peer_addr: None,
            envelope: env,
            capability: b.cap,
            voucher: AnonymousQuotaVoucher::mint(&stranger, 8192),
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
        "gap: onion final delivery with a self-minted voucher: {resp:?}"
    );
    gate_ran("trust_enforcement::repro_f24_self_minted_voucher_onion_delivered");
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

/// F-25 (DHT): an unadmitted key stores a self-signed envelope.
#[test]
fn repro_f25_unadmitted_dht_put_stored() {
    let node = spawn_daemon("f25d");
    let stranger = key(0xC7);
    let env = squat_catalog(&stranger, [0x77; 32], 1);
    let resp = send(
        &stranger,
        &node,
        MeshWireRequest::PutDhtEnvelope(DhtWireEnvelope::VaultCatalog(env)),
    );
    assert!(
        matches!(
            resp,
            MeshWireResponse::PutDhtEnvelopeAck { stored: true, .. }
        ),
        "gap: unadmitted DHT put stored: {resp:?}"
    );
    gate_ran("trust_enforcement::repro_f25_unadmitted_dht_put_stored");
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

/// F-01: an admitted reporter gossips `SlashingEvidence` naming the genesis; the daemon quarantines
/// it, and a valid chain for a new peer is refused afterwards.
#[test]
fn repro_f01_gossip_evidence_quarantines_genesis() {
    let node = spawn_daemon("f01");
    let reporter = key(0x81);
    assert!(accepted(&handshake(&reporter, &node, chain_for(&reporter))));
    let before = key(0x82);
    assert!(accepted(&handshake(&before, &node, chain_for(&before))));

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
    rt.block_on(async move {
        let kp = reporter.to_libp2p_keypair().unwrap();
        let mut swarm: libp2p::Swarm<MeshNetworkBehaviour> =
            build_mesh_client_swarm(kp, false).unwrap();
        let topic = gossipsub::IdentTopic::new("parvault-wot-slashing");
        swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
        swarm.dial(addr).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut published = false;
        let mut published_at = None;
        loop {
            tokio::select! {
                ev = swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(parvault::network::behaviour::MeshNetworkBehaviourEvent::Gossipsub(
                        gossipsub::Event::Subscribed { peer_id, .. },
                    )) = ev {
                        if peer_id == target && !published {
                            swarm.behaviour_mut().gossipsub.publish(topic.clone(), data.clone()).unwrap();
                            published = true;
                            published_at = Some(tokio::time::Instant::now());
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            if let Some(t) = published_at {
                if t.elapsed() > Duration::from_secs(2) {
                    break;
                }
            }
            assert!(tokio::time::Instant::now() < deadline, "gossip publish timed out");
        }
    });
    let after = key(0x83);
    let resp = handshake(&after, &node, chain_for(&after));
    assert!(
        !accepted(&resp),
        "gap: after the gossip, a valid genesis chain is refused: {resp:?}"
    );
    gate_ran("trust_enforcement::repro_f01_gossip_evidence_quarantines_genesis");
}
