//! Forward-Secret, Zero-Plaintext-IP Out-of-Band Admin RPC Protocol (`parvault::admin_rpc`).
//!
//! Enables an operator control plane (`parvault-control`) to poll telemetry, review zero-exposure
//! `VerifiableAbuseReport` queues, run two-phase keyed-HMAC dry-run cohort resolution, fan out
//! `SignedBadActorEvictionOrder` batches, and update anti-Sybil Hashcash PoW thresholds across a
//! fleet of `parvault-seed` nodes — while keeping **zero admin private keys** on front-line VPS
//! seed servers and **zero plaintext warrant IPs** on the wire or on disk (`ADR-19`).

use crate::crypto::NodeIdentity;
use crate::storage::{
    EvictionPurgeReport, EvictionTarget, QueuedTakedownEntry, SignedBadActorEvictionOrder,
};
use bincode::Options;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// Domain separator for `ServerHello` Ed25519 transport-binding signatures.
pub const ADMIN_RPC_HELLO_DOMAIN: &[u8] = b"parvault-admin-rpc-hello-v1:";
/// HKDF-SHA256 `info` label for deriving the per-request `ChaCha20Poly1305` session key.
pub const ADMIN_RPC_AEAD_INFO: &[u8] = b"parvault-admin-rpc-aead-v1";
/// Domain separator for challenge-bound `AuthenticatedAdminRpcRequest` Ed25519 signatures.
pub const ADMIN_RPC_REQ_DOMAIN: &[u8] = b"parvault-admin-rpc-req-v1:";
/// Bounded frame ceiling (`32 MiB`) preventing pre-auth / post-auth heap OOM bombs.
pub const MAX_ADMIN_RPC_FRAME_BYTES: usize = 32 * 1024 * 1024;
/// Maximum initial `Vec::with_capacity` pre-allocation (`64 KiB`) before socket bytes arrive.
pub const MAX_ADMIN_RPC_INITIAL_ALLOC_BYTES: usize = 64 * 1024;
/// Maximum allowed clock skew (`5 minutes`) on `AuthenticatedAdminRpcRequest::timestamp_ms`.
pub const MAX_ADMIN_RPC_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

/// Typed wire-framing rejection returned by [`validate_admin_rpc_frame_header`] before any
/// socket payload allocation occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdminRpcFrameError {
    #[error("admin_rpc frame length {0} overflows usize")]
    LengthOverflowsUsize(u32),
    #[error("admin_rpc frame length {declared} exceeds max {effective_max}")]
    ExceedsMaxFrameBytes {
        declared: usize,
        effective_max: usize,
    },
}

/// Validates a 4-byte big-endian `admin_rpc` wire length prefix against `max_len`
/// (hard-capped at `MAX_ADMIN_RPC_FRAME_BYTES + 64`) without panic, heap allocation, or integer
/// overflow, returning `(declared_frame_len, capped_initial_alloc_bytes)`.
pub const fn validate_admin_rpc_frame_header(
    len_buf: [u8; 4],
    max_len: usize,
) -> Result<(usize, usize), AdminRpcFrameError> {
    let hard_ceiling = MAX_ADMIN_RPC_FRAME_BYTES.saturating_add(64);
    let effective_max = if max_len < hard_ceiling {
        max_len
    } else {
        hard_ceiling
    };
    let len_u32 = u32::from_be_bytes(len_buf);
    if (len_u32 as u64) > (usize::MAX as u64) {
        return Err(AdminRpcFrameError::LengthOverflowsUsize(len_u32));
    }
    let len = len_u32 as usize;
    if len > effective_max {
        return Err(AdminRpcFrameError::ExceedsMaxFrameBytes {
            declared: len,
            effective_max,
        });
    }
    let initial_cap = if len < MAX_ADMIN_RPC_INITIAL_ALLOC_BYTES {
        len
    } else {
        MAX_ADMIN_RPC_INITIAL_ALLOC_BYTES
    };
    Ok((len, initial_cap))
}

/// Validates `admin_rpc` operator slice allowlist membership (strictly rejecting `[0u8; 32]`),
/// single-use 32-byte `challenge_nonce` binding, and symmetric `MAX_ADMIN_RPC_CLOCK_SKEW_MS`
/// (`±300,000 ms`) replay-window tolerance using overflow-free `u64::abs_diff`.
pub fn validate_admin_rpc_slice_replay_and_auth_meta(
    allowed_pubkeys: &[[u8; 32]],
    admin_pubkey: &[u8; 32],
    expected_challenge_nonce: &[u8; 32],
    request_challenge_nonce: &[u8; 32],
    now_ms: u64,
    request_timestamp_ms: u64,
) -> Result<(), &'static str> {
    if *admin_pubkey == [0u8; 32] {
        return Err("unauthorized admin_pubkey");
    }
    let mut authorized = false;
    let mut i = 0;
    while i < allowed_pubkeys.len() {
        if allowed_pubkeys[i] == *admin_pubkey {
            authorized = true;
            break;
        }
        i += 1;
    }
    if !authorized {
        return Err("unauthorized admin_pubkey");
    }
    if request_challenge_nonce != expected_challenge_nonce {
        return Err("challenge_nonce mismatch (replay rejected)");
    }
    if now_ms.abs_diff(request_timestamp_ms) > MAX_ADMIN_RPC_CLOCK_SKEW_MS {
        return Err("admin_rpc request timestamp outside 5-minute replay window");
    }
    Ok(())
}

/// Validates `admin_rpc` operator allowlist membership (strictly rejecting `[0u8; 32]`),
/// single-use 32-byte `challenge_nonce` binding, and symmetric `MAX_ADMIN_RPC_CLOCK_SKEW_MS`
/// (`±300,000 ms`) replay-window tolerance using overflow-free `u64::abs_diff`.
pub fn validate_admin_rpc_replay_and_auth_meta(
    allowlist: &AllowedAdminPubkeys,
    admin_pubkey: &[u8; 32],
    expected_challenge_nonce: &[u8; 32],
    request_challenge_nonce: &[u8; 32],
    now_ms: u64,
    request_timestamp_ms: u64,
) -> Result<(), &'static str> {
    let Ok(guard) = allowlist.0.read() else {
        return Err("unauthorized admin_pubkey");
    };
    validate_admin_rpc_slice_replay_and_auth_meta(
        &guard,
        admin_pubkey,
        expected_challenge_nonce,
        request_challenge_nonce,
        now_ms,
        request_timestamp_ms,
    )
}

/// Live health, memory, shard, subnet diversity, PoW policy, and governance telemetry snapshot
/// reported by a `parvault-seed` node over `SeedAdminRequest::GetSeedTelemetry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedTelemetrySnapshot {
    pub seed_peer_id: String,
    pub seed_ed25519_pubkey: [u8; 32],
    pub mode: String,
    pub version: String,
    pub uptime_secs: u64,
    pub rss_kib: u64,
    pub hwm_kib: u64,
    pub stored_regular_shards: usize,
    pub stored_blinded_shards: usize,
    pub used_storage_bytes: u64,
    pub max_storage_bytes: u64,
    pub active_public_peers: usize,
    pub unique_ipv4_24_subnets: usize,
    pub unique_ipv6_48_subnets: usize,
    pub min_public_pow_bits: u8,
    pub max_probationary_lease_bytes: u64,
    pub pending_takedowns_count: usize,
    pub active_eviction_blocks_count: usize,
    pub council_quorum_threshold: usize,
}

/// Authenticated out-of-band control-plane request sent from `parvault-control` to `parvault-seed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedAdminRequest {
    GetSeedTelemetry,
    SyncTakedownQueue {
        since_timestamp_ms: u64,
    },
    ResolveTargetImpact {
        target: EvictionTarget,
    },
    ExecuteSignedEvictionBatch {
        orders: Vec<SignedBadActorEvictionOrder>,
        propagate_to_swarm: bool,
    },
    RecordTakedownDecision {
        report_id: [u8; 32],
        approved: bool,
        admin_pubkey: [u8; 32],
        note: String,
    },
    UpdateAdmissionPolicy {
        min_public_pow_bits: u8,
        max_probationary_lease_bytes: u64,
    },
    /// Item 6 (F-45): install a council manifest on a public seed. The seed checks it with
    /// `council_manifest_decision` against its own configured scope root (never a field of
    /// this request). Appended: indices 0-5 keep their encoding.
    InstallCouncilManifest {
        manifest_bytes: Vec<u8>,
    },
}

/// Authenticated out-of-band control-plane response returned from `parvault-seed` to `parvault-control`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedAdminResponse {
    Telemetry(SeedTelemetrySnapshot),
    TakedownEntries(Vec<QueuedTakedownEntry>),
    TargetImpact {
        resolved_pubkeys: Vec<[u8; 32]>,
        local_regular_shards: usize,
        local_blinded_shards: usize,
        estimated_local_bytes: u64,
        reachable_public_peers: usize,
    },
    EvictionBatchResult {
        local_report: EvictionPurgeReport,
        swarm_propagated_report: EvictionPurgeReport,
        peers_contacted: usize,
        peers_accepted: usize,
    },
    Ack {
        ok: bool,
        message: Option<String>,
    },
    Error {
        message: String,
    },
    /// Reply to `InstallCouncilManifest`: `code` is `None` when installed (or already
    /// installed), else the reason code; `installed_epoch` is the seed's epoch either way.
    CouncilManifestResult {
        code: Option<String>,
        installed_epoch: Option<u64>,
    },
}

/// Ephemeral X25519 + fresh 32-byte anti-replay challenge greeting signed by `parvault-seed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHello {
    pub server_ephemeral_x25519: [u8; 32],
    pub challenge_nonce: [u8; 32],
    pub seed_ed25519_pubkey: [u8; 32],
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

impl ServerHello {
    pub fn sign_bytes(server_ephemeral_x25519: &[u8; 32], challenge_nonce: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ADMIN_RPC_HELLO_DOMAIN.len() + 64);
        buf.extend_from_slice(ADMIN_RPC_HELLO_DOMAIN);
        buf.extend_from_slice(server_ephemeral_x25519);
        buf.extend_from_slice(challenge_nonce);
        buf
    }

    pub fn issue(
        seed_identity: &NodeIdentity,
        server_ephemeral_x25519: [u8; 32],
        challenge_nonce: [u8; 32],
    ) -> Self {
        let msg = Self::sign_bytes(&server_ephemeral_x25519, &challenge_nonce);
        let sig = seed_identity.sign(&msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);
        Self {
            server_ephemeral_x25519,
            challenge_nonce,
            seed_ed25519_pubkey: seed_identity.public_key_bytes(),
            sig_r,
            sig_s,
        }
    }

    pub fn verify(&self) -> bool {
        let msg = Self::sign_bytes(&self.server_ephemeral_x25519, &self.challenge_nonce);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&self.sig_r);
        sig[32..].copy_from_slice(&self.sig_s);
        NodeIdentity::verify_with_pubkey(&self.seed_ed25519_pubkey, &msg, &sig)
    }
}

/// Encrypted inner envelope sealing the operator's `SeedAdminRequest` (including any confidential
/// warrant IP in `ResolveTargetImpact`) under ephemeral X25519 + `ChaCha20Poly1305`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedAdminRpcRequest {
    pub admin_pubkey: [u8; 32],
    pub challenge_nonce: [u8; 32],
    pub timestamp_ms: u64,
    pub request: SeedAdminRequest,
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

/// Computes the canonical challenge-bound signing payload for `AuthenticatedAdminRpcRequest`:
/// `"parvault-admin-rpc-req-v1:" || challenge_nonce || timestamp_ms.to_le_bytes() || bincode::serialize(request)`.
pub fn admin_rpc_request_sign_bytes(
    challenge_nonce: &[u8; 32],
    timestamp_ms: u64,
    request: &SeedAdminRequest,
) -> Vec<u8> {
    let req_bytes = bincode::serialize(request).expect("SeedAdminRequest bincode serialization");
    let mut out = Vec::with_capacity(ADMIN_RPC_REQ_DOMAIN.len() + 32 + 8 + req_bytes.len());
    out.extend_from_slice(ADMIN_RPC_REQ_DOMAIN);
    out.extend_from_slice(challenge_nonce);
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out.extend_from_slice(&req_bytes);
    out
}

fn derive_admin_rpc_aead_key(ecdh_shared: &[u8; 32], challenge_nonce: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(challenge_nonce), ecdh_shared);
    let mut key = [0u8; 32];
    hk.expand(ADMIN_RPC_AEAD_INFO, &mut key)
        .expect("32-byte HKDF expansion is always valid");
    key
}

fn bounded_bincode(limit: usize) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(limit as u64)
}

fn serialize_wire<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let bytes = bounded_bincode(MAX_ADMIN_RPC_FRAME_BYTES).serialize(value)?;
    if bytes.len() > MAX_ADMIN_RPC_FRAME_BYTES {
        anyhow::bail!(
            "admin_rpc payload length {} exceeds {} byte ceiling",
            bytes.len(),
            MAX_ADMIN_RPC_FRAME_BYTES
        );
    }
    Ok(bytes)
}

fn deserialize_wire<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> anyhow::Result<T> {
    if bytes.len() > MAX_ADMIN_RPC_FRAME_BYTES {
        anyhow::bail!(
            "admin_rpc frame length {} exceeds {} byte ceiling",
            bytes.len(),
            MAX_ADMIN_RPC_FRAME_BYTES
        );
    }
    Ok(bounded_bincode(bytes.len()).deserialize(bytes)?)
}

fn normalize_tcp_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if let Some(rest) = trimmed.strip_prefix("tcp://") {
        return rest.trim().to_string();
    }
    if let Some(rest) = trimmed.strip_prefix("http://") {
        return rest.trim_end_matches('/').to_string();
    }
    if trimmed.starts_with('/') {
        if let Ok(maddr) = trimmed.parse::<libp2p::Multiaddr>() {
            let mut host = None;
            let mut port = None;
            for p in maddr.iter() {
                match p {
                    libp2p::multiaddr::Protocol::Ip4(ip) => host = Some(ip.to_string()),
                    libp2p::multiaddr::Protocol::Ip6(ip) => host = Some(format!("[{ip}]")),
                    libp2p::multiaddr::Protocol::Dns(d)
                    | libp2p::multiaddr::Protocol::Dns4(d)
                    | libp2p::multiaddr::Protocol::Dns6(d) => host = Some(d.to_string()),
                    libp2p::multiaddr::Protocol::Tcp(tp) => port = Some(tp),
                    _ => {}
                }
            }
            if let (Some(h), Some(p)) = (host, port) {
                return format!("{h}:{p}");
            }
        }
    }
    trimmed.to_string()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Sends a single forward-secret, challenge-authenticated `SeedAdminRequest` to `endpoint` using an
/// arbitrary `sign_fn` callback (supporting both local `0600` seeds and hardware YubiKey / `ssh-agent`
/// signers in `parvault-control`).
///
/// Returns `(SeedAdminResponse, verified_seed_ed25519_pubkey)`.
pub async fn send_admin_rpc_with_signer<F>(
    endpoint: &str,
    expected_seed_pubkey: Option<[u8; 32]>,
    admin_pubkey: [u8; 32],
    request: &SeedAdminRequest,
    sign_fn: F,
) -> anyhow::Result<(SeedAdminResponse, [u8; 32])>
where
    F: FnOnce(&[u8]) -> anyhow::Result<[u8; 64]>,
{
    let addr = normalize_tcp_endpoint(endpoint);
    let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("timed out connecting to admin_rpc endpoint {addr}"))??;
    let _ = stream.set_nodelay(true);

    // 1. Read and verify `ServerHello`.
    let hello_bytes = read_length_prefixed_frame(&mut stream, 4096).await?;
    let hello: ServerHello = deserialize_wire(&hello_bytes)?;
    if !hello.verify() {
        anyhow::bail!("admin_rpc ServerHello Ed25519 signature verification failed");
    }
    if let Some(expected_pk) = expected_seed_pubkey {
        if hello.seed_ed25519_pubkey != expected_pk {
            anyhow::bail!(
                "admin_rpc pinned seed pubkey mismatch: expected {}, got {}",
                hex::encode(expected_pk),
                hex::encode(hello.seed_ed25519_pubkey)
            );
        }
    }

    // 2. Ephemeral X25519 ECDH + HKDF-SHA256 session AEAD key derivation.
    let client_secret = X25519StaticSecret::random_from_rng(OsRng);
    let client_public = X25519PublicKey::from(&client_secret);
    let server_public = X25519PublicKey::from(hello.server_ephemeral_x25519);
    let shared = client_secret.diffie_hellman(&server_public);
    let mut shared_bytes = *shared.as_bytes();
    if shared_bytes.iter().all(|&b| b == 0) {
        anyhow::bail!("rejected low-order X25519 public key in ServerHello");
    }
    let mut aead_key = derive_admin_rpc_aead_key(&shared_bytes, &hello.challenge_nonce);
    shared_bytes.zeroize();

    // 3. Sign challenge-bound request via callback (hardware/SSH-agent compatible).
    let timestamp_ms = now_unix_ms();
    let sign_payload = admin_rpc_request_sign_bytes(&hello.challenge_nonce, timestamp_ms, request);
    let sig = sign_fn(&sign_payload)?;
    if !NodeIdentity::verify_with_pubkey(&admin_pubkey, &sign_payload, &sig) {
        aead_key.zeroize();
        anyhow::bail!("admin_rpc sign_fn signature failed local verification against admin_pubkey");
    }
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&sig[..32]);
    sig_s.copy_from_slice(&sig[32..]);

    let auth_req = AuthenticatedAdminRpcRequest {
        challenge_nonce: hello.challenge_nonce,
        timestamp_ms,
        admin_pubkey,
        sig_r,
        sig_s,
        request: request.clone(),
    };
    let mut plaintext_req = serialize_wire(&auth_req)?;
    let cipher = ChaCha20Poly1305::new((&aead_key).into());
    let req_nonce = Nonce::from([0u8; 12]);
    let ciphertext = cipher
        .encrypt(&req_nonce, plaintext_req.as_ref())
        .map_err(|_| anyhow::anyhow!("ChaCha20Poly1305 request encryption failed"));
    plaintext_req.zeroize();
    let ciphertext = match ciphertext {
        Ok(ct) => ct,
        Err(e) => {
            aead_key.zeroize();
            return Err(e);
        }
    };

    // 4. Write `client_ephemeral_x25519 (32B) || len_u32_be || ciphertext`.
    let ct_len = u32::try_from(ciphertext.len())
        .map_err(|_| anyhow::anyhow!("admin_rpc ciphertext overflows u32"))?;
    stream.write_all(client_public.as_bytes()).await?;
    stream.write_all(&ct_len.to_be_bytes()).await?;
    stream.write_all(&ciphertext).await?;
    stream.flush().await?;

    // 5. Read `len_u32_be || ChaCha20Poly1305(nonce = [1u8; 12], response)`.
    let resp_ct = read_length_prefixed_frame(&mut stream, MAX_ADMIN_RPC_FRAME_BYTES + 64).await;
    let resp_ct = match resp_ct {
        Ok(ct) => ct,
        Err(e) => {
            aead_key.zeroize();
            return Err(e);
        }
    };
    let resp_nonce = Nonce::from([1u8; 12]);
    let decrypted = cipher.decrypt(&resp_nonce, resp_ct.as_ref()).map_err(|_| {
        anyhow::anyhow!("ChaCha20Poly1305 response decryption/tag verification failed")
    });
    aead_key.zeroize();
    let mut resp_plain = decrypted?;
    let parsed: SeedAdminResponse = deserialize_wire(&resp_plain)?;
    resp_plain.zeroize();

    Ok((parsed, hello.seed_ed25519_pubkey))
}

/// Convenience wrapper around [`send_admin_rpc_with_signer`] using an in-memory [`NodeIdentity`].
pub async fn send_admin_rpc_with_identity(
    endpoint: &str,
    expected_seed_pubkey: Option<[u8; 32]>,
    admin_identity: &NodeIdentity,
    request: &SeedAdminRequest,
) -> anyhow::Result<(SeedAdminResponse, [u8; 32])> {
    let admin_pk = admin_identity.public_key_bytes();
    send_admin_rpc_with_signer(endpoint, expected_seed_pubkey, admin_pk, request, |msg| {
        Ok(admin_identity.sign(msg))
    })
    .await
}

/// Thread-safe allowlist of authorized operator/council Ed25519 public keys accepted by
/// [`spawn_admin_rpc_listener`].
#[derive(Clone, Debug)]
pub struct AllowedAdminPubkeys(Arc<RwLock<Vec<[u8; 32]>>>);

impl AllowedAdminPubkeys {
    pub fn new(keys: Vec<[u8; 32]>) -> Self {
        Self(Arc::new(RwLock::new(dedup_pubkeys(keys))))
    }

    pub fn contains(&self, pk: &[u8; 32]) -> bool {
        if *pk == [0u8; 32] {
            return false;
        }
        self.0
            .read()
            .map(|guard| guard.contains(pk))
            .unwrap_or(false)
    }

    pub fn snapshot(&self) -> Vec<[u8; 32]> {
        self.0.read().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn update(&self, keys: Vec<[u8; 32]>) {
        if let Ok(mut guard) = self.0.write() {
            *guard = dedup_pubkeys(keys);
        }
    }
}

impl From<Vec<[u8; 32]>> for AllowedAdminPubkeys {
    fn from(keys: Vec<[u8; 32]>) -> Self {
        Self::new(keys)
    }
}

impl From<&[[u8; 32]]> for AllowedAdminPubkeys {
    fn from(keys: &[[u8; 32]]) -> Self {
        Self::new(keys.to_vec())
    }
}

impl From<Arc<RwLock<Vec<[u8; 32]>>>> for AllowedAdminPubkeys {
    fn from(shared: Arc<RwLock<Vec<[u8; 32]>>>) -> Self {
        Self(shared)
    }
}

fn dedup_pubkeys(keys: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(keys.len());
    for pk in keys {
        if pk != [0u8; 32] && !out.contains(&pk) {
            out.push(pk);
        }
    }
    out
}

/// Synchronous handler trait invoked inside `spawn_blocking` per authenticated admin RPC request.
pub trait SeedAdminRpcHandler: Send + Sync + 'static {
    fn handle_request(&self, request: SeedAdminRequest) -> SeedAdminResponse;
}

impl<F> SeedAdminRpcHandler for F
where
    F: Fn(SeedAdminRequest) -> SeedAdminResponse + Send + Sync + 'static,
{
    fn handle_request(&self, request: SeedAdminRequest) -> SeedAdminResponse {
        (self)(request)
    }
}

/// Lifecycle handle for a running `parvault-seed` out-of-band admin RPC listener.
#[derive(Debug)]
pub struct AdminRpcServerHandle {
    local_addr: SocketAddr,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl AdminRpcServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn wait(mut self) {
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for AdminRpcServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Binds a forward-secret `ChaCha20Poly1305` + `X25519` + `Ed25519` admin RPC TCP listener on
/// `bind_addr` (supporting `:0` ephemeral ports in tests) and spawns the background accept loop.
pub async fn spawn_admin_rpc_listener<A, H>(
    bind_addr: SocketAddr,
    seed_identity: NodeIdentity,
    allowed_admin_pubkeys: A,
    handler: H,
) -> anyhow::Result<(SocketAddr, AdminRpcServerHandle)>
where
    A: Into<AllowedAdminPubkeys>,
    H: SeedAdminRpcHandler,
{
    let listener = TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    let allowlist: AllowedAdminPubkeys = allowed_admin_pubkeys.into();
    let handler = Arc::new(handler);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((stream, _peer_addr)) => {
                            let seed_id = seed_identity.clone();
                            let allowed = allowlist.clone();
                            let h = Arc::clone(&handler);
                            tokio::spawn(async move {
                                let _ = tokio::time::timeout(
                                    Duration::from_secs(30),
                                    serve_single_admin_rpc_conn(stream, seed_id, allowed, h),
                                )
                                .await;
                            });
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "admin_rpc listener accept error");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });

    Ok((
        local_addr,
        AdminRpcServerHandle {
            local_addr,
            shutdown_tx,
            join_handle: Some(join_handle),
        },
    ))
}

async fn serve_single_admin_rpc_conn<H: SeedAdminRpcHandler>(
    mut stream: TcpStream,
    seed_identity: NodeIdentity,
    allowlist: AllowedAdminPubkeys,
    handler: Arc<H>,
) -> anyhow::Result<()> {
    let _ = stream.set_nodelay(true);

    // 1. Fresh ephemeral X25519 keypair + 32-byte CSPRNG challenge nonce per TCP connection.
    let server_secret = X25519StaticSecret::random_from_rng(OsRng);
    let server_public = X25519PublicKey::from(&server_secret);
    let mut challenge_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut challenge_nonce);

    let hello = ServerHello::issue(&seed_identity, *server_public.as_bytes(), challenge_nonce);
    let hello_bytes = serialize_wire(&hello)?;
    write_length_prefixed_frame(&mut stream, &hello_bytes).await?;

    // 2. Read `client_ephemeral_x25519 (32B) || len_u32_be || ciphertext`.
    let mut client_x25519_bytes = [0u8; 32];
    stream.read_exact(&mut client_x25519_bytes).await?;
    let ciphertext =
        read_length_prefixed_frame(&mut stream, MAX_ADMIN_RPC_FRAME_BYTES + 64).await?;

    let client_public = X25519PublicKey::from(client_x25519_bytes);
    let shared = server_secret.diffie_hellman(&client_public);
    let mut shared_bytes = *shared.as_bytes();
    if shared_bytes.iter().all(|&b| b == 0) {
        anyhow::bail!("rejected low-order client X25519 public key");
    }
    let mut aead_key = derive_admin_rpc_aead_key(&shared_bytes, &challenge_nonce);
    shared_bytes.zeroize();

    let cipher = ChaCha20Poly1305::new((&aead_key).into());
    let req_nonce = Nonce::from([0u8; 12]);
    let decrypted = cipher
        .decrypt(&req_nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("admin_rpc ChaCha20Poly1305 decryption failed"));
    let mut req_plain = match decrypted {
        Ok(p) => p,
        Err(e) => {
            aead_key.zeroize();
            return Err(e);
        }
    };
    let auth_req_res: anyhow::Result<AuthenticatedAdminRpcRequest> = deserialize_wire(&req_plain);
    req_plain.zeroize();
    let auth_req = match auth_req_res {
        Ok(r) => r,
        Err(e) => {
            aead_key.zeroize();
            return Err(e);
        }
    };

    // 3. Verify allowlisted operator pubkey, fresh challenge_nonce, clock skew, and Ed25519 signature.
    let now_ms = now_unix_ms();
    let response = match validate_admin_rpc_replay_and_auth_meta(
        &allowlist,
        &auth_req.admin_pubkey,
        &challenge_nonce,
        &auth_req.challenge_nonce,
        now_ms,
        auth_req.timestamp_ms,
    ) {
        Err(reason) => SeedAdminResponse::Error {
            message: reason.to_string(),
        },
        Ok(()) => {
            let expected_sign_bytes = admin_rpc_request_sign_bytes(
                &challenge_nonce,
                auth_req.timestamp_ms,
                &auth_req.request,
            );
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&auth_req.sig_r);
            sig[32..].copy_from_slice(&auth_req.sig_s);
            if !NodeIdentity::verify_with_pubkey(&auth_req.admin_pubkey, &expected_sign_bytes, &sig)
            {
                SeedAdminResponse::Error {
                    message: "invalid Ed25519 signature on admin_rpc request".to_string(),
                }
            } else {
                let req = auth_req.request;
                let h = Arc::clone(&handler);
                match tokio::task::spawn_blocking(move || h.handle_request(req)).await {
                    Ok(resp) => resp,
                    Err(join_err) => SeedAdminResponse::Error {
                        message: format!("admin_rpc handler panicked: {join_err}"),
                    },
                }
            }
        }
    };

    // 4. Encrypt & write `len_u32_be || ChaCha20Poly1305(nonce = [1u8; 12], bincode::serialize(&response))`.
    let mut resp_plain = serialize_wire(&response)?;
    let resp_nonce = Nonce::from([1u8; 12]);
    let resp_ct = cipher
        .encrypt(&resp_nonce, resp_plain.as_ref())
        .map_err(|_| anyhow::anyhow!("admin_rpc response encryption failed"));
    resp_plain.zeroize();
    aead_key.zeroize();
    let resp_ct = resp_ct?;
    write_length_prefixed_frame(&mut stream, &resp_ct).await?;
    Ok(())
}

async fn write_length_prefixed_frame(stream: &mut TcpStream, payload: &[u8]) -> anyhow::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| anyhow::anyhow!("admin_rpc frame overflows u32"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_length_prefixed_frame(
    stream: &mut TcpStream,
    max_len: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let (len, initial_cap) = validate_admin_rpc_frame_header(len_buf, max_len)?;
    let mut out = Vec::with_capacity(initial_cap);
    let mut limited = (&mut *stream).take(len as u64);
    let n = limited.read_to_end(&mut out).await?;
    if n != len {
        anyhow::bail!("truncated admin_rpc frame: expected {len} bytes, got {n}");
    }
    Ok(out)
}

#[cfg(test)]
mod golden_wire {
    //! Item 6 (plan-6 ruling change 5): the bincode encoding of every `SeedAdminRequest`
    //! variant and of the request sign bytes is pinned, so an appended variant cannot shift
    //! the indices or layout older seeds and `parvault-control` decode.
    use super::*;
    use crate::storage::EvictionTarget;

    fn requests() -> Vec<(&'static str, SeedAdminRequest)> {
        vec![
            ("GetSeedTelemetry", SeedAdminRequest::GetSeedTelemetry),
            (
                "SyncTakedownQueue",
                SeedAdminRequest::SyncTakedownQueue {
                    since_timestamp_ms: 7,
                },
            ),
            (
                "ResolveTargetImpact",
                SeedAdminRequest::ResolveTargetImpact {
                    target: EvictionTarget::PeerOrIssuerPubkey([0x11; 32]),
                },
            ),
            (
                "ExecuteSignedEvictionBatch",
                SeedAdminRequest::ExecuteSignedEvictionBatch {
                    orders: Vec::new(),
                    propagate_to_swarm: true,
                },
            ),
            (
                "RecordTakedownDecision",
                SeedAdminRequest::RecordTakedownDecision {
                    report_id: [0x22; 32],
                    approved: true,
                    admin_pubkey: [0x33; 32],
                    note: "ok".to_string(),
                },
            ),
            (
                "UpdateAdmissionPolicy",
                SeedAdminRequest::UpdateAdmissionPolicy {
                    min_public_pow_bits: 12,
                    max_probationary_lease_bytes: 4096,
                },
            ),
            (
                "InstallCouncilManifest",
                SeedAdminRequest::InstallCouncilManifest {
                    manifest_bytes: vec![1, 2, 3],
                },
            ),
        ]
    }

    const GOLDEN: &[(&str, &str)] = &[
        ("GetSeedTelemetry", "00000000"),
        ("SyncTakedownQueue", "010000000700000000000000"),
        ("ResolveTargetImpact", "02000000030000001111111111111111111111111111111111111111111111111111111111111111"),
        ("ExecuteSignedEvictionBatch", "03000000000000000000000001"),
        ("RecordTakedownDecision", "04000000222222222222222222222222222222222222222222222222222222222222222201333333333333333333333333333333333333333333333333333333333333333302000000000000006f6b"),
        ("UpdateAdmissionPolicy", "050000000c0010000000000000"),
        ("InstallCouncilManifest", "060000000300000000000000010203"),
    ];
    const GOLDEN_SIGN_BYTES: &str = "7061727661756c742d61646d696e2d7270632d7265712d76313a44444444444444444444444444444444444444444444444444444444444444440068e5cf8b010000060000000300000000000000010203";

    #[test]
    fn every_request_variant_has_pinned_bytes() {
        let got: Vec<(&str, String)> = requests()
            .into_iter()
            .map(|(n, r)| (n, hex::encode(bincode::serialize(&r).unwrap())))
            .collect();
        let wanted: Vec<(&str, String)> = GOLDEN.iter().map(|(n, h)| (*n, h.to_string())).collect();
        assert_eq!(
            got, wanted,
            "SeedAdminRequest encoding changed; got {got:#?}"
        );
    }

    #[test]
    fn request_sign_bytes_are_pinned() {
        let req = SeedAdminRequest::InstallCouncilManifest {
            manifest_bytes: vec![1, 2, 3],
        };
        let bytes = admin_rpc_request_sign_bytes(&[0x44; 32], 1_700_000_000_000, &req);
        assert_eq!(hex::encode(bytes), GOLDEN_SIGN_BYTES);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::merkle::hash_shard_leaf;
    use crate::storage::{BlockStore, PrivacyPreservingEvictionEngine, QuotaManager, ShardId};
    use std::net::IpAddr;
    use std::sync::Mutex;

    #[tokio::test]
    async fn test_admin_rpc_forward_secret_roundtrip_and_zero_plaintext_ip_disk_invariant(
    ) -> anyhow::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let seed_dir = temp_dir.path().join("seed-eu");
        let seed_id = NodeIdentity::generate();
        let operator_id = NodeIdentity::generate();
        let rogue_id = NodeIdentity::generate();

        let quota = QuotaManager::new(1024 * 1024 * 1024, 64 * 1024 * 1024);
        let block_store = BlockStore::new(&seed_dir, quota)?;
        let mut eviction = PrivacyPreservingEvictionEngine::load_or_init(&seed_dir)?;

        let warrant_ip: IpAddr = "203.0.113.66".parse()?;
        let bad_actor_pk = NodeIdentity::generate().public_key_bytes();
        eviction.record_peer_admission_ip(warrant_ip, bad_actor_pk)?;

        let shard_bytes = vec![0xAB; 4096];
        let shard_id = ShardId {
            stripe_merkle_root: [0x55; 32],
            shard_index: 0,
            shard_hash: hash_shard_leaf(0, &shard_bytes),
        };
        block_store.put_shard("bad-peer", &shard_id, &shard_bytes)?;
        eviction.record_regular_shard_ingress(
            Some(warrant_ip),
            Some("bad-peer"),
            Some(bad_actor_pk),
            "bad-peer",
            shard_id,
        )?;

        let shared_eviction = Arc::new(Mutex::new(eviction));
        let store_clone = block_store.clone();
        let seed_pk = seed_id.public_key_bytes();

        let (bound_addr, _handle) = spawn_admin_rpc_listener(
            "127.0.0.1:0".parse()?,
            seed_id,
            vec![operator_id.public_key_bytes()],
            move |req| match req {
                SeedAdminRequest::GetSeedTelemetry => {
                    SeedAdminResponse::Telemetry(SeedTelemetrySnapshot {
                        seed_peer_id: "seed-eu".to_string(),
                        seed_ed25519_pubkey: seed_pk,
                        mode: "public-bootstrap".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        uptime_secs: 42,
                        rss_kib: 6144,
                        hwm_kib: 8192,
                        stored_regular_shards: 1,
                        stored_blinded_shards: 0,
                        used_storage_bytes: 4096,
                        max_storage_bytes: 1024 * 1024 * 1024,
                        active_public_peers: 5,
                        unique_ipv4_24_subnets: 4,
                        unique_ipv6_48_subnets: 1,
                        min_public_pow_bits: 12,
                        max_probationary_lease_bytes: 64 * 1024 * 1024,
                        pending_takedowns_count: 0,
                        active_eviction_blocks_count: 0,
                        council_quorum_threshold: 2,
                    })
                }
                SeedAdminRequest::ResolveTargetImpact { target } => {
                    let ev = shared_eviction.lock().expect("eviction lock");
                    let (resolved_pubkeys, reg, blind, bytes) =
                        ev.count_matching_shards_dry_run(&target, &store_clone);
                    SeedAdminResponse::TargetImpact {
                        resolved_pubkeys,
                        local_regular_shards: reg,
                        local_blinded_shards: blind,
                        estimated_local_bytes: bytes,
                        reachable_public_peers: 3,
                    }
                }
                _ => SeedAdminResponse::Ack {
                    ok: true,
                    message: None,
                },
            },
        )
        .await?;

        let endpoint = bound_addr.to_string();

        // 1. Authorized operator gets telemetry and verifies pinned `seed_pk`.
        let (resp, verified_seed_pk) = send_admin_rpc_with_signer(
            &endpoint,
            Some(seed_pk),
            operator_id.public_key_bytes(),
            &SeedAdminRequest::GetSeedTelemetry,
            |payload| Ok(operator_id.sign(payload)),
        )
        .await?;
        assert_eq!(verified_seed_pk, seed_pk);
        match resp {
            SeedAdminResponse::Telemetry(snap) => {
                assert_eq!(snap.seed_peer_id, "seed-eu");
                assert_eq!(snap.council_quorum_threshold, 2);
            }
            other => panic!("expected Telemetry, got {other:?}"),
        }

        // 2. Unauthorized `rogue_id` is rejected cleanly.
        let (rogue_resp, _) = send_admin_rpc_with_identity(
            &endpoint,
            Some(seed_pk),
            &rogue_id,
            &SeedAdminRequest::GetSeedTelemetry,
        )
        .await?;
        assert!(matches!(rogue_resp, SeedAdminResponse::Error { .. }));

        // 3. Wrong pinned `expected_seed_pubkey` fails client MITM verification before sending request.
        let wrong_pin = send_admin_rpc_with_identity(
            &endpoint,
            Some([0xFF; 32]),
            &operator_id,
            &SeedAdminRequest::GetSeedTelemetry,
        )
        .await;
        assert!(wrong_pin.is_err());

        // 4. ResolveTargetImpact resolves HMAC cohort in RAM with ZERO plaintext IPs written to disk!
        let (impact_resp, _) = send_admin_rpc_with_identity(
            &endpoint,
            Some(seed_pk),
            &operator_id,
            &SeedAdminRequest::ResolveTargetImpact {
                target: EvictionTarget::IpAddress(warrant_ip),
            },
        )
        .await?;
        match impact_resp {
            SeedAdminResponse::TargetImpact {
                resolved_pubkeys,
                local_regular_shards,
                local_blinded_shards,
                estimated_local_bytes,
                reachable_public_peers,
            } => {
                assert_eq!(resolved_pubkeys, vec![bad_actor_pk]);
                assert_eq!(local_regular_shards, 1);
                assert_eq!(local_blinded_shards, 0);
                assert_eq!(estimated_local_bytes, 4096);
                assert_eq!(reachable_public_peers, 3);
            }
            other => panic!("expected TargetImpact, got {other:?}"),
        }

        // Verify ZERO occurrences of `"203.0.113.66"` or `[203, 0, 113, 66]` in `eviction_index.bin`.
        let raw_index = std::fs::read(seed_dir.join("eviction_index.bin"))?;
        assert!(
            !raw_index
                .windows("203.0.113.66".len())
                .any(|w| w == b"203.0.113.66"),
            "ASCII IP leaked to eviction_index.bin"
        );
        assert!(
            !raw_index.windows(4).any(|w| w == [203u8, 0, 113, 66]),
            "Raw IPv4 octets leaked to eviction_index.bin"
        );

        Ok(())
    }
}
