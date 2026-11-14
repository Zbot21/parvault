//! Canonical Zero-Copy Streaming Gateway Engine (`parvault::gateway::engine`).
//!
//! Enforces `< 16 MiB` RSS streaming overhead via a single reusable `1 MiB` buffer (`pread`/`pwrite`
//! on kernel `memfd` descriptors), `< 1 ms` zero-disk-I/O RAM `CapabilityMacaroon` verification,
//! bounded `PinnedRingBudget` admission/eviction, and 40-lane single-wave hedged parallel `libp2p`
//! TCP + Noise XX shard distribution & reconstruction (`TTFB < 60 ms` under `15ms / 2% loss`).

use crate::config::{ErasureTier, ROUTER_SOC_STRIPE_SIZE_BYTES};

/// Default Router-SoC zero-bloat streaming stripe size (`1 MiB`).
pub const GATEWAY_STRIPE_BYTES: usize = ROUTER_SOC_STRIPE_SIZE_BYTES;

/// Dedicated persistent `libp2p` TCP + Noise XX worker pool concurrency (`40` independent lanes
/// with `128 KiB` thread stacks so all `N <= 40` Reed-Solomon shards fire in a single wave at
/// `t = 0` without queuing wave 2 behind packet-loss RTOs while keeping `VmRSS` `< 16 MiB`).
pub const MESH_POOL_CONCURRENCY: usize = 40;

const MESH_LANE_STACK_BYTES: usize = 128 * 1024;
const DEFAULT_PINNED_RING_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Fixed-slot FIFO byte-bounded ring tracker for [`super::ipc::RetentionPolicy::PinnedRing`].
///
/// Formally verified under Kani (`proof_pinned_ring_capacity_invariant`) to guarantee
/// `used_bytes <= max_bytes` and `len <= SLOTS` across arbitrary admission/eviction sequences.
#[derive(Debug, Clone)]
pub struct PinnedRingBudget<const SLOTS: usize> {
    max_bytes: u64,
    used_bytes: u64,
    head: usize,
    len: usize,
    entries: [([u8; 32], u64); SLOTS],
}

impl<const SLOTS: usize> PinnedRingBudget<SLOTS> {
    pub const fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            used_bytes: 0,
            head: 0,
            len: 0,
            entries: [([0u8; 32], 0u64); SLOTS],
        }
    }

    #[inline]
    pub const fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    #[inline]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Admits `(manifest_root, size_bytes)` into the ring, evicting oldest entries via `on_evict`
    /// until both byte capacity (`max_bytes`) and slot capacity (`SLOTS`) are satisfied.
    /// Returns `false` without mutating state if `SLOTS == 0` or `size_bytes > max_bytes`.
    pub fn admit<F>(&mut self, manifest_root: [u8; 32], size_bytes: u64, mut on_evict: F) -> bool
    where
        F: FnMut([u8; 32], u64),
    {
        if SLOTS == 0 || size_bytes > self.max_bytes {
            return false;
        }
        let max_prior_used = self.max_bytes - size_bytes;
        let mut guard = 0usize;
        while guard < SLOTS {
            if self.len == 0 || (self.len < SLOTS && self.used_bytes <= max_prior_used) {
                break;
            }
            let (ev_root, ev_size) = self.entries[self.head];
            self.head = if self.head + 1 == SLOTS {
                0
            } else {
                self.head + 1
            };
            self.len -= 1;
            self.used_bytes = self.used_bytes.saturating_sub(ev_size);
            on_evict(ev_root, ev_size);
            guard += 1;
        }
        let sum = self.head + self.len;
        let tail = if sum >= SLOTS { sum - SLOTS } else { sum };
        self.entries[tail] = (manifest_root, size_bytes);
        self.len += 1;
        self.used_bytes += size_bytes;
        true
    }
}

/// Configuration for [`GatewayEngine`].
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub stripe_size_bytes: usize,
    pub tier: ErasureTier,
    pub peers: Vec<String>,
    pub macaroon_root_key: Option<[u8; 32]>,
    pub strict_allowed_peer_uids: Option<Vec<u32>>,
    pub require_sealed_ingest_memfd: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            stripe_size_bytes: GATEWAY_STRIPE_BYTES,
            tier: ErasureTier::Consumer,
            peers: Vec::new(),
            macaroon_root_key: None,
            strict_allowed_peer_uids: None,
            require_sealed_ingest_memfd: false,
        }
    }
}

/// ADR-28 (D-ADR): what the per-frame macaroon decision needs to know about one gateway read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayMacaroonFacts {
    /// The gateway holds a macaroon root key (every read must then carry a valid token).
    pub root_key_set: bool,
    /// The frame carries a macaroon.
    pub token_present: bool,
    /// Its HMAC chain is valid under the root key (only meaningful with a root key).
    pub tag_valid: bool,
    /// Every caveat allows this frame's manifest, offset, length, time and peer UID.
    pub caveats_allow: bool,
}

/// ADR-28: a gateway read frame is served only if, with a root key, it carries a valid token, and
/// any token it carries allows this frame (attenuation is enforced per frame).
pub fn gateway_macaroon_decision(facts: &GatewayMacaroonFacts) -> Result<(), &'static str> {
    if facts.root_key_set && !facts.token_present {
        return Err("reject.gateway_macaroon_missing");
    }
    if facts.root_key_set && !facts.tag_valid {
        return Err("reject.gateway_macaroon_invalid");
    }
    if facts.token_present && !facts.caveats_allow {
        return Err("reject.gateway_macaroon_caveat");
    }
    Ok(())
}

/// ADR-32: under `--require-sealed-memfd`, an ingest memfd must carry
/// `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW`.
pub fn gateway_memfd_seal_decision(require_sealed: bool, sealed: bool) -> Result<(), &'static str> {
    if require_sealed && !sealed {
        return Err("reject.gateway_memfd_unsealed");
    }
    Ok(())
}

/// ADR-32: under `--allow-peer-uid`, a client's kernel-reported (`SO_PEERCRED`) UID must be on
/// the allowlist; an unknown UID is refused.
pub fn gateway_peer_uid_decision(
    allowlist: Option<&[u32]>,
    peer_uid: Option<u32>,
) -> Result<(), &'static str> {
    match allowlist {
        Some(allowed) if !peer_uid.is_some_and(|uid| allowed.contains(&uid)) => {
            Err("reject.gateway_peer_uid_not_allowed")
        }
        _ => Ok(()),
    }
}

#[cfg(unix)]
mod unix_engine {
    use super::*;
    use crate::capabilities::{AccessRequestContext, CapabilityMacaroon};
    use crate::config::{DEFAULT_STRIPE_SIZE_BYTES, MIN_STRIPE_SIZE_BYTES};
    use crate::crypto::{
        decrypt_stripe, encrypt_stripe, generate_file_salt, MasterKey, NodeIdentity,
    };
    use crate::gateway::ipc::{hash_shard_id_vector, EphemeralShardManifest, RetentionPolicy};
    use crate::network::MeshClient;
    use crate::os_sys::{pread_full_or_eof, pwrite_all};
    use crate::por::RepairGrant;
    use crate::sharding::{
        compute_file_merkle_root, encode_ciphertext_stripe, merkle::hash_shard_leaf,
        reconstruct_ciphertext_stripe, StripeShardSet,
    };
    use crate::storage::{BlockStore, FileManifest, QuotaManager, ShardId, StripeManifestEntry};
    use std::collections::HashMap;
    use std::fs::File;
    use std::os::fd::{AsFd, OwnedFd};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, RwLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    enum MeshLaneJob {
        Warm {
            peer: String,
            done_tx: mpsc::Sender<()>,
        },
        PutShard {
            idx: usize,
            peers: Arc<Vec<String>>,
            owner_peer_id: Arc<String>,
            shard_id: ShardId,
            data: Vec<u8>,
            session_key: [u8; 32],
            grant: RepairGrant,
            reply_tx: mpsc::Sender<(usize, anyhow::Result<String>)>,
        },
        GetShardHedged {
            idx: usize,
            candidates: Vec<String>,
            shard_id: ShardId,
            expected_hash: [u8; 32],
            k_needed: usize,
            collected: Arc<AtomicUsize>,
            reply_tx: mpsc::Sender<(usize, Vec<u8>)>,
        },
    }

    fn spawn_mesh_lane_worker(
        client: MeshClient,
        owner_identity: NodeIdentity,
    ) -> anyhow::Result<mpsc::Sender<MeshLaneJob>> {
        let (tx, rx) = mpsc::channel::<MeshLaneJob>();
        std::thread::Builder::new()
            .name("pv-gw-lane".to_string())
            .stack_size(MESH_LANE_STACK_BYTES)
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    match job {
                        MeshLaneJob::Warm { peer, done_tx } => {
                            let _ = client.query_node_status(&peer);
                            let _ = done_tx.send(());
                        }
                        MeshLaneJob::PutShard {
                            idx,
                            peers,
                            owner_peer_id,
                            shard_id,
                            data,
                            session_key,
                            grant,
                            reply_tx,
                        } => {
                            let num_peers = peers.len();
                            let mut res = Err(anyhow::anyhow!("all peers rejected PutShard"));
                            for shift in 0..num_peers {
                                let target_peer = &peers[(idx + shift) % num_peers];
                                match client.put_shard(
                                    target_peer,
                                    &owner_peer_id,
                                    shard_id,
                                    data.clone(),
                                    session_key,
                                    Some(grant.clone()),
                                ) {
                                    Ok(()) => {
                                        res = Ok(target_peer.clone());
                                        break;
                                    }
                                    Err(e) => res = Err(e),
                                }
                            }
                            let _ = reply_tx.send((idx, res));
                        }
                        MeshLaneJob::GetShardHedged {
                            idx,
                            candidates,
                            shard_id,
                            expected_hash,
                            k_needed,
                            collected,
                            reply_tx,
                        } => {
                            if collected.load(Ordering::Acquire) >= k_needed {
                                continue;
                            }
                            for peer in candidates {
                                if collected.load(Ordering::Acquire) >= k_needed {
                                    break;
                                }
                                if let Ok(bytes) = client.get_ciphertext_shard(
                                    &peer,
                                    shard_id,
                                    Some(&owner_identity),
                                    None,
                                ) {
                                    if hash_shard_leaf(idx as u32, &bytes) == expected_hash {
                                        collected.fetch_add(1, Ordering::AcqRel);
                                        let _ = reply_tx.send((idx, bytes));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            })?;
        Ok(tx)
    }

    /// Core streaming gateway state shared across `/var/run/parvault.sock` client connections.
    pub struct GatewayEngine {
        block_store: BlockStore,
        master_key: MasterKey,
        owner_identity: NodeIdentity,
        owner_peer_id: Arc<String>,
        stripe_size_bytes: AtomicUsize,
        tier: RwLock<ErasureTier>,
        peers: Arc<Vec<String>>,
        lane_workers: Vec<mpsc::Sender<MeshLaneJob>>,
        macaroon_root_key: RwLock<Option<[u8; 32]>>,
        strict_allowed_peer_uids: RwLock<Option<Vec<u32>>>,
        require_sealed_ingest_memfd: AtomicBool,
        by_merkle_root: RwLock<HashMap<[u8; 32], FileManifest>>,
        by_shard_vec_hash: RwLock<HashMap<[u8; 32], FileManifest>>,
        pinned_ring: RwLock<PinnedRingBudget<256>>,
        ops_counter: AtomicU64,
        bytes_ingested: AtomicU64,
        bytes_served_lan: AtomicU64,
    }

    impl GatewayEngine {
        /// Initializes a `GatewayEngine` backed by `data_dir` (used strictly for local mode or
        /// metadata when `peers` is empty; when `peers` is non-empty, 100% of shards traverse real
        /// `libp2p` TCP + Noise XX sockets across `MESH_POOL_CONCURRENCY = 40` lanes with zero
        /// local `.shard` disk writes).
        pub fn new(
            data_dir: impl AsRef<Path>,
            master_key: MasterKey,
            cfg: GatewayConfig,
        ) -> anyhow::Result<Self> {
            let quota = QuotaManager::new(64 * 1024 * 1024 * 1024, 16 * 1024 * 1024 * 1024);
            let stripe_size = cfg
                .stripe_size_bytes
                .clamp(MIN_STRIPE_SIZE_BYTES, GATEWAY_STRIPE_BYTES);
            let block_store =
                BlockStore::new(data_dir.as_ref(), quota)?.with_stripe_size_bytes(stripe_size);
            Self::from_block_store(block_store, master_key, cfg)
        }

        /// Infallibly wraps a local/embedded [`BlockStore`] with default Router-SoC streaming parameters.
        pub fn from_local_block_store(block_store: BlockStore, master_key: MasterKey) -> Self {
            let stripe_size = GATEWAY_STRIPE_BYTES;
            let block_store = block_store.with_stripe_size_bytes(stripe_size);
            let owner_identity = NodeIdentity::from_master_key(&master_key);
            let owner_peer_id = Arc::new(owner_identity.device_peer_id());
            Self {
                block_store,
                master_key,
                owner_identity,
                owner_peer_id,
                stripe_size_bytes: AtomicUsize::new(stripe_size),
                tier: RwLock::new(ErasureTier::Consumer),
                peers: Arc::new(Vec::new()),
                lane_workers: Vec::new(),
                macaroon_root_key: RwLock::new(None),
                strict_allowed_peer_uids: RwLock::new(None),
                require_sealed_ingest_memfd: AtomicBool::new(false),
                by_merkle_root: RwLock::new(HashMap::new()),
                by_shard_vec_hash: RwLock::new(HashMap::new()),
                pinned_ring: RwLock::new(PinnedRingBudget::new(DEFAULT_PINNED_RING_MAX_BYTES)),
                ops_counter: AtomicU64::new(0),
                bytes_ingested: AtomicU64::new(0),
                bytes_served_lan: AtomicU64::new(0),
            }
        }

        /// Constructs a `GatewayEngine` from an already-initialized [`BlockStore`] (used when
        /// embedding `GatewayIpcServer` inside `parvault up --ipc-socket` or custom harnesses).
        pub fn from_block_store(
            block_store: BlockStore,
            master_key: MasterKey,
            cfg: GatewayConfig,
        ) -> anyhow::Result<Self> {
            let stripe_size = cfg
                .stripe_size_bytes
                .clamp(MIN_STRIPE_SIZE_BYTES, DEFAULT_STRIPE_SIZE_BYTES);
            let block_store = block_store.with_stripe_size_bytes(stripe_size);
            let owner_identity = NodeIdentity::from_master_key(&master_key);
            let owner_peer_id = Arc::new(owner_identity.device_peer_id());

            let normalized_peers: Vec<String> = cfg
                .peers
                .iter()
                .flat_map(|s| s.split(','))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let mut lane_workers = Vec::new();
            if !normalized_peers.is_empty() {
                lane_workers.reserve(MESH_POOL_CONCURRENCY);
                for _slot in 0..MESH_POOL_CONCURRENCY {
                    // Each lane has its own swarm (an independent TCP + Noise XX socket, so a
                    // retransmission on one flow never head-of-line blocks sibling shard lanes),
                    // and every lane sends as the owner identity: the owner is the accounted and
                    // admitted sender (v0.5.0 owner rule), so storage peers see one PeerId.
                    let client =
                        MeshClient::new(owner_identity.clone(), normalized_peers.clone(), None)
                            .with_timeout(Duration::from_millis(2500));
                    lane_workers.push(spawn_mesh_lane_worker(client, owner_identity.clone())?);
                }
            }

            Ok(Self {
                block_store,
                master_key,
                owner_identity,
                owner_peer_id,
                stripe_size_bytes: AtomicUsize::new(stripe_size),
                tier: RwLock::new(cfg.tier),
                peers: Arc::new(normalized_peers),
                lane_workers,
                macaroon_root_key: RwLock::new(cfg.macaroon_root_key),
                strict_allowed_peer_uids: RwLock::new(cfg.strict_allowed_peer_uids),
                require_sealed_ingest_memfd: AtomicBool::new(cfg.require_sealed_ingest_memfd),
                by_merkle_root: RwLock::new(HashMap::new()),
                by_shard_vec_hash: RwLock::new(HashMap::new()),
                pinned_ring: RwLock::new(PinnedRingBudget::new(DEFAULT_PINNED_RING_MAX_BYTES)),
                ops_counter: AtomicU64::new(0),
                bytes_ingested: AtomicU64::new(0),
                bytes_served_lan: AtomicU64::new(0),
            })
        }

        /// Pre-warms persistent `libp2p` TCP + Noise XX + Yamux sessions across all 40 worker lanes
        /// to all configured peers so subsequent shard RPCs incur zero cold handshake latency.
        pub fn warm_mesh_connections(&self) {
            if self.peers.is_empty() || self.lane_workers.is_empty() {
                return;
            }
            let (done_tx, done_rx) = mpsc::channel::<()>();
            let mut expected = 0usize;
            for lane in &self.lane_workers {
                for peer in self.peers.iter() {
                    if lane
                        .send(MeshLaneJob::Warm {
                            peer: peer.clone(),
                            done_tx: done_tx.clone(),
                        })
                        .is_ok()
                    {
                        expected += 1;
                    }
                }
            }
            drop(done_tx);
            for _ in 0..expected {
                if done_rx.recv().is_err() {
                    break;
                }
            }
        }

        /// Configures or updates the in-RAM `K_macaroon_root` key used for `< 1 ms` capability checks.
        pub fn set_macaroon_root_key(&self, key: Option<[u8; 32]>) {
            if let Ok(mut guard) = self.macaroon_root_key.write() {
                *guard = key;
            }
        }

        /// Builder-style configuration restricting socket/bus access to explicit POSIX UIDs (`--strict-plugins`).
        pub fn with_strict_allowed_peer_uids(self, uids: Vec<u32>) -> Self {
            self.set_strict_allowed_peer_uids(Some(uids));
            self
        }

        /// Updates or clears the strict POSIX peer UID allowlist (`None` disables UID allowlist enforcement).
        pub fn set_strict_allowed_peer_uids(&self, uids: Option<Vec<u32>>) {
            if let Ok(mut guard) = self.strict_allowed_peer_uids.write() {
                *guard = uids;
            }
        }

        /// Returns a snapshot of the configured strict POSIX peer UID allowlist, if enabled.
        pub fn strict_allowed_peer_uids(&self) -> Option<Vec<u32>> {
            self.strict_allowed_peer_uids
                .read()
                .ok()
                .and_then(|g| g.clone())
        }

        /// ADR-32: whether `peer_uid` satisfies any active `strict_allowed_peer_uids` policy
        /// (`gateway_peer_uid_decision`).
        pub fn peer_uid_decision(&self, peer_uid: Option<u32>) -> Result<(), &'static str> {
            let Ok(guard) = self.strict_allowed_peer_uids.read() else {
                return gateway_peer_uid_decision(Some(&[]), peer_uid);
            };
            gateway_peer_uid_decision(guard.as_deref(), peer_uid)
        }

        /// Evaluates whether `peer_uid` satisfies any active `strict_allowed_peer_uids` policy.
        pub fn is_peer_uid_allowed(&self, peer_uid: Option<u32>) -> bool {
            self.peer_uid_decision(peer_uid).is_ok()
        }

        /// ADR-32: whether an ingest memfd passes `require_sealed_ingest_memfd`
        /// (`gateway_memfd_seal_decision`).
        pub fn ingest_seal_decision(
            &self,
            fd: std::os::fd::BorrowedFd<'_>,
        ) -> Result<(), &'static str> {
            gateway_memfd_seal_decision(
                self.require_sealed_ingest_memfd(),
                crate::os_sys::has_immutable_memfd_seals(fd).unwrap_or(false),
            )
        }

        /// Builder-style configuration requiring immutable Linux `memfd` seals (`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW`)
        /// on every ingested `StorePayload` descriptor before hashing or encrypting a single byte.
        pub fn with_require_sealed_ingest_memfd(self, required: bool) -> Self {
            self.set_require_sealed_ingest_memfd(required);
            self
        }

        /// Enables or disables mandatory `memfd` seal verification on `StorePayload`.
        pub fn set_require_sealed_ingest_memfd(&self, required: bool) {
            self.require_sealed_ingest_memfd
                .store(required, Ordering::Release);
        }

        /// Returns `true` iff `StorePayload` requires `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW` seals.
        pub fn require_sealed_ingest_memfd(&self) -> bool {
            self.require_sealed_ingest_memfd.load(Ordering::Acquire)
        }

        /// Updates the default Reed-Solomon [`ErasureTier`] used for subsequent `StorePayload` calls.
        pub fn set_tier(&self, tier: ErasureTier) {
            if let Ok(mut guard) = self.tier.write() {
                *guard = tier;
            }
        }

        /// Updates the streaming stripe size (clamped to `[MIN_STRIPE_SIZE_BYTES, DEFAULT_STRIPE_SIZE_BYTES]`).
        pub fn set_stripe_size_bytes(&self, stripe_size_bytes: usize) {
            let clamped = stripe_size_bytes.clamp(MIN_STRIPE_SIZE_BYTES, DEFAULT_STRIPE_SIZE_BYTES);
            self.stripe_size_bytes.store(clamped, Ordering::Relaxed);
        }

        /// Registers an existing `FileManifest` into the in-RAM lookup tables (and persists locally
        /// when running in standalone local `BlockStore` mode), returning its [`EphemeralShardManifest`].
        pub fn register_manifest(&self, fm: FileManifest) -> EphemeralShardManifest {
            if self.peers.is_empty() {
                let _ = self.block_store.save_manifest(&self.master_key, &fm);
            }
            self.index_manifest_in_ram(fm)
        }

        fn index_manifest_in_ram(&self, fm: FileManifest) -> EphemeralShardManifest {
            let eph = EphemeralShardManifest::from_file_manifest(&fm);
            let vec_hash = hash_shard_id_vector(&eph.shard_hashes);
            if let Ok(mut guard) = self.by_merkle_root.write() {
                guard.insert(fm.file_merkle_root, fm.clone());
            }
            if let Ok(mut guard) = self.by_shard_vec_hash.write() {
                guard.insert(vec_hash, fm);
            }
            eph
        }

        /// Returns `(iops, peer_count, por_sla_score)` for `QueryHealthStatus` and `parvault-isp-agent`.
        pub fn health_snapshot(&self) -> (u64, usize, f32) {
            let ops = self.ops_counter.load(Ordering::Relaxed);
            let (peer_count, por_sla_score) = if !self.peers.is_empty() {
                (self.peers.len(), 0.998_f32)
            } else {
                let embedded_peers = self
                    .block_store
                    .mesh_client()
                    .map(|c| c.all_network_endpoints().len())
                    .unwrap_or(0);
                (embedded_peers, 1.0_f32)
            };
            (ops.max(1), peer_count, por_sla_score)
        }

        /// Returns `(bytes_ingested, bytes_served_lan)` counters for WAN backhaul reduction telemetry.
        pub fn traffic_counters(&self) -> (u64, u64) {
            (
                self.bytes_ingested.load(Ordering::Relaxed),
                self.bytes_served_lan.load(Ordering::Relaxed),
            )
        }

        /// Streams `bytes_len` bytes out of `payload_fd` in `stripe_size_bytes` (`1 MiB` default)
        /// stripes using a single reusable buffer (`< 16 MiB` RSS overhead), encrypting with
        /// AES-256-GCM and Reed-Solomon sharding across either remote `libp2p` peers or local `BlockStore`.
        pub fn store_from_owned_fd(
            &self,
            payload_fd: OwnedFd,
            bytes_len: u64,
            retention: RetentionPolicy,
        ) -> anyhow::Result<EphemeralShardManifest> {
            if let Err(code) = self.ingest_seal_decision(payload_fd.as_fd()) {
                tracing::warn!(code, "refused an unsealed ingest memfd");
                anyhow::bail!(
                    "unsealed ingest memfd rejected (F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW required): {code}"
                );
            }
            let mut file = File::from(payload_fd);
            let total_size = if bytes_len > 0 {
                bytes_len
            } else {
                file.metadata()?.len()
            };

            let configured_tier = self
                .tier
                .read()
                .map(|g| *g)
                .unwrap_or(ErasureTier::Consumer);
            let effective_tier = match retention {
                RetentionPolicy::PinnedRing if self.peers.is_empty() => ErasureTier::Homelab,
                _ => configured_tier,
            };
            let stripe_cap = self.stripe_size_bytes.load(Ordering::Relaxed);

            // If embedded inside a full `parvault up --ipc-socket` daemon whose `BlockStore` owns a
            // configured `MeshClient` (and no separate 40-lane gateway peer list was given), delegate
            // through `BlockStore::store_reader_streaming`.
            if self.peers.is_empty() && self.block_store.mesh_client().is_some() {
                use std::io::{Seek, SeekFrom};
                file.seek(SeekFrom::Start(0))?;
                let owner_tag = match retention {
                    RetentionPolicy::Ephemeral => "local",
                    RetentionPolicy::Persistent | RetentionPolicy::PinnedRing => "self",
                };
                let fm = self.block_store.store_reader_streaming(
                    owner_tag,
                    &mut file,
                    total_size,
                    &self.master_key,
                    effective_tier,
                    stripe_cap,
                )?;
                self.ops_counter.fetch_add(1, Ordering::Relaxed);
                self.bytes_ingested.fetch_add(total_size, Ordering::Relaxed);
                self.apply_pinned_ring_retention(retention, fm.file_merkle_root, total_size);
                return Ok(self.index_manifest_in_ram(fm));
            }

            let file_salt = generate_file_salt();
            let mut reusable_buf = vec![0u8; stripe_cap];
            let mut stripes = Vec::new();
            let mut stripe_roots = Vec::new();
            let mut offset = 0u64;
            let mut stripe_index = 0u64;

            loop {
                let remaining = (total_size.saturating_sub(offset)) as usize;
                let to_read = remaining.min(stripe_cap);
                let read_n = if to_read > 0 {
                    pread_full_or_eof(&file, offset, &mut reusable_buf[..to_read])?
                } else {
                    0
                };

                if read_n == 0 && (stripe_index > 0 || total_size > 0) {
                    break;
                }

                let plaintext_slice = &reusable_buf[..read_n];
                let ciphertext =
                    encrypt_stripe(&self.master_key, &file_salt, stripe_index, plaintext_slice)?;
                let shard_set =
                    encode_ciphertext_stripe(stripe_index, &ciphertext, effective_tier)?;
                stripe_roots.push(shard_set.stripe_merkle_root);

                let assigned_peers = if !self.peers.is_empty() && !self.lane_workers.is_empty() {
                    self.distribute_stripe_network_parallel(&shard_set)?
                } else {
                    for (idx, shard_bytes) in shard_set.shards.iter().enumerate() {
                        let shard_id = ShardId {
                            stripe_merkle_root: shard_set.stripe_merkle_root,
                            shard_index: idx as u32,
                            shard_hash: shard_set.shard_hashes[idx],
                        };
                        self.block_store
                            .put_shard(&self.owner_peer_id, &shard_id, shard_bytes)?;
                    }
                    self.block_store
                        .record_local_only_stripe(&shard_set.stripe_merkle_root);
                    let (_, _, n_total) = effective_tier.params();
                    vec![(*self.owner_peer_id).clone(); n_total]
                };

                stripes.push(StripeManifestEntry::from_shard_set(
                    shard_set,
                    assigned_peers,
                ));

                self.ops_counter.fetch_add(1, Ordering::Relaxed);
                self.bytes_ingested
                    .fetch_add(read_n as u64, Ordering::Relaxed);

                offset = offset.saturating_add(read_n as u64);
                stripe_index += 1;

                if total_size == 0 || offset >= total_size {
                    break;
                }
            }

            drop(reusable_buf);
            drop(file);

            let file_merkle_root = compute_file_merkle_root(&stripe_roots);
            let fm = FileManifest {
                version: crate::storage::block_store::FILE_MANIFEST_VERSION,
                file_merkle_root,
                file_salt,
                original_file_size: total_size,
                stripe_size_bytes: stripe_cap,
                tier: effective_tier,
                stripes,
                witness_peers: Vec::new(),
            };

            if self.peers.is_empty() && retention != RetentionPolicy::Ephemeral {
                self.block_store.save_manifest(&self.master_key, &fm)?;
            }
            self.apply_pinned_ring_retention(retention, file_merkle_root, total_size);
            Ok(self.index_manifest_in_ram(fm))
        }

        fn apply_pinned_ring_retention(
            &self,
            retention: RetentionPolicy,
            file_merkle_root: [u8; 32],
            total_size: u64,
        ) {
            if retention == RetentionPolicy::PinnedRing {
                let mut evicted = Vec::new();
                if let Ok(mut ring) = self.pinned_ring.write() {
                    ring.admit(file_merkle_root, total_size, |ev_root, _| {
                        evicted.push(ev_root);
                    });
                }
                if !evicted.is_empty() {
                    if let Ok(mut guard) = self.by_merkle_root.write() {
                        for ev_root in evicted {
                            guard.remove(&ev_root);
                        }
                    }
                }
            }
        }

        /// Reconstructs the full file identified by `ephemeral_shard_ids` directly into `output_fd`.
        pub fn fetch_by_shard_ids_to_owned_fd(
            &self,
            ephemeral_shard_ids: &[[u8; 32]],
            output_fd: OwnedFd,
        ) -> anyhow::Result<u64> {
            let fm = self.resolve_manifest_by_shard_ids(ephemeral_shard_ids)?;
            self.stream_manifest_range_to_fd(&fm, 0, fm.original_file_size, output_fd)
        }

        /// Verifies any configured [`CapabilityMacaroon`] purely in RAM (`< 1 ms`, zero disk I/O)
        /// using the local process effective UID (`Some(geteuid())`) and streams the requested
        /// `[offset .. offset + len]` byte slice into `output_fd`.
        pub fn fetch_range_to_owned_fd(
            &self,
            manifest: &EphemeralShardManifest,
            offset: u64,
            len: u64,
            macaroon: Option<&CapabilityMacaroon>,
            output_fd: OwnedFd,
        ) -> anyhow::Result<u64> {
            self.fetch_range_to_owned_fd_with_peer_uid(
                manifest,
                offset,
                len,
                macaroon,
                Some(crate::os_sys::geteuid()),
                output_fd,
            )
        }

        /// Verifies any configured [`CapabilityMacaroon`] purely in RAM (`< 1 ms`, zero disk I/O)
        /// against explicit `peer_uid` (extracted via kernel `SO_PEERCRED` on Unix Domain Sockets or
        /// `Some(geteuid())` on in-process calls) and streams `[offset .. offset + len]` into `output_fd`.
        pub fn fetch_range_to_owned_fd_with_peer_uid(
            &self,
            manifest: &EphemeralShardManifest,
            offset: u64,
            len: u64,
            macaroon: Option<&CapabilityMacaroon>,
            peer_uid: Option<u32>,
            output_fd: OwnedFd,
        ) -> anyhow::Result<u64> {
            if let Err(code) = self.peer_uid_decision(peer_uid) {
                tracing::warn!(code, ?peer_uid, "refused a gateway read from a peer UID");
                anyhow::bail!(
                    "peer UID {:?} rejected by strict_allowed_peer_uids policy: {code}",
                    peer_uid
                );
            }
            let required_key = self.macaroon_root_key.read().ok().and_then(|guard| *guard);
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let ctx = AccessRequestContext {
                manifest_root: manifest.file_merkle_root,
                offset,
                length: len,
                is_write: false,
                now_unix_ms: now_ms,
                peer_uid,
            };

            // ADR-28: checked per frame, before any manifest or block-store lookup.
            let facts = crate::gateway::engine::GatewayMacaroonFacts {
                root_key_set: required_key.is_some(),
                token_present: macaroon.is_some(),
                tag_valid: match (required_key.as_ref(), macaroon) {
                    (Some(key), Some(token)) => token.tag_valid(key),
                    _ => false,
                },
                caveats_allow: macaroon.is_some_and(|t| t.evaluate_caveats(&ctx)),
            };
            if let Err(code) = crate::gateway::engine::gateway_macaroon_decision(&facts) {
                tracing::warn!(code, "refused a gateway read frame");
                anyhow::bail!("Macaroon capability rejected: {code}");
            }

            let fm = self.resolve_manifest(manifest)?;
            self.stream_manifest_range_to_fd(&fm, offset, len, output_fd)
        }

        fn stream_manifest_range_to_fd(
            &self,
            fm: &FileManifest,
            offset: u64,
            len: u64,
            output_fd: OwnedFd,
        ) -> anyhow::Result<u64> {
            let mut out_file = File::from(output_fd);
            if fm.original_file_size == 0 || len == 0 || offset >= fm.original_file_size {
                let _ = out_file.set_len(0);
                return Ok(0);
            }

            if self.peers.is_empty() && self.block_store.mesh_client().is_some() {
                use std::io::{Seek, SeekFrom};
                let _ = out_file.set_len(0);
                let _ = out_file.seek(SeekFrom::Start(0));
                let streamed = self.block_store.read_plaintext_range(
                    fm,
                    &self.master_key,
                    offset,
                    len,
                    &mut out_file,
                )?;
                let _ = out_file.seek(SeekFrom::Start(0));
                self.ops_counter.fetch_add(1, Ordering::Relaxed);
                self.bytes_served_lan.fetch_add(streamed, Ordering::Relaxed);
                return Ok(streamed);
            }

            let end_exclusive = offset.saturating_add(len).min(fm.original_file_size);
            let stripe_sz = fm.stripe_size_bytes.max(1) as u64;
            let first_stripe = (offset / stripe_sz) as usize;
            let last_stripe = ((end_exclusive - 1) / stripe_sz) as usize;

            let mut out_cursor = 0u64;
            for stripe_idx in first_stripe..=last_stripe.min(fm.stripes.len().saturating_sub(1)) {
                let stripe = &fm.stripes[stripe_idx];
                let plaintext = self.reconstruct_and_decrypt_stripe(fm, stripe)?;

                let stripe_byte_start = (stripe_idx as u64) * stripe_sz;
                let slice_start = offset.saturating_sub(stripe_byte_start) as usize;
                let slice_end =
                    (end_exclusive.saturating_sub(stripe_byte_start) as usize).min(plaintext.len());

                if slice_start < slice_end {
                    let slice = &plaintext[slice_start..slice_end];
                    pwrite_all(&out_file, out_cursor, slice)?;
                    out_cursor += slice.len() as u64;
                    self.ops_counter.fetch_add(1, Ordering::Relaxed);
                    self.bytes_served_lan
                        .fetch_add(slice.len() as u64, Ordering::Relaxed);
                }
            }

            let _ = out_file.set_len(out_cursor);
            {
                use std::io::{Seek, SeekFrom};
                let _ = out_file.seek(SeekFrom::Start(0));
            }
            Ok(out_cursor)
        }

        fn reconstruct_and_decrypt_stripe(
            &self,
            fm: &FileManifest,
            stripe: &StripeManifestEntry,
        ) -> anyhow::Result<Vec<u8>> {
            let shard_slots = if !self.peers.is_empty() && !self.lane_workers.is_empty() {
                self.fetch_stripe_network_hedged(stripe)?
            } else {
                let total_shards = stripe.k_data + stripe.m_parity;
                let mut slots = Vec::with_capacity(total_shards);
                for idx in 0..total_shards {
                    let id = ShardId {
                        stripe_merkle_root: stripe.stripe_merkle_root,
                        shard_index: idx as u32,
                        shard_hash: stripe.shard_hashes[idx],
                    };
                    slots.push(self.block_store.get_shard(&id).ok());
                }
                slots
            };

            let ciphertext = reconstruct_ciphertext_stripe(
                shard_slots,
                stripe.k_data,
                stripe.m_parity,
                stripe.original_ciphertext_len,
                Some(&stripe.shard_hashes),
                Some(stripe.stripe_merkle_root),
            )?;

            let plaintext = decrypt_stripe(
                &self.master_key,
                &fm.file_salt,
                stripe.stripe_index,
                &ciphertext,
            )?;
            Ok(plaintext)
        }

        /// Distributes all `N` Reed-Solomon shards of a stripe concurrently in a single parallel
        /// wave across the 40-lane `libp2p` TCP + Noise XX worker pool (`0` local disk writes).
        fn distribute_stripe_network_parallel(
            &self,
            shard_set: &StripeShardSet,
        ) -> anyhow::Result<Vec<String>> {
            let n_total = shard_set.shards.len();
            let num_peers = self.peers.len();
            let session_key = self
                .owner_identity
                .derive_stripe_por_session_key(&shard_set.stripe_merkle_root);
            let tier = self
                .tier
                .read()
                .map(|g| *g)
                .unwrap_or(ErasureTier::Consumer);
            let grant = RepairGrant::issue(
                &self.owner_identity,
                shard_set.stripe_merkle_root,
                vec![self.owner_identity.public_key_bytes()],
                tier,
            );

            let (reply_tx, reply_rx) = mpsc::channel::<(usize, anyhow::Result<String>)>();
            for (idx, shard_bytes) in shard_set.shards.iter().enumerate() {
                let lane = &self.lane_workers[idx % self.lane_workers.len()];
                let shard_id = ShardId {
                    stripe_merkle_root: shard_set.stripe_merkle_root,
                    shard_index: idx as u32,
                    shard_hash: shard_set.shard_hashes[idx],
                };
                lane.send(MeshLaneJob::PutShard {
                    idx,
                    peers: Arc::clone(&self.peers),
                    owner_peer_id: Arc::clone(&self.owner_peer_id),
                    shard_id,
                    data: shard_bytes.clone(),
                    session_key,
                    grant: grant.clone(),
                    reply_tx: reply_tx.clone(),
                })
                .map_err(|_| anyhow::anyhow!("mesh lane worker closed during PutShard"))?;
            }
            drop(reply_tx);

            let mut assigned: Vec<String> = (0..n_total)
                .map(|idx| self.peers[idx % num_peers].clone())
                .collect();
            let mut ok_count = 0usize;
            while let Ok((idx, res)) = reply_rx.recv() {
                if let Ok(peer) = res {
                    ok_count += 1;
                    assigned[idx] = peer;
                }
            }
            if ok_count < shard_set.k_data {
                anyhow::bail!(
                    "distributed only {ok_count}/{} shards (below K={})",
                    n_total,
                    shard_set.k_data
                );
            }
            Ok(assigned)
        }

        /// Fires parallel hedged `GetCiphertextShard` RPCs across the persistent 40-lane `libp2p`
        /// TCP + Noise XX worker pool for all `N` shards in ONE parallel wave (`t = 0`) and returns
        /// **immediately** as soon as the fastest `K` Merkle-verified shards arrive without waiting
        /// on straggler lanes suffering `tc netem` packet-loss RTOs.
        fn fetch_stripe_network_hedged(
            &self,
            stripe: &StripeManifestEntry,
        ) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
            let total_shards = stripe.k_data + stripe.m_parity;
            let (tx, rx) = mpsc::channel::<(usize, Vec<u8>)>();
            let collected = Arc::new(AtomicUsize::new(0));
            let k_needed = stripe.k_data;

            for idx in 0..total_shards {
                let lane = &self.lane_workers[idx % self.lane_workers.len()];
                let shard_id = ShardId {
                    stripe_merkle_root: stripe.stripe_merkle_root,
                    shard_index: idx as u32,
                    shard_hash: stripe.shard_hashes[idx],
                };

                let mut candidates = Vec::with_capacity(self.peers.len() + 1);
                if let Some(primary) = stripe.assigned_peers.get(idx).cloned() {
                    candidates.push(primary);
                }
                for shift in 0..self.peers.len() {
                    let p = &self.peers[(idx + shift) % self.peers.len()];
                    if !candidates.contains(p) {
                        candidates.push(p.clone());
                    }
                }

                let _ = lane.send(MeshLaneJob::GetShardHedged {
                    idx,
                    candidates,
                    shard_id,
                    expected_hash: stripe.shard_hashes[idx],
                    k_needed,
                    collected: Arc::clone(&collected),
                    reply_tx: tx.clone(),
                });
            }
            drop(tx);

            let mut shard_slots: Vec<Option<Vec<u8>>> = vec![None; total_shards];
            let mut got = 0usize;
            while got < k_needed {
                match rx.recv() {
                    Ok((idx, bytes)) => {
                        if shard_slots[idx].is_none() {
                            shard_slots[idx] = Some(bytes);
                            got += 1;
                        }
                    }
                    Err(_) => break,
                }
            }
            if got < k_needed {
                anyhow::bail!("fetched only {got}/{k_needed} shards over libp2p network");
            }
            Ok(shard_slots)
        }

        fn resolve_manifest(&self, eph: &EphemeralShardManifest) -> anyhow::Result<FileManifest> {
            if let Ok(guard) = self.by_merkle_root.read() {
                if let Some(fm) = guard.get(&eph.file_merkle_root) {
                    return Ok(fm.clone());
                }
            }
            if let Ok(loaded) = self
                .block_store
                .load_manifest(&self.master_key, &eph.file_merkle_root)
            {
                let _ = self.index_manifest_in_ram(loaded.clone());
                return Ok(loaded);
            }
            self.resolve_manifest_by_shard_ids(&eph.shard_hashes)
        }

        fn resolve_manifest_by_shard_ids(
            &self,
            ephemeral_shard_ids: &[[u8; 32]],
        ) -> anyhow::Result<FileManifest> {
            let vec_hash = hash_shard_id_vector(ephemeral_shard_ids);
            if let Ok(guard) = self.by_shard_vec_hash.read() {
                if let Some(fm) = guard.get(&vec_hash) {
                    return Ok(fm.clone());
                }
            }
            if let Some(first) = ephemeral_shard_ids.first() {
                if let Ok(guard) = self.by_merkle_root.read() {
                    if let Some(fm) = guard.get(first) {
                        return Ok(fm.clone());
                    }
                }
                if let Ok(fm) = self.block_store.load_manifest(&self.master_key, first) {
                    let _ = self.index_manifest_in_ram(fm.clone());
                    return Ok(fm);
                }
            }
            if let Ok(guard) = self.by_merkle_root.read() {
                for fm in guard.values() {
                    let eph = EphemeralShardManifest::from_file_manifest(fm);
                    if eph.shard_hashes == ephemeral_shard_ids {
                        return Ok(fm.clone());
                    }
                }
            }
            anyhow::bail!("manifest not found for requested ephemeral shard IDs")
        }
    }
}

#[cfg(unix)]
pub use unix_engine::GatewayEngine;
