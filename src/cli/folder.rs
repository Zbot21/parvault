//! `parvault` commands: folder.

use super::CliEnv;
use crate::*;

pub(crate) async fn diff_folder(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        cfg, block_store, ..
    } = env;
    let Commands::DiffFolder {
        folder,
        snapshot,
        key_hex,
    } = command
    else {
        unreachable!("diff_folder() is only dispatched for Commands::DiffFolder")
    };
    let master_key = resolve_master_key(
        &cfg.data_dir,
        key_hex.as_deref(),
        cfg.device_sealing_passphrase.as_deref(),
    )?;
    let owner_identity = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
    let mut engine =
        FolderSyncEngine::new(block_store, master_key, owner_identity, cfg.default_tier);
    if let Some(snap_path) = &snapshot {
        if snap_path.exists() {
            let raw = std::fs::read(snap_path)?;
            let prev_snap = FolderSnapshotManifest::decode_bytes(&raw)?;
            engine.load_previous_snapshot(&prev_snap);
        }
    }
    let diff = engine.diff_folder(&folder)?;
    print_folder_sync_diff(&folder, &diff);
    Ok(())
}

/// How long a lite client waits for a seed to ack one `SyndicateLiteStripe`. The seed
/// erasure-encodes, checks (F-38-GRANT, every shard) and stores the whole stripe before it acks,
/// so the client default (1.2 s) times out on a slow or loaded seed and the stripe is then
/// reported NOT backed up.
pub(crate) const LITE_SYNDICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// B-SEED-SYND (L-46): waits before each retry of a stripe the seed refused as busy
/// (`reject.syndication_busy`); after the last one the stripe stays "not backed up" for the next
/// pass.
pub(crate) const SYNDICATION_BUSY_BACKOFF: [std::time::Duration; 3] = [
    std::time::Duration::from_secs(2),
    std::time::Duration::from_secs(5),
    std::time::Duration::from_secs(10),
];

/// Runs `attempt`, retrying after each `SYNDICATION_BUSY_BACKOFF` wait while the seed answers
/// busy; any other result (success or another error) returns at once.
pub(crate) fn with_busy_backoff<T>(
    mut attempt: impl FnMut() -> anyhow::Result<T>,
    mut sleep: impl FnMut(std::time::Duration),
) -> anyhow::Result<T> {
    let mut waits = SYNDICATION_BUSY_BACKOFF.iter();
    loop {
        match attempt() {
            Err(e)
                if e.to_string()
                    .contains(parvault::network::server_events::SYNDICATION_BUSY_TEXT) =>
            {
                match waits.next() {
                    Some(wait) => sleep(*wait),
                    None => return Err(e),
                }
            }
            other => return other,
        }
    }
}

/// The client for `SyndicateLiteStripe` to the seed only: `base` with
/// `LITE_SYNDICATION_TIMEOUT`. The timeout is per request, so `base` (used for the manifest and
/// snapshot DHT puts to every mesh endpoint) keeps the default.
pub(crate) fn lite_syndication_client(base: &MeshClient) -> MeshClient {
    base.clone().with_timeout(LITE_SYNDICATION_TIMEOUT)
}

/// B-113: the lite client's marker that every stripe it holds on the seed was sent with a
/// grant naming the seed as witness.
pub(crate) const LITE_WITNESS_MARKER: &str = "lite_seed_witness.v1";

/// B-113 (A-113 C12): printed by a lite pass while stripes from before the upgrade may be
/// unwitnessed.
pub(crate) fn lite_unwitnessed_notice() -> &'static str {
    "[parvault] lite stripes unwitnessed: stripes syndicated before v0.5.5 are not audited by the seed until you run 'parvault watch-folder --resyndicate-lite' (a full re-upload)"
}

/// B-113 (A-113 §10.2): the lite client's grant for one stripe names exactly one witness, the
/// seed's pinned key.
pub(crate) fn lite_grant(
    owner: &NodeIdentity,
    stripe_merkle_root: [u8; 32],
    seed_key: [u8; 32],
    tier: ErasureTier,
) -> RepairGrant {
    RepairGrant::issue(owner, stripe_merkle_root, vec![seed_key], tier)
}

/// The recovery phrase from `--seed-phrase` or `PARVAULT_SEED_PHRASE`, if any.
pub(crate) fn effective_seed_phrase(arg: Option<String>) -> Option<String> {
    arg.or_else(|| std::env::var("PARVAULT_SEED_PHRASE").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// G-23: the catalog to resume a vault from when this node has no snapshot of it.
/// `Ok(Ok(Some(snapshot)))` resumes; `Ok(Ok(None))` starts at version 1 (no ring, no catalog,
/// or only a catalog that is not this vault's, which is logged and never adopted);
/// `Ok(Err(code))` is [`catalog_resume_decision`]'s refusal (the ring did not answer).
///
/// [`catalog_resume_decision`]: parvault::sync::catalog_resume::catalog_resume_decision
fn resume_vault_from_ring(
    client: Option<&MeshClient>,
    catalog_dht_key: &[u8; 32],
    owner: &NodeIdentity,
    master_key: &MasterKey,
    phrase: &str,
    vault_namespace: &str,
) -> anyhow::Result<Result<Option<FolderSnapshotManifest>, &'static str>> {
    use parvault::sync::catalog_resume::{catalog_resume_decision, CatalogFetch, CatalogResume};
    let client = client.filter(|c| !c.all_network_endpoints().is_empty());
    let (fetch, best) = match client {
        None => (CatalogFetch::NoRing, None),
        Some(c) => {
            let (answered, found) = c.fetch_vault_catalogs(catalog_dht_key);
            // The newest catalog that is this vault's, else (for the log) any other.
            let rank = |e: &parvault::sync::EncryptedVaultCatalogEnvelope| {
                let verifies = e.verify_zero_knowledge();
                let key_matches =
                    e.dht_key == *catalog_dht_key && e.owner_pubkey == owner.public_key_bytes();
                (
                    verifies && key_matches,
                    e.monotonic_version,
                    verifies,
                    key_matches,
                )
            };
            let best = found
                .into_iter()
                .map(|e| (rank(&e), e))
                .max_by_key(|(r, _)| (r.0, r.1));
            let fetch = match (&best, answered) {
                (_, 0) => CatalogFetch::Unreachable,
                (None, _) => CatalogFetch::NotFound,
                (Some(((_, version, verifies, key_matches), _)), _) => CatalogFetch::Found {
                    envelope_verifies: *verifies,
                    key_matches: *key_matches,
                    version: *version,
                },
            };
            (fetch, best.map(|(_, e)| e))
        }
    };
    match catalog_resume_decision(false, fetch) {
        Err(code) => Ok(Err(code)),
        Ok(CatalogResume::Resume) => {
            let env = best.expect("Resume needs a catalog");
            let canonical = parvault::crypto::validate_recovery_seed_phrase_or_passphrase(phrase)?;
            let pq = parvault::crypto::PqVaultMasterKey::from_recovery_seed_phrase(
                &canonical,
                vault_namespace,
            );
            match env.open(master_key, &pq) {
                Ok(snapshot) => Ok(Ok(Some(snapshot))),
                Err(e) => {
                    tracing::warn!(
                        code = "warn.catalog_resume_foreign",
                        error = %e,
                        "the ring's catalog for this vault key does not open with this phrase; not adopted, starting at version 1"
                    );
                    Ok(Ok(None))
                }
            }
        }
        Ok(_) => {
            if let CatalogFetch::Found { .. } = fetch {
                tracing::warn!(
                    code = "warn.catalog_resume_foreign",
                    "the ring's catalog for this vault key is not this vault's (signature or owner); not adopted, starting at version 1"
                );
            }
            Ok(Ok(None))
        }
    }
}

/// The vault keys: derived from the recovery phrase and namespace when one is given (ADR-18),
/// otherwise the node's sealed master key (or `--key-hex`).
pub(crate) fn vault_keys(
    phrase: Option<&str>,
    vault_namespace: &str,
    cfg: &NodeConfig,
    key_hex: Option<&str>,
) -> anyhow::Result<(MasterKey, NodeIdentity)> {
    if let Some(phrase) = phrase {
        let canonical = parvault::crypto::validate_recovery_seed_phrase_or_passphrase(phrase)?;
        Ok((
            MasterKey::from_recovery_seed_phrase(&canonical, vault_namespace),
            NodeIdentity::from_recovery_seed_phrase(&canonical, vault_namespace),
        ))
    } else {
        let mk = resolve_master_key(
            &cfg.data_dir,
            key_hex,
            cfg.device_sealing_passphrase.as_deref(),
        )?;
        let id = NodeIdentity::from_master_key(&mk);
        Ok((mk, id))
    }
}

pub(crate) async fn watch_folder(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        eff,
        cfg,
        public_mode,
        mesh_client,
        block_store,
        ..
    } = env;
    let Commands::WatchFolder {
        folder,
        snapshot_out,
        tier,
        interval_secs,
        once,
        allow_local_only,
        key_hex,
        dry_run,
        prune_deleted,
        seed_phrase,
        vault_namespace,
        catalog_out,
        lite_seed_dir,
        device_cert,
        resyndicate_lite,
        no_gc,
        keep_last,
        keep_daily,
        keep_weekly,
        max_stored_bytes,
    } = command
    else {
        unreachable!("watch_folder() is only dispatched for Commands::WatchFolder")
    };
    // B-154: version GC is on unless `--no-gc` (one release), which keeps the `v0.5.5`
    // behaviour: no version store, no frees, `--prune-deleted` as before.
    let gc_on = !no_gc;
    // C37: the shortest interval, refused below the floor (not clamped).
    if let Err(code) =
        parvault::sync::retention::watch_interval_decision(interval_secs, once || dry_run)
    {
        anyhow::bail!(
            "{code}: --interval-secs must be at least {} (each pass uploads every changed file)",
            parvault::sync::retention::MIN_WATCH_INTERVAL_SECS
        );
    }
    // L-119: the folder's tunables, checked against the client ceilings (refused, not clamped).
    let policy = parvault::sync::retention::RetentionPolicy::checked(
        keep_last,
        keep_daily,
        keep_weekly,
        max_stored_bytes,
    )?;
    let effective_tier = if public_mode {
        println!(
            "[parvault] Public Commons mode active: zero-knowledge AES-256-GCM encryption + 10-of-20 Reed-Solomon sharding."
        );
        ErasureTier::Consumer
    } else {
        tier
    };
    let effective_seed_phrase = effective_seed_phrase(seed_phrase);
    anyhow::ensure!(
        catalog_out.is_none() || effective_seed_phrase.is_some(),
        "--catalog-out needs --seed-phrase (or PARVAULT_SEED_PHRASE): the catalog is sealed under the recovery phrase"
    );
    anyhow::ensure!(
        folder.is_dir(),
        "watched folder {} does not exist or is not a directory",
        folder.display()
    );

    let (master_key, owner_identity) = vault_keys(
        effective_seed_phrase.as_deref(),
        &vault_namespace,
        &cfg,
        key_hex.as_deref(),
    )?;
    // B-20, L-133 (track C, glue G-10): a seed vault's writer node registers the vault's keys
    // (never the phrase), so its daemon's VFS can list the vault. Idempotent.
    #[cfg(all(unix, feature = "vfs"))]
    if let Some(phrase) = effective_seed_phrase.as_deref() {
        parvault::vfs::register_vault_keys(&cfg.data_dir, phrase, &vault_namespace)?;
    }

    let mut store_for_sync = block_store
        .clone()
        .with_mesh_client(mesh_client.with_identity(owner_identity.clone()));
    let is_lite_net_seed = lite_seed_dir
        .as_ref()
        .map(|d| is_network_peer_addr(&d.to_string_lossy()))
        .unwrap_or(false);
    if is_lite_net_seed {
        store_for_sync.set_mesh_client(None);
    }

    let mut engine = FolderSyncEngine::new(
        store_for_sync.clone(),
        master_key.clone(),
        owner_identity.clone(),
        effective_tier,
    );

    let mut prev_syndicated = false;
    let mut prev_version = None;
    if snapshot_out.exists() {
        if let Ok(raw_prev) = std::fs::read(&snapshot_out) {
            if let Ok(prev_snapshot) = FolderSnapshotManifest::decode_bytes(&raw_prev) {
                prev_version = Some(prev_snapshot.version);
                prev_syndicated = prev_snapshot
                    .files
                    .values()
                    .flat_map(|f| f.manifest.stripes.iter())
                    .any(|s| s.assigned_peers.iter().any(|p| is_network_peer_addr(p)));
                engine.load_previous_snapshot(&prev_snapshot);
            }
        }
    }
    anyhow::ensure!(
        !resyndicate_lite || is_lite_net_seed,
        "--resyndicate-lite needs --lite-seed-dir with a seed address"
    );
    // B-113 (A-113 C12): stripes syndicated before this client named its seed as witness are
    // not audited by the seed. The marker says every stripe this client still holds on the
    // seed was sent with a witness grant.
    let witness_marker = cfg.data_dir.join(LITE_WITNESS_MARKER);
    let mut resyndicate_pending = resyndicate_lite;
    if is_lite_net_seed && !dry_run && !witness_marker.exists() {
        if !prev_syndicated {
            let _ = BlockStore::atomic_write_file(&witness_marker, b"1\n");
        } else if !resyndicate_lite {
            println!("{}", lite_unwitnessed_notice());
        }
    }

    if dry_run {
        let diff = engine.diff_folder(&folder)?;
        print_folder_sync_diff(&folder, &diff);
        return Ok(());
    }

    // B-154 2.3: one pass at a time per snapshot (the lock is held for the whole run), and C4:
    // a snapshot file older than its version store is refused.
    let gc_paths = parvault::sync::gc_journal::GcPaths::for_snapshot(&snapshot_out);
    let _pass_lock = if gc_on {
        let lock = parvault::sync::gc_journal::PassLock::acquire(&gc_paths)?;
        parvault::sync::gc_journal::check_snapshot_fresh(&snapshot_out, prev_version)?;
        Some(lock)
    } else {
        None
    };
    // Frees go through the owner's client; a lite client's go through its seed, as its
    // stripes did.
    let gc_client = if is_lite_net_seed {
        Some(super::mesh_client(
            &eff,
            owner_identity.clone(),
            mesh_client.all_network_endpoints(),
            lite_seed_dir
                .as_ref()
                .map(|d| d.to_string_lossy().to_string()),
        ))
    } else {
        engine.store().mesh_client().cloned()
    };
    if gc_on {
        engine.set_gc(parvault::sync::gc_journal::GcSettings {
            snapshot_out: snapshot_out.clone(),
            policy,
            data_dir: cfg.data_dir.clone(),
            client: gc_client.clone(),
            fetched_catalog: None,
        });
        if prune_deleted {
            println!(
                "[parvault] --prune-deleted is deprecated: version GC frees deleted files once no retained version holds them"
            );
        }
    }
    let catalog_dht_key = master_key.derive_vault_root_dht_key(&vault_namespace);
    // G-23 (B-169 K11): with no local snapshot, a seed-phrase vault resumes from the ring's
    // catalog, so a restored owner (or any fresh node given the phrase) continues the vault's
    // versions instead of starting at 1 and being refused as a rollback. Only a catalog that
    // verifies under this vault's owner key and catalog key is adopted; an unreachable ring
    // refuses the pass rather than fork the vault (retried each interval, or an error with
    // `--once`).
    if let Some(phrase) = effective_seed_phrase.as_deref() {
        if prev_version.is_none() {
            loop {
                match resume_vault_from_ring(
                    gc_client.as_ref(),
                    &catalog_dht_key,
                    &owner_identity,
                    &master_key,
                    phrase,
                    &vault_namespace,
                )? {
                    Ok(Some(snapshot)) => {
                        println!(
                            "[parvault] resumed vault '{vault_namespace}' from the ring's catalog version {}",
                            snapshot.version
                        );
                        engine.load_previous_snapshot(&snapshot);
                        break;
                    }
                    Ok(None) => break,
                    Err(code) if once => anyhow::bail!(
                        "{code}: no ring host answered for this vault's catalog; nothing was published (run again when a host is reachable)"
                    ),
                    Err(code) => {
                        tracing::warn!(
                            code,
                            "no ring host answered for this vault's catalog; nothing published, retrying next pass"
                        );
                        tokio::time::sleep(Duration::from_secs(interval_secs.max(1))).await;
                    }
                }
            }
        }
    }
    let mut retried_for_quota = false;

    loop {
        let mut pass_local_only = 0u64;
        let quota_refusals_before = engine
            .store()
            .mesh_client()
            .map(|c| c.quota_refusals())
            .unwrap_or(0);
        let (snapshot, lite_receipts_count) = if let Some(seed_dir) = &lite_seed_dir {
            let pq_kp = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
            let cert = if let Some(cert_arg) = &device_cert {
                let raw_cert = if Path::new(cert_arg).exists() {
                    std::fs::read_to_string(cert_arg)?
                } else {
                    cert_arg.clone()
                };
                PersonalDeviceCert::from_shareable_token(&raw_cert)
                    .or_else(|_| PersonalDeviceCert::from_json_str(&raw_cert))?
            } else {
                // F-38: the cert must name the identity this client sends as (the vault owner).
                let issued_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                PersonalDeviceCert::issue(
                    &pq_kp,
                    &owner_identity.device_peer_id(),
                    "lite-client",
                    issued_at,
                )?
            };

            let seed_str = seed_dir.to_string_lossy().to_string();
            if is_network_peer_addr(&seed_str) {
                // Stored locally first; counted after syndication below.
                let mut snap = engine.sync_folder_once(&folder)?;
                // F-38 (L-40): the seed requires the repair grant's owner to be the sender and the
                // device cert to name the sender, so send as the vault owner identity that signs
                // the grant. Its id is the Vault Device Peer ID `parvault identity --seed-phrase`
                // prints. Only the seed is contacted for syndication. `net_client` (default
                // timeout) also carries the manifest and snapshot DHT puts to every mesh endpoint;
                // only `syndication_client` waits LITE_SYNDICATION_TIMEOUT.
                let net_client = super::mesh_client(
                    &eff,
                    owner_identity.clone(),
                    mesh_client.all_network_endpoints(),
                    Some(seed_str.clone()),
                );
                let syndication_client = lite_syndication_client(&net_client);
                let store_with_net = block_store.clone().with_mesh_client(net_client.clone());
                let mut receipt_count = 0usize;
                let mut syndication_failures = 0usize;
                // B-113 (A-113 §10.2): the grant names the seed (its Noise-pinned key) as audit
                // witness. With no key there is no grant: the stripes wait for the next pass,
                // as with a busy seed. Requests then go over the same pinned connection, so a
                // seed with another key fails `PeerIdMismatch`.
                let seed_key = match syndication_client.remote_ed25519_pubkey(&seed_str) {
                    Ok(k) => Some(k),
                    Err(e) => {
                        tracing::error!(
                            code = "error.lite_seed_key_unresolved",
                            seed = %seed_str,
                            error = %e,
                            "the seed's key is unknown; no stripe is syndicated this pass"
                        );
                        None
                    }
                };
                let resyndicate = resyndicate_pending;
                for entry in snap.files.values_mut() {
                    let Some(seed_key) = seed_key else {
                        syndication_failures += 1;
                        break;
                    };
                    // A stripe with fewer than k shards on peers is not backed up (QA 2e M2-1).
                    let backed_up = |s: &parvault::storage::StripeManifestEntry| {
                        s.assigned_peers
                            .iter()
                            .filter(|p| is_network_peer_addr(p))
                            .count()
                            >= s.k_data
                    };
                    let needs_syndication =
                        resyndicate || entry.manifest.stripes.iter().any(|s| !backed_up(s));
                    if !needs_syndication {
                        continue;
                    }
                    let file_path = folder.join(&entry.relative_path);
                    if let Ok(mut file_handle) = std::fs::File::open(&file_path) {
                        use std::io::{Read, Seek, SeekFrom};
                        let stripe_cap = entry.manifest.stripe_size_bytes.max(1024);
                        for stripe_meta in &mut entry.manifest.stripes {
                            if !resyndicate && backed_up(stripe_meta) {
                                continue;
                            }
                            let start = stripe_meta.stripe_index * (stripe_cap as u64);
                            let mut slice_buf = Vec::new();
                            if file_handle.seek(SeekFrom::Start(start)).is_ok() {
                                let _ = (&mut file_handle)
                                    .take(stripe_cap as u64)
                                    .read_to_end(&mut slice_buf);
                            }
                            if let Ok(ciphertext_bytes) = encrypt_stripe(
                                &master_key,
                                &entry.manifest.file_salt,
                                stripe_meta.stripe_index,
                                &slice_buf,
                            ) {
                                let bundle = LiteStripeSyndicationBundle {
                                    stripe_index: stripe_meta.stripe_index,
                                    tier: snap.tier,
                                    ciphertext_bytes,
                                    expected_stripe_merkle_root: stripe_meta.stripe_merkle_root,
                                    expected_shard_hashes: stripe_meta.shard_hashes.clone(),
                                };
                                let grant = lite_grant(
                                    &owner_identity,
                                    stripe_meta.stripe_merkle_root,
                                    seed_key,
                                    snap.tier,
                                );
                                // B-SEED-SYND (L-46): a busy seed is retried after 2, 5
                                // and 10 s, then the stripe is left for the next pass.
                                match with_busy_backoff(
                                    || {
                                        syndication_client.syndicate_lite_stripe_with_grant(
                                            &seed_str,
                                            cert.clone(),
                                            bundle.clone(),
                                            Some(grant.clone()),
                                        )
                                    },
                                    std::thread::sleep,
                                ) {
                                    Err(e) => {
                                        syndication_failures += 1;
                                        tracing::error!(
                                            code = "error.lite_syndication_failed",
                                            stripe_index = stripe_meta.stripe_index,
                                            seed = %seed_str,
                                            error = %e,
                                            "lite seed refused or failed to syndicate the stripe; it stays only on this machine (the seed log has its reject code)"
                                        )
                                    }
                                    Ok((_receipt, syndicated_peers)) => {
                                        receipt_count += 1;
                                        let has_net = syndicated_peers
                                            .iter()
                                            .any(|p| is_network_peer_addr(p));
                                        // Shards the seed kept itself are labelled with its server id,
                                        // not an address: record them as the seed's multiaddr, as the
                                        // all-on-seed branch does, so they count as off this machine.
                                        stripe_meta.assigned_peers = if has_net {
                                            syndicated_peers
                                                .into_iter()
                                                .map(|p| {
                                                    if is_network_peer_addr(&p) {
                                                        p
                                                    } else {
                                                        seed_str.clone()
                                                    }
                                                })
                                                .collect()
                                        } else {
                                            vec![seed_str.clone(); stripe_meta.shard_hashes.len()]
                                        };
                                        // Every shard is now on the seed or its peers (QA 2e M2).
                                        store_with_net.forget_local_only_stripe(
                                            &stripe_meta.stripe_merkle_root,
                                        );
                                        for (idx, &sh_hash) in
                                            stripe_meta.shard_hashes.iter().enumerate()
                                        {
                                            let sid = ShardId {
                                                stripe_merkle_root: stripe_meta.stripe_merkle_root,
                                                shard_index: idx as u32,
                                                shard_hash: sh_hash,
                                            };
                                            let _ = block_store.delete_shard(
                                                &owner_identity.device_peer_id(),
                                                &sid,
                                            );
                                            let _ = block_store.delete_shard("local", &sid);
                                        }
                                    }
                                }
                            }
                        }
                        let _ = store_with_net.save_manifest(&master_key, &entry.manifest);
                    }
                }
                if resyndicate {
                    resyndicate_pending = false;
                    if syndication_failures == 0 {
                        let _ = BlockStore::atomic_write_file(&witness_marker, b"1\n");
                        println!(
                            "[parvault] re-syndicated {receipt_count} lite stripe(s) with the seed as audit witness"
                        );
                    } else {
                        println!(
                            "[parvault] re-syndication incomplete ({syndication_failures} stripe(s) failed); run --resyndicate-lite again"
                        );
                    }
                }
                // The first local pass counted every new stripe as local-only; after
                // syndication, report only the stripes still below k shards on peers (R3-1).
                pass_local_only = snap
                    .files
                    .values()
                    .flat_map(|f| f.manifest.stripes.iter())
                    .filter(|s| {
                        s.assigned_peers
                            .iter()
                            .filter(|p| is_network_peer_addr(p))
                            .count()
                            < s.k_data
                    })
                    .count() as u64;
                if let Some(ref env) = snap.signed_dht_envelope {
                    let _ = net_client
                        .put_dht_envelope(DhtWireEnvelope::ClassicalManifest(env.clone()));
                }
                engine.load_previous_snapshot(&snap);
                (snap, receipt_count)
            } else {
                let seed_quota =
                    QuotaManager::new(cfg.max_storage_bytes, cfg.bootstrap_grace_bytes);
                let seed_store = BlockStore::new(seed_dir, seed_quota)?
                    .with_stripe_size_bytes(cfg.stripe_size_bytes);
                let mut seed_server = ZeroTrustSeedServer::new_homelab_vault(
                    "paired-homelab-seed",
                    seed_store,
                    pq_kp.public_key(),
                    2,
                );
                let (snap, receipts) =
                    engine.sync_folder_lite_via_seed(&folder, &cert, &mut seed_server, &[])?;
                (snap, receipts.len())
            }
        } else {
            let (snap, n) =
                parvault::storage::local_only::track(|| engine.sync_folder_once(&folder));
            pass_local_only += n;
            (snap?, 0)
        };
        let pass = engine.last_pass();
        let raw_snapshot = bincode::serialize(&snapshot)?;
        // B-154 3: an unchanged pass leaves the snapshot file byte-identical.
        if std::fs::read(&snapshot_out).ok().as_deref() != Some(raw_snapshot.as_slice()) {
            BlockStore::atomic_write_file(&snapshot_out, &raw_snapshot)?;
        }

        let pruned_shards = if prune_deleted && !gc_on {
            if is_lite_net_seed {
                let seed_str = lite_seed_dir
                    .as_ref()
                    .map(|d| d.to_string_lossy().to_string());
                let net_client = super::mesh_client(
                    &eff,
                    owner_identity.clone(),
                    mesh_client.all_network_endpoints(),
                    seed_str,
                );
                let net_engine = FolderSyncEngine::new(
                    block_store.clone().with_mesh_client(net_client),
                    master_key.clone(),
                    owner_identity.clone(),
                    effective_tier,
                );
                net_engine.prune_deleted_file_shards(&snapshot)?
            } else {
                engine.prune_deleted_file_shards(&snapshot)?
            }
        } else {
            0
        };

        println!("=== Neighborhood Cloud Folder Sync Pass Complete ===");
        println!("Watched Folder     : {}", folder.display());
        if pass.no_change {
            println!("Snapshot Version   : {} (no change)", snapshot.version);
        } else {
            println!("Snapshot Version   : {}", snapshot.version);
        }
        println!(
            "Folder Merkle Root : {}",
            hex::encode(snapshot.folder_merkle_root)
        );
        println!("Files Synced       : {}", snapshot.files.len());
        println!("Changes            : {}", changes_line(&pass));
        if pass_local_only > 0 {
            println!(
                "Not Backed Up      : {}",
                parvault::storage::local_only::summary_line(pass_local_only)
            );
        }
        println!("Deleted Tombstones : {}", snapshot.deleted_tombstones.len());
        if lite_receipts_count > 0 {
            println!(
                "Lite Mode Syndicated: {} stripes cached on seed & syndicated (ADR-20)",
                lite_receipts_count
            );
        }
        if prune_deleted && !gc_on {
            println!("Pruned Shards      : {}", pruned_shards);
        }
        println!("Snapshot Saved To  : {}", snapshot_out.display());

        if let Some(phrase) = effective_seed_phrase.as_deref() {
            let cat_path = catalog_out
                .clone()
                .unwrap_or_else(|| snapshot_out.with_extension("catalog.bin"));
            // B-154 3 and C6: a no-change pass seals no catalog, unless the last acknowledged
            // one lags this version or the catalog file is missing.
            let published = if gc_on {
                parvault::sync::gc_journal::published_catalog_version(&snapshot_out)?
            } else {
                None
            };
            let lags = published.is_none_or(|v| v < snapshot.version);
            if !pass.no_change || lags || !cat_path.exists() {
                let (envelope, acked) = engine.publish_vault_catalog(
                    phrase,
                    &vault_namespace,
                    &snapshot,
                    gc_client.as_ref(),
                )?;
                if acked && gc_on {
                    parvault::sync::gc_journal::record_published_catalog(
                        &snapshot_out,
                        envelope.monotonic_version,
                        envelope.ciphertext_sha256,
                    )?;
                }
                let raw_env = bincode::serialize(&envelope)?;
                BlockStore::atomic_write_file(&cat_path, &raw_env)?;
            }
            println!("Catalog Envelope   : {}", cat_path.display());
            // C7: the catalog the ring holds now must be the one this device published.
            if gc_on {
                let fetched = gc_client
                    .as_ref()
                    .filter(|c| !c.all_network_endpoints().is_empty())
                    .and_then(|c| {
                        c.get_dht_envelope(&catalog_dht_key, DhtEnvelopeKind::VaultCatalog)
                            .ok()
                    })
                    .and_then(|e| match e {
                        DhtWireEnvelope::VaultCatalog(env) if env.verify_zero_knowledge() => {
                            Some((env.monotonic_version, env.ciphertext_sha256))
                        }
                        _ => None,
                    });
                engine.set_fetched_catalog(fetched);
            }
        }

        if gc_on {
            match engine.gc_after_pass(&snapshot, &cfg.data_dir) {
                Ok(report) => {
                    let hosts = gc_client
                        .as_ref()
                        .map(|c| c.all_network_endpoints().len() as u64)
                        .unwrap_or(0);
                    let stats = parvault::sync::gc_journal::folder_stats(
                        &snapshot, &policy, &report, hosts,
                    );
                    if let Err(e) = parvault::sync::gc_journal::write_stats(
                        &cfg.data_dir,
                        &snapshot_out,
                        &stats,
                    ) {
                        tracing::warn!(error = %e, "folder stats not written");
                    }
                    print_gc_lines(&report, &stats);
                    // C35: at its allowance on some host, an owner frees first, then retries
                    // the pass once.
                    let refused = engine
                        .store()
                        .mesh_client()
                        .map(|c| c.quota_refusals())
                        .unwrap_or(0)
                        > quota_refusals_before;
                    match parvault::sync::gc_journal::quota_retry_decision(
                        refused,
                        retried_for_quota,
                        report.freed_any(),
                    ) {
                        parvault::sync::gc_journal::QuotaRetry::Retry => {
                            let n = engine.requeue_not_backed_up();
                            println!(
                                "[parvault] a host refused this owner for quota; GC freed space, retrying {n} file(s) once"
                            );
                            retried_for_quota = true;
                            continue;
                        }
                        parvault::sync::gc_journal::QuotaRetry::Spent(code) => {
                            tracing::warn!(
                                code,
                                retried = retried_for_quota,
                                "a host refused this owner for quota and GC freed nothing more (or the retry is spent); the refused stripes stay on this machine"
                            );
                        }
                        parvault::sync::gc_journal::QuotaRetry::NotNeeded => {}
                    }
                }
                Err(e) => {
                    tracing::error!(code = "error.gc_failed", error = %e, "version GC failed; the journal is retried next pass");
                    if once {
                        return Err(e.into());
                    }
                }
            }
        }
        retried_for_quota = false;

        if once {
            parvault::storage::local_only::finish_one_shot(pass_local_only, allow_local_only);
            break;
        }
        if pass_local_only > 0 {
            tracing::error!(
                "{}",
                parvault::storage::local_only::summary_line(pass_local_only)
            );
        }
        tokio::time::sleep(Duration::from_secs(interval_secs.max(1))).await;
    }
    Ok(())
}

/// `Changes : 2 modified, 0 added, 0 deleted, 1.6 MB uploaded` or `none` (B-154 3).
fn changes_line(pass: &parvault::sync::PassSummary) -> String {
    if pass.no_change {
        return if pass.mtime_only {
            "none (modification times only)".to_string()
        } else {
            "none".to_string()
        };
    }
    format!(
        "{} modified, {} added, {} deleted, {:.1} MB uploaded",
        pass.modified,
        pass.added,
        pass.deleted,
        pass.uploaded_bytes as f64 / 1_000_000.0
    )
}

fn print_gc_lines(
    report: &parvault::sync::gc_journal::GcReport,
    stats: &parvault::sync::gc_journal::FolderStats,
) {
    println!(
        "Versions Retained  : {} (policy: last {}, daily {}, weekly {}{})",
        report.versions_kept,
        stats.keep_last,
        stats.keep_daily,
        stats.keep_weekly,
        stats
            .max_stored_bytes
            .map(|c| format!(", cap {c} bytes"))
            .unwrap_or_default()
    );
    println!(
        "Version GC         : {} version(s) dropped, {} shard(s) freed on hosts, {} local, {} order(s), {} DeleteShard fallback(s)",
        report.versions_dropped,
        report.shards_freed,
        report.local_shards_freed,
        report.orders_sent,
        report.fallback_deletes
    );
    println!(
        "Pending Frees      : {} ({} bytes); abandoned {} ({} bytes)",
        report.pending, report.pending_bytes, report.abandoned, report.abandoned_bytes
    );
    if report.clock_skew_refusals > 0 {
        println!(
            "Clock Skew         : {} free(s) refused as stale (reject.free_stale): check this machine's clock",
            report.clock_skew_refusals
        );
    }
    println!(
        "Folder Size        : {} bytes; stored {} bytes (expected on ring {} bytes, policy maximum {} bytes)",
        stats.disk_bytes,
        stats.stored_cipher_bytes,
        stats.expected_stored_bytes,
        stats.policy_max_bytes
    );
    println!(
        "Version Store      : {} bytes on this disk",
        stats.version_store_bytes
    );
    if report.foreign_catalog {
        println!(
            "Warning: another device publishes this vault's catalog; nothing was freed. One writer per vault folder."
        );
    }
    if let Some(code) = stats.warn_code {
        tracing::warn!(
            code,
            expected = stats.expected_stored_bytes,
            policy_max = stats.policy_max_bytes,
            "expected stored bytes exceed 1.25x what the retention policy can hold"
        );
        println!(
            "Warning ({code}): this folder's expected stored bytes ({}) exceed 1.25x what its retention policy can hold ({}): frees may be stuck or abandoned; see Pending Frees",
            stats.expected_stored_bytes, stats.policy_max_bytes
        );
    }
}

pub(crate) async fn list_snapshot(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let _ = env;
    let Commands::ListSnapshot { snapshot } = command else {
        unreachable!("list_snapshot() is only dispatched for Commands::ListSnapshot")
    };
    let raw_snapshot = std::fs::read(&snapshot)?;
    let snapshot_manifest = FolderSnapshotManifest::decode_bytes(&raw_snapshot)?;
    let entries = FolderSyncEngine::list_snapshot_catalog(&snapshot_manifest);
    println!("=== ParVault Vault Snapshot Catalog (Zero-Shard-Download Browse, ADR-20) ===");
    println!("Snapshot File      : {}", snapshot.display());
    println!("Snapshot Version   : {}", snapshot_manifest.version);
    println!(
        "Folder Merkle Root : {}",
        hex::encode(snapshot_manifest.folder_merkle_root)
    );
    println!("Total Files        : {}", entries.len());
    for item in &entries {
        println!(
            "  - {:<36} | {:>10} bytes | {} stripes | root={}",
            item.relative_path,
            item.size_bytes,
            item.stripe_count,
            &hex::encode(item.file_merkle_root)[..16]
        );
        // Full stripe roots: the value `evict --merkle-root` takes (R3-2).
        if let Some(entry) = snapshot_manifest.files.get(&item.relative_path) {
            for stripe in &entry.manifest.stripes {
                println!(
                    "      stripe {} root={}",
                    stripe.stripe_index,
                    hex::encode(stripe.stripe_merkle_root)
                );
            }
        }
    }
    Ok(())
}

pub(crate) async fn restore_folder(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        cfg,
        mesh_client,
        block_store,
        ..
    } = env;
    let Commands::RestoreFolder {
        snapshot,
        out_dir,
        key_hex,
        seed_phrase,
        vault_namespace,
        file,
        filter,
        version,
    } = command
    else {
        unreachable!("restore_folder() is only dispatched for Commands::RestoreFolder")
    };
    let (master_key, owner_identity) = vault_keys(
        effective_seed_phrase(seed_phrase).as_deref(),
        &vault_namespace,
        &cfg,
        key_hex.as_deref(),
    )?;
    // B-154 (T5): `--version N` restores a retained version from the snapshot's version store.
    let snapshot_manifest = match version {
        Some(n) => {
            let store = parvault::sync::retention::VersionStore::for_snapshot(&snapshot);
            let kept = store.list()?;
            if let Err(code) = parvault::sync::retention::version_restore_decision(&kept, n) {
                anyhow::bail!(
                    "{code}: version {n} is not retained; retained: {}",
                    kept.iter()
                        .map(|m| m.version.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            store.load(n)?
        }
        None => {
            let raw_snapshot = std::fs::read(&snapshot)?;
            FolderSnapshotManifest::decode_bytes(&raw_snapshot)?
        }
    };
    let store_with_owner = block_store
        .clone()
        .with_mesh_client(mesh_client.with_identity(owner_identity.clone()));
    let engine = FolderSyncEngine::new(
        store_with_owner,
        master_key,
        owner_identity,
        snapshot_manifest.tier,
    );
    if let Some(rel_file) = file {
        let restored_path = engine.restore_single_file(&snapshot_manifest, &rel_file, &out_dir)?;
        println!("=== Neighborhood Cloud Selective File Restore Verified ===");
        println!("Restored File      : {}", restored_path.display());
        println!("Relative Path      : {}", rel_file);
        println!("Snapshot Version   : {}", snapshot_manifest.version);
        println!(
            "Folder Merkle Root : {}",
            hex::encode(snapshot_manifest.folder_merkle_root)
        );
    } else if let Some(filter_csv) = filter {
        let filters: Vec<String> = filter_csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let report = engine.restore_selective_subset(&snapshot_manifest, &filters, &out_dir)?;
        println!("=== Neighborhood Cloud Selective Subset Restore Verified (ADR-20) ===");
        println!("Restored Directory : {}", out_dir.display());
        println!("Files Restored     : {:?}", report.files_restored);
        println!("Files Skipped      : {}", report.files_skipped);
        println!("Bytes Restored     : {} bytes", report.bytes_restored);
        println!(
            "Bytes Saved        : {} bytes (not downloaded)",
            report.bytes_saved_not_downloaded
        );
    } else {
        let count = engine.restore_folder(&snapshot_manifest, &out_dir)?;
        println!("=== Neighborhood Cloud Folder Restore Verified ===");
        println!("Restored Directory : {}", out_dir.display());
        println!("Snapshot Version   : {}", snapshot_manifest.version);
        println!(
            "Folder Merkle Root : {}",
            hex::encode(snapshot_manifest.folder_merkle_root)
        );
        println!(
            "Files Restored     : {} (all SHA-256 & AES-256-GCM tags verified)",
            count
        );
    }
    Ok(())
}

pub(crate) async fn recover_from_seed(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        mesh_client,
        block_store,
        ..
    } = env;
    let Commands::RecoverFromSeed {
        seed_phrase,
        vault_namespace,
        catalog_envelope,
        out_dir,
        filter,
    } = command
    else {
        unreachable!("recover_from_seed() is only dispatched for Commands::RecoverFromSeed")
    };
    let seed_phrase = effective_seed_phrase(seed_phrase).ok_or_else(|| {
        anyhow::anyhow!("recover-from-seed needs --seed-phrase or PARVAULT_SEED_PHRASE")
    })?;
    let canonical_seed =
        parvault::crypto::validate_recovery_seed_phrase_or_passphrase(&seed_phrase)?;
    let master_key = MasterKey::from_recovery_seed_phrase(&canonical_seed, &vault_namespace);
    let pq_master_key = parvault::crypto::PqVaultMasterKey::from_recovery_seed_phrase(
        &canonical_seed,
        &vault_namespace,
    );
    let owner_identity = NodeIdentity::from_recovery_seed_phrase(&canonical_seed, &vault_namespace);
    let recovery_store = block_store
        .clone()
        .with_mesh_client(mesh_client.with_identity(owner_identity.clone()));

    let envelope: EncryptedVaultCatalogEnvelope = if let Some(cat_path) = catalog_envelope {
        let raw_env = std::fs::read(&cat_path)?;
        bincode::deserialize(&raw_env)
            .or_else(|_| serde_json::from_slice::<EncryptedVaultCatalogEnvelope>(&raw_env))?
    } else {
        let dht_key = master_key.derive_vault_root_dht_key(&vault_namespace);
        if let Some(client) = recovery_store.mesh_client() {
            if !client.all_network_endpoints().is_empty() {
                match client.get_dht_envelope(&dht_key, DhtEnvelopeKind::VaultCatalog)? {
                    DhtWireEnvelope::VaultCatalog(env) => env,
                    _ => anyhow::bail!("unexpected DHT envelope kind for VaultCatalog"),
                }
            } else {
                recovery_store
                    .get_dht_vault_catalog_envelope(&dht_key)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "EncryptedVaultCatalogEnvelope not found in local DHT store"
                        )
                    })?
            }
        } else {
            recovery_store
                .get_dht_vault_catalog_envelope(&dht_key)
                .ok_or_else(|| {
                    anyhow::anyhow!("EncryptedVaultCatalogEnvelope not found in local DHT store")
                })?
        }
    };

    if let Some(filter_csv) = filter {
        let filters: Vec<String> = filter_csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let snapshot = envelope.open(&master_key, &pq_master_key)?;
        let engine =
            FolderSyncEngine::new(recovery_store, master_key, owner_identity, snapshot.tier);
        let report = engine.restore_selective_subset(&snapshot, &filters, &out_dir)?;
        println!("=== ParVault Selective Disaster Recovery From Seed Phrase Complete (ADR-18) ===");
        println!("Vault Namespace    : {}", vault_namespace);
        println!("Files Restored     : {:?}", report.files_restored);
        println!("Files Skipped      : {}", report.files_skipped);
        println!(
            "Bytes Saved        : {} bytes (not downloaded)",
            report.bytes_saved_not_downloaded
        );
    } else {
        let recovered_count = FolderSyncEngine::recover_folder_from_seed_phrase(
            &recovery_store,
            &seed_phrase,
            &vault_namespace,
            &envelope,
            &out_dir,
        )?;
        println!("=== ParVault Disaster Recovery From Seed Phrase Complete (ADR-18) ===");
        println!("Vault Namespace    : {}", vault_namespace);
        println!("Catalog Version    : {}", envelope.monotonic_version);
        println!("DHT Root Key (hex) : {}", hex::encode(envelope.dht_key));
        println!("Recovered To       : {}", out_dir.display());
        println!("Files Restored     : {}", recovered_count);
    }
    Ok(())
}

/// `folder-status` (B-154, track B2): the retained versions and stored bytes of a folder.
/// T0b stub: refused until track B2 builds it.
/// `parvault folder-status` (B-154 C30, L-122): one folder's versions, policy, frees and
/// accounting from its version store, journal and stats file. No network.
pub(crate) async fn folder_status(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv { cfg, .. } = env;
    let Commands::FolderStatus { snapshot } = command else {
        unreachable!("folder_status() is only dispatched for Commands::FolderStatus")
    };
    use parvault::sync::gc_journal::{stats_path, FolderStats, GcJournal, GcPaths};
    let store = parvault::sync::retention::VersionStore::for_snapshot(&snapshot);
    let versions = store.list()?;
    if versions.is_empty() {
        anyhow::bail!(
            "no version store for {} (back it up with watch-folder first; --no-gc keeps none)",
            snapshot.display()
        );
    }
    let journal = GcJournal::load(&GcPaths::for_snapshot(&snapshot))?;
    println!("=== Folder Status (B-154) ===");
    println!("Snapshot           : {}", snapshot.display());
    println!(
        "Versions Retained  : {} ({})",
        versions.len(),
        versions
            .iter()
            .map(|m| m.version.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if let Some((l, d, w, cap)) = journal.policy {
        println!(
            "Policy             : last {l}, daily {d}, weekly {w}{}",
            cap.map(|c| format!(", cap {c} bytes")).unwrap_or_default()
        );
    }
    println!(
        "Pending Frees      : {} ({} bytes); abandoned {} ({} bytes)",
        journal.pending.len(),
        journal.pending_bytes(),
        journal.abandoned.len(),
        journal.abandoned_bytes()
    );
    println!(
        "Version Store      : {} bytes on this disk",
        store.local_bytes()
    );
    match std::fs::read(stats_path(&cfg.data_dir, &snapshot))
        .ok()
        .and_then(|raw| serde_json::from_slice::<FolderStats>(&raw).ok())
    {
        Some(st) => {
            println!("Folder Size        : {} bytes", st.disk_bytes);
            println!(
                "Stored             : {} bytes (pre-erasure)",
                st.stored_cipher_bytes
            );
            println!(
                "Expected On Ring   : {} bytes (expected; policy maximum {} bytes)",
                st.expected_stored_bytes, st.policy_max_bytes
            );
            if st.warn {
                println!("Warning            : expected bytes exceed 1.25x the policy maximum");
            }
        }
        None => println!("Folder Size        : unknown (no stats file in this data dir)"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B-113 (A-113 §10.2): the lite grant names exactly the seed's pinned key; with no
    /// resolvable key (no pin, no `/p2p/` id, nothing listening) there is no key, so no grant.
    #[test]
    fn lite_client_grant_names_pinned_seed() {
        let owner = NodeIdentity::from_seed([0x31; 32]);
        let seed = NodeIdentity::from_seed([0x32; 32]);
        let seed_pid = seed.to_libp2p_keypair().unwrap().public().to_peer_id();
        let addr = "/ip4/127.0.0.1/tcp/9";
        let client = MeshClient::new(owner.clone(), Vec::new(), None)
            .with_timeout(std::time::Duration::from_millis(500));
        client.pin_peer_id(addr, seed_pid);
        let key = client.remote_ed25519_pubkey(addr).unwrap();
        assert_eq!(key, seed.public_key_bytes());
        let g = lite_grant(&owner, [7; 32], key, ErasureTier::Consumer);
        assert!(g.verify());
        assert_eq!(g.authorized_witness_pubkeys, vec![seed.public_key_bytes()]);
        assert_eq!(g.owner_pubkey, owner.public_key_bytes());
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            drop(l);
            format!("/ip4/127.0.0.1/tcp/{port}")
        };
        assert!(client.remote_ed25519_pubkey(&dead).is_err());
    }

    fn busy() -> anyhow::Error {
        anyhow::anyhow!(
            "SyndicateLiteStripe rejected: Some({:?})",
            parvault::network::server_events::SYNDICATION_BUSY_TEXT
        )
    }

    /// B-SEED-SYND: a busy seed is retried after 2, 5 and 10 s, then given up; other errors and
    /// success return at once.
    #[test]
    fn busy_seed_backoff_schedule() {
        use std::time::Duration;
        // Busy three times, then accepted: three waits, 2/5/10 s, then Ok.
        let mut calls = 0;
        let mut slept = Vec::new();
        let r = with_busy_backoff(
            || {
                calls += 1;
                if calls <= 3 {
                    Err(busy())
                } else {
                    Ok(calls)
                }
            },
            |d| slept.push(d),
        );
        assert_eq!(r.unwrap(), 4);
        assert_eq!(slept, [2, 5, 10].map(Duration::from_secs).to_vec());
        // Busy every time: three waits, then the busy error.
        let mut slept = Vec::new();
        let r: anyhow::Result<()> = with_busy_backoff(|| Err(busy()), |d| slept.push(d));
        assert!(r.is_err() && slept.len() == 3);
        // Another error: no retry.
        let mut slept = Vec::new();
        let mut calls = 0;
        let r: anyhow::Result<()> = with_busy_backoff(
            || {
                calls += 1;
                Err(anyhow::anyhow!("device cert does not name the sender"))
            },
            |d| slept.push(d),
        );
        assert!(r.is_err() && slept.is_empty() && calls == 1);
    }

    /// Only the seed-syndication client waits `LITE_SYNDICATION_TIMEOUT`; the base client that
    /// carries the DHT puts keeps the default (QA 2e r3).
    #[test]
    fn lite_syndication_client_uses_the_long_timeout() {
        let default = MeshClient::new(NodeIdentity::from_seed([0x32; 32]), Vec::new(), None)
            .request_timeout();
        let dht_client = MeshClient::new(
            NodeIdentity::from_seed([0x31; 32]),
            vec!["/ip4/127.0.0.1/tcp/2".to_string()],
            Some("/ip4/127.0.0.1/tcp/1".to_string()),
        );
        let syndication = lite_syndication_client(&dht_client);
        assert_eq!(syndication.request_timeout(), LITE_SYNDICATION_TIMEOUT);
        assert_eq!(dht_client.request_timeout(), default);
        assert!(LITE_SYNDICATION_TIMEOUT > default);
    }
}
