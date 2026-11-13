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

/// The recovery phrase from `--seed-phrase` or `PARVAULT_SEED_PHRASE`, if any.
fn effective_seed_phrase(arg: Option<String>) -> Option<String> {
    arg.or_else(|| std::env::var("PARVAULT_SEED_PHRASE").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The vault keys: derived from the recovery phrase and namespace when one is given (ADR-18),
/// otherwise the node's sealed master key (or `--key-hex`).
fn vault_keys(
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
        cfg,
        lan_port,
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
    } = command
    else {
        unreachable!("watch_folder() is only dispatched for Commands::WatchFolder")
    };
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

    if snapshot_out.exists() {
        if let Ok(raw_prev) = std::fs::read(&snapshot_out) {
            if let Ok(prev_snapshot) = FolderSnapshotManifest::decode_bytes(&raw_prev) {
                engine.load_previous_snapshot(&prev_snapshot);
            }
        }
    }

    if dry_run {
        let diff = engine.diff_folder(&folder)?;
        print_folder_sync_diff(&folder, &diff);
        return Ok(());
    }

    loop {
        let mut pass_local_only = 0u64;
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
                let node_id = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
                let issued_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                PersonalDeviceCert::issue(
                    &pq_kp,
                    &node_id.device_peer_id(),
                    "lite-client",
                    issued_at,
                )?
            };

            let seed_str = seed_dir.to_string_lossy().to_string();
            if is_network_peer_addr(&seed_str) {
                let (snap, n) =
                    parvault::storage::local_only::track(|| engine.sync_folder_once(&folder));
                pass_local_only += n;
                let mut snap = snap?;
                let net_client = MeshClient::new(
                    owner_identity.clone(),
                    mesh_client.all_network_endpoints(),
                    Some(seed_str.clone()),
                )
                .with_data_dir_discovery(cfg.data_dir.clone(), lan_port);
                let store_with_net = block_store.clone().with_mesh_client(net_client.clone());
                let mut receipt_count = 0usize;
                for entry in snap.files.values_mut() {
                    // A stripe with fewer than k shards on peers is not backed up (QA 2e M2-1).
                    let backed_up = |s: &parvault::storage::StripeManifestEntry| {
                        s.assigned_peers
                            .iter()
                            .filter(|p| is_network_peer_addr(p))
                            .count()
                            >= s.k_data
                    };
                    let needs_syndication = entry.manifest.stripes.iter().any(|s| !backed_up(s));
                    if !needs_syndication {
                        continue;
                    }
                    let file_path = folder.join(&entry.relative_path);
                    if let Ok(mut file_handle) = std::fs::File::open(&file_path) {
                        use std::io::{Read, Seek, SeekFrom};
                        let stripe_cap = entry.manifest.stripe_size_bytes.max(1024);
                        for stripe_meta in &mut entry.manifest.stripes {
                            if backed_up(stripe_meta) {
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
                                let grant = RepairGrant::issue(
                                    &owner_identity,
                                    stripe_meta.stripe_merkle_root,
                                    Vec::new(),
                                    snap.tier,
                                );
                                if let Ok((_receipt, syndicated_peers)) = net_client
                                    .syndicate_lite_stripe_with_grant(
                                        &seed_str,
                                        cert.clone(),
                                        bundle,
                                        Some(grant),
                                    )
                                {
                                    receipt_count += 1;
                                    let has_net =
                                        syndicated_peers.iter().any(|p| is_network_peer_addr(p));
                                    stripe_meta.assigned_peers = if has_net {
                                        syndicated_peers
                                    } else {
                                        vec![seed_str.clone(); stripe_meta.shard_hashes.len()]
                                    };
                                    for (idx, &sh_hash) in
                                        stripe_meta.shard_hashes.iter().enumerate()
                                    {
                                        let sid = ShardId {
                                            stripe_merkle_root: stripe_meta.stripe_merkle_root,
                                            shard_index: idx as u32,
                                            shard_hash: sh_hash,
                                        };
                                        let _ = block_store
                                            .delete_shard(&owner_identity.device_peer_id(), &sid);
                                        let _ = block_store.delete_shard("local", &sid);
                                    }
                                }
                            }
                        }
                        let _ = store_with_net.save_manifest(&master_key, &entry.manifest);
                    }
                }
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
        let raw_snapshot = bincode::serialize(&snapshot)?;
        BlockStore::atomic_write_file(&snapshot_out, &raw_snapshot)?;

        let pruned_shards = if prune_deleted {
            if is_lite_net_seed {
                let seed_str = lite_seed_dir
                    .as_ref()
                    .map(|d| d.to_string_lossy().to_string());
                let net_client = MeshClient::new(
                    owner_identity.clone(),
                    mesh_client.all_network_endpoints(),
                    seed_str,
                )
                .with_data_dir_discovery(cfg.data_dir.clone(), lan_port);
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
        println!("Snapshot Version   : {}", snapshot.version);
        println!(
            "Folder Merkle Root : {}",
            hex::encode(snapshot.folder_merkle_root)
        );
        println!("Files Synced       : {}", snapshot.files.len());
        if pass_local_only > 0 {
            println!(
                "Not Backed Up      : {}",
                parvault::storage::local_only::summary_line(pass_local_only)
            );
        }
        println!("Deleted Tombstones : {}", snapshot.deleted_tombstones.len());
        if lite_receipts_count > 0 {
            println!(
                "Lite Mode Syndicated: {} stripes cached on seed & syndicated (ADR-17)",
                lite_receipts_count
            );
        }
        if prune_deleted {
            println!("Pruned Shards      : {}", pruned_shards);
        }
        println!("Snapshot Saved To  : {}", snapshot_out.display());

        if let Some(cat_path) = &catalog_out {
            let phrase = effective_seed_phrase
                .as_deref()
                .expect("checked above: --catalog-out needs a seed phrase");
            let envelope =
                engine.export_encrypted_vault_catalog(phrase, &vault_namespace, &snapshot)?;
            if is_lite_net_seed {
                let seed_str = lite_seed_dir
                    .as_ref()
                    .map(|d| d.to_string_lossy().to_string());
                let net_client = MeshClient::new(
                    owner_identity.clone(),
                    mesh_client.all_network_endpoints(),
                    seed_str,
                )
                .with_data_dir_discovery(cfg.data_dir.clone(), lan_port);
                let _ =
                    net_client.put_dht_envelope(DhtWireEnvelope::VaultCatalog(envelope.clone()));
            }
            let raw_env = bincode::serialize(&envelope)?;
            BlockStore::atomic_write_file(cat_path, &raw_env)?;
            println!("Catalog Envelope   : {}", cat_path.display());
        } else if let Some(phrase) = effective_seed_phrase.as_deref() {
            let default_cat = snapshot_out.with_extension("catalog.bin");
            let envelope =
                engine.export_encrypted_vault_catalog(phrase, &vault_namespace, &snapshot)?;
            if is_lite_net_seed {
                let seed_str = lite_seed_dir
                    .as_ref()
                    .map(|d| d.to_string_lossy().to_string());
                let net_client = MeshClient::new(
                    owner_identity.clone(),
                    mesh_client.all_network_endpoints(),
                    seed_str,
                )
                .with_data_dir_discovery(cfg.data_dir.clone(), lan_port);
                let _ =
                    net_client.put_dht_envelope(DhtWireEnvelope::VaultCatalog(envelope.clone()));
            }
            let raw_env = bincode::serialize(&envelope)?;
            BlockStore::atomic_write_file(&default_cat, &raw_env)?;
            println!("Catalog Envelope   : {}", default_cat.display());
        }

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

pub(crate) async fn list_snapshot(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let _ = env;
    let Commands::ListSnapshot { snapshot } = command else {
        unreachable!("list_snapshot() is only dispatched for Commands::ListSnapshot")
    };
    let raw_snapshot = std::fs::read(&snapshot)?;
    let snapshot_manifest = FolderSnapshotManifest::decode_bytes(&raw_snapshot)?;
    let entries = FolderSyncEngine::list_snapshot_catalog(&snapshot_manifest);
    println!("=== ParVault Vault Snapshot Catalog (Zero-Shard-Download Browse, ADR-17) ===");
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
    let raw_snapshot = std::fs::read(&snapshot)?;
    let snapshot_manifest = FolderSnapshotManifest::decode_bytes(&raw_snapshot)?;
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
        println!("=== Neighborhood Cloud Selective Subset Restore Verified (ADR-17) ===");
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
        println!("=== ParVault Selective Disaster Recovery From Seed Phrase Complete (ADR-17) ===");
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
