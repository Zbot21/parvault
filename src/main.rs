use clap::Parser;
use libp2p::{
    futures::StreamExt,
    gossipsub, mdns,
    request_response::{self, Message},
    swarm::SwarmEvent,
    Multiaddr,
};
use parvault::{
    bootstrap::{
        EarnedStanding, LiteStripeSyndicationBundle, PersonalDeviceCert, ZeroTrustSeedServer,
    },
    config::{Cli, Commands, DaemonAction, ErasureTier, FileAction, NodeConfig},
    crypto::{
        compute_sha256, encrypt_stripe,
        pqc::{HybridKemKeypair, HybridPqPublicKey, HybridPqSigningKeypair},
        MasterKey, NodeIdentity, SoftwareTpm2Stub,
    },
    network::{
        behaviour::{
            DhtEnvelopeKind, DhtWireEnvelope, MeshNetworkBehaviourEvent, MeshWireRequest,
            MeshWireResponse,
        },
        build_mesh_swarm, is_network_peer_addr, MeshClient, WebOfTrustRegistry,
        DEFAULT_SUBTREE_SLASH_LIMIT,
    },
    por::{PorVerifierEngine, RepairGrant},
    sharding::Hash32,
    storage::{BlockStore, FileManifest, QuotaManager, ShardId, VoucherNullifierLedger},
    sync::{
        EncryptedVaultCatalogEnvelope, FolderSnapshotManifest, FolderSyncDiff, FolderSyncEngine,
    },
};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("parvault=info,warn")),
        )
        .init();

    let cli = Cli::parse();
    let mut cfg = NodeConfig::load_or_default(cli.config.as_ref())?;
    if let Some(ref override_dir) = cli.data_dir {
        cfg.data_dir = override_dir.clone();
    }

    let node_identity = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
    let effective_peers = cfg.effective_peers(&cli.peers);
    let effective_seed = cfg.effective_seed_addr(cli.seed_addr.as_deref());
    let mesh_client = MeshClient::new(node_identity.clone(), effective_peers, effective_seed);

    let mut quota = QuotaManager::new(cfg.max_storage_bytes, cfg.bootstrap_grace_bytes);
    quota.set_min_free_disk_bytes(cfg.min_free_disk_bytes);
    let block_store = BlockStore::new(&cfg.data_dir, quota)?.with_mesh_client(mesh_client.clone());

    match cli.command {
        Commands::Daemon { action } => match action {
            DaemonAction::Start {
                listen,
                enable_quic,
            } => {
                cfg.listen_tcp = listen;
                cfg.enable_quic = enable_quic;
                run_daemon(cfg, block_store).await?;
            }
        },
        Commands::File { action } => match action {
            FileAction::Store {
                path,
                path_flag,
                tier,
                key_hex,
            } => {
                let path = path
                    .or(path_flag)
                    .ok_or_else(|| anyhow::anyhow!("Missing input file path"))?;
                let master_key = resolve_master_key(
                    &cfg.data_dir,
                    key_hex.as_deref(),
                    cfg.device_sealing_passphrase.as_deref(),
                )?;
                let owner_identity = NodeIdentity::from_master_key(&master_key);
                let owner_peer_id = owner_identity.device_peer_id();
                let store_with_owner = block_store
                    .clone()
                    .with_mesh_client(mesh_client.with_identity(owner_identity));
                let (k, m, n) = tier.params();
                info!(
                    file = %path.display(),
                    ?tier,
                    k_data = k,
                    m_parity = m,
                    n_total = n,
                    stripe_size_mib = cfg.stripe_size_bytes / (1024 * 1024),
                    "Encrypting (AES-256-GCM) and Reed-Solomon sharding file..."
                );

                let manifest = store_with_owner.store_file_streaming(
                    &owner_peer_id,
                    &path,
                    &master_key,
                    tier,
                    cfg.stripe_size_bytes,
                )?;
                let (dht_key, _) = manifest.to_encrypted_dht_record(&master_key)?;

                println!("=== ParVault Vault Store Complete ===");
                println!(
                    "File Merkle Root : {}",
                    hex::encode(manifest.file_merkle_root)
                );
                println!("DHT Manifest Key : {}", hex::encode(dht_key));
                println!("Master Key (hex) : {}", master_key.to_hex());
                println!("Original Size    : {} bytes", manifest.original_file_size);
                println!(
                    "Erasure Scheme   : {}-of-{} ({:.1}% efficiency, {:.2}x expansion)",
                    k,
                    n,
                    (k as f64 / n as f64) * 100.0,
                    tier.expansion_factor()
                );
                println!("Total Stripes    : {}", manifest.stripes.len());
                println!("Total Shards     : {}", manifest.stripes.len() * n);
            }
            FileAction::Restore {
                manifest_or_root,
                manifest_or_root_flag,
                output,
                output_flag,
                key_hex,
            } => {
                let manifest_or_root = manifest_or_root
                    .or(manifest_or_root_flag)
                    .ok_or_else(|| anyhow::anyhow!("Missing manifest or Merkle root"))?;
                let output = output
                    .or(output_flag)
                    .ok_or_else(|| anyhow::anyhow!("Missing output path"))?;
                let master_key = resolve_master_key(
                    &cfg.data_dir,
                    key_hex.as_deref(),
                    cfg.device_sealing_passphrase.as_deref(),
                )?;
                let owner_identity = NodeIdentity::from_master_key(&master_key);
                let store_with_owner = block_store
                    .clone()
                    .with_mesh_client(mesh_client.with_identity(owner_identity));
                let manifest =
                    load_manifest_by_arg(&store_with_owner, &master_key, &manifest_or_root)?;

                info!(
                    merkle_root = %hex::encode(manifest.file_merkle_root),
                    output = %output.display(),
                    "Reconstructing Reed-Solomon ciphertext shards and decrypting stripes..."
                );

                store_with_owner.restore_file_streaming(&manifest, &master_key, &output)?;
                println!("=== ParVault Vault Restore Verified ===");
                println!("Restored File    : {}", output.display());
                println!(
                    "Verified Root    : {}",
                    hex::encode(manifest.file_merkle_root)
                );
                println!("Original Size    : {} bytes", manifest.original_file_size);
            }
        },
        Commands::Status => {
            let node_id = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
            let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
            let pq_fp = pq_keypair.public_key().fingerprint_hex();
            let q = block_store.quota();
            let q_guard = q.lock().expect("quota lock");
            println!("=== ParVault Daemon Node Status ===");
            println!("Data Directory        : {}", cfg.data_dir.display());
            println!("Device Peer ID        : {}", node_id.device_peer_id());
            println!("Owner PQ Fingerprint  : {}", pq_fp);
            println!(
                "Primary Transport     : TCP + Noise XX + Yamux ({})",
                cfg.listen_tcp
            );
            println!(
                "Secondary QUIC        : {}",
                if cfg.enable_quic {
                    "Enabled"
                } else {
                    "Disabled (ADR-08)"
                }
            );
            println!(
                "Streaming Stripe Size : {} MiB (ADR-01)",
                cfg.stripe_size_bytes / (1024 * 1024)
            );
            println!(
                "PoR Latency Ceiling   : <= {} ms (ADR-03)",
                cfg.por_timeout_ms
            );
            println!(
                "Topology Split Policy : {:.0}% Intra-ASN (<= {} ms RTT) / {:.0}% Cross-Region (ADR-06)",
                cfg.intra_asn_ratio * 100.0,
                cfg.local_rtt_threshold_ms,
                (1.0 - cfg.intra_asn_ratio) * 100.0
            );
            println!(
                "Local Storage Quota   : {} / {} bytes used ({} bytes bootstrap grace)",
                q_guard.used_storage_bytes(),
                q_guard.max_storage_bytes(),
                cfg.bootstrap_grace_bytes
            );
            println!(
                "Min Free Disk Reserve : {} bytes ({:.2} GiB)",
                cfg.min_free_disk_bytes,
                cfg.min_free_disk_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
            );
            println!(
                "Bandwidth Rate Limits : upload={} Mbps, download={} Mbps (0 = unlimited)",
                cfg.max_upload_mbps, cfg.max_download_mbps
            );
            println!("\nEarned Standing Progression Ladder (ADR-12):");
            println!(
                "  SoloPersonalVault -> PersonalDeviceRing -> BuddyMicroCluster -> ProbationaryConsumerPool -> EarnedVerifiedMixedPool -> EarnedHomelabAnchorPool"
            );
            for standing in [
                EarnedStanding::SoloPersonalVault,
                EarnedStanding::PersonalDeviceRing,
                EarnedStanding::BuddyMicroCluster,
                EarnedStanding::ProbationaryConsumerPool,
                EarnedStanding::EarnedVerifiedMixedPool,
                EarnedStanding::EarnedHomelabAnchorPool,
            ] {
                println!("  - {:?}", standing);
            }
            println!("\nSupported SLA Erasure Coding Pools:");
            for tier in [
                ErasureTier::Consumer,
                ErasureTier::Mixed,
                ErasureTier::Homelab,
                ErasureTier::Relay,
            ] {
                let (k, _m, n) = tier.params();
                println!(
                    "  - {:?}: {}-of-{} ({:.1}% net efficiency, {:.2}x expansion, repair trigger @ {}/{})",
                    tier,
                    k,
                    n,
                    (k as f64 / n as f64) * 100.0,
                    tier.expansion_factor(),
                    tier.repair_trigger_watermark(),
                    n
                );
            }
        }
        Commands::Identity => {
            let node_id = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
            let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
            let pq_pk = pq_keypair.public_key();
            let master_key = resolve_master_key(
                &cfg.data_dir,
                None,
                cfg.device_sealing_passphrase.as_deref(),
            )?;
            let mk_sha = compute_sha256(master_key.as_bytes());
            let mk_fp = hex::encode(&mk_sha[..8]);

            println!("=== ParVault Persistent Node Identity ===");
            println!("Device Peer ID          : {}", node_id.device_peer_id());
            println!(
                "Ed25519 Public Key (hex): {}",
                hex::encode(node_id.public_key_bytes())
            );
            println!("Owner PQ Public Key Hex : {}", pq_pk.to_hex()?);
            println!("Owner PQ Fingerprint    : {}", pq_pk.fingerprint_hex());
            println!("Master Key Fingerprint  : {}", mk_fp);
        }
        Commands::IssueDeviceCert {
            device_peer_id,
            device_label,
            cert_out,
        } => {
            let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
            let pq_pk = pq_keypair.public_key();
            let issued_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let cert =
                PersonalDeviceCert::issue(&pq_keypair, &device_peer_id, &device_label, issued_at)?;
            let json_str = cert.to_json_pretty()?;
            let token_str = cert.to_shareable_token()?;

            if let Some(out_path) = &cert_out {
                BlockStore::atomic_write_file(out_path, json_str.as_bytes())?;
            }

            println!("=== ParVault PersonalDeviceCert Issued (Ed25519 + ML-DSA-65) ===");
            println!("Device Peer ID          : {}", cert.device_peer_id);
            println!("Device Label            : {}", cert.device_label);
            println!("Issued At (Unix Secs)   : {}", cert.issued_unix_secs);
            println!("Owner PQ Fingerprint    : {}", pq_pk.fingerprint_hex());
            println!("Owner PQ Public Key Hex : {}", pq_pk.to_hex()?);
            if let Some(out_path) = &cert_out {
                println!("Certificate JSON File   : {}", out_path.display());
            }
            println!("Shareable Token         : {}", token_str);
        }
        Commands::VerifyDeviceCert {
            cert,
            owner_pq_pubkey_hex,
        } => {
            let raw_cert = if Path::new(&cert).exists() {
                std::fs::read_to_string(&cert)?
            } else {
                cert.clone()
            };
            let parsed_cert = PersonalDeviceCert::from_shareable_token(&raw_cert)
                .or_else(|_| PersonalDeviceCert::from_json_str(&raw_cert))?;

            let owner_pk = if let Some(hex_str) = owner_pq_pubkey_hex {
                HybridPqPublicKey::from_hex(hex_str.trim())?
            } else {
                HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?.public_key()
            };

            if parsed_cert.verify(&owner_pk).is_err() {
                anyhow::bail!(
                    "PersonalDeviceCert verification FAILED against owner PQ public key (fingerprint: {})",
                    owner_pk.fingerprint_hex()
                );
            }

            println!("=== ParVault PersonalDeviceCert Verification: PASS ===");
            println!("Device Peer ID          : {}", parsed_cert.device_peer_id);
            println!("Device Label            : {}", parsed_cert.device_label);
            println!("Issued At (Unix Secs)   : {}", parsed_cert.issued_unix_secs);
            println!("Owner PQ Fingerprint    : {}", owner_pk.fingerprint_hex());
            println!("Verification Status     : VALID (Ed25519 + FIPS 204 ML-DSA-65 verified)");
        }
        Commands::DiffFolder {
            folder,
            snapshot,
            key_hex,
        } => {
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
                    let prev_snap: FolderSnapshotManifest = bincode::deserialize(&raw)?;
                    engine.load_previous_snapshot(&prev_snap);
                }
            }
            let diff = engine.diff_folder(&folder)?;
            print_folder_sync_diff(&folder, &diff);
        }
        Commands::WatchFolder {
            folder,
            snapshot_out,
            tier,
            interval_secs,
            once,
            key_hex,
            dry_run,
            prune_deleted,
            seed_phrase,
            vault_namespace,
            catalog_out,
            lite_seed_dir,
            device_cert,
        } => {
            let effective_seed_phrase = seed_phrase
                .or_else(|| std::env::var("PARVAULT_SEED_PHRASE").ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let (master_key, owner_identity) =
                if let Some(phrase) = effective_seed_phrase.as_deref() {
                    (
                        MasterKey::from_recovery_seed_phrase(phrase, &vault_namespace),
                        NodeIdentity::from_recovery_seed_phrase(phrase, &vault_namespace),
                    )
                } else {
                    let mk = resolve_master_key(
                        &cfg.data_dir,
                        key_hex.as_deref(),
                        cfg.device_sealing_passphrase.as_deref(),
                    )?;
                    let id = NodeIdentity::from_master_key(&mk);
                    (mk, id)
                };

            let mut store_for_sync = block_store.clone();
            let is_lite_net_seed = lite_seed_dir
                .as_ref()
                .map(|d| is_network_peer_addr(&d.to_string_lossy()))
                .unwrap_or(false);
            if is_lite_net_seed {
                // In Lite Mode over the network, do not upload 20x shards directly from the laptop
                // during `sync_folder_once`; instead, encode locally, send 1.0x `SyndicateLiteStripe`
                // to `parvault-seed`, and remove the local scratch shards!
                store_for_sync.set_mesh_client(None);
            }

            let mut engine = FolderSyncEngine::new(
                store_for_sync.clone(),
                master_key.clone(),
                owner_identity.clone(),
                tier,
            );

            if snapshot_out.exists() {
                if let Ok(raw_prev) = std::fs::read(&snapshot_out) {
                    if let Ok(prev_snapshot) =
                        bincode::deserialize::<FolderSnapshotManifest>(&raw_prev)
                    {
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
                        let mut snap = engine.sync_folder_once(&folder)?;
                        let net_client = MeshClient::new(
                            owner_identity.clone(),
                            cfg.effective_peers(&cli.peers),
                            Some(seed_str.clone()),
                        );
                        let store_with_net =
                            block_store.clone().with_mesh_client(net_client.clone());
                        let mut receipt_count = 0usize;
                        for entry in snap.files.values_mut() {
                            let needs_syndication =
                                entry.manifest.stripes.iter().any(|s| {
                                    !s.assigned_peers.iter().any(|p| is_network_peer_addr(p))
                                });
                            if !needs_syndication {
                                continue;
                            }
                            let file_path = folder.join(&entry.relative_path);
                            if let Ok(mut file_handle) = std::fs::File::open(&file_path) {
                                use std::io::{Read, Seek, SeekFrom};
                                let stripe_cap = entry.manifest.stripe_size_bytes.max(1024);
                                for stripe_meta in &mut entry.manifest.stripes {
                                    if stripe_meta
                                        .assigned_peers
                                        .iter()
                                        .any(|p| is_network_peer_addr(p))
                                    {
                                        continue;
                                    }
                                    let start =
                                        (stripe_meta.stripe_index as u64) * (stripe_cap as u64);
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
                                            expected_stripe_merkle_root: stripe_meta
                                                .stripe_merkle_root,
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
                                            let has_net = syndicated_peers
                                                .iter()
                                                .any(|p| is_network_peer_addr(p));
                                            stripe_meta.assigned_peers = if has_net {
                                                syndicated_peers
                                            } else {
                                                vec![
                                                    seed_str.clone();
                                                    stripe_meta.shard_hashes.len()
                                                ]
                                            };
                                            // Remove temporary local scratch shards on the Lite Client
                                            for (idx, &sh_hash) in
                                                stripe_meta.shard_hashes.iter().enumerate()
                                            {
                                                let sid = ShardId {
                                                    stripe_merkle_root: stripe_meta
                                                        .stripe_merkle_root,
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
                        let seed_store = BlockStore::new(seed_dir, seed_quota)?;
                        let mut seed_server = ZeroTrustSeedServer::new_homelab_vault(
                            "paired-homelab-seed",
                            seed_store,
                            pq_kp.public_key(),
                            2,
                        );
                        let (snap, receipts) = engine.sync_folder_lite_via_seed(
                            &folder,
                            &cert,
                            &mut seed_server,
                            &[],
                        )?;
                        (snap, receipts.len())
                    }
                } else {
                    (engine.sync_folder_once(&folder)?, 0)
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
                            cfg.effective_peers(&cli.peers),
                            seed_str,
                        );
                        let net_engine = FolderSyncEngine::new(
                            block_store.clone().with_mesh_client(net_client),
                            master_key.clone(),
                            owner_identity.clone(),
                            tier,
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
                println!("Master Key (hex)   : {}", master_key.to_hex());

                if let Some(cat_path) = &catalog_out {
                    let phrase = effective_seed_phrase
                        .as_deref()
                        .unwrap_or("parvault-default-local-catalog-seed");
                    let envelope = engine.export_encrypted_vault_catalog(
                        phrase,
                        &vault_namespace,
                        &snapshot,
                    )?;
                    if is_lite_net_seed {
                        let seed_str = lite_seed_dir
                            .as_ref()
                            .map(|d| d.to_string_lossy().to_string());
                        let net_client = MeshClient::new(
                            owner_identity.clone(),
                            cfg.effective_peers(&cli.peers),
                            seed_str,
                        );
                        let _ = net_client
                            .put_dht_envelope(DhtWireEnvelope::VaultCatalog(envelope.clone()));
                    }
                    let raw_env = bincode::serialize(&envelope)?;
                    BlockStore::atomic_write_file(cat_path, &raw_env)?;
                    println!("Catalog Envelope   : {}", cat_path.display());
                } else if let Some(phrase) = effective_seed_phrase.as_deref() {
                    let default_cat = snapshot_out.with_extension("catalog.bin");
                    let envelope = engine.export_encrypted_vault_catalog(
                        phrase,
                        &vault_namespace,
                        &snapshot,
                    )?;
                    if is_lite_net_seed {
                        let seed_str = lite_seed_dir
                            .as_ref()
                            .map(|d| d.to_string_lossy().to_string());
                        let net_client = MeshClient::new(
                            owner_identity.clone(),
                            cfg.effective_peers(&cli.peers),
                            seed_str,
                        );
                        let _ = net_client
                            .put_dht_envelope(DhtWireEnvelope::VaultCatalog(envelope.clone()));
                    }
                    let raw_env = bincode::serialize(&envelope)?;
                    BlockStore::atomic_write_file(&default_cat, &raw_env)?;
                    println!("Catalog Envelope   : {}", default_cat.display());
                }

                if once {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs.max(1))).await;
            }
        }
        Commands::ListSnapshot { snapshot } => {
            let raw_snapshot = std::fs::read(&snapshot)?;
            let snapshot_manifest: FolderSnapshotManifest = bincode::deserialize(&raw_snapshot)?;
            let entries = FolderSyncEngine::list_snapshot_catalog(&snapshot_manifest);
            println!(
                "=== ParVault Vault Snapshot Catalog (Zero-Shard-Download Browse, ADR-17) ==="
            );
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
            }
        }
        Commands::RestoreFolder {
            snapshot,
            out_dir,
            key_hex,
            file,
            filter,
        } => {
            let master_key = resolve_master_key(
                &cfg.data_dir,
                key_hex.as_deref(),
                cfg.device_sealing_passphrase.as_deref(),
            )?;
            let raw_snapshot = std::fs::read(&snapshot)?;
            let snapshot_manifest: FolderSnapshotManifest = bincode::deserialize(&raw_snapshot)?;
            let owner_identity = NodeIdentity::from_master_key(&master_key);
            let engine = FolderSyncEngine::new(
                block_store,
                master_key,
                owner_identity,
                snapshot_manifest.tier,
            );
            if let Some(rel_file) = file {
                let restored_path =
                    engine.restore_single_file(&snapshot_manifest, &rel_file, &out_dir)?;
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
                let report =
                    engine.restore_selective_subset(&snapshot_manifest, &filters, &out_dir)?;
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
        }
        Commands::RecoverFromSeed {
            seed_phrase,
            vault_namespace,
            catalog_envelope,
            out_dir,
            filter,
        } => {
            let master_key = MasterKey::from_recovery_seed_phrase(&seed_phrase, &vault_namespace);
            let pq_master_key = parvault::crypto::PqVaultMasterKey::from_recovery_seed_phrase(
                &seed_phrase,
                &vault_namespace,
            );
            let owner_identity =
                NodeIdentity::from_recovery_seed_phrase(&seed_phrase, &vault_namespace);

            let envelope: EncryptedVaultCatalogEnvelope = if let Some(cat_path) = catalog_envelope {
                let raw_env = std::fs::read(&cat_path)?;
                bincode::deserialize(&raw_env).or_else(|_| {
                    serde_json::from_slice::<EncryptedVaultCatalogEnvelope>(&raw_env)
                })?
            } else {
                let dht_key = master_key.derive_vault_root_dht_key(&vault_namespace);
                if let Some(client) = block_store.mesh_client() {
                    if !client.all_network_endpoints().is_empty() {
                        match client.get_dht_envelope(&dht_key, DhtEnvelopeKind::VaultCatalog)? {
                            DhtWireEnvelope::VaultCatalog(env) => env,
                            _ => anyhow::bail!("unexpected DHT envelope kind for VaultCatalog"),
                        }
                    } else {
                        block_store
                            .get_dht_vault_catalog_envelope(&dht_key)
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "EncryptedVaultCatalogEnvelope not found in local DHT store"
                                )
                            })?
                    }
                } else {
                    block_store
                        .get_dht_vault_catalog_envelope(&dht_key)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "EncryptedVaultCatalogEnvelope not found in local DHT store"
                            )
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
                    FolderSyncEngine::new(block_store, master_key, owner_identity, snapshot.tier);
                let report = engine.restore_selective_subset(&snapshot, &filters, &out_dir)?;
                println!(
                    "=== ParVault Selective Disaster Recovery From Seed Phrase Complete (ADR-17) ==="
                );
                println!("Vault Namespace    : {}", vault_namespace);
                println!("Files Restored     : {:?}", report.files_restored);
                println!("Files Skipped      : {}", report.files_skipped);
                println!(
                    "Bytes Saved        : {} bytes (not downloaded)",
                    report.bytes_saved_not_downloaded
                );
            } else {
                let recovered_count = FolderSyncEngine::recover_folder_from_seed_phrase(
                    &block_store,
                    &seed_phrase,
                    &vault_namespace,
                    &envelope,
                    &out_dir,
                )?;
                println!("=== ParVault Disaster Recovery From Seed Phrase Complete (ADR-15) ===");
                println!("Vault Namespace    : {}", vault_namespace);
                println!("Catalog Version    : {}", envelope.monotonic_version);
                println!("DHT Root Key (hex) : {}", hex::encode(envelope.dht_key));
                println!("Recovered To       : {}", out_dir.display());
                println!("Files Restored     : {}", recovered_count);
            }
        }
        Commands::Scrub => {
            let report = block_store.scrub_all_shards()?;
            let healthy_shards =
                report.verified_healthy_shards + report.verified_healthy_blinded_shards;
            let corrupted_quarantined_shards = report.quarantined_corrupted_shards.len()
                + report.quarantined_corrupted_blinded_locators.len();
            let total_shards_scanned = healthy_shards + corrupted_quarantined_shards;
            println!("=== ParVault Local Bit-Rot Scrub Report (ADR-15) ===");
            println!("Data Directory               : {}", cfg.data_dir.display());
            println!("total_shards_scanned         : {}", total_shards_scanned);
            println!(
                "healthy_shards               : {} (regular: {}, blinded: {})",
                healthy_shards,
                report.verified_healthy_shards,
                report.verified_healthy_blinded_shards
            );
            println!(
                "corrupted_quarantined_shards : {}",
                corrupted_quarantined_shards
            );
        }
        Commands::Leave {
            handoff_to,
            keep_local,
        } => {
            let identity = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
            let target_dirs: Vec<std::path::PathBuf> = handoff_to
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from)
                .collect();
            let remove_local = !keep_local;
            let receipt = block_store.graceful_leave_and_redistribute(
                &identity,
                &target_dirs,
                remove_local,
            )?;
            println!("=== ParVault Graceful Node Decommission Complete (1.0x Direct Handoff) ===");
            println!("Departing Peer ID        : {}", receipt.departing_peer_id);
            println!(
                "Migrated Regular Shards  : {}",
                receipt.migrated_shards_count
            );
            println!(
                "Migrated Blinded Shards  : {}",
                receipt.migrated_blinded_shards_count
            );
            println!(
                "Total Bytes Handed Off   : {} bytes (saved 16x RS repair amplification)",
                receipt.total_bytes_handed_off
            );
            println!(
                "Handoff Manifest SHA-256 : {}",
                hex::encode(receipt.handoff_manifest_sha256)
            );
            println!(
                "Earned Standing Preserved: {} (zero PoR slashing penalty)",
                receipt.earned_standing_preserved
            );
            println!(
                "Signed Receipt Saved To  : {}",
                cfg.data_dir
                    .join("graceful_departure_receipt.json")
                    .display()
            );
        }
    }

    Ok(())
}

fn print_folder_sync_diff(folder: &Path, diff: &FolderSyncDiff) {
    println!("=== Neighborhood Cloud Dry-Run Folder Sync Diff ===");
    println!("Target Folder       : {}", folder.display());
    println!(
        "added               : {} {:?}",
        diff.added.len(),
        diff.added
    );
    println!(
        "modified            : {} {:?}",
        diff.modified.len(),
        diff.modified
    );
    println!(
        "deleted             : {} {:?}",
        diff.deleted.len(),
        diff.deleted
    );
    println!(
        "unchanged           : {} {:?}",
        diff.unchanged.len(),
        diff.unchanged
    );
    println!(
        "ignored             : {} {:?}",
        diff.ignored.len(),
        diff.ignored
    );
    println!("total_upload_bytes  : {}", diff.total_upload_bytes);
}

fn resolve_master_key(
    data_dir: &Path,
    key_hex: Option<&str>,
    passphrase: Option<&str>,
) -> anyhow::Result<MasterKey> {
    if let Some(hex_str) = key_hex {
        Ok(MasterKey::from_hex(hex_str)?)
    } else {
        let sealer = SoftwareTpm2Stub::from_passphrase_or_csprng_in_dir(data_dir, passphrase)?;
        let sealed_path = data_dir.join("master_key.sealed");
        sealer.load_or_create_master_key(&sealed_path)
    }
}

fn load_manifest_by_arg(
    block_store: &BlockStore,
    master_key: &MasterKey,
    arg: &str,
) -> anyhow::Result<FileManifest> {
    let as_path = Path::new(arg);
    if as_path.exists() {
        let raw = std::fs::read(as_path)?;
        Ok(FileManifest::from_encrypted_dht_record(master_key, &raw)?)
    } else {
        let decoded = hex::decode(arg.trim())?;
        if decoded.len() != 32 {
            anyhow::bail!("Expected 64-character hex Merkle root or valid manifest path");
        }
        let mut root: Hash32 = [0u8; 32];
        root.copy_from_slice(&decoded);
        Ok(block_store.load_manifest(master_key, &root)?)
    }
}

async fn run_daemon(cfg: NodeConfig, block_store: BlockStore) -> anyhow::Result<()> {
    let node_identity = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
    let keypair = node_identity.to_libp2p_keypair()?;
    let local_peer_id = keypair.public().to_peer_id();
    let genesis_pubkey = NodeIdentity::resolve_genesis_root_pubkey_in_dir(
        &cfg.data_dir,
        cfg.genesis_root_pubkey_hex.as_deref(),
    )?;

    let mut wot = WebOfTrustRegistry::with_persistence_dir(
        genesis_pubkey,
        DEFAULT_SUBTREE_SLASH_LIMIT,
        &cfg.data_dir,
    );
    let mut por_verifier =
        PorVerifierEngine::with_persistence_dir(cfg.por_timeout_ms, &cfg.data_dir);
    let mut nullifier_ledger =
        VoucherNullifierLedger::with_persistence_dir(genesis_pubkey, &cfg.data_dir);
    let pq_kem = HybridKemKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
    let pq_signer = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
    let mut lite_seed_server = ZeroTrustSeedServer::new_homelab_vault(
        node_identity.device_peer_id(),
        block_store.clone(),
        pq_signer.public_key(),
        2,
    );

    let mut swarm = build_mesh_swarm(keypair, cfg.enable_quic)?;
    let tcp_addr: Multiaddr = cfg.listen_tcp.parse()?;
    swarm.listen_on(tcp_addr)?;

    if cfg.enable_quic {
        let quic_addr: Multiaddr = cfg.listen_quic.parse()?;
        swarm.listen_on(quic_addr)?;
    }

    let slash_topic = gossipsub::IdentTopic::new("parvault-wot-slashing");
    swarm.behaviour_mut().gossipsub.subscribe(&slash_topic)?;

    if let Some(client) = block_store.mesh_client() {
        for peer_str in client.all_network_endpoints() {
            if let Ok(addr) = parvault::network::parse_peer_multiaddr(&peer_str) {
                let _ = swarm.dial(addr);
            }
        }
    }

    let mut scrub_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    scrub_interval.tick().await;
    let mut maint_epoch: u64 = 1;

    info!(
        %local_peer_id,
        listen_tcp = %cfg.listen_tcp,
        enable_quic = cfg.enable_quic,
        "parvault-daemon started (Noise XX + Yamux active)"
    );

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!(%address, "Listening on mesh transport address");
                    }
                    SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Mdns(
                        mdns::Event::Discovered(list),
                    )) => {
                        for (peer_id, multiaddr) in list {
                            info!(%peer_id, %multiaddr, "Discovered LAN peer via mDNS");
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                        }
                    }
                    SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. },
                    )) => {
                        if let Ok(ev) =
                            bincode::deserialize::<parvault::network::SlashingEvidence>(&message.data)
                        {
                            if wot.apply_slashing_evidence(&ev) {
                                warn!(
                                    offender = %hex::encode(ev.offender_pubkey),
                                    "Applied Gossipsub SlashingEvidence and quarantined offender"
                                );
                            }
                        }
                    }
                    SwarmEvent::Behaviour(MeshNetworkBehaviourEvent::ReqResp(
                        request_response::Event::Message {
                            peer,
                            message: Message::Request { request, channel, .. },
                        },
                    )) => {
                        let response = handle_wire_request(
                            &peer.to_string(),
                            request,
                            &block_store,
                            &mut wot,
                            &mut por_verifier,
                            &mut nullifier_ledger,
                            &pq_kem,
                            &mut lite_seed_server,
                        );
                        let _ = swarm.behaviour_mut().req_resp.send_response(channel, response);
                    }
                    _ => {}
                }
            }
            _ = scrub_interval.tick() => {
                maint_epoch = maint_epoch.saturating_add(1);
                let _ = block_store.sweep_expired_blinded_shards(maint_epoch);
                let _ = block_store.scrub_all_shards();
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl-C, shutting down parvault-daemon cleanly.");
                break;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_wire_request(
    remote_peer_id: &str,
    request: MeshWireRequest,
    block_store: &BlockStore,
    wot: &mut WebOfTrustRegistry,
    por_verifier: &mut PorVerifierEngine,
    nullifier_ledger: &mut VoucherNullifierLedger,
    pq_kem: &HybridKemKeypair,
    lite_seed_server: &mut ZeroTrustSeedServer,
) -> MeshWireResponse {
    match request {
        MeshWireRequest::HandshakeWoT { chain, .. } => match wot.verify_and_admit_chain(&chain) {
            Ok(_) => MeshWireResponse::HandshakeAck {
                accepted: true,
                reason: None,
            },
            Err(e) => {
                // ADR-15 Red-Team Fix (RT3-03): Never penalize `chain.leaf_pubkey()` on an
                // unverified `HandshakeWoT` failure, because an attacker could send 3 forged
                // chains with a bit-flipped signature for an honest node's pubkey to frame and
                // quarantine that honest node and its parent WoT branch!
                MeshWireResponse::HandshakeAck {
                    accepted: false,
                    reason: Some(e.to_string()),
                }
            }
        },
        MeshWireRequest::PutShard {
            owner_peer_id,
            shard_id,
            shard_bytes,
            session_key_commit,
            repair_grant,
        } => {
            if let Some(grant) = repair_grant {
                por_verifier.register_repair_grant(grant);
            }
            por_verifier.register_shard_session(&shard_id, session_key_commit);
            let effective_owner = if owner_peer_id.is_empty()
                || owner_peer_id == "local"
                || owner_peer_id == "self"
            {
                remote_peer_id
            } else {
                owner_peer_id.as_str()
            };
            match block_store.put_shard(effective_owner, &shard_id, &shard_bytes) {
                Ok(_) => MeshWireResponse::PutShardAck {
                    stored: true,
                    error: None,
                },
                Err(e) => MeshWireResponse::PutShardAck {
                    stored: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::DeleteShard {
            shard_id,
            owner_signature: (owner_pub, payload, r, s),
        } => {
            let mut sig64 = [0u8; 64];
            sig64[..32].copy_from_slice(&r);
            sig64[32..].copy_from_slice(&s);
            if !por_verifier.authorize_owner_shard_delete(
                &shard_id,
                &owner_pub,
                payload.as_slice(),
                &sig64,
            ) {
                return MeshWireResponse::DeleteShardAck {
                    deleted: false,
                    error: Some("unauthorized owner shard delete signature".to_string()),
                };
            }
            match block_store.delete_shard(remote_peer_id, &shard_id) {
                Ok(deleted) => MeshWireResponse::DeleteShardAck {
                    deleted,
                    error: None,
                },
                Err(e) => MeshWireResponse::DeleteShardAck {
                    deleted: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::PorAudit(challenge) => {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            match por_verifier.handle_incoming_challenge(&challenge, now_ms, block_store) {
                Ok(resp) => MeshWireResponse::PorAuditResult(Some(resp)),
                Err(e) => {
                    warn!(peer = remote_peer_id, error = %e, "Dropped PoR challenge in RAM pre-check");
                    MeshWireResponse::PorAuditResult(None)
                }
            }
        }
        MeshWireRequest::GetCiphertextShard {
            shard_id,
            owner_signature,
            repair_proof,
        } => {
            let owner_sig_storage;
            let owner_sig_ref = if let Some((owner_pub, payload, r, s)) = &owner_signature {
                let mut sig64 = [0u8; 64];
                sig64[..32].copy_from_slice(r);
                sig64[32..].copy_from_slice(s);
                owner_sig_storage = (*owner_pub, payload.as_slice(), sig64);
                Some((
                    owner_sig_storage.0,
                    owner_sig_storage.1,
                    &owner_sig_storage.2,
                ))
            } else {
                None
            };

            let repair_ref = repair_proof
                .as_ref()
                .map(|(grant, receipts)| (grant, receipts.as_slice()));

            match por_verifier.authorize_raw_shard_read(
                &shard_id,
                owner_sig_ref.as_ref(),
                repair_ref,
                block_store,
            ) {
                Ok(bytes) => MeshWireResponse::CiphertextShardResult {
                    shard_bytes: Some(bytes),
                    error: None,
                },
                Err(e) => MeshWireResponse::CiphertextShardResult {
                    shard_bytes: None,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::PutBlindedShard {
            blinded_id,
            shard_bytes,
            capability,
            voucher,
            current_epoch,
            lease_duration_epochs,
            delete_verifier,
        } => {
            nullifier_ledger.set_trusted_issuer_pubkey(voucher.issuer_pubkey);
            match block_store.put_blinded_shard_with_lease(
                &blinded_id,
                &shard_bytes,
                capability,
                &voucher,
                nullifier_ledger,
                current_epoch,
                lease_duration_epochs,
                delete_verifier,
            ) {
                Ok(_) => MeshWireResponse::PutBlindedShardAck {
                    stored: true,
                    error: None,
                },
                Err(e) => MeshWireResponse::PutBlindedShardAck {
                    stored: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::GetBlindedShard {
            blinded_id,
            capability,
            timestamp_ms,
            read_sig,
        } => {
            if read_sig.len() != 64 {
                return MeshWireResponse::BlindedShardResult {
                    shard_bytes: None,
                    error: Some("invalid 64-byte capability signature length".to_string()),
                };
            }
            let mut sig64 = [0u8; 64];
            sig64.copy_from_slice(&read_sig);
            match block_store.get_blinded_shard_authorized(
                &blinded_id,
                &capability,
                timestamp_ms,
                &sig64,
            ) {
                Ok(bytes) => MeshWireResponse::BlindedShardResult {
                    shard_bytes: Some(bytes),
                    error: None,
                },
                Err(e) => MeshWireResponse::BlindedShardResult {
                    shard_bytes: None,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::RenewBlindedLease {
            blinded_id,
            current_epoch,
            extension_epochs,
        } => {
            let renewed =
                block_store.renew_blinded_shard_lease(&blinded_id, current_epoch, extension_epochs);
            MeshWireResponse::RenewBlindedLeaseAck { renewed }
        }
        MeshWireRequest::DeleteBlindedShardTombstone {
            blinded_id,
            tombstone,
        } => match block_store.delete_blinded_shard_with_tombstone(&blinded_id, &tombstone) {
            Ok(deleted) => MeshWireResponse::DeleteBlindedShardAck {
                deleted,
                error: None,
            },
            Err(e) => MeshWireResponse::DeleteBlindedShardAck {
                deleted: false,
                error: Some(e.to_string()),
            },
        },
        MeshWireRequest::MultiSegmentPorAudit(challenge) => {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            match por_verifier.handle_multi_segment_challenge(&challenge, now_ms, block_store) {
                Ok(resp) => MeshWireResponse::MultiSegmentPorAuditResult(Some(resp)),
                Err(e) => {
                    warn!(peer = remote_peer_id, error = %e, "Dropped MultiSegmentPorAudit in RAM pre-check");
                    MeshWireResponse::MultiSegmentPorAuditResult(None)
                }
            }
        }
        MeshWireRequest::RelayPqOnionEnvelope {
            target_peer_addr,
            envelope,
            capability,
            voucher,
            current_epoch,
            lease_duration_epochs,
            delete_verifier,
        } => {
            if let Some(next_hop) = target_peer_addr {
                if let Some(client) = block_store.mesh_client() {
                    match client.relay_pq_onion_envelope(
                        &next_hop,
                        None,
                        envelope,
                        capability,
                        voucher,
                        current_epoch,
                        lease_duration_epochs,
                        delete_verifier,
                    ) {
                        Ok(()) => MeshWireResponse::RelayPqOnionAck {
                            delivered: true,
                            error: None,
                        },
                        Err(e) => MeshWireResponse::RelayPqOnionAck {
                            delivered: false,
                            error: Some(e.to_string()),
                        },
                    }
                } else {
                    MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some("no MeshClient available for onion forwarding".to_string()),
                    }
                }
            } else {
                match envelope.open_pq(pq_kem) {
                    Ok((blinded_id, shard_bytes)) => {
                        nullifier_ledger.set_trusted_issuer_pubkey(voucher.issuer_pubkey);
                        match block_store.put_blinded_shard_with_lease(
                            &blinded_id,
                            &shard_bytes,
                            capability,
                            &voucher,
                            nullifier_ledger,
                            current_epoch,
                            lease_duration_epochs,
                            delete_verifier,
                        ) {
                            Ok(_) => MeshWireResponse::RelayPqOnionAck {
                                delivered: true,
                                error: None,
                            },
                            Err(e) => MeshWireResponse::RelayPqOnionAck {
                                delivered: false,
                                error: Some(e.to_string()),
                            },
                        }
                    }
                    Err(e) => MeshWireResponse::RelayPqOnionAck {
                        delivered: false,
                        error: Some(e.to_string()),
                    },
                }
            }
        }
        MeshWireRequest::SyndicateLiteStripe {
            cert,
            bundle,
            repair_grant,
        } => {
            if let Some(ref grant) = repair_grant {
                por_verifier.register_repair_grant(grant.clone());
            }
            match lite_seed_server.ingest_and_syndicate_lite_stripe_with_grant(
                &cert,
                &bundle,
                &[],
                repair_grant,
            ) {
                Ok((receipt, syndicated_peers)) => MeshWireResponse::SyndicateLiteStripeAck {
                    receipt: Some(receipt),
                    syndicated_peers,
                    error: None,
                },
                Err(e) => MeshWireResponse::SyndicateLiteStripeAck {
                    receipt: None,
                    syndicated_peers: Vec::new(),
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::PutDhtEnvelope(env) => {
            let res = match env {
                DhtWireEnvelope::ClassicalManifest(m) => block_store.put_dht_manifest_envelope(m),
                DhtWireEnvelope::PostQuantumManifest(m) => {
                    block_store.put_dht_pq_manifest_envelope(m)
                }
                DhtWireEnvelope::VaultCatalog(m) => block_store.put_dht_vault_catalog_envelope(m),
            };
            match res {
                Ok(()) => MeshWireResponse::PutDhtEnvelopeAck {
                    stored: true,
                    error: None,
                },
                Err(e) => MeshWireResponse::PutDhtEnvelopeAck {
                    stored: false,
                    error: Some(e.to_string()),
                },
            }
        }
        MeshWireRequest::GetDhtEnvelope { dht_key, kind } => {
            let found = match kind {
                DhtEnvelopeKind::ClassicalManifest => block_store
                    .get_dht_manifest_envelope(&dht_key)
                    .map(DhtWireEnvelope::ClassicalManifest),
                DhtEnvelopeKind::PostQuantumManifest => block_store
                    .get_dht_pq_manifest_envelope(&dht_key)
                    .map(DhtWireEnvelope::PostQuantumManifest),
                DhtEnvelopeKind::VaultCatalog => block_store
                    .get_dht_vault_catalog_envelope(&dht_key)
                    .map(DhtWireEnvelope::VaultCatalog),
            };
            if let Some(env) = found {
                MeshWireResponse::GetDhtEnvelopeResult {
                    envelope: Some(env),
                    error: None,
                }
            } else {
                MeshWireResponse::GetDhtEnvelopeResult {
                    envelope: None,
                    error: Some("DHT envelope not found".to_string()),
                }
            }
        }
    }
}
