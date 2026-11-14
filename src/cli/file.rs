//! `parvault` commands: file.

use super::CliEnv;
use crate::*;

pub(crate) async fn file(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        cfg,
        public_mode,
        mesh_client,
        block_store,
        ..
    } = env;
    let Commands::File { action } = command else {
        unreachable!("file() is only dispatched for Commands::File")
    };
    match action {
        FileAction::Store {
            path,
            path_flag,
            tier,
            key_hex,
        } => {
            let path = path
                .or(path_flag)
                .ok_or_else(|| anyhow::anyhow!("Missing input file path"))?;
            let effective_tier = if public_mode {
                println!(
                    "[parvault] Public Commons mode active: zero-knowledge AES-256-GCM encryption + 10-of-20 Reed-Solomon sharding."
                );
                ErasureTier::Consumer
            } else {
                tier
            };
            let master_key = resolve_master_key(
                &cfg.data_dir,
                key_hex.as_deref(),
                cfg.device_sealing_passphrase.as_deref(),
            )?;
            let owner_identity = NodeIdentity::from_master_key(&master_key);
            let owner_peer_id = owner_identity.device_peer_id();
            // v0.5.0: storing on ring peers needs a ring credential; say so instead of failing
            // on every shard.
            if !mesh_client.all_network_endpoints().is_empty()
                && parvault::network::admission::process_source()
                    .and_then(|source| source.credential(&owner_identity, [0u8; 32], None))
                    .is_none()
            {
                anyhow::bail!("{}", parvault::crypto::keys::NOT_IN_RING_MESSAGE);
            }
            let store_with_owner = block_store
                .clone()
                .with_mesh_client(mesh_client.with_identity(owner_identity));
            let (k, m, n) = effective_tier.params();
            info!(
                file = %path.display(),
                tier = ?effective_tier,
                k_data = k,
                m_parity = m,
                n_total = n,
                stripe_size_kib = cfg.stripe_size_bytes / 1024,
                "Encrypting (AES-256-GCM) and Reed-Solomon sharding file..."
            );

            let manifest = store_with_owner.store_file_streaming(
                &owner_peer_id,
                &path,
                &master_key,
                effective_tier,
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
                effective_tier.expansion_factor()
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
            let manifest = load_manifest_by_arg(&store_with_owner, &master_key, &manifest_or_root)?;

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
    }
    Ok(())
}
