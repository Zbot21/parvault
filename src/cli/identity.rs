//! `parvault` commands: identity.

use super::CliEnv;
use crate::*;

pub(crate) async fn status(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        cfg,
        trust_mode,
        block_store,
        ..
    } = env;
    let Commands::Status = command else {
        unreachable!("status() is only dispatched for Commands::Status")
    };
    let node_id = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
    let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
    let pq_fp = pq_keypair.public_key().fingerprint_hex();
    let q = block_store.quota();
    let q_guard = q.lock().expect("quota lock");
    println!("=== ParVault Daemon Node Status ===");
    println!("Data Directory        : {}", cfg.data_dir.display());
    println!("Device Peer ID        : {}", node_id.device_peer_id());
    println!("Owner PQ Fingerprint  : {}", pq_fp);
    println!("Hardware Profile      : {}", cfg.hardware_profile);
    println!("Trust Pool Mode       : {}", trust_mode);
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
    let local_only = block_store.local_only_stripe_count();
    println!(
        "Local-Only Stripes    : {}{}",
        local_only,
        if local_only > 0 {
            " (kept only on this machine: NOT backed up)"
        } else {
            ""
        }
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
    Ok(())
}

pub(crate) async fn identity(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv { cfg, .. } = env;
    let Commands::Identity = command else {
        unreachable!("identity() is only dispatched for Commands::Identity")
    };
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
    Ok(())
}

pub(crate) async fn issue_device_cert(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv { cfg, .. } = env;
    let Commands::IssueDeviceCert {
        device_peer_id,
        device_label,
        cert_out,
    } = command
    else {
        unreachable!("issue_device_cert() is only dispatched for Commands::IssueDeviceCert")
    };
    let pq_keypair = HybridPqSigningKeypair::load_or_generate_in_dir(&cfg.data_dir)?;
    let pq_pk = pq_keypair.public_key();
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cert = PersonalDeviceCert::issue(&pq_keypair, &device_peer_id, &device_label, issued_at)?;
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
    Ok(())
}

pub(crate) async fn verify_device_cert(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv { cfg, .. } = env;
    let Commands::VerifyDeviceCert {
        cert,
        owner_pq_pubkey_hex,
    } = command
    else {
        unreachable!("verify_device_cert() is only dispatched for Commands::VerifyDeviceCert")
    };
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
    Ok(())
}
