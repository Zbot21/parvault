//! `parvault` commands: maintenance.

use super::CliEnv;
use crate::*;

pub(crate) async fn scrub(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        cfg, block_store, ..
    } = env;
    let Commands::Scrub = command else {
        unreachable!("scrub() is only dispatched for Commands::Scrub")
    };
    let report = block_store.scrub_all_shards()?;
    let healthy_shards = report.verified_healthy_shards + report.verified_healthy_blinded_shards;
    let corrupted_quarantined_shards = report.quarantined_corrupted_shards.len()
        + report.quarantined_corrupted_blinded_locators.len();
    let total_shards_scanned = healthy_shards + corrupted_quarantined_shards;
    println!("=== ParVault Local Bit-Rot Scrub Report (ADR-15) ===");
    println!("Data Directory               : {}", cfg.data_dir.display());
    println!("total_shards_scanned         : {}", total_shards_scanned);
    println!(
        "healthy_shards               : {} (regular: {}, blinded: {})",
        healthy_shards, report.verified_healthy_shards, report.verified_healthy_blinded_shards
    );
    println!(
        "corrupted_quarantined_shards : {}",
        corrupted_quarantined_shards
    );
    Ok(())
}

pub(crate) async fn leave(env: CliEnv, command: Commands) -> anyhow::Result<()> {
    let CliEnv {
        cfg, block_store, ..
    } = env;
    let Commands::Leave {
        handoff_to,
        keep_local,
    } = command
    else {
        unreachable!("leave() is only dispatched for Commands::Leave")
    };
    let identity = NodeIdentity::load_or_generate_in_dir(&cfg.data_dir)?;
    let target_dirs: Vec<PathBuf> = handoff_to
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    let remove_local = !keep_local;
    let receipt =
        block_store.graceful_leave_and_redistribute(&identity, &target_dirs, remove_local)?;
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
    Ok(())
}
