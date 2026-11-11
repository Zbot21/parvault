//! TLA+ Formal Verification & Lite-Client Seed Failover Integration Suite (`ADR-17` / `ADR-19`):
//!
//! 1. Executes the TLC Model Checker (`tla2tools.jar`) across all 7 formal TLA+ specifications
//!    in `specs/` as a first-class Rust integration test (`cargo test --release`):
//!    - `ParVaultProtocol.tla`
//!    - `ParVaultConfidentialityAndTrust.tla`
//!    - `ParVaultAnonymity.tla`
//!    - `ParVaultPostQuantum.tla`
//!    - `ParVaultBootstrapAndEarnedTier.tla`
//!    - `ParVaultLiteClientAndSeedFailover.tla`
//!    - `ParVaultZeroKeyAdminAndQuorum.tla`
//! 2. Verifies end-to-end `ADR-17` Lite-Client (`LiteSeedBacked`) 1.0x encrypted stripe deposit
//!    to `ZeroTrustSeedServer`, background 20-shard Reed-Solomon mesh syndication,
//!    "Cloud-Away-From-Home" selective subset restore, and automatic failover to direct
//!    16-of-20 mesh reconstruction when the NAS / seed server dies.

use parvault::{
    bootstrap::{LiteRestoreRoute, PersonalDeviceCert, ZeroTrustSeedServer},
    config::ErasureTier,
    crypto::{pqc::HybridPqSigningKeypair, MasterKey, NodeIdentity},
    storage::{BlockStore, QuotaManager},
    sync::FolderSyncEngine,
};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "parvault-tla-lite-{}-{}-{}",
        label,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn locate_tla2tools_jar() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("TLA2TOOLS_JAR") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    for candidate in [
        "/tmp/tla2tools.jar",
        "/root/tla2tools.jar",
        "tla2tools.jar",
        "../tla2tools.jar",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[test]
fn test_all_7_tla_plus_formal_specifications_via_tlc_model_checker() {
    let Some(jar_path) = locate_tla2tools_jar() else {
        panic!(
            "tla2tools.jar not found in TLA2TOOLS_JAR, /tmp/tla2tools.jar, or /root/tla2tools.jar. \
             Download https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar to run TLA+ integration proofs."
        );
    };

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let specs_dir = manifest_dir.join("specs");
    let meta_base = unique_temp_dir("tlc-states");

    let specs = [
        "ParVaultProtocol",
        "ParVaultConfidentialityAndTrust",
        "ParVaultAnonymity",
        "ParVaultPostQuantum",
        "ParVaultBootstrapAndEarnedTier",
        "ParVaultLiteClientAndSeedFailover",
        "ParVaultZeroKeyAdminAndQuorum",
    ];

    for spec_name in specs {
        let spec_meta = meta_base.join(spec_name);
        let cfg_file = format!("{spec_name}.cfg");
        let tla_file = format!("{spec_name}.tla");

        let output = Command::new("java")
            .current_dir(&specs_dir)
            .arg("-XX:+UseParallelGC")
            .arg("-cp")
            .arg(&jar_path)
            .arg("tlc2.TLC")
            .args(["-workers", "auto", "-cleanup", "-metadir"])
            .arg(&spec_meta)
            .arg("-config")
            .arg(&cfg_file)
            .arg(&tla_file)
            .output()
            .unwrap_or_else(|e| panic!("Failed to invoke java tlc2.TLC for {spec_name}: {e}"));

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success()
                && stdout.contains("Model checking completed. No error has been found."),
            "TLC model checking failed for {spec_name}:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        );
    }

    let _ = fs::remove_dir_all(&meta_base);
}

#[test]
fn test_lite_client_seed_syndication_nas_death_failover_and_selective_partial_restore() {
    let base = unique_temp_dir("lite-seed-failover");
    let laptop_store_dir = base.join("laptop_local");
    let nas_seed_dir = base.join("nas_seed");
    let watched_dir = base.join("laptop_workspace");
    let away_restore_dir = base.join("coffee_shop_selective_restore");
    let nas_dead_restore_dir = base.join("nas_dead_selective_restore");

    fs::create_dir_all(watched_dir.join("docs")).unwrap();
    fs::create_dir_all(watched_dir.join("src")).unwrap();
    fs::create_dir_all(watched_dir.join("media")).unwrap();

    let doc_bytes = b"# Zero-Trust Architecture\nLite client + Seed syndication with NAS failover.";
    let src_bytes = b"pub fn verify_protocol_symmetry() -> bool { true }";
    let media_bytes: Vec<u8> = (0..8192).map(|i| ((i * 37 + 11) & 0xFF) as u8).collect();

    fs::write(watched_dir.join("docs/architecture.md"), doc_bytes).unwrap();
    fs::write(watched_dir.join("src/engine.rs"), src_bytes).unwrap();
    fs::write(watched_dir.join("media/archive.bin"), &media_bytes).unwrap();

    // 1. Initialize Laptop Lite Client & Paired Homelab NAS Seed Server (`16-of-20` Homelab tier)
    let owner_pq = HybridPqSigningKeypair::generate().unwrap();
    let laptop_id = NodeIdentity::generate();
    let laptop_cert = PersonalDeviceCert::issue(
        &owner_pq,
        &laptop_id.device_peer_id(),
        "Roaming-Laptop-Lite",
        1_700_000_000,
    )
    .unwrap();

    let laptop_store = BlockStore::new(
        &laptop_store_dir,
        QuotaManager::new(200 * 1024 * 1024, 20 * 1024 * 1024),
    )
    .unwrap();
    let nas_store = BlockStore::new(
        &nas_seed_dir,
        QuotaManager::new(500 * 1024 * 1024, 50 * 1024 * 1024),
    )
    .unwrap();
    let mut nas_seed_server = ZeroTrustSeedServer::new_homelab_vault(
        "homelab-nas-seed-box",
        nas_store,
        owner_pq.public_key(),
        2,
    );

    // Create 20 external Neighborhood Cloud mesh peer stores
    let mut mesh_stores: Vec<BlockStore> = Vec::with_capacity(20);
    for i in 0..20 {
        let p_dir = base.join(format!("mesh_peer_{i}"));
        let p_store = BlockStore::new(
            &p_dir,
            QuotaManager::new(100 * 1024 * 1024, 10 * 1024 * 1024),
        )
        .unwrap();
        mesh_stores.push(p_store);
    }
    let mesh_refs: Vec<&BlockStore> = mesh_stores.iter().collect();

    let master_key = MasterKey::generate();
    let mut laptop_engine =
        FolderSyncEngine::new(laptop_store, master_key, laptop_id, ErasureTier::Homelab);

    // 2. Laptop syncs in Lite Mode via NAS Seed Server -> NAS caches & syndicates 20 RS shards to mesh
    let (snapshot, receipts) = laptop_engine
        .sync_folder_lite_via_seed(&watched_dir, &laptop_cert, &mut nas_seed_server, &mesh_refs)
        .unwrap();
    assert_eq!(snapshot.files.len(), 3);
    assert_eq!(receipts.len(), 3);
    for r in &receipts {
        assert!(r.cached_on_seed_server);
        assert_eq!(r.total_shards_syndicated, 20);
        assert_eq!(r.mesh_peers_populated, 20);
    }
    assert_eq!(
        nas_seed_server.personal_device_quota_charged(&laptop_cert.device_peer_id),
        0,
        "Lite client must incur 0 reciprocity quota charge on its own HomelabRedundancyVault"
    );

    // 3. Browse catalog on laptop with zero shard downloads
    let catalog_items = FolderSyncEngine::list_snapshot_catalog(&snapshot);
    assert_eq!(catalog_items.len(), 3);

    // 4. Scenario A ("Cloud-Away-From-Home" while NAS is Online):
    //    Selectively restore ONLY `src/*.rs` via 1-hop Seed Server Fast Path
    let report_online = laptop_engine
        .restore_selective_with_seed_fallback(
            &snapshot,
            &["src/*.rs".to_string()],
            &laptop_cert,
            Some(&nas_seed_server),
            &mesh_refs,
            &away_restore_dir,
        )
        .unwrap();
    assert_eq!(
        report_online.route_used,
        LiteRestoreRoute::ViaSeedServerFastPath
    );
    assert_eq!(report_online.files_restored, vec!["src/engine.rs"]);
    assert_eq!(report_online.files_skipped, 2);
    assert_eq!(
        report_online.bytes_saved_not_downloaded,
        (doc_bytes.len() + media_bytes.len()) as u64
    );
    assert_eq!(
        fs::read(away_restore_dir.join("src/engine.rs")).unwrap(),
        src_bytes
    );
    assert!(!away_restore_dir.join("media/archive.bin").exists());

    // 5. Scenario B (Catastrophic NAS Death + 4 Mesh Peers Offline):
    //    Destroy NAS (`seed_server = None`) AND take 4 of the 20 mesh peers offline (leaving 16 of 20 shards).
    let surviving_16_mesh_refs: Vec<&BlockStore> = mesh_stores.iter().skip(4).collect();
    assert_eq!(surviving_16_mesh_refs.len(), 16);

    let report_nas_dead = laptop_engine
        .restore_selective_with_seed_fallback(
            &snapshot,
            &["docs/*".to_string()],
            &laptop_cert,
            None, // NAS is completely dead/unreachable!
            &surviving_16_mesh_refs,
            &nas_dead_restore_dir,
        )
        .unwrap();
    assert_eq!(
        report_nas_dead.route_used,
        LiteRestoreRoute::DirectFromMeshPeersFallback
    );
    assert_eq!(report_nas_dead.files_restored, vec!["docs/architecture.md"]);
    assert_eq!(report_nas_dead.files_skipped, 2);
    assert_eq!(
        fs::read(nas_dead_restore_dir.join("docs/architecture.md")).unwrap(),
        doc_bytes
    );

    // 6. Partial Byte-Range Stripe Restore directly from the 16 surviving mesh peers (while NAS is dead)
    let (range_slice, range_route) = laptop_engine
        .restore_file_byte_range(
            &snapshot,
            "media/archive.bin",
            (100, 256),
            Some(&laptop_cert),
            None,
            &surviving_16_mesh_refs,
        )
        .unwrap();
    assert_eq!(range_route, LiteRestoreRoute::DirectFromMeshPeersFallback);
    assert_eq!(range_slice, &media_bytes[100..356]);

    // 7. Graceful Node Decommission (`leave` — 1.0x direct shard handoff to a replacement peer):
    //    Node 4 (`mesh_stores[4]`) gracefully leaves the network and hands off its 3 hosted shards
    //    directly to a brand-new replacement node (`replacement_store`) at 1.0x bandwidth.
    let replacement_dir = base.join("replacement_mesh_peer");
    let replacement_store = BlockStore::new(
        &replacement_dir,
        QuotaManager::new(10 * 1024 * 1024, 10 * 1024 * 1024),
    )
    .unwrap();
    let departing_identity = NodeIdentity::generate();
    let leave_receipt = mesh_stores[4]
        .graceful_leave_and_redistribute(
            &departing_identity,
            std::slice::from_ref(&replacement_dir),
            true,
        )
        .unwrap();
    assert!(leave_receipt.verify_signature());
    assert!(leave_receipt.earned_standing_preserved);
    assert_eq!(leave_receipt.migrated_shards_count, 3); // 1 shard per file across the 3 files

    // Even with Node 4 now completely decommissioned and wiped, substituting `replacement_store`
    // keeps all 16 required shards online with zero 16x Reed-Solomon repair overhead!
    let mut post_leave_16_refs: Vec<&BlockStore> = vec![&replacement_store];
    post_leave_16_refs.extend(mesh_stores.iter().skip(5));
    assert_eq!(post_leave_16_refs.len(), 16);

    let (post_leave_slice, _) = laptop_engine
        .restore_file_byte_range(
            &snapshot,
            "src/engine.rs",
            (0, src_bytes.len() as u64),
            Some(&laptop_cert),
            None,
            &post_leave_16_refs,
        )
        .unwrap();
    assert_eq!(post_leave_slice, src_bytes);

    let _ = fs::remove_dir_all(&base);
}
