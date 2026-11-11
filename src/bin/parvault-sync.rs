//! `parvault-sync` — Zero-Key Incremental Folder Synchronization Plugin for `parvault`
//! (`/var/run/parvault.sock`, `ADR-33`, `docs/GATEWAY_SOCKET_PROTOCOL.md`).
//!
//! Operates strictly as an unprivileged sibling client over [`parvault::gateway::ipc::GatewayBus`]:
//! holds **zero** `MasterKey` and **zero** `NodeIdentity` secrets in its synchronization engine or
//! catalog state, seals ingested `memfd`s (`F_ADD_SEALS`) before `SCM_RIGHTS` transfer, and
//! verifies end-to-end streaming `SHA-256` digests on `1 MiB` chunked `pull` restores.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use parvault::capabilities::CapabilityMacaroon;
use parvault::gateway::ipc::DEFAULT_IPC_SOCKET_PATH;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "parvault-sync",
    version,
    about = "ParVault Zero-Key Incremental Folder Sync Plugin (diff, push, watch, pull, list, self-test over /var/run/parvault.sock)"
)]
struct SyncCli {
    /// Path to the `parvault` Unix Domain Socket (`parvault up --ipc-socket ...`).
    #[arg(long, default_value = DEFAULT_IPC_SOCKET_PATH, global = true)]
    socket: PathBuf,

    /// Path to the local zero-key `GatewayFolderCatalog` state file.
    #[arg(long, default_value = "./.parvault_gateway_catalog.bin", global = true)]
    catalog: PathBuf,

    /// Optional `PARVAULT-MAC-V1:` attenuated capability macaroon presented on `pull` range reads.
    #[arg(long, global = true, value_name = "PARVAULT-MAC-V1:...")]
    macaroon: Option<String>,

    #[command(subcommand)]
    command: SyncCommand,
}

#[derive(Debug, Subcommand)]
enum SyncCommand {
    /// Compute a dry-run incremental diff against `--catalog` without uploading any bytes.
    Diff {
        /// Local directory to compare against `--catalog`.
        #[arg(long, value_name = "DIR")]
        folder: PathBuf,
    },
    /// Incrementally push added and modified files in `--folder` over `--socket` via sealed `memfd`.
    Push {
        /// Local directory to synchronize.
        #[arg(long, value_name = "DIR")]
        folder: PathBuf,

        /// Store payloads with `RetentionPolicy::Ephemeral` instead of `Persistent`.
        #[arg(long, default_value_t = false)]
        ephemeral: bool,
    },
    /// Continuously poll `--folder` and push incremental changes at `--interval-secs`.
    Watch {
        /// Local directory to watch and synchronize.
        #[arg(long, value_name = "DIR")]
        folder: PathBuf,

        /// Polling interval in seconds.
        #[arg(long, default_value_t = 10)]
        interval_secs: u64,
    },
    /// Restore synchronized files from `--catalog` over `--socket` into `--output` with streaming SHA-256 verification.
    Pull {
        /// Destination directory for verified restored files.
        #[arg(long, value_name = "DIR")]
        output: PathBuf,

        /// Optional relative path prefix, basename, or glob filter(s) to restore selectively.
        #[arg(long = "filter", value_name = "PREFIX", value_delimiter = ',')]
        filters: Vec<String>,
    },
    /// List files and tombstones recorded in `--catalog` with zero shard traffic.
    List,
    /// Run a self-contained sealed-`memfd` + attenuated-macaroon incremental push/diff/pull smoke test.
    SelfTest,
}

fn main() -> anyhow::Result<()> {
    let cli = SyncCli::parse();
    let default_macaroon = match cli
        .macaroon
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(
            CapabilityMacaroon::from_compact_token(raw)
                .map_err(|e| anyhow::anyhow!("invalid --macaroon token: {e}"))?,
        ),
        None => None,
    };

    #[cfg(not(unix))]
    {
        let _ = (&cli, &default_macaroon);
        anyhow::bail!("parvault-sync requires Unix Domain Sockets (Linux / Unix)");
    }

    #[cfg(unix)]
    {
        use parvault::gateway::ipc::{GatewayBus, RetentionPolicy};
        use parvault::sync::{GatewayFolderCatalog, GatewayFolderSync};
        use std::time::{Duration, Instant};

        let load_sync_client = |socket: &std::path::Path,
                                catalog_path: &std::path::Path,
                                mac: Option<CapabilityMacaroon>|
         -> anyhow::Result<GatewayFolderSync> {
            let bus = GatewayBus::unix_socket(socket);
            let mut sync = GatewayFolderSync::new(bus).with_default_macaroon(mac);
            if catalog_path.is_file() {
                let existing = GatewayFolderCatalog::load_from_file(catalog_path)?;
                sync.load_catalog(existing);
            }
            Ok(sync)
        };

        match cli.command {
            SyncCommand::Diff { folder } => {
                let sync = load_sync_client(&cli.socket, &cli.catalog, default_macaroon)?;
                let diff = sync.diff_folder(&folder)?;
                println!(
                    "Gateway Sync Diff for {} (catalog v{}):",
                    folder.display(),
                    sync.catalog().version
                );
                println!("  added       : {}", diff.added.len());
                println!("  modified    : {}", diff.modified.len());
                println!("  deleted     : {}", diff.deleted.len());
                println!("  unchanged   : {}", diff.unchanged.len());
                println!("  ignored     : {}", diff.ignored.len());
                println!("  upload_bytes: {}", diff.total_upload_bytes);
                for p in &diff.added {
                    println!("  + {p}");
                }
                for p in &diff.modified {
                    println!("  ~ {p}");
                }
                for p in &diff.deleted {
                    println!("  - {p}");
                }
            }
            SyncCommand::Push { folder, ephemeral } => {
                let mut sync = load_sync_client(&cli.socket, &cli.catalog, default_macaroon)?;
                let retention = if ephemeral {
                    RetentionPolicy::Ephemeral
                } else {
                    RetentionPolicy::Persistent
                };
                let t0 = Instant::now();
                let updated = sync.sync_folder_once(&folder, retention)?;
                updated.save_to_file(&cli.catalog)?;
                println!(
                    "[parvault-sync] pushed {} (v{}, files={}, tombstones={}, root={}, {:.2} ms)",
                    folder.display(),
                    updated.version,
                    updated.files.len(),
                    updated.deleted_tombstones.len(),
                    hex::encode(updated.folder_merkle_root),
                    t0.elapsed().as_secs_f64() * 1000.0
                );
            }
            SyncCommand::Watch {
                folder,
                interval_secs,
            } => {
                let poll = Duration::from_secs(interval_secs.max(1));
                let mut sync = load_sync_client(&cli.socket, &cli.catalog, default_macaroon)?;
                println!(
                    "[parvault-sync] watching {} every {}s over {} (catalog={})",
                    folder.display(),
                    poll.as_secs(),
                    cli.socket.display(),
                    cli.catalog.display()
                );
                loop {
                    let diff = sync.diff_folder(&folder)?;
                    if !diff.added.is_empty()
                        || !diff.modified.is_empty()
                        || !diff.deleted.is_empty()
                    {
                        let updated =
                            sync.sync_folder_once(&folder, RetentionPolicy::Persistent)?;
                        updated.save_to_file(&cli.catalog)?;
                        println!(
                            "[parvault-sync] synced v{} (+{} ~{} -{}, root={})",
                            updated.version,
                            diff.added.len(),
                            diff.modified.len(),
                            diff.deleted.len(),
                            hex::encode(updated.folder_merkle_root)
                        );
                    }
                    std::thread::sleep(poll);
                }
            }
            SyncCommand::Pull { output, filters } => {
                if !cli.catalog.is_file() {
                    anyhow::bail!(
                        "catalog file '{}' does not exist; run `parvault-sync push` first or pass --catalog",
                        cli.catalog.display()
                    );
                }
                let sync = load_sync_client(&cli.socket, &cli.catalog, default_macaroon)?;
                let t0 = Instant::now();
                let restored = sync.restore_to_folder(&output, &filters)?;
                println!(
                    "[parvault-sync] restored {restored} verified file(s) to {} in {:.2} ms",
                    output.display(),
                    t0.elapsed().as_secs_f64() * 1000.0
                );
            }
            SyncCommand::List => {
                if !cli.catalog.is_file() {
                    anyhow::bail!("catalog file '{}' does not exist", cli.catalog.display());
                }
                let cat = GatewayFolderCatalog::load_from_file(&cli.catalog)?;
                println!(
                    "GatewayFolderCatalog v{} (root={}, files={}, tombstones={}):",
                    cat.version,
                    hex::encode(cat.folder_merkle_root),
                    cat.files.len(),
                    cat.deleted_tombstones.len()
                );
                for entry in cat.files.values() {
                    println!(
                        "  {:>10} B  sha256={}  {}",
                        entry.size_bytes,
                        hex::encode(entry.plaintext_sha256),
                        entry.relative_path
                    );
                }
                for tomb in cat.deleted_tombstones.values() {
                    println!(
                        "  [deleted@v{}] {}",
                        tomb.deleted_at_version, tomb.relative_path
                    );
                }
            }
            SyncCommand::SelfTest => {
                run_self_test()?;
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn run_self_test() -> anyhow::Result<()> {
    use parvault::{
        capabilities::{CapabilityMacaroon, Caveat},
        config::HardwareProfile,
        crypto::MasterKey,
        gateway::ipc::{read_self_rss_bytes, GatewayBus, GatewayIpcServer, RetentionPolicy},
        storage::{BlockStore, QuotaManager},
        sync::{compute_file_sha256_streaming, GatewayFolderCatalog, GatewayFolderSync},
    };
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    struct TempDirGuard(PathBuf);
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let mut nonce = [0u8; 6];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let tmp_dir = std::env::temp_dir().join(format!(
        "parvault_sync_selftest_{}_{}",
        std::process::id(),
        hex::encode(nonce)
    ));
    std::fs::create_dir_all(&tmp_dir)?;
    let _guard = TempDirGuard(tmp_dir.clone());

    let t0 = Instant::now();
    let sock_path = tmp_dir.join("sync_selftest.sock");
    let catalog_path = tmp_dir.join("sync_catalog.bin");
    let src_dir = tmp_dir.join("src_vault");
    let out_dir = tmp_dir.join("pulled_vault");
    std::fs::create_dir_all(src_dir.join("sub"))?;
    std::fs::create_dir_all(src_dir.join("nested"))?;

    let root_key = [0x5Au8; 32];
    let local_uid = parvault::os_sys::geteuid();
    let store = BlockStore::new(
        tmp_dir.join("store"),
        QuotaManager::new(512 * 1024 * 1024, 64 * 1024 * 1024),
    )?;
    let mut srv = GatewayIpcServer::new(&sock_path, store, MasterKey::generate())
        .with_profile(HardwareProfile::RouterSoc)
        .with_require_sealed_ingest_memfd(true)
        .with_strict_allowed_peer_uids(vec![local_uid])
        .with_macaroon_root_key(root_key)
        .spawn()?;

    std::fs::write(src_dir.join(".parvaultignore"), b"*.ignored\n")?;
    std::fs::write(src_dir.join("alpha.txt"), b"initial alpha document")?;
    let initial_bravo: Vec<u8> = (0..(1536 * 1024)).map(|i| (i % 251) as u8).collect();
    std::fs::write(src_dir.join("sub/bravo.bin"), &initial_bravo)?;
    std::fs::write(src_dir.join("skip.ignored"), b"must never be uploaded")?;

    // 1. Initial push
    let mut pusher = GatewayFolderSync::new(GatewayBus::unix_socket(&sock_path));
    let cat1 = pusher.sync_folder_once(&src_dir, RetentionPolicy::Persistent)?;
    cat1.save_to_file(&catalog_path)?;
    anyhow::ensure!(cat1.version == 1, "expected catalog v1");
    anyhow::ensure!(cat1.files.len() == 2, "expected 2 non-ignored files");

    // 2. Edit + add + delete -> diff + incremental push
    let updated_bravo: Vec<u8> = (0..(1600 * 1024))
        .map(|i| ((i * 7 + 13) % 253) as u8)
        .collect();
    std::fs::write(src_dir.join("sub/bravo.bin"), &updated_bravo)?;
    std::fs::write(
        src_dir.join("nested/charlie.txt"),
        b"incremental charlie payload",
    )?;
    std::fs::remove_file(src_dir.join("alpha.txt"))?;

    let reloaded = GatewayFolderCatalog::load_from_file(&catalog_path)?;
    let mut inc_sync =
        GatewayFolderSync::with_catalog(GatewayBus::unix_socket(&sock_path), reloaded);
    let diff = inc_sync.diff_folder(&src_dir)?;
    anyhow::ensure!(
        diff.added == vec!["nested/charlie.txt".to_string()],
        "unexpected diff.added: {:?}",
        diff.added
    );
    anyhow::ensure!(
        diff.modified == vec!["sub/bravo.bin".to_string()],
        "unexpected diff.modified: {:?}",
        diff.modified
    );
    anyhow::ensure!(
        diff.deleted == vec!["alpha.txt".to_string()],
        "unexpected diff.deleted: {:?}",
        diff.deleted
    );

    let cat2 = inc_sync.sync_folder_once(&src_dir, RetentionPolicy::Persistent)?;
    cat2.save_to_file(&catalog_path)?;
    anyhow::ensure!(cat2.version == 2, "expected catalog v2");
    anyhow::ensure!(
        cat2.deleted_tombstones.contains_key("alpha.txt"),
        "expected tombstone for alpha.txt"
    );

    // 3. Offline-attenuated ReadOnly + AllowedPeerUid macaroon pull & byte-exact SHA-256 check
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let root_mac = CapabilityMacaroon::mint(&root_key, [0x11u8; 32], [0x22u8; 32], Vec::new())?;
    let attenuated_mac = root_mac
        .attenuate(Caveat::ReadOnly)?
        .attenuate(Caveat::AllowedPeerUid(local_uid))?
        .attenuate(Caveat::ExpiresAtUnixMs(now_ms + 60_000))?;

    let pull_cat = GatewayFolderCatalog::load_from_file(&catalog_path)?;
    let puller = GatewayFolderSync::with_catalog(GatewayBus::unix_socket(&sock_path), pull_cat)
        .with_default_macaroon(Some(attenuated_mac));
    let restored_count = puller.restore_to_folder(&out_dir, &[])?;
    srv.shutdown();

    anyhow::ensure!(restored_count == 2, "expected 2 restored files");
    anyhow::ensure!(
        !out_dir.join("alpha.txt").exists(),
        "deleted file must not exist"
    );
    anyhow::ensure!(
        !out_dir.join("skip.ignored").exists(),
        "ignored file must not exist"
    );

    let (_, src_bravo_sha) = compute_file_sha256_streaming(&src_dir.join("sub/bravo.bin"))?;
    let (out_bravo_len, out_bravo_sha) =
        compute_file_sha256_streaming(&out_dir.join("sub/bravo.bin"))?;
    anyhow::ensure!(
        out_bravo_len == updated_bravo.len() as u64 && out_bravo_sha == src_bravo_sha,
        "bravo.bin SHA-256 mismatch"
    );

    let (_, src_charlie_sha) = compute_file_sha256_streaming(&src_dir.join("nested/charlie.txt"))?;
    let (_, out_charlie_sha) = compute_file_sha256_streaming(&out_dir.join("nested/charlie.txt"))?;
    anyhow::ensure!(
        out_charlie_sha == src_charlie_sha,
        "charlie.txt SHA-256 mismatch"
    );

    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let rss_mib = read_self_rss_bytes() as f64 / (1024.0 * 1024.0);
    println!(
        "parvault-sync self-test: PASS (latency={elapsed_ms:.2} ms, rss={rss_mib:.2} MiB, files={restored_count}, catalog_v={})",
        cat2.version
    );
    Ok(())
}
