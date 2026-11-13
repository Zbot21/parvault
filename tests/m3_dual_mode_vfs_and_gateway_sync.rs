//! Milestone M3 Integration & Security Suite (`ADR-33`):
//! 1. Synchronous `GatewayBus` (`InProcess` vs `UnixSocket`) parity, `memfd` seal enforcement, and
//!    `SO_PEERCRED` / `geteuid()` UID policy parity.
//! 2. Dual-mode `VirtualVaultFs` (`=y` in-process `--no-socket` zero `.sock` on disk vs `=m`
//!    Unix socket), `.parvaultignore` seeding, stoppable `VfsWebdavServerHandle` HTTP `206 Partial
//!    Content` Range streaming, and bounded `LruBlockCache` eviction.
//! 3. Zero-key `GatewayFolderSync` over both `InProcess` and `UnixSocket` with `.parvaultignore`,
//!    zero-reupload incremental fast path, tombstone tracking, selective `--filter` restore, and
//!    attenuated `CapabilityMacaroon` enforcement (including unauthorized UID & byte-budget rejection).
//! 4. Tampered `GatewayFolderCatalog` path-traversal (`../escape`, `/abs`, `C:`, symlink) rejection.

#![forbid(unsafe_code)]
#![cfg(unix)]

use parvault::capabilities::{CapabilityMacaroon, Caveat};
use parvault::config::{ErasureTier, HardwareProfile};
use parvault::crypto::MasterKey;
use parvault::gateway::ipc::{
    create_memfd, create_memfd_sized, EphemeralShardManifest, GatewayBus, GatewayIpcServer,
    RetentionPolicy,
};
use parvault::gateway::{pwrite_all, GatewayConfig, GatewayEngine};
use parvault::os_sys::geteuid;
use parvault::storage::{BlockStore, FileManifest, QuotaManager};
use parvault::sync::{
    compute_file_sha256_streaming, sanitize_sync_relative_path, DeletedFileTombstone,
    GatewayFolderCatalog, GatewayFolderSync, GatewaySyncedFileEntry,
};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut s = seed ^ 0x9E37_79B9_7F4A_7C15;
    for chunk in out.chunks_mut(8) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let b = s.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
    out
}

fn count_socket_files_recursive(dir: &Path) -> usize {
    let Ok(rd) = fs::read_dir(dir) else {
        return 0;
    };
    let mut count = 0usize;
    for ent in rd.flatten() {
        let Ok(ft) = ent.file_type() else {
            continue;
        };
        if ft.is_socket() {
            count += 1;
        } else if ft.is_dir() {
            count += count_socket_files_recursive(&ent.path());
        }
    }
    count
}

#[test]
fn test_gateway_bus_sync_surface_parity_and_sealed_memfd_enforcement() {
    let tmp = tempdir().expect("tempdir");
    let uid = geteuid();
    let root_key = [0x33u8; 32];
    let payload = deterministic_bytes(101, 1_310_720);

    // InProcess engine (`--no-socket`)
    let inproc_cfg = GatewayConfig {
        stripe_size_bytes: HardwareProfile::RouterSoc.stripe_size_bytes(),
        tier: ErasureTier::Consumer,
        peers: Vec::new(),
        macaroon_root_key: Some(root_key),
        strict_allowed_peer_uids: Some(vec![uid]),
        require_sealed_ingest_memfd: true,
    };
    let inproc_engine = Arc::new(
        GatewayEngine::new(
            tmp.path().join("inproc_store"),
            MasterKey::from_bytes([0x21; 32]),
            inproc_cfg,
        )
        .expect("inproc GatewayEngine"),
    );
    let bus_inproc = GatewayBus::in_process(Arc::clone(&inproc_engine));

    // UnixSocket engine
    let sock_path = tmp.path().join("sync_surface.sock");
    let sock_store = BlockStore::new(
        tmp.path().join("sock_store"),
        QuotaManager::new(512 * 1024 * 1024, 64 * 1024 * 1024),
    )
    .expect("sock BlockStore");
    let mut srv = GatewayIpcServer::new(&sock_path, sock_store, MasterKey::from_bytes([0x21; 32]))
        .with_profile(HardwareProfile::RouterSoc)
        .with_tier(ErasureTier::Consumer)
        .with_macaroon_root_key(root_key)
        .with_strict_allowed_peer_uids(vec![uid])
        .with_require_sealed_ingest_memfd(true)
        .spawn()
        .expect("spawn GatewayIpcServer");
    let bus_sock = GatewayBus::unix_socket(&sock_path);

    for (label, bus) in [("inproc", &bus_inproc), ("unix_sock", &bus_sock)] {
        // 1. Unsealed memfd must be rejected by `store_memfd_sync`
        let unsealed = File::from(create_memfd_sized("unsealed-m3", payload.len() as u64).unwrap());
        pwrite_all(&unsealed, 0, &payload).unwrap();
        let err = bus
            .store_memfd_sync(
                unsealed.as_raw_fd(),
                payload.len() as u64,
                RetentionPolicy::Persistent,
            )
            .expect_err("unsealed memfd must be rejected");
        assert!(
            err.to_string().contains("unsealed ingest memfd rejected"),
            "{label}: unexpected error {err}"
        );

        // 2. `store_sealed_memfd_sync` seals and stores cleanly
        let man = bus
            .store_sealed_memfd_sync(
                unsealed.as_raw_fd(),
                payload.len() as u64,
                RetentionPolicy::Persistent,
            )
            .unwrap_or_else(|e| panic!("{label}: store_sealed_memfd_sync failed: {e}"));
        assert_eq!(man.total_size, payload.len() as u64);

        // 3. `fetch_into_memfd_sync` reconstructs full payload
        let out_mfd = File::from(create_memfd("fetch-full-m3").unwrap());
        let full_n = bus
            .fetch_into_memfd_sync(man.shard_hashes.clone(), out_mfd.as_raw_fd())
            .expect("fetch_into_memfd_sync");
        assert_eq!(full_n, payload.len() as u64);
        let mut full_vec = vec![0u8; full_n as usize];
        let mut out_reader = out_mfd;
        out_reader.seek(SeekFrom::Start(0)).unwrap();
        out_reader.read_exact(&mut full_vec).unwrap();
        assert_eq!(full_vec, payload, "{label}: full payload mismatch");

        // 4. `fetch_range_bytes_sync` with attenuated macaroon across 1 MiB stripe boundary
        let mac = CapabilityMacaroon::mint(&root_key, [0xAA; 32], [0xBB; 32], Vec::new())
            .unwrap()
            .attenuate(Caveat::AllowedManifest(man.file_merkle_root))
            .unwrap()
            .attenuate(Caveat::ReadOnly)
            .unwrap()
            .attenuate(Caveat::AllowedPeerUid(uid))
            .unwrap()
            .attenuate(Caveat::ByteRange {
                offset: 1_000_000,
                length: 120_000,
            })
            .unwrap();
        let slice = bus
            .fetch_range_bytes_sync(&man, 1_000_128, 96_000, Some(mac))
            .expect("fetch_range_bytes_sync");
        assert_eq!(slice, payload[1_000_128..1_096_128]);

        // 5. `register_manifest_sync` + `query_health_sync`
        let sparse_fm = FileManifest {
            version: 2,
            file_merkle_root: [0x55; 32],
            file_salt: [0x66; 32],
            original_file_size: 0,
            stripe_size_bytes: 1_048_576,
            tier: ErasureTier::Consumer,
            stripes: Vec::new(),
            witness_peers: Vec::new(),
        };
        let reg = bus
            .register_manifest_sync(sparse_fm)
            .expect("register_manifest_sync");
        assert_eq!(reg.file_merkle_root, [0x55; 32]);

        let (iops, _peers, sla) = bus.query_health_sync().expect("query_health_sync");
        assert!(iops >= 1);
        assert!(sla > 0.0);
    }

    // 6. Disallowed `strict_allowed_peer_uids` on `GatewayBus::InProcess` MUST reject BOTH
    //    synchronous (`*_sync`) and asynchronous methods identically to `UnixSocket` `SO_PEERCRED`:
    let denied_engine = Arc::new(
        GatewayEngine::new(
            tmp.path().join("denied_uid_store"),
            MasterKey::from_bytes([0x22; 32]),
            GatewayConfig {
                stripe_size_bytes: HardwareProfile::RouterSoc.stripe_size_bytes(),
                tier: ErasureTier::Consumer,
                peers: Vec::new(),
                macaroon_root_key: None,
                strict_allowed_peer_uids: Some(vec![uid.wrapping_add(1)]),
                require_sealed_ingest_memfd: false,
            },
        )
        .expect("denied GatewayEngine"),
    );
    let denied_bus = GatewayBus::in_process(Arc::clone(&denied_engine));
    let denied_mfd = File::from(create_memfd_sized("denied-m3", 64).unwrap());
    pwrite_all(&denied_mfd, 0, &[0xAB; 64]).unwrap();
    let denied_fm = FileManifest {
        version: 2,
        file_merkle_root: [0x77; 32],
        file_salt: [0x88; 32],
        original_file_size: 0,
        stripe_size_bytes: 1_048_576,
        tier: ErasureTier::Consumer,
        stripes: Vec::new(),
        witness_peers: Vec::new(),
    };
    let dummy_ephem = EphemeralShardManifest {
        file_merkle_root: [0x77; 32],
        shard_hashes: Vec::new(),
        total_size: 0,
        stripe_size_bytes: 1_048_576,
    };

    assert_eq!(
        denied_bus
            .store_memfd_sync(denied_mfd.as_raw_fd(), 64, RetentionPolicy::Ephemeral)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        denied_bus
            .store_sealed_memfd_sync(denied_mfd.as_raw_fd(), 64, RetentionPolicy::Ephemeral)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        denied_bus
            .fetch_into_memfd_sync(Vec::new(), denied_mfd.as_raw_fd())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        denied_bus
            .fetch_range_into_memfd_sync(&dummy_ephem, 0, 0, denied_mfd.as_raw_fd(), None)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        denied_bus
            .fetch_range_bytes_sync(&dummy_ephem, 0, 0, None)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        denied_bus
            .register_manifest_sync(denied_fm.clone())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        denied_bus.query_health_sync().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current_thread runtime");
    rt.block_on(async {
        assert!(denied_bus
            .store_payload_fd(denied_mfd.as_raw_fd(), 64, RetentionPolicy::Ephemeral)
            .await
            .unwrap_err()
            .to_string()
            .contains("strict_allowed_peer_uids"));
        assert!(denied_bus
            .store_sealed_payload_fd(denied_mfd.as_raw_fd(), 64, RetentionPolicy::Ephemeral)
            .await
            .unwrap_err()
            .to_string()
            .contains("strict_allowed_peer_uids"));
        assert!(denied_bus
            .fetch_payload_to_fd(Vec::new(), denied_mfd.as_raw_fd())
            .await
            .unwrap_err()
            .to_string()
            .contains("strict_allowed_peer_uids"));
        assert!(denied_bus
            .fetch_range_to_fd(dummy_ephem, 0, 0, denied_mfd.as_raw_fd(), None)
            .await
            .unwrap_err()
            .to_string()
            .contains("strict_allowed_peer_uids"));
        assert!(denied_bus
            .register_manifest(denied_fm)
            .await
            .unwrap_err()
            .to_string()
            .contains("strict_allowed_peer_uids"));
        assert!(denied_bus
            .query_health()
            .await
            .unwrap_err()
            .to_string()
            .contains("strict_allowed_peer_uids"));
    });
    assert_eq!(
        denied_engine.traffic_counters().0,
        0,
        "disallowed peer UID must never ingest bytes in-process"
    );

    assert_eq!(
        count_socket_files_recursive(&tmp.path().join("inproc_store")),
        0,
        "in-process store must contain zero .sock files"
    );
    srv.shutdown();
}

#[cfg(feature = "vfs")]
fn verify_embedding_doc_snippet(root_key: &[u8; 32]) -> anyhow::Result<()> {
    use parvault::{
        capabilities::{CapabilityMacaroon, Caveat},
        gateway::{GatewayBus, RetentionPolicy, DEFAULT_IPC_SOCKET_PATH},
        sync::{sanitize_sync_relative_path, GatewayFolderSync},
        vfs::{VirtualVaultFs, WebdavVerifier},
    };
    use std::path::Path;

    let bus = GatewayBus::unix_socket(DEFAULT_IPC_SOCKET_PATH);
    assert_eq!(
        sanitize_sync_relative_path("docs\\guide//intro.md").as_deref(),
        Some("docs/guide/intro.md")
    );

    let mut sync = GatewayFolderSync::new(bus.clone());
    let catalog = sync.sync_folder_once(Path::new("./my-folder"), RetentionPolicy::Persistent)?;
    catalog.save_to_file(Path::new("./.parvault_gateway_catalog.bin"))?;

    let read_token =
        CapabilityMacaroon::mint(root_key, [0x11; 32], [0x22; 32], vec![Caveat::ReadOnly])?;
    let reader = GatewayFolderSync::with_catalog(bus.clone(), catalog)
        .with_default_macaroon(Some(read_token.clone()));
    reader.restore_to_folder(Path::new("./restored-docs"), &["docs/*".to_string()])?;

    let vfs = VirtualVaultFs::with_bus(bus, Path::new("/tmp/pv-vfs-cache"), 64 * 1024 * 1024)?
        .with_default_macaroon(Some(read_token));
    // F-43: every WebDAV request must present a read-only token under this root key.
    let mut webdav = vfs.spawn_webdav_server("127.0.0.1:0", WebdavVerifier::RootKey(*root_key))?;
    let _addr = webdav.local_addr();
    webdav.shutdown();
    Ok(())
}

#[cfg(feature = "vfs")]
#[test]
fn test_dual_mode_vfs_no_socket_inprocess_vs_unix_socket_webdav_range_and_lru() {
    use parvault::vfs::VirtualVaultFs;

    if std::hint::black_box(false) {
        let _ = verify_embedding_doc_snippet(&[0x42; 32]);
    }

    let tmp = tempdir().expect("tempdir");

    // Prepare seed directory with nested files, `.git/`, and `.parvaultignore`
    let seed_dir = tmp.path().join("seed_vault");
    fs::create_dir_all(seed_dir.join(".git")).unwrap();
    fs::create_dir_all(seed_dir.join("media")).unwrap();
    fs::write(seed_dir.join(".parvaultignore"), b"*.private\n").unwrap();
    fs::write(seed_dir.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(seed_dir.join("notes.private"), b"excluded by ignore").unwrap();

    // 3.5 MiB media file so 2 MiB LRU cache evicts deterministically
    let video_bytes = deterministic_bytes(202, 3 * 1024 * 1024 + 512 * 1024);
    fs::write(seed_dir.join("media/clip.bin"), &video_bytes).unwrap();
    fs::write(seed_dir.join("readme.txt"), b"dual-mode vfs readme").unwrap();

    // Mode A: `=y` Built-in InProcess VFS (`--no-socket`, zero `.sock` files anywhere in `inproc_root`)
    let inproc_root = tmp.path().join("mode_y_no_socket");
    let inproc_engine = Arc::new(
        GatewayEngine::new(
            inproc_root.join("store"),
            MasterKey::generate(),
            GatewayConfig {
                stripe_size_bytes: HardwareProfile::RouterSoc.stripe_size_bytes(),
                tier: ErasureTier::Consumer,
                peers: Vec::new(),
                macaroon_root_key: None,
                strict_allowed_peer_uids: None,
                require_sealed_ingest_memfd: true,
            },
        )
        .unwrap(),
    );
    let vfs_inproc = VirtualVaultFs::with_bus(
        GatewayBus::in_process(Arc::clone(&inproc_engine)),
        inproc_root.join("cache"),
        2 * 1024 * 1024,
    )
    .expect("VirtualVaultFs::with_bus in_process");
    let seeded_inproc = vfs_inproc
        .ingest_local_directory(&seed_dir)
        .expect("ingest inproc");
    assert_eq!(
        seeded_inproc, 2,
        "must skip .git, .parvaultignore, and *.private"
    );
    assert!(vfs_inproc.lookup_path("/.git/HEAD").is_none());
    assert!(vfs_inproc.lookup_path("/notes.private").is_none());
    assert_eq!(
        count_socket_files_recursive(&inproc_root),
        0,
        "--no-socket built-in VFS must create zero .sock files on disk"
    );

    // Mode B: `=m` Split-Plugin UnixSocket VFS
    let sock_root = tmp.path().join("mode_m_socket");
    let sock_path = sock_root.join("vfs.sock");
    let sock_store = BlockStore::new(
        sock_root.join("store"),
        QuotaManager::new(512 * 1024 * 1024, 64 * 1024 * 1024),
    )
    .unwrap();
    let mut srv = GatewayIpcServer::new(&sock_path, sock_store, MasterKey::generate())
        .with_profile(HardwareProfile::RouterSoc)
        .with_require_sealed_ingest_memfd(true)
        .spawn()
        .unwrap();
    let vfs_sock = VirtualVaultFs::new(&sock_path, sock_root.join("cache"), 2 * 1024 * 1024)
        .expect("VirtualVaultFs::new unix_socket");
    let seeded_sock = vfs_sock
        .ingest_local_directory(&seed_dir)
        .expect("ingest sock");
    assert_eq!(seeded_sock, 2);
    assert_eq!(count_socket_files_recursive(&sock_root), 1);

    // Verify byte-for-byte parity + LRU eviction on both VFS instances
    let clip_inproc = vfs_inproc.lookup_path("/media/clip.bin").unwrap();
    let clip_sock = vfs_sock.lookup_path("/media/clip.bin").unwrap();
    let s1 = vfs_inproc
        .read_at(clip_inproc.ino, 0, video_bytes.len() as u64)
        .unwrap();
    let s2 = vfs_sock
        .read_at(clip_sock.ino, 0, video_bytes.len() as u64)
        .unwrap();
    assert_eq!(s1, video_bytes);
    assert_eq!(s2, video_bytes);
    let stats_inproc = vfs_inproc.cache_stats();
    assert!(stats_inproc.used_bytes <= 2 * 1024 * 1024);
    assert!(stats_inproc.evictions >= 2);

    // Live stoppable `spawn_webdav_server` HTTP 206 Partial Content Range test on `--no-socket` VFS
    // F-43: a read-only token under the server's root key on every request.
    let webdav_key = [0x5A; 32];
    let webdav_token = parvault::capabilities::CapabilityMacaroon::mint(
        &webdav_key,
        [1; 32],
        [2; 32],
        vec![parvault::capabilities::Caveat::ReadOnly],
    )
    .unwrap()
    .to_compact_token();
    let mut webdav_handle = vfs_inproc
        .spawn_webdav_server(
            "127.0.0.1:0",
            parvault::vfs::WebdavVerifier::RootKey(webdav_key),
        )
        .expect("spawn_webdav_server");
    let addr = webdav_handle.local_addr();

    {
        let mut conn = TcpStream::connect(addr).expect("connect webdav");
        let req = format!(
            "GET /media/clip.bin HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {webdav_token}\r\nRange: bytes=1048590-2097209\r\nConnection: close\r\n\r\n"
        );
        conn.write_all(req.as_bytes()).unwrap();
        let mut raw_resp = Vec::new();
        conn.read_to_end(&mut raw_resp).unwrap();

        let hdr_end = raw_resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("HTTP header terminator")
            + 4;
        let hdr_str = String::from_utf8_lossy(&raw_resp[..hdr_end]);
        assert!(
            hdr_str.starts_with("HTTP/1.1 206 Partial Content"),
            "unexpected status: {hdr_str}"
        );
        assert!(hdr_str.contains(&format!(
            "Content-Range: bytes 1048590-2097209/{}",
            video_bytes.len()
        )));
        let body = &raw_resp[hdr_end..];
        assert_eq!(body, &video_bytes[1_048_590..=2_097_209]);
    }

    webdav_handle.shutdown();
    assert!(
        TcpStream::connect(addr).is_err(),
        "WebDAV listener must close cleanly on shutdown()"
    );
    srv.shutdown();
}

#[test]
fn test_gateway_folder_sync_inprocess_and_socket_incremental_macaroon_and_filters() {
    let tmp = tempdir().expect("tempdir");
    let local_uid = geteuid();
    let root_key = [0x77u8; 32];

    for use_socket in [false, true] {
        let mode_dir = tmp.path().join(if use_socket {
            "sock_mode"
        } else {
            "inproc_mode"
        });
        fs::create_dir_all(&mode_dir).unwrap();

        let engine = Arc::new(
            GatewayEngine::new(
                mode_dir.join("store"),
                MasterKey::generate(),
                GatewayConfig {
                    stripe_size_bytes: HardwareProfile::RouterSoc.stripe_size_bytes(),
                    tier: ErasureTier::Consumer,
                    peers: Vec::new(),
                    macaroon_root_key: Some(root_key),
                    strict_allowed_peer_uids: Some(vec![local_uid]),
                    require_sealed_ingest_memfd: true,
                },
            )
            .unwrap(),
        );

        let (bus, mut maybe_srv) = if use_socket {
            let sock = mode_dir.join("gw.sock");
            let srv = GatewayIpcServer::bind(&sock, Arc::clone(&engine))
                .unwrap()
                .spawn()
                .unwrap();
            (GatewayBus::unix_socket(&sock), Some(srv))
        } else {
            (GatewayBus::in_process(Arc::clone(&engine)), None)
        };

        let src = mode_dir.join("workspace");
        fs::create_dir_all(src.join("docs")).unwrap();
        fs::create_dir_all(src.join("images")).unwrap();
        fs::create_dir_all(src.join(".git")).unwrap();
        fs::write(src.join(".parvaultignore"), b"*.draft\nbuild/\n").unwrap();
        fs::write(src.join(".git/config"), b"[core]\n").unwrap();
        fs::write(src.join("docs/draft.draft"), b"skip me").unwrap();
        fs::write(src.join("docs/spec.md"), b"# Architecture Spec v1").unwrap();
        let photo_bytes = deterministic_bytes(303, 1_400_000);
        fs::write(src.join("images/photo.raw"), &photo_bytes).unwrap();

        // 1. Initial sync (v1)
        let mut syncer = GatewayFolderSync::new(bus.clone());
        let cat1 = syncer
            .sync_folder_once(&src, RetentionPolicy::Persistent)
            .expect("sync v1");
        assert_eq!(cat1.version, 1);
        assert_eq!(cat1.files.len(), 2);
        assert!(!cat1.files.contains_key("docs/draft.draft"));
        let ingested_after_v1 = engine.traffic_counters().0;
        assert!(ingested_after_v1 > 1_400_000);

        // 2. Second sync with zero changes -> incremental fast-path uploads ZERO bytes
        let cat2 = syncer
            .sync_folder_once(&src, RetentionPolicy::Persistent)
            .expect("sync v2 unchanged");
        assert_eq!(cat2.version, 2);
        assert_eq!(cat2.folder_merkle_root, cat1.folder_merkle_root);
        assert_eq!(
            engine.traffic_counters().0,
            ingested_after_v1,
            "unchanged incremental sync must upload 0 bytes"
        );

        // 3. Modify docs/spec.md, add docs/guide.md, delete images/photo.raw
        fs::write(
            src.join("docs/spec.md"),
            b"# Architecture Spec v2 (updated)",
        )
        .unwrap();
        let guide_bytes = deterministic_bytes(404, 1_250_000);
        fs::write(src.join("docs/guide.md"), &guide_bytes).unwrap();
        fs::remove_file(src.join("images/photo.raw")).unwrap();

        let diff3 = syncer.diff_folder(&src).expect("diff v3");
        assert_eq!(diff3.added, vec!["docs/guide.md".to_string()]);
        assert_eq!(diff3.modified, vec!["docs/spec.md".to_string()]);
        assert_eq!(diff3.deleted, vec!["images/photo.raw".to_string()]);

        let cat3 = syncer
            .sync_folder_once(&src, RetentionPolicy::Persistent)
            .expect("sync v3");
        assert_eq!(cat3.version, 3);
        assert!(cat3.deleted_tombstones.contains_key("images/photo.raw"));

        let cat_path = mode_dir.join("gateway_catalog.bin");
        cat3.save_to_file(&cat_path).expect("save catalog");
        let loaded_cat = GatewayFolderCatalog::load_from_file(&cat_path).expect("load catalog");
        assert_eq!(loaded_cat, cat3);

        // 4. Unauthorized restores MUST fail cleanly before writing output files:
        // (a) Missing macaroon
        let no_mac_puller = GatewayFolderSync::with_catalog(bus.clone(), loaded_cat.clone());
        assert!(no_mac_puller
            .restore_to_folder(&mode_dir.join("out_nomac"), &[])
            .is_err());

        // (b) Wrong AllowedPeerUid macaroon
        let wrong_uid_mac = CapabilityMacaroon::mint(&root_key, [0x01; 32], [0x99; 32], Vec::new())
            .unwrap()
            .attenuate(Caveat::ReadOnly)
            .unwrap()
            .attenuate(Caveat::AllowedPeerUid(local_uid.wrapping_add(1)))
            .unwrap();
        let wrong_uid_puller = GatewayFolderSync::with_catalog(bus.clone(), loaded_cat.clone())
            .with_default_macaroon(Some(wrong_uid_mac));
        assert!(wrong_uid_puller
            .restore_to_folder(&mode_dir.join("out_baduid"), &[])
            .is_err());

        // (c) Budget-exceeded ByteRange macaroon (allows only first 4096 B, fails on 1.25 MiB guide.md)
        let small_budget_mac =
            CapabilityMacaroon::mint(&root_key, [0x02; 32], [0x99; 32], Vec::new())
                .unwrap()
                .attenuate(Caveat::ReadOnly)
                .unwrap()
                .attenuate(Caveat::AllowedPeerUid(local_uid))
                .unwrap()
                .attenuate(Caveat::ByteRange {
                    offset: 0,
                    length: 4096,
                })
                .unwrap();
        let budget_out = mode_dir.join("out_budget");
        let budget_puller = GatewayFolderSync::with_catalog(bus.clone(), loaded_cat.clone())
            .with_default_macaroon(Some(small_budget_mac));
        assert!(budget_puller.restore_to_folder(&budget_out, &[]).is_err());
        assert!(
            !budget_out.join("docs/guide.md").exists(),
            "failed range restore must never leave partial target file"
        );

        // 5. Valid attenuated macaroon + selective `--filter` restore + full restore
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let valid_mac = CapabilityMacaroon::mint(&root_key, [0x03; 32], [0x99; 32], Vec::new())
            .unwrap()
            .attenuate(Caveat::ReadOnly)
            .unwrap()
            .attenuate(Caveat::AllowedPeerUid(local_uid))
            .unwrap()
            .attenuate(Caveat::ExpiresAtUnixMs(now_ms + 60_000))
            .unwrap();

        let valid_puller = GatewayFolderSync::with_catalog(bus.clone(), loaded_cat)
            .with_default_macaroon(Some(valid_mac));

        let filtered_out = mode_dir.join("out_filtered");
        let n_filtered = valid_puller
            .restore_to_folder(&filtered_out, &["docs/spec.md".to_string()])
            .expect("selective restore");
        assert_eq!(n_filtered, 1);
        assert_eq!(
            fs::read(filtered_out.join("docs/spec.md")).unwrap(),
            b"# Architecture Spec v2 (updated)"
        );
        assert!(!filtered_out.join("docs/guide.md").exists());

        let full_out = mode_dir.join("out_full");
        let n_full = valid_puller
            .restore_to_folder(&full_out, &[])
            .expect("full restore");
        assert_eq!(n_full, 2);
        let (_, guide_sha_expected) =
            compute_file_sha256_streaming(&src.join("docs/guide.md")).unwrap();
        let (_, guide_sha_actual) =
            compute_file_sha256_streaming(&full_out.join("docs/guide.md")).unwrap();
        assert_eq!(guide_sha_actual, guide_sha_expected);

        if !use_socket {
            assert_eq!(count_socket_files_recursive(&mode_dir), 0);
        }
        if let Some(ref mut s) = maybe_srv {
            s.shutdown();
        }
    }
}

#[test]
fn test_tampered_gateway_catalog_path_traversal_rejected() {
    assert_eq!(sanitize_sync_relative_path(""), None);
    assert_eq!(sanitize_sync_relative_path("/etc/passwd"), None);
    assert_eq!(sanitize_sync_relative_path("\\Windows\\System32"), None);
    assert_eq!(sanitize_sync_relative_path("C:\\boot.ini"), None);
    assert_eq!(sanitize_sync_relative_path("C:secret"), None);
    assert_eq!(sanitize_sync_relative_path("../escape"), None);
    assert_eq!(sanitize_sync_relative_path("docs/../../escape"), None);
    assert_eq!(sanitize_sync_relative_path("docs\\..\\escape"), None);
    assert_eq!(sanitize_sync_relative_path("./local"), None);
    assert_eq!(sanitize_sync_relative_path("bad\0nul"), None);
    assert_eq!(
        sanitize_sync_relative_path("docs//nested\\report.pdf/"),
        Some("docs/nested/report.pdf".to_string())
    );

    let tmp = tempdir().expect("tempdir");
    let engine = Arc::new(GatewayEngine::from_local_block_store(
        BlockStore::new(
            tmp.path().join("store"),
            QuotaManager::new(128 * 1024 * 1024, 32 * 1024 * 1024),
        )
        .unwrap(),
        MasterKey::generate(),
    ));
    let bus = GatewayBus::in_process(engine);

    let outside_canary = tmp.path().join("escape.txt");
    fs::write(&outside_canary, b"untouched canary").unwrap();
    let restore_dir = tmp.path().join("restore_sandbox");

    let sample_entry = |rel: &str| GatewaySyncedFileEntry {
        relative_path: rel.to_string(),
        size_bytes: 0,
        modified_unix_ms: 1,
        plaintext_sha256: [0u8; 32],
        ephemeral_manifest: EphemeralShardManifest {
            file_merkle_root: [0xAB; 32],
            shard_hashes: Vec::new(),
            total_size: 0,
            stripe_size_bytes: 1_048_576,
        },
    };

    let malicious_cases: Vec<(&str, &str)> = vec![
        ("../escape.txt", "../escape.txt"),
        ("sub/../../escape.txt", "sub/../../escape.txt"),
        ("/etc/passwd", "/etc/passwd"),
        ("C:\\escape.txt", "C:\\escape.txt"),
        ("safe.txt", "../escape.txt"),
        ("docs//safe.txt", "docs//safe.txt"),
    ];

    for (bad_key, bad_rel) in malicious_cases {
        let mut files = BTreeMap::new();
        files.insert(bad_key.to_string(), sample_entry(bad_rel));
        let tampered = GatewayFolderCatalog {
            version: 1,
            folder_merkle_root: [0x11; 32],
            files,
            deleted_tombstones: BTreeMap::new(),
        };
        let syncer = GatewayFolderSync::with_catalog(bus.clone(), tampered);
        let err = syncer
            .restore_to_folder(&restore_dir, &[])
            .expect_err("tampered catalog must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    // Tampered tombstone attempting to unlink `../escape.txt` must also be rejected
    let mut tombstones = BTreeMap::new();
    tombstones.insert(
        "../escape.txt".to_string(),
        DeletedFileTombstone {
            relative_path: "../escape.txt".to_string(),
            deleted_at_version: 2,
            previous_merkle_root: [0x22; 32],
        },
    );
    let tampered_tomb_cat = GatewayFolderCatalog {
        version: 2,
        folder_merkle_root: [0x22; 32],
        files: BTreeMap::new(),
        deleted_tombstones: tombstones,
    };
    let tomb_syncer = GatewayFolderSync::with_catalog(bus, tampered_tomb_cat);
    assert!(tomb_syncer.restore_to_folder(&restore_dir, &[]).is_err());
    assert_eq!(
        fs::read(&outside_canary).unwrap(),
        b"untouched canary",
        "outside canary must never be overwritten or unlinked"
    );
}
