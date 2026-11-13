//! End-to-End Integration & Security Tests for `GatewayBus`, `memfd` Sealing (`F_ADD_SEALS`),
//! Kernel `SO_PEERCRED` Peer UID Isolation, and `parvault token` Offline Macaroon Attenuation (`ADR-32`).

#![cfg(unix)]

mod common;

use parvault::capabilities::{AccessRequestContext, CapabilityMacaroon, Caveat};
use parvault::config::{ErasureTier, HardwareProfile};
use parvault::crypto::MasterKey;
use parvault::gateway::{
    create_memfd_sized, pread_full_or_eof, pwrite_all, validate_plugin_security_flags, GatewayBus,
    GatewayConfig, GatewayEngine, GatewayIpcClient, GatewayIpcServer, RetentionPolicy,
    DEFAULT_MACAROON_ROOT_KEY_FILE,
};
use parvault::os_sys::{geteuid, has_immutable_memfd_seals, seal_memfd_immutable};
use parvault::storage::{BlockStore, QuotaManager};
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::watch;

fn deterministic_payload(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    for chunk in out.chunks_mut(8) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let bytes = s.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    out
}

#[tokio::test]
async fn test_gateway_bus_in_process_vs_unix_socket_bit_for_bit_parity() {
    let tmp = tempdir().expect("tempdir");
    let root_key = [0x42u8; 32];
    let my_uid = geteuid();
    let payload = deterministic_payload(2 * 1024 * 1024 + 311_296);

    // 1. Setup InProcess GatewayBus (--no-socket mode)
    let inproc_dir = tmp.path().join("inproc");
    let inproc_cfg = GatewayConfig {
        stripe_size_bytes: HardwareProfile::RouterSoc.stripe_size_bytes(),
        tier: ErasureTier::Consumer,
        peers: Vec::new(),
        macaroon_root_key: Some(root_key),
        strict_allowed_peer_uids: Some(vec![my_uid]),
        require_sealed_ingest_memfd: true,
    };
    let inproc_engine = Arc::new(
        GatewayEngine::new(&inproc_dir, MasterKey::from_bytes([0x11; 32]), inproc_cfg).unwrap(),
    );
    let bus_inproc = GatewayBus::in_process(Arc::clone(&inproc_engine));

    // 2. Setup UnixSocket GatewayBus (/var/run/parvault.sock mode)
    let sock_dir = tmp.path().join("sock_store");
    let sock_path = tmp.path().join("parvault_parity.sock");
    let sock_store = BlockStore::new(
        &sock_dir,
        QuotaManager::new(512 * 1024 * 1024, 64 * 1024 * 1024),
    )
    .unwrap();
    let mut srv = GatewayIpcServer::new(&sock_path, sock_store, MasterKey::from_bytes([0x11; 32]))
        .with_profile(HardwareProfile::RouterSoc)
        .with_tier(ErasureTier::Consumer)
        .with_macaroon_root_key(root_key)
        .with_strict_allowed_peer_uids(vec![my_uid])
        .with_require_sealed_ingest_memfd(true)
        .spawn()
        .expect("spawn GatewayIpcServer");
    let bus_sock = GatewayBus::unix_socket(&sock_path);

    // Store identical payload across both transports using sealed memfd descriptors:
    let mfd_a = File::from(create_memfd_sized("parity-a", payload.len() as u64).unwrap());
    pwrite_all(&mfd_a, 0, &payload).unwrap();
    let man_inproc = bus_inproc
        .store_sealed_payload_fd(
            mfd_a.as_raw_fd(),
            payload.len() as u64,
            RetentionPolicy::Persistent,
        )
        .await
        .expect("inproc store_sealed_payload_fd");

    let mfd_b = File::from(create_memfd_sized("parity-b", payload.len() as u64).unwrap());
    pwrite_all(&mfd_b, 0, &payload).unwrap();
    let man_sock = bus_sock
        .store_sealed_payload_fd(
            mfd_b.as_raw_fd(),
            payload.len() as u64,
            RetentionPolicy::Persistent,
        )
        .await
        .expect("sock store_sealed_payload_fd");

    assert_eq!(man_inproc.total_size, man_sock.total_size);
    assert_eq!(man_inproc.stripe_size_bytes, man_sock.stripe_size_bytes);
    assert_eq!(man_inproc.shard_hashes.len(), man_sock.shard_hashes.len());

    // Fetch cross-stripe byte range [900_000 .. 900_000 + 300_000] gated by AllowedPeerUid(geteuid()):
    let slice_off = 900_000u64;
    let slice_len = 300_000u64;

    let mac_inproc = CapabilityMacaroon::mint(
        &root_key,
        [0xAA; 32],
        [0xBB; 32],
        vec![
            Caveat::AllowedManifest(man_inproc.file_merkle_root),
            Caveat::ByteRange {
                offset: 850_000,
                length: 400_000,
            },
            Caveat::ReadOnly,
            Caveat::AllowedPeerUid(my_uid),
        ],
    )
    .unwrap();
    let mac_sock = CapabilityMacaroon::mint(
        &root_key,
        [0xAA; 32],
        [0xBB; 32],
        vec![
            Caveat::AllowedManifest(man_sock.file_merkle_root),
            Caveat::ByteRange {
                offset: 850_000,
                length: 400_000,
            },
            Caveat::ReadOnly,
            Caveat::AllowedPeerUid(my_uid),
        ],
    )
    .unwrap();

    let out_inproc = File::from(create_memfd_sized("range-inproc", slice_len).unwrap());
    let n_inproc = bus_inproc
        .fetch_range_to_fd(
            man_inproc.clone(),
            slice_off,
            slice_len,
            out_inproc.as_raw_fd(),
            Some(mac_inproc),
        )
        .await
        .expect("inproc fetch_range_to_fd");

    let out_sock = File::from(create_memfd_sized("range-sock", slice_len).unwrap());
    let n_sock = bus_sock
        .fetch_range_to_fd(
            man_sock.clone(),
            slice_off,
            slice_len,
            out_sock.as_raw_fd(),
            Some(mac_sock),
        )
        .await
        .expect("sock fetch_range_to_fd");

    assert_eq!(n_inproc, slice_len);
    assert_eq!(n_sock, slice_len);

    let mut buf_inproc = vec![0u8; slice_len as usize];
    let mut buf_sock = vec![0u8; slice_len as usize];
    assert_eq!(
        pread_full_or_eof(&out_inproc, 0, &mut buf_inproc).unwrap(),
        slice_len as usize
    );
    assert_eq!(
        pread_full_or_eof(&out_sock, 0, &mut buf_sock).unwrap(),
        slice_len as usize
    );
    assert_eq!(buf_inproc, buf_sock);
    assert_eq!(
        buf_inproc.as_slice(),
        &payload[slice_off as usize..(slice_off + slice_len) as usize]
    );

    // Full-file FetchPayload + QueryHealthStatus parity (F-47: a whole-file token per manifest):
    let full_tok = |root: [u8; 32]| {
        CapabilityMacaroon::mint(
            &root_key,
            [0xAA; 32],
            [0xBB; 32],
            vec![Caveat::AllowedManifest(root), Caveat::ReadOnly],
        )
        .unwrap()
    };
    let full_a = File::from(create_memfd_sized("full-a", payload.len() as u64).unwrap());
    let full_b = File::from(create_memfd_sized("full-b", payload.len() as u64).unwrap());
    assert_eq!(
        bus_inproc
            .fetch_payload_to_fd(
                man_inproc.shard_hashes.clone(),
                full_a.as_raw_fd(),
                Some(full_tok(man_inproc.file_merkle_root)),
            )
            .await
            .unwrap(),
        payload.len() as u64
    );
    assert_eq!(
        bus_sock
            .fetch_payload_to_fd(
                man_sock.shard_hashes.clone(),
                full_b.as_raw_fd(),
                Some(full_tok(man_sock.file_merkle_root)),
            )
            .await
            .unwrap(),
        payload.len() as u64
    );

    let (iops_a, peers_a, sla_a) = bus_inproc.query_health().await.unwrap();
    let (iops_b, peers_b, sla_b) = bus_sock.query_health().await.unwrap();
    assert!(iops_a >= 1 && iops_b >= 1);
    assert_eq!(peers_a, peers_b);
    assert!((sla_a - sla_b).abs() < f32::EPSILON);

    srv.shutdown();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_require_sealed_ingest_memfd_blocks_unsealed_and_accepts_sealed() {
    let tmp = tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sealed_enforced.sock");
    let store = BlockStore::new(
        tmp.path().join("store"),
        QuotaManager::new(256 * 1024 * 1024, 64 * 1024 * 1024),
    )
    .unwrap();
    let server = GatewayIpcServer::new(&sock_path, store, MasterKey::generate())
        .with_profile(HardwareProfile::RouterSoc)
        .with_require_sealed_ingest_memfd(true);
    let engine_ref = Arc::clone(server.engine());
    let mut handle = server.spawn().unwrap();

    let client = GatewayIpcClient::new(&sock_path);
    let data = deterministic_payload(128 * 1024);

    // 1. Unsealed memfd MUST be rejected before hashing or encrypting a single byte:
    let unsealed_file = File::from(create_memfd_sized("unsealed-in", data.len() as u64).unwrap());
    pwrite_all(&unsealed_file, 0, &data).unwrap();
    assert!(!has_immutable_memfd_seals(unsealed_file.as_fd()).unwrap());

    let err = client
        .store_payload_fd(
            unsealed_file.as_raw_fd(),
            data.len() as u64,
            RetentionPolicy::Ephemeral,
        )
        .await
        .expect_err("unsealed memfd must be rejected");
    assert!(
        err.to_string().contains(
            "unsealed ingest memfd rejected (F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW required)"
        ),
        "unexpected error message: {err}"
    );
    assert_eq!(
        engine_ref.traffic_counters().0,
        0,
        "zero bytes may be ingested from an unsealed memfd"
    );

    // Also verify InProcess GatewayBus enforces the exact same seal gate:
    let inproc_bus = GatewayBus::in_process(Arc::clone(&engine_ref));
    let err_inproc = inproc_bus
        .store_payload_fd(
            unsealed_file.as_raw_fd(),
            data.len() as u64,
            RetentionPolicy::Ephemeral,
        )
        .await
        .expect_err("inproc unsealed memfd must be rejected");
    assert!(err_inproc.to_string().contains(
        "unsealed ingest memfd rejected (F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW required)"
    ));

    // 2. Sealing via seal_memfd_immutable succeeds and prevents post-seal TOCTOU tampering:
    seal_memfd_immutable(unsealed_file.as_fd()).expect("seal_memfd_immutable");
    assert!(has_immutable_memfd_seals(unsealed_file.as_fd()).unwrap());
    assert!(pwrite_all(&unsealed_file, 0, b"tamper").is_err());

    let manifest = client
        .store_payload_fd(
            unsealed_file.as_raw_fd(),
            data.len() as u64,
            RetentionPolicy::Ephemeral,
        )
        .await
        .expect("sealed memfd must succeed");
    assert_eq!(manifest.total_size, data.len() as u64);
    assert_eq!(engine_ref.traffic_counters().0, data.len() as u64);

    handle.shutdown();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_strict_allowed_peer_uids_so_peercred_rejects_unauthorized_uid() {
    let tmp = tempdir().expect("tempdir");
    let wrong_uid = geteuid().wrapping_add(1);

    // (a) Synchronous thread accept loop (`spawn`) rejects wrong UID immediately on `accept()`:
    let sync_sock = tmp.path().join("strict_sync.sock");
    let sync_store = BlockStore::new(
        tmp.path().join("sync_store"),
        QuotaManager::new(128 * 1024 * 1024, 32 * 1024 * 1024),
    )
    .unwrap();
    let mut sync_srv = GatewayIpcServer::new(&sync_sock, sync_store, MasterKey::generate())
        .with_strict_allowed_peer_uids(vec![wrong_uid])
        .spawn()
        .unwrap();

    let sync_client = GatewayIpcClient::new(&sync_sock);
    assert!(
        sync_client.query_health_sync().is_err(),
        "sync server must close socket immediately on SO_PEERCRED mismatch"
    );
    sync_srv.shutdown();

    // (b) Asynchronous Tokio accept loop (`bind(..).serve(..)`) rejects wrong UID immediately on `accept()`:
    let async_sock = tmp.path().join("strict_async.sock");
    let async_cfg = GatewayConfig {
        stripe_size_bytes: HardwareProfile::RouterSoc.stripe_size_bytes(),
        tier: ErasureTier::Consumer,
        peers: Vec::new(),
        macaroon_root_key: None,
        strict_allowed_peer_uids: Some(vec![wrong_uid]),
        require_sealed_ingest_memfd: false,
    };
    let async_eng = Arc::new(
        GatewayEngine::new(
            tmp.path().join("async_store"),
            MasterKey::generate(),
            async_cfg,
        )
        .unwrap(),
    );
    let async_srv = GatewayIpcServer::bind(&async_sock, async_eng).unwrap();
    let (tx, rx) = watch::channel(false);
    let srv_task = tokio::spawn(async move { async_srv.serve(rx).await });

    let async_client = GatewayIpcClient::new(&async_sock);
    assert!(
        async_client.query_health().await.is_err(),
        "async Tokio server must close socket immediately on SO_PEERCRED mismatch"
    );

    let _ = tx.send(true);
    let _ = srv_task.await;
}

#[tokio::test]
async fn test_cli_mint_offline_attenuate_inspect_and_gateway_fetch_range_enforcement() {
    let tmp = tempdir().expect("tempdir");
    let data_dir = tmp.path().join("cli_data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let parvault_bin = env!("CARGO_BIN_EXE_parvault");

    // Verify CLI startup guardrails reject misconfigured --strict-plugins and --no-socket + --ipc-socket:
    assert!(validate_plugin_security_flags(true, true, false, &[]).is_err());
    assert!(validate_plugin_security_flags(false, false, true, &[]).is_err());
    assert_eq!(
        validate_plugin_security_flags(false, false, true, &[1000, 1000, 1001]).unwrap(),
        Some(vec![1000, 1001])
    );

    let bad_strict = common::output_within_deadline(Command::new(parvault_bin).args([
        "--data-dir",
        data_dir.to_str().unwrap(),
        "gateway",
        "--strict-plugins",
        "serve",
    ]));
    assert!(
        !bad_strict.status.success(),
        "`parvault gateway --strict-plugins serve` without --allow-peer-uid must fail fast"
    );

    // 1. Start a live protected GatewayIpcServer and ingest a 512 KiB file so we have a real Merkle root:
    let sock_path = tmp.path().join("cli_token_test.sock");
    let store = BlockStore::new(
        tmp.path().join("gw_store"),
        QuotaManager::new(256 * 1024 * 1024, 64 * 1024 * 1024),
    )
    .unwrap();

    // Mint initial root token via `parvault token mint` (auto-creating 0600 <data_dir>/macaroon_root.key!):
    let mint_out = Command::new(parvault_bin)
        .args([
            "--data-dir",
            data_dir.to_str().unwrap(),
            "token",
            "mint",
            "--key-id",
            "media-plugin-v1",
        ])
        .output()
        .expect("run parvault token mint");
    assert!(
        mint_out.status.success(),
        "token mint stderr: {}",
        String::from_utf8_lossy(&mint_out.stderr)
    );
    let root_token = String::from_utf8(mint_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(root_token.starts_with("PARVAULT-MAC-V1:"));

    // Verify <data_dir>/macaroon_root.key was created atomically with 0600 permissions:
    let key_file_path = data_dir.join(DEFAULT_MACAROON_ROOT_KEY_FILE);
    let key_meta = std::fs::metadata(&key_file_path).expect("macaroon_root.key exists");
    assert_eq!(
        key_meta.permissions().mode() & 0o777,
        0o600,
        "macaroon_root.key must be 0600 owner-only"
    );
    let root_key_hex = std::fs::read_to_string(&key_file_path)
        .unwrap()
        .trim()
        .to_string();
    let root_key_bytes: [u8; 32] = hex::decode(&root_key_hex).unwrap().try_into().unwrap();

    let ipc_server = GatewayIpcServer::new(&sock_path, store, MasterKey::generate())
        .with_profile(HardwareProfile::RouterSoc)
        .with_macaroon_root_key(root_key_bytes)
        .with_require_sealed_ingest_memfd(true);
    let engine_ref = Arc::clone(ipc_server.engine());
    let mut srv = ipc_server.spawn().unwrap();
    let bus = GatewayBus::unix_socket(&sock_path);

    let payload = deterministic_payload(512 * 1024);
    let in_file = File::from(create_memfd_sized("cli-tok-in", payload.len() as u64).unwrap());
    pwrite_all(&in_file, 0, &payload).unwrap();
    let manifest = bus
        .store_sealed_payload_fd(
            in_file.as_raw_fd(),
            payload.len() as u64,
            RetentionPolicy::Persistent,
        )
        .await
        .unwrap();
    let manifest_hex = hex::encode(manifest.file_merkle_root);
    let my_uid = geteuid();

    // 2. Offline attenuate `root_token` via `parvault token attenuate` (ZERO root key passed!):
    let empty_dir = tmp.path().join("offline_no_keys");
    std::fs::create_dir_all(&empty_dir).unwrap();
    let att_out = Command::new(parvault_bin)
        .args([
            "--data-dir",
            empty_dir.to_str().unwrap(),
            "token",
            "attenuate",
            "--token",
            &root_token,
            "--manifest-hex",
            &manifest_hex,
            "--byte-range",
            "65536:131072",
            "--ttl-secs",
            "3600",
            "--read-only",
            "--allow-peer-uid",
            &my_uid.to_string(),
        ])
        .output()
        .expect("run parvault token attenuate");
    assert!(
        att_out.status.success(),
        "token attenuate stderr: {}",
        String::from_utf8_lossy(&att_out.stderr)
    );
    assert!(
        !empty_dir.join(DEFAULT_MACAROON_ROOT_KEY_FILE).exists(),
        "offline attenuate must never create or touch a root key file"
    );
    let attenuated_token = String::from_utf8(att_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(attenuated_token.starts_with("PARVAULT-MAC-V1:"));
    assert_ne!(attenuated_token, root_token);

    // 3. Inspect via `parvault token inspect --verify-key-hex`:
    let inspect_ok = Command::new(parvault_bin)
        .args([
            "token",
            "inspect",
            "--token",
            &attenuated_token,
            "--verify-key-hex",
            &root_key_hex,
            "--manifest-hex",
            &manifest_hex,
            "--offset",
            "65536",
            "--len",
            "32768",
            "--peer-uid",
            &my_uid.to_string(),
        ])
        .output()
        .unwrap();
    assert!(inspect_ok.status.success());
    let inspect_ok_stdout = String::from_utf8_lossy(&inspect_ok.stdout);
    assert!(
        inspect_ok_stdout.contains("verified: true"),
        "expected verified: true, got:\n{inspect_ok_stdout}"
    );

    let inspect_bad_write = Command::new(parvault_bin)
        .args([
            "token",
            "inspect",
            "--token",
            &attenuated_token,
            "--verify-key-hex",
            &root_key_hex,
            "--manifest-hex",
            &manifest_hex,
            "--offset",
            "65536",
            "--len",
            "32768",
            "--write",
        ])
        .output()
        .unwrap();
    assert!(inspect_bad_write.status.success());
    assert!(
        String::from_utf8_lossy(&inspect_bad_write.stdout).contains("verified: false"),
        "write request against ReadOnly caveat must report verified: false"
    );

    // 4. Present the CLI-attenuated token over GatewayBus::UnixSocket `FetchRange`:
    let parsed_mac = CapabilityMacaroon::from_compact_token(&attenuated_token).unwrap();

    // (a) Authorized sub-range [65536 .. 65536 + 32768] succeeds:
    let out_ok = File::from(create_memfd_sized("range-ok", 32768).unwrap());
    let streamed = bus
        .fetch_range_to_fd(
            manifest.clone(),
            65536,
            32768,
            out_ok.as_raw_fd(),
            Some(parsed_mac.clone()),
        )
        .await
        .expect("authorized FetchRange must succeed");
    assert_eq!(streamed, 32768);
    let mut slice_buf = vec![0u8; 32768];
    pread_full_or_eof(&out_ok, 0, &mut slice_buf).unwrap();
    assert_eq!(&slice_buf, &payload[65536..65536 + 32768]);

    // (b) Out-of-bounds range [0 .. 32768] fails:
    let out_oob = File::from(create_memfd_sized("range-oob", 32768).unwrap());
    assert!(
        bus.fetch_range_to_fd(
            manifest.clone(),
            0,
            32768,
            out_oob.as_raw_fd(),
            Some(parsed_mac.clone()),
        )
        .await
        .is_err(),
        "out-of-bounds FetchRange must be rejected"
    );

    // (c) Wrong peer_uid fails Caveat::AllowedPeerUid:
    let out_wrong_uid = create_memfd_sized("range-uid", 4096).unwrap();
    assert!(
        engine_ref
            .fetch_range_to_owned_fd_with_peer_uid(
                &manifest,
                65536,
                4096,
                Some(&parsed_mac),
                Some(my_uid.wrapping_add(1)),
                out_wrong_uid,
            )
            .is_err(),
        "wrong peer_uid must be rejected by Caveat::AllowedPeerUid"
    );

    // (d) Write context fails Caveat::ReadOnly:
    let write_ctx = AccessRequestContext {
        manifest_root: manifest.file_merkle_root,
        offset: 65536,
        length: 4096,
        is_write: true,
        now_unix_ms: 0,
        peer_uid: Some(my_uid),
    };
    assert!(parsed_mac
        .verify_in_ram(&root_key_bytes, &write_ctx)
        .is_err());

    srv.shutdown();
}

/// Plan-4 `@structural socket-mode` (`specs/ParVaultGatewayPluginBus.tla`): the gateway socket is
/// owner-only (`0600`) once the server is bound.
#[test]
fn gateway_socket_is_mode_0600() {
    let tmp = tempdir().unwrap();
    let sock = tmp.path().join("mode.sock");
    let cfg = GatewayConfig {
        stripe_size_bytes: HardwareProfile::RouterSoc.stripe_size_bytes(),
        tier: ErasureTier::Consumer,
        peers: Vec::new(),
        macaroon_root_key: None,
        strict_allowed_peer_uids: None,
        require_sealed_ingest_memfd: false,
    };
    let eng =
        Arc::new(GatewayEngine::new(tmp.path().join("store"), MasterKey::generate(), cfg).unwrap());
    let _srv = GatewayIpcServer::bind(&sock, eng).unwrap();
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "gateway socket mode is {mode:o}");
}
