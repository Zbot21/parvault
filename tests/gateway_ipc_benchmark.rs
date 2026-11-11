//! Task Gate 1 (`parvault::gateway::ipc` + `parvault::capabilities` + `parvault-seed --no-fs`):
//! 1. `test_gateway_zero_copy_ipc_streaming`: `100 MiB` anonymous `memfd` passed over
//!    Unix Domain Socket `SCM_RIGHTS`, streamed in `1 MiB` (`RouterSoc`) stripes, reconstructed
//!    bit-for-bit, with `/proc/self/status` `VmRSS` overhead strictly `< 16 MiB`.
//! 2. `test_gateway_macaroon_sub_millisecond_ram_enforcement`: `< 1 ms` zero-disk-I/O
//!    `CapabilityMacaroon` attenuation and range enforcement over IPC.
//! 3. `test_parvault_seed_no_fs_zero_disk_and_ram_cap_enforcement`: `parvault-seed --no-fs
//!    --in-memory-mb` zero-filesystem container/router mode + hard RAM ceiling + `0x00` wipe.

#![cfg(unix)]

use parvault::{
    bootstrap::ZeroTrustSeedServer,
    capabilities::{CapabilityMacaroon, Caveat},
    config::HardwareProfile,
    crypto::{compute_sha256, MasterKey, NodeIdentity},
    gateway::ipc::{
        create_memfd, read_self_rss_bytes, GatewayIpcClient, GatewayIpcServer, RetentionPolicy,
    },
    storage::{
        AnonymousQuotaVoucher, BlindedShardCapability, BlindedShardId, BlockStore, EvictionTarget,
        PrivacyPreservingEvictionEngine, QuotaManager,
    },
};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn fill_deterministic_1mib(buf: &mut [u8], stripe_idx: u64) {
    let mut state = stripe_idx
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0xD1B5_4A32_D192_ED03);
    for chunk in buf.as_chunks_mut::<8>().0 {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        *chunk = z.to_le_bytes();
    }
}

#[test]
fn test_gateway_zero_copy_ipc_streaming() {
    let tmp = tempdir().expect("tempdir");
    let sock_path = tmp.path().join("parvault_gate1.sock");
    let store_dir = tmp.path().join("gateway_store");

    let quota = QuotaManager::new(1024 * 1024 * 1024, 256 * 1024 * 1024);
    let store = BlockStore::new(&store_dir, quota)
        .expect("create BlockStore")
        .with_stripe_size_bytes(HardwareProfile::RouterSoc.stripe_size_bytes());
    let mk = MasterKey::generate();

    let mut server = GatewayIpcServer::new(&sock_path, store, mk)
        .with_profile(HardwareProfile::RouterSoc)
        .spawn()
        .expect("spawn GatewayIpcServer");

    let client = GatewayIpcClient::new(&sock_path);

    // 1. Allocate 100 MiB memfd in kernel shmem without mapping PTEs into userspace VmRSS.
    const PAYLOAD_MIB: usize = 100;
    const STRIPE_BYTES: usize = 1024 * 1024;
    let total_bytes = (PAYLOAD_MIB * STRIPE_BYTES) as u64;

    let in_memfd = create_memfd("parvault-gate1-100mb-in").expect("create input memfd");
    let mut in_file = File::from(in_memfd);
    let mut expected_sha = Sha256::new();
    {
        let mut chunk = vec![0u8; STRIPE_BYTES];
        for idx in 0..PAYLOAD_MIB {
            fill_deterministic_1mib(&mut chunk, idx as u64);
            expected_sha.update(&chunk);
            in_file.write_all(&chunk).expect("write 1 MiB to memfd");
        }
        in_file
            .seek(SeekFrom::Start(0))
            .expect("rewind input memfd");
    }
    let expected_digest: [u8; 32] = expected_sha.finalize().into();

    // Warm up allocator / thread stack once with a health check before measuring streaming RSS delta.
    let (_iops, _peers, sla) = client.query_health_sync().expect("query health");
    assert!((sla - 1.0).abs() < f32::EPSILON);

    let rss_baseline = read_self_rss_bytes();

    // 2. Pass the 100 MiB memfd via SCM_RIGHTS to GatewayIpcServer (`StorePayload`).
    let manifest = client
        .store_memfd(in_file.as_raw_fd(), total_bytes, RetentionPolicy::Ephemeral)
        .expect("store 100 MiB memfd over SCM_RIGHTS");
    assert_eq!(manifest.total_size, total_bytes);
    assert_eq!(manifest.shard_hashes.len(), PAYLOAD_MIB * 20);

    let rss_after_store = read_self_rss_bytes();
    let store_rss_delta = rss_after_store.saturating_sub(rss_baseline);
    assert!(
        store_rss_delta < 16 * 1024 * 1024,
        "StorePayload RSS delta {} bytes ({:.2} MiB) exceeded 16 MiB ceiling",
        store_rss_delta,
        store_rss_delta as f64 / (1024.0 * 1024.0)
    );

    // 3. Reconstruct all 100 x 1 MiB Reed-Solomon stripes into an output memfd via SCM_RIGHTS.
    let out_memfd = create_memfd("parvault-gate1-100mb-out").expect("create output memfd");
    let streamed = client
        .fetch_into_memfd(manifest.shard_hashes.clone(), out_memfd.as_raw_fd())
        .expect("fetch 100 MiB into output memfd over SCM_RIGHTS");
    assert_eq!(streamed, total_bytes);

    let rss_after_fetch = read_self_rss_bytes();
    let fetch_rss_delta = rss_after_fetch.saturating_sub(rss_baseline);
    assert!(
        fetch_rss_delta < 16 * 1024 * 1024,
        "FetchPayload RSS delta {} bytes ({:.2} MiB) exceeded 16 MiB ceiling",
        fetch_rss_delta,
        fetch_rss_delta as f64 / (1024.0 * 1024.0)
    );

    // 4. Verify reconstructed 100 MiB payload bit-for-bit in 1 MiB streaming reads.
    let mut out_file = File::from(out_memfd);
    out_file
        .seek(SeekFrom::Start(0))
        .expect("rewind output memfd");
    let mut actual_sha = Sha256::new();
    let mut read_buf = vec![0u8; STRIPE_BYTES];
    let mut verified_bytes = 0u64;
    loop {
        let n = out_file.read(&mut read_buf).expect("read output memfd");
        if n == 0 {
            break;
        }
        actual_sha.update(&read_buf[..n]);
        verified_bytes += n as u64;
    }
    assert_eq!(verified_bytes, total_bytes);
    let actual_digest: [u8; 32] = actual_sha.finalize().into();
    assert_eq!(
        actual_digest, expected_digest,
        "100 MiB zero-copy memfd round-trip SHA-256 mismatch"
    );

    server.shutdown();
}

#[test]
fn test_gateway_macaroon_sub_millisecond_ram_enforcement() {
    let tmp = tempdir().expect("tempdir");
    let sock_path = tmp.path().join("parvault_macaroon.sock");
    let store = BlockStore::new(
        tmp.path().join("store"),
        QuotaManager::new(256 * 1024 * 1024, 64 * 1024 * 1024),
    )
    .expect("store");
    let root_key = [0x42u8; 32];
    let mut server = GatewayIpcServer::new(&sock_path, store, MasterKey::generate())
        .with_profile(HardwareProfile::RouterSoc)
        .with_macaroon_root_key(root_key)
        .spawn()
        .expect("spawn server");

    let client = GatewayIpcClient::new(&sock_path);
    let payload: Vec<u8> = (0..(2 * 1024 * 1024)).map(|i| (i % 253) as u8).collect();
    let in_mfd = create_memfd("mac-in").expect("memfd");
    let mut in_f = File::from(in_mfd);
    in_f.write_all(&payload).unwrap();
    in_f.seek(SeekFrom::Start(0)).unwrap();
    let manifest = client
        .store_memfd(
            in_f.as_raw_fd(),
            payload.len() as u64,
            RetentionPolicy::Persistent,
        )
        .expect("store");

    let root_mac = CapabilityMacaroon::mint(
        &root_key,
        [0x11; 32],
        [0x22; 32],
        vec![Caveat::AllowedManifest(manifest.file_merkle_root)],
    )
    .expect("mint root macaroon");
    let attenuated = root_mac
        .attenuate(Caveat::ByteRange {
            offset: 1024 * 1024,
            length: 512 * 1024,
        })
        .unwrap()
        .attenuate(Caveat::ReadOnly)
        .unwrap();

    // Direct RAM verification latency check (< 1 ms):
    let t0 = Instant::now();
    for _ in 0..100 {
        attenuated
            .verify_in_ram(
                &root_key,
                &parvault::capabilities::AccessRequestContext {
                    manifest_root: manifest.file_merkle_root,
                    offset: 1024 * 1024,
                    length: 256 * 1024,
                    now_unix_ms: 1_700_000_000_000,
                    is_write: false,
                },
            )
            .expect("valid attenuated macaroon");
    }
    let avg_verify = t0.elapsed() / 100;
    assert!(
        avg_verify < Duration::from_millis(1),
        "Macaroon verify_in_ram took {:?} (>= 1 ms)",
        avg_verify
    );

    // Authorized range over IPC succeeds:
    let ok_mfd = create_memfd("mac-ok").unwrap();
    let n = client
        .fetch_range_into_memfd(
            &manifest,
            1024 * 1024,
            256 * 1024,
            ok_mfd.as_raw_fd(),
            Some(attenuated.clone()),
        )
        .expect("authorized range fetch");
    assert_eq!(n, 256 * 1024);

    // Unauthorized range (offset 0 outside [1 MiB .. 1.5 MiB]) rejected without disk shard reads:
    let bad_mfd = create_memfd("mac-bad").unwrap();
    let err = client
        .fetch_range_into_memfd(
            &manifest,
            0,
            64 * 1024,
            bad_mfd.as_raw_fd(),
            Some(attenuated),
        )
        .expect_err("out-of-bounds byte range must fail");
    assert!(
        err.to_string()
            .to_ascii_lowercase()
            .contains("macaroon capability rejected"),
        "unexpected error: {err}"
    );

    server.shutdown();
}

#[test]
fn test_parvault_seed_no_fs_zero_disk_and_ram_cap_enforcement() {
    let tmp = tempdir().expect("tempdir");
    let forbidden_data_dir = tmp.path().join("must_never_be_created");
    assert!(!forbidden_data_dir.exists());

    // 1. Subprocess test of `parvault-seed start --no-fs --in-memory-mb 4 --once`:
    //    Confirm zero directory or files are created on disk!
    let seed_bin = env!("CARGO_BIN_EXE_parvault-seed");
    let out = Command::new(seed_bin)
        .args([
            "start",
            "--mode",
            "public-bootstrap",
            "--no-fs",
            "--in-memory-mb",
            "4",
            "--listen",
            "/ip4/127.0.0.1/tcp/0",
            "--no-lan-discovery",
            "--data-dir",
            forbidden_data_dir.to_str().unwrap(),
            "--once",
        ])
        .output()
        .expect("spawn parvault-seed --no-fs");
    assert!(
        out.status.success(),
        "parvault-seed --no-fs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"max_storage_bytes\":4194304"));
    assert!(
        !forbidden_data_dir.exists(),
        "--no-fs created persistent directory on disk!"
    );

    // 2. Hard 1 MiB RAM byte-cap enforcement + LRU lease eviction + 0x00 zero-wipe verification:
    let cap_bytes: u64 = 1024 * 1024; // 1 MiB strict ceiling
    let mut quota = QuotaManager::new(cap_bytes, cap_bytes);
    quota.set_min_free_disk_bytes(0);
    let mem_store = BlockStore::new_in_memory(quota);
    assert!(mem_store.is_in_memory());

    let issuer = NodeIdentity::generate();
    let mut seed_srv = ZeroTrustSeedServer::new_public_bootstrapper(
        "mem-seed-1",
        mem_store.clone(),
        issuer.public_key_bytes(),
        2,
    );
    let mut eviction = PrivacyPreservingEvictionEngine::new_in_memory();
    let mk = MasterKey::generate();

    let mut last_locator = [0u8; 32];
    let mut last_bid_opt = None;
    for i in 0..12u32 {
        let shard = vec![(i as u8).wrapping_add(0x31); 128 * 1024]; // 12 x 128 KiB = 1.5 MiB > 1 MiB cap
        let bid = BlindedShardId {
            locator: compute_sha256(&i.to_be_bytes()),
            content_sha256: compute_sha256(&shard),
        };
        let (_, cap) = BlindedShardCapability::derive_keypair(&mk, &bid.locator);
        let voucher = AnonymousQuotaVoucher::mint(&issuer, 256 * 1024);
        seed_srv
            .ingest_blinded_shard_with_lease(
                &bid,
                &shard,
                cap,
                &voucher,
                parvault::storage::BlindedLeaseSpec::new(1 + u64::from(i), 30, [0xAA; 32]),
            )
            .expect("ingest blinded shard into bounded RAM store");
        eviction
            .record_blinded_shard_ingress(None, Some("peer-ram"), issuer.public_key_bytes(), bid)
            .expect("record in-memory attribution");

        assert!(
            mem_store.in_memory_used_bytes() <= cap_bytes,
            "in_memory_used_bytes {} exceeded 1 MiB cap {} at step {}",
            mem_store.in_memory_used_bytes(),
            cap_bytes,
            i
        );
        last_locator = bid.locator;
        last_bid_opt = Some(bid);
    }

    // Oldest shards (0..4) must have been evicted & 0x00-wiped to stay <= 1 MiB (8 x 128 KiB):
    assert_eq!(mem_store.blinded_lease_stats().1, 8);
    assert_eq!(mem_store.in_memory_used_bytes(), 8 * 128 * 1024);

    // Zero-wipe eviction of surviving blinded shard in RAM:
    let purge = eviction
        .evict_target(&EvictionTarget::BlindedLocator(last_locator), &mem_store)
        .expect("evict blinded locator in RAM");
    assert_eq!(purge.purged_blinded_shards, 1);
    assert_eq!(purge.zero_wiped_bytes, 128 * 1024);
    assert!(!mem_store.has_blinded_shard_on_disk(&last_bid_opt.unwrap()));
    assert!(!forbidden_data_dir.exists());
}
