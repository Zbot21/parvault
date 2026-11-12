//! Task Gate 4 (`parvault::vfs` + `parvault-fuse`):
//! `test_vfs_lazy_fetch_latency`:
//! 1. Mounts a virtual **`10 GiB` (`10,737,418,240` bytes)** vault fixture as instant metadata
//!    stubs over `/var/run/parvault.sock` (`GatewayIpcServer` + `VirtualVaultFs`) with zero eager
//!    full-file shard downloads.
//! 2. Requests a **`5 MiB`** slice at **`4.5 GiB` (`4,831,838,208`)** offset and asserts:
//!    - Exact bit-for-bit AES-256-GCM + Reed-Solomon (`10-of-20`) decrypted plaintext bytes.
//!    - **Time-To-First-Byte (`TTFB`) strictly `< 50 ms`**.
//!    - Bounded `LruBlockCache` (`4 MiB` capacity) deterministically evicts least-recently-used
//!      `.blk` files on disk so `used_bytes <= 4 MiB` and `evictions >= 1`.
//! 3. Validates the unprivileged HTTP `Range` (`206 Partial Content`) + WebDAV (`PROPFIND`)
//!    virtual drive frontend against the same `10 GiB` vault at the `4.5 GiB` offset.

#![cfg(all(unix, feature = "vfs"))]

use parvault::{
    config::{ErasureTier, HardwareProfile, ROUTER_SOC_STRIPE_SIZE_BYTES},
    crypto::{encrypt_stripe, generate_file_salt, MasterKey},
    gateway::ipc::{EphemeralShardManifest, GatewayIpcClient, GatewayIpcServer},
    sharding::{encode_ciphertext_stripe, merkle::compute_file_merkle_root},
    storage::{BlockStore, FileManifest, QuotaManager, ShardId, StripeManifestEntry},
    vfs::VirtualVaultFs,
};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tempfile::tempdir;

fn deterministic_stripe_plaintext(stripe_index: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut state = stripe_index
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x517C_C1B7_2722_0A95);
    for chunk in out.as_chunks_mut::<8>().0 {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        *chunk = z.to_le_bytes();
    }
    out
}

#[test]
fn test_vfs_lazy_fetch_latency() {
    let tmp = tempdir().expect("tempdir");
    let sock_path = tmp.path().join("parvault_gate4.sock");
    let store_dir = tmp.path().join("gateway_store");
    let cache_dir = tmp.path().join("vfs_lru_cache");

    let quota = QuotaManager::new(2 * 1024 * 1024 * 1024, 256 * 1024 * 1024);
    let store = BlockStore::new(&store_dir, quota)
        .expect("create BlockStore")
        .with_stripe_size_bytes(ROUTER_SOC_STRIPE_SIZE_BYTES);
    let mk = MasterKey::generate();

    // Build a 10 GiB (10,240 x 1 MiB stripes) FileManifest, populating real AES-256-GCM +
    // 10-of-20 Reed-Solomon shards for the 4.5 GiB target window (stripes 4608..4615) and
    // header window (stripes 0..2). Unaccessed regions remain sparse so the test runs in <1s
    // while exercising real 10 GiB index arithmetic and real cryptographic RS reconstruction!
    const TEN_GIB: u64 = 10 * 1024 * 1024 * 1024;
    const TOTAL_STRIPES: u64 = TEN_GIB / (ROUTER_SOC_STRIPE_SIZE_BYTES as u64); // 10,240
    const TARGET_OFFSET: u64 = 4_831_838_208; // Exact 4.5 GiB (4608 * 1 MiB)
    const SLICE_LEN: u64 = 5 * 1024 * 1024; // 5 MiB slice across stripes 4608..=4612

    let file_salt = generate_file_salt();
    let tier = ErasureTier::Consumer;
    let (k_data, m_parity, n_total) = tier.params();

    let mut stripes = Vec::with_capacity(TOTAL_STRIPES as usize);
    let mut stripe_roots = Vec::with_capacity(TOTAL_STRIPES as usize);

    for idx in 0..TOTAL_STRIPES {
        if idx < 2 || (4608..=4614).contains(&idx) {
            let plain = deterministic_stripe_plaintext(idx, ROUTER_SOC_STRIPE_SIZE_BYTES);
            let ct = encrypt_stripe(&mk, &file_salt, idx, &plain).expect("AES-256-GCM encrypt");
            let shard_set = encode_ciphertext_stripe(idx, &ct, tier).expect("RS 10-of-20 encode");
            // Store only K = 10 shards (simulating 10 offline peers out of 20!) to prove real RS erasure recovery!
            for shard_idx in 0..k_data {
                // Deliberately store odd/mixed indices (e.g. 2..12) so parity shards MUST be decoded over GF(2^8)!
                let chosen = shard_idx + 2;
                let sid = ShardId {
                    stripe_merkle_root: shard_set.stripe_merkle_root,
                    shard_index: chosen as u32,
                    shard_hash: shard_set.shard_hashes[chosen],
                };
                store
                    .put_shard("local", &sid, &shard_set.shards[chosen])
                    .expect("store shard");
            }
            stripe_roots.push(shard_set.stripe_merkle_root);
            stripes.push(StripeManifestEntry {
                stripe_index: idx,
                k_data,
                m_parity,
                original_ciphertext_len: shard_set.original_ciphertext_len,
                shard_len: shard_set.shard_len,
                stripe_merkle_root: shard_set.stripe_merkle_root,
                shard_hashes: shard_set.shard_hashes,
                assigned_peers: vec!["local".to_string(); n_total],
                shard_chunk_roots: Vec::new(),
            });
        } else {
            let sparse_root = [0u8; 32];
            stripe_roots.push(sparse_root);
            stripes.push(StripeManifestEntry {
                stripe_index: idx,
                k_data,
                m_parity,
                original_ciphertext_len: 0,
                shard_len: 0,
                stripe_merkle_root: sparse_root,
                shard_hashes: vec![[0u8; 32]; n_total],
                assigned_peers: Vec::new(),
                shard_chunk_roots: Vec::new(),
            });
        }
    }

    let file_merkle_root = compute_file_merkle_root(&stripe_roots);
    let manifest_10gib = FileManifest {
        version: 2,
        file_merkle_root,
        file_salt,
        original_file_size: TEN_GIB,
        stripe_size_bytes: ROUTER_SOC_STRIPE_SIZE_BYTES,
        tier,
        stripes,
        witness_peers: Vec::new(),
    };
    store
        .save_manifest(&mk, &manifest_10gib)
        .expect("save 10 GiB manifest");

    let mut server = GatewayIpcServer::new(&sock_path, store, mk)
        .with_profile(HardwareProfile::RouterSoc)
        .spawn()
        .expect("spawn GatewayIpcServer");

    let client = GatewayIpcClient::new(&sock_path);
    let eph = client
        .register_manifest(manifest_10gib.clone())
        .expect("register 10 GiB manifest over IPC");
    assert_eq!(eph.total_size, TEN_GIB);
    assert_eq!(eph.shard_hashes.len() as u64, TOTAL_STRIPES);

    // 1. Mount VirtualVaultFs with a strict 4 MiB LRU disk cache (< 5 MiB read slice!)
    let cache_cap_bytes = 4 * 1024 * 1024;
    let vfs =
        VirtualVaultFs::new(&sock_path, &cache_dir, cache_cap_bytes).expect("init VirtualVaultFs");
    let ino = vfs
        .register_stub_file(
            "/vault/dataset_10gib.bin",
            EphemeralShardManifest::from_file_manifest(&manifest_10gib),
            None,
        )
        .expect("register 10 GiB stub file");

    // Metadata stub must report 10 GiB instantly with ZERO cached blocks fetched yet:
    let attr = vfs.getattr(ino).expect("getattr");
    assert_eq!(attr.size_bytes, TEN_GIB);
    assert_eq!(vfs.cache_stats().used_bytes, 0);

    // 2. Request 5 MiB slice at 4.5 GiB offset and assert TTFB < 50 ms + bit-for-bit accuracy:
    let (data, ttfb) = vfs
        .read_range_with_ttfb(ino, TARGET_OFFSET, SLICE_LEN)
        .expect("lazy read 5 MiB at 4.5 GiB offset");

    assert!(
        ttfb < Duration::from_millis(50),
        "VFS lazy fetch TTFB {:?} exceeded 50 ms SLA ceiling!",
        ttfb
    );
    assert_eq!(data.len(), SLICE_LEN as usize);

    for rel_blk in 0..5u64 {
        let expected_blk =
            deterministic_stripe_plaintext(4608 + rel_blk, ROUTER_SOC_STRIPE_SIZE_BYTES);
        let start = (rel_blk as usize) * ROUTER_SOC_STRIPE_SIZE_BYTES;
        let end = start + ROUTER_SOC_STRIPE_SIZE_BYTES;
        assert_eq!(
            &data[start..end],
            expected_blk.as_slice(),
            "plaintext mismatch at stripe {}",
            4608 + rel_blk
        );
    }

    // 3. Validate LRU disk cache capacity ceiling (4 MiB) & eviction of oldest 1 MiB block(s):
    let stats = vfs.cache_stats();
    assert!(
        stats.used_bytes <= cache_cap_bytes,
        "LRU cache used_bytes {} exceeded capacity {}",
        stats.used_bytes,
        cache_cap_bytes
    );
    assert!(
        stats.evictions >= 1,
        "Expected >= 1 LRU eviction when reading 5 MiB through a 4 MiB cache, got {}",
        stats.evictions
    );
    let blk_files_on_disk = std::fs::read_dir(&cache_dir)
        .expect("read cache_dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "blk"))
        .count();
    assert!(
        blk_files_on_disk <= 4,
        "Expected <= 4 .blk files on disk under 4 MiB cap, found {blk_files_on_disk}"
    );

    // 4. Verify unprivileged HTTP Range (206 Partial Content) + WebDAV PROPFIND server at 4.5 GiB:
    let http_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let http_addr = http_listener.local_addr().unwrap();
    drop(http_listener);
    let vfs_http = vfs.clone();
    let addr_str = http_addr.to_string();
    std::thread::spawn(move || {
        let _ = vfs_http.serve_webdav_blocking(&addr_str);
    });
    std::thread::sleep(Duration::from_millis(30));

    // WebDAV PROPFIND check:
    {
        let mut stream = TcpStream::connect(http_addr).expect("connect webdav");
        stream
            .write_all(b"PROPFIND /vault HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 207 Multi-Status"));
        assert!(resp.contains("10737418240"));
    }

    // HTTP 206 Partial Content Range check at 4.5 GiB + 123 bytes (4096-byte slice):
    {
        let range_start = TARGET_OFFSET + 123;
        let range_end = range_start + 4096 - 1;
        let mut stream = TcpStream::connect(http_addr).expect("connect http range");
        let req = format!(
            "GET /vault/dataset_10gib.bin HTTP/1.1\r\nHost: localhost\r\nRange: bytes={range_start}-{range_end}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        let sep = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("HTTP header separator");
        let hdr = String::from_utf8_lossy(&raw[..sep]);
        assert!(hdr.starts_with("HTTP/1.1 206 Partial Content"), "hdr={hdr}");
        let body = &raw[sep + 4..];
        assert_eq!(body.len(), 4096);
        assert_eq!(body, &data[123..123 + 4096]);
    }

    server.shutdown();
}
