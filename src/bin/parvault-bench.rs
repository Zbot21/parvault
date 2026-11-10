use clap::{Parser, Subcommand};
use parvault::{
    config::ErasureTier,
    crypto::{
        decrypt_stripe, encrypt_stripe, generate_file_salt,
        pqc::{HybridKemKeypair, HybridPqSigningKeypair, PqVaultMasterKey},
        MasterKey,
    },
    sharding::{
        merkle::MerkleTree,
        reed_solomon::{encode_ciphertext_stripe, reconstruct_zero_trust_with_quarantine},
    },
    storage::{BlockStore, QuotaManager},
    sync::compute_file_sha256_streaming,
};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const STRIPE_SIZE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB per ADR-01
const VALID_BIP39_SEED: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[derive(Parser, Debug)]
#[command(
    name = "parvault-bench",
    version,
    about = "Empirical wall-clock and /proc/self/status memory benchmark suite for ParVault"
)]
struct BenchCli {
    /// Total streaming file payload size in MiB (must be a multiple of 16 MiB; default: 64 MiB = 4 stripes).
    #[arg(long, global = true, default_value_t = 64)]
    payload_mib: usize,

    #[command(subcommand)]
    command: Option<BenchCommand>,
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum BenchCommand {
    /// Run the full empirical crypto, Reed-Solomon, and streaming RSS/HWM benchmark suite.
    Run,
    /// Alias for `run`: execute all empirical benchmarks and emit Markdown summary tables.
    All,
}

#[derive(Debug, Clone, Copy, Default)]
struct ProcMemSnapshot {
    vm_rss_kib: u64,
    vm_hwm_kib: u64,
    ru_maxrss_kib: u64,
}

impl ProcMemSnapshot {
    fn capture() -> Self {
        let mut snap = Self::default();
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    snap.vm_rss_kib = parse_kib_field(rest);
                } else if let Some(rest) = line.strip_prefix("VmHWM:") {
                    snap.vm_hwm_kib = parse_kib_field(rest);
                }
            }
        }
        snap.ru_maxrss_kib = query_rusage_maxrss_kib().max(snap.vm_hwm_kib);
        snap
    }

    fn rss_mib(self) -> f64 {
        self.vm_rss_kib as f64 / 1024.0
    }

    fn hwm_mib(self) -> f64 {
        self.vm_hwm_kib as f64 / 1024.0
    }
}

#[cfg(target_os = "linux")]
fn trim_allocs() {
    extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }
    // SAFETY: `malloc_trim(0)` releases free glibc heap arenas back to the OS kernel so `VmRSS`
    // measures live resident allocations rather than unmapped allocator cache pages.
    unsafe {
        let _ = malloc_trim(0);
    }
}

#[cfg(not(target_os = "linux"))]
fn trim_allocs() {}

fn parse_kib_field(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|tok| tok.parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(unix)]
fn query_rusage_maxrss_kib() -> u64 {
    #[repr(C)]
    #[derive(Default)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct Rusage {
        ru_utime: Timeval,
        ru_stime: Timeval,
        ru_maxrss: i64,
        ru_ixrss: i64,
        ru_idrss: i64,
        ru_isrss: i64,
        ru_minflt: i64,
        ru_majflt: i64,
        ru_nswap: i64,
        ru_inblock: i64,
        ru_oublock: i64,
        ru_msgsnd: i64,
        ru_msgrcv: i64,
        ru_nsignals: i64,
        ru_nvcsw: i64,
        ru_nivcsw: i64,
    }

    extern "C" {
        fn getrusage(who: i32, usage: *mut Rusage) -> i32;
    }

    const RUSAGE_SELF: i32 = 0;
    let mut usage = Rusage::default();
    // SAFETY: `Rusage` matches the Linux LP64 `struct rusage` layout and is zero-initialized.
    let rc = unsafe { getrusage(RUSAGE_SELF, &mut usage) };
    if rc == 0 && usage.ru_maxrss > 0 {
        usage.ru_maxrss as u64
    } else {
        0
    }
}

#[cfg(not(unix))]
fn query_rusage_maxrss_kib() -> u64 {
    0
}

fn unique_bench_temp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("parvault-bench-{}-{}", std::process::id(), nanos));
    fs::create_dir_all(&dir).expect("create benchmark temp dir");
    dir
}

fn main() -> anyhow::Result<()> {
    let cli = BenchCli::parse();
    let _cmd = cli.command.unwrap_or(BenchCommand::Run);
    let payload_mib = cli.payload_mib.max(16);
    let payload_bytes = payload_mib * 1024 * 1024;
    let num_stripes = payload_bytes.div_ceil(STRIPE_SIZE_BYTES);

    println!("================================================================================");
    println!(
        " ParVault Empirical Cryptography, Reed-Solomon & Memory Benchmark (`parvault-bench`)"
    );
    println!("================================================================================");
    println!(
        " Streaming Payload : {} MiB ({} x 16 MiB stripes)",
        payload_mib, num_stripes
    );
    println!(
        " Memory Telemetry  : Linux /proc/self/status (VmRSS, VmHWM) + getrusage(RUSAGE_SELF)"
    );
    println!();

    // -------------------------------------------------------------------------
    // Phase 1: Streaming Multi-Stripe Store & Restore with Process Memory Proof
    // -------------------------------------------------------------------------
    let mem_baseline = ProcMemSnapshot::capture();
    let bench_dir = unique_bench_temp_dir();
    let input_path = bench_dir.join("streaming_payload.bin");
    let output_path = bench_dir.join("restored_payload.bin");
    let store_dir = bench_dir.join("block_store");

    // Stream-generate input file on disk in 64 KiB chunks so test setup never allocates the full payload in RAM.
    {
        let mut f = File::create(&input_path)?;
        let mut chunk = [0u8; 65_536];
        let total_chunks = payload_bytes / chunk.len();
        for c in 0..total_chunks {
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte = ((c.wrapping_mul(131).wrapping_add(i * 17)) & 0xFF) as u8;
            }
            f.write_all(&chunk)?;
        }
        f.sync_all()?;
    }

    let input_sha256 = compute_file_sha256_streaming(&input_path)?;
    let mem_after_input_gen = ProcMemSnapshot::capture();

    let quota = QuotaManager::new(10 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
    let store = BlockStore::new(&store_dir, quota)?;
    let master_key = MasterKey::generate();

    let store_start = Instant::now();
    let manifest = store.store_file_streaming(
        "bench-local-owner",
        &input_path,
        &master_key,
        ErasureTier::Homelab,
        STRIPE_SIZE_BYTES,
    )?;
    let store_elapsed = store_start.elapsed();
    let store_mib_s = (payload_mib as f64) / store_elapsed.as_secs_f64();
    trim_allocs();
    let mem_after_store = ProcMemSnapshot::capture();

    let restore_start = Instant::now();
    store.restore_file_streaming(&manifest, &master_key, &output_path)?;
    let restore_elapsed = restore_start.elapsed();
    let restore_mib_s = (payload_mib as f64) / restore_elapsed.as_secs_f64();
    trim_allocs();
    let mem_after_restore = ProcMemSnapshot::capture();

    let restored_sha256 = compute_file_sha256_streaming(&output_path)?;
    assert_eq!(
        input_sha256, restored_sha256,
        "Restored streaming payload SHA-256 must match original input"
    );

    let _ = fs::remove_dir_all(&bench_dir);

    // -------------------------------------------------------------------------
    // Phase 2: Cryptographic Primitive & Subkey Benchmarks
    // -------------------------------------------------------------------------
    // 2a. Argon2id (m=64 MiB, t=3, p=4) + HKDF seed-phrase key derivation
    let argon_start = Instant::now();
    let derived_mk = MasterKey::from_recovery_seed_phrase(VALID_BIP39_SEED, "bench-vault-ns");
    let argon_ms = argon_start.elapsed().as_secs_f64() * 1000.0;
    std::hint::black_box(&derived_mk);

    // Allocate a single 16 MiB stripe buffer for symmetric & Reed-Solomon throughput measurements
    let mut stripe_buf = vec![0u8; STRIPE_SIZE_BYTES];
    for (i, b) in stripe_buf.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(73).wrapping_add(19)) & 0xFF) as u8;
    }
    let file_salt = generate_file_salt();

    // 2b. AES-256-GCM 16 MiB stripe encryption & decryption
    let aes_enc_start = Instant::now();
    let aes_ct = encrypt_stripe(&derived_mk, &file_salt, 0, &stripe_buf)?;
    let aes_enc_elapsed = aes_enc_start.elapsed();
    let aes_enc_mib_s = 16.0 / aes_enc_elapsed.as_secs_f64();

    let aes_dec_start = Instant::now();
    let aes_pt = decrypt_stripe(&derived_mk, &file_salt, 0, &aes_ct)?;
    let aes_dec_elapsed = aes_dec_start.elapsed();
    let aes_dec_mib_s = 16.0 / aes_dec_elapsed.as_secs_f64();
    assert_eq!(aes_pt.len(), stripe_buf.len());
    drop(aes_pt);

    // 2c. PqVaultMasterKey (AES-256-GCM + ChaCha20-Poly1305 dual-cipher) 16 MiB stripe
    let pq_mk = PqVaultMasterKey::generate();
    let pq_enc_start = Instant::now();
    let pq_ct = pq_mk.encrypt_stripe_pq(&file_salt, 0, &stripe_buf)?;
    let pq_enc_elapsed = pq_enc_start.elapsed();
    let pq_enc_mib_s = 16.0 / pq_enc_elapsed.as_secs_f64();

    let pq_dec_start = Instant::now();
    let pq_pt = pq_mk.decrypt_stripe_pq(&file_salt, 0, &pq_ct)?;
    let pq_dec_elapsed = pq_dec_start.elapsed();
    let pq_dec_mib_s = 16.0 / pq_dec_elapsed.as_secs_f64();
    assert_eq!(pq_pt.len(), stripe_buf.len());
    drop(pq_pt);
    drop(pq_ct);

    // 2d. X25519 + ML-KEM-768 (X-Wing HKDF-SHA512) encapsulation & decapsulation (average over 50 iterations)
    let kem_kp = HybridKemKeypair::generate()?;
    let kem_pub = kem_kp.public_key();
    let kem_iters = 50u32;
    let mut kem_enc_total_ns = 0u128;
    let mut kem_dec_total_ns = 0u128;
    for _ in 0..kem_iters {
        let t0 = Instant::now();
        let (ss_enc, ct) = HybridKemKeypair::encapsulate(&kem_pub)?;
        kem_enc_total_ns += t0.elapsed().as_nanos();

        let t1 = Instant::now();
        let ss_dec = kem_kp.decapsulate(&ct)?;
        kem_dec_total_ns += t1.elapsed().as_nanos();
        assert_eq!(ss_enc, ss_dec);
    }
    let kem_enc_us = (kem_enc_total_ns as f64 / f64::from(kem_iters)) / 1_000.0;
    let kem_dec_us = (kem_dec_total_ns as f64 / f64::from(kem_iters)) / 1_000.0;

    // 2e. Ed25519 + ML-DSA-65 composite signing & verification (average over 50 iterations)
    let sig_kp = HybridPqSigningKeypair::generate()?;
    let sig_pub = sig_kp.public_key();
    let sample_msg = b"parvault-benchmark-composite-signature-transcript-v1";
    let sig_iters = 50u32;
    let mut sig_sign_total_ns = 0u128;
    let mut sig_verify_total_ns = 0u128;
    for _ in 0..sig_iters {
        let t0 = Instant::now();
        let sig = sig_kp.sign(sample_msg)?;
        sig_sign_total_ns += t0.elapsed().as_nanos();

        let t1 = Instant::now();
        let ok = HybridPqSigningKeypair::verify(&sig_pub, sample_msg, &sig);
        sig_verify_total_ns += t1.elapsed().as_nanos();
        assert!(ok);
    }
    let sig_sign_us = (sig_sign_total_ns as f64 / f64::from(sig_iters)) / 1_000.0;
    let sig_verify_us = (sig_verify_total_ns as f64 / f64::from(sig_iters)) / 1_000.0;

    // -------------------------------------------------------------------------
    // Phase 3: Reed-Solomon GF(2^8) Encoding & 4-Erasure Merkle Quarantine Reconstruction
    // -------------------------------------------------------------------------
    // 3a. Consumer Tier (10-of-20)
    let rs_cons_enc_start = Instant::now();
    let cons_set = encode_ciphertext_stripe(0, &aes_ct, ErasureTier::Consumer)?;
    let rs_cons_enc_mib_s = 16.0 / rs_cons_enc_start.elapsed().as_secs_f64();

    let cons_tree = MerkleTree::from_shards(&cons_set.shards);
    let cons_proofs: Vec<Option<_>> = (0..cons_set.shards.len())
        .map(|i| cons_tree.generate_proof(i))
        .collect();
    let mut cons_slots: Vec<Option<Vec<u8>>> = cons_set.shards.into_iter().map(Some).collect();
    for slot in cons_slots.iter_mut().take(4) {
        *slot = None; // Drop 4 shards
    }
    let rs_cons_rec_start = Instant::now();
    let (cons_reconstructed, cons_poisoned) = reconstruct_zero_trust_with_quarantine(
        cons_slots,
        Some(&cons_proofs),
        cons_set.k_data,
        cons_set.m_parity,
        &cons_set.shard_hashes,
        cons_set.stripe_merkle_root,
    )?;
    let rs_cons_rec_mib_s = 16.0 / rs_cons_rec_start.elapsed().as_secs_f64();
    assert!(cons_poisoned.is_empty());
    assert_eq!(cons_reconstructed.len(), 20);
    drop(cons_reconstructed);

    // 3b. Homelab Tier (16-of-20)
    let rs_home_enc_start = Instant::now();
    let home_set = encode_ciphertext_stripe(0, &aes_ct, ErasureTier::Homelab)?;
    let rs_home_enc_mib_s = 16.0 / rs_home_enc_start.elapsed().as_secs_f64();

    let home_tree = MerkleTree::from_shards(&home_set.shards);
    let home_proofs: Vec<Option<_>> = (0..home_set.shards.len())
        .map(|i| home_tree.generate_proof(i))
        .collect();
    let mut home_slots: Vec<Option<Vec<u8>>> = home_set.shards.into_iter().map(Some).collect();
    for slot in home_slots.iter_mut().take(4) {
        *slot = None; // Drop 4 shards (maximum fault tolerance for 16-of-20)
    }
    let rs_home_rec_start = Instant::now();
    let (home_reconstructed, home_poisoned) = reconstruct_zero_trust_with_quarantine(
        home_slots,
        Some(&home_proofs),
        home_set.k_data,
        home_set.m_parity,
        &home_set.shard_hashes,
        home_set.stripe_merkle_root,
    )?;
    let rs_home_rec_mib_s = 16.0 / rs_home_rec_start.elapsed().as_secs_f64();
    assert!(home_poisoned.is_empty());
    assert_eq!(home_reconstructed.len(), 20);
    drop(home_reconstructed);
    drop(aes_ct);
    drop(stripe_buf);

    // -------------------------------------------------------------------------
    // Output Markdown Tables
    // -------------------------------------------------------------------------
    println!("### 1. Streaming Memory Footprint (`{payload_mib} MiB` File in `16 MiB` Stripes)");
    println!("| Measurement Checkpoint | `VmRSS` (Current Resident) | `VmHWM` / `ru_maxrss` (Peak Resident) | Streaming Throughput |");
    println!("| :--- | :---: | :---: | :---: |");
    println!(
        "| **Process Baseline (Startup)** | `{:.2} MiB` (`{} KiB`) | `{:.2} MiB` (`{} KiB`) | — |",
        mem_baseline.rss_mib(),
        mem_baseline.vm_rss_kib,
        mem_baseline.hwm_mib(),
        mem_baseline.vm_hwm_kib
    );
    println!(
        "| **After `{payload_mib} MiB` 64 KiB-Chunked File Setup** | `{:.2} MiB` (`{} KiB`) | `{:.2} MiB` (`{} KiB`) | — |",
        mem_after_input_gen.rss_mib(),
        mem_after_input_gen.vm_rss_kib,
        mem_after_input_gen.hwm_mib(),
        mem_after_input_gen.vm_hwm_kib
    );
    println!(
        "| **After `store_file_streaming` (`{num_stripes} x 16 MiB`, `16-of-20`)** | `{:.2} MiB` (`{} KiB`) | `{:.2} MiB` (`{} KiB`) | **`{:.1} MiB/s`** |",
        mem_after_store.rss_mib(),
        mem_after_store.vm_rss_kib,
        mem_after_store.hwm_mib(),
        mem_after_store.vm_hwm_kib,
        store_mib_s
    );
    println!(
        "| **After `restore_file_streaming` + SHA-256 Verify** | `{:.2} MiB` (`{} KiB`) | `{:.2} MiB` (`{} KiB`) | **`{:.1} MiB/s`** |",
        mem_after_restore.rss_mib(),
        mem_after_restore.vm_rss_kib,
        mem_after_restore.hwm_mib(),
        mem_after_restore.vm_hwm_kib,
        restore_mib_s
    );
    println!();

    println!("### 2. Cryptographic & Reed-Solomon Primitive Benchmarks (Empirical Wall-Clock)");
    println!(
        "| Subsystem / Operation | Parameters / Construction | Measured Throughput / Latency |"
    );
    println!("| :--- | :--- | :---: |");
    println!(
        "| **`Argon2id` + `HKDF-SHA256` Seed Derivation** | `m = 64 MiB (65,536 KiB), t = 3, p = 4` (BIP-39 12-word) | **`{:.2} ms`** |",
        argon_ms
    );
    println!(
        "| **`AES-256-GCM` Stripe Encryption** | `16 MiB` stripe + HKDF per-purpose subkey/nonce | **`{:.1} MiB/s`** |",
        aes_enc_mib_s
    );
    println!(
        "| **`AES-256-GCM` Stripe Decryption** | `16 MiB` stripe + tag verification | **`{:.1} MiB/s`** |",
        aes_dec_mib_s
    );
    println!(
        "| **`PqVaultMasterKey` Dual-Cipher Encryption** | `16 MiB` (`AES-256-GCM` inner + `ChaCha20-Poly1305` outer) | **`{:.1} MiB/s`** |",
        pq_enc_mib_s
    );
    println!(
        "| **`PqVaultMasterKey` Dual-Cipher Decryption** | `16 MiB` (`ChaCha20-Poly1305` outer + `AES-256-GCM` inner) | **`{:.1} MiB/s`** |",
        pq_dec_mib_s
    );
    println!(
        "| **`HybridKemKeypair::encapsulate` (X-Wing)** | `X25519 + NIST FIPS 203 ML-KEM-768` (`HKDF-SHA512`) | **`{:.1} us`** |",
        kem_enc_us
    );
    println!(
        "| **`HybridKemKeypair::decapsulate` (X-Wing)** | `X25519 + NIST FIPS 203 ML-KEM-768` (`HKDF-SHA512`) | **`{:.1} us`** |",
        kem_dec_us
    );
    println!(
        "| **`HybridPqSigningKeypair::sign`** | `Ed25519 + NIST FIPS 204 ML-DSA-65` | **`{:.1} us`** |",
        sig_sign_us
    );
    println!(
        "| **`HybridPqSigningKeypair::verify`** | `Ed25519 + NIST FIPS 204 ML-DSA-65` | **`{:.1} us`** |",
        sig_verify_us
    );
    println!(
        "| **Reed-Solomon $GF(2^8)$ Encode (`Consumer 10-of-20`)** | `16 MiB` stripe -> `20 x 1.6 MiB` shards + Merkle tree | **`{:.1} MiB/s`** |",
        rs_cons_enc_mib_s
    );
    println!(
        "| **Reed-Solomon $GF(2^8)$ Reconstruct (`Consumer 10-of-20`)** | 4 erasures + pre-decoding Merkle quarantine | **`{:.1} MiB/s`** |",
        rs_cons_rec_mib_s
    );
    println!(
        "| **Reed-Solomon $GF(2^8)$ Encode (`Homelab 16-of-20`)** | `16 MiB` stripe -> `20 x 1.0 MiB` shards + Merkle tree | **`{:.1} MiB/s`** |",
        rs_home_enc_mib_s
    );
    println!(
        "| **Reed-Solomon $GF(2^8)$ Reconstruct (`Homelab 16-of-20`)** | 4 erasures + pre-decoding Merkle quarantine | **`{:.1} MiB/s`** |",
        rs_home_rec_mib_s
    );

    Ok(())
}
