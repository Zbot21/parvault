#![forbid(unsafe_code)]

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

const SOC_STRIPE_SIZE_BYTES: usize = BlockStore::SOC_ROUTER_STRIPE_SIZE_BYTES; // 1 MiB for Router SoC
const DESKTOP_STRIPE_SIZE_BYTES: usize = BlockStore::DEFAULT_STRIPE_SIZE_BYTES; // 16 MiB per ADR-01
const VALID_BIP39_SEED: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[derive(Parser, Debug)]
#[command(
    name = "parvault-bench",
    version,
    about = "Empirical wall-clock and /proc/self/status memory benchmark suite for ParVault"
)]
struct BenchCli {
    /// Total streaming file payload size in MiB (default: 64 MiB).
    #[arg(long, global = true, default_value_t = 64)]
    payload_mib: usize,

    /// Target hardware profile to benchmark: 'router-soc' (1 MiB stripes), 'desktop' (16 MiB stripes), or 'all' (measures both).
    #[arg(long, global = true, default_value = "all")]
    profile: String,

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
    cpu_time_ns: u64,
}

impl ProcMemSnapshot {
    fn capture() -> Self {
        #[cfg(unix)]
        {
            Self {
                vm_rss_kib: parvault::os_sys::read_self_rss_bytes() / 1024,
                vm_hwm_kib: parvault::os_sys::read_self_hwm_bytes() / 1024,
                cpu_time_ns: parvault::os_sys::process_cpu_time_ns(),
            }
        }
        #[cfg(not(unix))]
        {
            Self::default()
        }
    }

    fn rss_mib(self) -> f64 {
        self.vm_rss_kib as f64 / 1024.0
    }

    fn hwm_mib(self) -> f64 {
        self.vm_hwm_kib as f64 / 1024.0
    }
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

#[derive(Debug, Clone)]
struct StreamingRunMetrics {
    profile_name: String,
    stripe_size_bytes: usize,
    num_stripes: usize,
    mem_baseline: ProcMemSnapshot,
    mem_after_input_gen: ProcMemSnapshot,
    mem_after_store: ProcMemSnapshot,
    mem_after_restore: ProcMemSnapshot,
    store_mib_s: f64,
    restore_mib_s: f64,
}

fn run_streaming_profile(
    profile_name: &str,
    stripe_size_bytes: usize,
    payload_mib: usize,
) -> anyhow::Result<StreamingRunMetrics> {
    let mem_baseline = ProcMemSnapshot::capture();
    let bench_dir = unique_bench_temp_dir();
    let safe_label = profile_name.to_lowercase().replace([' ', '/', '-'], "_");
    let input_path = bench_dir.join(format!("payload_{safe_label}.bin"));
    let output_path = bench_dir.join(format!("restored_{safe_label}.bin"));
    let store_dir = bench_dir.join("block_store");

    let payload_bytes = payload_mib * 1024 * 1024;
    let num_stripes = payload_bytes.div_ceil(stripe_size_bytes);

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
    let store = BlockStore::new(&store_dir, quota)?.with_stripe_size_bytes(stripe_size_bytes);
    let master_key = MasterKey::generate();

    let store_start = Instant::now();
    let manifest = store.store_file_streaming(
        "bench-local-owner",
        &input_path,
        &master_key,
        ErasureTier::Homelab,
        stripe_size_bytes,
    )?;
    let store_elapsed = store_start.elapsed();
    let store_mib_s = (payload_mib as f64) / store_elapsed.as_secs_f64();
    let mem_after_store = ProcMemSnapshot::capture();

    let restore_start = Instant::now();
    store.restore_file_streaming(&manifest, &master_key, &output_path)?;
    let restore_elapsed = restore_start.elapsed();
    let restore_mib_s = (payload_mib as f64) / restore_elapsed.as_secs_f64();
    let mem_after_restore = ProcMemSnapshot::capture();

    let restored_sha256 = compute_file_sha256_streaming(&output_path)?;
    assert_eq!(
        input_sha256, restored_sha256,
        "Restored streaming payload SHA-256 must match original input for profile {}",
        profile_name
    );

    let _ = fs::remove_dir_all(&bench_dir);

    Ok(StreamingRunMetrics {
        profile_name: profile_name.to_string(),
        stripe_size_bytes,
        num_stripes,
        mem_baseline,
        mem_after_input_gen,
        mem_after_store,
        mem_after_restore,
        store_mib_s,
        restore_mib_s,
    })
}

fn main() -> anyhow::Result<()> {
    let cli = BenchCli::parse();
    let _cmd = cli.command.unwrap_or(BenchCommand::Run);
    let payload_mib = cli.payload_mib.max(16);
    let profile_req = cli.profile.to_lowercase();

    println!("================================================================================");
    println!(
        " ParVault Empirical Cryptography, Reed-Solomon & Memory Benchmark (`parvault-bench`)"
    );
    println!("================================================================================");
    println!(" Streaming Payload : {} MiB", payload_mib);
    println!(" Selected Profile  : {}", cli.profile);
    println!(
        " Memory Telemetry  : Linux /proc/self/status (VmRSS, VmHWM) + CLOCK_PROCESS_CPUTIME_ID"
    );
    println!("================================================================================");
    println!();

    // -------------------------------------------------------------------------
    // Phase 1: Streaming Multi-Stripe Store & Restore with Process Memory Proof
    // -------------------------------------------------------------------------
    let mut streaming_results = Vec::new();

    let run_soc = profile_req == "router-soc" || profile_req == "all";
    let run_desktop =
        profile_req == "desktop" || profile_req == "homelab-nas" || profile_req == "all";

    // Run Router-SoC profile FIRST when requested, ensuring its peak VmHWM is measured
    // from a fresh process baseline before any large 16 MiB desktop buffers are allocated.
    if run_soc {
        println!(">>> Running Profile: Router-SoC (1 MiB stripes, target < 32 MiB RAM)...");
        let soc_res = run_streaming_profile("Router-SoC", SOC_STRIPE_SIZE_BYTES, payload_mib)?;
        streaming_results.push(soc_res);
    }

    if run_desktop {
        println!(">>> Running Profile: Desktop / Homelab-NAS (16 MiB stripes, high throughput)...");
        let desk_res = run_streaming_profile(
            "Desktop / Homelab-NAS",
            DESKTOP_STRIPE_SIZE_BYTES,
            payload_mib,
        )?;
        streaming_results.push(desk_res);
    }

    // -------------------------------------------------------------------------
    // Phase 2: Cryptographic Primitive & Subkey Benchmarks
    // -------------------------------------------------------------------------
    // 2a. Argon2id (m=64 MiB, t=3, p=4) + HKDF seed-phrase key derivation
    let argon_start = Instant::now();
    let derived_mk = MasterKey::from_recovery_seed_phrase(VALID_BIP39_SEED, "bench-vault-ns");
    let argon_ms = argon_start.elapsed().as_secs_f64() * 1000.0;
    std::hint::black_box(&derived_mk);

    // Single 1 MiB stripe for tiny SoC primitive measurement
    let mut stripe_buf_1m = vec![0u8; SOC_STRIPE_SIZE_BYTES];
    for (i, b) in stripe_buf_1m.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(73).wrapping_add(19)) & 0xFF) as u8;
    }
    let file_salt = generate_file_salt();

    // 2b. AES-256-GCM 1 MiB & 16 MiB stripe encryption & decryption
    let aes_enc_1m_start = Instant::now();
    let aes_ct_1m = encrypt_stripe(&derived_mk, &file_salt, 0, &stripe_buf_1m)?;
    let aes_enc_1m_elapsed = aes_enc_1m_start.elapsed();
    let aes_enc_1m_mib_s = 1.0 / aes_enc_1m_elapsed.as_secs_f64();

    let aes_dec_1m_start = Instant::now();
    let aes_pt_1m = decrypt_stripe(&derived_mk, &file_salt, 0, &aes_ct_1m)?;
    let aes_dec_1m_elapsed = aes_dec_1m_start.elapsed();
    let aes_dec_1m_mib_s = 1.0 / aes_dec_1m_elapsed.as_secs_f64();
    assert_eq!(aes_pt_1m.len(), stripe_buf_1m.len());
    drop(aes_pt_1m);

    // 16 MiB stripe buffer for desktop symmetric & Reed-Solomon throughput measurements
    let mut stripe_buf_16m = vec![0u8; DESKTOP_STRIPE_SIZE_BYTES];
    for (i, b) in stripe_buf_16m.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(73).wrapping_add(19)) & 0xFF) as u8;
    }

    let aes_enc_16m_start = Instant::now();
    let aes_ct_16m = encrypt_stripe(&derived_mk, &file_salt, 0, &stripe_buf_16m)?;
    let aes_enc_16m_elapsed = aes_enc_16m_start.elapsed();
    let aes_enc_16m_mib_s = 16.0 / aes_enc_16m_elapsed.as_secs_f64();

    let aes_dec_16m_start = Instant::now();
    let aes_pt_16m = decrypt_stripe(&derived_mk, &file_salt, 0, &aes_ct_16m)?;
    let aes_dec_16m_elapsed = aes_dec_16m_start.elapsed();
    let aes_dec_16m_mib_s = 16.0 / aes_dec_16m_elapsed.as_secs_f64();
    assert_eq!(aes_pt_16m.len(), stripe_buf_16m.len());
    drop(aes_pt_16m);

    // 2c. PqVaultMasterKey (AES-256-GCM + ChaCha20-Poly1305 dual-cipher) 16 MiB stripe
    let pq_mk = PqVaultMasterKey::generate();
    let pq_enc_start = Instant::now();
    let pq_ct = pq_mk.encrypt_stripe_pq(&file_salt, 0, &stripe_buf_16m)?;
    let pq_enc_elapsed = pq_enc_start.elapsed();
    let pq_enc_mib_s = 16.0 / pq_enc_elapsed.as_secs_f64();

    let pq_dec_start = Instant::now();
    let pq_pt = pq_mk.decrypt_stripe_pq(&file_salt, 0, &pq_ct)?;
    let pq_dec_elapsed = pq_dec_start.elapsed();
    let pq_dec_mib_s = 16.0 / pq_dec_elapsed.as_secs_f64();
    assert_eq!(pq_pt.len(), stripe_buf_16m.len());
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
    // 3a. Router-SoC 1 MiB Stripe Reed-Solomon (Homelab 16-of-20)
    let rs_soc_enc_start = Instant::now();
    let soc_set = encode_ciphertext_stripe(0, &aes_ct_1m, ErasureTier::Homelab)?;
    let rs_soc_enc_mib_s = 1.0 / rs_soc_enc_start.elapsed().as_secs_f64();

    let soc_tree = MerkleTree::from_shards(&soc_set.shards);
    let soc_proofs: Vec<Option<_>> = (0..soc_set.shards.len())
        .map(|i| soc_tree.generate_proof(i))
        .collect();
    let mut soc_slots: Vec<Option<Vec<u8>>> = soc_set.shards.into_iter().map(Some).collect();
    for slot in soc_slots.iter_mut().take(4) {
        *slot = None; // Drop 4 shards
    }
    let rs_soc_rec_start = Instant::now();
    let (soc_reconstructed, soc_poisoned) = reconstruct_zero_trust_with_quarantine(
        soc_slots,
        Some(&soc_proofs),
        soc_set.k_data,
        soc_set.m_parity,
        &soc_set.shard_hashes,
        soc_set.stripe_merkle_root,
    )?;
    let rs_soc_rec_mib_s = 1.0 / rs_soc_rec_start.elapsed().as_secs_f64();
    assert!(soc_poisoned.is_empty());
    assert_eq!(soc_reconstructed.len(), 20);
    drop(soc_reconstructed);

    // 3b. Consumer Tier (10-of-20) on 16 MiB Stripe
    let rs_cons_enc_start = Instant::now();
    let cons_set = encode_ciphertext_stripe(0, &aes_ct_16m, ErasureTier::Consumer)?;
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

    // 3c. Homelab Tier (16-of-20) on 16 MiB Stripe
    let rs_home_enc_start = Instant::now();
    let home_set = encode_ciphertext_stripe(0, &aes_ct_16m, ErasureTier::Homelab)?;
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
    drop(aes_ct_1m);
    drop(aes_ct_16m);
    drop(stripe_buf_1m);
    drop(stripe_buf_16m);

    // -------------------------------------------------------------------------
    // Output Markdown Tables
    // -------------------------------------------------------------------------
    println!(
        "### 1. Empirical Streaming Memory Footprint & Throughput (`{payload_mib} MiB` Payload)"
    );
    println!();
    println!("#### Comparative Overview");
    println!("| Profile | Stripe Size | Stripes | Baseline RSS | Peak VmHWM | SoC < 32 MiB Gate | Store Speed | Restore Speed |");
    println!("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |");
    for res in &streaming_results {
        let stripe_label = if res.stripe_size_bytes >= 1024 * 1024 {
            format!("{} MiB", res.stripe_size_bytes / (1024 * 1024))
        } else {
            format!("{} KiB", res.stripe_size_bytes / 1024)
        };
        let gate_status = if res.stripe_size_bytes == SOC_STRIPE_SIZE_BYTES {
            if res.mem_after_store.hwm_mib() <= 32.0 {
                "**PASS (< 32 MiB)**"
            } else {
                "FAIL (> 32 MiB)"
            }
        } else {
            "Desktop Target"
        };
        println!(
            "| **{}** | `{}` | `{}` | `{:.2} MiB` | **`{:.2} MiB`** (`{} KiB`) | {} | **`{:.1} MiB/s`** | **`{:.1} MiB/s`** |",
            res.profile_name,
            stripe_label,
            res.num_stripes,
            res.mem_baseline.rss_mib(),
            res.mem_after_store.hwm_mib(),
            res.mem_after_store.vm_hwm_kib,
            gate_status,
            res.store_mib_s,
            res.restore_mib_s
        );
    }
    println!();

    for res in &streaming_results {
        let stripe_label = if res.stripe_size_bytes >= 1024 * 1024 {
            format!("{} MiB", res.stripe_size_bytes / (1024 * 1024))
        } else {
            format!("{} KiB", res.stripe_size_bytes / 1024)
        };
        println!(
            "#### Checkpoint Breakdown: {} (`{}` Stripes)",
            res.profile_name, stripe_label
        );
        println!("| Measurement Checkpoint | `VmRSS` (Resident) | `VmHWM` (Peak) | CPU Time (`ms`) | Throughput |");
        println!("| :--- | :---: | :---: | :---: | :---: |");
        println!(
            "| **Process Baseline (Startup)** | `{:.2} MiB` (`{} KiB`) | `{:.2} MiB` (`{} KiB`) | `{:.2} ms` | — |",
            res.mem_baseline.rss_mib(),
            res.mem_baseline.vm_rss_kib,
            res.mem_baseline.hwm_mib(),
            res.mem_baseline.vm_hwm_kib,
            res.mem_baseline.cpu_time_ns as f64 / 1_000_000.0
        );
        println!(
            "| **After `{payload_mib} MiB` Chunked Setup** | `{:.2} MiB` (`{} KiB`) | `{:.2} MiB` (`{} KiB`) | `{:.2} ms` | — |",
            res.mem_after_input_gen.rss_mib(),
            res.mem_after_input_gen.vm_rss_kib,
            res.mem_after_input_gen.hwm_mib(),
            res.mem_after_input_gen.vm_hwm_kib,
            res.mem_after_input_gen.cpu_time_ns as f64 / 1_000_000.0
        );
        println!(
            "| **After `store_file_streaming` (`{} x {}`, `16-of-20`)** | `{:.2} MiB` (`{} KiB`) | **`{:.2} MiB`** (`{} KiB`) | `{:.2} ms` | **`{:.1} MiB/s`** |",
            res.num_stripes,
            stripe_label,
            res.mem_after_store.rss_mib(),
            res.mem_after_store.vm_rss_kib,
            res.mem_after_store.hwm_mib(),
            res.mem_after_store.vm_hwm_kib,
            res.mem_after_store.cpu_time_ns as f64 / 1_000_000.0,
            res.store_mib_s
        );
        println!(
            "| **After `restore_file_streaming` + SHA-256 Verify** | `{:.2} MiB` (`{} KiB`) | `{:.2} MiB` (`{} KiB`) | `{:.2} ms` | **`{:.1} MiB/s`** |",
            res.mem_after_restore.rss_mib(),
            res.mem_after_restore.vm_rss_kib,
            res.mem_after_restore.hwm_mib(),
            res.mem_after_restore.vm_hwm_kib,
            res.mem_after_restore.cpu_time_ns as f64 / 1_000_000.0,
            res.restore_mib_s
        );
        println!();
    }

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
        "| **`AES-256-GCM` Stripe Encryption (Router-SoC)** | `1 MiB` stripe + HKDF per-purpose subkey/nonce | **`{:.1} MiB/s`** |",
        aes_enc_1m_mib_s
    );
    println!(
        "| **`AES-256-GCM` Stripe Decryption (Router-SoC)** | `1 MiB` stripe + tag verification | **`{:.1} MiB/s`** |",
        aes_dec_1m_mib_s
    );
    println!(
        "| **`AES-256-GCM` Stripe Encryption (Desktop)** | `16 MiB` stripe + HKDF per-purpose subkey/nonce | **`{:.1} MiB/s`** |",
        aes_enc_16m_mib_s
    );
    println!(
        "| **`AES-256-GCM` Stripe Decryption (Desktop)** | `16 MiB` stripe + tag verification | **`{:.1} MiB/s`** |",
        aes_dec_16m_mib_s
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
        "| **Reed-Solomon $GF(2^8)$ Encode (`Router-SoC 16-of-20`)** | `1 MiB` stripe -> `20 x 64 KiB` shards + Merkle tree | **`{:.1} MiB/s`** |",
        rs_soc_enc_mib_s
    );
    println!(
        "| **Reed-Solomon $GF(2^8)$ Reconstruct (`Router-SoC 16-of-20`)** | 4 erasures + pre-decoding Merkle quarantine | **`{:.1} MiB/s`** |",
        rs_soc_rec_mib_s
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
