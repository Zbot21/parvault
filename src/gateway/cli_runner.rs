//! Shared CLI Subcommands & Execution Runner for `parvault token` and `parvault gateway`
//! (`ADR-32` / `docs/GATEWAY_SOCKET_PROTOCOL.md`).

use crate::capabilities::{
    AccessRequestContext, CapabilityMacaroon, Caveat, COMPACT_MACAROON_PREFIX,
};
use crate::config::{ErasureTier, HardwareProfile, NodeConfig};
use crate::crypto::{write_secret_file_atomic_0600, LocalFileKeystore, MasterKey};
use crate::gateway::{GatewayConfig, DEFAULT_IPC_SOCKET_PATH, GATEWAY_STRIPE_BYTES};
use clap::{Args, Subcommand};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Canonical filename inside `<data_dir>` storing a `0600` hex-encoded 32-byte Macaroon root key.
pub const DEFAULT_MACAROON_ROOT_KEY_FILE: &str = "macaroon_root.key";

/// CLI subcommands under `parvault token { mint, attenuate, inspect }`.
#[derive(Debug, Clone, Subcommand)]
pub enum TokenAction {
    /// Mint a new root or pre-attenuated `PARVAULT-MAC-V1:` capability macaroon.
    Mint {
        /// Optional 64-character hex 32-byte root key (if omitted, loads or atomically creates `<data_dir>/macaroon_root.key` with `0600` permissions).
        #[arg(long, value_name = "64-HEX")]
        macaroon_key_hex: Option<String>,

        /// Logical key identifier or 64-hex issuer fingerprint bound into the root HMAC tag.
        #[arg(long, default_value = "default")]
        key_id: String,

        /// Restrict capability to a single 32-byte `file_merkle_root` (64-character hex).
        #[arg(long, value_name = "64-HEX")]
        manifest_hex: Option<String>,

        /// Restrict capability to a byte window `<OFFSET>:<LEN>` (e.g. `1048576:65536`).
        #[arg(long, value_name = "OFFSET:LEN")]
        byte_range: Option<String>,

        /// Restrict capability lifetime to `<TTL_SECS>` seconds from current Unix time.
        #[arg(long, value_name = "SECS")]
        ttl_secs: Option<u64>,

        /// Attach `Caveat::ReadOnly` prohibiting write/mutation operations.
        #[arg(long, default_value_t = false)]
        read_only: bool,

        /// Bind capability to a specific POSIX client UID verified via kernel `SO_PEERCRED`.
        #[arg(long, value_name = "UID")]
        allow_peer_uid: Option<u32>,

        /// Emit structured JSON output instead of the raw `PARVAULT-MAC-V1:...` string.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Offline caveat attenuation: narrow an existing `PARVAULT-MAC-V1:` token with zero root key access.
    Attenuate {
        /// Existing `PARVAULT-MAC-V1:...` token to attenuate offline.
        #[arg(long, value_name = "PARVAULT-MAC-V1:...")]
        token: String,

        /// Restrict capability to a single 32-byte `file_merkle_root` (64-character hex).
        #[arg(long, value_name = "64-HEX")]
        manifest_hex: Option<String>,

        /// Restrict capability to a byte window `<OFFSET>:<LEN>` (must be within any outer byte range).
        #[arg(long, value_name = "OFFSET:LEN")]
        byte_range: Option<String>,

        /// Restrict capability lifetime to `<TTL_SECS>` seconds from current Unix time.
        #[arg(long, value_name = "SECS")]
        ttl_secs: Option<u64>,

        /// Attach `Caveat::ReadOnly` prohibiting write/mutation operations.
        #[arg(long, default_value_t = false)]
        read_only: bool,

        /// Bind capability to a specific POSIX client UID verified via kernel `SO_PEERCRED`.
        #[arg(long, value_name = "UID")]
        allow_peer_uid: Option<u32>,

        /// Emit structured JSON output instead of the raw `PARVAULT-MAC-V1:...` string.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Parse and inspect a `PARVAULT-MAC-V1:` token, optionally running `< 1 ms` in-RAM verification.
    Inspect {
        /// `PARVAULT-MAC-V1:...` token to decode and inspect.
        #[arg(long, value_name = "PARVAULT-MAC-V1:...")]
        token: String,

        /// Optional 64-character hex 32-byte root key to cryptographically verify the HMAC chain & caveats.
        #[arg(long, value_name = "64-HEX")]
        verify_key_hex: Option<String>,

        /// Simulated request 32-byte `file_merkle_root` (64-character hex) for verification.
        #[arg(long, value_name = "64-HEX")]
        manifest_hex: Option<String>,

        /// Simulated request byte offset for verification (default: `0`).
        #[arg(long, default_value_t = 0)]
        offset: u64,

        /// Simulated request byte length for verification (default: `0`).
        #[arg(long, default_value_t = 0)]
        len: u64,

        /// Simulate a write/mutating request during verification (`Caveat::ReadOnly` will reject).
        #[arg(long, default_value_t = false)]
        write: bool,

        /// Simulated peer POSIX UID for verification (defaults to current `geteuid()` on Unix).
        #[arg(long, value_name = "UID")]
        peer_uid: Option<u32>,

        /// Emit structured JSON output.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

/// Shared options for `parvault gateway { serve, health, ipc-roundtrip, self-test }`.
/// Global `--data-dir`, `--profile`, and `--peers` flags are inherited from top-level [`crate::config::Cli`].
#[derive(Debug, Clone, Args)]
pub struct GatewayCommonOpts {
    /// Unix Domain Socket path to bind (`serve`) or query (`health` / `ipc-roundtrip`).
    #[arg(long, default_value = DEFAULT_IPC_SOCKET_PATH)]
    pub socket: PathBuf,

    /// Run `GatewayEngine` purely in-process (`GatewayBus::InProcess`) without binding a filesystem socket.
    #[arg(long, default_value_t = false)]
    pub no_socket: bool,

    /// Default Reed-Solomon erasure tier (`consumer`, `homelab`, `mixed`, `relay`).
    #[arg(long, value_enum)]
    pub tier: Option<ErasureTier>,

    /// Optional explicit streaming stripe size in bytes.
    #[arg(long)]
    pub stripe_bytes: Option<usize>,

    /// Optional 64-character hex 32-byte `K_macaroon_root` key enforcing `< 1 ms` in-RAM capability verification.
    #[arg(long, value_name = "64-HEX")]
    pub macaroon_root_key_hex: Option<String>,

    /// Reject any Unix socket client whose kernel `SO_PEERCRED` UID is not in `--allow-peer-uid`.
    #[arg(long, default_value_t = false)]
    pub strict_plugins: bool,

    /// Comma-delimited list of POSIX UIDs authorized to connect when `--strict-plugins` is active.
    #[arg(long, value_delimiter = ',', value_name = "UID")]
    pub allow_peer_uid: Vec<u32>,

    /// Require immutable Linux `memfd` seals (`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW`) on all `StorePayload` calls.
    #[arg(long, default_value_t = false)]
    pub require_sealed_memfd: bool,
}

/// Subcommands under `parvault gateway`.
#[derive(Debug, Clone, Subcommand)]
pub enum GatewayAction {
    /// Start the standalone outbound 40-lane zero-copy IPC gateway listener (default action).
    Serve,
    /// Query live health status (`IpcCommand::QueryHealthStatus`) from `--socket` and emit JSON.
    #[command(visible_alias = "status")]
    Health,
    /// Execute an end-to-end sealed `memfd` + `SCM_RIGHTS` sharding upload, 64 KiB TTFB probe, and
    /// full SHA-256 restore benchmark against `--socket`, outputting JSON metrics.
    IpcRoundtrip {
        /// Total streaming payload size in MiB.
        #[arg(long, default_value_t = 100)]
        size_mib: usize,
        /// Network interface name in `/proc/net/dev` to sample TX/RX byte deltas.
        #[arg(long, default_value = "eth0")]
        net_iface: String,
    },
    /// Run a self-contained in-process sealed `memfd` + `SCM_RIGHTS` zero-copy round-trip smoke test.
    SelfTest,
}

/// Validates `--no-socket`, `--ipc-socket`, and `--strict-plugins` / `--allow-peer-uid` combinations
/// on daemon/gateway startup so misconfigurations fail fast rather than silently blocking or exposing sockets.
pub fn validate_plugin_security_flags(
    has_explicit_ipc_socket: bool,
    no_socket: bool,
    strict_plugins: bool,
    allow_peer_uids: &[u32],
) -> anyhow::Result<Option<Vec<u32>>> {
    if no_socket && has_explicit_ipc_socket {
        anyhow::bail!("--no-socket cannot be combined with --ipc-socket");
    }
    if strict_plugins && allow_peer_uids.is_empty() {
        anyhow::bail!(
            "--strict-plugins requires at least one --allow-peer-uid <UID> (or pass --no-socket without --strict-plugins to disable socket plugins entirely)"
        );
    }
    if strict_plugins || !allow_peer_uids.is_empty() {
        let mut dedup = Vec::with_capacity(allow_peer_uids.len());
        for &uid in allow_peer_uids {
            if !dedup.contains(&uid) {
                dedup.push(uid);
            }
        }
        Ok(Some(dedup))
    } else {
        Ok(None)
    }
}

/// Parses an explicit 64-char hex Macaroon root key, or loads `<data_dir>/macaroon_root.key` if it exists.
pub fn resolve_optional_macaroon_root_key(
    data_dir: &Path,
    explicit_hex: Option<&str>,
) -> anyhow::Result<Option<[u8; 32]>> {
    if let Some(raw) = explicit_hex.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(Some(parse_hex_32(raw, "--macaroon-root-key-hex")?));
    }
    let key_path = data_dir.join(DEFAULT_MACAROON_ROOT_KEY_FILE);
    if key_path.is_file() {
        return Ok(Some(load_macaroon_key_file(&key_path)?));
    }
    Ok(None)
}

/// Loads an existing `<data_dir>/macaroon_root.key` or atomically generates a fresh `0600` 32-byte root key.
pub fn load_or_create_macaroon_root_key(
    data_dir: &Path,
    explicit_hex: Option<&str>,
) -> anyhow::Result<[u8; 32]> {
    if let Some(raw) = explicit_hex.map(str::trim).filter(|s| !s.is_empty()) {
        let key = parse_hex_32(raw, "--macaroon-key-hex")?;
        anyhow::ensure!(
            key != [0u8; 32],
            "all-zero macaroon root key is cryptographically invalid"
        );
        return Ok(key);
    }
    let key_path = data_dir.join(DEFAULT_MACAROON_ROOT_KEY_FILE);
    if key_path.is_file() {
        return load_macaroon_key_file(&key_path);
    }
    let mut fresh = [0u8; 32];
    loop {
        OsRng.fill_bytes(&mut fresh);
        if fresh != [0u8; 32] {
            break;
        }
    }
    let hex_encoded = hex::encode(fresh);
    write_secret_file_atomic_0600(&key_path, hex_encoded.as_bytes())?;
    Ok(fresh)
}

fn load_macaroon_key_file(path: &Path) -> anyhow::Result<[u8; 32]> {
    let raw = std::fs::read(path)?;
    let key = if raw.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        arr
    } else {
        let text = std::str::from_utf8(&raw)
            .map_err(|_| anyhow::anyhow!("invalid UTF-8 in {}", path.display()))?;
        parse_hex_32(text.trim(), &path.display().to_string())?
    };
    anyhow::ensure!(
        key != [0u8; 32],
        "all-zero macaroon root key in {} is rejected",
        path.display()
    );
    Ok(key)
}

fn parse_hex_32(raw: &str, flag_name: &str) -> anyhow::Result<[u8; 32]> {
    let decoded =
        hex::decode(raw.trim()).map_err(|e| anyhow::anyhow!("invalid {flag_name} hex: {e}"))?;
    anyhow::ensure!(
        decoded.len() == 32,
        "{flag_name} must decode to exactly 32 bytes (got {})",
        decoded.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn derive_key_id_bytes(key_id: &str) -> [u8; 32] {
    let trimmed = key_id.trim();
    if trimmed.len() == 64 {
        if let Ok(decoded) = hex::decode(trimmed) {
            if decoded.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decoded);
                return arr;
            }
        }
    }
    let mut h = Sha256::new();
    h.update(b"parvault-macaroon-key-id-v1:");
    h.update(trimmed.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn parse_byte_range_spec(spec: &str) -> anyhow::Result<(u64, u64)> {
    let (off_str, len_str) = spec.trim().split_once(':').ok_or_else(|| {
        anyhow::anyhow!("invalid --byte-range '{spec}' (expected '<OFFSET>:<LEN>')")
    })?;
    let offset = off_str
        .trim()
        .parse::<u64>()
        .map_err(|e| anyhow::anyhow!("invalid --byte-range offset '{off_str}': {e}"))?;
    let length = len_str
        .trim()
        .parse::<u64>()
        .map_err(|e| anyhow::anyhow!("invalid --byte-range length '{len_str}': {e}"))?;
    Ok((offset, length))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn collect_cli_caveats(
    manifest_hex: Option<&str>,
    byte_range: Option<&str>,
    ttl_secs: Option<u64>,
    read_only: bool,
    allow_peer_uid: Option<u32>,
) -> anyhow::Result<Vec<Caveat>> {
    let mut out = Vec::new();
    if let Some(m_hex) = manifest_hex.map(str::trim).filter(|s| !s.is_empty()) {
        out.push(Caveat::AllowedManifest(parse_hex_32(
            m_hex,
            "--manifest-hex",
        )?));
    }
    if let Some(range_str) = byte_range.map(str::trim).filter(|s| !s.is_empty()) {
        let (offset, length) = parse_byte_range_spec(range_str)?;
        out.push(Caveat::ByteRange { offset, length });
    }
    if let Some(ttl) = ttl_secs {
        let exp_ms = now_unix_ms().saturating_add(ttl.saturating_mul(1000));
        out.push(Caveat::ExpiresAtUnixMs(exp_ms));
    }
    if read_only {
        out.push(Caveat::ReadOnly);
    }
    if let Some(uid) = allow_peer_uid {
        out.push(Caveat::AllowedPeerUid(uid));
    }
    Ok(out)
}

fn describe_caveat_json(c: &Caveat) -> serde_json::Value {
    match c {
        Caveat::AllowedManifest(root) => serde_json::json!({
            "type": "AllowedManifest",
            "manifest_hex": hex::encode(root),
        }),
        Caveat::ByteRange { offset, length } => serde_json::json!({
            "type": "ByteRange",
            "offset": offset,
            "length": length,
        }),
        Caveat::ExpiresAtUnixMs(ms) => serde_json::json!({
            "type": "ExpiresAtUnixMs",
            "expires_at_unix_ms": ms,
        }),
        Caveat::ReadOnly => serde_json::json!({
            "type": "ReadOnly",
        }),
        Caveat::AllowedPeerUid(uid) => serde_json::json!({
            "type": "AllowedPeerUid",
            "uid": uid,
        }),
    }
}

fn describe_caveat_text(c: &Caveat) -> String {
    match c {
        Caveat::AllowedManifest(root) => format!("AllowedManifest({})", hex::encode(root)),
        Caveat::ByteRange { offset, length } => {
            format!("ByteRange(offset={offset}, length={length})")
        }
        Caveat::ExpiresAtUnixMs(ms) => format!("ExpiresAtUnixMs({ms})"),
        Caveat::ReadOnly => "ReadOnly".to_string(),
        Caveat::AllowedPeerUid(uid) => format!("AllowedPeerUid({uid})"),
    }
}

/// Executes `parvault token { mint, attenuate, inspect }`.
pub fn execute_token_cli(action: TokenAction, data_dir: &Path) -> anyhow::Result<()> {
    match action {
        TokenAction::Mint {
            macaroon_key_hex,
            key_id,
            manifest_hex,
            byte_range,
            ttl_secs,
            read_only,
            allow_peer_uid,
            json,
        } => {
            let root_key = load_or_create_macaroon_root_key(data_dir, macaroon_key_hex.as_deref())?;
            let mut nonce_id = [0u8; 32];
            OsRng.fill_bytes(&mut nonce_id);
            let issuer_fp = derive_key_id_bytes(&key_id);
            let caveats = collect_cli_caveats(
                manifest_hex.as_deref(),
                byte_range.as_deref(),
                ttl_secs,
                read_only,
                allow_peer_uid,
            )?;
            let mac = CapabilityMacaroon::mint(&root_key, nonce_id, issuer_fp, caveats)?;
            let compact = mac.to_compact_token();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "prefix": COMPACT_MACAROON_PREFIX,
                        "token": compact,
                        "key_id": hex::encode(mac.issuer_fingerprint),
                        "nonce_id": hex::encode(mac.nonce_id),
                        "caveat_count": mac.caveats.len(),
                        "caveats": mac.caveats.iter().map(describe_caveat_json).collect::<Vec<_>>(),
                    })
                );
            } else {
                println!("{compact}");
            }
            Ok(())
        }

        TokenAction::Attenuate {
            token,
            manifest_hex,
            byte_range,
            ttl_secs,
            read_only,
            allow_peer_uid,
            json,
        } => {
            // 100% offline HMAC-SHA256 caveat chaining — requires zero root key access.
            let mut mac = CapabilityMacaroon::from_compact_token(&token)?;
            let extra = collect_cli_caveats(
                manifest_hex.as_deref(),
                byte_range.as_deref(),
                ttl_secs,
                read_only,
                allow_peer_uid,
            )?;
            anyhow::ensure!(
                !extra.is_empty(),
                "attenuate requires at least one caveat flag (--manifest-hex, --byte-range, --ttl-secs, --read-only, or --allow-peer-uid)"
            );
            for cav in extra {
                mac = mac.attenuate(cav)?;
            }
            let compact = mac.to_compact_token();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "token": compact,
                        "key_id": hex::encode(mac.issuer_fingerprint),
                        "nonce_id": hex::encode(mac.nonce_id),
                        "caveat_count": mac.caveats.len(),
                        "caveats": mac.caveats.iter().map(describe_caveat_json).collect::<Vec<_>>(),
                    })
                );
            } else {
                println!("{compact}");
            }
            Ok(())
        }

        TokenAction::Inspect {
            token,
            verify_key_hex,
            manifest_hex,
            offset,
            len,
            write,
            peer_uid,
            json,
        } => {
            let mac = CapabilityMacaroon::from_compact_token(&token)?;
            let manifest_root = match manifest_hex
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(h) => parse_hex_32(h, "--manifest-hex")?,
                None => [0u8; 32],
            };
            let effective_peer_uid = peer_uid.or_else(|| {
                #[cfg(unix)]
                {
                    Some(crate::os_sys::geteuid())
                }
                #[cfg(not(unix))]
                {
                    None
                }
            });

            let verification: Option<(bool, Option<String>)> = if let Some(vk_hex) = verify_key_hex
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let root_key = parse_hex_32(vk_hex, "--verify-key-hex")?;
                let ctx = AccessRequestContext {
                    manifest_root,
                    offset,
                    length: len,
                    is_write: write,
                    now_unix_ms: now_unix_ms(),
                    peer_uid: effective_peer_uid,
                };
                match mac.verify_in_ram(&root_key, &ctx) {
                    Ok(()) => Some((true, None)),
                    Err(e) => Some((false, Some(e.to_string()))),
                }
            } else {
                None
            };

            if json {
                let mut obj = serde_json::json!({
                    "key_id": hex::encode(mac.issuer_fingerprint),
                    "nonce_id": hex::encode(mac.nonce_id),
                    "tag": hex::encode(mac.tag),
                    "caveat_count": mac.caveats.len(),
                    "caveats": mac.caveats.iter().map(describe_caveat_json).collect::<Vec<_>>(),
                });
                if let Some((ok, reason)) = verification {
                    obj["verified"] = serde_json::Value::Bool(ok);
                    if let Some(err_msg) = reason {
                        obj["verify_error"] = serde_json::Value::String(err_msg);
                    }
                }
                println!("{obj}");
            } else {
                println!("key_id      : {}", hex::encode(mac.issuer_fingerprint));
                println!("nonce_id    : {}", hex::encode(mac.nonce_id));
                println!("tag         : {}", hex::encode(mac.tag));
                println!("caveats ({}) :", mac.caveats.len());
                for (idx, c) in mac.caveats.iter().enumerate() {
                    println!("  [{idx}] {}", describe_caveat_text(c));
                }
                if let Some((ok, reason)) = verification {
                    println!("verified: {ok}");
                    if let Some(err_msg) = reason {
                        println!("verify_error: {err_msg}");
                    }
                }
            }
            Ok(())
        }
    }
}

fn load_or_init_gateway_master_key(
    data_dir: &Path,
    passphrase: Option<&str>,
) -> anyhow::Result<MasterKey> {
    std::fs::create_dir_all(data_dir)?;
    let sealer = LocalFileKeystore::from_passphrase_or_csprng_in_dir(data_dir, passphrase)?;
    let sealed_path = data_dir.join("master_key.sealed");
    sealer.load_or_create_master_key(&sealed_path)
}

#[cfg(unix)]
async fn run_ipc_roundtrip_probe(
    socket_path: &Path,
    size_mib: usize,
    net_iface: &str,
) -> anyhow::Result<()> {
    use crate::gateway::{
        create_memfd_sized, pread_full_or_eof, pwrite_all, read_self_rss_bytes, GatewayIpcClient,
        RetentionPolicy,
    };
    use crate::os_sys::read_net_dev_bytes;
    use std::os::fd::AsRawFd;
    use std::time::Instant;

    let total_bytes = (size_mib as u64) * 1024 * 1024;
    let client = GatewayIpcClient::new(socket_path);
    let (rx_before, tx_before) = read_net_dev_bytes(net_iface).unwrap_or((0, 0));

    let in_mfd = create_memfd_sized("parvault-gate-in", total_bytes)?;
    let in_file = std::fs::File::from(in_mfd);
    let mut chunk = vec![0u8; GATEWAY_STRIPE_BYTES];
    let mut in_hasher = Sha256::new();
    let mut rng_state = 0xCAFE_BABE_1337_4242u64;
    let mut written = 0u64;
    while written < total_bytes {
        let len = ((total_bytes - written) as usize).min(GATEWAY_STRIPE_BYTES);
        for word in chunk[..len].as_chunks_mut::<8>().0 {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            word.copy_from_slice(&rng_state.to_le_bytes());
        }
        in_hasher.update(&chunk[..len]);
        pwrite_all(&in_file, written, &chunk[..len])?;
        written += len as u64;
    }
    let sha256_in = hex::encode(in_hasher.finalize());

    let t_store = Instant::now();
    let manifest = client
        .store_sealed_payload_fd(
            in_file.as_raw_fd(),
            total_bytes,
            RetentionPolicy::Persistent,
        )
        .await?;
    let upload_ms = t_store.elapsed().as_secs_f64() * 1000.0;
    drop(in_file);

    let ttfb_len = 65_536u64.min(total_bytes);
    let ttfb_mfd = create_memfd_sized("parvault-ttfb", ttfb_len)?;
    let ttfb_file = std::fs::File::from(ttfb_mfd);
    let t_ttfb = Instant::now();
    let ttfb_bytes = client
        .fetch_range_to_fd(manifest.clone(), 0, ttfb_len, ttfb_file.as_raw_fd(), None)
        .await?;
    let ttfb_ms = t_ttfb.elapsed().as_secs_f64() * 1000.0;
    anyhow::ensure!(ttfb_bytes == ttfb_len, "TTFB slice incomplete");
    drop(ttfb_file);

    let out_mfd = create_memfd_sized("parvault-gate-out", total_bytes)?;
    let out_file = std::fs::File::from(out_mfd);
    let t_restore = Instant::now();
    let restored_bytes = client
        .fetch_payload_to_fd(manifest.shard_hashes.clone(), out_file.as_raw_fd())
        .await?;
    let restore_ms = t_restore.elapsed().as_secs_f64() * 1000.0;
    anyhow::ensure!(
        restored_bytes == total_bytes,
        "restored {restored_bytes} != expected {total_bytes}"
    );

    let mut out_hasher = Sha256::new();
    let mut rd_off = 0u64;
    while rd_off < total_bytes {
        let len = ((total_bytes - rd_off) as usize).min(GATEWAY_STRIPE_BYTES);
        let n = pread_full_or_eof(&out_file, rd_off, &mut chunk[..len])?;
        anyhow::ensure!(n == len, "short pread from restored memfd");
        out_hasher.update(&chunk[..n]);
        rd_off += n as u64;
    }
    let sha256_out = hex::encode(out_hasher.finalize());
    anyhow::ensure!(
        sha256_in == sha256_out,
        "SHA-256 mismatch: in={sha256_in} out={sha256_out}"
    );

    let (rx_after, tx_after) = read_net_dev_bytes(net_iface).unwrap_or((0, 0));
    let tx_delta = tx_after.saturating_sub(tx_before);
    let rx_delta = rx_after.saturating_sub(rx_before);
    let vm_rss_bytes = read_self_rss_bytes();

    println!(
        "{}",
        serde_json::json!({
            "size_bytes": total_bytes,
            "sha256_in": sha256_in,
            "sha256_out": sha256_out,
            "bit_for_bit_verified": true,
            "ttfb_ms": ttfb_ms,
            "upload_ms": upload_ms,
            "restore_ms": restore_ms,
            "iface": net_iface,
            "tx_bytes_delta": tx_delta,
            "rx_bytes_delta": rx_delta,
            "client_vm_rss_bytes": vm_rss_bytes,
            "shard_count": manifest.shard_hashes.len()
        })
    );
    Ok(())
}

/// Executes `parvault gateway { serve, health, ipc-roundtrip, self-test }`.
pub async fn execute_gateway_cli(
    opts: GatewayCommonOpts,
    action: Option<GatewayAction>,
    node_cfg: &NodeConfig,
    cli_profile: Option<HardwareProfile>,
    cli_peers: &[String],
) -> anyhow::Result<()> {
    let action = action.unwrap_or(GatewayAction::Serve);

    #[cfg(not(unix))]
    {
        let _ = (
            &opts,
            &action,
            node_cfg,
            cli_profile,
            cli_peers,
            load_or_init_gateway_master_key,
        );
        anyhow::bail!("parvault gateway requires Unix Domain Sockets (Linux / Unix)");
    }

    #[cfg(unix)]
    {
        use crate::gateway::{
            create_memfd, pread_full_or_eof, pwrite_all, read_self_rss_bytes, GatewayBus,
            GatewayEngine, GatewayIpcClient, GatewayIpcServer, RetentionPolicy,
        };
        use crate::storage::{BlockStore, QuotaManager};
        use std::os::fd::AsRawFd;
        use std::sync::Arc;
        use tokio::sync::watch;

        match action {
            GatewayAction::Health => {
                if opts.no_socket {
                    anyhow::bail!(
                        "`parvault gateway health` queries an active Unix socket and cannot be used with --no-socket"
                    );
                }
                let client = GatewayIpcClient::new(&opts.socket);
                let (iops, peer_count, por_sla_score) = client.query_health().await?;
                println!(
                    "{}",
                    serde_json::json!({
                        "socket": opts.socket.display().to_string(),
                        "iops": iops,
                        "peer_count": peer_count,
                        "por_sla_score": por_sla_score
                    })
                );
            }
            GatewayAction::IpcRoundtrip {
                size_mib,
                net_iface,
            } => {
                if opts.no_socket {
                    anyhow::bail!(
                        "`parvault gateway ipc-roundtrip` benchmarks an active Unix socket and cannot be used with --no-socket"
                    );
                }
                run_ipc_roundtrip_probe(&opts.socket, size_mib, &net_iface).await?;
            }
            GatewayAction::SelfTest => {
                struct TempDirGuard(PathBuf);
                impl Drop for TempDirGuard {
                    fn drop(&mut self) {
                        let _ = std::fs::remove_dir_all(&self.0);
                    }
                }
                let mut nonce = [0u8; 6];
                OsRng.fill_bytes(&mut nonce);
                let tmp_dir = std::env::temp_dir().join(format!(
                    "parvault_gw_selftest_{}_{}",
                    std::process::id(),
                    hex::encode(nonce)
                ));
                std::fs::create_dir_all(&tmp_dir)?;
                let _guard = TempDirGuard(tmp_dir.clone());
                let sock = tmp_dir.join("parvault_selftest.sock");
                let store_dir = tmp_dir.join("store");
                let quota = QuotaManager::new(512 * 1024 * 1024, 64 * 1024 * 1024);
                let store = BlockStore::new(&store_dir, quota)?;
                let mk = MasterKey::generate();
                let mut srv = GatewayIpcServer::new(&sock, store, mk)
                    .with_profile(HardwareProfile::RouterSoc)
                    .with_require_sealed_ingest_memfd(true)
                    .with_strict_allowed_peer_uids(vec![crate::os_sys::geteuid()])
                    .spawn()?;

                let bus = GatewayBus::unix_socket(&sock);
                let in_mfd = create_memfd("selftest-in")?;
                let in_file = std::fs::File::from(in_mfd);
                let sample = vec![0x5Au8; 2 * 1024 * 1024];
                pwrite_all(&in_file, 0, &sample)?;

                let manifest = bus
                    .store_sealed_payload_fd(
                        in_file.as_raw_fd(),
                        sample.len() as u64,
                        RetentionPolicy::Ephemeral,
                    )
                    .await?;

                let out_mfd = create_memfd("selftest-out")?;
                let out_file = std::fs::File::from(out_mfd);
                let streamed = bus
                    .fetch_payload_to_fd(manifest.shard_hashes.clone(), out_file.as_raw_fd())
                    .await?;
                assert_eq!(streamed, sample.len() as u64);
                let mut roundtrip = vec![0u8; sample.len()];
                let read_n = pread_full_or_eof(&out_file, 0, &mut roundtrip)?;
                assert_eq!(read_n, sample.len());
                srv.shutdown();
                if roundtrip != sample {
                    anyhow::bail!("parvault gateway self-test payload mismatch");
                }
                let rss_mib = read_self_rss_bytes() as f64 / (1024.0 * 1024.0);
                println!(
                    "parvault gateway self-test: PASS (2 MiB sealed memfd SCM_RIGHTS + SO_PEERCRED round-trip verified, RSS={rss_mib:.2} MiB)"
                );
            }
            GatewayAction::Serve => {
                let strict_allowed_peer_uids = validate_plugin_security_flags(
                    false,
                    opts.no_socket,
                    opts.strict_plugins,
                    &opts.allow_peer_uid,
                )?;
                if let Some(ref watched) = node_cfg.watched_folder {
                    tracing::warn!(
                        watched_folder = %watched.display(),
                        "`parvault gateway serve` does not run FolderSyncEngine; `watched_folder` in config is ignored (use `parvault up --watch --ipc-socket /var/run/parvault.sock` for full single-daemon P2P + folder sync + plugin socket hosting, or push over /var/run/parvault.sock)"
                    );
                }

                let profile = cli_profile.unwrap_or(HardwareProfile::RouterSoc);
                std::fs::create_dir_all(&node_cfg.data_dir)?;
                let mk = load_or_init_gateway_master_key(
                    &node_cfg.data_dir,
                    node_cfg.device_sealing_passphrase.as_deref(),
                )?;
                let macaroon_root_key = resolve_optional_macaroon_root_key(
                    &node_cfg.data_dir,
                    opts.macaroon_root_key_hex.as_deref(),
                )?;
                let peers = node_cfg.effective_peers(cli_peers);
                let stripe_size_bytes = opts.stripe_bytes.unwrap_or_else(|| {
                    if peers.is_empty() {
                        profile.stripe_size_bytes()
                    } else {
                        512 * 1024
                    }
                });
                let tier = opts.tier.unwrap_or(node_cfg.default_tier);
                let gw_cfg = GatewayConfig {
                    stripe_size_bytes,
                    tier,
                    peers: peers.clone(),
                    macaroon_root_key,
                    strict_allowed_peer_uids,
                    require_sealed_ingest_memfd: opts.require_sealed_memfd,
                };
                let engine = Arc::new(GatewayEngine::new(&node_cfg.data_dir, mk, gw_cfg)?);
                if !peers.is_empty() {
                    let warm_ref = Arc::clone(&engine);
                    tokio::task::spawn_blocking(move || warm_ref.warm_mesh_connections()).await?;
                }

                if opts.no_socket {
                    let _bus = GatewayBus::in_process(Arc::clone(&engine));
                    tracing::warn!(
                        "`parvault gateway serve --no-socket` active: Unix Domain Socket listener disabled; external plugin ingress is off (use GatewayBus::InProcess for embedded library callers)"
                    );
                    println!(
                        "[parvault] gateway running in-process (--no-socket, profile={}, stripe={} B, peers={})",
                        profile,
                        stripe_size_bytes,
                        peers.len()
                    );
                    let _ = tokio::signal::ctrl_c().await;
                    return Ok(());
                }

                let server = GatewayIpcServer::bind(&opts.socket, engine)?;
                println!(
                    "[parvault] gateway listening on {} (profile={}, stripe={} B, peers={}, strict_plugins={}, sealed_memfd={})",
                    opts.socket.display(),
                    profile,
                    stripe_size_bytes,
                    peers.len(),
                    opts.strict_plugins || !opts.allow_peer_uid.is_empty(),
                    opts.require_sealed_memfd,
                );
                let (tx, rx) = watch::channel(false);
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = tx.send(true);
                });
                server.serve(rx).await?;
            }
        }
        Ok(())
    }
}
