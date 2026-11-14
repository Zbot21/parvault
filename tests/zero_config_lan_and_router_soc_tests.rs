//! v0.3.0 End-to-End Integration Suite (`ADR-18` & `ADR-19`):
//! Verifies:
//! 1. Zero-IP Home LAN Auto-Discovery (`discover --json`), 4-Word SAS Pairing (`pair` / `join`),
//!    and zero-`--peers` `file store`, `file restore`, and `watch-folder --once`.
//! 2. DHCP IP/Port Change Self-Healing via cryptographic `PeerId`-keyed `KnownPeersStore` & `MeshClient`.
//! 3. Interoperable `1 MiB` (`router-soc`) <-> `4 MiB` (`homelab-nas`) <-> `16 MiB` (`desktop`)
//!    streaming stripe sharding and cross-profile SHA-256 bit-for-bit restoration.
//! 4. Embedded zero-dependency `RouterNasStatusServer` HTTP JSON API (`/api/v1/health`, `/api/v1/peers`),
//!    responsive `< 6 KiB` HTML dashboard (`/`), live `VmRSS`/`VmHWM` telemetry, and `404` handling.
//! 5. Zero-IP Online WAN Rendezvous (`pair --wan` / `join --wan`), STUN-over-Noise reflection,
//!    and Dynamic-ISP-IP (`DDNS`) rotation across isolated networks without LAN broadcast.
//! 6. Zero-Pairing BitTorrent-Style Public Tracker Swarm (`--public --tracker <seed>`).
//! 7. Zero-Plaintext-IP Bad-Actor & Illegal-Content Shard Eviction (`ADR-19`), Cryptographic
//!    Reporter Burden-of-Proof (`VerifiableAbuseReport`), Emergency Warrant Eviction, Strict
//!    `PrivateRing` Isolation, and `2-of-3` Federated Public Tracker Operator Council Quorum.

use parvault::{
    config::NodeConfig,
    crypto::{MasterKey, NodeIdentity},
    network::{
        node_identity_libp2p_peer_id, reflect_observed_wan_multiaddr, seal_ddns_heartbeat,
        KnownPeersStore, MeshClient, TrustPoolMode, WanPeerCard, WanRendezvousRegistry,
    },
    router_nas::{RouterNasLiveSnapshot, RouterNasPeerEntry},
    sharding::merkle::hash_shard_leaf,
    storage::{
        load_or_generate_tracker_admin_identity, AnonymousQuotaVoucher, BlindedShardCapability,
        BlindedShardId, BlockStore, EvictionTarget, PrivacyPreservingEvictionEngine,
        PublicTrackerTakedownQueue, QuotaManager, ShardId, SignedBadActorEvictionOrder,
        TakedownReviewStatus, VerifiableAbuseReport, VoucherNullifierLedger,
    },
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// v0.5.0 requires ring admission for storage: every process these tests start (and every
/// in-process `MeshClient`) shares one ring genesis, provisioned before the first spawn.
fn provision_ring_genesis() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| std::env::set_var("PARVAULT_GENESIS_SEED_HEX", "47".repeat(32)));
}

struct ChildGuard(Vec<Child>);

impl ChildGuard {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, child: Child) {
        self.0.push(child);
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "parvault-v030-{}-{}-{}",
        label,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).expect("create unique temp dir");
    dir
}

fn reserve_free_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral TCP port");
    listener.local_addr().expect("local TCP addr").port()
}

fn reserve_free_udp_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral UDP port");
    sock.local_addr().expect("local UDP addr").port()
}

fn wait_for_tcp_port(port: u16, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("Timed out waiting for TCP listener on 127.0.0.1:{port}");
}

fn wait_for_beacon_files(registry_dir: &Path, expected_count: usize, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let count = fs::read_dir(registry_dir)
            .ok()
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("beacon"))
                    .count()
            })
            .unwrap_or(0);
        if count >= expected_count {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "Timed out waiting for {expected_count} signed .beacon files in {}",
        registry_dir.display()
    );
}

fn extract_field_after_colon(stdout: &str, prefix: &str) -> String {
    stdout
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with(prefix) {
                trimmed
                    .split_once(':')
                    .map(|(_, rhs)| rhs.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("Missing line starting with '{prefix}' in:\n{stdout}"))
}

fn assert_cmd_ok(out: &Output, ctx: &str) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "{ctx} failed (status={:?}):\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    stdout
}

fn http_get_raw(port: u16, path: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect HTTP status server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .expect("write HTTP request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read HTTP response");
    let text = String::from_utf8_lossy(&raw).to_string();
    let (headers, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("Invalid HTTP response from {path}:\n{text}"));
    let status_line = headers.lines().next().unwrap_or_default();
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("Failed to parse HTTP status code from '{status_line}'"));
    (status_code, headers.to_string(), body.to_string())
}

#[test]
fn test_1_zero_ip_home_lan_auto_discovery_4word_pairing_and_cli_backup_restore() {
    provision_ring_genesis();
    let base = unique_temp_dir("lan-zero-ip");
    let registry_dir = base.join("lan_registry");
    fs::create_dir_all(&registry_dir).unwrap();

    let parvault_bin = env!("CARGO_BIN_EXE_parvault");
    let seed_bin = env!("CARGO_BIN_EXE_parvault-seed");
    let disc_port = reserve_free_udp_port();

    let seed_port = reserve_free_tcp_port();
    let node1_port = reserve_free_tcp_port();
    let node2_port = reserve_free_tcp_port();

    let seed_dir = base.join("seed_node");
    let node1_dir = base.join("router_node_1");
    let node2_dir = base.join("router_node_2");
    fs::create_dir_all(&seed_dir).unwrap();
    fs::create_dir_all(&node1_dir).unwrap();
    fs::create_dir_all(&node2_dir).unwrap();

    // Initialize router_node_1 via `parvault init --profile router-soc` to verify turnkey init too
    let init_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&node1_dir)
        .args([
            "--profile",
            "router-soc",
            "init",
            "--label",
            "LivingRoom-Router",
            "--max-storage-gib",
            "32",
        ])
        .output()
        .expect("run parvault init");
    let init_stdout = assert_cmd_ok(&init_out, "parvault init");
    assert!(
        node1_dir.join("config.toml").is_file(),
        "parvault init must create config.toml; stdout:\n{init_stdout}"
    );

    let mut guards = ChildGuard::new();

    // 1. Spin up 1 parvault-seed + 2 parvault storage nodes on ephemeral ports
    guards.push(
        Command::new(seed_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
            .args([
                "start",
                "--mode",
                "homelab-vault",
                "--listen",
                &format!("/ip4/127.0.0.1/tcp/{seed_port}"),
                "--lan-discovery-port",
                &disc_port.to_string(),
                "--data-dir",
            ])
            .arg(&seed_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn parvault-seed"),
    );

    guards.push(
        Command::new(parvault_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
            .arg("--data-dir")
            .arg(&node1_dir)
            .args([
                "--profile",
                "router-soc",
                "--lan-discovery-port",
                &disc_port.to_string(),
                "up",
                "--listen",
                &format!("/ip4/127.0.0.1/tcp/{node1_port}"),
                "--pair",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn router_node_1"),
    );

    guards.push(
        Command::new(parvault_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
            .arg("--data-dir")
            .arg(&node2_dir)
            .args([
                "--profile",
                "homelab-nas",
                "--lan-discovery-port",
                &disc_port.to_string(),
                "daemon",
                "start",
                "--listen",
                &format!("/ip4/127.0.0.1/tcp/{node2_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn router_node_2"),
    );

    for port in [seed_port, node1_port, node2_port] {
        wait_for_tcp_port(port, Duration::from_secs(10));
    }
    wait_for_beacon_files(&registry_dir, 3, Duration::from_secs(10));

    // 2. Run `parvault discover --json` with ZERO `--peers` and ZERO IP addresses
    let discover_client_dir = base.join("discover_client");
    fs::create_dir_all(&discover_client_dir).unwrap();
    let disc_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .env_remove("PARVAULT_PEERS")
        .arg("--data-dir")
        .arg(&discover_client_dir)
        .args([
            "discover",
            "--json",
            "--timeout-ms",
            "600",
            "--port",
            &disc_port.to_string(),
        ])
        .output()
        .expect("run parvault discover --json");
    let disc_stdout = assert_cmd_ok(&disc_out, "parvault discover --json");
    let discovered: Vec<Value> =
        serde_json::from_str(&disc_stdout).expect("parse discover --json array");
    assert_eq!(
        discovered.len(),
        3,
        "Expected all 3 LAN nodes discovered with zero IPs, got:\n{disc_stdout}"
    );
    for entry in &discovered {
        let maddr = entry["multiaddr"].as_str().expect("multiaddr string");
        let pid = entry["peer_id"].as_str().expect("peer_id string");
        assert!(
            maddr.contains(&format!("/p2p/{pid}")),
            "Discovered multiaddr must pin cryptographic /p2p/<PeerId>: {maddr}"
        );
    }

    // 3. Verify 4-word SAS pairing (`pair --once` + `join --code ...`) pins peer & rejects wrong code
    let pair_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&node1_dir)
        .args([
            "--no-lan-discovery",
            "pair",
            "--once",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{node1_port}"),
        ])
        .output()
        .expect("run parvault pair --once");
    let pair_stdout = assert_cmd_ok(&pair_out, "parvault pair --once");
    let sas_code = extract_field_after_colon(&pair_stdout, "Home LAN Pairing Code");
    assert_eq!(
        sas_code.split('-').count(),
        4,
        "Expected 4-word BIP-39 SAS code, got '{sas_code}'"
    );

    let join_client_dir = base.join("laptop_join_client");
    fs::create_dir_all(&join_client_dir).unwrap();

    // Wrong 4-word code MUST fail verification
    let wrong_join = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&join_client_dir)
        .args([
            "join",
            "--code",
            "abandon-abandon-abandon-zoo",
            "--timeout-ms",
            "400",
            "--port",
            &disc_port.to_string(),
        ])
        .output()
        .expect("run parvault join with wrong code");
    assert!(
        !wrong_join.status.success(),
        "parvault join must reject wrong 4-word SAS code"
    );
    assert!(
        !join_client_dir.join("known_peers.json").exists(),
        "Failed join must not persist known_peers.json"
    );

    // Correct 4-word code MUST succeed and pin node1 in known_peers.json
    let ok_join = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&join_client_dir)
        .args([
            "join",
            "--code",
            &sas_code,
            "--timeout-ms",
            "800",
            "--port",
            &disc_port.to_string(),
        ])
        .output()
        .expect("run parvault join with valid code");
    let join_stdout = assert_cmd_ok(&ok_join, "parvault join valid code");
    assert!(join_stdout.contains("zero IP config ready!"));
    let pinned_store = KnownPeersStore::load(&join_client_dir);
    assert_eq!(
        pinned_store.peers.len(),
        1,
        "known_peers.json must contain exactly the paired router peer"
    );
    let node1_id = NodeIdentity::load_or_generate_in_dir(&node1_dir).unwrap();
    let expected_node1_pid = node_identity_libp2p_peer_id(&node1_id).unwrap().to_string();
    assert!(
        pinned_store.peers.contains_key(&expected_node1_pid),
        "known_peers.json must be keyed by node1's cryptographic libp2p PeerId"
    );

    // 4. Zero-`--peers` `parvault file store` -> wipe uploader -> `parvault file restore`!
    let zero_ip_store_dir = base.join("zero_ip_uploader");
    let zero_ip_restore_dir = base.join("zero_ip_restorer");
    fs::create_dir_all(&zero_ip_store_dir).unwrap();
    fs::create_dir_all(&zero_ip_restore_dir).unwrap();

    let input_file = base.join("family_photo.bin");
    let payload: Vec<u8> = (0..(180 * 1024))
        .map(|i| ((i * 37 + 11) & 0xFF) as u8)
        .collect();
    fs::write(&input_file, &payload).unwrap();

    let store_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .env_remove("PARVAULT_PEERS")
        .arg("--data-dir")
        .arg(&zero_ip_store_dir)
        .args([
            "--lan-discovery-port",
            &disc_port.to_string(),
            "file",
            "store",
            "--path",
        ])
        .arg(&input_file)
        .output()
        .expect("zero-IP parvault file store");
    let store_stdout = assert_cmd_ok(&store_out, "zero-IP file store");
    let merkle_root = extract_field_after_colon(&store_stdout, "File Merkle Root");
    let master_key_hex = extract_field_after_colon(&store_stdout, "Master Key (hex)");

    // Wipe uploader local state completely to prove shards & manifest live on LAN peers
    fs::remove_dir_all(&zero_ip_store_dir).unwrap();

    let restored_file = base.join("restored_family_photo.bin");
    let restore_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .env_remove("PARVAULT_PEERS")
        .arg("--data-dir")
        .arg(&zero_ip_restore_dir)
        .args([
            "--lan-discovery-port",
            &disc_port.to_string(),
            "file",
            "restore",
            &merkle_root,
            "--output",
        ])
        .arg(&restored_file)
        .args(["--key-hex", &master_key_hex])
        .output()
        .expect("zero-IP parvault file restore");
    assert_cmd_ok(&restore_out, "zero-IP file restore");
    assert_eq!(fs::read(&restored_file).unwrap(), payload);

    // 5. Zero-`--peers` `parvault watch-folder --once` + `restore-folder`
    let watch_client_dir = base.join("zero_ip_watch_client");
    let watch_src = base.join("home_vault");
    let watch_snap = base.join("home_vault.manifest.bin");
    let watch_restored = base.join("home_vault_restored");
    fs::create_dir_all(&watch_client_dir).unwrap();
    fs::create_dir_all(watch_src.join("notes")).unwrap();
    fs::write(
        watch_src.join("notes/router_nas.md"),
        b"Zero-IP LAN folder backup verified end-to-end!",
    )
    .unwrap();

    let watch_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .env_remove("PARVAULT_PEERS")
        .arg("--data-dir")
        .arg(&watch_client_dir)
        .args([
            "--lan-discovery-port",
            &disc_port.to_string(),
            "watch-folder",
            "--folder",
        ])
        .arg(&watch_src)
        .arg("--snapshot-out")
        .arg(&watch_snap)
        .args(["--tier", "consumer", "--once"])
        .output()
        .expect("zero-IP watch-folder --once");
    let watch_stdout = assert_cmd_ok(&watch_out, "zero-IP watch-folder --once");
    let watch_key_hex = extract_field_after_colon(&watch_stdout, "Master Key (hex)");

    // Wipe local client shards so restore-folder pulls from LAN peers with zero --peers
    fs::remove_dir_all(&watch_client_dir).unwrap();
    let fresh_restore_client = base.join("fresh_folder_restorer");
    fs::create_dir_all(&fresh_restore_client).unwrap();

    let restore_folder_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .env_remove("PARVAULT_PEERS")
        .arg("--data-dir")
        .arg(&fresh_restore_client)
        .args([
            "--lan-discovery-port",
            &disc_port.to_string(),
            "restore-folder",
            "--snapshot",
        ])
        .arg(&watch_snap)
        .arg("--out-dir")
        .arg(&watch_restored)
        .args(["--key-hex", &watch_key_hex])
        .output()
        .expect("zero-IP restore-folder");
    assert_cmd_ok(&restore_folder_out, "zero-IP restore-folder");
    assert_eq!(
        fs::read(watch_restored.join("notes/router_nas.md")).unwrap(),
        b"Zero-IP LAN folder backup verified end-to-end!"
    );

    drop(guards);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_2_dhcp_ip_port_change_self_healing() {
    provision_ring_genesis();
    let base = unique_temp_dir("dhcp-self-heal");
    let registry_dir = base.join("lan_registry");
    fs::create_dir_all(&registry_dir).unwrap();

    let parvault_bin = env!("CARGO_BIN_EXE_parvault");
    let disc_port = reserve_free_udp_port();

    let port_a1 = reserve_free_tcp_port();
    let port_b1 = reserve_free_tcp_port();
    let node_a_dir = base.join("nas_node_a");
    let node_b_dir = base.join("nas_node_b");
    fs::create_dir_all(&node_a_dir).unwrap();
    fs::create_dir_all(&node_b_dir).unwrap();

    let mut phase1_guards = ChildGuard::new();
    for (dir, port) in [(&node_a_dir, port_a1), (&node_b_dir, port_b1)] {
        phase1_guards.push(
            Command::new(parvault_bin)
                .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
                .arg("--data-dir")
                .arg(dir)
                .args([
                    "--profile",
                    "router-soc",
                    "--lan-discovery-port",
                    &disc_port.to_string(),
                    "daemon",
                    "start",
                    "--listen",
                    &format!("/ip4/127.0.0.1/tcp/{port}"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn phase1 daemon"),
        );
    }
    wait_for_tcp_port(port_a1, Duration::from_secs(10));
    wait_for_tcp_port(port_b1, Duration::from_secs(10));
    wait_for_beacon_files(&registry_dir, 2, Duration::from_secs(10));

    let client_dir = base.join("laptop_client");
    fs::create_dir_all(&client_dir).unwrap();
    let src_file = base.join("dhcp_resilient.bin");
    let payload: Vec<u8> = (0..(256 * 1024))
        .map(|i| ((i * 97 + 5) & 0xFF) as u8)
        .collect();
    fs::write(&src_file, &payload).unwrap();

    // Store file on initial ports (port_a1, port_b1)
    let store_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&client_dir)
        .args([
            "--lan-discovery-port",
            &disc_port.to_string(),
            "file",
            "store",
            "--path",
        ])
        .arg(&src_file)
        .output()
        .expect("store before DHCP change");
    let store_stdout = assert_cmd_ok(&store_out, "store before DHCP change");
    let merkle_root = extract_field_after_colon(&store_stdout, "File Merkle Root");
    let master_key_hex = extract_field_after_colon(&store_stdout, "Master Key (hex)");

    // Delete local client shards & manifests while preserving `known_peers.json` (which still has old ports!)
    let _ = fs::remove_dir_all(client_dir.join("shards"));
    let _ = fs::remove_dir_all(client_dir.join("manifests"));
    let known_before = KnownPeersStore::load(&client_dir);
    assert_eq!(known_before.peers.len(), 2);
    let addrs_before = known_before.active_multiaddrs();
    assert!(addrs_before
        .iter()
        .any(|a| a.contains(&format!("/tcp/{port_a1}/"))));
    assert!(addrs_before
        .iter()
        .any(|a| a.contains(&format!("/tcp/{port_b1}/"))));

    // Simulate DHCP lease change / router reboot: stop both daemons and restart SAME `node_identity.seed`s on NEW ports!
    drop(phase1_guards);
    for entry in fs::read_dir(&registry_dir).unwrap().flatten() {
        let _ = fs::remove_file(entry.path());
    }

    let mut port_a2 = reserve_free_tcp_port();
    while port_a2 == port_a1 || port_a2 == port_b1 {
        port_a2 = reserve_free_tcp_port();
    }
    let mut port_b2 = reserve_free_tcp_port();
    while port_b2 == port_a1 || port_b2 == port_b1 || port_b2 == port_a2 {
        port_b2 = reserve_free_tcp_port();
    }

    let mut phase2_guards = ChildGuard::new();
    for (dir, port) in [(&node_a_dir, port_a2), (&node_b_dir, port_b2)] {
        phase2_guards.push(
            Command::new(parvault_bin)
                .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
                .arg("--data-dir")
                .arg(dir)
                .args([
                    "--profile",
                    "router-soc",
                    "--lan-discovery-port",
                    &disc_port.to_string(),
                    "daemon",
                    "start",
                    "--listen",
                    &format!("/ip4/127.0.0.1/tcp/{port}"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn phase2 daemon on new port"),
        );
    }
    wait_for_tcp_port(port_a2, Duration::from_secs(10));
    wait_for_tcp_port(port_b2, Duration::from_secs(10));
    wait_for_beacon_files(&registry_dir, 2, Duration::from_secs(10));

    // Client still has stale `port_a1` & `port_b1` in `known_peers.json` — `MeshClient::with_data_dir_discovery`
    // must hit the dead endpoints, auto-invoke LAN discovery, heal `known_peers.json` by PeerId, and restore!
    let restored_file = base.join("dhcp_restored.bin");
    let restore_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&client_dir)
        .args([
            "--lan-discovery-port",
            &disc_port.to_string(),
            "file",
            "restore",
            &merkle_root,
            "--output",
        ])
        .arg(&restored_file)
        .args(["--key-hex", &master_key_hex])
        .output()
        .expect("restore after DHCP port change");
    assert_cmd_ok(&restore_out, "restore after DHCP port change");
    assert_eq!(fs::read(&restored_file).unwrap(), payload);

    let known_after = KnownPeersStore::load(&client_dir);
    let addrs_after = known_after.active_multiaddrs();
    assert!(
        addrs_after
            .iter()
            .any(|a| a.contains(&format!("/tcp/{port_a2}/p2p/"))),
        "KnownPeersStore must update node A's address to new port {port_a2}, got {addrs_after:?}"
    );
    assert!(
        addrs_after
            .iter()
            .any(|a| a.contains(&format!("/tcp/{port_b2}/p2p/"))),
        "KnownPeersStore must update node B's address to new port {port_b2}, got {addrs_after:?}"
    );

    drop(phase2_guards);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_3_interoperable_router_soc_1mib_homelab_4mib_desktop_16mib_streaming_stripes() {
    provision_ring_genesis();
    let base = unique_temp_dir("cross-profile-stripes");
    let registry_dir = base.join("lan_registry");
    fs::create_dir_all(&registry_dir).unwrap();

    let parvault_bin = env!("CARGO_BIN_EXE_parvault");
    let disc_port = reserve_free_udp_port();
    let daemon_port_1 = reserve_free_tcp_port();
    let daemon_port_2 = reserve_free_tcp_port();

    let mut guards = ChildGuard::new();
    for (idx, port) in [daemon_port_1, daemon_port_2].into_iter().enumerate() {
        let ndir = base.join(format!("storage_daemon_{idx}"));
        fs::create_dir_all(&ndir).unwrap();
        guards.push(
            Command::new(parvault_bin)
                .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
                .arg("--data-dir")
                .arg(&ndir)
                .args([
                    "--profile",
                    "router-soc",
                    "--lan-discovery-port",
                    &disc_port.to_string(),
                    "daemon",
                    "start",
                    "--listen",
                    &format!("/ip4/127.0.0.1/tcp/{port}"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn storage daemon"),
        );
    }
    wait_for_tcp_port(daemon_port_1, Duration::from_secs(10));
    wait_for_tcp_port(daemon_port_2, Duration::from_secs(10));
    wait_for_beacon_files(&registry_dir, 2, Duration::from_secs(10));

    // Deterministic 5 MiB payload (`5 * 1024 * 1024` bytes)
    let payload_5mib: Vec<u8> = (0usize..(5 * 1024 * 1024))
        .map(|i| ((i.wrapping_mul(131).wrapping_add(17)) & 0xFF) as u8)
        .collect();
    let expected_sha256: [u8; 32] = Sha256::digest(&payload_5mib).into();
    let src_5mib = base.join("firmware_5mib.bin");
    fs::write(&src_5mib, &payload_5mib).unwrap();

    // 1. Store 5 MiB with `--profile router-soc` (1 MiB stripes -> 5 stripes)
    let soc_client_dir = base.join("soc_uploader");
    fs::create_dir_all(&soc_client_dir).unwrap();
    let soc_store = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&soc_client_dir)
        .args([
            "--profile",
            "router-soc",
            "--lan-discovery-port",
            &disc_port.to_string(),
            "file",
            "store",
            "--path",
        ])
        .arg(&src_5mib)
        .output()
        .expect("store 5 MiB with router-soc profile");
    let soc_stdout = assert_cmd_ok(&soc_store, "router-soc 5 MiB store");
    assert_eq!(
        extract_field_after_colon(&soc_stdout, "Total Stripes"),
        "5",
        "5 MiB payload on --profile router-soc (1 MiB stripes) must produce 5 stripes:\n{soc_stdout}"
    );
    let soc_root = extract_field_after_colon(&soc_stdout, "File Merkle Root");
    let soc_key = extract_field_after_colon(&soc_stdout, "Master Key (hex)");
    fs::remove_dir_all(&soc_client_dir).unwrap();

    // 2. Store 5 MiB with `--profile homelab-nas` (4 MiB stripes -> 2 stripes)
    let nas_client_dir = base.join("nas_uploader");
    fs::create_dir_all(&nas_client_dir).unwrap();
    let nas_store = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&nas_client_dir)
        .args([
            "--profile",
            "homelab-nas",
            "--lan-discovery-port",
            &disc_port.to_string(),
            "file",
            "store",
            "--path",
        ])
        .arg(&src_5mib)
        .output()
        .expect("store 5 MiB with homelab-nas profile");
    let nas_stdout = assert_cmd_ok(&nas_store, "homelab-nas 5 MiB store");
    assert_eq!(
        extract_field_after_colon(&nas_stdout, "Total Stripes"),
        "2",
        "5 MiB payload on --profile homelab-nas (4 MiB stripes) must produce 2 stripes:\n{nas_stdout}"
    );
    let nas_root = extract_field_after_colon(&nas_stdout, "File Merkle Root");
    let nas_key = extract_field_after_colon(&nas_stdout, "Master Key (hex)");
    fs::remove_dir_all(&nas_client_dir).unwrap();

    // 3. Restore the 5-stripe `router-soc` file on a `--profile desktop` (16 MiB) client!
    let desktop_client_dir = base.join("desktop_restorer");
    fs::create_dir_all(&desktop_client_dir).unwrap();
    let restored_on_desktop = base.join("restored_on_desktop.bin");
    let desk_restore = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&desktop_client_dir)
        .args([
            "--profile",
            "desktop",
            "--lan-discovery-port",
            &disc_port.to_string(),
            "file",
            "restore",
            &soc_root,
            "--output",
        ])
        .arg(&restored_on_desktop)
        .args(["--key-hex", &soc_key])
        .output()
        .expect("restore router-soc file on desktop profile");
    assert_cmd_ok(&desk_restore, "desktop restore of router-soc 5-stripe file");
    let actual_desktop_sha: [u8; 32] =
        Sha256::digest(fs::read(&restored_on_desktop).unwrap()).into();
    assert_eq!(actual_desktop_sha, expected_sha256);

    // 4. Restore the 2-stripe `homelab-nas` (4 MiB) file on a `--profile router-soc` (1 MiB) client!
    let tiny_restorer_dir = base.join("soc_restorer");
    fs::create_dir_all(&tiny_restorer_dir).unwrap();
    let restored_on_soc = base.join("restored_on_soc.bin");
    let soc_restore = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&tiny_restorer_dir)
        .args([
            "--profile",
            "router-soc",
            "--lan-discovery-port",
            &disc_port.to_string(),
            "file",
            "restore",
            &nas_root,
            "--output",
        ])
        .arg(&restored_on_soc)
        .args(["--key-hex", &nas_key])
        .output()
        .expect("restore homelab-nas file on router-soc profile");
    assert_cmd_ok(&soc_restore, "router-soc restore of homelab-nas file");
    let actual_soc_sha: [u8; 32] = Sha256::digest(fs::read(&restored_on_soc).unwrap()).into();
    assert_eq!(actual_soc_sha, expected_sha256);

    drop(guards);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_4_embedded_router_nas_status_server_http_and_html_dashboard() {
    provision_ring_genesis();
    let base = unique_temp_dir("router-nas-http");
    let registry_dir = base.join("lan_registry");
    let watched_usb = base.join("mnt_usb_nas");
    fs::create_dir_all(&registry_dir).unwrap();
    fs::create_dir_all(&watched_usb).unwrap();
    fs::write(watched_usb.join("hello.txt"), b"router-nas-usb-share").unwrap();

    let parvault_bin = env!("CARGO_BIN_EXE_parvault");
    let disc_port = reserve_free_udp_port();
    let router_p2p_port = reserve_free_tcp_port();
    let neighbor_p2p_port = reserve_free_tcp_port();
    let status_http_port = reserve_free_tcp_port();

    let router_dir = base.join("router_appliance");
    let neighbor_dir = base.join("neighbor_daemon");
    fs::create_dir_all(&router_dir).unwrap();
    fs::create_dir_all(&neighbor_dir).unwrap();

    let mut guards = ChildGuard::new();

    // Spin up a neighbor LAN peer so `/api/v1/peers` on the router appliance populates automatically
    guards.push(
        Command::new(parvault_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
            .arg("--data-dir")
            .arg(&neighbor_dir)
            .args([
                "--lan-discovery-port",
                &disc_port.to_string(),
                "daemon",
                "start",
                "--listen",
                &format!("/ip4/127.0.0.1/tcp/{neighbor_p2p_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn neighbor daemon"),
    );
    wait_for_tcp_port(neighbor_p2p_port, Duration::from_secs(10));

    // Spin up turnkey `parvault up --profile router-soc --status-http 127.0.0.1:<port> --pair`
    guards.push(
        Command::new(parvault_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
            .arg("--data-dir")
            .arg(&router_dir)
            .args([
                "--profile",
                "router-soc",
                "--lan-discovery-port",
                &disc_port.to_string(),
                "up",
                "--listen",
                &format!("/ip4/127.0.0.1/tcp/{router_p2p_port}"),
                "--status-http",
                &format!("127.0.0.1:{status_http_port}"),
                "--folder",
            ])
            .arg(&watched_usb)
            .arg("--pair")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn router-soc appliance"),
    );

    wait_for_tcp_port(router_p2p_port, Duration::from_secs(10));
    wait_for_tcp_port(status_http_port, Duration::from_secs(10));
    wait_for_beacon_files(&registry_dir, 2, Duration::from_secs(10));

    // Compute expected deterministic 4-word SAS pairing code for router_dir
    let pair_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &registry_dir)
        .arg("--data-dir")
        .arg(&router_dir)
        .args([
            "--no-lan-discovery",
            "pair",
            "--once",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{router_p2p_port}"),
        ])
        .output()
        .expect("query router SAS code");
    let expected_sas = extract_field_after_colon(
        &assert_cmd_ok(&pair_out, "query router SAS"),
        "Home LAN Pairing Code",
    );

    // 1. Verify `GET /api/v1/health`
    let (status_health, headers_health, body_health) =
        http_get_raw(status_http_port, "/api/v1/health");
    assert_eq!(status_health, 200);
    let headers_lower = headers_health.to_ascii_lowercase();
    assert!(headers_lower.contains("application/json"));
    assert!(headers_lower.contains("x-content-type-options: nosniff"));
    assert!(headers_lower.contains("cache-control: no-store"));

    let snap: RouterNasLiveSnapshot =
        serde_json::from_str(&body_health).expect("deserialize RouterNasLiveSnapshot");
    assert_eq!(snap.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(snap.hardware_profile, "router-soc");
    assert_eq!(snap.stripe_size_bytes, 1_048_576);
    assert_eq!(
        snap.pairing_sas_code.as_deref(),
        Some(expected_sas.as_str())
    );
    #[cfg(target_os = "linux")]
    {
        assert!(snap.rss_kib > 0, "Linux VmRSS must be > 0 KiB");
        assert!(
            snap.hwm_kib >= snap.rss_kib,
            "VmHWM ({}) must be >= VmRSS ({})",
            snap.hwm_kib,
            snap.rss_kib
        );
        assert!(
            snap.hwm_kib < 32 * 1024,
            "Router-SoC idle/appliance VmHWM ({} KiB) must stay well under 32 MiB",
            snap.hwm_kib
        );
    }

    // 2. Verify `GET /api/v1/peers` (poll briefly if background updater hasn't completed tick 1)
    let mut peers: Vec<RouterNasPeerEntry> = Vec::new();
    for _ in 0..20 {
        let (st, _, b) = http_get_raw(status_http_port, "/api/v1/peers");
        assert_eq!(st, 200);
        peers = serde_json::from_str(&b).expect("deserialize RouterNasPeerEntry vec");
        if !peers.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    assert!(
        !peers.is_empty(),
        "GET /api/v1/peers must report discovered neighbor LAN daemon"
    );
    assert!(peers[0].multiaddr.contains("/p2p/"));

    // 3. Verify `GET /` HTML dashboard (`< 6 KiB` target, contains VmRSS/VmHWM & 4-word SAS code)
    let (status_html, headers_html, body_html) = http_get_raw(status_http_port, "/");
    assert_eq!(status_html, 200);
    assert!(headers_html.to_ascii_lowercase().contains("text/html"));
    assert!(
        body_html.len() <= 6 * 1024,
        "Embedded Router NAS HTML dashboard must be <= 6 KiB, got {} bytes",
        body_html.len()
    );
    assert!(
        body_html.contains(&expected_sas),
        "HTML dashboard must display the 4-word pairing SAS code '{expected_sas}'"
    );
    assert!(
        body_html.contains("VmRSS") || body_html.contains("VmHWM") || body_html.contains("MiB"),
        "HTML dashboard must render memory telemetry"
    );

    // 4. Verify unknown path returns `404 Not Found` JSON
    let (status_404, headers_404, body_404) =
        http_get_raw(status_http_port, "/api/v1/nonexistent-endpoint");
    assert_eq!(status_404, 404);
    assert!(headers_404
        .to_ascii_lowercase()
        .contains("application/json"));
    let err_json: Value = serde_json::from_str(&body_404).expect("404 JSON body");
    assert!(err_json.is_object());

    drop(guards);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_5_zero_ip_online_wan_rendezvous_stun_reflection_and_ddns_ip_rotation() {
    provision_ring_genesis();
    let base = unique_temp_dir("wan-rendezvous");
    let empty_reg_alice = base.join("isolated_lan_alice");
    let empty_reg_bob = base.join("isolated_lan_bob");
    fs::create_dir_all(&empty_reg_alice).unwrap();
    fs::create_dir_all(&empty_reg_bob).unwrap();

    let parvault_bin = env!("CARGO_BIN_EXE_parvault");
    let seed_bin = env!("CARGO_BIN_EXE_parvault-seed");

    let seed_port = reserve_free_tcp_port();
    let alice_port_1 = reserve_free_tcp_port();
    let seed_maddr = format!("/ip4/127.0.0.1/tcp/{seed_port}");

    let seed_dir = base.join("wan_seed_anchor");
    let alice_dir = base.join("alice_home_router");
    let bob_dir = base.join("bob_remote_laptop");
    fs::create_dir_all(&seed_dir).unwrap();
    fs::create_dir_all(&alice_dir).unwrap();
    fs::create_dir_all(&bob_dir).unwrap();

    let mut guards = ChildGuard::new();

    // 1. Start Online WAN Rendezvous Anchor (`parvault-seed` with `--no-lan-discovery`)
    guards.push(
        Command::new(seed_bin)
            .args([
                "start",
                "--mode",
                "homelab-vault",
                "--no-lan-discovery",
                "--listen",
                &seed_maddr,
                "--data-dir",
            ])
            .arg(&seed_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn WAN seed anchor"),
    );
    wait_for_tcp_port(seed_port, Duration::from_secs(10));

    // 2. Start Alice's daemon in City A (`--no-lan-discovery`, isolated registry dir)
    let mut alice_guard = ChildGuard::new();
    alice_guard.push(
        Command::new(parvault_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &empty_reg_alice)
            .arg("--data-dir")
            .arg(&alice_dir)
            .args([
                "--no-lan-discovery",
                "--seed-addr",
                &seed_maddr,
                "up",
                "--wan",
                "--listen",
                &format!("/ip4/127.0.0.1/tcp/{alice_port_1}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn Alice WAN daemon"),
    );
    wait_for_tcp_port(alice_port_1, Duration::from_secs(10));

    // Alice publishes encrypted 4-word `WanPeerCard` to `seed_maddr` (also exercising STUN-over-Noise reflection!)
    let pair_wan_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_reg_alice)
        .arg("--data-dir")
        .arg(&alice_dir)
        .args([
            "--no-lan-discovery",
            "--seed-addr",
            &seed_maddr,
            "pair",
            "--wan",
            "--once",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{alice_port_1}"),
        ])
        .output()
        .expect("run Alice pair --wan --once");
    let pair_wan_stdout = assert_cmd_ok(&pair_wan_out, "Alice pair --wan --once");
    assert!(
        pair_wan_stdout.contains("observed=/ip4/127.0.0.1/tcp/"),
        "WAN rendezvous must reflect STUN-over-Noise observed external address, got:\n{pair_wan_stdout}"
    );
    let wan_code = extract_field_after_colon(&pair_wan_stdout, "Home LAN Pairing Code");

    // Also unit-verify `reflect_observed_wan_multiaddr` helper directly for public ISP IPv4
    let simulated_remote: libp2p::Multiaddr = "/ip4/198.51.100.10/tcp/54321".parse().unwrap();
    let alice_id = NodeIdentity::load_or_generate_in_dir(&alice_dir).unwrap();
    let alice_pid = node_identity_libp2p_peer_id(&alice_id).unwrap().to_string();
    let reflected =
        reflect_observed_wan_multiaddr(&simulated_remote, alice_port_1, &alice_pid).unwrap();
    assert_eq!(
        reflected,
        format!("/ip4/198.51.100.10/tcp/{alice_port_1}/p2p/{alice_pid}")
    );

    // 3. Bob in City B (`--no-lan-discovery`, isolated registry): wrong code fails, Alice's 4-word code joins!
    let bad_wan_join = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_reg_bob)
        .arg("--data-dir")
        .arg(&bob_dir)
        .args([
            "--no-lan-discovery",
            "--seed-addr",
            &seed_maddr,
            "join",
            "--wan",
            "--code",
            "abandon-abandon-abandon-zoo",
        ])
        .output()
        .expect("Bob join wrong WAN code");
    assert!(
        !bad_wan_join.status.success(),
        "Wrong 4-word WAN code must fail AEAD decryption & reject join"
    );

    let ok_wan_join = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_reg_bob)
        .arg("--data-dir")
        .arg(&bob_dir)
        .args([
            "--no-lan-discovery",
            "--seed-addr",
            &seed_maddr,
            "join",
            "--wan",
            "--code",
            &wan_code,
        ])
        .output()
        .expect("Bob join valid WAN code");
    let bob_join_stdout = assert_cmd_ok(&ok_wan_join, "Bob join --wan");
    assert!(bob_join_stdout.contains(&alice_pid));

    // Bob stores a file directly onto Alice over Noise XX using only the WAN-paired KnownPeersStore!
    let secret_doc = base.join("cross_city_contract.txt");
    let secret_bytes = b"Zero-IP Online WAN Rendezvous + STUN-over-Noise verified across cities!";
    fs::write(&secret_doc, secret_bytes).unwrap();

    let bob_store = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_reg_bob)
        .arg("--data-dir")
        .arg(&bob_dir)
        .args([
            "--no-lan-discovery",
            "--seed-addr",
            &seed_maddr,
            "file",
            "store",
            "--path",
        ])
        .arg(&secret_doc)
        .output()
        .expect("Bob WAN file store");
    let bob_store_stdout = assert_cmd_ok(&bob_store, "Bob WAN file store");
    let root_hex = extract_field_after_colon(&bob_store_stdout, "File Merkle Root");
    let key_hex = extract_field_after_colon(&bob_store_stdout, "Master Key (hex)");

    // Wipe Bob's local shards & manifests so restore MUST traverse the network to Alice
    let _ = fs::remove_dir_all(bob_dir.join("shards"));
    let _ = fs::remove_dir_all(bob_dir.join("manifests"));

    // 4. Simulate ISP Dynamic IP / Port Rotation:
    //    (a) Verify encrypted DDNS heartbeat rotation from `198.51.100.10` -> `203.0.113.77` on the live seed anchor,
    //    (b) Restart Alice on a brand-new port `alice_port_2`, publish updated WAN presence, and restore from Bob!
    drop(alice_guard);

    let mut alice_port_2 = reserve_free_tcp_port();
    while alice_port_2 == alice_port_1 || alice_port_2 == seed_port {
        alice_port_2 = reserve_free_tcp_port();
    }

    let bob_client = MeshClient::new(
        NodeIdentity::load_or_generate_in_dir(&bob_dir).unwrap(),
        vec![],
        Some(seed_maddr.clone()),
    );
    let alice_client = MeshClient::new(alice_id.clone(), vec![], Some(seed_maddr.clone()));
    let ddns_secret = "shared-coop-ring-ddns-secret-v1";

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let card_isp_v1 = WanPeerCard::new(
        &alice_id,
        "Alice-Router",
        "router-nas",
        vec![format!("/ip4/198.51.100.10/tcp/4001/p2p/{alice_pid}")],
        Some(seed_maddr.clone()),
        None,
        3600,
        now_ms,
    )
    .unwrap();
    alice_client
        .publish_wan_ddns_heartbeat(&seed_maddr, ddns_secret, &card_isp_v1)
        .expect("publish ISP v1 DDNS card");

    // Verify seed's on-disk WanRendezvousRegistry cannot decrypt `WanPeerCard` without `ddns_secret`
    let mut local_reg_check = WanRendezvousRegistry::load_or_new(None);
    let sealed = seal_ddns_heartbeat(ddns_secret, &card_isp_v1, &alice_id).unwrap();
    local_reg_check
        .register(sealed.slot_key, sealed.clone(), now_ms)
        .unwrap();
    assert!(parvault::network::open_ddns_heartbeat("wrong-secret", &sealed).is_err());

    // ISP rotates Alice's WAN endpoint -> publish updated heartbeat (`now_ms + 1000`)
    let card_isp_v2 = WanPeerCard::new(
        &alice_id,
        "Alice-Router",
        "router-nas",
        vec![format!("/ip4/127.0.0.1/tcp/{alice_port_2}/p2p/{alice_pid}")],
        Some(seed_maddr.clone()),
        None,
        3600,
        now_ms + 1_000,
    )
    .unwrap();
    alice_client
        .publish_wan_ddns_heartbeat(&seed_maddr, ddns_secret, &card_isp_v2)
        .expect("publish ISP v2 rotated DDNS card");

    let resolved_ddns = bob_client
        .lookup_wan_ddns_cards(&seed_maddr, ddns_secret)
        .expect("Bob lookup rotated DDNS card");
    assert!(
        resolved_ddns.iter().any(|c| {
            c.libp2p_peer_id == alice_pid
                && c.wan_multiaddrs.contains(&format!(
                    "/ip4/127.0.0.1/tcp/{alice_port_2}/p2p/{alice_pid}"
                ))
        }),
        "Bob must resolve Alice's rotated endpoint via encrypted WAN DDNS: {resolved_ddns:?}"
    );

    // Restart Alice's live daemon on `alice_port_2` and update Bob's pinned address via DDNS/WAN pair
    guards.push(
        Command::new(parvault_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &empty_reg_alice)
            .arg("--data-dir")
            .arg(&alice_dir)
            .args([
                "--no-lan-discovery",
                "--seed-addr",
                &seed_maddr,
                "up",
                "--wan",
                "--listen",
                &format!("/ip4/127.0.0.1/tcp/{alice_port_2}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn Alice on rotated port"),
    );
    wait_for_tcp_port(alice_port_2, Duration::from_secs(10));

    // Re-publish Alice's rotated port to WAN rendezvous & let Bob re-sync and restore the file!
    let _ = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_reg_alice)
        .arg("--data-dir")
        .arg(&alice_dir)
        .args([
            "--no-lan-discovery",
            "--seed-addr",
            &seed_maddr,
            "pair",
            "--wan",
            "--once",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{alice_port_2}"),
        ])
        .output()
        .unwrap();
    let _ = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_reg_bob)
        .arg("--data-dir")
        .arg(&bob_dir)
        .args([
            "--no-lan-discovery",
            "--seed-addr",
            &seed_maddr,
            "join",
            "--wan",
            "--code",
            &wan_code,
        ])
        .output()
        .unwrap();

    let restored_doc = base.join("restored_contract.txt");
    let bob_restore = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_reg_bob)
        .arg("--data-dir")
        .arg(&bob_dir)
        .args([
            "--no-lan-discovery",
            "--seed-addr",
            &seed_maddr,
            "file",
            "restore",
            &root_hex,
            "--output",
        ])
        .arg(&restored_doc)
        .args(["--key-hex", &key_hex])
        .output()
        .expect("Bob WAN file restore after port rotation");
    assert_cmd_ok(&bob_restore, "Bob WAN file restore after port rotation");
    assert_eq!(fs::read(&restored_doc).unwrap(), secret_bytes);

    drop(guards);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_6_zero_pairing_public_tracker_swarm() {
    provision_ring_genesis();
    let base = unique_temp_dir("public-tracker-swarm");
    let empty_lan = base.join("no_lan");
    fs::create_dir_all(&empty_lan).unwrap();

    let parvault_bin = env!("CARGO_BIN_EXE_parvault");
    let seed_bin = env!("CARGO_BIN_EXE_parvault-seed");

    let tracker_port = reserve_free_tcp_port();
    let tracker_maddr = format!("/ip4/127.0.0.1/tcp/{tracker_port}");
    let tracker_dir = base.join("public_tracker_seed");
    fs::create_dir_all(&tracker_dir).unwrap();

    let mut guards = ChildGuard::new();

    // 1. Spin up 1 `parvault-seed --mode public-bootstrap` tracker
    guards.push(
        Command::new(seed_bin)
            .args([
                "start",
                "--mode",
                "public-bootstrap",
                "--no-lan-discovery",
                "--listen",
                &tracker_maddr,
                "--data-dir",
            ])
            .arg(&tracker_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn public-bootstrap tracker"),
    );
    wait_for_tcp_port(tracker_port, Duration::from_secs(10));

    // 2. Spin up 3 completely unacquainted stranger `--public --tracker <seed>` storage daemons
    let stranger_ports = [
        reserve_free_tcp_port(),
        reserve_free_tcp_port(),
        reserve_free_tcp_port(),
    ];
    let mut stranger_dirs = Vec::new();
    for (idx, port) in stranger_ports.iter().enumerate() {
        let sdir = base.join(format!("stranger_daemon_{idx}"));
        fs::create_dir_all(&sdir).unwrap();
        stranger_dirs.push(sdir.clone());
        guards.push(
            Command::new(parvault_bin)
                .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
                .arg("--data-dir")
                .arg(&sdir)
                .args([
                    "--no-lan-discovery",
                    "--public",
                    "--tracker",
                    &tracker_maddr,
                    "up",
                    "--listen",
                    &format!("/ip4/127.0.0.1/tcp/{port}"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn stranger --public daemon"),
        );
    }
    for port in stranger_ports {
        wait_for_tcp_port(port, Duration::from_secs(10));
    }

    // Poll `parvault --public --tracker <seed> discover --json` from a 4th stranger client until all 3 daemons appear
    let uploader_dir = base.join("stranger_uploader_client");
    fs::create_dir_all(&uploader_dir).unwrap();
    let mut discovered_public: Vec<Value> = Vec::new();
    for _ in 0..30 {
        let out = Command::new(parvault_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
            .arg("--data-dir")
            .arg(&uploader_dir)
            .args([
                "--no-lan-discovery",
                "--public",
                "--tracker",
                &tracker_maddr,
                "discover",
                "--json",
            ])
            .output()
            .expect("discover via public tracker");
        if out.status.success() {
            if let Ok(parsed) = serde_json::from_slice::<Vec<Value>>(&out.stdout) {
                if parsed.len() >= 3 {
                    discovered_public = parsed;
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    assert!(
        discovered_public.len() >= 3,
        "Stranger client must discover >= 3 stranger daemons via Public Tracker with zero pairing, got: {discovered_public:?}"
    );
    assert!(discovered_public
        .iter()
        .all(|e| e["source"].as_str() == Some("public-tracker")));

    // 3. Store a file with ZERO pairing, ZERO join codes, ZERO manual peer IPs!
    let public_payload_path = base.join("opensource_release.bin");
    let public_payload: Vec<u8> = (0..(220 * 1024))
        .map(|i| ((i * 53 + 29) & 0xFF) as u8)
        .collect();
    fs::write(&public_payload_path, &public_payload).unwrap();

    let fresh_uploader_dir = base.join("zero_state_public_uploader");
    fs::create_dir_all(&fresh_uploader_dir).unwrap();
    let pub_store_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
        .arg("--data-dir")
        .arg(&fresh_uploader_dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "--tracker",
            &tracker_maddr,
            "file",
            "store",
            "--path",
        ])
        .arg(&public_payload_path)
        .output()
        .expect("store file onto public commons swarm");
    let pub_store_stdout = assert_cmd_ok(&pub_store_out, "public commons file store");
    assert!(
        pub_store_stdout.contains("10-of-20"),
        "Public Commons mode must enforce Consumer 10-of-20 erasure redundancy:\n{pub_store_stdout}"
    );
    let pub_root = extract_field_after_colon(&pub_store_stdout, "File Merkle Root");
    let pub_key = extract_field_after_colon(&pub_store_stdout, "Master Key (hex)");

    // Verify remote stranger daemons hold ciphertext shards on disk
    let remote_shard_total: usize = stranger_dirs
        .iter()
        .map(|d| {
            fs::read_dir(d.join("shards"))
                .ok()
                .map(|rd| {
                    rd.filter_map(Result::ok)
                        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("shard"))
                        .count()
                })
                .unwrap_or(0)
        })
        .sum();
    assert!(
        remote_shard_total >= 10,
        "Expected stranger --public daemons to store >= 10 shards, found {remote_shard_total}"
    );

    // Wipe uploader completely and restore from a 5th stranger machine using ONLY `--public --tracker`!
    fs::remove_dir_all(&fresh_uploader_dir).unwrap();
    let fifth_stranger_dir = base.join("stranger_downloader_client");
    fs::create_dir_all(&fifth_stranger_dir).unwrap();
    let restored_public_path = base.join("restored_release.bin");

    let pub_restore_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
        .arg("--data-dir")
        .arg(&fifth_stranger_dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "--tracker",
            &tracker_maddr,
            "file",
            "restore",
            &pub_root,
            "--output",
        ])
        .arg(&restored_public_path)
        .args(["--key-hex", &pub_key])
        .output()
        .expect("restore file from public commons swarm");
    assert_cmd_ok(&pub_restore_out, "public commons file restore");
    assert_eq!(fs::read(&restored_public_path).unwrap(), public_payload);

    drop(guards);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_7_zero_plaintext_ip_bad_actor_eviction_burden_of_proof_and_council_quorum() {
    provision_ring_genesis();
    let base = unique_temp_dir("adr19-eviction-governance");
    let empty_lan = base.join("no_lan");
    fs::create_dir_all(&empty_lan).unwrap();

    // =========================================================================
    // PART A: Forensic Zero-Plaintext-IP Invariant, Cross-Node Unlinkability,
    //         0x00 Shredding, and Blinded Cohort Eviction (`PrivacyPreservingEvictionEngine`)
    // =========================================================================
    let node_a_dir = base.join("forensic_node_a");
    let node_b_dir = base.join("forensic_node_b");
    let store_a = BlockStore::new(
        &node_a_dir,
        QuotaManager::new(500 * 1024 * 1024, 50 * 1024 * 1024),
    )
    .unwrap();
    let mut evict_a = PrivacyPreservingEvictionEngine::load_or_init(&node_a_dir).unwrap();
    let evict_b = PrivacyPreservingEvictionEngine::load_or_init(&node_b_dir).unwrap();

    let bad_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 66));
    let honest_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));

    // Unlinkability: two nodes derive completely uncorrelated HMAC tags for the same IP
    assert_ne!(
        evict_a.compute_ip_hmac_tag(bad_ip),
        evict_b.compute_ip_hmac_tag(bad_ip),
        "Per-node keyed HMAC tags must be cryptographically uncorrelated across nodes"
    );

    let bad_actor_id = NodeIdentity::generate();
    let bad_cohort_voucher_issuer = NodeIdentity::generate();
    let honest_id = NodeIdentity::generate();

    let bad_bytes = vec![0xABu8; 4096];
    let bad_shard_id = ShardId {
        stripe_merkle_root: [0x66; 32],
        shard_index: 0,
        shard_hash: hash_shard_leaf(0, &bad_bytes),
    };
    store_a
        .put_shard(&bad_actor_id.device_peer_id(), &bad_shard_id, &bad_bytes)
        .unwrap();
    evict_a
        .record_regular_shard_ingress(
            Some(bad_ip),
            Some("12D3KooWBadActorPeerId"),
            Some(bad_actor_id.public_key_bytes()),
            &bad_actor_id.device_peer_id(),
            bad_shard_id,
        )
        .unwrap();
    evict_a
        .record_peer_admission_ip(bad_ip, bad_cohort_voucher_issuer.public_key_bytes())
        .unwrap();

    // Also store blinded `.bshard`s so we verify both IP-cohort blinded purge and `PeerOrIssuerPubkey` blinded purge
    let mk_blinded = MasterKey::generate();
    let blinded_bytes = vec![0xCDu8; 2048];
    let blinded_id = BlindedShardId::derive(&mk_blinded, &[0x99; 32], 0, &blinded_bytes);
    let (_, blinded_cap) = BlindedShardCapability::derive_keypair(&mk_blinded, &blinded_id.locator);
    let blinded_voucher = AnonymousQuotaVoucher::mint(&bad_cohort_voucher_issuer, 8192);
    let mut nullifier_ledger =
        VoucherNullifierLedger::new(bad_cohort_voucher_issuer.public_key_bytes());
    store_a
        .put_blinded_shard(
            &blinded_id,
            &blinded_bytes,
            blinded_cap,
            &blinded_voucher,
            &mut nullifier_ledger,
        )
        .unwrap();
    let second_cohort_issuer = NodeIdentity::generate();
    let blinded_id_2 = BlindedShardId::derive(&mk_blinded, &[0x9A; 32], 1, &blinded_bytes);
    let (_, blinded_cap_2) =
        BlindedShardCapability::derive_keypair(&mk_blinded, &blinded_id_2.locator);
    let blinded_voucher_2 = AnonymousQuotaVoucher::mint(&second_cohort_issuer, 8192);
    let mut nullifier_ledger_2 =
        VoucherNullifierLedger::new(second_cohort_issuer.public_key_bytes());
    store_a
        .put_blinded_shard(
            &blinded_id_2,
            &blinded_bytes,
            blinded_cap_2,
            &blinded_voucher_2,
            &mut nullifier_ledger_2,
        )
        .unwrap();
    evict_a
        .record_blinded_shard_ingress(
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200))),
            Some("12D3KooWInnocentRelay"),
            bad_cohort_voucher_issuer.public_key_bytes(),
            blinded_id,
        )
        .unwrap();
    evict_a
        .record_blinded_shard_ingress(
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200))),
            Some("12D3KooWInnocentRelay"),
            second_cohort_issuer.public_key_bytes(),
            blinded_id_2,
        )
        .unwrap();

    let honest_bytes = vec![0x77u8; 4096];
    let honest_shard_id = ShardId {
        stripe_merkle_root: [0x22; 32],
        shard_index: 0,
        shard_hash: hash_shard_leaf(0, &honest_bytes),
    };
    store_a
        .put_shard(&honest_id.device_peer_id(), &honest_shard_id, &honest_bytes)
        .unwrap();
    evict_a
        .record_regular_shard_ingress(
            Some(honest_ip),
            Some("12D3KooWHonestPeerId"),
            Some(honest_id.public_key_bytes()),
            &honest_id.device_peer_id(),
            honest_shard_id,
        )
        .unwrap();

    let resolved_pks = evict_a.resolve_pubkeys_for_ip(bad_ip);
    assert_eq!(
        resolved_pks,
        vec![bad_cohort_voucher_issuer.public_key_bytes()]
    );

    // Evict bad_ip and verify zero plaintext IP strings in `eviction_index.bin`!
    let purge_ip = evict_a
        .evict_target(&EvictionTarget::IpAddress(bad_ip), &store_a)
        .unwrap();
    assert_eq!(purge_ip.purged_regular_shards, 1);
    assert_eq!(purge_ip.purged_blinded_shards, 1);
    assert!(purge_ip.zero_wiped_bytes >= 4096 + 2048);
    assert!(purge_ip.firewall_rule_installed);
    assert!(!store_a.has_blinded_shard_on_disk(&blinded_id));

    let raw_index = fs::read(node_a_dir.join("eviction_index.bin")).unwrap();
    for forbidden in [
        b"203.0.113.66".as_slice(),
        b"203.0.113".as_slice(),
        b"198.51.100.42".as_slice(),
        b"198.51.100.200".as_slice(),
        b"12D3KooWBadActorPeerId".as_slice(),
        b"12D3KooWHonestPeerId".as_slice(),
    ] {
        assert!(
            !raw_index.windows(forbidden.len()).any(|w| w == forbidden),
            "CRITICAL PRIVACY VIOLATION: eviction_index.bin leaked plaintext identifier {:?}",
            String::from_utf8_lossy(forbidden)
        );
    }

    // Bad actor's regular shard is gone & future ingress blocked; honest user's shard is 100% intact!
    assert!(store_a.get_shard(&bad_shard_id).is_err());
    assert_eq!(store_a.get_shard(&honest_shard_id).unwrap(), honest_bytes);
    assert!(evict_a
        .is_ingress_blocked(Some(bad_ip), None, None, None, None)
        .is_some());
    assert!(evict_a
        .is_ingress_blocked(Some(honest_ip), None, None, None, None)
        .is_none());

    // Also verify explicit `PeerOrIssuerPubkey` cohort eviction purges `.bshard` blinded shards!
    let purge_cohort = evict_a
        .evict_target(
            &EvictionTarget::PeerOrIssuerPubkey(second_cohort_issuer.public_key_bytes()),
            &store_a,
        )
        .unwrap();
    assert_eq!(purge_cohort.purged_blinded_shards, 1);
    assert!(!store_a.has_blinded_shard_on_disk(&blinded_id_2));

    // =========================================================================
    // PART B & C: Live Public Tracker Swarm Governance, Anti-Griefing,
    //             Reporter Burden-of-Proof (`report-abuse` -> `approve-takedown`),
    //             Emergency Warrant Eviction, and Strict `PrivateRing` Isolation
    // =========================================================================
    let parvault_bin = env!("CARGO_BIN_EXE_parvault");
    let seed_bin = env!("CARGO_BIN_EXE_parvault-seed");

    let tracker_port = reserve_free_tcp_port();
    let pub_daemon_port = reserve_free_tcp_port();
    let priv_daemon_port = reserve_free_tcp_port();

    let tracker_maddr = format!("/ip4/127.0.0.1/tcp/{tracker_port}");
    let pub_daemon_maddr = format!("/ip4/127.0.0.1/tcp/{pub_daemon_port}");
    let priv_daemon_maddr = format!("/ip4/127.0.0.1/tcp/{priv_daemon_port}");

    let tracker_dir = base.join("gov_public_tracker");
    let pub_daemon_dir = base.join("gov_public_daemon");
    let priv_daemon_dir = base.join("gov_private_ring_daemon");
    fs::create_dir_all(&tracker_dir).unwrap();
    fs::create_dir_all(&pub_daemon_dir).unwrap();
    fs::create_dir_all(&priv_daemon_dir).unwrap();

    // Pre-generate tracker_admin.seed so we know its pubkey for assertions
    let tracker_admin_id = load_or_generate_tracker_admin_identity(&tracker_dir).unwrap();

    let mut guards = ChildGuard::new();
    guards.push(
        Command::new(seed_bin)
            .args([
                "start",
                "--mode",
                "public-bootstrap",
                "--no-lan-discovery",
                "--listen",
                &tracker_maddr,
                "--data-dir",
            ])
            .arg(&tracker_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gov public tracker"),
    );
    wait_for_tcp_port(tracker_port, Duration::from_secs(10));

    guards.push(
        Command::new(parvault_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
            .arg("--data-dir")
            .arg(&pub_daemon_dir)
            .args([
                "--no-lan-discovery",
                "--public",
                "--tracker",
                &tracker_maddr,
                "up",
                "--listen",
                &pub_daemon_maddr,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gov public daemon"),
    );

    guards.push(
        Command::new(parvault_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
            .arg("--data-dir")
            .arg(&priv_daemon_dir)
            .args([
                "--no-lan-discovery",
                "daemon",
                "start",
                "--listen",
                &priv_daemon_maddr,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn private ring daemon"),
    );

    wait_for_tcp_port(pub_daemon_port, Duration::from_secs(10));
    wait_for_tcp_port(priv_daemon_port, Duration::from_secs(10));

    // Wait for `pub_daemon` to register with `tracker_maddr` and pin `tracker_admin_pubkey`
    let probe_client = MeshClient::new(NodeIdentity::generate(), vec![], None);
    for _ in 0..30 {
        if let Ok(cards) = probe_client.announce_and_discover_public_tracker(&tracker_maddr, None) {
            if !cards.is_empty() {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }

    // Store an HONEST user's private file and an ILLEGAL leaked-capability file on `pub_daemon`
    let honest_client_dir = base.join("honest_public_user");
    let bad_client_dir = base.join("illegal_uploader");
    fs::create_dir_all(&honest_client_dir).unwrap();
    fs::create_dir_all(&bad_client_dir).unwrap();

    let honest_file_path = base.join("honest_family_tax_return.txt");
    fs::write(
        &honest_file_path,
        b"Honest user's private zero-knowledge encrypted tax return",
    )
    .unwrap();
    let honest_store_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
        .arg("--data-dir")
        .arg(&honest_client_dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "--tracker",
            &tracker_maddr,
            "file",
            "store",
            "--path",
        ])
        .arg(&honest_file_path)
        .output()
        .expect("store honest file");
    let honest_stdout = assert_cmd_ok(&honest_store_out, "store honest file");
    let honest_root_hex = extract_field_after_colon(&honest_stdout, "File Merkle Root");
    let honest_key_hex = extract_field_after_colon(&honest_stdout, "Master Key (hex)");

    let illegal_file_path = base.join("leaked_contraband.bin");
    fs::write(
        &illegal_file_path,
        b"Simulated publicly-shared contraband payload with leaked capability key",
    )
    .unwrap();
    let illegal_store_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
        .arg("--data-dir")
        .arg(&bad_client_dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "--tracker",
            &tracker_maddr,
            "file",
            "store",
            "--path",
        ])
        .arg(&illegal_file_path)
        .output()
        .expect("store illegal file");
    let illegal_stdout = assert_cmd_ok(&illegal_store_out, "store illegal file");
    let illegal_root_hex = extract_field_after_colon(&illegal_stdout, "File Merkle Root");
    let illegal_key_hex = extract_field_after_colon(&illegal_stdout, "Master Key (hex)");
    let illegal_manifest_path = bad_client_dir
        .join("manifests")
        .join(format!("{illegal_root_hex}.manifest.bin"));
    assert!(illegal_manifest_path.is_file());

    // Load honest manifest so a griefer can try to frame it with a guessed key
    let honest_mk = MasterKey::from_hex(&honest_key_hex).unwrap();
    let honest_raw_manifest = fs::read(
        honest_client_dir
            .join("manifests")
            .join(format!("{honest_root_hex}.manifest.bin")),
    )
    .unwrap();
    let honest_manifest = parvault::storage::FileManifest::from_encrypted_dht_record(
        &honest_mk,
        &honest_raw_manifest,
    )
    .unwrap();
    let honest_stripe0_root = honest_manifest.stripes[0].stripe_merkle_root;

    // 1. INVARIANT (a): Random `--public` peer attempting `BroadcastEvictionOrder` MUST BE REJECTED!
    let random_griefer = NodeIdentity::generate();
    let griefer_client = MeshClient::new(random_griefer.clone(), vec![], None);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let forged_evict_order = SignedBadActorEvictionOrder::issue(
        &random_griefer,
        EvictionTarget::StripeMerkleRoot(honest_stripe0_root),
        "griefer-trying-to-delete-honest-data",
        now_ms,
        0,
    );
    let griefer_evict_res =
        griefer_client.broadcast_eviction_order(&pub_daemon_maddr, forged_evict_order);
    assert!(
        griefer_evict_res.is_err(),
        "Random --public peer MUST NOT be permitted to evict anyone's shards: {griefer_evict_res:?}"
    );

    // 2. INVARIANT (c): `PrivateRing` daemon MUST REJECT a Public Tracker Admin's eviction order!
    let admin_order_against_private = SignedBadActorEvictionOrder::issue(
        &tracker_admin_id,
        EvictionTarget::IpAddress(bad_ip),
        "public-tracker-admin-order",
        now_ms,
        0,
    );
    let priv_res =
        griefer_client.broadcast_eviction_order(&priv_daemon_maddr, admin_order_against_private);
    assert!(
        priv_res.is_err(),
        "PrivateRing node MUST reject external Public Tracker Admin eviction orders: {priv_res:?}"
    );

    // 3. Griefer framing attempt with wrong `MasterKey` MUST fail cryptographic burden-of-proof!
    let honest_sample_shards: Vec<(u32, Vec<u8>)> =
        (0..honest_manifest.stripes[0].shard_hashes.len())
            .filter_map(|idx| {
                let sid = ShardId {
                    stripe_merkle_root: honest_stripe0_root,
                    shard_index: idx as u32,
                    shard_hash: honest_manifest.stripes[0].shard_hashes[idx],
                };
                let rel = format!("{}.shard", sid.file_key());
                fs::read(pub_daemon_dir.join("shards").join(&rel))
                    .or_else(|_| fs::read(honest_client_dir.join("shards").join(&rel)))
                    .ok()
                    .map(|b| (idx as u32, b))
            })
            .take(honest_manifest.stripes[0].k_data)
            .collect();
    assert_eq!(
        honest_sample_shards.len(),
        honest_manifest.stripes[0].k_data,
        "must collect k_data sample shards for framing burden-of-proof test"
    );
    let wrong_guessed_key = MasterKey::generate().to_hex();
    let framing_report = VerifiableAbuseReport::submit_signed(
        &random_griefer,
        "malicious-framer@example.org",
        "false framing attempt without real decryption key",
        None,
        honest_manifest.clone(),
        wrong_guessed_key,
        0,
        honest_sample_shards,
        now_ms,
    );
    assert!(
        framing_report
            .verify_cryptographic_burden_of_proof()
            .is_err(),
        "AES-256-GCM tag verification MUST defeat wrong-key framing report"
    );
    assert!(
        griefer_client
            .submit_abuse_takedown_report(&tracker_maddr, framing_report)
            .is_err(),
        "Live Public Tracker MUST reject unverified framing report"
    );

    // 4. Legitimate reporter submits `parvault report-abuse` with leaked capability -> queues as PendingAdminReview!
    let reporter_dir = base.join("legit_reporter");
    fs::create_dir_all(&reporter_dir).unwrap();
    let report_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
        .arg("--data-dir")
        .arg(&reporter_dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "--tracker",
            &tracker_maddr,
            "report-abuse",
            "--manifest",
        ])
        .arg(&illegal_manifest_path)
        .args([
            "--disclosed-key-hex",
            &illegal_key_hex,
            "--allegation",
            "Verified illegal contraband share link",
            "--contact",
            "trust-safety@example.org",
            "--bad-actor-ip",
            "203.0.113.66",
        ])
        .output()
        .expect("run parvault report-abuse");
    let report_stdout = assert_cmd_ok(&report_out, "parvault report-abuse");
    assert!(report_stdout.contains("PendingAdminReview"));
    let report_id_hex = extract_field_after_colon(&report_stdout, "Report ID");

    // Verify queued as PendingAdminReview AND illegal file is NOT auto-evicted before admin review!
    let queue_before = PublicTrackerTakedownQueue::load_or_init(&tracker_dir).unwrap();
    let entries_before = queue_before.list_entries();
    assert_eq!(entries_before.len(), 1);
    assert!(matches!(
        entries_before[0].status,
        TakedownReviewStatus::PendingAdminReview
    ));

    // Wipe local uploader shards so restore checks `pub_daemon` directly
    fs::remove_dir_all(&bad_client_dir).unwrap();
    fs::remove_dir_all(&honest_client_dir).unwrap();

    let pre_approval_check_dir = base.join("pre_approval_check");
    fs::create_dir_all(&pre_approval_check_dir).unwrap();
    let pre_check_file = base.join("pre_check.bin");
    let pre_restore = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
        .arg("--data-dir")
        .arg(&pre_approval_check_dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "--tracker",
            &tracker_maddr,
            "file",
            "restore",
            &illegal_root_hex,
            "--output",
        ])
        .arg(&pre_check_file)
        .args(["--key-hex", &illegal_key_hex])
        .output()
        .expect("restore before admin approval");
    assert_cmd_ok(
        &pre_restore,
        "shards must remain intact while PendingAdminReview",
    );
    fs::remove_dir_all(&pre_approval_check_dir).unwrap();

    // 5. Public Tracker Admin approves takedown (`approve-takedown --propagate`) -> purges across swarm!
    let approve_out = Command::new(seed_bin)
        .args([
            "--peers",
            &pub_daemon_maddr,
            "admin",
            "approve-takedown",
            "--data-dir",
        ])
        .arg(&tracker_dir)
        .args([
            "--report-id",
            &report_id_hex,
            "--note",
            "Confirmed hash match; approved for swarm purge",
            "--propagate",
        ])
        .output()
        .expect("run parvault-seed admin approve-takedown");
    let approve_stdout = assert_cmd_ok(&approve_out, "admin approve-takedown");
    assert!(
        approve_stdout.contains("Approved") || approve_stdout.contains("approve"),
        "Expected approval confirmation in:\n{approve_stdout}"
    );

    // Illegal file MUST now fail to restore from the public swarm (`0x00`-shredded)!
    let post_approval_dir = base.join("post_approval_check");
    fs::create_dir_all(&post_approval_dir).unwrap();
    let post_check_file = base.join("post_check.bin");
    let post_restore = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
        .arg("--data-dir")
        .arg(&post_approval_dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "--tracker",
            &tracker_maddr,
            "file",
            "restore",
            &illegal_root_hex,
            "--output",
        ])
        .arg(&post_check_file)
        .args(["--key-hex", &illegal_key_hex])
        .output()
        .expect("restore after admin takedown");
    assert!(
        !post_restore.status.success(),
        "Evicted illegal content MUST NOT be restorable after Public Tracker Admin approval!"
    );

    // Meanwhile, HONEST user's private file on the exact same `--public` swarm MUST still restore 100%!
    let honest_verify_dir = base.join("honest_verify_after_takedown");
    fs::create_dir_all(&honest_verify_dir).unwrap();
    let honest_restored_path = base.join("honest_restored.txt");
    let honest_restore = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
        .arg("--data-dir")
        .arg(&honest_verify_dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "--tracker",
            &tracker_maddr,
            "file",
            "restore",
            &honest_root_hex,
            "--output",
        ])
        .arg(&honest_restored_path)
        .args(["--key-hex", &honest_key_hex])
        .output()
        .expect("restore honest file after takedown");
    assert_cmd_ok(&honest_restore, "honest file must remain 100% intact");
    assert_eq!(
        fs::read(&honest_restored_path).unwrap(),
        b"Honest user's private zero-knowledge encrypted tax return"
    );

    // 6. Verify `emergency-evict --warrant-ref` works on Public Tracker AND is hard-rejected on `homelab-vault`!
    let homelab_seed_dir = base.join("private_homelab_seed");
    fs::create_dir_all(&homelab_seed_dir).unwrap();
    // Initialize homelab-vault marker via `status --mode homelab-vault` or `start --mode homelab-vault --once`
    let hl_once = Command::new(seed_bin)
        .args([
            "start",
            "--mode",
            "homelab-vault",
            "--no-lan-discovery",
            "--listen",
            &format!("/ip4/127.0.0.1/tcp/{}", reserve_free_tcp_port()),
            "--once",
            "--data-dir",
        ])
        .arg(&homelab_seed_dir)
        .output()
        .expect("init homelab-vault seed");
    assert_cmd_ok(&hl_once, "homelab-vault --once");

    let forbidden_emergency = Command::new(seed_bin)
        .args(["admin", "emergency-evict", "--data-dir"])
        .arg(&homelab_seed_dir)
        .args(["--ip", "203.0.113.99", "--warrant-ref", "SHOULD-FAIL"])
        .output()
        .expect("attempt emergency-evict on homelab-vault");
    assert!(
        !forbidden_emergency.status.success(),
        "homelab-vault seed MUST refuse Public Tracker Admin emergency-evict!"
    );

    let ok_emergency = Command::new(seed_bin)
        .args([
            "--peers",
            &pub_daemon_maddr,
            "admin",
            "emergency-evict",
            "--data-dir",
        ])
        .arg(&tracker_dir)
        .args([
            "--ip",
            "203.0.113.66",
            "--warrant-ref",
            "NCMEC-WARRANT-2026-001",
            "--propagate",
        ])
        .output()
        .expect("emergency-evict on public-bootstrap tracker");
    assert_cmd_ok(&ok_emergency, "public-bootstrap emergency-evict");

    // Verify pub_daemon's `eviction_index.bin` ALSO contains zero plaintext IP strings after propagated warrant!
    let pub_daemon_idx = fs::read(pub_daemon_dir.join("eviction_index.bin")).unwrap();
    assert!(
        !pub_daemon_idx
            .windows(b"203.0.113.66".len())
            .any(|w| w == b"203.0.113.66"),
        "Propagated IP warrant must never write plaintext IP into storage daemon's eviction_index.bin"
    );

    // =========================================================================
    // PART D: `2-of-3` Federated Public Tracker Operator Council Quorum
    //         (`TrackerOperatorCosignature` + `parvault-seed admin cosign-eviction`)
    // =========================================================================
    let op1_dir = base.join("council_op1");
    let op2_dir = base.join("council_op2");
    let op3_dir = base.join("council_op3");
    let rogue4_dir = base.join("unvetted_rogue_tracker4");
    for d in [&op1_dir, &op2_dir, &op3_dir, &rogue4_dir] {
        fs::create_dir_all(d).unwrap();
    }
    let op1_id = load_or_generate_tracker_admin_identity(&op1_dir).unwrap();
    let op2_id = load_or_generate_tracker_admin_identity(&op2_dir).unwrap();
    let op3_id = load_or_generate_tracker_admin_identity(&op3_dir).unwrap();
    let rogue4_id = load_or_generate_tracker_admin_identity(&rogue4_dir).unwrap();

    // Spin up a live `--public` storage daemon pinned to the 3-operator council (`2-of-3` majority quorum!)
    let council_daemon_port = reserve_free_tcp_port();
    let council_daemon_maddr = format!("/ip4/127.0.0.1/tcp/{council_daemon_port}");
    let council_daemon_dir = base.join("council_guarded_daemon");
    fs::create_dir_all(&council_daemon_dir).unwrap();

    let mut council_cfg = NodeConfig {
        data_dir: council_daemon_dir.clone(),
        listen_tcp: council_daemon_maddr.clone(),
        lan_discovery_enabled: false,
        trust_mode: TrustPoolMode::PublicCommons,
        eviction_authorities: vec![
            hex::encode(op1_id.public_key_bytes()),
            hex::encode(op2_id.public_key_bytes()),
            hex::encode(op3_id.public_key_bytes()),
        ],
        tracker_eviction_quorum: None, // Automatic `default_tracker_quorum_threshold(3)` == 2!
        ..NodeConfig::default()
    };
    council_cfg.min_free_disk_bytes = 64 * 1024 * 1024;
    let council_cfg_path = council_daemon_dir.join("config.toml");
    fs::write(
        &council_cfg_path,
        toml::to_string_pretty(&council_cfg).unwrap(),
    )
    .unwrap();

    guards.push(
        Command::new(parvault_bin)
            .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
            .arg("--config")
            .arg(&council_cfg_path)
            .arg("--data-dir")
            .arg(&council_daemon_dir)
            .args([
                "--no-lan-discovery",
                "--public",
                "daemon",
                "start",
                "--listen",
                &council_daemon_maddr,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn 2-of-3 council daemon"),
    );
    wait_for_tcp_port(council_daemon_port, Duration::from_secs(10));

    // Store a target stripe on `council_daemon`
    let council_uploader_dir = base.join("council_uploader");
    fs::create_dir_all(&council_uploader_dir).unwrap();
    let target_file = base.join("council_target.bin");
    fs::write(&target_file, vec![0x5Au8; 64 * 1024]).unwrap();

    let c_store_out = Command::new(parvault_bin)
        .env("PARVAULT_LAN_REGISTRY_DIR", &empty_lan)
        .arg("--data-dir")
        .arg(&council_uploader_dir)
        .args([
            "--no-lan-discovery",
            "--public",
            "--peers",
            &council_daemon_maddr,
            "file",
            "store",
            "--path",
        ])
        .arg(&target_file)
        .output()
        .expect("store file on council daemon");
    let c_store_stdout = assert_cmd_ok(&c_store_out, "store on council daemon");
    let c_root_hex = extract_field_after_colon(&c_store_stdout, "File Merkle Root");
    let c_key_hex = extract_field_after_colon(&c_store_stdout, "Master Key (hex)");
    let c_mk = MasterKey::from_hex(&c_key_hex).unwrap();
    let c_manifest = parvault::storage::FileManifest::from_encrypted_dht_record(
        &c_mk,
        &fs::read(
            council_uploader_dir
                .join("manifests")
                .join(format!("{c_root_hex}.manifest.bin")),
        )
        .unwrap(),
    )
    .unwrap();
    let target_stripe_root = c_manifest.stripes[0].stripe_merkle_root;

    let count_council_shards = || -> usize {
        fs::read_dir(council_daemon_dir.join("shards"))
            .ok()
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("shard"))
                    .count()
            })
            .unwrap_or(0)
    };
    let shards_initial = count_council_shards();
    assert!(shards_initial >= 10);

    // (1) Unvetted 4th rogue tracker host (`0-of-3` council votes) MUST be rejected!
    let rogue_order = SignedBadActorEvictionOrder::issue(
        &rogue4_id,
        EvictionTarget::StripeMerkleRoot(target_stripe_root),
        "unvetted-rogue-tracker-wipe",
        now_ms,
        0,
    );
    assert!(
        probe_client
            .broadcast_eviction_order(&council_daemon_maddr, rogue_order)
            .is_err(),
        "Unvetted 4th tracker MUST have zero eviction authority"
    );
    assert_eq!(count_council_shards(), shards_initial);

    // (2) Single rogue council member `op1` (`1-of-3` votes < `2-of-3` quorum) MUST be rejected!
    let exported_order_path = base.join("op1_proposal.order.json");
    let op1_export = Command::new(seed_bin)
        .args(["admin", "emergency-evict", "--data-dir"])
        .arg(&op1_dir)
        .args([
            "--merkle-root",
            &hex::encode(target_stripe_root),
            "--warrant-ref",
            "COUNCIL-PROPOSAL-42",
            "--export-order",
        ])
        .arg(&exported_order_path)
        .output()
        .expect("op1 export 1-of-3 order");
    assert_cmd_ok(&op1_export, "op1 export order");

    // Try broadcasting the `1-of-3` order directly to `council_daemon` -> MUST fail quorum!
    let raw_exported = fs::read_to_string(&exported_order_path).unwrap();
    let single_sig_order: SignedBadActorEvictionOrder = if let Ok(vec_orders) =
        serde_json::from_str::<Vec<SignedBadActorEvictionOrder>>(&raw_exported)
    {
        vec_orders
            .into_iter()
            .next()
            .expect("non-empty exported orders")
    } else {
        serde_json::from_str(&raw_exported).expect("parse exported SignedBadActorEvictionOrder")
    };
    assert_eq!(
        single_sig_order.valid_council_signer_count(&[
            op1_id.public_key_bytes(),
            op2_id.public_key_bytes(),
            op3_id.public_key_bytes(),
        ]),
        1
    );
    assert!(
        probe_client
            .broadcast_eviction_order(&council_daemon_maddr, single_sig_order)
            .is_err(),
        "1-of-3 single council operator MUST NOT be able to unilaterally wipe shards!"
    );
    assert_eq!(
        count_council_shards(),
        shards_initial,
        "Shards must remain 100% untouched after rejected 1-of-3 order"
    );

    // (3) Independent 2nd council operator `op2` co-signs & propagates (`2-of-3` quorum met!) -> PURGED!
    let op2_cosign = Command::new(seed_bin)
        .args([
            "--peers",
            &council_daemon_maddr,
            "admin",
            "cosign-eviction",
            "--data-dir",
        ])
        .arg(&op2_dir)
        .arg("--order-file")
        .arg(&exported_order_path)
        .arg("--propagate")
        .output()
        .expect("op2 cosign-eviction --propagate");
    assert_cmd_ok(&op2_cosign, "op2 2-of-3 cosign-eviction");
    assert_eq!(
        count_council_shards(),
        0,
        "2-of-3 co-signed council order MUST zero-shred all targeted shards on council_daemon!"
    );

    drop(guards);
    let _ = fs::remove_dir_all(&base);
}
