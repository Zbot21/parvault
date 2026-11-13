use crate::crypto::{NodeIdentity, BIP39_ENGLISH_WORDLIST};
use hkdf::Hkdf;
use libp2p::{identity, multiaddr::Protocol, Multiaddr, PeerId};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Default UDP port for Zero-IP Home Network Auto-Discovery (`ADR-22`).
pub const DEFAULT_LAN_DISCOVERY_PORT: u16 = 4009;

/// Administratively scoped IPv4 multicast group (`239.255.80.86`, ASCII `'P','V'`) for LAN discovery.
pub const LAN_MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 80, 86);

/// String form of `LAN_MULTICAST_GROUP` (`"239.255.80.86"`).
pub const LAN_MULTICAST_ADDR_STR: &str = "239.255.80.86";

/// Active UDP discovery probe payload sent by `discover_lan_peers`.
pub const LAN_DISCOVER_PROBE_MAGIC: &[u8] = b"PARVAULT-DISCOVER-V1";

/// Cryptographic domain separation prefix for `Ed25519` `LanBeaconPacket` signatures.
pub const LAN_BEACON_SIGNING_DOMAIN: &[u8] = b"parvault-lan-beacon-v1:";

/// Optional environment variable pointing to a shared ephemeral directory for localhost /
/// isolated-container `<libp2p_peer_id>.beacon` fallback discovery.
pub const LAN_REGISTRY_ENV_VAR: &str = "PARVAULT_LAN_REGISTRY_DIR";

/// Maximum acceptable age / clock skew (`15s`) for signed LAN discovery beacons.
pub const MAX_LAN_BEACON_AGE_MS: u64 = 15_000;

/// Maximum serialized `LanBeaconPacket` wire size accepted from UDP or registry files (`4 KiB`).
const MAX_BEACON_WIRE_BYTES: usize = 4096;

/// Default deterministic pairing nonce used when deriving a node's standing 4-word SAS code.
pub const DEFAULT_LAN_PAIRING_NONCE: &[u8] = b"parvault-default-lan-sas-v1";

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn write_len_prefixed_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn normalize_optional_str(opt: Option<&str>) -> Option<String> {
    opt.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_explicit_listen_ip(opt: Option<&str>) -> Option<String> {
    let trimmed = opt.map(str::trim).filter(|s| !s.is_empty())?;
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        if ip.is_unspecified() {
            return None;
        }
        return Some(ip.to_string());
    }
    None
}

/// Derives the canonical `libp2p::PeerId` from a raw 32-byte `Ed25519` public key.
pub fn derive_libp2p_peer_id_from_ed25519_pubkey(
    ed25519_pubkey: &[u8; 32],
) -> anyhow::Result<PeerId> {
    let ed_pub = identity::ed25519::PublicKey::try_from_bytes(ed25519_pubkey)
        .map_err(|e| anyhow::anyhow!("invalid Ed25519 public key bytes: {e}"))?;
    Ok(identity::PublicKey::from(ed_pub).to_peer_id())
}

/// Derives the canonical `libp2p::PeerId` corresponding to a `NodeIdentity`.
pub fn node_identity_libp2p_peer_id(identity: &NodeIdentity) -> anyhow::Result<PeerId> {
    derive_libp2p_peer_id_from_ed25519_pubkey(&identity.public_key_bytes())
}

/// Extracts `(tcp_listen_port, explicit_listen_ip)` from a `libp2p::Multiaddr`.
/// Unspecified addresses (`0.0.0.0`, `::`) normalize `explicit_listen_ip` to `None` so LAN
/// peers automatically bind the observed source IP of the UDP beacon datagram.
pub fn extract_listen_port_and_ip(listen_maddr: &Multiaddr) -> Option<(u16, Option<String>)> {
    let mut ip_str: Option<String> = None;
    let mut tcp_port: Option<u16> = None;
    for proto in listen_maddr.iter() {
        match proto {
            Protocol::Ip4(v4) => {
                if !v4.is_unspecified() {
                    ip_str = Some(v4.to_string());
                }
            }
            Protocol::Ip6(v6) => {
                if !v6.is_unspecified() {
                    ip_str = Some(v6.to_string());
                }
            }
            Protocol::Tcp(port) => {
                tcp_port = Some(port);
            }
            _ => {}
        }
    }
    tcp_port.map(|port| (port, ip_str))
}

/// Cryptographically signed LAN discovery beacon packet (`Ed25519` over `"parvault-lan-beacon-v1:"`).
///
/// Binds `libp2p_peer_id` directly to `ed25519_pubkey` so no attacker on a shared home/office Wi-Fi
/// or router bridge can spoof another node's `PeerId`, redirect traffic to an unauthenticated port,
/// or forge a 4-word SAS pairing commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanBeaconPacket {
    pub libp2p_peer_id: String,
    pub device_peer_id: String,
    pub node_label: String,
    pub role: String,
    pub tcp_listen_port: u16,
    pub explicit_listen_ip: Option<String>,
    pub available_bytes: u64,
    pub timestamp_ms: u64,
    pub ed25519_pubkey: [u8; 32],
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
    pub owner_pq_fingerprint: Option<String>,
    pub pairing_sas_commitment: Option<[u8; 32]>,
}

/// Optional endpoint & SAS pairing metadata attached when signing a [`LanBeaconPacket`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LanBeaconOptions<'a> {
    pub explicit_listen_ip: Option<&'a str>,
    pub owner_pq_fingerprint: Option<&'a str>,
    pub pairing_sas_commitment: Option<[u8; 32]>,
}

/// What a LAN beacon check knows (ADR-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconFacts {
    /// Non-zero port, bounded label and role, a specified explicit IP if any.
    pub well_formed: bool,
    /// `libp2p_peer_id` and `device_peer_id` are derived from the signing key.
    pub identity_bound: bool,
    /// Signed within `MAX_LAN_BEACON_AGE_MS` (the replay window).
    pub fresh: bool,
    pub sig_valid: bool,
}

/// ADR-22: a LAN beacon is recorded only if it is well formed, names the identity of its own
/// key (no spoofed peer id), is fresh, and is signed by that key.
pub fn beacon_decision(f: &BeaconFacts) -> Result<(), &'static str> {
    if !f.well_formed {
        return Err("reject.beacon_malformed");
    }
    if !f.identity_bound {
        return Err("reject.beacon_spoofed");
    }
    if !f.fresh {
        return Err("reject.beacon_stale");
    }
    if !f.sig_valid {
        return Err("reject.beacon_sig_invalid");
    }
    Ok(())
}

impl LanBeaconPacket {
    pub fn sign_new(
        identity: &NodeIdentity,
        node_label: &str,
        role: &str,
        tcp_listen_port: u16,
        available_bytes: u64,
        timestamp_ms: u64,
        options: LanBeaconOptions<'_>,
    ) -> anyhow::Result<Self> {
        let ed25519_pubkey = identity.public_key_bytes();
        let peer_id = derive_libp2p_peer_id_from_ed25519_pubkey(&ed25519_pubkey)?;
        let mut pkt = Self {
            libp2p_peer_id: peer_id.to_string(),
            device_peer_id: identity.device_peer_id(),
            node_label: node_label.trim().to_string(),
            role: role.trim().to_string(),
            tcp_listen_port,
            explicit_listen_ip: normalize_explicit_listen_ip(options.explicit_listen_ip),
            available_bytes,
            timestamp_ms,
            ed25519_pubkey,
            sig_r: [0u8; 32],
            sig_s: [0u8; 32],
            owner_pq_fingerprint: normalize_optional_str(options.owner_pq_fingerprint),
            pairing_sas_commitment: options.pairing_sas_commitment,
        };
        let preimage = pkt.canonical_signing_bytes();
        let sig = identity.sign(&preimage);
        pkt.sig_r.copy_from_slice(&sig[..32]);
        pkt.sig_s.copy_from_slice(&sig[32..64]);
        Ok(pkt)
    }

    /// Length-prefixed canonical byte preimage under `"parvault-lan-beacon-v1:"`.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(LAN_BEACON_SIGNING_DOMAIN);
        write_len_prefixed_bytes(&mut buf, self.libp2p_peer_id.as_bytes());
        write_len_prefixed_bytes(&mut buf, self.device_peer_id.as_bytes());
        write_len_prefixed_bytes(&mut buf, self.node_label.as_bytes());
        write_len_prefixed_bytes(&mut buf, self.role.as_bytes());
        buf.extend_from_slice(&self.tcp_listen_port.to_be_bytes());
        match &self.explicit_listen_ip {
            Some(ip) => {
                buf.push(1);
                write_len_prefixed_bytes(&mut buf, ip.as_bytes());
            }
            None => buf.push(0),
        }
        buf.extend_from_slice(&self.available_bytes.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        buf.extend_from_slice(&self.ed25519_pubkey);
        match &self.owner_pq_fingerprint {
            Some(fp) => {
                buf.push(1);
                write_len_prefixed_bytes(&mut buf, fp.as_bytes());
            }
            None => buf.push(0),
        }
        match &self.pairing_sas_commitment {
            Some(commit) => {
                buf.push(1);
                buf.extend_from_slice(commit);
            }
            None => buf.push(0),
        }
        buf
    }

    /// Verifies:
    /// 1. Non-zero `tcp_listen_port`,
    /// 2. `libp2p_peer_id` and `device_peer_id` cryptographically match `ed25519_pubkey`,
    /// 3. Timestamp freshness within `max_age_ms` (`<= 15s` replay window),
    /// 4. Domain-separated `Ed25519` signature validity over all beacon fields.
    pub fn verify(&self, now_ms: u64, max_age_ms: u64) -> anyhow::Result<PeerId> {
        let well_formed = self.tcp_listen_port != 0
            && self.node_label.len() <= 128
            && self.role.len() <= 64
            && self.explicit_listen_ip.as_deref().is_none_or(|ip| {
                ip.parse::<IpAddr>()
                    .is_ok_and(|parsed| !parsed.is_unspecified())
            });
        let expected_peer_id = derive_libp2p_peer_id_from_ed25519_pubkey(&self.ed25519_pubkey).ok();
        let expected_device_id =
            format!("parvault-peer-{}", &hex::encode(self.ed25519_pubkey)[..16]);
        let identity_bound = expected_peer_id.is_some_and(|pid| {
            self.libp2p_peer_id
                .parse::<PeerId>()
                .is_ok_and(|claimed| claimed == pid)
                && self.libp2p_peer_id == pid.to_string()
        }) && self.device_peer_id == expected_device_id;
        let mut sig64 = [0u8; 64];
        sig64[..32].copy_from_slice(&self.sig_r);
        sig64[32..64].copy_from_slice(&self.sig_s);
        let facts = BeaconFacts {
            well_formed,
            identity_bound,
            fresh: now_ms.abs_diff(self.timestamp_ms) <= max_age_ms,
            sig_valid: NodeIdentity::verify_with_pubkey(
                &self.ed25519_pubkey,
                &self.canonical_signing_bytes(),
                &sig64,
            ),
        };
        match (beacon_decision(&facts), expected_peer_id) {
            (Ok(()), Some(pid)) => Ok(pid),
            (Err(code), _) => {
                tracing::warn!(code, peer = %self.libp2p_peer_id, "ignored a LAN beacon");
                anyhow::bail!("LAN beacon rejected: {code}")
            }
            (Ok(()), None) => anyhow::bail!("LAN beacon rejected: no peer id"),
        }
    }

    /// Verifies the packet against the current wall-clock time using `MAX_LAN_BEACON_AGE_MS` (`15s`).
    pub fn verify_now(&self) -> anyhow::Result<PeerId> {
        self.verify(current_unix_ms(), MAX_LAN_BEACON_AGE_MS)
    }

    pub fn to_wire_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BEACON_WIRE_BYTES {
            anyhow::bail!(
                "invalid LanBeaconPacket byte length {} (max {})",
                bytes.len(),
                MAX_BEACON_WIRE_BYTES
            );
        }
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// Verified LAN peer discovered via UDP broadcast/multicast or `PARVAULT_LAN_REGISTRY_DIR`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredLanPeer {
    pub libp2p_peer_id: String,
    pub device_peer_id: String,
    pub node_label: String,
    pub role: String,
    pub source_ip: String,
    pub tcp_listen_port: u16,
    /// Cryptographically pinned `/ip4/<ip>/tcp/<port>/p2p/<libp2p_peer_id>` (or `/ip6/...`) Multiaddr.
    pub multiaddr: String,
    pub available_bytes: u64,
    pub timestamp_ms: u64,
    pub ed25519_pubkey: [u8; 32],
    pub owner_pq_fingerprint: Option<String>,
    pub pairing_sas_commitment: Option<[u8; 32]>,
}

impl DiscoveredLanPeer {
    fn from_verified_packet(pkt: LanBeaconPacket, resolved_ip: IpAddr) -> Self {
        let source_ip = resolved_ip.to_string();
        let multiaddr = match resolved_ip {
            IpAddr::V4(v4) => format!(
                "/ip4/{v4}/tcp/{}/p2p/{}",
                pkt.tcp_listen_port, pkt.libp2p_peer_id
            ),
            IpAddr::V6(v6) => format!(
                "/ip6/{v6}/tcp/{}/p2p/{}",
                pkt.tcp_listen_port, pkt.libp2p_peer_id
            ),
        };
        Self {
            libp2p_peer_id: pkt.libp2p_peer_id,
            device_peer_id: pkt.device_peer_id,
            node_label: pkt.node_label,
            role: pkt.role,
            source_ip,
            tcp_listen_port: pkt.tcp_listen_port,
            multiaddr,
            available_bytes: pkt.available_bytes,
            timestamp_ms: pkt.timestamp_ms,
            ed25519_pubkey: pkt.ed25519_pubkey,
            owner_pq_fingerprint: pkt.owner_pq_fingerprint,
            pairing_sas_commitment: pkt.pairing_sas_commitment,
        }
    }
}

/// Configuration for `LanBeaconResponder`.
#[derive(Debug, Clone)]
pub struct LanBeaconConfig {
    pub discovery_port: u16,
    pub node_label: String,
    pub role: String,
    pub tcp_listen_port: u16,
    pub explicit_listen_ip: Option<String>,
    pub available_bytes: u64,
    pub owner_pq_fingerprint: Option<String>,
    pub pairing_sas_commitment: Option<[u8; 32]>,
}

impl LanBeaconConfig {
    pub fn new(
        node_label: impl Into<String>,
        role: impl Into<String>,
        tcp_listen_port: u16,
    ) -> Self {
        Self {
            discovery_port: DEFAULT_LAN_DISCOVERY_PORT,
            node_label: node_label.into(),
            role: role.into(),
            tcp_listen_port,
            explicit_listen_ip: None,
            available_bytes: 0,
            owner_pq_fingerprint: None,
            pairing_sas_commitment: None,
        }
    }

    pub fn with_discovery_port(mut self, discovery_port: u16) -> Self {
        self.discovery_port = discovery_port;
        self
    }

    pub fn with_explicit_listen_ip(mut self, explicit_listen_ip: Option<String>) -> Self {
        self.explicit_listen_ip = normalize_explicit_listen_ip(explicit_listen_ip.as_deref());
        self
    }

    pub fn with_listen_multiaddr(mut self, listen_maddr: &Multiaddr) -> Self {
        if let Some((port, ip)) = extract_listen_port_and_ip(listen_maddr) {
            self.tcp_listen_port = port;
            self.explicit_listen_ip = ip;
        }
        self
    }

    pub fn with_available_bytes(mut self, available_bytes: u64) -> Self {
        self.available_bytes = available_bytes;
        self
    }

    pub fn with_owner_pq_fingerprint(mut self, owner_pq_fingerprint: Option<String>) -> Self {
        self.owner_pq_fingerprint = normalize_optional_str(owner_pq_fingerprint.as_deref());
        self
    }

    pub fn with_pairing_sas_commitment(mut self, pairing_sas_commitment: Option<[u8; 32]>) -> Self {
        self.pairing_sas_commitment = pairing_sas_commitment;
        self
    }
}

#[derive(Debug, Clone)]
struct LiveBeaconState {
    node_label: String,
    role: String,
    tcp_listen_port: u16,
    explicit_listen_ip: Option<String>,
    available_bytes: u64,
    owner_pq_fingerprint: Option<String>,
    pairing_sas_commitment: Option<[u8; 32]>,
}

impl LiveBeaconState {
    fn sign_packet(&self, identity: &NodeIdentity) -> anyhow::Result<LanBeaconPacket> {
        LanBeaconPacket::sign_new(
            identity,
            &self.node_label,
            &self.role,
            self.tcp_listen_port,
            self.available_bytes,
            current_unix_ms(),
            LanBeaconOptions {
                explicit_listen_ip: self.explicit_listen_ip.as_deref(),
                owner_pq_fingerprint: self.owner_pq_fingerprint.as_deref(),
                pairing_sas_commitment: self.pairing_sas_commitment,
            },
        )
    }
}

fn active_registry_dir() -> Option<PathBuf> {
    std::env::var(LAN_REGISTRY_ENV_VAR)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

fn write_registry_beacon_atomic(dir: &Path, pkt: &LanBeaconPacket) -> anyhow::Result<()> {
    if pkt.tcp_listen_port == 0 {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    let bytes = pkt.to_wire_bytes()?;
    let mut nonce = [0u8; 6];
    OsRng.fill_bytes(&mut nonce);
    let final_path = dir.join(format!("{}.beacon", pkt.libp2p_peer_id));
    let tmp_path = dir.join(format!(
        ".tmp.{}.{}.beacon",
        pkt.libp2p_peer_id,
        hex::encode(nonce)
    ));
    let mut file = std::fs::File::create(&tmp_path)?;
    file.write_all(&bytes)?;
    file.flush()?;
    drop(file);
    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    Ok(())
}

fn remove_registry_beacon_if_matching_port(dir: &Path, peer_id: &str, expected_port: u16) {
    let path = dir.join(format!("{peer_id}.beacon"));
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(existing) = LanBeaconPacket::from_wire_bytes(&bytes) {
            if existing.tcp_listen_port == expected_port {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Determines the primary outbound LAN IPv4 address via a zero-packet OS kernel routing lookup.
pub fn detect_primary_lan_ipv4() -> Option<Ipv4Addr> {
    for probe_target in [
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), DEFAULT_LAN_DISCOVERY_PORT),
        SocketAddrV4::new(Ipv4Addr::new(10, 255, 255, 254), DEFAULT_LAN_DISCOVERY_PORT),
        SocketAddrV4::new(Ipv4Addr::new(172, 28, 0, 1), DEFAULT_LAN_DISCOVERY_PORT),
    ] {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(probe_target).is_ok() {
                if let Ok(SocketAddr::V4(local)) = sock.local_addr() {
                    let ip = *local.ip();
                    if !ip.is_unspecified() && !ip.is_loopback() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

#[cfg(unix)]
fn bind_reusable_udp_v4(port: u16) -> std::io::Result<UdpSocket> {
    crate::os_sys::bind_reusable_udp_v4(port)
}

#[cfg(not(unix))]
fn bind_reusable_udp_v4(port: u16) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
}

fn configure_discovery_socket(sock: &UdpSocket) {
    let _ = sock.set_broadcast(true);
    let _ = sock.set_multicast_loop_v4(true);
    let _ = sock.join_multicast_v4(&LAN_MULTICAST_GROUP, &Ipv4Addr::UNSPECIFIED);
    if let Some(lan_ip) = detect_primary_lan_ipv4() {
        let _ = sock.join_multicast_v4(&LAN_MULTICAST_GROUP, &lan_ip);
    }
}

/// Handle to a running background `LanBeaconResponder` thread.
/// Automatically stops the responder and cleans up any ephemeral `.beacon` file on `Drop`.
pub struct LanBeaconHandle {
    libp2p_peer_id: String,
    identity: NodeIdentity,
    stop_flag: Arc<AtomicBool>,
    live_state: Arc<Mutex<LiveBeaconState>>,
    registry_dir: Option<PathBuf>,
    join_handle: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for LanBeaconHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanBeaconHandle")
            .field("libp2p_peer_id", &self.libp2p_peer_id)
            .finish()
    }
}

impl LanBeaconHandle {
    pub fn libp2p_peer_id(&self) -> &str {
        &self.libp2p_peer_id
    }

    /// Updates the advertised TCP listen endpoint (useful when binding `:0` ephemeral ports)
    /// and immediately refreshes the signed registry beacon if `PARVAULT_LAN_REGISTRY_DIR` is set.
    pub fn update_listen_endpoint(&self, tcp_listen_port: u16, explicit_listen_ip: Option<String>) {
        let normalized_ip = normalize_explicit_listen_ip(explicit_listen_ip.as_deref());
        let pkt_opt = if let Ok(mut guard) = self.live_state.lock() {
            guard.tcp_listen_port = tcp_listen_port;
            guard.explicit_listen_ip = normalized_ip;
            guard.sign_packet(&self.identity).ok()
        } else {
            None
        };
        if let (Some(ref dir), Some(ref pkt)) = (&self.registry_dir, &pkt_opt) {
            let _ = write_registry_beacon_atomic(dir, pkt);
        }
    }

    /// Updates the advertised free storage quota in bytes.
    pub fn update_available_bytes(&self, available_bytes: u64) {
        let pkt_opt = if let Ok(mut guard) = self.live_state.lock() {
            guard.available_bytes = available_bytes;
            guard.sign_packet(&self.identity).ok()
        } else {
            None
        };
        if let (Some(ref dir), Some(ref pkt)) = (&self.registry_dir, &pkt_opt) {
            let _ = write_registry_beacon_atomic(dir, pkt);
        }
    }

    /// Updates the advertised 4-word SAS pairing commitment (`Some(commitment)` or `None`).
    pub fn update_pairing_commitment(&self, commitment: Option<[u8; 32]>) {
        let pkt_opt = if let Ok(mut guard) = self.live_state.lock() {
            guard.pairing_sas_commitment = commitment;
            guard.sign_packet(&self.identity).ok()
        } else {
            None
        };
        if let (Some(ref dir), Some(ref pkt)) = (&self.registry_dir, &pkt_opt) {
            let _ = write_registry_beacon_atomic(dir, pkt);
        }
    }

    /// Signals the background responder to shut down cleanly and removes its `.beacon` file.
    pub fn shutdown(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.join_handle.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
        if let Some(ref dir) = self.registry_dir {
            let port = self
                .live_state
                .lock()
                .map(|g| g.tcp_listen_port)
                .unwrap_or(0);
            if port > 0 {
                remove_registry_beacon_if_matching_port(dir, &self.libp2p_peer_id, port);
            }
        }
    }
}

impl Drop for LanBeaconHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Dual-path Zero-Config LAN Beacon Responder (signed UDP broadcast/multicast + ephemeral registry fallback).
pub struct LanBeaconResponder;

impl LanBeaconResponder {
    pub fn spawn(
        identity: NodeIdentity,
        config: LanBeaconConfig,
    ) -> anyhow::Result<LanBeaconHandle> {
        let peer_id = node_identity_libp2p_peer_id(&identity)?;
        let libp2p_peer_id = peer_id.to_string();
        let explicit_listen_ip = normalize_explicit_listen_ip(config.explicit_listen_ip.as_deref());
        let owner_pq_fingerprint = normalize_optional_str(config.owner_pq_fingerprint.as_deref());

        let live_state = Arc::new(Mutex::new(LiveBeaconState {
            node_label: if config.node_label.trim().is_empty() {
                identity.device_peer_id()
            } else {
                config.node_label.trim().to_string()
            },
            role: if config.role.trim().is_empty() {
                "daemon".to_string()
            } else {
                config.role.trim().to_string()
            },
            tcp_listen_port: config.tcp_listen_port,
            explicit_listen_ip,
            available_bytes: config.available_bytes,
            owner_pq_fingerprint,
            pairing_sas_commitment: config.pairing_sas_commitment,
        }));

        let registry_dir = active_registry_dir();
        if let Some(ref dir) = registry_dir {
            if let Ok(guard) = live_state.lock() {
                if guard.tcp_listen_port > 0 {
                    if let Ok(initial_pkt) = guard.sign_packet(&identity) {
                        let _ = write_registry_beacon_atomic(dir, &initial_pkt);
                    }
                }
            }
        }

        let udp_sock = if config.discovery_port > 0 {
            match bind_reusable_udp_v4(config.discovery_port) {
                Ok(sock) => {
                    configure_discovery_socket(&sock);
                    let _ = sock.set_read_timeout(Some(Duration::from_millis(80)));
                    Some(sock)
                }
                Err(e) => {
                    debug!(
                        port = config.discovery_port,
                        error = %e,
                        "UDP discovery port bind unavailable; falling back to registry / ephemeral broadcast"
                    );
                    UdpSocket::bind("0.0.0.0:0").ok().inspect(|sock| {
                        configure_discovery_socket(sock);
                        let _ = sock.set_read_timeout(Some(Duration::from_millis(80)));
                    })
                }
            }
        } else {
            None
        };

        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop_flag);
        let thread_state = Arc::clone(&live_state);
        let thread_identity = identity.clone();
        let thread_registry = registry_dir.clone();
        let discovery_port = config.discovery_port;

        let join_handle = std::thread::Builder::new()
            .name("parvault-lan-beacon".to_string())
            .spawn(move || {
                let mut recv_buf = [0u8; 2048];
                let mut last_broadcast = Instant::now()
                    .checked_sub(Duration::from_secs(10))
                    .unwrap_or_else(Instant::now);
                let mut last_registry_refresh = Instant::now();

                while !thread_stop.load(Ordering::Relaxed) {
                    if last_registry_refresh.elapsed() >= Duration::from_secs(2) {
                        if let Some(ref dir) = thread_registry {
                            if let Ok(guard) = thread_state.lock() {
                                if guard.tcp_listen_port > 0 {
                                    if let Ok(pkt) = guard.sign_packet(&thread_identity) {
                                        let _ = write_registry_beacon_atomic(dir, &pkt);
                                    }
                                }
                            }
                        }
                        last_registry_refresh = Instant::now();
                    }

                    if let Some(ref sock) = udp_sock {
                        if discovery_port > 0 && last_broadcast.elapsed() >= Duration::from_secs(5)
                        {
                            if let Ok(guard) = thread_state.lock() {
                                if guard.tcp_listen_port > 0 {
                                    if let Ok(pkt) = guard.sign_packet(&thread_identity) {
                                        if let Ok(wire) = pkt.to_wire_bytes() {
                                            let _ = sock.send_to(
                                                &wire,
                                                SocketAddrV4::new(
                                                    Ipv4Addr::BROADCAST,
                                                    discovery_port,
                                                ),
                                            );
                                            let _ = sock.send_to(
                                                &wire,
                                                SocketAddrV4::new(
                                                    LAN_MULTICAST_GROUP,
                                                    discovery_port,
                                                ),
                                            );
                                            if let Some(lan_ip) = detect_primary_lan_ipv4() {
                                                let octets = lan_ip.octets();
                                                let slash24_bcast = Ipv4Addr::new(
                                                    octets[0], octets[1], octets[2], 255,
                                                );
                                                let _ = sock.send_to(
                                                    &wire,
                                                    SocketAddrV4::new(
                                                        slash24_bcast,
                                                        discovery_port,
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            last_broadcast = Instant::now();
                        }

                        match sock.recv_from(&mut recv_buf) {
                            Ok((len, src_addr)) => {
                                let trimmed = trim_ascii_slice(&recv_buf[..len]);
                                if trimmed == LAN_DISCOVER_PROBE_MAGIC {
                                    if let Ok(guard) = thread_state.lock() {
                                        if guard.tcp_listen_port > 0 {
                                            if let Ok(pkt) = guard.sign_packet(&thread_identity) {
                                                if let Ok(wire) = pkt.to_wire_bytes() {
                                                    let _ = sock.send_to(&wire, src_addr);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(ref e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut => {}
                            Err(_) => {
                                std::thread::sleep(Duration::from_millis(25));
                            }
                        }
                    } else {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            })?;

        Ok(LanBeaconHandle {
            libp2p_peer_id,
            identity,
            stop_flag,
            live_state,
            registry_dir,
            join_handle: Mutex::new(Some(join_handle)),
        })
    }
}

fn trim_ascii_slice(mut s: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = s.split_first() {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = s.split_last() {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn resolve_beacon_peer_ip(
    pkt: &LanBeaconPacket,
    observed_src_ip: Option<IpAddr>,
    local_lan_ip: Option<Ipv4Addr>,
) -> IpAddr {
    if let Some(ref explicit) = pkt.explicit_listen_ip {
        if let Ok(parsed) = explicit.parse::<IpAddr>() {
            if !parsed.is_unspecified() {
                if parsed.is_loopback() {
                    // Only use loopback when beacon came from local machine or local registry.
                    let is_local_origin = match observed_src_ip {
                        None => true,
                        Some(src) if src.is_loopback() => true,
                        Some(IpAddr::V4(v4)) if Some(v4) == local_lan_ip => true,
                        _ => false,
                    };
                    if is_local_origin {
                        return parsed;
                    }
                } else {
                    return parsed;
                }
            }
        }
    }
    observed_src_ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn merge_discovered_candidate(
    by_peer_id: &mut BTreeMap<String, DiscoveredLanPeer>,
    candidate: DiscoveredLanPeer,
) {
    match by_peer_id.get(&candidate.libp2p_peer_id) {
        None => {
            by_peer_id.insert(candidate.libp2p_peer_id.clone(), candidate);
        }
        Some(existing) => {
            let candidate_newer = candidate.timestamp_ms > existing.timestamp_ms;
            let same_port_better_ip = candidate.tcp_listen_port == existing.tcp_listen_port
                && existing.source_ip == "127.0.0.1"
                && candidate.source_ip != "127.0.0.1"
                && candidate.timestamp_ms + 2_000 >= existing.timestamp_ms;
            if candidate_newer || same_port_better_ip {
                by_peer_id.insert(candidate.libp2p_peer_id.clone(), candidate);
            }
        }
    }
}

fn scan_registry_dir_into(
    dir: &Path,
    now_ms: u64,
    local_lan_ip: Option<Ipv4Addr>,
    by_peer_id: &mut BTreeMap<String, DiscoveredLanPeer>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_beacon = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| !name.starts_with(".tmp.") && name.ends_with(".beacon"));
        if !is_beacon {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(pkt) = LanBeaconPacket::from_wire_bytes(&bytes) else {
            continue;
        };
        if pkt.verify(now_ms, MAX_LAN_BEACON_AGE_MS).is_ok() {
            let ip = resolve_beacon_peer_ip(&pkt, None, local_lan_ip);
            let peer = DiscoveredLanPeer::from_verified_packet(pkt, ip);
            merge_discovered_candidate(by_peer_id, peer);
        }
    }
}

fn send_lan_discovery_probes(
    socks: &[UdpSocket],
    discovery_port: u16,
    local_lan_ip: Option<Ipv4Addr>,
) {
    if discovery_port == 0 {
        return;
    }
    if let Some(primary) = socks.first() {
        let _ = primary.send_to(
            LAN_DISCOVER_PROBE_MAGIC,
            SocketAddrV4::new(Ipv4Addr::BROADCAST, discovery_port),
        );
        let _ = primary.send_to(
            LAN_DISCOVER_PROBE_MAGIC,
            SocketAddrV4::new(LAN_MULTICAST_GROUP, discovery_port),
        );
        if let Some(lan_ip) = local_lan_ip {
            let octs = lan_ip.octets();
            let slash24_bcast = Ipv4Addr::new(octs[0], octs[1], octs[2], 255);
            let _ = primary.send_to(
                LAN_DISCOVER_PROBE_MAGIC,
                SocketAddrV4::new(slash24_bcast, discovery_port),
            );
        }
    }
    // Fan out across multiple ephemeral source ports to `127.0.0.1:<discovery_port>` so Linux
    // `SO_REUSEPORT` 4-tuple hashing reaches co-located localhost daemons even without multicast.
    let localhost_target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, discovery_port);
    for sock in socks {
        let _ = sock.send_to(LAN_DISCOVER_PROBE_MAGIC, localhost_target);
    }
}

/// Actively scans the local network (`255.255.255.255`, `239.255.80.86`, local `/24` broadcast,
/// and `127.0.0.1`) plus `PARVAULT_LAN_REGISTRY_DIR` (if set), returning cryptographically
/// verified and deduplicated `DiscoveredLanPeer` records with `/p2p/<PeerId>` Multiaddrs.
pub fn discover_lan_peers(timeout: Duration, discovery_port: u16) -> Vec<DiscoveredLanPeer> {
    // A zero timeout means LAN discovery is off (`--no-lan-discovery`): no beacon registry
    // read and no probe, so nothing new is pinned.
    if timeout.is_zero() {
        return Vec::new();
    }
    let mut by_peer_id: BTreeMap<String, DiscoveredLanPeer> = BTreeMap::new();
    let local_lan_ip = detect_primary_lan_ipv4();
    let registry_dir = active_registry_dir();

    if let Some(ref dir) = registry_dir {
        scan_registry_dir_into(dir, current_unix_ms(), local_lan_ip, &mut by_peer_id);
    }

    if discovery_port > 0 && !timeout.is_zero() {
        let mut probe_socks = Vec::with_capacity(6);
        for _ in 0..6 {
            if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                let _ = sock.set_broadcast(true);
                let _ = sock.set_multicast_loop_v4(true);
                let _ = sock.set_nonblocking(true);
                probe_socks.push(sock);
            }
        }

        if !probe_socks.is_empty() {
            let started = Instant::now();
            let halfway = timeout / 2;
            let mut resent_halfway = false;
            send_lan_discovery_probes(&probe_socks, discovery_port, local_lan_ip);

            let mut recv_buf = [0u8; 2048];
            while started.elapsed() < timeout {
                if !resent_halfway
                    && timeout >= Duration::from_millis(90)
                    && started.elapsed() >= halfway
                {
                    send_lan_discovery_probes(&probe_socks, discovery_port, local_lan_ip);
                    resent_halfway = true;
                }

                let mut any_packet = false;
                for sock in &probe_socks {
                    while let Ok((len, src_addr)) = sock.recv_from(&mut recv_buf) {
                        any_packet = true;
                        if let Ok(pkt) = LanBeaconPacket::from_wire_bytes(&recv_buf[..len]) {
                            if pkt.verify(current_unix_ms(), MAX_LAN_BEACON_AGE_MS).is_ok() {
                                let ip =
                                    resolve_beacon_peer_ip(&pkt, Some(src_addr.ip()), local_lan_ip);
                                let peer = DiscoveredLanPeer::from_verified_packet(pkt, ip);
                                merge_discovered_candidate(&mut by_peer_id, peer);
                            }
                        }
                    }
                }

                if !any_packet {
                    let remaining = timeout.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        break;
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(12)));
                }
            }
        }
    }

    if let Some(ref dir) = registry_dir {
        scan_registry_dir_into(dir, current_unix_ms(), local_lan_ip, &mut by_peer_id);
    }

    let mut out: Vec<DiscoveredLanPeer> = by_peer_id.into_values().collect();
    out.sort_by(|a, b| {
        a.node_label
            .cmp(&b.node_label)
            .then_with(|| a.libp2p_peer_id.cmp(&b.libp2p_peer_id))
    });
    out
}

/// Persistent peer entry stored inside `<data_dir>/known_peers.json`, keyed by `libp2p_peer_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownPeerRecord {
    pub libp2p_peer_id: String,
    #[serde(default)]
    pub device_peer_id: String,
    #[serde(default)]
    pub node_label: String,
    #[serde(default)]
    pub role: String,
    pub multiaddr: String,
    #[serde(default)]
    pub available_bytes: u64,
    #[serde(default)]
    pub last_seen_ms: u64,
    #[serde(default)]
    pub ed25519_pubkey: Option<[u8; 32]>,
    #[serde(default)]
    pub owner_pq_fingerprint: Option<String>,
}

/// DHCP-resilient persistent peer store at `<data_dir>/known_peers.json`.
///
/// Keyed by cryptographic `libp2p_peer_id`: when a home router's DHCP server or ISP assigns a
/// new IP/port to a known storage appliance, `upsert_discovered` updates its endpoint while
/// preserving its pinned `/p2p/<PeerId>` identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownPeersStore {
    #[serde(default)]
    pub peers: BTreeMap<String, KnownPeerRecord>,
    /// TOFU-pinned Public Tracker Admin Ed25519 public keys keyed by tracker endpoint / PeerId (`ADR-26`).
    #[serde(default)]
    pub tracker_admin_pubkeys: BTreeMap<String, [u8; 32]>,
}

impl KnownPeersStore {
    pub const FILE_NAME: &'static str = "known_peers.json";

    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(Self::FILE_NAME);
        let Ok(bytes) = std::fs::read(&path) else {
            return Self::default();
        };
        serde_json::from_slice(&bytes).unwrap_or_default()
    }

    pub fn save(&self, data_dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(Self::FILE_NAME);
        let mut nonce = [0u8; 6];
        OsRng.fill_bytes(&mut nonce);
        let tmp_path = data_dir.join(format!(".tmp.known_peers.{}.json", hex::encode(nonce)));
        let serialized = serde_json::to_vec_pretty(self)?;
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(&serialized)?;
        file.sync_all()?;
        drop(file);
        if let Err(e) = std::fs::rename(&tmp_path, &path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e.into());
        }
        Ok(())
    }

    pub fn upsert_single(&mut self, peer: &DiscoveredLanPeer) {
        if let Some(existing) = self.peers.get(&peer.libp2p_peer_id) {
            if let Some(pinned_pk) = existing.ed25519_pubkey {
                if pinned_pk != peer.ed25519_pubkey {
                    return;
                }
            }
        }
        self.peers.insert(
            peer.libp2p_peer_id.clone(),
            KnownPeerRecord {
                libp2p_peer_id: peer.libp2p_peer_id.clone(),
                device_peer_id: peer.device_peer_id.clone(),
                node_label: peer.node_label.clone(),
                role: peer.role.clone(),
                multiaddr: peer.multiaddr.clone(),
                available_bytes: peer.available_bytes,
                last_seen_ms: peer.timestamp_ms,
                ed25519_pubkey: Some(peer.ed25519_pubkey),
                owner_pq_fingerprint: peer.owner_pq_fingerprint.clone(),
            },
        );
    }

    pub fn upsert_discovered(&mut self, peers: &[DiscoveredLanPeer]) {
        for peer in peers {
            self.upsert_single(peer);
        }
    }

    /// Upserts a verified `/p2p/<PeerId>` multiaddr (e.g., from Online WAN Rendezvous or Public Tracker).
    pub fn upsert_pinned_multiaddr(
        &mut self,
        libp2p_peer_id: &str,
        multiaddr: &str,
        label: Option<&str>,
        role: Option<&str>,
    ) {
        let pid = libp2p_peer_id.trim();
        let maddr_trimmed = multiaddr.trim();
        if pid.is_empty() || maddr_trimmed.is_empty() {
            return;
        }
        let ensured_maddr = if maddr_trimmed.contains("/p2p/") {
            maddr_trimmed.to_string()
        } else {
            format!("{maddr_trimmed}/p2p/{pid}")
        };
        let now_ms = current_unix_ms();
        match self.peers.get_mut(pid) {
            Some(existing) => {
                existing.multiaddr = ensured_maddr;
                existing.last_seen_ms = now_ms;
                if let Some(l) = label.filter(|s| !s.trim().is_empty()) {
                    existing.node_label = l.trim().to_string();
                }
                if let Some(r) = role.filter(|s| !s.trim().is_empty()) {
                    existing.role = r.trim().to_string();
                }
            }
            None => {
                self.peers.insert(
                    pid.to_string(),
                    KnownPeerRecord {
                        libp2p_peer_id: pid.to_string(),
                        device_peer_id: String::new(),
                        node_label: label.unwrap_or(pid).trim().to_string(),
                        role: role.unwrap_or("daemon").trim().to_string(),
                        multiaddr: ensured_maddr,
                        available_bytes: 0,
                        last_seen_ms: now_ms,
                        ed25519_pubkey: None,
                        owner_pq_fingerprint: None,
                    },
                );
            }
        }
    }

    pub fn active_multiaddrs(&self) -> Vec<String> {
        self.peers.values().map(|r| r.multiaddr.clone()).collect()
    }

    pub fn multiaddr_for_peer_id(&self, libp2p_peer_id: &str) -> Option<&str> {
        self.peers
            .get(libp2p_peer_id.trim())
            .map(|r| r.multiaddr.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// TOFU-pins the official `tracker_admin_pubkey` (`tracker_admin.seed`) advertised by a
    /// Public Tracker (`parvault-seed --mode public-bootstrap`) so `--public` nodes accept
    /// admin-approved takedowns while rejecting forged/MITM swaps (`ADR-26`).
    pub fn pin_tracker_admin_pubkey(&mut self, tracker_key: &str, admin_pubkey: [u8; 32]) {
        let key = tracker_key.trim();
        if key.is_empty() || admin_pubkey == [0u8; 32] {
            return;
        }
        self.tracker_admin_pubkeys
            .entry(key.to_string())
            .or_insert(admin_pubkey);
    }

    /// Returns all unique TOFU-pinned `tracker_admin_pubkey` values across configured public trackers.
    pub fn pinned_tracker_admin_pubkeys(&self) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        for &pk in self.tracker_admin_pubkeys.values() {
            if !out.contains(&pk) {
                out.push(pk);
            }
        }
        out
    }
}

/// Human-friendly 4-word BIP-39 Short Authentication String (SAS) code for Zero-IP Home/WAN Pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanPairingCode {
    /// Four hyphen-separated BIP-39 words (`"anchor-velvet-orbit-oak"`).
    pub code: String,
    /// Individual 4 BIP-39 words.
    pub words: [String; 4],
    /// 32-byte commitment published in signed `LanBeaconPacket::pairing_sas_commitment`.
    pub commitment: [u8; 32],
    /// Compact non-interactive pairing token (`pvpair1:<peer_id>:<nonce_hex>:<w1-w2-w3-w4>`).
    pub compact_token: String,
}

impl LanPairingCode {
    pub fn as_str(&self) -> &str {
        &self.code
    }
}

impl std::fmt::Display for LanPairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.code)
    }
}

/// Generates a fresh 128-bit cryptographic nonce for `derive_4word_pairing_sas`.
pub fn generate_random_pairing_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Computes the 32-byte `SHA-256` pairing SAS commitment bound to `(libp2p_peer_id, owner_pq_fingerprint, code)`.
pub fn compute_pairing_sas_commitment(
    libp2p_peer_id: &str,
    owner_pq_fingerprint: Option<&str>,
    normalized_code: &str,
) -> [u8; 32] {
    let norm_fp = normalize_optional_str(owner_pq_fingerprint).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(b"parvault-lan-sas-commit-v1:");
    hasher.update((libp2p_peer_id.trim().len() as u32).to_be_bytes());
    hasher.update(libp2p_peer_id.trim().as_bytes());
    hasher.update((norm_fp.len() as u32).to_be_bytes());
    hasher.update(norm_fp.as_bytes());
    hasher.update((normalized_code.len() as u32).to_be_bytes());
    hasher.update(normalized_code.as_bytes());
    hasher.finalize().into()
}

/// Normalizes a 4-word BIP-39 SAS string (`"Word1-word2 word3-WORD4"` -> `"word1-word2-word3-word4"`),
/// returning `None` if it does not consist of exactly 4 valid words from `BIP39_ENGLISH_WORDLIST`.
pub fn normalize_4word_sas_code(raw: &str) -> Option<String> {
    let parts: Vec<String> = raw
        .trim()
        .split(|c: char| c == '-' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect();
    if parts.len() != 4 {
        return None;
    }
    for word in &parts {
        if BIP39_ENGLISH_WORDLIST
            .binary_search(&word.as_str())
            .is_err()
        {
            return None;
        }
    }
    Some(format!(
        "{}-{}-{}-{}",
        parts[0], parts[1], parts[2], parts[3]
    ))
}

/// Deterministically derives a human-friendly 4-word BIP-39 SAS pairing code (`44 bits` = 4 x 11-bit
/// wordlist indices) from `(libp2p_peer_id, owner_pq_fingerprint, pairing_nonce)`.
pub fn derive_4word_pairing_sas(
    libp2p_peer_id: &str,
    owner_pq_fingerprint: Option<&str>,
    pairing_nonce: &[u8],
) -> LanPairingCode {
    let peer_trimmed = libp2p_peer_id.trim();
    let norm_fp = normalize_optional_str(owner_pq_fingerprint).unwrap_or_default();

    let mut ikm = Vec::with_capacity(peer_trimmed.len() + norm_fp.len() + pairing_nonce.len() + 16);
    write_len_prefixed_bytes(&mut ikm, peer_trimmed.as_bytes());
    write_len_prefixed_bytes(&mut ikm, norm_fp.as_bytes());
    write_len_prefixed_bytes(&mut ikm, pairing_nonce);

    let hk = Hkdf::<Sha256>::new(Some(b"parvault-lan-pairing-sas-salt-v1"), &ikm);
    let mut okm = [0u8; 16];
    hk.expand(b"parvault-lan-4word-sas-v1", &mut okm)
        .expect("16-byte HKDF expand is always valid");

    let packed = u64::from_be_bytes([
        okm[0], okm[1], okm[2], okm[3], okm[4], okm[5], okm[6], okm[7],
    ]);
    let idx0 = ((packed >> 53) & 0x7ff) as usize;
    let idx1 = ((packed >> 42) & 0x7ff) as usize;
    let idx2 = ((packed >> 31) & 0x7ff) as usize;
    let idx3 = ((packed >> 20) & 0x7ff) as usize;

    let words = [
        BIP39_ENGLISH_WORDLIST[idx0].to_string(),
        BIP39_ENGLISH_WORDLIST[idx1].to_string(),
        BIP39_ENGLISH_WORDLIST[idx2].to_string(),
        BIP39_ENGLISH_WORDLIST[idx3].to_string(),
    ];
    let code = format!("{}-{}-{}-{}", words[0], words[1], words[2], words[3]);
    let commitment = compute_pairing_sas_commitment(peer_trimmed, Some(&norm_fp), &code);
    let compact_token = format!(
        "pvpair1:{peer_trimmed}:{}:{code}",
        hex::encode(pairing_nonce)
    );

    LanPairingCode {
        code,
        words,
        commitment,
        compact_token,
    }
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Verifies a user-supplied 4-word BIP-39 SAS pairing code (or `pvpair1:...` compact token)
/// against a cryptographically verified `DiscoveredLanPeer`.
pub fn verify_lan_pairing_code(peer: &DiscoveredLanPeer, code: &str) -> bool {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        return false;
    }

    if let Some(rest) = trimmed.strip_prefix("pvpair1:") {
        let parts: Vec<&str> = rest.split(':').collect();
        if parts.len() != 3 {
            return false;
        }
        let (token_peer_id, nonce_hex, token_words) = (parts[0], parts[1], parts[2]);
        if token_peer_id != peer.libp2p_peer_id {
            return false;
        }
        let Ok(nonce_bytes) = hex::decode(nonce_hex) else {
            return false;
        };
        let Some(norm_words) = normalize_4word_sas_code(token_words) else {
            return false;
        };
        let expected = derive_4word_pairing_sas(
            &peer.libp2p_peer_id,
            peer.owner_pq_fingerprint.as_deref(),
            &nonce_bytes,
        );
        if expected.code != norm_words {
            return false;
        }
        if let Some(ref peer_commit) = peer.pairing_sas_commitment {
            return constant_time_eq_32(peer_commit, &expected.commitment);
        }
        return true;
    }

    let Some(norm_words) = normalize_4word_sas_code(trimmed) else {
        return false;
    };

    if let Some(ref peer_commit) = peer.pairing_sas_commitment {
        let candidate_commit = compute_pairing_sas_commitment(
            &peer.libp2p_peer_id,
            peer.owner_pq_fingerprint.as_deref(),
            &norm_words,
        );
        return constant_time_eq_32(peer_commit, &candidate_commit);
    }

    // Fallback when a running storage daemon did not set a custom ephemeral pairing commitment
    // (e.g. `parvault pair --once` derived the standing node SAS using `DEFAULT_LAN_PAIRING_NONCE`).
    let default_sas = derive_4word_pairing_sas(
        &peer.libp2p_peer_id,
        peer.owner_pq_fingerprint.as_deref(),
        DEFAULT_LAN_PAIRING_NONCE,
    );
    default_sas.code == norm_words
}

/// High-level Zero-Config peer resolution helper:
/// - Returns normalized `explicit_peers` immediately if non-empty.
/// - Otherwise scans the LAN via `discover_lan_peers(timeout, discovery_port)`, merges fresh
///   peers into `<data_dir>/known_peers.json` (healing any DHCP IP/port changes), persists the
///   updated `KnownPeersStore`, and returns all known `/ip4/.../tcp/.../p2p/<PeerId>` Multiaddrs.
pub fn resolve_zero_config_peers(
    data_dir: &Path,
    explicit_peers: &[String],
    discovery_port: u16,
    timeout: Duration,
) -> Vec<String> {
    let mut normalized_explicit = Vec::new();
    for raw in explicit_peers {
        for item in raw.split(',') {
            let trimmed = item.trim();
            if !trimmed.is_empty() && !normalized_explicit.contains(&trimmed.to_string()) {
                normalized_explicit.push(trimmed.to_string());
            }
        }
    }
    if !normalized_explicit.is_empty() {
        return normalized_explicit;
    }

    let discovered = discover_lan_peers(timeout, discovery_port);
    let mut store = KnownPeersStore::load(data_dir);
    if !discovered.is_empty() {
        store.upsert_discovered(&discovered);
        let _ = store.save(data_dir);
    }
    store.active_multiaddrs()
}

/// Extended Zero-Config peer resolver combining Home LAN Auto-Discovery, Persistent `KnownPeersStore`,
/// Online WAN DDNS Dynamic-IP Healing, and optional `--public` BitTorrent-style Tracker discovery.
pub fn resolve_zero_config_peers_with_wan(
    data_dir: &Path,
    explicit_peers: &[String],
    discovery_port: u16,
    timeout: Duration,
    identity: &NodeIdentity,
    wan_anchors: &[String],
    public_tracker_mode: bool,
) -> Vec<String> {
    let mut normalized_explicit = Vec::new();
    for raw in explicit_peers {
        for item in raw.split(',') {
            let trimmed = item.trim();
            if !trimmed.is_empty() && !normalized_explicit.contains(&trimmed.to_string()) {
                normalized_explicit.push(trimmed.to_string());
            }
        }
    }
    if !normalized_explicit.is_empty() {
        return normalized_explicit;
    }

    let _ = resolve_zero_config_peers(data_dir, &[], discovery_port, timeout);

    let clean_anchors: Vec<String> = wan_anchors
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    if !clean_anchors.is_empty() {
        let client = crate::network::client::MeshClient::new(
            identity.clone(),
            Vec::new(),
            clean_anchors.first().cloned(),
        )
        .with_data_dir_discovery(data_dir.to_path_buf(), discovery_port)
        .with_timeout(Duration::from_millis(800));

        let existing_records: Vec<KnownPeerRecord> = KnownPeersStore::load(data_dir)
            .peers
            .into_values()
            .collect();

        for anchor in &clean_anchors {
            if public_tracker_mode {
                let _ = client.announce_and_discover_public_tracker(anchor, None);
            }
            for rec in &existing_records {
                let _ = client.lookup_wan_ddns_cards(anchor, &rec.libp2p_peer_id);
                if let Some(ref fp) = rec.owner_pq_fingerprint {
                    let _ = client.lookup_wan_ddns_cards(anchor, fp);
                }
            }
        }
    }

    let mut addrs = KnownPeersStore::load(data_dir).active_multiaddrs();
    if addrs.is_empty() && !clean_anchors.is_empty() {
        addrs.extend(clean_anchors);
    }
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_lan_beacon_rejects_tampering_and_peer_id_spoofing() {
        let real_id = NodeIdentity::generate();
        let attacker_id = NodeIdentity::generate();
        let now_ms = current_unix_ms();

        let valid = LanBeaconPacket::sign_new(
            &real_id,
            "living-room-router",
            "router-nas",
            4001,
            64 * 1024 * 1024 * 1024,
            now_ms,
            LanBeaconOptions {
                explicit_listen_ip: Some("192.168.1.1"),
                owner_pq_fingerprint: Some("pq-fp-abcd1234"),
                pairing_sas_commitment: None,
            },
        )
        .expect("sign valid beacon");

        let expected_pid = node_identity_libp2p_peer_id(&real_id).expect("peer id");
        assert_eq!(
            valid.verify(now_ms, MAX_LAN_BEACON_AGE_MS).expect("valid"),
            expected_pid
        );

        // 1. Tampering with `tcp_listen_port` invalidates Ed25519 signature
        let mut bad_port = valid.clone();
        bad_port.tcp_listen_port = 9999;
        assert!(bad_port.verify(now_ms, MAX_LAN_BEACON_AGE_MS).is_err());

        // 2. Tampering with `role` or `available_bytes` invalidates Ed25519 signature
        let mut bad_quota = valid.clone();
        bad_quota.available_bytes += 1;
        assert!(bad_quota.verify(now_ms, MAX_LAN_BEACON_AGE_MS).is_err());

        // 3. Attacker signing a beacon with their own Ed25519 key while claiming victim's `PeerId`
        let mut spoofed = LanBeaconPacket::sign_new(
            &attacker_id,
            "evil-spoof",
            "router-nas",
            4001,
            1_000_000,
            now_ms,
            LanBeaconOptions {
                explicit_listen_ip: Some("192.168.1.66"),
                ..LanBeaconOptions::default()
            },
        )
        .expect("attacker sign");
        spoofed.libp2p_peer_id = expected_pid.to_string();
        let preimage = spoofed.canonical_signing_bytes();
        let re_sig = attacker_id.sign(&preimage);
        spoofed.sig_r.copy_from_slice(&re_sig[..32]);
        spoofed.sig_s.copy_from_slice(&re_sig[32..64]);
        assert!(
            spoofed.verify(now_ms, MAX_LAN_BEACON_AGE_MS).is_err(),
            "PeerId != ed25519_pubkey spoofing must be rejected even with valid attacker signature"
        );

        // 4. Replay outside 15s window is rejected
        assert!(valid
            .verify(now_ms + MAX_LAN_BEACON_AGE_MS + 100, MAX_LAN_BEACON_AGE_MS)
            .is_err());
    }

    #[test]
    fn test_4word_bip39_sas_pairing_and_verification() {
        let router_id = NodeIdentity::generate();
        let router_pid = node_identity_libp2p_peer_id(&router_id)
            .unwrap()
            .to_string();
        let nonce = [0x5au8; 16];
        let pq_fp = Some("ml-dsa-65:deadbeefcafe");

        let sas = derive_4word_pairing_sas(&router_pid, pq_fp, &nonce);
        assert_eq!(sas.words.len(), 4);
        assert!(normalize_4word_sas_code(&sas.code).is_some());

        let pkt = LanBeaconPacket::sign_new(
            &router_id,
            "openwrt-nas",
            "router-nas",
            4001,
            10_000_000,
            current_unix_ms(),
            LanBeaconOptions {
                explicit_listen_ip: Some("192.168.1.1"),
                owner_pq_fingerprint: pq_fp,
                pairing_sas_commitment: Some(sas.commitment),
            },
        )
        .unwrap();
        let discovered =
            DiscoveredLanPeer::from_verified_packet(pkt, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        // Exact 4-word code, case/space-normalized 4-word code, and compact token all succeed
        assert!(verify_lan_pairing_code(&discovered, &sas.code));
        let spaced_upper = sas.code.replace('-', " ").to_ascii_uppercase();
        assert!(verify_lan_pairing_code(&discovered, &spaced_upper));
        assert!(verify_lan_pairing_code(&discovered, &sas.compact_token));

        // Wrong BIP-39 words, invalid words, or another node's PeerId all fail
        assert!(!verify_lan_pairing_code(
            &discovered,
            "abandon-abandon-abandon-abandon"
        ));
        assert!(!verify_lan_pairing_code(
            &discovered,
            "not-a-valid-bip39word"
        ));

        let mut other_peer = discovered.clone();
        other_peer.owner_pq_fingerprint = Some("ml-dsa-65:tampered".to_string());
        assert!(!verify_lan_pairing_code(&other_peer, &sas.code));
    }

    #[test]
    fn test_known_peers_store_dhcp_ip_and_port_healing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nas_id = NodeIdentity::generate();
        let nas_pid = node_identity_libp2p_peer_id(&nas_id).unwrap().to_string();
        let now_ms = current_unix_ms();

        let pkt_old = LanBeaconPacket::sign_new(
            &nas_id,
            "home-nas",
            "router-nas",
            4001,
            50_000_000,
            now_ms,
            LanBeaconOptions {
                explicit_listen_ip: Some("192.168.1.20"),
                ..LanBeaconOptions::default()
            },
        )
        .unwrap();
        let peer_old = DiscoveredLanPeer::from_verified_packet(
            pkt_old,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        );

        let mut store = KnownPeersStore::load(dir.path());
        store.upsert_discovered(&[peer_old]);
        store
            .save(dir.path())
            .expect("save initial known_peers.json");

        let reloaded = KnownPeersStore::load(dir.path());
        assert_eq!(
            reloaded.active_multiaddrs(),
            vec![format!("/ip4/192.168.1.20/tcp/4001/p2p/{nas_pid}")]
        );

        // Router reboots and DHCP assigns new IP 192.168.1.88 and port 4011 with the SAME NodeIdentity
        let pkt_new = LanBeaconPacket::sign_new(
            &nas_id,
            "home-nas",
            "router-nas",
            4011,
            49_000_000,
            now_ms + 5_000,
            LanBeaconOptions {
                explicit_listen_ip: Some("192.168.1.88"),
                ..LanBeaconOptions::default()
            },
        )
        .unwrap();
        let peer_new = DiscoveredLanPeer::from_verified_packet(
            pkt_new,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 88)),
        );

        let mut store2 = KnownPeersStore::load(dir.path());
        store2.upsert_discovered(&[peer_new]);
        store2
            .save(dir.path())
            .expect("save healed known_peers.json");

        let healed = KnownPeersStore::load(dir.path());
        assert_eq!(healed.len(), 1, "must deduplicate by cryptographic PeerId");
        assert_eq!(
            healed.active_multiaddrs(),
            vec![format!("/ip4/192.168.1.88/tcp/4011/p2p/{nas_pid}")]
        );
    }

    #[test]
    fn test_live_localhost_udp_and_registry_discovery() {
        let reg_dir = tempfile::tempdir().expect("registry tempdir");
        let data_dir = tempfile::tempdir().expect("client data tempdir");

        // Allocate a dedicated ephemeral UDP port so parallel test runners never collide
        let probe_port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let id1 = NodeIdentity::generate();
        let id2 = NodeIdentity::generate();
        let pid1 = node_identity_libp2p_peer_id(&id1).unwrap().to_string();
        let pid2 = node_identity_libp2p_peer_id(&id2).unwrap().to_string();

        // Test live UDP responder on `probe_port`
        let cfg1 = LanBeaconConfig::new("node-alpha", "daemon", 14101)
            .with_discovery_port(probe_port)
            .with_explicit_listen_ip(Some("127.0.0.1".to_string()))
            .with_available_bytes(10 * 1024 * 1024);
        let handle1 = LanBeaconResponder::spawn(id1, cfg1).expect("spawn responder 1");

        // Also write a signed registry beacon for `id2` into `reg_dir` and test registry scan directly
        let pkt2 = LanBeaconPacket::sign_new(
            &id2,
            "node-beta",
            "router-nas",
            14102,
            20 * 1024 * 1024,
            current_unix_ms(),
            LanBeaconOptions {
                explicit_listen_ip: Some("127.0.0.1"),
                ..LanBeaconOptions::default()
            },
        )
        .unwrap();
        write_registry_beacon_atomic(reg_dir.path(), &pkt2).expect("write registry beacon");

        let mut reg_map = BTreeMap::new();
        scan_registry_dir_into(reg_dir.path(), current_unix_ms(), None, &mut reg_map);
        assert!(
            reg_map.contains_key(&pid2),
            "registry fallback must discover signed .beacon in < 50ms"
        );

        // Live UDP discovery via `resolve_zero_config_peers`
        let resolved =
            resolve_zero_config_peers(data_dir.path(), &[], probe_port, Duration::from_millis(180));
        assert!(
            resolved.contains(&format!("/ip4/127.0.0.1/tcp/14101/p2p/{pid1}")),
            "live UDP probe must discover responder 1: got {resolved:?}"
        );

        handle1.shutdown();
    }
}
