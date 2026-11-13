//! Zero-IP Online WAN Rendezvous, STUN-over-Noise Reflection & Dynamic-IP Peering (ADR-23).
//!
//! Provides zero-knowledge 4-word pairing, dynamic-IP presence heartbeats,
//! public commons tracker announcements, and STUN-over-Noise external address reflection
//! so `parvault` nodes can peer across the Internet without static IPs or manual port/IP exchange.

use crate::crypto::{
    decrypt_manifest, encrypt_manifest, MasterKey, NodeIdentity, BIP39_ENGLISH_WORDLIST,
};
pub use crate::network::behaviour::SignedWanRendezvousEntry;
use hkdf::Hkdf;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of distinct WAN rendezvous slots maintained by a seed or daemon.
pub const MAX_WAN_RENDEZVOUS_SLOTS: usize = 16_384;

/// Maximum number of active peer entries allowed per private pairing/DDNS slot.
pub const MAX_ENTRIES_PER_SLOT: usize = 8;

/// Maximum number of active peer entries allowed for the public commons tracker slot.
pub const MAX_PUBLIC_SWARM_ENTRIES: usize = 64;

/// Maximum byte size of the encrypted payload in a rendezvous entry (4 KiB anti-OOM cap).
pub const MAX_ENTRY_BYTES: usize = 4096;

/// Slots one signer key may hold at a time (F-22).
pub const MAX_RENDEZVOUS_SLOTS_PER_SIGNER: usize = 8;
/// Entries registered from one Sybil subnet (`canonical_sybil_subnet_key`) at a time (F-22).
pub const MAX_RENDEZVOUS_SLOTS_PER_SUBNET: usize = 32;

/// What the rendezvous quota decision needs to know about one registration (F-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RendezvousFacts {
    /// The signer already has an entry in this slot (a refresh, not a new slot).
    pub is_update: bool,
    /// Slots the signer holds now.
    pub signer_slots: usize,
    /// Live entries registered from the sender's subnet now.
    pub subnet_slots: usize,
}

/// Registration stays pre-admission (pairing needs it), but a new entry is refused once its
/// signer holds 8 slots or its subnet 32 entries (F-22). Refreshing an existing entry is allowed.
pub fn rendezvous_register_decision(facts: &RendezvousFacts) -> Result<(), &'static str> {
    if !facts.is_update
        && (facts.signer_slots >= MAX_RENDEZVOUS_SLOTS_PER_SIGNER
            || facts.subnet_slots >= MAX_RENDEZVOUS_SLOTS_PER_SUBNET)
    {
        return Err("reject.rendezvous_quota");
    }
    Ok(())
}

/// Default time-to-live for a WAN rendezvous entry in seconds (1 hour).
pub const DEFAULT_WAN_TTL_SECS: u64 = 3600;

/// Maximum allowed time-to-live for a WAN rendezvous entry (24 hours).
pub const MAX_WAN_TTL_SECS: u64 = 86_400;

/// Well-known passphrase / identifier for the zero-pairing Public Commons Tracker swarm.
pub const PUBLIC_COMMONS_TRACKER_KEY: &str = "parvault-public-commons-tracker-v1";

/// Blinded 32-byte slot key for the Public Commons Tracker swarm:
/// `SHA-256("parvault-public-commons-tracker-v1")`.
pub const PUBLIC_COMMONS_SWARM_SLOT: [u8; 32] = [
    0x43, 0xdc, 0x70, 0x4c, 0x72, 0xd4, 0xd6, 0xbd, 0x2a, 0x19, 0xec, 0x49, 0xd9, 0x2a, 0x84, 0x4e,
    0x5b, 0x35, 0xc3, 0x37, 0x14, 0xf0, 0x79, 0xad, 0xc9, 0x0f, 0xc4, 0x58, 0x86, 0xed, 0xf4, 0xd2,
];

/// Returns the blinded 32-byte slot key for the Public Commons Tracker swarm.
pub const fn public_commons_swarm_slot() -> [u8; 32] {
    PUBLIC_COMMONS_SWARM_SLOT
}

/// Current Unix timestamp in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Converts a 32-byte Ed25519 public key into its canonical `libp2p::PeerId`.
pub fn ed25519_pubkey_to_peer_id(pubkey_bytes: &[u8; 32]) -> Result<PeerId, String> {
    let ed_pub = libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey_bytes)
        .map_err(|e| format!("invalid ed25519 public key bytes: {e}"))?;
    let pubkey = libp2p::identity::PublicKey::from(ed_pub);
    Ok(pubkey.to_peer_id())
}

/// Normalizes a human-friendly pairing code or passphrase (NFKD, lowercase, trimmed,
/// hyphen-separated words).
pub fn normalize_wan_code(code: &str) -> String {
    code.split(|c: char| c.is_whitespace() || c == '-' || c == '_')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect::<Vec<_>>()
        .join("-")
}

/// Derives a blinded 32-byte rendezvous slot key from a human-friendly code or passphrase:
/// `slot_key = HKDF-SHA256(normalized_code, "parvault-wan-rendezvous-slot-v1")`.
///
/// The rendezvous server (`parvault-seed` or Kademlia DHT) sees ONLY this blinded `slot_key`
/// and NEVER learns the code or identity of the pairing peers.
pub fn derive_slot_key_from_code(code: &str) -> [u8; 32] {
    let normalized = normalize_wan_code(code);
    let hk = Hkdf::<Sha256>::new(None, normalized.as_bytes());
    let mut slot_key = [0u8; 32];
    hk.expand(b"parvault-wan-rendezvous-slot-v1", &mut slot_key)
        .expect("32-byte HKDF expansion is always valid");
    slot_key
}

/// Derives the 256-bit AEAD wrapping key from a human-friendly code or passphrase:
/// `wrap_key = MasterKey::from_bytes(HKDF-SHA256(normalized_code, "parvault-wan-rendezvous-wrap-v1"))`.
pub fn derive_wrap_key_from_code(code: &str) -> MasterKey {
    let normalized = normalize_wan_code(code);
    let hk = Hkdf::<Sha256>::new(None, normalized.as_bytes());
    let mut key_bytes = [0u8; 32];
    hk.expand(b"parvault-wan-rendezvous-wrap-v1", &mut key_bytes)
        .expect("32-byte HKDF expansion is always valid");
    MasterKey::from_bytes(key_bytes)
}

/// Generates a random 4-word BIP-39 English pairing code (e.g. `anchor-velvet-orbit-oak`).
pub fn generate_wan_pairing_code() -> String {
    let mut rng = rand::rngs::OsRng;
    let list_len = BIP39_ENGLISH_WORDLIST.len();
    let w1 = BIP39_ENGLISH_WORDLIST[rng.gen_range(0..list_len)];
    let w2 = BIP39_ENGLISH_WORDLIST[rng.gen_range(0..list_len)];
    let w3 = BIP39_ENGLISH_WORDLIST[rng.gen_range(0..list_len)];
    let w4 = BIP39_ENGLISH_WORDLIST[rng.gen_range(0..list_len)];
    format!("{w1}-{w2}-{w3}-{w4}")
}

/// Derives a blinded 32-byte Dynamic-IP DDNS slot key for post-pairing peer presence:
/// `slot_key = HKDF-SHA256(fingerprint_or_secret, "parvault-wan-ddns-v1")`.
pub fn derive_peer_ddns_slot_key(fingerprint_or_secret: &str) -> [u8; 32] {
    let normalized = fingerprint_or_secret.trim();
    let hk = Hkdf::<Sha256>::new(None, normalized.as_bytes());
    let mut slot_key = [0u8; 32];
    hk.expand(b"parvault-wan-ddns-v1", &mut slot_key)
        .expect("32-byte HKDF expansion is always valid");
    slot_key
}

/// Derives the AEAD wrapping key for post-pairing peer presence heartbeats.
pub fn derive_peer_ddns_wrap_key(fingerprint_or_secret: &str) -> MasterKey {
    let normalized = fingerprint_or_secret.trim();
    let hk = Hkdf::<Sha256>::new(None, normalized.as_bytes());
    let mut key_bytes = [0u8; 32];
    hk.expand(b"parvault-wan-ddns-wrap-v1", &mut key_bytes)
        .expect("32-byte HKDF expansion is always valid");
    MasterKey::from_bytes(key_bytes)
}

/// Cryptographically signed WAN peer card exchanged over encrypted rendezvous mailboxes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WanPeerCard {
    /// Canonical libp2p `PeerId` string (e.g. `12D3KooW...`).
    pub libp2p_peer_id: String,
    /// Human-friendly deterministic device peer identifier (e.g. `parvault-peer-a1b2c3d4...`).
    pub device_peer_id: String,
    /// User-configured node label (e.g. `chris-laptop`, `homelab-router`).
    pub node_label: String,
    /// Role (`"daemon"`, `"router-nas"`, `"homelab-seed"`, `"client"`).
    pub role: String,
    /// Public dialable multiaddrs (`/ip4/...`, `/ip6/...`, `/dns4/...`).
    pub wan_multiaddrs: Vec<String>,
    /// Optional seed/relay multiaddr fallback for symmetric NAT hole-punching.
    pub relay_seed_addr: Option<String>,
    /// Optional post-quantum owner fingerprint.
    pub owner_pq_fingerprint: Option<String>,
    /// Creation timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
    /// Time-to-live in seconds.
    pub ttl_secs: u64,
    /// Publisher's Ed25519 public key.
    pub ed25519_pubkey: [u8; 32],
    /// Signature half `r`.
    pub sig_r: [u8; 32],
    /// Signature half `s`.
    pub sig_s: [u8; 32],
}

impl WanPeerCard {
    /// Formats the domain-separated signing payload binding `libp2p_peer_id` to `ed25519_pubkey`.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"parvault-wan-peercard-v1:");
        out.extend_from_slice(self.libp2p_peer_id.as_bytes());
        out.extend_from_slice(b":");
        out.extend_from_slice(self.device_peer_id.as_bytes());
        out.extend_from_slice(b":");
        out.extend_from_slice(self.node_label.as_bytes());
        out.extend_from_slice(b":");
        out.extend_from_slice(self.role.as_bytes());
        out.extend_from_slice(b":");
        for addr in &self.wan_multiaddrs {
            out.extend_from_slice(addr.as_bytes());
            out.extend_from_slice(b",");
        }
        out.extend_from_slice(b":");
        if let Some(ref relay) = self.relay_seed_addr {
            out.extend_from_slice(relay.as_bytes());
        }
        out.extend_from_slice(b":");
        if let Some(ref pq) = self.owner_pq_fingerprint {
            out.extend_from_slice(pq.as_bytes());
        }
        out.extend_from_slice(b":");
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.extend_from_slice(&self.ttl_secs.to_be_bytes());
        out.extend_from_slice(&self.ed25519_pubkey);
        out
    }

    /// Constructs and signs a new `WanPeerCard` using `NodeIdentity`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: &NodeIdentity,
        node_label: impl Into<String>,
        role: impl Into<String>,
        wan_multiaddrs: Vec<String>,
        relay_seed_addr: Option<String>,
        owner_pq_fingerprint: Option<String>,
        ttl_secs: u64,
        timestamp_ms: u64,
    ) -> anyhow::Result<Self> {
        let pubkey_bytes = node_id.public_key_bytes();
        let libp2p_kp = node_id.to_libp2p_keypair()?;
        let libp2p_peer_id = libp2p_kp.public().to_peer_id().to_string();
        let device_peer_id = node_id.device_peer_id();
        let node_label = node_label.into();
        let role = role.into();

        let mut card = Self {
            libp2p_peer_id,
            device_peer_id,
            node_label,
            role,
            wan_multiaddrs,
            relay_seed_addr,
            owner_pq_fingerprint,
            timestamp_ms,
            ttl_secs,
            ed25519_pubkey: pubkey_bytes,
            sig_r: [0u8; 32],
            sig_s: [0u8; 32],
        };
        let payload = card.signing_payload();
        let sig = node_id.sign(&payload);
        card.sig_r.copy_from_slice(&sig[..32]);
        card.sig_s.copy_from_slice(&sig[32..]);

        Ok(card)
    }

    /// Verifies that:
    /// 1. `libp2p_peer_id` matches `ed25519_pubkey` (anti-spoofing).
    /// 2. The Ed25519 signature is cryptographically valid over the payload.
    pub fn verify_signature(&self) -> bool {
        let Ok(expected_peer_id) = ed25519_pubkey_to_peer_id(&self.ed25519_pubkey) else {
            return false;
        };
        if expected_peer_id.to_string() != self.libp2p_peer_id {
            return false;
        }

        let payload = self.signing_payload();

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.sig_r);
        sig_bytes[32..].copy_from_slice(&self.sig_s);

        NodeIdentity::verify_with_pubkey(&self.ed25519_pubkey, &payload, &sig_bytes)
    }

    /// Checks whether this peer card has expired.
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        let ttl_ms = self.ttl_secs.saturating_mul(1000);
        current_time_ms.saturating_sub(self.timestamp_ms) > ttl_ms
    }
}

/// Seals a `WanPeerCard` into a zero-knowledge `SignedWanRendezvousEntry` encrypted under
/// the 4-word code wrapping key.
pub fn seal_wan_peer_card(
    code: &str,
    card: &WanPeerCard,
    node_id: &NodeIdentity,
) -> anyhow::Result<SignedWanRendezvousEntry> {
    let slot_key = derive_slot_key_from_code(code);
    let wrap_key = derive_wrap_key_from_code(code);
    let card_bytes = bincode::serialize(card)?;
    let encrypted_peer_card = encrypt_manifest(&wrap_key, &card_bytes)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let payload = SignedWanRendezvousEntry::signing_payload(
        &slot_key,
        card.timestamp_ms,
        card.ttl_secs,
        &encrypted_peer_card,
    );
    let sig = node_id.sign(&payload);
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&sig[..32]);
    sig_s.copy_from_slice(&sig[32..]);

    Ok(SignedWanRendezvousEntry {
        slot_key,
        encrypted_peer_card,
        timestamp_ms: card.timestamp_ms,
        ttl_secs: card.ttl_secs,
        ed25519_pubkey: node_id.public_key_bytes(),
        sig_r,
        sig_s,
    })
}

/// Opens and decrypts a `SignedWanRendezvousEntry` using the 4-word code.
///
/// Returns `Err` if:
/// - Outer anti-spam signature fails.
/// - Slot key does not match code.
/// - AES-256-GCM authentication fails (wrong code).
/// - Inner `WanPeerCard` signature fails.
pub fn open_wan_peer_card(
    code: &str,
    entry: &SignedWanRendezvousEntry,
) -> anyhow::Result<WanPeerCard> {
    if !entry.verify_signature() {
        anyhow::bail!("outer entry signature verification failed");
    }
    let expected_slot_key = derive_slot_key_from_code(code);
    if entry.slot_key != expected_slot_key {
        anyhow::bail!("slot key mismatch");
    }
    let wrap_key = derive_wrap_key_from_code(code);
    let decrypted_bytes = decrypt_manifest(&wrap_key, &entry.encrypted_peer_card)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;
    let card: WanPeerCard = bincode::deserialize(&decrypted_bytes)
        .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?;
    if !card.verify_signature() {
        anyhow::bail!("inner peer card signature verification failed");
    }
    Ok(card)
}

/// Seals a dynamic-IP DDNS presence heartbeat under a peer's secret/fingerprint.
pub fn seal_ddns_heartbeat(
    fingerprint_or_secret: &str,
    card: &WanPeerCard,
    node_id: &NodeIdentity,
) -> anyhow::Result<SignedWanRendezvousEntry> {
    let slot_key = derive_peer_ddns_slot_key(fingerprint_or_secret);
    let wrap_key = derive_peer_ddns_wrap_key(fingerprint_or_secret);
    let card_bytes = bincode::serialize(card)?;
    let encrypted_peer_card = encrypt_manifest(&wrap_key, &card_bytes)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let payload = SignedWanRendezvousEntry::signing_payload(
        &slot_key,
        card.timestamp_ms,
        card.ttl_secs,
        &encrypted_peer_card,
    );
    let sig = node_id.sign(&payload);
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&sig[..32]);
    sig_s.copy_from_slice(&sig[32..]);

    Ok(SignedWanRendezvousEntry {
        slot_key,
        encrypted_peer_card,
        timestamp_ms: card.timestamp_ms,
        ttl_secs: card.ttl_secs,
        ed25519_pubkey: node_id.public_key_bytes(),
        sig_r,
        sig_s,
    })
}

/// Opens a dynamic-IP DDNS presence heartbeat.
pub fn open_ddns_heartbeat(
    fingerprint_or_secret: &str,
    entry: &SignedWanRendezvousEntry,
) -> anyhow::Result<WanPeerCard> {
    if !entry.verify_signature() {
        anyhow::bail!("outer entry signature verification failed");
    }
    let expected_slot_key = derive_peer_ddns_slot_key(fingerprint_or_secret);
    if entry.slot_key != expected_slot_key {
        anyhow::bail!("slot key mismatch");
    }
    let wrap_key = derive_peer_ddns_wrap_key(fingerprint_or_secret);
    let decrypted_bytes = decrypt_manifest(&wrap_key, &entry.encrypted_peer_card)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;
    let card: WanPeerCard = bincode::deserialize(&decrypted_bytes)
        .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?;
    if !card.verify_signature() {
        anyhow::bail!("inner peer card signature verification failed");
    }
    Ok(card)
}

/// Seals a `WanPeerCard` into the Public Commons Tracker swarm slot.
pub fn seal_public_tracker_card(
    card: &WanPeerCard,
    node_id: &NodeIdentity,
) -> anyhow::Result<SignedWanRendezvousEntry> {
    let slot_key = PUBLIC_COMMONS_SWARM_SLOT;
    let wrap_key = derive_wrap_key_from_code(PUBLIC_COMMONS_TRACKER_KEY);
    let card_bytes = bincode::serialize(card)?;
    let encrypted_peer_card = encrypt_manifest(&wrap_key, &card_bytes)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let payload = SignedWanRendezvousEntry::signing_payload(
        &slot_key,
        card.timestamp_ms,
        card.ttl_secs,
        &encrypted_peer_card,
    );
    let sig = node_id.sign(&payload);
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&sig[..32]);
    sig_s.copy_from_slice(&sig[32..]);

    Ok(SignedWanRendezvousEntry {
        slot_key,
        encrypted_peer_card,
        timestamp_ms: card.timestamp_ms,
        ttl_secs: card.ttl_secs,
        ed25519_pubkey: node_id.public_key_bytes(),
        sig_r,
        sig_s,
    })
}

/// Opens a `WanPeerCard` from the Public Commons Tracker swarm slot.
pub fn open_public_tracker_card(entry: &SignedWanRendezvousEntry) -> anyhow::Result<WanPeerCard> {
    if !entry.verify_signature() {
        anyhow::bail!("outer entry signature verification failed");
    }
    if entry.slot_key != PUBLIC_COMMONS_SWARM_SLOT {
        anyhow::bail!("slot key mismatch for public tracker card");
    }
    let wrap_key = derive_wrap_key_from_code(PUBLIC_COMMONS_TRACKER_KEY);
    let decrypted_bytes = decrypt_manifest(&wrap_key, &entry.encrypted_peer_card)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;
    let card: WanPeerCard = bincode::deserialize(&decrypted_bytes)
        .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?;
    if !card.verify_signature() {
        anyhow::bail!("inner peer card signature verification failed");
    }
    Ok(card)
}

/// STUN-over-Noise External Address Reflection:
/// Extracts the remote caller's observed public IP and formats a dialable WAN multiaddr
/// using the remote peer's listen port (or remote connection port if listen port is 0).
pub fn reflect_observed_wan_multiaddr(
    remote_addr: &Multiaddr,
    local_listen_port: u16,
    peer_id: &str,
) -> Option<String> {
    let mut ip_proto = None;
    let mut observed_port = None;

    for proto in remote_addr.iter() {
        match proto {
            Protocol::Ip4(ip) => ip_proto = Some(format!("/ip4/{ip}")),
            Protocol::Ip6(ip) => ip_proto = Some(format!("/ip6/{ip}")),
            Protocol::Dns4(dns) => ip_proto = Some(format!("/dns4/{dns}")),
            Protocol::Dns(dns) => ip_proto = Some(format!("/dns/{dns}")),
            Protocol::Tcp(p) => observed_port = Some(p),
            Protocol::Udp(p) => observed_port = Some(p),
            _ => {}
        }
    }

    let ip_str = ip_proto?;
    let effective_port = if local_listen_port > 0 {
        local_listen_port
    } else {
        observed_port.unwrap_or(4001)
    };

    if !peer_id.is_empty() {
        Some(format!("{ip_str}/tcp/{effective_port}/p2p/{peer_id}"))
    } else {
        Some(format!("{ip_str}/tcp/{effective_port}"))
    }
}

/// Bounded in-memory and disk-persisted registry for WAN rendezvous mailboxes.
///
/// Hosts:
/// - Private 4-word pairing mailboxes (max 8 entries per slot, TTL 3600s).
/// - Zero-knowledge DDNS presence mailboxes (max 8 entries per slot).
/// - Public Commons Tracker swarm mailbox (`PUBLIC_COMMONS_SWARM_SLOT`, max 64 entries).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanRendezvousRegistry {
    slots: HashMap<[u8; 32], Vec<SignedWanRendezvousEntry>>,
    #[serde(skip)]
    disk_path: Option<PathBuf>,
    /// Subnet each live entry was registered from, keyed by (slot, signer). In memory only.
    #[serde(skip)]
    registrant_subnet: HashMap<([u8; 32], [u8; 32]), String>,
}

impl Default for WanRendezvousRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WanRendezvousRegistry {
    /// Creates a fresh in-memory registry.
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
            disk_path: None,
            registrant_subnet: HashMap::new(),
        }
    }

    /// Creates a registry configured to persist to `disk_path`.
    pub fn with_disk_path(path: impl Into<PathBuf>) -> Self {
        Self {
            slots: HashMap::new(),
            disk_path: Some(path.into()),
            registrant_subnet: HashMap::new(),
        }
    }

    /// Loads an existing registry from `disk_path` if present, otherwise returns a new instance.
    pub fn load_or_new(disk_path: Option<&Path>) -> Self {
        if let Some(p) = disk_path {
            if p.exists() {
                if let Ok(bytes) = std::fs::read(p) {
                    if let Ok(mut reg) = bincode::deserialize::<WanRendezvousRegistry>(&bytes) {
                        reg.disk_path = Some(p.to_path_buf());
                        reg.prune_expired(now_ms());
                        return reg;
                    }
                }
            }
            return Self::with_disk_path(p);
        }
        Self::new()
    }

    /// Saves the registry atomically to disk if a path is configured.
    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(ref path) = self.disk_path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let bytes = bincode::serialize(self)?;
            crate::crypto::write_secret_file_atomic_0600(path, &bytes)
                .map_err(|e| anyhow::anyhow!("failed to save wan registry: {e}"))?;
        }
        Ok(())
    }

    /// Registers a signed entry into `slot_key`.
    ///
    /// Validates outer anti-spam signature, size bounds, and expiration.
    /// Updates existing entry if published by the same `ed25519_pubkey` with newer timestamp.
    pub fn register(
        &mut self,
        slot_key: [u8; 32],
        entry: SignedWanRendezvousEntry,
        current_time_ms: u64,
    ) -> Result<bool, String> {
        self.register_from(slot_key, entry, current_time_ms, None)
    }

    /// [`Self::register`] with the sender's Sybil subnet, which the F-22 caps count against.
    pub fn register_from(
        &mut self,
        slot_key: [u8; 32],
        entry: SignedWanRendezvousEntry,
        current_time_ms: u64,
        source_subnet: Option<String>,
    ) -> Result<bool, String> {
        if entry.slot_key != slot_key {
            return Err("slot_key mismatch".into());
        }

        if entry.encrypted_peer_card.len() > MAX_ENTRY_BYTES {
            return Err(format!(
                "entry payload {} exceeds max bound {}",
                entry.encrypted_peer_card.len(),
                MAX_ENTRY_BYTES
            ));
        }

        if entry.ttl_secs > MAX_WAN_TTL_SECS {
            return Err(format!(
                "ttl_secs {} exceeds maximum allowed {}",
                entry.ttl_secs, MAX_WAN_TTL_SECS
            ));
        }

        if entry.is_expired(current_time_ms) {
            return Err("entry is already expired".into());
        }

        if !entry.verify_signature() {
            return Err("outer entry signature verification failed".into());
        }

        self.prune_expired(current_time_ms);

        let signer = entry.ed25519_pubkey;
        let slots = &self.slots;
        self.registrant_subnet.retain(|(slot, signer), _| {
            slots
                .get(slot)
                .is_some_and(|es| es.iter().any(|e| e.ed25519_pubkey == *signer))
        });
        let facts = RendezvousFacts {
            is_update: self
                .slots
                .get(&slot_key)
                .is_some_and(|es| es.iter().any(|e| e.ed25519_pubkey == signer)),
            signer_slots: self
                .slots
                .values()
                .filter(|es| es.iter().any(|e| e.ed25519_pubkey == signer))
                .count(),
            subnet_slots: source_subnet.as_ref().map_or(0, |sn| {
                self.registrant_subnet.values().filter(|v| *v == sn).count()
            }),
        };
        if let Err(code) = rendezvous_register_decision(&facts) {
            tracing::warn!(code, "refused a rendezvous registration over quota");
            return Err("rendezvous quota exceeded".into());
        }
        if let Some(sn) = source_subnet {
            self.registrant_subnet.insert((slot_key, signer), sn);
        }

        if !self.slots.contains_key(&slot_key) && self.slots.len() >= MAX_WAN_RENDEZVOUS_SLOTS {
            self.evict_oldest_slot();
        }

        let is_public_swarm = slot_key == PUBLIC_COMMONS_SWARM_SLOT;
        let max_entries = if is_public_swarm {
            MAX_PUBLIC_SWARM_ENTRIES
        } else {
            MAX_ENTRIES_PER_SLOT
        };

        let entries = self.slots.entry(slot_key).or_default();

        if let Some(pos) = entries
            .iter()
            .position(|e| e.ed25519_pubkey == entry.ed25519_pubkey)
        {
            if entry.timestamp_ms >= entries[pos].timestamp_ms {
                entries[pos] = entry;
                let _ = self.save();
                return Ok(true);
            } else {
                return Ok(false);
            }
        }

        if entries.len() >= max_entries {
            entries.sort_by_key(|e| e.timestamp_ms);
            entries.remove(0);
        }

        entries.push(entry);
        let _ = self.save();
        Ok(true)
    }

    /// Looks up active, unexpired entries in `slot_key`.
    pub fn lookup(
        &mut self,
        slot_key: &[u8; 32],
        current_time_ms: u64,
    ) -> Vec<SignedWanRendezvousEntry> {
        self.prune_expired(current_time_ms);
        self.slots.get(slot_key).cloned().unwrap_or_default()
    }

    /// Looks up and returns `/24`-diverse sampled entries from the Public Commons Tracker swarm.
    pub fn lookup_public_swarm(
        &mut self,
        limit: usize,
        current_time_ms: u64,
    ) -> Vec<SignedWanRendezvousEntry> {
        let entries = self.lookup(&PUBLIC_COMMONS_SWARM_SLOT, current_time_ms);
        sample_diverse_public_peers(&entries, limit)
    }

    /// Prunes expired entries and removes empty slots.
    pub fn prune_expired(&mut self, current_time_ms: u64) {
        self.slots.retain(|_, entries| {
            entries.retain(|e| !e.is_expired(current_time_ms));
            !entries.is_empty()
        });
    }

    /// Evicts the oldest slot across the registry.
    fn evict_oldest_slot(&mut self) {
        if let Some((&oldest_key, _)) = self
            .slots
            .iter()
            .min_by_key(|(_, entries)| entries.iter().map(|e| e.timestamp_ms).min().unwrap_or(0))
        {
            self.slots.remove(&oldest_key);
        }
    }

    /// Returns the number of distinct active slots.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Returns the total number of entries across all active slots.
    pub fn total_entries_count(&self) -> usize {
        self.slots.values().map(|v| v.len()).sum()
    }
}

/// Extracts an IP subnet prefix key (`/24` IPv4 or `/48` IPv6) from a multiaddr string for diversity sampling.
fn extract_subnet_key(maddr_str: &str) -> Option<String> {
    if let Ok(maddr) = maddr_str.parse::<Multiaddr>() {
        for proto in maddr.iter() {
            match proto {
                Protocol::Ip4(ipv4) => {
                    let oct = ipv4.octets();
                    return Some(format!("ipv4-{}.{}.{}", oct[0], oct[1], oct[2]));
                }
                Protocol::Ip6(ipv6) => {
                    let seg = ipv6.segments();
                    return Some(format!("ipv6-{:x}:{:x}:{:x}", seg[0], seg[1], seg[2]));
                }
                Protocol::Dns4(dns) | Protocol::Dns(dns) => {
                    return Some(format!("dns-{dns}"));
                }
                _ => {}
            }
        }
    }
    None
}

/// Samples up to `limit` entries with `/24` IPv4 and `/48` IPv6 subnet diversity.
pub fn sample_diverse_public_peers(
    entries: &[SignedWanRendezvousEntry],
    limit: usize,
) -> Vec<SignedWanRendezvousEntry> {
    if entries.len() <= limit {
        return entries.to_vec();
    }

    let mut buckets: HashMap<String, Vec<SignedWanRendezvousEntry>> = HashMap::new();
    for entry in entries {
        let key = if let Ok(card) = open_public_tracker_card(entry) {
            card.wan_multiaddrs
                .iter()
                .find_map(|m| extract_subnet_key(m))
                .unwrap_or_else(|| hex::encode(&entry.ed25519_pubkey[..4]))
        } else {
            hex::encode(&entry.ed25519_pubkey[..4])
        };
        buckets.entry(key).or_default().push(entry.clone());
    }

    let mut result = Vec::with_capacity(limit);
    let mut round = 0;
    while result.len() < limit {
        let mut added_in_round = false;
        for entries in buckets.values_mut() {
            if round < entries.len() {
                result.push(entries[round].clone());
                added_in_round = true;
                if result.len() >= limit {
                    break;
                }
            }
        }
        if !added_in_round {
            break;
        }
        round += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendezvous_quota_caps_signer_and_subnet() {
        let f = |is_update, signer_slots, subnet_slots| RendezvousFacts {
            is_update,
            signer_slots,
            subnet_slots,
        };
        assert_eq!(rendezvous_register_decision(&f(false, 7, 31)), Ok(()));
        assert_eq!(
            rendezvous_register_decision(&f(false, 8, 0)),
            Err("reject.rendezvous_quota")
        );
        assert_eq!(
            rendezvous_register_decision(&f(false, 0, 32)),
            Err("reject.rendezvous_quota")
        );
        // A refresh of an existing entry is never refused.
        assert_eq!(rendezvous_register_decision(&f(true, 8, 32)), Ok(()));
    }
    use crate::crypto::compute_sha256;

    #[test]
    fn test_wan_pairing_alice_bob_zk() {
        let alice_id = NodeIdentity::generate();
        let bob_id = NodeIdentity::generate();

        let pairing_code = "anchor-velvet-orbit-oak";
        let alice_addr = format!(
            "/ip4/198.51.100.10/tcp/4001/p2p/{}",
            alice_id.to_libp2p_keypair().unwrap().public().to_peer_id()
        );
        let bob_addr = format!(
            "/ip4/203.0.113.50/tcp/4001/p2p/{}",
            bob_id.to_libp2p_keypair().unwrap().public().to_peer_id()
        );

        let t0 = 1_000_000;
        let card_alice = WanPeerCard::new(
            &alice_id,
            "alice-laptop",
            "daemon",
            vec![alice_addr],
            None,
            Some("alice-fingerprint".into()),
            3600,
            t0,
        )
        .unwrap();

        let card_bob = WanPeerCard::new(
            &bob_id,
            "bob-server",
            "router-nas",
            vec![bob_addr],
            None,
            Some("bob-fingerprint".into()),
            3600,
            t0,
        )
        .unwrap();

        let entry_alice = seal_wan_peer_card(pairing_code, &card_alice, &alice_id).unwrap();
        let entry_bob = seal_wan_peer_card(pairing_code, &card_bob, &bob_id).unwrap();

        let slot_key = derive_slot_key_from_code(pairing_code);
        let mut registry = WanRendezvousRegistry::new();

        assert!(registry
            .register(slot_key, entry_alice.clone(), t0)
            .unwrap());
        assert!(registry.register(slot_key, entry_bob.clone(), t0).unwrap());

        let looked_up = registry.lookup(&slot_key, t0);
        assert_eq!(looked_up.len(), 2);

        // Verify that the rendezvous registry / untrusted server CANNOT decrypt the cards
        // without the 4-word code.
        let random_key = MasterKey::generate();
        assert!(decrypt_manifest(&random_key, &entry_alice.encrypted_peer_card).is_err());

        // Bob opens Alice's card using the 4-word code
        let alice_found = looked_up
            .iter()
            .find(|e| e.ed25519_pubkey == alice_id.public_key_bytes())
            .unwrap();
        let opened_alice = open_wan_peer_card(pairing_code, alice_found).unwrap();
        assert_eq!(opened_alice.node_label, "alice-laptop");
        assert_eq!(opened_alice.role, "daemon");
        assert_eq!(opened_alice.wan_multiaddrs.len(), 1);

        // Opening with normalized code (spaces / uppercase) succeeds
        let opened_normalized =
            open_wan_peer_card("  ANCHOR  velvet-orbit_oak  ", alice_found).unwrap();
        assert_eq!(opened_normalized.node_label, "alice-laptop");

        // Opening with wrong 4-word code fails cleanly
        let wrong_code = "apple-banana-cherry-date";
        assert!(open_wan_peer_card(wrong_code, alice_found).is_err());
    }

    #[test]
    fn test_dynamic_wan_ip_rotation() {
        let alice_id = NodeIdentity::generate();
        let _bob_id = NodeIdentity::generate();
        let alice_peer_id = alice_id
            .to_libp2p_keypair()
            .unwrap()
            .public()
            .to_peer_id()
            .to_string();

        let ddns_secret = "alice-bob-coop-ring-secret-v1";
        let slot_key = derive_peer_ddns_slot_key(ddns_secret);
        let mut registry = WanRendezvousRegistry::new();

        let t0 = 10_000;
        let initial_addr = format!("/ip4/198.51.100.10/tcp/4001/p2p/{alice_peer_id}");
        let card1 = WanPeerCard::new(
            &alice_id,
            "alice-node",
            "daemon",
            vec![initial_addr.clone()],
            None,
            None,
            3600,
            t0,
        )
        .unwrap();

        let entry1 = seal_ddns_heartbeat(ddns_secret, &card1, &alice_id).unwrap();
        registry.register(slot_key, entry1, t0).unwrap();

        let bob_lookup = registry.lookup(&slot_key, t0);
        let bob_resolved = open_ddns_heartbeat(ddns_secret, &bob_lookup[0]).unwrap();
        assert_eq!(bob_resolved.wan_multiaddrs[0], initial_addr);

        // Alice's ISP changes public IP from 198.51.100.10 to 203.0.113.77
        let t1 = t0 + 100_000;
        let new_addr = format!("/ip4/203.0.113.77/tcp/4001/p2p/{alice_peer_id}");
        let card2 = WanPeerCard::new(
            &alice_id,
            "alice-node",
            "daemon",
            vec![new_addr.clone()],
            None,
            None,
            3600,
            t1,
        )
        .unwrap();

        let entry2 = seal_ddns_heartbeat(ddns_secret, &card2, &alice_id).unwrap();
        // Register updated IP
        registry.register(slot_key, entry2, t1).unwrap();

        // Check that slot updated in-place (no duplicate entry for Alice)
        let bob_lookup_updated = registry.lookup(&slot_key, t1);
        assert_eq!(bob_lookup_updated.len(), 1);
        let bob_resolved_updated =
            open_ddns_heartbeat(ddns_secret, &bob_lookup_updated[0]).unwrap();
        assert_eq!(bob_resolved_updated.wan_multiaddrs[0], new_addr);
    }

    #[test]
    fn test_anti_tamper_signature_and_bounded_eviction() {
        let node_id = NodeIdentity::generate();
        let code = "forest-river-mountain-sky";
        let t0 = 1_000_000;

        let card = WanPeerCard::new(
            &node_id,
            "test-node",
            "daemon",
            vec!["/ip4/198.51.100.1/tcp/4001".into()],
            None,
            None,
            10, // 10s TTL
            t0,
        )
        .unwrap();

        let mut entry = seal_wan_peer_card(code, &card, &node_id).unwrap();
        assert!(entry.verify_signature());

        // Tampering with encrypted payload breaks outer signature
        entry.encrypted_peer_card[0] ^= 0xff;
        assert!(!entry.verify_signature());

        let mut registry = WanRendezvousRegistry::new();
        let slot_key = derive_slot_key_from_code(code);
        assert!(registry.register(slot_key, entry, t0).is_err());

        // Re-seal valid entry
        let valid_entry = seal_wan_peer_card(code, &card, &node_id).unwrap();
        assert!(registry.register(slot_key, valid_entry, t0).unwrap());

        // At t0 + 15s (> 10s TTL), entry is pruned
        let expired_lookup = registry.lookup(&slot_key, t0 + 15_000);
        assert!(expired_lookup.is_empty());
        assert_eq!(registry.slot_count(), 0);

        // Test max entries per slot (max 8)
        let mut reg2 = WanRendezvousRegistry::new();
        for i in 0..10 {
            let id = NodeIdentity::generate();
            let c = WanPeerCard::new(
                &id,
                format!("node-{i}"),
                "daemon",
                vec!["/ip4/1.2.3.4/tcp/4001".into()],
                None,
                None,
                3600,
                t0 + i,
            )
            .unwrap();
            let e = seal_wan_peer_card(code, &c, &id).unwrap();
            reg2.register(slot_key, e, t0).unwrap();
        }
        let entries = reg2.lookup(&slot_key, t0);
        assert_eq!(entries.len(), MAX_ENTRIES_PER_SLOT);
    }

    #[test]
    fn test_stun_over_noise_reflection() {
        let peer_id = "12D3KooWStunTestPeerId123456789";

        // IPv4 reflection with custom listen port
        let remote_ipv4: Multiaddr = "/ip4/198.51.100.10/tcp/54321".parse().unwrap();
        let reflected_ipv4 = reflect_observed_wan_multiaddr(&remote_ipv4, 4001, peer_id);
        assert_eq!(
            reflected_ipv4,
            Some(format!("/ip4/198.51.100.10/tcp/4001/p2p/{peer_id}"))
        );

        // IPv6 reflection
        let remote_ipv6: Multiaddr = "/ip6/2001:db8::1/tcp/54321".parse().unwrap();
        let reflected_ipv6 = reflect_observed_wan_multiaddr(&remote_ipv6, 4001, peer_id);
        assert_eq!(
            reflected_ipv6,
            Some(format!("/ip6/2001:db8::1/tcp/4001/p2p/{peer_id}"))
        );

        // DNS4 reflection
        let remote_dns: Multiaddr = "/dns4/seed.parvault.net/tcp/4002".parse().unwrap();
        let reflected_dns = reflect_observed_wan_multiaddr(&remote_dns, 0, peer_id);
        assert_eq!(
            reflected_dns,
            Some(format!("/dns4/seed.parvault.net/tcp/4002/p2p/{peer_id}"))
        );
    }

    #[test]
    fn test_public_commons_tracker_swarm() {
        assert_eq!(
            PUBLIC_COMMONS_SWARM_SLOT,
            compute_sha256(PUBLIC_COMMONS_TRACKER_KEY.as_bytes())
        );

        let id = NodeIdentity::generate();
        let t0 = 100_000;
        let card = WanPeerCard::new(
            &id,
            "stranger-node",
            "daemon",
            vec!["/ip4/203.0.113.100/tcp/4001".into()],
            None,
            None,
            3600,
            t0,
        )
        .unwrap();

        let entry = seal_public_tracker_card(&card, &id).unwrap();
        assert_eq!(entry.slot_key, PUBLIC_COMMONS_SWARM_SLOT);

        let mut registry = WanRendezvousRegistry::new();
        registry
            .register(PUBLIC_COMMONS_SWARM_SLOT, entry.clone(), t0)
            .unwrap();

        let swarm_peers = registry.lookup_public_swarm(10, t0);
        assert_eq!(swarm_peers.len(), 1);

        let opened = open_public_tracker_card(&swarm_peers[0]).unwrap();
        assert_eq!(opened.node_label, "stranger-node");
    }
}
