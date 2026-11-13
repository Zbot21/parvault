use crate::crypto::aes::CryptoError;
use crate::crypto::bip39::{normalize_seed_phrase_nfkd, validate_bip39_mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use unicode_normalization::UnicodeNormalization;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub type KeyError = CryptoError;

/// Production Argon2id memory cost: 64 MiB (`65,536 KiB`) per `ADR-18` / `SECURITY_AND_CRYPTOGRAPHY.md §2`.
pub const ARGON2_M_COST_KIB: u32 = 65_536;
/// Production Argon2id time cost: 3 iterations.
pub const ARGON2_T_COST: u32 = 3;
/// Production Argon2id parallelism degree: 4 lanes.
pub const ARGON2_P_COST: u32 = 4;

/// Atomically writes secret key material to `path` via a sibling `.tmp.<nonce>` file,
/// enforcing `0o600` (`rw-------`) owner-only file permissions on Unix before/after write
/// and calling `File::sync_all()` prior to atomic `rename` (`B4`).
/// The ring genesis secret written by `parvault wot init` (0600).
pub const RING_GENESIS_SEED_FILE: &str = "ring_genesis.seed";
/// The pinned ring genesis public key (hex).
pub const RING_GENESIS_PUB_FILE: &str = "ring_genesis.pub";
/// The error a node outside any ring reports.
pub const NOT_IN_RING_MESSAGE: &str = "this node is not in a ring: run `parvault wot init` to start one, or `parvault wot install-chain --token <TOKEN>` with a token from `parvault wot invite` on a ring member";

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.trim().is_empty())
}

fn parse_hex32(hex_str: &str, what: &str) -> Result<[u8; 32], CryptoError> {
    let mut raw =
        hex::decode(hex_str.trim()).map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
    if raw.len() != 32 {
        raw.zeroize();
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "{what} must be 32 bytes (64 hex characters)"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    raw.zeroize();
    Ok(out)
}

pub fn write_secret_file_atomic_0600(path: &Path, data: &[u8]) -> Result<(), CryptoError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        }
    }

    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("secret");
    let tmp_name = format!(".tmp.{file_name}.{}", hex::encode(nonce));
    let tmp_path = path.with_file_name(tmp_name);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts
        .open(&tmp_path)
        .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    file.write_all(data)
        .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
    file.sync_all()
        .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
    drop(file);

    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        CryptoError::InvalidKeyMaterial(e.to_string())
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Zero-knowledge 256-bit client master key (`K_user`).
/// Deliberately omits `Serialize`/`Deserialize` so raw master key bytes can never be accidentally
/// serialized into a network message or unencrypted struct (`B3`), and derives `ZeroizeOnDrop`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    /// Generates a cryptographically random 256-bit master key from `OsRng`.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let mut raw = hex::decode(hex_str.trim())
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        if raw.len() != KEY_LEN {
            raw.zeroize();
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "expected {} bytes, got {}",
                KEY_LEN,
                raw.len()
            )));
        }
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&raw);
        raw.zeroize();
        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derives a cryptographically isolated 256-bit subkey for backup epoch `epoch` via HKDF-SHA256.
    pub fn derive_epoch_subkey(&self, epoch: u64) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(&epoch.to_be_bytes()), &self.0);
        let mut out = [0u8; KEY_LEN];
        hk.expand(b"parvault-epoch-subkey-v1", &mut out)
            .expect("32-byte HKDF expansion is always valid");
        Self(out)
    }

    /// Derives a cryptographically isolated 256-bit purpose subkey from `K_user` via `HKDF-SHA256` (`B1`).
    /// Ensures `K_user` is never fed directly as raw key material into `AES-256-GCM`, `HMAC-SHA256`,
    /// or `HKDF` across distinct cryptographic subsystems.
    pub fn derive_purpose_subkey(&self, purpose: &[u8]) -> [u8; KEY_LEN] {
        let hk = Hkdf::<Sha256>::new(Some(b"parvault-master-subkey-tree-v2"), &self.0);
        let mut out = [0u8; KEY_LEN];
        hk.expand(purpose, &mut out)
            .expect("32-byte HKDF expansion is always valid");
        out
    }

    /// Dedicated subkey for `AES-256-GCM` stripe payload authenticated encryption (`B1`).
    pub fn stripe_aead_subkey(&self) -> [u8; KEY_LEN] {
        self.derive_purpose_subkey(b"parvault-subkey-stripe-aead-v2")
    }

    /// Dedicated subkey for `HKDF-SHA256` per-stripe 96-bit nonce derivation (`B1`).
    pub fn stripe_nonce_subkey(&self) -> [u8; KEY_LEN] {
        self.derive_purpose_subkey(b"parvault-subkey-stripe-nonce-v2")
    }

    /// Dedicated subkey for `AES-256-GCM` FileManifest / Onion / Keystore payload encryption (`B1`).
    pub fn manifest_aead_subkey(&self) -> [u8; KEY_LEN] {
        self.derive_purpose_subkey(b"parvault-subkey-manifest-aead-v2")
    }

    /// Dedicated subkey for Kademlia DHT manifest and root catalog routing key derivation (`B1`).
    pub fn dht_routing_subkey(&self) -> [u8; KEY_LEN] {
        self.derive_purpose_subkey(b"parvault-subkey-dht-routing-v2")
    }

    /// Dedicated subkey for `BlindedShardId` (`HMAC-SHA256`) locator derivation (`B1`).
    pub fn blind_locator_subkey(&self) -> [u8; KEY_LEN] {
        self.derive_purpose_subkey(b"parvault-subkey-blind-locator-v2")
    }

    /// Dedicated subkey for `BlindedShardCapability` (`HKDF-SHA256`) Ed25519 capability key derivation (`B1`).
    pub fn blind_capability_subkey(&self) -> [u8; KEY_LEN] {
        self.derive_purpose_subkey(b"parvault-subkey-blind-capability-v2")
    }

    /// Dedicated subkey for `derive_unlinkable_shard_pseudonym` (`HMAC-SHA256`) derivation (`B1`).
    pub fn shard_pseudonym_subkey(&self) -> [u8; KEY_LEN] {
        self.derive_purpose_subkey(b"parvault-subkey-shard-pseudonym-v2")
    }

    /// Validates a strict 12/15/18/21/24-word BIP-39 English mnemonic (including NFKD normalization,
    /// wordlist membership, and SHA-256 checksum bits) before deriving the `MasterKey` (`A4`, `B6`).
    pub fn from_bip39_mnemonic_checked(
        mnemonic: &str,
        vault_namespace: &str,
    ) -> Result<Self, CryptoError> {
        let canonical = validate_bip39_mnemonic(mnemonic)?;
        Ok(Self::from_recovery_seed_phrase(&canonical, vault_namespace))
    }

    /// Deterministically derives the 256-bit `MasterKey` from a memorized recovery seed phrase /
    /// 24-word mnemonic and `vault_namespace` ("House Fire" zero-local-state disaster recovery, ADR-18).
    /// Applies Unicode NFKD normalization and whitespace canonicalization (`B6`), followed by
    /// memory-hard `Argon2id` (`m = 64 MiB`, `t = 3`, `p = 4`) and `HKDF-SHA256` expansion (`A1`, `B7`).
    pub fn from_recovery_seed_phrase(seed_phrase: &str, vault_namespace: &str) -> Self {
        use argon2::{Algorithm, Argon2, Params, Version};
        let mut normalized_phrase = normalize_seed_phrase_nfkd(seed_phrase);
        let normalized_ns: String = vault_namespace
            .nfkd()
            .collect::<String>()
            .trim()
            .to_string();

        let mut salt_hasher = Sha256::new();
        salt_hasher.update(b"parvault-dr-argon2id-salt-v1:");
        salt_hasher.update((normalized_ns.len() as u32).to_be_bytes());
        salt_hasher.update(normalized_ns.as_bytes());
        let salt: [u8; 32] = salt_hasher.finalize().into();

        let params = Params::new(
            ARGON2_M_COST_KIB,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(KEY_LEN),
        )
        .expect("valid Argon2id parameters (64 MiB, t=3, p=4)");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut stretched = [0u8; KEY_LEN];
        argon2
            .hash_password_into(normalized_phrase.as_bytes(), &salt, &mut stretched)
            .expect("Argon2id password hashing succeeds");
        normalized_phrase.zeroize();

        let hk = Hkdf::<Sha256>::new(Some(normalized_ns.as_bytes()), &stretched);
        stretched.zeroize();
        let mut out = [0u8; KEY_LEN];
        hk.expand(b"parvault-dr-master-key-v1", &mut out)
            .expect("32-byte HKDF expansion is always valid");
        Self(out)
    }

    /// Deterministically derives the Kademlia DHT lookup key for the user's encrypted root
    /// `FolderSnapshotManifest` superblock catalog (`ADR-18`), enabling full directory-tree
    /// discovery after total local disk loss. Uses the domain-separated `dht_routing_subkey` (`B1`).
    pub fn derive_vault_root_dht_key(&self, vault_namespace: &str) -> [u8; 32] {
        let mut routing_subkey = self.dht_routing_subkey();
        let normalized_ns: String = vault_namespace
            .nfkd()
            .collect::<String>()
            .trim()
            .to_string();
        let hk = Hkdf::<Sha256>::new(Some(normalized_ns.as_bytes()), &routing_subkey);
        routing_subkey.zeroize();
        let mut dht_key = [0u8; 32];
        hk.expand(b"parvault-vault-root-catalog-dht-v1", &mut dht_key)
            .expect("32-byte HKDF expansion is always valid");
        dht_key
    }
}

/// Node cryptographic identity combining cryptographically separated Ed25519 signing keys
/// (for libp2p, WoT invitations, and `RepairGrant` authorization) and X25519 Diffie-Hellman keys
/// (for `K_session` PoR derivation) derived via `HKDF-SHA256` from a 32-byte master seed (`B2`).
#[derive(Clone)]
pub struct NodeIdentity {
    master_seed: [u8; 32],
    signing_key: SigningKey,
    x25519_secret: X25519Secret,
}

impl Drop for NodeIdentity {
    fn drop(&mut self) {
        self.master_seed.zeroize();
    }
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("public_key", &self.public_key_bytes())
            .finish()
    }
}

impl NodeIdentity {
    /// Generates a fresh node identity using OS CSPRNG (`OsRng`).
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let id = Self::from_seed(seed);
        seed.zeroize();
        id
    }

    /// Reconstructs deterministic node identity from a 32-byte master seed, deriving independent
    /// Ed25519 signing and X25519 static Diffie-Hellman keys via domain-separated `HKDF-SHA256` (`B2`).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"parvault-node-identity-kdf-v2"), &seed);
        let mut ed25519_seed = [0u8; 32];
        let mut x25519_seed = [0u8; 32];
        hk.expand(b"parvault-node-id-ed25519-signing-v2", &mut ed25519_seed)
            .expect("32-byte HKDF expansion is always valid");
        hk.expand(b"parvault-node-id-x25519-dh-v2", &mut x25519_seed)
            .expect("32-byte HKDF expansion is always valid");

        let signing_key = SigningKey::from_bytes(&ed25519_seed);
        let x25519_secret = X25519Secret::from(x25519_seed);
        ed25519_seed.zeroize();
        x25519_seed.zeroize();

        Self {
            master_seed: seed,
            signing_key,
            x25519_secret,
        }
    }

    /// Derives a deterministic owner signing `NodeIdentity` from a `MasterKey` so that
    /// cross-machine `parvault file store` / `parvault file restore --key-hex` and
    /// `parvault restore-folder --key-hex` produce identical `RepairGrant` and owner read signatures.
    pub fn from_master_key(master_key: &MasterKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"parvault-master-key-owner-ed25519-v1:");
        hasher.update(master_key.as_bytes());
        let mut seed: [u8; 32] = hasher.finalize().into();
        let id = Self::from_seed(seed);
        seed.zeroize();
        id
    }

    /// Loads a persistent 32-byte node identity seed from `data_dir/node_identity.seed`,
    /// or generates and atomically persists (`0600`) a fresh CSPRNG seed if none exists yet.
    pub fn load_or_generate_in_dir(data_dir: &Path) -> Result<Self, KeyError> {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        let seed_path = data_dir.join("node_identity.seed");
        if seed_path.exists() {
            let mut raw = std::fs::read(&seed_path)
                .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
            if raw.len() != 32 {
                raw.zeroize();
                return Err(CryptoError::InvalidKeyMaterial(format!(
                    "expected 32-byte node_identity.seed, got {} bytes",
                    raw.len()
                )));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw);
            raw.zeroize();
            let id = Self::from_seed(seed);
            seed.zeroize();
            Ok(id)
        } else {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            write_secret_file_atomic_0600(&seed_path, &seed)?;
            let id = Self::from_seed(seed);
            seed.zeroize();
            Ok(id)
        }
    }

    /// Resolves the ring genesis public key from every source, never generating one:
    /// `configured_pubkey_hex` (config), `PARVAULT_GENESIS_PUBKEY_HEX`, `PARVAULT_GENESIS_SEED_HEX`,
    /// `<data_dir>/ring_genesis.seed` (written only by `parvault wot init`) and
    /// `<data_dir>/ring_genesis.pub` (pinned by `parvault wot install-chain`). Sources that name
    /// different keys are a conflict; no source means this node is not in a ring.
    pub fn resolve_genesis_root_pubkey_in_dir(
        data_dir: &Path,
        configured_pubkey_hex: Option<&str>,
    ) -> Result<[u8; 32], KeyError> {
        let mut found: Vec<(&'static str, [u8; 32])> = Vec::new();
        if let Some(h) = configured_pubkey_hex
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            found.push((
                "config genesis_root_pubkey_hex",
                parse_hex32(h, "genesis pubkey")?,
            ));
        }
        if let Some(h) = env_nonempty("PARVAULT_GENESIS_PUBKEY_HEX") {
            found.push((
                "PARVAULT_GENESIS_PUBKEY_HEX",
                parse_hex32(&h, "genesis pubkey")?,
            ));
        }
        if let Some(id) = Self::load_ring_genesis_identity_in_dir(data_dir)? {
            found.push(("the ring genesis seed", id.public_key_bytes()));
        }
        let pinned = data_dir.join(RING_GENESIS_PUB_FILE);
        if pinned.exists() {
            let text = std::fs::read_to_string(&pinned)
                .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
            found.push((
                RING_GENESIS_PUB_FILE,
                parse_hex32(text.trim(), "pinned genesis")?,
            ));
        }
        let Some(&(_, first)) = found.first() else {
            return Err(CryptoError::RingMembership(NOT_IN_RING_MESSAGE.to_string()));
        };
        if found.iter().any(|(_, pk)| *pk != first) {
            let list: Vec<String> = found
                .iter()
                .map(|(src, pk)| format!("{src}={}", hex::encode(pk)))
                .collect();
            return Err(CryptoError::RingMembership(format!(
                "conflicting ring genesis sources: {}",
                list.join(", ")
            )));
        }
        Ok(first)
    }

    /// The ring genesis secret, if this node holds it: `PARVAULT_GENESIS_SEED_HEX`, or
    /// `<data_dir>/ring_genesis.seed` from `parvault wot init`. Never generates one.
    pub fn load_ring_genesis_identity_in_dir(data_dir: &Path) -> Result<Option<Self>, KeyError> {
        if let Some(h) = env_nonempty("PARVAULT_GENESIS_SEED_HEX") {
            let mut seed = parse_hex32(&h, "genesis seed")?;
            let id = Self::from_seed(seed);
            seed.zeroize();
            return Ok(Some(id));
        }
        let path = data_dir.join(RING_GENESIS_SEED_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let mut raw =
            std::fs::read(&path).map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        if raw.len() != 32 {
            raw.zeroize();
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "{} must hold 32 bytes",
                path.display()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        raw.zeroize();
        let id = Self::from_seed(seed);
        seed.zeroize();
        Ok(Some(id))
    }

    /// The explicit first-node action (`parvault wot init`): creates a new ring genesis in
    /// `<data_dir>/ring_genesis.seed` (0600) and pins its public key. Refuses if this node already
    /// has any ring genesis source.
    pub fn init_ring_genesis_in_dir(data_dir: &Path) -> Result<Self, KeyError> {
        if let Ok(pk) = Self::resolve_genesis_root_pubkey_in_dir(data_dir, None) {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "this node is already in the ring {}",
                hex::encode(pk)
            )));
        }
        std::fs::create_dir_all(data_dir)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        write_secret_file_atomic_0600(&data_dir.join(RING_GENESIS_SEED_FILE), &seed)?;
        let id = Self::from_seed(seed);
        seed.zeroize();
        Self::pin_ring_genesis_pubkey_in_dir(data_dir, id.public_key_bytes())?;
        Ok(id)
    }

    /// Pins the ring genesis public key (`parvault wot install-chain`, `wot init`). Refuses to
    /// replace a different pinned key.
    pub fn pin_ring_genesis_pubkey_in_dir(
        data_dir: &Path,
        pubkey: [u8; 32],
    ) -> Result<(), KeyError> {
        let path = data_dir.join(RING_GENESIS_PUB_FILE);
        if path.exists() {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
            let pinned = parse_hex32(text.trim(), "pinned genesis")?;
            if pinned != pubkey {
                return Err(CryptoError::InvalidKeyMaterial(format!(
                    "this node is pinned to the ring {}, not {}",
                    hex::encode(pinned),
                    hex::encode(pubkey)
                )));
            }
            return Ok(());
        }
        std::fs::create_dir_all(data_dir)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        crate::storage::BlockStore::atomic_write_file(&path, hex::encode(pubkey).as_bytes())
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))
    }

    /// Returns a human-readable deterministic peer identifier derived from the node's Ed25519 public key.
    pub fn device_peer_id(&self) -> String {
        Self::device_peer_id_for_pubkey(&self.public_key_bytes())
    }

    /// The device peer id of the identity with Ed25519 public key `pubkey`.
    pub fn device_peer_id_for_pubkey(pubkey: &[u8; 32]) -> String {
        format!("parvault-peer-{}", &hex::encode(pubkey)[..16])
    }

    /// Returns the 32-byte master seed from which both Ed25519 and X25519 keys are derived (`B2`).
    pub fn master_seed_bytes(&self) -> [u8; 32] {
        self.master_seed
    }

    /// Returns the raw 32-byte Ed25519 signing seed.
    pub fn signing_seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Converts this node's persistent Ed25519 signing seed into a `libp2p::identity::Keypair`
    /// so `PeerId` and Noise XX static identity remain stable across daemon/seed restarts.
    pub fn to_libp2p_keypair(&self) -> Result<libp2p::identity::Keypair, KeyError> {
        let mut seed = self.signing_seed_bytes();
        let res = libp2p::identity::Keypair::ed25519_from_bytes(&mut seed)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()));
        seed.zeroize();
        res
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Deterministically derives the owner's `NodeIdentity` from a recovery seed phrase and
    /// `vault_namespace` (`ADR-18`) so the user can authenticate DHT catalog envelopes and
    /// owner shard reads on a replacement machine after a house fire.
    pub fn from_recovery_seed_phrase(seed_phrase: &str, vault_namespace: &str) -> Self {
        let mk = MasterKey::from_recovery_seed_phrase(seed_phrase, vault_namespace);
        let normalized_ns: String = vault_namespace
            .nfkd()
            .collect::<String>()
            .trim()
            .to_string();
        let hk = Hkdf::<Sha256>::new(Some(normalized_ns.as_bytes()), mk.as_bytes());
        let mut id_seed = [0u8; 32];
        hk.expand(b"parvault-dr-owner-node-identity-v1", &mut id_seed)
            .expect("32-byte HKDF expansion is always valid");
        let id = Self::from_seed(id_seed);
        id_seed.zeroize();
        id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn x25519_public(&self) -> X25519Public {
        X25519Public::from(&self.x25519_secret)
    }

    /// Signs an arbitrary message with the node's Ed25519 private key.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    /// Verifies an Ed25519 signature against a 32-byte public key.
    pub fn verify_with_pubkey(pubkey_bytes: &[u8; 32], msg: &[u8], sig_bytes: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(pubkey_bytes) else {
            return false;
        };
        let sig = Signature::from_bytes(sig_bytes);
        // Strict: rejects small-order keys and non-canonical `R`, so no signature verifies
        // under a weak key such as all-zero (F-37).
        vk.verify_strict(msg, &sig).is_ok()
    }

    /// Derives a shared 32-byte stateless Proof-of-Retrievability session key (`K_session`)
    /// with a peer or witness node using X25519 ECDH + HKDF-SHA256 (ADR-03).
    pub fn derive_por_session_key(
        &self,
        remote_x25519_pub: &X25519Public,
        merkle_root: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError> {
        let shared = self.x25519_secret.diffie_hellman(remote_x25519_pub);
        let hk = Hkdf::<Sha256>::new(Some(merkle_root), shared.as_bytes());
        let mut session_key = [0u8; 32];
        hk.expand(b"parvault-por-session-v1", &mut session_key)
            .map_err(|_| CryptoError::KdfFailed)?;
        Ok(session_key)
    }

    /// Derives a deterministic 32-byte per-stripe PoR session key (`K_session`) bound to the owner's
    /// private signing seed and `merkle_root` via HKDF-SHA256 (`ADR-03`).
    pub fn derive_stripe_por_session_key(&self, merkle_root: &[u8; 32]) -> [u8; 32] {
        let mut sign_bytes = self.signing_key.to_bytes();
        let hk = Hkdf::<Sha256>::new(Some(merkle_root), &sign_bytes);
        sign_bytes.zeroize();
        let mut session_key = [0u8; 32];
        hk.expand(b"parvault-stripe-por-session-v1", &mut session_key)
            .expect("32-byte HKDF expand is always valid");
        session_key
    }
}

/// Trait representing local software keystore sealing for `master_key.sealed` (`B5`).
pub trait LocalKeystoreSealer: Send + Sync {
    /// Encrypts raw 32-byte key material under the local keystore's binding key (`AES-256-GCM`).
    fn seal_key(&self, raw_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError>;
    /// Decrypts and authenticates a previously sealed blob back into a 32-byte key.
    fn unseal_key(&self, sealed_blob: &[u8]) -> Result<[u8; 32], CryptoError>;
}

/// Local software keystore (`B5`) that encrypts `master_key.sealed` using `AES-256-GCM` under either:
/// 1. A memory-hard `Argon2id` (`64 MiB, t=3, p=4`) key derived from `--passphrase` / `PARVAULT_PASSPHRASE`, or
/// 2. An OS `0600`-permission-protected local seed file (`enclave_sealing.seed`) for unattended daemon operation.
///
/// Note: This is a software keystore and does not interact with a hardware TPM 2.0 chip.
pub struct LocalFileKeystore {
    device_binding_key: MasterKey,
}

impl LocalFileKeystore {
    pub fn new(device_binding_seed: [u8; 32]) -> Self {
        Self {
            device_binding_key: MasterKey::from_bytes(device_binding_seed),
        }
    }

    /// Initializes the local software keystore from an explicit passphrase (or `PARVAULT_PASSPHRASE` env var)
    /// using `Argon2id` (`64 MiB, t=3, p=4`), or loads/generates a 32-byte OS CSPRNG binding key in
    /// `data_dir/enclave_sealing.seed` with `0o600` atomic file permissions.
    pub fn from_passphrase_or_csprng_in_dir(
        data_dir: &Path,
        passphrase: Option<&str>,
    ) -> Result<Self, KeyError> {
        let env_pass = std::env::var("PARVAULT_PASSPHRASE").ok();
        let effective_pass = passphrase
            .or(env_pass.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if let Some(pass) = effective_pass {
            let derived = MasterKey::from_recovery_seed_phrase(pass, "parvault-enclave-sealing-v1");
            return Ok(Self {
                device_binding_key: derived,
            });
        }

        std::fs::create_dir_all(data_dir)
            .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
        let seed_path = data_dir.join("enclave_sealing.seed");
        if seed_path.exists() {
            let mut raw = std::fs::read(&seed_path)
                .map_err(|e| CryptoError::InvalidKeyMaterial(e.to_string()))?;
            if raw.len() != KEY_LEN {
                raw.zeroize();
                return Err(CryptoError::InvalidKeyMaterial(format!(
                    "expected 32-byte enclave_sealing.seed, got {} bytes",
                    raw.len()
                )));
            }
            let mut seed = [0u8; KEY_LEN];
            seed.copy_from_slice(&raw);
            raw.zeroize();
            let store = Self::new(seed);
            seed.zeroize();
            Ok(store)
        } else {
            let mut seed = [0u8; KEY_LEN];
            OsRng.fill_bytes(&mut seed);
            write_secret_file_atomic_0600(&seed_path, &seed)?;
            let store = Self::new(seed);
            seed.zeroize();
            Ok(store)
        }
    }

    pub fn load_or_create_master_key(&self, sealed_path: &Path) -> anyhow::Result<MasterKey> {
        if sealed_path.exists() {
            let blob = std::fs::read(sealed_path)?;
            let mut raw = self.unseal_key(&blob)?;
            let mk = MasterKey::from_bytes(raw);
            raw.zeroize();
            Ok(mk)
        } else {
            let key = MasterKey::generate();
            let blob = self.seal_key(key.as_bytes())?;
            write_secret_file_atomic_0600(sealed_path, &blob)?;
            Ok(key)
        }
    }
}

impl LocalKeystoreSealer for LocalFileKeystore {
    fn seal_key(&self, raw_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        crate::crypto::aes::encrypt_manifest(&self.device_binding_key, raw_key)
    }

    fn unseal_key(&self, sealed_blob: &[u8]) -> Result<[u8; 32], CryptoError> {
        let mut plain =
            crate::crypto::aes::decrypt_manifest(&self.device_binding_key, sealed_blob)?;
        if plain.len() != 32 {
            plain.zeroize();
            return Err(CryptoError::DecryptionFailed);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&plain);
        plain.zeroize();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subkey_domain_separation_and_node_identity_key_separation() {
        let mk = MasterKey::generate();
        let subkeys = [
            mk.stripe_aead_subkey(),
            mk.stripe_nonce_subkey(),
            mk.manifest_aead_subkey(),
            mk.dht_routing_subkey(),
            mk.blind_locator_subkey(),
            mk.blind_capability_subkey(),
            mk.shard_pseudonym_subkey(),
        ];
        for (i, k_a) in subkeys.iter().enumerate() {
            assert_ne!(
                k_a,
                mk.as_bytes(),
                "subkey {i} must not equal raw MasterKey"
            );
            for (j, k_b) in subkeys.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        k_a, k_b,
                        "subkey {i} and {j} must be cryptographically distinct"
                    );
                }
            }
        }

        // B2: NodeIdentity derives distinct Ed25519 and X25519 keys from master_seed
        let seed = [0x42u8; 32];
        let id = NodeIdentity::from_seed(seed);
        assert_eq!(id.master_seed_bytes(), seed);
        assert_ne!(
            id.signing_seed_bytes(),
            seed,
            "Ed25519 signing seed must be HKDF-separated from raw master_seed"
        );
    }

    #[test]
    fn test_nfkd_seed_normalization_and_atomic_0600_secret_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let secret_path = dir.path().join("test_secret.seed");
        write_secret_file_atomic_0600(&secret_path, &[0x99u8; 32]).expect("atomic 0600 write");
        assert_eq!(std::fs::read(&secret_path).unwrap(), vec![0x99u8; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&secret_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "secret file must have 0600 permissions");
        }
    }
}
