//! The encrypted genesis backup bundle (B-169, arch056b K1-K12): Argon2id with a random salt,
//! then HKDF-SHA256 (`parvault-ring-backup-v1`), XChaCha20-Poly1305, a fixed length-exact header
//! that is all AAD.
//!
//! The ADR-18 derivations are not reused (their salt is deterministic and their namespace and
//! AAD are fixed); only the crates and the cost constants are.
//!
//! File layout, v1 (all integers little-endian; [`HEADER_LEN`] bytes of header, then the
//! ciphertext of exactly `body_len` bytes plus the 16-byte tag, then nothing):
//!
//! | offset | len | field |
//! | --: | --: | :-- |
//! | 0 | 8 | magic `PVRNGBAK` |
//! | 8 | 2 | version (1) |
//! | 10 | 1 | KDF id (1: Argon2id v0x13 then HKDF-SHA256) |
//! | 11 | 4 | Argon2 m (KiB) |
//! | 15 | 4 | Argon2 t |
//! | 19 | 4 | Argon2 p |
//! | 23 | 16 | salt |
//! | 39 | 24 | XChaCha20 nonce |
//! | 63 | 32 | ring id (the genesis public key) |
//! | 95 | 32 | node id (the node's Ed25519 public key) |
//! | 127 | 4 | body length |
//!
//! The body is a list of named entries ([`BackupBody`]); a restore writes only names from a
//! fixed set, so it never writes outside the files it knows.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

/// The file magic.
pub const MAGIC: [u8; 8] = *b"PVRNGBAK";
/// The only bundle version this release reads and writes.
pub const VERSION: u16 = 1;
/// KDF id 1: Argon2id (v0x13), then HKDF-SHA256 with [`HKDF_INFO`].
pub const KDF_ARGON2ID_HKDF: u8 = 1;
/// The HKDF info string (K1).
pub const HKDF_INFO: &[u8] = b"parvault-ring-backup-v1";
/// The header length.
pub const HEADER_LEN: usize = 131;
/// The AEAD tag length.
pub const TAG_LEN: usize = 16;
/// The largest body (K3).
pub const MAX_BODY_LEN: u32 = 1024 * 1024;
/// The largest bundle file a reader accepts.
pub const MAX_BUNDLE_LEN: usize = HEADER_LEN + MAX_BODY_LEN as usize + TAG_LEN;

/// Reader limit (K2): m at least 19 MiB. All limits are checked before the KDF allocates.
pub const KDF_M_MIN_KIB: u32 = 19 * 1024;
/// Reader limit: m at most 64 MiB.
pub const KDF_M_MAX_KIB: u32 = 64 * 1024;
/// Reader limit: t at least 2.
pub const KDF_T_MIN: u32 = 2;
/// Reader limit: t at most 10.
pub const KDF_T_MAX: u32 = 10;
/// Reader limit: p at least 1.
pub const KDF_P_MIN: u32 = 1;
/// Reader limit: p at most 4.
pub const KDF_P_MAX: u32 = 4;

/// The shortest passphrase, in characters (K8).
pub const PASSPHRASE_MIN_CHARS: usize = 20;

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory, KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// The writer's default (K1): 64 MiB, t=3, p=4 (the ADR-18 argon2 cost constants, `keys.rs`).
    pub const DEFAULT: Self = Self {
        m_kib: crate::crypto::keys::ARGON2_M_COST_KIB,
        t: crate::crypto::keys::ARGON2_T_COST,
        p: crate::crypto::keys::ARGON2_P_COST,
    };
    /// The `router-soc` writer (K1): 19 MiB, t=2, p=1.
    pub const ROUTER_SOC: Self = Self {
        m_kib: 19 * 1024,
        t: 2,
        p: 1,
    };

    /// Whether a reader accepts these parameters (K2).
    pub const fn within_reader_limits(self) -> bool {
        self.m_kib >= KDF_M_MIN_KIB
            && self.m_kib <= KDF_M_MAX_KIB
            && self.t >= KDF_T_MIN
            && self.t <= KDF_T_MAX
            && self.p >= KDF_P_MIN
            && self.p <= KDF_P_MAX
    }
}

/// The v1 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupHeader {
    /// The bundle version.
    pub version: u16,
    /// The KDF id.
    pub kdf_id: u8,
    /// The KDF parameters.
    pub kdf: KdfParams,
    /// The Argon2 salt.
    pub salt: [u8; 16],
    /// The XChaCha20 nonce.
    pub nonce: [u8; 24],
    /// The ring genesis public key.
    pub ring_id: [u8; 32],
    /// The node's Ed25519 public key.
    pub node_id: [u8; 32],
    /// The plaintext body length.
    pub body_len: u32,
}

impl BackupHeader {
    /// The header bytes (the AAD).
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..8].copy_from_slice(&MAGIC);
        h[8..10].copy_from_slice(&self.version.to_le_bytes());
        h[10] = self.kdf_id;
        h[11..15].copy_from_slice(&self.kdf.m_kib.to_le_bytes());
        h[15..19].copy_from_slice(&self.kdf.t.to_le_bytes());
        h[19..23].copy_from_slice(&self.kdf.p.to_le_bytes());
        h[23..39].copy_from_slice(&self.salt);
        h[39..63].copy_from_slice(&self.nonce);
        h[63..95].copy_from_slice(&self.ring_id);
        h[95..127].copy_from_slice(&self.node_id);
        h[127..131].copy_from_slice(&self.body_len.to_le_bytes());
        h
    }

    /// Reads the fields of a header without judging its version or parameters.
    pub fn decode(h: &[u8; HEADER_LEN]) -> Self {
        let u32_at = |o: usize| u32::from_le_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&h[23..39]);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&h[39..63]);
        let mut ring_id = [0u8; 32];
        ring_id.copy_from_slice(&h[63..95]);
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&h[95..127]);
        Self {
            version: u16::from_le_bytes([h[8], h[9]]),
            kdf_id: h[10],
            kdf: KdfParams {
                m_kib: u32_at(11),
                t: u32_at(15),
                p: u32_at(19),
            },
            salt,
            nonce,
            ring_id,
            node_id,
            body_len: u32_at(127),
        }
    }
}

/// The restore decision (claim `B169-RESTORE`): `Ok` only when every fact holds; otherwise the
/// code of the first failing one, in this order. A restore computes the facts in the same order,
/// each only when the ones before it hold (no KDF over refused parameters), and writes nothing
/// before `Ok`. Codes: `reject.backup_format` (bad magic, an unknown version or KDF id, a wrong
/// length or trailing bytes, K4), `reject.backup_kdf_params` (K2), `reject.backup_auth_failed`
/// (a wrong passphrase or a modified bundle), `reject.backup_inconsistent` (K5),
/// `reject.backup_wrong_ring` (K6), `reject.backup_target_not_empty`,
/// `reject.backup_move_not_confirmed` (K11).
#[allow(clippy::fn_params_excessive_bools)]
pub const fn ring_restore_decision(
    version_ok: bool,
    params_ok: bool,
    tag_ok: bool,
    consistent: bool,
    ring_matches: bool,
    target_empty: bool,
    move_confirmed: bool,
) -> Result<(), &'static str> {
    if !version_ok {
        return Err("reject.backup_format");
    }
    if !params_ok {
        return Err("reject.backup_kdf_params");
    }
    if !tag_ok {
        return Err("reject.backup_auth_failed");
    }
    if !consistent {
        return Err("reject.backup_inconsistent");
    }
    if !ring_matches {
        return Err("reject.backup_wrong_ring");
    }
    if !target_empty {
        return Err("reject.backup_target_not_empty");
    }
    if !move_confirmed {
        return Err("reject.backup_move_not_confirmed");
    }
    Ok(())
}

/// The passphrase-file decision (claim `B169-KEYFILE`, K8): a file inside the `--out`
/// directory is refused (`reject.backup_passphrase_in_out`: it would travel with the bundle),
/// then one that is not a regular `0600` file of this user (`reject.backup_passphrase_mode`),
/// then one whose text is not a valid passphrase (`reject.backup_passphrase_weak`).
pub const fn passphrase_file_decision(
    inside_out: bool,
    owner_only: bool,
    valid: bool,
) -> Result<(), &'static str> {
    if inside_out {
        return Err("reject.backup_passphrase_in_out");
    }
    if !owner_only {
        return Err("reject.backup_passphrase_mode");
    }
    if !valid {
        return Err("reject.backup_passphrase_weak");
    }
    Ok(())
}

/// Checks a bundle's framing (K4): the magic, version 1, KDF id 1, a body at most
/// [`MAX_BODY_LEN`] and a file length of exactly header plus body plus tag (no trailing bytes).
/// Returns the header and the ciphertext.
pub fn parse_bundle(bytes: &[u8]) -> Option<(BackupHeader, &[u8])> {
    if bytes.len() < HEADER_LEN || bytes.len() > MAX_BUNDLE_LEN {
        return None;
    }
    let mut h = [0u8; HEADER_LEN];
    h.copy_from_slice(&bytes[..HEADER_LEN]);
    if h[0..8] != MAGIC {
        return None;
    }
    let header = BackupHeader::decode(&h);
    let framed = header.version == VERSION
        && header.kdf_id == KDF_ARGON2ID_HKDF
        && header.body_len <= MAX_BODY_LEN
        && bytes.len() == HEADER_LEN + header.body_len as usize + TAG_LEN;
    framed.then_some((header, &bytes[HEADER_LEN..]))
}

/// The AEAD key: Argon2id(passphrase, salt, params), then HKDF-SHA256 with [`HKDF_INFO`] (K1).
/// `None` for parameters outside the reader limits, checked before Argon2 allocates (K2).
pub fn derive_key(
    passphrase: &str,
    salt: &[u8; 16],
    kdf: KdfParams,
) -> Option<Zeroizing<[u8; 32]>> {
    if !kdf.within_reader_limits() {
        return None;
    }
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32)).ok()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut ikm = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut ikm[..])
        .ok()?;
    let hk = Hkdf::<Sha256>::new(None, &ikm[..]);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, &mut key[..])
        .expect("32-byte HKDF expansion is always valid");
    Some(key)
}

/// Encrypts `body` into a v1 bundle for `ring_id` and `node_id`, with a fresh random salt and
/// nonce: one message per key (K3).
pub fn seal(
    passphrase: &str,
    kdf: KdfParams,
    ring_id: [u8; 32],
    node_id: [u8; 32],
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        body.len() <= MAX_BODY_LEN as usize,
        "the backup body is {} bytes, above the {MAX_BODY_LEN}-byte limit",
        body.len()
    );
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let header = BackupHeader {
        version: VERSION,
        kdf_id: KDF_ARGON2ID_HKDF,
        kdf,
        salt,
        nonce,
        ring_id,
        node_id,
        body_len: body.len() as u32,
    };
    let aad = header.encode();
    let key = derive_key(passphrase, &salt, kdf).ok_or_else(|| {
        anyhow::anyhow!("the writer's KDF parameters are outside the reader limits")
    })?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).expect("32-byte key");
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: body,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("backup encryption failed"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypts the ciphertext of a bundle [`parse_bundle`] accepted, with the header as AAD.
/// `None` when the tag does not verify. The caller checks the KDF parameters first.
pub fn open(
    key: &[u8; 32],
    header: &BackupHeader,
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let aad = header.encode();
    cipher
        .decrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

/// The passphrase in a passphrase file's bytes (K8): a leading UTF-8 BOM and one trailing
/// newline (`\n` or `\r\n`) are stripped, nothing else. `None` for non-UTF-8 or fewer than
/// [`PASSPHRASE_MIN_CHARS`] characters.
pub fn passphrase_from_file_bytes(raw: &[u8]) -> Option<Zeroizing<String>> {
    let mut b = raw;
    if let Some(rest) = b.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        b = rest;
    }
    if let Some(rest) = b.strip_suffix(b"\r\n") {
        b = rest;
    } else if let Some(rest) = b.strip_suffix(b"\n") {
        b = rest;
    }
    let s = std::str::from_utf8(b).ok()?;
    (s.chars().count() >= PASSPHRASE_MIN_CHARS).then(|| Zeroizing::new(s.to_string()))
}

/// The body: named entries, in order. Encoded as a `u16` count, then per entry a `u8` name
/// length, the ASCII name, a `u32` data length and the data.
#[derive(Default)]
pub struct BackupBody {
    /// `(name, bytes)`; the bytes are zeroized on drop.
    pub entries: Vec<(String, Zeroizing<Vec<u8>>)>,
}

impl std::fmt::Debug for BackupBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.entries.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("BackupBody")
            .field("entries", &names)
            .finish()
    }
}

impl BackupBody {
    /// The encoded body (zeroized on drop).
    pub fn encode(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        anyhow::ensure!(self.entries.len() <= u16::MAX as usize, "too many entries");
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for (name, data) in &self.entries {
            anyhow::ensure!(
                name.len() <= u8::MAX as usize && name.is_ascii(),
                "bad entry name"
            );
            anyhow::ensure!(data.len() <= MAX_BODY_LEN as usize, "entry too large");
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
        }
        Ok(out)
    }

    /// Decodes a body; `None` on any framing error or trailing byte.
    pub fn decode(mut b: &[u8]) -> Option<Self> {
        fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            if b.len() < n {
                return None;
            }
            let (head, rest) = b.split_at(n);
            *b = rest;
            Some(head)
        }
        let count = u16::from_le_bytes(take(&mut b, 2)?.try_into().ok()?);
        let mut entries = Vec::new();
        for _ in 0..count {
            let nlen = take(&mut b, 1)?[0] as usize;
            let name = std::str::from_utf8(take(&mut b, nlen)?).ok()?;
            if !name.is_ascii() {
                return None;
            }
            let dlen = u32::from_le_bytes(take(&mut b, 4)?.try_into().ok()?) as usize;
            let data = Zeroizing::new(take(&mut b, dlen)?.to_vec());
            entries.push((name.to_string(), data));
        }
        b.is_empty().then_some(Self { entries })
    }

    /// The bytes of the entry `name`.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery staple";

    fn key_for(h: &BackupHeader, pass: &str) -> Zeroizing<[u8; 32]> {
        derive_key(pass, &h.salt, h.kdf).unwrap()
    }

    #[test]
    fn seal_then_open_round_trips_and_every_header_field_is_authenticated() {
        let body = b"entries".to_vec();
        let bundle = seal(PASS, KdfParams::ROUTER_SOC, [1; 32], [2; 32], &body).unwrap();
        let (h, ct) = parse_bundle(&bundle).unwrap();
        assert_eq!((h.ring_id, h.node_id), ([1; 32], [2; 32]));
        assert_eq!(&open(&key_for(&h, PASS), &h, ct).unwrap()[..], &body[..]);
        assert!(open(&key_for(&h, "wrong horse battery staple"), &h, ct).is_none());
        // The parameters, salt, nonce and ids: each flipped byte is refused by the tag.
        for i in [12usize, 23, 40, 63, 100] {
            let mut b = bundle.clone();
            b[i] ^= 1;
            let (h2, ct2) = parse_bundle(&b).unwrap();
            if let Some(k) = derive_key(PASS, &h2.salt, h2.kdf) {
                assert!(open(&k, &h2, ct2).is_none(), "byte {i}");
            }
        }
    }

    #[test]
    fn framing_refuses_versions_kdf_ids_lengths_and_trailing_bytes() {
        let bundle = seal(PASS, KdfParams::ROUTER_SOC, [1; 32], [2; 32], b"x").unwrap();
        let mut trailing = bundle.clone();
        trailing.push(0);
        let mut v2 = bundle.clone();
        v2[8] = 2;
        let mut kdf2 = bundle.clone();
        kdf2[10] = 2;
        let mut magic = bundle.clone();
        magic[0] = b'X';
        let short = bundle[..bundle.len() - 1].to_vec();
        for b in [&trailing, &v2, &kdf2, &magic, &short] {
            assert!(parse_bundle(b).is_none());
        }
        assert!(parse_bundle(&bundle).is_some());
    }

    #[test]
    fn kdf_params_outside_reader_limits_are_refused_before_allocating() {
        let salt = [0u8; 16];
        for (m_kib, t, p) in [
            (4 * 1024 * 1024, 3, 4),
            (65_536, 1, 4),
            (65_536, 11, 4),
            (65_536, 3, 5),
            (65_536, 3, 0),
            (18 * 1024, 3, 4),
        ] {
            assert!(derive_key(PASS, &salt, KdfParams { m_kib, t, p }).is_none());
        }
        assert!(KdfParams::DEFAULT.within_reader_limits());
        assert!(KdfParams::ROUTER_SOC.within_reader_limits());
    }

    #[test]
    fn passphrase_strips_one_newline_and_a_bom_only() {
        let p = "a".repeat(20);
        let get = |b: &[u8]| passphrase_from_file_bytes(b).map(|s| s.to_string());
        assert_eq!(get(p.as_bytes()), Some(p.clone()));
        assert_eq!(get(format!("{p}\n").as_bytes()), Some(p.clone()));
        assert_eq!(get(format!("{p}\r\n").as_bytes()), Some(p.clone()));
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(format!("{p}\r\n").as_bytes());
        assert_eq!(get(&bom), Some(p.clone()));
        // Two newlines: one is stripped; the other is part of the passphrase.
        assert_eq!(get(format!("{p}\n\n").as_bytes()), Some(format!("{p}\n")));
        assert_eq!(get("a".repeat(19).as_bytes()), None);
        assert_eq!(get(format!("{}\n", "a".repeat(19)).as_bytes()), None);
        assert_eq!(get(&[0xff; 24]), None);
        // Counted in characters, not bytes.
        assert!(get("é".repeat(20).as_bytes()).is_some());
        assert!(get("é".repeat(19).as_bytes()).is_none());
    }

    #[test]
    fn body_round_trips_and_refuses_trailing_or_short_bytes() {
        let body = BackupBody {
            entries: vec![
                ("a".into(), Zeroizing::new(vec![1, 2])),
                ("b".into(), Zeroizing::new(vec![])),
            ],
        };
        let enc = body.encode().unwrap();
        let dec = BackupBody::decode(&enc).unwrap();
        assert_eq!(dec.get("a"), Some(&[1u8, 2][..]));
        assert_eq!(dec.get("b"), Some(&[][..]));
        let mut t = enc.to_vec();
        t.push(0);
        assert!(BackupBody::decode(&t).is_none());
        assert!(BackupBody::decode(&enc[..enc.len() - 1]).is_none());
    }

    #[test]
    fn the_decisions_are_ok_only_when_every_fact_holds() {
        assert_eq!(
            ring_restore_decision(true, true, true, true, true, true, true),
            Ok(())
        );
        assert_eq!(
            ring_restore_decision(true, true, true, true, true, true, false),
            Err("reject.backup_move_not_confirmed")
        );
        assert_eq!(
            ring_restore_decision(true, false, false, true, true, true, true),
            Err("reject.backup_kdf_params")
        );
        assert_eq!(passphrase_file_decision(false, true, true), Ok(()));
        assert_eq!(
            passphrase_file_decision(true, false, false),
            Err("reject.backup_passphrase_in_out")
        );
    }
}
