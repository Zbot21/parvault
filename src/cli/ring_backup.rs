//! `parvault ring backup | restore`: the encrypted genesis backup (B-169, arch056b K1-K12;
//! `v0.5.6` track E), on `parvault::crypto::backup_envelope`. Both run under the data-dir lock
//! (`DataDirLock`, B-174), so neither runs beside a daemon on the same data dir.
//!
//! In the bundle (K7, D-50 Q11): the ring genesis seed and pin, the node identity seed, the
//! installed chains, the council manifest and history, the two PQ key files, `config.toml`, and
//! the vault master key (unsealed inside the bundle, resealed for the new node on restore).
//! Never in it: `macaroon_root.key` (a restore would revive every token ever minted), the TLS
//! key, quota, PoR and shard state.

use parvault::config::RingAction;
use parvault::crypto::backup_envelope::{
    self as env, passphrase_file_decision, ring_restore_decision, BackupBody, KdfParams,
};
use parvault::crypto::keys::{fsync_dir, write_secret_file_atomic_0600};
use parvault::crypto::{LocalFileKeystore, LocalKeystoreSealer, NodeIdentity};
use parvault::datadir_lock::{ignored_on_empty_volume, DataDirLock, LockPurpose};
use parvault::network::admission::CHAIN_DIR_NAME;
use std::path::Path;
use zeroize::Zeroizing;

/// The files a bundle carries by name (K7); chains are `wot_chains/<64 hex>.bin`.
const BUNDLE_FILES: &[&str] = &[
    "ring_genesis.seed",
    "ring_genesis.pub",
    "node_identity.seed",
    "council_manifest.bin",
    "council_history.bin",
    "node_pq_kem.bin",
    "owner_pq_keypair.bin",
    "config.toml",
];
/// The vault master key's entry (32 raw bytes; resealed on restore).
const VAULT_MASTER_KEY: &str = "vault_master_key";
/// A restore's staging directory in the target data dir (K9).
const RESTORE_STAGE: &str = ".ring_restore.stage";
/// The write-ahead list of a restore's files (K9): present only while files are being moved.
const RESTORE_PENDING: &str = ".ring_restore.pending";

/// What `ring backup | restore` reads from its caller: the data dir and, from a `NodeConfig`,
/// the hardware profile (K1: `router-soc` writes with 19 MiB, t=2, p=1) and the configured
/// genesis pin (K6). `main` passes `&cfg.data_dir` until integration glue G-13 passes `&cfg`;
/// both compile against this one `run`.
pub(crate) trait RingTarget {
    /// The data dir.
    fn data_dir(&self) -> &Path;
    /// The writer's KDF parameters (K1).
    fn writer_kdf(&self) -> KdfParams {
        KdfParams::DEFAULT
    }
    /// The genesis public key the config pins, if any (K6).
    fn configured_genesis(&self) -> Option<&str> {
        None
    }
}

impl RingTarget for std::path::PathBuf {
    fn data_dir(&self) -> &Path {
        self
    }
}

impl RingTarget for parvault::config::NodeConfig {
    fn data_dir(&self) -> &Path {
        &self.data_dir
    }
    fn writer_kdf(&self) -> KdfParams {
        if self.hardware_profile == parvault::profile::HardwareProfile::RouterSoc {
            KdfParams::ROUTER_SOC
        } else {
            KdfParams::DEFAULT
        }
    }
    fn configured_genesis(&self) -> Option<&str> {
        self.genesis_root_pubkey_hex
            .as_deref()
            .filter(|s| !s.trim().is_empty())
    }
}

pub(crate) fn run<T: RingTarget + ?Sized>(action: RingAction, target: &T) -> anyhow::Result<()> {
    let data_dir = target.data_dir();
    match action {
        RingAction::Backup {
            out,
            passphrase_file,
        } => {
            let _lock = DataDirLock::acquire(data_dir, LockPurpose::RingBackup)?;
            backup(data_dir, &out, &passphrase_file, target.writer_kdf())
        }
        RingAction::Restore {
            from,
            passphrase_file,
            expect_ring,
            confirm_move,
        } => {
            let _lock = DataDirLock::acquire(data_dir, LockPurpose::RingRestore)?;
            let expected = expected_rings(expect_ring.as_deref(), target.configured_genesis())?;
            restore(data_dir, &from, &passphrase_file, &expected, confirm_move)
        }
    }
}

/// K6: the ring ids a restore must match: `--expect-ring`, the config's genesis pin and
/// `PARVAULT_GENESIS_PUBKEY_HEX`, each when given. Empty: print the ring id and proceed.
fn expected_rings(flag: Option<&str>, config: Option<&str>) -> anyhow::Result<Vec<[u8; 32]>> {
    let env = std::env::var("PARVAULT_GENESIS_PUBKEY_HEX")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let mut out = Vec::new();
    for (what, v) in [
        ("--expect-ring", flag),
        ("the config's genesis_root_pubkey_hex", config),
        ("PARVAULT_GENESIS_PUBKEY_HEX", env.as_deref()),
    ] {
        if let Some(h) = v {
            out.push(
                parse_hex32(h.as_bytes())
                    .ok_or_else(|| anyhow::anyhow!("{what} must be 64 hex characters"))?,
            );
        }
    }
    Ok(out)
}

/// Reads the passphrase file (K8). `out` is the backup's `--out` directory (a passphrase file
/// inside it would travel with the bundle).
fn read_passphrase(file: &Path, out: Option<&Path>) -> anyhow::Result<Zeroizing<String>> {
    use parvault::capabilities::{read_owner_only_file, OwnerFileRefusal};
    let inside_out = match out {
        Some(out) => {
            let dir = std::fs::canonicalize(out)?;
            let parent = file
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            std::fs::canonicalize(parent).is_ok_and(|p| p.starts_with(&dir))
        }
        None => false,
    };
    let (raw, owner_only) = if inside_out {
        (None, true)
    } else {
        match read_owner_only_file(file) {
            Ok(raw) => (Some(raw), true),
            Err(OwnerFileRefusal::NotOwnerOnly { is_file, uid, mode }) => {
                tracing::warn!(is_file, uid, mode, "passphrase file is not owner-only");
                (None, false)
            }
            Err(e) => anyhow::bail!("cannot read the passphrase file {}: {e:?}", file.display()),
        }
    };
    let pass = raw
        .as_ref()
        .and_then(|r| env::passphrase_from_file_bytes(r));
    match passphrase_file_decision(inside_out, owner_only, pass.is_some()) {
        Ok(()) => Ok(pass.expect("valid passphrase")),
        Err(code) => {
            tracing::warn!(code, "refused: passphrase file");
            anyhow::bail!(
                "{code}: {} must be a regular 0600 file of this user, outside the --out \
                 directory, holding UTF-8 text of at least {} characters (one trailing newline \
                 and a BOM are ignored)",
                file.display(),
                env::PASSPHRASE_MIN_CHARS
            )
        }
    }
}

fn read_opt(path: &Path) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(Zeroizing::new(b))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!("cannot read {}: {e}", path.display())),
    }
}

fn pub_of_seed(seed: &[u8]) -> Option<[u8; 32]> {
    let mut s: [u8; 32] = seed.try_into().ok()?;
    let pk = NodeIdentity::from_seed(s).public_key_bytes();
    zeroize::Zeroize::zeroize(&mut s);
    Some(pk)
}

fn parse_hex32(text: &[u8]) -> Option<[u8; 32]> {
    let raw = hex::decode(std::str::from_utf8(text).ok()?.trim()).ok()?;
    raw.as_slice().try_into().ok()
}

fn is_chain_name(name: &str) -> bool {
    name.strip_prefix(CHAIN_DIR_NAME)
        .and_then(|r| r.strip_prefix('/'))
        .and_then(|r| r.strip_suffix(".bin"))
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn backup(
    data_dir: &Path,
    out: &Path,
    passphrase_file: &Path,
    kdf: KdfParams,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(out)?;
    let pass = read_passphrase(passphrase_file, Some(out))?;
    let mut body = BackupBody::default();
    for name in BUNDLE_FILES {
        if let Some(bytes) = read_opt(&data_dir.join(name))? {
            body.entries.push(((*name).to_string(), bytes));
        }
    }
    if let Ok(rd) = std::fs::read_dir(data_dir.join(CHAIN_DIR_NAME)) {
        let mut names: Vec<String> = Vec::new();
        for e in rd {
            let name = format!("{CHAIN_DIR_NAME}/{}", e?.file_name().to_string_lossy());
            if is_chain_name(&name) {
                names.push(name);
            }
        }
        names.sort();
        for name in names {
            let bytes = std::fs::read(data_dir.join(&name))?;
            body.entries.push((name, Zeroizing::new(bytes)));
        }
    }
    let node_id = body
        .get("node_identity.seed")
        .and_then(pub_of_seed)
        .ok_or_else(|| anyhow::anyhow!("{} has no node identity", data_dir.display()))?;
    let ring_id = body
        .get("ring_genesis.seed")
        .and_then(pub_of_seed)
        .or_else(|| body.get("ring_genesis.pub").and_then(parse_hex32))
        .ok_or_else(|| anyhow::anyhow!("{}", parvault::crypto::keys::NOT_IN_RING_MESSAGE))?;
    // The vault master key (D-50 Q11), unsealed with this node's keystore; never created here.
    let sealed = data_dir.join("master_key.sealed");
    if sealed.exists() {
        anyhow::ensure!(
            data_dir.join("enclave_sealing.seed").exists()
                || std::env::var_os("PARVAULT_PASSPHRASE").is_some(),
            "cannot unseal {}: no enclave_sealing.seed and no PARVAULT_PASSPHRASE",
            sealed.display()
        );
        let keystore = LocalFileKeystore::from_passphrase_or_csprng_in_dir(data_dir, None)?;
        let blob = std::fs::read(&sealed)?;
        let mut raw = keystore.unseal_key(&blob)?;
        body.entries
            .push((VAULT_MASTER_KEY.to_string(), Zeroizing::new(raw.to_vec())));
        zeroize::Zeroize::zeroize(&mut raw);
    }
    let plain = body.encode()?;
    let bundle = env::seal(&pass, kdf, ring_id, node_id, &plain)?;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = out.join(format!(
        "parvault-ring-backup-{}-{secs}.pvbak",
        &hex::encode(node_id)[..16]
    ));
    write_secret_file_atomic_0600(&path, &bundle)?;
    fsync_dir(out)?;
    println!("Wrote the encrypted ring backup to {}", path.display());
    println!("  ring id: {}", hex::encode(ring_id));
    println!("  node id: {}", hex::encode(node_id));
    println!(
        "Keep the passphrase somewhere else than this file. The bundle holds this node's \
         identity: restoring it moves the node (the old one must be retired)."
    );
    Ok(())
}

/// K5: every entry name is known, the seeds are 32 bytes, and the header ids are the public
/// keys of the body's seeds (the ring id from the genesis seed when the body holds it, and the
/// pin must agree).
fn body_consistent(body: &BackupBody, header: &env::BackupHeader) -> bool {
    let names_ok = body.entries.iter().all(|(n, _)| {
        BUNDLE_FILES.contains(&n.as_str()) || is_chain_name(n) || n == VAULT_MASTER_KEY
    });
    let mut seen = std::collections::BTreeSet::new();
    let unique = body.entries.iter().all(|(n, _)| seen.insert(n.as_str()));
    let node_ok = body.get("node_identity.seed").and_then(pub_of_seed) == Some(header.node_id);
    let seed = body.get("ring_genesis.seed").map(pub_of_seed);
    let pin = body.get("ring_genesis.pub").map(parse_hex32);
    let ring_ok = match (seed, pin) {
        (None, None) => false,
        (s, p) => {
            s.is_none_or(|s| s == Some(header.ring_id))
                && p.is_none_or(|p| p == Some(header.ring_id))
        }
    };
    let mk_ok = body.get(VAULT_MASTER_KEY).is_none_or(|k| k.len() == 32);
    names_ok && unique && node_ok && ring_ok && mk_ok
}

/// The files a crashed restore left in the target (K9), from its write-ahead list.
fn pending_names(data_dir: &Path) -> anyhow::Result<Vec<String>> {
    let Some(text) = read_opt(&data_dir.join(RESTORE_PENDING))? else {
        return Ok(Vec::new());
    };
    let text = std::str::from_utf8(&text)
        .map_err(|_| anyhow::anyhow!("{RESTORE_PENDING} is not text"))?
        .to_string();
    let names: Vec<String> = text.lines().map(str::to_string).collect();
    anyhow::ensure!(
        names.iter().all(|n| BUNDLE_FILES.contains(&n.as_str())
            || is_chain_name(n)
            || n == "master_key.sealed"
            || n == "enclave_sealing.seed"),
        "{RESTORE_PENDING} names a file a restore never writes; remove the data dir by hand"
    );
    Ok(names)
}

/// The staging file `atomic_write_file` leaves when a kill hits the write of the list.
fn is_pending_staging(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|n| n.strip_prefix(RESTORE_PENDING))
        .is_some_and(|rest| rest.starts_with(".tmp."))
}

/// Whether the target holds nothing but the ignore list (A-146-3) and what a crashed restore
/// left (its staging dir, its write-ahead list and the files that list names).
fn target_empty(data_dir: &Path, pending: &[String]) -> anyhow::Result<bool> {
    let rd = match std::fs::read_dir(data_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e.into()),
    };
    for e in rd {
        let name = e?.file_name();
        let Some(name) = name.to_str() else {
            return Ok(false);
        };
        let known = ignored_on_empty_volume(name)
            || name == RESTORE_STAGE
            || name == RESTORE_PENDING
            || is_pending_staging(name)
            || pending
                .iter()
                .any(|p| p == name || (name == CHAIN_DIR_NAME && is_chain_name(p)));
        if !known {
            return Ok(false);
        }
    }
    Ok(true)
}

fn restore(
    data_dir: &Path,
    from: &Path,
    passphrase_file: &Path,
    expected: &[[u8; 32]],
    confirm_move: bool,
) -> anyhow::Result<()> {
    use std::io::Read;
    let pass = read_passphrase(passphrase_file, None)?;
    let mut bytes = Vec::new();
    std::fs::File::open(from)
        .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", from.display()))?
        .take(env::MAX_BUNDLE_LEN as u64 + 1)
        .read_to_end(&mut bytes)?;
    // The facts, in the decision's order; each only when the ones before it hold.
    let framed = env::parse_bundle(&bytes);
    let version_ok = framed.is_some();
    let params_ok = framed.is_some_and(|(h, _)| h.kdf.within_reader_limits());
    let plain = match framed {
        Some((h, ct)) if params_ok => {
            env::derive_key(&pass, &h.salt, h.kdf).and_then(|k| env::open(&k, &h, ct))
        }
        _ => None,
    };
    let tag_ok = plain.is_some();
    let body = plain.as_ref().and_then(|p| BackupBody::decode(p));
    let header = framed.map(|(h, _)| h);
    let consistent = match (&body, &header) {
        (Some(b), Some(h)) => body_consistent(b, h),
        _ => false,
    };
    let ring_matches =
        consistent && header.is_some_and(|h| expected.iter().all(|e| *e == h.ring_id));
    let pending = pending_names(data_dir)?;
    let empty = ring_matches && target_empty(data_dir, &pending)?;
    if let (Some(h), true) = (header, consistent) {
        println!("Bundle for ring {}", hex::encode(h.ring_id));
        println!("  node id: {}", hex::encode(h.node_id));
        if expected.is_empty() {
            println!("  (no --expect-ring and no configured genesis: check this ring id)");
        }
    }
    if let Err(code) = ring_restore_decision(
        version_ok,
        params_ok,
        tag_ok,
        consistent,
        ring_matches,
        empty,
        confirm_move,
    ) {
        tracing::warn!(code, "refused: ring restore");
        let why = match code {
            c if c.ends_with("move_not_confirmed") => {
                "a restore MOVES this node: the old node with this identity must be stopped \
                 and retired (two live nodes with one identity break the one-writer rule). \
                 Rerun with --confirm-move once it is."
            }
            c if c.ends_with("target_not_empty") => {
                "restore into an empty data dir (before the first `up`; on a Synology run the \
                 ring-restore service first)"
            }
            c if c.ends_with("auth_failed") => "wrong passphrase, or the bundle was modified",
            _ => "the bundle was not restored",
        };
        anyhow::bail!("{code}: {why}");
    }
    let body = body.expect("decided Ok");
    let header = header.expect("decided Ok");
    write_restore(data_dir, &body, &pending)?;
    println!(
        "Restored node {} of ring {} into {}. This is a move: retire the old node; do not \
         start both.",
        hex::encode(header.node_id),
        hex::encode(header.ring_id),
        data_dir.display()
    );
    Ok(())
}

/// K9: stage every file (0600, fsynced), write the list, rename each into place, fsync, then
/// drop the stage and last the list. A kill at any point leaves either nothing of the restore or the
/// list, which the next run clears before it starts over.
fn write_restore(data_dir: &Path, body: &BackupBody, pending: &[String]) -> anyhow::Result<()> {
    for name in pending {
        match std::fs::remove_file(data_dir.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    for e in std::fs::read_dir(data_dir)? {
        let e = e?;
        if e.file_name().to_str().is_some_and(is_pending_staging) {
            std::fs::remove_file(e.path())?;
        }
    }
    let stage = data_dir.join(RESTORE_STAGE);
    if stage.exists() {
        std::fs::remove_dir_all(&stage)?;
    }
    std::fs::create_dir_all(stage.join(CHAIN_DIR_NAME))?;
    let mut names: Vec<String> = Vec::new();
    for (name, data) in &body.entries {
        if name == VAULT_MASTER_KEY {
            continue;
        }
        write_secret_file_atomic_0600(&stage.join(name), data)?;
        names.push(name.clone());
    }
    if let Some(mk) = body.get(VAULT_MASTER_KEY) {
        let mut raw: [u8; 32] = mk.try_into().expect("checked 32 bytes");
        let keystore = LocalFileKeystore::from_passphrase_or_csprng_in_dir(&stage, None)?;
        let blob = keystore.seal_key(&raw)?;
        zeroize::Zeroize::zeroize(&mut raw);
        write_secret_file_atomic_0600(&stage.join("master_key.sealed"), &blob)?;
        names.push("master_key.sealed".to_string());
        if stage.join("enclave_sealing.seed").exists() {
            names.push("enclave_sealing.seed".to_string());
        }
    }
    fsync_dir(&stage.join(CHAIN_DIR_NAME))?;
    fsync_dir(&stage)?;
    parvault::storage::fsio::atomic_write_file(
        &data_dir.join(RESTORE_PENDING),
        names.join("\n").as_bytes(),
    )?;
    fsync_dir(data_dir)?;
    let has_chains = names.iter().any(|n| is_chain_name(n));
    if has_chains {
        std::fs::create_dir_all(data_dir.join(CHAIN_DIR_NAME))?;
    }
    for name in &names {
        std::fs::rename(stage.join(name), data_dir.join(name))?;
    }
    if has_chains {
        fsync_dir(&data_dir.join(CHAIN_DIR_NAME))?;
    }
    fsync_dir(data_dir)?;
    // The stage first: while the list exists, a rerun redoes the whole restore.
    std::fs::remove_dir_all(&stage)?;
    fsync_dir(data_dir)?;
    std::fs::remove_file(data_dir.join(RESTORE_PENDING))?;
    fsync_dir(data_dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use parvault::config::NodeConfig;
    use parvault::profile::HardwareProfile;
    use std::path::PathBuf;

    fn write_0600(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// A genesis node in `<tmp>/src` and its bundle written through a `NodeConfig` (glue G-13).
    fn bundle_with(tmp: &Path, profile: HardwareProfile) -> (NodeConfig, PathBuf, PathBuf) {
        let src = tmp.join("src");
        NodeIdentity::init_ring_genesis_in_dir(&src).unwrap();
        NodeIdentity::load_or_generate_in_dir(&src).unwrap();
        let pass = tmp.join("pass");
        write_0600(&pass, b"a passphrase of twenty-plus characters");
        let cfg = NodeConfig {
            data_dir: src,
            hardware_profile: profile,
            ..NodeConfig::default()
        };
        let out = tmp.join("out");
        run(
            RingAction::Backup {
                out: out.clone(),
                passphrase_file: pass.clone(),
            },
            &cfg,
        )
        .unwrap();
        let bundle = std::fs::read_dir(&out)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        (cfg, bundle, pass)
    }

    #[test]
    fn k1_the_router_soc_profile_writes_its_own_kdf_parameters() {
        for (profile, want) in [
            (HardwareProfile::RouterSoc, KdfParams::ROUTER_SOC),
            (HardwareProfile::Desktop, KdfParams::DEFAULT),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let (_, bundle, _) = bundle_with(tmp.path(), profile);
            let (h, _) = env::parse_bundle(&std::fs::read(bundle).unwrap()).unwrap();
            assert_eq!(h.kdf, want, "{profile:?}");
        }
    }

    #[test]
    fn k6_a_restore_matches_the_configured_genesis_pin() {
        let tmp = tempfile::tempdir().unwrap();
        let (src, bundle, pass) = bundle_with(tmp.path(), HardwareProfile::RouterSoc);
        let ring = std::fs::read_to_string(src.data_dir.join("ring_genesis.pub")).unwrap();
        let restore_into = |name: &str, pin: String| {
            let cfg = NodeConfig {
                data_dir: tmp.path().join(name),
                genesis_root_pubkey_hex: Some(pin),
                ..NodeConfig::default()
            };
            let r = run(
                RingAction::Restore {
                    from: bundle.clone(),
                    passphrase_file: pass.clone(),
                    expect_ring: None,
                    confirm_move: true,
                },
                &cfg,
            );
            (r, cfg.data_dir)
        };
        let (r, dir) = restore_into("other", "ab".repeat(32));
        let e = r.unwrap_err().to_string();
        assert!(e.starts_with("reject.backup_wrong_ring"), "{e}");
        assert!(!dir.join("node_identity.seed").exists());
        let (r, dir) = restore_into("same", ring.trim().to_string());
        r.unwrap();
        assert_eq!(
            std::fs::read(dir.join("ring_genesis.seed")).unwrap(),
            std::fs::read(src.data_dir.join("ring_genesis.seed")).unwrap()
        );
    }
}
