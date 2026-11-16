//! The data-dir lock (B-174, A-146-1; `v0.5.6` track E): an exclusive lock on
//! `<data>/.parvault.lock` (std `File::try_lock`, no `unsafe`, no new crate), held by `up` and
//! `daemon start` for the process lifetime and by `wot init`, `wot install-chain`,
//! `ring backup` and `ring restore`. A second holder is refused (`reject.datadir_locked`).
//!
//! `up` takes it in `onboarding::up_setup_preflight`, before the command creates any file in
//! the data dir, and parks it with [`hold_for_process`]; the daemon then takes it back with
//! [`take_process_lock`] and holds it until it exits (qa-t0, proposal g). The lock is an
//! open-file-description lock (`flock`): the kernel releases it when the process dies, even on
//! SIGKILL, so a stale lock file never blocks a restart.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The lock file in a data dir.
pub const DATADIR_LOCK_FILE: &str = ".parvault.lock";

/// What the lock is taken for (logged with a refusal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockPurpose {
    /// `up` and `daemon start`, for the process lifetime.
    Daemon,
    /// `wot init`.
    RingInit,
    /// `wot install-chain` (join).
    InstallChain,
    /// `ring backup`.
    RingBackup,
    /// `ring restore`.
    RingRestore,
}

impl LockPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::RingInit => "wot init",
            Self::InstallChain => "wot install-chain",
            Self::RingBackup => "ring backup",
            Self::RingRestore => "ring restore",
        }
    }
}

/// Why the lock was not taken.
#[derive(Debug)]
pub enum LockRefusal {
    /// Another process (or another open of the file) holds it; the refusal code.
    Held(&'static str),
    /// The lock file could not be opened or locked.
    Io(std::io::Error),
}

impl std::fmt::Display for LockRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held(code) => write!(
                f,
                "{code}: the data dir is in use by another parvault process \
                 (stop it first; one data dir serves one process)"
            ),
            Self::Io(e) => write!(f, "cannot lock the data dir: {e}"),
        }
    }
}

impl std::error::Error for LockRefusal {}

/// A held data-dir lock; released on drop (or when the process dies).
#[derive(Debug)]
pub struct DataDirLock {
    path: PathBuf,
    purpose: LockPurpose,
    // Held for its lock; closing it releases the lock.
    _file: std::fs::File,
}

impl DataDirLock {
    /// Takes the lock on `data_dir` for `purpose`, creating the data dir and the lock file
    /// (`0600`, never through a symlink) if needed. Never blocks: a held lock is refused with
    /// [`LockRefusal::Held`] (`reject.datadir_locked`; claim `B174-LOCK`).
    pub fn acquire(data_dir: &Path, purpose: LockPurpose) -> Result<Self, LockRefusal> {
        std::fs::create_dir_all(data_dir).map_err(LockRefusal::Io)?;
        let path = data_dir.join(DATADIR_LOCK_FILE);
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = opts.open(&path).map_err(LockRefusal::Io)?;
        match file.try_lock() {
            Ok(()) => Ok(Self {
                path,
                purpose,
                _file: file,
            }),
            Err(std::fs::TryLockError::WouldBlock) => {
                let code = "reject.datadir_locked";
                tracing::warn!(
                    code,
                    purpose = purpose.as_str(),
                    path = %path.display(),
                    "refused: the data dir is locked by another process"
                );
                Err(LockRefusal::Held(code))
            }
            Err(std::fs::TryLockError::Error(e)) => Err(LockRefusal::Io(e)),
        }
    }

    /// The lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What it was taken for.
    pub fn purpose(&self) -> LockPurpose {
        self.purpose
    }
}

/// The lock `up` took before the command created any file, parked for the daemon.
static PROCESS_LOCK: Mutex<Option<DataDirLock>> = Mutex::new(None);

/// Parks `lock` for the rest of the process (`up`'s preflight hands it to the daemon).
pub fn hold_for_process(lock: DataDirLock) {
    let mut slot = PROCESS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    *slot = Some(lock);
}

/// Takes back the parked lock if it is for `data_dir`; `None` if none is parked.
pub fn take_process_lock(data_dir: &Path) -> Option<DataDirLock> {
    let mut slot = PROCESS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if slot
        .as_ref()
        .is_some_and(|l| l.path == data_dir.join(DATADIR_LOCK_FILE))
    {
        slot.take()
    } else {
        None
    }
}

/// The daemon's lock: the one `up` parked, or a new one (`daemon start`).
pub fn daemon_lock(data_dir: &Path) -> Result<DataDirLock, LockRefusal> {
    match take_process_lock(data_dir) {
        Some(l) => Ok(l),
        None => DataDirLock::acquire(data_dir, LockPurpose::Daemon),
    }
}

/// The files `up --init-if-absent` ignores when it decides whether a volume is empty
/// (A-146-3): a fixed list, nothing else. The join-token file is ignored by its own name when it
/// lives in the data dir; the genesis staging files (A-146-2, arch056c 2.4) are swept first.
pub const EMPTY_VOLUME_IGNORED: &[&str] = &[
    "lost+found",
    "@eaDir",
    DATADIR_LOCK_FILE,
    EDGE_TLS_KEY_FILE,
    EDGE_TLS_CERT_FILE,
];

/// The edge TLS key the daemon writes at its first `up` (track A, A-TLS-6).
pub const EDGE_TLS_KEY_FILE: &str = "edge_tls.key";
/// The edge TLS certificate the daemon writes at its first `up` (track A, A-TLS-6).
pub const EDGE_TLS_CERT_FILE: &str = "edge_tls.crt";

/// The ring files a data dir holds (arch056c 2.5: five values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum RingFiles {
    /// Neither `ring_genesis.seed` nor `ring_genesis.pub`.
    Neither,
    /// The seed without its pin: an init killed between the two writes (A-146-2).
    SeedOnly,
    /// The pin without a seed: a joined node, or a partial state when no chain is stored.
    PinOnly,
    /// Seed and pin name the same key: this node started the ring.
    Agree,
    /// Seed and pin name different keys: never repaired (arch056c 2.2).
    Disagree,
}

/// What `up --init-if-absent` sees in the data dir, after the staging files are swept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct VolumeState {
    /// The ring files.
    pub ring: RingFiles,
    /// Any entry outside the ring files, the chain dir and [`EMPTY_VOLUME_IGNORED`].
    pub other_files: bool,
    /// At least one installed delegation chain (`wot_chains/*.bin`).
    pub chain_stored: bool,
}

/// What `up` does about the ring before it starts (B-146 item 8, A-146-1 to A-146-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitIfAbsent {
    /// Neither flag: today's behaviour (no change to the data dir).
    Skip,
    /// An empty volume: start a new ring here, once.
    Init,
    /// A seed without its pin: write the pin from the on-disk seed (arch056c 2.1).
    ResumePin,
    /// This node is already in its ring: nothing to do.
    OwnRing,
    /// A join token is configured: join (it always wins, A-146-4).
    Join,
    /// Refused, with the code: `reject.init_volume_not_empty` (a non-empty volume that holds no
    /// ring, Q6) or `reject.init_partial_state` (a pin without a seed or chain, or a seed and pin
    /// that disagree, A-146-2).
    Refuse(&'static str),
}

/// The `up --init-if-absent` / `--join-token-file` decision (claim `B146-INIT`). A configured
/// join token never leads to [`InitIfAbsent::Init`] (A-146-4), and nothing ever makes a second
/// genesis: `Init` only for a volume with no ring file and nothing else in it.
pub fn init_if_absent_decision(
    volume_state: VolumeState,
    join_token_set: bool,
    flag: bool,
) -> InitIfAbsent {
    use InitIfAbsent::*;
    let v = volume_state;
    if v.ring == RingFiles::Disagree {
        return Refuse("reject.init_partial_state");
    }
    if join_token_set {
        return match v.ring {
            // A genesis holder is never re-pinned to another ring by a token.
            RingFiles::SeedOnly | RingFiles::Agree => Refuse("reject.init_partial_state"),
            _ => Join,
        };
    }
    if !flag {
        return Skip;
    }
    match v.ring {
        RingFiles::Neither if v.other_files => Refuse("reject.init_volume_not_empty"),
        RingFiles::Neither if v.chain_stored => Refuse("reject.init_partial_state"),
        RingFiles::Neither => Init,
        RingFiles::SeedOnly => ResumePin,
        RingFiles::PinOnly if v.chain_stored => OwnRing,
        RingFiles::PinOnly => Refuse("reject.init_partial_state"),
        RingFiles::Agree => OwnRing,
        RingFiles::Disagree => Refuse("reject.init_partial_state"),
    }
}

/// Reads [`VolumeState`] from `data_dir` (a missing dir is empty). `ignored_name` is the
/// join-token file's name when that file lives in the data dir. Run under the lock, after
/// [`crate::crypto::NodeIdentity::sweep_genesis_staging_files`].
pub fn classify_volume(
    data_dir: &Path,
    ignored_name: Option<&std::ffi::OsStr>,
) -> std::io::Result<VolumeState> {
    use crate::crypto::keys::{RING_GENESIS_PUB_FILE, RING_GENESIS_SEED_FILE};
    use crate::network::admission::CHAIN_DIR_NAME;
    let entries = match std::fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VolumeState {
                ring: RingFiles::Neither,
                other_files: false,
                chain_stored: false,
            })
        }
        Err(e) => return Err(e),
    };
    let mut other_files = false;
    for entry in entries {
        let name = entry?.file_name();
        let known = name == RING_GENESIS_SEED_FILE
            || name == RING_GENESIS_PUB_FILE
            || name == CHAIN_DIR_NAME
            || ignored_name.is_some_and(|n| n == name)
            || EMPTY_VOLUME_IGNORED.iter().any(|i| name == *i);
        other_files |= !known;
    }
    let chain_stored = match std::fs::read_dir(data_dir.join(CHAIN_DIR_NAME)) {
        Ok(rd) => {
            let mut any = false;
            for e in rd {
                any |= e?.path().extension().is_some_and(|x| x == "bin");
            }
            any
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    let seed = read_seed_pub(&data_dir.join(RING_GENESIS_SEED_FILE))?;
    let pin = read_pin(&data_dir.join(RING_GENESIS_PUB_FILE))?;
    let ring = match (seed, pin) {
        (None, None) => RingFiles::Neither,
        (Some(_), None) => RingFiles::SeedOnly,
        (None, Some(_)) => RingFiles::PinOnly,
        (Some(s), Some(p)) if s == p => RingFiles::Agree,
        (Some(_), Some(_)) => RingFiles::Disagree,
    };
    Ok(VolumeState {
        ring,
        other_files,
        chain_stored,
    })
}

/// The public key of an on-disk genesis seed (never the env seed; arch056c 2.1). A seed file
/// that is not 32 bytes is an error, never treated as absent.
fn read_seed_pub(path: &Path) -> std::io::Result<Option<[u8; 32]>> {
    use zeroize::Zeroize;
    let mut raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if raw.len() != 32 {
        raw.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} must hold 32 bytes", path.display()),
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw);
    raw.zeroize();
    let id = crate::crypto::NodeIdentity::from_seed(seed);
    seed.zeroize();
    Ok(Some(id.public_key_bytes()))
}

fn read_pin(path: &Path) -> std::io::Result<Option<[u8; 32]>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let raw = hex::decode(text.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let pin: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} must hold 64 hex characters", path.display()),
        )
    })?;
    Ok(Some(pin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_holder_is_refused_until_the_first_drops() {
        let dir = tempfile::tempdir().unwrap();
        let a = DataDirLock::acquire(dir.path(), LockPurpose::Daemon).unwrap();
        let b = DataDirLock::acquire(dir.path(), LockPurpose::RingInit);
        let b = b.unwrap_err();
        assert!(matches!(b, LockRefusal::Held(_)), "{b:?}");
        assert!(b.to_string().starts_with("reject.datadir_locked: "), "{b}");
        assert_eq!(a.purpose(), LockPurpose::Daemon);
        drop(a);
        let c = DataDirLock::acquire(dir.path(), LockPurpose::RingInit).unwrap();
        assert_eq!(c.path(), dir.path().join(DATADIR_LOCK_FILE));
    }

    #[cfg(unix)]
    #[test]
    fn the_lock_file_is_0600_and_never_followed_through_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let l = DataDirLock::acquire(dir.path(), LockPurpose::Daemon).unwrap();
        let mode = std::fs::metadata(l.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(l);
        let other = tempfile::tempdir().unwrap();
        let target = other.path().join("victim");
        std::fs::write(&target, b"x").unwrap();
        let link_dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(&target, link_dir.path().join(DATADIR_LOCK_FILE)).unwrap();
        let r = DataDirLock::acquire(link_dir.path(), LockPurpose::Daemon);
        assert!(matches!(r, Err(LockRefusal::Io(_))), "{r:?}");
    }

    #[test]
    fn the_parked_lock_is_handed_to_the_daemon_once() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        hold_for_process(DataDirLock::acquire(dir.path(), LockPurpose::Daemon).unwrap());
        assert!(take_process_lock(other.path()).is_none());
        // Still parked: a fresh acquire is refused.
        assert!(matches!(
            DataDirLock::acquire(dir.path(), LockPurpose::Daemon),
            Err(LockRefusal::Held(_))
        ));
        let l = daemon_lock(dir.path()).unwrap();
        assert!(take_process_lock(dir.path()).is_none());
        drop(l);
    }
}
