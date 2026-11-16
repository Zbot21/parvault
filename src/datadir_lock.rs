//! The data-dir lock (B-174, A-146-1; `v0.5.6` track E): an exclusive lock on
//! `<data>/.parvault.lock` (std `File::try_lock`, no `unsafe`, no new crate), held by `up` and
//! `daemon start` for the process lifetime and by `wot init`, `wot install-chain`,
//! `ring backup` and `ring restore`. A second holder is refused (`reject.datadir_locked`).
//!
//! `v0.5.6` T0 seam: every call site exists; [`DataDirLock::acquire`] passes through (takes no
//! lock and creates no file) until track E fills it in, so nothing changes before then.

use std::path::{Path, PathBuf};

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

/// Why the lock was not taken.
#[derive(Debug)]
pub enum LockRefusal {
    /// Another process holds it.
    Held,
    /// The lock file could not be opened or locked.
    Io(std::io::Error),
}

impl std::fmt::Display for LockRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held => write!(f, "the data dir is in use by another parvault process"),
            Self::Io(e) => write!(f, "cannot lock the data dir: {e}"),
        }
    }
}

impl std::error::Error for LockRefusal {}

/// A held data-dir lock; released on drop.
#[derive(Debug)]
pub struct DataDirLock {
    path: PathBuf,
    purpose: LockPurpose,
}

impl DataDirLock {
    /// Takes the lock on `data_dir` for `purpose`. T0 stub: passes through (no lock, no file).
    pub fn acquire(data_dir: &Path, purpose: LockPurpose) -> Result<Self, LockRefusal> {
        Ok(Self {
            path: data_dir.join(DATADIR_LOCK_FILE),
            purpose,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t0_lock_passes_through_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let a = DataDirLock::acquire(dir.path(), LockPurpose::Daemon).unwrap();
        let b = DataDirLock::acquire(dir.path(), LockPurpose::RingInit).unwrap();
        assert_eq!(a.path(), b.path());
        assert_eq!(b.purpose(), LockPurpose::RingInit);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
