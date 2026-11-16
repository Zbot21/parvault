//! `parvault ring backup | restore`: the encrypted genesis backup (B-169, K1-K12; `v0.5.6`
//! track E), on `parvault::crypto::backup_envelope`. Both run under the data-dir lock
//! (`DataDirLock`, B-174).
//!
//! `v0.5.6` T0 stub: the lock call site is in place (it passes through until track E fills it
//! in); both subcommands are then refused (`reject.not_built_yet`).

use parvault::config::RingAction;
use parvault::datadir_lock::{DataDirLock, LockPurpose};
use std::path::Path;

pub(crate) fn run(action: RingAction, data_dir: &Path) -> anyhow::Result<()> {
    let (purpose, entry) = match action {
        RingAction::Backup { .. } => (LockPurpose::RingBackup, "ring backup"),
        RingAction::Restore { .. } => (LockPurpose::RingRestore, "ring restore"),
    };
    let _lock = DataDirLock::acquire(data_dir, purpose)?;
    Err(parvault::seam::not_built_yet(parvault::seam::Unbuilt { track: "E", entry }).into())
}
