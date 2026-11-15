//! Crash-safe file writes (client-side: no runtime dependencies).

use crate::storage::error::StorageError;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Reads a state file for a fail-closed load: `Ok(None)` only when the file is absent. Any other
/// read error is returned, so a caller never mistakes an unreadable file for an empty state.
pub fn read_state_file(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(raw) => Ok(Some(raw)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Writes `bytes` to `target_path` atomically: temp file, `sync_all`, rename (ADR-19).
pub fn atomic_write_file(target_path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }
    let rnd: [u8; 8] = rand::Rng::gen(&mut rand::rngs::OsRng);
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("parvault_blob");
    let tmp_path = parent.join(format!(".{file_name}.tmp.{}", hex::encode(rnd)));
    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp_path, target_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(StorageError::Io(e));
    }
    Ok(())
}
