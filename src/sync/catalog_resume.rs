//! A vault catalog fetched from the ring: whether the VFS imports it (claim `B20-LIST`, track C)
//! and whether a `watch-folder` pass with no local snapshot resumes the vault from it (glue G-23,
//! B-169 K11: a restored owner, or any fresh node given the seed phrase, continues the vault's
//! versions instead of starting at 1 and being refused as a rollback).

/// What [`catalog_import_decision`] allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogImport {
    /// A newer catalog: apply it.
    Apply,
    /// The version already loaded: nothing to do.
    Unchanged,
}

/// Claim `B20-LIST` (`@guard`): whether a fetched vault catalog is imported. A catalog that
/// fails verification or names another vault key is foreign (`reject.catalog_foreign`); one
/// older than the loaded version is a rollback (`reject.catalog_rollback`).
pub const fn catalog_import_decision(
    envelope_verifies: bool,
    key_matches: bool,
    envelope_version: u64,
    loaded_version: u64,
) -> Result<CatalogImport, &'static str> {
    if !envelope_verifies || !key_matches {
        return Err("reject.catalog_foreign");
    }
    if envelope_version < loaded_version {
        return Err("reject.catalog_rollback");
    }
    if envelope_version == loaded_version {
        return Ok(CatalogImport::Unchanged);
    }
    Ok(CatalogImport::Apply)
}

/// What a fetched catalog looks like to [`catalog_resume_decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum CatalogFetch {
    /// No ring endpoint is configured (a local-only folder): there is no ring to resume from.
    NoRing,
    /// Endpoints are configured but none answered.
    Unreachable,
    /// The ring answered and holds no catalog for this vault key.
    NotFound,
    /// The ring's newest catalog for this vault key: whether it verifies and names this vault's
    /// owner key and catalog DHT key.
    Found {
        envelope_verifies: bool,
        key_matches: bool,
        version: u64,
    },
}

/// What [`catalog_resume_decision`] allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogResume {
    /// A local snapshot exists: the pass continues from it.
    Local,
    /// No catalog of this vault exists (or none can be trusted): start at version 1.
    Fresh,
    /// Continue from the ring's catalog: the pass publishes above its version.
    Resume,
}

/// Claim `CATALOG-RESUME` (`@guard`, glue G-23): with no local snapshot, a `watch-folder` pass
/// with a seed phrase resumes from the ring's catalog only when [`catalog_import_decision`]
/// would import it (it verifies and names this vault's keys); a foreign or unverifiable catalog
/// is never adopted (start fresh, logged by the caller). An unreachable ring refuses the pass
/// (`reject.catalog_resume_unreachable`, retried next pass) rather than publish version 1 and
/// fork the vault.
pub fn catalog_resume_decision(
    has_local_snapshot: bool,
    fetch: CatalogFetch,
) -> Result<CatalogResume, &'static str> {
    if has_local_snapshot {
        return Ok(CatalogResume::Local);
    }
    match fetch {
        CatalogFetch::NoRing | CatalogFetch::NotFound => Ok(CatalogResume::Fresh),
        CatalogFetch::Unreachable => Err("reject.catalog_resume_unreachable"),
        CatalogFetch::Found {
            envelope_verifies,
            key_matches,
            version,
        } => match catalog_import_decision(envelope_verifies, key_matches, version, 0) {
            Ok(_) => Ok(CatalogResume::Resume),
            Err(_) => Ok(CatalogResume::Fresh),
        },
    }
}

/// D16 (`v0.5.6` QA fix): the one rule for a seed vault namespace that a data dir keeps files
/// for (`vaults/<ns>.vaultkey`, `vaults/<ns>.floor`). `register_vault_keys` refuses any other
/// (`reject.vault_namespace_unsupported`) and a ring backup carries the floor of every name it
/// allows, so no registered vault's rollback floor is lost in a backup. 1 to 128 bytes of
/// printable ASCII (spaces allowed), no `/` or `\`, not `.` or `..`: the backup format's entry
/// names are ASCII (`crypto::backup_envelope`) and a restore lists them one per line.
pub fn vault_namespace_ok(ns: &str) -> bool {
    (1..=128).contains(&ns.len())
        && ns != "."
        && ns != ".."
        && ns
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'/' && b != b'\\')
}
