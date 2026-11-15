//! Signed, epoch-versioned eviction council manifest (F-08, ADR-19, ADR-26).
//!
//! The council that may sign eviction orders is no longer read from config, env or CLI. It is a
//! [`CouncilManifest`]: epoch 1 is signed by the scope root (the ring genesis, or in public mode
//! the pinned tracker admin key), and epoch `n + 1` by a quorum of epoch `n`. Every epoch has a
//! strict majority quorum (`2 * quorum > members`). A node with no manifest accepts no council
//! orders. The single resolver is [`council_from_manifest`].
//!
//! Known limit: a quorum of epoch `n` that signs two different epoch `n + 1` manifests forks the
//! council; nodes keep whichever successor they install first (no equivocation proof exists).
//!
//! Formal model: `specs/ParVaultZeroKeyAdminAndQuorum.tla` (guards `ring-scope`, `council-manifest`).

use crate::crypto::NodeIdentity;
use crate::storage::block_store::{BlockStore, StorageError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Domain separator for [`CouncilManifest`] signatures.
pub const COUNCIL_MANIFEST_DOMAIN: &[u8] = b"parvault-council-manifest-v1:";
/// Domain separator for re-root signatures (F-53, L-98): followed by the old scope root, then the
/// same fields as [`CouncilManifest::canonical_sign_bytes`], so a rotation's signatures never
/// verify as a re-root and the reverse.
pub const COUNCIL_REROOT_DOMAIN: &[u8] = b"parvault-council-reroot-v1:";
/// Most members a council may have.
pub const MAX_COUNCIL_MEMBERS: usize = 64;
/// Largest encoded manifest accepted from disk or the wire.
pub const MAX_COUNCIL_MANIFEST_BYTES: usize = 64 * 1024;
/// File holding the installed manifest.
pub const COUNCIL_MANIFEST_FILE: &str = "council_manifest.bin";
/// File holding every installed epoch of this scope, oldest first (served to peers behind).
pub const COUNCIL_HISTORY_FILE: &str = "council_history.bin";
/// Most epochs kept in the history (the oldest are dropped).
pub const MAX_COUNCIL_HISTORY: usize = 256;

/// One signature over [`CouncilManifest::canonical_sign_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CouncilSignature {
    pub signer_pubkey: [u8; 32],
    pub sig_r: [u8; 32],
    pub sig_s: [u8; 32],
}

/// The eviction council of one scope at one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CouncilManifest {
    /// Ring genesis, or the pinned tracker admin key in public mode. Signs epoch 1.
    pub scope_root: [u8; 32],
    pub epoch: u64,
    /// Member keys, strictly ascending (canonical, no duplicates).
    pub members: Vec<[u8; 32]>,
    pub quorum: u32,
    pub issued_at_ms: u64,
    pub signatures: Vec<CouncilSignature>,
}

/// Inputs of [`council_manifest_decision`], computed by [`CouncilManifest::facts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CouncilManifestFacts {
    pub members: usize,
    /// Members strictly ascending and none all-zero.
    pub members_canonical: bool,
    pub quorum: usize,
    pub epoch: u64,
    /// Epoch of the installed manifest, if any.
    pub current_epoch: Option<u64>,
    /// The manifest's scope root is the one this node trusts (and equals the current one's).
    pub scope_matches: bool,
    /// Epoch 1: the scope root signed it. Epoch n + 1: a quorum of epoch n's members signed it
    /// (for a re-root, under [`COUNCIL_REROOT_DOMAIN`]).
    pub authorised: bool,
    /// The manifest's scope root differs from the installed one's (a re-root, L-98).
    pub rerooted: bool,
    /// The node runs in public mode (a private ring's root is its genesis and never moves).
    pub public_mode: bool,
    /// A re-root carries the new root's own signature under [`COUNCIL_REROOT_DOMAIN`].
    pub new_root_signed: bool,
}

/// Who installs a manifest, which fixes the one re-root shape it may accept (verdict change 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CouncilInstallRole {
    /// A private ring node: the root is the ring genesis; no re-root.
    Private,
    /// A public seed: a re-root only onto its configured root.
    PublicSeed,
    /// A public client: a re-root only away from its pinned root.
    PublicClient,
}

/// F-08: a council manifest is accepted only with 1..=64 canonical members, a strict majority
/// quorum, and a valid epoch chain from what this node holds.
pub fn council_manifest_decision(f: &CouncilManifestFacts) -> Result<(), &'static str> {
    if f.members == 0 || f.members > MAX_COUNCIL_MEMBERS || !f.members_canonical {
        return Err("reject.council_members_invalid");
    }
    if f.quorum == 0 || f.quorum > f.members || 2 * f.quorum <= f.members {
        return Err("reject.council_quorum_below_majority");
    }
    if f.rerooted && !f.public_mode {
        return Err("reject.council_reroot_private");
    }
    let next_epoch = match f.current_epoch {
        None => f.epoch == 1,
        Some(cur) => cur.checked_add(1) == Some(f.epoch),
    };
    if !f.scope_matches || !next_epoch || !f.authorised {
        return Err("reject.council_epoch_chain");
    }
    if f.rerooted && !f.new_root_signed {
        return Err("reject.council_reroot_unsigned");
    }
    Ok(())
}

impl CouncilManifest {
    /// An unsigned manifest with `members` sorted and deduplicated.
    pub fn new(
        scope_root: [u8; 32],
        epoch: u64,
        mut members: Vec<[u8; 32]>,
        quorum: u32,
        issued_at_ms: u64,
    ) -> Self {
        members.sort_unstable();
        members.dedup();
        Self {
            scope_root,
            epoch,
            members,
            quorum,
            issued_at_ms,
            signatures: Vec::new(),
        }
    }

    /// Deterministic signing payload (golden vector in the tests).
    pub fn canonical_sign_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            COUNCIL_MANIFEST_DOMAIN.len() + 32 + 8 + 4 + 8 + 4 + 32 * self.members.len(),
        );
        out.extend_from_slice(COUNCIL_MANIFEST_DOMAIN);
        self.push_fields(&mut out);
        out
    }

    /// Re-root signing payload: [`COUNCIL_REROOT_DOMAIN`], the old root, then the manifest
    /// fields (golden vector in the tests). Binds what the signers move the council away from.
    pub fn reroot_sign_bytes(&self, old_root: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            COUNCIL_REROOT_DOMAIN.len() + 64 + 8 + 4 + 8 + 4 + 32 * self.members.len(),
        );
        out.extend_from_slice(COUNCIL_REROOT_DOMAIN);
        out.extend_from_slice(old_root);
        self.push_fields(&mut out);
        out
    }

    fn push_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.scope_root);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.quorum.to_be_bytes());
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&(self.members.len() as u32).to_be_bytes());
        for m in &self.members {
            out.extend_from_slice(m);
        }
    }

    /// Adds `signer`'s signature (once per key).
    pub fn sign(&mut self, signer: &NodeIdentity) {
        let msg = self.canonical_sign_bytes();
        self.sign_bytes(signer, &msg);
    }

    /// Adds `signer`'s re-root signature away from `old_root` (once per key). The quorum of the
    /// installed epoch and the new root both sign this (L-98).
    pub fn sign_reroot(&mut self, signer: &NodeIdentity, old_root: &[u8; 32]) {
        let msg = self.reroot_sign_bytes(old_root);
        self.sign_bytes(signer, &msg);
    }

    fn sign_bytes(&mut self, signer: &NodeIdentity, msg: &[u8]) {
        let signer_pubkey = signer.public_key_bytes();
        if self
            .signatures
            .iter()
            .any(|s| s.signer_pubkey == signer_pubkey)
        {
            return;
        }
        let sig = signer.sign(msg);
        let mut sig_r = [0u8; 32];
        let mut sig_s = [0u8; 32];
        sig_r.copy_from_slice(&sig[..32]);
        sig_s.copy_from_slice(&sig[32..]);
        self.signatures.push(CouncilSignature {
            signer_pubkey,
            sig_r,
            sig_s,
        });
    }

    /// Distinct keys in `allowed` with a valid signature over `msg`.
    fn valid_signers(&self, msg: &[u8], allowed: &[[u8; 32]]) -> usize {
        let mut seen: Vec<[u8; 32]> = Vec::new();
        for s in self.signatures.iter().take(MAX_COUNCIL_MEMBERS + 1) {
            if !allowed.contains(&s.signer_pubkey) || seen.contains(&s.signer_pubkey) {
                continue;
            }
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&s.sig_r);
            sig[32..].copy_from_slice(&s.sig_s);
            if NodeIdentity::verify_with_pubkey(&s.signer_pubkey, msg, &sig) {
                seen.push(s.signer_pubkey);
            }
        }
        seen.len()
    }

    /// The facts for installing `self` as `role` on a node trusting `expected_root` that holds
    /// `current`. A re-root (`self.scope_root` differs from `current`'s) matches the scope only
    /// in its role's one shape: a seed onto its configured root, a client away from its pinned
    /// root (verdict change 3).
    pub fn facts(
        &self,
        expected_root: [u8; 32],
        current: Option<&CouncilManifest>,
        role: CouncilInstallRole,
    ) -> CouncilManifestFacts {
        let members_canonical =
            self.members.windows(2).all(|w| w[0] < w[1]) && !self.members.contains(&[0u8; 32]);
        let rerooted = current.is_some_and(|c| c.scope_root != self.scope_root);
        let scope_matches = expected_root != [0u8; 32]
            && self.scope_root != [0u8; 32]
            && match current {
                Some(c) if rerooted => match role {
                    CouncilInstallRole::PublicSeed => self.scope_root == expected_root,
                    CouncilInstallRole::PublicClient => c.scope_root == expected_root,
                    CouncilInstallRole::Private => false,
                },
                _ => self.scope_root == expected_root,
            };
        let canonical = self.canonical_sign_bytes();
        let (authorised, new_root_signed) = match current {
            None => (
                self.valid_signers(&canonical, &[self.scope_root]) == 1,
                false,
            ),
            Some(c) if rerooted => {
                let msg = self.reroot_sign_bytes(&c.scope_root);
                (
                    self.valid_signers(&msg, &c.members) >= c.quorum as usize,
                    self.valid_signers(&msg, &[self.scope_root]) == 1,
                )
            }
            Some(c) => (
                self.valid_signers(&canonical, &c.members) >= c.quorum as usize,
                false,
            ),
        };
        CouncilManifestFacts {
            members: self.members.len(),
            members_canonical,
            quorum: self.quorum as usize,
            epoch: self.epoch,
            current_epoch: current.map(|c| c.epoch),
            scope_matches,
            authorised,
            rerooted,
            public_mode: role != CouncilInstallRole::Private,
            new_root_signed,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_COUNCIL_MANIFEST_BYTES {
            return None;
        }
        use bincode::Options;
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_COUNCIL_MANIFEST_BYTES as u64)
            .deserialize(bytes)
            .ok()
    }
}

fn manifest_path(data_dir: &Path) -> PathBuf {
    data_dir.join(COUNCIL_MANIFEST_FILE)
}

/// The installed manifest in `data_dir`, if any.
pub fn load_council_manifest(data_dir: &Path) -> Option<CouncilManifest> {
    let bytes = std::fs::read(manifest_path(data_dir)).ok()?;
    CouncilManifest::from_bytes(&bytes)
}

/// Serializes [`install_council_manifest`] (read, check, write) across the admin RPC and the
/// council fetch paths of one process.
static INSTALL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Item 6 (plan-6 ruling change 1): a seed installs a council manifest over admin RPC only in
/// public mode, only with a persistent store, and only against its configured scope root.
/// F-53 (L-57, L-98): when that root's secret is on this seed's disk (`root_on_disk`) and no
/// manifest is installed under it (`installed_under_root`, never the epoch of a manifest under
/// another root), nothing installs: neither epoch 1 nor a re-root onto the on-disk root.
/// Returns that root.
pub fn seed_council_install_decision(
    public_mode: bool,
    in_memory: bool,
    configured_root: Option<[u8; 32]>,
    root_on_disk: bool,
    installed_under_root: Option<u64>,
) -> Result<[u8; 32], &'static str> {
    if !public_mode {
        return Err("reject.council_install_not_public");
    }
    if in_memory {
        return Err("reject.council_install_in_memory");
    }
    let root = configured_root
        .filter(|r| *r != [0u8; 32])
        .ok_or("reject.council_no_scope_root")?;
    if root_on_disk && installed_under_root.is_none() {
        return Err("reject.council_root_on_disk");
    }
    Ok(root)
}

/// Epoch of the manifest installed in `data_dir`, if any (whatever its root).
pub fn installed_council_epoch(data_dir: &Path) -> Option<u64> {
    load_council_manifest(data_dir).map(|m| m.epoch)
}

/// Epoch of the manifest installed in `data_dir` under `root` only (verdict change 4).
pub fn installed_council_epoch_under(data_dir: &Path, root: Option<[u8; 32]>) -> Option<u64> {
    council_from_manifest(data_dir, root).map(|m| m.epoch)
}

/// Installs `manifest` in `data_dir` as `role` if [`council_manifest_decision`] accepts it
/// against the installed one. Logs and returns the reason code otherwise. Re-installing the
/// manifest already installed is a no-op that succeeds.
///
/// Write order (verdict change 7): history, then the manifest, then (a client's re-root only)
/// the pins, through [`repin_tracker_admin`]. A crash after the manifest write leaves a B
/// manifest with an A pin; [`council_scope_root`] still resolves B through the history, and
/// [`repair_council_pins`] (run at every `parvault` start) finishes the re-pin.
pub fn install_council_manifest(
    data_dir: &Path,
    manifest: &CouncilManifest,
    expected_root: [u8; 32],
    role: CouncilInstallRole,
) -> Result<(), String> {
    let _guard = INSTALL_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let current = load_council_manifest(data_dir);
    if current.as_ref() == Some(manifest) && manifest.scope_root == expected_root {
        return Ok(());
    }
    let facts = manifest.facts(expected_root, current.as_ref(), role);
    if let Err(code) = council_manifest_decision(&facts) {
        tracing::warn!(code, epoch = manifest.epoch, "refused a council manifest");
        return Err(code.to_string());
    }
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let mut history = load_council_history(data_dir);
    if current.is_none() {
        history.clear();
    }
    history.push(manifest.clone());
    let excess = history.len().saturating_sub(MAX_COUNCIL_HISTORY);
    history.drain(..excess);
    let history_bytes = bincode::serialize(&history).map_err(|e| e.to_string())?;
    BlockStore::atomic_write_file(&data_dir.join(COUNCIL_HISTORY_FILE), &history_bytes)
        .map_err(|e: StorageError| e.to_string())?;
    BlockStore::atomic_write_file(&manifest_path(data_dir), &manifest.to_bytes())
        .map_err(|e: StorageError| e.to_string())?;
    if facts.rerooted && role == CouncilInstallRole::PublicClient {
        if let Some(old) = current.map(|c| c.scope_root) {
            repin_tracker_admin(data_dir, old, manifest.scope_root)?;
        }
    }
    Ok(())
}

/// Write-ahead record of a re-pin in progress (`council_repin_intent.json`). It is written before
/// either pin store and removed after both, so a crash between the two store writes leaves it on
/// disk and [`repair_council_pins`] replays it at the next start, with or without a manifest.
pub const COUNCIL_REPIN_INTENT_FILE: &str = "council_repin_intent.json";

/// A re-pin onto `new`: of `tracker` (`council repin`), whose pin before the re-pin was `prev`,
/// or (no tracker) of every pin of `prev` (a client's re-root). Replaying it is idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepinIntent {
    /// The tracker re-pinned by `council repin`; `None` for a re-root's re-pin.
    pub tracker: Option<String>,
    /// The key re-pinned away from (the tracker's pin before the re-pin), if any.
    pub prev: Option<[u8; 32]>,
    /// The key re-pinned to.
    pub new: [u8; 32],
}

/// Reads the write-ahead re-pin record: absent is `None`; one that exists but cannot be read or
/// decoded fails closed (`reject.council_repin_intent_unreadable`,
/// `reject.council_repin_intent_corrupt`), since dropping it could leave an old root pinned.
pub fn repin_intent_load_decision(
    read: std::io::Result<Option<Vec<u8>>>,
) -> Result<Option<RepinIntent>, &'static str> {
    match read {
        Ok(None) => Ok(None),
        Ok(Some(bytes)) => serde_json::from_slice::<RepinIntent>(&bytes)
            .map(Some)
            .map_err(|_| "reject.council_repin_intent_corrupt"),
        Err(_) => Err("reject.council_repin_intent_unreadable"),
    }
}

fn load_repin_intent(data_dir: &Path) -> Result<Option<RepinIntent>, &'static str> {
    repin_intent_load_decision(read_pin_file(&data_dir.join(COUNCIL_REPIN_INTENT_FILE)))
}

/// Applies `intent` to both pin stores. Both load before anything is written (B-52); then, when
/// `log_intent`, the intent is written ahead; then `known_peers.json`, then the legacy file; then
/// the intent is removed. Every crash point converges on the next start: before the intent write
/// neither store changed, after it [`repair_council_pins`] replays the intent.
fn apply_repin(data_dir: &Path, intent: &RepinIntent, log_intent: bool) -> Result<(), String> {
    let legacy = legacy_pinned_admins(data_dir).map_err(str::to_string)?;
    let mut store =
        crate::network::KnownPeersStore::try_load(data_dir).map_err(|e| e.to_string())?;
    let new = intent.new;
    let moved = intent.prev.filter(|o| *o != new);
    let intent_path = data_dir.join(COUNCIL_REPIN_INTENT_FILE);
    if log_intent {
        let bytes = serde_json::to_vec(intent).map_err(|e| e.to_string())?;
        crate::storage::fsio::atomic_write_file(&intent_path, &bytes)
            .map_err(|e| format!("reject.tracker_pin_not_persisted: {e}"))?;
    }
    let mut changed = false;
    if let Some(t) = intent.tracker.as_deref() {
        changed |= store.set_tracker_admin_pubkey(t, new) != Some(new);
    }
    if let Some(o) = moved {
        changed |= store.repin_tracker_admin_pubkey(o, new) > 0;
    }
    if changed || intent.tracker.is_some() {
        store.save(data_dir).map_err(|e| e.to_string())?;
    }
    let legacy_out: Option<Vec<[u8; 32]>> = match moved {
        Some(o) if legacy.contains(&o) => Some(
            legacy
                .iter()
                .map(|pk| if *pk == o { new } else { *pk })
                .collect(),
        ),
        None if intent.tracker.is_some() && intent.prev.is_none() && !legacy.contains(&new) => {
            Some(legacy.iter().copied().chain([new]).collect())
        }
        _ => None,
    };
    if let Some(keys) = legacy_out {
        let mut out: Vec<String> = Vec::new();
        for pk in keys {
            let h = hex::encode(pk);
            if !out.contains(&h) {
                out.push(h);
            }
        }
        let json = serde_json::to_vec_pretty(&out).map_err(|e| e.to_string())?;
        crate::storage::fsio::atomic_write_file(
            &data_dir.join("pinned_tracker_admins.json"),
            &json,
        )
        .map_err(|e| format!("reject.tracker_pin_not_persisted: {e}"))?;
    }
    match std::fs::remove_file(&intent_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("reject.tracker_pin_not_persisted: {e}")),
    }
}

/// Replaces the pinned tracker admin key `old` with `new` in both on-disk pin stores
/// (`known_peers.json` and the legacy `pinned_tracker_admins.json`), crash-safe through the
/// write-ahead [`RepinIntent`]. The in-memory map of a running client is updated by its caller
/// (`MeshClient::repin_tracker_admin_pubkey`).
pub fn repin_tracker_admin(data_dir: &Path, old: [u8; 32], new: [u8; 32]) -> Result<(), String> {
    let intent = RepinIntent {
        tracker: None,
        prev: Some(old),
        new,
    };
    apply_repin(data_dir, &intent, true)
}

/// `parvault council repin`: pins `tracker` to `new` in `known_peers.json`; every pin of its
/// previous key moves too (both stores, as in [`repin_tracker_admin`]), and a tracker with no pin
/// adds `new` to the legacy list. Both stores load before either is written (B-52), so a store that
/// does not load leaves both files unchanged; the write-ahead [`RepinIntent`] makes a crash
/// between the two store writes finish at the next start. Returns the tracker's previous pin.
pub fn repin_tracker(
    data_dir: &Path,
    tracker: &str,
    new: [u8; 32],
) -> Result<Option<[u8; 32]>, String> {
    // A re-pin cut short earlier finishes first, so its old key is not lost (B-66 addendum).
    replay_repin_intent(data_dir)?;
    legacy_pinned_admins(data_dir).map_err(str::to_string)?;
    let prev = crate::network::KnownPeersStore::try_load(data_dir)
        .map_err(|e| e.to_string())?
        .tracker_admin_pubkey(tracker);
    let intent = RepinIntent {
        tracker: Some(tracker.to_string()),
        prev,
        new,
    };
    apply_repin(data_dir, &intent, true)?;
    Ok(prev)
}

/// Replays a write-ahead re-pin left by a crash, if any. Returns it.
fn replay_repin_intent(data_dir: &Path) -> Result<Option<RepinIntent>, String> {
    let Some(intent) = load_repin_intent(data_dir).map_err(str::to_string)? else {
        return Ok(None);
    };
    apply_repin(data_dir, &intent, false)?;
    tracing::info!(
        new = %hex::encode(intent.new),
        "finished an interrupted tracker re-pin"
    );
    Ok(Some(intent))
}

/// A re-pin from the first root onto the second.
pub type RePin = ([u8; 32], [u8; 32]);

/// Finishes a client re-pin cut short by a crash (verdict change 7), run at every public start
/// before the pins load: first replays a write-ahead [`RepinIntent`] (this needs no manifest);
/// then, while any earlier root of the installed chain is still pinned in either store (even
/// when the installed root is pinned too), re-pins it to the installed root. Returns the last
/// `(old, new)` pair re-pinned, if any.
pub fn repair_council_pins(data_dir: &Path) -> Result<Option<RePin>, String> {
    let mut done = replay_repin_intent(data_dir)?
        .and_then(|i| i.prev.filter(|p| *p != i.new).map(|p| (p, i.new)));
    let Some(m) = load_council_manifest(data_dir) else {
        return Ok(done);
    };
    let (mut pins, legacy) = disk_pins(data_dir).map_err(str::to_string)?;
    pins.extend(legacy);
    for old in chain_roots(data_dir, &m)
        .into_iter()
        .filter(|r| *r != m.scope_root && pins.contains(r))
    {
        repin_tracker_admin(data_dir, old, m.scope_root)?;
        tracing::info!(
            old = %hex::encode(old),
            new = %hex::encode(m.scope_root),
            "finished an interrupted council re-pin"
        );
        done = Some((old, m.scope_root));
    }
    Ok(done)
}

/// The scope roots of the installed chain, newest first: the installed manifest's, then each
/// earlier root in the history. The history is one chain (cleared on a first install) whose
/// root changes only at a verified re-root.
fn chain_roots(data_dir: &Path, installed: &CouncilManifest) -> Vec<[u8; 32]> {
    let mut roots = vec![installed.scope_root];
    for h in load_council_history(data_dir).iter().rev() {
        if h.epoch < installed.epoch && !roots.contains(&h.scope_root) {
            roots.push(h.scope_root);
        }
    }
    roots
}

fn load_council_history(data_dir: &Path) -> Vec<CouncilManifest> {
    use bincode::Options;
    let limit = (MAX_COUNCIL_HISTORY * MAX_COUNCIL_MANIFEST_BYTES) as u64;
    std::fs::read(data_dir.join(COUNCIL_HISTORY_FILE))
        .ok()
        .and_then(|b| {
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(limit)
                .deserialize::<Vec<CouncilManifest>>(&b)
                .ok()
        })
        .unwrap_or_default()
}

/// The manifests of the chain that `scope_root` roots (or rooted before a re-root) after
/// `from_epoch`, oldest first, as served to a peer behind: the installed history plus the
/// installed manifest, cut to the oldest that fit in [`MAX_COUNCIL_MANIFEST_BYTES`] (the peer
/// installs them and asks again from its new epoch). A peer still under the old root gets the
/// re-root and what follows it (verdict change 6).
pub fn council_chain_after(
    data_dir: &Path,
    scope_root: [u8; 32],
    from_epoch: u64,
) -> Vec<CouncilManifest> {
    let Some(latest) = load_council_manifest(data_dir) else {
        return Vec::new();
    };
    if scope_root == [0u8; 32] || !chain_roots(data_dir, &latest).contains(&scope_root) {
        return Vec::new();
    }
    let mut chain: Vec<CouncilManifest> = load_council_history(data_dir)
        .into_iter()
        .filter(|m| m.epoch > from_epoch && m.epoch < latest.epoch)
        .collect();
    if latest.epoch > from_epoch {
        chain.push(latest);
    }
    chain.sort_by_key(|m| m.epoch);
    chain.dedup_by_key(|m| m.epoch);
    let mut used = 0usize;
    let mut out = Vec::new();
    for m in chain {
        // Vec length prefix plus each manifest's encoding.
        used += m.to_bytes().len();
        if used + 8 > MAX_COUNCIL_MANIFEST_BYTES {
            break;
        }
        out.push(m);
    }
    out
}

/// Installs `chain` (oldest first) one manifest at a time through
/// [`council_manifest_decision`], stopping at the first one refused. After each install the
/// root is re-resolved (a client's re-root moves it to the new root; verdict change 6), so a
/// chain [re-root, `e + 2`] installs whole. Returns how many installed and the final root.
pub fn install_council_chain(
    data_dir: &Path,
    chain: &[CouncilManifest],
    expected_root: [u8; 32],
    role: CouncilInstallRole,
) -> (usize, [u8; 32]) {
    let mut installed = 0;
    let mut root = expected_root;
    for m in chain {
        if install_council_manifest(data_dir, m, root, role).is_err() {
            break;
        }
        if role == CouncilInstallRole::PublicClient {
            root = m.scope_root;
        }
        installed += 1;
    }
    (installed, root)
}

/// The single council resolver: the installed manifest, if its scope root is `scope_root` (see
/// [`council_scope_root`]; each role passes the root of its mode). With no such manifest no
/// council order passes.
pub fn council_from_manifest(
    data_dir: &Path,
    scope_root: Option<[u8; 32]>,
) -> Option<CouncilManifest> {
    let root = scope_root?;
    let m = load_council_manifest(data_dir)?;
    (m.scope_root == root).then_some(m)
}

/// `(members, quorum)` of [`council_from_manifest`]; with no manifest an empty council and an
/// unreachable quorum, so no council order passes.
pub fn council_members_and_quorum(
    data_dir: &Path,
    scope_root: Option<[u8; 32]>,
) -> (Vec<[u8; 32]>, usize) {
    match council_from_manifest(data_dir, scope_root) {
        Some(m) => (m.members, m.quorum as usize),
        None => (Vec::new(), usize::MAX),
    }
}

/// The scope root of this node's council, by mode (as the pre-manifest resolvers split it):
/// private mode trusts the ring genesis only, so no public tracker authority affects a private
/// ring. Public mode trusts a pinned tracker admin key: once a manifest is installed, the key
/// that rooted it (while it is still pinned), so a change in pin order cannot strip the
/// council (QA 2c R1); before that, the first key in `known_peers.json`'s order (sorted by
/// tracker address), else the legacy `pinned_tracker_admins.json`, else `extra_pinned`.
pub fn council_scope_root(
    data_dir: &Path,
    genesis_pubkey: Option<[u8; 32]>,
    public_mode: bool,
    extra_pinned: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if !public_mode {
        return genesis_pubkey;
    }
    // B-52: a pin store that does not load resolves no root (no council, orders refused), never
    // a fall-through to `extra_pinned` or another stored key.
    let (pinned, legacy) = match disk_pins(data_dir) {
        Ok(p) => p,
        Err(code) => {
            tracing::warn!(
                code,
                "no council scope root: a tracker pin store does not load"
            );
            return None;
        }
    };
    if let Some(m) = load_council_manifest(data_dir) {
        // A root of the installed chain still pinned (the installed one, or the one it was
        // re-rooted from while a crash-interrupted re-pin is pending; verdict change 7).
        if chain_roots(data_dir, &m)
            .iter()
            .any(|r| pinned.contains(r) || extra_pinned.contains(r) || legacy.contains(r))
        {
            return Some(m.scope_root);
        }
    }
    pinned
        .first()
        .or(legacy.first())
        .or(extra_pinned.first())
        .copied()
}

fn read_pin_file(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The legacy `pinned_tracker_admins.json` pins, failing closed (B-52): a file that exists but
/// cannot be read or decoded is its reason code (`reject.tracker_pins_unreadable`), never an
/// empty list that would let the scope root fall through to another key.
fn legacy_pinned_admins(data_dir: &Path) -> Result<Vec<[u8; 32]>, &'static str> {
    let list = crate::config::tracker_pins_load_decision(read_pin_file(
        &data_dir.join("pinned_tracker_admins.json"),
    ))?;
    Ok(list
        .iter()
        .filter_map(|h| {
            let b = hex::decode(h.trim()).ok()?;
            <[u8; 32]>::try_from(b.as_slice()).ok()
        })
        .collect())
}

/// Pins of `known_peers.json`, then of the legacy file.
type DiskPins = (Vec<[u8; 32]>, Vec<[u8; 32]>);

/// The pins of both on-disk stores (`known_peers.json` first, then the legacy file), failing
/// closed on either with its reason code (`reject.known_peers_corrupt`,
/// `reject.known_peers_unreadable`, `reject.tracker_pins_unreadable`).
fn disk_pins(data_dir: &Path) -> Result<DiskPins, &'static str> {
    let known = crate::network::discovery::known_peers_load_decision(read_pin_file(
        &data_dir.join(crate::network::KnownPeersStore::FILE_NAME),
    ))?
    .unwrap_or_default()
    .pinned_tracker_admin_pubkeys();
    Ok((known, legacy_pinned_admins(data_dir)?))
}

/// The first pinned tracker admin key: `known_peers.json`'s order, else the legacy file. A pin
/// store that does not load is an error, never "no pin" (B-52). In particular a damaged
/// `known_peers.json` never falls back to the legacy pins (B-123): those could hold a key that
/// trust-on-first-use took while the damaged store showed no pins.
pub fn pinned_admin_root(data_dir: &Path) -> Result<Option<[u8; 32]>, &'static str> {
    let (known, legacy) = disk_pins(data_dir)?;
    Ok(known.first().or(legacy.first()).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeIdentity {
        NodeIdentity::from_seed([b; 32])
    }

    fn genesis_signed(members: &[u8], quorum: u32) -> (NodeIdentity, CouncilManifest) {
        let root = id(1);
        let mut m = CouncilManifest::new(
            root.public_key_bytes(),
            1,
            members.iter().map(|b| id(*b).public_key_bytes()).collect(),
            quorum,
            1_000,
        );
        m.sign(&root);
        (root, m)
    }

    #[test]
    fn epoch_chain_and_majority_floor() {
        let (root, m1) = genesis_signed(&[2, 3, 4], 2);
        let rk = root.public_key_bytes();
        assert_eq!(
            council_manifest_decision(&m1.facts(rk, None, CouncilInstallRole::Private)),
            Ok(())
        );
        // Below majority.
        let (_, low) = genesis_signed(&[2, 3, 4], 1);
        assert_eq!(
            council_manifest_decision(&low.facts(rk, None, CouncilInstallRole::Private)),
            Err("reject.council_quorum_below_majority")
        );
        // Epoch 2 signed by one member of a 2-of-3: refused; by two: accepted.
        let mut m2 = CouncilManifest::new(rk, 2, vec![id(5).public_key_bytes()], 1, 2_000);
        m2.sign(&id(2));
        assert_eq!(
            council_manifest_decision(&m2.facts(rk, Some(&m1), CouncilInstallRole::Private)),
            Err("reject.council_epoch_chain")
        );
        m2.sign(&id(3));
        assert_eq!(
            council_manifest_decision(&m2.facts(rk, Some(&m1), CouncilInstallRole::Private)),
            Ok(())
        );
        // Same or skipped epoch: refused.
        assert_eq!(
            council_manifest_decision(&m1.facts(rk, Some(&m1), CouncilInstallRole::Private)),
            Err("reject.council_epoch_chain")
        );
        // Epoch 1 from another root: refused.
        assert_eq!(
            council_manifest_decision(&m1.facts(
                id(9).public_key_bytes(),
                None,
                CouncilInstallRole::Private
            )),
            Err("reject.council_epoch_chain")
        );
    }

    /// A node at epoch 1 fetches a 1 -> 2 -> 3 chain from a peer and ends at 3; a forged epoch 2
    /// in the chain installs nothing.
    #[test]
    fn chain_fetch_steps_forward_and_stops_at_a_forgery() {
        let (root, m1) = genesis_signed(&[2, 3, 4], 2);
        let rk = root.public_key_bytes();
        let next = |prev_epoch: u64, signers: &[u8]| {
            let mut m = CouncilManifest::new(
                rk,
                prev_epoch + 1,
                [2u8, 3, 4]
                    .iter()
                    .map(|b| id(*b).public_key_bytes())
                    .collect(),
                2,
                prev_epoch * 1_000,
            );
            for b in signers {
                m.sign(&id(*b));
            }
            m
        };
        let m2 = next(1, &[2, 3]);
        let m3 = next(2, &[3, 4]);
        let peer = tempfile::tempdir().unwrap();
        for m in [&m1, &m2, &m3] {
            install_council_manifest(peer.path(), m, rk, CouncilInstallRole::Private).unwrap();
        }
        let behind = tempfile::tempdir().unwrap();
        install_council_manifest(behind.path(), &m1, rk, CouncilInstallRole::Private).unwrap();
        let chain = council_chain_after(peer.path(), rk, 1);
        assert_eq!(
            chain.iter().map(|m| m.epoch).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(
            install_council_chain(behind.path(), &chain, rk, CouncilInstallRole::Private).0,
            2
        );
        assert_eq!(load_council_manifest(behind.path()).unwrap().epoch, 3);
        assert!(council_chain_after(peer.path(), rk, 3).is_empty());

        let forged = next(1, &[8, 9]);
        let behind = tempfile::tempdir().unwrap();
        install_council_manifest(behind.path(), &m1, rk, CouncilInstallRole::Private).unwrap();
        assert_eq!(
            install_council_chain(
                behind.path(),
                &[forged, m3],
                rk,
                CouncilInstallRole::Private
            )
            .0,
            0
        );
        assert_eq!(load_council_manifest(behind.path()).unwrap().epoch, 1);
    }

    /// Scope root by mode (ADR-26 table): private = genesis even with pins; public = first pinned
    /// tracker admin (disk pins, then the caller's pins), never the genesis (hybrid nodes).
    #[test]
    fn scope_root_follows_the_mode() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = Some([1u8; 32]);
        assert_eq!(
            council_scope_root(dir.path(), genesis, false, &[[2; 32]]),
            genesis
        );
        assert_eq!(
            council_scope_root(dir.path(), genesis, true, &[[2; 32]]),
            Some([2; 32])
        );
        assert_eq!(council_scope_root(dir.path(), genesis, true, &[]), None);
        std::fs::write(
            dir.path().join("pinned_tracker_admins.json"),
            format!("[\"{}\"]", hex::encode([3u8; 32])),
        )
        .unwrap();
        assert_eq!(
            council_scope_root(dir.path(), genesis, true, &[[2; 32]]),
            Some([3; 32])
        );
        assert_eq!(council_scope_root(dir.path(), None, false, &[]), None);
    }

    /// QA 2c R1(b): once installed, a public node's council keeps the root that signed it while
    /// that key is still pinned, even if another pinned key now sorts first.
    #[test]
    fn public_scope_root_follows_the_installed_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (id(0x10), id(0x20));
        let (first, second) = if a.public_key_bytes() < b.public_key_bytes() {
            (a, b)
        } else {
            (b, a)
        };
        std::fs::write(
            dir.path().join("pinned_tracker_admins.json"),
            format!(
                "[\"{}\", \"{}\"]",
                hex::encode(first.public_key_bytes()),
                hex::encode(second.public_key_bytes())
            ),
        )
        .unwrap();
        assert_eq!(
            council_scope_root(dir.path(), None, true, &[]),
            Some(first.public_key_bytes())
        );
        let mut m = CouncilManifest::new(
            second.public_key_bytes(),
            1,
            vec![id(3).public_key_bytes()],
            1,
            1,
        );
        m.sign(&second);
        install_council_manifest(
            dir.path(),
            &m,
            second.public_key_bytes(),
            CouncilInstallRole::PublicClient,
        )
        .unwrap();
        assert_eq!(
            council_scope_root(dir.path(), None, true, &[]),
            Some(second.public_key_bytes())
        );
    }

    #[test]
    fn manifest_golden_vector() {
        let (_, m) = genesis_signed(&[2, 3, 4], 2);
        let bytes = m.canonical_sign_bytes();
        assert_eq!(
            bytes.len(),
            COUNCIL_MANIFEST_DOMAIN.len() + 32 + 8 + 4 + 8 + 4 + 96
        );
        let digest = crate::crypto::compute_sha256(&bytes);
        assert_eq!(hex::encode(digest), GOLDEN_MANIFEST_SHA256);
        assert_eq!(hex::encode(m.signatures[0].sig_r), GOLDEN_MANIFEST_SIG_R);
    }

    /// A (root 1) epoch 1 with members 2,3,4 (2-of-3); a re-root to `new_root` at epoch 2 with
    /// members `members`, signed under the re-root domain by `quorum_signers` and (if
    /// `new_root_signs`) the new root.
    fn reroot(
        new_root: &NodeIdentity,
        members: &[u8],
        quorum_signers: &[u8],
        new_root_signs: bool,
    ) -> (CouncilManifest, CouncilManifest) {
        let (root, m1) = genesis_signed(&[2, 3, 4], 2);
        let mut r = CouncilManifest::new(
            new_root.public_key_bytes(),
            2,
            members.iter().map(|b| id(*b).public_key_bytes()).collect(),
            2,
            2_000,
        );
        for b in quorum_signers {
            r.sign_reroot(&id(*b), &root.public_key_bytes());
        }
        if new_root_signs {
            r.sign_reroot(new_root, &root.public_key_bytes());
        }
        (m1, r)
    }

    /// Verdict change 1: re-root bytes golden vector (domain, old root, then the manifest
    /// fields), and the re-root and rotation domains never cross-verify.
    #[test]
    fn reroot_golden_vector_and_domain_separation() {
        let b = id(0x42);
        let (m1, r) = reroot(&b, &[5, 6, 7], &[2, 3], true);
        let old = m1.scope_root;
        let bytes = r.reroot_sign_bytes(&old);
        assert_eq!(
            bytes.len(),
            COUNCIL_REROOT_DOMAIN.len() + 32 + 32 + 8 + 4 + 8 + 4 + 96
        );
        assert_eq!(&bytes[..COUNCIL_REROOT_DOMAIN.len()], COUNCIL_REROOT_DOMAIN);
        assert_eq!(
            &bytes[COUNCIL_REROOT_DOMAIN.len()..COUNCIL_REROOT_DOMAIN.len() + 32],
            &old
        );
        assert_eq!(
            &bytes[COUNCIL_REROOT_DOMAIN.len() + 32..],
            &r.canonical_sign_bytes()[COUNCIL_MANIFEST_DOMAIN.len()..]
        );
        let digest = crate::crypto::compute_sha256(&bytes);
        assert_eq!(hex::encode(digest), GOLDEN_REROOT_SHA256);
        assert_eq!(hex::encode(r.signatures[0].sig_r), GOLDEN_REROOT_SIG_R);

        // Re-root signatures do not verify as a rotation...
        let canonical = r.canonical_sign_bytes();
        assert_eq!(r.valid_signers(&canonical, &m1.members), 0);
        assert_eq!(r.valid_signers(&canonical, &[b.public_key_bytes()]), 0);
        // ...and a rotation's do not verify as a re-root (same members, same epoch).
        let mut rot = r.clone();
        rot.signatures.clear();
        for s in [2u8, 3] {
            rot.sign(&id(s));
        }
        rot.sign(&b);
        assert_eq!(
            rot.valid_signers(&rot.reroot_sign_bytes(&old), &m1.members),
            0
        );
        assert_eq!(
            council_manifest_decision(&rot.facts(
                b.public_key_bytes(),
                Some(&m1),
                CouncilInstallRole::PublicSeed
            )),
            Err("reject.council_epoch_chain")
        );
        // A re-root bound to another old root does not verify against this chain.
        let mut other = r.clone();
        other.signatures.clear();
        for s in [2u8, 3] {
            other.sign_reroot(&id(s), &id(0x55).public_key_bytes());
        }
        other.sign_reroot(&b, &id(0x55).public_key_bytes());
        assert_eq!(
            council_manifest_decision(&other.facts(
                b.public_key_bytes(),
                Some(&m1),
                CouncilInstallRole::PublicSeed
            )),
            Err("reject.council_epoch_chain")
        );
    }

    /// Verdict changes 2 and 3: the one shape per role, and none in private mode.
    #[test]
    fn reroot_acceptance_shapes() {
        let b = id(0x42);
        let bk = b.public_key_bytes();
        let (m1, r) = reroot(&b, &[5, 6, 7], &[2, 3], true);
        let a = m1.scope_root;
        let ok = |root, role| council_manifest_decision(&r.facts(root, Some(&m1), role));
        assert_eq!(ok(bk, CouncilInstallRole::PublicSeed), Ok(()));
        assert_eq!(ok(a, CouncilInstallRole::PublicClient), Ok(()));
        // A seed whose configured root is not the new root, a client not pinned to the old.
        assert_eq!(
            ok(a, CouncilInstallRole::PublicSeed),
            Err("reject.council_epoch_chain")
        );
        assert_eq!(
            ok(bk, CouncilInstallRole::PublicClient),
            Err("reject.council_epoch_chain")
        );
        assert_eq!(
            ok(
                id(0x66).public_key_bytes(),
                CouncilInstallRole::PublicClient
            ),
            Err("reject.council_epoch_chain")
        );
        // Private mode: never.
        assert_eq!(
            ok(a, CouncilInstallRole::Private),
            Err("reject.council_reroot_private")
        );
        assert_eq!(
            ok(bk, CouncilInstallRole::Private),
            Err("reject.council_reroot_private")
        );
        // Without B, or below quorum.
        let (_, unsigned) = reroot(&b, &[5, 6, 7], &[2, 3], false);
        assert_eq!(
            council_manifest_decision(&unsigned.facts(
                bk,
                Some(&m1),
                CouncilInstallRole::PublicSeed
            )),
            Err("reject.council_reroot_unsigned")
        );
        let (_, low) = reroot(&b, &[5, 6, 7], &[2], true);
        assert_eq!(
            council_manifest_decision(&low.facts(bk, Some(&m1), CouncilInstallRole::PublicSeed)),
            Err("reject.council_epoch_chain")
        );
        // Not the next epoch.
        let mut skip = CouncilManifest::new(bk, 3, r.members.clone(), 2, 3_000);
        for s in [2u8, 3] {
            skip.sign_reroot(&id(s), &a);
        }
        skip.sign_reroot(&b, &a);
        assert_eq!(
            council_manifest_decision(&skip.facts(bk, Some(&m1), CouncilInstallRole::PublicSeed)),
            Err("reject.council_epoch_chain")
        );
    }

    /// Verdict change 4: a seed with its root on disk installs nothing until a council exists
    /// under that root; the gate reads the epoch under the configured root only.
    #[test]
    fn seed_root_on_disk_gate() {
        let r = Some([7u8; 32]);
        assert_eq!(
            seed_council_install_decision(true, false, r, true, None),
            Err("reject.council_root_on_disk")
        );
        assert_eq!(
            seed_council_install_decision(true, false, r, true, Some(3)),
            Ok([7; 32])
        );
        assert_eq!(
            seed_council_install_decision(true, false, r, false, None),
            Ok([7; 32])
        );
        // The three earlier checks keep their codes and order.
        assert_eq!(
            seed_council_install_decision(false, false, r, true, None),
            Err("reject.council_install_not_public")
        );
        assert_eq!(
            seed_council_install_decision(true, true, r, true, None),
            Err("reject.council_install_in_memory")
        );
        assert_eq!(
            seed_council_install_decision(true, false, None, true, None),
            Err("reject.council_no_scope_root")
        );
        // A stale manifest under another root does not open the gate.
        let dir = tempfile::tempdir().unwrap();
        let (root, m1) = genesis_signed(&[2, 3, 4], 2);
        install_council_manifest(
            dir.path(),
            &m1,
            root.public_key_bytes(),
            CouncilInstallRole::PublicSeed,
        )
        .unwrap();
        assert_eq!(installed_council_epoch(dir.path()), Some(1));
        assert_eq!(installed_council_epoch_under(dir.path(), r), None);
        assert_eq!(
            installed_council_epoch_under(dir.path(), Some(root.public_key_bytes())),
            Some(1)
        );
    }

    fn pin_known_peer(dir: &Path, tracker: &str, pk: [u8; 32]) {
        let mut store = crate::network::KnownPeersStore::load(dir);
        store.set_tracker_admin_pubkey(tracker, pk);
        store.save(dir).unwrap();
    }

    /// Verdict changes 6 and 7: a client fetches [re-root, e + 2] under its pinned root A,
    /// installs both, ends pinned to B in both on-disk stores, and the serving seed answers a
    /// request under A with the re-root and what follows it.
    #[test]
    fn client_follows_reroot_chain_and_repins() {
        let b = id(0x42);
        let bk = b.public_key_bytes();
        let (m1, r) = reroot(&b, &[5, 6, 7], &[2, 3], true);
        let a = m1.scope_root;
        let mut m3 = CouncilManifest::new(bk, 3, r.members.clone(), 2, 3_000);
        m3.sign(&id(5));
        m3.sign(&id(6));

        let seed = tempfile::tempdir().unwrap();
        install_council_manifest(seed.path(), &m1, a, CouncilInstallRole::PublicSeed).unwrap();
        install_council_manifest(seed.path(), &r, bk, CouncilInstallRole::PublicSeed).unwrap();
        install_council_manifest(seed.path(), &m3, bk, CouncilInstallRole::PublicSeed).unwrap();

        let client = tempfile::tempdir().unwrap();
        pin_known_peer(client.path(), "/ip4/10.0.0.1/tcp/4002", a);
        std::fs::write(
            client.path().join("pinned_tracker_admins.json"),
            format!("[\"{}\"]", hex::encode(a)),
        )
        .unwrap();
        install_council_manifest(client.path(), &m1, a, CouncilInstallRole::PublicClient).unwrap();

        let chain = council_chain_after(seed.path(), a, 1);
        assert_eq!(
            chain.iter().map(|m| m.epoch).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(
            install_council_chain(client.path(), &chain, a, CouncilInstallRole::PublicClient),
            (2, bk)
        );
        assert_eq!(load_council_manifest(client.path()).unwrap().epoch, 3);
        assert_eq!(
            crate::network::KnownPeersStore::load(client.path()).pinned_tracker_admin_pubkeys(),
            vec![bk]
        );
        assert_eq!(legacy_pinned_admins(client.path()), Ok(vec![bk]));
        assert_eq!(council_scope_root(client.path(), None, true, &[]), Some(bk));
        // After the re-root, an A-signed epoch 4 never installs.
        let (root_a, _) = genesis_signed(&[2, 3, 4], 2);
        let mut a4 = CouncilManifest::new(a, 4, vec![id(8).public_key_bytes()], 1, 4_000);
        a4.sign(&root_a);
        for s in [2u8, 3, 5, 6] {
            a4.sign(&id(s));
        }
        assert!(
            install_council_manifest(client.path(), &a4, bk, CouncilInstallRole::PublicClient)
                .is_err()
        );
        assert!(
            install_council_manifest(client.path(), &a4, a, CouncilInstallRole::PublicClient)
                .is_err()
        );
        // A peer under an unrelated root gets nothing.
        assert!(council_chain_after(seed.path(), id(0x66).public_key_bytes(), 0).is_empty());
    }

    /// Verdict change 7: a crash after the manifest write and before the pin write leaves a B
    /// manifest with A pins. The scope still resolves to B, and the start-up repair re-pins.
    #[test]
    fn crash_between_manifest_and_pin_write_recovers() {
        let b = id(0x42);
        let bk = b.public_key_bytes();
        let (m1, r) = reroot(&b, &[5, 6, 7], &[2, 3], true);
        let a = m1.scope_root;
        let client = tempfile::tempdir().unwrap();
        pin_known_peer(client.path(), "/ip4/10.0.0.1/tcp/4002", a);
        std::fs::write(
            client.path().join("pinned_tracker_admins.json"),
            format!("[\"{}\"]", hex::encode(a)),
        )
        .unwrap();
        install_council_manifest(client.path(), &m1, a, CouncilInstallRole::PublicClient).unwrap();
        install_council_manifest(client.path(), &r, a, CouncilInstallRole::PublicClient).unwrap();
        // Simulate the crash: roll both pin stores back to A.
        pin_known_peer(client.path(), "/ip4/10.0.0.1/tcp/4002", a);
        std::fs::write(
            client.path().join("pinned_tracker_admins.json"),
            format!("[\"{}\"]", hex::encode(a)),
        )
        .unwrap();
        assert_eq!(council_scope_root(client.path(), None, true, &[]), Some(bk));
        assert_eq!(repair_council_pins(client.path()), Ok(Some((a, bk))));
        assert_eq!(legacy_pinned_admins(client.path()), Ok(vec![bk]));
        assert_eq!(
            crate::network::KnownPeersStore::load(client.path()).pinned_tracker_admin_pubkeys(),
            vec![bk]
        );
        assert_eq!(repair_council_pins(client.path()), Ok(None));
    }

    /// Crash-safe re-pin (F-53 QA): every state a crash between the two pin-store writes can leave
    /// converges on B at the next start, and A never resolves as the root afterwards.
    #[test]
    fn interrupted_repin_converges_on_new_root() {
        let a = id(0x41).public_key_bytes();
        let bk = id(0x42).public_key_bytes();
        let legacy_a = format!("[\"{}\"]", hex::encode(a));
        // Write-ahead intent, no manifest: known = B, legacy = A, intent A -> B.
        let dir = tempfile::tempdir().unwrap();
        pin_known_peer(dir.path(), "/ip4/10.0.0.1/tcp/4002", bk);
        std::fs::write(dir.path().join("pinned_tracker_admins.json"), &legacy_a).unwrap();
        let intent = RepinIntent {
            tracker: None,
            prev: Some(a),
            new: bk,
        };
        std::fs::write(
            dir.path().join(COUNCIL_REPIN_INTENT_FILE),
            serde_json::to_vec(&intent).unwrap(),
        )
        .unwrap();
        assert_eq!(repair_council_pins(dir.path()), Ok(Some((a, bk))));
        assert_eq!(legacy_pinned_admins(dir.path()), Ok(vec![bk]));
        assert!(!dir.path().join(COUNCIL_REPIN_INTENT_FILE).exists());
        std::fs::remove_file(dir.path().join(crate::network::KnownPeersStore::FILE_NAME)).unwrap();
        assert_eq!(council_scope_root(dir.path(), None, true, &[]), Some(bk));
        assert_eq!(repair_council_pins(dir.path()), Ok(None));

        // No intent (written by a binary before the fix), manifest under B: B pinned in
        // known_peers.json no longer stops the repair of the legacy A pin.
        let b = id(0x42);
        let (m1, r) = reroot(&b, &[5, 6, 7], &[2, 3], true);
        let a = m1.scope_root;
        let client = tempfile::tempdir().unwrap();
        pin_known_peer(client.path(), "/ip4/10.0.0.1/tcp/4002", a);
        let legacy_a = format!("[\"{}\"]", hex::encode(a));
        std::fs::write(client.path().join("pinned_tracker_admins.json"), &legacy_a).unwrap();
        install_council_manifest(client.path(), &m1, a, CouncilInstallRole::PublicClient).unwrap();
        install_council_manifest(client.path(), &r, a, CouncilInstallRole::PublicClient).unwrap();
        std::fs::write(client.path().join("pinned_tracker_admins.json"), &legacy_a).unwrap();
        assert_eq!(repair_council_pins(client.path()), Ok(Some((a, bk))));
        assert_eq!(legacy_pinned_admins(client.path()), Ok(vec![bk]));
        assert_eq!(repair_council_pins(client.path()), Ok(None));

        // `council repin` cut short after known_peers.json: rerunning it finishes the legacy file
        // (it used to see B as the previous pin and leave A there).
        let dir = tempfile::tempdir().unwrap();
        let t = "/ip4/10.0.0.1/tcp/4002";
        pin_known_peer(dir.path(), t, bk);
        std::fs::write(dir.path().join("pinned_tracker_admins.json"), &legacy_a).unwrap();
        let intent = RepinIntent {
            tracker: Some(t.to_string()),
            prev: Some(a),
            new: bk,
        };
        std::fs::write(
            dir.path().join(COUNCIL_REPIN_INTENT_FILE),
            serde_json::to_vec(&intent).unwrap(),
        )
        .unwrap();
        assert_eq!(repin_tracker(dir.path(), t, bk), Ok(Some(bk)));
        assert_eq!(legacy_pinned_admins(dir.path()), Ok(vec![bk]));
        assert!(!dir.path().join(COUNCIL_REPIN_INTENT_FILE).exists());
    }

    /// Write-ahead intent, driven (F-53 QA D1): a re-pin whose legacy-store write really fails
    /// after `known_peers.json` was written leaves the intent on disk, and the next start
    /// converges both stores on B. The failure is a real kernel limit that also binds root: the
    /// data dir is sized so the legacy file's temp path (one byte longer than the intent's) hits
    /// `PATH_MAX` (`ENAMETOOLONG`) while every other path the re-pin touches fits.
    #[cfg(target_os = "linux")]
    #[test]
    fn repin_legacy_write_failure_keeps_intent_and_converges() {
        const PATH_MAX: usize = 4096;
        // Length of `<dir>/` plus the `fsio::atomic_write_file` temp name `.<name>.tmp.<16 hex>`.
        let tmp_len = |name: &str| 1 + 1 + name.len() + 5 + 16;
        let legacy_name = "pinned_tracker_admins.json";
        assert_eq!(
            tmp_len(legacy_name),
            tmp_len(COUNCIL_REPIN_INTENT_FILE) + 1,
            "the test needs the legacy temp path to be the longest, by one byte"
        );
        let a = id(0x41).public_key_bytes();
        let bk = id(0x42).public_key_bytes();
        let root = tempfile::tempdir().unwrap();
        // The longest dir whose intent temp path still fits (PATH_MAX counts the NUL).
        let want = PATH_MAX - 1 - tmp_len(COUNCIL_REPIN_INTENT_FILE);
        let mut dir = root.path().to_path_buf();
        loop {
            let remaining = want - dir.as_os_str().len();
            if remaining == 0 {
                break;
            }
            // Each component costs its length plus a separator; never leave a remainder of 1.
            let n = match remaining {
                r if r > 402 => 200,
                r if r > 201 => r / 2 - 1,
                r => r - 1,
            };
            dir.push("d".repeat(n));
        }
        std::fs::create_dir_all(&dir).unwrap();
        pin_known_peer(&dir, "/ip4/10.0.0.1/tcp/4002", a);
        std::fs::write(dir.join(legacy_name), format!("[\"{}\"]", hex::encode(a))).unwrap();

        let err = repin_tracker_admin(&dir, a, bk).unwrap_err();
        assert!(err.starts_with("reject.tracker_pin_not_persisted"), "{err}");
        // known_peers.json was written, the legacy file was not, and the intent survives.
        assert_eq!(
            crate::network::KnownPeersStore::load(&dir).pinned_tracker_admin_pubkeys(),
            vec![bk]
        );
        assert_eq!(legacy_pinned_admins(&dir), Ok(vec![a]));
        let intent = std::fs::read(dir.join(COUNCIL_REPIN_INTENT_FILE))
            .expect("the write-ahead intent must be on disk after the failed legacy write");
        assert_eq!(
            serde_json::from_slice::<RepinIntent>(&intent).unwrap(),
            RepinIntent {
                tracker: None,
                prev: Some(a),
                new: bk,
            }
        );

        // The restart, once the dir is writable again (moved to a short path). No manifest is
        // installed, so only the intent can finish the re-pin.
        let short = root.path().join("restarted");
        std::fs::rename(&dir, &short).unwrap();
        assert_eq!(repair_council_pins(&short), Ok(Some((a, bk))));
        assert_eq!(legacy_pinned_admins(&short), Ok(vec![bk]));
        assert_eq!(
            crate::network::KnownPeersStore::load(&short).pinned_tracker_admin_pubkeys(),
            vec![bk]
        );
        assert!(!short.join(COUNCIL_REPIN_INTENT_FILE).exists());
        std::fs::remove_file(short.join(crate::network::KnownPeersStore::FILE_NAME)).unwrap();
        assert_eq!(council_scope_root(&short, None, true, &[]), Some(bk));
        assert_eq!(repair_council_pins(&short), Ok(None));
    }

    /// Repair moves every old root (F-53 QA D2): after A -> B -> C, with A pinned in
    /// `known_peers.json` and B in the legacy file, one start-up repair leaves only C pinned.
    #[test]
    fn repair_moves_every_old_root_of_the_chain() {
        let b = id(0x42);
        let bk = b.public_key_bytes();
        let c = id(0x43);
        let ck = c.public_key_bytes();
        let (m1, r) = reroot(&b, &[5, 6, 7], &[2, 3], true);
        let a = m1.scope_root;
        let mut r2 = CouncilManifest::new(ck, 3, r.members.clone(), 2, 3_000);
        for s in [5u8, 6] {
            r2.sign_reroot(&id(s), &bk);
        }
        r2.sign_reroot(&c, &bk);
        let dir = tempfile::tempdir().unwrap();
        // Installed as a seed, so no install re-pins and the pins stay as planted.
        install_council_manifest(dir.path(), &m1, a, CouncilInstallRole::PublicSeed).unwrap();
        install_council_manifest(dir.path(), &r, bk, CouncilInstallRole::PublicSeed).unwrap();
        install_council_manifest(dir.path(), &r2, ck, CouncilInstallRole::PublicSeed).unwrap();
        assert_eq!(chain_roots(dir.path(), &r2), vec![ck, bk, a]);
        pin_known_peer(dir.path(), "/ip4/10.0.0.1/tcp/4002", a);
        std::fs::write(
            dir.path().join("pinned_tracker_admins.json"),
            format!("[\"{}\"]", hex::encode(bk)),
        )
        .unwrap();
        assert!(repair_council_pins(dir.path()).unwrap().is_some());
        assert_eq!(
            crate::network::KnownPeersStore::load(dir.path()).pinned_tracker_admin_pubkeys(),
            vec![ck]
        );
        assert_eq!(legacy_pinned_admins(dir.path()), Ok(vec![ck]));
        assert_eq!(repair_council_pins(dir.path()), Ok(None));
    }

    /// A write-ahead re-pin record that does not decode fails closed and is kept.
    #[test]
    fn corrupt_repin_intent_fails_closed() {
        assert_eq!(repin_intent_load_decision(Ok(None)), Ok(None));
        assert_eq!(
            repin_intent_load_decision(Ok(Some(b"{".to_vec()))),
            Err("reject.council_repin_intent_corrupt")
        );
        assert_eq!(
            repin_intent_load_decision(Err(std::io::Error::other("eio"))),
            Err("reject.council_repin_intent_unreadable")
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(COUNCIL_REPIN_INTENT_FILE), b"{").unwrap();
        assert_eq!(
            repair_council_pins(dir.path()),
            Err("reject.council_repin_intent_corrupt".to_string())
        );
        assert_eq!(
            std::fs::read(dir.path().join(COUNCIL_REPIN_INTENT_FILE)).unwrap(),
            b"{"
        );
    }

    /// QA MED (B-52): a pin store that exists but does not load resolves no public scope root
    /// (never a fall-through to `extra_pinned`), and a re-pin over it fails without writing.
    #[test]
    fn corrupt_pin_store_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("pinned_tracker_admins.json");
        let known = dir.path().join(crate::network::KnownPeersStore::FILE_NAME);
        // Accept side: a readable legacy file resolves its key ahead of `extra_pinned`.
        std::fs::write(&legacy, format!("[\"{}\"]", hex::encode([3u8; 32]))).unwrap();
        assert_eq!(
            council_scope_root(dir.path(), None, true, &[[2; 32]]),
            Some([3; 32])
        );
        assert_eq!(pinned_admin_root(dir.path()), Ok(Some([3; 32])));
        // Reject side: the same file corrupt resolves nothing (it used to give [2; 32]).
        std::fs::write(&legacy, b"{not json").unwrap();
        assert_eq!(council_scope_root(dir.path(), None, true, &[[2; 32]]), None);
        assert_eq!(
            pinned_admin_root(dir.path()),
            Err("reject.tracker_pins_unreadable")
        );
        assert_eq!(
            repin_tracker_admin(dir.path(), [3; 32], [4; 32]),
            Err("reject.tracker_pins_unreadable".to_string())
        );
        assert_eq!(std::fs::read(&legacy).unwrap(), b"{not json");
        // A corrupt known_peers.json fails closed the same way, even with a good legacy file
        // (B-123: never a fall-back to the legacy pins).
        std::fs::write(&legacy, format!("[\"{}\"]", hex::encode([3u8; 32]))).unwrap();
        std::fs::write(&known, b"{\"peers\":").unwrap();
        assert_eq!(council_scope_root(dir.path(), None, true, &[[2; 32]]), None);
        assert_eq!(
            pinned_admin_root(dir.path()),
            Err("reject.known_peers_corrupt")
        );
        assert!(repair_council_pins(dir.path()).is_ok());
        // Private mode reads no pin store.
        assert_eq!(
            council_scope_root(dir.path(), Some([1; 32]), false, &[]),
            Some([1; 32])
        );
    }

    // Cross-checked outside Rust (Python `cryptography`: HKDF-SHA256 seed derivation, Ed25519),
    // which also reproduces GOLDEN_MANIFEST_* below.
    const GOLDEN_REROOT_SHA256: &str =
        "af6ba147ad326b89b29fc9bc632b816ca95f525fa0d99f107231798c30cd2dcd";
    const GOLDEN_REROOT_SIG_R: &str =
        "30980d7aa8b70ebdde3112571a4440348e35c2e2ea5a36a3bdaf8640e2b942db";

    const GOLDEN_MANIFEST_SHA256: &str =
        "a157461fbba93aed729ec15a251b4aeafb6bd2b4add1986c1d549aeff1eabc31";
    const GOLDEN_MANIFEST_SIG_R: &str =
        "28b124cf6de8c6ac65bf4edbd8ee5aa7ca43194b527da0b28b0e6ef26402715d";
}
