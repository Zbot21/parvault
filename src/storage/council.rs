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

use crate::crypto::NodeIdentity;
use crate::storage::block_store::{BlockStore, StorageError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Domain separator for [`CouncilManifest`] signatures.
pub const COUNCIL_MANIFEST_DOMAIN: &[u8] = b"parvault-council-manifest-v1:";
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
    /// Epoch 1: the scope root signed it. Epoch n + 1: a quorum of epoch n's members signed it.
    pub authorised: bool,
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
    let next_epoch = match f.current_epoch {
        None => f.epoch == 1,
        Some(cur) => cur.checked_add(1) == Some(f.epoch),
    };
    if !f.scope_matches || !next_epoch || !f.authorised {
        return Err("reject.council_epoch_chain");
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
        out.extend_from_slice(&self.scope_root);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.quorum.to_be_bytes());
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&(self.members.len() as u32).to_be_bytes());
        for m in &self.members {
            out.extend_from_slice(m);
        }
        out
    }

    /// Adds `signer`'s signature (once per key).
    pub fn sign(&mut self, signer: &NodeIdentity) {
        let signer_pubkey = signer.public_key_bytes();
        if self
            .signatures
            .iter()
            .any(|s| s.signer_pubkey == signer_pubkey)
        {
            return;
        }
        let sig = signer.sign(&self.canonical_sign_bytes());
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

    /// Distinct keys in `allowed` with a valid signature on this manifest.
    fn valid_signers(&self, allowed: &[[u8; 32]]) -> usize {
        let msg = self.canonical_sign_bytes();
        let mut seen: Vec<[u8; 32]> = Vec::new();
        for s in self.signatures.iter().take(MAX_COUNCIL_MEMBERS + 1) {
            if !allowed.contains(&s.signer_pubkey) || seen.contains(&s.signer_pubkey) {
                continue;
            }
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&s.sig_r);
            sig[32..].copy_from_slice(&s.sig_s);
            if NodeIdentity::verify_with_pubkey(&s.signer_pubkey, &msg, &sig) {
                seen.push(s.signer_pubkey);
            }
        }
        seen.len()
    }

    /// The facts for installing `self` on a node trusting `expected_root` that holds `current`.
    pub fn facts(
        &self,
        expected_root: [u8; 32],
        current: Option<&CouncilManifest>,
    ) -> CouncilManifestFacts {
        let members_canonical =
            self.members.windows(2).all(|w| w[0] < w[1]) && !self.members.contains(&[0u8; 32]);
        let scope_matches = expected_root != [0u8; 32]
            && self.scope_root == expected_root
            && current.is_none_or(|c| c.scope_root == self.scope_root);
        let authorised = match current {
            None => self.valid_signers(&[self.scope_root]) == 1,
            Some(c) => self.valid_signers(&c.members) >= c.quorum as usize,
        };
        CouncilManifestFacts {
            members: self.members.len(),
            members_canonical,
            quorum: self.quorum as usize,
            epoch: self.epoch,
            current_epoch: current.map(|c| c.epoch),
            scope_matches,
            authorised,
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

/// Installs `manifest` in `data_dir` if [`council_manifest_decision`] accepts it against the
/// installed one. Logs and returns the reason code otherwise.
pub fn install_council_manifest(
    data_dir: &Path,
    manifest: &CouncilManifest,
    expected_root: [u8; 32],
) -> Result<(), String> {
    let current = load_council_manifest(data_dir);
    let facts = manifest.facts(expected_root, current.as_ref());
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
        .map_err(|e: StorageError| e.to_string())
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

/// The manifests of `scope_root` after `from_epoch`, oldest first, as served to a peer behind:
/// the installed history plus the installed manifest, cut to the oldest that fit in
/// [`MAX_COUNCIL_MANIFEST_BYTES`] (the peer installs them and asks again from its new epoch).
pub fn council_chain_after(
    data_dir: &Path,
    scope_root: [u8; 32],
    from_epoch: u64,
) -> Vec<CouncilManifest> {
    let Some(latest) = council_from_manifest(data_dir, Some(scope_root)) else {
        return Vec::new();
    };
    let mut chain: Vec<CouncilManifest> = load_council_history(data_dir)
        .into_iter()
        .filter(|m| m.scope_root == scope_root && m.epoch > from_epoch && m.epoch < latest.epoch)
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
/// [`council_manifest_decision`], stopping at the first one refused. Returns how many installed.
pub fn install_council_chain(
    data_dir: &Path,
    chain: &[CouncilManifest],
    expected_root: [u8; 32],
) -> usize {
    let mut installed = 0;
    for m in chain {
        if install_council_manifest(data_dir, m, expected_root).is_err() {
            break;
        }
        installed += 1;
    }
    installed
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
    if let Some(m) = load_council_manifest(data_dir) {
        let pinned = crate::network::KnownPeersStore::load(data_dir).pinned_tracker_admin_pubkeys();
        if pinned.contains(&m.scope_root)
            || extra_pinned.contains(&m.scope_root)
            || legacy_pinned_admins(data_dir).contains(&m.scope_root)
        {
            return Some(m.scope_root);
        }
    }
    pinned_admin_root(data_dir).or_else(|| extra_pinned.first().copied())
}

fn legacy_pinned_admins(data_dir: &Path) -> Vec<[u8; 32]> {
    std::fs::read_to_string(data_dir.join("pinned_tracker_admins.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
        .unwrap_or_default()
        .iter()
        .filter_map(|h| {
            let b = hex::decode(h.trim()).ok()?;
            <[u8; 32]>::try_from(b.as_slice()).ok()
        })
        .collect()
}

pub fn pinned_admin_root(data_dir: &Path) -> Option<[u8; 32]> {
    crate::network::KnownPeersStore::load(data_dir)
        .pinned_tracker_admin_pubkeys()
        .first()
        .copied()
        .or_else(|| legacy_pinned_admins(data_dir).first().copied())
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
        assert_eq!(council_manifest_decision(&m1.facts(rk, None)), Ok(()));
        // Below majority.
        let (_, low) = genesis_signed(&[2, 3, 4], 1);
        assert_eq!(
            council_manifest_decision(&low.facts(rk, None)),
            Err("reject.council_quorum_below_majority")
        );
        // Epoch 2 signed by one member of a 2-of-3: refused; by two: accepted.
        let mut m2 = CouncilManifest::new(rk, 2, vec![id(5).public_key_bytes()], 1, 2_000);
        m2.sign(&id(2));
        assert_eq!(
            council_manifest_decision(&m2.facts(rk, Some(&m1))),
            Err("reject.council_epoch_chain")
        );
        m2.sign(&id(3));
        assert_eq!(council_manifest_decision(&m2.facts(rk, Some(&m1))), Ok(()));
        // Same or skipped epoch: refused.
        assert_eq!(
            council_manifest_decision(&m1.facts(rk, Some(&m1))),
            Err("reject.council_epoch_chain")
        );
        // Epoch 1 from another root: refused.
        assert_eq!(
            council_manifest_decision(&m1.facts(id(9).public_key_bytes(), None)),
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
            install_council_manifest(peer.path(), m, rk).unwrap();
        }
        let behind = tempfile::tempdir().unwrap();
        install_council_manifest(behind.path(), &m1, rk).unwrap();
        let chain = council_chain_after(peer.path(), rk, 1);
        assert_eq!(
            chain.iter().map(|m| m.epoch).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(install_council_chain(behind.path(), &chain, rk), 2);
        assert_eq!(load_council_manifest(behind.path()).unwrap().epoch, 3);
        assert!(council_chain_after(peer.path(), rk, 3).is_empty());

        let forged = next(1, &[8, 9]);
        let behind = tempfile::tempdir().unwrap();
        install_council_manifest(behind.path(), &m1, rk).unwrap();
        assert_eq!(install_council_chain(behind.path(), &[forged, m3], rk), 0);
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
        install_council_manifest(dir.path(), &m, second.public_key_bytes()).unwrap();
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

    const GOLDEN_MANIFEST_SHA256: &str =
        "a157461fbba93aed729ec15a251b4aeafb6bd2b4add1986c1d549aeff1eabc31";
    const GOLDEN_MANIFEST_SIG_R: &str =
        "28b124cf6de8c6ac65bf4edbd8ee5aa7ca43194b527da0b28b0e6ef26402715d";
}
