//! `parvault council init | install | show`: the signed eviction council (F-08, ADR-19).

use parvault::config::{CouncilAction, NodeConfig};
use parvault::crypto::NodeIdentity;
use parvault::storage::council::{
    council_scope_root, install_council_manifest, load_council_manifest, repair_council_pins,
    repin_tracker_admin, CouncilInstallRole, CouncilManifest,
};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn parse_key(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let raw = hex::decode(hex_str.trim())?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| anyhow::anyhow!("a member key must be 32 bytes (64 hex)"))
}

pub(crate) fn run(
    action: CouncilAction,
    cfg: &NodeConfig,
    public_mode: bool,
) -> anyhow::Result<()> {
    let data_dir = &cfg.data_dir;
    if public_mode {
        repair_council_pins(data_dir).map_err(|e| anyhow::anyhow!("council re-pin repair: {e}"))?;
    }
    let role = if public_mode {
        CouncilInstallRole::PublicClient
    } else {
        CouncilInstallRole::Private
    };
    let genesis = parvault::network::admission::server_ring_genesis(
        data_dir,
        cfg.genesis_root_pubkey_hex.as_deref(),
        true,
    )
    .ok()
    .flatten();
    let root = council_scope_root(data_dir, genesis, public_mode, &[]);
    match action {
        CouncilAction::Init { members, quorum } => {
            anyhow::ensure!(
                !public_mode,
                "in public mode the tracker admin signs the council; use `parvault council install`"
            );
            let Some(genesis) = NodeIdentity::load_ring_genesis_identity_in_dir(data_dir)? else {
                anyhow::bail!(
                    "council init needs the ring genesis secret; in public mode install the \
                     tracker admin's manifest with `parvault council install`"
                );
            };
            let members = members
                .iter()
                .map(|m| parse_key(m))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let mut manifest =
                CouncilManifest::new(genesis.public_key_bytes(), 1, members, quorum, now_ms());
            manifest.sign(&genesis);
            install_council_manifest(data_dir, &manifest, genesis.public_key_bytes(), role)
                .map_err(|code| anyhow::anyhow!("council manifest refused: {code}"))?;
            println!(
                "Installed council epoch 1 ({} members, quorum {}).",
                manifest.members.len(),
                manifest.quorum
            );
            println!("{}", hex::encode(manifest.to_bytes()));
        }
        CouncilAction::Install { manifest } => {
            let bytes = hex::decode(manifest.trim())?;
            let manifest = CouncilManifest::from_bytes(&bytes)
                .ok_or_else(|| anyhow::anyhow!("not a council manifest"))?;
            let root = root.ok_or_else(|| {
                anyhow::anyhow!(
                    "no council scope root: private mode needs a ring genesis, public mode a \
                     pinned tracker admin key"
                )
            })?;
            install_council_manifest(data_dir, &manifest, root, role)
                .map_err(|code| anyhow::anyhow!("council manifest refused: {code}"))?;
            println!("Installed council epoch {}.", manifest.epoch);
            if manifest.scope_root != root {
                println!(
                    "Council re-rooted: now pinned to tracker admin key {}.",
                    hex::encode(manifest.scope_root)
                );
            }
        }
        CouncilAction::Repin {
            tracker,
            admin_pubkey,
        } => {
            anyhow::ensure!(public_mode, "council repin is for --public mode only");
            let new = parse_key(&admin_pubkey)?;
            anyhow::ensure!(new != [0u8; 32], "the admin key must not be all zero");
            let mut store = parvault::network::KnownPeersStore::load(data_dir);
            let old = store.set_tracker_admin_pubkey(&tracker, new);
            store.save(data_dir)?;
            match old {
                // Moves the legacy store too (every tracker pinned to `old`).
                Some(old) if old != new => repin_tracker_admin(data_dir, old, new)
                    .map_err(|e| anyhow::anyhow!("re-pin not persisted: {e}"))?,
                Some(_) => {}
                None => cfg.persist_pinned_tracker_admin(new)?,
            }
            println!(
                "Pinned {} to tracker admin key {}.",
                tracker.trim(),
                hex::encode(new)
            );
            if load_council_manifest(data_dir).is_some_and(|m| m.scope_root != new) {
                println!(
                    "The installed council is under another root: delete council_manifest.bin and \
                     install the new tracker's manifest with `parvault council install`."
                );
            }
        }
        CouncilAction::Show => match load_council_manifest(data_dir) {
            Some(m) => {
                println!("Scope root : {}", hex::encode(m.scope_root));
                println!("Epoch      : {}", m.epoch);
                println!("Quorum     : {} of {}", m.quorum, m.members.len());
                for k in &m.members {
                    println!("Member     : {}", hex::encode(k));
                }
                println!("{}", hex::encode(m.to_bytes()));
            }
            None => println!("No council manifest installed: this node accepts no council orders."),
        },
    }
    Ok(())
}
