//! `parvault wot init | invite | install-chain`: ring membership (bootstrap option A).

use parvault::config::WotAction;
use parvault::crypto::NodeIdentity;
use parvault::datadir_lock::{DataDirLock, LockPurpose};
use parvault::network::admission::{issue_invitation, AdmissionSource, RingInvitation};
use std::path::Path;

pub(crate) fn run(action: WotAction, data_dir: &Path) -> anyhow::Result<()> {
    match action {
        WotAction::Init => {
            // B-174 (track E): init runs under the data-dir lock.
            let _lock = DataDirLock::acquire(data_dir, LockPurpose::RingInit)?;
            NodeIdentity::sweep_genesis_staging_files(data_dir)?;
            // A-146-2: a seed without its pin is an interrupted init; complete it.
            let state = parvault::datadir_lock::classify_volume(data_dir, None)?;
            if state.ring == parvault::datadir_lock::RingFiles::SeedOnly {
                let pk = NodeIdentity::resume_ring_pin_from_seed_file(data_dir)?;
                println!(
                    "Completed an interrupted ring init. Genesis public key: {}",
                    hex::encode(pk)
                );
                return Ok(());
            }
            let genesis = NodeIdentity::init_ring_genesis_in_dir(data_dir)?;
            println!(
                "Started a new ring. Genesis public key: {}",
                hex::encode(genesis.public_key_bytes())
            );
            println!(
                "Invite another node with: parvault wot invite --peer <its Ed25519 public key>"
            );
        }
        WotAction::Invite { peer, out } => {
            let raw = hex::decode(peer.trim())?;
            anyhow::ensure!(
                raw.len() == 32,
                "--peer must be a 32-byte public key (64 hex)"
            );
            let mut invitee = [0u8; 32];
            invitee.copy_from_slice(&raw);
            let Some(genesis) = NodeIdentity::load_ring_genesis_identity_in_dir(data_dir)? else {
                anyhow::bail!(
                    "this node does not hold a ring genesis: run `parvault wot init` to start a \
                     ring here, or run `invite` on the node that started the ring"
                );
            };
            let invitation = RingInvitation {
                genesis_pubkey: genesis.public_key_bytes(),
                chain: issue_invitation(&genesis, invitee),
            };
            let token = invitation.encode_hex()?;
            match out {
                // A-146-6: written 0600 atomically; only the path is printed (a log or a
                // terminal never shows the token).
                Some(path) => {
                    parvault::crypto::keys::write_secret_file_atomic_0600(&path, token.as_bytes())?;
                    println!(
                        "Wrote the invite for {} to {}",
                        hex::encode(invitee),
                        path.display()
                    );
                }
                None => println!("{token}"),
            }
        }
        WotAction::InstallChain { token } => {
            // B-174 (track E): a join runs under the data-dir lock.
            let _lock = DataDirLock::acquire(data_dir, LockPurpose::InstallChain)?;
            let invitation = decode_invitation(&token)?;
            println!("{}", install_invitation(data_dir, &invitation)?);
        }
    }
    Ok(())
}

/// Decodes an invite token; text that is not one gets a message saying where tokens come from
/// (B-155 item 1: a placeholder printed `Invalid character 'P' at position 0`).
pub(crate) fn decode_invitation(token: &str) -> anyhow::Result<RingInvitation> {
    let t = token.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!(
            "not a token: paste the token from the ring holder's invite log (or its `wot invite \
             --out` file)"
        );
    }
    RingInvitation::decode_hex(t).map_err(|e| {
        anyhow::anyhow!("not a valid invite token ({e}): copy the whole token from the ring holder")
    })
}

/// Whether this node is already in the ring `invitation` names: pinned to its genesis and
/// holding an installed chain for its own key.
pub(crate) fn is_member_of(data_dir: &Path, invitation: &RingInvitation) -> bool {
    let pinned =
        std::fs::read_to_string(data_dir.join(parvault::crypto::keys::RING_GENESIS_PUB_FILE))
            .ok()
            .and_then(|t| hex::decode(t.trim()).ok());
    if pinned.as_deref() != Some(&invitation.genesis_pubkey[..]) {
        return false;
    }
    if !data_dir.join("node_identity.seed").exists() {
        return false;
    }
    let Ok(node) = NodeIdentity::load_or_generate_in_dir(data_dir) else {
        return false;
    };
    let leaf = node.public_key_bytes();
    data_dir
        .join(parvault::network::admission::CHAIN_DIR_NAME)
        .join(format!("{}.bin", hex::encode(leaf)))
        .exists()
}

/// Verifies `invitation` and installs it: pins its genesis and stores its chain. The caller
/// holds the data-dir lock. Returns the line to print.
pub(crate) fn install_invitation(
    data_dir: &Path,
    invitation: &RingInvitation,
) -> anyhow::Result<String> {
    anyhow::ensure!(
        invitation.chain.hops.first().map(|h| h.inviter_pubkey) == Some(invitation.genesis_pubkey),
        "the invitation's chain does not start at its ring genesis"
    );
    let source = AdmissionSource::from_data_dir(data_dir);
    // Validates links and signatures before anything is written.
    let leaf = source.check_chain(&invitation.chain)?;
    NodeIdentity::pin_ring_genesis_pubkey_in_dir(data_dir, invitation.genesis_pubkey)?;
    source.store_chain(&invitation.chain)?;
    let node = NodeIdentity::load_or_generate_in_dir(data_dir)?;
    let note = if leaf == node.public_key_bytes() {
        " (this node's key)"
    } else {
        ""
    };
    Ok(format!(
        "Joined the ring {}. Installed chain for {}{note}",
        hex::encode(invitation.genesis_pubkey),
        hex::encode(leaf)
    ))
}
