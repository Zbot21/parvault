//! `parvault wot init | invite | install-chain`: ring membership (bootstrap option A).

use parvault::config::WotAction;
use parvault::crypto::NodeIdentity;
use parvault::network::admission::{issue_invitation, AdmissionSource, RingInvitation};
use std::path::Path;

pub(crate) fn run(action: WotAction, data_dir: &Path) -> anyhow::Result<()> {
    match action {
        WotAction::Init => {
            let genesis = NodeIdentity::init_ring_genesis_in_dir(data_dir)?;
            println!(
                "Started a new ring. Genesis public key: {}",
                hex::encode(genesis.public_key_bytes())
            );
            println!(
                "Invite another node with: parvault wot invite --peer <its Ed25519 public key>"
            );
        }
        WotAction::Invite { peer } => {
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
            println!("{}", invitation.encode_hex()?);
        }
        WotAction::InstallChain { token } => {
            let invitation = RingInvitation::decode_hex(&token)?;
            anyhow::ensure!(
                invitation.chain.hops.first().map(|h| h.inviter_pubkey)
                    == Some(invitation.genesis_pubkey),
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
            println!(
                "Joined the ring {}. Installed chain for {}{note}",
                hex::encode(invitation.genesis_pubkey),
                hex::encode(leaf)
            );
        }
    }
    Ok(())
}
