//! `parvault wot invite | install-chain`: ring admission tokens (bootstrap option A).

use parvault::config::WotAction;
use parvault::crypto::NodeIdentity;
use parvault::network::admission::{decode_chain, encode_chain, issue_invitation, AdmissionSource};
use std::path::Path;

pub(crate) fn run(action: WotAction, data_dir: &Path) -> anyhow::Result<()> {
    let source = AdmissionSource::from_data_dir(data_dir);
    match action {
        WotAction::Invite { peer } => {
            let raw = hex::decode(peer.trim())?;
            anyhow::ensure!(
                raw.len() == 32,
                "--peer must be a 32-byte public key (64 hex)"
            );
            let mut invitee = [0u8; 32];
            invitee.copy_from_slice(&raw);
            anyhow::ensure!(
                source.holds_genesis(),
                "this node does not hold the ring genesis seed; set PARVAULT_GENESIS_SEED_HEX \
                 or run `invite` on a node that has <data_dir>/genesis_root.seed"
            );
            let genesis = NodeIdentity::load_or_generate_genesis_identity_in_dir(data_dir, None)?;
            let chain = issue_invitation(&genesis, invitee);
            println!("{}", hex::encode(encode_chain(&chain)?));
        }
        WotAction::InstallChain { token } => {
            let chain = decode_chain(&hex::decode(token.trim())?)?;
            let leaf = source.store_chain(&chain)?;
            let node = NodeIdentity::load_or_generate_in_dir(data_dir)?;
            let note = if leaf == node.public_key_bytes() {
                " (this node's key)"
            } else {
                ""
            };
            println!("Installed chain for {}{note}", hex::encode(leaf));
        }
    }
    Ok(())
}
