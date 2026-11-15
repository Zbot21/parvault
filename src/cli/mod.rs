//! Command implementations of the `parvault` binary, moved verbatim out of `main.rs`.

pub(crate) mod abuse;
pub(crate) mod council;
pub(crate) mod daemon;
pub(crate) mod daemon_cmds;
pub(crate) mod early;
pub(crate) mod file;
pub(crate) mod folder;
pub(crate) mod identity;
pub(crate) mod maintenance;
pub(crate) mod net;
pub(crate) mod onboarding;
pub(crate) mod wot;

use crate::*;

/// State `main()` prepares before dispatching a command.
pub(crate) struct CliEnv {
    /// The resolved configuration (one resolver for the dump and the command).
    pub(crate) eff: Arc<parvault::config::EffectiveConfig>,
    /// Hex SHA-256 of this command's `parvault.config-dump/1`.
    pub(crate) config_digest: String,
    pub(crate) cfg: NodeConfig,
    pub(crate) lan_port: u16,
    pub(crate) lan_enabled: bool,
    pub(crate) trust_mode: parvault::network::TrustPoolMode,
    pub(crate) public_mode: bool,
    pub(crate) public_trackers: Vec<String>,
    pub(crate) wan_seeds: Vec<String>,
    pub(crate) external_addrs: Vec<String>,
    pub(crate) node_identity: NodeIdentity,
    pub(crate) mesh_client: MeshClient,
    pub(crate) block_store: BlockStore,
    pub(crate) cli: CliGlobals,
}

/// Global CLI flags some commands read directly.
pub(crate) struct CliGlobals {
    pub(crate) lan_discovery_port: Option<u16>,
    pub(crate) seed_addr: Option<String>,
    pub(crate) config: Option<PathBuf>,
}

/// The one `MeshClient` constructor of the `parvault` binary (`docs/LAB_MODE.md`, A2). In
/// deterministic mode: no data-dir discovery (`known_peers.json` is never loaded, no healed
/// rewrite), LAN discovery off, and the fixed dial set on its swarm. Otherwise the data-dir
/// discovery and the resolved LAN setting.
pub(crate) fn mesh_client(
    eff: &parvault::config::EffectiveConfig,
    identity: NodeIdentity,
    peers: Vec<String>,
    seed_addr: Option<String>,
) -> MeshClient {
    let client = MeshClient::new(identity, peers, seed_addr);
    if eff.deterministic() {
        client
            .with_lan_discovery(false)
            .with_dial_set(Arc::new(eff.dial_set()), eff.dial_set_entries())
    } else {
        client
            .with_data_dir_discovery(eff.cfg.data_dir.clone(), eff.lan_port)
            .with_lan_discovery(eff.lan_enabled)
    }
}
