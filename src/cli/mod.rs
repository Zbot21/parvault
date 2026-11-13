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
pub(crate) mod onboarding;
pub(crate) mod wot;

use crate::*;

/// State `main()` prepares before dispatching a command.
pub(crate) struct CliEnv {
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
