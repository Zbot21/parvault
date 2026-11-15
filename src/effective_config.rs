//! The one configuration resolver (`v0.5.4` NEW-5, `docs/LAB_MODE.md`): every input (defaults,
//! profile, file, environment, flags and the lab overrides) resolved once, with where each value
//! came from. The daemon and `config dump` read the same [`EffectiveConfig`], so a dump cannot
//! describe a configuration the daemon does not run.

use crate::config::{
    lab_addr_decision, lab_bind_decision, lab_side_channel_decision, Cli, Commands, ConfigAction,
    DaemonAction, NodeConfig,
};
use crate::config_dump::{FieldKind, DUMP_SCHEMA};
use crate::lab_dial::{DialEntry, DialSet};
use crate::network::wot::TrustPoolMode;
use clap::{parser::ValueSource, ArgMatches, CommandFactory};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Where a value came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Default,
    Profile,
    File,
    Env(&'static str),
    /// The long flag name, without dashes.
    Flag(String),
    /// Overridden by deterministic lab mode.
    Lab,
}

impl Source {
    /// Set explicitly (file, environment or flag), as opposed to a default, a profile value or a
    /// lab override. Only explicit settings conflict with lab mode.
    pub fn is_explicit(&self) -> bool {
        matches!(self, Self::File | Self::Env(_) | Self::Flag(_))
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("default"),
            Self::Profile => f.write_str("profile"),
            Self::File => f.write_str("file"),
            Self::Env(name) => write!(f, "env:{name}"),
            Self::Flag(name) => write!(f, "flag:--{name}"),
            Self::Lab => f.write_str("lab"),
        }
    }
}

/// The environment variables the resolver reads: exactly the `Env` rows of `DUMP_SCHEMA`, read
/// once. A variable set to an empty string counts as unset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvSnapshot {
    vars: BTreeMap<&'static str, String>,
}

impl EnvSnapshot {
    /// Reads every `Env` row of `DUMP_SCHEMA` from the process environment.
    pub fn capture() -> Self {
        let mut vars = BTreeMap::new();
        for (name, kind, _) in DUMP_SCHEMA {
            if *kind == FieldKind::Env {
                // The one indirect env read in the resolver (ENV_SCAN_INDIRECT): the names are
                // the table's own rows.
                if let Some(v) = std::env::var_os(name) {
                    let v = v.to_string_lossy().into_owned();
                    if !v.trim().is_empty() {
                        vars.insert(*name, v);
                    }
                }
            }
        }
        Self { vars }
    }

    /// A snapshot from explicit pairs (tests). Names outside `DUMP_SCHEMA` are ignored.
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let mut vars = BTreeMap::new();
        for (name, kind, _) in DUMP_SCHEMA {
            if *kind == FieldKind::Env {
                if let Some((_, v)) = pairs.iter().find(|(n, _)| n == name) {
                    if !v.trim().is_empty() {
                        vars.insert(*name, (*v).to_string());
                    }
                }
            }
        }
        Self { vars }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    pub fn is_set(&self, name: &str) -> bool {
        self.vars.contains_key(name)
    }
}

/// The configuration file as read: its path and text, if any.
#[derive(Clone, Debug, Default)]
pub struct ConfigFileInput {
    pub path: Option<PathBuf>,
    pub raw: Option<String>,
}

impl ConfigFileInput {
    /// The same lookup as `NodeConfig::load_for_cli`: `--config`, else `<data_dir>/config.toml`
    /// if it is a file. Reads at most that one file and creates nothing.
    pub fn load(explicit: Option<&Path>, cli_data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let path = match explicit {
            Some(p) => Some(p.to_path_buf()),
            None => {
                let candidate = cli_data_dir
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from(".parvault-data"))
                    .join("config.toml");
                candidate.is_file().then_some(candidate)
            }
        };
        let raw = match &path {
            Some(p) => Some(std::fs::read_to_string(p)?),
            None => None,
        };
        Ok(Self { path, raw })
    }
}

/// Which command the configuration was resolved for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandScope {
    /// `config dump`.
    ConfigDump,
    Up,
    DaemonStart,
    /// `discover`, `pair`, `join`: refused in lab mode.
    Discovery,
    Other,
}

/// File keys accepted under another name (`#[serde(alias)]` in `NodeConfig`).
const KEY_ALIASES: &[(&str, &str)] = &[
    ("profile", "hardware_profile"),
    ("trackers", "public_trackers"),
    ("label", "node_label"),
    ("status_http", "status_http_bind"),
    ("watch_folder", "watched_folder"),
];

/// The resolved configuration.
#[derive(Clone, Debug)]
pub struct EffectiveConfig {
    /// Every key resolved, command flags and lab overrides included.
    pub cfg: NodeConfig,
    pub scope: CommandScope,
    pub config_file: Option<PathBuf>,
    pub unknown_file_keys: usize,
    pub env: EnvSnapshot,
    key_sources: BTreeMap<String, Source>,
    arg_sources: BTreeMap<String, Source>,
    arg_values: BTreeMap<String, Value>,
    arg_present: BTreeMap<String, bool>,
    active_args: Vec<String>,
    /// `bootstrap_peers` after `--peers` / `PARVAULT_PEERS`.
    pub explicit_peers: Vec<String>,
    pub seed_addr: Option<String>,
    pub wan_seeds: Vec<String>,
    pub public_trackers: Vec<String>,
    pub external_addrs: Vec<String>,
    pub lan_port: u16,
    pub lan_enabled: bool,
    pub trust_mode: TrustPoolMode,
    /// `up --wan`.
    pub wan_flag: bool,
    pub listeners: Listeners,
}

/// Every listener the command binds (the IPC socket is a path).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listeners {
    pub tcp: Option<String>,
    pub quic: Option<String>,
    pub status_http: Option<String>,
    pub webdav: Option<String>,
    pub ipc_socket: Option<PathBuf>,
    pub insecure_metrics: Option<String>,
}

fn push_unique(out: &mut Vec<String>, s: &str) {
    let t = s.trim();
    if !t.is_empty() && !out.iter().any(|e| e == t) {
        out.push(t.to_string());
    }
}

fn split_list(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        push_unique(&mut out, part);
    }
    out
}

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

/// The source of an argument: the deepest matches that define it and saw it on the command line
/// win (a global flag may be given after the subcommand).
fn arg_source(chain: &[&ArgMatches], id: &str, long: Option<&str>) -> Source {
    let mut seen_default = false;
    for m in chain.iter().rev() {
        match m.try_get_raw(id) {
            Ok(_) => match m.value_source(id) {
                Some(ValueSource::CommandLine) => {
                    return Source::Flag(long.unwrap_or(id).to_string());
                }
                Some(ValueSource::DefaultValue) => seen_default = true,
                _ => {}
            },
            Err(_) => continue,
        }
    }
    let _ = seen_default;
    Source::Default
}

impl EffectiveConfig {
    /// Resolves the configuration for `cli` (its `matches` give the flag sources).
    pub fn resolve(
        cli: &Cli,
        matches: &ArgMatches,
        env: EnvSnapshot,
        file: ConfigFileInput,
    ) -> anyhow::Result<Self> {
        // 1. File, with sources from the parsed table.
        let mut key_sources: BTreeMap<String, Source> = BTreeMap::new();
        for (name, kind, _) in DUMP_SCHEMA {
            if *kind == FieldKind::Key {
                key_sources.insert((*name).to_string(), Source::Default);
            }
        }
        let mut unknown_file_keys = 0usize;
        let mut cfg = match &file.raw {
            Some(raw) => {
                let table: toml::Value = toml::from_str(raw)?;
                if let Some(t) = table.as_table() {
                    for (k, v) in t {
                        if k == "lab" {
                            if let Some(lab) = v.as_table() {
                                for (lk, _) in lab {
                                    let full = format!("lab.{lk}");
                                    if key_sources.contains_key(&full) {
                                        key_sources.insert(full, Source::File);
                                    } else {
                                        unknown_file_keys += 1;
                                    }
                                }
                            } else {
                                unknown_file_keys += 1;
                            }
                            continue;
                        }
                        let canonical = KEY_ALIASES
                            .iter()
                            .find(|(alias, _)| alias == k)
                            .map(|(_, c)| *c)
                            .unwrap_or(k.as_str());
                        if key_sources.contains_key(canonical) {
                            key_sources.insert(canonical.to_string(), Source::File);
                        } else {
                            unknown_file_keys += 1;
                        }
                    }
                }
                let parsed = NodeConfig::from_toml_str(raw)?;
                if key_sources.get("hardware_profile") == Some(&Source::File) {
                    for k in [
                        "stripe_size_bytes",
                        "min_free_disk_bytes",
                        "max_connections",
                    ] {
                        if key_sources.get(k) == Some(&Source::Default) {
                            key_sources.insert(k.to_string(), Source::Profile);
                        }
                    }
                }
                parsed
            }
            None => NodeConfig::default(),
        };

        // 2. The argument chain (top level, then the subcommand, then its action).
        let cmd = Cli::command();
        let mut chain: Vec<&ArgMatches> = vec![matches];
        let mut cmd_chain: Vec<clap::Command> = vec![cmd.clone()];
        let mut cur = matches;
        let mut cur_cmd = cmd;
        while let Some((name, sub)) = cur.subcommand() {
            let Some(sub_cmd) = cur_cmd.find_subcommand(name).cloned() else {
                break;
            };
            chain.push(sub);
            cmd_chain.push(sub_cmd.clone());
            cur = sub;
            cur_cmd = sub_cmd;
        }
        let scope = match &cli.command {
            Commands::Config {
                action: ConfigAction::Dump,
            } => CommandScope::ConfigDump,
            Commands::Up { .. } => CommandScope::Up,
            Commands::Daemon {
                action: DaemonAction::Start { .. },
            } => CommandScope::DaemonStart,
            Commands::Discover { .. } | Commands::Pair { .. } | Commands::Join { .. } => {
                CommandScope::Discovery
            }
            _ => CommandScope::Other,
        };
        // Active args: the globals, plus the leaf command's own for `up` / `daemon start`.
        let mut active_args: Vec<String> = Vec::new();
        let mut arg_sources = BTreeMap::new();
        let mut longs: BTreeMap<String, Option<String>> = BTreeMap::new();
        let leaf_has_args = matches!(scope, CommandScope::Up | CommandScope::DaemonStart);
        for (depth, c) in cmd_chain.iter().enumerate() {
            let is_leaf = depth + 1 == cmd_chain.len();
            for a in c.get_arguments() {
                let id = a.get_id().as_str().to_string();
                if id == "help" || id == "version" {
                    continue;
                }
                let wanted = (depth == 0 && a.is_global_set()) || (is_leaf && leaf_has_args);
                if wanted && !active_args.contains(&id) {
                    longs.insert(id.clone(), a.get_long().map(str::to_string));
                    active_args.push(id);
                }
            }
        }
        for id in &active_args {
            let long = longs.get(id).cloned().flatten();
            arg_sources.insert(id.clone(), arg_source(&chain, id, long.as_deref()));
        }
        let flag = |id: &str| -> Option<Source> {
            arg_sources
                .get(id)
                .filter(|s| matches!(s, Source::Flag(_)))
                .cloned()
        };

        // 3. Global flags and the environment, in the order the effective_* readers used.
        if let Some(dir) = &cli.data_dir {
            cfg.data_dir = dir.clone();
            if let Some(s) = flag("data_dir") {
                key_sources.insert("data_dir".into(), s);
            }
        }
        if let Some(profile) = cli.profile {
            cfg.apply_hardware_profile(profile);
            if let Some(s) = flag("profile") {
                key_sources.insert("hardware_profile".into(), s);
            }
            for k in [
                "stripe_size_bytes",
                "min_free_disk_bytes",
                "max_connections",
            ] {
                key_sources.insert(k.into(), Source::Profile);
            }
        }

        let explicit_peers = if !cli.peers.is_empty() {
            key_sources.insert(
                "bootstrap_peers".into(),
                flag("peers").unwrap_or(Source::Default),
            );
            let mut v = Vec::new();
            for p in &cli.peers {
                push_unique(&mut v, p);
            }
            v
        } else if let Some(list) = env
            .get("PARVAULT_PEERS")
            .map(split_list)
            .filter(|l| !l.is_empty())
        {
            key_sources.insert("bootstrap_peers".into(), Source::Env("PARVAULT_PEERS"));
            list
        } else {
            cfg.bootstrap_peers.clone()
        };
        cfg.bootstrap_peers = explicit_peers.clone();

        let seed_addr = if let Some(s) = cli
            .seed_addr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            key_sources.insert(
                "lite_seed_addr".into(),
                flag("seed_addr").unwrap_or(Source::Default),
            );
            Some(s.to_string())
        } else if let Some(s) = env
            .get("PARVAULT_SEED_ADDR")
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            key_sources.insert("lite_seed_addr".into(), Source::Env("PARVAULT_SEED_ADDR"));
            Some(s.to_string())
        } else {
            cfg.lite_seed_addr.clone()
        };
        cfg.lite_seed_addr = seed_addr.clone();

        // WAN seeds: the configured list (env, then file) is the key; the effective list also
        // takes the seed address first, as `effective_wan_rendezvous_seeds` did.
        let mut configured_wan = Vec::new();
        if let Some(e) = env.get("PARVAULT_WAN_SEEDS") {
            for p in split_list(e) {
                push_unique(&mut configured_wan, &p);
            }
            if !configured_wan.is_empty() {
                key_sources.insert(
                    "wan_rendezvous_seeds".into(),
                    Source::Env("PARVAULT_WAN_SEEDS"),
                );
            }
        }
        for s in &cfg.wan_rendezvous_seeds {
            push_unique(&mut configured_wan, s);
        }
        cfg.wan_rendezvous_seeds = configured_wan.clone();
        let mut wan_seeds = Vec::new();
        if let Some(s) = &seed_addr {
            push_unique(&mut wan_seeds, s);
        }
        for s in &configured_wan {
            push_unique(&mut wan_seeds, s);
        }

        // Trust mode, then trackers (which add the seed address in public mode).
        let env_public = env.get("PARVAULT_PUBLIC").is_some_and(truthy);
        let mut trust_mode = cfg.trust_mode;
        if (cli.public || env_public || !cli.trackers.is_empty())
            && cfg.trust_mode == TrustPoolMode::PrivateRing
        {
            trust_mode = TrustPoolMode::Hybrid;
            let src = if cli.public {
                flag("public").unwrap_or(Source::Default)
            } else if env_public {
                Source::Env("PARVAULT_PUBLIC")
            } else {
                flag("trackers").unwrap_or(Source::Default)
            };
            key_sources.insert("trust_mode".into(), src);
        }
        cfg.trust_mode = trust_mode;
        let public_mode = trust_mode.allows_public_commons();

        let mut configured_trackers = Vec::new();
        for t in &cli.trackers {
            push_unique(&mut configured_trackers, t);
        }
        if !configured_trackers.is_empty() {
            key_sources.insert(
                "public_trackers".into(),
                flag("trackers").unwrap_or(Source::Default),
            );
        }
        if let Some(e) = env.get("PARVAULT_TRACKERS") {
            let before = configured_trackers.len();
            for p in split_list(e) {
                push_unique(&mut configured_trackers, &p);
            }
            if before == 0 && !configured_trackers.is_empty() {
                key_sources.insert("public_trackers".into(), Source::Env("PARVAULT_TRACKERS"));
            }
        }
        for t in &cfg.public_trackers {
            push_unique(&mut configured_trackers, t);
        }
        cfg.public_trackers = configured_trackers.clone();
        let mut public_trackers = configured_trackers;
        if public_mode {
            if let Some(s) = &seed_addr {
                push_unique(&mut public_trackers, s);
            }
        }

        let mut external_addrs = Vec::new();
        for a in &cli.external_addrs {
            push_unique(&mut external_addrs, a);
        }
        if !external_addrs.is_empty() {
            key_sources.insert(
                "external_addrs".into(),
                flag("external_addrs").unwrap_or(Source::Default),
            );
        }
        if let Some(e) = env.get("PARVAULT_EXTERNAL_ADDRS") {
            let before = external_addrs.len();
            for p in split_list(e) {
                push_unique(&mut external_addrs, &p);
            }
            if before == 0 && !external_addrs.is_empty() {
                key_sources.insert(
                    "external_addrs".into(),
                    Source::Env("PARVAULT_EXTERNAL_ADDRS"),
                );
            }
        }
        for a in &cfg.external_addrs {
            push_unique(&mut external_addrs, a);
        }
        cfg.external_addrs = external_addrs.clone();

        let lan_port = if let Some(p) = cli.lan_discovery_port {
            key_sources.insert(
                "lan_discovery_port".into(),
                flag("lan_discovery_port").unwrap_or(Source::Default),
            );
            p
        } else if let Some(p) = env
            .get("PARVAULT_LAN_DISCOVERY_PORT")
            .and_then(|v| v.trim().parse::<u16>().ok())
            .filter(|p| *p > 0)
        {
            key_sources.insert(
                "lan_discovery_port".into(),
                Source::Env("PARVAULT_LAN_DISCOVERY_PORT"),
            );
            p
        } else if cfg.lan_discovery_port == 0 {
            crate::config::DEFAULT_LAN_DISCOVERY_PORT
        } else {
            cfg.lan_discovery_port
        };
        cfg.lan_discovery_port = lan_port;

        if cli.no_lan_discovery {
            cfg.lan_discovery_enabled = false;
            key_sources.insert(
                "lan_discovery_enabled".into(),
                flag("no_lan_discovery").unwrap_or(Source::Default),
            );
        } else if env.get("PARVAULT_NO_LAN_DISCOVERY").is_some_and(truthy) {
            cfg.lan_discovery_enabled = false;
            key_sources.insert(
                "lan_discovery_enabled".into(),
                Source::Env("PARVAULT_NO_LAN_DISCOVERY"),
            );
        }

        if cfg
            .node_label
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            for name in ["HOSTNAME", "COMPUTERNAME"] {
                if let Some(h) = env.get(name) {
                    cfg.node_label = Some(h.trim().to_string());
                    key_sources.insert("node_label".into(), Source::Env(name));
                    break;
                }
            }
        }

        if cfg.device_sealing_passphrase.is_none() && env.is_set("PARVAULT_PASSPHRASE") {
            key_sources.insert(
                "device_sealing_passphrase".into(),
                Source::Env("PARVAULT_PASSPHRASE"),
            );
        }

        if cli.lab_deterministic {
            cfg.lab.deterministic = true;
            key_sources.insert(
                "lab.deterministic".into(),
                flag("lab_deterministic").unwrap_or(Source::Default),
            );
        }

        // 4. The command's own flags. A flag overrides the file only when given; the clap
        // default applies only when the file does not set the key.
        let mut arg_values: BTreeMap<String, Value> = BTreeMap::new();
        let mut arg_present: BTreeMap<String, bool> = BTreeMap::new();
        let mut wan_flag = false;
        let mut listeners = Listeners::default();
        let key_from_flag =
            |key_sources: &mut BTreeMap<String, Source>, key: &str, id: &str| -> bool {
                if let Some(s) = arg_sources.get(id).filter(|s| matches!(s, Source::Flag(_))) {
                    key_sources.insert(key.to_string(), s.clone());
                    true
                } else {
                    false
                }
            };
        let mut set_args = |pairs: Vec<(&str, Value)>| {
            for (k, v) in pairs {
                arg_values.insert(k.to_string(), v);
            }
        };
        match &cli.command {
            Commands::Up {
                folder,
                interval_secs,
                status_http,
                pair,
                wan,
                listen,
                tier,
                ipc_socket,
                no_socket,
                no_audit,
                strict_plugins,
                allow_peer_uid,
                require_sealed_memfd,
                macaroon_root_key_hex,
                vfs_webdav_listen,
                vfs_fuse_fd,
                vfs_seed_dir,
                vfs_cache_mib,
                dump_config: _,
            } => {
                if let Some(l) = listen {
                    cfg.listen_tcp = l.clone();
                    key_from_flag(&mut key_sources, "listen_tcp", "listen");
                }
                if *no_audit {
                    cfg.por_audit_enabled = false;
                    key_from_flag(&mut key_sources, "por_audit_enabled", "no_audit");
                }
                if let Some(s) = status_http {
                    cfg.status_http_bind = Some(s.clone());
                    key_from_flag(&mut key_sources, "status_http_bind", "status_http");
                }
                if let Some(f) = folder {
                    cfg.watched_folder = Some(f.clone());
                    key_from_flag(&mut key_sources, "watched_folder", "folder");
                }
                wan_flag = *wan;
                listeners.webdav = vfs_webdav_listen.clone();
                listeners.ipc_socket = if *no_socket { None } else { ipc_socket.clone() };
                arg_present.insert(
                    "macaroon_root_key_hex".into(),
                    macaroon_root_key_hex.is_some(),
                );
                set_args(vec![
                    ("folder", serde_json::json!(folder)),
                    ("interval_secs", serde_json::json!(interval_secs)),
                    ("status_http", serde_json::json!(status_http)),
                    ("pair", serde_json::json!(pair)),
                    ("wan", serde_json::json!(wan)),
                    ("listen", serde_json::json!(listen)),
                    ("tier", serde_json::json!(tier.map(|t| format!("{t:?}")))),
                    ("ipc_socket", serde_json::json!(ipc_socket)),
                    ("no_socket", serde_json::json!(no_socket)),
                    ("no_audit", serde_json::json!(no_audit)),
                    ("strict_plugins", serde_json::json!(strict_plugins)),
                    ("allow_peer_uid", serde_json::json!(allow_peer_uid)),
                    (
                        "require_sealed_memfd",
                        serde_json::json!(require_sealed_memfd),
                    ),
                    ("vfs_webdav_listen", serde_json::json!(vfs_webdav_listen)),
                    ("vfs_fuse_fd", serde_json::json!(vfs_fuse_fd)),
                    ("vfs_seed_dir", serde_json::json!(vfs_seed_dir)),
                    ("vfs_cache_mib", serde_json::json!(vfs_cache_mib)),
                ]);
            }
            Commands::Daemon {
                action:
                    DaemonAction::Start {
                        listen,
                        enable_quic,
                        status_http,
                        ipc_socket,
                        no_socket,
                        no_audit,
                        strict_plugins,
                        allow_peer_uid,
                        require_sealed_memfd,
                        macaroon_root_key_hex,
                        vfs_webdav_listen,
                        vfs_fuse_fd,
                        vfs_seed_dir,
                        vfs_cache_mib,
                        dump_config: _,
                        #[cfg(feature = "lab-insecure-metrics")]
                        lab_insecure_metrics,
                    },
            } => {
                #[cfg(feature = "lab-insecure-metrics")]
                {
                    listeners.insecure_metrics = lab_insecure_metrics.clone();
                    set_args(vec![(
                        "lab_insecure_metrics",
                        serde_json::json!(lab_insecure_metrics),
                    )]);
                }
                if key_from_flag(&mut key_sources, "listen_tcp", "listen")
                    || key_sources.get("listen_tcp") == Some(&Source::Default)
                {
                    cfg.listen_tcp = listen.clone();
                }
                if key_from_flag(&mut key_sources, "enable_quic", "enable_quic")
                    || key_sources.get("enable_quic") == Some(&Source::Default)
                {
                    cfg.enable_quic = *enable_quic;
                }
                if *no_audit {
                    cfg.por_audit_enabled = false;
                    key_from_flag(&mut key_sources, "por_audit_enabled", "no_audit");
                }
                if let Some(s) = status_http {
                    cfg.status_http_bind = Some(s.clone());
                    key_from_flag(&mut key_sources, "status_http_bind", "status_http");
                }
                listeners.webdav = vfs_webdav_listen.clone();
                listeners.ipc_socket = if *no_socket { None } else { ipc_socket.clone() };
                arg_present.insert(
                    "macaroon_root_key_hex".into(),
                    macaroon_root_key_hex.is_some(),
                );
                set_args(vec![
                    ("listen", serde_json::json!(listen)),
                    ("enable_quic", serde_json::json!(enable_quic)),
                    ("status_http", serde_json::json!(status_http)),
                    ("ipc_socket", serde_json::json!(ipc_socket)),
                    ("no_socket", serde_json::json!(no_socket)),
                    ("no_audit", serde_json::json!(no_audit)),
                    ("strict_plugins", serde_json::json!(strict_plugins)),
                    ("allow_peer_uid", serde_json::json!(allow_peer_uid)),
                    (
                        "require_sealed_memfd",
                        serde_json::json!(require_sealed_memfd),
                    ),
                    ("vfs_webdav_listen", serde_json::json!(vfs_webdav_listen)),
                    ("vfs_fuse_fd", serde_json::json!(vfs_fuse_fd)),
                    ("vfs_seed_dir", serde_json::json!(vfs_seed_dir)),
                    ("vfs_cache_mib", serde_json::json!(vfs_cache_mib)),
                ]);
            }
            _ => {}
        }
        set_args(vec![
            ("config", serde_json::json!(cli.config)),
            ("data_dir", serde_json::json!(cli.data_dir)),
            (
                "profile",
                serde_json::json!(cli.profile.map(|p| p.to_string())),
            ),
            ("peers", serde_json::json!(cli.peers)),
            ("seed_addr", serde_json::json!(cli.seed_addr)),
            ("external_addrs", serde_json::json!(cli.external_addrs)),
            (
                "lan_discovery_port",
                serde_json::json!(cli.lan_discovery_port),
            ),
            ("no_lan_discovery", serde_json::json!(cli.no_lan_discovery)),
            ("public", serde_json::json!(cli.public)),
            ("trackers", serde_json::json!(cli.trackers)),
            (
                "lab_deterministic",
                serde_json::json!(cli.lab_deterministic),
            ),
        ]);

        // 5. Lab overrides: a default that turns a channel on is turned off, source `lab`.
        // Explicit settings are left as they are; lab_side_channel_decision refuses them.
        if cfg.lab.deterministic
            && cfg.lan_discovery_enabled
            && !key_sources
                .get("lan_discovery_enabled")
                .is_some_and(Source::is_explicit)
        {
            cfg.lan_discovery_enabled = false;
            key_sources.insert("lan_discovery_enabled".into(), Source::Lab);
        }
        let lan_enabled = cfg.lan_discovery_enabled;

        listeners.tcp = Some(cfg.listen_tcp.clone());
        listeners.quic = cfg.enable_quic.then(|| cfg.listen_quic.clone());
        listeners.status_http = cfg.status_http_bind.clone();
        if scope == CommandScope::ConfigDump {
            // No command flags: what `up` would bind from the file alone.
            listeners.webdav = None;
            listeners.ipc_socket = None;
        }

        Ok(Self {
            cfg,
            scope,
            config_file: file.path,
            unknown_file_keys,
            env,
            key_sources,
            arg_sources,
            arg_values,
            arg_present,
            active_args,
            explicit_peers,
            seed_addr,
            wan_seeds,
            public_trackers,
            external_addrs,
            lan_port,
            lan_enabled,
            trust_mode,
            wan_flag,
            listeners,
        })
    }

    pub fn deterministic(&self) -> bool {
        self.cfg.lab.deterministic
    }

    pub fn public_mode(&self) -> bool {
        self.trust_mode.allows_public_commons()
    }

    pub fn key_source(&self, key: &str) -> Source {
        self.key_sources
            .get(key)
            .cloned()
            .unwrap_or(Source::Default)
    }

    pub fn arg_source(&self, id: &str) -> Source {
        self.arg_sources.get(id).cloned().unwrap_or(Source::Default)
    }

    /// The args of this command, in `DUMP_SCHEMA` terms.
    pub fn is_active_arg(&self, id: &str) -> bool {
        self.active_args.iter().any(|a| a == id)
    }

    pub fn active_args(&self) -> &[String] {
        &self.active_args
    }

    /// A non-secret arg's value. Secret args are never stored, only their presence.
    pub fn arg_value(&self, id: &str) -> Option<&Value> {
        self.arg_values.get(id)
    }

    pub fn arg_is_present(&self, id: &str) -> bool {
        if let Some(p) = self.arg_present.get(id) {
            return *p;
        }
        self.arg_values
            .get(id)
            .is_some_and(|v| !v.is_null() && v != &Value::Bool(false))
    }

    /// The configured dial set: `bootstrap_peers` ∪ `lite_seed_addr` ∪ `lab.relays`, in that
    /// order, duplicates removed.
    pub fn dial_set_entries(&self) -> Vec<String> {
        let mut out = Vec::new();
        for p in &self.explicit_peers {
            push_unique(&mut out, p);
        }
        if let Some(s) = &self.seed_addr {
            push_unique(&mut out, s);
        }
        for r in self.cfg.lab.relays.iter().flatten() {
            push_unique(&mut out, r);
        }
        out
    }

    /// `Open` unless deterministic; then the parsed dial set (entries that fail
    /// `lab_addr_decision` are refused at startup by `lab_startup_decision`).
    pub fn dial_set(&self) -> DialSet {
        if !self.deterministic() {
            return DialSet::Open;
        }
        let mut entries: Vec<DialEntry> = Vec::new();
        for raw in self.dial_set_entries() {
            if let Some(e) = crate::network::traversal_gate::dial_entry_from_str(&raw) {
                if !entries.contains(&e) {
                    entries.push(e);
                }
            }
        }
        DialSet::Fixed(entries)
    }

    /// Settings that turn a side channel on, each with its source: refused in lab mode
    /// (`reject.lab_config_conflict`). Only explicit settings count.
    pub fn lab_conflicts(&self) -> Vec<(&'static str, Source)> {
        let mut out = Vec::new();
        let explicit = |k: &str| self.key_source(k).is_explicit();
        if self.cfg.lan_discovery_enabled && explicit("lan_discovery_enabled") {
            out.push((
                "lan_discovery_enabled",
                self.key_source("lan_discovery_enabled"),
            ));
        }
        if self.trust_mode != TrustPoolMode::PrivateRing && explicit("trust_mode") {
            out.push(("trust_mode", self.key_source("trust_mode")));
        }
        if !self.cfg.public_trackers.is_empty() && explicit("public_trackers") {
            out.push(("public_trackers", self.key_source("public_trackers")));
        }
        if !self.cfg.wan_rendezvous_seeds.is_empty() && explicit("wan_rendezvous_seeds") {
            out.push((
                "wan_rendezvous_seeds",
                self.key_source("wan_rendezvous_seeds"),
            ));
        }
        if self
            .env
            .is_set(crate::network::discovery::LAN_REGISTRY_ENV_VAR)
        {
            out.push((
                crate::network::discovery::LAN_REGISTRY_ENV_VAR,
                Source::Env(crate::network::discovery::LAN_REGISTRY_ENV_VAR),
            ));
        }
        if self.wan_flag {
            out.push(("wan", self.arg_source("wan")));
        }
        out
    }

    /// The side channels this configuration runs.
    pub fn side_channels(&self) -> SideChannels {
        let det = self.deterministic();
        let wan = !det && (self.wan_flag || !self.wan_seeds.is_empty());
        SideChannels {
            mdns: !det && self.lan_enabled,
            lan_beacon: !det && self.lan_enabled,
            lan_registry: !det
                && self
                    .env
                    .is_set(crate::network::discovery::LAN_REGISTRY_ENV_VAR),
            known_peers_file: !det,
            wan_rendezvous: wan,
            trackers: !det && self.public_mode() && !self.public_trackers.is_empty(),
            relay_forward: !det,
            zero_config_resolution: !det,
        }
    }
}

/// The side channels a configuration runs (`effective.side_channels` in the dump).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideChannels {
    pub mdns: bool,
    pub lan_beacon: bool,
    pub lan_registry: bool,
    pub known_peers_file: bool,
    pub wan_rendezvous: bool,
    pub trackers: bool,
    pub relay_forward: bool,
    pub zero_config_resolution: bool,
}

/// Every startup check of deterministic mode, in order: the command and the conflicts
/// (`lab_side_channel_decision`), the relay list, every listener (`lab_bind_decision`) and
/// every dial-set and relay address (`lab_addr_decision`). `Err((code, detail))`: the detail
/// names the key or value, never a secret.
pub fn lab_startup_decision(eff: &EffectiveConfig) -> Result<(), (&'static str, String)> {
    if !eff.deterministic() {
        return Ok(());
    }
    if let Err(code) = lab_side_channel_decision(eff) {
        let detail = eff
            .lab_conflicts()
            .into_iter()
            .map(|(k, s)| format!("{k} (source {s})"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err((code, detail));
    }
    if eff.cfg.lab.relays.is_none() {
        return Err((
            "reject.lab_relays_missing",
            "[lab] relays must be set (it may be empty)".into(),
        ));
    }
    if matches!(
        eff.scope,
        CommandScope::Up | CommandScope::DaemonStart | CommandScope::ConfigDump
    ) {
        let l = &eff.listeners;
        for (name, bind) in [
            ("listen_tcp", l.tcp.as_ref()),
            ("listen_quic", l.quic.as_ref()),
            ("status_http_bind", l.status_http.as_ref()),
            ("vfs_webdav_listen", l.webdav.as_ref()),
            ("lab_insecure_metrics", l.insecure_metrics.as_ref()),
        ] {
            if let Some(b) = bind {
                let addr = b.rsplit_once('=').map(|(_, a)| a).unwrap_or(b);
                lab_bind_decision(addr).map_err(|code| (code, format!("{name} = {addr}")))?;
            }
        }
    }
    for raw in eff.dial_set_entries() {
        lab_addr_decision(&raw).map_err(|code| (code, raw.clone()))?;
    }
    Ok(())
}
