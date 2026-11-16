//! `parvault config dump` (`v0.5.4` NEW-5, schema `parvault.config-dump/1`, `docs/LAB_MODE.md`).
//!
//! The renderer's only input is [`DUMP_SCHEMA`]: every config key, every argument of the global
//! flags, `up` and `daemon start`, every environment variable the crate reads, and the key files,
//! each classified. A row's class decides what may be printed ([`dump_field_repr`]); a secret
//! prints only whether it is set and where from. The parsed TOML, `NodeConfig`'s `Serialize`,
//! the environment and the `ArgMatches` are never iterated, so an unclassified input cannot
//! reach the output; unknown file keys are counted, never named.

/// What a row describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    /// A `NodeConfig` key (`lab.*` for the `[lab]` table).
    Key,
    /// A clap argument id.
    Arg,
    /// An environment variable.
    Env,
    /// A key file in the data directory (always `SecretPath`).
    File,
}

/// What may be printed for a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum FieldClass {
    Plain,
    /// A URL or address: printed without its `user:password@` part.
    PlainUrl,
    /// Only `{"set", "source"}`: no value, length, hash or prefix.
    Secret,
    /// A key file: only whether it exists (metadata) and its path, never its contents.
    SecretPath,
    /// Selects the output mode (`--dump-config`); classified, never rendered, so the dump of a
    /// command and the running command hash the same.
    Control,
}

/// How a row is rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpRepr {
    /// `{"value", "source"}`.
    Value,
    /// `{"value", "source"}` with userinfo removed (`"userinfo_removed": true` if any was), or
    /// `{"set": true, "unparsed": true, "source"}` when a value cannot be checked.
    ValueWithoutUserinfo,
    /// `{"set", "source"}`.
    SetOnly,
    /// Nothing.
    Omitted,
}

/// The class decides the representation; `present` never turns a secret into a value.
pub fn dump_field_repr(class: FieldClass, present: bool) -> DumpRepr {
    let _ = present;
    match class {
        FieldClass::Plain => DumpRepr::Value,
        FieldClass::PlainUrl => DumpRepr::ValueWithoutUserinfo,
        FieldClass::Secret | FieldClass::SecretPath => DumpRepr::SetOnly,
        FieldClass::Control => DumpRepr::Omitted,
    }
}

use FieldClass::{Control, Plain, PlainUrl, Secret, SecretPath};
use FieldKind::{Arg, Env, File, Key};

/// Every input, classified. `dump_schema_classifies_every_key` and
/// `dump_schema_covers_every_env_read` (tests/config_dump.rs) fail on anything missing.
pub const DUMP_SCHEMA: &[(&str, FieldKind, FieldClass)] = &[
    // NodeConfig keys.
    ("data_dir", Key, Plain),
    ("listen_tcp", Key, PlainUrl),
    ("enable_quic", Key, Plain),
    ("listen_quic", Key, PlainUrl),
    ("hardware_profile", Key, Plain),
    ("stripe_size_bytes", Key, Plain),
    ("max_connections", Key, Plain),
    ("default_tier", Key, Plain),
    ("max_storage_bytes", Key, Plain),
    ("bootstrap_grace_bytes", Key, Plain),
    ("por_timeout_ms", Key, Plain),
    ("local_rtt_threshold_ms", Key, Plain),
    ("intra_asn_ratio", Key, Plain),
    ("override_asn", Key, Plain),
    ("override_region", Key, Plain),
    ("bootstrap_peers", Key, PlainUrl),
    ("lite_seed_addr", Key, PlainUrl),
    ("wan_rendezvous_seeds", Key, PlainUrl),
    ("public_trackers", Key, PlainUrl),
    ("trust_mode", Key, Plain),
    ("external_addrs", Key, PlainUrl),
    ("lan_discovery_enabled", Key, Plain),
    ("lan_discovery_port", Key, Plain),
    ("node_label", Key, Plain),
    ("status_http_bind", Key, PlainUrl),
    ("watched_folder", Key, Plain),
    ("genesis_root_pubkey_hex", Key, Plain),
    ("device_sealing_passphrase", Key, Secret),
    ("min_free_disk_bytes", Key, Plain),
    ("max_upload_mbps", Key, Plain),
    ("max_download_mbps", Key, Plain),
    ("por_audit_enabled", Key, Plain),
    ("por_audit_interval_secs", Key, Plain),
    ("por_audit_rtt_ms", Key, Plain),
    ("quota_write_epoch_secs", Key, Plain),
    ("max_held_shards", Key, Plain),
    ("lab.deterministic", Key, Plain),
    ("lab.relays", Key, PlainUrl),
    // Global args.
    ("config", Arg, Plain),
    ("data_dir", Arg, Plain),
    ("profile", Arg, Plain),
    ("peers", Arg, PlainUrl),
    ("seed_addr", Arg, PlainUrl),
    ("external_addrs", Arg, PlainUrl),
    ("lan_discovery_port", Arg, Plain),
    ("no_lan_discovery", Arg, Plain),
    ("public", Arg, Plain),
    ("trackers", Arg, PlainUrl),
    ("lab_deterministic", Arg, Plain),
    // `up` and `daemon start` args.
    ("folder", Arg, Plain),
    ("interval_secs", Arg, Plain),
    ("status_http", Arg, PlainUrl),
    ("pair", Arg, Plain),
    ("wan", Arg, Plain),
    ("listen", Arg, PlainUrl),
    ("tier", Arg, Plain),
    ("enable_quic", Arg, Plain),
    ("ipc_socket", Arg, Plain),
    ("no_socket", Arg, Plain),
    ("no_audit", Arg, Plain),
    ("strict_plugins", Arg, Plain),
    ("allow_peer_uid", Arg, Plain),
    ("require_sealed_memfd", Arg, Plain),
    ("macaroon_root_key_hex", Arg, Secret),
    ("vfs_webdav_listen", Arg, PlainUrl),
    ("vfs_fuse_fd", Arg, Plain),
    ("vfs_seed_dir", Arg, Plain),
    ("vfs_cache_mib", Arg, Plain),
    ("lab_insecure_metrics", Arg, PlainUrl),
    // v0.5.6 (T0): `up` and `daemon start` args of tracks A, B2 and E. A join token is read
    // from its file, never passed as an arg (A-146-5).
    ("init_if_absent", Arg, Plain),
    ("join_token_file", Arg, Plain),
    ("tls_san", Arg, PlainUrl),
    ("insecure_plain_http", Arg, Plain),
    ("gateway_socket_group", Arg, Plain),
    ("no_gc", Arg, Plain),
    ("dump_config", Arg, Control),
    // v0.5.6: `watch-folder` retention args (track B2) and `status --live` args (track D); not
    // args of `up` or `daemon start`, so no dump shows them yet.
    ("keep_last", Arg, Plain),
    ("keep_daily", Arg, Plain),
    ("keep_weekly", Arg, Plain),
    ("max_stored_bytes", Arg, Plain),
    ("socket", Arg, Plain),
    ("macaroon_file", Arg, Plain),
    // Environment variables read under src/.
    ("PARVAULT_PEERS", Env, PlainUrl),
    ("PARVAULT_SEED_ADDR", Env, PlainUrl),
    ("PARVAULT_WAN_SEEDS", Env, PlainUrl),
    ("PARVAULT_TRACKERS", Env, PlainUrl),
    ("PARVAULT_EXTERNAL_ADDRS", Env, PlainUrl),
    ("PARVAULT_LAN_DISCOVERY_PORT", Env, Plain),
    ("PARVAULT_NO_LAN_DISCOVERY", Env, Plain),
    ("PARVAULT_PUBLIC", Env, Plain),
    ("PARVAULT_LAN_REGISTRY_DIR", Env, Plain),
    ("HOSTNAME", Env, Plain),
    ("COMPUTERNAME", Env, Plain),
    ("PARVAULT_GENESIS_PUBKEY_HEX", Env, Plain),
    ("PARVAULT_TEST_SCHED_NO_PRIORITY", Env, Plain),
    ("PARVAULT_KAD_REPLICATION_SECS", Env, Plain),
    ("PARVAULT_DHT_STORE_MAX_KEYS", Env, Plain),
    ("PARVAULT_DHT_STORE_MAX_BYTES", Env, Plain),
    ("PARVAULT_PASSPHRASE", Env, Secret),
    ("PARVAULT_SEED_PHRASE", Env, Secret),
    ("PARVAULT_GENESIS_SEED_HEX", Env, Secret),
    ("PARVAULT_JOIN_TOKEN", Env, Secret),
    // Key files in the data directory.
    ("macaroon_root.key", File, SecretPath),
    ("node_identity.seed", File, SecretPath),
    ("enclave_sealing.seed", File, SecretPath),
    ("master_key.sealed", File, SecretPath),
    ("ring_genesis.seed", File, SecretPath),
    ("node_pq_kem.bin", File, SecretPath),
    ("owner_pq_keypair.bin", File, SecretPath),
    // Per-vault key files (archC1 cond. 5): one `*` in the last component matches any file.
    ("vaults/*.vaultkey", File, SecretPath),
];

/// Whether the key file `name` exists under `data_dir`, from metadata only. A `*` in the last
/// path component (`vaults/*.vaultkey`) matches any file name with the same prefix and suffix.
pub fn secret_file_present(data_dir: &std::path::Path, name: &str) -> bool {
    let path = data_dir.join(name);
    let Some((prefix, suffix)) = path
        .file_name()
        .and_then(|f| f.to_str())
        .and_then(|f| f.split_once('*'))
    else {
        return path.exists();
    };
    let Some(dir) = path.parent() else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let f = e.file_name();
        let f = f.to_string_lossy();
        f.len() >= prefix.len() + suffix.len()
            && f.starts_with(prefix)
            && f.ends_with(suffix)
            && e.file_type().is_ok_and(|t| t.is_file())
    })
}

/// The class of `name` for `kind`, if classified.
pub fn dump_class(name: &str, kind: FieldKind) -> Option<FieldClass> {
    DUMP_SCHEMA
        .iter()
        .find(|(n, k, _)| *n == name && *k == kind)
        .map(|(_, _, c)| *c)
}

/// Removes the `user:password@` part of a URL (`scheme://user:pw@host/...`). A multiaddr or a
/// `host:port` has no userinfo and is returned as is. `None` when the value cannot be checked
/// (an `@` outside a URL authority): it is then not printed.
pub fn url_without_userinfo(raw: &str) -> Option<(String, bool)> {
    if let Some(idx) = raw.find("://") {
        let (scheme, rest) = raw.split_at(idx + 3);
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if let Some(at) = authority.rfind('@') {
            let host = &authority[at + 1..];
            return Some((format!("{scheme}{host}{tail}"), true));
        }
        if tail.contains('@') {
            return None;
        }
        return Some((raw.to_string(), false));
    }
    if raw.contains('@') {
        return None;
    }
    Some((raw.to_string(), false))
}

/// SHA-256 of the dump bytes; `/api/v1/health` serves it as `config_digest` (lowercase hex).
pub fn config_digest(dump: &str) -> [u8; 32] {
    crate::crypto::compute_sha256(dump.as_bytes())
}

#[cfg(feature = "daemon-runtime")]
pub use render::render_dump;

#[cfg(feature = "daemon-runtime")]
mod render {
    use super::*;
    use crate::effective_config::{EffectiveConfig, Source};
    use serde_json::{json, Map, Value};
    use std::collections::BTreeMap;

    pub const SCHEMA: &str = "parvault.config-dump/1";

    fn obj(m: BTreeMap<String, Value>) -> Value {
        let mut out = Map::new();
        for (k, v) in m {
            out.insert(k, v);
        }
        Value::Object(out)
    }

    /// A value with duplicates removed from arrays (order kept).
    fn dedup(v: Value) -> Value {
        match v {
            Value::Array(items) => {
                let mut out: Vec<Value> = Vec::new();
                for i in items {
                    if !out.contains(&i) {
                        out.push(i);
                    }
                }
                Value::Array(out)
            }
            other => other,
        }
    }

    /// The URL representation of a value: each string without userinfo.
    fn url_repr(v: &Value, source: &Source) -> Value {
        let mut removed = false;
        let mut unparsed = false;
        let mut strip = |s: &str| -> Value {
            match url_without_userinfo(s) {
                Some((clean, r)) => {
                    removed |= r;
                    Value::String(clean)
                }
                None => {
                    unparsed = true;
                    Value::Null
                }
            }
        };
        let value = match v {
            Value::String(s) => strip(s),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|i| match i {
                        Value::String(s) => strip(s),
                        other => other.clone(),
                    })
                    .collect(),
            ),
            other => other.clone(),
        };
        let mut m = BTreeMap::new();
        m.insert("source".to_string(), json!(source.to_string()));
        if unparsed {
            m.insert("set".to_string(), json!(true));
            m.insert("unparsed".to_string(), json!(true));
        } else {
            m.insert("value".to_string(), dedup(value));
            if removed {
                m.insert("userinfo_removed".to_string(), json!(true));
            }
        }
        obj(m)
    }

    fn set_only(present: bool, source: String) -> Value {
        let mut m = BTreeMap::new();
        m.insert("set".to_string(), json!(present));
        m.insert("source".to_string(), json!(source));
        obj(m)
    }

    fn plain(v: Value, source: &Source) -> Value {
        let mut m = BTreeMap::new();
        m.insert("value".to_string(), dedup(v));
        m.insert("source".to_string(), json!(source.to_string()));
        obj(m)
    }

    /// One row's rendering, or `None` when the row is omitted.
    fn row(repr: DumpRepr, value: Value, present: bool, source: &Source) -> Option<Value> {
        match repr {
            DumpRepr::Value => Some(plain(value, source)),
            DumpRepr::ValueWithoutUserinfo => Some(url_repr(&value, source)),
            DumpRepr::SetOnly => Some(set_only(present, source.to_string())),
            DumpRepr::Omitted => None,
        }
    }

    fn key_value(cfg_json: &Value, name: &str) -> Value {
        let mut cur = cfg_json;
        for part in name.split('.') {
            match cur.get(part) {
                Some(v) => cur = v,
                None => return Value::Null,
            }
        }
        cur.clone()
    }

    /// Renders the dump: canonical JSON (sorted keys, 2-space indent, trailing newline), with
    /// no timestamp, PID or binary path.
    pub fn render_dump(eff: &EffectiveConfig) -> String {
        // Values are read from the resolved config by key name; secret rows read presence only.
        let cfg_json = serde_json::to_value(&eff.cfg).unwrap_or(Value::Null);
        let mut values = BTreeMap::new();
        let mut args = BTreeMap::new();
        let mut env = BTreeMap::new();
        let mut secrets = BTreeMap::new();
        for (name, kind, class) in DUMP_SCHEMA {
            let (name, kind, class) = (*name, *kind, *class);
            match kind {
                FieldKind::Key => {
                    let raw = key_value(&cfg_json, name);
                    let present = !raw.is_null();
                    let source = eff.key_source(name);
                    let repr = dump_field_repr(class, present);
                    let value = if repr == DumpRepr::SetOnly {
                        Value::Null
                    } else {
                        raw
                    };
                    if let Some(v) = row(repr, value, present, &source) {
                        if repr == DumpRepr::SetOnly {
                            secrets.insert(name.to_string(), v);
                        } else {
                            values.insert(name.to_string(), v);
                        }
                    }
                }
                FieldKind::Arg => {
                    if !eff.is_active_arg(name) {
                        continue;
                    }
                    let present = eff.arg_is_present(name);
                    let source = eff.arg_source(name);
                    let repr = dump_field_repr(class, present);
                    let value = if repr == DumpRepr::SetOnly {
                        Value::Null
                    } else {
                        eff.arg_value(name).cloned().unwrap_or(Value::Null)
                    };
                    if let Some(v) = row(repr, value, present, &source) {
                        if repr == DumpRepr::SetOnly {
                            secrets.insert(format!("arg:{name}"), v);
                        } else {
                            args.insert(name.to_string(), v);
                        }
                    }
                }
                FieldKind::Env => {
                    let present = eff.env.is_set(name);
                    match dump_field_repr(class, present) {
                        DumpRepr::SetOnly => {
                            secrets
                                .insert(name.to_string(), set_only(present, format!("env:{name}")));
                        }
                        DumpRepr::Omitted => {}
                        // Env values are inputs: they show up as the source of the keys they
                        // set. Here only whether each is set.
                        DumpRepr::Value | DumpRepr::ValueWithoutUserinfo => {
                            env.insert(name.to_string(), json!({ "set": present }));
                        }
                    }
                }
                FieldKind::File => {
                    let path = eff.cfg.data_dir.join(name);
                    // Metadata only: the file is never opened.
                    let present = secret_file_present(&eff.cfg.data_dir, name);
                    if dump_field_repr(class, present) == DumpRepr::SetOnly {
                        secrets.insert(
                            name.to_string(),
                            set_only(present, format!("file:{}", path.display())),
                        );
                    }
                }
            }
        }

        let l = &eff.listeners;
        let listeners = json!({
            "tcp": l.tcp,
            "quic": l.quic,
            "status_http": l.status_http,
            "webdav": l.webdav,
            "ipc_socket": l.ipc_socket,
        });
        let sc = eff.side_channels();
        let side = json!({
            "mdns": sc.mdns,
            "lan_beacon": sc.lan_beacon,
            "lan_registry": sc.lan_registry,
            "known_peers_file": sc.known_peers_file,
            "wan_rendezvous": sc.wan_rendezvous,
            "trackers": sc.trackers,
            "relay_forward": sc.relay_forward,
            "zero_config_resolution": sc.zero_config_resolution,
        });
        let clean_list = |list: Vec<String>| -> Value {
            Value::Array(
                list.iter()
                    .map(|s| match url_without_userinfo(s) {
                        Some((c, _)) => Value::String(c),
                        None => Value::Null,
                    })
                    .collect(),
            )
        };
        let dial_set = if eff.deterministic() {
            clean_list(eff.dial_set_entries())
        } else {
            Value::Null
        };
        let relays = match &eff.cfg.lab.relays {
            Some(r) => clean_list(r.clone()),
            None => Value::Null,
        };
        let effective = json!({
            "deterministic": eff.deterministic(),
            "listeners": listeners,
            "dial_set": dial_set,
            "relays": relays,
            "side_channels": side,
            "metrics": {
                "path": "/metrics",
                "auth": "readonly-macaroon",
                "insecure_listener": l.insecure_metrics.as_ref().map(|s| {
                    url_without_userinfo(s).map(|(c, _)| c)
                }),
            },
        });

        let mut top = BTreeMap::new();
        top.insert("schema".to_string(), json!(SCHEMA));
        top.insert("binary".to_string(), json!("parvault"));
        top.insert("version".to_string(), json!(env!("CARGO_PKG_VERSION")));
        top.insert(
            "config_file".to_string(),
            json!(eff.config_file.as_ref().map(|p| p.display().to_string())),
        );
        top.insert(
            "unknown_file_keys".to_string(),
            json!(eff.unknown_file_keys),
        );
        top.insert("values".to_string(), obj(values));
        top.insert("args".to_string(), obj(args));
        top.insert("env".to_string(), obj(env));
        top.insert("secrets".to_string(), obj(secrets));
        top.insert("effective".to_string(), effective);
        let mut out = serde_json::to_string_pretty(&obj(top)).unwrap_or_default();
        out.push('\n');
        out
    }

    /// The one-line error document (exit 3).
    pub fn render_dump_error(code: &str) -> String {
        format!("{}\n", json!({ "error": code, "schema": SCHEMA }))
    }
}

#[cfg(feature = "daemon-runtime")]
pub use render::render_dump_error;

#[cfg(test)]
mod tests {
    use super::*;

    /// archC1 cond. 5: `vaults/*.vaultkey` is set when any per-vault key file exists, and not
    /// for a directory, another suffix or a missing `vaults/`.
    #[test]
    fn vaultkey_glob_matches_only_key_files() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        let name = "vaults/*.vaultkey";
        assert!(!secret_file_present(d, name));
        std::fs::create_dir_all(d.join("vaults/dir.vaultkey")).unwrap();
        std::fs::write(d.join("vaults/a.vaultkey.bak"), b"x").unwrap();
        assert!(!secret_file_present(d, name));
        std::fs::write(d.join("vaults/home.vaultkey"), b"x").unwrap();
        assert!(secret_file_present(d, name));
        assert_eq!(
            dump_class(name, FieldKind::File),
            Some(FieldClass::SecretPath)
        );
        assert!(!secret_file_present(d, "macaroon_root.key"));
    }

    #[test]
    fn userinfo_is_removed_and_unparseable_values_are_hidden() {
        assert_eq!(
            url_without_userinfo("https://u:secret@tracker.example/announce"),
            Some(("https://tracker.example/announce".to_string(), true))
        );
        assert_eq!(
            url_without_userinfo("https://tracker.example:443/a?b=c"),
            Some(("https://tracker.example:443/a?b=c".to_string(), false))
        );
        assert_eq!(
            url_without_userinfo("/ip4/10.0.0.1/tcp/4001/p2p/12D3KooW"),
            Some(("/ip4/10.0.0.1/tcp/4001/p2p/12D3KooW".to_string(), false))
        );
        assert_eq!(url_without_userinfo("user:pw@host:4001"), None);
        assert_eq!(url_without_userinfo("https://host/path@x"), None);
    }

    #[test]
    fn secrets_never_render_a_value() {
        for class in [Plain, PlainUrl, Secret, SecretPath, Control] {
            for present in [false, true] {
                let r = dump_field_repr(class, present);
                match class {
                    Secret | SecretPath => assert_eq!(r, DumpRepr::SetOnly),
                    Plain => assert_eq!(r, DumpRepr::Value),
                    PlainUrl => assert_eq!(r, DumpRepr::ValueWithoutUserinfo),
                    Control => assert_eq!(r, DumpRepr::Omitted),
                }
            }
        }
    }

    #[test]
    fn schema_rows_are_unique() {
        for (i, (n, k, _)) in DUMP_SCHEMA.iter().enumerate() {
            assert!(
                !DUMP_SCHEMA[..i]
                    .iter()
                    .any(|(n2, k2, _)| n2 == n && k2 == k),
                "duplicate row {n} {k:?}"
            );
            if *k == File {
                assert_eq!(dump_class(n, *k), Some(SecretPath));
            }
        }
    }
}
