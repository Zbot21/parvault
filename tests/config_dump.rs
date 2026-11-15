//! `parvault config dump` / `--dump-config` against the real binary (`v0.5.4` NEW-5,
//! `docs/LAB_MODE.md`). Every test writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

use base64::Engine;
use clap::CommandFactory;
use parvault::config::{Cli, NodeConfig};
use parvault::config_dump::{dump_class, FieldClass, FieldKind, DUMP_SCHEMA};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// `parvault` with none of the variables the dump reads set, unless a test sets them.
fn parvault() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    for (name, kind, _) in DUMP_SCHEMA {
        if *kind == FieldKind::Env {
            cmd.env_remove(name);
        }
    }
    cmd.env("NO_COLOR", "1");
    cmd
}

fn run(cmd: &mut Command) -> (i32, String, String) {
    let out = common::output_within_deadline(cmd);
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn dump(data_dir: &Path, extra: &[&str]) -> (i32, String, String) {
    let mut cmd = parvault();
    cmd.arg("--data-dir").arg(data_dir).args(extra);
    run(&mut cmd)
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not JSON ({e}):\n{text}"))
}

fn temp(label: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("pv-dump-{label}-"))
        .tempdir()
        .unwrap()
}

/// Every key path of a JSON document, `a.b.c`, in sorted order.
fn key_paths(v: &serde_json::Value, prefix: &str, out: &mut BTreeSet<String>) {
    if let serde_json::Value::Object(m) = v {
        for (k, child) in m {
            let p = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            out.insert(p.clone());
            key_paths(child, &p, out);
        }
    }
}

/// Two runs, and two data directories with the same contents (the same relative `--data-dir`
/// under two working directories), print the same bytes. The key set matches the golden file and
/// the schema's required properties.
#[test]
fn dump_is_byte_stable() {
    let a = temp("stable-a");
    let b = temp("stable-b");
    for root in [a.path(), b.path()] {
        std::fs::create_dir_all(root.join("d")).unwrap();
        std::fs::write(
            root.join("cfg.toml"),
            "listen_tcp = \"/ip4/127.0.0.1/tcp/4001\"\nbootstrap_peers = [\"/ip4/10.0.0.2/tcp/4001\", \"/ip4/10.0.0.2/tcp/4001\"]\n",
        )
        .unwrap();
    }
    let run_in = |root: &Path| {
        let mut cmd = parvault();
        cmd.current_dir(root)
            .args(["--data-dir", "d", "--config", "cfg.toml", "config", "dump"]);
        run(&mut cmd)
    };
    let (c1, o1, e1) = run_in(a.path());
    let (c2, o2, _) = run_in(a.path());
    let (c3, o3, _) = run_in(b.path());
    assert_eq!((c1, c2, c3), (0, 0, 0), "{e1}");
    assert_eq!(o1, o2);
    assert_eq!(o1, o3);
    assert!(o1.ends_with("}\n"));
    let doc = json(&o1);
    // Arrays keep their order, without duplicates.
    assert_eq!(
        doc["values"]["bootstrap_peers"]["value"],
        serde_json::json!(["/ip4/10.0.0.2/tcp/4001"])
    );
    let mut keys = BTreeSet::new();
    key_paths(&doc, "", &mut keys);
    // The golden file lists the stable structure: top level, `effective`, and the value rows.
    let golden: BTreeSet<String> = include_str!("golden/config-dump-1.keys")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    let shown: BTreeSet<String> = keys
        .iter()
        .filter(|k| !k.starts_with("args.") && !k.starts_with("env.") && !k.starts_with("secrets."))
        .cloned()
        .collect();
    assert_eq!(shown, golden, "dump key set differs from the golden file");
    let schema = json(include_str!("../docs/schemas/config-dump-1.json"));
    for req in schema["required"].as_array().unwrap() {
        assert!(doc.get(req.as_str().unwrap()).is_some(), "missing {req}");
    }
    assert_eq!(doc["schema"], schema["properties"]["schema"]["const"]);
    gate_ran("config_dump::dump_is_byte_stable");
}

/// One key each from default, profile, file, env and flag; `daemon start`'s `--listen` left at
/// its clap default shows `default`.
#[test]
fn dump_shows_sources() {
    let t = temp("src");
    let cfg = t.path().join("cfg.toml");
    std::fs::write(
        &cfg,
        "hardware_profile = \"router-soc\"\nmax_storage_bytes = 1024\n",
    )
    .unwrap();
    let mut cmd = parvault();
    cmd.env("PARVAULT_PEERS", "/ip4/10.0.0.9/tcp/4001")
        .arg("--data-dir")
        .arg(t.path().join("d"))
        .arg("--config")
        .arg(&cfg)
        .args([
            "--lan-discovery-port",
            "4100",
            "daemon",
            "start",
            "--dump-config",
        ]);
    let (code, out, err) = run(&mut cmd);
    assert_eq!(code, 0, "{err}");
    let doc = json(&out);
    let src = |k: &str| doc["values"][k]["source"].as_str().unwrap().to_string();
    assert_eq!(src("por_timeout_ms"), "default");
    assert_eq!(src("stripe_size_bytes"), "profile");
    assert_eq!(src("max_storage_bytes"), "file");
    assert_eq!(src("bootstrap_peers"), "env:PARVAULT_PEERS");
    assert_eq!(src("lan_discovery_port"), "flag:--lan-discovery-port");
    assert_eq!(src("listen_tcp"), "default");
    assert_eq!(doc["args"]["listen"]["source"], "default");
    assert_eq!(
        doc["values"]["listen_tcp"]["value"],
        "/ip4/0.0.0.0/tcp/4001"
    );
    gate_ran("config_dump::dump_shows_sources");
}

const CANARY: &str = "Cx9CanaryQ7z";

fn canary_forms(c: &str) -> Vec<String> {
    vec![
        c.to_string(),
        hex::encode(c),
        hex::encode_upper(c),
        base64::engine::general_purpose::STANDARD.encode(c),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(c),
        c.chars()
            .map(|ch| format!("%{:02X}", ch as u32))
            .collect::<String>(),
    ]
}

/// No secret reaches stdout or stderr in any common encoding; the mistyped key's name is absent
/// and counted.
#[test]
fn dump_never_prints_secret_canary() {
    let t = temp("canary");
    let cfg = t.path().join("cfg.toml");
    std::fs::write(
        &cfg,
        format!(
            "device_sealing_passphrase = \"{CANARY}a\"\ndevice_sealing_pasphrase = \"{CANARY}b\"\npublic_trackers = [\"https://u:{CANARY}c@tracker.example/announce\"]\n"
        ),
    )
    .unwrap();
    let key_hex = hex::encode(format!("{CANARY}d").as_bytes())
        .chars()
        .chain(std::iter::repeat('0'))
        .take(64)
        .collect::<String>();
    for extra in [
        vec!["config", "dump"],
        vec![
            "daemon",
            "start",
            "--macaroon-root-key-hex",
            key_hex.as_str(),
            "--dump-config",
        ],
        vec![
            "up",
            "--macaroon-root-key-hex",
            key_hex.as_str(),
            "--dump-config",
        ],
    ] {
        let mut cmd = parvault();
        cmd.env("PARVAULT_PASSPHRASE", format!("{CANARY}e"))
            .env("PARVAULT_SEED_PHRASE", format!("{CANARY}f"))
            .env("PARVAULT_GENESIS_SEED_HEX", format!("{CANARY}g"))
            .arg("--data-dir")
            .arg(t.path().join("d"))
            .arg("--config")
            .arg(&cfg)
            .args(&extra);
        let (code, out, err) = run(&mut cmd);
        assert_eq!(code, 0, "{extra:?}: {err}");
        let both = format!("{out}{err}");
        for suffix in ["a", "b", "c", "d", "e", "f", "g"] {
            for form in canary_forms(&format!("{CANARY}{suffix}")) {
                assert!(!both.contains(&form), "{extra:?} leaked {form}:\n{both}");
            }
        }
        // The hex form of the key canary is the flag value itself.
        assert!(!both.contains(&key_hex));
        for form in canary_forms(CANARY) {
            assert!(!both.contains(&form), "{extra:?} leaked {form}");
        }
        assert!(!both.contains("device_sealing_pasphrase"));
        let doc = json(&out);
        assert_eq!(doc["unknown_file_keys"], 1);
        assert_eq!(doc["values"]["public_trackers"]["userinfo_removed"], true);
    }
    gate_ran("config_dump::dump_never_prints_secret_canary");
}

/// Each secret row is exactly `{"set", "source"}`.
#[test]
fn dump_lists_secret_as_set() {
    let t = temp("secret");
    let cfg = t.path().join("cfg.toml");
    std::fs::write(&cfg, "device_sealing_passphrase = \"x\"\n").unwrap();
    let mut cmd = parvault();
    cmd.env("PARVAULT_SEED_PHRASE", "y")
        .arg("--data-dir")
        .arg(t.path().join("d"))
        .arg("--config")
        .arg(&cfg)
        .args([
            "daemon",
            "start",
            "--macaroon-root-key-hex",
            &"ab".repeat(32),
            "--dump-config",
        ]);
    let (code, out, err) = run(&mut cmd);
    assert_eq!(code, 0, "{err}");
    let doc = json(&out);
    let secrets = doc["secrets"].as_object().unwrap();
    let expected: BTreeSet<String> = DUMP_SCHEMA
        .iter()
        .filter(|(_, _, c)| matches!(c, FieldClass::Secret | FieldClass::SecretPath))
        .map(|(n, k, _)| {
            if *k == FieldKind::Arg {
                format!("arg:{n}")
            } else {
                n.to_string()
            }
        })
        .collect();
    assert_eq!(
        secrets.keys().cloned().collect::<BTreeSet<_>>(),
        expected,
        "secret rows"
    );
    for (name, row) in secrets {
        let keys: BTreeSet<&str> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, BTreeSet::from(["set", "source"]), "{name}: {row}");
    }
    assert_eq!(secrets["device_sealing_passphrase"]["set"], true);
    assert_eq!(secrets["PARVAULT_SEED_PHRASE"]["set"], true);
    assert_eq!(secrets["arg:macaroon_root_key_hex"]["set"], true);
    assert_eq!(
        secrets["arg:macaroon_root_key_hex"]["source"],
        "flag:--macaroon-root-key-hex"
    );
    assert_eq!(secrets["macaroon_root.key"]["set"], false);
    gate_ran("config_dump::dump_lists_secret_as_set");
}

fn flatten_toml(v: &toml::Value, prefix: &str, out: &mut BTreeSet<String>) {
    if let toml::Value::Table(t) = v {
        for (k, child) in t {
            let p = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            if child.is_table() {
                flatten_toml(child, &p, out);
            } else {
                out.insert(p);
            }
        }
    }
}

/// Every `NodeConfig` key and every arg id of the global args, `up` and `daemon start` is a
/// `DUMP_SCHEMA` row.
#[test]
fn dump_schema_classifies_every_key() {
    let mut keys = BTreeSet::new();
    flatten_toml(
        &toml::Value::try_from(NodeConfig::default()).unwrap(),
        "",
        &mut keys,
    );
    // `None` fields are left out of TOML; JSON keeps them.
    if let serde_json::Value::Object(m) = serde_json::to_value(NodeConfig::default()).unwrap() {
        for (k, v) in m {
            if let serde_json::Value::Object(inner) = v {
                for ik in inner.keys() {
                    keys.insert(format!("{k}.{ik}"));
                }
            } else {
                keys.insert(k);
            }
        }
    }
    for k in &keys {
        assert!(
            dump_class(k, FieldKind::Key).is_some(),
            "key {k} unclassified"
        );
    }
    let cmd = Cli::command();
    let mut ids: Vec<String> = cmd
        .get_arguments()
        .map(|a| a.get_id().to_string())
        .collect();
    let up = cmd.find_subcommand("up").expect("up");
    ids.extend(up.get_arguments().map(|a| a.get_id().to_string()));
    let start = cmd
        .find_subcommand("daemon")
        .and_then(|d| d.find_subcommand("start"))
        .expect("daemon start");
    ids.extend(start.get_arguments().map(|a| a.get_id().to_string()));
    for id in ids {
        if id == "help" || id == "version" {
            continue;
        }
        assert!(
            dump_class(&id, FieldKind::Arg).is_some(),
            "arg {id} unclassified"
        );
    }
    gate_ran("config_dump::dump_schema_classifies_every_key");
}

/// Env reads whose argument is not a literal or a crate `const`, each with its reason.
const ENV_SCAN_INDIRECT: &[(&str, &str, &str)] = &[
    (
        "src/crypto/keys.rs",
        "name",
        "env_nonempty's own body; its callers pass literals and are scanned",
    ),
    (
        "src/effective_config.rs",
        "name",
        "EnvSnapshot::capture reads exactly the DUMP_SCHEMA Env rows",
    ),
    (
        "src/bin/parvault-seed.rs",
        "env_name.trim()",
        "reads a variable the operator names (--admin-key-env); seed dump is v0.5.8 (Q6)",
    ),
];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The string-literal value of `const NAME: &str = "..."` anywhere in `src/`.
fn const_literal(sources: &[(String, String)], name: &str) -> Option<String> {
    let needle = format!("const {name}: &str = \"");
    sources.iter().find_map(|(_, text)| {
        let rest = &text[text.find(&needle)? + needle.len()..];
        Some(rest[..rest.find('"')?].to_string())
    })
}

/// Source scan: every `env::var(`, `env::var_os(`, `env_nonempty(` and clap `env = "…"` under
/// `src/` names a `DUMP_SCHEMA` env row (a literal, or a `const` resolved to its literal), or is
/// listed in `ENV_SCAN_INDIRECT`. `env!` / `option_env!` are compile time and not reads.
#[test]
fn dump_schema_covers_every_env_read() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rs_files(&root.join("src"), &mut files);
    let sources: Vec<(String, String)> = files
        .iter()
        .map(|p| {
            (
                p.strip_prefix(root).unwrap().to_string_lossy().to_string(),
                std::fs::read_to_string(p).unwrap(),
            )
        })
        .collect();
    let mut found = 0usize;
    let mut indirect_used = BTreeSet::new();
    for (path, text) in &sources {
        for line in text.lines() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for pat in ["env::var(", "env::var_os(", "env_nonempty(", "env = \""] {
                let mut rest = code;
                while let Some(i) = rest.find(pat) {
                    let after = &rest[i + pat.len()..];
                    rest = after;
                    // `fn env_nonempty(name: &str)` is the helper's definition.
                    if pat == "env_nonempty(" && code.contains("fn env_nonempty(") {
                        continue;
                    }
                    found += 1;
                    let arg: String = if pat == "env = \"" {
                        format!("\"{}\"", &after[..after.find('"').unwrap_or(0)])
                    } else {
                        let mut depth = 0i32;
                        let mut end = after.len();
                        for (j, ch) in after.char_indices() {
                            match ch {
                                '(' => depth += 1,
                                ')' if depth == 0 => {
                                    end = j;
                                    break;
                                }
                                ')' => depth -= 1,
                                _ => {}
                            }
                        }
                        after[..end].trim().to_string()
                    };
                    let name = if let Some(lit) =
                        arg.strip_prefix('"').and_then(|a| a.strip_suffix('"'))
                    {
                        Some(lit.to_string())
                    } else if arg.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                        && !arg.is_empty()
                    {
                        Some(const_literal(&sources, &arg).unwrap_or_else(|| {
                            panic!("{path}: const {arg} has no literal in src/")
                        }))
                    } else {
                        None
                    };
                    match name {
                        Some(n) => assert!(
                            dump_class(&n, FieldKind::Env).is_some(),
                            "{path}: env var {n} is not a DUMP_SCHEMA row"
                        ),
                        None => {
                            let hit = ENV_SCAN_INDIRECT
                                .iter()
                                .find(|(p, a, _)| *p == path && *a == arg);
                            assert!(
                                hit.is_some(),
                                "{path}: indirect env read `{arg}` not listed"
                            );
                            indirect_used.insert((path.clone(), arg));
                        }
                    }
                }
            }
        }
    }
    assert!(found >= 15, "scan found only {found} env reads");
    // A stale exception is an error too.
    assert_eq!(
        indirect_used.len(),
        ENV_SCAN_INDIRECT.len(),
        "{indirect_used:?}"
    );
    gate_ran("config_dump::dump_schema_covers_every_env_read");
}

/// A listing of `dir`: (relative path, length, mtime, contents) of every entry.
fn snapshot_dir(dir: &Path) -> Vec<(String, u64, std::time::SystemTime, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            let md = e.metadata().unwrap();
            let rel = p.strip_prefix(dir).unwrap().to_string_lossy().to_string();
            if md.is_dir() {
                stack.push(p.clone());
                out.push((rel, 0, md.modified().unwrap(), Vec::new()));
            } else {
                out.push((
                    rel,
                    md.len(),
                    md.modified().unwrap(),
                    std::fs::read(&p).unwrap(),
                ));
            }
        }
    }
    out.sort();
    out
}

/// `config dump`, `daemon start --dump-config` and `up --dump-config` (with `--status-http`,
/// which otherwise creates a macaroon key) leave a missing data dir missing and an existing one
/// unchanged: no `macaroon_root.key`, no identity file.
#[test]
fn dump_paths_have_no_side_effects() {
    let t = temp("nofx");
    for extra in [
        vec!["config", "dump"],
        vec![
            "daemon",
            "start",
            "--status-http",
            "127.0.0.1:4080",
            "--dump-config",
        ],
        vec!["up", "--status-http", "127.0.0.1:4080", "--dump-config"],
    ] {
        let missing = t.path().join(format!("missing-{}", extra[0]));
        let (code, _, err) = dump(&missing, &extra);
        assert_eq!(code, 0, "{extra:?}: {err}");
        assert!(!missing.exists(), "{extra:?} created the data dir");

        let existing = t.path().join(format!("empty-{}", extra[0]));
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::write(existing.join("keep.txt"), b"keep").unwrap();
        let before = snapshot_dir(&existing);
        std::thread::sleep(Duration::from_millis(20));
        let (code, _, err) = dump(&existing, &extra);
        assert_eq!(code, 0, "{extra:?}: {err}");
        assert_eq!(
            snapshot_dir(&existing),
            before,
            "{extra:?} changed the data dir"
        );
        assert!(!existing.join("macaroon_root.key").exists());
        assert!(!existing.join("node_identity.seed").exists());
    }
    gate_ran("config_dump::dump_paths_have_no_side_effects");
}

/// The running daemon serves `config_digest` = SHA-256 of `--dump-config` of the same command.
#[test]
fn daemon_digest_matches_dump() {
    use sha2::Digest;
    let t = temp("digest");
    let dir = t.path().join("d");
    std::fs::create_dir_all(&dir).unwrap();
    let root_key = [0x28u8; 32];
    std::fs::write(dir.join("macaroon_root.key"), hex::encode(root_key)).unwrap();
    let args = [
        "--no-lan-discovery",
        "daemon",
        "start",
        "--listen",
        common::LOOPBACK_EPHEMERAL,
        "--status-http",
        "127.0.0.1:0",
        "--no-socket",
    ];
    let mut dump_args: Vec<&str> = args.to_vec();
    dump_args.push("--dump-config");
    // The daemon needs a ring; the dump sees the same environment (the secret shows as set).
    let genesis = hex::encode([0x47u8; 32]);
    let mut cmd = parvault();
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", t.path().join("reg"))
        .env("PARVAULT_GENESIS_SEED_HEX", &genesis);
    cmd.arg("--data-dir").arg(&dir).args(&dump_args);
    let (code, dumped, err) = run(&mut cmd);
    assert_eq!(code, 0, "{err}");
    let want = hex::encode(sha2::Sha256::digest(dumped.as_bytes()));

    let log = t.path().join("daemon.log");
    let mut cmd = parvault();
    cmd.env("PARVAULT_LAN_REGISTRY_DIR", t.path().join("reg"))
        .env("PARVAULT_GENESIS_SEED_HEX", &genesis)
        .env("RUST_LOG", "info")
        .arg("--data-dir")
        .arg(&dir)
        .args(args);
    let f = std::fs::File::create(&log).unwrap();
    let mut child = cmd
        .stdout(Stdio::from(f.try_clone().unwrap()))
        .stderr(Stdio::from(f))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let addr: std::net::SocketAddr = loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(rest) = text.split("Status Server listening on http://").nth(1) {
            break rest.split_whitespace().next().unwrap().parse().unwrap();
        }
        assert!(Instant::now() < deadline, "no status listener:\n{text}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let token = parvault::capabilities::CapabilityMacaroon::mint(
        &root_key,
        [5; 32],
        [6; 32],
        vec![parvault::capabilities::Caveat::ReadOnly],
    )
    .unwrap()
    .to_compact_token();
    let body = loop {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "GET /api/v1/health HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\r\n"
        )
        .unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        if text.starts_with("HTTP/1.1 200") {
            break text;
        }
        assert!(Instant::now() < deadline, "{text}");
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = child.kill();
    let _ = child.wait();
    let json_body = &body[body.find("\r\n\r\n").unwrap() + 4..];
    let health = json(json_body);
    assert_eq!(
        health["config_digest"],
        want,
        "log:\n{}",
        std::fs::read_to_string(&log).unwrap()
    );
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains(&format!("config_digest={want}")), "{text}");
    gate_ran("config_dump::daemon_digest_matches_dump");
}

/// A config that does not resolve: one JSON line with the reason code on stdout, exit 3.
#[test]
fn dump_unresolvable_config_exits_3() {
    let t = temp("bad");
    let cfg = t.path().join("cfg.toml");
    std::fs::write(&cfg, "[lab]\ndeterministic = true\n").unwrap();
    let mut cmd = parvault();
    cmd.arg("--data-dir")
        .arg(t.path().join("d"))
        .arg("--config")
        .arg(&cfg)
        .args(["config", "dump"]);
    let (code, out, _) = run(&mut cmd);
    assert_eq!(code, 3);
    assert_eq!(out.lines().count(), 1);
    let doc = json(&out);
    assert_eq!(doc["error"], "reject.lab_relays_missing");
    assert_eq!(doc["schema"], "parvault.config-dump/1");
    gate_ran("config_dump::dump_unresolvable_config_exits_3");
}
