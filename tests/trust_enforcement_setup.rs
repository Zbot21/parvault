//! `v0.5.6` track E suite: setup and ops (plan Sections 3.12 to 3.15). Claims of track E put
//! their differential pairs here; `tests/trust_enforcement.rs` is frozen.
//!
//! Every test runs the real `parvault` binary on scratch data dirs and ephemeral loopback ports,
//! and writes its sentinel (`gate_ran`) last, after its assertions.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

/// Kills its daemons on drop, so a failed assertion never leaks a process.
struct Daemons(Vec<Child>);

impl Daemons {
    fn stop_all(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.0.clear();
    }
}

impl Drop for Daemons {
    fn drop(&mut self) {
        self.stop_all();
    }
}

/// `parvault --data-dir <dir> --no-lan-discovery`, ring env cleared, LAN registry outside `dir`
/// (so the data dir holds only what the command writes).
fn pv(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parvault"));
    cmd.env_remove("PARVAULT_GENESIS_SEED_HEX")
        .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
        .env_remove("PARVAULT_PEERS")
        .env_remove("PARVAULT_JOIN_TOKEN")
        .env_remove("PARVAULT_PASSPHRASE")
        .env(
            "PARVAULT_LAN_REGISTRY_DIR",
            dir.with_extension("lan-registry"),
        )
        .arg("--data-dir")
        .arg(dir)
        .arg("--no-lan-discovery");
    cmd
}

fn run(dir: &Path, args: &[&str]) -> Output {
    common::output_within_deadline(pv(dir).args(args))
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn up_args<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    let mut a = vec!["up", "--no-socket", "--listen", common::LOOPBACK_EPHEMERAL];
    a.extend_from_slice(extra);
    a
}

/// Starts `up <extra>` and waits until it listens.
fn spawn_up(dir: &Path, extra: &[&str], log: &Path) -> Child {
    common::spawn_on_ephemeral_port(pv(dir).args(up_args(extra)), log).0
}

/// Runs `up <extra>`, which must refuse (exit on its own).
fn up_refused(dir: &Path, extra: &[&str]) -> Output {
    let out = run(dir, &up_args(extra));
    assert!(!out.status.success(), "up started: {}", text(&out));
    out
}

/// Every entry under `dir` but the lock file, with its bytes and mode.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
    use std::os::unix::fs::PermissionsExt;
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd {
            let p = e.unwrap().path();
            if p.file_name().is_some_and(|n| n == ".parvault.lock") {
                continue;
            }
            let meta = std::fs::symlink_metadata(&p).unwrap();
            let mode = meta.permissions().mode();
            if meta.is_dir() {
                stack.push(p.clone());
                out.insert(p, (Vec::new(), mode));
            } else {
                let bytes = std::fs::read(&p).unwrap();
                out.insert(p, (bytes, mode));
            }
        }
    }
    out
}

/// The public key of the 32-byte genesis seed in `dir`, and the pinned key, as hex.
fn ring_of(dir: &Path) -> (Option<String>, Option<String>) {
    let seed = std::fs::read(dir.join("ring_genesis.seed")).ok().map(|s| {
        let seed: [u8; 32] = s.as_slice().try_into().expect("32-byte seed");
        hex::encode(parvault::crypto::NodeIdentity::from_seed(seed).public_key_bytes())
    });
    let pin = std::fs::read_to_string(dir.join("ring_genesis.pub"))
        .ok()
        .map(|t| t.trim().to_string());
    (seed, pin)
}

fn write_0600(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// This node's Ed25519 key (hex), from `parvault identity`.
fn node_key(dir: &Path) -> String {
    let out = run(dir, &["identity"]);
    assert!(out.status.success(), "{}", text(&out));
    text(&out)
        .lines()
        .find_map(|l| {
            l.split("Ed25519 Public Key (hex): ")
                .nth(1)
                .map(|k| k.trim().to_string())
        })
        .expect("key line")
}

// ---- B146-INIT ----------------------------------------------------------------------------

/// B146-INIT accept: an empty volume gets one ring at the first `up --init-if-absent`; a
/// restart is a no-op on the same ring. `lost+found` and `@eaDir` do not make it non-empty
/// (A-146-3), the genesis staging file a killed init leaves is swept (arch056c 2.4), and
/// neither the log nor `/proc/<pid>/environ` holds the seed (A-146-5).
#[test]
fn b146_empty_volume_inits_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vol");
    std::fs::create_dir_all(dir.join("lost+found")).unwrap();
    std::fs::create_dir_all(dir.join("@eaDir")).unwrap();
    let staged = dir.join(".tmp.ring_genesis.seed.00112233445566ff");
    write_0600(&staged, &[7u8; 32]);
    let log1 = tmp.path().join("1.log");
    let mut d = Daemons(vec![spawn_up(&dir, &["--init-if-absent"], &log1)]);
    let (seed, pin) = ring_of(&dir);
    assert!(seed.is_some() && seed == pin, "seed {seed:?} pin {pin:?}");
    assert!(!staged.exists(), "staging file not swept");
    let log = std::fs::read_to_string(&log1).unwrap();
    assert!(log.contains("Started a new ring"), "{log}");
    let seed_hex = hex::encode(std::fs::read(dir.join("ring_genesis.seed")).unwrap());
    let environ = std::fs::read(format!("/proc/{}/environ", d.0[0].id())).unwrap();
    assert!(!String::from_utf8_lossy(&environ).contains(&seed_hex));
    assert!(!log.contains(&seed_hex), "the log holds the seed");
    d.stop_all();
    let log2 = tmp.path().join("2.log");
    d.0.push(spawn_up(&dir, &["--init-if-absent"], &log2));
    assert_eq!(ring_of(&dir), (seed.clone(), seed));
    let log = std::fs::read_to_string(&log2).unwrap();
    assert!(!log.contains("Started a new ring"), "{log}");
    gate_ran("trust_enforcement_setup::b146_empty_volume_inits_once");
}

/// B146-INIT reject: a non-empty volume that holds no ring is refused and left as it was.
#[test]
fn b146_unknown_volume_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("photos.db"), b"not ours").unwrap();
    let before = snapshot(&dir);
    let out = up_refused(&dir, &["--init-if-absent"]);
    assert!(
        text(&out).contains("reject.init_volume_not_empty"),
        "{}",
        text(&out)
    );
    assert_eq!(snapshot(&dir), before);
    assert_eq!(ring_of(&dir), (None, None));
    gate_ran("trust_enforcement_setup::b146_unknown_volume_refused");
}

/// A-146-2 (arch056c 2.1): a seed without its pin is resumed from the on-disk seed; the
/// daemon then runs in that ring.
#[test]
fn b146_seed_without_pin_resumes() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    write_0600(&dir.join("ring_genesis.seed"), &[9u8; 32]);
    let want = hex::encode(parvault::crypto::NodeIdentity::from_seed([9u8; 32]).public_key_bytes());
    let _d = Daemons(vec![spawn_up(
        &dir,
        &["--init-if-absent"],
        &tmp.path().join("up.log"),
    )]);
    assert_eq!(ring_of(&dir), (Some(want.clone()), Some(want)));
    gate_ran("trust_enforcement_setup::b146_seed_without_pin_resumes");
}

/// A-146-2 (arch056c 2.2, 2.3): a pin without a seed or chain, and a seed and pin that
/// disagree, are refused (`reject.init_partial_state`), the directory byte-identical.
#[test]
fn b146_partial_states_refused_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let pin_only = tmp.path().join("pin");
    std::fs::create_dir_all(&pin_only).unwrap();
    std::fs::write(pin_only.join("ring_genesis.pub"), "ab".repeat(32)).unwrap();
    let disagree = tmp.path().join("disagree");
    std::fs::create_dir_all(&disagree).unwrap();
    write_0600(&disagree.join("ring_genesis.seed"), &[3u8; 32]);
    std::fs::write(disagree.join("ring_genesis.pub"), "cd".repeat(32)).unwrap();
    for dir in [&pin_only, &disagree] {
        let before = snapshot(dir);
        let out = up_refused(dir, &["--init-if-absent"]);
        assert!(
            text(&out).contains("reject.init_partial_state"),
            "{}",
            text(&out)
        );
        assert_eq!(snapshot(dir), before, "{}", dir.display());
    }
    gate_ran("trust_enforcement_setup::b146_partial_states_refused_unchanged");
}

/// A-146-2: SIGKILL at any point of a first init never leaves two keys. Each round kills a
/// `wot init` after a growing delay, then `up --init-if-absent` must start with the seed
/// matching the pin and no staging file left.
#[test]
fn b146_sigkill_mid_init_then_rerun_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    for round in 0..20u64 {
        let dir = tmp.path().join(format!("vol{round}"));
        let mut init = pv(&dir)
            .args(["wot", "init"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(round * 3));
        let _ = init.kill();
        let _ = init.wait();
        let (seed, pin) = ring_of(&dir);
        assert!(
            pin.is_none() || seed == pin,
            "round {round}: seed {seed:?} pin {pin:?}"
        );
        let _d = Daemons(vec![spawn_up(
            &dir,
            &["--init-if-absent"],
            &tmp.path().join(format!("{round}.log")),
        )]);
        let (seed, pin) = ring_of(&dir);
        assert!(seed.is_some() && seed == pin, "round {round}");
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "round {round}: {leftovers:?}");
    }
    gate_ran("trust_enforcement_setup::b146_sigkill_mid_init_then_rerun_succeeds");
}

// ---- B146-JOIN ----------------------------------------------------------------------------

/// A ring holder `a` (wot init) and a joining node `b` with its identity; returns b's token
/// file (from `wot invite --out`).
fn ring_and_invite(tmp: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let a = tmp.join("a");
    let b = tmp.join("b");
    let init = run(&a, &["wot", "init"]);
    assert!(init.status.success(), "{}", text(&init));
    let key = node_key(&b);
    let tok = tmp.join("b.token");
    let out = run(
        &a,
        &[
            "wot",
            "invite",
            "--peer",
            &key,
            "--out",
            tok.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    (a, b, tok)
}

/// B146-JOIN accept, A-146-5 and A-146-6: `wot invite --out` writes the token `0600` and prints
/// only the path; `up --init-if-absent --join-token-file` joins that ring (no init), a restart
/// is a no-op, and neither the log nor `/proc/<pid>/environ` holds the token.
#[test]
fn b146_join_token_file_joins_once() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let (a, b, tok) = ring_and_invite(tmp.path());
    let token = std::fs::read_to_string(&tok).unwrap();
    assert_eq!(
        std::fs::metadata(&tok).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let again = tmp.path().join("again.token");
    let printed = run(
        &a,
        &[
            "wot",
            "invite",
            "--peer",
            &node_key(&b),
            "--out",
            again.to_str().unwrap(),
        ],
    );
    let printed = text(&printed);
    assert!(!printed.contains(token.trim()), "token printed: {printed}");
    assert!(printed.contains("again.token"), "{printed}");
    let ring = ring_of(&a).1.unwrap();
    let t = tok.to_str().unwrap();
    let log = tmp.path().join("b1.log");
    let mut d = Daemons(vec![spawn_up(
        &b,
        &["--init-if-absent", "--join-token-file", t],
        &log,
    )]);
    assert_eq!(ring_of(&b), (None, Some(ring.clone())));
    let environ = std::fs::read(format!("/proc/{}/environ", d.0[0].id())).unwrap();
    assert!(!String::from_utf8_lossy(&environ).contains(token.trim()));
    assert!(!std::fs::read_to_string(&log)
        .unwrap()
        .contains(token.trim()));
    d.stop_all();
    d.0.push(spawn_up(
        &b,
        &["--init-if-absent", "--join-token-file", t],
        &tmp.path().join("b2.log"),
    ));
    assert_eq!(ring_of(&b), (None, Some(ring)));
    gate_ran("trust_enforcement_setup::b146_join_token_file_joins_once");
}

/// B146-JOIN reject (A-146-5): a join-token file that is not `0600` is refused, and nothing is
/// initialised although `--init-if-absent` is set (A-146-4).
#[test]
fn b146_join_token_mode_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let (_a, b, tok) = ring_and_invite(tmp.path());
    std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = up_refused(
        &b,
        &[
            "--init-if-absent",
            "--join-token-file",
            tok.to_str().unwrap(),
        ],
    );
    assert!(
        text(&out).contains("reject.join_token_mode"),
        "{}",
        text(&out)
    );
    assert_eq!(ring_of(&b), (None, None));
    gate_ran("trust_enforcement_setup::b146_join_token_mode_refused");
}

/// B146-JOIN reject: a consumed token is not replayed into a node that left its ring
/// (`reject.join_token_used`).
#[test]
fn b146_join_token_used_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (_a, b, tok) = ring_and_invite(tmp.path());
    let t = tok.to_str().unwrap();
    let d = Daemons(vec![spawn_up(
        &b,
        &["--join-token-file", t],
        &tmp.path().join("b.log"),
    )]);
    drop(d);
    std::fs::remove_dir_all(b.join("wot_chains")).unwrap();
    std::fs::remove_file(b.join("ring_genesis.pub")).unwrap();
    let out = up_refused(&b, &["--join-token-file", t]);
    assert!(
        text(&out).contains("reject.join_token_used"),
        "{}",
        text(&out)
    );
    assert_eq!(ring_of(&b), (None, None));
    gate_ran("trust_enforcement_setup::b146_join_token_used_refused");
}

/// A-146-4: a configured join token always wins: a join that fails never falls back to
/// `--init-if-absent` on an empty volume. B-155 item 1: a placeholder says what a token is.
#[test]
fn b146_failed_join_never_inits() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    let tok = tmp.path().join("placeholder.token");
    write_0600(&tok, b"PASTE_TOKEN_HERE\n");
    let out = up_refused(
        &dir,
        &[
            "--init-if-absent",
            "--join-token-file",
            tok.to_str().unwrap(),
        ],
    );
    assert!(
        text(&out).contains("not a token: paste the token from the ring holder's invite log"),
        "{}",
        text(&out)
    );
    assert_eq!(ring_of(&dir), (None, None));
    let chain = run(
        &dir,
        &["wot", "install-chain", "--token", "PASTE_TOKEN_HERE"],
    );
    assert!(!chain.status.success());
    assert!(text(&chain).contains("not a token"), "{}", text(&chain));
    gate_ran("trust_enforcement_setup::b146_failed_join_never_inits");
}

/// A-146-5: `PARVAULT_JOIN_TOKEN` is never read; setting it is refused rather than ignored (an
/// ignored token next to `--init-if-absent` would start a new ring instead of joining).
#[test]
fn b146_env_join_token_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vol");
    let out = common::output_within_deadline(
        pv(&dir)
            .env("PARVAULT_JOIN_TOKEN", "00")
            .args(up_args(&["--init-if-absent"])),
    );
    assert!(!out.status.success());
    assert!(
        text(&out).contains("reject.join_token_env"),
        "{}",
        text(&out)
    );
    assert_eq!(ring_of(&dir), (None, None));
    gate_ran("trust_enforcement_setup::b146_env_join_token_refused");
}

// ---- B174-LOCK ----------------------------------------------------------------------------

/// B174-LOCK accept (A-146-1): 20 rounds of two concurrent `up --init-if-absent` on one empty
/// volume: one daemon runs, the other is refused (`reject.datadir_locked`), and the volume holds
/// exactly one ring whose seed matches its pin.
#[test]
fn b174_concurrent_init_one_ring() {
    let tmp = tempfile::tempdir().unwrap();
    for round in 0..20 {
        let dir = tmp.path().join(format!("vol{round}"));
        let logs = [0, 1].map(|i| tmp.path().join(format!("{round}-{i}.log")));
        let mut d = Daemons(
            logs.iter()
                .map(|log| {
                    let f = std::fs::File::create(log).unwrap();
                    pv(&dir)
                        .args(up_args(&["--init-if-absent"]))
                        .env("RUST_LOG", "info")
                        .env("NO_COLOR", "1")
                        .stdout(f.try_clone().unwrap())
                        .stderr(f)
                        .spawn()
                        .unwrap()
                })
                .collect(),
        );
        // Exactly one exits, refused; the other keeps running and listens.
        let deadline = Instant::now() + Duration::from_secs(30);
        let exited = loop {
            let done: Vec<usize> = (0..2)
                .filter(|&i| d.0[i].try_wait().unwrap().is_some())
                .collect();
            if !done.is_empty() {
                break done;
            }
            assert!(Instant::now() < deadline, "round {round}: neither exited");
            std::thread::sleep(Duration::from_millis(25));
        };
        assert_eq!(exited.len(), 1, "round {round}: both exited");
        let loser = exited[0];
        let winner = 1 - loser;
        let lost = std::fs::read_to_string(&logs[loser]).unwrap();
        assert!(
            lost.contains("reject.datadir_locked"),
            "round {round}: {lost}"
        );
        common::wait_for_listen_addr(
            &mut d.0[winner],
            || std::fs::read_to_string(&logs[winner]).unwrap_or_default(),
            Duration::from_secs(20),
        );
        let (seed, pin) = ring_of(&dir);
        assert!(seed.is_some() && seed == pin, "round {round}");
        assert!(d.0[winner].try_wait().unwrap().is_none());
    }
    gate_ran("trust_enforcement_setup::b174_concurrent_init_one_ring");
}

/// B174-LOCK reject: while a daemon runs, `wot init`, `wot install-chain` and a second `up` on
/// its data dir are refused (`reject.datadir_locked`) and change nothing.
#[test]
fn b174_second_holder_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vol");
    let _d = Daemons(vec![spawn_up(
        &dir,
        &["--init-if-absent"],
        &tmp.path().join("up.log"),
    )]);
    let before = ring_of(&dir);
    let chains = snapshot(&dir.join("wot_chains"));
    for args in [
        vec!["wot", "init"],
        vec!["wot", "install-chain", "--token", "00"],
        up_args(&[]),
    ] {
        let out = run(&dir, &args);
        assert!(!out.status.success(), "{args:?}: {}", text(&out));
        assert!(
            text(&out).contains("reject.datadir_locked"),
            "{args:?}: {}",
            text(&out)
        );
    }
    // The running daemon writes its own state; the ring files are what a holder could break.
    assert_eq!(ring_of(&dir), before);
    assert_eq!(snapshot(&dir.join("wot_chains")), chains);
    gate_ran("trust_enforcement_setup::b174_second_holder_refused");
}

/// T0 stubs still open in track E until B-169 lands: `ring backup|restore`.
#[test]
fn track_e_ring_backup_stubs_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");
    let pass = tmp.path().join("pass");
    let p = pass.to_str().unwrap();
    for (args, entry) in [
        (
            vec!["ring", "backup", "--out", "b", "--passphrase-file", p],
            "ring backup",
        ),
        (
            vec!["ring", "restore", "--from", "b.bin", "--passphrase-file", p],
            "ring restore",
        ),
    ] {
        common::assert_not_built_yet(&common::parvault_in(&dir, &args), entry);
    }
    gate_ran("trust_enforcement_setup::track_e_ring_backup_stubs_refuse");
}
