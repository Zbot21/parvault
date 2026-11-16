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

/// B174-LOCK reject: while a daemon runs, `wot init`, `wot install-chain`, `ring backup` and a
/// second `up` on its data dir are refused (`reject.datadir_locked`) and change nothing.
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
    let pass = tmp.path().join("pass");
    write_0600(&pass, PASS.as_bytes());
    let out = tmp.path().join("out");
    let (p, o) = (pass.to_str().unwrap(), out.to_str().unwrap());
    for args in [
        vec!["wot", "init"],
        vec!["wot", "install-chain", "--token", "00"],
        vec!["ring", "backup", "--out", o, "--passphrase-file", p],
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

// ---- B169-RESTORE, B169-KEYFILE -----------------------------------------------------------

const PASS: &str = "correct horse battery staple, twice";

/// The content of the `vaults/*.vaultkey` a test node holds (archC1 condition 5: never backed up).
const VAULTKEY: [u8; 32] = [0x7e; 32];

/// The files a bundle carries (K7) that a test node has.
const CARRIED: &[&str] = &[
    "ring_genesis.seed",
    "ring_genesis.pub",
    "node_identity.seed",
    "node_pq_kem.bin",
    "owner_pq_keypair.bin",
    "config.toml",
];

/// A genesis node with a vault master key (`parvault init` then `wot init`), plus state a
/// bundle must leave out (K7).
fn genesis_node(dir: &Path) {
    let init = run(dir, &["init"]);
    assert!(init.status.success(), "{}", text(&init));
    let wot = run(dir, &["wot", "init"]);
    assert!(wot.status.success(), "{}", text(&wot));
    write_0600(&dir.join("macaroon_root.key"), &[0x5a; 32]);
    // archC1 condition 5 (L-133): per-vault derived keys never go in a bundle.
    std::fs::create_dir_all(dir.join("vaults")).unwrap();
    write_0600(&dir.join("vaults/photos.vaultkey"), &VAULTKEY);
    // Track C's version floor (L-133): not secret, and it does go in a bundle.
    std::fs::write(dir.join("vaults/photos.floor"), b"42").unwrap();
    std::fs::write(dir.join("quota_state.bin"), b"quota").unwrap();
    std::fs::write(dir.join("por_audit_state.json"), b"{}").unwrap();
    assert!(dir.join("master_key.sealed").exists());
}

fn pass_file(tmp: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = tmp.join(name);
    write_0600(&p, bytes);
    p
}

/// `ring backup` of `dir` into `out`; returns the bundle path.
fn backup(dir: &Path, out: &Path, pass: &Path) -> PathBuf {
    let o = run(
        dir,
        &[
            "ring",
            "backup",
            "--out",
            out.to_str().unwrap(),
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    let mut found: Vec<PathBuf> = std::fs::read_dir(out)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "pvbak"))
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
    let b = found.pop().unwrap();
    assert!(text(&o).contains(b.to_str().unwrap()), "{}", text(&o));
    b
}

fn restore_cmd(target: &Path, bundle: &Path, pass: &Path, extra: &[&str]) -> Command {
    let mut c = pv(target);
    c.args([
        "ring",
        "restore",
        "--from",
        bundle.to_str().unwrap(),
        "--passphrase-file",
        pass.to_str().unwrap(),
    ])
    .args(extra);
    c
}

fn restore(target: &Path, bundle: &Path, pass: &Path, extra: &[&str]) -> Output {
    common::output_within_deadline(&mut restore_cmd(target, bundle, pass, extra))
}

/// The vault master key in `dir`, unsealed with its keystore.
fn master_key(dir: &Path) -> [u8; 32] {
    use parvault::crypto::{LocalFileKeystore, LocalKeystoreSealer};
    assert!(dir.join("enclave_sealing.seed").exists());
    let ks = LocalFileKeystore::from_passphrase_or_csprng_in_dir(dir, None).unwrap();
    ks.unseal_key(&std::fs::read(dir.join("master_key.sealed")).unwrap())
        .unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// B169-RESTORE accept (K5, K7, K12): a genesis node and a joined node (pin and chain, no
/// genesis seed) are backed up and restored into empty data dirs: every carried file is
/// byte-identical, the master key unseals to the same key, the left-out files are absent, the
/// bundle holds no secret seed or the master key in clear, and the restored node starts. The
/// passphrase file is written with CRLF and read back with a BOM and no newline (K8).
#[test]
fn b169_backup_restores_byte_identical_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    genesis_node(&a);
    let key = node_key(&tmp.path().join("b"));
    let tok = tmp.path().join("b.tok");
    let inv = run(
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
    assert!(inv.status.success(), "{}", text(&inv));
    let b = tmp.path().join("b");
    let chain = run(
        &b,
        &[
            "wot",
            "install-chain",
            "--token",
            std::fs::read_to_string(&tok).unwrap().trim(),
        ],
    );
    assert!(chain.status.success(), "{}", text(&chain));
    let crlf = pass_file(tmp.path(), "crlf", format!("{PASS}\r\n").as_bytes());
    let mut bom_bytes = vec![0xEF, 0xBB, 0xBF];
    bom_bytes.extend_from_slice(PASS.as_bytes());
    let bom = pass_file(tmp.path(), "bom", &bom_bytes);
    for (src, name) in [(&a, "a"), (&b, "b")] {
        let bundle = backup(src, &tmp.path().join(format!("out-{name}")), &crlf);
        let raw = std::fs::read(&bundle).unwrap();
        let mut secrets: Vec<Vec<u8>> = ["ring_genesis.seed", "node_identity.seed"]
            .iter()
            .filter_map(|f| std::fs::read(src.join(f)).ok())
            .collect();
        if src.join("master_key.sealed").exists() {
            secrets.push(master_key(src).to_vec());
        }
        if src.join("vaults").exists() {
            secrets.push(VAULTKEY.to_vec());
        }
        for s in &secrets {
            assert!(!contains(&raw, s), "{name}: a secret in clear");
            assert!(
                !contains(&raw, hex::encode(s).as_bytes()),
                "{name}: hex secret"
            );
        }
        let target = tmp.path().join(format!("restored-{name}"));
        let out = restore(&target, &bundle, &bom, &["--confirm-move"]);
        assert!(out.status.success(), "{name}: {}", text(&out));
        for f in CARRIED {
            assert_eq!(
                std::fs::read(src.join(f)).ok(),
                std::fs::read(target.join(f)).ok(),
                "{name}: {f}"
            );
        }
        let bytes = |d: &Path| -> Vec<Vec<u8>> {
            snapshot(&d.join("wot_chains"))
                .into_values()
                .map(|(b, _)| b)
                .collect()
        };
        assert_eq!(bytes(src), bytes(&target), "{name}: chains");
        if src.join("master_key.sealed").exists() {
            assert_eq!(master_key(src), master_key(&target), "{name}: master key");
        }
        for f in [
            "macaroon_root.key",
            "quota_state.bin",
            "por_audit_state.json",
            "vaults/photos.vaultkey",
        ] {
            assert!(!target.join(f).exists(), "{name}: {f} restored");
        }
        if src.join("vaults").exists() {
            assert_eq!(
                std::fs::read(target.join("vaults/photos.floor")).unwrap(),
                b"42",
                "{name}: version floor"
            );
        }
        assert!(!target.join("macaroon_root.key").exists(), "{name}");
        assert!(!target.join(".ring_restore.pending").exists());
        assert!(!target.join(".ring_restore.stage").exists());
    }
    let _d = Daemons(vec![spawn_up(
        &tmp.path().join("restored-a"),
        &["--init-if-absent"],
        &tmp.path().join("up.log"),
    )]);
    assert_eq!(ring_of(&tmp.path().join("restored-a")), ring_of(&a));
    gate_ran("trust_enforcement_setup::b169_backup_restores_byte_identical_identity");
}

/// archC1 condition 5 and L-133: a bundle never carries `vaults/*.vaultkey`, not even
/// encrypted, and does carry track C's version floor `vaults/*.floor`: the decrypted body of a
/// real bundle has exactly the floor under `vaults/` and no vaultkey bytes.
#[test]
fn b169_vaultkeys_are_not_in_the_bundle() {
    use parvault::crypto::backup_envelope::{derive_key, open, parse_bundle, BackupBody};
    let tmp = tempfile::tempdir().unwrap();
    let (_a, bundle, _pass) = bundle_fixture(tmp.path());
    let raw = std::fs::read(&bundle).unwrap();
    let (h, ct) = parse_bundle(&raw).unwrap();
    let key = derive_key(PASS, &h.salt, h.kdf).unwrap();
    let plain = open(&key, &h, ct).unwrap();
    let body = BackupBody::decode(&plain).unwrap();
    let vaults: Vec<&str> = body
        .entries
        .iter()
        .map(|(n, _)| n.as_str())
        .filter(|n| n.starts_with("vaults"))
        .collect();
    assert_eq!(vaults, ["vaults/photos.floor"], "{body:?}");
    assert_eq!(body.get("vaults/photos.floor"), Some(&b"42"[..]));
    assert!(!contains(&plain, &VAULTKEY));
    gate_ran("trust_enforcement_setup::b169_vaultkeys_are_not_in_the_bundle");
}

// --- G-23: a vault resumes from the ring's catalog (B-169 K11) ---------------------------------

/// The vault phrase and namespace of the G-23 tests.
const K11_PHRASE: &str = "k11 restored owner vault phrase";
const K11_NS: &str = "k11";

/// A storage host in the ring whose genesis seed is `seed` (hex), on a loopback port; killed
/// on drop. Returns (daemons, data dir, `addr/p2p/id`).
fn k11_host(tmp: &Path, name: &str, seed_hex: &str) -> (Daemons, PathBuf, String) {
    let dir = tmp.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let id = parvault::crypto::NodeIdentity::load_or_generate_in_dir(&dir).unwrap();
    let pid = parvault::network::node_identity_libp2p_peer_id(&id).unwrap();
    let mut cmd = pv(&dir);
    cmd.env("PARVAULT_GENESIS_SEED_HEX", seed_hex).args([
        "daemon",
        "start",
        "--no-socket",
        "--listen",
        common::LOOPBACK_EPHEMERAL,
    ]);
    let (child, addr) = common::spawn_on_ephemeral_port(&mut cmd, &tmp.join(format!("{name}.log")));
    (Daemons(vec![child]), dir, format!("{addr}/p2p/{pid}"))
}

/// One `watch-folder --once` pass of `folder` from node `dir` against `peers`, with the vault
/// phrase; `extra_env` adds variables. Waits up to 120 s.
fn k11_pass(
    dir: &Path,
    folder: &Path,
    snap: &Path,
    peers: &str,
    extra_env: &[(&str, &str)],
) -> Output {
    let mut cmd = pv(dir);
    cmd.env("PARVAULT_SEED_PHRASE", K11_PHRASE)
        .env("RUST_LOG", "info")
        .envs(extra_env.iter().copied())
        .args(["--peers", peers, "watch-folder", "--folder"])
        .arg(folder)
        .arg("--snapshot-out")
        .arg(snap)
        .args(["--vault-namespace", K11_NS, "--once"]);
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn k11_pass_ok(dir: &Path, folder: &Path, snap: &Path, peers: &str) -> String {
    let out = k11_pass(dir, folder, snap, peers, &[]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    t
}

/// The vault catalog version the host holds on disk (its envelope store file).
fn k11_host_catalog_version(host_dir: &Path) -> Option<u64> {
    let mk = parvault::crypto::MasterKey::from_recovery_seed_phrase(K11_PHRASE, K11_NS);
    let key = mk.derive_vault_root_dht_key(K11_NS);
    parvault::storage::ZeroTrustDhtStore::with_persistence_dir(host_dir)
        .get_vault_catalog_envelope(&key)
        .map(|e| e.monotonic_version)
}

fn k11_shards(host_dir: &Path) -> std::collections::BTreeSet<String> {
    std::fs::read_dir(host_dir.join("shards"))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// A ring owner A (`init`, `wot init`) with one host in its ring and a vault backed up twice
/// (catalog version 2 on the host). Returns (tmp-relative paths, host, A's genesis seed hex).
struct K11Ring {
    a: PathBuf,
    folder: PathBuf,
    snap_a: PathBuf,
    host: Daemons,
    host_dir: PathBuf,
    host_addr: String,
    seed_hex: String,
}

fn k11_ring(tmp: &Path) -> K11Ring {
    let a = tmp.join("a");
    assert!(run(&a, &["init"]).status.success());
    assert!(run(&a, &["wot", "init"]).status.success());
    let seed_hex = hex::encode(std::fs::read(a.join("ring_genesis.seed")).unwrap());
    let (host, host_dir, host_addr) = k11_host(tmp, "host", &seed_hex);
    let folder = tmp.join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    let snap_a = tmp.join("a.snap");
    std::fs::write(folder.join("f.txt"), "v1").unwrap();
    let t = k11_pass_ok(&a, &folder, &snap_a, &host_addr);
    assert!(t.contains("Snapshot Version   : 1"), "{t}");
    std::fs::write(folder.join("f.txt"), "v2").unwrap();
    let t = k11_pass_ok(&a, &folder, &snap_a, &host_addr);
    assert!(t.contains("Snapshot Version   : 2"), "{t}");
    assert_eq!(k11_host_catalog_version(&host_dir), Some(2));
    K11Ring {
        a,
        folder,
        snap_a,
        host,
        host_dir,
        host_addr,
        seed_hex,
    }
}

/// K11 (G-23, claim CATALOG-RESUME accept): the owner is moved with `ring backup` and
/// `ring restore --confirm-move` (no folder snapshot travels in the bundle). The restored node's
/// first pass resumes from the ring's catalog (version 2), publishes version 3 and frees nothing
/// on the host. The old node, still running (a clone, not a move), then hits C7: its next pass
/// sees the restored node's catalog, frees nothing and says so.
#[test]
fn b169_restored_owner_publishes_above_and_frees_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = k11_ring(tmp.path());
    let pass = pass_file(tmp.path(), "pass.txt", format!("{PASS}\n").as_bytes());
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let bundle = backup(&r.a, &out, &pass);
    let b = tmp.path().join("b");
    let o = restore(&b, &bundle, &pass, &["--confirm-move"]);
    assert!(o.status.success(), "{}", text(&o));
    let held = k11_shards(&r.host_dir);
    std::fs::write(r.folder.join("f.txt"), "v3 from the restored node").unwrap();
    let t = k11_pass_ok(&b, &r.folder, &tmp.path().join("b.snap"), &r.host_addr);
    assert!(
        t.contains("resumed vault 'k11' from the ring's catalog version 2"),
        "{t}"
    );
    assert!(t.contains("Snapshot Version   : 3"), "{t}");
    assert_eq!(k11_host_catalog_version(&r.host_dir), Some(3), "{t}");
    let after = k11_shards(&r.host_dir);
    assert!(
        held.is_subset(&after),
        "the restored node's pass freed shards\n{t}"
    );
    // C7: the old node is still there and runs a changed pass.
    std::fs::write(r.folder.join("f.txt"), "v3 from the old node").unwrap();
    let t = k11_pass_ok(&r.a, &r.folder, &r.snap_a, &r.host_addr);
    assert!(t.contains("reject.gc_foreign_catalog"), "{t}");
    assert!(
        held.is_subset(&k11_shards(&r.host_dir)),
        "the old node freed shards\n{t}"
    );
    assert_eq!(k11_host_catalog_version(&r.host_dir), Some(3), "{t}");
    r.host.stop_all();
    gate_ran("trust_enforcement_setup::b169_restored_owner_publishes_above_and_frees_nothing");
}

/// G-23: a fresh node given only the seed phrase (no backup, no snapshot) resumes the vault the
/// same way: its first pass over the same folder resumes version 2 and finds no change
/// (nothing published), and a changed file then publishes version 3 above the ring's 2.
#[test]
fn g23_fresh_node_from_phrase_resumes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = k11_ring(tmp.path());
    let c = tmp.path().join("c");
    assert!(run(&c, &["init"]).status.success());
    let t = text(&{
        let out = k11_pass(
            &c,
            &r.folder,
            &tmp.path().join("c.snap"),
            &r.host_addr,
            &[("PARVAULT_GENESIS_SEED_HEX", &r.seed_hex)],
        );
        assert!(out.status.success(), "{}", text(&out));
        out
    });
    assert!(
        t.contains("resumed vault 'k11' from the ring's catalog version 2"),
        "{t}"
    );
    assert!(t.contains("Snapshot Version   : 2 (no change)"), "{t}");
    assert_eq!(k11_host_catalog_version(&r.host_dir), Some(2), "{t}");
    std::fs::write(r.folder.join("f.txt"), "v3 from a fresh node").unwrap();
    let out = k11_pass(
        &c,
        &r.folder,
        &tmp.path().join("c.snap"),
        &r.host_addr,
        &[("PARVAULT_GENESIS_SEED_HEX", &r.seed_hex)],
    );
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(
        !t.contains("resumed vault"),
        "resumed again from a local snapshot\n{t}"
    );
    assert!(t.contains("Snapshot Version   : 3"), "{t}");
    assert_eq!(k11_host_catalog_version(&r.host_dir), Some(3), "{t}");
    r.host.stop_all();
    gate_ran("trust_enforcement_setup::g23_fresh_node_from_phrase_resumes");
}

/// G-23 (claim CATALOG-RESUME reject): with no snapshot and no ring host answering, the pass
/// refuses (`reject.catalog_resume_unreachable`) and publishes nothing (no snapshot written),
/// rather than start the vault again at version 1.
#[test]
fn g23_unreachable_ring_refuses_to_publish() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path().join("d");
    assert!(run(&d, &["init"]).status.success());
    let folder = tmp.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("f.txt"), "x").unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let snap = tmp.path().join("d.snap");
    let out = k11_pass(
        &d,
        &folder,
        &snap,
        &format!("/ip4/127.0.0.1/tcp/{port}"),
        &[],
    );
    let t = text(&out);
    assert!(!out.status.success(), "{t}");
    assert!(t.contains("reject.catalog_resume_unreachable"), "{t}");
    assert!(!snap.exists(), "a snapshot was written\n{t}");
    gate_ran("trust_enforcement_setup::g23_unreachable_ring_refuses_to_publish");
}

/// G-23: a catalog at this vault's key that another owner signed is never adopted: the fresh
/// node logs `warn.catalog_resume_foreign` and starts at version 1.
#[test]
fn g23_foreign_catalog_not_adopted() {
    use parvault::crypto::{MasterKey, NodeIdentity, PqVaultMasterKey};
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    assert!(run(&a, &["init"]).status.success());
    assert!(run(&a, &["wot", "init"]).status.success());
    let seed_hex = hex::encode(std::fs::read(a.join("ring_genesis.seed")).unwrap());
    // A squatter seals a catalog under this vault's keys but signs it with its own identity,
    // and it is already in the host's envelope store.
    let host_dir = tmp.path().join("host");
    {
        let scratch = tmp.path().join("scratch");
        let folder = tmp.path().join("sq");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("x.txt"), "squat").unwrap();
        let mk = MasterKey::from_recovery_seed_phrase(K11_PHRASE, K11_NS);
        let pq = PqVaultMasterKey::from_recovery_seed_phrase(K11_PHRASE, K11_NS);
        let squatter = NodeIdentity::generate();
        let mut engine = parvault::sync::FolderSyncEngine::new(
            parvault::storage::BlockStore::new(
                &scratch,
                parvault::storage::QuotaManager::new(1 << 30, 1 << 28),
            )
            .unwrap(),
            mk.clone(),
            squatter.clone(),
            parvault::config::ErasureTier::Homelab,
        );
        let mut snap = engine.sync_folder_once(&folder).unwrap();
        snap.version = 9;
        let env =
            parvault::sync::EncryptedVaultCatalogEnvelope::seal(&mk, &pq, &squatter, K11_NS, &snap)
                .unwrap();
        assert!(env.verify_zero_knowledge());
        parvault::storage::ZeroTrustDhtStore::with_persistence_dir(&host_dir)
            .put_vault_catalog_envelope(env)
            .unwrap();
    }
    let (mut host, _, host_addr) = k11_host(tmp.path(), "host", &seed_hex);
    let folder = tmp.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("f.txt"), "mine").unwrap();
    let out = k11_pass(&a, &folder, &tmp.path().join("a.snap"), &host_addr, &[]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("warn.catalog_resume_foreign"), "{t}");
    assert!(!t.contains("resumed vault"), "{t}");
    assert!(t.contains("Snapshot Version   : 1"), "{t}");
    host.stop_all();
    gate_ran("trust_enforcement_setup::g23_foreign_catalog_not_adopted");
}

/// C37: `up --interval-secs` below the floor is refused, and (glue G-22) before any side
/// effect: `up --init-if-absent --interval-secs 1` on a fresh empty volume leaves it empty (no
/// ring, no identity, no lock).
#[test]
fn c37_up_interval_below_floor_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let out = up_refused(&tmp.path().join("vol"), &["--interval-secs", "1"]);
    assert!(
        text(&out).contains("reject.interval_below_floor"),
        "{}",
        text(&out)
    );
    let vol = tmp.path().join("fresh");
    std::fs::create_dir(&vol).unwrap();
    let out = up_refused(&vol, &["--init-if-absent", "--interval-secs", "1"]);
    assert!(
        text(&out).contains("reject.interval_below_floor"),
        "{}",
        text(&out)
    );
    let left: Vec<_> = std::fs::read_dir(&vol)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "the volume was written: {left:?}");
    gate_ran("trust_enforcement_setup::c37_up_interval_below_floor_refused");
}

/// A genesis node, its bundle and the passphrase file.
fn bundle_fixture(tmp: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let a = tmp.join("a");
    genesis_node(&a);
    let pass = pass_file(tmp, "pass", PASS.as_bytes());
    let bundle = backup(&a, &tmp.join("out"), &pass);
    (a, bundle, pass)
}

/// An empty target with an ignored entry, its snapshot, and the refusal text of a restore.
fn refused_restore(tmp: &Path, name: &str, bundle: &Path, pass: &Path, extra: &[&str]) -> String {
    let target = tmp.join(name);
    std::fs::create_dir_all(target.join("lost+found")).unwrap();
    let before = snapshot(&target);
    let out = common::output_within_deadline(&mut restore_cmd(&target, bundle, pass, extra));
    assert!(!out.status.success(), "{name}: restored: {}", text(&out));
    assert_eq!(snapshot(&target), before, "{name}: target changed");
    text(&out)
}

/// B169-RESTORE reject (each leaves the target byte-identical): a wrong passphrase, a flipped
/// header byte (ids, salt, nonce: all AAD) and a flipped ciphertext byte are
/// `reject.backup_auth_failed`.
#[test]
fn b169_wrong_passphrase_or_tamper_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (_a, bundle, pass) = bundle_fixture(tmp.path());
    let wrong = pass_file(tmp.path(), "wrong", b"incorrect horse battery staple");
    let t = refused_restore(tmp.path(), "t0", &bundle, &wrong, &["--confirm-move"]);
    assert!(t.contains("reject.backup_auth_failed"), "{t}");
    let raw = std::fs::read(&bundle).unwrap();
    for (i, at) in [30usize, 50, 70, 110, raw.len() - 1]
        .into_iter()
        .enumerate()
    {
        let mut b = raw.clone();
        b[at] ^= 0x01;
        let f = tmp.path().join(format!("flip{i}.pvbak"));
        std::fs::write(&f, &b).unwrap();
        let t = refused_restore(
            tmp.path(),
            &format!("t{}", i + 1),
            &f,
            &pass,
            &["--confirm-move"],
        );
        assert!(t.contains("reject.backup_auth_failed"), "byte {at}: {t}");
    }
    gate_ran("trust_enforcement_setup::b169_wrong_passphrase_or_tamper_refused");
}

/// B169-RESTORE reject (K6): `--expect-ring` of another ring is `reject.backup_wrong_ring`.
#[test]
fn b169_foreign_ring() {
    let tmp = tempfile::tempdir().unwrap();
    let (_a, bundle, pass) = bundle_fixture(tmp.path());
    let other = "ab".repeat(32);
    let t = refused_restore(
        tmp.path(),
        "t",
        &bundle,
        &pass,
        &["--expect-ring", &other, "--confirm-move"],
    );
    assert!(t.contains("reject.backup_wrong_ring"), "{t}");
    gate_ran("trust_enforcement_setup::b169_foreign_ring");
}

/// B169-RESTORE reject: a target that is not empty (a node already there) is
/// `reject.backup_target_not_empty`, unchanged.
#[test]
fn b169_target_not_empty_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, bundle, pass) = bundle_fixture(tmp.path());
    let before = snapshot(&a);
    let out = restore(&a, &bundle, &pass, &["--confirm-move"]);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("reject.backup_target_not_empty"),
        "{}",
        text(&out)
    );
    assert_eq!(snapshot(&a), before);
    gate_ran("trust_enforcement_setup::b169_target_not_empty_refused");
}

/// B169-RESTORE reject (K2): a bundle claiming 4 GiB of Argon2 memory is
/// `reject.backup_kdf_params` with no allocation: it runs under a 3 GiB address-space limit
/// that a real restore (the control) fits in.
#[test]
fn b169_kdf_params_refused_before_allocating() {
    let tmp = tempfile::tempdir().unwrap();
    let (_a, bundle, pass) = bundle_fixture(tmp.path());
    let mut raw = std::fs::read(&bundle).unwrap();
    raw[11..15].copy_from_slice(&(4u32 * 1024 * 1024).to_le_bytes());
    let huge = tmp.path().join("huge.pvbak");
    std::fs::write(&huge, &raw).unwrap();
    let limited = |target: &Path, b: &Path| {
        let c = restore_cmd(target, b, &pass, &["--confirm-move"]);
        let prog = c.get_program().to_owned();
        let args: Vec<_> = c.get_args().map(|a| a.to_owned()).collect();
        let mut sh = Command::new("sh");
        sh.arg("-c")
            .arg("ulimit -v 3145728; exec \"$0\" \"$@\"")
            .arg(prog)
            .args(args)
            .env("MALLOC_ARENA_MAX", "2")
            .env_remove("PARVAULT_GENESIS_PUBKEY_HEX")
            .env_remove("PARVAULT_PASSPHRASE");
        common::output_within_deadline(&mut sh)
    };
    let target = tmp.path().join("t");
    std::fs::create_dir_all(&target).unwrap();
    let out = limited(&target, &huge);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("reject.backup_kdf_params"),
        "{}",
        text(&out)
    );
    assert_eq!(snapshot(&target), BTreeMap::new());
    let control = limited(&tmp.path().join("control"), &bundle);
    assert!(control.status.success(), "control: {}", text(&control));
    gate_ran("trust_enforcement_setup::b169_kdf_params_refused_before_allocating");
}

/// B169-RESTORE reject (K5): a correctly encrypted bundle whose header node id is not the
/// body's node key is `reject.backup_inconsistent`.
#[test]
fn b169_inconsistent_ids_refused() {
    use parvault::crypto::backup_envelope::{seal, BackupBody, KdfParams};
    use zeroize::Zeroizing;
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    genesis_node(&a);
    let mut body = BackupBody::default();
    for f in [
        "ring_genesis.seed",
        "ring_genesis.pub",
        "node_identity.seed",
    ] {
        body.entries.push((
            f.to_string(),
            Zeroizing::new(std::fs::read(a.join(f)).unwrap()),
        ));
    }
    let ring: [u8; 32] = hex::decode(ring_of(&a).1.unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let forged = seal(
        PASS,
        KdfParams::ROUTER_SOC,
        ring,
        [0x55; 32],
        &body.encode().unwrap(),
    )
    .unwrap();
    let f = tmp.path().join("forged.pvbak");
    std::fs::write(&f, forged).unwrap();
    let pass = pass_file(tmp.path(), "pass", PASS.as_bytes());
    let t = refused_restore(tmp.path(), "t", &f, &pass, &["--confirm-move"]);
    assert!(t.contains("reject.backup_inconsistent"), "{t}");
    gate_ran("trust_enforcement_setup::b169_inconsistent_ids_refused");
}

/// B169-RESTORE reject (K4): trailing bytes, an unknown version and a truncated bundle are
/// `reject.backup_format`.
#[test]
fn b169_format_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (_a, bundle, pass) = bundle_fixture(tmp.path());
    let raw = std::fs::read(&bundle).unwrap();
    let mut trailing = raw.clone();
    trailing.push(0);
    let mut v2 = raw.clone();
    v2[8] = 2;
    let short = raw[..raw.len() - 1].to_vec();
    for (i, b) in [trailing, v2, short].into_iter().enumerate() {
        let f = tmp.path().join(format!("f{i}.pvbak"));
        std::fs::write(&f, b).unwrap();
        let t = refused_restore(tmp.path(), &format!("t{i}"), &f, &pass, &["--confirm-move"]);
        assert!(t.contains("reject.backup_format"), "{i}: {t}");
    }
    gate_ran("trust_enforcement_setup::b169_format_refused");
}

/// B169-RESTORE reject (K11): without `--confirm-move` the restore is refused, names the ring
/// and node, and says the old node must be retired.
#[test]
fn b169_move_not_confirmed_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, bundle, pass) = bundle_fixture(tmp.path());
    let t = refused_restore(tmp.path(), "t", &bundle, &pass, &[]);
    assert!(t.contains("reject.backup_move_not_confirmed"), "{t}");
    assert!(t.contains(&ring_of(&a).1.unwrap()), "{t}");
    assert!(t.contains("retired"), "{t}");
    gate_ran("trust_enforcement_setup::b169_move_not_confirmed_refused");
}

/// B169-KEYFILE accept: a `0600` passphrase file of 20 characters outside `--out` backs up.
#[test]
fn b169_passphrase_file_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    genesis_node(&a);
    let pass = pass_file(tmp.path(), "pass", "x".repeat(20).as_bytes());
    backup(&a, &tmp.path().join("out"), &pass);
    gate_ran("trust_enforcement_setup::b169_passphrase_file_accepted");
}

/// B169-KEYFILE reject (K8): a passphrase file that is group-readable is
/// `reject.backup_passphrase_mode`; one inside `--out` is `reject.backup_passphrase_in_out`;
/// 19 characters, or bytes that are not UTF-8, are `reject.backup_passphrase_weak`. No bundle
/// is written.
#[test]
fn b169_passphrase_mode_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    genesis_node(&a);
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let loose = pass_file(tmp.path(), "loose", PASS.as_bytes());
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o640)).unwrap();
    let inside = pass_file(&out, "inside", PASS.as_bytes());
    let short = pass_file(tmp.path(), "short", "x".repeat(19).as_bytes());
    let latin1 = pass_file(tmp.path(), "latin1", &[0xe9; 24]);
    for (f, code) in [
        (&loose, "reject.backup_passphrase_mode"),
        (&inside, "reject.backup_passphrase_in_out"),
        (&short, "reject.backup_passphrase_weak"),
        (&latin1, "reject.backup_passphrase_weak"),
    ] {
        let o = run(
            &a,
            &[
                "ring",
                "backup",
                "--out",
                out.to_str().unwrap(),
                "--passphrase-file",
                f.to_str().unwrap(),
            ],
        );
        assert!(!o.status.success());
        assert!(text(&o).contains(code), "{code}: {}", text(&o));
    }
    let bundles = std::fs::read_dir(&out)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "pvbak")
        })
        .count();
    assert_eq!(bundles, 0);
    gate_ran("trust_enforcement_setup::b169_passphrase_mode_refused");
}

/// K9: SIGKILL at any point of a restore, then a rerun succeeds with the same identity. Each
/// round kills the restore after a growing delay (across the KDF and the file moves); one more
/// case starts from a crash after half the files were moved.
#[test]
fn b169_restore_sigkill_then_rerun_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, bundle, pass) = bundle_fixture(tmp.path());
    let want = ring_of(&a);
    let node = std::fs::read(a.join("node_identity.seed")).unwrap();
    let check = |target: &Path, label: &str| {
        let out = restore(target, &bundle, &pass, &["--confirm-move"]);
        assert!(out.status.success(), "{label}: {}", text(&out));
        assert_eq!(ring_of(target), want, "{label}");
        assert_eq!(
            std::fs::read(target.join("node_identity.seed")).unwrap(),
            node,
            "{label}"
        );
        assert_eq!(master_key(target), master_key(&a), "{label}");
    };
    let (mut finished, mut cut) = (0, 0);
    for round in 0..24u64 {
        let target = tmp.path().join(format!("k{round}"));
        let mut child = restore_cmd(&target, &bundle, &pass, &["--confirm-move"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(round * 8));
        let _ = child.kill();
        let status = child.wait().unwrap();
        let label = format!("round {round}");
        // Complete: the list is written before the first rename and removed last, so no list
        // and no stage with the node seed in place means every file was moved (the kill may land
        // after that, before the process exits).
        let complete = !target.join(".ring_restore.pending").exists()
            && !target.join(".ring_restore.stage").exists()
            && target.join("node_identity.seed").exists();
        if status.success() || complete {
            finished += 1;
            assert_eq!(ring_of(&target), want, "{label}");
            assert_eq!(
                std::fs::read(target.join("node_identity.seed")).unwrap(),
                node,
                "{label}"
            );
            assert_eq!(master_key(&target), master_key(&a), "{label}");
            assert!(!target.join(".ring_restore.pending").exists(), "{label}");
            assert!(!target.join(".ring_restore.stage").exists(), "{label}");
        } else {
            cut += 1;
            check(&target, &label);
        }
    }
    assert!(
        cut > 0,
        "no round was killed mid-restore ({finished} finished)"
    );
    // A crash after the list was written and half the files were moved.
    let target = tmp.path().join("half");
    check(&target, "first");
    let stage = target.join(".ring_restore.stage");
    std::fs::create_dir_all(&stage).unwrap();
    let moved = ["ring_genesis.pub", "node_pq_kem.bin"];
    std::fs::write(
        target.join(".ring_restore.pending"),
        CARRIED.join("\n") + "\nmaster_key.sealed\nenclave_sealing.seed\nvaults/photos.floor",
    )
    .unwrap();
    for f in CARRIED
        .iter()
        .filter(|f| !moved.contains(f) && target.join(f).exists())
    {
        std::fs::rename(target.join(f), stage.join(f)).unwrap();
    }
    check(&target, "after a crash mid-move");
    gate_ran("trust_enforcement_setup::b169_restore_sigkill_then_rerun_succeeds");
}

/// The v1 fixture (K4): `tests/fixtures/ring_backup_v1.pvbak`, written once by this release
/// (passphrase [`FIXTURE_PASS`], ring seed `11`*32, node seed `22`*32, master key `33`*32,
/// `router-soc` KDF). Every later release must decrypt and restore it.
const FIXTURE_PASS: &str = "parvault ring backup v1 fixture";

#[test]
fn b169_v1_fixture_restores() {
    use parvault::crypto::NodeIdentity;
    let tmp = tempfile::tempdir().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ring_backup_v1.pvbak");
    let pass = pass_file(tmp.path(), "pass", FIXTURE_PASS.as_bytes());
    let ring = hex::encode(NodeIdentity::from_seed([0x11; 32]).public_key_bytes());
    let target = tmp.path().join("t");
    let out = restore(
        &target,
        &fixture,
        &pass,
        &["--expect-ring", &ring, "--confirm-move"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(ring_of(&target), (Some(ring.clone()), Some(ring)));
    assert_eq!(
        std::fs::read(target.join("node_identity.seed")).unwrap(),
        vec![0x22; 32]
    );
    assert_eq!(master_key(&target), [0x33; 32]);
    gate_ran("trust_enforcement_setup::b169_v1_fixture_restores");
}

/// Writes the v1 fixture (run once, by hand: `--ignored`, with `PARVAULT_WRITE_FIXTURE=<path>`).
#[test]
#[ignore]
fn b169_write_v1_fixture() {
    use parvault::crypto::backup_envelope::{seal, BackupBody, KdfParams};
    use parvault::crypto::NodeIdentity;
    use zeroize::Zeroizing;
    let ring = NodeIdentity::from_seed([0x11; 32]).public_key_bytes();
    let node = NodeIdentity::from_seed([0x22; 32]).public_key_bytes();
    let body = BackupBody {
        entries: vec![
            ("ring_genesis.seed".into(), Zeroizing::new(vec![0x11; 32])),
            (
                "ring_genesis.pub".into(),
                Zeroizing::new(hex::encode(ring).into_bytes()),
            ),
            ("node_identity.seed".into(), Zeroizing::new(vec![0x22; 32])),
            ("vault_master_key".into(), Zeroizing::new(vec![0x33; 32])),
        ],
    };
    let b = seal(
        FIXTURE_PASS,
        KdfParams::ROUTER_SOC,
        ring,
        node,
        &body.encode().unwrap(),
    )
    .unwrap();
    std::fs::write(std::env::var("PARVAULT_WRITE_FIXTURE").unwrap(), &b).unwrap();
    println!("FIXTURE_HEX={}", hex::encode(&b));
}
