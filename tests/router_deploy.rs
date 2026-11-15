//! B-53 / B-54: static checks on the shipped OpenWrt procd service and the OpenWrt install path.

const PROCD: &str = include_str!("../deploy/router-soc/parvault-nas.procd");
const INSTALL: &str = include_str!("../scripts/install.sh");

fn code_lines(src: &str) -> impl Iterator<Item = &str> {
    src.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// `limits as=` counts every thread's reserved stack, so a tokio daemon fails to start under it.
#[test]
fn procd_sets_no_address_space_limit() {
    let limits: Vec<&str> = code_lines(PROCD)
        .filter(|l| l.starts_with("procd_set_param limits"))
        .collect();
    assert_eq!(limits, ["procd_set_param limits nofile=1024"]);
}

/// procd needs all three respawn values (threshold, timeout, retry).
#[test]
fn procd_respawn_has_three_values() {
    let line = code_lines(PROCD)
        .find(|l| l.starts_with("procd_set_param respawn"))
        .expect("respawn line");
    let vals: Vec<&str> = line.split_whitespace().skip(2).collect();
    assert_eq!(vals.len(), 3, "{line}");
    assert!(vals.iter().all(|v| v.parse::<u32>().is_ok()), "{line}");
}

/// The daemon runs as the `parvault` user, never root.
#[test]
fn procd_runs_as_service_user() {
    assert!(code_lines(PROCD).any(|l| l == "procd_set_param user \"$SVC_USER\""));
    assert!(code_lines(PROCD).any(|l| l == "SVC_USER=parvault"));
    // The call in start_service, not the `init_service_user() {` definition.
    assert!(code_lines(PROCD).any(|l| l == "init_service_user || return 1"));
}

/// Stop is procd's own TERM to its instance; `killall` would also kill CLI runs of `parvault`.
#[test]
fn procd_stop_does_not_killall() {
    assert!(!code_lines(PROCD).any(|l| l.contains("killall")));
    assert!(!code_lines(PROCD).any(|l| l.starts_with("stop_service")));
    assert!(code_lines(PROCD).any(|l| l.starts_with("procd_set_param term_timeout")));
}

/// The service's PROG is where install.sh puts the binary on OpenWrt.
#[test]
fn procd_prog_matches_openwrt_install_dir() {
    assert!(code_lines(PROCD).any(|l| l == "PROG=/usr/bin/parvault"));
    assert!(INSTALL.contains("DEFAULT_INSTALL_DIR=/usr/bin"));
    assert!(INSTALL.contains("/etc/openwrt_release"));
}

/// The data directory is set up only on a mounted NAS disk with POSIX owners, and chown runs
/// only when some entry is not the service user's (D1: not just the top directory).
#[test]
fn procd_requires_mounted_posix_disk_and_chowns_when_any_entry_differs() {
    let lines: Vec<&str> = code_lines(PROCD).collect();
    assert!(lines.contains(&"NAS=/mnt/nas"));
    assert!(lines.contains(&"DATA=$NAS/.parvault-data"));
    assert!(lines.iter().any(|l| l.contains("/proc/mounts")));
    assert!(lines.iter().any(|l| l.contains("is not a mountpoint")));
    assert!(lines
        .iter()
        .any(|l| l.starts_with("vfat|msdos|exfat|ntfs|ntfs3|fuseblk)")));
    assert!(!lines.iter().any(|l| l.contains("mkdir -p")));
    // busybox find on OpenWrt rejects -quit.
    assert!(!lines.iter().any(|l| l.contains("-quit")));
    assert!(lines.contains(&"find \"$1\" ! -user \"$2\" | head -n 1"));
    let chown = lines
        .iter()
        .position(|l| l.starts_with("chown "))
        .expect("chown line");
    assert_eq!(lines.iter().filter(|l| l.starts_with("chown ")).count(), 1);
    assert_eq!(
        lines[chown - 1],
        "if [ -n \"$(not_owned_by \"$DATA\" \"$SVC_USER\")\" ]; then",
        "chown is not guarded by the whole-tree owner check"
    );
    assert!(lines[chown + 1].starts_with("[ -z \"$(not_owned_by \"$DATA\" \"$SVC_USER\")\" ]"));
}

/// Runs `body` in `sh` with the procd script's functions loaded; returns (stdout, stderr).
fn run_procd_fn(body: &str, args: &[&str]) -> (String, String) {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/deploy/router-soc/parvault-nas.procd"
    );
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(". \"$0\"; {body}"))
        .arg(script)
        .args(args)
        .output()
        .expect("run sh");
    assert!(out.status.success(), "{body}: {out:?}");
    (
        String::from_utf8(out.stdout).expect("utf8"),
        String::from_utf8(out.stderr).expect("utf8"),
    )
}

fn current_user() -> String {
    let out = std::process::Command::new("id")
        .arg("-un")
        .output()
        .expect("id -un");
    String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_string()
}

/// D1: `not_owned_by` walks the whole tree. Every entry is the current user's, so it is empty
/// for that user, and for any other user it names the first entry (the walk includes the top).
#[test]
fn procd_not_owned_by_walks_the_tree() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("chunks")).expect("mkdir");
    std::fs::write(dir.path().join("chunks/c1"), b"x").expect("write");
    let path = dir.path().to_str().expect("path");
    let me = current_user();
    let other = if me == "root" { "nobody" } else { "root" };
    let (mine, _) = run_procd_fn("not_owned_by \"$1\" \"$2\"", &[path, &me]);
    assert_eq!(mine, "");
    let (theirs, _) = run_procd_fn("not_owned_by \"$1\" \"$2\"", &[path, other]);
    assert_eq!(theirs.trim(), path);
}

/// D3: the listen address is the first IPv4 address in uci's value; IPv6-only, malformed,
/// wildcard or empty values fall back to loopback with a log line naming the cause.
#[test]
fn procd_listen_addr_takes_ipv4_only() {
    let call = "listen_addr_for \"$1\" \"$2\"";
    for (raw, want) in [
        ("192.168.1.1/24", "/ip4/192.168.1.1/tcp/4001"),
        ("192.168.1.1", "/ip4/192.168.1.1/tcp/4001"),
        ("fd00::1/64 10.0.0.1/24", "/ip4/10.0.0.1/tcp/4001"),
        ("192.168.1.1 192.168.2.1", "/ip4/192.168.1.1/tcp/4001"),
    ] {
        let (out, err) = run_procd_fn(call, &[raw, "static"]);
        assert_eq!(out.trim(), want, "{raw}");
        assert!(!err.contains("127.0.0.1"), "{raw}: {err}");
    }
    for raw in [
        "fd00::1/64",
        "0.0.0.0",
        "0.0.0.0/0",
        "256.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "1..2.3",
        "a.b.c.d",
    ] {
        let (out, err) = run_procd_fn(call, &[raw, "static"]);
        assert_eq!(out.trim(), "/ip4/127.0.0.1/tcp/4001", "{raw}");
        assert!(
            err.contains(&format!("network.lan.ipaddr ({raw}) has no IPv4 address")),
            "{raw}: {err}"
        );
    }
    let (out, err) = run_procd_fn(call, &["", "dhcp"]);
    assert_eq!(out.trim(), "/ip4/127.0.0.1/tcp/4001");
    assert!(err.contains("LAN is a DHCP client (dumb AP"), "{err}");
    let (out, err) = run_procd_fn(call, &["", "static"]);
    assert_eq!(out.trim(), "/ip4/127.0.0.1/tcp/4001");
    assert!(err.contains("network.lan.ipaddr is unset"), "{err}");
}

/// D2, D3: procd restarts the service when the NAS disk mounts and reloads it when the
/// network config changes.
#[test]
fn procd_has_mount_and_network_triggers() {
    let lines: Vec<&str> = code_lines(PROCD).collect();
    let start = lines
        .iter()
        .position(|l| *l == "service_triggers() {")
        .expect("service_triggers");
    let body: Vec<&str> = lines[start..]
        .iter()
        .take_while(|l| **l != "}")
        .copied()
        .collect();
    assert!(body.contains(&"procd_add_restart_mount_trigger \"$NAS\""));
    assert!(body.contains(&"procd_add_reload_trigger network"));
}

/// P2P TCP listens on the LAN address from uci, never `0.0.0.0` on the WAN.
#[test]
fn procd_passes_lan_listen_addr() {
    let lines: Vec<&str> = code_lines(PROCD).collect();
    let cmd = lines
        .iter()
        .position(|l| l.starts_with("procd_set_param command"))
        .expect("command line");
    assert!(lines[cmd].ends_with('\\'), "{}", lines[cmd]);
    assert_eq!(lines[cmd + 1], "--listen \"$(lan_listen_addr)\"");
    assert!(lines.contains(
        &"listen_addr_for \"$(uci -q get network.lan.ipaddr)\" \"$(uci -q get network.lan.proto)\""
    ));
    assert!(!lines.iter().any(|l| l.contains("0.0.0.0")));
}
