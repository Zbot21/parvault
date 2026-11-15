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
/// only when the owner differs, so a started service never walks the chunk store.
#[test]
fn procd_requires_mounted_posix_disk_and_chowns_only_on_owner_change() {
    let lines: Vec<&str> = code_lines(PROCD).collect();
    assert!(lines.contains(&"NAS=/mnt/nas"));
    assert!(lines.contains(&"DATA=$NAS/.parvault-data"));
    assert!(lines.iter().any(|l| l.contains("/proc/mounts")));
    assert!(lines.iter().any(|l| l.contains("is not a mountpoint")));
    assert!(lines
        .iter()
        .any(|l| l.starts_with("vfat|msdos|exfat|ntfs|ntfs3|fuseblk)")));
    assert!(!lines.iter().any(|l| l.contains("mkdir -p")));
    let chown = lines
        .iter()
        .position(|l| l.starts_with("chown "))
        .expect("chown line");
    assert_eq!(lines.iter().filter(|l| l.starts_with("chown ")).count(), 1);
    assert!(
        lines[chown - 1].starts_with("if [ \"$(owner_of \"$DATA\")\" != \"$SVC_USER\" ]"),
        "chown is not guarded by an owner check: {}",
        lines[chown - 1]
    );
}

/// P2P listens on the LAN address from uci, never `0.0.0.0` on the WAN; loopback when unset.
#[test]
fn procd_passes_lan_listen_addr() {
    let lines: Vec<&str> = code_lines(PROCD).collect();
    let cmd = lines
        .iter()
        .position(|l| l.starts_with("procd_set_param command"))
        .expect("command line");
    assert!(lines[cmd].ends_with('\\'), "{}", lines[cmd]);
    assert_eq!(lines[cmd + 1], "--listen \"$(lan_listen_addr)\"");
    assert!(lines.contains(&"ip=\"$(uci -q get network.lan.ipaddr)\""));
    assert!(lines.contains(&"ip=127.0.0.1"));
    assert!(lines.contains(&"echo \"/ip4/$ip/tcp/4001\""));
    assert!(!lines.iter().any(|l| l.contains("0.0.0.0")));
}
