//! B-53 / B-54: static checks on the shipped OpenWrt procd service and router config. The KVM
//! canary (`scripts/openwrt_kvm_canary.sh`) runs them on a real OpenWrt image.

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
    for line in code_lines(PROCD).filter(|l| l.contains("procd_set_param limits")) {
        assert!(!line.contains(" as="), "address-space limit in: {line}");
        assert!(line.contains("nofile=1024"), "nofile limit missing: {line}");
    }
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
    assert!(code_lines(PROCD).any(|l| l.starts_with("init_service_user")));
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
