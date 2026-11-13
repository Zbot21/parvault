//! Helpers shared by integration test binaries (`mod common;`).

// Each test binary compiles this module and uses only some of its helpers.
#![allow(dead_code)]

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// How long a command that must exit on its own (for example a daemon that must refuse to start)
/// may run before the test fails.
pub const EXIT_DEADLINE: Duration = Duration::from_secs(30);

/// Runs `cmd` to completion and returns its output, but kills it and fails the test if it is still
/// running after `EXIT_DEADLINE`: a daemon that starts instead of refusing would otherwise keep
/// the test waiting forever.
pub fn output_within_deadline(cmd: &mut Command) -> Output {
    use std::io::Read;
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn command");
    // Drain both pipes while polling, so a chatty child never blocks on a full pipe.
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    };
    let out = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll command") {
            break status;
        }
        if start.elapsed() >= EXIT_DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!("command did not exit within {}s", EXIT_DEADLINE.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: out.join().expect("stdout reader"),
        stderr: err.join().expect("stderr reader"),
    }
}

/// The listen address to give a test daemon: an ephemeral loopback port the kernel assigns at
/// bind time. Never reserve a port and release it for a daemon to bind later: libp2p-tcp sets
/// `SO_REUSEPORT`, so a daemon in another test process can silently co-bind the same port and
/// clients reach the wrong daemon.
pub const LOOPBACK_EPHEMERAL: &str = "/ip4/127.0.0.1/tcp/0";

/// The loopback TCP address a daemon reports in its "listening on" log line, if any (`parvault`
/// logs "Listening on mesh transport address", `parvault-seed` "listening on transport address").
pub fn listen_addr_in(log: &str) -> Option<String> {
    const PREFIX: &str = "/ip4/127.0.0.1/tcp/";
    log.lines()
        .filter(|l| l.contains("istening on"))
        .find_map(|l| {
            let rest = &l[l.find(PREFIX)? + PREFIX.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let port: u16 = digits.parse().ok()?;
            (port != 0).then(|| format!("{PREFIX}{port}"))
        })
}

/// Waits until the text `log_text()` returns (from its own offset on) holds a daemon's listen
/// address, and returns it. Panics if `child` exits first or after `timeout`.
pub fn wait_for_listen_addr(
    child: &mut std::process::Child,
    log_text: impl Fn() -> String,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let text = log_text();
        if let Some(addr) = listen_addr_in(&text) {
            return addr;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("daemon exited ({status}) before listening:\n{text}");
        }
        assert!(Instant::now() < deadline, "daemon not listening:\n{text}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Spawns `cmd` (a daemon told to listen on `LOOPBACK_EPHEMERAL`) with stdout and stderr in
/// `log`, and returns it with the address it actually bound.
pub fn spawn_on_ephemeral_port(
    cmd: &mut Command,
    log: &std::path::Path,
) -> (std::process::Child, String) {
    let file = std::fs::File::create(log).expect("create daemon log");
    let mut child = cmd
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::from(file.try_clone().expect("clone log handle")))
        .stderr(Stdio::from(file))
        .spawn()
        .expect("spawn daemon");
    let addr = wait_for_listen_addr(
        &mut child,
        || std::fs::read_to_string(log).unwrap_or_default(),
        Duration::from_secs(20),
    );
    (child, addr)
}

/// The TCP port of a `/ip4/.../tcp/<port>` address.
pub fn tcp_port_of(addr: &str) -> u16 {
    addr.rsplit('/')
        .next()
        .and_then(|p| p.parse().ok())
        .expect("tcp port in address")
}
