//! Helpers shared by integration test binaries (`mod common;`).

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// How long a command that must exit on its own (for example a daemon that must refuse to start)
/// may run before the test fails.
pub const EXIT_DEADLINE: Duration = Duration::from_secs(30);

/// Runs `cmd` to completion and returns its output, but kills it and fails the test if it is still
/// running after `EXIT_DEADLINE`: a daemon that starts instead of refusing would otherwise keep
/// the test waiting forever.
pub fn output_within_deadline(cmd: &mut Command) -> Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn command");
    let start = Instant::now();
    while child.try_wait().expect("poll command").is_none() {
        if start.elapsed() >= EXIT_DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!("daemon did not refuse within {}s", EXIT_DEADLINE.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("collect command output")
}
