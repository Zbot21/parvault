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
