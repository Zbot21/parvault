//! `v0.5.6` T0 seam (`architecture/plans/v0.5.6-usability.md` Section 2.1): the one refusal
//! every not-yet-built entry point returns until its track fills it in.
//!
//! A stub on a path the daemon already runs passes through and never comes here. A stub behind
//! a new entry point (a new flag, subcommand, IPC command, wire request or route) refuses with
//! [`not_built_yet`], which logs `reject.not_built_yet` and names the stub. This file is the only
//! place that literal is written. Each track deletes its calls as it lands; at integration the
//! Lead deletes this module (G3: `grep -rn reject.not_built_yet src` is empty at `v0.5.6`).

use std::io;

/// Which stubbed entry point refused, for the log and the error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unbuilt {
    /// The track that fills it in (`A`, `B1`, `B2`, `C`, `D`, `E`).
    pub track: &'static str,
    /// The entry point, as a user or peer reaches it (a flag, command, variant or route).
    pub entry: &'static str,
}

/// The refusal code of every stub (G3 greps for it).
pub const NOT_BUILT_YET: &str = "reject.not_built_yet";

/// Logs and returns the refusal of a stubbed entry point.
pub fn not_built_yet(unbuilt: Unbuilt) -> io::Error {
    tracing::warn!(
        code = NOT_BUILT_YET,
        track = unbuilt.track,
        entry = unbuilt.entry,
        "refused: not built yet (v0.5.6 T0 stub)"
    );
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "{NOT_BUILT_YET}: {} is not built yet (v0.5.6 track {})",
            unbuilt.entry, unbuilt.track
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refusal_names_the_code_and_the_entry() {
        let e = not_built_yet(Unbuilt {
            track: "A",
            entry: "tls show",
        });
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        let text = e.to_string();
        assert!(
            text.starts_with("reject.not_built_yet: tls show "),
            "{text}"
        );
        assert!(text.contains("track A"), "{text}");
    }
}
