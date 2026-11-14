//! Stripes kept only on this machine (R3-1).
//!
//! When no ring peer accepts a stripe, or the node has no peers, `BlockStore::place_stripe`
//! keeps all its shards locally. That data is **not backed up**. Each store path counts those
//! stripes on the calling thread ([`track`]) so one-shot commands can say so and exit with
//! [`EXIT_CODE_LOCAL_ONLY`]; `BlockStore` also persists their roots for `parvault status`.

use std::cell::Cell;

/// Exit code of a one-shot store command (`watch-folder --once`, `file store`,
/// `parvault-sync push`) that kept at least one stripe only on this machine, unless
/// `--allow-local-only` is given.
pub const EXIT_CODE_LOCAL_ONLY: i32 = 3;

/// File in the data directory listing local-only stripe roots (hex, one per line).
pub const LOCAL_ONLY_STRIPES_FILE: &str = "local_only_stripes.txt";

thread_local! {
    static LOCAL_ONLY: Cell<u64> = const { Cell::new(0) };
}

/// Counts `n` local-only stripes on the current thread.
pub fn note(n: u64) {
    LOCAL_ONLY.with(|c| c.set(c.get().saturating_add(n)));
}

/// Runs `f` and returns its result with the local-only stripes it stored on this thread.
pub fn track<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = LOCAL_ONLY.with(|c| c.replace(0));
    let out = f();
    let n = LOCAL_ONLY.with(|c| c.replace(before));
    LOCAL_ONLY.with(|c| c.set(c.get().saturating_add(n)));
    (out, n)
}

/// The one summary line for local-only stripes.
pub fn summary_line(n: u64) -> String {
    format!("{n} stripe(s) kept only on this machine: NOT backed up")
}

/// Prints the summary line and exits with [`EXIT_CODE_LOCAL_ONLY`] when `n > 0` and the user
/// did not pass `--allow-local-only`; with the flag, prints the line and returns.
pub fn finish_one_shot(n: u64, allow_local_only: bool) {
    if n == 0 {
        return;
    }
    println!("{}", summary_line(n));
    if !allow_local_only {
        std::process::exit(EXIT_CODE_LOCAL_ONLY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn track_counts_only_inside_and_nests() {
        note(5);
        let ((), outer) = track(|| {
            note(1);
            let ((), inner) = track(|| note(2));
            assert_eq!(inner, 2);
        });
        assert_eq!(outer, 3);
    }
}
