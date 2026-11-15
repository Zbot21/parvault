//! Build facts for the release guard (`v0.5.4`, `docs/METRICS.md`): every binary prints them in
//! `--version --verbose`, and `scripts/check_no_insecure_metrics.sh` reads them from shipped
//! artifacts. In every feature set, so the plugin binaries print them too.

/// The build facts the release guard and `--version --verbose` read (one source).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildFacts {
    pub insecure_metrics_feature: bool,
    pub debug_assertions: bool,
}

pub const fn build_facts() -> BuildFacts {
    BuildFacts {
        insecure_metrics_feature: cfg!(feature = "lab-insecure-metrics"),
        debug_assertions: cfg!(debug_assertions),
    }
}

/// The two lines `--version --verbose` adds (`docs/METRICS.md`, release guard).
pub fn build_facts_lines(f: BuildFacts) -> String {
    let features = if f.insecure_metrics_feature {
        "lab-insecure-metrics"
    } else {
        "none"
    };
    format!(
        "debug_assertions: {}\nfeatures: {features}",
        if f.debug_assertions { "on" } else { "off" }
    )
}

/// clap's `long_version`: the version, then the build-facts lines.
pub fn long_version() -> &'static str {
    static LONG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    LONG.get_or_init(|| {
        format!(
            "{}\n{}",
            env!("CARGO_PKG_VERSION"),
            build_facts_lines(build_facts())
        )
    })
}
