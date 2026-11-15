#![deny(unsafe_code)]

// v0.5.4 (docs/METRICS.md): the unauthenticated metrics listener never builds in a release
// profile. A profile override that turns debug assertions on gets past this; the build-env and
// artifact checks (scripts/check_release_build_env.sh, scripts/check_no_insecure_metrics.sh)
// catch that.
#[cfg(all(feature = "lab-insecure-metrics", not(debug_assertions)))]
compile_error!(
    "feature `lab-insecure-metrics` is debug-only: it must never be built with debug assertions off"
);

// Feature split (item 3, plan-3 module table): `daemon-runtime` modules need tokio or libp2p;
// the rest build under `ipc-client` alone.
#[cfg(feature = "daemon-runtime")]
pub mod admin_rpc;
#[cfg(feature = "daemon-runtime")]
pub mod bootstrap;
pub mod capabilities;
#[cfg(feature = "daemon-runtime")]
pub mod config;
pub mod config_dump;
pub mod crypto;
#[cfg(feature = "daemon-runtime")]
pub mod effective_config;
pub mod gateway;
pub mod http_edge;
#[cfg(all(unix, feature = "lab-insecure-metrics"))]
pub mod insecure_metrics;
pub mod lab_dial;
#[cfg(feature = "daemon-runtime")]
pub mod network;
#[cfg(unix)]
pub mod os_sys;
pub mod por;
pub mod profile;
#[cfg(all(unix, feature = "status-ui"))]
pub mod router_nas;
#[cfg(feature = "daemon-runtime")]
pub mod runtime;
pub mod sharding;
pub mod storage;
pub mod sync;
#[cfg(feature = "daemon-runtime")]
pub mod telemetry;
#[cfg(feature = "status-ui")]
pub mod traversal_metrics;
#[cfg(feature = "vfs")]
pub mod vfs;

pub use gateway::ipc;

// The harnesses prove daemon decisions; a dependent that runs `cargo kani` on a plugin feature set
// (no `daemon-runtime`) must still compile this crate.
#[cfg(all(kani, feature = "daemon-runtime"))]
mod kani_proofs;
