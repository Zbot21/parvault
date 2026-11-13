#![deny(unsafe_code)]

// Feature split (item 3, plan-3 module table): `daemon-runtime` modules need tokio or libp2p;
// the rest build under `ipc-client` alone.
#[cfg(feature = "daemon-runtime")]
pub mod admin_rpc;
#[cfg(feature = "daemon-runtime")]
pub mod bootstrap;
pub mod capabilities;
#[cfg(feature = "daemon-runtime")]
pub mod config;
pub mod crypto;
pub mod gateway;
pub mod http_edge;
#[cfg(feature = "daemon-runtime")]
pub mod network;
#[cfg(unix)]
pub mod os_sys;
pub mod por;
pub mod profile;
#[cfg(feature = "daemon-runtime")]
pub mod router_nas;
pub mod sharding;
pub mod storage;
pub mod sync;
#[cfg(feature = "daemon-runtime")]
pub mod telemetry;
#[cfg(feature = "vfs")]
pub mod vfs;

pub use gateway::ipc;

#[cfg(kani)]
mod kani_proofs;
