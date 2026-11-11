#![deny(unsafe_code)]

pub mod admin_rpc;
pub mod bootstrap;
pub mod capabilities;
pub mod config;
pub mod crypto;
pub mod gateway;
pub mod network;
#[cfg(unix)]
pub mod os_sys;
pub mod por;
pub mod router_nas;
pub mod sharding;
pub mod storage;
pub mod sync;
pub mod telemetry;
#[cfg(feature = "vfs")]
pub mod vfs;

pub use gateway::ipc;

#[cfg(kani)]
mod kani_proofs;
