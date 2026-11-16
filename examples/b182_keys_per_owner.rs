//! B-182 measurement (arch182 section 5, the B182-9 decision): reads a COPY of a host's
//! `zero_trust_dht_store.bin` and prints each owner's envelope key count and its share of the
//! per-owner key cap of each profile. Read only: the given file is copied into a temporary
//! directory first, and that copy is what the store loads (loading never writes).
//!
//! `cargo run --release --example b182_keys_per_owner -- <path to a store file copy>`

use parvault::profile::HardwareProfile;
use parvault::storage::block_store::{DhtStoreLimits, DHT_STORE_FILE};
use parvault::storage::ZeroTrustDhtStore;

fn main() {
    let Some(src) = std::env::args_os().nth(1) else {
        eprintln!("usage: b182_keys_per_owner <path to a zero_trust_dht_store.bin copy>");
        std::process::exit(2);
    };
    let tmp = tempfile::tempdir().expect("temporary directory");
    std::fs::copy(&src, tmp.path().join(DHT_STORE_FILE)).expect("copy the store file");
    let store = ZeroTrustDhtStore::with_persistence_dir(tmp.path());
    if store.is_corrupt() {
        eprintln!("the store file does not decode");
        std::process::exit(1);
    }
    let per_owner = store.keys_per_owner();
    let (keys, bytes) = store.usage();
    println!(
        "store: {} owner(s), {keys} key(s), {bytes} byte(s)",
        per_owner.len()
    );
    let profiles = [
        ("router-soc", HardwareProfile::RouterSoc),
        ("homelab-nas", HardwareProfile::HomelabNas),
        ("desktop", HardwareProfile::Desktop),
    ];
    for (name, p) in profiles {
        let l = DhtStoreLimits::for_profile(p);
        println!(
            "{name}: total {keys}/{} keys ({:.1} %), owner share {} keys",
            l.max_keys,
            100.0 * keys as f64 / l.max_keys as f64,
            l.max_owner_keys
        );
    }
    for (i, k) in per_owner.iter().enumerate() {
        let shares: Vec<String> = profiles
            .iter()
            .map(|(name, p)| {
                let share = DhtStoreLimits::for_profile(*p).max_owner_keys;
                format!("{name} {:.1} %", 100.0 * *k as f64 / share as f64)
            })
            .collect();
        let over_half = profiles
            .iter()
            .any(|(_, p)| *k * 2 > DhtStoreLimits::for_profile(*p).max_owner_keys);
        println!(
            "owner {i}: {k} key(s); share of the owner cap: {}{}",
            shares.join(", "),
            if over_half {
                "  (above 50 % on some profile)"
            } else {
                ""
            }
        );
    }
}
