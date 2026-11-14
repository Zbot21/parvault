//! The WebDAV edge's plain GET (no `Range`) streams the whole file block by block, byte for byte.
//! A guard for B-23 (bounding open-ended `Range: bytes=N-` hydration, v0.6.0), whose
//! open-ended-Range test is designed in plan-5 and lands with that fix.
#![cfg(target_os = "linux")]

use parvault::capabilities::{CapabilityMacaroon, Caveat};
use parvault::config::{ErasureTier, HardwareProfile};
use parvault::crypto::MasterKey;
use parvault::gateway::GatewayIpcServer;
use parvault::storage::{BlockStore, QuotaManager};
use parvault::vfs::{VfsWebdavServerHandle, VirtualVaultFs, WebdavVerifier};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

/// Writes this test's gate sentinel (`suite` line in `.enforcement.map`), after its workload.
fn gate_ran(name: &str) {
    if let Ok(dir) = std::env::var("GATES_SENTINEL_DIR") {
        std::fs::write(std::path::Path::new(&dir).join(name), b"ran").expect("sentinel");
    }
}

const MIB: u64 = 1024 * 1024;
const BLOCKS: u64 = 12;
const ROOT: [u8; 32] = [0x6B; 32];

fn content() -> Vec<u8> {
    let mut s = 0x2545_F491_4F6C_DD1Du64;
    (0..BLOCKS * MIB)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}

fn token(caveats: Vec<Caveat>) -> CapabilityMacaroon {
    let mut nonce = [0u8; 32];
    nonce[0] = caveats.len() as u8 + 1;
    CapabilityMacaroon::mint(&ROOT, nonce, [0u8; 32], caveats).unwrap()
}

/// A 12-block file behind a ReadOnly WebDAV edge; the cache holds the whole file, so every block
/// the edge fetches shows up as a miss.
fn edge(
    dir: &Path,
) -> (
    parvault::gateway::GatewayIpcServerHandle,
    VirtualVaultFs,
    VfsWebdavServerHandle,
) {
    let sock = dir.join("gw.sock");
    let store = BlockStore::new(dir.join("store"), QuotaManager::new(512 * MIB, 64 * MIB)).unwrap();
    let server = GatewayIpcServer::new(&sock, store, MasterKey::generate())
        .with_profile(HardwareProfile::RouterSoc)
        .with_tier(ErasureTier::Consumer)
        .with_macaroon_root_key(ROOT)
        .with_require_sealed_ingest_memfd(true)
        .spawn()
        .unwrap();
    let seed = dir.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    std::fs::write(seed.join("f.bin"), content()).unwrap();
    let vfs = VirtualVaultFs::new(&sock, dir.join("cache"), 2 * BLOCKS * MIB)
        .unwrap()
        .with_default_macaroon(Some(token(Vec::new())));
    assert_eq!(vfs.ingest_local_directory(&seed).unwrap(), 1);
    let vfs = vfs.with_default_macaroon(Some(token(vec![Caveat::ReadOnly])));
    let handle = vfs
        .spawn_webdav_server("127.0.0.1:0", WebdavVerifier::RootKey(ROOT))
        .unwrap();
    (server, vfs, handle)
}

fn request(addr: std::net::SocketAddr, range: Option<&str>) -> TcpStream {
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let range = range.map(|r| format!("Range: {r}\r\n")).unwrap_or_default();
    let bearer = token(vec![Caveat::ReadOnly]).to_compact_token();
    write!(
        c,
        "GET /f.bin HTTP/1.1\r\nHost: t\r\n{range}Authorization: Bearer {bearer}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    c
}

#[test]
fn plain_get_still_streams_the_whole_file() {
    let tmp = tempfile::tempdir().unwrap();
    let (_gw, _vfs, handle) = edge(tmp.path());
    let mut c = request(handle.local_addr(), None);
    let mut resp = Vec::new();
    c.read_to_end(&mut resp).unwrap();
    let split = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP head")
        + 4;
    assert!(
        resp.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&resp[..split])
    );
    assert_eq!(resp.len() - split, (BLOCKS * MIB) as usize, "body length");
    assert!(resp[split..] == content()[..], "body differs");
    gate_ran("vfs_webdav_plain_get::plain_get_still_streams_the_whole_file");
}
