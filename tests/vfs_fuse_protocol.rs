//! FUSE wire-protocol conformance of `VirtualVaultFs::serve_fuse_fd_blocking`, driven over a
//! datagram socketpair standing in for `/dev/fuse` (one frame per read, as the kernel delivers).
//! The real-kernel mount is exercised by `tests/vfs_mp4_seek_gate.rs`.
#![cfg(unix)]

use parvault::vfs::VirtualVaultFs;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

const FUSE_FORGET: u32 = 2;
const FUSE_GETATTR: u32 = 3;
const FUSE_INTERRUPT: u32 = 36;
const FUSE_DESTROY: u32 = 38;
const FUSE_BATCH_FORGET: u32 = 42;

fn frame(opcode: u32, unique: u64, nodeid: u64, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(40 + body.len());
    f.extend_from_slice(&((40 + body.len()) as u32).to_ne_bytes());
    f.extend_from_slice(&opcode.to_ne_bytes());
    f.extend_from_slice(&unique.to_ne_bytes());
    f.extend_from_slice(&nodeid.to_ne_bytes());
    f.extend_from_slice(&[0u8; 16]); // uid, gid, pid, padding
    f.extend_from_slice(body);
    f
}

/// D-1 (plan-5): FORGET, BATCH_FORGET and INTERRUPT take no reply. A reply makes the real kernel
/// fail the write with ENOENT, which used to end the loop and kill the mount.
#[test]
fn no_reply_opcodes_get_no_reply_and_the_loop_keeps_serving() {
    let tmp = tempfile::tempdir().unwrap();
    let vfs = VirtualVaultFs::new(
        tmp.path().join("absent.sock"),
        tmp.path().join("cache"),
        1 << 20,
    )
    .unwrap();
    let (kernel, dev) = UnixDatagram::pair().unwrap();
    let dev = File::from(OwnedFd::from(dev));
    let server = std::thread::spawn(move || vfs.serve_fuse_fd_blocking(dev));
    kernel
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    kernel
        .send(&frame(FUSE_FORGET, 1, 2, &1u64.to_ne_bytes()))
        .unwrap();
    kernel
        .send(&frame(FUSE_INTERRUPT, 2, 0, &99u64.to_ne_bytes()))
        .unwrap();
    let mut batch = Vec::new();
    batch.extend_from_slice(&1u32.to_ne_bytes()); // count
    batch.extend_from_slice(&0u32.to_ne_bytes()); // dummy
    batch.extend_from_slice(&2u64.to_ne_bytes()); // nodeid
    batch.extend_from_slice(&1u64.to_ne_bytes()); // nlookup
    kernel
        .send(&frame(FUSE_BATCH_FORGET, 3, 0, &batch))
        .unwrap();
    kernel.send(&frame(FUSE_GETATTR, 7, 1, &[0u8; 16])).unwrap();

    let mut buf = [0u8; 4096];
    let n = kernel.recv(&mut buf).expect("a reply to GETATTR");
    assert!(n >= 16, "short reply");
    let unique = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
    let error = i32::from_ne_bytes(buf[4..8].try_into().unwrap());
    assert_eq!(
        unique, 7,
        "the first reply must answer GETATTR, not a no-reply opcode"
    );
    assert_eq!(error, 0, "GETATTR on the root succeeds");

    kernel.send(&frame(FUSE_DESTROY, 8, 0, &[])).unwrap();
    let n = kernel.recv(&mut buf).expect("a reply to DESTROY");
    assert_eq!(u64::from_ne_bytes(buf[8..16].try_into().unwrap()), 8);
    assert!(n >= 16);
    server
        .join()
        .unwrap()
        .expect("the loop ends cleanly on DESTROY");
}
