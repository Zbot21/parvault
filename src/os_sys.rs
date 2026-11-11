//! Minimal Audited POSIX / Linux OS Boundary (`parvault::os_sys`).
//!
//! `parvault` enforces `#![deny(unsafe_code)]` across the library crate and `#![forbid(unsafe_code)]`
//! across all binary targets. Every unavoidable POSIX kernel FFI call in the entire repository is
//! isolated in this module inside a narrowly scoped `#[allow(unsafe_code)]` wrapper with explicit
//! precondition validation and a documented `// SAFETY:` proof.
//!
//! Bulk zero-copy `memfd` streaming (`pread_full_or_eof` and `pwrite_all`) and `/proc` telemetry
//! (`read_self_rss_bytes`, `read_self_anon_rss_bytes`, `read_self_hwm_bytes`, `read_net_dev_bytes`)
//! are implemented in 100% safe Rust using `std::os::unix::fs::FileExt::{read_at, write_at}` and
//! `std::fs` with **zero** `unsafe` blocks.

use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;

/// Reads up to `buf.len()` bytes starting at `offset` via POSIX `pread` (`FileExt::read_at`),
/// looping until either `buf` is filled or `EOF` is reached without modifying the file
/// description's cursor or faulting shared-memory `mmap` PTEs into `VmRSS`.
///
/// Implemented in 100% safe Rust (`0` `unsafe` blocks).
pub fn pread_full_or_eof(file: &File, mut offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0usize;
    while total < buf.len() {
        match file.read_at(&mut buf[total..], offset) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                offset = offset.saturating_add(n as u64);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Writes all of `buf` starting at `offset` via POSIX `pwrite` (`FileExt::write_at`) without
/// modifying the file description's cursor or faulting shared-memory `mmap` PTEs into `VmRSS`.
///
/// Implemented in 100% safe Rust (`0` `unsafe` blocks).
pub fn pwrite_all(file: &File, mut offset: u64, buf: &[u8]) -> io::Result<()> {
    let mut written = 0usize;
    while written < buf.len() {
        match file.write_at(&buf[written..], offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "pwrite_all wrote 0 bytes before completing slice",
                ));
            }
            Ok(n) => {
                written += n;
                offset = offset.saturating_add(n as u64);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Reads total resident set size `VmRSS` (in bytes) from `/proc/self/status` (`0` if unavailable).
pub fn read_self_rss_bytes() -> u64 {
    read_proc_status_kib_field("VmRSS:").saturating_mul(1024)
}

/// Reads anonymous heap resident set size `RssAnon` (in bytes) from `/proc/self/status`.
pub fn read_self_anon_rss_bytes() -> u64 {
    read_proc_status_kib_field("RssAnon:").saturating_mul(1024)
}

/// Reads peak high-water-mark resident set size `VmHWM` (in bytes) from `/proc/self/status`.
pub fn read_self_hwm_bytes() -> u64 {
    read_proc_status_kib_field("VmHWM:").saturating_mul(1024)
}

fn read_proc_status_kib_field(prefix: &str) -> u64 {
    let Ok(contents) = fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix(prefix) {
            if let Some(num_tok) = rest.split_whitespace().next() {
                if let Ok(kib) = num_tok.parse::<u64>() {
                    return kib;
                }
            }
        }
    }
    0
}

/// Reads `(rx_bytes, tx_bytes)` for `iface` (e.g. `"eth0"` or `"lo"`) from `/proc/net/dev` in
/// 100% safe Rust.
pub fn read_net_dev_bytes(iface: &str) -> io::Result<(u64, u64)> {
    let raw = fs::read_to_string("/proc/net/dev")?;
    for line in raw.lines().skip(2) {
        if let Some((name, cols)) = line.split_once(':') {
            if name.trim() == iface {
                let mut nums = cols
                    .split_whitespace()
                    .filter_map(|t| t.parse::<u64>().ok());
                let rx_bytes = nums.next().unwrap_or(0);
                // Skip rx_packets..rx_multicast (7 fields) to reach column 8 (`tx_bytes`).
                let tx_bytes = nums.nth(7).unwrap_or(0);
                return Ok((rx_bytes, tx_bytes));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("network interface '{iface}' not found in /proc/net/dev"),
    ))
}

/// Returns total process CPU time consumed (`user + system`) in nanoseconds via
/// `CLOCK_PROCESS_CPUTIME_ID` (`0` if unsupported by the host kernel).
#[allow(unsafe_code)]
pub fn process_cpu_time_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, stack-allocated, fully initialized `libc::timespec` exclusively
    // borrowed via `&mut ts` for the duration of the synchronous `clock_gettime` kernel call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc == 0 {
        (ts.tv_sec.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec.max(0) as u64)
    } else {
        0
    }
}

/// Returns calling thread CPU time consumed in nanoseconds via `CLOCK_THREAD_CPUTIME_ID`
/// (`0` if unsupported by the host kernel).
#[allow(unsafe_code)]
pub fn thread_cpu_time_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, stack-allocated, fully initialized `libc::timespec` exclusively
    // borrowed via `&mut ts` for the duration of the synchronous `clock_gettime` kernel call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if rc == 0 {
        (ts.tv_sec.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec.max(0) as u64)
    } else {
        0
    }
}

/// Returns the effective POSIX user ID (`geteuid(2)`), which POSIX guarantees is infallible.
#[allow(unsafe_code)]
pub fn geteuid() -> u32 {
    // SAFETY: `libc::geteuid()` takes no pointers, mutates no memory, and is unconditionally
    // thread-safe and infallible per POSIX.1-2017.
    unsafe { libc::geteuid() }
}

/// Returns the effective POSIX group ID (`getegid(2)`), which POSIX guarantees is infallible.
#[allow(unsafe_code)]
pub fn getegid() -> u32 {
    // SAFETY: `libc::getegid()` takes no pointers, mutates no memory, and is unconditionally
    // thread-safe and infallible per POSIX.1-2017.
    unsafe { libc::getegid() }
}

/// Allocates an anonymous Linux kernel `memfd` (`MFD_CLOEXEC | MFD_ALLOW_SEALING`) optionally
/// pre-sized to `initial_size` bytes via safe `File::set_len`.
#[allow(unsafe_code)]
pub fn create_memfd(name: &str, initial_size: u64) -> io::Result<OwnedFd> {
    let sanitized: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    let c_name = CString::new(if sanitized.is_empty() {
        "parvault-shm"
    } else {
        &sanitized
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    #[cfg(target_os = "linux")]
    // SAFETY: `c_name` is a NUL-terminated `CString` alive across the syscall, and
    // `MFD_CLOEXEC | MFD_ALLOW_SEALING` are valid `memfd_create(2)` flags. On return >= 0, the
    // kernel hands exclusive ownership of a fresh open file descriptor to this process, which is
    // immediately adopted into `OwnedFd`.
    let owned = unsafe {
        let raw_fd = libc::syscall(
            libc::SYS_memfd_create,
            c_name.as_ptr(),
            (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as libc::c_uint,
        ) as libc::c_int;
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(raw_fd)
    };

    #[cfg(not(target_os = "linux"))]
    let owned: OwnedFd = {
        let _ = &c_name;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "memfd_create is only supported on Linux",
        ));
    };

    if initial_size > 0 {
        let file = File::from(owned);
        file.set_len(initial_size)?;
        return Ok(OwnedFd::from(file));
    }
    Ok(owned)
}

/// Validates and adopts an open `/dev/fuse` character-device file descriptor inherited at process
/// startup (e.g. from `fusermount3` or container init via `parvault-fuse mount-fd --fuse-fd <N>`).
#[allow(unsafe_code)]
pub fn adopt_fuse_dev_fd(fuse_fd: RawFd) -> io::Result<File> {
    if fuse_fd <= 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to adopt invalid or stdio file descriptor {fuse_fd} as /dev/fuse"),
        ));
    }
    // SAFETY: We first verify with `fcntl(F_GETFD)` and `fstat` that `fuse_fd` is a currently open
    // character-device descriptor (`S_IFCHR`) before duplicating (`F_DUPFD_CLOEXEC`) into a
    // dedicated owned `File`. Duplicating rather than directly consuming `fuse_fd` guarantees full
    // I/O safety even if `fuse_fd` were accidentally aliased elsewhere in the process!
    unsafe {
        let flags = libc::fcntl(fuse_fd, libc::F_GETFD);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fuse_fd, &mut st) < 0 {
            return Err(io::Error::last_os_error());
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFCHR {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("descriptor {fuse_fd} is not a /dev/fuse character device"),
            ));
        }
        let dup_fd = libc::fcntl(fuse_fd, libc::F_DUPFD_CLOEXEC, 3);
        if dup_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(File::from_raw_fd(dup_fd))
    }
}

/// Sends `buf` over Unix Domain Socket `sock_fd` via `sendmsg(2)` (`MSG_NOSIGNAL`), optionally
/// attaching a single open file descriptor via `SOL_SOCKET` / `SCM_RIGHTS` ancillary data.
#[allow(unsafe_code)]
pub fn sendmsg_scm_rights(
    sock_fd: BorrowedFd<'_>,
    buf: &[u8],
    attached_fd: Option<RawFd>,
) -> io::Result<usize> {
    if let Some(fd) = attached_fd {
        if fd < 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
    }

    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    #[repr(C)]
    union AlignedCmsgBuf {
        bytes: [u8; 64],
        _align: libc::cmsghdr,
    }
    let mut cmsg_storage = AlignedCmsgBuf { bytes: [0u8; 64] };

    // SAFETY:
    // 1. `sock_fd` is a `BorrowedFd<'_>` guaranteed live for the duration of this call.
    // 2. `iov` points to `buf` (`buf.len()` readable bytes) which outlives `sendmsg`.
    // 3. `cmsg_storage` is `cmsghdr`-aligned and `64` bytes >= `CMSG_SPACE(sizeof(RawFd))` (24 B on LP64).
    // 4. `CMSG_FIRSTHDR` is checked for non-null before writing `SCM_RIGHTS` via `write_unaligned`.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1 as _;

        if let Some(fd_to_pass) = attached_fd {
            let fd_sz = std::mem::size_of::<RawFd>() as u32;
            let space = libc::CMSG_SPACE(fd_sz) as usize;
            if space > cmsg_storage.bytes.len() {
                return Err(io::Error::other(
                    "CMSG_SPACE exceeds stack ancillary buffer",
                ));
            }
            msg.msg_control = cmsg_storage.bytes.as_mut_ptr().cast();
            msg.msg_controllen = space as _;

            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fd_sz) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd_to_pass);
        }

        let n = libc::sendmsg(sock_fd.as_raw_fd(), &msg, libc::MSG_NOSIGNAL);
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

/// Receives up to `buf.len()` bytes from Unix Domain Socket `sock_fd` via `recvmsg(2)`
/// (`MSG_CMSG_CLOEXEC`), adopting at most one `SCM_RIGHTS` file descriptor into `OwnedFd` and
/// immediately closing any unexpected extra descriptors so file descriptors can never leak.
#[allow(unsafe_code)]
pub fn recvmsg_scm_rights(
    sock_fd: BorrowedFd<'_>,
    buf: &mut [u8],
) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };

    #[repr(C)]
    union AlignedCmsgBuf {
        bytes: [u8; 64],
        _align: libc::cmsghdr,
    }
    let mut cmsg_storage = AlignedCmsgBuf { bytes: [0u8; 64] };

    // SAFETY:
    // 1. `sock_fd` is a `BorrowedFd<'_>` guaranteed live for the duration of `recvmsg`.
    // 2. `iov` points to mutable `buf` (`buf.len()` writable bytes) outliving `recvmsg`.
    // 3. `cmsg_storage` is `cmsghdr`-aligned and sized via `CMSG_SPACE(sizeof(RawFd))` (<= 64 B).
    // 4. Kernel-delivered `SCM_RIGHTS` descriptors (`MSG_CMSG_CLOEXEC`) are fresh open FDs owned by
    //    this process; every `raw_fd >= 0` is immediately wrapped in `OwnedFd::from_raw_fd`, so any
    //    surplus descriptors drop and close cleanly on loop iteration exit.
    unsafe {
        let fd_sz = std::mem::size_of::<RawFd>();
        let space = libc::CMSG_SPACE(fd_sz as u32) as usize;
        if space > cmsg_storage.bytes.len() {
            return Err(io::Error::other(
                "CMSG_SPACE exceeds stack ancillary buffer",
            ));
        }

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1 as _;
        msg.msg_control = cmsg_storage.bytes.as_mut_ptr().cast();
        msg.msg_controllen = space as _;

        let n = libc::recvmsg(sock_fd.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut received_fd: Option<OwnedFd> = None;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const u8;
                let cmsg_end = (cmsg as *const u8).add((*cmsg).cmsg_len as usize);
                let mut cur = data_ptr;
                while cur.add(fd_sz) <= cmsg_end {
                    let raw_fd = std::ptr::read_unaligned(cur.cast::<RawFd>());
                    if raw_fd >= 0 {
                        let owned = OwnedFd::from_raw_fd(raw_fd);
                        if received_fd.is_none() {
                            received_fd = Some(owned);
                        }
                    }
                    cur = cur.add(fd_sz);
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }

        Ok((n as usize, received_fd))
    }
}

/// Binds an IPv4 UDP socket on `0.0.0.0:port` with `SOCK_CLOEXEC`, `SO_REUSEADDR`, and
/// `SO_REUSEPORT` enabled before `bind(2)` so co-located local ParVault daemons can share the Home
/// LAN discovery broadcast/multicast port cleanly without `EADDRINUSE`.
#[allow(unsafe_code)]
pub fn bind_reusable_udp_v4(port: u16) -> io::Result<UdpSocket> {
    // SAFETY:
    // 1. `libc::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)` returns either `-1` or a fresh owned FD.
    // 2. `one` and `addr` (`libc::sockaddr_in`) are stack-initialized and match exact `setsockopt` /
    //    `bind` lengths (`size_of::<libc::c_int>()` and `size_of::<libc::sockaddr_in>()`).
    // 3. On `bind` error, `libc::close(fd)` releases the descriptor before returning `Err`; on
    //    success, `UdpSocket::from_raw_fd(fd)` assumes exclusive ownership.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = port.to_be();
        addr.sin_addr = libc::in_addr {
            s_addr: libc::INADDR_ANY.to_be(),
        };

        if libc::bind(
            fd,
            (&addr as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            let err = io::Error::last_os_error();
            let _ = libc::close(fd);
            return Err(err);
        }
        Ok(UdpSocket::from_raw_fd(fd))
    }
}

/// Verified peer process credentials extracted from a connected Unix Domain Socket via
/// Linux `SO_PEERCRED` (`getsockopt(2)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerUcred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Queries kernel-verified peer credentials (`pid`, `uid`, `gid`) of a connected Unix Domain
/// Socket via `getsockopt(SOL_SOCKET, SO_PEERCRED)` on Linux.
#[allow(unsafe_code)]
pub fn peer_socket_ucred(sock_fd: BorrowedFd<'_>) -> io::Result<PeerUcred> {
    #[cfg(target_os = "linux")]
    {
        let mut ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut optlen = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY:
        // 1. `sock_fd` is a live `BorrowedFd<'_>` valid across the synchronous `getsockopt` call.
        // 2. `ucred` is stack-allocated and fully initialized, and `optlen` is initialized to
        //    `size_of::<libc::ucred>()`.
        // 3. Both `rc == 0` and `optlen == size_of::<libc::ucred>()` are checked before reading
        //    kernel-populated credential fields.
        let rc = unsafe {
            libc::getsockopt(
                sock_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut ucred as *mut libc::ucred).cast(),
                &mut optlen,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if (optlen as usize) != std::mem::size_of::<libc::ucred>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected SO_PEERCRED optlen {optlen}"),
            ));
        }
        Ok(PeerUcred {
            pid: ucred.pid.max(0) as u32,
            uid: ucred.uid,
            gid: ucred.gid,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = sock_fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_PEERCRED is only supported on Linux",
        ))
    }
}

/// Permanently seals an anonymous Linux `memfd` (`MFD_ALLOW_SEALING`) with
/// `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE` so neither the sender nor any other
/// holder can mutate or resize the shared-memory payload after ingestion (anti-TOCTOU guarantee).
#[allow(unsafe_code)]
pub fn seal_memfd_immutable(fd: BorrowedFd<'_>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let seals: libc::c_int =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        // SAFETY: `fd` is a live `BorrowedFd<'_>` valid for the duration of `fcntl(F_ADD_SEALS)`.
        // `F_ADD_SEALS` consumes a scalar `c_int` seal mask and dereferences no pointers.
        let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "memfd sealing is only supported on Linux",
        ))
    }
}

/// Returns `true` iff `fd` is a Linux `memfd` carrying at least `F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`.
#[allow(unsafe_code)]
pub fn has_immutable_memfd_seals(fd: BorrowedFd<'_>) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let required: libc::c_int = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        // SAFETY: `fd` is a live `BorrowedFd<'_>` valid for the duration of `fcntl(F_GET_SEALS)`.
        // `F_GET_SEALS` takes no additional arguments and dereferences no pointers.
        let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
        if seals < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((seals & required) == required)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "memfd sealing inspection is only supported on Linux",
        ))
    }
}

/// Safely validates and duplicates an open file descriptor via `fcntl(F_DUPFD_CLOEXEC, 0)` into a
/// fresh [`OwnedFd`] sharing the same underlying kernel open file description (mirroring
/// `SCM_RIGHTS` descriptor duplication for `GatewayBus::InProcess` without closing the caller's FD).
#[allow(unsafe_code)]
pub fn dup_fd_cloexec(raw_fd: RawFd) -> io::Result<OwnedFd> {
    if raw_fd < 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    // SAFETY: `fcntl(raw_fd, F_DUPFD_CLOEXEC, 0)` atomically validates that `raw_fd` is currently
    // open in this process's descriptor table (`EBADF` if closed/invalid) and allocates a fresh,
    // unaliased file descriptor with `FD_CLOEXEC` set. On return `>= 0`, `OwnedFd::from_raw_fd`
    // takes exclusive ownership of the newly created duplicate descriptor.
    unsafe {
        let dup_fd = libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 0);
        if dup_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(dup_fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream as StdUnixStream;

    #[test]
    fn test_safe_pread_pwrite_memfd_and_cpu_clocks() {
        let mfd = create_memfd("os-sys-test", 4096).expect("create_memfd");
        let file = File::from(mfd);
        let payload = b"parvault-v040-zero-unsafe-pread-pwrite";
        pwrite_all(&file, 128, payload).expect("pwrite_all");

        let mut out = vec![0u8; payload.len()];
        let n = pread_full_or_eof(&file, 128, &mut out).expect("pread_full_or_eof");
        assert_eq!(n, payload.len());
        assert_eq!(&out, payload);

        let _ = geteuid();
        let _ = getegid();
        assert!(process_cpu_time_ns() > 0 || thread_cpu_time_ns() == 0);
        assert!(read_self_rss_bytes() > 0);
        assert!(read_self_hwm_bytes() >= read_self_rss_bytes() || read_self_hwm_bytes() > 0);
    }

    #[test]
    fn test_scm_rights_sendmsg_recvmsg_and_reusable_udp() {
        let (s1, s2) = StdUnixStream::pair().expect("unix pair");
        let mfd = create_memfd("scm-test", 16).expect("memfd");
        let f_in = File::from(mfd);
        pwrite_all(&f_in, 0, b"hello-scm-rights").expect("write");

        let sent = sendmsg_scm_rights(s1.as_fd(), &[1, 2, 3, 4], Some(f_in.as_raw_fd()))
            .expect("sendmsg_scm_rights");
        assert_eq!(sent, 4);

        let mut hdr = [0u8; 4];
        let (rcvd, maybe_fd) =
            recvmsg_scm_rights(s2.as_fd(), &mut hdr).expect("recvmsg_scm_rights");
        assert_eq!(rcvd, 4);
        assert_eq!(hdr, [1, 2, 3, 4]);
        let f_out = File::from(maybe_fd.expect("delivered OwnedFd"));
        let mut buf = [0u8; 16];
        assert_eq!(pread_full_or_eof(&f_out, 0, &mut buf).unwrap(), 16);
        assert_eq!(&buf, b"hello-scm-rights");

        // Negative FD must fail cleanly with EBADF:
        assert!(sendmsg_scm_rights(s1.as_fd(), &[0; 4], Some(-1)).is_err());
        assert!(dup_fd_cloexec(-1).is_err());
        // Non-char-device / invalid FD rejected by adopt_fuse_dev_fd:
        assert!(adopt_fuse_dev_fd(-1).is_err());
        assert!(adopt_fuse_dev_fd(f_out.as_raw_fd()).is_err());

        // Reusable UDP port 0 bind succeeds:
        let sock = bind_reusable_udp_v4(0).expect("bind_reusable_udp_v4");
        assert!(sock.local_addr().unwrap().port() > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_memfd_immutable_seals_and_peer_socket_ucred() {
        // (a) Verify memfd sealing: false before seal, true after seal, and subsequent writes/resizes fail with EPERM.
        let mfd = create_memfd("seal-test", 32).expect("create_memfd");
        let file = File::from(mfd);
        pwrite_all(&file, 0, b"immutable-zero-copy-payload-0001").expect("initial pwrite");
        assert!(
            !has_immutable_memfd_seals(file.as_fd()).expect("has_immutable_memfd_seals pre"),
            "fresh memfd must not report immutable seals before seal_memfd_immutable"
        );

        let dup = dup_fd_cloexec(file.as_raw_fd()).expect("dup_fd_cloexec");
        seal_memfd_immutable(dup.as_fd()).expect("seal_memfd_immutable");
        drop(dup);

        assert!(
            has_immutable_memfd_seals(file.as_fd()).expect("has_immutable_memfd_seals post"),
            "sealed memfd must report immutable seals across shared open file description"
        );

        let write_err =
            pwrite_all(&file, 0, b"tamper").expect_err("pwrite after F_SEAL_WRITE must fail");
        assert_eq!(write_err.raw_os_error(), Some(libc::EPERM));

        let grow_err = file
            .set_len(64)
            .expect_err("set_len grow after F_SEAL_GROW must fail");
        assert_eq!(grow_err.raw_os_error(), Some(libc::EPERM));

        let shrink_err = file
            .set_len(8)
            .expect_err("set_len shrink after F_SEAL_SHRINK must fail");
        assert_eq!(shrink_err.raw_os_error(), Some(libc::EPERM));

        // Reads still succeed cleanly after immutable sealing:
        let mut verify_buf = [0u8; 32];
        assert_eq!(
            pread_full_or_eof(&file, 0, &mut verify_buf).expect("pread sealed"),
            32
        );
        assert_eq!(&verify_buf, b"immutable-zero-copy-payload-0001");

        // (b) Verify SO_PEERCRED over a real UnixStream::pair() matches geteuid() / getegid() / pid.
        let (a, b) = StdUnixStream::pair().expect("UnixStream::pair");
        let cred_a = peer_socket_ucred(a.as_fd()).expect("peer_socket_ucred a");
        let cred_b = peer_socket_ucred(b.as_fd()).expect("peer_socket_ucred b");
        assert_eq!(cred_a.uid, geteuid());
        assert_eq!(cred_a.gid, getegid());
        assert_eq!(cred_a.pid, std::process::id());
        assert_eq!(cred_a, cred_b);
    }
}
