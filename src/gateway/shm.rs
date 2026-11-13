//! Zero-Copy Linux `memfd_create` + `AF_UNIX` `SCM_RIGHTS` File Descriptor Transport (`parvault::gateway::shm`).
//!
//! Provides asynchronous Tokio Unix Domain Socket `SCM_RIGHTS` framing (`send_frame_with_fd`,
//! `recv_frame_with_fd`) and re-exports safe `pread`/`pwrite` + `memfd` helpers from [`crate::os_sys`].
//! Contains **zero** `unsafe` blocks.

use crate::gateway::ipc::{validate_ipc_frame_header, MAX_IPC_FRAME_BYTES as IPC_MAX_FRAME_BYTES};
use crate::os_sys::{recvmsg_scm_rights, sendmsg_scm_rights};
use std::io;
use std::os::fd::{AsFd, OwnedFd, RawFd};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub use crate::os_sys::{create_memfd, pread_full_or_eof, pwrite_all};

/// Maximum serialized Bincode control frame size (`16 MiB`) accepted on the Unix Domain Socket.
pub const MAX_IPC_FRAME_BYTES: usize = IPC_MAX_FRAME_BYTES;

/// Router-SoC zero-bloat streaming stripe size (`1 MiB`).
pub use crate::profile::GATEWAY_STRIPE_BYTES;

/// Sends a length-prefixed frame (`[u32 BE len][payload]`) over asynchronous `stream`, optionally
/// attaching a single `RawFd` via `SOL_SOCKET` / `SCM_RIGHTS` ancillary data on the 4-byte header.
pub async fn send_frame_with_fd(
    stream: &mut UnixStream,
    payload: &[u8],
    attached_fd: Option<RawFd>,
) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_IPC_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "IPC control frame {} invalid or exceeds MAX_IPC_FRAME_BYTES ({MAX_IPC_FRAME_BYTES})",
                payload.len()
            ),
        ));
    }
    let len_bytes = (payload.len() as u32).to_be_bytes();

    if let Some(fd_to_pass) = attached_fd {
        let mut header_sent = 0usize;
        let mut fd_sent = false;
        while header_sent < 4 {
            stream.writable().await?;
            let send_res = stream.try_io(tokio::io::Interest::WRITABLE, || {
                sendmsg_scm_rights(
                    stream.as_fd(),
                    &len_bytes[header_sent..],
                    if fd_sent { None } else { Some(fd_to_pass) },
                )
            });
            match send_res {
                Ok(n) if n > 0 => {
                    fd_sent = true;
                    header_sent += n;
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Unix socket closed during SCM_RIGHTS header send",
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    } else {
        stream.write_all(&len_bytes).await?;
    }

    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Receives a length-prefixed frame (`[u32 BE len][payload]`) from asynchronous `stream`,
/// extracting any kernel-duplicated file descriptor delivered via `SCM_RIGHTS` (`MSG_CMSG_CLOEXEC`).
pub async fn recv_frame_with_fd(stream: &mut UnixStream) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut len_bytes = [0u8; 4];
    let mut header_read = 0usize;
    let mut received_fd: Option<OwnedFd> = None;

    while header_read < 4 {
        stream.readable().await?;
        let recv_res = stream.try_io(tokio::io::Interest::READABLE, || {
            recvmsg_scm_rights(stream.as_fd(), &mut len_bytes[header_read..])
        });
        match recv_res {
            Ok((0, maybe_fd)) => {
                drop(maybe_fd);
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF reading IPC frame header",
                ));
            }
            Ok((n, maybe_fd)) => {
                if let Some(fd) = maybe_fd {
                    received_fd = Some(fd);
                }
                header_read += n;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }

    let (body_len, init_cap) = validate_ipc_frame_header(len_bytes, MAX_IPC_FRAME_BYTES)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let mut body = Vec::with_capacity(init_cap);
    let read_n = stream.take(body_len as u64).read_to_end(&mut body).await?;
    if read_n != body_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated IPC control payload",
        ));
    }
    Ok((body, received_fd))
}
