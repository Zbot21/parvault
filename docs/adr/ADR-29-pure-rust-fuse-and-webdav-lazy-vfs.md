# ADR-29: Pure-Rust Userspace `/dev/fuse` (`ABI 7.31`) & WebDAV Lazy Virtual Filesystem (`parvault-fuse`)

- **Status:** Accepted (`v0.4.0`)
- **Subsystem:** `vfs` / `bin/parvault-fuse`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Mounting a `10 TiB` cloud vault on a `512 GiB` laptop or headless container must expose instant POSIX directory trees and random-access media/file seeks (`< 50 ms` TTFB) without hydrating untouched files, without linking C `libfuse` (which breaks zero-dependency static `musl` builds), and without raw pointer casts on kernel `/dev/fuse` packets.

## Decision

1. **Zero-`unsafe` Pure-Rust `/dev/fuse` `ABI 7.31` Engine (`src/vfs.rs`):** Speaks Linux FUSE kernel wire protocol `7.31` directly over an inherited `/dev/fuse` descriptor (`os_sys::adopt_fuse_dev_fd`) using 100% safe `from_ne_bytes` header parsers (`parse_fuse_in_header`, `parse_fuse_read_in`)—eliminating C `libfuse` and `unsafe` pointer casts alike—behind `--features vfs`.
2. **Lazy Metadata Inodes (`VfsStubNode`) & Bounded `LruBlockCache`:** Registers virtual directory trees in RAM with `0` upfront shard fetches. On `FUSE_READ` or unprivileged HTTP `206 Partial Content` / WebDAV `PROPFIND`, `compute_vfs_block_window` requests only the overlapping `1 MiB` block(s) from `parvault-gateway` via `SCM_RIGHTS` `memfd` and caches hot blocks inside a byte-bounded `LruBlockCache`.

## Consequences & Verification

- **F-43 (L-43, L-44):** every WebDAV request must present a read-only ADR-28 macaroon (`Authorization: Bearer`, or the Basic-auth password), checked by `vfs::webdav_auth_decision` before any lookup; the server cannot be built without a verifier. That edge decision is the only client gate, including `ByteRange` against the requested range: client tokens never reach the gateway, and the built-in VFS (WebDAV and FUSE) reads with a ReadOnly macaroon the daemon mints in memory.

- **Consequences:** Mounts `10 GiB` (`10,240`-stripe) sparse vaults in milliseconds with **`14.59 ms` TTFB** (`< 50 ms` gate) at a `4.5 GiB` seek offset even with `10` missing shards reconstructed on the fly, packaged in a `2.88 MiB` ARM64 / `3.62 MiB` x86_64 static `musl` binary.
- **Verification:** Kani harnesses `proof_fuse_header_parser_no_panic` and `proof_vfs_block_window_power_of_two_and_zero_bounds`; `tests/vfs_lazy_stream.rs`; `parvault-fuse self-test`.
