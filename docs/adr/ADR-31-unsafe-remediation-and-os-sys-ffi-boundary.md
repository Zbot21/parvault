# ADR-31: Crate-Wide `#![deny/forbid(unsafe_code)]` Policy & `src/os_sys.rs` POSIX FFI Isolation Boundary

- **Status:** Accepted (`v0.4.0`)
- **Subsystem:** `lib` / `os_sys` / `bin/*`
- **Index:** [Master ADR Index & Cryptographic Suite Guide (`docs/ADR.md`)](../ADR.md)

---

## Context

Cryptographic, network-parsing, and FUSE wire-handling daemons written in Rust lose their memory-safety guarantees if ad-hoc `unsafe` pointer casts (`read_unaligned`), scattered `libc` calls, or blanket `#[allow(...)]` lint suppressions proliferate across feature modules.

## Decision

1. **Compiler-Enforced Crate-Root Gates:** `src/lib.rs` enforces `#![deny(unsafe_code)]`, while `src/main.rs`, `src/bin/parvault-seed.rs`, `src/bin/parvault-gateway.rs`, `src/bin/parvault-fuse.rs`, and `src/bin/parvault-bench.rs` all enforce `#![forbid(unsafe_code)]` (`0` `unsafe` permitted anywhere in any binary crate).
2. **Safe `FileExt` I/O & Single-File Kernel Boundary (`src/os_sys.rs`):** Positional `pread_full_or_eof` and `pwrite_all` use 100% safe `std::os::unix::fs::FileExt::{read_at, write_at}` (`0` `unsafe`), and `/dev/fuse` wire headers use safe `from_ne_bytes` slice parsers. All **9** unavoidable POSIX/Linux kernel syscalls (`clock_gettime` process/thread clocks, `geteuid`/`getegid`, `SYS_memfd_create`, `adopt_fuse_dev_fd`, `SCM_RIGHTS` `sendmsg`/`recvmsg`, and `bind_reusable_udp_v4`) are quarantined inside `src/os_sys.rs` behind safe `OwnedFd` / `BorrowedFd` signatures with line-by-line `// SAFETY:` proofs.
3. **Minimized Lint Suppressions & Continuous Audit:** Refactored 22 avoidable `#[allow(...)]` attributes into typed structs and boxed enum variants, leaving only `9` `#[allow(unsafe_code)]` items in `src/os_sys.rs` and `4` public SemVer cryptographic constructors—audited in [`docs/SAFETY_AND_LINT_AUDIT.md`](../SAFETY_AND_LINT_AUDIT.md) and enforced by `audit_workspace_hardening.sh`.

## Consequences & Verification

- **Consequences:** Shrinks the `unsafe` Trusted Computing Base (TCB) of the entire repository to `9` tiny POSIX syscall wrappers in one file (`src/os_sys.rs`) with `0` `unsafe` across all cryptographic, wire, sharding, storage, gateway, and VFS logic.
- **Verification:** [`docs/SAFETY_AND_LINT_AUDIT.md`](../SAFETY_AND_LINT_AUDIT.md), `cargo clippy --all-targets -- -D warnings`, `cargo kani` (`15/15` harnesses), and `audit_workspace_hardening.sh`.
