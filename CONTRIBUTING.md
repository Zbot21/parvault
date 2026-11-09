# Contributing to `parvault` (`parvault` & `parvault-seed`)

Thank you for contributing to **Neighborhood Cloud (`parvault`)**! Because `parvault` and `parvault-seed` are zero-knowledge, post-quantum cryptographic backup daemons designed to protect irreplaceable user data across untrusted peers, every contribution is held to strict mathematical, memory-safety, and formal-verification standards.

---

## 1. Prerequisites

1. **Rust Toolchain:** Rust `1.80+` (`2021` edition) via `rustup`.
2. **Static `musl` Targets (Optional for local cross-builds):**
   ```bash
   rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
   ```
3. **Java `17+` & `tla2tools.jar` (When modifying protocol state machines in `specs/`):**
   Required to run the TLA+ TLC model checker across the 5 formal specifications in [`specs/`](specs/).

---

## 2. Architectural Orientation

Before writing code, please read:
- **[`AGENTS.md`](AGENTS.md):** Module-by-module source map (`src/`) and the **7 Non-Negotiable Zero-Trust & Memory-Safety Rules**.
- **[`docs/ADR.md`](docs/ADR.md):** Architectural Decision Records (`ADR-01` through `ADR-16`) documenting why every cryptographic, erasure-coding, and game-theoretic design choice was made.
- **[`docs/SECURITY_AND_CRYPTOGRAPHY.md`](docs/SECURITY_AND_CRYPTOGRAPHY.md):** Mathematical proofs, combinatorial anonymity bounds, post-quantum hybrid combiners, and TLA+ invariants.
- **[`docs/USER_AND_CLI_GUIDE.md`](docs/USER_AND_CLI_GUIDE.md):** Complete CLI flag reference and operational workflows for `parvault` and `parvault-seed`.

---

## 3. Pre-Pull-Request Verification Checklist

Every Pull Request must pass the following local checks before review:

### Step 1: Formatting & Linting
```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

### Step 2: Full Release Test Suite & `parvault-seed self-test`
```bash
cargo test --release
cargo run --release --bin parvault-seed -- self-test
```

### Step 3: TLA+ Formal Specification Check (If Touching Protocol State Machines)
If your change modifies shard placement, Web-of-Trust slashing, Proof-of-Retrievability (`PoR`) auditing, 4-layer shard anonymization, post-quantum key encapsulation, or elastic bootstrap / earned tier progression, update and re-verify the corresponding `.tla` specification in [`specs/`](specs/):
```bash
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultProtocol.cfg specs/ParVaultProtocol.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultConfidentialityAndTrust.cfg specs/ParVaultConfidentialityAndTrust.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultAnonymity.cfg specs/ParVaultAnonymity.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultPostQuantum.cfg specs/ParVaultPostQuantum.tla
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config specs/ParVaultBootstrapAndEarnedTier.cfg specs/ParVaultBootstrapAndEarnedTier.tla
```

---

## 4. Proposing Protocol Changes (`ADR` Workflow)

Any non-trivial change to wire framing, cryptographic primitives, erasure-coding parameters, or storage formats requires an **Architectural Decision Record (`ADR`)** entry in [`docs/ADR.md`](docs/ADR.md):
1. State the **Context** (what threat vector, hardware constraint, or usability gap is being addressed).
2. State the **Decision** with explicit domain-separation tags, data structures, and error bounds.
3. Add a dedicated integration or adversarial regression test in [`tests/`](tests/).

---

## 5. Security Vulnerability Disclosure

**Never report suspected cryptographic, wire-protocol, or path-traversal vulnerabilities in public GitHub issues or pull requests.**
Please follow our private disclosure process in **[`SECURITY.md`](SECURITY.md)**.

---

## 6. License (`AGPL-3.0-only`)

By contributing to `parvault`, you agree that your contributions will be licensed under the **GNU Affero General Public License v3.0 only (`AGPL-3.0-only`)** as set forth in [`LICENSE`](LICENSE).
