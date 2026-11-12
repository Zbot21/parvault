@AGENTS.md

## Claude Code notes

- `AGENTS.md` above is the source of truth; keep it updated rather than this file.
- Build with `CARGO_TARGET_DIR=$HOME/.cache/parvault-target/parvault` (ext4 is much faster than `/mnt/c`, and target dirs are never shared between agents).
- During iteration run the change-scoped gates (`run_scoped_gates.sh` once queue item 1 in `parvault-docs/HANDOFF.md` lands); full `cargo kani` and all TLC specs only before QA sign-off.
- Commit locally on the branch you are given; never push or tag.
