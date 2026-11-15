#!/usr/bin/env bash
# Run before a release-profile build (release.yml, ci.yml; v0.5.4, docs/METRICS.md). The guard
# against the debug-only metrics listener keys on effective debug assertions, which a profile
# name does not fix: this fails if anything in the environment or a cargo config could turn
# them on (or otherwise change codegen flags) for a shipped build.
#
#   scripts/check_release_build_env.sh [<repo root>]
#
# Fails (exit 1) on: RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS, CARGO_TARGET_*_RUSTFLAGS,
# CARGO_PROFILE_*_DEBUG_ASSERTIONS set; a .cargo/config or .cargo/config.toml (in the repo or in
# $CARGO_HOME) with a [profile table, rustflags or debug-assertions; or a [profile.*] in
# Cargo.toml with debug-assertions = true. CARGO_TARGET_*_LINKER is allowed.
set -uo pipefail
root="${1:-.}"
bad=0

while IFS='=' read -r name _; do
  case "$name" in
    RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS) echo "FAIL env: $name is set"; bad=1 ;;
    CARGO_TARGET_*_RUSTFLAGS) echo "FAIL env: $name is set"; bad=1 ;;
    CARGO_PROFILE_*_DEBUG_ASSERTIONS) echo "FAIL env: $name is set"; bad=1 ;;
  esac
done < <(env)

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
for cfg in "$root/.cargo/config" "$root/.cargo/config.toml" "$cargo_home/config" "$cargo_home/config.toml"; do
  [[ -f "$cfg" ]] || continue
  if LC_ALL=C grep -nE '^[[:space:]]*\[profile|rustflags|debug-assertions' "$cfg"; then
    echo "FAIL cargo config: $cfg sets a profile, rustflags or debug-assertions"
    bad=1
  fi
done

if [[ ! -f "$root/Cargo.toml" ]]; then
  echo "check_release_build_env: $root/Cargo.toml not found" >&2
  exit 2
fi
if awk '/^\[profile\./{p=1; next} /^\[/{p=0} p && /^[[:space:]]*debug-assertions[[:space:]]*=[[:space:]]*true/{print FILENAME": "$0; f=1} END{exit !f}' "$root/Cargo.toml"; then
  echo "FAIL Cargo.toml: a shipped profile sets debug-assertions = true"
  bad=1
fi

[[ $bad -eq 0 ]] && echo "ok: release build environment is clean"
exit "$bad"
