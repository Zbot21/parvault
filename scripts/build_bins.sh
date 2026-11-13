#!/usr/bin/env bash
# One plugin build script for CI, release and metrics (plan-3 ruling change 9). Each binary is
# built in its own cargo invocation with its own feature set, so cargo's feature unification
# cannot put tokio or libp2p back into a plugin. Copies results to OUT_DIR/<bin>[-<target>].
# Usage: scripts/build_bins.sh --profile <release|soc> [--target <triple>] --out <dir> [bin...]
set -euo pipefail
PROFILE=release; TARGET=""; OUT=""; BINS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE=$2; shift 2 ;;
    --target) TARGET=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    -*) echo "build_bins.sh: unknown flag $1" >&2; exit 2 ;;
    *) BINS+=("$1"); shift ;;
  esac
done
[[ -n "$OUT" ]] || { echo "build_bins.sh: --out is required" >&2; exit 2; }
[[ ${#BINS[@]} -gt 0 ]] || BINS=(parvault parvault-seed parvault-fuse parvault-sync parvault-status)
features_for() {
  case "$1" in
    parvault|parvault-seed|parvault-bench) echo "" ;;                      # default (daemon-runtime, vfs)
    parvault-fuse) echo "--no-default-features --features vfs" ;;
    parvault-sync) echo "--no-default-features --features ipc-client" ;;
    parvault-status) echo "--no-default-features --features status-ui" ;;
    *) echo "build_bins.sh: no feature set for $1" >&2; return 2 ;;
  esac
}
mkdir -p "$OUT"
TDIR=${CARGO_TARGET_DIR:-target}
for bin in "${BINS[@]}"; do
  feats=$(features_for "$bin")
  # shellcheck disable=SC2086
  cargo build --profile "$PROFILE" ${TARGET:+--target "$TARGET"} $feats --bin "$bin"
  dir="$TDIR/${TARGET:+$TARGET/}$( [[ $PROFILE == dev ]] && echo debug || echo "$PROFILE")"
  cp "$dir/$bin" "$OUT/$bin${TARGET:+-$TARGET}"
  echo "built $OUT/$bin${TARGET:+-$TARGET} ($feats)"
done
