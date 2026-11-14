#!/usr/bin/env bash
# Plan-3 / L-48: the plugin feature sets link no async runtime. For each set, singly and
# combined, `cargo tree -e normal --target all` must contain none of tokio, libp2p*, mio,
# quinn*. Used by CI and by tests/static_build_checks.rs (so the local gate runs it too).
# Usage: scripts/check_no_runtime_deps.sh [repo-root]
set -euo pipefail
cd "${1:-.}"
CARGO=${CARGO:-cargo}
# Plugin feature sets. A new plugin feature (e.g. status-ui) is added here and to the combined set.
SETS=("ipc-client" "vfs" "status-ui" "ipc-client,vfs" "vfs,status-ui" "ipc-client,vfs,status-ui")
BANNED='^(tokio|libp2p[a-z0-9_-]*|mio|quinn[a-z0-9_-]*)$'
fail=0
for set in "${SETS[@]}"; do
  crates=$("$CARGO" tree -e normal --target all --no-default-features --features "$set" \
    --prefix none --format '{p}' 2>/dev/null | awk '{print $1}' | sort -u) \
    || { echo "[ERROR] cargo tree failed for --features $set" >&2; exit 2; }
  [[ -n "$crates" ]] || { echo "[ERROR] empty dependency tree for --features $set" >&2; exit 2; }
  bad=$(grep -E "$BANNED" <<<"$crates" || true)
  if [[ -n "$bad" ]]; then
    echo "[FAIL] --no-default-features --features $set links: $(tr '\n' ' ' <<<"$bad")"
    fail=1
  else
    echo "[PASS] --no-default-features --features $set: no tokio/libp2p/mio/quinn ($(wc -l <<<"$crates") crates)"
  fi
done
exit $fail
