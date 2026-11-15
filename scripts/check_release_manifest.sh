#!/usr/bin/env bash
# L-16 seam (v0.5.5, plan 1.3, G-1 C10): a shipped daemon-runtime binary carries the default
# manifest only. Reads each binary's embedded `--version` line (no execution, so it works for
# cross-compiled targets): it must name `household-ring-v1` and no other manifest. Called by
# scripts/build_bins.sh for parvault, parvault-seed and parvault-bench.
# Usage: scripts/check_release_manifest.sh <binary>...
set -euo pipefail
[[ $# -gt 0 ]] || { echo "check_release_manifest.sh: no binary given" >&2; exit 2; }
DEFAULT="household-ring-v1"
fail=0
for bin in "$@"; do
  [[ -f "$bin" ]] || { echo "[ERROR] $bin: no such file" >&2; exit 2; }
  names=$(LC_ALL=C grep -aoE '\(manifest [a-z0-9-]+\)' "$bin" | sort -u | sed -E 's/^\(manifest (.*)\)$/\1/' || true)
  if [[ "$names" != "$DEFAULT" ]]; then
    echo "[FAIL] $bin: manifest(s) '$(tr '\n' ' ' <<<"$names" | sed 's/ $//')', release builds ship '$DEFAULT' only" >&2
    fail=1
  else
    echo "[PASS] $bin: manifest $DEFAULT"
  fi
done
exit $fail
