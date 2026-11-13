#!/usr/bin/env bash
# Runs the client-only plugin self-tests (item 3) against a standalone gateway.
# Usage: scripts/plugin_self_test.sh <parvault> <parvault-fuse> <parvault-sync>
# Starts `parvault gateway serve` with a fresh root key in a temp dir, mints a token, runs
# `parvault-fuse self-test` and `parvault-sync self-test` with it, and stops the gateway by PID.
set -euo pipefail
PV=$(realpath "$1"); FUSE=$(realpath "$2"); SYNC=$(realpath "$3")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/pv-plugin-selftest.XXXXXX")
GW_PID=""
cleanup() {
  if [[ -n "$GW_PID" ]]; then kill "$GW_PID" 2>/dev/null || true; wait "$GW_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
KEY=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
SOCK="$WORK/gw.sock"
"$PV" --data-dir "$WORK/data" gateway --socket "$SOCK" --macaroon-root-key-hex "$KEY" \
  --require-sealed-memfd serve >"$WORK/gateway.log" 2>&1 &
GW_PID=$!
for _ in $(seq 1 200); do
  [[ -S "$SOCK" ]] && break
  kill -0 "$GW_PID" 2>/dev/null || { cat "$WORK/gateway.log"; echo "gateway exited" >&2; exit 1; }
  sleep 0.1
done
[[ -S "$SOCK" ]] || { cat "$WORK/gateway.log"; echo "gateway socket not up after 20 s" >&2; exit 1; }
TOKEN=$("$PV" --data-dir "$WORK/data" token mint --macaroon-key-hex "$KEY")
(cd "$WORK" && "$FUSE" --socket "$SOCK" --macaroon "$TOKEN" self-test)
(cd "$WORK" && "$SYNC" --socket "$SOCK" --macaroon "$TOKEN" self-test)
