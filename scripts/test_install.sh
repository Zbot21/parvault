#!/usr/bin/env bash
# Tests scripts/install.sh before publishing (plan-7 section 3): serves release-style assets
# (<bin>-<target>, SHA256SUMS) built by build_bins.sh from a local HTTP server and installs them
# into a temp dir with the script's default version (no PARVAULT_VERSION).
# Usage: scripts/test_install.sh <dir-with-parvault,parvault-seed,parvault-fuse,parvault-sync,parvault-status>
set -euo pipefail
SRC=$(realpath "$1")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/pv-install-test.XXXXXX")
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
case "$(uname -m)" in x86_64|amd64) T=x86_64-unknown-linux-musl ;; aarch64|arm64) T=aarch64-unknown-linux-musl ;; esac
VERSION=$(sed -n 's/^VERSION="\${PARVAULT_VERSION:-\(v[^}]*\)}"$/\1/p' "$ROOT/scripts/install.sh")
[[ -n "$VERSION" ]] || { echo "install.sh has no stamped default version" >&2; exit 1; }
ASSETS="$WORK/srv/$VERSION"; mkdir -p "$ASSETS" "$WORK/bin"
for b in parvault parvault-seed parvault-fuse parvault-sync parvault-status; do cp "$SRC/$b" "$ASSETS/$b-$T"; done
(cd "$ASSETS" && sha256sum ./*-"$T" | sed 's# \./# #' > SHA256SUMS)
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK/srv" >/dev/null 2>&1 & PID=$!
for _ in $(seq 1 50); do curl -fs "http://127.0.0.1:$PORT/$VERSION/SHA256SUMS" >/dev/null && break; sleep 0.1; done
PARVAULT_BASE_URL="http://127.0.0.1:$PORT/$VERSION" PARVAULT_INSTALL_DIR="$WORK/bin" sh "$ROOT/scripts/install.sh"
for b in parvault parvault-seed parvault-fuse parvault-sync parvault-status; do
  [[ -x "$WORK/bin/$b" ]] || { echo "not installed: $b" >&2; exit 1; }
done
echo "test_install: PASS ($VERSION, $T)"
