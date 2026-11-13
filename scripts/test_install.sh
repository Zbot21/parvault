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
ASSETS="$WORK/srv/$VERSION"; mkdir -p "$ASSETS" "$WORK/bin" "$WORK/bin-upper"
for b in parvault parvault-seed parvault-fuse parvault-sync parvault-status; do cp "$SRC/$b" "$ASSETS/$b-$T"; done
(cd "$ASSETS" && sha256sum ./*-"$T" | sed 's# \./# #' > SHA256SUMS)
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK/srv" >/dev/null 2>&1 & PID=$!
for _ in $(seq 1 50); do curl -fs "http://127.0.0.1:$PORT/$VERSION/SHA256SUMS" >/dev/null && break; sleep 0.1; done
PARVAULT_BASE_URL="http://127.0.0.1:$PORT/$VERSION" PARVAULT_INSTALL_DIR="$WORK/bin" sh "$ROOT/scripts/install.sh"
for b in parvault parvault-seed parvault-fuse parvault-sync parvault-status; do
  [[ -x "$WORK/bin/$b" ]] || { echo "not installed: $b" >&2; exit 1; }
done

# Negative controls (release QA 7): each must make install.sh fail and install nothing.
must_fail() {  # <label> <expected message> <assets dir> [base url]
  local dest="$WORK/neg-$1"; mkdir -p "$dest"
  if PARVAULT_BASE_URL="${4:-http://127.0.0.1:$PORT/$3}" PARVAULT_INSTALL_DIR="$dest" \
      sh "$ROOT/scripts/install.sh" >"$WORK/neg-$1.log" 2>&1; then
    echo "test_install: FAIL: install.sh accepted $1" >&2; cat "$WORK/neg-$1.log" >&2; exit 1
  fi
  # It must fail for the right reason, not e.g. a network error.
  grep -qF "$2" "$WORK/neg-$1.log" || { echo "test_install: FAIL: $1 failed without '$2'" >&2; cat "$WORK/neg-$1.log" >&2; exit 1; }
  [[ -z "$(ls -A "$dest")" ]] || { echo "test_install: FAIL: $1 installed files" >&2; exit 1; }
  echo "negative control ok: $1 ($2)"
}
cp -r "$ASSETS" "$WORK/srv/tampered-bin"
printf 'x' >> "$WORK/srv/tampered-bin/parvault-$T"
must_fail tampered-binary "FAILED" tampered-bin
cp -r "$ASSETS" "$WORK/srv/tampered-sums"
sed -i "s/^[0-9a-f]\{64\}  parvault-sync-$T\$/$(printf '0%.0s' $(seq 64))  parvault-sync-$T/" "$WORK/srv/tampered-sums/SHA256SUMS"
must_fail tampered-sums-line "FAILED" tampered-sums
must_fail plain-http-off-loopback "plain http only to 127.0.0.1, localhost or [::1]" "$VERSION" "http://example.invalid/$VERSION"
must_fail http-loopback-prefix-host "plain http only to 127.0.0.1, localhost or [::1]" "$VERSION" "http://127.0.0.1.evil.example/$VERSION"
must_fail http-userinfo "plain http only to 127.0.0.1, localhost or [::1]" "$VERSION" "http://localhost@evil.example/$VERSION"
must_fail http-userinfo-after-port "plain http only to 127.0.0.1, localhost or [::1]" "$VERSION" "http://localhost:80@evil.example/$VERSION"
must_fail http-userinfo-ip-port "plain http only to 127.0.0.1, localhost or [::1]" "$VERSION" "http://127.0.0.1:$PORT@evil.example/$VERSION"
must_fail http-uppercase-off-loopback "plain http only to 127.0.0.1, localhost or [::1]" "$VERSION" "HTTP://example.invalid/$VERSION"
must_fail http-empty-port "plain http only to 127.0.0.1, localhost or [::1]" "$VERSION" "http://127.0.0.1:/$VERSION"
must_fail other-scheme "PARVAULT_BASE_URL" "$VERSION" "ftp://127.0.0.1/$VERSION"
# The scheme is case-insensitive: an upper-case HTTP:// to loopback installs.
PARVAULT_BASE_URL="HTTP://127.0.0.1:$PORT/$VERSION" PARVAULT_INSTALL_DIR="$WORK/bin-upper" \
  sh "$ROOT/scripts/install.sh" >"$WORK/upper.log" 2>&1 || { echo "test_install: FAIL: HTTP:// to 127.0.0.1 refused" >&2; cat "$WORK/upper.log" >&2; exit 1; }
echo "positive control ok: HTTP://127.0.0.1:$PORT (upper-case scheme)"
echo "test_install: PASS ($VERSION, $T)"
