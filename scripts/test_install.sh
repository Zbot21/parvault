#!/usr/bin/env bash
# Tests scripts/install.sh before publishing (plan-7 section 3): serves dev-build assets
# (<bin>-<target>-dev, SHA256SUMS, SHA256SUMS.sig) made from binaries built by build_bins.sh from
# a local HTTP server and installs them into a temp dir with the script's default version (no
# PARVAULT_VERSION). Signatures use throwaway keys (L-113 signature cases below).
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
ASSETS="$WORK/srv/$VERSION"; mkdir -p "$ASSETS" "$WORK/bin" "$WORK/bin-upper" "$WORK/keys"
# The key in install.sh is the one in security/dev-allowed-signers.
want=$(grep -v '^#' "$ROOT/security/dev-allowed-signers")
got=$(sed -n "s/^DEV_ALLOWED_SIGNERS='\(.*\)'\$/\1/p" "$ROOT/scripts/install.sh")
[[ "$want" == "$got" ]] || { echo "test_install: FAIL: install.sh DEV_ALLOWED_SIGNERS differs from security/dev-allowed-signers" >&2; exit 1; }
grep -q "^RELEASE_ALLOWED_SIGNERS=''\$" "$ROOT/scripts/install.sh" \
  || { echo "test_install: FAIL: install.sh carries a release key; none exists yet (L-113)" >&2; exit 1; }
# Throwaway keys: a test dev key, an unrelated key, and a test release key.
for k in dev other release; do ssh-keygen -q -t ed25519 -N '' -C "test-$k" -f "$WORK/keys/$k"; done
echo "parvault-dev namespaces=\"parvault-dev-build\" $(cut -d' ' -f1,2 "$WORK/keys/dev.pub")" > "$WORK/keys/dev-signers"
echo "parvault-release namespaces=\"parvault-release-build\" $(cut -d' ' -f1,2 "$WORK/keys/release.pub")" > "$WORK/keys/release-signers"
export PARVAULT_TEST_DEV_SIGNERS="$WORK/keys/dev-signers"
sign() { rm -f "$1/SHA256SUMS.sig"; ssh-keygen -q -Y sign -f "$WORK/keys/$2" -n "$3" "$1/SHA256SUMS"; }  # <dir> <key> <namespace>
for b in parvault parvault-seed parvault-fuse parvault-sync parvault-status; do cp "$SRC/$b" "$ASSETS/$b-$T-dev"; done
bash "$ROOT/scripts/make_sums.sh" "$ASSETS" "$VERSION" dev >/dev/null
sign "$ASSETS" dev parvault-dev-build
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORK/srv" >/dev/null 2>&1 & PID=$!
for _ in $(seq 1 50); do curl -fs "http://127.0.0.1:$PORT/$VERSION/SHA256SUMS" >/dev/null && break; sleep 0.1; done
PARVAULT_ALLOW_DEV_BUILD=1 PARVAULT_BASE_URL="http://127.0.0.1:$PORT/$VERSION" PARVAULT_INSTALL_DIR="$WORK/bin" \
  sh "$ROOT/scripts/install.sh" | tee "$WORK/valid.log"
for b in parvault parvault-seed parvault-fuse parvault-sync parvault-status; do
  [[ -x "$WORK/bin/$b" ]] || { echo "not installed: $b" >&2; exit 1; }
done
grep -qF "Installed DEV build $VERSION" "$WORK/valid.log" || { echo "test_install: FAIL: install did not say it is a DEV build" >&2; exit 1; }
echo "positive control ok: valid dev signature with PARVAULT_ALLOW_DEV_BUILD=1"
export PARVAULT_ALLOW_DEV_BUILD=1

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
printf 'x' >> "$WORK/srv/tampered-bin/parvault-$T-dev"
must_fail tampered-binary "FAILED" tampered-bin
cp -r "$ASSETS" "$WORK/srv/tampered-sums"
sed -i "s/^[0-9a-f]\{64\}  parvault-sync-$T-dev\$/$(printf '0%.0s' $(seq 64))  parvault-sync-$T-dev/" "$WORK/srv/tampered-sums/SHA256SUMS"
must_fail sums-changed-after-signing "does not verify" tampered-sums
# L-113 signature cases.
mk() { rm -rf "$WORK/srv/$1"; cp -r "$ASSETS" "$WORK/srv/$1"; }  # <name>: a copy of the valid assets
PARVAULT_ALLOW_DEV_BUILD=0 must_fail dev-build-without-opt-in "is a DEV build" "$VERSION"
mk missing-sig; rm "$WORK/srv/missing-sig/SHA256SUMS.sig"
must_fail missing-sig "PARVAULT_ALLOW_UNSIGNED=1" missing-sig
mk wrong-key; sign "$WORK/srv/wrong-key" other parvault-dev-build
must_fail wrong-key "does not verify" wrong-key
# The real dev key in install.sh (no test override) rejects a test-key signature too.
PARVAULT_TEST_DEV_SIGNERS="" must_fail test-key-vs-embedded-key "does not verify" "$VERSION"
mk dev-in-release-ns; sign "$WORK/srv/dev-in-release-ns" dev parvault-release-build
must_fail dev-sig-in-release-namespace "does not verify" dev-in-release-ns
PARVAULT_TEST_RELEASE_SIGNERS="$WORK/keys/release-signers" \
  must_fail dev-sig-in-release-namespace-with-release-key "does not verify" dev-in-release-ns
mk replay; bash "$ROOT/scripts/make_sums.sh" "$WORK/srv/replay" v0.0.1 dev >/dev/null; sign "$WORK/srv/replay" dev parvault-dev-build
must_fail old-signature-replayed-for-new-tag "SHA256SUMS is for v0.0.1, not $VERSION" replay
mk kind-mismatch; sed -i "1s/.*/# parvault $VERSION release/" "$WORK/srv/kind-mismatch/SHA256SUMS"; sign "$WORK/srv/kind-mismatch" dev parvault-dev-build
must_fail release-header-dev-key "says 'release' but the dev key signed it" kind-mismatch
mk no-header; sed -i 1d "$WORK/srv/no-header/SHA256SUMS"; sign "$WORK/srv/no-header" dev parvault-dev-build
must_fail signed-without-header "has no '# parvault <tag> <kind>' first line" no-header
mk two-sides; sed -i "1s/.*/# parvault $VERSION dev extra/" "$WORK/srv/two-sides/SHA256SUMS"; sign "$WORK/srv/two-sides" dev parvault-dev-build
must_fail malformed-header "malformed SHA256SUMS first line" two-sides
# No verifier on PATH (OpenWrt/dropbear): warns and continues (L-81), or refuses when required.
mkdir -p "$WORK/nokeygen"; for c in sh curl sha256sum grep head mv chmod mktemp rm cp uname tr cat printf sed id sudo mkdir ls; do
  p=$(command -v "$c" 2>/dev/null) && ln -sf "$p" "$WORK/nokeygen/$c"; done
PATH="$WORK/nokeygen" PARVAULT_REQUIRE_SIGNATURE=1 must_fail no-verifier-required "PARVAULT_REQUIRE_SIGNATURE=1 but no signature verifier" "$VERSION"
mkdir -p "$WORK/bin-noverify"
PATH="$WORK/nokeygen" PARVAULT_BASE_URL="http://127.0.0.1:$PORT/$VERSION" PARVAULT_INSTALL_DIR="$WORK/bin-noverify" \
  "$WORK/nokeygen/sh" "$ROOT/scripts/install.sh" >"$WORK/noverify.log" 2>&1 \
  || { echo "test_install: FAIL: no-verifier install refused" >&2; cat "$WORK/noverify.log" >&2; exit 1; }
grep -qF "cannot verify SHA256SUMS.sig" "$WORK/noverify.log" || { echo "test_install: FAIL: no-verifier install did not warn" >&2; exit 1; }
echo "positive control ok: no verifier warns and continues (L-81)"
# A missing signature installs only with PARVAULT_ALLOW_UNSIGNED=1, and says so.
mkdir -p "$WORK/bin-unsigned"
PARVAULT_ALLOW_UNSIGNED=1 PARVAULT_BASE_URL="http://127.0.0.1:$PORT/missing-sig" PARVAULT_INSTALL_DIR="$WORK/bin-unsigned" \
  sh "$ROOT/scripts/install.sh" >"$WORK/unsigned.log" 2>&1 \
  || { echo "test_install: FAIL: PARVAULT_ALLOW_UNSIGNED=1 refused" >&2; cat "$WORK/unsigned.log" >&2; exit 1; }
grep -qF "UNSIGNED" "$WORK/unsigned.log" || { echo "test_install: FAIL: unsigned install did not say UNSIGNED" >&2; exit 1; }
echo "positive control ok: missing signature with PARVAULT_ALLOW_UNSIGNED=1"
# Non-vacuity of the release path: a test release key in the release namespace verifies as release.
mk release-ok; sed -i "1s/.*/# parvault $VERSION release/" "$WORK/srv/release-ok/SHA256SUMS"
for b in parvault parvault-seed parvault-fuse parvault-sync parvault-status; do mv "$WORK/srv/release-ok/$b-$T-dev" "$WORK/srv/release-ok/$b-$T"; done
sed -i "s/-dev\$//" "$WORK/srv/release-ok/SHA256SUMS"; sign "$WORK/srv/release-ok" release parvault-release-build
mkdir -p "$WORK/bin-release"
PARVAULT_ALLOW_DEV_BUILD=0 PARVAULT_TEST_RELEASE_SIGNERS="$WORK/keys/release-signers" PARVAULT_BASE_URL="http://127.0.0.1:$PORT/release-ok" \
  PARVAULT_INSTALL_DIR="$WORK/bin-release" sh "$ROOT/scripts/install.sh" >"$WORK/release.log" 2>&1 \
  || { echo "test_install: FAIL: test release signature refused" >&2; cat "$WORK/release.log" >&2; exit 1; }
grep -qF "signature verified (release key)" "$WORK/release.log" || { echo "test_install: FAIL: release path did not verify as release" >&2; exit 1; }
echo "positive control ok: test release key verifies as release (path is live, key is absent in install.sh)"
must_fail release-sig-without-release-key "does not verify" release-ok
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
