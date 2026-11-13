#!/usr/bin/env sh
# ParVault (parvault, parvault-seed, parvault-fuse, parvault-sync, parvault-status) Static Binary Installer
set -eu

REPO="${PARVAULT_REPO:-Zbot21/parvault}"
INSTALL_DIR="${PARVAULT_INSTALL_DIR:-/usr/local/bin}"
# The default version is this release's own tag: every ParVault release is a pre-release, so
# GitHub has no "Latest" release to resolve. gen_metrics.sh fails if it differs from Cargo.toml's
# version, and release.yml fails if it differs from the tag. PARVAULT_VERSION=latest asks GitHub
# for its "Latest" release, which does not exist (404) while every release is a pre-release.
VERSION="${PARVAULT_VERSION:-v0.5.0}"
BINS="${PARVAULT_BINS:-parvault parvault-seed parvault-fuse parvault-sync parvault-status}"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)
    TARGET="x86_64-unknown-linux-musl"
    ;;
  aarch64|arm64)
    TARGET="aarch64-unknown-linux-musl"
    ;;
  *)
    echo "Unsupported architecture: $ARCH (supported: x86_64, aarch64)" >&2
    exit 1
    ;;
esac

# HTTPS only. PARVAULT_BASE_URL (scripts/test_install.sh serves local assets) may use plain
# http only to the exact hosts 127.0.0.1, localhost or [::1], with an optional numeric port and
# no userinfo; the scheme is case-insensitive.
PROTO="=https"
refuse_base_url() {
  echo "PARVAULT_BASE_URL '$PARVAULT_BASE_URL': plain http only to 127.0.0.1, localhost or [::1] (optional port, no user@); use https for anything else" >&2
  exit 1
}
if [ -n "${PARVAULT_BASE_URL:-}" ]; then
  BASE_URL="$PARVAULT_BASE_URL"
  url_lc=$(printf '%s' "$BASE_URL" | tr 'A-Z' 'a-z')
  case "$url_lc" in
    https://*) ;;
    http://*)
      rest=${url_lc#http://}
      authority=${rest%%/*}
      case "$authority" in *@*) refuse_base_url ;; esac
      case "$authority" in
        127.0.0.1|localhost|"[::1]") ;;
        127.0.0.1:*|localhost:*|"[::1]":*)
          port=${authority##*:}
          case "$port" in ''|*[!0-9]*) refuse_base_url ;; esac
          ;;
        *) refuse_base_url ;;
      esac
      PROTO="=http"
      ;;
    *) refuse_base_url ;;
  esac
elif [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> Downloading ParVault static musl binaries (${BINS}) for ${TARGET} from ${BASE_URL} ..."
curl --proto "$PROTO" --tlsv1.2 -fsSL "${BASE_URL}/SHA256SUMS" -o "${TMP_DIR}/SHA256SUMS"
for bin in $BINS; do
  curl --proto "$PROTO" --tlsv1.2 -fsSL "${BASE_URL}/${bin}-${TARGET}" -o "${TMP_DIR}/${bin}-${TARGET}"
done

echo "==> Verifying SHA256SUMS ..."
(
  cd "$TMP_DIR"
  for bin in $BINS; do
    grep -E " ${bin}-${TARGET}$" SHA256SUMS | sha256sum -c -
    mv "${bin}-${TARGET}" "${bin}"
    chmod +x "${bin}"
  done
)

echo "==> Running built-in self-tests ..."
# The plugins' self-tests need a running daemon (v0.5.0), so they are only version-checked here;
# scripts/plugin_self_test.sh runs them against a gateway.
for bin in $BINS; do
  case "$bin" in
    parvault)
      "${TMP_DIR}/${bin}" gateway self-test
      ;;
    parvault-seed)
      "${TMP_DIR}/${bin}" self-test
      ;;
    *)
      "${TMP_DIR}/${bin}" --version
      ;;
  esac
done

for bin in $BINS; do
  if [ -w "$INSTALL_DIR" ]; then
    mv "${TMP_DIR}/${bin}" "${INSTALL_DIR}/${bin}"
  else
    sudo mv "${TMP_DIR}/${bin}" "${INSTALL_DIR}/${bin}"
  fi
done

echo "==> Installed ${BINS} to ${INSTALL_DIR}!"
