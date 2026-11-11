#!/usr/bin/env sh
# ParVault (parvault, parvault-seed, parvault-fuse) Static Binary Installer
set -eu

REPO="${PARVAULT_REPO:-Zbot21/parvault}"
INSTALL_DIR="${PARVAULT_INSTALL_DIR:-/usr/local/bin}"
VERSION="${PARVAULT_VERSION:-latest}"
BINS="${PARVAULT_BINS:-parvault parvault-seed parvault-fuse}"

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

if [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> Downloading ParVault static musl binaries (${BINS}) for ${TARGET} from ${BASE_URL} ..."
curl --proto '=https' --tlsv1.2 -fsSL "${BASE_URL}/SHA256SUMS" -o "${TMP_DIR}/SHA256SUMS"
for bin in $BINS; do
  curl --proto '=https' --tlsv1.2 -fsSL "${BASE_URL}/${bin}-${TARGET}" -o "${TMP_DIR}/${bin}-${TARGET}"
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

echo "==> Running built-in cryptographic, IPC & VFS self-tests ..."
for bin in $BINS; do
  case "$bin" in
    parvault)
      "${TMP_DIR}/${bin}" gateway self-test
      ;;
    parvault-seed|parvault-fuse)
      "${TMP_DIR}/${bin}" self-test
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
