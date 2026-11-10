#!/usr/bin/env sh
# ParVault (parvault + parvault-seed) Static Binary Installer
set -eu

REPO="${PARVAULT_REPO:-Zbot21/parvault}"
INSTALL_DIR="${PARVAULT_INSTALL_DIR:-/usr/local/bin}"

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

BASE_URL="https://github.com/${REPO}/releases/latest/download"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> Downloading ParVault static musl binaries for ${TARGET} from ${BASE_URL} ..."
curl --proto '=https' --tlsv1.2 -fsSL "${BASE_URL}/parvault-${TARGET}" -o "${TMP_DIR}/parvault-${TARGET}"
curl --proto '=https' --tlsv1.2 -fsSL "${BASE_URL}/parvault-seed-${TARGET}" -o "${TMP_DIR}/parvault-seed-${TARGET}"
curl --proto '=https' --tlsv1.2 -fsSL "${BASE_URL}/SHA256SUMS" -o "${TMP_DIR}/SHA256SUMS"

echo "==> Verifying SHA256SUMS ..."
(
  cd "$TMP_DIR"
  grep -E " (parvault-${TARGET}|parvault-seed-${TARGET})$" SHA256SUMS | sha256sum -c -
)

mv "${TMP_DIR}/parvault-${TARGET}" "${TMP_DIR}/parvault"
mv "${TMP_DIR}/parvault-seed-${TARGET}" "${TMP_DIR}/parvault-seed"
chmod +x "${TMP_DIR}/parvault" "${TMP_DIR}/parvault-seed"

echo "==> Running built-in cryptographic & Reed-Solomon self-test ..."
"${TMP_DIR}/parvault-seed" self-test

if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP_DIR}/parvault" "${INSTALL_DIR}/parvault"
  mv "${TMP_DIR}/parvault-seed" "${INSTALL_DIR}/parvault-seed"
else
  sudo mv "${TMP_DIR}/parvault" "${INSTALL_DIR}/parvault"
  sudo mv "${TMP_DIR}/parvault-seed" "${INSTALL_DIR}/parvault-seed"
fi

echo "==> Installed parvault and parvault-seed to ${INSTALL_DIR}!"
