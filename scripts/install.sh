#!/usr/bin/env sh
# ParVault (parvault, parvault-seed, parvault-fuse, parvault-sync, parvault-status) Static Binary Installer
set -eu

REPO="${PARVAULT_REPO:-Zbot21/parvault}"
# OpenWrt keeps binaries in /usr/bin, where the procd service (deploy/router-soc) runs them.
if [ -f /etc/openwrt_release ]; then
  DEFAULT_INSTALL_DIR=/usr/bin
else
  DEFAULT_INSTALL_DIR=/usr/local/bin
fi
INSTALL_DIR="${PARVAULT_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
# The default version is this release's own tag: every ParVault release is a pre-release, so
# GitHub has no "Latest" release to resolve. gen_metrics.sh fails if it differs from Cargo.toml's
# version, and release.yml fails if it differs from the tag. PARVAULT_VERSION=latest asks GitHub
# for its "Latest" release, which does not exist (404) while every release is a pre-release; once
# it does, the tag it names must be this script's own version or newer (no downgrade).
VERSION="${PARVAULT_VERSION:-v0.5.5}"
MIN_VERSION=v0.5.5   # equal to the default above (scripts/test_install.sh checks)
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
fi
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

refuse() { echo "REFUSED: $*" >&2; exit 1; }
is_tag() { printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; }
# 0 when tag $1 is older than tag $2 (both vX.Y.Z).
older_than() {
  a=${1#v}; b=${2#v}
  for _ in 1 2 3; do
    x=${a%%.*}; y=${b%%.*}
    [ "$x" -lt "$y" ] && return 0
    [ "$x" -gt "$y" ] && return 1
    a=${a#*.}; b=${b#*.}
  done
  return 1
}
# PARVAULT_VERSION=latest: resolve the tag GitHub calls Latest first, so SHA256SUMS is checked
# against a real tag below (an old signed SHA256SUMS cannot be served as "latest").
if [ "$VERSION" = "latest" ]; then
  LATEST_URL="https://api.github.com/repos/${REPO}/releases/latest"
  # scripts/test_install.sh serves its own answer; honoured only with a loopback PARVAULT_BASE_URL.
  if [ "$PROTO" = "=http" ] && [ -n "${PARVAULT_TEST_LATEST_URL:-}" ]; then LATEST_URL="$PARVAULT_TEST_LATEST_URL"; fi
  curl --proto "$PROTO" --tlsv1.2 -fsSL "$LATEST_URL" -o "${TMP_DIR}/latest.json" \
    || refuse "PARVAULT_VERSION=latest: no Latest release at ${LATEST_URL} (every ParVault release so far is a pre-release); set PARVAULT_VERSION to a tag"
  VERSION=$(grep -o '"tag_name" *: *"[^"]*"' "${TMP_DIR}/latest.json" | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/')
  is_tag "$VERSION" || refuse "PARVAULT_VERSION=latest: ${LATEST_URL} names no vX.Y.Z tag"
  if older_than "$VERSION" "$MIN_VERSION"; then
    refuse "Latest release ${VERSION} is older than this installer (${MIN_VERSION}); refusing a downgrade. Set PARVAULT_VERSION to a tag to install an older one on purpose"
  fi
  echo "==> Latest release: ${VERSION}"
fi
if [ -z "${BASE_URL:-}" ]; then
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

# Signing keys (L-113). Signatures are `ssh-keygen -Y sign` over SHA256SUMS (OpenSSH 8.1+).
# DEV builds: every v0.5.x artifact. Signed with the dev/test key, never trusted as a release;
# installed only with PARVAULT_ALLOW_DEV_BUILD=1. Same line as security/dev-allowed-signers.
DEV_PRINCIPAL=parvault-dev
DEV_NAMESPACE=parvault-dev-build
DEV_FINGERPRINT="SHA256:w3YrtCVqvG0hUxHHdnrlxuxg/X8LkeuUaZudDswGQ+A"
DEV_ALLOWED_SIGNERS='parvault-dev namespaces="parvault-dev-build" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICiFelo+GbGOK+cTOrayrTjMsc+FNPw7TkGyYJxj6RiS'
# RELEASE builds: none exist yet. They start with the owner's offline key (security/
# release-allowed-signers); while this is empty, nothing verifies as a release.
RELEASE_PRINCIPAL=parvault-release
RELEASE_NAMESPACE=parvault-release-build
RELEASE_ALLOWED_SIGNERS=''
printf '%s\n' "$DEV_ALLOWED_SIGNERS" > "${TMP_DIR}/dev-signers"
printf '%s\n' "$RELEASE_ALLOWED_SIGNERS" > "${TMP_DIR}/release-signers"
# scripts/test_install.sh swaps in throwaway keys; honoured only with a loopback PARVAULT_BASE_URL.
if [ "$PROTO" = "=http" ]; then
  if [ -n "${PARVAULT_TEST_DEV_SIGNERS:-}" ]; then cp "$PARVAULT_TEST_DEV_SIGNERS" "${TMP_DIR}/dev-signers"; fi
  if [ -n "${PARVAULT_TEST_RELEASE_SIGNERS:-}" ]; then cp "$PARVAULT_TEST_RELEASE_SIGNERS" "${TMP_DIR}/release-signers"; fi
fi

fetch() { curl --proto "$PROTO" --tlsv1.2 -fsSL "${BASE_URL}/$1" -o "${TMP_DIR}/$1"; }

echo "==> Downloading SHA256SUMS and SHA256SUMS.sig from ${BASE_URL} ..."
fetch SHA256SUMS
HAVE_SIG=1
fetch SHA256SUMS.sig 2>/dev/null || HAVE_SIG=0

# Which key signed it: dev, release, or nobody this script trusts.
SIGNED_KIND=""; UNVERIFIED=0
has_verifier() { command -v ssh-keygen >/dev/null 2>&1 && ssh-keygen '-?' 2>&1 | grep -q -- '-Y verify'; }
verify_as() {  # <signers file> <principal> <namespace>
  grep -q '^[^#]' "$1" || return 1
  ssh-keygen -Y verify -f "$1" -I "$2" -n "$3" -s "${TMP_DIR}/SHA256SUMS.sig" \
    < "${TMP_DIR}/SHA256SUMS" >/dev/null 2>&1
}
if [ "$HAVE_SIG" = 1 ]; then
  if has_verifier; then
    if verify_as "${TMP_DIR}/release-signers" "$RELEASE_PRINCIPAL" "$RELEASE_NAMESPACE"; then
      SIGNED_KIND=release
    elif verify_as "${TMP_DIR}/dev-signers" "$DEV_PRINCIPAL" "$DEV_NAMESPACE"; then
      SIGNED_KIND=dev
    else
      refuse "SHA256SUMS.sig does not verify against the ParVault release key or the dev key (${DEV_FINGERPRINT}); the sums or the signature were changed, or another key signed them"
    fi
    echo "==> SHA256SUMS signature verified (${SIGNED_KIND} key)"
  elif [ "${PARVAULT_REQUIRE_SIGNATURE:-0}" = 1 ]; then
    refuse "PARVAULT_REQUIRE_SIGNATURE=1 but no signature verifier: install OpenSSH 8.1+ (ssh-keygen -Y)"
  else
    # L-81: warn and continue; SHA-256 below still checks integrity, not origin. The first line's
    # tag and kind are unsigned here: the tag is still checked, and 'release' is refused below.
    UNVERIFIED=1
    echo "WARNING: cannot verify SHA256SUMS.sig: no ssh-keygen with -Y (OpenSSH 8.1+; OpenWrt ships dropbear)." >&2
    echo "WARNING: the build's origin, kind (dev/release) and tag are UNVERIFIED; continuing with SHA-256 integrity only." >&2
    echo "WARNING: verify on another machine with OpenSSH 8.1+:" >&2
    echo "WARNING:   curl -fsSLO https://raw.githubusercontent.com/${REPO}/main/security/dev-allowed-signers" >&2
    echo "WARNING:   ssh-keygen -Y verify -f dev-allowed-signers -I ${DEV_PRINCIPAL} -n ${DEV_NAMESPACE} -s SHA256SUMS.sig < SHA256SUMS" >&2
    echo "WARNING: it must report dev key ${DEV_FINGERPRINT}. Set PARVAULT_REQUIRE_SIGNATURE=1 to refuse instead." >&2
  fi
elif [ "${PARVAULT_ALLOW_UNSIGNED:-0}" = 1 ]; then
  echo "WARNING: no SHA256SUMS.sig: this build is UNSIGNED; installing because PARVAULT_ALLOW_UNSIGNED=1" >&2
else
  refuse "no SHA256SUMS.sig at ${BASE_URL}: unsigned build. Set PARVAULT_ALLOW_UNSIGNED=1 to install it anyway"
fi

# The signed first line binds the tag and the kind: '# parvault <tag> <kind>' (make_sums.sh).
HEADER=$(head -n 1 "${TMP_DIR}/SHA256SUMS")
case "$HEADER" in
  "# parvault "*) set -f; set -- $HEADER; set +f
    [ "$#" -eq 4 ] || refuse "malformed SHA256SUMS first line: ${HEADER}"
    H_TAG=${3:-}; H_KIND=${4:-} ;;
  *) H_TAG=""; H_KIND="" ;;
esac
if [ -z "$H_TAG" ]; then
  if [ -n "$SIGNED_KIND" ]; then
    refuse "signed SHA256SUMS has no '# parvault <tag> <kind>' first line"
  elif [ "$HAVE_SIG" = 1 ]; then
    refuse "SHA256SUMS has no '# parvault <tag> <kind>' first line, so its tag cannot be checked"
  fi
  echo "WARNING: unsigned SHA256SUMS has no '# parvault <tag> <kind>' first line: its tag is not checked" >&2
else
  if [ "$H_TAG" != "$VERSION" ]; then
    refuse "SHA256SUMS is for ${H_TAG}, not ${VERSION} (an older signed SHA256SUMS served for this tag)"
  fi
  case "$H_KIND" in dev|release) ;; *) refuse "SHA256SUMS first line names unknown kind '${H_KIND}'" ;; esac
  if [ -n "$SIGNED_KIND" ] && [ "$H_KIND" != "$SIGNED_KIND" ]; then
    refuse "SHA256SUMS says '${H_KIND}' but the ${SIGNED_KIND} key signed it"
  fi
  # Only the release key makes a release; an unverified or unsigned 'release' line proves nothing.
  if [ -z "$SIGNED_KIND" ] && [ "$H_KIND" = release ]; then
    refuse "SHA256SUMS says 'release' but no release signature was verified$([ "$UNVERIFIED" = 1 ] && echo ' (no ssh-keygen -Y here)')"
  fi
fi
KIND=${SIGNED_KIND:-$H_KIND}
SFX=""
if [ "$KIND" = dev ]; then
  SFX="-dev"
  if [ "${PARVAULT_ALLOW_DEV_BUILD:-0}" != 1 ]; then
    refuse "${H_TAG:-this} is a DEV build (dev/test key, not a release key; L-113). Set PARVAULT_ALLOW_DEV_BUILD=1 to install it"
  fi
  echo "==> This is a DEV build of ${H_TAG}: signed with the dev/test key, not a release. Installing because PARVAULT_ALLOW_DEV_BUILD=1."
fi

echo "==> Downloading ParVault static musl binaries (${BINS}) for ${TARGET} ..."
for bin in $BINS; do
  fetch "${bin}-${TARGET}${SFX}"
done

echo "==> Verifying SHA256SUMS ..."
(
  cd "$TMP_DIR"
  for bin in $BINS; do
    line=$(grep -E "^[0-9a-f]{64}  ${bin}-${TARGET}${SFX}\$" SHA256SUMS) \
      || { echo "${bin}-${TARGET}${SFX}: not listed in SHA256SUMS: FAILED" >&2; exit 1; }
    printf '%s\n' "$line" | sha256sum -c -
    mv "${bin}-${TARGET}${SFX}" "${bin}"
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

if [ "$KIND" = dev ]; then
  echo "==> Installed DEV build ${H_TAG} (${BINS}) to ${INSTALL_DIR}. Dev builds are for testing, not release use."
else
  echo "==> Installed ${BINS} to ${INSTALL_DIR}!"
fi
