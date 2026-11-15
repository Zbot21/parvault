#!/usr/bin/env bash
# Signs a DEV build's SHA256SUMS with the dev key (L-110, L-113), then verifies the signature.
# Run by the Lead on the desktop only: the private key never goes to CI, GitHub or the box.
# Usage: scripts/sign_dev_build.sh <dist-dir>     (writes <dist-dir>/SHA256SUMS.sig)
# Key: $PARVAULT_DEV_SIGNING_KEY, default ~/.ssh/parvault_dev_signing_ed25519.
set -euo pipefail
[[ $# -eq 1 ]] || { echo "usage: sign_dev_build.sh <dist-dir>" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
DIR=$1 SUMS=$1/SHA256SUMS
KEY=${PARVAULT_DEV_SIGNING_KEY:-$HOME/.ssh/parvault_dev_signing_ed25519}
PRINCIPAL=parvault-dev NAMESPACE=parvault-dev-build
SIGNERS="$ROOT/security/dev-allowed-signers"
[[ -f "$SUMS" ]] || { echo "sign_dev_build.sh: no $SUMS" >&2; exit 1; }
[[ -f "$KEY" ]] || { echo "sign_dev_build.sh: no key at $KEY" >&2; exit 1; }
head=$(head -n1 "$SUMS")
[[ "$head" =~ ^#\ parvault\ v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?\ dev$ ]] \
  || { echo "sign_dev_build.sh: first line '$head' is not '# parvault <tag> dev'; the dev key signs only dev builds" >&2; exit 1; }
# Every listed asset that is present must match before anything is signed.
(cd "$DIR" && grep -v '^#' SHA256SUMS | sha256sum -c --ignore-missing --strict -)
# The key must be the one in dev-allowed-signers, not just any key.
pub=$(ssh-keygen -y -f "$KEY" | awk '{print $1" "$2}')
grep -v '^#' "$SIGNERS" | grep -qF "$pub" || { echo "sign_dev_build.sh: $KEY is not the key in $SIGNERS" >&2; exit 1; }
# v0.5.4 (docs/METRICS.md): no signed binary carries the debug insecure metrics listener. Every
# listed binary must be present and is checked (marker, and --version --verbose where it runs).
mapfile -t listed < <(grep -v '^#' "$SUMS" | awk '{print $2}' | sed 's/^\*//' | grep -E -- '-musl-dev$')
[[ ${#listed[@]} -gt 0 ]] || { echo "sign_dev_build.sh: SHA256SUMS lists no binary" >&2; exit 1; }
bins=(); for f in "${listed[@]}"; do bins+=("$DIR/$f"); done
bash "$ROOT/scripts/check_no_insecure_metrics.sh" "${bins[@]}" \
  || { echo "sign_dev_build.sh: a listed binary failed the insecure-metrics check; nothing signed" >&2; exit 1; }
rm -f "$SUMS.sig"
ssh-keygen -q -Y sign -f "$KEY" -n "$NAMESPACE" "$SUMS"
ssh-keygen -Y verify -f "$SIGNERS" -I "$PRINCIPAL" -n "$NAMESPACE" -s "$SUMS.sig" < "$SUMS"
echo "sign_dev_build.sh: signed ${head#\# } -> $SUMS.sig (DEV build, principal $PRINCIPAL, namespace $NAMESPACE)"
