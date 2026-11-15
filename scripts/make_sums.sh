#!/usr/bin/env bash
# Writes <dir>/SHA256SUMS for the assets in <dir> (L-17). The first line binds the tag and the
# build kind, and is covered by the signature, so a signed SHA256SUMS of an older tag cannot be
# served for a newer one: "# parvault <tag> <kind>". install.sh checks it.
# Usage: scripts/make_sums.sh <dir> <tag> <kind>
set -euo pipefail
[[ $# -eq 3 ]] || { echo "usage: make_sums.sh <dir> <tag> <kind>" >&2; exit 2; }
DIR=$1 TAG=$2 KIND=$3
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "make_sums.sh: bad tag '$TAG'" >&2; exit 2; }
[[ "$KIND" == dev ]] || { echo "make_sums.sh: only kind 'dev' exists (L-113)" >&2; exit 2; }
cd "$DIR"
shopt -s nullglob
files=()
for f in *; do
  case "$f" in SHA256SUMS|SHA256SUMS.sig) continue ;; esac
  [[ -f "$f" ]] && files+=("$f")
done
[[ ${#files[@]} -gt 0 ]] || { echo "make_sums.sh: no assets in $DIR" >&2; exit 2; }
{ echo "# parvault $TAG $KIND"; printf '%s\n' "${files[@]}" | LC_ALL=C sort | xargs -d '\n' sha256sum --; } > SHA256SUMS
cat SHA256SUMS
