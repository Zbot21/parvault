#!/usr/bin/env bash
# Deterministic router-SoC bundle (L-17): fixed order, mtime, owner and modes, and no gzip name
# or time, so the same commit gives the same bytes. Needs GNU tar and SOURCE_DATE_EPOCH.
# Usage: scripts/make_bundle.sh <out.tar.gz>
set -euo pipefail
[[ $# -eq 1 ]] || { echo "usage: make_bundle.sh <out.tar.gz>" >&2; exit 2; }
[[ -n "${SOURCE_DATE_EPOCH:-}" ]] || { echo "make_bundle.sh: SOURCE_DATE_EPOCH is not set" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
OUTF=$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/pv-bundle.XXXXXX"); trap 'rm -rf "$STAGE"' EXIT
# Flat layout, as before: parvault-router.toml, parvault-nas.procd, prplos-lxc-manifest.json.
install -m 0644 "$ROOT/deploy/router-soc/parvault-router.toml" "$STAGE/parvault-router.toml"
install -m 0644 "$ROOT/deploy/router-soc/parvault-nas.procd" "$STAGE/parvault-nas.procd"
install -m 0644 "$ROOT/deploy/prplos-lxc-manifest.json" "$STAGE/prplos-lxc-manifest.json"
LC_ALL=C tar --sort=name --format=gnu --mtime="@$SOURCE_DATE_EPOCH" \
  --owner=0 --group=0 --numeric-owner -C "$STAGE" -cf - \
  parvault-nas.procd parvault-router.toml prplos-lxc-manifest.json | gzip -9 -n > "$OUTF"
