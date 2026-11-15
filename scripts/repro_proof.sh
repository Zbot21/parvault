#!/usr/bin/env bash
# Reproducibility proof (L-17): builds HEAD twice from two exports at different paths, with
# different target dirs and CARGO_HOMEs, and compares every output byte for byte. On a mismatch it
# runs diffoscope (if installed) and fails.
# Usage: scripts/repro_proof.sh --target <triple> --work <dir> [--image <docker-image>] [--bundle]
#                               [--keep] [bin...]
# With --image, both builds run in that image (deploy/Dockerfile.build), as release.yml does.
# The matching outputs stay in <work>/a/out.
set -euo pipefail
TARGET=""; WORK=""; IMAGE=""; KEEP=0; EXTRA=(); BINS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET=$2; shift 2 ;;
    --work) WORK=$2; shift 2 ;;
    --image) IMAGE=$2; shift 2 ;;
    --bundle) EXTRA+=(--bundle); shift ;;
    --keep) KEEP=1; shift ;;
    -*) echo "repro_proof.sh: unknown flag $1" >&2; exit 2 ;;
    *) BINS+=("$1"); shift ;;
  esac
done
[[ -n "$TARGET" && -n "$WORK" ]] || { echo "repro_proof.sh: --target and --work are required" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
mkdir -p "$WORK"; WORK=$(cd "$WORK" && pwd -P)
SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct); export SOURCE_DATE_EPOCH
COMMIT=$(git -C "$ROOT" rev-parse HEAD)
# Two layouts that differ in every path the build sees.
declare -A SRC=([a]=a/src/parvault [b]=b/elsewhere/deeper/pv-checkout)
declare -A TGT=([a]=a/target [b]=b/t2)
declare -A CH=([a]=a/cargo-home [b]=b/other-cargo)
for s in a b; do
  rm -rf "${WORK:?}/$s"; mkdir -p "$WORK/${SRC[$s]}" "$WORK/${TGT[$s]}" "$WORK/${CH[$s]}" "$WORK/$s/out"
  git -C "$ROOT" archive "$COMMIT" | tar -x -C "$WORK/${SRC[$s]}"
done
# Native builds share the registry download cache but not the unpacked sources' path.
seed_registry() { [[ -d "${CARGO_HOME:-$HOME/.cargo}/registry/cache" ]] && mkdir -p "$1/registry" \
  && cp -r "${CARGO_HOME:-$HOME/.cargo}/registry/cache" "$1/registry/" 2>/dev/null || true; }
build() {  # <side>
  local s=$1
  if [[ -n "$IMAGE" ]]; then
    local m=/w$s   # a different mount point per side
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e SOURCE_DATE_EPOCH \
      -e CARGO_HOME="$m/${CH[$s]}" -e CARGO_TARGET_DIR="$m/${TGT[$s]}" \
      -v "$WORK:$m" -w "$m/${SRC[$s]}" "$IMAGE" \
      bash scripts/build_release.sh --target "$TARGET" --out "$m/$s/out" "${EXTRA[@]}" "${BINS[@]}"
  else
    seed_registry "$WORK/${CH[$s]}"
    (cd "$WORK/${SRC[$s]}" && env -u RUSTFLAGS CARGO_HOME="$WORK/${CH[$s]}" \
      CARGO_TARGET_DIR="$WORK/${TGT[$s]}" \
      bash scripts/build_release.sh --target "$TARGET" --out "$WORK/$s/out" "${EXTRA[@]}" "${BINS[@]}")
  fi
}
build a > "$WORK/a.log" 2>&1 || { tail -50 "$WORK/a.log" >&2; exit 1; }
build b > "$WORK/b.log" 2>&1 || { tail -50 "$WORK/b.log" >&2; exit 1; }
(cd "$WORK/a/out" && sha256sum -- * | LC_ALL=C sort -k2) > "$WORK/a.sums"
(cd "$WORK/b/out" && sha256sum -- * | LC_ALL=C sort -k2) > "$WORK/b.sums"
echo "repro_proof: commit $COMMIT, $TARGET, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH${IMAGE:+, image $IMAGE}"
echo "  a: $WORK/${SRC[a]} (target ${TGT[a]}, CARGO_HOME ${CH[a]})"
echo "  b: $WORK/${SRC[b]} (target ${TGT[b]}, CARGO_HOME ${CH[b]})"
cat "$WORK/a.sums"
if cmp -s "$WORK/a.sums" "$WORK/b.sums"; then
  echo "repro_proof: MATCH ($(wc -l < "$WORK/a.sums") files)"
  [[ $KEEP -eq 1 ]] || rm -rf "${WORK:?}/a/src" "${WORK:?}/b" "${WORK:?}/a/target" "${WORK:?}/a/cargo-home"
  exit 0
fi
echo "repro_proof: MISMATCH" >&2
diff "$WORK/a.sums" "$WORK/b.sums" >&2 || true
if command -v diffoscope >/dev/null; then
  for f in $(cd "$WORK/a/out" && ls); do
    cmp -s "$WORK/a/out/$f" "$WORK/b/out/$f" && continue
    diffoscope --text "$WORK/diffoscope-$f.txt" "$WORK/a/out/$f" "$WORK/b/out/$f" >/dev/null 2>&1 || true
    echo "diffoscope: $WORK/diffoscope-$f.txt" >&2
  done
else
  echo "repro_proof: diffoscope not installed; compare with cmp -l or install diffoscope" >&2
fi
exit 1
