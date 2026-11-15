#!/usr/bin/env bash
# Reproducible static musl build of the shipped binaries (L-17). This is the one place that sets
# the release build flags: path remapping for rustc, the C prefix map, the C compiler and linker
# per target, and SOURCE_DATE_EPOCH. release.yml and repro-check.yml run it inside the build image
# (deploy/Dockerfile.build); scripts/repro_proof.sh runs it twice in two directories and compares.
#
# Usage: scripts/build_release.sh --target <x86_64|aarch64>-unknown-linux-musl --out <dir>
#                                 [--kind dev] [--bundle] [--image] [bin...]
# Outputs <out>/<bin>-<target>-<kind>; with --bundle, <out>/parvault-router-soc-bundle-<kind>.tar.gz;
# with --image (all five binaries), the container archive <out>/parvault-image-<amd64|arm64>-<kind>.tar (B-131).
# Every v0.5.x artifact is a dev build (L-113); there is no release kind yet.
set -euo pipefail
TARGET=""; OUT=""; KIND=dev; BUNDLE=0; IMAGE=0; BINS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --kind) KIND=$2; shift 2 ;;
    --bundle) BUNDLE=1; shift ;;
    --image) IMAGE=1; shift ;;
    -*) echo "build_release.sh: unknown flag $1" >&2; exit 2 ;;
    *) BINS+=("$1"); shift ;;
  esac
done
[[ -n "$TARGET" && -n "$OUT" ]] || { echo "build_release.sh: --target and --out are required" >&2; exit 2; }
[[ "$KIND" == dev ]] || { echo "build_release.sh: only --kind dev exists (L-113); release builds start with the owner key" >&2; exit 2; }
[[ ${#BINS[@]} -gt 0 ]] || BINS=(parvault parvault-seed parvault-fuse parvault-sync parvault-status)
# Flags come only from here: a caller's RUSTFLAGS would replace or mix with them.
for v in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS; do
  [[ -z "${!v:-}" ]] || { echo "build_release.sh: unset $v; this script sets the build flags" >&2; exit 2; }
done

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
# v0.5.4 (docs/METRICS.md): nothing in the caller's environment or a cargo config may turn debug
# assertions on (or set codegen flags) for a shipped build. Checked before this script sets its
# own path-remap flags below.
bash "$ROOT/scripts/check_release_build_env.sh" "$ROOT" || { echo "build_release.sh: release build environment refused" >&2; exit 2; }
CARGO_HOME_DIR=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
mkdir -p "$CARGO_TARGET_DIR" "$OUT"
TDIR=$(cd "$CARGO_TARGET_DIR" && pwd -P)
OUT=$(cd "$OUT" && pwd -P)
# rustc, cargo and the linker ignore SOURCE_DATE_EPOCH; tar and gzip use it for the bundle.
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct)
fi
export SOURCE_DATE_EPOCH

case "$TARGET" in
  x86_64-unknown-linux-musl)  CC=musl-gcc; LD=x86_64-linux-gnu-gcc; AR=ar ;;
  aarch64-unknown-linux-musl) CC=aarch64-linux-gnu-gcc; LD=aarch64-linux-gnu-gcc; AR=aarch64-linux-gnu-ar ;;
  *) echo "build_release.sh: unsupported target $TARGET" >&2; exit 2 ;;
esac
for t in "$CC" "$LD" "$AR"; do
  command -v "$t" >/dev/null || { echo "build_release.sh: $t not found (use deploy/Dockerfile.build)" >&2; exit 2; }
done
T_UP=$(tr 'a-z-' 'A-Z_' <<<"$TARGET"); T_LO=${TARGET//-/_}
# One explicit C compiler and linker per target. C (ring) builds against musl headers on x86_64
# (musl-gcc) and with the GNU cross gcc on aarch64; rustc links with its self-contained musl CRT
# and gcc as the driver on both.
export "CARGO_TARGET_${T_UP}_LINKER=$LD" "CC_${T_LO}=$CC" "AR_${T_LO}=$AR"

# Paths that reach the binary: the checkout, the registry sources under CARGO_HOME, and OUT_DIRs
# under the target dir. On a match rustc applies the last remap given, so the most specific
# prefix (target dir, which may sit inside the checkout) comes last.
remap=("$ROOT=/build/parvault" "$CARGO_HOME_DIR=/build/cargo" "$TDIR=/build/target")
rf=(); cf=""
for m in "${remap[@]}"; do rf+=("--remap-path-prefix=$m"); cf+=" -ffile-prefix-map=$m"; done
CARGO_ENCODED_RUSTFLAGS=$(IFS=$'\x1f'; echo "${rf[*]}")
export CARGO_ENCODED_RUSTFLAGS "CFLAGS_${T_LO}=${cf# }"

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/pv-build.XXXXXX"); trap 'rm -rf "$STAGE"' EXIT
# The soc profile strips symbols (Cargo.toml); there is no second strip.
bash "$ROOT/scripts/build_bins.sh" --profile soc --target "$TARGET" --out "$STAGE" "${BINS[@]}"
built=()
for b in "${BINS[@]}"; do
  install -m 0755 "$STAGE/$b-$TARGET" "$OUT/$b-$TARGET-$KIND"; built+=("$OUT/$b-$TARGET-$KIND")
done
bash "$ROOT/scripts/check_scalar_erasure_coding.sh" "${built[@]}"   # L-102
bash "$ROOT/scripts/check_no_insecure_metrics.sh" "${built[@]}"     # v0.5.4, docs/METRICS.md
if [[ $IMAGE -eq 1 ]]; then
  case "$TARGET" in x86_64-*) arch=amd64 ;; aarch64-*) arch=arm64 ;; esac
  bash "$ROOT/scripts/make_dev_image.sh" --arch "$arch" --bins "$OUT" --target "$TARGET" \
    --out "$OUT/parvault-image-$arch-$KIND.tar"
fi
if [[ $BUNDLE -eq 1 ]]; then bash "$ROOT/scripts/make_bundle.sh" "$OUT/parvault-router-soc-bundle-$KIND.tar.gz"; fi
echo "build_release.sh: $TARGET ($KIND, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH):"
(cd "$OUT" && sha256sum -- *-"$KIND"*)
