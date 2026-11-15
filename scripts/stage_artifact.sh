#!/usr/bin/env bash
# ==============================================================================
# stage_artifact.sh — Build, Resolve, Stage and Record One Binary (Provenance)
# ==============================================================================
# The only supported way for a gate script to stage a binary. It builds the
# binary with cargo (`--locked`), takes the executable path from cargo's JSON
# messages (so CARGO_TARGET_DIR, --target and --profile are honoured), copies
# it to --dest (optionally stripping it), and prints one provenance line:
#
#   GATE-ARTIFACT bin=<bin> sha256=<staged hex> src_sha256=<built hex>
#                 commit=<sha>[-dirty] pinned=<crate|none> srcdir=<source>
#                 strip=<tool|none> cache=<hit|miss|off> src=<exe> dest=<dest>
# Each value is percent-encoded: '%' %25, space %20, tab %09, CR %0D, LF %0A.
# Hashes read stdin: sha256sum escapes a file name holding a backslash, LF or CR.
#
# srcdir is a directory (working tree), git:<url> (cargo install at the pin)
# or archive:<checkout>@<sha> (git archive of the pinned commit). The line is
# also appended to "$GATES_SENTINEL_DIR/artifacts" when that is set, so
# run_enforcement_gates.sh can verify it.
#
# Sources:
#   --src <dir>                     working tree (default: current directory)
#   --src <checkout> --rev <sha>    git archive of <sha>; checkout is untouched
#   --git <url> --rev <sha>         cargo install --git at <sha>
# --rev needs --lock <Cargo.lock> --lock-crate <crate>, and <sha> must equal
# the lock pin. A plain --src with --lock-crate must be clean and at the pin.
#
# Format and rules: ../references/enforcement_gates.md
# Exit codes: 0 staged, 2 any error (nothing is staged on error).
# ==============================================================================

set -euo pipefail

BIN=""
DEST=""
SRC="."
PACKAGE=""
PROFILE=""
TARGET=""
LOCK=""
LOCK_CRATE=""
GIT_URL=""
GIT_REV=""
CACHE=""
BUILD_DIR=""
STRIP=0

usage() {
  cat <<'EOF'
Usage: stage_artifact.sh --bin <name> --dest <path> [OPTIONS]

Options:
  --package <pkg>       cargo -p <pkg>
  --profile <name>      cargo --profile <name> (default: cargo's default)
  --target <triple>     cargo --target <triple>
  --src <dir>           Directory to build in (default: current directory)
  --git <url>           Build a lock-pinned crate with cargo install --git
  --rev <sha>           With --git or --src: the pinned commit to build
  --lock <Cargo.lock>   With --lock-crate: lock file that pins the source
  --lock-crate <crate>  Crate whose git pin the source must match
  --cache <dir>         Reuse pinned builds (--rev modes), verified by hash
  --build-dir <dir>     Disk directory for external builds (--rev modes): the
                        archive tree, the install root and the cargo target.
                        Created if missing; only the helper's own temporary
                        subdirectories are removed, never the directory itself.
  --strip               Strip the staged copy before recording its sha256.
                        STRIP_TOOL (default: strip) must be a command name on
                        PATH named strip or <prefix>-strip, outside the repo.
  -h, --help            Show this help message and exit.
EOF
}

die() {
  echo "ERROR: stage_artifact.sh: $*" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin|--dest|--package|--profile|--target|--src|--lock|--lock-crate|--git|--rev|--cache|--build-dir)
      [[ $# -ge 2 ]] || die "$1 requires an argument."
      case "$1" in
        --bin) BIN="$2" ;;
        --dest) DEST="$2" ;;
        --package) PACKAGE="$2" ;;
        --profile) PROFILE="$2" ;;
        --target) TARGET="$2" ;;
        --src) SRC="$2" ;;
        --lock) LOCK="$2" ;;
        --lock-crate) LOCK_CRATE="$2" ;;
        --git) GIT_URL="$2" ;;
        --rev) GIT_REV="$2" ;;
        --cache) CACHE="$2" ;;
        --build-dir) BUILD_DIR="$2" ;;
      esac
      shift 2
      ;;
    --strip) STRIP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "Unknown argument: $1" ;;
  esac
done

[[ -n "$BIN" && -n "$DEST" ]] || { usage >&2; die "--bin and --dest are required."; }
[[ -z "$LOCK" && -z "$LOCK_CRATE" ]] || [[ -n "$LOCK" && -n "$LOCK_CRATE" ]] \
  || die "--lock and --lock-crate must be given together."
[[ -z "$GIT_URL" || -n "$GIT_REV" ]] || die "--git needs --rev."
[[ -z "$GIT_REV" || -n "$LOCK_CRATE" ]] || die "--rev needs --lock and --lock-crate (the rev must be the pin)."
[[ -z "$CACHE" || -n "$GIT_REV" ]] || die "--cache is only for pinned builds (--rev)."
[[ -n "$GIT_URL" || -d "$SRC" ]] || die "--src is not a directory: $SRC"
command -v python3 >/dev/null 2>&1 || die "python3 is required."
command -v cargo >/dev/null 2>&1 || die "cargo is required (not on PATH)."

WORKDIR="$(mktemp -d)" || die "mktemp failed."
EXT_TMP=""  # the helper's own subdirectory of --build-dir, removed on exit
trap 'rm -rf "$WORKDIR" ${EXT_TMP:+"$EXT_TMP"}' EXIT
trap 'exit 130' INT TERM HUP  # signals exit through the EXIT trap, so cleanup runs

# --strip: a PATH command named strip or <prefix>-strip, never a path or a
# file inside the repository or the source tree.
STRIP_BIN="none"
if [[ "$STRIP" -eq 1 ]]; then
  STRIP_NAME="${STRIP_TOOL:-strip}"
  [[ "$STRIP_NAME" != */* ]] || die "STRIP_TOOL must be a command name on PATH, not a path: $STRIP_NAME"
  [[ "$STRIP_NAME" =~ (^|-)strip$ ]] || die "STRIP_TOOL must be named strip or <prefix>-strip: $STRIP_NAME"
  STRIP_BIN="$(type -P "$STRIP_NAME")" || die "STRIP_TOOL '$STRIP_NAME' is not on PATH"
  STRIP_BIN="$(realpath "$STRIP_BIN")" || die "cannot resolve $STRIP_NAME"
  for root in "$(git rev-parse --show-toplevel 2>/dev/null || true)" \
              "$( [[ -n "$GIT_URL" ]] || git -C "$SRC" rev-parse --show-toplevel 2>/dev/null || true)"; do
    if [[ -n "$root" && "$STRIP_BIN" == "$(realpath "$root")"/* ]]; then
      die "STRIP_TOOL resolves inside a repository ($STRIP_BIN); use a system strip."
    fi
  done
fi

PIN=""
if [[ -n "$LOCK_CRATE" ]]; then
  [[ -f "$LOCK" ]] || die "lock file not found: $LOCK"
  PIN="$(python3 - "$LOCK" "$LOCK_CRATE" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
pins = set()
for block in text.split("[[package]]")[1:]:
    name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
    source = re.search(r'^source\s*=\s*"git\+[^"#]*#([0-9a-f]{7,40})"', block, re.M)
    if name and name.group(1) == sys.argv[2] and source:
        pins.add(source.group(1))
if len(pins) != 1:
    sys.exit(f"expected exactly one git pin for '{sys.argv[2]}', found {len(pins)}")
print(pins.pop())
PY
)" || die "cannot read the git pin of '$LOCK_CRATE' from $LOCK"
fi
if [[ -n "$GIT_REV" ]]; then
  [[ "$GIT_REV" =~ ^[0-9a-f]{7,40}$ ]] || die "--rev must be a commit sha, got '$GIT_REV'"
  [[ "$PIN" == "$GIT_REV"* || "$GIT_REV" == "$PIN"* ]] || die "--rev $GIT_REV is not the $LOCK pin of $LOCK_CRATE ($PIN)."
fi

# cargo_build <dir>: build --bin in <dir>; sets EXE from cargo's JSON output.
cargo_build() {
  local args=(build --locked --message-format=json-render-diagnostics --bin "$BIN")
  [[ -z "$PACKAGE" ]] || args+=(-p "$PACKAGE")
  [[ -z "$PROFILE" ]] || args+=(--profile "$PROFILE")
  [[ -z "$TARGET" ]] || args+=(--target "$TARGET")
  (cd "$1" && if [[ -n "${EXT_TARGET:-}" ]]; then export CARGO_TARGET_DIR="$EXT_TARGET"; fi \
    && cargo "${args[@]}") > "$WORKDIR/build.json" || die "cargo ${args[*]} failed in $1"
  EXE="$(python3 - "$WORKDIR/build.json" "$BIN" <<'PY'
import json
import sys

exe = None
with open(sys.argv[1], encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") == "compiler-artifact" and msg.get("executable") \
                and msg.get("target", {}).get("name") == sys.argv[2]:
            exe = msg["executable"]
if not exe:
    sys.exit(f"cargo reported no executable for bin '{sys.argv[2]}'")
print(exe)
PY
)" || die "could not resolve the executable for '$BIN' from cargo's JSON output"
}

EXE=""
CACHE_STATE="off"
KEEP_SRC=0
if [[ -n "$GIT_URL" ]]; then
  COMMIT="$GIT_REV"
  SRCDIR="git:$GIT_URL"
elif [[ -n "$GIT_REV" ]]; then
  git -C "$SRC" rev-parse --git-dir >/dev/null 2>&1 || die "--src $SRC is not a git checkout"
  git -C "$SRC" cat-file -e "$GIT_REV^{commit}" 2>/dev/null || die "commit $GIT_REV is not present in $SRC"
  COMMIT="$(git -C "$SRC" rev-parse "$GIT_REV^{commit}")" || die "git rev-parse failed in $SRC"
  SRCDIR="archive:$(cd "$SRC" && pwd)@$COMMIT"
else
  # Working tree; a cross-repo source must be clean and at the pin.
  COMMIT="none"
  if git -C "$SRC" rev-parse --git-dir >/dev/null 2>&1; then
    COMMIT="$(git -C "$SRC" rev-parse HEAD)" || die "git rev-parse failed in $SRC"
    # Untracked files count: an untracked src/bin/*.rs would be built too.
    DIRTY="$(git -C "$SRC" status --porcelain --untracked-files=all)" || die "git status failed in $SRC"
    [[ -z "$DIRTY" ]] || COMMIT="$COMMIT-dirty"
  fi
  if [[ -n "$LOCK_CRATE" ]]; then
    [[ "$COMMIT" != *-dirty ]] || die "$SRC has uncommitted changes; build the pin with --rev $PIN instead."
    [[ "$COMMIT" == "$PIN"* ]] || die "$SRC is at $COMMIT, but $LOCK pins $LOCK_CRATE at $PIN (use --rev $PIN)."
  fi
  SRCDIR="$(cd "$SRC" && pwd)"
fi

# Optional cache for pinned builds, keyed by crate, full commit, target,
# profile and a hash of the build configuration (rustc and cargo versions,
# --package, and RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS / RUSTC* / CARGO_BUILD_* /
# CARGO_PROFILE_* / CARGO_TARGET_<triple>_* variables). A cached file is used
# only when its recorded hash still matches.
if [[ -n "$CACHE" ]]; then
  [[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "--cache needs a full 40-character commit (got $COMMIT)"
  RUSTC_V="$(rustc -vV)" || die "rustc -vV failed; cannot key the cache"
  CARGO_V="$(cargo -V)" || die "cargo -V failed; cannot key the cache"
  # grep finds nothing when no such variable is set; that is an empty set.
  ENV_CFG="$(env | LC_ALL=C grep -E '^(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|RUSTC[A-Z_]*|CARGO_BUILD_[A-Z_]*|CARGO_PROFILE_[A-Z_]*|CARGO_TARGET_[A-Z0-9_]+_[A-Z_]+)=' \
    | LC_ALL=C grep -v '^CARGO_TARGET_DIR=' | LC_ALL=C sort)" || ENV_CFG=""
  CFG="$(printf '%s\n%s\npackage=%s\n%s\n' "$RUSTC_V" "$CARGO_V" "$PACKAGE" "$ENV_CFG" | sha256sum | cut -c1-16)"
  KEYDIR="$CACHE/$LOCK_CRATE@$COMMIT+${TARGET:-host}+${PROFILE:-default}+$CFG"
  if [[ -f "$KEYDIR/$BIN" && -f "$KEYDIR/$BIN.sha256" ]] \
      && [[ "$(sha256sum < "$KEYDIR/$BIN" | cut -d' ' -f1)" == "$(cat "$KEYDIR/$BIN.sha256")" ]]; then
    EXE="$KEYDIR/$BIN"
    CACHE_STATE="hit"
  else
    CACHE_STATE="miss"
  fi
fi

# External builds (--rev modes) go to --build-dir when given: the archive tree
# and install root in a temporary subdirectory, the cargo target in
# <build-dir>/target so it is reused. Otherwise they use WORKDIR (TMPDIR).
EXT_BASE="$WORKDIR"
EXT_TARGET=""
if [[ -n "$BUILD_DIR" && -n "$GIT_REV" && -z "$EXE" ]]; then
  mkdir -p "$BUILD_DIR" || die "cannot create --build-dir $BUILD_DIR"
  BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"
  EXT_TMP="$(mktemp -d "$BUILD_DIR/stage-artifact.XXXXXX")" || die "cannot create a subdirectory in $BUILD_DIR"
  EXT_BASE="$EXT_TMP"
  EXT_TARGET="$BUILD_DIR/target"
fi

if [[ -z "$EXE" ]]; then
  if [[ -n "$GIT_URL" ]]; then
    ARGS=(install --locked --git "$GIT_URL" --rev "$GIT_REV" --root "$EXT_BASE/root" --bin "$BIN" "$LOCK_CRATE")
    [[ -z "$PROFILE" ]] || ARGS+=(--profile "$PROFILE")
    [[ -z "$TARGET" ]] || ARGS+=(--target "$TARGET")
    ( if [[ -n "$EXT_TARGET" ]]; then export CARGO_TARGET_DIR="$EXT_TARGET"; fi; cargo "${ARGS[@]}" ) >&2 \
      || die "cargo ${ARGS[*]} failed"
    EXE="$EXT_BASE/root/bin/$BIN"
    KEEP_SRC=1
  elif [[ -n "$GIT_REV" ]]; then
    mkdir -p "$EXT_BASE/archive"
    git -C "$SRC" archive --format=tar "$COMMIT" | tar -x -C "$EXT_BASE/archive" \
      || die "git archive of $COMMIT from $SRC failed"
    cargo_build "$EXT_BASE/archive"
    [[ "$EXE" != "$EXT_BASE"/* ]] || KEEP_SRC=1
  else
    cargo_build "$SRC"
  fi
  [[ -f "$EXE" ]] || die "expected executable $EXE does not exist"
  if [[ "$CACHE_STATE" == miss ]]; then
    mkdir -p "$KEYDIR" || die "cannot create cache $KEYDIR"
    cp "$EXE" "$KEYDIR/$BIN.tmp" && mv "$KEYDIR/$BIN.tmp" "$KEYDIR/$BIN" || die "cannot write cache $KEYDIR"
    sha256sum < "$KEYDIR/$BIN" | cut -d' ' -f1 > "$KEYDIR/$BIN.sha256" || die "cannot write cache hash"
    EXE="$KEYDIR/$BIN"
    KEEP_SRC=0
  fi
fi

mkdir -p "$(dirname "$DEST")" || die "cannot create $(dirname "$DEST")"
DEST="$(cd "$(dirname "$DEST")" && pwd)/$(basename "$DEST")"
# A build in WORKDIR is removed on exit; keep the built file next to the
# destination so the recorded src stays checkable.
if [[ "$KEEP_SRC" -eq 1 ]]; then
  cp "$EXE" "$DEST.src" || die "cannot keep the built binary at $DEST.src"
  EXE="$DEST.src"
fi
SRC_SUM="$(sha256sum < "$EXE" | cut -d' ' -f1)" || die "sha256sum failed"
cp "$EXE" "$DEST.tmp" || die "cannot copy $EXE to $DEST.tmp"
if [[ "$STRIP" -eq 1 ]]; then
  "$STRIP_BIN" "$DEST.tmp" || { rm -f "$DEST.tmp"; die "$STRIP_BIN failed on $DEST.tmp"; }
fi
mv "$DEST.tmp" "$DEST" || die "cannot move the staged binary to $DEST"
SUM="$(sha256sum < "$DEST" | cut -d' ' -f1)" || die "sha256sum failed"
# Values are percent-encoded ('%', space, tab, CR, LF), so the record
# splits on spaces whatever the paths hold.
pct() {
  local v="${1//%/%25}"
  v="${v// /%20}"; v="${v//$'\t'/%09}"; v="${v//$'\r'/%0D}"; v="${v//$'\n'/%0A}"
  printf '%s' "$v"
}
LINE="GATE-ARTIFACT bin=$(pct "$BIN") sha256=$SUM src_sha256=$SRC_SUM commit=$(pct "$COMMIT") pinned=$(pct "${LOCK_CRATE:-none}") srcdir=$(pct "$SRCDIR") strip=$(pct "$STRIP_BIN") cache=$CACHE_STATE src=$(pct "$EXE") dest=$(pct "$DEST")"
if [[ -n "${GATES_SENTINEL_DIR:-}" ]]; then
  printf '%s\n' "$LINE" >> "$GATES_SENTINEL_DIR/artifacts" || die "cannot record to $GATES_SENTINEL_DIR/artifacts"
fi
printf '%s\n' "$LINE"
