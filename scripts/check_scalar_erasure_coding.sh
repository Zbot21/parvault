#!/usr/bin/env bash
# Scalar-only erasure coding, enforced in CI (L-102).
#
# Fails if a binary carries the SIMD GF(2^8) erasure-coding kernel of `reed-solomon-erasure`
# (its `simd-accel` feature: a C kernel and two 256x16 nibble tables). Two checks:
#
# 1. Table content (works on stripped binaries): the SIMD path needs `MUL_TABLE_LOW` and
#    `MUL_TABLE_HIGH`, whose rows lie contiguous in memory. The scalar `MUL_TABLE` holds the same
#    products with a different layout (row stride 256, high nibbles at stride 16), so a contiguous
#    256-byte window of either nibble table appears only when the SIMD tables are linked.
# 2. Symbols (when the binary has a symbol table): no `MUL_TABLE_LOW`, `MUL_TABLE_HIGH` or
#    `reedsolomon_gal_mul*` symbol, and no byte-shuffle table-lookup instruction (`pshufb` /
#    `vpshufb` on x86_64, `tbl` on aarch64) inside the erasure-coding functions only, so unrelated
#    crypto code does not trip it.
# 3. Dependencies (`--cargo-lock`): checks 1 and 2 know only the `reed-solomon-erasure` kernel, so
#    a SIMD GF(2^8) kernel from another crate (`reed-solomon-simd`, `reed-solomon-novelpoly`, a fork
#    under a new name or source) would pass them. `Cargo.lock` may hold no erasure-coding or GF
#    crate except `reed-solomon-erasure` from crates.io (list and reasons in `DENIED_CRATES`).
#
# Usage: scripts/check_scalar_erasure_coding.sh [--require-symbols] [--expect-simd] [--insn-only]
#                                               [--cargo-lock <Cargo.lock>] [<binary>...]
#   --require-symbols  fail (exit 2) on a binary without a symbol table instead of running only
#                      check 1 (use on an unstripped build so check 2 cannot be skipped)
#   --expect-simd      invert: pass only if every binary is flagged by every check that ran
#                      (the CI non-vacuity run on a deliberately SIMD-enabled build)
#   --insn-only        run only the scoped instruction scan of check 2 (no table or symbol-name
#                      check; implies --require-symbols), so CI can show that scan alone flags a
#                      SIMD build; otherwise the symbol-name check answers first
#   --cargo-lock FILE  run check 3 on FILE (binaries are then optional)
# Env: NM, OBJDUMP (default `nm`, `objdump`; set them for a cross target, e.g. llvm-objdump).
# Exit: 0 pass, 1 SIMD erasure coding found (or, with --expect-simd, not found), 2 usage/tool error.
set -euo pipefail

REQUIRE_SYMBOLS=0
EXPECT_SIMD=0
INSN_ONLY=0
CARGO_LOCK=""
BINS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-symbols) REQUIRE_SYMBOLS=1; shift ;;
    --expect-simd) EXPECT_SIMD=1; shift ;;
    --insn-only) INSN_ONLY=1; REQUIRE_SYMBOLS=1; shift ;;
    --cargo-lock)
      [[ $# -ge 2 ]] || { echo "check_scalar_erasure_coding.sh: --cargo-lock needs a file" >&2; exit 2; }
      CARGO_LOCK=$2; shift 2 ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    -*) echo "check_scalar_erasure_coding.sh: unknown option $1" >&2; exit 2 ;;
    *) BINS+=("$1"); shift ;;
  esac
done
[[ ${#BINS[@]} -gt 0 || -n "$CARGO_LOCK" ]] || { echo "check_scalar_erasure_coding.sh: no binaries given" >&2; exit 2; }
if [[ -n "$CARGO_LOCK" && $EXPECT_SIMD -eq 1 ]]; then
  echo "check_scalar_erasure_coding.sh: --expect-simd applies to binaries, not --cargo-lock" >&2; exit 2
fi
NM=${NM:-nm}
OBJDUMP=${OBJDUMP:-objdump}
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }

# Check 3: crates that implement erasure coding or GF(2^8)/GF(2^16) arithmetic, any of which can
# carry its own SIMD kernel that checks 1 and 2 do not know. Only `reed-solomon-erasure` (built
# without `simd-accel`, which the CI feature-graph step checks) may be in the lock, and only from
# crates.io, so a patched or git fork under the same name is refused too. A name not in the list
# but matching DENIED_NAME_RE is refused as well, so a fork renamed `reed-solomon-erasure-x` or a new
# GF crate is caught before anyone reviews its kernel; extend the list when a new one is vetted.
DENIED_CRATES=(
  reed-solomon-simd        # SSSE3/AVX2/NEON GF(2^16) kernels (Leopard-RS port)
  reed-solomon-novelpoly   # AVX GF(2^16) FFT kernels
  reed-solomon-16          # SIMD GF(2^16) (predecessor of reed-solomon-simd)
  reed-solomon             # a second Reed-Solomon implementation
  reed-solomon-erasure-simd
  leopard-codec            # Leopard-RS GF(2^8)/GF(2^16) with SIMD
  raptorq                  # RaptorQ fountain code, SIMD GF(256) octet math
  isal-rs isa-l erasure-isa-l  # Intel ISA-L bindings (assembly GF(2^8) kernels)
  galois_2p8 gf256 g2p galois_field gf2_8 # GF(2^8) arithmetic crates (gf256 has SIMD)
  zfec-rs                  # zfec erasure code
)
DENIED_NAME_RE='(reed[-_]?solomon|galois|^gf[-_]?(2|256)|erasure|raptor|^isa[-_]?l|leopard|fec$|^zfec)'
dependency_check() {
  python3 -I - "$1" "$DENIED_NAME_RE" "${DENIED_CRATES[@]}" <<'PY'
import re, sys
lock, name_re, denied = sys.argv[1], re.compile(sys.argv[2]), set(sys.argv[3:])
ALLOWED = "reed-solomon-erasure"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
pkgs, cur = [], None
for line in open(lock, encoding="utf-8"):
    line = line.strip()
    if line == "[[package]]":
        cur = {}; pkgs.append(cur)
    elif cur is not None and (m := re.match(r'^(name|version|source) = "(.*)"$', line)):
        cur[m.group(1)] = m.group(2)
if not pkgs:
    print(f"error no [[package]] entries in {lock}"); sys.exit(0)
bad = []
for p in pkgs:
    n = p.get("name", "")
    if n == ALLOWED:
        if p.get("source") != CRATES_IO:
            bad.append(f"{n} {p.get('version')} from {p.get('source', 'a path')} (only crates.io)")
    elif n in denied or name_re.search(n):
        bad.append(f"{n} {p.get('version')}")
print("found " + "; ".join(bad) if bad else "clean")
PY
}

# Check 1: prints "found" or "clean".
table_content_check() {
  python3 -I - "$1" <<'PY'
import sys
POLY = 29  # reed-solomon-erasure GENERATING_POLYNOMIAL (x^8 + x^4 + x^3 + x^2 + 1)
log = [0] * 256
exp = [0] * 510
b = 1
for i in range(255):
    log[b] = i
    b <<= 1
    if b >= 256:
        b = (b - 256) ^ POLY
for i in range(1, 256):
    exp[log[i]] = i
    exp[log[i] + 255] = i
def mul(a, c):
    return 0 if a == 0 or c == 0 else exp[log[a] + log[c]]
low = bytes(mul(a, n) for a in range(16, 32) for n in range(16))
high = bytes(mul(a, n << 4) for a in range(16, 32) for n in range(16))
data = open(sys.argv[1], "rb").read()
print("found" if (low in data or high in data) else "clean")
PY
}

# Check 2: prints "nosym", "found <why>" or "clean".
symbol_check() {
  local bin=$1 syms
  if ! syms=$("$NM" -C --defined-only -S "$bin" 2>/dev/null) || [[ -z "$syms" ]]; then
    echo nosym; return
  fi
  local named=""
  [[ $INSN_ONLY -eq 1 ]] || named=$(grep -E '(^|[^A-Za-z_])(MUL_TABLE_LOW|MUL_TABLE_HIGH|reedsolomon_gal_mul[A-Za-z_]*)($|[^A-Za-z_])' <<<"$syms" | head -3 || true)
  if [[ -n "$named" ]]; then
    echo "found symbol: $(head -1 <<<"$named" | awk '{print $NF}')"; return
  fi
  local arch insn
  arch=$("$OBJDUMP" -f "$bin" 2>/dev/null | sed -n 's/^architecture: \([^,]*\).*/\1/p')
  case "$arch" in
    *aarch64*) insn='[[:space:]]tbl[[:space:]]' ;;
    *x86-64*|*x86_64*|*i386*) insn='[[:space:]]v?pshufb[[:space:]]' ;;
    *) echo "unknown architecture '$arch' in $bin" >&2; echo error; return ;;
  esac
  # Function symbols (with size) of the erasure-coding code: the crate and our sharding wrapper.
  local hits=""
  while read -r addr size _type name; do
    local start=$((16#$addr)) stop=$((16#$addr + 16#$size))
    if "$OBJDUMP" -d --no-show-raw-insn --start-address="$start" --stop-address="$stop" "$bin" 2>/dev/null \
      | grep -Eq "$insn"; then
      hits="$name"; break
    fi
  done < <(awk '$3 ~ /^[tTwW]$/ && NF >= 4' <<<"$syms" \
    | grep -E 'reed_solomon_erasure::|sharding::reed_solomon::|reedsolomon_' || true)
  if [[ -n "$hits" ]]; then echo "found shuffle in: $hits"; else echo clean; fi
}

status=0
if [[ -n "$CARGO_LOCK" ]]; then
  [[ -f "$CARGO_LOCK" ]] || { echo "check_scalar_erasure_coding.sh: no such file $CARGO_LOCK" >&2; exit 2; }
  d=$(dependency_check "$CARGO_LOCK")
  case "$d" in
    clean) echo "[PASS] $CARGO_LOCK: no erasure-coding or GF crate but reed-solomon-erasure (crates.io)" ;;
    found*) echo "[FAIL] $CARGO_LOCK: denied erasure-coding/GF dependency: ${d#found }"; status=1 ;;
    *) echo "[ERROR] $CARGO_LOCK: ${d#error }" >&2; exit 2 ;;
  esac
fi
for bin in "${BINS[@]}"; do
  [[ -f "$bin" ]] || { echo "check_scalar_erasure_coding.sh: no such file $bin" >&2; exit 2; }
  if [[ $INSN_ONLY -eq 1 ]]; then t=skipped; else t=$(table_content_check "$bin"); fi
  s=$(symbol_check "$bin")
  [[ "$s" == error ]] && exit 2
  if [[ "$s" == nosym && $REQUIRE_SYMBOLS -eq 1 ]]; then
    echo "[ERROR] $bin: no symbol table (--require-symbols)" >&2; exit 2
  fi
  flagged=0; total=1
  [[ $INSN_ONLY -eq 1 ]] && total=0
  [[ "$t" == found ]] && flagged=$((flagged + 1))
  if [[ "$s" != nosym ]]; then
    total=$((total + 1))
    [[ "$s" == found* ]] && flagged=$((flagged + 1))
  fi
  summary="tables=$t symbols=${s}"
  if [[ $EXPECT_SIMD -eq 1 ]]; then
    if [[ $flagged -eq $total ]]; then echo "[PASS] $bin: SIMD build detected ($summary)"
    else echo "[FAIL] $bin: SIMD build not detected by every check ($summary)"; status=1; fi
  else
    if [[ $flagged -eq 0 ]]; then echo "[PASS] $bin: scalar-only erasure coding ($summary)"
    else echo "[FAIL] $bin: SIMD GF(2^8) erasure coding linked ($summary)"; status=1; fi
  fi
done
exit $status
