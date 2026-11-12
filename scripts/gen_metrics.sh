#!/usr/bin/env bash
# ==============================================================================
# gen_metrics.sh: metrics generator for docs/metrics.txt
# ==============================================================================
# Default mode (used by `scripts/sync_doc_metrics.sh --generate`, run in CI):
#   prints `key = value` lines computed from the tree only: no network, no
#   cargo build, stable order. It prints:
#     - counts taken from the source (Kani harnesses, TLA+ specs, ADRs,
#       test functions)
#     - values derived from the static measured keys in docs/metrics.txt
#       (MiB from exact bytes, min-max ranges), so they cannot disagree.
#
# Fails closed: every value is computed and checked before anything is
# printed. An impossible value (empty, 0) exits 1 with a message on stderr
# and prints nothing on stdout, so --generate cannot write it into the docs.
#
# --measured [sizes|tlc] (opt-in, never run by CI; default both): re-runs the repository's existing
#   measurement commands and prints fresh values for the STATIC measured keys.
#   Review them, then copy them into the static section of docs/metrics.txt
#   with a new provenance comment (command + date). It runs:
#     - `cargo build --profile soc --target <t> --bin <b>` for both musl
#       targets, then `stat` -> size.<bin>.<arch>.bytes
#       (aarch64 needs CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER)
#     - TLC on every specs/*.tla (needs TLA2TOOLS_JAR) ->
#       tlc.generated.<Spec>, tlc.distinct.<Spec>, tlc.depth.<Spec> (store
#       only the depth keys a doc uses)
#   Benchmark, RSS and latency keys are min-max ranges over repeated runs of
#   parvault-bench and the self-tests, so they are re-measured by hand (see
#   the comments in docs/metrics.txt).
# ==============================================================================
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# 1234567 -> 1,234,567 (locale-independent)
group() { printf '%s' "$1" | rev | sed -E 's/([0-9]{3})/\1,/g; s/,$//' | rev; }
fail() { echo "gen_metrics.sh: $*" >&2; exit 1; }

if [[ "${1:-}" == "--measured" ]]; then
  what="${2:-all}"
  [[ "$what" == all || "$what" == sizes || "$what" == tlc ]] || fail "usage: --measured [sizes|tlc]"
  out=""
  if [[ "$what" != tlc ]]; then
    [[ -n "${CARGO_TARGET_DIR:-}" ]] || fail "--measured sizes needs CARGO_TARGET_DIR"
    for target in aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
      arch="${target%%-*}"
      for bin in parvault parvault-seed parvault-fuse parvault-sync; do
        cargo build -q --profile soc --target "$target" --bin "$bin" >&2
        bytes="$(stat -c %s "$CARGO_TARGET_DIR/$target/soc/$bin")"
        [[ "$bytes" =~ ^[1-9][0-9]*$ ]] || fail "no size for $bin ($target)"
        out+="size.$bin.$arch.bytes = $(group "$bytes") B"$'\n'
      done
    done
  fi
  if [[ "$what" != sizes ]]; then
    [[ -f "${TLA2TOOLS_JAR:-}" ]] || fail "--measured tlc needs TLA2TOOLS_JAR"
    meta="$(mktemp -d)"; trap 'rm -rf "$meta"' EXIT
    for spec in specs/*.tla; do
      [[ -f "$spec" ]] || fail "no specs/*.tla"
      name="$(basename "$spec" .tla)"
      log="$(cd specs && java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC -workers auto -cleanup \
        -metadir "$meta/$name" -config "$name.cfg" "$name.tla")" || fail "TLC failed on $name"
      line="$(grep -E '[0-9,]+ states generated, [0-9,]+ distinct states found' <<<"$log" | tail -1 || true)"
      [[ -n "$line" ]] || fail "no state counts in TLC output for $name"
      gen="$(sed -E 's/^([0-9,]+) states generated.*/\1/' <<<"$line" | tr -d ,)"
      dist="$(sed -E 's/.*generated, ([0-9,]+) distinct.*/\1/' <<<"$line" | tr -d ,)"
      depth="$(sed -nE 's/.*depth of the complete state graph search is ([0-9]+).*/\1/p' <<<"$log" | tail -1)"
      [[ -n "$depth" ]] || fail "no search depth in TLC output for $name"
      out+="tlc.generated.$name = $(group "$gen")"$'\n'"tlc.distinct.$name = $(group "$dist")"$'\n'
      out+="tlc.depth.$name = $depth"$'\n'
    done
  fi
  printf '%s' "$out"
  exit 0
fi
[[ $# -eq 0 ]] || fail "usage: gen_metrics.sh [--measured [sizes|tlc]]"

export LC_ALL=C

# --- Counts from the tree (each checked before any output) ---------------------
# count <regex> <file>...: matching lines across existing .rs files; a missing
# file is an error, not 0.
count() {
  local re="$1"; shift
  local f
  for f in "$@"; do [[ -f "$f" ]] || fail "missing file: $f"; done
  { grep -hE "$re" "$@" || true; } | wc -l
}
rs_under() { find "$1" -type f -name '*.rs' -print | sort; }
positive() { [[ "$2" =~ ^[1-9][0-9]*$ ]] || fail "$1 is '$2' (expected a positive count)"; }

kani_re='^\s*#\[kani::proof\]'
test_re='^\s*#\[(tokio::)?test(\(.*\))?\]'
mapfile -t src_rs < <(rs_under src)
mapfile -t test_rs < <(find tests -maxdepth 1 -type f -name '*.rs' -print | sort)
mapfile -t specs < <(find specs -maxdepth 1 -type f -name '*.tla' -print)
mapfile -t adrs < <(find docs/adr -maxdepth 1 -type f -name 'ADR-[0-9]*.md' -printf '%f\n' | grep -oE '^ADR-[0-9]+' | sort -t- -k2,2n)
[[ ${#src_rs[@]} -gt 0 ]] || fail "no src/**/*.rs"
[[ ${#test_rs[@]} -gt 0 ]] || fail "no tests/*.rs"

kani_total="$(count "$kani_re" "${src_rs[@]}")";                positive kani_harnesses "$kani_total"
kani_module="$(count "$kani_re" src/kani_proofs.rs)";            positive kani_harnesses_module "$kani_module"
kani_caps="$(count "$kani_re" src/capabilities.rs)";             positive kani_harnesses.capabilities "$kani_caps"
kani_aes="$(count "$kani_re" src/crypto/aes.rs)";                positive kani_harnesses.aes "$kani_aes"
kani_rs="$(count "$kani_re" src/sharding/reed_solomon.rs)";      positive kani_harnesses.reed_solomon "$kani_rs"
tla_specs="${#specs[@]}";                                        positive tla_specs "$tla_specs"
adr_count="${#adrs[@]}";                                         positive adr_count "$adr_count"
adr_last="${adrs[adr_count - 1]}"
[[ "$adr_last" =~ ^ADR-[0-9]+$ ]] || fail "adr_last is '$adr_last'"
[[ -f src/network/behaviour.rs ]] || fail "missing file: src/network/behaviour.rs"
wire_variants="$(awk '/^pub enum MeshWireRequest \{/{p=1;next} p&&/^\}/{exit} p' src/network/behaviour.rs | grep -cE '^    [A-Z][A-Za-z0-9]*\b' || true)"
positive wire_request_variants "$wire_variants"
tests_unit="$(count "$test_re" "${src_rs[@]}")";                 positive tests_unit "$tests_unit"
tests_int="$(count "$test_re" "${test_rs[@]}")";                 positive tests_integration "$tests_int"
tests_total=$((tests_unit + tests_int))

version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+].*)?$ ]] || fail "crate version is '$version'"

counts="crate_version_tag = v$version
kani_harnesses = $kani_total
kani_harnesses_module = $kani_module
kani_pass = $kani_total / $kani_total
kani_pass_compact = $kani_total/$kani_total
kani_harnesses.capabilities = $kani_caps
kani_harnesses.aes = $kani_aes
kani_harnesses.reed_solomon = $kani_rs
tla_specs = $tla_specs
wire_request_variants = $wire_variants
tla_pass = $tla_specs / $tla_specs
adr_count = $adr_count
adr_last = $adr_last
tests_unit = $tests_unit
tests_integration = $tests_int
tests_total = $tests_total
tests_pass = $tests_total / $tests_total"

# --- Values derived from static measured keys ----------------------------------
[[ -f docs/metrics.txt ]] || fail "missing docs/metrics.txt"
derived="$(python3 - docs/metrics.txt <<'PY'
import re, sys
static = {}
in_gen = False
for raw in open(sys.argv[1], encoding="utf-8"):
    s = raw.strip()
    if s.startswith("# >>> generated"): in_gen = True; continue
    if s.startswith("# <<< end generated"): in_gen = False; continue
    if in_gen or not s or s.startswith("#"): continue
    k, v = (x.strip() for x in s.split("=", 1))
    static[k] = v

def num(v):  # first number in a value, commas removed
    return float(re.search(r"[0-9][0-9,]*\.?[0-9]*", v).group(0).replace(",", ""))
def span(v):  # (low, high) of 'a–b unit' or 'a unit'
    nums = [float(x.replace(",", "")) for x in re.findall(r"[0-9][0-9,]*\.?[0-9]*", v.split(" ")[0])]
    return min(nums), max(nums)
out = []

# Binary sizes: MiB from exact bytes, then per-arch min-max ranges.
sizes = {}
for k, v in static.items():
    m = re.fullmatch(r"size\.([a-z-]+)\.(aarch64|x86_64)\.bytes", k)
    if m:
        mib = num(v) / 1048576
        sizes.setdefault(m.group(2), []).append(mib)
        out.append((f"size.{m.group(1)}.{m.group(2)}", f"{mib:.2f} MiB"))
BINS = ("parvault", "parvault-seed", "parvault-fuse", "parvault-sync")
missing = [f"size.{b}.{a}.bytes" for a in ("aarch64", "x86_64") for b in BINS
           if f"size.{b}.{a}.bytes" not in static]
if missing:
    sys.exit("missing static keys: " + ", ".join(missing))
for arch in ("aarch64", "x86_64"):
    v = sizes[arch]
    out.append((f"size.{arch}.range", f"{min(v):.2f}–{max(v):.2f} MiB"))
allsz = sizes["aarch64"] + sizes["x86_64"]
out.append(("size.all.range", f"{min(allsz):.2f}–{max(allsz):.2f} MiB"))

# Router-SoC peak VmHWM range (store / restore) and its KiB form.
lo, hi = num(static["bench.soc.vmhwm_store"]), num(static["bench.soc.vmhwm_restore"])
out.append(("bench.soc.vmhwm", f"{lo:.2f}–{hi:.2f} MiB"))
lo, hi = num(static["bench.soc.vmhwm_store_kib"]), num(static["bench.soc.vmhwm_restore_kib"])
out.append(("bench.soc.vmhwm_kib", f"{lo:,.0f}–{hi:,.0f} KiB"))
out.append(("bench.soc.baseline_rss_min", f"{span(static['bench.soc.baseline_rss'])[0]:.2f} MiB"))
# Headroom of the Router-SoC restore peak inside 32 / 48 MiB cgroups, and the
# desktop-to-router peak reduction factor.
peak = num(static["bench.soc.vmhwm_restore"])
for cg in (32, 48):
    out.append((f"bench.soc.headroom_{cg}m", f"{cg - peak:.2f} MiB"))
out.append(("bench.soc.vmhwm_reduction", f"{num(static['bench.desktop.vmhwm']) / peak:.1f}x"))

# AES-256-GCM stripe encryption span across Router-SoC and Desktop runs.
a, b = span(static["aes.enc.desktop"]), span(static["aes.enc.soc"])
out.append(("aes.enc.span", f"{min(a[0], b[0]):.1f}–{max(a[1], b[1]):.1f} MiB/s"))

# TLC totals: sums of the per-spec counts (every spec needs both keys).
specs = sorted(k[len("tlc.distinct."):] for k in static if k.startswith("tlc.distinct."))
if not specs or any(f"tlc.generated.{s}" not in static for s in specs):
    sys.exit("tlc.generated.<Spec> / tlc.distinct.<Spec> keys missing or unpaired")
for kind in ("generated", "distinct"):
    out.append((f"tlc.{kind}", f"{sum(int(num(static[f'tlc.{kind}.{s}'])) for s in specs):,}"))

for k, v in out:
    if not v or v.startswith(("0 ", "0.00")):
        sys.exit(f"derived value {k} = '{v}' is empty or zero")
    print(f"{k} = {v}")
PY
)" || fail "deriving values from docs/metrics.txt failed"
[[ -n "$derived" ]] || fail "no derived values"

printf '%s\n%s\n' "$counts" "$derived"
