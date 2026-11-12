#!/usr/bin/env bash
# ==============================================================================
# gen_metrics.sh: metrics generator for docs/metrics.txt
# ==============================================================================
# Default mode (used by `scripts/sync_doc_metrics.sh --generate`, run in CI):
#   prints `key = value` lines computed from the tree only: no network, no
#   cargo build, stable order. It prints:
#     - counts taken from the source (version, Kani harnesses, TLA+ specs,
#       ADRs, test functions, integration suites)
#     - values derived from the static measured keys in docs/metrics.txt
#       (MiB from exact bytes, min-max ranges), so they cannot disagree.
#
# --measured (opt-in, never run by CI): re-runs the repository's existing
#   measurement commands and prints fresh values for the STATIC measured keys.
#   Review them, then copy them into the static section of docs/metrics.txt
#   with a new provenance comment (command + date). It runs:
#     - `cargo build --profile soc --target <t> --bin <b>` for both musl
#       targets, then `stat` -> size.<bin>.<arch>.bytes
#       (aarch64 needs CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER)
#     - TLC on every specs/*.tla (needs TLA2TOOLS_JAR) ->
#       tlc.generated, tlc.distinct.<Spec>
#   Benchmark, RSS and latency keys are min-max ranges over repeated runs of
#   parvault-bench and the self-tests, so they are re-measured by hand (see
#   the comments in docs/metrics.txt).
# ==============================================================================
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# 1234567 -> 1,234,567 (locale-independent)
group() { printf '%s' "$1" | rev | sed -E 's/([0-9]{3})/\1,/g; s/,$//' | rev; }

if [[ "${1:-}" == "--measured" ]]; then
  : "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}"
  for target in aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
    arch="${target%%-*}"
    for bin in parvault parvault-seed parvault-fuse parvault-sync; do
      cargo build -q --profile soc --target "$target" --bin "$bin" >&2
      bytes="$(stat -c %s "$CARGO_TARGET_DIR/$target/soc/$bin")"
      printf 'size.%s.%s.bytes = %s B\n' "$bin" "$arch" "$(group "$bytes")"
    done
  done
  : "${TLA2TOOLS_JAR:?set TLA2TOOLS_JAR}"
  meta="$(mktemp -d)"; trap 'rm -rf "$meta"' EXIT
  total=0
  for spec in specs/*.tla; do
    name="$(basename "$spec" .tla)"
    out="$(cd specs && java -XX:+UseParallelGC -cp "$TLA2TOOLS_JAR" tlc2.TLC -workers auto -cleanup \
      -metadir "$meta/$name" -config "$name.cfg" "$name.tla")"
    line="$(grep -E '[0-9,]+ states generated, [0-9,]+ distinct states found' <<<"$out" | tail -1)"
    gen="$(sed -E 's/^([0-9,]+) states generated.*/\1/' <<<"$line" | tr -d ,)"
    dist="$(sed -E 's/.*generated, ([0-9,]+) distinct.*/\1/' <<<"$line" | tr -d ,)"
    total=$((total + gen))
    printf 'tlc.distinct.%s = %s\n' "$name" "$(group "$dist")"
  done
  printf 'tlc.generated = %s\n' "$(group "$total")"
  exit 0
fi
[[ $# -eq 0 ]] || { echo "usage: gen_metrics.sh [--measured]" >&2; exit 2; }

export LC_ALL=C

# --- Counts from the tree -----------------------------------------------------
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
kani_total="$(grep -rhE '^\s*#\[kani::proof\]' src | wc -l)"
kani_module="$(grep -hE '^\s*#\[kani::proof\]' src/kani_proofs.rs | wc -l)"
tla_specs="$(find specs -maxdepth 1 -name '*.tla' | wc -l)"
adr_count="$(find docs/adr -maxdepth 1 -name 'ADR-[0-9]*.md' | wc -l)"
adr_last="$(find docs/adr -maxdepth 1 -name 'ADR-[0-9]*.md' -printf '%f\n' | sort | tail -1 | grep -oE '^ADR-[0-9]+')"
suites="$(find tests -maxdepth 1 -name '*.rs' | wc -l)"
test_attr='^\s*#\[(tokio::)?test(\(.*\))?\]'
tests_unit="$(grep -rhE "$test_attr" src | wc -l)"
kani_in() { grep -hE '^\s*#\[kani::proof\]' "$1" | wc -l; }
tests_int="$(grep -hE "$test_attr" tests/*.rs | wc -l)"
tests_total=$((tests_unit + tests_int))

cat <<EOF
crate_version = $version
kani_harnesses = $kani_total
kani_harnesses_module = $kani_module
kani_pass = $kani_total / $kani_total
kani_pass_compact = $kani_total/$kani_total
kani_harnesses.capabilities = $(kani_in src/capabilities.rs)
kani_harnesses.aes = $(kani_in src/crypto/aes.rs)
kani_harnesses.reed_solomon = $(kani_in src/sharding/reed_solomon.rs)
tla_specs = $tla_specs
tla_pass = $tla_specs / $tla_specs
adr_count = $adr_count
adr_last = $adr_last
integration_suites = $suites
tests_unit = $tests_unit
tests_integration = $tests_int
tests_total = $tests_total
tests_pass = $tests_total / $tests_total
EOF

# --- Values derived from static measured keys ----------------------------------
python3 - docs/metrics.txt <<'PY'
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

# TLC distinct states: sum of the per-spec counts.
dist = sum(int(num(v)) for k, v in static.items() if k.startswith("tlc.distinct."))
out.append(("tlc.distinct", f"{dist:,}"))

for k, v in out:
    print(f"{k} = {v}")
PY
