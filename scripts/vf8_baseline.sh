#!/usr/bin/env bash
# VF-8 baseline (v0.5.6 plan E7, track C): records restore TTFB on a real daemon, idle and under
# in-daemon scavenger load (L-72 S1), as build/baselines/vf8-<label>.json. Record only; nothing
# here gates. It runs the L-72 accept test (a 48 MiB hydration, a GET of a never-read 3 MiB
# file, then an idle GET of another never-read 3 MiB file) RUNS times and keeps every sample.
# Usage: scripts/vf8_baseline.sh [label] (default: the hostname); RUNS (default 5), PROFILE
# (cargo profile, default release) from the environment.
set -euo pipefail
cd "$(dirname "$0")/.."
LABEL=${1:-$(hostname -s)}
RUNS=${RUNS:-5}
PROFILE=${PROFILE:-release}
OUT=build/baselines/vf8-${LABEL}.json
mkdir -p build/baselines
samples=()
for i in $(seq 1 "$RUNS"); do
  line=$(cargo test --locked --profile "$PROFILE" --test trust_enforcement_restore \
    l72_foreground_ttfb_under_load -- --exact --nocapture 2>&1 | grep '^L72 ttfb' | tail -1)
  [[ -n $line ]] || { echo "[ERROR] run $i printed no L72 line" >&2; exit 2; }
  samples+=("$line")
done
python3 -I - "$OUT" "$LABEL" "$PROFILE" "${samples[@]}" <<'PY'
import json, re, sys, time
out, label, profile, lines = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
def ms(v):
    m = re.fullmatch(r"([\d.]+)(ns|µs|us|ms|s)", v)
    n, u = float(m.group(1)), m.group(2)
    return n * {"ns": 1e-6, "µs": 1e-3, "us": 1e-3, "ms": 1, "s": 1e3}[u]
runs = []
for l in lines:
    f = dict(re.findall(r"(\w+)=(\S+)", l))
    runs.append({"ttfb_loaded_ms": round(ms(f["loaded"]), 3), "ttfb_idle_ms": round(ms(f["idle"]), 3)})
def med(k):
    v = sorted(r[k] for r in runs); return v[len(v) // 2]
doc = {"baseline": "VF-8", "label": label, "profile": profile,
       "recorded_unix": int(time.time()), "runs": runs,
       "median_ttfb_loaded_ms": med("ttfb_loaded_ms"), "median_ttfb_idle_ms": med("ttfb_idle_ms"),
       "bound_ms_2x_idle_plus_100": round(2 * med("ttfb_idle_ms") + 100, 3)}
json.dump(doc, open(out, "w"), indent=2); open(out, "a").write("\n")
print(json.dumps(doc))
PY
echo "VF-8 baseline written to $OUT"
