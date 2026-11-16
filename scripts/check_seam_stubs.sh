#!/usr/bin/env bash
# v0.5.6 T0, G3 (plan Section 2.1, release gate E8): lists every call of the seam refusal
# `seam::not_built_yet` under src/ with the track that owns it. During v0.5.6 development it
# passes; once Cargo.toml's package version is 0.5.6 or later it fails while any call remains,
# so the release gate catches a leftover stub. src/seam.rs itself (the definition) is not a call
# site; the Lead deletes it at integration. A call with no `track: "<X>"` within its next six
# lines fails at any version.
# Usage: scripts/check_seam_stubs.sh [repo-root]
set -euo pipefail
ROOT=${1:-.}
exec python3 -I - "$ROOT" <<'PY'
import os, re, sys
root = sys.argv[1]
text = open(os.path.join(root, "Cargo.toml")).read()
pkg = re.search(r"^\[package\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
ver = re.search(r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)', pkg.group(1) if pkg else "", re.M)
if not ver:
    print("[ERROR] no [package] version in Cargo.toml"); sys.exit(2)
version = tuple(int(x) for x in ver.groups())
calls, fails = [], []
for d, _, files in os.walk(os.path.join(root, "src")):
    for f in sorted(files):
        if not f.endswith(".rs"):
            continue
        path = os.path.join(d, f)
        rel = os.path.relpath(path, root)
        if rel == os.path.join("src", "seam.rs"):
            continue
        lines = open(path).read().split("\n")
        for i, line in enumerate(lines):
            code = line.split("//", 1)[0]
            if re.search(r"\bnot_built_yet\s*\(", code):
                m = None
                for nxt in lines[i:i + 7]:
                    m = re.search(r'track:\s*"([^"]+)"', nxt)
                    if m:
                        break
                track = m.group(1) if m else None
                calls.append((rel, i + 1, track))
                if track is None:
                    fails.append(f"{rel}:{i + 1}: a not_built_yet call names no track")
for rel, ln, track in calls:
    print(f"[STUB] {rel}:{ln} track={track}")
if version >= (0, 5, 6) and calls:
    fails.append(f"version {'.'.join(map(str, version))}: {len(calls)} not_built_yet stub(s) remain (G3)")
for f in fails:
    print("[FAIL]", f)
print(f"seam-stubs: {len(calls)} call site(s), version {'.'.join(map(str, version))}, {len(fails)} failure(s)")
sys.exit(1 if fails else 0)
PY
