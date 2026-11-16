#!/usr/bin/env bash
# v0.5.6 T0 (arch056c 5.1): every `#[kani::proof]` under src/ is collected by Kani.
# A harness file under src/kani_proofs/ with no `mod` line in its mod.rs is never compiled, so
# `cargo kani` skips it without a word. Static half (always): each src/kani_proofs/<name>.rs has
# a `mod <name>;` line in src/kani_proofs/mod.rs. Runtime half (with a file): the harness count
# Kani reports equals the `#[kani::proof]` count under src/.
#   --log <file>   output of `cargo kani` (its "Complete - N successfully verified harnesses,
#                  F failures, T total." line: T must equal the source count and F be 0)
#   --list <file>  `cargo kani list --format json` output (kani-list.json)
# Usage: scripts/check_kani_count.sh [repo-root] [--log <file> | --list <file>]
set -euo pipefail
ROOT=.
if [[ $# -gt 0 && $1 != --* ]]; then ROOT=$1; shift; fi
exec python3 -I - "$ROOT" "$@" <<'PY'
import json, os, re, sys
root, args = sys.argv[1], sys.argv[2:]
fails = []
kdir = os.path.join(root, "src", "kani_proofs")
mod_rs = open(os.path.join(kdir, "mod.rs")).read()
# Line comments blanked so a commented-out `mod` line does not count.
mod_code = re.sub(r"//[^\n]*", "", mod_rs)
for name in sorted(os.listdir(kdir)):
    if not name.endswith(".rs") or name == "mod.rs":
        continue
    stem = name[:-3]
    if not re.search(r"^\s*(pub(\([a-z]+\))?\s+)?mod\s+" + re.escape(stem) + r"\s*;", mod_code, re.M):
        fails.append(f"src/kani_proofs/{name}: no `mod {stem};` in src/kani_proofs/mod.rs (its harnesses would be skipped)")
proof = re.compile(r"^\s*#\[kani::proof\]", re.M)
src_count = 0
for d, _, files in os.walk(os.path.join(root, "src")):
    for f in files:
        if f.endswith(".rs"):
            src_count += len(proof.findall(open(os.path.join(d, f)).read()))
print(f"kani-count: {src_count} #[kani::proof] under src/")
if args:
    if len(args) != 2 or args[0] not in ("--log", "--list"):
        print("usage: check_kani_count.sh [repo-root] [--log <file> | --list <file>]"); sys.exit(2)
    text = open(args[1]).read()
    if args[0] == "--log":
        m = re.findall(r"Complete - (\d+) successfully verified harnesses, (\d+) failures, (\d+) total", text)
        if not m:
            print(f"[ERROR] {args[1]}: no Kani summary line"); sys.exit(2)
        ok, failed, total = map(int, m[-1])
        if failed:
            fails.append(f"Kani reported {failed} failure(s)")
        seen = total
    else:
        data = json.loads(text)
        seen = data.get("totals", {}).get("standard-harnesses")
        if seen is None:
            seen = sum(len(v) for v in data.get("standard-harnesses", {}).values())
    print(f"kani-count: Kani collected {seen}")
    if seen != src_count:
        fails.append(f"Kani collected {seen} harness(es), the source declares {src_count}")
for f in fails:
    print("[FAIL]", f)
sys.exit(1 if fails else 0)
PY
