#!/usr/bin/env bash
# Ruling change 5 (item 3): no feature cfg inside a function named by a claim or kani row of
# .enforcement.map, nor inside a `*Facts` struct its signature names. A decision must behave the
# same on every feature set; gate whole modules instead. The function list comes from the map.
# Usage: scripts/check_claim_cfg.sh [repo-root]
set -euo pipefail
ROOT=${1:-.}
exec python3 -I - "$ROOT" <<'PY'
import os, re, sys
root = sys.argv[1]
rows = [l.split() for l in open(os.path.join(root, ".enforcement.map")) if l.startswith(("claim", "kani"))]
targets = set()
for r in rows:
    for f in r[1:]:
        if f.startswith("sym="):
            path, fn = f[4:].split("::", 1)
            targets.add((path, fn))
        elif f.startswith("harness="):
            targets.add(("src/kani_proofs.rs", f[8:]))
FEAT = re.compile(r"cfg!?\s*\(\s*(all|any|not)?\s*\(?\s*feature|cfg_attr\s*\(\s*feature")

def block(src, start):
    """Text from `start` through the brace that closes the first `{` after it."""
    i = src.index("{", start)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{": depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0: return src[start:j + 1]
    raise ValueError("unbalanced braces")

fails, checked = [], 0
for path, fn in sorted(targets):
    full = os.path.join(root, path)
    if not os.path.exists(full):
        fails.append(f"{path}::{fn}: file missing (stale map row)"); continue
    src = open(full).read()
    m = re.search(r"\bfn\s+" + re.escape(fn) + r"\s*[<(]", src)
    if not m:
        fails.append(f"{path}::{fn}: function not found (stale map row)"); continue
    body = block(src, m.start())
    checked += 1
    if FEAT.search(body):
        fails.append(f"{path}::{fn}: feature cfg inside a claimed/kani function")
    sig = body[: body.index("{")]
    for facts in set(re.findall(r"\b(\w+Facts)\b", sig)):
        sm = re.search(r"\bstruct\s+" + facts + r"\b", src)
        if sm and FEAT.search(block(src, sm.start())):
            fails.append(f"{path}::{facts}: feature cfg inside the facts struct of {fn}")
for f in fails: print("[FAIL]", f)
print(f"claim-cfg: {checked} function(s) checked, {len(fails)} failure(s)")
sys.exit(1 if fails else 0)
PY
