#!/usr/bin/env bash
# L-16 seam (v0.5.5, G-1 rulings 1 and C3). Manifest selection is compile time only:
#   1. No `feature = "manifest-..."` cfg in any .rs file but src/manifest/mod.rs (Cargo.toml
#      declares the features), so no claimed function grows a manifest branch and
#      check_claim_cfg.sh stays sufficient.
#   2. No `--all-features` in a command that compiles: it enables two manifests and fails by
#      design. `cargo tree` only resolves and is exempt by name. Comment lines are prose.
# Scans the files git tracks under the root, or every file when the root is not a work tree
# (the planted-tree tests in tests/static_build_checks.rs).
# Usage: scripts/check_manifest_cfg.sh [repo-root]
set -euo pipefail
ROOT=${1:-.}
exec python3 -I - "$ROOT" <<'PY'
import os, re, subprocess, sys
root = sys.argv[1]
SELF = "scripts/check_manifest_cfg.sh"
try:
    out = subprocess.run(["git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"], capture_output=True, check=True)
    files = [f for f in out.stdout.decode().split("\0") if f]
    if not files:
        raise ValueError
except (subprocess.CalledProcessError, ValueError, FileNotFoundError):
    files = []
    for d, _, fs in os.walk(root):
        parts = os.path.relpath(d, root).split(os.sep)
        if ".git" in parts or "target" in parts:
            continue
        files += [os.path.relpath(os.path.join(d, f), root) for f in fs]
MANIFEST_CFG = re.compile(r'feature\s*=\s*"manifest-')
ALL_FEATURES = re.compile(r"--all-features\b")
COMPILING_EXT = (".sh", ".yml", ".yaml", ".py", ".toml", ".mk", "Makefile", "Dockerfile")
fails, scanned = [], 0
for rel in sorted(files):
    path = os.path.join(root, rel)
    if not os.path.isfile(path) or rel == SELF:
        continue
    try:
        text = open(path, encoding="utf-8").read()
    except (UnicodeDecodeError, OSError):
        continue
    scanned += 1
    for n, line in enumerate(text.splitlines(), 1):
        if rel.endswith(".rs") and rel != "src/manifest/mod.rs" and MANIFEST_CFG.search(line):
            fails.append(f"{rel}:{n}: manifest feature cfg outside src/manifest/mod.rs")
        if rel.endswith(COMPILING_EXT) and ALL_FEATURES.search(line):
            code = line.split("#", 1)[0]
            if ALL_FEATURES.search(code) and not re.search(r"\bcargo\s+tree\b", code):
                fails.append(f"{rel}:{n}: --all-features in a compiling command (only `cargo tree` may use it)")
for f in fails:
    print("[FAIL]", f)
print(f"manifest-cfg: {scanned} file(s) scanned, {len(fails)} failure(s)")
sys.exit(1 if fails else 0)
PY
