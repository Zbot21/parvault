#!/usr/bin/env bash
# Reproducible Formal Verification Runner for ParVault v0.5.0:
# 1. Runs every Kani Rust Bounded Model Checking symbolic harness (`cargo kani`)
# 2. Runs TLC on every TLA+ specification `specs/*.tla`, each with its own `.cfg`
# Counts live only in docs/metrics.txt.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "================================================================================"
echo "  [1/2] Kani Rust Bounded Model Checking (all harnesses)"
echo "================================================================================"
if ! command -v cargo-kani >/dev/null 2>&1; then
  echo "ERROR: cargo-kani not found. Install via: cargo install --locked kani-verifier && cargo kani setup" >&2
  exit 1
fi
cargo kani

echo ""
echo "================================================================================"
echo "  [2/2] TLA+ TLC Model Checking (every specs/*.tla)"
echo "================================================================================"
TLA_JAR="${TLA2TOOLS_JAR:-/root/tla2tools.jar}"
if [ ! -f "$TLA_JAR" ]; then
  TLA_JAR="/tmp/tla2tools.jar"
  if [ ! -f "$TLA_JAR" ]; then
    echo "==> Downloading tla2tools.jar v1.8.0 to ${TLA_JAR} ..."
    curl --proto '=https' --tlsv1.2 -fsSL \
      https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar \
      -o "$TLA_JAR"
  fi
fi

cd "${REPO_ROOT}/specs"
shopt -s nullglob
SPECS=()
for file in *.tla; do
  spec="${file%.tla}"
  if [ ! -f "${spec}.cfg" ]; then
    echo "ERROR: specs/${spec}.tla has no specs/${spec}.cfg" >&2
    exit 1
  fi
  SPECS+=("$spec")
done
shopt -u nullglob
if [ "${#SPECS[@]}" -eq 0 ]; then
  echo "ERROR: no specs/*.tla found" >&2
  exit 1
fi

for spec in "${SPECS[@]}"; do
  echo "===> Verifying ${spec}.tla (${spec}.cfg) ..."
  java -XX:+UseParallelGC -cp "$TLA_JAR" tlc2.TLC -workers auto -cleanup -config "${spec}.cfg" "${spec}.tla"
done

echo ""
echo "================================================================================"
echo "  ALL KANI HARNESSES & ${#SPECS[@]} TLA+ SPECS VERIFIED (0 ERRORS)"
echo "================================================================================"
