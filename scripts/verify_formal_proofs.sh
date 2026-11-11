#!/usr/bin/env bash
# Reproducible Formal Verification Runner for ParVault v0.4.0:
# 1. Runs all 15 Kani Rust Bounded Model Checking symbolic harnesses (`cargo kani`)
# 2. Runs all 7 TLA+ TLC protocol state-machine specifications (`specs/*.tla`)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "================================================================================"
echo "  [1/2] Kani Rust Bounded Model Checking (15 Symbolic Harnesses)"
echo "================================================================================"
if ! command -v cargo-kani >/dev/null 2>&1; then
  echo "ERROR: cargo-kani not found. Install via: cargo install --locked kani-verifier && cargo kani setup" >&2
  exit 1
fi
cargo kani

echo ""
echo "================================================================================"
echo "  [2/2] TLA+ TLC Model Checking (All 7 Protocol Specifications)"
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

SPECS=(
  ParVaultProtocol
  ParVaultConfidentialityAndTrust
  ParVaultAnonymity
  ParVaultPostQuantum
  ParVaultBootstrapAndEarnedTier
  ParVaultLiteClientAndSeedFailover
  ParVaultZeroKeyAdminAndQuorum
)

cd "${REPO_ROOT}/specs"
for spec in "${SPECS[@]}"; do
  echo "===> Verifying ${spec}.tla (${spec}.cfg) ..."
  java -XX:+UseParallelGC -cp "$TLA_JAR" tlc2.TLC -workers auto -cleanup -config "${spec}.cfg" "${spec}.tla"
done

echo ""
echo "================================================================================"
echo "  ALL 15 KANI BOUNDED MODEL CHECKING HARNESSES & 7 TLA+ SPECS VERIFIED (0 ERRORS)"
echo "================================================================================"
