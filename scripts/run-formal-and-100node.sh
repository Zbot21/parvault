#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.cargo/env"
export PATH="/usr/local/bin:$PATH"
cd /mnt/c/Users/chris/.gemini/antigravity/scratch/parvault-daemon
export CARGO_TARGET_DIR="$HOME/parvault-target"

echo "========================================================================"
echo " PART 1: TLA+ Formal Protocol Model Checking (TLC on ParVaultProtocol.tla)"
echo "========================================================================"

if ! command -v java >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update && apt-get install -y default-jre-headless
fi

if [ ! -f /tmp/tla2tools.jar ]; then
  echo "Downloading official TLA+ TLC model checker (tla2tools.jar v1.8.0)..."
  curl -sSL https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar -o /tmp/tla2tools.jar
fi

rm -rf /tmp/tlc-states && mkdir -p /tmp/tlc-states
cp specs/ParVaultProtocol.tla specs/ParVaultProtocol.cfg specs/ParVaultConfidentialityAndTrust.tla specs/ParVaultConfidentialityAndTrust.cfg specs/ParVaultAnonymity.tla specs/ParVaultAnonymity.cfg specs/ParVaultPostQuantum.tla specs/ParVaultPostQuantum.cfg specs/ParVaultBootstrapAndEarnedTier.tla specs/ParVaultBootstrapAndEarnedTier.cfg /tmp/tlc-states/
pushd /tmp/tlc-states >/dev/null
java -XX:+UseParallelGC -cp /tmp/tla2tools.jar tlc2.TLC \
  -workers auto \
  -config ParVaultProtocol.cfg \
  ParVaultProtocol.tla

rm -rf states
java -XX:+UseParallelGC -cp /tmp/tla2tools.jar tlc2.TLC \
  -workers auto \
  -config ParVaultConfidentialityAndTrust.cfg \
  ParVaultConfidentialityAndTrust.tla

rm -rf states
java -XX:+UseParallelGC -cp /tmp/tla2tools.jar tlc2.TLC \
  -workers auto \
  -config ParVaultAnonymity.cfg \
  ParVaultAnonymity.tla

rm -rf states
java -XX:+UseParallelGC -cp /tmp/tla2tools.jar tlc2.TLC \
  -workers auto \
  -config ParVaultPostQuantum.cfg \
  ParVaultPostQuantum.tla

rm -rf states
java -XX:+UseParallelGC -cp /tmp/tla2tools.jar tlc2.TLC \
  -workers auto \
  -config ParVaultBootstrapAndEarnedTier.cfg \
  ParVaultBootstrapAndEarnedTier.tla
popd >/dev/null

echo "========================================================================"
echo " PART 2: Code-Level Formal & Zero-Trust Verification (stateright + GF(2^8))"
echo "========================================================================"

cargo test --release --test formal_verification --test zero_trust_adversarial --test confidentiality_and_trust_proofs --test anonymity_and_degraded_net_tests --test post_quantum_security_proofs --test bootstrap_and_earned_tier_tests -- --nocapture

echo "========================================================================"
echo " PART 3: 100-Node Empirical Validation Run (50 x 100 MB Vaults, 30% Churn)"
echo "========================================================================"

cargo build --release --bin parvault
"$CARGO_TARGET_DIR/release/parvault" benchmark100-node \
  --num-nodes 100 \
  --num-vaults 50 \
  --vault-size-mb 100 \
  --churn-percent 30
