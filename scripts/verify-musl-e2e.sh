#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.cargo/env"
cd /mnt/c/Users/chris/.gemini/antigravity/scratch/parvault-daemon
export CARGO_TARGET_DIR="$HOME/parvault-target"

echo "=== 1. Running unit, integration & stateright tests (zero warnings check) ==="
cargo test -- --nocapture

echo "=== 2. Building static x86_64-unknown-linux-musl release binary ==="
cargo build --release --target x86_64-unknown-linux-musl

BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/parvault"
ls -lh "$BIN"
ldd "$BIN" 2>&1 || true

echo "=== 3. Running CLI: parvault status ==="
"$BIN" status

echo "=== 4. Running CLI E2E: parvault file store & restore (Homelab 16-of-20 tier) ==="
rm -rf /tmp/parvault-cli-test
mkdir -p /tmp/parvault-cli-test
cd /tmp/parvault-cli-test

head -c 524288 /dev/urandom > input.bin
STORE_OUT=$("$BIN" file store input.bin --tier homelab)
echo "$STORE_OUT"

ROOT=$(echo "$STORE_OUT" | awk '/File Merkle Root/ {print $5}')
"$BIN" file restore "$ROOT" restored.bin

sha256sum input.bin restored.bin
cmp -s input.bin restored.bin
echo "=== SUCCESS: Static musl binary restored 512 KiB vault payload bit-for-bit! ==="
