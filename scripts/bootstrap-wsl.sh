#!/usr/bin/env bash
set -euo pipefail

echo "=== [ParVault] Bootstrapping WSL2 Ubuntu Toolchain for parvault-daemon ==="

sudo apt-get update
sudo apt-get install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  musl-tools \
  musl-dev \
  gcc-aarch64-linux-gnu \
  iproute2 \
  iputils-ping \
  curl \
  git \
  ca-certificates

if ! command -v rustup >/dev/null 2>&1; then
  echo "=== Installing rustup (stable toolchain) ==="
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  source "$HOME/.cargo/env"
else
  source "$HOME/.cargo/env"
fi

echo "=== Adding static musl cross-compilation targets ==="
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

echo "=== Toolchain Verification ==="
rustc --version
cargo --version
musl-gcc --version | head -n 1

echo "=== [ParVault] WSL2 Environment Ready! ==="
