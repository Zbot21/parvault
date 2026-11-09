#!/usr/bin/env bash
set -euo pipefail

echo "=== [ParVault] Installing Docker Engine & QEMU ARM64 emulation in WSL2 ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  docker.io \
  docker-compose-v2 \
  qemu-user \
  qemu-user-binfmt \
  binfmt-support \
  iptables \
  iproute2

# Ensure musl headers/specs work for aarch64-unknown-linux-musl cross-compilation
if [ ! -e /usr/local/bin/aarch64-linux-musl-gcc ]; then
  echo "=== Installing aarch64-linux-musl-cross toolchain ==="
  curl -sSL https://musl.cc/aarch64-linux-musl-cross.tgz -o /tmp/aarch64-musl.tgz
  tar -xzf /tmp/aarch64-musl.tgz -C /opt
  ln -sf /opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc /usr/local/bin/aarch64-linux-musl-gcc
  ln -sf /opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-ar /usr/local/bin/aarch64-linux-musl-ar
  ln -sf /opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-strip /usr/local/bin/aarch64-linux-musl-strip
  rm -f /tmp/aarch64-musl.tgz
fi

aarch64-linux-musl-gcc --version | head -n 1
qemu-aarch64 --version | head -n 1
docker --version
