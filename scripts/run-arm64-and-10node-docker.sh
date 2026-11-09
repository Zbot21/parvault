#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.cargo/env"
export PATH="/usr/local/bin:$PATH"
cd /mnt/c/Users/chris/.gemini/antigravity/scratch/parvault-daemon
export CARGO_TARGET_DIR="$HOME/parvault-target"

echo "========================================================================"
echo " STEP 1: Cross-Compiling Static x86_64 & aarch64 musl Release Binaries  "
echo "========================================================================"

cargo build --release --target x86_64-unknown-linux-musl

export CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc
export AR_aarch64_unknown_linux_musl=aarch64-linux-musl-ar
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc
cargo build --release --target aarch64-unknown-linux-musl

mkdir -p dist
cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/parvault" dist/parvault-x86_64-unknown-linux-musl
cp "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/parvault" dist/parvault-aarch64-unknown-linux-musl

file dist/parvault-x86_64-unknown-linux-musl
file dist/parvault-aarch64-unknown-linux-musl
ls -lh dist/parvault-x86_64-unknown-linux-musl dist/parvault-aarch64-unknown-linux-musl

echo "========================================================================"
echo " STEP 2: Starting Docker Engine & Testing ARM64 (aarch64-musl) Container"
echo "========================================================================"

if ! docker info >/dev/null 2>&1; then
  systemctl start docker || (dockerd >/tmp/dockerd.log 2>&1 & sleep 4)
fi
docker info | grep -E "Server Version|Architecture|Operating System" || true

# Run the ARM64 (linux/arm64) container with the static aarch64-unknown-linux-musl binary
cp dist/parvault-aarch64-unknown-linux-musl /tmp/parvault-arm64
chmod +x /tmp/parvault-arm64

docker run --rm --platform linux/arm64 \
  -v /tmp/parvault-arm64:/usr/local/bin/parvault:ro \
  arm64v8/alpine:3.20 /bin/sh -c '
  set -e
  echo "Container Arch : $(uname -m)"
  /usr/local/bin/parvault status
  dd if=/dev/urandom of=/tmp/arm64_vault.bin bs=1024 count=256 2>/dev/null
  OUT=$(/usr/local/bin/parvault file store /tmp/arm64_vault.bin --tier homelab)
  echo "$OUT"
  ROOT=$(echo "$OUT" | awk "/File Merkle Root/ {print \$5}")
  /usr/local/bin/parvault file restore "$ROOT" /tmp/arm64_restored.bin
  sha256sum /tmp/arm64_vault.bin /tmp/arm64_restored.bin
  cmp -s /tmp/arm64_vault.bin /tmp/arm64_restored.bin
  echo "[PASS] aarch64-unknown-linux-musl static binary verified inside linux/arm64 Docker container!"
'

echo "========================================================================"
echo " STEP 3: Launching 10-Node Mesh in Docker (10.42.0.0/16 + tc netem)     "
echo "========================================================================"

rm -rf /tmp/docker-x86 && mkdir -p /tmp/docker-x86
cp dist/parvault-x86_64-unknown-linux-musl /tmp/docker-x86/parvault
cat > /tmp/docker-x86/Dockerfile << 'EOF'
FROM alpine:3.20
RUN apk add --no-cache iproute2 iputils
COPY parvault /usr/local/bin/parvault
RUN chmod +x /usr/local/bin/parvault
EOF

docker build -t parvault:x86_64-musl /tmp/docker-x86

# Clean up any prior mesh containers or network
for i in $(seq -w 1 10); do
  docker rm -f "mesh-node$i" >/dev/null 2>&1 || true
done
docker network rm parvault-val-net >/dev/null 2>&1 || true

docker network create --driver bridge --subnet 10.42.0.0/16 parvault-val-net

IPS=(
  "10.42.1.11"
  "10.42.1.12"
  "10.42.1.13"
  "10.42.1.14"
  "10.42.1.15"
  "10.42.1.16"
  "10.42.1.17"
  "10.42.2.18"
  "10.42.2.19"
  "10.42.2.20"
)

for idx in "${!IPS[@]}"; do
  num=$(printf "%02d" $((idx + 1)))
  ip="${IPS[$idx]}"
  docker run -d \
    --name "mesh-node$num" \
    --network parvault-val-net \
    --ip "$ip" \
    --cap-add NET_ADMIN \
    parvault:x86_64-musl \
    /bin/sh -c "tc qdisc add dev eth0 root netem delay 5ms loss 1% && exec /usr/local/bin/parvault daemon start --listen /ip4/0.0.0.0/tcp/4001" >/dev/null
done

sleep 2
docker ps --filter "name=mesh-node" --format "table {{.Names}}\t{{.Status}}\t{{.Networks}}"

echo "========================================================================"
echo " STEP 4: Running 1 GiB 10-Node Validation Benchmark + 4-Node Hard Kill  "
echo "========================================================================"

"$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/parvault" benchmark \
  --nodes "10.42.1.11:4001,10.42.1.12:4001,10.42.1.13:4001,10.42.1.14:4001,10.42.1.15:4001,10.42.1.16:4001,10.42.1.17:4001,10.42.2.18:4001,10.42.2.19:4001,10.42.2.20:4001" \
  --payload-mib 1024 \
  --por-challenges 50 \
  --killed-node-indices "0,1,2,3" \
  --kill-cmd "docker kill mesh-node01 mesh-node02 mesh-node03 mesh-node04 >/dev/null"

echo "=== Container Status After 4-Node Kill Injection ==="
docker ps -a --filter "name=mesh-node" --format "table {{.Names}}\t{{.Status}}"

# Clean up containers and bridge network
for i in $(seq -w 1 10); do
  docker rm -f "mesh-node$i" >/dev/null 2>&1 || true
done
docker network rm parvault-val-net >/dev/null 2>&1 || true
