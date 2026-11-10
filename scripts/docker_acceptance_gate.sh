#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== [1/7] Building parvault:acceptance image from alpine:3.20 + static musl binaries ==="
BUILD_CTX="/tmp/parvault-acceptance-image"
rm -rf "$BUILD_CTX"
mkdir -p "$BUILD_CTX"
cp target/x86_64-unknown-linux-musl/release/parvault "$BUILD_CTX/parvault"
cp target/x86_64-unknown-linux-musl/release/parvault-seed "$BUILD_CTX/parvault-seed"
chmod +x "$BUILD_CTX/parvault" "$BUILD_CTX/parvault-seed"

cat > "$BUILD_CTX/Dockerfile" <<'EOF'
FROM alpine:3.20
COPY parvault /usr/local/bin/parvault
COPY parvault-seed /usr/local/bin/parvault-seed
EXPOSE 4001/tcp 4002/tcp
EOF

docker build -t parvault:acceptance "$BUILD_CTX"

echo "=== [2/7] Cleaning up previous acceptance containers & creating bridge network ==="
CONTAINERS=(parvault-seed-0 parvault-client)
for i in $(seq 1 10); do
    CONTAINERS+=("parvault-node-$i")
done
docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
docker network rm parvault-acceptance-net >/dev/null 2>&1 || true
docker network create --subnet=172.28.0.0/24 parvault-acceptance-net

echo "=== [3/7] Starting parvault-seed + 10 parvault daemon containers + 1 isolated client container ==="
docker run -d --name parvault-seed-0 \
    --network parvault-acceptance-net --ip 172.28.0.10 \
    parvault:acceptance \
    /usr/local/bin/parvault-seed start \
    --mode public-bootstrap \
    --listen /ip4/0.0.0.0/tcp/4002 \
    --data-dir /var/lib/parvault-seed

PEERS_LIST=()
for i in $(seq 1 10); do
    IP="172.28.0.$((10 + i))"
    PEERS_LIST+=("/ip4/${IP}/tcp/4001")
    docker run -d --name "parvault-node-$i" \
        --network parvault-acceptance-net --ip "$IP" \
        -w /var/lib/parvault \
        parvault:acceptance \
        /usr/local/bin/parvault \
        daemon start --listen /ip4/0.0.0.0/tcp/4001
done

PEERS_CSV="$(IFS=,; echo "${PEERS_LIST[*]}")"
SEED_MULTIADDR="/ip4/172.28.0.10/tcp/4002"

# Start isolated client container with ZERO volume mounts
docker run -d --name parvault-client \
    --network parvault-acceptance-net --ip 172.28.0.50 \
    parvault:acceptance \
    sleep 3600

sleep 2

echo "=== Verifying zero shared volume mounts on parvault-client ==="
CLIENT_MOUNTS="$(docker inspect -f '{{json .Mounts}}' parvault-client)"
echo "parvault-client Mounts: $CLIENT_MOUNTS"
if [ "$CLIENT_MOUNTS" != "[]" ] && [ "$CLIENT_MOUNTS" != "null" ]; then
    echo "ERROR: parvault-client has volume mounts: $CLIENT_MOUNTS"
    exit 1
fi

SEED_PHRASE="abandon ability able about above absent absorb abstract absurd abuse access accident"
VAULT_NS="docker-live-acceptance-vault"

echo "=== [4/7] Creating test dataset inside parvault-client and running 'parvault watch-folder --once' ==="
docker exec parvault-client sh -cex '
    mkdir -p /tmp/client-upload-state /workspace/source_vault/docs /workspace/source_vault/src /workspace/source_vault/data
    echo "# ParVault Live Multi-Container Network Proof" > /workspace/source_vault/docs/readme.md
    echo "pub fn verify_live_libp2p_recovery() -> bool { true }" > /workspace/source_vault/src/kernel.rs
    dd if=/dev/urandom of=/workspace/source_vault/data/blob.bin bs=1024 count=64 status=none
    cd /workspace/source_vault
    sha256sum docs/readme.md src/kernel.rs data/blob.bin > /tmp/expected.sha256
    cat /tmp/expected.sha256
'

docker exec -w /tmp/client-upload-state parvault-client /usr/local/bin/parvault \
    --peers "$PEERS_CSV" \
    --seed-addr "$SEED_MULTIADDR" \
    watch-folder \
    --folder /workspace/source_vault \
    --once \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "$VAULT_NS"

echo "=== Verifying shards and DHT records landed on remote daemon containers ==="
for i in $(seq 1 10); do
    SHARD_COUNT="$(docker exec "parvault-node-$i" sh -c 'ls -1 /var/lib/parvault/.parvault-data/shards/*.shard 2>/dev/null | wc -l')"
    echo "parvault-node-$i stored shard files: $SHARD_COUNT"
    if [ "$SHARD_COUNT" -lt 1 ]; then
        echo "ERROR: parvault-node-$i has 0 shards on disk!"
        exit 1
    fi
done
SEED_SHARD_COUNT="$(docker exec parvault-seed-0 sh -c 'ls -1 /var/lib/parvault-seed/shards/*.shard 2>/dev/null | wc -l')"
echo "parvault-seed-0 stored shard files: $SEED_SHARD_COUNT"

echo "=== Wiping local source folder and upload state inside parvault-client ==="
docker exec parvault-client sh -cex '
    rm -rf /workspace/source_vault /tmp/client-upload-state
    mkdir -p /tmp/client-fresh-recovery-state /workspace/recovered_vault
'

echo "=== [5/7] Killing 4 of the 10 storage daemon containers (parvault-node-1..4) ==="
docker kill parvault-node-1 parvault-node-2 parvault-node-3 parvault-node-4

echo "=== [6/7] Running 'parvault recover-from-seed' from isolated client container into empty directory ==="
docker exec -w /tmp/client-fresh-recovery-state parvault-client /usr/local/bin/parvault \
    --peers "$PEERS_CSV" \
    recover-from-seed \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "$VAULT_NS" \
    --out-dir /workspace/recovered_vault

echo "=== [7/7] Verifying SHA-256 integrity of all recovered files ==="
docker exec parvault-client sh -cex '
    cd /workspace/recovered_vault
    sha256sum -c /tmp/expected.sha256
    ls -la docs/readme.md src/kernel.rs data/blob.bin
'

echo "=== ACCEPTANCE GATE PASSED: 100% byte-identical recovery across live libp2p containers after killing 4 storage nodes ==="
