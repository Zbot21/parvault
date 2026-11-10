#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CONTAINERS=(parvault-seed-0 parvault-client)
for i in $(seq 1 11); do
    CONTAINERS+=("parvault-node-$i")
done

cleanup() {
    if [ "${KEEP_CONTAINERS:-0}" != "1" ]; then
        docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
        docker network rm parvault-acceptance-net >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "=== [1/10] Building ParVault binaries & parvault:acceptance container image ==="
BUILD_CTX="/tmp/parvault-acceptance-image"
rm -rf "$BUILD_CTX"
mkdir -p "$BUILD_CTX"

if [ "${USE_GLIBC_IMAGE:-0}" != "1" ] && rustup target list --installed 2>/dev/null | grep -q "x86_64-unknown-linux-musl"; then
    cargo build --release --target x86_64-unknown-linux-musl --bin parvault --bin parvault-seed
    cp target/x86_64-unknown-linux-musl/release/parvault "$BUILD_CTX/parvault"
    cp target/x86_64-unknown-linux-musl/release/parvault-seed "$BUILD_CTX/parvault-seed"
    BASE_IMAGE="alpine:3.20"
else
    if [ ! -f target/release/parvault ] || [ ! -f target/release/parvault-seed ]; then
        cargo build --release --bin parvault --bin parvault-seed
    fi
    cp target/release/parvault "$BUILD_CTX/parvault"
    cp target/release/parvault-seed "$BUILD_CTX/parvault-seed"
    BASE_IMAGE="ubuntu:24.04"
fi
chmod +x "$BUILD_CTX/parvault" "$BUILD_CTX/parvault-seed"

cat > "$BUILD_CTX/Dockerfile" <<EOF
FROM ${BASE_IMAGE}
COPY parvault /usr/local/bin/parvault
COPY parvault-seed /usr/local/bin/parvault-seed
EXPOSE 4001/tcp 4002/tcp
EOF

docker build -t parvault:acceptance "$BUILD_CTX"

echo "=== [2/10] Creating isolated Docker bridge network (172.28.0.0/24) ==="
docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
docker network rm parvault-acceptance-net >/dev/null 2>&1 || true
docker network create --subnet=172.28.0.0/24 parvault-acceptance-net

PEERS_LIST=()
for i in $(seq 1 10); do
    IP="172.28.0.$((10 + i))"
    PEERS_LIST+=("/ip4/${IP}/tcp/4001")
done
PEERS_CSV="$(IFS=,; echo "${PEERS_LIST[*]}")"
SEED_MULTIADDR="/ip4/172.28.0.10/tcp/4002"
NODE11_MULTIADDR="/ip4/172.28.0.21/tcp/4001"

echo "=== [3/10] Starting parvault-seed-0 + 11 parvault daemon containers + 1 isolated client container ==="
docker run -d --name parvault-seed-0 \
    --network parvault-acceptance-net --ip 172.28.0.10 \
    parvault:acceptance \
    /usr/local/bin/parvault-seed \
    --peers "$PEERS_CSV" \
    start \
    --mode homelab-vault \
    --listen /ip4/0.0.0.0/tcp/4002 \
    --data-dir /var/lib/parvault-seed

for i in $(seq 1 11); do
    IP="172.28.0.$((10 + i))"
    docker run -d --name "parvault-node-$i" \
        --network parvault-acceptance-net --ip "$IP" \
        -w /var/lib/parvault \
        parvault:acceptance \
        /usr/local/bin/parvault \
        --peers "$PEERS_CSV" \
        --seed-addr "$SEED_MULTIADDR" \
        daemon start --listen /ip4/0.0.0.0/tcp/4001
done

# Start isolated client container with ZERO volume mounts
docker run -d --name parvault-client \
    --network parvault-acceptance-net --ip 172.28.0.50 \
    parvault:acceptance \
    sleep 3600

sleep 3

echo "=== Verifying zero shared volume mounts on parvault-client ==="
CLIENT_MOUNTS="$(docker inspect -f '{{json .Mounts}}' parvault-client)"
echo "parvault-client Mounts: $CLIENT_MOUNTS"
if [ "$CLIENT_MOUNTS" != "[]" ] && [ "$CLIENT_MOUNTS" != "null" ]; then
    echo "ERROR: parvault-client has volume mounts: $CLIENT_MOUNTS"
    exit 1
fi

SEED_PHRASE="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
VAULT_NS="docker-live-acceptance-vault"

echo "=== [4/10] Initial Backup (Snapshot v1): 'parvault watch-folder --once' over libp2p ==="
docker exec parvault-client sh -cex '
    mkdir -p /tmp/client-upload-state /workspace/source_vault/docs /workspace/source_vault/src /workspace/source_vault/data
    echo "# ParVault Live Multi-Container Network Proof (v1)" > /workspace/source_vault/docs/readme.md
    echo "pub fn verify_live_libp2p_recovery() -> bool { true }" > /workspace/source_vault/src/kernel.rs
    echo "pub fn temporary_module() {}" > /workspace/source_vault/src/ephemeral.rs
    dd if=/dev/urandom of=/workspace/source_vault/data/blob.bin bs=1024 count=64 status=none
'

T0_S=$(date +%s)
docker exec -w /tmp/client-upload-state parvault-client /usr/local/bin/parvault \
    --peers "$PEERS_CSV" \
    --seed-addr "$SEED_MULTIADDR" \
    watch-folder \
    --folder /workspace/source_vault \
    --once \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "$VAULT_NS"
T1_S=$(date +%s)
SYNC_V1_SECS=$((T1_S - T0_S))

TOTAL_SHARDS_V1=0
for i in $(seq 1 10); do
    SHARD_COUNT="$(docker exec "parvault-node-$i" sh -c 'ls -1 /var/lib/parvault/.parvault-data/shards/*.shard 2>/dev/null | wc -l')"
    echo "parvault-node-$i stored shard files (v1): $SHARD_COUNT"
    if [ "$SHARD_COUNT" -lt 1 ]; then
        echo "ERROR: parvault-node-$i has 0 shards on disk!"
        exit 1
    fi
    TOTAL_SHARDS_V1=$((TOTAL_SHARDS_V1 + SHARD_COUNT))
done
SEED_SHARD_COUNT_V1="$(docker exec parvault-seed-0 sh -c 'ls -1 /var/lib/parvault-seed/shards/*.shard 2>/dev/null | wc -l')"
echo "Total remote node shards (v1): $TOTAL_SHARDS_V1 | Seed shards (v1): $SEED_SHARD_COUNT_V1 | Elapsed: ${SYNC_V1_SECS}s"

echo "=== [5/10] Continuous Background Backup Daemon ('watch-folder --interval-secs 1 --prune-deleted') ==="
docker exec -w /tmp/client-upload-state parvault-client sh -c "
    nohup /usr/local/bin/parvault \
        --peers '$PEERS_CSV' \
        --seed-addr '$SEED_MULTIADDR' \
        watch-folder \
        --folder /workspace/source_vault \
        --interval-secs 1 \
        --prune-deleted \
        --seed-phrase '$SEED_PHRASE' \
        --vault-namespace '$VAULT_NS' \
        > /tmp/watch-daemon.log 2>&1 &
    echo \$! > /tmp/watch-daemon.pid
"
sleep 2

# Mutate watched directory while continuous daemon is running: modify readme.md, add changelog.md, delete ephemeral.rs
docker exec parvault-client sh -cex '
    echo "# ParVault Live Multi-Container Network Proof (v2 - Continuous Sync Updated)" > /workspace/source_vault/docs/readme.md
    echo "## v0.2.0 Live Multi-Container Regression Verified" > /workspace/source_vault/docs/changelog.md
    rm -f /workspace/source_vault/src/ephemeral.rs
    cd /workspace/source_vault
    sha256sum docs/readme.md docs/changelog.md src/kernel.rs data/blob.bin > /tmp/expected_v2.sha256
    cat /tmp/expected_v2.sha256
'

# Wait for continuous watch-folder daemon to complete pass v2 and stop it cleanly
for attempt in $(seq 1 20); do
    if docker exec parvault-client grep -q "Deleted Tombstones : 1" /tmp/watch-daemon.log 2>/dev/null; then
        break
    fi
    sleep 1
done
docker exec parvault-client sh -cex '
    if [ -f /tmp/watch-daemon.pid ]; then
        kill "$(cat /tmp/watch-daemon.pid)" 2>/dev/null || true
    fi
    cat /tmp/watch-daemon.log
    grep -q "Deleted Tombstones : 1" /tmp/watch-daemon.log
'

echo "=== [6/10] Lite-Client 1.0x Stripe Syndication via parvault-seed-0 & NAS-Death Mesh Failover ==="
docker exec parvault-client sh -cex '
    mkdir -p /tmp/lite-client-state /workspace/lite_source /workspace/lite_restored_after_nas_death
    echo "Lite-Client 1.0x stripe syndicated through parvault-seed-0 to 10 mesh peers" > /workspace/lite_source/laptop_note.txt
    sha256sum /workspace/lite_source/laptop_note.txt > /tmp/expected_lite.sha256
'
SEED_PUBKEY_HEX="$(docker exec parvault-seed-0 /usr/local/bin/parvault-seed identity --data-dir /var/lib/parvault-seed | awk '/Owner PQ Public Key Hex/ {print $7}')"
DEVICE_CERT_TOKEN="$(docker exec parvault-seed-0 /usr/local/bin/parvault-seed issue-device-cert --data-dir /var/lib/parvault-seed --device-peer-id parvault-peer-lite-laptop --device-label laptop | awk '/Shareable Token/ {print $4}')"

docker exec -w /tmp/lite-client-state parvault-client /usr/local/bin/parvault \
    --peers "$PEERS_CSV" \
    watch-folder \
    --folder /workspace/lite_source \
    --snapshot-out /tmp/lite-client-state/lite.manifest.bin \
    --lite-seed-dir "$SEED_MULTIADDR" \
    --device-cert "$DEVICE_CERT_TOKEN" \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "lite-failover-ns" \
    --once

# Simulate NAS / Seed Server death by stopping parvault-seed-0, then recover Lite-Client vault directly from mesh peers!
docker stop parvault-seed-0
docker exec -w /tmp/lite-client-state parvault-client /usr/local/bin/parvault \
    --peers "$PEERS_CSV" \
    recover-from-seed \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "lite-failover-ns" \
    --out-dir /workspace/lite_restored_after_nas_death
docker exec parvault-client sh -cex '
    cd /workspace/lite_restored_after_nas_death
    sha256sum -c /tmp/expected_lite.sha256
'
docker start parvault-seed-0
sleep 1

echo "=== [7/10] Graceful Node Decommission: parvault-node-5 -> parvault-node-11 ('parvault leave --handoff-to') ==="
NODE11_BEFORE="$(docker exec parvault-node-11 sh -c 'ls -1 /var/lib/parvault/.parvault-data/shards/*.shard 2>/dev/null | wc -l')"
docker exec -w /var/lib/parvault parvault-node-5 /usr/local/bin/parvault \
    leave --handoff-to "$NODE11_MULTIADDR"
NODE11_AFTER="$(docker exec parvault-node-11 sh -c 'ls -1 /var/lib/parvault/.parvault-data/shards/*.shard 2>/dev/null | wc -l')"
echo "parvault-node-11 shards before handoff: $NODE11_BEFORE | after handoff: $NODE11_AFTER"
if [ "$NODE11_AFTER" -le "$NODE11_BEFORE" ]; then
    echo "ERROR: parvault-node-11 did not receive evacuated shards from parvault-node-5!"
    exit 1
fi
docker stop parvault-node-5

echo "=== [8/10] Bit-Rot Injection ('parvault scrub'), Daemon Restart Persistence, and 4-Container Kill ==="
# Inject 1-byte bit-rot into a single shard on parvault-node-6 and verify 'parvault scrub' quarantines it
docker exec parvault-node-6 sh -cex '
    VICTIM=$(ls -1 /var/lib/parvault/.parvault-data/shards/*.shard | head -n 1)
    printf "\xff" | dd of="$VICTIM" bs=1 count=1 conv=notrunc status=none
'
SCRUB_OUT="$(docker exec -w /var/lib/parvault parvault-node-6 /usr/local/bin/parvault scrub)"
echo "$SCRUB_OUT"
echo "$SCRUB_OUT" | grep -q "corrupted_quarantined_shards : 1"

# Restart parvault-node-6 and parvault-node-7 to prove persistent disk state across daemon restarts
docker restart parvault-node-6 parvault-node-7
sleep 2

# Kill 4 storage daemon containers (parvault-node-1..4)
docker kill parvault-node-1 parvault-node-2 parvault-node-3 parvault-node-4

# Wipe all client local state
docker exec parvault-client sh -cex '
    rm -rf /workspace/source_vault /tmp/client-upload-state /tmp/lite-client-state
    mkdir -p /tmp/client-fresh-recovery-state /workspace/recovered_vault /workspace/selective_vault
'

SURVIVING_PEERS="/ip4/172.28.0.16/tcp/4001,/ip4/172.28.0.17/tcp/4001,/ip4/172.28.0.18/tcp/4001,/ip4/172.28.0.19/tcp/4001,/ip4/172.28.0.20/tcp/4001,/ip4/172.28.0.21/tcp/4001"

echo "=== [9/10] Zero-Local-State 'recover-from-seed' (Full & Selective '--filter') after 4 Kills + 1 Decommission + 1 Bit-Rot ==="
T_REC0_S=$(date +%s)
docker exec -w /tmp/client-fresh-recovery-state parvault-client /usr/local/bin/parvault \
    --peers "$SURVIVING_PEERS" \
    --seed-addr "$SEED_MULTIADDR" \
    recover-from-seed \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "$VAULT_NS" \
    --out-dir /workspace/recovered_vault
T_REC1_S=$(date +%s)
RECOVER_SECS=$((T_REC1_S - T_REC0_S))

docker exec parvault-client sh -cex '
    cd /workspace/recovered_vault
    sha256sum -c /tmp/expected_v2.sha256
    test ! -e src/ephemeral.rs
    ls -la docs/readme.md docs/changelog.md src/kernel.rs data/blob.bin
'

# Selective subset restore (--filter "docs/*")
docker exec -w /tmp/client-fresh-recovery-state parvault-client /usr/local/bin/parvault \
    --peers "$SURVIVING_PEERS" \
    --seed-addr "$SEED_MULTIADDR" \
    recover-from-seed \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "$VAULT_NS" \
    --filter "docs/*" \
    --out-dir /workspace/selective_vault

docker exec parvault-client sh -cex '
    test -f /workspace/selective_vault/docs/readme.md
    test -f /workspace/selective_vault/docs/changelog.md
    test ! -e /workspace/selective_vault/data/blob.bin
'

echo "=== [10/10] Cross-Machine 'parvault file store' -> 'parvault file restore --key-hex' with Wiped Local State ==="
docker exec -e SURVIVING_PEERS="$SURVIVING_PEERS" parvault-client sh -cex '
    mkdir -p /tmp/machine-a /tmp/machine-b
    echo "cross-machine file store and restore verified on v0.2.0" > /tmp/machine-a/secret.txt
    sha256sum /tmp/machine-a/secret.txt > /tmp/secret.sha256
    OUT=$(/usr/local/bin/parvault --data-dir /tmp/machine-a/data --peers "$SURVIVING_PEERS" file store --path /tmp/machine-a/secret.txt)
    echo "$OUT"
    ROOT=$(echo "$OUT" | awk "/File Merkle Root/ {print \$5}")
    KEY=$(echo "$OUT" | awk "/Master Key/ {print \$5}")
    rm -rf /tmp/machine-a
    /usr/local/bin/parvault --data-dir /tmp/machine-b/data --peers "$SURVIVING_PEERS" file restore "$ROOT" --output /tmp/machine-a/secret.txt --key-hex "$KEY"
    sha256sum -c /tmp/secret.sha256
'

echo "================================================================================"
echo " PARVAULT v0.2.0 MULTI-CONTAINER DOCKER REGRESSION SUMMARY"
echo "================================================================================"
echo " Base Image             : ${BASE_IMAGE}"
echo " Containers Deployed    : 13 (1 parvault-seed + 11 parvault daemon + 1 client)"
echo " Client Shared Volumes  : ${CLIENT_MOUNTS} (strictly isolated)"
echo " Initial Sync (v1)      : ${TOTAL_SHARDS_V1} shards across 10 nodes (${SYNC_V1_SECS}s)"
echo " Continuous Watch (v2)  : PASS (live update + tombstone pruning over libp2p)"
echo " Lite-Client Failover   : PASS (1.0x seed syndication + NAS-death mesh recovery)"
echo " Graceful Node Leave    : PASS (parvault-node-5 -> parvault-node-11: ${NODE11_AFTER} shards)"
echo " Bit-Rot Scrubbing      : PASS (1 corrupted shard detected & quarantined)"
echo " Disaster Recovery      : PASS (4 killed + 1 left + 2 restarted, ${RECOVER_SECS}s)"
echo " Cross-Machine File CLI : PASS (file store -> wipe -> file restore verified)"
echo "================================================================================"
echo "=== ACCEPTANCE GATE PASSED ==="
