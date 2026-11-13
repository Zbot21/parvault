#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CONTAINERS=(
    parvault-seed-0
    parvault-client
    parvault-router-soc
    parvault-soc-store
    parvault-soc-restore
    parvault-soc-extract
    parvault-invitee
    parvault-outsider
)
for i in $(seq 1 11); do
    CONTAINERS+=("parvault-node-$i")
done

SOC_VOL_NAME="parvault-soc-nas-vol"

# v0.5.0 ring admission: every container shares one ring genesis (fresh per gate run), so the
# nodes, the seed and the clients admit each other.
RING_GENESIS_SEED_HEX="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"

cleanup() {
    if [ "${KEEP_CONTAINERS:-0}" != "1" ]; then
        docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
        docker volume rm -f "$SOC_VOL_NAME" >/dev/null 2>&1 || true
        docker network rm parvault-acceptance-net >/dev/null 2>&1 || true
        rm -rf /tmp/parvault-soc-bin >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "=== [1/12] Building ParVault binaries & parvault:acceptance container image ==="
BUILD_CTX="/tmp/parvault-acceptance-image"
rm -rf "$BUILD_CTX"
mkdir -p "$BUILD_CTX"

# Capture before grepping: with pipefail, `cmd | grep -q` fails when grep exits early and cmd
# gets SIGPIPE.
INSTALLED_TARGETS="$(rustup target list --installed 2>/dev/null || true)"
if [ "${USE_GLIBC_IMAGE:-0}" != "1" ] && grep -q "x86_64-unknown-linux-musl" <<<"$INSTALLED_TARGETS"; then
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
RUN if command -v apt-get >/dev/null 2>&1; then (apt-get update -o Acquire::Retries=3 && apt-get install -y --no-install-recommends wget netcat-openbsd ca-certificates && rm -rf /var/lib/apt/lists/*) || true; fi
COPY parvault /usr/local/bin/parvault
COPY parvault-seed /usr/local/bin/parvault-seed
EXPOSE 4001/tcp 4002/tcp 4009/udp 4080/tcp
EOF

docker build -t parvault:acceptance "$BUILD_CTX"

echo "=== [2/12] Creating isolated Docker bridge network (172.28.0.0/24) ==="
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

echo "=== [3/12] Starting parvault-seed-0 + 11 parvault daemon containers + 1 isolated client container ==="
docker run -d --name parvault-seed-0 \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
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
        -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
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
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
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

echo "=== [3b/12] Ring membership: an invited node serves the ring; a non-member is refused ==="
# The invitee never holds the ring secret: it joins with 'wot invite' (on a ring member) and
# 'wot install-chain', then runs a daemon that stores a ring member's file.
docker run -d --name parvault-invitee \
    --network parvault-acceptance-net --ip 172.28.0.40 \
    parvault:acceptance \
    sleep 3600
INVITEE_KEY="$(docker exec parvault-invitee /usr/local/bin/parvault --data-dir /var/lib/invitee --no-lan-discovery identity \
    | awk -F': ' '/Ed25519 Public Key/ {print $2}')"
RING_TOKEN="$(docker exec parvault-node-1 /usr/local/bin/parvault --data-dir /tmp/ring-inviter --no-lan-discovery \
    wot invite --peer "$INVITEE_KEY")"
docker exec parvault-invitee /usr/local/bin/parvault --data-dir /var/lib/invitee --no-lan-discovery \
    wot install-chain --token "$RING_TOKEN"
if docker exec parvault-invitee test -e /var/lib/invitee/ring_genesis.seed; then
    echo "ERROR: the invitee holds a ring genesis secret"
    exit 1
fi
docker exec -d parvault-invitee /usr/local/bin/parvault --data-dir /var/lib/invitee --no-lan-discovery \
    daemon start --listen /ip4/0.0.0.0/tcp/4001
sleep 3
docker exec parvault-client sh -cex '
    mkdir -p /tmp/ring-check
    echo "stored on an invited ring member" > /tmp/ring-check/doc.txt
    /usr/local/bin/parvault --data-dir /tmp/ring-check/data --no-lan-discovery \
        --peers /ip4/172.28.0.40/tcp/4001 file store --path /tmp/ring-check/doc.txt
'
# The outsider runs its own ring: its credential does not admit it to this ring.
docker run -d --name parvault-outsider \
    --network parvault-acceptance-net --ip 172.28.0.41 \
    parvault:acceptance \
    sleep 3600
docker exec parvault-outsider /usr/local/bin/parvault --data-dir /var/lib/outsider --no-lan-discovery wot init
docker exec parvault-outsider sh -c 'echo "outsider data" > /tmp/outsider.txt'
# The outsider is refused, keeps the stripe locally, says it is not backed up and exits 3.
set +e
OUTSIDER_OUT="$(docker exec parvault-outsider /usr/local/bin/parvault --data-dir /var/lib/outsider \
    --no-lan-discovery --peers /ip4/172.28.0.11/tcp/4001 file store --path /tmp/outsider.txt 2>&1)"
OUTSIDER_RC=$?
set -e
echo "$OUTSIDER_OUT"
if [ "$OUTSIDER_RC" -ne 3 ] || ! grep -q "NOT backed up" <<<"$OUTSIDER_OUT"; then
    echo "ERROR: the outsider's store did not report NOT backed up with exit 3 (exit $OUTSIDER_RC)"
    exit 1
fi
OUTSIDER_ROOT="$(awk '/File Merkle Root/ {print $5}' <<<"$OUTSIDER_OUT")"
if [ "${#OUTSIDER_ROOT}" -ne 64 ]; then
    echo "ERROR: could not read the outsider's stripe root from its store output"
    exit 1
fi
# The daemon creates its shards directory at start, so it must exist.
if ! NODE1_SHARDS="$(docker exec parvault-node-1 ls /var/lib/parvault/.parvault-data/shards)"; then
    echo "ERROR: node-1 has no shards directory to check"
    exit 1
fi
if grep -q "^${OUTSIDER_ROOT:0:16}" <<<"$NODE1_SHARDS"; then
    echo "ERROR: a non-member stored data on a ring node"
    exit 1
fi
# Capture the log first: `docker logs | grep -q` fails under pipefail once the log is long.
NODE1_LOG="$(docker logs parvault-node-1 2>&1)"
if ! grep -q "reject.peer_not_admitted" <<<"$NODE1_LOG"; then
    echo "ERROR: the ring node did not log the refusal"
    exit 1
fi
echo "Ring membership verified: invitee served the ring, outsider refused."

echo "=== [4/12] Zero-IP Home LAN Auto-Discovery ('parvault discover') over 172.28.0.0/24 Bridge ==="
DISCOVER_TABLE="$(docker exec parvault-client /usr/local/bin/parvault --data-dir /tmp/zero-ip-discover discover --timeout-ms 1200)"
echo "$DISCOVER_TABLE"
DISCOVER_JSON="$(docker exec parvault-client /usr/local/bin/parvault --data-dir /tmp/zero-ip-discover discover --json --timeout-ms 1200)"
DISCOVERED_COUNT="$(echo "$DISCOVER_JSON" | grep -c '"peer_id"' || true)"
echo "Zero-IP discovered verified LAN peers on 172.28.0.0/24: $DISCOVERED_COUNT"
if [ "$DISCOVERED_COUNT" -lt 10 ]; then
    echo "ERROR: Expected parvault discover (with zero IP arguments) to find >= 10 LAN daemons, found $DISCOVERED_COUNT"
    echo "$DISCOVER_JSON"
    exit 1
fi

# Also prove zero-`--peers` file store & restore over Docker bridge auto-discovery.
# The CLI never prints the master key (W-02): store and restore with one explicit key.
ZKEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
docker exec -e ZKEY="$ZKEY" parvault-client sh -cex '
    mkdir -p /tmp/zero-ip-store /tmp/zero-ip-restore
    echo "Zero-IP LAN discovery file store/restore over 172.28.0.0/24 bridge" > /tmp/zero-ip-store/lan_zero_ip.txt
    sha256sum /tmp/zero-ip-store/lan_zero_ip.txt > /tmp/lan_zero_ip.sha256
    ZOUT=$(/usr/local/bin/parvault --data-dir /tmp/zero-ip-store/data file store --path /tmp/zero-ip-store/lan_zero_ip.txt --key-hex "$ZKEY")
    echo "$ZOUT"
    ZROOT=$(echo "$ZOUT" | awk "/File Merkle Root/ {print \$5}")
    rm -rf /tmp/zero-ip-store
    /usr/local/bin/parvault --data-dir /tmp/zero-ip-restore/data file restore "$ZROOT" --output /tmp/zero-ip-store/lan_zero_ip.txt --key-hex "$ZKEY"
    sha256sum -c /tmp/lan_zero_ip.sha256
'

SEED_PHRASE="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
VAULT_NS="docker-live-acceptance-vault"

echo "=== [5/12] Initial Backup (Snapshot v1): 'parvault watch-folder --once' over libp2p ==="
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

echo "=== [6/12] Continuous Background Backup Daemon ('watch-folder --interval-secs 1 --prune-deleted') ==="
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
    echo "## v0.3.0 Live Multi-Container Regression Verified" > /workspace/source_vault/docs/changelog.md
    rm -f /workspace/source_vault/src/ephemeral.rs
    cd /workspace/source_vault
    sha256sum docs/readme.md docs/changelog.md src/kernel.rs data/blob.bin > /tmp/expected_v2.sha256
    cat /tmp/expected_v2.sha256
'

# Wait for continuous watch-folder daemon to complete pass v2 (including Catalog Envelope DHT publish!) and stop it cleanly
for attempt in $(seq 1 25); do
    if docker exec parvault-client awk '/Deleted Tombstones : 1/{found=1} found && /Catalog Envelope/{ok=1} END{exit !ok}' /tmp/watch-daemon.log 2>/dev/null; then
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

echo "=== [7/12] Lite-Client 1.0x Stripe Syndication via parvault-seed-0 & NAS-Death Mesh Failover ==="
docker exec parvault-client sh -cex '
    mkdir -p /tmp/lite-client-state /workspace/lite_source /workspace/lite_restored_after_nas_death
    echo "Lite-Client 1.0x stripe syndicated through parvault-seed-0 to 10 mesh peers" > /workspace/lite_source/laptop_note.txt
    sha256sum < /workspace/lite_source/laptop_note.txt | cut -d " " -f1 > /tmp/expected_lite.hash
'
# Every shard file in the client container before the lite run (other stages' vaults live here).
LITE_SHARDS_BEFORE="$(docker exec parvault-client sh -c 'find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -name "*.shard" -type f -print 2>/dev/null | sort')"
SEED_PUBKEY_HEX="$(docker exec parvault-seed-0 /usr/local/bin/parvault-seed identity --data-dir /var/lib/parvault-seed | awk '/Owner PQ Public Key Hex/ {print $7}')"
# The lite client syndicates as its vault identity, which also signs the repair grant (F-25,
# F-38): the cert names the Vault Device Peer ID that `parvault identity --seed-phrase` prints.
LITE_DEVICE_ID="$(docker exec -w /tmp/lite-client-state parvault-client /usr/local/bin/parvault identity \
    --seed-phrase "$SEED_PHRASE" --vault-namespace "lite-failover-ns" 2>/dev/null | awk '/Vault Device Peer ID/ {print $6}')"
if [ -z "$LITE_DEVICE_ID" ]; then
    echo "ERROR: could not read the Vault Device Peer ID"
    exit 1
fi
DEVICE_CERT_TOKEN="$(docker exec parvault-seed-0 /usr/local/bin/parvault-seed issue-device-cert --data-dir /var/lib/parvault-seed --device-peer-id "$LITE_DEVICE_ID" --device-label laptop | awk '/Shareable Token/ {print $4}')"

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

# B-SEED-SYND (L-46): the seed logs its in-lock handler time and its off-task fan-out time.
LITE_SYND_TIMES="$(docker logs parvault-seed-0 2>&1 | grep -E 'lite syndication (ingested on the seed|fan-out finished)' || true)"
echo "$LITE_SYND_TIMES"
if ! echo "$LITE_SYND_TIMES" | grep -q 'handler_ms=' || ! echo "$LITE_SYND_TIMES" | grep -q 'job_ms='; then
    echo "ERROR: stage 7: parvault-seed-0 logged no lite syndication handler/job durations"
    exit 1
fi

# Simulate NAS / Seed Server death by stopping parvault-seed-0, then recover the Lite-Client vault
# from mesh peers only. By design a successful lite syndication deletes the client's local shards
# (src/cli/folder.rs, after syndication), so there is nothing to wipe: instead assert the lite run
# left no shard file anywhere in the container, hide the source folder, and restore into a fresh
# data dir and working dir, so the restore can read neither local shards nor the original file.
LITE_SHARDS_AFTER="$(docker exec parvault-client sh -c 'find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -name "*.shard" -type f -print 2>/dev/null | sort')"
LITE_NEW_SHARDS="$(comm -13 <(printf '%s\n' "$LITE_SHARDS_BEFORE") <(printf '%s\n' "$LITE_SHARDS_AFTER") | sed '/^$/d')"
if [ -n "$LITE_NEW_SHARDS" ]; then
    echo "ERROR: stage 7: the lite run kept local shards, so the restore could read them:"
    echo "$LITE_NEW_SHARDS"
    exit 1
fi
if ! docker exec parvault-client test -s /tmp/lite-client-state/lite.manifest.bin; then
    echo "ERROR: stage 7: the lite run wrote no snapshot; nothing was synced"
    exit 1
fi
docker exec parvault-client sh -cex '
    mv /workspace/lite_source /workspace/lite_source.hidden-for-restore
    mkdir -p /tmp/lite-restore-fresh/data /tmp/lite-restore-fresh/cwd
    test -z "$(ls -A /tmp/lite-restore-fresh/data)"
'
docker stop parvault-seed-0
docker exec -w /tmp/lite-restore-fresh/cwd parvault-client /usr/local/bin/parvault \
    --data-dir /tmp/lite-restore-fresh/data \
    --peers "$PEERS_CSV" \
    recover-from-seed \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "lite-failover-ns" \
    --out-dir /workspace/lite_restored_after_nas_death
# Compare the restored file's content (not a path: a path-based check would re-hash the source).
docker exec parvault-client sh -cex '
    test ! -e /workspace/lite_source
    RESTORED="$(find /workspace/lite_restored_after_nas_death -type f -name laptop_note.txt)"
    test "$(printf "%s\n" "$RESTORED" | sed "/^$/d" | wc -l)" -eq 1
    test "$(sha256sum < "$RESTORED" | cut -d " " -f1)" = "$(cat /tmp/expected_lite.hash)"
'
docker start parvault-seed-0
for attempt in $(seq 1 30); do
    if docker exec parvault-client nc -z 172.28.0.10 4002 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "=== [8/12] Graceful Node Decommission: parvault-node-5 -> parvault-node-11 ('parvault leave --handoff-to') ==="
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

echo "=== [9/12] Bit-Rot Injection ('parvault scrub'), Daemon Restart Persistence, and 4-Container Kill ==="
# Inject 1-byte bit-rot into a single shard on parvault-node-6 and verify 'parvault scrub' quarantines it
docker exec parvault-node-6 sh -cex '
    VICTIM=$(ls -1 /var/lib/parvault/.parvault-data/shards/*.shard | head -n 1)
    printf "\xff" | dd of="$VICTIM" bs=1 count=1 conv=notrunc status=none
'
SCRUB_OUT="$(docker exec -w /var/lib/parvault parvault-node-6 /usr/local/bin/parvault scrub)"
echo "$SCRUB_OUT"
grep -q "corrupted_quarantined_shards : 1" <<<"$SCRUB_OUT"

# Restart parvault-node-6 and parvault-node-7 to prove persistent disk state across daemon restarts
docker restart parvault-node-6 parvault-node-7
for ip in 172.28.0.16 172.28.0.17; do
    for attempt in $(seq 1 30); do
        if docker exec parvault-client nc -z "$ip" 4001 >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
done

# Kill 4 storage daemon containers (parvault-node-1..4)
docker kill parvault-node-1 parvault-node-2 parvault-node-3 parvault-node-4

# Wipe all client local state
docker exec parvault-client sh -cex '
    rm -rf /workspace/source_vault /tmp/client-upload-state /tmp/lite-client-state
    mkdir -p /tmp/client-fresh-recovery-state /workspace/recovered_vault /workspace/selective_vault
'

SURVIVING_PEERS="/ip4/172.28.0.16/tcp/4001,/ip4/172.28.0.17/tcp/4001,/ip4/172.28.0.18/tcp/4001,/ip4/172.28.0.19/tcp/4001,/ip4/172.28.0.20/tcp/4001,/ip4/172.28.0.21/tcp/4001"

echo "=== [10/12] Zero-Local-State 'recover-from-seed' (Full & Selective '--filter') after 4 Kills + 1 Decommission + 1 Bit-Rot ==="
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

echo "=== [11/12] Cross-Machine 'parvault file store' -> 'parvault file restore --key-hex' with Wiped Local State ==="
XKEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
docker exec -e SURVIVING_PEERS="$SURVIVING_PEERS" -e KEY="$XKEY" parvault-client sh -cex '
    mkdir -p /tmp/machine-a /tmp/machine-b
    echo "cross-machine file store and restore verified on v0.3.0" > /tmp/machine-a/secret.txt
    sha256sum /tmp/machine-a/secret.txt > /tmp/secret.sha256
    OUT=$(/usr/local/bin/parvault --data-dir /tmp/machine-a/data --peers "$SURVIVING_PEERS" file store --path /tmp/machine-a/secret.txt --key-hex "$KEY")
    echo "$OUT"
    ROOT=$(echo "$OUT" | awk "/File Merkle Root/ {print \$5}")
    rm -rf /tmp/machine-a
    /usr/local/bin/parvault --data-dir /tmp/machine-b/data --peers "$SURVIVING_PEERS" file restore "$ROOT" --output /tmp/machine-a/secret.txt --key-hex "$KEY"
    sha256sum -c /tmp/secret.sha256
'

echo "=== [12/12] Building deploy/Dockerfile.router-soc (FROM scratch) & Live 48 MiB Cgroup SoC Proof ==="
docker build -f deploy/Dockerfile.router-soc -t parvault:router-soc .
docker images parvault:router-soc
ROUTER_SOC_IMAGE_SIZE="$(docker images parvault:router-soc --format '{{.Size}}')"

docker rm -f parvault-soc-extract >/dev/null 2>&1 || true
docker create --name parvault-soc-extract parvault:router-soc >/dev/null
docker cp parvault-soc-extract:/parvault /tmp/parvault-soc-bin
docker rm -f parvault-soc-extract >/dev/null
SOC_BIN_BYTES="$(stat -c%s /tmp/parvault-soc-bin)"
SOC_BIN_MIB="$(awk "BEGIN {printf \"%.2f MiB\", ${SOC_BIN_BYTES}/1048576}")"
echo "Stripped parvault (--profile soc, musl) binary size: ${SOC_BIN_MIB} (${SOC_BIN_BYTES} bytes)"
echo "Total parvault:router-soc (FROM scratch) image size : ${ROUTER_SOC_IMAGE_SIZE}"

# Start a live `parvault:router-soc` appliance container constrained to --memory=48m --memory-swap=48m
docker run -d --name parvault-router-soc \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    --network parvault-acceptance-net --ip 172.28.0.60 \
    --memory=48m --memory-swap=48m \
    parvault:router-soc
sleep 2

SOC_DAEMON_OOM="$(docker inspect -f '{{.State.OOMKilled}}' parvault-router-soc)"
SOC_DAEMON_RUNNING="$(docker inspect -f '{{.State.Running}}' parvault-router-soc)"
if [ "$SOC_DAEMON_OOM" != "false" ] || [ "$SOC_DAEMON_RUNNING" != "true" ]; then
    echo "ERROR: parvault-router-soc daemon failed inside 48m cgroup (OOMKilled=$SOC_DAEMON_OOM, Running=$SOC_DAEMON_RUNNING)"
    docker logs parvault-router-soc || true
    exit 1
fi

# Verify embedded RouterNasStatusServer HTTP telemetry on 172.28.0.60:4080
SOC_HEALTH_JSON="$(docker exec parvault-client sh -c '
    if command -v wget >/dev/null 2>&1; then
        wget -qO- http://172.28.0.60:4080/api/v1/health
    else
        bash -c '\''exec 3<>/dev/tcp/172.28.0.60/4080 && printf "GET /api/v1/health HTTP/1.0\r\nHost: 172.28.0.60\r\nConnection: close\r\n\r\n" >&3 && cat <&3'\'' | sed "1,/^\r\{0,1\}$/d"
    fi
' || true)"
echo "parvault-router-soc /api/v1/health: $SOC_HEALTH_JSON"
echo "$SOC_HEALTH_JSON" | grep -Eq '"hardware_profile"[[:space:]]*:[[:space:]]*"router-soc"'

# Store and restore a multi-stripe (5 MiB = 5 x 1 MiB stripes) payload inside a 48 MiB cgroup container!
docker volume rm -f "$SOC_VOL_NAME" >/dev/null 2>&1 || true
docker volume create "$SOC_VOL_NAME" >/dev/null
SOC_EXPECTED_SHA256="$(docker run --rm -v "$SOC_VOL_NAME:/mnt/nas" parvault:acceptance sh -ce '
    mkdir -p /mnt/nas/store-data /mnt/nas/restore-data
    dd if=/dev/urandom of=/mnt/nas/router_soc_5mib.bin bs=1048576 count=5 status=none
    sha256sum /mnt/nas/router_soc_5mib.bin | awk "{print \$1}"
')"

SOC_KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
SOC_STORE_OUT="$(docker run --name parvault-soc-store \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    --network parvault-acceptance-net \
    --memory=48m --memory-swap=48m \
    -v "$SOC_VOL_NAME:/mnt/nas" \
    parvault:router-soc \
    --profile router-soc \
    --data-dir /mnt/nas/store-data \
    file store --path /mnt/nas/router_soc_5mib.bin --key-hex "$SOC_KEY")"
echo "$SOC_STORE_OUT"

SOC_STORE_OOM="$(docker inspect -f '{{.State.OOMKilled}}' parvault-soc-store)"
SOC_STORE_EXIT="$(docker inspect -f '{{.State.ExitCode}}' parvault-soc-store)"
docker rm -f parvault-soc-store >/dev/null
if [ "$SOC_STORE_OOM" != "false" ] || [ "$SOC_STORE_EXIT" != "0" ]; then
    echo "ERROR: parvault-soc-store hit OOM or failed in 48m cgroup (OOMKilled=$SOC_STORE_OOM, Exit=$SOC_STORE_EXIT)"
    exit 1
fi
echo "$SOC_STORE_OUT" | grep -Eq "Total Stripes[[:space:]]*:[[:space:]]*5"

SOC_ROOT="$(echo "$SOC_STORE_OUT" | awk '/File Merkle Root/ {print $5}')"

# Wipe local store-data so restore pulls all 5 stripes over libp2p inside another 48 MiB cgroup container!
docker run --rm -v "$SOC_VOL_NAME:/mnt/nas" parvault:acceptance rm -rf /mnt/nas/store-data

SOC_RESTORE_OUT="$(docker run --name parvault-soc-restore \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    --network parvault-acceptance-net \
    --memory=48m --memory-swap=48m \
    -v "$SOC_VOL_NAME:/mnt/nas" \
    parvault:router-soc \
    --profile router-soc \
    --data-dir /mnt/nas/restore-data \
    file restore "$SOC_ROOT" --output /mnt/nas/restored_5mib.bin --key-hex "$SOC_KEY")"
echo "$SOC_RESTORE_OUT"

SOC_RESTORE_OOM="$(docker inspect -f '{{.State.OOMKilled}}' parvault-soc-restore)"
SOC_RESTORE_EXIT="$(docker inspect -f '{{.State.ExitCode}}' parvault-soc-restore)"
docker rm -f parvault-soc-restore >/dev/null
if [ "$SOC_RESTORE_OOM" != "false" ] || [ "$SOC_RESTORE_EXIT" != "0" ]; then
    echo "ERROR: parvault-soc-restore hit OOM or failed in 48m cgroup (OOMKilled=$SOC_RESTORE_OOM, Exit=$SOC_RESTORE_EXIT)"
    exit 1
fi

SOC_ACTUAL_SHA256="$(docker run --rm -v "$SOC_VOL_NAME:/mnt/nas" parvault:acceptance sh -ce 'sha256sum /mnt/nas/restored_5mib.bin | awk "{print \$1}"')"
if [ "$SOC_ACTUAL_SHA256" != "$SOC_EXPECTED_SHA256" ]; then
    echo "ERROR: SHA-256 mismatch after 48m cgroup Router-SoC restore ($SOC_ACTUAL_SHA256 != $SOC_EXPECTED_SHA256)"
    exit 1
fi

SOC_DAEMON_OOM_AFTER="$(docker inspect -f '{{.State.OOMKilled}}' parvault-router-soc)"
if [ "$SOC_DAEMON_OOM_AFTER" != "false" ]; then
    echo "ERROR: parvault-router-soc daemon OOMKilled during multi-stripe transfer!"
    exit 1
fi

echo "================================================================================"
echo " PARVAULT v0.3.0 MULTI-CONTAINER & ROUTER-SOC DOCKER ACCEPTANCE SUMMARY"
echo "================================================================================"
echo " Base Image             : ${BASE_IMAGE}"
echo " Containers Deployed    : 16 (1 parvault-seed + 11 daemon + 1 router-soc + 1 client + 1 invitee + 1 outsider)"
echo " Client Shared Volumes  : ${CLIENT_MOUNTS} (strictly isolated)"
echo " Zero-IP LAN Discovery  : PASS (${DISCOVERED_COUNT} daemons auto-discovered with 0 IPs)"
echo " Initial Sync (v1)      : ${TOTAL_SHARDS_V1} shards across 10 nodes (${SYNC_V1_SECS}s)"
echo " Continuous Watch (v2)  : PASS (live update + tombstone pruning over libp2p)"
echo " Lite-Client Failover   : PASS (1.0x seed syndication + NAS-death mesh recovery)"
echo " Graceful Node Leave    : PASS (parvault-node-5 -> parvault-node-11: ${NODE11_AFTER} shards)"
echo " Bit-Rot Scrubbing      : PASS (1 corrupted shard detected & quarantined)"
echo " Disaster Recovery      : PASS (4 killed + 1 left + 2 restarted, ${RECOVER_SECS}s)"
echo " Cross-Machine File CLI : PASS (file store -> wipe -> file restore verified)"
echo " Router-SoC Binary      : ${SOC_BIN_MIB} stripped static musl (--profile soc)"
echo " Router-SoC Image       : ${ROUTER_SOC_IMAGE_SIZE} (FROM scratch)"
echo " 48 MiB Cgroup SoC Gate : PASS (5 x 1 MiB stripes store+restore, 0 OOM kills)"
echo "================================================================================"
echo "=== ACCEPTANCE GATE PASSED ==="
