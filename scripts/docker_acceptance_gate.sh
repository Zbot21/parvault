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
    parvault-status-sidecar
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
TDIR="${CARGO_TARGET_DIR:-target}"
if [ "${USE_GLIBC_IMAGE:-0}" != "1" ] && grep -q "x86_64-unknown-linux-musl" <<<"$INSTALLED_TARGETS"; then
    cargo build --release --target x86_64-unknown-linux-musl --bin parvault --bin parvault-seed
    cp "$TDIR/x86_64-unknown-linux-musl/release/parvault" "$BUILD_CTX/parvault"
    cp "$TDIR/x86_64-unknown-linux-musl/release/parvault-seed" "$BUILD_CTX/parvault-seed"
    BASE_IMAGE="alpine:3.20"
    STATUS_TARGET="--target x86_64-unknown-linux-musl"
else
    if [ ! -f "$TDIR/release/parvault" ] || [ ! -f "$TDIR/release/parvault-seed" ]; then
        cargo build --release --bin parvault --bin parvault-seed
    fi
    cp "$TDIR/release/parvault" "$BUILD_CTX/parvault"
    cp "$TDIR/release/parvault-seed" "$BUILD_CTX/parvault-seed"
    BASE_IMAGE="ubuntu:24.04"
    STATUS_TARGET=""
fi
# The sidecar with its own feature set (no tokio, no libp2p), as releases build it.
# shellcheck disable=SC2086
bash scripts/build_bins.sh --profile release $STATUS_TARGET --out "$BUILD_CTX/sidecar" parvault-status
cp "$BUILD_CTX"/sidecar/parvault-status* "$BUILD_CTX/parvault-status"
chmod +x "$BUILD_CTX/parvault" "$BUILD_CTX/parvault-seed" "$BUILD_CTX/parvault-status"

cat > "$BUILD_CTX/Dockerfile" <<EOF
FROM ${BASE_IMAGE}
RUN if command -v apt-get >/dev/null 2>&1; then (apt-get update -o Acquire::Retries=3 && apt-get install -y --no-install-recommends wget netcat-openbsd ca-certificates && rm -rf /var/lib/apt/lists/*) || true; fi
COPY parvault /usr/local/bin/parvault
COPY parvault-seed /usr/local/bin/parvault-seed
COPY parvault-status /usr/local/bin/parvault-status
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
# The seed logs with ANSI colours (field "handler_ms<ESC>[0m<ESC>[2m=84"); strip them first.
LITE_SYND_TIMES="$(docker logs parvault-seed-0 2>&1 | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -E 'lite syndication (ingested on the seed|fan-out finished)' || true)"
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

echo "=== [7b/12] Eviction council (F-08/F-09): signed manifest; member order applied; non-member refused ==="
# node-1 holds the ring genesis and signs epoch 1 of a 1-of-1 council whose member is node-2;
# nodes 2, 3 and 6 install that manifest. node-2 (a member) propagates a bounded, epoch-stamped
# order that node-6 applies; node-3 (not a member) cannot propagate at all.
NODE2_KEY="$(docker exec -w /var/lib/parvault parvault-node-2 /usr/local/bin/parvault --no-lan-discovery identity \
    | awk -F': ' '/Ed25519 Public Key/ {print $2}')"
COUNCIL_HEX="$(docker exec -w /var/lib/parvault parvault-node-1 /usr/local/bin/parvault --no-lan-discovery \
    council init --member "$NODE2_KEY" --quorum 1 | tail -n 1)"
for n in 2 3 6; do
    docker exec -w /var/lib/parvault "parvault-node-$n" /usr/local/bin/parvault --no-lan-discovery \
        council install --manifest "$COUNCIL_HEX"
done
if ! docker exec -w /var/lib/parvault parvault-node-6 /usr/local/bin/parvault --no-lan-discovery council show \
    | grep -q '^Epoch *: 1$'; then
    echo "ERROR: parvault-node-6 did not install council epoch 1"
    exit 1
fi
docker exec -w /var/lib/parvault parvault-node-2 /usr/local/bin/parvault --peers "$PEERS_CSV" --no-lan-discovery \
    evict --ip 203.0.113.77 --reason council-stage --propagate
COUNCIL_APPLIED=0
for _ in $(seq 1 20); do
    if docker logs parvault-node-6 2>&1 | grep -q 'applied an eviction order'; then
        COUNCIL_APPLIED=1
        break
    fi
    sleep 0.5
done
if [ "$COUNCIL_APPLIED" -ne 1 ]; then
    echo "ERROR: parvault-node-6 did not apply the council member's order"
    exit 1
fi
if NONMEMBER_OUT="$(docker exec -w /var/lib/parvault parvault-node-3 /usr/local/bin/parvault --peers "$PEERS_CSV" \
    --no-lan-discovery evict --ip 203.0.113.78 --propagate 2>&1)"; then
    echo "ERROR: a non-member propagated an eviction order: $NONMEMBER_OUT"
    exit 1
fi
case "$NONMEMBER_OUT" in
    *"member of the installed council"*) ;;
    *) echo "ERROR: unexpected non-member refusal: $NONMEMBER_OUT"; exit 1 ;;
esac

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
# Item 3: the status page needs a read-only token; give the appliance a known gateway root key.
SOC_STATUS_KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
docker run -d --name parvault-router-soc \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    --network parvault-acceptance-net --ip 172.28.0.60 \
    --memory=48m --memory-swap=48m \
    parvault:router-soc \
    up --profile router-soc --config /etc/parvault/router.toml --macaroon-root-key-hex "$SOC_STATUS_KEY"
sleep 2
mint_status_token() {
    docker run --rm parvault:acceptance /usr/local/bin/parvault --data-dir /tmp/mint \
        token mint --macaroon-key-hex "$1" --read-only | tr -d '\r\n'
}
SOC_STATUS_TOKEN="$(mint_status_token "$SOC_STATUS_KEY")"
# status_get <url> [token] [host]: prints the status code then the body.
status_get() {
    docker exec parvault-client sh -c '
        set -- "$1" "$2" "$3"
        hdr=""
        [ -n "$2" ] && hdr="--header=Authorization: Bearer $2"
        hosthdr=""
        [ -n "$3" ] && hosthdr="--header=Host: $3"
        out="$(wget -q -S -O- ${hdr:+"$hdr"} ${hosthdr:+"$hosthdr"} "$1" 2>&1)"
        printf "%s\n" "$out" | awk "/HTTP\\/1.1 [0-9]+/ {print \$2; exit}"
        printf "%s\n" "$out"
    ' sh "$1" "${2:-}" "${3:-}" || true
}

SOC_DAEMON_OOM="$(docker inspect -f '{{.State.OOMKilled}}' parvault-router-soc)"
SOC_DAEMON_RUNNING="$(docker inspect -f '{{.State.Running}}' parvault-router-soc)"
if [ "$SOC_DAEMON_OOM" != "false" ] || [ "$SOC_DAEMON_RUNNING" != "true" ]; then
    echo "ERROR: parvault-router-soc daemon failed inside 48m cgroup (OOMKilled=$SOC_DAEMON_OOM, Running=$SOC_DAEMON_RUNNING)"
    docker logs parvault-router-soc || true
    exit 1
fi

# Verify embedded RouterNasStatusServer HTTP telemetry on 172.28.0.60:4080
SOC_NO_TOKEN_CODE="$(status_get http://172.28.0.60:4080/api/v1/health | head -1)"
if [ "$SOC_NO_TOKEN_CODE" != "401" ]; then
    echo "ERROR: router-soc status page answered $SOC_NO_TOKEN_CODE without a token (want 401)"
    exit 1
fi
SOC_HEALTH_JSON="$(status_get http://172.28.0.60:4080/api/v1/health "$SOC_STATUS_TOKEN")"
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

echo "=== [12b/12] parvault-status sidecar: no key, token-gated status over the gateway socket ==="
SIDE_KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
SIDE_TOKEN="$(mint_status_token "$SIDE_KEY")"
docker run -d --name parvault-status-sidecar \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    -e SIDE_KEY="$SIDE_KEY" -e SIDE_TOKEN="$SIDE_TOKEN" \
    --network parvault-acceptance-net --ip 172.28.0.61 \
    --memory=48m --memory-swap=48m \
    parvault:acceptance sh -c '
        mkdir -p /run/pv /var/lib/parvault /tmp/sidecar-cwd
        /usr/local/bin/parvault --data-dir /var/lib/parvault --no-lan-discovery up --profile router-soc \
            --ipc-socket /run/pv/gw.sock --macaroon-root-key-hex "$SIDE_KEY" > /tmp/daemon.log 2>&1 &
        i=0; while [ ! -S /run/pv/gw.sock ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done
        cd /tmp/sidecar-cwd
        (umask 077; printf "%s\n" "$SIDE_TOKEN" > /run/pv/status.token)
        exec /usr/local/bin/parvault-status --socket /run/pv/gw.sock --listen 0.0.0.0:4081 --macaroon-file /run/pv/status.token'
SIDE_UP=0
for _ in $(seq 1 100); do
    if docker logs parvault-status-sidecar 2>&1 | grep -q "Status Server listening"; then SIDE_UP=1; break; fi
    sleep 0.2
done
if [ "$SIDE_UP" != "1" ]; then
    echo "ERROR: parvault-status did not start"; docker logs parvault-status-sidecar || true
    docker exec parvault-status-sidecar cat /tmp/daemon.log || true
    exit 1
fi
SIDE_OK="$(status_get http://172.28.0.61:4081/api/v1/health "$SIDE_TOKEN")"
SIDE_NONE="$(status_get http://172.28.0.61:4081/api/v1/health | head -1)"
SIDE_DNS="$(status_get http://172.28.0.61:4081/api/v1/health "$SIDE_TOKEN" rebind.example:4081 | head -1)"
SIDE_QUERY="$(status_get "http://172.28.0.61:4081/api/v1/health?token=$SIDE_TOKEN" | head -1)"
echo "sidecar: token=$(echo "$SIDE_OK" | head -1) none=$SIDE_NONE dns-host=$SIDE_DNS query-token=$SIDE_QUERY"
if [ "$(echo "$SIDE_OK" | head -1)" != "200" ] || ! echo "$SIDE_OK" | grep -q '"version"' \
    || [ "$SIDE_NONE" != "401" ] || [ "$SIDE_DNS" != "403" ] || [ "$SIDE_QUERY" != "401" ]; then
    echo "ERROR: parvault-status sidecar answers wrong"; docker logs parvault-status-sidecar || true
    exit 1
fi
SIDE_WRITTEN="$(docker exec parvault-status-sidecar sh -c 'ls -A /tmp/sidecar-cwd | wc -l')"
if [ "$SIDE_WRITTEN" != "0" ]; then
    echo "ERROR: parvault-status wrote files in its working directory"; exit 1
fi
if docker logs parvault-status-sidecar 2>&1 | grep -qF "$SIDE_TOKEN"; then
    echo "ERROR: the status token is in the sidecar log"; exit 1
fi
SIDE_OOM="$(docker inspect -f '{{.State.OOMKilled}}' parvault-status-sidecar)"
[ "$SIDE_OOM" = "false" ] || { echo "ERROR: sidecar container OOMKilled"; exit 1; }
SIDE_BIN_BYTES="$(docker exec parvault-status-sidecar stat -c%s /usr/local/bin/parvault-status)"

echo "=== [12c/12] Mounted MP4 probe and random seek: /dev/fuse and WebDAV 206, then netem 15ms/2% ==="
# Plan-5 / design ledger 7.2. The release test binary tests/vfs_mp4_seek_gate.rs runs in a glibc
# image with fuse3 and ffmpeg. FUSE leg: --device /dev/fuse + SYS_ADMIN. WebDAV leg: an
# unprivileged container (no device, no caps), then the same leg with tc netem on its loopback,
# which delays the HTTP hop between ffmpeg and the WebDAV edge (stripes stay local: a mesh-fetched
# netem leg is deferred). A missing /dev/fuse is SKIPPED, and a FAIL under GATES_REQUIRE_REAL=1.
VFS_CTX="/tmp/parvault-acceptance-vfs"
rm -rf "$VFS_CTX"
mkdir -p "$VFS_CTX"
VFS_TEST_BIN="$(cargo test --release --test vfs_mp4_seek_gate --no-run --message-format=json 2>/dev/null \
    | sed -n 's/.*"executable":"\([^"]*vfs_mp4_seek_gate[^"]*\)".*/\1/p' | tail -1)"
[ -x "$VFS_TEST_BIN" ] || { echo "ERROR: stage 12c: no vfs_mp4_seek_gate test binary"; exit 1; }
cargo build --release --bin parvault-fuse
cp "$VFS_TEST_BIN" "$VFS_CTX/vfs_mp4_seek_gate"
cp "$TDIR/release/parvault-fuse" "$VFS_CTX/parvault-fuse"
cat > "$VFS_CTX/Dockerfile" <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -o Acquire::Retries=3 \
    && apt-get install -y --no-install-recommends fuse3 ffmpeg iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY vfs_mp4_seek_gate /usr/local/bin/vfs_mp4_seek_gate
COPY parvault-fuse /usr/local/bin/parvault-fuse
ENV PARVAULT_FUSE_BIN=/usr/local/bin/parvault-fuse TMPDIR=/var/tmp
ENTRYPOINT ["/usr/local/bin/vfs_mp4_seek_gate", "--test-threads=1", "--nocapture"]
EOF
docker build -t parvault:acceptance-vfs "$VFS_CTX"

VFS_FUSE_RESULT="SKIPPED (no /dev/fuse)"
if [ -c /dev/fuse ] && docker run --rm --device /dev/fuse --cap-add SYS_ADMIN \
        --security-opt apparmor:unconfined --entrypoint test parvault:acceptance-vfs -c /dev/fuse; then
    docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
        -e GATES_REQUIRE_REAL=1 parvault:acceptance-vfs \
        fuse_mount_mp4_probe_and_random_seek parvault_fuse_plugin_mount_rss_under_16_mib \
        || { echo "ERROR: stage 12c: the FUSE leg failed"; exit 1; }
    VFS_FUSE_RESULT="PASS"
elif [ "${GATES_REQUIRE_REAL:-0}" = "1" ]; then
    echo "ERROR: stage 12c: /dev/fuse cannot be passed into a container (GATES_REQUIRE_REAL=1)"
    exit 1
else
    echo "SKIPPED: stage 12c FUSE leg: /dev/fuse cannot be passed into a container"
fi

# Unprivileged WebDAV leg: no device, no capabilities.
docker run --rm -e GATES_REQUIRE_REAL=1 parvault:acceptance-vfs webdav_206_mp4_probe_and_random_seek \
    || { echo "ERROR: stage 12c: the unprivileged WebDAV leg failed"; exit 1; }

# netem leg: NET_ADMIN only for tc; a 100 ms budget, and the cache cap. The per-block miss set is
# logged, not asserted: under latency an abandoned `Range: bytes=N-` can hydrate up to about one
# TCP window of extra blocks (B-23, v0.6.0).
docker run --rm --cap-add NET_ADMIN -e GATES_REQUIRE_REAL=1 -e PARVAULT_VFS_TTFB_BUDGET_MS=100 \
    -e PARVAULT_VFS_GATE_LATENCY=1 \
    --entrypoint sh parvault:acceptance-vfs -c \
    'tc qdisc add dev lo root netem delay 15ms loss 2% && exec /usr/local/bin/vfs_mp4_seek_gate --test-threads=1 --nocapture webdav_206_mp4_probe_and_random_seek' \
    || { echo "ERROR: stage 12c: the WebDAV leg under netem 15ms/2% failed"; exit 1; }
echo "Mounted MP4 gate verified: FUSE ${VFS_FUSE_RESULT}; WebDAV 206 PASS (plain and under netem)."

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
echo " Eviction Council       : PASS (signed manifest epoch 1; member order applied; non-member refused)"
echo " Graceful Node Leave    : PASS (parvault-node-5 -> parvault-node-11: ${NODE11_AFTER} shards)"
echo " Bit-Rot Scrubbing      : PASS (1 corrupted shard detected & quarantined)"
echo " Disaster Recovery      : PASS (4 killed + 1 left + 2 restarted, ${RECOVER_SECS}s)"
echo " Cross-Machine File CLI : PASS (file store -> wipe -> file restore verified)"
echo " Router-SoC Binary      : ${SOC_BIN_MIB} stripped static musl (--profile soc)"
echo " Router-SoC Image       : ${ROUTER_SOC_IMAGE_SIZE} (FROM scratch)"
echo " 48 MiB Cgroup SoC Gate : PASS (5 x 1 MiB stripes store+restore, 0 OOM kills)"
echo " Status page (item 3)   : PASS (router-soc: no token 401, read-only token 200)"
echo " parvault-status sidecar: PASS (200 / 401 / DNS Host 403 / ?token= 401; no files; ${SIDE_BIN_BYTES} B)"
echo " Mounted MP4 (item 5)   : FUSE ${VFS_FUSE_RESULT}; WebDAV 206 PASS (plain + netem 15ms/2%, < 100 ms)"
echo "================================================================================"
echo "=== ACCEPTANCE GATE PASSED ==="
