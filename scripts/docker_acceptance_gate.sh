#!/usr/bin/env bash
# ParVault multi-container Docker acceptance gate (12 stages).
#
# Concurrency (B-110): every Docker resource this run creates is private to it, so two gates can
# run on one host at once. RUN_ID="${PARVAULT_GATE_RUN_ID:-$$-$RANDOM}" (lowercase [a-z0-9_.-])
# suffixes every container (parvault-<role>-$RUN_ID), the network (parvault-acceptance-net-$RUN_ID),
# the volume, the image tags (parvault:acceptance-$RUN_ID, parvault:acceptance-vfs-$RUN_ID,
# parvault:router-soc-$RUN_ID) and labels the unnamed --rm containers (parvault.gate.run=$RUN_ID).
# The extracted SoC binary and other scratch live in a per-run mktemp directory (RUN_TMP). The
# two image build contexts, which hold the binaries staged by stage_artifact.sh, live in a per-run
# stage directory, STAGE_DIR="${PARVAULT_GATE_STAGE_ROOT:-$HOME/.cache/parvault-gate-stage}/$RUN_ID",
# which the EXIT trap keeps: run_enforcement_gates.sh re-hashes every recorded dest after the gate
# exits (A-DOCKER). The run holds an flock on STAGE_DIR/.lock while it runs; at start, stage dirs
# older than PARVAULT_GATE_STAGE_TTL_MIN (default 1440, 24 h) whose lock is free are pruned, so a
# run in progress is never pruned, and a second live run with the same RUN_ID is refused. The /24 subnet
# is 172.28.X.0/24 with X derived from RUN_ID; on a pool overlap (another run, or any other
# network) the next X is tried, so Docker's own pool check makes the choice atomic. Every IP is
# ${NET_PREFIX}.N. The EXIT trap removes only this run's names, label, tags and RUN_TMP, never
# a shared prefix. KEEP_CONTAINERS=1 keeps them for debugging.
set -e -o pipefail
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RUN_ID="${PARVAULT_GATE_RUN_ID:-$$-$RANDOM}"
if ! [[ "$RUN_ID" =~ ^[a-z0-9][a-z0-9_.-]{0,40}$ ]]; then
    echo "ERROR: PARVAULT_GATE_RUN_ID must match ^[a-z0-9][a-z0-9_.-]{0,40}\$ (got '$RUN_ID')"
    exit 2
fi
RUN_LABEL="parvault.gate.run=${RUN_ID}"
NET_NAME="parvault-acceptance-net-${RUN_ID}"
IMG_ACCEPT="parvault:acceptance-${RUN_ID}"
IMG_VFS="parvault:acceptance-vfs-${RUN_ID}"
IMG_SOC="parvault:router-soc-${RUN_ID}"
SOC_VOL_NAME="parvault-soc-nas-vol-${RUN_ID}"
RUN_TMP="$(mktemp -d "${TMPDIR:-/tmp}/parvault-gate-${RUN_ID}.XXXXXX")"
NET_PREFIX=""  # 172.28.X, set in stage 2

# Per-run stage directory, kept after exit (see header). Lock it, then prune old unlocked ones.
STAGE_ROOT="${PARVAULT_GATE_STAGE_ROOT:-$HOME/.cache/parvault-gate-stage}"
STAGE_TTL_MIN="${PARVAULT_GATE_STAGE_TTL_MIN:-1440}"
[[ "$STAGE_TTL_MIN" =~ ^[0-9]+$ ]] || { echo "ERROR: PARVAULT_GATE_STAGE_TTL_MIN must be a number of minutes"; exit 2; }
STAGE_DIR="${STAGE_ROOT}/${RUN_ID}"
mkdir -p "$STAGE_DIR"
exec 9>"$STAGE_DIR/.lock"
if ! flock -n 9; then
    echo "ERROR: another gate run with id ${RUN_ID} holds ${STAGE_DIR}/.lock"
    exit 2
fi
touch "$STAGE_DIR"
find "$STAGE_ROOT" -mindepth 1 -maxdepth 1 -type d -mmin "+${STAGE_TTL_MIN}" -print0 2>/dev/null \
    | while IFS= read -r -d '' old; do
        [ "$old" = "$STAGE_DIR" ] && continue
        # Hold the old run's lock while removing it; a live run keeps its lock, so it is skipped.
        flock -n "$old/.lock" rm -rf -- "$old" 2>/dev/null || true
    done
echo "=== Gate run id: ${RUN_ID} (network ${NET_NAME}, temp ${RUN_TMP}, stage ${STAGE_DIR}) ==="

CONTAINERS=(
    "parvault-seed-0-${RUN_ID}"
    "parvault-client-${RUN_ID}"
    "parvault-router-soc-${RUN_ID}"
    "parvault-soc-store-${RUN_ID}"
    "parvault-soc-restore-${RUN_ID}"
    "parvault-soc-extract-${RUN_ID}"
    "parvault-invitee-${RUN_ID}"
    "parvault-outsider-${RUN_ID}"
    "parvault-status-sidecar-${RUN_ID}"
    "parvault-vfs-netem-${RUN_ID}"
    "parvault-vfs-netem-tc-${RUN_ID}"
    "parvault-vfs-fuse-${RUN_ID}"
)
for i in $(seq 1 11); do
    CONTAINERS+=("parvault-node-$i-${RUN_ID}")
done

# v0.5.0 ring admission: every container shares one ring genesis (fresh per gate run), so the
# nodes, the seed and the clients admit each other.
RING_GENESIS_SEED_HEX="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"

cleanup() {
    if [ "${KEEP_CONTAINERS:-0}" != "1" ]; then
        docker rm -fv "${CONTAINERS[@]}" >/dev/null 2>&1 || true
        docker ps -aq --filter "label=${RUN_LABEL}" | xargs -r docker rm -fv >/dev/null 2>&1 || true
        docker volume rm -f "$SOC_VOL_NAME" >/dev/null 2>&1 || true
        docker network rm "$NET_NAME" >/dev/null 2>&1 || true
        docker rmi "$IMG_ACCEPT" "$IMG_VFS" "$IMG_SOC" >/dev/null 2>&1 || true
        rm -rf "$RUN_TMP" >/dev/null 2>&1 || true
    else
        echo "KEEP_CONTAINERS=1: kept run ${RUN_ID} (network ${NET_NAME}, temp ${RUN_TMP})"
    fi
}
trap cleanup EXIT

# B-106: assert_nonroot reads host uids (docker top) as the container's uids. That holds only
# without a uid remap, so a rootless or userns-remapped Docker fails the gate (as the suite gate does).
DOCKER_SECOPTS="$(docker info --format '{{json .SecurityOptions}}' 2>&1)" \
    || { echo "ERROR: docker info: $DOCKER_SECOPTS"; exit 1; }
if [[ "$DOCKER_SECOPTS" =~ rootless|userns ]]; then
    echo "ERROR: B-106: Docker runs rootless or with userns remap ($DOCKER_SECOPTS); the host uid checks would be wrong"
    exit 1
fi

echo "=== [1/12] Building ParVault binaries & "$IMG_ACCEPT" container image ==="
BUILD_CTX="$STAGE_DIR/acceptance-image"
rm -rf "$BUILD_CTX"
mkdir -p "$BUILD_CTX"

# Capture before grepping: with pipefail, `cmd | grep -q` fails when grep exits early and cmd
# gets SIGPIPE.
INSTALLED_TARGETS="$(rustup target list --installed 2>/dev/null || true)"
# parvault and parvault-seed are staged through scripts/stage_artifact.sh (A-DOCKER, B-47): it
# builds them, copies them into the image context and records their hashes for the enforcement gate.
STAGE_TRIPLE=""
BASE_IMAGE="ubuntu:24.04"
if [ "${USE_GLIBC_IMAGE:-0}" != "1" ] && grep -q "x86_64-unknown-linux-musl" <<<"$INSTALLED_TARGETS"; then
    STAGE_TRIPLE="x86_64-unknown-linux-musl"
    BASE_IMAGE="alpine:3.20"
fi
for b in parvault parvault-seed; do
    bash scripts/stage_artifact.sh --bin "$b" --profile release ${STAGE_TRIPLE:+--target "$STAGE_TRIPLE"} --dest "$BUILD_CTX/$b"
done
# The sidecar with its own feature set (no tokio, no libp2p), as releases build it
# (scripts/build_bins.sh features_for parvault-status).
bash scripts/stage_artifact.sh --bin parvault-status --profile release --no-default-features --features status-ui \
    ${STAGE_TRIPLE:+--target "$STAGE_TRIPLE"} --dest "$BUILD_CTX/parvault-status"
chmod +x "$BUILD_CTX/parvault" "$BUILD_CTX/parvault-seed" "$BUILD_CTX/parvault-status"

cat > "$BUILD_CTX/Dockerfile" <<EOF
FROM ${BASE_IMAGE}
# Distro packages the gate's shell checks use (HTTP client, netcat). Nothing is downloaded into
# the image but these packages; every ParVault binary comes from stage_artifact.sh (A-DOCKER).
ARG GATE_TOOLS="wget netcat-openbsd ca-certificates"
RUN if command -v apt-get >/dev/null 2>&1; then (apt-get update -o Acquire::Retries=3 && apt-get install -y --no-install-recommends \${GATE_TOOLS} && rm -rf /var/lib/apt/lists/*) || true; fi
COPY parvault /usr/local/bin/parvault
COPY parvault-seed /usr/local/bin/parvault-seed
COPY parvault-status /usr/local/bin/parvault-status
# Non-root (B-106): uid/gid 65532 owns every dir the gate writes outside /tmp.
RUN printf 'parvault:x:65532:65532:parvault:/var/lib/parvault:/sbin/nologin\n' >> /etc/passwd && printf 'parvault:x:65532:\n' >> /etc/group && mkdir -p /var/lib/parvault /var/lib/parvault-seed /var/lib/invitee /var/lib/outsider /run/pv /mnt/nas /workspace && chown 65532:65532 /var/lib/parvault /var/lib/parvault-seed /var/lib/invitee /var/lib/outsider /run/pv /mnt/nas /workspace
USER parvault:parvault
WORKDIR /var/lib/parvault
EXPOSE 4001/tcp 4002/tcp 4009/udp 4080/tcp
EOF

docker build -t "$IMG_ACCEPT" "$BUILD_CTX"

# --- B-106 container policy (begin) ---
# B-106: no process in a checked container runs as root, and the container gains no privilege.
# assert_nonroot checks, per container:
#   - docker inspect: user parvault:parvault, not privileged, CapAdd empty, CapDrop ["ALL"],
#     no-new-privileges, no device, no device cgroup rule, no host or shared PID/IPC/UTS/network
#     namespace (the gate network only);
#   - docker top (host view): ruid euid suid fsuid rgid egid sgid fsgid of every process are
#     non-zero (the host uid is the container uid: the gate refuses rootless and userns-remapped
#     Docker, see the check before stage 1);
#   - /proc/<pid>/status of every process, read from a helper that joins the container's PID
#     namespace (works for the FROM scratch image too): Uid and Gid non-zero, CapEff empty,
#     NoNewPrivs 1;
#   - with --daemon, a parvault process runs, so an exited daemon cannot pass.
# Two containers are waived, by name, with the reason printed. Their waiver is checked, not
# assumed (waiver_errors): the image, the user, the exact added capability, not privileged, no
# host namespace, and the exact devices and network.
#   FUSE_WAIVED: the stage 12c FUSE harness (vfs_mp4_seek_gate plus parvault-fuse, not a shipped
#     image) runs as uid 0, adds only SYS_ADMIN, has no-new-privileges, and gets only /dev/fuse.
#     Why root: the image does ship a setuid-root /usr/bin/fusermount3 (`find / -perm -4000` in it
#     also lists chfn chsh gpasswd mount newgrp passwd su umount), but a setuid exec cannot gain
#     CAP_SYS_ADMIN outside the bounding set (Docker's default has none), and no-new-privileges
#     disables setuid. mount(2) needs SYS_ADMIN either way, so root plus only SYS_ADMIN is the
#     smallest grant.
#   NETEM_TC_WAIVED: the stage 12c one-shot tc sidecar runs as uid 0 with CapDrop ALL plus only
#     NET_ADMIN, in the netem test container's network namespace, and nothing else.
FUSE_WAIVED="parvault-vfs-fuse-${RUN_ID}"
FUSE_WAIVER_REASON="stage 12c FUSE harness: mount(2) of /dev/fuse needs CAP_SYS_ADMIN (gate harness, not a shipped image)"
NETEM_TC_WAIVED="parvault-vfs-netem-tc-${RUN_ID}"
NETEM_TC_WAIVER_REASON="stage 12c one-shot tc sidecar: tc qdisc on the netem test container's lo needs CAP_NET_ADMIN (gate harness, not a shipped image)"
NETEM_TC_TARGET="parvault-vfs-netem-${RUN_ID}"
POLICY_FMT='{{.Config.Image}}|{{.Config.User}}|{{.HostConfig.Privileged}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.NetworkMode}}|{{range .HostConfig.Devices}}{{.PathOnHost}}:{{.PathInContainer}};{{end}}|{{json .HostConfig.DeviceCgroupRules}}'
# policy_errors <container> <image|-> <user> <capadd> <capdrop|-> <nnp yes|-> <devices> <network|->:
# prints one line per violation of the container's docker inspect policy. <capadd> is a JSON list
# without CAP_ prefixes, or none; <devices> is "host:container;" per device, or empty; <network>
# '-' means any network but host or another container's.
policy_errors() {
    local c="$1" want_img="$2" want_user="$3" want_cap="$4" want_drop="$5" want_nnp="$6" want_dev="$7" want_net="$8"
    local out img user priv capadd capdrop secopt pidm ipcm utsm netm dev devrules m
    out="$(docker inspect -f "$POLICY_FMT" "$c" 2>&1)" || { echo "cannot inspect: $out"; return 0; }
    IFS='|' read -r img user priv capadd capdrop secopt pidm ipcm utsm netm dev devrules <<<"$out"
    # Docker may report a capability with or without its CAP_ prefix.
    capadd="${capadd//\"CAP_/\"}"
    capdrop="${capdrop//\"CAP_/\"}"
    case "$capadd" in null|'[]') capadd=none ;; esac
    [ "$want_img" = - ] || [ "$img" = "$want_img" ] || echo "image $img, not $want_img"
    [ "$user" = "$want_user" ] || echo "user '$user', not '$want_user'"
    [ "$priv" = false ] || echo "privileged ($priv)"
    [ "$capadd" = "$want_cap" ] || echo "CapAdd $capadd, not $want_cap"
    [ "$want_drop" = - ] || [ "$capdrop" = "$want_drop" ] || echo "CapDrop $capdrop, not $want_drop"
    [ "$want_nnp" = - ] || [[ "$secopt" =~ \"no-new-privileges(:true)?\" ]] || echo "no no-new-privileges (SecurityOpt $secopt)"
    for m in "PidMode=$pidm" "IpcMode=$ipcm" "UTSMode=$utsm"; do
        case "${m#*=}" in host|container:*) echo "$m" ;; esac
    done
    if [ "$want_net" = - ]; then
        case "$netm" in host|container:*|none) echo "NetworkMode $netm" ;; esac
    elif [ "$netm" != "$want_net" ]; then
        echo "NetworkMode $netm, not $want_net"
    fi
    [ "$dev" = "$want_dev" ] || echo "devices '$dev', not '$want_dev'"
    case "$devrules" in null|'[]') ;; *) echo "DeviceCgroupRules $devrules" ;; esac
}
# waiver_errors <waived container>: the checked waiver, or one line per violation.
waiver_errors() {
    local tid
    case "$1" in
        "$FUSE_WAIVED")
            policy_errors "$1" "$IMG_VFS" "0:0" '["SYS_ADMIN"]' - yes "/dev/fuse:/dev/fuse;" - ;;
        "$NETEM_TC_WAIVED")
            # Docker keeps container:<name> or resolves it to container:<id>; accept either.
            tid="$(docker inspect -f '{{.Id}}' "$NETEM_TC_TARGET" 2>/dev/null || echo none)"
            policy_errors "$1" "$IMG_VFS" "0:0" '["NET_ADMIN"]' '["ALL"]' yes "" "container:$NETEM_TC_TARGET" \
                | { grep -vx "NetworkMode container:$tid, not container:$NETEM_TC_TARGET" || true; } ;;
        *) echo "not a waived container" ;;
    esac
}
waiver_reason() {
    case "$1" in
        "$FUSE_WAIVED") echo "$FUSE_WAIVER_REASON" ;;
        "$NETEM_TC_WAIVED") echo "$NETEM_TC_WAIVER_REASON" ;;
    esac
}
# Runs in IMG_ACCEPT, in the checked container's PID namespace: pid name ruid euid suid fsuid rgid
# egid sgid fsgid CapEff NoNewPrivs, one line per process. Its own sh and awk are listed too and
# pass (uid 65532, CapDrop ALL, no-new-privileges).
PROC_SCAN='for s in /proc/[0-9]*/status; do
    awk "/^Name:/ {n=\$2} /^Pid:/ {p=\$2} /^Uid:/ {u=\$2\" \"\$3\" \"\$4\" \"\$5} /^Gid:/ {g=\$2\" \"\$3\" \"\$4\" \"\$5}
         /^CapEff:/ {c=\$2} /^NoNewPrivs:/ {x=\$2} END {if (p != \"\") print p, n, u, g, c, x}" "$s" 2>/dev/null || true
done'
assert_nonroot() {
    local need_daemon=0 c top bad errs scan checked=()
    if [ "${1:-}" = "--daemon" ]; then need_daemon=1; shift; fi
    for c in "$@"; do
        if [ "$c" = "$FUSE_WAIVED" ] || [ "$c" = "$NETEM_TC_WAIVED" ]; then
            errs="$(waiver_errors "$c")"
            if [ -n "$errs" ]; then
                echo "ERROR: B-106: waived container $c breaks its waiver ($(waiver_reason "$c")):"
                echo "$errs"
                exit 1
            fi
            echo "B-106: WAIVED (runs as root): $c: $(waiver_reason "$c")"
            continue
        fi
        errs="$(policy_errors "$c" - "parvault:parvault" none '["ALL"]' yes "" -)"
        if [ -n "$errs" ]; then
            echo "ERROR: B-106: $c is not confined:"
            echo "$errs"
            exit 1
        fi
        if ! top="$(docker top "$c" -eo pid,ruid,euid,suid,fsuid,rgid,egid,sgid,fsgid,comm 2>&1)"; then
            echo "ERROR: B-106: cannot list the processes of $c: $top"
            exit 1
        fi
        bad="$(awk 'NR > 1 { for (i = 2; i <= 9; i++) if ($i == 0) { print; next } }' <<<"$top")"
        if [ -n "$bad" ]; then
            echo "ERROR: B-106: $c runs process(es) with a root uid or gid (pid ruid euid suid fsuid rgid egid sgid fsgid comm):"
            echo "$bad"
            exit 1
        fi
        if [ "$need_daemon" = 1 ] && ! awk 'NR > 1 && $10 ~ /^parvault/ {found=1} END {exit !found}' <<<"$top"; then
            echo "ERROR: B-106: $c runs no parvault process, so its uid cannot be checked:"
            echo "$top"
            exit 1
        fi
        if ! scan="$(docker run --rm --label "$RUN_LABEL" --pid "container:$c" --network none --cap-drop ALL \
                --security-opt no-new-privileges "$IMG_ACCEPT" sh -c "$PROC_SCAN" 2>&1)" || [ -z "$scan" ]; then
            echo "ERROR: B-106: cannot read /proc/<pid>/status in $c: $scan"
            exit 1
        fi
        bad="$(awk '{ for (i = 3; i <= 10; i++) if ($i == 0) { print; next } }
                    $11 !~ /^0+$/ || $12 != 1 { print }' <<<"$scan")"
        if [ -n "$bad" ]; then
            echo "ERROR: B-106: $c has a process with a root id, a capability or new privileges allowed (pid name ruid euid suid fsuid rgid egid sgid fsgid CapEff NoNewPrivs):"
            echo "$bad"
            exit 1
        fi
        checked+=("$c")
    done
    [ "${#checked[@]}" -eq 0 ] || echo "B-106: non-root, CapEff empty, no-new-privileges verified in: ${checked[*]}"
}
# The run flags of every container assert_nonroot checks (and of the SoC one-shots).
CONFINE=(--cap-drop ALL --security-opt no-new-privileges)
# assert_oneshot_confined <created container> <image>: for a foreground one-shot that
# assert_nonroot cannot see running. Checked after `docker create`, before `docker start`: the
# image's user is parvault:parvault, and the container keeps it and gains no privilege.
assert_oneshot_confined() {
    local c="$1" img="$2" iuser errs
    iuser="$(docker inspect -f '{{.Config.User}}' "$img" 2>&1)" \
        || { echo "ERROR: B-106: cannot inspect image $img: $iuser"; exit 1; }
    [ "$iuser" = "parvault:parvault" ] \
        || { echo "ERROR: B-106: image $img runs as '$iuser', not parvault:parvault"; exit 1; }
    errs="$(policy_errors "$c" "$img" "parvault:parvault" none '["ALL"]' yes "" -)"
    if [ -n "$errs" ]; then
        echo "ERROR: B-106: one-shot $c is not confined:"
        echo "$errs"
        exit 1
    fi
    echo "B-106: one-shot confined (image user parvault:parvault, no capability): $c"
}
# --- B-106 container policy (end) ---

echo "=== [2/12] Creating isolated Docker bridge network (per-run 172.28.X.0/24) ==="
docker rm -fv "${CONTAINERS[@]}" >/dev/null 2>&1 || true
docker network rm "$NET_NAME" >/dev/null 2>&1 || true
# X starts at a hash of RUN_ID; Docker refuses an overlapping pool, so a taken X moves on.
NET_X0=$(( $(printf '%s' "$RUN_ID" | cksum | cut -d' ' -f1) % 256 ))
for k in $(seq 0 255); do
    X=$(( (NET_X0 + k) % 256 ))
    if NET_ERR="$(docker network create --label "$RUN_LABEL" --subnet="172.28.${X}.0/24" "$NET_NAME" 2>&1)"; then
        NET_PREFIX="172.28.${X}"
        break
    fi
    grep -qi "overlap" <<<"$NET_ERR" || { echo "ERROR: docker network create: $NET_ERR"; exit 1; }
done
[ -n "$NET_PREFIX" ] || { echo "ERROR: no free 172.28.X.0/24 subnet for run ${RUN_ID}"; exit 1; }
NET_SUBNET="${NET_PREFIX}.0/24"
echo "Run ${RUN_ID}: network ${NET_NAME} on ${NET_SUBNET}"

PEERS_LIST=()
for i in $(seq 1 10); do
    IP="${NET_PREFIX}.$((10 + i))"
    PEERS_LIST+=("/ip4/${IP}/tcp/4001")
done
PEERS_CSV="$(IFS=,; echo "${PEERS_LIST[*]}")"
SEED_MULTIADDR="/ip4/${NET_PREFIX}.10/tcp/4002"
NODE11_MULTIADDR="/ip4/${NET_PREFIX}.21/tcp/4001"

echo "=== [3/12] Starting parvault-seed-0-${RUN_ID} + 11 parvault daemon containers + 1 isolated client container ==="
docker run -d --name parvault-seed-0-${RUN_ID} "${CONFINE[@]}" \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    --network "$NET_NAME" --ip ${NET_PREFIX}.10 \
    "$IMG_ACCEPT" \
    /usr/local/bin/parvault-seed \
    --peers "$PEERS_CSV" \
    start \
    --mode homelab-vault \
    --listen /ip4/0.0.0.0/tcp/4002 \
    --data-dir /var/lib/parvault-seed

for i in $(seq 1 11); do
    IP="${NET_PREFIX}.$((10 + i))"
    docker run -d --name "parvault-node-$i-${RUN_ID}" "${CONFINE[@]}" \
        -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
        --network "$NET_NAME" --ip "$IP" \
        -w /var/lib/parvault \
        "$IMG_ACCEPT" \
        /usr/local/bin/parvault \
        --peers "$PEERS_CSV" \
        --seed-addr "$SEED_MULTIADDR" \
        daemon start --listen /ip4/0.0.0.0/tcp/4001
done

# Start isolated client container with ZERO volume mounts
docker run -d --name parvault-client-${RUN_ID} "${CONFINE[@]}" \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    --network "$NET_NAME" --ip ${NET_PREFIX}.50 \
    "$IMG_ACCEPT" \
    sleep 3600

sleep 3

echo "=== Verifying zero shared volume mounts on parvault-client-${RUN_ID} ==="
CLIENT_MOUNTS="$(docker inspect -f '{{json .Mounts}}' parvault-client-${RUN_ID})"
echo "parvault-client-${RUN_ID} Mounts: $CLIENT_MOUNTS"
if [ "$CLIENT_MOUNTS" != "[]" ] && [ "$CLIENT_MOUNTS" != "null" ]; then
    echo "ERROR: parvault-client-${RUN_ID} has volume mounts: $CLIENT_MOUNTS"
    exit 1
fi

echo "=== [3b/12] Ring membership: an invited node serves the ring; a non-member is refused ==="
# The invitee never holds the ring secret: it joins with 'wot invite' (on a ring member) and
# 'wot install-chain', then runs a daemon that stores a ring member's file.
docker run -d --name parvault-invitee-${RUN_ID} "${CONFINE[@]}" \
    --network "$NET_NAME" --ip ${NET_PREFIX}.40 \
    "$IMG_ACCEPT" \
    sleep 3600
INVITEE_KEY="$(docker exec parvault-invitee-${RUN_ID} /usr/local/bin/parvault --data-dir /var/lib/invitee --no-lan-discovery identity \
    | awk -F': ' '/Ed25519 Public Key/ {print $2}')"
RING_TOKEN="$(docker exec parvault-node-1-${RUN_ID} /usr/local/bin/parvault --data-dir /tmp/ring-inviter --no-lan-discovery \
    wot invite --peer "$INVITEE_KEY")"
docker exec parvault-invitee-${RUN_ID} /usr/local/bin/parvault --data-dir /var/lib/invitee --no-lan-discovery \
    wot install-chain --token "$RING_TOKEN"
if docker exec parvault-invitee-${RUN_ID} test -e /var/lib/invitee/ring_genesis.seed; then
    echo "ERROR: the invitee holds a ring genesis secret"
    exit 1
fi
docker exec -d parvault-invitee-${RUN_ID} /usr/local/bin/parvault --data-dir /var/lib/invitee --no-lan-discovery \
    daemon start --listen /ip4/0.0.0.0/tcp/4001
sleep 3
docker exec -e INVITEE_ADDR="/ip4/${NET_PREFIX}.40/tcp/4001" parvault-client-${RUN_ID} sh -cex '
    mkdir -p /tmp/ring-check
    echo "stored on an invited ring member" > /tmp/ring-check/doc.txt
    /usr/local/bin/parvault --data-dir /tmp/ring-check/data --no-lan-discovery \
        --peers "$INVITEE_ADDR" file store --path /tmp/ring-check/doc.txt
'
NODE_CONTAINERS=()
for i in $(seq 1 11); do NODE_CONTAINERS+=("parvault-node-$i-${RUN_ID}"); done
assert_nonroot --daemon "parvault-seed-0-${RUN_ID}" "${NODE_CONTAINERS[@]}" "parvault-invitee-${RUN_ID}"
assert_nonroot "parvault-client-${RUN_ID}"
# The outsider runs its own ring: its credential does not admit it to this ring.
docker run -d --name parvault-outsider-${RUN_ID} "${CONFINE[@]}" \
    --network "$NET_NAME" --ip ${NET_PREFIX}.41 \
    "$IMG_ACCEPT" \
    sleep 3600
docker exec parvault-outsider-${RUN_ID} /usr/local/bin/parvault --data-dir /var/lib/outsider --no-lan-discovery wot init
docker exec parvault-outsider-${RUN_ID} sh -c 'echo "outsider data" > /tmp/outsider.txt'
# The outsider is refused, keeps the stripe locally, says it is not backed up and exits 3.
set +e
OUTSIDER_OUT="$(docker exec parvault-outsider-${RUN_ID} /usr/local/bin/parvault --data-dir /var/lib/outsider \
    --no-lan-discovery --peers /ip4/${NET_PREFIX}.11/tcp/4001 file store --path /tmp/outsider.txt 2>&1)"
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
if ! NODE1_SHARDS="$(docker exec parvault-node-1-${RUN_ID} ls /var/lib/parvault/.parvault-data/shards)"; then
    echo "ERROR: node-1 has no shards directory to check"
    exit 1
fi
if grep -q "^${OUTSIDER_ROOT:0:16}" <<<"$NODE1_SHARDS"; then
    echo "ERROR: a non-member stored data on a ring node"
    exit 1
fi
# Capture the log first: `docker logs | grep -q` fails under pipefail once the log is long.
NODE1_LOG="$(docker logs parvault-node-1-${RUN_ID} 2>&1)"
if ! grep -q "reject.peer_not_admitted" <<<"$NODE1_LOG"; then
    echo "ERROR: the ring node did not log the refusal"
    exit 1
fi
echo "Ring membership verified: invitee served the ring, outsider refused."

echo "=== [4/12] Zero-IP Home LAN Auto-Discovery ('parvault discover') over ${NET_PREFIX}.0/24 Bridge ==="
DISCOVER_TABLE="$(docker exec parvault-client-${RUN_ID} /usr/local/bin/parvault --data-dir /tmp/zero-ip-discover discover --timeout-ms 1200)"
echo "$DISCOVER_TABLE"
DISCOVER_JSON="$(docker exec parvault-client-${RUN_ID} /usr/local/bin/parvault --data-dir /tmp/zero-ip-discover discover --json --timeout-ms 1200)"
DISCOVERED_COUNT="$(echo "$DISCOVER_JSON" | grep -c '"peer_id"' || true)"
echo "Zero-IP discovered verified LAN peers on ${NET_PREFIX}.0/24: $DISCOVERED_COUNT"
if [ "$DISCOVERED_COUNT" -lt 10 ]; then
    echo "ERROR: Expected parvault discover (with zero IP arguments) to find >= 10 LAN daemons, found $DISCOVERED_COUNT"
    echo "$DISCOVER_JSON"
    exit 1
fi

# Also prove zero-`--peers` file store & restore over Docker bridge auto-discovery.
# The CLI never prints the master key (W-02): store and restore with one explicit key.
ZKEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
docker exec -e ZKEY="$ZKEY" -e NET_SUBNET="$NET_SUBNET" parvault-client-${RUN_ID} sh -cex '
    mkdir -p /tmp/zero-ip-store /tmp/zero-ip-restore
    echo "Zero-IP LAN discovery file store/restore over ${NET_SUBNET} bridge" > /tmp/zero-ip-store/lan_zero_ip.txt
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
docker exec parvault-client-${RUN_ID} sh -cex '
    mkdir -p /tmp/client-upload-state /workspace/source_vault/docs /workspace/source_vault/src /workspace/source_vault/data
    echo "# ParVault Live Multi-Container Network Proof (v1)" > /workspace/source_vault/docs/readme.md
    echo "pub fn verify_live_libp2p_recovery() -> bool { true }" > /workspace/source_vault/src/kernel.rs
    echo "pub fn temporary_module() {}" > /workspace/source_vault/src/ephemeral.rs
    dd if=/dev/urandom of=/workspace/source_vault/data/blob.bin bs=1024 count=64 status=none
'

T0_S=$(date +%s)
docker exec -w /tmp/client-upload-state parvault-client-${RUN_ID} /usr/local/bin/parvault \
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
    SHARD_COUNT="$(docker exec "parvault-node-$i-${RUN_ID}" sh -c 'ls -1 /var/lib/parvault/.parvault-data/shards/*.shard 2>/dev/null | wc -l')"
    echo "parvault-node-$i-${RUN_ID} stored shard files (v1): $SHARD_COUNT"
    if [ "$SHARD_COUNT" -lt 1 ]; then
        echo "ERROR: parvault-node-$i-${RUN_ID} has 0 shards on disk!"
        exit 1
    fi
    TOTAL_SHARDS_V1=$((TOTAL_SHARDS_V1 + SHARD_COUNT))
done
SEED_SHARD_COUNT_V1="$(docker exec parvault-seed-0-${RUN_ID} sh -c 'ls -1 /var/lib/parvault-seed/shards/*.shard 2>/dev/null | wc -l')"
echo "Total remote node shards (v1): $TOTAL_SHARDS_V1 | Seed shards (v1): $SEED_SHARD_COUNT_V1 | Elapsed: ${SYNC_V1_SECS}s"

echo "=== [6/12] Continuous Background Backup Daemon ('watch-folder --interval-secs 1 --prune-deleted') ==="
docker exec -w /tmp/client-upload-state parvault-client-${RUN_ID} sh -c "
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
docker exec parvault-client-${RUN_ID} sh -cex '
    echo "# ParVault Live Multi-Container Network Proof (v2 - Continuous Sync Updated)" > /workspace/source_vault/docs/readme.md
    echo "## v0.3.0 Live Multi-Container Regression Verified" > /workspace/source_vault/docs/changelog.md
    rm -f /workspace/source_vault/src/ephemeral.rs
    cd /workspace/source_vault
    sha256sum docs/readme.md docs/changelog.md src/kernel.rs data/blob.bin > /tmp/expected_v2.sha256
    cat /tmp/expected_v2.sha256
'

# Wait for continuous watch-folder daemon to complete pass v2 (including Catalog Envelope DHT publish!) and stop it cleanly
for attempt in $(seq 1 25); do
    if docker exec parvault-client-${RUN_ID} awk '/Deleted Tombstones : 1/{found=1} found && /Catalog Envelope/{ok=1} END{exit !ok}' /tmp/watch-daemon.log 2>/dev/null; then
        break
    fi
    sleep 1
done
docker exec parvault-client-${RUN_ID} sh -cex '
    if [ -f /tmp/watch-daemon.pid ]; then
        kill "$(cat /tmp/watch-daemon.pid)" 2>/dev/null || true
    fi
    cat /tmp/watch-daemon.log
    grep -q "Deleted Tombstones : 1" /tmp/watch-daemon.log
'

echo "=== [7/12] Lite-Client 1.0x Stripe Syndication via parvault-seed-0-${RUN_ID} & NAS-Death Mesh Failover ==="
docker exec parvault-client-${RUN_ID} sh -cex '
    mkdir -p /tmp/lite-client-state /workspace/lite_source /workspace/lite_restored_after_nas_death
    echo "Lite-Client 1.0x stripe syndicated through parvault-seed-0 to 10 mesh peers" > /workspace/lite_source/laptop_note.txt
    sha256sum < /workspace/lite_source/laptop_note.txt | cut -d " " -f1 > /tmp/expected_lite.hash
'
# Every shard file in the client container before the lite run (other stages' vaults live here).
LITE_SHARDS_BEFORE="$(docker exec parvault-client-${RUN_ID} sh -c 'find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -name "*.shard" -type f -print 2>/dev/null | sort')"
SEED_PUBKEY_HEX="$(docker exec parvault-seed-0-${RUN_ID} /usr/local/bin/parvault-seed identity --data-dir /var/lib/parvault-seed | awk '/Owner PQ Public Key Hex/ {print $7}')"
# The lite client syndicates as its vault identity, which also signs the repair grant (F-25,
# F-38): the cert names the Vault Device Peer ID that `parvault identity --seed-phrase` prints.
LITE_DEVICE_ID="$(docker exec -w /tmp/lite-client-state parvault-client-${RUN_ID} /usr/local/bin/parvault identity \
    --seed-phrase "$SEED_PHRASE" --vault-namespace "lite-failover-ns" 2>/dev/null | awk '/Vault Device Peer ID/ {print $6}')"
if [ -z "$LITE_DEVICE_ID" ]; then
    echo "ERROR: could not read the Vault Device Peer ID"
    exit 1
fi
DEVICE_CERT_TOKEN="$(docker exec parvault-seed-0-${RUN_ID} /usr/local/bin/parvault-seed issue-device-cert --data-dir /var/lib/parvault-seed --device-peer-id "$LITE_DEVICE_ID" --device-label laptop | awk '/Shareable Token/ {print $4}')"

docker exec -w /tmp/lite-client-state parvault-client-${RUN_ID} /usr/local/bin/parvault \
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
LITE_SYND_TIMES="$(docker logs parvault-seed-0-${RUN_ID} 2>&1 | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -E 'lite syndication (ingested on the seed|fan-out finished)' || true)"
echo "$LITE_SYND_TIMES"
if ! echo "$LITE_SYND_TIMES" | grep -q 'handler_ms=' || ! echo "$LITE_SYND_TIMES" | grep -q 'job_ms='; then
    echo "ERROR: stage 7: parvault-seed-0-${RUN_ID} logged no lite syndication handler/job durations"
    exit 1
fi

# Simulate NAS / Seed Server death by stopping parvault-seed-0-${RUN_ID}, then recover the Lite-Client vault
# from mesh peers only. By design a successful lite syndication deletes the client's local shards
# (src/cli/folder.rs, after syndication), so there is nothing to wipe: instead assert the lite run
# left no shard file anywhere in the container, hide the source folder, and restore into a fresh
# data dir and working dir, so the restore can read neither local shards nor the original file.
LITE_SHARDS_AFTER="$(docker exec parvault-client-${RUN_ID} sh -c 'find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -name "*.shard" -type f -print 2>/dev/null | sort')"
LITE_NEW_SHARDS="$(comm -13 <(printf '%s\n' "$LITE_SHARDS_BEFORE") <(printf '%s\n' "$LITE_SHARDS_AFTER") | sed '/^$/d')"
if [ -n "$LITE_NEW_SHARDS" ]; then
    echo "ERROR: stage 7: the lite run kept local shards, so the restore could read them:"
    echo "$LITE_NEW_SHARDS"
    exit 1
fi
if ! docker exec parvault-client-${RUN_ID} test -s /tmp/lite-client-state/lite.manifest.bin; then
    echo "ERROR: stage 7: the lite run wrote no snapshot; nothing was synced"
    exit 1
fi
docker exec parvault-client-${RUN_ID} sh -cex '
    mv /workspace/lite_source /workspace/lite_source.hidden-for-restore
    mkdir -p /tmp/lite-restore-fresh/data /tmp/lite-restore-fresh/cwd
    test -z "$(ls -A /tmp/lite-restore-fresh/data)"
'
docker stop parvault-seed-0-${RUN_ID}
docker exec -w /tmp/lite-restore-fresh/cwd parvault-client-${RUN_ID} /usr/local/bin/parvault \
    --data-dir /tmp/lite-restore-fresh/data \
    --peers "$PEERS_CSV" \
    recover-from-seed \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "lite-failover-ns" \
    --out-dir /workspace/lite_restored_after_nas_death
# Compare the restored file's content (not a path: a path-based check would re-hash the source).
docker exec parvault-client-${RUN_ID} sh -cex '
    test ! -e /workspace/lite_source
    RESTORED="$(find /workspace/lite_restored_after_nas_death -type f -name laptop_note.txt)"
    test "$(printf "%s\n" "$RESTORED" | sed "/^$/d" | wc -l)" -eq 1
    test "$(sha256sum < "$RESTORED" | cut -d " " -f1)" = "$(cat /tmp/expected_lite.hash)"
'
docker start parvault-seed-0-${RUN_ID}
for attempt in $(seq 1 30); do
    if docker exec parvault-client-${RUN_ID} nc -z ${NET_PREFIX}.10 4002 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "=== [7b/12] Eviction council (F-08/F-09): signed manifest; member order applied; non-member refused ==="
# node-1 holds the ring genesis and signs epoch 1 of a 1-of-1 council whose member is node-2;
# nodes 2, 3 and 6 install that manifest. node-2 (a member) propagates a bounded, epoch-stamped
# order that node-6 applies; node-3 (not a member) cannot propagate at all.
NODE2_KEY="$(docker exec -w /var/lib/parvault parvault-node-2-${RUN_ID} /usr/local/bin/parvault --no-lan-discovery identity \
    | awk -F': ' '/Ed25519 Public Key/ {print $2}')"
COUNCIL_HEX="$(docker exec -w /var/lib/parvault parvault-node-1-${RUN_ID} /usr/local/bin/parvault --no-lan-discovery \
    council init --member "$NODE2_KEY" --quorum 1 | tail -n 1)"
for n in 2 3 6; do
    docker exec -w /var/lib/parvault "parvault-node-$n-${RUN_ID}" /usr/local/bin/parvault --no-lan-discovery \
        council install --manifest "$COUNCIL_HEX"
done
if ! docker exec -w /var/lib/parvault parvault-node-6-${RUN_ID} /usr/local/bin/parvault --no-lan-discovery council show \
    | grep -q '^Epoch *: 1$'; then
    echo "ERROR: parvault-node-6-${RUN_ID} did not install council epoch 1"
    exit 1
fi
docker exec -w /var/lib/parvault parvault-node-2-${RUN_ID} /usr/local/bin/parvault --peers "$PEERS_CSV" --no-lan-discovery \
    evict --ip 203.0.113.77 --reason council-stage --propagate
COUNCIL_APPLIED=0
for _ in $(seq 1 20); do
    if docker logs parvault-node-6-${RUN_ID} 2>&1 | grep -q 'applied an eviction order'; then
        COUNCIL_APPLIED=1
        break
    fi
    sleep 0.5
done
if [ "$COUNCIL_APPLIED" -ne 1 ]; then
    echo "ERROR: parvault-node-6-${RUN_ID} did not apply the council member's order"
    exit 1
fi
if NONMEMBER_OUT="$(docker exec -w /var/lib/parvault parvault-node-3-${RUN_ID} /usr/local/bin/parvault --peers "$PEERS_CSV" \
    --no-lan-discovery evict --ip 203.0.113.78 --propagate 2>&1)"; then
    echo "ERROR: a non-member propagated an eviction order: $NONMEMBER_OUT"
    exit 1
fi
case "$NONMEMBER_OUT" in
    *"member of the installed council"*) ;;
    *) echo "ERROR: unexpected non-member refusal: $NONMEMBER_OUT"; exit 1 ;;
esac

echo "=== [8/12] Graceful Node Decommission: parvault-node-5-${RUN_ID} -> parvault-node-11-${RUN_ID} ('parvault leave --handoff-to') ==="
NODE11_BEFORE="$(docker exec parvault-node-11-${RUN_ID} sh -c 'ls -1 /var/lib/parvault/.parvault-data/shards/*.shard 2>/dev/null | wc -l')"
docker exec -w /var/lib/parvault parvault-node-5-${RUN_ID} /usr/local/bin/parvault \
    leave --handoff-to "$NODE11_MULTIADDR"
NODE11_AFTER="$(docker exec parvault-node-11-${RUN_ID} sh -c 'ls -1 /var/lib/parvault/.parvault-data/shards/*.shard 2>/dev/null | wc -l')"
echo "parvault-node-11-${RUN_ID} shards before handoff: $NODE11_BEFORE | after handoff: $NODE11_AFTER"
if [ "$NODE11_AFTER" -le "$NODE11_BEFORE" ]; then
    echo "ERROR: parvault-node-11-${RUN_ID} did not receive evacuated shards from parvault-node-5-${RUN_ID}!"
    exit 1
fi
docker stop parvault-node-5-${RUN_ID}

echo "=== [9/12] Bit-Rot Injection ('parvault scrub'), Daemon Restart Persistence, and 4-Container Kill ==="
# Inject 1-byte bit-rot into a single shard on parvault-node-6-${RUN_ID} and verify 'parvault scrub' quarantines it
docker exec parvault-node-6-${RUN_ID} sh -cex '
    VICTIM=$(ls -1 /var/lib/parvault/.parvault-data/shards/*.shard | head -n 1)
    printf "\xff" | dd of="$VICTIM" bs=1 count=1 conv=notrunc status=none
'
SCRUB_OUT="$(docker exec -w /var/lib/parvault parvault-node-6-${RUN_ID} /usr/local/bin/parvault scrub)"
echo "$SCRUB_OUT"
grep -q "corrupted_quarantined_shards : 1" <<<"$SCRUB_OUT"

# Restart parvault-node-6-${RUN_ID} and parvault-node-7-${RUN_ID} to prove persistent disk state across daemon restarts
docker restart parvault-node-6-${RUN_ID} parvault-node-7-${RUN_ID}
for ip in ${NET_PREFIX}.16 ${NET_PREFIX}.17; do
    for attempt in $(seq 1 30); do
        if docker exec parvault-client-${RUN_ID} nc -z "$ip" 4001 >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
done

# Kill 4 storage daemon containers (parvault-node-1-${RUN_ID}..4)
docker kill parvault-node-1-${RUN_ID} parvault-node-2-${RUN_ID} parvault-node-3-${RUN_ID} parvault-node-4-${RUN_ID}

# Wipe all client local state
docker exec parvault-client-${RUN_ID} sh -cex '
    rm -rf /workspace/source_vault /tmp/client-upload-state /tmp/lite-client-state
    mkdir -p /tmp/client-fresh-recovery-state /workspace/recovered_vault /workspace/selective_vault
'

SURVIVING_PEERS="/ip4/${NET_PREFIX}.16/tcp/4001,/ip4/${NET_PREFIX}.17/tcp/4001,/ip4/${NET_PREFIX}.18/tcp/4001,/ip4/${NET_PREFIX}.19/tcp/4001,/ip4/${NET_PREFIX}.20/tcp/4001,/ip4/${NET_PREFIX}.21/tcp/4001"

echo "=== [10/12] Zero-Local-State 'recover-from-seed' (Full & Selective '--filter') after 4 Kills + 1 Decommission + 1 Bit-Rot ==="
T_REC0_S=$(date +%s)
docker exec -w /tmp/client-fresh-recovery-state parvault-client-${RUN_ID} /usr/local/bin/parvault \
    --peers "$SURVIVING_PEERS" \
    --seed-addr "$SEED_MULTIADDR" \
    recover-from-seed \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "$VAULT_NS" \
    --out-dir /workspace/recovered_vault
T_REC1_S=$(date +%s)
RECOVER_SECS=$((T_REC1_S - T_REC0_S))

docker exec parvault-client-${RUN_ID} sh -cex '
    cd /workspace/recovered_vault
    sha256sum -c /tmp/expected_v2.sha256
    test ! -e src/ephemeral.rs
    ls -la docs/readme.md docs/changelog.md src/kernel.rs data/blob.bin
'

# Selective subset restore (--filter "docs/*")
docker exec -w /tmp/client-fresh-recovery-state parvault-client-${RUN_ID} /usr/local/bin/parvault \
    --peers "$SURVIVING_PEERS" \
    --seed-addr "$SEED_MULTIADDR" \
    recover-from-seed \
    --seed-phrase "$SEED_PHRASE" \
    --vault-namespace "$VAULT_NS" \
    --filter "docs/*" \
    --out-dir /workspace/selective_vault

docker exec parvault-client-${RUN_ID} sh -cex '
    test -f /workspace/selective_vault/docs/readme.md
    test -f /workspace/selective_vault/docs/changelog.md
    test ! -e /workspace/selective_vault/data/blob.bin
'

echo "=== [11/12] Cross-Machine 'parvault file store' -> 'parvault file restore --key-hex' with Wiped Local State ==="
XKEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
docker exec -e SURVIVING_PEERS="$SURVIVING_PEERS" -e KEY="$XKEY" parvault-client-${RUN_ID} sh -cex '
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
docker build -f deploy/Dockerfile.router-soc -t "$IMG_SOC" .
docker images "$IMG_SOC"
ROUTER_SOC_IMAGE_SIZE="$(docker images "$IMG_SOC" --format '{{.Size}}')"

docker rm -fv parvault-soc-extract-${RUN_ID} >/dev/null 2>&1 || true
docker create --name parvault-soc-extract-${RUN_ID} "$IMG_SOC" >/dev/null
docker cp parvault-soc-extract-${RUN_ID}:/parvault "$RUN_TMP/soc-bin"
docker rm -fv parvault-soc-extract-${RUN_ID} >/dev/null
SOC_BIN_BYTES="$(stat -c%s "$RUN_TMP/soc-bin")"
SOC_BIN_MIB="$(awk "BEGIN {printf \"%.2f MiB\", ${SOC_BIN_BYTES}/1048576}")"
echo "Stripped parvault (--profile soc, musl) binary size: ${SOC_BIN_MIB} (${SOC_BIN_BYTES} bytes)"
echo "Total ${IMG_SOC} (FROM scratch) image size : ${ROUTER_SOC_IMAGE_SIZE}"
# Metrics of record (docs/metrics.txt docker.*): `docker images` disk usage (unpacked), and the
# image's content size (compressed layers; `docker image inspect .Size` on the containerd store).
echo "metric docker.unpacked = ${ROUTER_SOC_IMAGE_SIZE}"
echo "metric docker.compressed.bytes = $(docker image inspect -f '{{.Size}}' "$IMG_SOC")"

# Start a live `"$IMG_SOC"` appliance container constrained to --memory=48m --memory-swap=48m
# Item 3: the status page needs a read-only token; give the appliance a known gateway root key.
# router.toml binds the status page to 127.0.0.1:4080 (B-54), the container's own loopback; as in the
# image's CMD, pass --status-http 0.0.0.0:4080 (the container's interface, not a router WAN) so the
# client container can reach it at ${NET_PREFIX}.60:4080.
SOC_STATUS_KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
docker run -d --name parvault-router-soc-${RUN_ID} "${CONFINE[@]}" \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    --network "$NET_NAME" --ip ${NET_PREFIX}.60 \
    --memory=48m --memory-swap=48m \
    "$IMG_SOC" \
    up --profile router-soc --config /etc/parvault/router.toml --macaroon-root-key-hex "$SOC_STATUS_KEY" \
    --status-http 0.0.0.0:4080
sleep 2
mint_status_token() {
    docker run --rm --label "$RUN_LABEL" "$IMG_ACCEPT" /usr/local/bin/parvault --data-dir /tmp/mint \
        token mint --macaroon-key-hex "$1" --read-only | tr -d '\r\n'
}
SOC_STATUS_TOKEN="$(mint_status_token "$SOC_STATUS_KEY")"
# status_get <url> [token] [host]: prints the status code then the body.
status_get() {
    docker exec parvault-client-${RUN_ID} sh -c '
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
# status_get_tls <url> <ca file> [token] [host]: the same over HTTPS from the host (v0.5.6, B-1):
# curl checks the edge certificate against <ca file>; prints the status code then the response.
status_get_tls() {
    local hdr=() out
    [ -n "${3:-}" ] && hdr+=(-H "Authorization: Bearer $3")
    [ -n "${4:-}" ] && hdr+=(-H "Host: $4")
    out="$(curl -sS -i --max-time 20 --cacert "$2" "${hdr[@]}" "$1" 2>&1)" || true
    printf '%s\n' "$out" | awk '/^HTTP\/1.1 [0-9]+/ {print $2; exit}'
    printf '%s\n' "$out"
}

assert_nonroot --daemon "parvault-router-soc-${RUN_ID}"

# soc_proc <tag>: the router daemon's VmRSS, VmHWM and thread count, read from the host's
# /proc (the scratch image has no shell). Metrics of record for docs/metrics.txt.
soc_proc() {
    soc_pid="$(docker inspect -f '{{.State.Pid}}' parvault-router-soc-${RUN_ID})"
    awk -v tag="$1" '/^(VmRSS|VmHWM|Threads):/ {
        k = $1; sub(":", "", k); print "metric router_soc." tag "." k " = " $2 ($3 ? " " $3 : "")
    }' "/proc/$soc_pid/status"
}

SOC_DAEMON_OOM="$(docker inspect -f '{{.State.OOMKilled}}' parvault-router-soc-${RUN_ID})"
SOC_DAEMON_RUNNING="$(docker inspect -f '{{.State.Running}}' parvault-router-soc-${RUN_ID})"
if [ "$SOC_DAEMON_OOM" != "false" ] || [ "$SOC_DAEMON_RUNNING" != "true" ]; then
    echo "ERROR: parvault-router-soc-${RUN_ID} daemon failed inside 48m cgroup (OOMKilled=$SOC_DAEMON_OOM, Running=$SOC_DAEMON_RUNNING)"
    docker logs parvault-router-soc-${RUN_ID} || true
    exit 1
fi

# Verify embedded RouterNasStatusServer telemetry on ${NET_PREFIX}.60:4080. v0.5.6 (B-1, L-81,
# track A): a non-loopback status bind serves HTTPS with the daemon's own certificate (made at its
# first start; integration glue G-11). The scheme comes from the daemon's start line; over HTTPS
# the host's curl checks the certificate copied out of the appliance's data dir.
SOC_SCHEME="$(docker logs parvault-router-soc-${RUN_ID} 2>&1 | sed -n 's/.*Status Server listening on \(https\{0,1\}\):\/\/.*/\1/p' | head -1)"
SOC_SCHEME="${SOC_SCHEME:-http}"
SOC_CA=""
if [ "$SOC_SCHEME" = "https" ]; then
    command -v curl >/dev/null || { echo "ERROR: router-soc serves HTTPS and the host has no curl"; exit 1; }
    docker cp "parvault-router-soc-${RUN_ID}:/mnt/nas/.parvault-data/edge_tls.pem" "$RUN_TMP/soc_edge.pem" \
        || { echo "ERROR: no edge_tls.pem in the router-soc data dir"; exit 1; }
    sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$RUN_TMP/soc_edge.pem" > "$RUN_TMP/soc_ca.pem"
    rm -f "$RUN_TMP/soc_edge.pem"
    SOC_CA="$RUN_TMP/soc_ca.pem"
fi
# soc_get <path> [token]: status code then body, over the appliance's scheme.
soc_get() {
    if [ "$SOC_SCHEME" = "https" ]; then
        status_get_tls "https://${NET_PREFIX}.60:4080$1" "$SOC_CA" "${2:-}"
    else
        status_get "http://${NET_PREFIX}.60:4080$1" "${2:-}"
    fi
}
SOC_NO_TOKEN_CODE="$(soc_get /api/v1/health | head -1)"
if [ "$SOC_NO_TOKEN_CODE" != "401" ]; then
    echo "ERROR: router-soc status page ($SOC_SCHEME) answered $SOC_NO_TOKEN_CODE without a token (want 401)"
    exit 1
fi
SOC_HEALTH_JSON="$(soc_get /api/v1/health "$SOC_STATUS_TOKEN")"
echo "parvault-router-soc-${RUN_ID} /api/v1/health ($SOC_SCHEME): $SOC_HEALTH_JSON"
echo "$SOC_HEALTH_JSON" | grep -Eq '"hardware_profile"[[:space:]]*:[[:space:]]*"router-soc"'
soc_proc idle

# v0.5.4 NEW-3 (docs/METRICS.md): /metrics on the same listener, behind the same token.
SOC_METRICS_NONE="$(soc_get /metrics | head -1)"
if [ "$SOC_METRICS_NONE" != "401" ]; then
    echo "ERROR: router-soc /metrics answered $SOC_METRICS_NONE without a token (want 401)"
    exit 1
fi
SOC_METRICS="$(soc_get /metrics "$SOC_STATUS_TOKEN")"
if ! printf '%s\n' "$SOC_METRICS" | grep -Eq '^parvault_build_info\{version="[^"]+",profile="router-soc",deterministic="0"\} 1$'; then
    echo "ERROR: router-soc /metrics has no parvault_build_info line"
    printf '%s\n' "$SOC_METRICS" | head -20
    exit 1
fi
echo "router-soc /metrics: $(printf '%s\n' "$SOC_METRICS" | grep -c '^parvault_') series"

# v0.5.4 NEW-4 (docs/LAB_MODE.md): one direct probe from the client container to the appliance,
# against an empty data directory.
SOC_PEER_ID="$(docker logs parvault-router-soc-${RUN_ID} 2>&1 | grep 'parvault-daemon started' \
    | grep -o '12D3KooW[1-9A-HJ-NP-Za-km-z]*' | head -1)"
if [ -z "$SOC_PEER_ID" ]; then
    echo "ERROR: no PeerId in the router-soc log"; docker logs parvault-router-soc-${RUN_ID} || true
    exit 1
fi
SOC_PROBE_RC=0
SOC_PROBE="$(docker exec parvault-client-${RUN_ID} /usr/local/bin/parvault --data-dir /tmp/probe-empty \
    net probe --peer "/ip4/${NET_PREFIX}.60/tcp/4001/p2p/${SOC_PEER_ID}" --force-direct)" || SOC_PROBE_RC=$?
echo "client -> router-soc probe (exit ${SOC_PROBE_RC}): ${SOC_PROBE}"
if [ "$SOC_PROBE_RC" != "0" ] || ! printf '%s' "$SOC_PROBE" | grep -q '"result":"connected"'; then
    echo "ERROR: the probe of the router-soc appliance did not connect"
    exit 1
fi

# Store and restore a multi-stripe (5 MiB = 5 x 1 MiB stripes) payload inside a 48 MiB cgroup container!
docker volume rm -f "$SOC_VOL_NAME" >/dev/null 2>&1 || true
docker volume create "$SOC_VOL_NAME" >/dev/null
SOC_EXPECTED_SHA256="$(docker run --rm --label "$RUN_LABEL" -v "$SOC_VOL_NAME:/mnt/nas" "$IMG_ACCEPT" sh -ce '
    mkdir -p /mnt/nas/store-data /mnt/nas/restore-data
    dd if=/dev/urandom of=/mnt/nas/router_soc_5mib.bin bs=1048576 count=5 status=none
    sha256sum /mnt/nas/router_soc_5mib.bin | awk "{print \$1}"
')"

SOC_KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
docker create --name parvault-soc-store-${RUN_ID} "${CONFINE[@]}" \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    --network "$NET_NAME" \
    --memory=48m --memory-swap=48m \
    -v "$SOC_VOL_NAME:/mnt/nas" \
    "$IMG_SOC" \
    --profile router-soc \
    --data-dir /mnt/nas/store-data \
    file store --path /mnt/nas/router_soc_5mib.bin --key-hex "$SOC_KEY" >/dev/null
assert_oneshot_confined "parvault-soc-store-${RUN_ID}" "$IMG_SOC"
SOC_STORE_OUT="$(docker start -a parvault-soc-store-${RUN_ID})"
echo "$SOC_STORE_OUT"

SOC_STORE_OOM="$(docker inspect -f '{{.State.OOMKilled}}' parvault-soc-store-${RUN_ID})"
SOC_STORE_EXIT="$(docker inspect -f '{{.State.ExitCode}}' parvault-soc-store-${RUN_ID})"
docker rm -fv parvault-soc-store-${RUN_ID} >/dev/null
if [ "$SOC_STORE_OOM" != "false" ] || [ "$SOC_STORE_EXIT" != "0" ]; then
    echo "ERROR: parvault-soc-store-${RUN_ID} hit OOM or failed in 48m cgroup (OOMKilled=$SOC_STORE_OOM, Exit=$SOC_STORE_EXIT)"
    exit 1
fi
echo "$SOC_STORE_OUT" | grep -Eq "Total Stripes[[:space:]]*:[[:space:]]*5"

SOC_ROOT="$(echo "$SOC_STORE_OUT" | awk '/File Merkle Root/ {print $5}')"

# Wipe local store-data so restore pulls all 5 stripes over libp2p inside another 48 MiB cgroup container!
docker run --rm --label "$RUN_LABEL" -v "$SOC_VOL_NAME:/mnt/nas" "$IMG_ACCEPT" rm -rf /mnt/nas/store-data

docker create --name parvault-soc-restore-${RUN_ID} "${CONFINE[@]}" \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    --network "$NET_NAME" \
    --memory=48m --memory-swap=48m \
    -v "$SOC_VOL_NAME:/mnt/nas" \
    "$IMG_SOC" \
    --profile router-soc \
    --data-dir /mnt/nas/restore-data \
    file restore "$SOC_ROOT" --output /mnt/nas/restored_5mib.bin --key-hex "$SOC_KEY" >/dev/null
assert_oneshot_confined "parvault-soc-restore-${RUN_ID}" "$IMG_SOC"
SOC_RESTORE_OUT="$(docker start -a parvault-soc-restore-${RUN_ID})"
echo "$SOC_RESTORE_OUT"

SOC_RESTORE_OOM="$(docker inspect -f '{{.State.OOMKilled}}' parvault-soc-restore-${RUN_ID})"
SOC_RESTORE_EXIT="$(docker inspect -f '{{.State.ExitCode}}' parvault-soc-restore-${RUN_ID})"
docker rm -fv parvault-soc-restore-${RUN_ID} >/dev/null
if [ "$SOC_RESTORE_OOM" != "false" ] || [ "$SOC_RESTORE_EXIT" != "0" ]; then
    echo "ERROR: parvault-soc-restore-${RUN_ID} hit OOM or failed in 48m cgroup (OOMKilled=$SOC_RESTORE_OOM, Exit=$SOC_RESTORE_EXIT)"
    exit 1
fi

SOC_ACTUAL_SHA256="$(docker run --rm --label "$RUN_LABEL" -v "$SOC_VOL_NAME:/mnt/nas" "$IMG_ACCEPT" sh -ce 'sha256sum /mnt/nas/restored_5mib.bin | awk "{print \$1}"')"
if [ "$SOC_ACTUAL_SHA256" != "$SOC_EXPECTED_SHA256" ]; then
    echo "ERROR: SHA-256 mismatch after 48m cgroup Router-SoC restore ($SOC_ACTUAL_SHA256 != $SOC_EXPECTED_SHA256)"
    exit 1
fi

SOC_DAEMON_OOM_AFTER="$(docker inspect -f '{{.State.OOMKilled}}' parvault-router-soc-${RUN_ID})"
if [ "$SOC_DAEMON_OOM_AFTER" != "false" ]; then
    echo "ERROR: parvault-router-soc-${RUN_ID} daemon OOMKilled during multi-stripe transfer!"
    exit 1
fi
soc_proc after_transfer

echo "=== [12b/12] parvault-status sidecar: no key, token-gated status over the gateway socket ==="
SIDE_KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
SIDE_TOKEN="$(mint_status_token "$SIDE_KEY")"
# v0.5.6 (B-1, L-81, A-TLS-3): parvault-status refuses plain HTTP on a non-loopback --listen; it
# serves HTTPS with a PEM it loads (it never generates one). The gate makes a P-256 leaf with
# openssl on the host; the container writes it 0600 as its own user (the key-file rule).
command -v openssl >/dev/null && command -v curl >/dev/null \
    || { echo "ERROR: stage 12b needs openssl and curl on the host (sidecar over TLS)"; exit 1; }
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=parvault-status" \
    -addext "subjectAltName=IP:${NET_PREFIX}.61" -addext "basicConstraints=critical,CA:FALSE" \
    -addext "extendedKeyUsage=serverAuth" -keyout "$RUN_TMP/side.key" -out "$RUN_TMP/side_ca.pem" 2>/dev/null \
    || { echo "ERROR: openssl could not make the sidecar certificate"; exit 1; }
SIDE_PEM="$(cat "$RUN_TMP/side_ca.pem" "$RUN_TMP/side.key")"
rm -f "$RUN_TMP/side.key"
docker run -d --name parvault-status-sidecar-${RUN_ID} "${CONFINE[@]}" \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    -e SIDE_KEY="$SIDE_KEY" -e SIDE_TOKEN="$SIDE_TOKEN" -e SIDE_PEM="$SIDE_PEM" \
    --network "$NET_NAME" --ip ${NET_PREFIX}.61 \
    --memory=48m --memory-swap=48m \
    "$IMG_ACCEPT" sh -c '
        mkdir -p /run/pv /var/lib/parvault /tmp/sidecar-cwd
        /usr/local/bin/parvault --data-dir /var/lib/parvault --no-lan-discovery up --profile router-soc \
            --ipc-socket /run/pv/gw.sock --macaroon-root-key-hex "$SIDE_KEY" > /tmp/daemon.log 2>&1 &
        i=0; while [ ! -S /run/pv/gw.sock ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done
        cd /tmp/sidecar-cwd
        (umask 077; printf "%s\n" "$SIDE_TOKEN" > /run/pv/status.token; printf "%s\n" "$SIDE_PEM" > /run/pv/edge.pem)
        unset SIDE_PEM
        exec /usr/local/bin/parvault-status --socket /run/pv/gw.sock --listen 0.0.0.0:4081 --macaroon-file /run/pv/status.token \
            --tls-pem /run/pv/edge.pem'
SIDE_UP=0
for _ in $(seq 1 100); do
    if docker logs parvault-status-sidecar-${RUN_ID} 2>&1 | grep -q "Status Server listening on https://"; then SIDE_UP=1; break; fi
    sleep 0.2
done
if [ "$SIDE_UP" != "1" ]; then
    echo "ERROR: parvault-status did not start over HTTPS"; docker logs parvault-status-sidecar-${RUN_ID} || true
    docker exec parvault-status-sidecar-${RUN_ID} cat /tmp/daemon.log || true
    exit 1
fi
assert_nonroot --daemon "parvault-status-sidecar-${RUN_ID}"
assert_nonroot "parvault-outsider-${RUN_ID}"
SIDE_URL="https://${NET_PREFIX}.61:4081/api/v1/health"
SIDE_CA="$RUN_TMP/side_ca.pem"
SIDE_OK="$(status_get_tls "$SIDE_URL" "$SIDE_CA" "$SIDE_TOKEN")"
SIDE_NONE="$(status_get_tls "$SIDE_URL" "$SIDE_CA" | head -1)"
SIDE_DNS="$(status_get_tls "$SIDE_URL" "$SIDE_CA" "$SIDE_TOKEN" rebind.example:4081 | head -1)"
SIDE_QUERY="$(status_get_tls "$SIDE_URL?token=$SIDE_TOKEN" "$SIDE_CA" | head -1)"
# Plain HTTP to the TLS port gets no HTTP answer.
SIDE_PLAIN="$(status_get "http://${NET_PREFIX}.61:4081/api/v1/health" "$SIDE_TOKEN" | head -1)"
echo "sidecar (https): token=$(echo "$SIDE_OK" | head -1) none=$SIDE_NONE dns-host=$SIDE_DNS query-token=$SIDE_QUERY plain-http=${SIDE_PLAIN:-none}"
if [ "$(echo "$SIDE_OK" | head -1)" != "200" ] || ! echo "$SIDE_OK" | grep -q '"version"' \
    || [ "$SIDE_NONE" != "401" ] || [ "$SIDE_DNS" != "403" ] || [ "$SIDE_QUERY" != "401" ] \
    || [ -n "$SIDE_PLAIN" ]; then
    echo "ERROR: parvault-status sidecar answers wrong"; docker logs parvault-status-sidecar-${RUN_ID} || true
    exit 1
fi
SIDE_WRITTEN="$(docker exec parvault-status-sidecar-${RUN_ID} sh -c 'ls -A /tmp/sidecar-cwd | wc -l')"
if [ "$SIDE_WRITTEN" != "0" ]; then
    echo "ERROR: parvault-status wrote files in its working directory"; exit 1
fi
if docker logs parvault-status-sidecar-${RUN_ID} 2>&1 | grep -qF "$SIDE_TOKEN"; then
    echo "ERROR: the status token is in the sidecar log"; exit 1
fi
SIDE_OOM="$(docker inspect -f '{{.State.OOMKilled}}' parvault-status-sidecar-${RUN_ID})"
[ "$SIDE_OOM" = "false" ] || { echo "ERROR: sidecar container OOMKilled"; exit 1; }
SIDE_BIN_BYTES="$(docker exec parvault-status-sidecar-${RUN_ID} stat -c%s /usr/local/bin/parvault-status)"

echo "=== [12c/12] Mounted MP4 probe and random seek: /dev/fuse and WebDAV 206, then netem 15ms/2% ==="
# Plan-5 / design ledger 7.2. The release test binary tests/vfs_mp4_seek_gate.rs runs in a glibc
# image with fuse3 and ffmpeg. FUSE leg: --device /dev/fuse + SYS_ADMIN. WebDAV leg: an
# unprivileged container (no device, no caps), then the same leg with tc netem on its loopback,
# which delays the HTTP hop between ffmpeg and the WebDAV edge (stripes stay local: a mesh-fetched
# netem leg is deferred). A missing /dev/fuse is SKIPPED, and a FAIL under GATES_REQUIRE_REAL=1.
VFS_CTX="$STAGE_DIR/acceptance-vfs"
rm -rf "$VFS_CTX"
mkdir -p "$VFS_CTX"
VFS_TEST_BIN="$(cargo test --locked --release --test vfs_mp4_seek_gate --no-run --message-format=json 2>/dev/null \
    | sed -n 's/.*"executable":"\([^"]*vfs_mp4_seek_gate[^"]*\)".*/\1/p' | tail -1)"
[ -x "$VFS_TEST_BIN" ] || { echo "ERROR: stage 12c: no vfs_mp4_seek_gate test binary"; exit 1; }
# The test binary is not staged through stage_artifact.sh: the helper stages `--bin` targets
# only (no `--test`). It is the gate's own harness, not a shipped artifact (A-DOCKER, B-47).
cp "$VFS_TEST_BIN" "$VFS_CTX/vfs_mp4_seek_gate"
# parvault-fuse with its release feature set (scripts/build_bins.sh features_for parvault-fuse).
bash scripts/stage_artifact.sh --bin parvault-fuse --profile release --no-default-features --features vfs \
    --dest "$VFS_CTX/parvault-fuse"
cat > "$VFS_CTX/Dockerfile" <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -o Acquire::Retries=3 \
    && apt-get install -y --no-install-recommends fuse3 ffmpeg iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY vfs_mp4_seek_gate /usr/local/bin/vfs_mp4_seek_gate
COPY parvault-fuse /usr/local/bin/parvault-fuse
# TMPDIR=/tmp: on an Ubuntu 24.04+ host the AppArmor fusermount3 profile attaches by path even
# inside the container (apparmor:unconfined does not stop it) and denies mount points outside
# $HOME, /mnt, /media, /run/user/<uid> and /tmp ("failed mntpnt match" under /var/tmp).
ENV PARVAULT_FUSE_BIN=/usr/local/bin/parvault-fuse TMPDIR=/tmp
# Non-root (B-106) for the WebDAV legs; the FUSE leg runs as root (see below).
RUN printf 'parvault:x:65532:65532:parvault:/var/lib/parvault:/usr/sbin/nologin\n' >> /etc/passwd \
    && printf 'parvault:x:65532:\n' >> /etc/group \
    && mkdir -p /var/lib/parvault && chown 65532:65532 /var/lib/parvault
USER parvault:parvault
WORKDIR /var/lib/parvault
ENTRYPOINT ["/usr/local/bin/vfs_mp4_seek_gate", "--test-threads=1", "--nocapture"]
EOF
docker build -t "$IMG_VFS" "$VFS_CTX"

VFS_FUSE_RESULT="SKIPPED (no /dev/fuse)"
# The FUSE leg runs as root with SYS_ADMIN, in a container assert_nonroot waives (FUSE_WAIVED,
# see assert_nonroot for the reason). It is created, its waiver checked, and only then started.
# The /dev/fuse probe needs no privilege and runs as uid 65532.
if [ -c /dev/fuse ] && docker run --rm --label "$RUN_LABEL" --device /dev/fuse \
        --security-opt apparmor:unconfined --entrypoint test "$IMG_VFS" -c /dev/fuse; then
    docker rm -fv "$FUSE_WAIVED" >/dev/null 2>&1 || true
    docker create --label "$RUN_LABEL" --name "$FUSE_WAIVED" --user 0:0 --device /dev/fuse --cap-add SYS_ADMIN \
        --security-opt no-new-privileges --security-opt apparmor:unconfined -e GATES_REQUIRE_REAL=1 "$IMG_VFS" \
        fuse_mount_mp4_probe_and_random_seek parvault_fuse_plugin_mount_rss_under_16_mib >/dev/null
    assert_nonroot "$FUSE_WAIVED"
    docker start "$FUSE_WAIVED" >/dev/null
    VFS_FUSE_RC="$(timeout --kill-after=30 600 docker wait "$FUSE_WAIVED")" || VFS_FUSE_RC="timeout"
    docker logs "$FUSE_WAIVED" 2>&1 || true
    docker rm -fv "$FUSE_WAIVED" >/dev/null 2>&1 || true
    [ "$VFS_FUSE_RC" = "0" ] || { echo "ERROR: stage 12c: the FUSE leg failed or exceeded 600 s (exit $VFS_FUSE_RC)"; exit 1; }
    VFS_FUSE_RESULT="PASS"
elif [ "${GATES_REQUIRE_REAL:-0}" = "1" ]; then
    echo "ERROR: stage 12c: /dev/fuse cannot be passed into a container (GATES_REQUIRE_REAL=1)"
    exit 1
else
    echo "SKIPPED: stage 12c FUSE leg: /dev/fuse cannot be passed into a container"
fi

# Unprivileged WebDAV leg: no device, no capabilities.
docker run --rm --label "$RUN_LABEL" -e GATES_REQUIRE_REAL=1 "$IMG_VFS" webdav_206_mp4_probe_and_random_seek \
    || { echo "ERROR: stage 12c: the unprivileged WebDAV leg failed"; exit 1; }

# netem leg: NET_ADMIN only for tc; a 100 ms budget on the median of 5 cold requests (B-56: one
# sample can carry a 200 ms loss RTO), and the cache cap. The per-block miss set is
# logged, not asserted: under latency an abandoned `Range: bytes=N-` can hydrate up to about one
# TCP window of extra blocks (B-23, v0.6.0).
# Bounded (B-56): a hang (seen once as ~590 s, a lost shutdown wake SYN) fails the gate loudly.
VFS_NETEM="$NETEM_TC_TARGET"
# B-106: the test container runs as uid 65532 with no capability. A one-shot root sidecar,
# NETEM_TC_WAIVED (waived by name in assert_nonroot), joins its network namespace with only
# NET_ADMIN and adds netem on lo; the test waits for that, then runs.
docker rm -fv "$VFS_NETEM" "$NETEM_TC_WAIVED" >/dev/null 2>&1 || true
docker run -d --name "$VFS_NETEM" --label "$RUN_LABEL" "${CONFINE[@]}" -e GATES_REQUIRE_REAL=1 -e PARVAULT_VFS_TTFB_BUDGET_MS=100 \
    -e PARVAULT_VFS_GATE_LATENCY=1 \
    --entrypoint sh "$IMG_VFS" -c \
    'i=0; while [ ! -e /tmp/netem.ready ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done
     [ -e /tmp/netem.ready ] || { echo "netem was never applied"; exit 97; }
     exec /usr/local/bin/vfs_mp4_seek_gate --test-threads=1 --nocapture webdav_206_mp4_probe_and_random_seek' >/dev/null
# The full policy (not privileged, no capability, no-new-privileges, ids) before the sidecar joins it.
assert_nonroot "$VFS_NETEM"
docker create --label "$RUN_LABEL" --name "$NETEM_TC_WAIVED" --network "container:$VFS_NETEM" --user 0:0 \
    "${CONFINE[@]}" --cap-add NET_ADMIN --entrypoint tc \
    "$IMG_VFS" qdisc add dev lo root netem delay 15ms loss 2% >/dev/null
assert_nonroot "$NETEM_TC_WAIVED"
docker start -a "$NETEM_TC_WAIVED" \
    || { echo "ERROR: stage 12c: the netem sidecar could not add netem on lo"; exit 1; }
docker rm -fv "$NETEM_TC_WAIVED" >/dev/null
VFS_NETEM_QDISC="$(docker exec "$VFS_NETEM" tc qdisc show dev lo)"
grep -q "netem" <<<"$VFS_NETEM_QDISC" || { echo "ERROR: stage 12c: no netem qdisc on lo: $VFS_NETEM_QDISC"; exit 1; }
docker exec "$VFS_NETEM" touch /tmp/netem.ready
VFS_NETEM_RC="$(timeout --kill-after=30 600 docker wait "$VFS_NETEM")" || VFS_NETEM_RC="timeout"
docker logs "$VFS_NETEM" 2>&1 || true
docker rm -fv "$VFS_NETEM" >/dev/null 2>&1 || true
[ "$VFS_NETEM_RC" = "0" ] \
    || { echo "ERROR: stage 12c: the WebDAV leg under netem 15ms/2% failed or exceeded 600 s (exit $VFS_NETEM_RC)"; exit 1; }
echo "Mounted MP4 gate verified: FUSE ${VFS_FUSE_RESULT}; WebDAV 206 PASS (plain and under netem)."

echo "================================================================================"
PARVAULT_VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
echo " PARVAULT v${PARVAULT_VERSION} MULTI-CONTAINER & ROUTER-SOC DOCKER ACCEPTANCE SUMMARY"
echo "================================================================================"
echo " Base Image             : ${BASE_IMAGE}"
echo " Containers Deployed    : 16 (1 parvault-seed + 11 daemon + 1 router-soc + 1 client + 1 invitee + 1 outsider)"
echo " Client Shared Volumes  : ${CLIENT_MOUNTS} (strictly isolated)"
echo " Zero-IP LAN Discovery  : PASS (${DISCOVERED_COUNT} daemons auto-discovered with 0 IPs)"
echo " Initial Sync (v1)      : ${TOTAL_SHARDS_V1} shards across 10 nodes (${SYNC_V1_SECS}s)"
echo " Continuous Watch (v2)  : PASS (live update + tombstone pruning over libp2p)"
echo " Lite-Client Failover   : PASS (1.0x seed syndication + NAS-death mesh recovery)"
echo " Eviction Council       : PASS (signed manifest epoch 1; member order applied; non-member refused)"
echo " Graceful Node Leave    : PASS (parvault-node-5-${RUN_ID} -> parvault-node-11-${RUN_ID}: ${NODE11_AFTER} shards)"
echo " Bit-Rot Scrubbing      : PASS (1 corrupted shard detected & quarantined)"
echo " Disaster Recovery      : PASS (4 killed + 1 left + 2 restarted, ${RECOVER_SECS}s)"
echo " Cross-Machine File CLI : PASS (file store -> wipe -> file restore verified)"
echo " Router-SoC Binary      : ${SOC_BIN_MIB} stripped static musl (--profile soc)"
echo " Router-SoC Image       : ${ROUTER_SOC_IMAGE_SIZE} (FROM scratch)"
echo " 48 MiB Cgroup SoC Gate : PASS (5 x 1 MiB stripes store+restore, 0 OOM kills)"
echo " Status page (item 3)   : PASS (router-soc: no token 401, read-only token 200)"
echo " parvault-status sidecar: PASS (200 / 401 / DNS Host 403 / ?token= 401; no files; ${SIDE_BIN_BYTES} B)"
echo " Mounted MP4 (item 5)   : FUSE ${VFS_FUSE_RESULT}; WebDAV 206 PASS (plain + netem 15ms/2%, < 100 ms)"
echo " Non-root (B-106)       : PASS (uid/gid 65532, CapEff empty, no-new-privileges in every daemon container; waived: ${FUSE_WAIVED} (FUSE harness, SYS_ADMIN), ${NETEM_TC_WAIVED} (tc sidecar, NET_ADMIN)"
echo "================================================================================"
echo "=== ACCEPTANCE GATE PASSED ==="
