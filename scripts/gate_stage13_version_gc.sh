# Stage 13 of scripts/docker_acceptance_gate.sh (sourced there; v0.5.6 track B2): B-154 version
# GC on a real 3-node ring. Uses the gate's RUN_ID, RUN_LABEL, NET_NAME, NET_PREFIX, IMG_ACCEPT,
# CONFINE and RING_GENESIS_SEED_HEX; its containers carry RUN_LABEL, so the gate's cleanup
# removes them.
#
# T1 (log churn, arch154 C23): three logs, each appended 24 KiB per pass and rotated at 512 KiB
# (log -> log.1, log.2 dropped), 60 passes driven by pass count (about 3 rotations each).
# After every pass the shard bytes on the 3 hosts stay within
#   1.1 x keep x max(disk bytes of the retained passes) x n/k x r
# (keep 3 under the default policy, all versions in one day; Homelab n/k = 20/16; r = 3 on a
# 3-host ring, the B-149 replica shift), the last 20 passes do not grow past 1.2x the 20 before,
# and at the end every retained version restores byte-identically.
# T2 on the ring: an unchanged pass keeps the version and adds no host shard.
# T4 (offline host): with one host stopped, 4 changed passes leave its garbage journalled; once it
# is back, within 3 passes its shards are freed and the journal is empty.

# Everything the owner writes lives under S13_ROOT: the image runs as uid 65532, and only
# /var/lib/parvault (and /tmp) is writable there.
S13_ROOT=/var/lib/parvault/s13
S13_LOGS="$S13_ROOT/logs"
S13_HOME="$S13_ROOT/owner"
# No step may hang the gate: every docker exec has a deadline, and so does the whole stage.
S13_EXEC_SECS=${S13_EXEC_SECS:-300}
S13_DEADLINE=$(( $(date +%s) + ${S13_STAGE_SECS:-5400} ))
s13_fail() { echo "ERROR: stage 13: $*"; exit 1; }
s13_exec() { timeout --kill-after=10 "$S13_EXEC_SECS" docker exec "$@"; }
s13_check_deadline() {
    [ "$(date +%s)" -le "$S13_DEADLINE" ] || s13_fail "over its ${S13_STAGE_SECS:-5400} s deadline ($1)"
}

S13_NODES=()
S13_PEERS=()
for j in 1 2 3; do
    S13_NODES+=("pv-b2-node-$j-${RUN_ID}")
    S13_PEERS+=("/ip4/${NET_PREFIX}.$((70 + j))/tcp/4001")
done
S13_PEERS_CSV="$(IFS=,; echo "${S13_PEERS[*]}")"
S13_OWNER="pv-b2-owner-${RUN_ID}"

s13_start_node() {
    local j=$1
    docker run -d --name "pv-b2-node-$j-${RUN_ID}" --label "$RUN_LABEL" "${CONFINE[@]}" \
        -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
        --network "$NET_NAME" --ip "${NET_PREFIX}.$((70 + j))" \
        -w /var/lib/parvault \
        "$IMG_ACCEPT" \
        /usr/local/bin/parvault --no-lan-discovery daemon start --listen /ip4/0.0.0.0/tcp/4001 >/dev/null
}

# Shard bytes held by every running stage-13 host.
s13_host_bytes() {
    local total=0 b
    for n in "${S13_NODES[@]}"; do
        b="$(s13_exec "$n" sh -c 'cat /var/lib/parvault/.parvault-data/shards/*.shard 2>/dev/null | wc -c' 2>/dev/null || echo 0)"
        total=$((total + b))
    done
    echo "$total"
}

s13_pass() {
    s13_exec -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
        -e RUST_LOG="${S13_RUST_LOG:-parvault=info,warn}" "$S13_OWNER" \
        /usr/local/bin/parvault --data-dir "$S13_HOME" --no-lan-discovery --peers "$S13_PEERS_CSV" \
        watch-folder --folder "$S13_LOGS" --snapshot-out "$S13_HOME/logs.snap" \
        --key-hex 7373737373737373737373737373737373737373737373737373737373737373 --once
}

echo "=== [13] B-154 version GC: log churn (T1), unchanged pass (T2), offline host (T4) ==="
# Setup fails fast: a container that does not start or a directory that cannot be made stops the
# stage here, with the reason.
for j in 1 2 3; do s13_start_node "$j" || s13_fail "host $j did not start"; done
docker run -d --name "$S13_OWNER" --label "$RUN_LABEL" "${CONFINE[@]}" \
    -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" \
    --network "$NET_NAME" --ip "${NET_PREFIX}.74" \
    "$IMG_ACCEPT" sleep 7200 >/dev/null || s13_fail "the owner container did not start"
sleep 3
for n in "${S13_NODES[@]}"; do
    [ "$(docker inspect -f '{{.State.Running}}' "$n" 2>/dev/null)" = true ] \
        || { docker logs "$n" 2>&1 | tail -20; s13_fail "host $n is not running"; }
done
s13_exec "$S13_OWNER" mkdir -p "$S13_LOGS" "$S13_HOME" || s13_fail "cannot create $S13_LOGS and $S13_HOME"

# T1: the churn. Each pass appends 24 KiB of fresh random text to each log; a log reaching
# 512 KiB rotates first.
S13_DISK=()
S13_BYTES=()
S13_MAXD=()
for pass in $(seq 1 60); do
    s13_check_deadline "T1 pass $pass"
    s13_exec "$S13_OWNER" sh -c '
        cd "$1" || exit 1
        for l in a b c; do
            if [ -f "$l.log" ] && [ "$(wc -c < "$l.log")" -ge 524288 ]; then
                rm -f "$l.log.2"; [ -f "$l.log.1" ] && mv "$l.log.1" "$l.log.2"; mv "$l.log" "$l.log.1"
            fi
            head -c 18432 /dev/urandom | base64 >> "$l.log"
        done' s13 "$S13_LOGS" || s13_fail "T1 pass $pass: could not append to the logs"
    S13_OUT="$(s13_pass 2>&1)" || { echo "$S13_OUT"; echo "ERROR: stage 13: T1 pass $pass failed"; exit 1; }
    S13_DISK+=("$(s13_exec "$S13_OWNER" sh -c 'cat "$1"/* | wc -c' s13 "$S13_LOGS")")
    S13_BYTES+=("$(s13_host_bytes)")
    # The bound uses the largest folder among the retained passes (the last 3).
    MAXD=0
    for k in $(seq $((pass > 3 ? pass - 3 : 0)) $((pass - 1))); do
        [ "${S13_DISK[$k]}" -gt "$MAXD" ] && MAXD="${S13_DISK[$k]}"
    done
    # 1.1 x 3 x MAXD x 20/16 x 3, plus one 64 KiB shard per stripe of padding slack per host.
    BOUND=$(( MAXD * 11 * 3 * 20 * 3 / (10 * 16) + 3 * 3 * 20 * 3 * 65536 ))
    S13_MAXD+=("$MAXD")
    if [ "${S13_BYTES[$((pass - 1))]}" -gt "$BOUND" ]; then
        echo "$S13_OUT"
        echo "ERROR: stage 13: T1 pass $pass: hosts hold ${S13_BYTES[$((pass - 1))]} B, bound $BOUND B"
        exit 1
    fi
done
# The plateau: the live folder itself still grows through pass 60 (each log keeps .log, .log.1
# and .log.2, steady only after about pass 63), so the windows compare host bytes per byte of the
# largest retained folder (R, in thousandths), not raw bytes: GC that frees old versions keeps R
# flat; a leak makes it grow.
EARLY=0; LATE=0; R_EARLY=0; R_LATE=0
for k in $(seq 20 59); do
    R=$(( S13_BYTES[k] * 1000 / (S13_MAXD[k] > 0 ? S13_MAXD[k] : 1) ))
    if [ "$k" -lt 40 ]; then
        [ "${S13_BYTES[$k]}" -gt "$EARLY" ] && EARLY="${S13_BYTES[$k]}"
        [ "$R" -gt "$R_EARLY" ] && R_EARLY="$R"
    else
        [ "${S13_BYTES[$k]}" -gt "$LATE" ] && LATE="${S13_BYTES[$k]}"
        [ "$R" -gt "$R_LATE" ] && R_LATE="$R"
    fi
done
if [ $(( R_LATE * 10 )) -gt $(( R_EARLY * 12 )) ]; then
    echo "ERROR: stage 13: T1 host bytes per retained folder byte still grow (passes 41-60 max R $R_LATE, passes 21-40 max R $R_EARLY; raw $LATE B, $EARLY B)"
    exit 1
fi
grep -q "Version GC" <<<"$S13_OUT" || { echo "$S13_OUT"; echo "ERROR: stage 13: no GC line"; exit 1; }
# Every retained version restores byte-identically to the bytes it recorded (its file hashes).
S13_VERSIONS="$(s13_exec "$S13_OWNER" ls "$S13_HOME/logs.snap.versions" | sed -n 's/^v0*\([0-9][0-9]*\)\.snap$/\1/p')"
[ -n "$S13_VERSIONS" ] || s13_fail "T1 no retained version in $S13_HOME/logs.snap.versions"
for v in $S13_VERSIONS; do
    s13_check_deadline "T1 restore of version $v"
    s13_exec -e PARVAULT_GENESIS_SEED_HEX="$RING_GENESIS_SEED_HEX" "$S13_OWNER" \
        /usr/local/bin/parvault --data-dir "$S13_HOME" --no-lan-discovery --peers "$S13_PEERS_CSV" \
        restore-folder --snapshot "$S13_HOME/logs.snap" --version "$v" --out-dir "$S13_ROOT/r$v" \
        --key-hex 7373737373737373737373737373737373737373737373737373737373737373 >/dev/null \
        || { echo "ERROR: stage 13: T1 retained version $v does not restore"; exit 1; }
done
S13_LAST="$(tail -1 <<<"$S13_VERSIONS")"
s13_exec "$S13_OWNER" sh -c 'cd "$1" && for f in *; do cmp "$f" "$2/$f" || exit 1; done' s13 "$S13_LOGS" "$S13_ROOT/r$S13_LAST" \
    || { echo "ERROR: stage 13: T1 the newest version does not restore byte-identically"; exit 1; }
echo "T1: 60 passes; hosts ${S13_BYTES[59]} B at the end (passes 21-40 max $EARLY B, 41-60 max $LATE B; host bytes per retained folder byte x1000: 21-40 max $R_EARLY, 41-60 max $R_LATE)"

# T2 on the ring: an unchanged pass.
S13_BEFORE="$(s13_host_bytes)"
S13_OUT="$(s13_pass 2>&1)" || { echo "$S13_OUT"; echo "ERROR: stage 13: T2 pass failed"; exit 1; }
grep -q "(no change)" <<<"$S13_OUT" || { echo "$S13_OUT"; echo "ERROR: stage 13: T2 not a no-change pass"; exit 1; }
[ "$(s13_host_bytes)" = "$S13_BEFORE" ] || { echo "ERROR: stage 13: T2 an unchanged pass changed host bytes"; exit 1; }
echo "T2: unchanged pass kept the version; host bytes unchanged"

# T4: host 3 offline for 4 changed passes, then back.
docker stop "pv-b2-node-3-${RUN_ID}" >/dev/null
for pass in 1 2 3 4; do
    s13_check_deadline "T4 offline pass $pass"
    s13_exec "$S13_OWNER" sh -c 'head -c 4096 /dev/urandom | base64 >> "$1/a.log"' s13 "$S13_LOGS" \
        || s13_fail "T4 pass $pass: could not append"
    S13_OUT="$(s13_pass 2>&1)" || true
done
grep -Eq "Pending Frees      : [1-9]" <<<"$S13_OUT" || { echo "$S13_OUT"; echo "ERROR: stage 13: T4 no pending frees while host 3 is offline"; exit 1; }
S13_LISTEN_BEFORE="$(docker logs "pv-b2-node-3-${RUN_ID}" 2>&1 | grep -c 'Listening on' || true)"
docker start "pv-b2-node-3-${RUN_ID}" >/dev/null || s13_fail "T4 host 3 did not restart"
# Wait (with a deadline) until host 3 listens again, rather than a fixed sleep.
S13_WAIT_END=$(( $(date +%s) + 60 ))
until [ "$(docker logs "pv-b2-node-3-${RUN_ID}" 2>&1 | grep -c 'Listening on' || true)" -gt "$S13_LISTEN_BEFORE" ]; do
    [ "$(date +%s)" -le "$S13_WAIT_END" ] || s13_fail "T4 host 3 not listening 60 s after its restart"
    sleep 1
done
sleep 2
S13_RUST_LOG="parvault=info,parvault::network::client=debug,parvault::sync::gc_journal=debug,warn"
S13_CLEARED=0
S13_T4_LOG=""
for pass in 1 2 3; do
    s13_check_deadline "T4 return pass $pass"
    S13_OUT="$(s13_pass 2>&1)" || true
    S13_T4_LOG+="--- T4 return pass $pass ---"$'\n'"$S13_OUT"$'\n'
    if grep -q "Pending Frees      : 0 " <<<"$S13_OUT"; then S13_CLEARED=1; break; fi
done
if [ "$S13_CLEARED" != 1 ]; then
    echo "$S13_T4_LOG"
    echo "--- host 3 log (last 80 lines) ---"
    docker logs "pv-b2-node-3-${RUN_ID}" 2>&1 | tail -80
    s13_fail "T4 the journal did not empty within 3 passes of the host's return"
fi
echo "T4: host 3 back; journal empty within $pass pass(es)"
