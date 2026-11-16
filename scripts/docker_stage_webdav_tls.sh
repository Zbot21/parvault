#!/usr/bin/env bash
# Docker stage 14-webdav-tls (v0.5.6 E1 steps 5 and 9; plan v0.5.6-usability.md Section 1.4).
#
# One parvault daemon in a bridge-mode container (uid 65532, no capability, no-new-privileges)
# serves the read-only WebDAV edge over TLS on 0.0.0.0:8443 with a seeded fixture (two text
# files, a 3 MiB and a 64 MiB binary) and `--tls-san pv-edge.test`. Then:
#   - published-port leg (E1+ step 9): from the host, through `-p 127.0.0.1::8443`, curl with the
#     exported certificate and the pin, by the --tls-san name (--resolve) and by 127.0.0.1:
#     PROPFIND Depth 1 is 207 and lists the fixture, every file reads back equal (cmp), a Range
#     read is 206 with the right bytes, PUT is 405;
#   - davfs2 leg (step 5): a client container on the same network mounts the edge read-only with
#     `trust_ca_cert` and the token in `secrets`, lists it and cmp's every file, the 64 MiB one
#     included. davfs2 needs /dev/fuse and SYS_ADMIN, so the client runs as root (the one waived
#     container of this stage); no /dev/fuse is SKIPPED, and a FAIL under GATES_REQUIRE_REAL=1.
#
# Every Docker resource is private to the run (RUN_ID suffix and label); the EXIT trap removes
# only those. The parvault binary is staged through scripts/stage_artifact.sh (A-DOCKER).
# Standalone: `bash scripts/docker_stage_webdav_tls.sh`; the acceptance gate calls it as its
# stage 14 with PARVAULT_GATE_RUN_ID and PARVAULT_GATE_STAGE_DIR set.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RUN_ID="${PARVAULT_GATE_RUN_ID:-tls$$-$RANDOM}"
[[ "$RUN_ID" =~ ^[a-z0-9][a-z0-9_.-]{0,40}$ ]] || { echo "ERROR: bad PARVAULT_GATE_RUN_ID '$RUN_ID'"; exit 2; }
LABEL="parvault.gate.run=${RUN_ID}"
NET="pvtls-net-${RUN_ID}"
IMG="parvault:webdav-tls-${RUN_ID}"
EDGE="pvtls-edge-${RUN_ID}"
DAVFS_WAIVED="pvtls-davfs2-${RUN_ID}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/pvtls-${RUN_ID}.XXXXXX")"
CTX="${PARVAULT_GATE_STAGE_DIR:-${HOME}/.cache/parvault-gate-stage/${RUN_ID}}/webdav-tls-image"

cleanup() {
    local rc=$?
    if [ "${KEEP_CONTAINERS:-0}" != "1" ]; then
        docker rm -fv "$EDGE" "$DAVFS_WAIVED" >/dev/null 2>&1 || true
        docker network rm "$NET" >/dev/null 2>&1 || true
        docker image rm "$IMG" >/dev/null 2>&1 || true
        rm -rf "$TMP"
    fi
    exit "$rc"
}
trap cleanup EXIT

fail() { echo "ERROR: stage 14-webdav-tls: $*"; [ -n "${EDGE_LOGS:-}" ] && docker logs "$EDGE" 2>&1 | tail -40; exit 1; }

echo "=== [14] WebDAV over TLS: published port (--tls-san) and davfs2 read-only mount ==="

# Fixture (host side, mounted read-only into the edge and the client).
SEED="$TMP/seed"
mkdir -p "$SEED"
printf 'ParVault E1 notes\r\nline two\r\n' > "$SEED/notes.txt"
printf 'read me\n' > "$SEED/readme.txt"
head -c $((3 * 1024 * 1024)) /dev/urandom > "$SEED/photo.bin"
head -c $((64 * 1024 * 1024)) /dev/urandom > "$SEED/video.bin"
chmod 0755 "$SEED" && chmod 0644 "$SEED"/*

rm -rf "$CTX"
mkdir -p "$CTX"
bash scripts/stage_artifact.sh --bin parvault --profile release --dest "$CTX/parvault"
chmod +x "$CTX/parvault"
cat > "$CTX/Dockerfile" <<'EOF'
FROM ubuntu:24.04
RUN apt-get update -o Acquire::Retries=3 \
    && apt-get install -y --no-install-recommends davfs2 curl ca-certificates busybox-syslogd \
    && rm -rf /var/lib/apt/lists/*
COPY parvault /usr/local/bin/parvault
RUN printf 'parvault:x:65532:65532:parvault:/var/lib/parvault:/usr/sbin/nologin\n' >> /etc/passwd \
    && printf 'parvault:x:65532:\n' >> /etc/group \
    && mkdir -p /var/lib/parvault && chown 65532:65532 /var/lib/parvault
USER parvault:parvault
WORKDIR /var/lib/parvault
EOF
docker build -q -t "$IMG" "$CTX" >/dev/null

docker network create --label "$LABEL" "$NET" >/dev/null

# The edge: bridge mode, published on host loopback only, confined.
docker run -d --name "$EDGE" --label "$LABEL" --network "$NET" \
    --cap-drop ALL --security-opt no-new-privileges --user 65532:65532 \
    -p 127.0.0.1::8443 -v "$SEED:/seed:ro" -e RUST_LOG=info -e NO_COLOR=1 \
    --entrypoint sh "$IMG" -c '
      set -e
      parvault --data-dir /var/lib/parvault/d --no-lan-discovery wot init
      exec parvault --data-dir /var/lib/parvault/d --no-lan-discovery up --no-socket \
        --listen /ip4/0.0.0.0/tcp/4001 --vfs-webdav-listen 0.0.0.0:8443 --vfs-seed-dir /seed \
        --tls-san pv-edge.test' >/dev/null
EDGE_LOGS=1
for _ in $(seq 1 600); do
    LOG="$(docker logs "$EDGE" 2>&1 || true)"
    if grep -q "Ingested built-in VFS seed directory" <<<"$LOG" && grep -q "WebDAV listening on https://" <<<"$LOG"; then
        break
    fi
    docker inspect -f '{{.State.Running}}' "$EDGE" 2>/dev/null | grep -q true || fail "the edge exited"
    sleep 0.2
done
grep -q "WebDAV listening on https://" <<<"$LOG" || fail "no TLS WebDAV listener"
# Non-root: every process of the edge runs as 65532.
docker top "$EDGE" -eo pid,ruid,euid,comm | awk 'NR > 1 && ($2 == 0 || $3 == 0) { exit 1 }' || fail "the edge runs as root"

pv() { docker exec "$EDGE" parvault --data-dir /var/lib/parvault/d --no-lan-discovery "$@"; }
pv tls export --out /var/lib/parvault/d/webdav.crt >/dev/null
docker exec "$EDGE" cat /var/lib/parvault/d/webdav.crt > "$TMP/webdav.crt"
PIN="$(pv tls show | sed -n 's/^pin (curl): *//p')"
[ -n "$PIN" ] || fail "no pin from tls show"
pv token mint --ttl-secs 3600 --out /var/lib/parvault/d/webdav.token >/dev/null
TOKEN="$(docker exec "$EDGE" cat /var/lib/parvault/d/webdav.token)"
[ "${#TOKEN}" -lt 255 ] || fail "token is ${#TOKEN} characters (L-123 Q4: under 255)"
PORTS="$(docker port "$EDGE" 8443/tcp)"
HP="$(sed -n 's/^127\.0\.0\.1:\([0-9]*\)$/\1/p' <<<"$PORTS")"
HP="${HP%%$'\n'*}"
[ -n "$HP" ] || fail "no published port"
EDGE_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$EDGE")"

# --- Published-port leg (step 9) ---------------------------------------------------------------
c() { curl -sS --max-time 300 --cacert "$TMP/webdav.crt" --pinnedpubkey "$PIN" -u "token:$TOKEN" "$@"; }
for base in "https://pv-edge.test:$HP" "https://127.0.0.1:$HP"; do
    R=(--resolve "pv-edge.test:$HP:127.0.0.1")
    LIST="$(c "${R[@]}" -X PROPFIND -H 'Depth: 1' -w '\n%{http_code}' "$base/")" || fail "PROPFIND $base"
    [ "$(tail -1 <<<"$LIST")" = "207" ] || fail "PROPFIND $base: $(tail -1 <<<"$LIST")"
    for f in notes.txt readme.txt photo.bin video.bin; do
        grep -q "<D:href>/$f</D:href>" <<<"$LIST" || fail "$f not listed at $base"
        c "${R[@]}" -o "$TMP/got-$f" "$base/$f" || fail "GET $f at $base"
        cmp -s "$TMP/got-$f" "$SEED/$f" || fail "$f differs at $base"
    done
    CODE="$(c "${R[@]}" -r 1000000-1000999 -o "$TMP/range" -w '%{http_code}' "$base/photo.bin")"
    [ "$CODE" = "206" ] || fail "Range read at $base: $CODE"
    cmp -s "$TMP/range" <(tail -c +1000001 "$SEED/photo.bin" | head -c 1000) || fail "Range bytes at $base"
    CODE="$(c "${R[@]}" -X PUT --data-binary x -o /dev/null -w '%{http_code}' "$base/new.txt")"
    [ "$CODE" = "405" ] || fail "PUT at $base: $CODE"
done
# A name outside the SANs is refused (A-TLS-7): curl fails the name check.
if c --resolve "other.test:$HP:127.0.0.1" -o /dev/null "https://other.test:$HP/" 2>/dev/null; then
    fail "a name outside the certificate was accepted"
fi
echo "published-port leg: PASS (by --tls-san name and by IP; 4 files cmp; 206; PUT 405)"

# --- davfs2 leg (step 5) -----------------------------------------------------------------------
DAVFS_RESULT="SKIPPED (no /dev/fuse)"
if [ -c /dev/fuse ]; then
    cp "$TMP/webdav.crt" "$TMP/pv.pem"
    printf 'https://%s:8443/ token %s\n' "$EDGE_IP" "$TOKEN" > "$TMP/secrets"
    chmod 0644 "$TMP/pv.pem"
    docker create --name "$DAVFS_WAIVED" --label "$LABEL" --network "$NET" --user 0:0 \
        --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
        -v "$SEED:/seed:ro" -v "$TMP/pv.pem:/etc/davfs2/certs/pv.pem:ro" -v "$TMP/secrets:/run/secrets.in:ro" -e DAVFS_DEBUG="${DAVFS_DEBUG:-}" \
        --entrypoint sh "$IMG" -c '
          set -e
          syslogd -n -O /tmp/sys.log & sleep 0.3
          install -m 0600 /run/secrets.in /etc/davfs2/secrets
          if [ -n "${DAVFS_DEBUG:-}" ]; then echo "debug most" >> /etc/davfs2/davfs2.conf; fi
          echo "trust_ca_cert pv.pem" >> /etc/davfs2/davfs2.conf
          echo "use_locks 0" >> /etc/davfs2/davfs2.conf
          mkdir -p /mnt/vault
          mount -t davfs "'"https://$EDGE_IP:8443/"'" /mnt/vault -o ro
          ls -la /mnt/vault || { sleep 1; tail -80 /tmp/sys.log; exit 4; }
          for f in notes.txt readme.txt photo.bin video.bin; do cmp /mnt/vault/$f /seed/$f; done
          if touch /mnt/vault/new.txt 2>/dev/null; then echo "write allowed"; exit 3; fi
          umount /mnt/vault
          echo DAVFS2_OK' >/dev/null
    RC="$(docker start -a "$DAVFS_WAIVED" > "$TMP/davfs.log" 2>&1; echo $?)"
    cat "$TMP/davfs.log"
    [ "$RC" = "0" ] && grep -q DAVFS2_OK "$TMP/davfs.log" || fail "the davfs2 leg failed (rc $RC)"
    DAVFS_RESULT="PASS"
elif [ "${GATES_REQUIRE_REAL:-0}" = "1" ]; then
    fail "/dev/fuse is missing (GATES_REQUIRE_REAL=1)"
else
    echo "SKIPPED: stage 14 davfs2 leg: no /dev/fuse"
fi

# Log hygiene (step 10): the token is not in the edge's log, raw or in Basic form.
B64="$(printf 'token:%s' "$TOKEN" | base64 -w0)"
LOG="$(docker logs "$EDGE" 2>&1)"
if grep -qF "$TOKEN" <<<"$LOG" || grep -qF "$B64" <<<"$LOG"; then fail "the token is in the edge log"; fi
echo "Stage 14-webdav-tls: published port PASS; davfs2 ${DAVFS_RESULT}; token absent from the log"
