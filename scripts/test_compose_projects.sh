#!/usr/bin/env bash
# Tests the shipped compose projects (B-146, B-169) on a real Docker host, with the real dev image:
#   deploy/synology/compose.yaml       start a ring with ONE service (`up --init-if-absent`): first
#                                      start healthy, no exited init container, a rebuild keeps the
#                                      ring; an invite service with `depends_on: service_healthy`
#                                      works on a fresh volume and on later starts
#   deploy/synology/join.compose.yaml  join: identity -> invite on the holder -> token -> healthy;
#                                      the joiner stores a file and restores it byte-identical
#   deploy/docker/compose.yaml         join from a Docker host on a non-default --listen port,
#                                      healthy through the image's own HEALTHCHECK
#   docs/SYNOLOGY.md ring backup       the documented encrypted backup (K10): passphrase project,
#                                      `ring backup` with the daemon stopped, then the restore in
#                                      the documented order (the main project's `ring-restore`
#                                      service before the daemon's first start): same ring and
#                                      node key; the same restore after a first start is refused
# Each run uses its own project and volume names (<prefix>-<pid>-<n>) and loopback ports, adds
# --no-lan-discovery so it never meets a real ring, and removes everything with `down -v`.
# Usage: scripts/test_compose_projects.sh [image tag]   (default parvault:<Cargo.toml version>-dev,
#        already loaded). Safe to run twice at once: each run takes a free 10-port slot (mesh 4101+10k
#        .. +5, status +1000; k<10, held by flock) and tests its own tag of the image, so a
#        concurrent `docker load` that retags <image tag> cannot change what it tests.
#        PORT_BASE picks the ports by hand and skips the slot search.
set -euo pipefail
cd "$(dirname "$0")/.."
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
SRC_TAG=${1:-parvault:$version-dev}
# Every name this run makes starts with $COMPOSE_TEST_PREFIX- (default pvct; lowercase: compose
# project and image names must be).
PREFIX=${COMPOSE_TEST_PREFIX:-pvct}
[[ "$PREFIX" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo "test_compose_projects: COMPOSE_TEST_PREFIX must be lowercase" >&2; exit 2; }
ID="$PREFIX-$$"
# shellcheck source=scripts/lib_test_slots.sh
source "$(dirname "$0")/lib_test_slots.sh"
if [[ -n "${PORT_BASE:-}" ]]; then PB=$PORT_BASE; else pick_port_base compose 4101 10 10 || exit 1; fi
TAG="$PREFIX-img:$ID"   # this run's own tag of the image, removed at the end
WORK=$(mktemp -d)
mkdir -m 0777 "$WORK/io"   # before any client(): docker would make it root-owned
cleanup() {
  # the bundle is owned by 65532: remove it from inside a container
  if [[ -d "$WORK/rbak" ]]; then
    docker run --rm -v "$WORK/rbak:/b" --entrypoint sh "$BB" -c 'rm -f /b/*' >/dev/null 2>&1 || true
  fi
  for f in "$WORK"/p*.yaml; do
    [[ -e "$f" ]] && { docker compose -f "$f" down -v --remove-orphans >/dev/null 2>&1 || true; }
  done
  docker volume rm "$ID-6-data" "$ID-sec" >/dev/null 2>&1 || true   # the backup test's external volumes
  docker rmi "$TAG" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
BB=$(sed -n 's#^ *image: \(busybox@sha256:[0-9a-f]*\).*#\1#p' docs/SYNOLOGY.md | head -1)
[[ -n "$BB" ]] || { echo "test_compose_projects: FAIL: no pinned busybox in docs/SYNOLOGY.md" >&2; exit 1; }
trap cleanup EXIT
fail() { echo "test_compose_projects: FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
docker image inspect "$SRC_TAG" >/dev/null 2>&1 || fail "image $SRC_TAG is not loaded (docker load -i parvault-image-<arch>-dev.tar)"
with_image_lock docker tag "$SRC_TAG" "$TAG" || fail "could not tag $SRC_TAG"

# variant <src> <n> <port> [peers]: unique project/volume, no container_name, loopback ports,
# no LAN discovery, the test's tag. Everything else is the shipped file.
variant() {
  local out="$WORK/p$2.yaml" peers=""
  [[ -n "${4:-}" ]] && peers=", \"--peers\", \"$4\""
  sed -e "s/^name: parvault$/name: $ID-$2/" -e "s/^\(    name: \)parvault-data\b/\1$ID-$2-data/" \
      -e '/container_name: parvault/d' -e "s#image: parvault:[^ ]*#image: $TAG#" \
      -e "s#\"--status-http\", \"127.0.0.1:4080\"\]#\"--status-http\", \"127.0.0.1:$(($3 + 1000))\", \"--listen\", \"/ip4/0.0.0.0/tcp/$3\", \"--no-lan-discovery\"$peers]#" \
      -e "s#\"/ip4/0.0.0.0/tcp/4011\",#\"/ip4/0.0.0.0/tcp/$3\",#" -e "s#\"--peers\", \"192.168.1.10:4001\",#\"--peers\", \"${4:-}\",#" \
      "$1" > "$out"
  grep -q "$ID-$2-data" "$out" || fail "variant of $1 did not rename its volume"
  echo "$out"
}
# enable_invite <file> <key> [keep_depends_on]: uncomment the example invite service only.
enable_invite() {
  python3 -I - "$1" "$2" "${3:-yes}" <<'EOF'
import re, sys
path, key, keep = sys.argv[1:]
s = open(path).read()
def on(m):
    return re.sub(r'^  # ?', '  ', m.group(0), flags=re.M).replace('NODE_KEY_64_HEX', key)
s = re.sub(r'^  # invite-node2:\n(?:  #   .*\n)+', on, s, flags=re.M)
if keep != 'yes':
    s = re.sub(r'(  invite-node2:\n    <<: \*oneshot\n)    depends_on:\n      parvault:\n        condition: service_healthy\n', r'\1', s)
open(path, 'w').write(s)
EOF
}
# enable_restore <file> <bundle name> <ring id> <secrets volume> <backup dir>: uncomment the
# documented ring-restore service, the daemon's depends_on and the secrets volume (K10).
enable_restore() {
  python3 -I - "$@" <<'EOF'
import re, sys
path, bundle, ring, sec, bak = sys.argv[1:]
s = open(path).read()
s = re.sub(r'^    # (depends_on:\n)    #   (ring-restore:\n)    #     (condition: service_completed_successfully\n)',
           r'    \1      \2        \3', s, flags=re.M)
def on(m):
    return re.sub(r'^  # ?', '  ', m.group(0), flags=re.M)
s = re.sub(r'^  # ring-restore:\n(?:  #   .*\n)+', on, s, flags=re.M)
s = re.sub(r'^  # parvault-secrets: .*\n  #   external: true\n  #   name: parvault-secrets\n',
           '  parvault-secrets:\n    external: true\n    name: %s\n' % sec, s, flags=re.M)
s = s.replace('BUNDLE_FILE_NAME', bundle).replace('RING_ID_64_HEX', ring).replace('/volume1/parvault-backup', bak)
if re.search(r'^(    # depends_on:|  # ring-restore:|  # parvault-secrets:)', s, re.M) or 'condition: service_completed_successfully' not in s:
    sys.exit('enable_restore: the compose file no longer has the documented commented blocks')
open(path, 'w').write(s)
EOF
}
up() { docker compose -f "$1" up -d >"$WORK/up.log" 2>&1; }
# run_once <file> <service>: a one-shot project in the foreground; returns the service's exit code.
run_once() { docker compose -f "$1" up --abort-on-container-exit --exit-code-from "$2" >"$WORK/up.log" 2>&1; }
logs() { docker compose -f "$1" logs --no-log-prefix "$2" 2>&1 | tr -d '\r'; }
state() { docker compose -f "$1" ps -a --format '{{.Service}} {{.State}} {{.ExitCode}}' | awk -v s="$2" '$1==s {print $2" "$3}'; }
wait_healthy() {
  local c; c=$(docker compose -f "$1" ps -q parvault)
  for _ in $(seq 1 40); do
    [[ "$(docker inspect -f '{{.State.Health.Status}}' "$c")" == healthy ]] && return 0
    sleep 3
  done
  fail "$1 daemon not healthy after 120 s: $(docker logs "$c" 2>&1 | tail -5)"
}
genesis_of() { logs "$1" parvault | sed -n 's/^Started a new ring. Genesis public key: //p' | tail -1; }
ring_of() { client "$1" wot invite --peer "$(printf '11%.0s' $(seq 32))" | tr -d ' \n' | cut -c1-64; }
key_of() { logs "$1" identity | sed -n 's/^Ed25519 Public Key (hex): //p'; }
client() { # <n> <args...>: a one-off client on node n's volume, host network
  local n=$1; shift
  docker run --rm --user 65532:65532 --network host --read-only --tmpfs /tmp --cap-drop ALL \
    --security-opt no-new-privileges:true -v "$ID-$n-data:/var/lib/parvault" -v "$WORK/io:/io" \
    "$TAG" --data-dir /var/lib/parvault "$@" --no-lan-discovery 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
}

# 1. Start a ring: one service.
R=$(variant deploy/synology/compose.yaml 1 "$PB")
up "$R" || fail "ring first start: $(tail -3 "$WORK/up.log")"
wait_healthy "$R"
G=$(genesis_of "$R"); [[ ${#G} == 64 ]] || fail "the daemon printed no genesis key: $(logs "$R" parvault | tail -5)"
[[ "$(docker compose -f "$R" ps -a --format '{{.Service}}' | sort | tr '\n' ' ')" == "parvault " ]] \
  || fail "the ring project has other containers: $(docker compose -f "$R" ps -a --format '{{.Service}} {{.State}}')"
ok "ring first start healthy, genesis $G, one container (no exited init)"
docker compose -f "$R" down >/dev/null 2>&1; up "$R" || fail "ring rebuild: $(tail -3 "$WORK/up.log")"
wait_healthy "$R"
[[ -z "$(genesis_of "$R")" ]] || fail "a rebuild started a new ring: $(genesis_of "$R")"
[[ "$(ring_of 1)" == "$G" ]] || fail "after a rebuild the ring is $(ring_of 1), not $G"
ok "rebuild keeps ring $G; no second genesis"

# 2. Join with the Synology join project.
J=$(variant deploy/synology/join.compose.yaml 2 $((PB + 1)) "127.0.0.1:$PB")
if up "$J"; then fail "join without a token should fail its install-chain step"; fi
[[ "$(state "$J" install-chain)" == "exited 1" && "$(state "$J" parvault)" == "created 0" ]] \
  || fail "join without token: install-chain '$(state "$J" install-chain)', daemon '$(state "$J" parvault)'"
K=$(key_of "$J"); [[ ${#K} == 64 ]] || fail "identity printed no key"
ok "join without token: install-chain exit 1, daemon waits in Created; key $K"
enable_invite "$R" "$K"
up "$R" || fail "invite rebuild: $(tail -3 "$WORK/up.log")"
TOKEN=$(logs "$R" invite-node2 | tr -d ' \n')
[[ "$TOKEN" == "$G"* ]] || fail "invite log is not a token for ring $G: ${TOKEN:0:80}"
sed -i "s/PASTE_TOKEN_HERE/$TOKEN/" "$J"
up "$J" || fail "join with token: $(tail -3 "$WORK/up.log")"
wait_healthy "$J"
logs "$J" install-chain | grep -q "^Joined the ring $G. Installed chain for $K (this node's key)" \
  || fail "install-chain said: $(logs "$J" install-chain)"
docker compose -f "$J" down >/dev/null 2>&1; up "$J" || fail "join rebuild: $(tail -3 "$WORK/up.log")"
wait_healthy "$J"
ok "joined ring $G; a rebuild re-installs the token (exit 0) and stays healthy"

head -c 65536 /dev/urandom > "$WORK/io/sample.bin"; chmod 0644 "$WORK/io/sample.bin"
PEERS="127.0.0.1:$PB,127.0.0.1:$((PB + 1))"
root=$(client 2 file store --path /io/sample.bin --peers "$PEERS" | sed -n 's/^File Merkle Root : //p')
[[ ${#root} == 64 ]] || fail "file store from the joiner printed no root"
client 2 file restore --manifest-or-root "$root" --output /io/restored.bin --peers "$PEERS" | grep -q 'Restore Verified' \
  || fail "restore did not verify"
cmp -s "$WORK/io/sample.bin" "$WORK/io/restored.bin" || fail "restored file differs"
for p in "$R" "$J"; do
  docker logs "$(docker compose -f "$p" ps -q parvault)" 2>&1 | grep -q 'Kademlia routing table updated' \
    || fail "$p daemon never logged a Kademlia routing table update"
done
ok "joiner stored 64 KiB (root $root) and restored it byte-identical; both daemons logged a Kademlia update"

# 3. The fresh-volume race: an invite beside the daemon's init on the very first start.
N=$(variant deploy/synology/compose.yaml 3 $((PB + 2))); enable_invite "$N" "$K" no
# Without depends_on the invite races the daemon's first-start init; it loses on some starts (timing-dependent, so this
# control is reported, not asserted).
up "$N" || true
if [[ "$(state "$N" invite-node2)" == "exited 1" ]] && logs "$N" invite-node2 | grep -q "does not hold a ring genesis"; then
  ok "control: invite without depends_on lost the race this run: does not hold a ring genesis"
else
  ok "control: invite without depends_on won the race this run ($(state "$N" invite-node2)); not asserted"
fi
S=$(variant deploy/synology/compose.yaml 4 $((PB + 3))); enable_invite "$S" "$K"
up "$S" || fail "fresh volume with invite: $(tail -3 "$WORK/up.log")"
[[ "$(state "$S" invite-node2)" == "exited 0" ]] || fail "invite with depends_on: $(state "$S" invite-node2)"
docker compose -f "$S" down >/dev/null 2>&1; up "$S" || fail "later start with invite: $(tail -3 "$WORK/up.log")"
[[ "$(state "$S" invite-node2)" == "exited 0" ]] || fail "later start: invite '$(state "$S" invite-node2)'"
ok "invite with depends_on service_healthy: token on the first start and on a later start"

# 4. A generic Docker host joins on a non-default --listen port.
D=$(variant deploy/docker/compose.yaml 5 $((PB + 4)) "127.0.0.1:$PB")
grep -q 'healthcheck:' <(sed -n '/^  parvault:/,$p' "$D") && fail "deploy/docker/compose.yaml overrides the image HEALTHCHECK"
if up "$D"; then fail "docker join without a token should fail its install-chain step"; fi
K5=$(key_of "$D"); sed -i "s/invite-node2/invite-node5/" "$R"; sed -i "s/$K/$K5/" "$R"
up "$R" || fail "second invite: $(tail -3 "$WORK/up.log")"
sed -i "s/PASTE_TOKEN_HERE/$(logs "$R" invite-node5 | tr -d ' \n')/" "$D"
up "$D" || fail "docker join with token: $(tail -3 "$WORK/up.log")"
wait_healthy "$D"
docker logs "$(docker compose -f "$D" ps -q parvault)" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -q "listen_tcp=/ip4/0.0.0.0/tcp/$((PB + 4))" \
  || fail "docker node is not on --listen port $((PB + 4))"
ok "docker-host node joined on tcp/$((PB + 4)), healthy through the image HEALTHCHECK"

# 5. The documented encrypted ring backup and restore (B-169, K10).
doc_project() { # <project name> <out file> <from=to>...: the yaml block of that project in docs/SYNOLOGY.md
  python3 -I - "$@" <<'EOF2'
import re, sys
name, out, *subs = sys.argv[1:]
m = re.search(r'```yaml\n(name: %s\n.*?)```' % re.escape(name), open("docs/SYNOLOGY.md").read(), re.S)
if not m: sys.exit("no yaml block for " + name)
y = m.group(1)
for kv in subs:
    k, v = kv.split("=", 1)
    if k not in y: sys.exit("%s: no %s in the doc block" % (name, k))
    y = y.replace(k, v)
open(out, "w").write(y)
EOF2
}
docker image inspect "$BB" >/dev/null 2>&1 || fail "pinned busybox $BB is not pulled (docker pull busybox:1.37.0)"
B=$(variant deploy/synology/compose.yaml 6 $((PB + 5)))
up "$B" || fail "backup ring first start: $(tail -3 "$WORK/up.log")"
wait_healthy "$B"
GB=$(genesis_of "$B"); [[ ${#GB} == 64 ]] || fail "backup ring printed no genesis key"
KA=$(client 6 identity | sed -n 's/^Ed25519 Public Key (hex): //p'); [[ ${#KA} == 64 ]] || fail "no node key of ring A"
mkdir -m 0700 "$WORK/secin"; printf '%s\n' "a passphrase of more than twenty characters" > "$WORK/secin/passphrase.txt"
doc_project parvault-passphrase "$WORK/ppass.yaml" "name: parvault-passphrase=name: $ID-pass" \
  "name: parvault-secrets=name: $ID-sec" "/volume1/parvault-secrets-in=$WORK/secin"
run_once "$WORK/ppass.yaml" passphrase || fail "passphrase project: $(tail -3 "$WORK/up.log")"
logs "$WORK/ppass.yaml" passphrase | grep -qx installed || fail "passphrase said: $(logs "$WORK/ppass.yaml" passphrase)"
[[ "$(docker run --rm -v "$ID-sec:/s:ro" --entrypoint stat "$BB" -c '%u %a' /s/passphrase)" == "65532 600" ]] \
  || fail "the installed passphrase is not 65532 0600"
ok "passphrase project: installed 65532 0600 in its own volume"
mkdir -m 0777 "$WORK/rbak"
doc_project parvault-ring-backup "$WORK/prbak.yaml" "name: parvault-ring-backup=name: $ID-rbak" \
  "name: parvault-data=name: $ID-6-data" "name: parvault-secrets=name: $ID-sec" \
  "/volume1/parvault-backup=$WORK/rbak" "image: parvault:0.5.5-dev=image: $TAG"
if run_once "$WORK/prbak.yaml" ring-backup; then fail "ring backup ran beside the daemon"; fi
logs "$WORK/prbak.yaml" ring-backup | grep -q 'reject.datadir_locked' || fail "backup beside the daemon said: $(logs "$WORK/prbak.yaml" ring-backup)"
ok "ring backup with the daemon running: reject.datadir_locked"
docker compose -f "$B" stop parvault >/dev/null 2>&1   # the doc says: Stop the project first
docker compose -f "$WORK/prbak.yaml" down >/dev/null 2>&1
run_once "$WORK/prbak.yaml" ring-backup || fail "ring backup project: $(tail -3 "$WORK/up.log") $(logs "$WORK/prbak.yaml" ring-backup)"
BUNDLE=$(logs "$WORK/prbak.yaml" ring-backup | sed -n 's#^Wrote the encrypted ring backup to /backup/##p')
[[ -n "$BUNDLE" && -s "$WORK/rbak/$BUNDLE" ]] || fail "no bundle: $(logs "$WORK/prbak.yaml" ring-backup)"
logs "$WORK/prbak.yaml" ring-backup | grep -q "ring id: $GB" || fail "the bundle is not for ring $GB"
ok "ring backup: $BUNDLE for ring $GB"
# K10, the wrong order: a volume whose daemon already started once has a new ring; the restore refuses it.
W=$(variant deploy/synology/compose.yaml 7 $((PB + 6)))
up "$W" || fail "main project on a new volume: $(tail -3 "$WORK/up.log")"
wait_healthy "$W"
GW=$(genesis_of "$W"); [[ ${#GW} == 64 && "$GW" != "$GB" ]] || fail "throwaway ring '$GW'"
docker compose -f "$W" down >/dev/null 2>&1
enable_restore "$W" "$BUNDLE" "$GB" "$ID-sec" "$WORK/rbak"
if up "$W"; then fail "restore over a started volume should fail"; fi
[[ "$(state "$W" ring-restore)" == "exited 1" && "$(state "$W" parvault)" == "created 0" ]] \
  || fail "restore over a started volume: ring-restore '$(state "$W" ring-restore)', daemon '$(state "$W" parvault)'"
logs "$W" ring-restore | grep -q 'reject.backup_target_not_empty' || fail "restore over a started volume said: $(logs "$W" ring-restore)"
[[ "$(ring_of 7)" == "$GW" ]] || fail "the refused restore changed ring $GW"
ok "restore after a first start: reject.backup_target_not_empty, the daemon held back, ring $GW kept"
docker compose -f "$W" down -v >/dev/null 2>&1
# K10, the documented order: ring-restore before the daemon's first start, on a new volume.
M=$(variant deploy/synology/compose.yaml 8 $((PB + 7)))
enable_restore "$M" "$BUNDLE" "$GB" "$ID-sec" "$WORK/rbak"
up "$M" || fail "documented restore: $(tail -3 "$WORK/up.log") $(logs "$M" ring-restore)"
wait_healthy "$M"
[[ "$(state "$M" ring-restore)" == "exited 0" ]] || fail "ring-restore: $(state "$M" ring-restore)"
logs "$M" ring-restore | grep -q "^Restored node $KA of ring $GB" || fail "ring-restore said: $(logs "$M" ring-restore)"
[[ -z "$(genesis_of "$M")" ]] || fail "the daemon started a new ring after the restore"
[[ "$(ring_of 8)" == "$GB" ]] || fail "restored node is in ring $(ring_of 8), not $GB"
[[ "$(client 8 identity | sed -n 's/^Ed25519 Public Key (hex): //p')" == "$KA" ]] || fail "restored node key is not $KA"
docker compose -f "$M" down >/dev/null 2>&1
M2=$(variant deploy/synology/compose.yaml 8 $((PB + 7)))   # the blocks commented again, as the doc says
up "$M2" || fail "restored node, restore commented out: $(tail -3 "$WORK/up.log")"
wait_healthy "$M2"
[[ "$(ring_of 8)" == "$GB" ]] || fail "restored node lost ring $GB"
ok "documented restore: ring $GB, node $KA, healthy; healthy again with the restore commented out"
echo "test_compose_projects: PASS ($SRC_TAG = $(docker image inspect -f '{{.Id}}' "$TAG"))"
