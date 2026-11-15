#!/usr/bin/env bash
# Tests the shipped compose projects (B-146) on a real Docker host, with the real dev image:
#   deploy/synology/compose.yaml       start a ring: first start healthy, a rebuild keeps the ring,
#                                      `init` exits 1 on later starts; an invite service with
#                                      `depends_on: service_healthy` works on a fresh volume and on
#                                      later starts, and one without it fails (the race it avoids)
#   deploy/synology/join.compose.yaml  join: identity -> invite on the holder -> token -> healthy;
#                                      the joiner stores a file and restores it byte-identical
#   deploy/docker/compose.yaml         join from a Docker host on a non-default --listen port,
#                                      healthy through the image's own HEALTHCHECK
#   docs/SYNOLOGY.md export + import  the documented backup projects: stop a ring's daemon, export its
#                                      volume to one tar, import it over a throwaway ring's volume (the main
#                                      project started once, with a planted file) and over A's own volume
#                                      with an extra file: A's genesis and node key, extras gone
# Each run uses its own project and volume names (pvct-<pid>-<n>) and loopback ports, adds
# --no-lan-discovery so it never meets a real ring, and removes everything with `down -v`.
# Usage: scripts/test_compose_projects.sh [image tag]   (default parvault:<Cargo.toml version>-dev,
#        already loaded). PORT_BASE (default 4101) picks the mesh ports PORT_BASE..PORT_BASE+5.
set -euo pipefail
cd "$(dirname "$0")/.."
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
TAG=${1:-parvault:$version-dev}
PB=${PORT_BASE:-4101}
ID="pvct-$$"
WORK=$(mktemp -d)
cleanup() {
  # the export tar is root-owned 0600: remove it from inside a container
  [[ -d "$WORK/bak" ]] && docker run --rm -v "$WORK/bak:/b" --entrypoint rm "$BB" -rf /b/parvault-data.tar >/dev/null 2>&1 || true
  for f in "$WORK"/p*.yaml; do
    [[ -e "$f" ]] && { docker compose -f "$f" down -v --remove-orphans >/dev/null 2>&1 || true; }
  done
  docker volume rm "$ID-6-data" "$ID-7-data" >/dev/null 2>&1 || true   # the backup test's volumes
  rm -rf "$WORK"
}
BB=$(sed -n 's#^ *image: \(busybox@sha256:[0-9a-f]*\).*#\1#p' docs/SYNOLOGY.md | head -1)
[[ -n "$BB" ]] || { echo "test_compose_projects: FAIL: no pinned busybox in docs/SYNOLOGY.md" >&2; exit 1; }
trap cleanup EXIT
fail() { echo "test_compose_projects: FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
docker image inspect "$TAG" >/dev/null 2>&1 || fail "image $TAG is not loaded (docker load -i parvault-image-<arch>-dev.tar)"

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
# enable_invite <file> <key> [keep_depends_on]: uncomment the example invite service.
enable_invite() {
  python3 -I - "$1" "$2" "${3:-yes}" <<'EOF'
import re, sys
path, key, keep = sys.argv[1:]
s = open(path).read()
s = re.sub(r'^  # (invite-node2:)', r'  \1', s, flags=re.M)
s = re.sub(r'^  #   ', '    ', s, flags=re.M).replace('NODE_KEY_64_HEX', key)
if keep != 'yes':
    s = re.sub(r'(  invite-node2:\n    <<: \*oneshot\n)    depends_on:\n      parvault:\n        condition: service_healthy\n', r'\1', s)
open(path, 'w').write(s)
EOF
}
up() { docker compose -f "$1" up -d >"$WORK/up.log" 2>&1; }
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
genesis_of() { logs "$1" init | sed -n 's/^Started a new ring. Genesis public key: //p'; }
key_of() { logs "$1" identity | sed -n 's/^Ed25519 Public Key (hex): //p'; }
client() { # <n> <args...>: a one-off client on node n's volume, host network
  local n=$1; shift
  docker run --rm --user 65532:65532 --network host --read-only --tmpfs /tmp --cap-drop ALL \
    --security-opt no-new-privileges:true -v "$ID-$n-data:/var/lib/parvault" -v "$WORK/io:/io" \
    "$TAG" --data-dir /var/lib/parvault "$@" --no-lan-discovery 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
}

# 1. Start a ring.
R=$(variant deploy/synology/compose.yaml 1 "$PB")
up "$R" || fail "ring first start: $(tail -3 "$WORK/up.log")"
wait_healthy "$R"
G=$(genesis_of "$R"); [[ ${#G} == 64 ]] || fail "init printed no genesis key: $(logs "$R" init)"
[[ "$(state "$R" init)" == "exited 0" ]] || fail "init on first start: $(state "$R" init)"
ok "ring first start healthy, genesis $G"
docker compose -f "$R" down >/dev/null 2>&1; up "$R" || fail "ring rebuild: $(tail -3 "$WORK/up.log")"
wait_healthy "$R"
[[ "$(state "$R" init)" == "exited 1" ]] || fail "init on a later start: $(state "$R" init)"
logs "$R" init | grep -q "this node is already in the ring $G" || fail "init re-run said: $(logs "$R" init)"
ok "rebuild keeps the ring; init exits 1: $(logs "$R" init)"

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

mkdir -m 0777 "$WORK/io"; head -c 65536 /dev/urandom > "$WORK/io/sample.bin"; chmod 0644 "$WORK/io/sample.bin"
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

# 3. The fresh-volume race: an invite beside init on the very first start.
N=$(variant deploy/synology/compose.yaml 3 $((PB + 2))); enable_invite "$N" "$K" no
# Without depends_on the invite races init; it loses on some starts (timing-dependent, so this
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
[[ "$(state "$S" init) $(state "$S" invite-node2)" == "exited 1 exited 0" ]] \
  || fail "later start: init '$(state "$S" init)', invite '$(state "$S" invite-node2)'"
ok "invite with depends_on service_healthy: token on the first start and on a later start (init exit 1 does not block it)"

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

# 5. The documented backup: export one tar, import it into a NEW volume, same ring.
doc_project() { # <project name> <out file> <volume> <backup dir>: the yaml block of that project in docs/SYNOLOGY.md
  python3 -I - "$1" docs/SYNOLOGY.md "$3" "$4" > "$2" <<'EOF2'
import re, sys
name, doc, vol, bak = sys.argv[1:]
m = re.search(r'```yaml\n(name: %s\n.*?)```' % re.escape(name), open(doc).read(), re.S)
if not m: sys.exit("no yaml block for " + name)
print(m.group(1).replace("name: parvault-data", "name: " + vol).replace("/volume1/parvault-backup", bak), end="")
EOF2
}
docker image inspect "$BB" >/dev/null 2>&1 || fail "pinned busybox $BB is not pulled (docker pull busybox:1.37.0)"
mkdir "$WORK/bak"
B=$(variant deploy/synology/compose.yaml 6 $((PB + 5)))
up "$B" || fail "backup ring first start: $(tail -3 "$WORK/up.log")"
wait_healthy "$B"
GB=$(genesis_of "$B"); [[ ${#GB} == 64 ]] || fail "backup ring printed no genesis key"
docker compose -f "$B" stop parvault >/dev/null 2>&1   # the doc says: Stop the project first
doc_project parvault-export "$WORK/pexp.yaml" "$ID-6-data" "$WORK/bak"
up "$WORK/pexp.yaml" || fail "export project: $(tail -3 "$WORK/up.log")"
logs "$WORK/pexp.yaml" export | grep -qx exported || fail "export said: $(logs "$WORK/pexp.yaml" export)"
[[ "$(state "$WORK/pexp.yaml" export)" == "exited 0" ]] || fail "export state: $(state "$WORK/pexp.yaml" export)"
[[ "$(docker run --rm -v "$WORK/bak:/b:ro" --entrypoint stat "$BB" -c '%U %a' /b/parvault-data.tar)" == "root 600" ]] \
  || fail "tar is not root 0600"
docker run --rm -v "$WORK/bak:/b:ro" --entrypoint tar "$BB" -tvf /b/parvault-data.tar | grep -q '65532' \
  || fail "tar does not keep the 65532 owner"
ok "export: one tar, root 0600, files owned by 65532 inside"
# The documented restore: build and start the main project once on a NEW volume (init makes a
# throwaway ring B), let its daemon write, plant a file, then stop, import, start.
sh_vol() { docker run --rm -v "$1:/data" --entrypoint sh "$BB" -c "$2"; }   # one-shot busybox on a volume
KA=$(client 6 identity | sed -n 's/^Ed25519 Public Key (hex): //p'); [[ ${#KA} == 64 ]] || fail "no node key of ring A"
M=$(variant deploy/synology/compose.yaml 7 $((PB + 5)))
up "$M" || fail "main project on the new volume: $(tail -3 "$WORK/up.log")"
wait_healthy "$M"
GT=$(genesis_of "$M"); [[ ${#GT} == 64 && "$GT" != "$GB" ]] || fail "throwaway ring B genesis '$GT' (ring A $GB)"
KT=$(client 7 identity | sed -n 's/^Ed25519 Public Key (hex): //p'); [[ ${#KT} == 64 && "$KT" != "$KA" ]] || fail "throwaway node key '$KT'"
[[ "$(client 7 wot invite --peer "$K" | tr -d ' \n')" == "$GT"* ]] || fail "daemon of ring B could not write an invite"
sh_vol "$ID-7-data" 'echo planted > /data/planted-file' || fail "could not plant a file"
docker compose -f "$M" stop parvault >/dev/null 2>&1
doc_project parvault-import "$WORK/pimp.yaml" "$ID-7-data" "$WORK/bak"
up "$WORK/pimp.yaml" || fail "import project: $(tail -3 "$WORK/up.log")"
logs "$WORK/pimp.yaml" import | grep -qx imported || fail "import said: $(logs "$WORK/pimp.yaml" import)"
docker compose -f "$B" down >/dev/null 2>&1     # frees the port; its volume stays for the case below
up "$M" || fail "daemon on the restored volume: $(tail -3 "$WORK/up.log")"
wait_healthy "$M"
# the init container is restarted, so its log still holds the first run: read the last line only
LAST=$(logs "$M" init | tail -1)
[[ "$LAST" == *"this node is already in the ring $GB" ]] || fail "restored volume is not ring $GB: $LAST"
[[ "$LAST" != *"$GT"* ]] || fail "throwaway genesis $GT survived the import"
[[ "$(client 7 identity | sed -n 's/^Ed25519 Public Key (hex): //p')" == "$KA" ]] || fail "node key is not ring A's"
INV=$(client 7 wot invite --peer "$K" | tr -d ' \n')
[[ "$INV" == "$GB"* ]] || fail "wot invite on the restored volume gave: ${INV:0:80}"
sh_vol "$ID-7-data" 'test ! -e /data/planted-file' || fail "planted file survived the import"
ok "import over a throwaway ring: healthy, genesis $GB, node key $KA, invite is A's; ring B $GT and the planted file are gone"
docker compose -f "$M" down >/dev/null 2>&1
# Over an existing volume of ring A that has a newer extra file.
sh_vol "$ID-6-data" 'echo newer > /data/newer-extra'
doc_project parvault-import "$WORK/pimp6.yaml" "$ID-6-data" "$WORK/bak"
up "$WORK/pimp6.yaml" || fail "import over ring A's volume: $(tail -3 "$WORK/up.log")"
logs "$WORK/pimp6.yaml" import | grep -qx imported || fail "import over A said: $(logs "$WORK/pimp6.yaml" import)"
sh_vol "$ID-6-data" 'test ! -e /data/newer-extra' || fail "extra file survived the import over ring A's volume"
up "$B" || fail "ring A after import over it: $(tail -3 "$WORK/up.log")"
wait_healthy "$B"
[[ "$(logs "$B" init | tail -1)" == *"this node is already in the ring $GB" ]] || fail "ring A changed: $(logs "$B" init | tail -1)"
ok "import over ring A's own volume: the newer extra file is gone, ring A healthy"
echo "test_compose_projects: PASS ($TAG)"
