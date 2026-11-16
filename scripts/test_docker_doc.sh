#!/usr/bin/env bash
# Runs the command blocks of docs/DOCKER.md verbatim on a real Docker host with the real dev image
# (B-146). Each block is the text after its `<!-- docker-doc: NAME -->` marker. Only the `vars`
# block is replaced: the test sets its own VOL, NAME, PORT, PEERS and CHECK (pvdd-<pid>-*,
# loopback ports), and the KEY= / TOKEN= placeholder lines are filled from earlier output. LAN
# discovery is off in every container (PARVAULT_NO_LAN_DISCOVERY=1, added by a `docker run`
# wrapper) so the test never meets a real ring. `firewall` is not run (it changes the host).
# Steps: verify -> load -> ring -> health -> identity -> invite -> join -> health -> roundtrip
#        -> upgrade (ring kept) -> remove. Everything is removed at the end.
# Usage: scripts/test_docker_doc.sh <dir with SHA256SUMS, SHA256SUMS.sig, parvault-image-amd64-dev.tar>
#        Safe to run twice at once: each run takes a free 10-port slot (4201+10k, k<10, held by
#        flock; two mesh ports used) and, after the doc's own `load` block (which retags the doc's
#        tag; the tag is put back and the load is serialised), runs every later block with IMG set
#        to this run's own tag of the loaded image. PORT_BASE picks the ports by hand.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
DOC="$REPO/docs/DOCKER.md"
DIST=$(cd "${1:?usage: test_docker_doc.sh <dist dir>}" && pwd)
ID="pvdd-$$"
# shellcheck source=scripts/lib_test_slots.sh
source "$(dirname "$0")/lib_test_slots.sh"
if [[ -n "${PORT_BASE:-}" ]]; then PB=$PORT_BASE; else pick_port_base doc 4201 10 10 || exit 1; fi
WORK=$(mktemp -d)
cleanup() {
  restore_shared_tag
  command docker rm -fv "$ID-a" "$ID-b" >/dev/null 2>&1 || true
  command docker volume rm "$ID-a" "$ID-b" >/dev/null 2>&1 || true
  command docker rmi "pvdd-img:$ID" >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
fail() { echo "test_docker_doc: FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

block() { # the commands of block NAME, verbatim
  awk -v m="<!-- docker-doc: $1 -->" '
    $0 == m {want=1; next}
    want && /^```/ { if (infence) exit; infence=1; next }
    want && infence {print}' "$DOC"
}
for b in vars verify load ring health identity invite join firewall roundtrip upgrade remove; do
  [[ -n "$(block "$b")" ]] || fail "docs/DOCKER.md has no '$b' block"
done
IMG=$(block vars | sed -n 's/^IMG=\([^ ]*\).*/\1/p')
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO/Cargo.toml" | head -1)"
[[ "$IMG" == "parvault:$version-dev" ]] || fail "vars block IMG is '$IMG', Cargo.toml says $version"

# run <node a|b> <block> [extra lines run first]: one block in a fresh bash with that node's vars.
run() {
  local node=$1 name=$2 pre=${3:-} port peers
  if [[ $node == a ]]; then port=$PB; peers="127.0.0.1:$((PB + 1))"; else port=$((PB + 1)); peers="127.0.0.1:$PB"; fi
  {
    echo 'set -euo pipefail'
    # shellcheck disable=SC2016  # written into the generated script verbatim, expanded there
    echo 'docker() { if [[ "$1" == run ]]; then shift; command docker run -e PARVAULT_NO_LAN_DISCOVERY=1 "$@"; else command docker "$@"; fi; }'
    echo "IMG=${RUN_IMG:-$IMG} VOL=$ID-$node NAME=$ID-$node PORT=$port PEERS=$peers CHECK=$WORK/check-$node BACKUP=$WORK/backup-$node"
    echo "$pre"
    block "$name" | grep -vE '^(KEY|TOKEN)=PASTE_'
  } > "$WORK/$node-$name.sh"
  (cd "$WORK/dist" && timeout 300 bash "$WORK/$node-$name.sh") > "$WORK/$node-$name.out" 2>&1 \
    || fail "block '$name' on node $node: $(sed 's/\x1b\[[0-9;]*m//g' "$WORK/$node-$name.out" | tail -5)"
  sed 's/\x1b\[[0-9;]*m//g' "$WORK/$node-$name.out"
}

# 1. verify and load (in a copy of the dist dir; dev-allowed-signers from this repo, not curl)
mkdir "$WORK/dist"
for f in SHA256SUMS SHA256SUMS.sig parvault-image-amd64-dev.tar; do ln -s "$DIST/$f" "$WORK/dist/$f"; done
cp "$REPO/security/dev-allowed-signers" "$WORK/dist/"
out=$(run a verify 'curl() { echo "(test: dev-allowed-signers from the repo)"; }')
grep -q 'Good "parvault-dev-build" signature for parvault-dev' <<<"$out" || fail "verify: $out"
grep -q 'parvault-image-amd64-dev.tar: OK' <<<"$out" || fail "verify sha256: $out"
ok "verify: $(grep -o 'Good "parvault-dev-build" signature[^$]*' <<<"$out" | head -1); $(head -n1 "$DIST/SHA256SUMS"); tar sha256 OK"
# The load block retags $IMG (the doc's tag); under one lock, give the loaded image this run's tag
# and put $IMG back on what it was, then run every later block on the run's tag.
load_and_adopt() {
  begin_load "$IMG"   # records the tag's current image, inside the lock
  out=$(run a load) || return 1
  grep -q "^Loaded image: $IMG" <<<"$out" || fail "load: $out"
  adopt_loaded_image "$IMG" "pvdd-img:$ID" || fail "could not tag the loaded image"
}
with_image_lock load_and_adopt
RUN_IMG="pvdd-img:$ID"
ok "load: $(tr '\n' ' ' <<<"$out")"

# 2. start a ring on node a
out=$(run a ring)
G=$(sed -n 's/^Started a new ring. Genesis public key: //p' <<<"$out"); [[ ${#G} == 64 ]] || fail "ring: $out"
run a health >/dev/null
ok "ring: genesis $G, daemon $ID-a healthy on tcp/$PB"
if (run a ring) >/dev/null 2>&1; then fail "a second wot init (and run) should fail"; fi
# The daemon holds the data dir (B-174): the re-run's `wot init` is refused by the lock.
grep -q "Error: reject.datadir_locked" "$WORK/a-ring.out" || fail "re-run of wot init: $(head -3 "$WORK/a-ring.out")"
ok "re-run of the ring block stops at wot init: $(grep -o 'Error: reject.datadir_locked' "$WORK/a-ring.out")"

# 3. join node b
K=$(run b identity | sed -n 's/^Ed25519 Public Key (hex): //p'); [[ ${#K} == 64 ]] || fail "identity printed no key"
TOKEN=$(run a invite "KEY=$K" | tr -d ' \n'); [[ "$TOKEN" == "$G"* ]] || fail "invite printed no token"
out=$(run b join "TOKEN=$TOKEN")
grep -q "^Joined the ring $G. Installed chain for $K (this node's key)" <<<"$out" || fail "join: $out"
run b health >/dev/null
ok "join: node b ($K) joined ring $G, healthy on tcp/$((PB + 1)) with --peers 127.0.0.1:$PB"
[[ "$(command docker inspect -f '{{.Config.Healthcheck.Test}}' "$ID-b")" == *"gateway --socket /run/parvault/parvault.sock health"* ]] \
  || fail "node b is not using the image's own HEALTHCHECK"

# 5. store and restore from node b
out=$(run b roundtrip)
if ! { grep -q 'Restore Verified' <<<"$out" && grep -qx 'byte-identical' <<<"$out"; }; then fail "roundtrip: $out"; fi
for n in a b; do
  command docker logs "$ID-$n" 2>&1 | grep -q 'Kademlia routing table updated' || fail "$ID-$n logged no Kademlia update"
done
ok "roundtrip: $(grep '^root ' <<<"$out"), restore verified, byte-identical; both daemons logged a Kademlia update"

# 6. upgrade (same image): the container is replaced, the ring is kept
run b upgrade >/dev/null; run b health >/dev/null
out=$(run b roundtrip)
grep -qx 'byte-identical' <<<"$out" || fail "roundtrip after upgrade: $out"
ok "upgrade: node b replaced, healthy, still in the ring (a second round trip passed)"

# 7. remove node b
run b remove >/dev/null
command docker volume inspect "$ID-b" >/dev/null 2>&1 && fail "remove left the volume"
[[ -n "$(ls -A "$WORK/backup-b/$ID-b-backup")" ]] || fail "remove made no backup"
ok "remove: node b stopped, copied ($(find "$WORK/backup-b/$ID-b-backup" -mindepth 1 -maxdepth 1 | wc -l) entries), container and volume gone"
echo "test_docker_doc: PASS ($IMG)"
