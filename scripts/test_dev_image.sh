#!/usr/bin/env bash
# Tests a dev container archive (B-131) the way deploy/synology/compose.yaml runs it: docker load,
# `wot init` once, then run with a fresh named volume, cap_drop ALL, no-new-privileges, a read-only root and tmpfs
# /run/parvault and /tmp. Checks that every process runs as 65532, the data volume is owned by
# 65532, and the healthcheck turns healthy. Needs Docker; the archive's arch must match the host.
# Usage: scripts/test_dev_image.sh <parvault-image-<arch>-dev.tar>
set -euo pipefail
TAR=$1
NAME="pv-devimg-test-$$"; VOL="pv-devimg-test-$$"
# shellcheck source=lib_test_slots.sh
source "$(dirname "$0")/lib_test_slots.sh"
RUNTAG="pv-devimg-test:$$"   # this run's own tag of the loaded image, removed at the end
cleanup() {
  restore_shared_tag
  docker rm -fv "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$VOL" >/dev/null 2>&1 || true
  docker rmi "$RUNTAG" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "test_dev_image: FAIL: $*" >&2; docker logs "$NAME" 2>&1 | tail -30 >&2 || true; exit 1; }

# `docker load` retags parvault:<ver>-dev, which a live container's tag may be: load under a lock,
# tag the loaded image for this run, put the shared tag back, and test only $RUNTAG.
load_and_adopt() {
  [[ -n "$LOADED_GUESS" ]] && begin_load "$LOADED_GUESS"   # records the tag's current image, inside the lock
  LOADED=$(docker load -i "$TAR" | sed -n 's/^Loaded image: //p')
  [[ "$LOADED" =~ ^parvault:[0-9]+\.[0-9]+\.[0-9]+-dev$ ]] || fail "loaded '$LOADED', want parvault:<ver>-dev"
  adopt_loaded_image "$LOADED" "$RUNTAG" || fail "could not tag the loaded image"
}
# the tar's tag is not known before loading: read it from the tar's manifest
LOADED_GUESS=$(tar -xOf "$TAR" manifest.json 2>/dev/null | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["RepoTags"][0])' 2>/dev/null || true)
with_image_lock load_and_adopt
TAG=$RUNTAG
echo "loaded $TAG ($(docker image inspect -f '{{.Architecture}} {{.Id}}' "$TAG"))"
[[ "$(docker image inspect -f '{{.Config.User}}' "$TAG")" == "65532:65532" ]] || fail "image user is not 65532:65532"
# No status listener by default (router_nas.rs: no flag, no listener); compose.yaml opts in.
cmd=$(docker image inspect -f '{{json .Config.Cmd}}' "$TAG")
[[ "$cmd" != *status-http* ]] || fail "image Cmd passes --status-http: $cmd"
echo "default Cmd: $cmd (no --status-http)"

HARD=(--cap-drop ALL --security-opt no-new-privileges:true --read-only
  --tmpfs /run/parvault:uid=65532,gid=65532,mode=0700 --tmpfs /tmp:mode=1777)
# First run (docs/SYNOLOGY.md step 3): a fresh node must start a ring or join one before `up`.
docker run --rm -v "$VOL:/var/lib/parvault" "${HARD[@]}" "$TAG" --data-dir /var/lib/parvault wot init \
  > "/tmp/$NAME-init.log" 2>&1 || { cat "/tmp/$NAME-init.log" >&2; fail "wot init failed"; }
rm -f "/tmp/$NAME-init.log"
echo "first run: wot init ok (as 65532, hardened)"
docker run -d --name "$NAME" -v "$VOL:/var/lib/parvault" "${HARD[@]}" "$TAG" >/dev/null

health=""
for _ in $(seq 1 60); do
  [[ "$(docker inspect -f '{{.State.Running}}' "$NAME")" == true ]] || fail "container exited ($(docker inspect -f '{{.State.ExitCode}}' "$NAME"))"
  health=$(docker inspect -f '{{.State.Health.Status}}' "$NAME")
  [[ "$health" == healthy ]] && break
  sleep 3
done
[[ "$health" == healthy ]] || fail "health is '$health' after 180 s: $(docker inspect -f '{{json .State.Health.Log}}' "$NAME" | tail -c 600)"
echo "health: healthy ($(docker inspect -f '{{(index .State.Health.Log 0).Output}}' "$NAME" | tr -d '\n' | cut -c1-120))"

uids=$(docker top "$NAME" -eo pid,uid,args | awk 'NR>1 {print $2}' | sort -u)
[[ "$uids" == 65532 ]] || fail "processes run as uid(s) '$uids', want only 65532"
echo "processes: uid 65532 only ($(docker top "$NAME" -eo pid,uid,comm | awk 'NR>1 {print $2" "$3}' | head -3 | tr '\n' ';'))"
caps=$(awk '/^CapEff/ {print $2}' "/proc/$(docker inspect -f '{{.State.Pid}}' "$NAME")/status")
[[ "$caps" == 0000000000000000 ]] || fail "effective capabilities $caps, want none"
echo "capabilities: none (CapEff=$caps)"
# Nothing listens on 4080 in the container's network namespace (TCP LISTEN = state 0A, port 0FF0).
pid=$(docker inspect -f '{{.State.Pid}}' "$NAME")
if awk 'FNR>1 && $4 == "0A" {split($2, a, ":"); if (a[2] == "0FF0") f=1} END {exit !f}' "/proc/$pid/net/tcp" "/proc/$pid/net/tcp6"; then
  fail "a socket listens on port 4080 with the default Cmd"
fi
echo "status page: no listener on 4080 by default"
# docker cp streams a tar that keeps numeric owners: the volume root and what the daemon wrote.
owners=$(docker cp "$NAME:/var/lib/parvault" - | tar -tv --numeric-owner | awk '{print $2}' | sort -u)
[[ "$owners" == "65532/65532" ]] || fail "data volume entries owned by '$owners', want only 65532/65532"
echo "data volume: $(docker cp "$NAME:/var/lib/parvault" - | tar -t | wc -l) entries, all owned by 65532:65532"
echo "test_dev_image: PASS ($LOADED)"
