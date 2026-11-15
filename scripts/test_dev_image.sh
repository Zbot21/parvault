#!/usr/bin/env bash
# Tests a dev container archive (B-131) the way deploy/synology/compose.yaml runs it: docker load,
# then run with a fresh named volume, cap_drop ALL, no-new-privileges, a read-only root and tmpfs
# /run/parvault and /tmp. Checks that every process runs as 65532, the data volume is owned by
# 65532, and the healthcheck turns healthy. Needs Docker; the archive's arch must match the host.
# Usage: scripts/test_dev_image.sh <parvault-image-<arch>-dev.tar>
set -euo pipefail
TAR=$1
NAME="pv-devimg-test-$$"; VOL="pv-devimg-test-$$"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; docker volume rm "$VOL" >/dev/null 2>&1 || true; }
trap cleanup EXIT
fail() { echo "test_dev_image: FAIL: $*" >&2; docker logs "$NAME" 2>&1 | tail -30 >&2 || true; exit 1; }

TAG=$(docker load -i "$TAR" | sed -n 's/^Loaded image: //p')
[[ "$TAG" =~ ^parvault:[0-9]+\.[0-9]+\.[0-9]+-dev$ ]] || fail "loaded '$TAG', want parvault:<ver>-dev"
echo "loaded $TAG ($(docker image inspect -f '{{.Architecture}} {{.Id}}' "$TAG"))"
[[ "$(docker image inspect -f '{{.Config.User}}' "$TAG")" == "65532:65532" ]] || fail "image user is not 65532:65532"

docker run -d --name "$NAME" -v "$VOL:/var/lib/parvault" \
  --cap-drop ALL --security-opt no-new-privileges:true --read-only \
  --tmpfs /run/parvault:uid=65532,gid=65532,mode=0700 --tmpfs /tmp:mode=1777 \
  "$TAG" >/dev/null

health=""
for _ in $(seq 1 60); do
  [[ "$(docker inspect -f '{{.State.Running}}' "$NAME")" == true ]] || fail "container exited ($(docker inspect -f '{{.State.ExitCode}}' "$NAME"))"
  health=$(docker inspect -f '{{.State.Health.Status}}' "$NAME")
  [[ "$health" == healthy ]] && break
  sleep 3
done
[[ "$health" == healthy ]] || fail "health is '$health' after 180 s: $(docker inspect -f '{{json .State.Health.Log}}' "$NAME" | tail -c 600)"
echo "health: healthy ($(docker inspect -f '{{(index .State.Health.Log 0).Output}}' "$NAME" | tr -d '\n' | cut -c1-120))"

uids=$(docker top "$NAME" -eo uid,args | awk 'NR>1 {print $1}' | sort -u)
[[ "$uids" == 65532 ]] || fail "processes run as uid(s) '$uids', want only 65532"
echo "processes: uid 65532 only ($(docker top "$NAME" -eo uid,args | awk 'NR>1' | cut -c1-100 | head -3 | tr '\n' ';'))"
caps=$(awk '/^CapEff/ {print $2}' "/proc/$(docker inspect -f '{{.State.Pid}}' "$NAME")/status")
[[ "$caps" == 0000000000000000 ]] || fail "effective capabilities $caps, want none"
echo "capabilities: none (CapEff=$caps)"
# docker cp streams a tar that keeps numeric owners: the volume root and what the daemon wrote.
owners=$(docker cp "$NAME:/var/lib/parvault" - | tar -tv --numeric-owner | awk '{print $2}' | sort -u)
[[ "$owners" == "65532/65532" ]] || fail "data volume entries owned by '$owners', want only 65532/65532"
echo "data volume: $(docker cp "$NAME:/var/lib/parvault" - | tar -t | wc -l) entries, all owned by 65532:65532"
echo "test_dev_image: PASS ($TAG)"
