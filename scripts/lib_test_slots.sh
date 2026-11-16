# Sourced by the Docker test scripts. Two helpers so two runs can share one Docker host:
#   pick_port_base <name> <first> <width> <slots>  -> sets PB: the first free slot of <width> ports
#       starting at <first> + k*<width>. A slot is held with a flock on /tmp/parvault-test-<name>-<k>.lock
#       (fd kept open until the script exits) and must also be unbound on the host (ss), so a
#       concurrent run, or a daemon of the box, is never hit. Ranges never reach 4001/4009/4011/4080.
#   with_image_lock <cmd...>  -> run <cmd> under one host-wide lock (docker load + retag + restore).
pick_port_base() {
  local name=$1 first=$2 width=$3 slots=$4 k fd p busy
  for ((k = 0; k < slots; k++)); do
    exec {fd}>"/tmp/parvault-test-$name-$k.lock"
    flock -n "$fd" || { exec {fd}>&-; continue; }
    busy=0
    for ((p = first + k * width; p < first + (k + 1) * width; p++)); do
      for q in $p $((p + 1000)); do
        ss -Hltn "sport = :$q" 2>/dev/null | grep -q . && busy=1
      done
    done
    if ((busy == 0)); then PB=$((first + k * width)); return 0; fi
    exec {fd}>&-
  done
  echo "no free port slot for $name" >&2; return 1
}
LOCK_HELD=0; GUARD_TAG=""
with_image_lock() {
  local fd rc=0
  exec {fd}>/tmp/parvault-test-image-load.lock
  flock "$fd"
  LOCK_HELD=1
  "$@" || rc=$?
  LOCK_HELD=0
  exec {fd}>&-
  return $rc
}
# A `docker load` retags <tag> (a tag a live container may have been started from). To make that
# window safe: under the lock, begin_load records what <tag> pointed at in a file; adopt_loaded_image
# (or restore_shared_tag, in the caller's EXIT trap) puts it back; and the next run to take the
# lock restores a record left by a killed run (SIGKILL runs no trap) before it records its own.
_prior_file() { echo "/tmp/parvault-test-image-prior-${1//[^A-Za-z0-9._-]/_}"; }
_restore_from_record() { # <tag>; lock held. Prior empty (the tag did not exist): untag.
  local f prior cur; f=$(_prior_file "$1"); [[ -e "$f" ]] || return 0
  prior=$(<"$f"); cur=$(docker image inspect -f '{{.Id}}' "$1" 2>/dev/null || true)
  if [[ -n "$prior" ]]; then [[ "$cur" == "$prior" ]] || docker tag "$prior" "$1" >/dev/null 2>&1 || true
  elif [[ -n "$cur" ]]; then docker rmi "$1" >/dev/null 2>&1 || true; fi
  rm -f "$f"
}
# begin_load <tag>: call inside with_image_lock, right before the load.
begin_load() {
  GUARD_TAG=$1
  _restore_from_record "$1"
  docker image inspect -f '{{.Id}}' "$1" 2>/dev/null > "$(_prior_file "$1")" || : > "$(_prior_file "$1")"
}
# restore_shared_tag: call from the EXIT trap, so a failed or interrupted run cannot leave the tag moved.
restore_shared_tag() {
  [[ -n "$GUARD_TAG" ]] || return 0
  if ((LOCK_HELD)); then _restore_from_record "$GUARD_TAG"; else with_image_lock _restore_from_record "$GUARD_TAG"; fi
}
# adopt_loaded_image <tag> <run tag>: after a `docker load` that (re)tagged <tag>: give the loaded image
# its own per-run tag and put <tag> back on what it pointed at before (untag it if it did not exist).
adopt_loaded_image() {
  local tag=$1 runtag=$2 new
  new=$(docker image inspect -f '{{.Id}}' "$tag") || return 1
  docker tag "$new" "$runtag" || return 1
  _restore_from_record "$tag"
}
