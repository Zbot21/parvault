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
with_image_lock() {
  local fd rc=0
  exec {fd}>/tmp/parvault-test-image-load.lock
  flock "$fd"
  "$@" || rc=$?
  exec {fd}>&-
  return $rc
}
# adopt_loaded_image <tag> <prior id> <run tag>: after a `docker load` that (re)tagged <tag>: give the
# loaded image its own per-run tag and put <tag> back on what it pointed at before (it may be the
# tag a live container was started from), so the load never moves a shared tag.
adopt_loaded_image() {
  local tag=$1 prior=$2 runtag=$3 new
  new=$(docker image inspect -f '{{.Id}}' "$tag") || return 1
  docker tag "$new" "$runtag" || return 1
  if [[ -n "$prior" && "$prior" != "$new" ]]; then docker tag "$prior" "$tag" || return 1; fi
}
