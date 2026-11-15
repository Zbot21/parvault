#!/usr/bin/env bash
# Parallel, low-SSD-wear formal verification runner (TLA+ TLC and Kani). See
# docs/VERIFY_RUNNER.md for the measurements behind the defaults.
#
# Usage: scripts/verify.sh <tlc|kani|all|test|list-tlc|list-kani> [cargo test args...]
#
#   tlc        TLC on every specs/<Spec>.cfg and specs/<Spec>.<Variant>.cfg (as CI's
#              tla-model-check job), one cfg per run, each with its -metadir in /dev/shm.
#   kani       every #[kani::proof] / #[kani::proof_for_contract] harness: one
#              `cargo kani -j KANI_JOBS` (KANI_MODE=jobs, default) or KANI_MODE=shard.
#   all        tlc, then kani; failures are summed and reported at the end.
#   test       cargo test --locked [args] (the only step VERIFY_MOLD applies to).
#   list-tlc   print the discovered cfgs (specs/-relative), one per line.
#   list-kani  print the discovered harnesses (fully qualified), one per line.
#
# Environment (all optional):
#   SPEC=<name>        only cfgs whose spec or cfg basename is <name>
#                      (ParVaultProtocol, or ParVaultZeroKeyAdminAndQuorum.RootOffDisk)
#   TLC_HEAP_PCT=70    -Xms = -Xmx = this % of MemTotal, 1..75 (30 under pvjob); refused
#                      unless heap + TLC_SHM_MIN_MB + TLC_MEM_MARGIN_MB <= MemAvailable
#   TLC_MEM_MARGIN_MB=2048  RAM left free beside the heap and /dev/shm
#   TLC_WORKERS=auto   TLC -workers
#   TLC_SHM_MIN_MB=2048  refuse to start TLC with less free space in /dev/shm
#   TLA2TOOLS_JAR      else /opt/tla/tla2tools.jar, else ~/.cache/tla/tla2tools.jar
#   HARNESS=<a,b>      only these harnesses (bare or fully qualified names, comma-separated)
#   KANI_JOBS=N        CBMC threads / shard workers (default nproc --all / 2)
#   KANI_MODE=jobs     jobs: one `cargo kani -j N` (one compile); shard: N workers, each
#                      `cargo kani --harness <h> --exact` (see the docs section)
#   KANI_SHARD_TARGETS=1  shard mode: per-worker CARGO_TARGET_DIR (default 1)
#   FAIL_FAST=1        stop at the first failing cfg or harness
#   VERIFY_MOLD=1      link the `test` step with mold, in its own target dir
#   VERIFY_LOG_DIR     each run logs to <dir>/<stamp>/ (default $CARGO_TARGET_DIR/verify-logs)
#   VERIFY_DRY_RUN=1   print each command and its relevant env instead of running it
set -euo pipefail

# A shell started with SIGINT ignored (a background job of a non-interactive shell, as every
# pvjob job is) can neither trap nor reset it, so INT would not stop TLC or Kani. Re-exec
# once with SIGINT at its default.
if [[ -z "${VERIFY_SIGINT_RESET:-}" ]] \
   && (( (16#$(awk '/^SigIgn:/ {print $2}' /proc/$$/status) & 2) != 0 )); then
  export VERIFY_SIGINT_RESET=1
  exec python3 -I -c 'import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
os.execv("/bin/bash", ["bash"] + sys.argv[1:])' "${BASH_SOURCE[0]}" "$@"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

die() { echo "verify: $*" >&2; exit 2; }
log() { echo "verify: $*"; }

MODE="${1:-}"
[[ -n "$MODE" ]] || die "usage: scripts/verify.sh <tlc|kani|all|test|list-tlc|list-kani>"
shift || true

DRY="${VERIFY_DRY_RUN:-0}"
FAIL_FAST="${FAIL_FAST:-0}"
BASE_TARGET="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
# A per-run subdir, so a reused VERIFY_LOG_DIR never mixes in an earlier run's results.
LOG_DIR="${VERIFY_LOG_DIR:-$BASE_TARGET/verify-logs}/$STAMP"
FAILURES=()

# ---------------------------------------------------------------------------
# Cleanup, on EXIT and on INT, TERM and HUP: remove every /dev/shm dir this run made, TERM
# every child process group, wait at most about 2 s, then KILL any group still alive. Children
# lead their own process groups (set -m), so a group kill aimed at this shell (pvjob's TERM,
# then KILL 3 s later) does not reach them; this must finish inside that 3 s.
# ---------------------------------------------------------------------------
SHM_DIRS=()
CHILDREN=()
rm_shm() {
  local d
  for d in "${SHM_DIRS[@]+"${SHM_DIRS[@]}"}"; do
    [[ "$d" == /dev/shm/tlc-* ]] && rm -rf -- "$d"
  done
  return 0
}
group_alive() { kill -0 -- "-$1" 2>/dev/null || kill -0 "$1" 2>/dev/null; }
cleanup() {
  local rc=$? p i live
  trap '' INT TERM HUP
  rm_shm
  for p in "${CHILDREN[@]+"${CHILDREN[@]}"}"; do
    kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null || true
  done
  for (( i = 0; i < 20; i++ )); do
    live=0
    for p in "${CHILDREN[@]+"${CHILDREN[@]}"}"; do group_alive "$p" && live=1; done
    (( live )) || break
    sleep 0.1
  done
  for p in "${CHILDREN[@]+"${CHILDREN[@]}"}"; do
    kill -KILL -- "-$p" 2>/dev/null || kill -KILL "$p" 2>/dev/null || true
  done
  rm_shm  # a child may have written there between the first pass and its death
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Removes one pid from CHILDREN (an element, not a substring of every element).
drop_child() {
  local keep=() c
  for c in "${CHILDREN[@]+"${CHILDREN[@]}"}"; do [[ "$c" == "$1" ]] || keep+=("$c"); done
  CHILDREN=("${keep[@]+"${keep[@]}"}")
}

# mapfile with empty lines dropped: `mapfile <<< ""` gives one empty element, not none.
lines_to_array() {
  local -n _arr="$1"
  local _l
  _arr=()
  while IFS= read -r _l; do [[ -n "$_l" ]] && _arr+=("$_l"); done <<< "$2"
  return 0
}

# Runs "$@" in its own process group in the background and waits, so INT/TERM reach this
# shell at once (bash defers traps while a foreground child runs) and cleanup can kill it.
run_child() {
  local out="$1"; shift
  set -m
  "$@" >"$out" 2>&1 &
  local pid=$!
  set +m
  CHILDREN+=("$pid")
  local rc=0
  wait "$pid" || rc=$?
  drop_child "$pid"
  return "$rc"
}

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
# Every specs/<Spec>.cfg and specs/<Spec>.<Variant>.cfg whose <Spec>.tla exists; a .tla
# without its <Spec>.cfg is an error (CI's tla-model-check rules). Sorted, spec order.
discover_cfgs() {
  local f spec cfg
  shopt -s nullglob
  for f in specs/*.tla; do
    spec="$(basename "$f" .tla)"
    [[ -f "specs/$spec.cfg" ]] || die "specs/$spec.tla has no specs/$spec.cfg"
    echo "$spec.cfg"
    for cfg in specs/"$spec".*.cfg; do echo "$(basename "$cfg")"; done
  done
  for cfg in specs/*.*.cfg; do
    [[ -f "specs/$(basename "${cfg%%.*}").tla" ]] || die "$cfg has no matching .tla"
  done
  shopt -u nullglob
}

# Every #[kani::proof] / #[kani::proof_for_contract(..)] fn in the library sources, as the
# fully qualified name `cargo kani --harness <name> --exact` takes (module path from the
# file path plus enclosing inline `mod` blocks; rustfmt indentation gives the nesting).
discover_harnesses() {
  python3 -I - "$REPO_ROOT" <<'PY'
import os, re, sys
root = sys.argv[1]
attr = re.compile(r"^(\s*)#\[kani::(proof|proof_for_contract\(.*\))\]\s*$")
fn = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
mod = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
out = []
src = os.path.join(root, "src")
for d, dirs, files in os.walk(src):
    rel_d = os.path.relpath(d, src)
    if rel_d == "bin" or rel_d.startswith("bin" + os.sep):
        continue
    for name in files:
        if not name.endswith(".rs"):
            continue
        rel = os.path.relpath(os.path.join(d, name), src)
        if rel == "main.rs" or rel.startswith("cli" + os.sep):  # the bin's module tree
            continue
        parts = rel[:-3].split(os.sep)
        if parts[-1] in ("mod", "lib"):
            parts = parts[:-1]
        lines = open(os.path.join(d, name), encoding="utf-8").read().split("\n")
        for i, line in enumerate(lines):
            m = attr.match(line)
            if not m:
                continue
            indent = len(m.group(1))
            name_ = None
            for j in range(i + 1, min(i + 12, len(lines))):
                f = fn.match(lines[j])
                if f:
                    name_ = f.group(1)
                    break
            if name_ is None:
                sys.exit(f"{rel}:{i+1}: kani attribute with no fn after it")
            mods, cur = [], indent
            for k in range(i - 1, -1, -1):
                mm = mod.match(lines[k])
                if mm and len(mm.group(1)) < cur:
                    mods.insert(0, mm.group(2))
                    cur = len(mm.group(1))
                    if cur == 0:
                        break
            out.append("::".join(parts + mods + [name_]))
for h in sorted(set(out)):
    print(h)
PY
}

# ---------------------------------------------------------------------------
# TLC
# ---------------------------------------------------------------------------
tla_jar() {
  local j
  for j in "${TLA2TOOLS_JAR:-}" /opt/tla/tla2tools.jar "$HOME/.cache/tla/tla2tools.jar"; do
    [[ -n "$j" && -f "$j" ]] && { echo "$j"; return 0; }
  done
  die "tla2tools.jar not found (set TLA2TOOLS_JAR)"
}

# The heap is pinned (-Xms = -Xmx), and /dev/shm is tmpfs in the same RAM, so the heap plus
# the /dev/shm room TLC is guaranteed (TLC_SHM_MIN_MB) plus a margin must fit in MemAvailable
# now; otherwise refuse rather than push the box into swap or the OOM killer.
tlc_heap_mb() {
  local pct="${TLC_HEAP_PCT:-70}" shm="${TLC_SHM_MIN_MB:-2048}" margin="${TLC_MEM_MARGIN_MB:-2048}"
  local mi="${VERIFY_MEMINFO:-/proc/meminfo}" total avail heap
  [[ "$pct" =~ ^[0-9]+$ && "$pct" -ge 1 && "$pct" -le 75 ]] || die "TLC_HEAP_PCT must be 1..75"
  [[ "$margin" =~ ^[0-9]+$ ]] || die "TLC_MEM_MARGIN_MB must be a number of MiB"
  total="$(awk '/^MemTotal:/ {print int($2 / 1024)}' "$mi")"
  avail="$(awk '/^MemAvailable:/ {print int($2 / 1024)}' "$mi")"
  [[ -n "$total" && -n "$avail" ]] || die "no MemTotal/MemAvailable in $mi"
  heap=$(( total * pct / 100 ))
  if (( heap + shm + margin > avail )); then
    die "TLC heap ${heap} MiB (TLC_HEAP_PCT=$pct of ${total} MiB) + /dev/shm ${shm} MiB (TLC_SHM_MIN_MB) + margin ${margin} MiB (TLC_MEM_MARGIN_MB) exceeds MemAvailable ${avail} MiB; lower TLC_HEAP_PCT or wait for memory"
  fi
  echo "$heap"
}

shm_free_mb() { df -Pm /dev/shm | awk 'NR==2 {print $4}'; }

run_tlc() {
  local cfgs=() c spec base list
  list="$(discover_cfgs)" || exit 2  # a process substitution would hide a discovery error
  lines_to_array cfgs "$list"
  [[ ${#cfgs[@]} -gt 0 ]] || die "no TLC cfg found in specs/"
  if [[ -n "${SPEC:-}" ]]; then
    local keep=()
    for c in "${cfgs[@]}"; do
      base="${c%.cfg}"; spec="${c%%.*}"
      [[ "$SPEC" == "$spec" || "$SPEC" == "$base" ]] && keep+=("$c")
    done
    [[ ${#keep[@]} -gt 0 ]] || die "SPEC=$SPEC matches no cfg"
    cfgs=("${keep[@]}")
  fi
  local jar heap workers="${TLC_WORKERS:-auto}" min="${TLC_SHM_MIN_MB:-2048}"
  jar="$(tla_jar)"; heap="$(tlc_heap_mb)"
  mkdir -p "$LOG_DIR/tlc"
  log "TLC: ${#cfgs[@]} cfg(s), heap ${heap} MiB pinned, workers $workers, jar $jar"
  for c in "${cfgs[@]}"; do
    base="${c%.cfg}"; spec="${c%%.*}"
    local free; free="$(shm_free_mb)"
    if (( free < min )); then
      FAILURES+=("tlc $c: /dev/shm has ${free} MiB free, need ${min} (TLC_SHM_MIN_MB)")
      log "FAIL tlc $c (no room in /dev/shm)"
      if [[ "$FAIL_FAST" == 1 ]]; then return 0; fi
      continue
    fi
    local meta="/dev/shm/tlc-$base-$$" lf="$LOG_DIR/tlc/$base.log"
    local cmd=(java "-Xms${heap}m" "-Xmx${heap}m" -XX:+UseParallelGC "-Djava.io.tmpdir=$meta"
               -cp "$jar" tlc2.TLC -workers "$workers" -cleanup -noGenerateSpecTE
               -metadir "$meta" -config "$c" "$spec.tla")
    if [[ "$DRY" == 1 ]]; then echo "DRY tlc: (cd specs && ${cmd[*]})"; continue; fi
    SHM_DIRS+=("$meta")
    mkdir -p "$meta"
    local t0=$SECONDS rc=0
    pushd specs >/dev/null
    run_child "$lf" "${cmd[@]}" || rc=$?
    popd >/dev/null
    rm -rf -- "$meta"
    local dt=$(( SECONDS - t0 ))
    # A positive cfg passes only when TLC exits 0 and prints no "Error:" line.
    if (( rc == 0 )) && ! grep -q '^Error:' "$lf"; then
      log "PASS tlc $c (${dt}s) $(grep -m1 'distinct states found' "$lf" || true)"
    else
      FAILURES+=("tlc $c: rc=$rc ($(grep -m1 '^Error:' "$lf" || echo 'no Error line')) log $lf")
      log "FAIL tlc $c (${dt}s, rc=$rc) log $lf"
      if [[ "$FAIL_FAST" == 1 ]]; then return 0; fi
    fi
  done
}

# ---------------------------------------------------------------------------
# Kani. KANI_MODE=jobs (default): one `cargo kani -j KANI_JOBS`, which compiles the crate
# once and runs CBMC on KANI_JOBS threads. KANI_MODE=shard: KANI_JOBS workers, each running
# `cargo kani --harness <h> --exact` for its share (one recompile per harness; per-worker
# target dirs, since workers on one target dir queue on cargo's build-directory lock).
# ---------------------------------------------------------------------------
run_kani() {
  local hs=() h list
  list="$(discover_harnesses)" || exit 2
  lines_to_array hs "$list"
  [[ ${#hs[@]} -gt 0 ]] || die "no Kani harness found"
  if [[ -n "${HARNESS:-}" ]]; then
    local keep=() want=() x
    IFS=, read -r -a want <<< "$HARNESS"
    for x in "${want[@]}"; do
      local hit=0
      for h in "${hs[@]}"; do
        if [[ "$h" == "$x" || "${h##*::}" == "$x" ]]; then keep+=("$h"); hit=1; fi
      done
      (( hit )) || die "HARNESS: $x matches no harness"
    done
    hs=("${keep[@]}")
  fi
  local jobs="${KANI_JOBS:-$(( $(nproc --all) / 2 ))}" mode="${KANI_MODE:-jobs}"
  [[ "$jobs" =~ ^[0-9]+$ && "$jobs" -ge 1 ]] || die "KANI_JOBS must be >= 1"
  (( jobs > ${#hs[@]} )) && jobs=${#hs[@]}
  mkdir -p "$LOG_DIR/kani"
  local t0=$SECONDS
  case "$mode" in
    jobs) kani_jobs "$jobs" "${hs[@]}" ;;
    shard) kani_shard "$jobs" "${hs[@]}" ;;
    *) die "KANI_MODE must be jobs or shard" ;;
  esac
  [[ "$DRY" == 1 ]] && return 0
  local res status hname secs
  for res in "$LOG_DIR"/kani/*.result; do
    [[ -f "$res" ]] || continue
    read -r status hname secs < "$res"
    [[ "$status" == PASS ]] || FAILURES+=("kani $hname: $status (${secs}s) log ${res%.result}.log")
  done
  local n_res; n_res="$(find "$LOG_DIR/kani" -name '*.result' | wc -l)"
  if (( n_res < ${#hs[@]} )) && [[ "$FAIL_FAST" != 1 ]]; then
    FAILURES+=("kani: only $n_res of ${#hs[@]} harnesses reported a result (log $LOG_DIR/kani)")
  fi
  log "Kani ($mode, $jobs) wall time $(( SECONDS - t0 ))s for ${#hs[@]} harness(es); per-harness: $LOG_DIR/kani/times.tsv"
  sort -t$'\t' -k3,3gr "$LOG_DIR/kani/times.tsv" 2>/dev/null | head -5 | sed 's/^/verify:   slowest: /' || true
}

# Kani's own result lines name the thread, not the harness: each line is timestamped as it
# arrives, and a thread's result block belongs to the harness it last started.
kani_jobs() {
  local jobs="$1"; shift
  local cmd=(env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS cargo kani -j "$jobs" --output-format terse)
  [[ "$FAIL_FAST" == 1 ]] && cmd+=(--fail-fast)
  if [[ -n "${HARNESS:-}" ]]; then
    local h; for h in "$@"; do cmd+=(--harness "$h"); done
    cmd+=(--exact)
  fi
  log "Kani: ${#@} harness(es), mode jobs, $jobs CBMC thread(s), one compile"
  if [[ "$DRY" == 1 ]]; then echo "DRY kani: CARGO_TARGET_DIR=$BASE_TARGET ${cmd[*]}"; return 0; fi
  local raw="$LOG_DIR/kani/kani.log" rc=0
  # shellcheck disable=SC2016
  CARGO_TARGET_DIR="$BASE_TARGET" run_child "$raw" bash -o pipefail -c \
    '"$@" 2>&1 | while IFS= read -r l; do printf "%s %s\n" "$EPOCHREALTIME" "$l"; done' _ "${cmd[@]}" \
    || rc=$?
  python3 -I - "$raw" "$LOG_DIR/kani" "$rc" <<'PY'
import os, re, sys
raw, out, rc = sys.argv[1], sys.argv[2], sys.argv[3]
start, cur, block, t0 = {}, None, [], None
times = open(os.path.join(out, "times.tsv"), "a")
def emit(thread, lines, ts):
    h, t_start = start.get(thread, (None, None))
    if h is None:
        return
    text = "\n".join(lines)
    st = "PASS" if "VERIFICATION:- SUCCESSFUL" in text else "FAIL"
    safe = h.replace("::", "__")
    open(os.path.join(out, safe + ".log"), "w").write(text + "\n")
    dt = float(ts) - float(t_start)
    open(os.path.join(out, safe + ".result"), "w").write(f"{st} {h} {dt:.1f}\n")
    times.write(f"{st}\t{h}\t{dt:.1f}\tthread{thread}\n")
    print(f"verify: {st} kani {h} ({dt:.1f}s, thread {thread})")
for line in open(raw, errors="replace"):
    ts, _, l = line.rstrip("\n").partition(" ")
    # With -j 1 Kani prints no "Thread N: " prefixes; that output counts as thread "-".
    m = re.match(r"^(?:Thread (\d+): )?Checking harness (\S+?)\.\.\.$", l)
    if m:
        start[m.group(1) or "-"] = (m.group(2), ts)
        continue
    m = re.match(r"^Thread (\d+): $", l)
    if m:
        cur, block = m.group(1), [l]
        continue
    if cur is None and l == "VERIFICATION RESULT:":
        cur, block = "-", [l]
        continue
    if cur is not None:
        block.append(l)
        if l.startswith("Verification Time:"):
            emit(cur, block, ts)
            cur, block = None, []
if rc != "0":
    print(f"verify: cargo kani exited {rc}; full log {raw}")
PY
  if (( rc != 0 )); then FAILURES+=("cargo kani -j $jobs exited $rc (log $raw)"); fi
}

kani_shard() {
  local jobs="$1"; shift
  local hs=("$@") shard_targets="${KANI_SHARD_TARGETS:-1}"
  log "Kani: ${#hs[@]} harness(es), mode shard, $jobs worker(s), per-worker target dirs: $shard_targets"
  local w pids=()
  for (( w = 0; w < jobs; w++ )); do
    local tdir="$BASE_TARGET"
    [[ "$shard_targets" == 1 && "$jobs" -gt 1 ]] && tdir="$BASE_TARGET/kani-w$w"
    local mine=() i h
    for (( i = w; i < ${#hs[@]}; i += jobs )); do mine+=("${hs[$i]}"); done
    if [[ "$DRY" == 1 ]]; then
      for h in "${mine[@]}"; do echo "DRY kani w$w: CARGO_TARGET_DIR=$tdir cargo kani --harness $h --exact"; done
      continue
    fi
    set -m  # each worker leads its own process group, so cleanup can kill its cargo too
    kani_worker "$w" "$tdir" "${mine[@]}" &
    set +m
    pids+=("$!")
    CHILDREN+=("$!")
  done
  [[ "$DRY" == 1 ]] && return 0
  local p
  for p in "${pids[@]}"; do wait "$p" || true; drop_child "$p"; done
}

kani_worker() {
  local w="$1" tdir="$2"; shift 2
  local h
  for h in "$@"; do
    [[ "$FAIL_FAST" == 1 && -e "$LOG_DIR/kani/.failed" ]] && return 0
    local safe="${h//::/__}" lf rc=0 t0=$SECONDS
    lf="$LOG_DIR/kani/$safe.log"
    env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR="$tdir" \
      cargo kani --harness "$h" --exact >"$lf" 2>&1 || rc=$?
    local dt=$(( SECONDS - t0 )) st=PASS
    # Pass needs rc 0 and Kani's own success line (guards against a filter that matched nothing).
    if (( rc != 0 )) || ! grep -q 'VERIFICATION:- SUCCESSFUL' "$lf"; then st="FAIL(rc=$rc)"; fi
    echo "$st $h $dt" > "$LOG_DIR/kani/$safe.result"
    printf '%s\t%s\t%s\tw%s\n' "$st" "$h" "$dt" "$w" >> "$LOG_DIR/kani/times.tsv"
    echo "verify: $st kani $h (${dt}s, w$w)"
    [[ "$st" == PASS ]] || touch "$LOG_DIR/kani/.failed"
  done
}

# ---------------------------------------------------------------------------
# cargo test (VERIFY_MOLD=1: mold linker, own target dir; never Kani/release/repro/Docker)
# ---------------------------------------------------------------------------
run_test() {
  local tdir="$BASE_TARGET" flags="${RUSTFLAGS:-}"
  if [[ "${VERIFY_MOLD:-0}" == 1 ]]; then
    if command -v mold >/dev/null 2>&1; then
      tdir="$BASE_TARGET-mold"
      flags="${flags:+$flags }-C link-arg=-fuse-ld=mold"
      log "mold: on (target dir $tdir)"
    else
      log "mold: VERIFY_MOLD=1 but mold is not installed; linking with the default linker"
    fi
  fi
  if [[ "$DRY" == 1 ]]; then
    echo "DRY test: CARGO_TARGET_DIR=$tdir RUSTFLAGS=${flags:-<unset>} cargo test --locked $*"
    return 0
  fi
  local rc=0
  if [[ -n "$flags" ]]; then
    CARGO_TARGET_DIR="$tdir" RUSTFLAGS="$flags" cargo test --locked "$@" || rc=$?
  else
    CARGO_TARGET_DIR="$tdir" cargo test --locked "$@" || rc=$?
  fi
  (( rc == 0 )) || FAILURES+=("cargo test: rc=$rc")
}

summary() {
  [[ "$DRY" == 1 ]] && return 0
  echo "================================================================================"
  if [[ ${#FAILURES[@]} -eq 0 ]]; then
    log "ALL PASSED ($MODE). Logs: $LOG_DIR"
    return 0
  fi
  log "${#FAILURES[@]} FAILURE(S) ($MODE):"
  local f; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  return 1
}

case "$MODE" in
  list-tlc) discover_cfgs ;;  # set -e ends the run on a discovery error
  list-kani) discover_harnesses ;;
  tlc) run_tlc; summary ;;
  kani) run_kani; summary ;;
  all)
    run_tlc
    if [[ "$FAIL_FAST" != 1 || ${#FAILURES[@]} -eq 0 ]]; then run_kani; fi
    summary ;;
  test) run_test "$@"; summary ;;
  *) die "unknown mode: $MODE" ;;
esac
