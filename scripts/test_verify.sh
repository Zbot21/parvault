#!/usr/bin/env bash
# Tests for scripts/verify.sh. Light by default (fake java/cargo/mold, no TLC or Kani run):
#   - discovery matches CI's cfg rules, docs/metrics.txt and every harness= in .enforcement.map
#   - VERIFY_KANI_LIST=1 (needs cargo-kani; heavy, run under pvjob): discovery == `cargo kani list`
#   - both scripts are committed executable (the tests themselves run them through bash)
#   - /dev/shm/tlc-* is removed on success, failure, INT, TERM and HUP; a child that ignores
#     TERM is KILLed about 2 s later, so nothing survives a cancel
#   - the TLC heap is refused unless it fits in MemAvailable beside /dev/shm (fake meminfo)
#   - an empty discovery stops the run; a reused VERIFY_LOG_DIR does not mix runs
#   - failures are summed and the exit code is non-zero; FAIL_FAST stops early
#   - VERIFY_MOLD reaches only the `test` step, never cargo kani
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
V="$REPO_ROOT/scripts/verify.sh"
unset VERIFY_SIGINT_RESET
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0 FAIL=0
ok() { echo "ok   $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
shm_left() { find /dev/shm -maxdepth 1 -name "tlc-*-$1" 2>/dev/null | wc -l; }

# --- Executable bits (make and CI run the scripts directly) ------------------------------
if git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  modes="$(git -C "$REPO_ROOT" ls-files -s scripts/verify.sh scripts/test_verify.sh | cut -d' ' -f1 | sort -u)"
  check "verify.sh and test_verify.sh are committed 100755 ($modes)" '[ "$modes" = 100755 ]'
fi

# --- Discovery --------------------------------------------------------------------------
bash "$V" list-tlc > "$WORK/cfgs"
( cd specs; for f in *.tla; do s="${f%.tla}"; echo "$s.cfg"; for c in "$s".*.cfg; do [ -f "$c" ] && echo "$c"; done; done ) > "$WORK/ci-cfgs"
check "cfgs match CI's tla-model-check loop" 'diff -q "$WORK/cfgs" "$WORK/ci-cfgs" >/dev/null'
n_tla="$(sed -n 's/^tla_specs *= *//p' docs/metrics.txt)"
check "one base cfg per spec (metrics tla_specs=$n_tla)" '[ "$(grep -c "^[^.]*\.cfg$" "$WORK/cfgs")" = "$n_tla" ]'

bash "$V" list-kani > "$WORK/harnesses"
n_kani="$(sed -n 's/^kani_harnesses *= *//p' docs/metrics.txt)"
check "harness count == metrics kani_harnesses ($n_kani)" '[ "$(wc -l < "$WORK/harnesses")" = "$n_kani" ]'
n_attr="$(grep -rhoE '^\s*#\[kani::proof(_for_contract\(.*\))?\]' src | wc -l)"
check "every kani attribute in src/ is discovered ($n_attr)" '[ "$(wc -l < "$WORK/harnesses")" = "$n_attr" ]'
missing="$(grep -oE 'harness=[A-Za-z0-9_]+' .enforcement.map | cut -d= -f2 | sort -u \
  | while read -r h; do grep -q "::$h\$" "$WORK/harnesses" || echo "$h"; done)"
check "every .enforcement.map harness= is discovered${missing:+ (missing: $missing)}" '[ -z "$missing" ]'

if [[ "${VERIFY_KANI_LIST:-0}" == 1 ]]; then
  # `cargo kani list` takes no --manifest-path and writes kani-list.json to the cwd.
  if cargo kani list --format json > "$WORK/kani-list.out" 2>&1; then
    mv kani-list.json "$WORK/"
  else
    bad "cargo kani list ran (log below)"; tail -20 "$WORK/kani-list.out"; echo '{}' > "$WORK/kani-list.json"
  fi
  python3 -I - "$WORK/kani-list.json" > "$WORK/kani-list" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
names = set()
for v in d.get("standard-harnesses", {}).values():
    names.update(v)
for v in d.get("contract-harnesses", {}).values():
    names.update(v)
for n in sorted(names):
    print(n)
PY
  check "discovery == cargo kani list" 'diff "$WORK/harnesses" "$WORK/kani-list"'
fi

# A discovery error stops the run (it must not run a partial list).
cp -r "$REPO_ROOT/scripts" "$REPO_ROOT/specs" "$WORK/" && mkdir -p "$WORK/repo" && mv "$WORK/scripts" "$WORK/specs" "$WORK/repo/"
touch "$WORK/repo/specs/Orphan.tla"
rc=0; bash "$WORK/repo/scripts/verify.sh" tlc > "$WORK/out" 2>&1 || rc=$?
check "a .tla without its .cfg stops the TLC run (rc $rc)" '[ $rc = 2 ] && grep -q "Orphan.tla has no" "$WORK/out" && ! grep -q "TLC:" "$WORK/out"'
rm -f "$WORK/repo/specs/"*.tla "$WORK/repo/specs/"*.cfg
rc=0; bash "$WORK/repo/scripts/verify.sh" tlc > "$WORK/out" 2>&1 || rc=$?
check "no cfg at all stops the TLC run (rc $rc)" '[ $rc = 2 ] && grep -q "no TLC cfg found" "$WORK/out"'
mkdir -p "$WORK/repo/src"  # no kani attribute anywhere
rc=0; bash "$WORK/repo/scripts/verify.sh" kani > "$WORK/out" 2>&1 || rc=$?
check "no harness at all stops the Kani run (rc $rc)" '[ $rc = 2 ] && grep -q "no Kani harness found" "$WORK/out"'
rm -rf "$WORK/repo"

# --- Fakes ------------------------------------------------------------------------------
mkdir -p "$WORK/bin"
cat > "$WORK/bin/java" <<'EOF'
#!/usr/bin/env bash
# Fake TLC: records its -metadir, writes a file there, then behaves per FAKE_TLC.
meta=""; while [ $# -gt 0 ]; do [ "$1" = -metadir ] && meta="$2"; shift; done
echo "$meta" >> "$FAKE_LOG"
echo state > "$meta/fake.st"
case "${FAKE_TLC:-pass}" in
  pass) echo "Model checking completed. No error has been found."; echo "9 distinct states found";;
  fail) echo "Error: Invariant Foo is violated."; exit 12;;
  hang) sleep 30;;
  stubborn) trap '' INT TERM HUP; sleep 3071;;  # ignores TERM; sleep inherits that
esac
EOF
cat > "$WORK/bin/cargo" <<'EOF'
#!/usr/bin/env bash
# Fake cargo kani: fails the harness named in FAKE_KANI_FAIL; logs env for the mold check.
# With -j it prints Kani's terse multi-thread format for every harness (or each --harness).
echo "RUSTFLAGS=${RUSTFLAGS-<unset>} TARGET=$CARGO_TARGET_DIR ARGS=$*" >> "$FAKE_LOG"
if [ -n "${FAKE_KANI_HANG:-}" ]; then trap '' INT TERM HUP; sleep 3072; exit 0; fi
hs=() jobs=0 ff=0
while [ $# -gt 0 ]; do
  case "$1" in --harness) hs+=("$2"); shift;; -j) jobs="$2"; shift;; --fail-fast) ff=1;; esac; shift
done
if [ "$jobs" = 0 ]; then
  if [ -n "${FAKE_KANI_FAIL:-}" ] && [ "${hs[0]:-}" = "$FAKE_KANI_FAIL" ]; then echo "VERIFICATION:- FAILED"; exit 1; fi
  echo "VERIFICATION:- SUCCESSFUL"; exit 0
fi
[ ${#hs[@]} -gt 0 ] || mapfile -t hs < <(bash "$FAKE_REPO/scripts/verify.sh" list-kani)
rc=0 i=0
for h in "${hs[@]}"; do
  t=$((i % jobs)); i=$((i + 1))
  if [ "$jobs" = 1 ]; then  # Kani prints no thread prefixes with -j 1
    echo "Checking harness $h..."; echo; echo "VERIFICATION RESULT:"
  else
    echo "Thread $t: Checking harness $h..."
    echo "Thread $t: "; echo "VERIFICATION RESULT:"
  fi
  if [ "$h" = "${FAKE_KANI_FAIL:-}" ]; then echo "VERIFICATION:- FAILED"; rc=1; else echo "VERIFICATION:- SUCCESSFUL"; fi
  echo "Verification Time: 0.01s"
  [ "$rc" = 1 ] && [ "$ff" = 1 ] && break
done
echo "Complete - done"
exit $rc
EOF
printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/mold"
chmod +x "$WORK/bin/"*
export FAKE_REPO="$REPO_ROOT" PATH="$WORK/bin:$PATH" TLA2TOOLS_JAR="$WORK/fake.jar" FAKE_LOG="$WORK/fake.log"
export CARGO_TARGET_DIR="$WORK/target" TLC_HEAP_PCT=1 TLC_SHM_MIN_MB=1 TLC_MEM_MARGIN_MB=1
survivors() { { pgrep -f "sleep 307[12]|$WORK/bin/(java|cargo)" 2>/dev/null || true; } | wc -l; }
: > "$WORK/fake.jar"

# --- TLC: /dev/shm cleanup and result semantics -----------------------------------------
: > "$FAKE_LOG"
SPEC=ParVaultZeroKeyAdminAndQuorum bash "$V" tlc > "$WORK/out" 2>&1 & p=$!; wait $p; rc=$?
check "TLC pass: rc 0, both ZeroKey cfgs run" '[ $rc = 0 ] && [ "$(grep -c "PASS tlc" "$WORK/out")" = 2 ]'
check "TLC pass: metadir was in /dev/shm/tlc-<cfg>-<pid>" 'grep -q "^/dev/shm/tlc-ParVaultZeroKeyAdminAndQuorum.RootOffDisk-$p$" "$FAKE_LOG"'
check "TLC pass: /dev/shm/tlc-*-$p removed" '[ "$(shm_left $p)" = 0 ]'
check "TLC pass: heap pinned (-Xms = -Xmx)" 'grep -q "heap .* MiB pinned" "$WORK/out"'

FAKE_TLC=fail SPEC=ParVaultProtocol bash "$V" tlc > "$WORK/out" 2>&1 & p=$!; rc=0; wait $p || rc=$?
check "TLC violation on a positive cfg fails (rc $rc) with a summary" '[ $rc = 1 ] && grep -q "Invariant Foo is violated" "$WORK/out"'
check "TLC fail: /dev/shm cleaned" '[ "$(shm_left $p)" = 0 ]'

# INT-ignored: started with SIGINT ignored, as a pvjob job is (the runner re-execs to reset it).
for sig in INT TERM HUP INT-ignored; do
  : > "$FAKE_LOG"
  t0=$SECONDS rc=0
  if [[ "$sig" == INT-ignored ]]; then
    (trap '' INT; FAKE_TLC=hang SPEC=ParVaultProtocol exec timeout -s INT 2 bash "$V" tlc) > "$WORK/out" 2>&1 || rc=$?
  else
    FAKE_TLC=hang SPEC=ParVaultProtocol timeout -s "$sig" 2 bash "$V" tlc > "$WORK/out" 2>&1 || rc=$?
  fi
  meta="$(head -1 "$FAKE_LOG")"
  check "TLC $sig: the fake TLC ran with a /dev/shm/tlc-* metadir" '[[ "$meta" == /dev/shm/tlc-ParVaultProtocol-* ]]'
  check "TLC $sig: exits promptly (rc $rc, $((SECONDS - t0))s) and /dev/shm cleaned" \
    '[ $rc = 124 ] && [ $((SECONDS - t0)) -lt 10 ] && [ ! -e "$meta" ]'
  check "TLC $sig: fake TLC child killed" '! pgrep -f "$WORK/bin/java" >/dev/null'
done

# A fake meminfo with room for the heap, so the per-cfg /dev/shm check is what refuses.
printf 'MemTotal: 1048576 kB\nMemAvailable: 99999999999999 kB\n' > "$WORK/meminfo-big"
VERIFY_MEMINFO="$WORK/meminfo-big" TLC_SHM_MIN_MB=999999999 SPEC=ParVaultProtocol bash "$V" tlc > "$WORK/out" 2>&1 && rc=0 || rc=$?
check "TLC refuses to start without room in /dev/shm" '[ $rc = 1 ] && grep -q "TLC_SHM_MIN_MB" "$WORK/out"'

# A child that ignores TERM (as cargo-kani and cbmc did on a real cancel) is KILLed.
for what in tlc kani; do
  t0=$SECONDS rc=0
  if [[ "$what" == tlc ]]; then
    FAKE_TLC=stubborn SPEC=ParVaultProtocol timeout -s TERM 2 bash "$V" tlc > "$WORK/out" 2>&1 || rc=$?
  else
    FAKE_KANI_HANG=1 HARNESS=proof_webdav_auth_decision timeout -s TERM 2 bash "$V" kani > "$WORK/out" 2>&1 || rc=$?
  fi
  dt=$((SECONDS - t0)); sleep 0.3
  n="$(survivors)"
  check "$what, TERM-ignoring child: runner exits within the grace (rc $rc, ${dt}s), $n survivor(s)" \
    '[ $rc = 124 ] && [ $dt -lt 7 ] && [ "$n" = 0 ] && [ -z "$(find /dev/shm -maxdepth 1 -name "tlc-*" -newer "$WORK/fake.jar" -user "$(id -u)" 2>/dev/null)" ]'
  pkill -KILL -f "sleep 307[12]" 2>/dev/null || true
done

# TLC heap vs MemAvailable (fake meminfo: 100 GiB total, 50 GiB available).
printf 'MemTotal: 104857600 kB\nMemAvailable: 52428800 kB\n' > "$WORK/meminfo"
rc=0; VERIFY_MEMINFO="$WORK/meminfo" TLC_HEAP_PCT=70 TLC_SHM_MIN_MB=2048 TLC_MEM_MARGIN_MB=2048 VERIFY_DRY_RUN=1 \
  SPEC=ParVaultProtocol bash "$V" tlc > "$WORK/out" 2>&1 || rc=$?
check "TLC heap 70 % of 100 GiB does not fit 50 GiB available: refused (rc $rc)" \
  '[ $rc = 2 ] && grep -q "exceeds MemAvailable 51200 MiB" "$WORK/out" && ! grep -q "^DRY tlc" "$WORK/out"'
rc=0; VERIFY_MEMINFO="$WORK/meminfo" TLC_HEAP_PCT=40 TLC_SHM_MIN_MB=2048 TLC_MEM_MARGIN_MB=2048 VERIFY_DRY_RUN=1 \
  SPEC=ParVaultProtocol bash "$V" tlc > "$WORK/out" 2>&1 || rc=$?
check "TLC heap 40 % (40960 + 2048 + 2048 <= 51200 MiB) runs pinned at 40960 MiB (rc $rc)" \
  '[ $rc = 0 ] && grep -q "^DRY tlc: .*-Xms40960m -Xmx40960m" "$WORK/out"'
rc=0; VERIFY_MEMINFO="$WORK/meminfo-big" TLC_HEAP_PCT=80 VERIFY_DRY_RUN=1 SPEC=ParVaultProtocol bash "$V" tlc > "$WORK/out" 2>&1 || rc=$?
check "TLC_HEAP_PCT above 75 is refused (rc $rc)" '[ $rc = 2 ] && grep -q "TLC_HEAP_PCT must be 1..75" "$WORK/out"'

# --- Kani: jobs mode (default) and shard mode; failure summary, FAIL_FAST --------------
: > "$FAKE_LOG"
KANI_JOBS=4 bash "$V" kani > "$WORK/out" 2>&1 && rc=0 || rc=$?
check "Kani jobs: one cargo kani -j 4 --output-format terse" '[ "$(wc -l < "$FAKE_LOG")" = 1 ] && grep -q "ARGS=kani -j 4 --output-format terse$" "$FAKE_LOG"'
check "Kani jobs: rc 0, a PASS per harness" '[ $rc = 0 ] && [ "$(grep -c "PASS kani" "$WORK/out")" = "$n_kani" ]'
d="$(sed -n "s#^verify: ALL PASSED (kani). Logs: ##p" "$WORK/out")"
check "Kani jobs: per-harness log, result and times.tsv" '[ "$(ls "$d"/kani/*.result | wc -l)" = "$n_kani" ] && [ "$(wc -l < "$d/kani/times.tsv")" = "$n_kani" ] && grep -q "VERIFICATION RESULT" "$d/kani/kani_proofs__proof_webdav_auth_decision.log"'
FAKE_KANI_FAIL=kani_proofs::proof_webdav_auth_decision KANI_JOBS=3 bash "$V" kani > "$WORK/out" 2>&1 && rc=0 || rc=$?
check "Kani jobs failure: rc 1, summary names the harness" '[ $rc = 1 ] && grep -q "^  - kani kani_proofs::proof_webdav_auth_decision: FAIL" "$WORK/out"'
: > "$FAKE_LOG"
HARNESS=proof_webdav_auth_decision FAIL_FAST=1 bash "$V" kani > "$WORK/out" 2>&1
check "Kani jobs: HARNESS= passes --harness <fq> --exact, FAIL_FAST passes --fail-fast" \
  'grep -q "fail-fast --harness kani_proofs::proof_webdav_auth_decision --exact$" "$FAKE_LOG"'
: > "$FAKE_LOG"
KANI_MODE=shard KANI_JOBS=4 bash "$V" kani > "$WORK/out" 2>&1 && rc=0 || rc=$?
check "Kani shard: rc 0, every harness once with --exact" '[ $rc = 0 ] && [ "$(grep -c -- "--exact" "$FAKE_LOG")" = "$n_kani" ]'
check "Kani shard: 4 per-worker target dirs" '[ "$(grep -o "TARGET=[^ ]*" "$FAKE_LOG" | sort -u | wc -l)" = 4 ]'
FAKE_KANI_FAIL=kani_proofs::proof_webdav_auth_decision KANI_MODE=shard KANI_JOBS=3 bash "$V" kani > "$WORK/out" 2>&1 && rc=0 || rc=$?
check "Kani shard failure: rc 1, summary names the harness" '[ $rc = 1 ] && grep -q "^  - kani kani_proofs::proof_webdav_auth_decision" "$WORK/out"'
: > "$FAKE_LOG"
FAKE_KANI_FAIL="$(head -1 "$WORK/harnesses")" FAIL_FAST=1 KANI_MODE=shard KANI_JOBS=1 bash "$V" kani > "$WORK/out" 2>&1 && rc=0 || rc=$?
check "Kani shard FAIL_FAST=1 stops after the first failure" '[ $rc = 1 ] && [ "$(wc -l < "$FAKE_LOG")" = 1 ]'

: > "$FAKE_LOG"
HARNESS=proof_webdav_auth_decision,crypto::aes::kani_proofs::proof_stripe_nonce_injectivity_and_no_panic KANI_MODE=shard KANI_JOBS=2 bash "$V" kani > "$WORK/out" 2>&1
check "HARNESS=a,b: two harnesses on two workers" '[ "$(grep -c -- "--exact" "$FAKE_LOG")" = 2 ] && [ "$(grep -o "TARGET=[^ ]*" "$FAKE_LOG" | sort -u | wc -l)" = 2 ]'
HARNESS=no_such_harness bash "$V" kani > "$WORK/out" 2>&1 && rc=0 || rc=$?
check "HARNESS= with an unknown name fails (rc $rc)" '[ $rc = 2 ]'

HARNESS=proof_webdav_auth_decision bash "$V" kani > "$WORK/out" 2>&1 && rc=0 || rc=$?
check "Kani jobs, one harness (-j 1, no thread prefixes): rc 0, one PASS" '[ $rc = 0 ] && [ "$(grep -c "PASS kani" "$WORK/out")" = 1 ]'

# A reused VERIFY_LOG_DIR: a failed run, then a passing one; the second sees only its own results.
FAKE_KANI_FAIL=kani_proofs::proof_webdav_auth_decision VERIFY_LOG_DIR="$WORK/logs" KANI_JOBS=4 bash "$V" kani > /dev/null 2>&1 || true
rc=0; VERIFY_LOG_DIR="$WORK/logs" KANI_JOBS=4 bash "$V" kani > "$WORK/out" 2>&1 || rc=$?
d="$(sed -n "s#^verify: ALL PASSED (kani). Logs: ##p" "$WORK/out")"
check "reused VERIFY_LOG_DIR: second run passes (rc $rc) in its own <dir>/<stamp>, times.tsv has $n_kani rows" \
  '[ $rc = 0 ] && [[ "$d" == "$WORK/logs/"?* ]] && [ "$(wc -l < "$d/kani/times.tsv")" = "$n_kani" ] && [ "$(ls -d "$WORK/logs"/*/ | wc -l)" = 2 ]'

# --- all: a TLC failure is summed with Kani's results -----------------------------------
FAKE_TLC=fail SPEC=ParVaultProtocol HARNESS=proof_webdav_auth_decision bash "$V" all > "$WORK/out" 2>&1 && rc=0 || rc=$?
check "all: TLC failure still runs Kani, rc 1, one failure" '[ $rc = 1 ] && grep -q "PASS kani" "$WORK/out" && grep -q "1 FAILURE(S) (all)" "$WORK/out"'

# --- mold: only the test step -----------------------------------------------------------
: > "$FAKE_LOG"
VERIFY_MOLD=1 RUSTFLAGS="-C debuginfo=0" HARNESS=proof_webdav_auth_decision bash "$V" kani > /dev/null 2>&1
check "VERIFY_MOLD=1 + RUSTFLAGS: cargo kani sees RUSTFLAGS unset" 'grep -q "^RUSTFLAGS=<unset> " "$FAKE_LOG"'
: > "$FAKE_LOG"
VERIFY_MOLD=1 bash "$V" test --lib > /dev/null 2>&1
check "VERIFY_MOLD=1: test step links with mold in its own target dir" \
  'grep -q "RUSTFLAGS=-C link-arg=-fuse-ld=mold TARGET=$CARGO_TARGET_DIR-mold ARGS=test --locked --lib" "$FAKE_LOG"'
: > "$FAKE_LOG"
bash "$V" test --lib > /dev/null 2>&1
check "no VERIFY_MOLD: test step has no mold flag, shared target dir" 'grep -q "^RUSTFLAGS=<unset> TARGET=$CARGO_TARGET_DIR ARGS" "$FAKE_LOG"'
PATH="$(echo "$PATH" | sed "s#$WORK/bin:##")" bash -c 'command -v mold' >/dev/null 2>&1 || {
  : > "$FAKE_LOG"
  rm "$WORK/bin/mold"
  VERIFY_MOLD=1 bash "$V" test --lib > "$WORK/out" 2>&1
  check "VERIFY_MOLD=1 without mold: skips with a message" 'grep -q "mold is not installed" "$WORK/out" && grep -q "^RUSTFLAGS=<unset>" "$FAKE_LOG"'
}

echo "test_verify: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
