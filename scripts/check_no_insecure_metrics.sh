#!/usr/bin/env bash
# Fails closed if a binary carries the debug-only unauthenticated metrics listener (v0.5.4,
# docs/METRICS.md, feature `lab-insecure-metrics`).
#
#   scripts/check_no_insecure_metrics.sh [--marker-only] <bin>...
#
# 1. Marker scan (every file, mandatory): the listener sends PARVAULT-LAB-INSECURE-METRICS-v1 as
#    a response header and logs it at start, so the bytes are in any binary that has it, after
#    LTO, opt-level "z" and strip.
# 2. Exec check (where the file runs on this host, unless --marker-only): `--version --verbose`
#    must print `debug_assertions: off` and a `features:` line without lab-insecure-metrics.
#    Where it cannot run (a cross target without qemu-user) the script says so and relies on the
#    marker scan.
# Exit 0: every file scanned, nothing found. 1: a finding. 2: a file is missing or unreadable,
# or no check ran.
set -uo pipefail

MARKER="PARVAULT-LAB-INSECURE-METRICS-v1"
marker_only=0
files=()
for a in "$@"; do
  case "$a" in
    --marker-only) marker_only=1 ;;
    -*) echo "check_no_insecure_metrics: unknown option $a" >&2; exit 2 ;;
    *) files+=("$a") ;;
  esac
done
if [[ ${#files[@]} -eq 0 ]]; then
  echo "check_no_insecure_metrics: no files given" >&2
  exit 2
fi

found=0
scanned=0
for f in "${files[@]}"; do
  if [[ ! -f "$f" || ! -r "$f" ]]; then
    echo "check_no_insecure_metrics: $f: missing or unreadable" >&2
    exit 2
  fi
  if LC_ALL=C grep -aqF "$MARKER" "$f"; then
    echo "FAIL marker: $f carries $MARKER (the debug insecure metrics listener)"
    found=1
  else
    echo "ok   marker: $f"
  fi
  scanned=$((scanned + 1))

  if [[ $marker_only -eq 1 ]]; then
    echo "exec-check: skipped ($f: --marker-only)"
    continue
  fi
  if [[ ! -x "$f" ]]; then
    echo "exec-check: skipped ($f: not executable on this host)"
    continue
  fi
  out="$("$f" --version --verbose 2>/dev/null)"
  rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "exec-check: skipped ($f: not executable on this host, rc=$rc)"
    continue
  fi
  da="$(printf '%s\n' "$out" | sed -n 's/^debug_assertions: //p')"
  feats="$(printf '%s\n' "$out" | sed -n 's/^features: //p')"
  if [[ -z "$da" || -z "$feats" ]]; then
    echo "FAIL exec: $f: --version --verbose lacks the debug_assertions or features line"
    found=1
  elif [[ "$da" != "off" ]]; then
    echo "FAIL exec: $f: debug_assertions: $da"
    found=1
  elif [[ ",$feats," == *",lab-insecure-metrics,"* ]]; then
    echo "FAIL exec: $f: features: $feats"
    found=1
  else
    echo "ok   exec:   $f (debug_assertions: off, features: $feats)"
  fi
done

if [[ $scanned -ne ${#files[@]} ]]; then
  echo "check_no_insecure_metrics: not every file was scanned" >&2
  exit 2
fi
exit "$found"
