#!/usr/bin/env bash
# L-34 docs-commands gate (plan-7 section 3). See scripts/doc_commands.py for the annotations.
# Usage: scripts/doc_commands.sh extract | check | run <dir-with-release-binaries>
set -euo pipefail
exec python3 "$(dirname "$0")/doc_commands.py" "$@"
