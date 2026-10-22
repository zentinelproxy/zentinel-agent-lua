#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request.
#
# With scripts/smoke/block-admin.lua loaded:
#   * the v2 handshake works and an ordinary request is forwarded (200) with
#     the header the script adds;
#   * /admin and paths under it get 403 and never reach the upstream, while
#     /administrator and /public are forwarded;
#   * with the agent stopped the ordinary request is refused.

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}
SCRIPT="$(cd "$(dirname "$0")" && pwd)/smoke/block-admin.lua"

python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name lua \
    --agent-arg=--script --agent-arg "$SCRIPT" \
    --clean '{"name": "ordinary request", "path": "/smoke", "upstream_headers": {"X-Lua-Smoke": "1"}}' \
    --case '{"name": "/admin blocked", "path": "/admin", "expect": 403}' \
    --case '{"name": "/admin/users blocked", "path": "/admin/users?id=1", "expect": 403}' \
    --case '{"name": "/administrator allowed", "path": "/administrator", "expect": 200}' \
    --case '{"name": "/public allowed", "path": "/public/index.html", "expect": 200}'
