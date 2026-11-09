#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The developer path end to end, exactly as BUILDING_APPS.md and the
# walkthrough videos show it, against real local storage nodes:
#
#   make app-dev        your app's account (and the local set), funded
#   make dev-wallet     a player's wallet in the terminal, funded
#   make starter        the Connect starter app, here in the background
#   examples/connect-starter check: connect, pay inside and over the grant,
#     prove holdings, disconnect (the starter's own HTTP API on one side, the
#     terminal wallet on the other)
#   the Python client's example, against the same account
#
# CI runs this (the developer-path job); so can you. Everything it starts it
# stops, unless DEVELOPER_PATH_KEEP is set.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
STARTER_LOG="$REPO/.dsm-dev/starter.log"
PYTHON="${DEVELOPER_PATH_PYTHON:-python3}"
starter_pid=""

stop_all() {
    local code=$?
    if [ -n "$starter_pid" ]; then kill "$starter_pid" 2>/dev/null || :; fi
    if [ -z "${DEVELOPER_PATH_KEEP:-}" ]; then
        make --no-print-directory dev-down || :
    fi
    if [ "$code" != 0 ]; then
        echo "[developer-path] logs:" >&2
        for log in "$STARTER_LOG" .dsm-dev/app/host.log .dsm-dev/wallet/host.log; do
            if [ -f "$log" ]; then
                echo "--- $log" >&2
                tail -40 "$log" >&2
            fi
        done
    fi
    exit "$code"
}
trap stop_all EXIT

make --no-print-directory app-dev
make --no-print-directory dev-wallet

(cd examples/connect-starter && npm ci --no-audit --no-fund && npm run build)
mkdir -p .dsm-dev
node examples/connect-starter/dist/server.js >"$STARTER_LOG" 2>&1 &
starter_pid=$!
for _ in $(seq 1 60); do
    if curl -fsS --max-time 5 http://127.0.0.1:3000/api/state >/dev/null 2>&1; then break; fi
    kill -0 "$starter_pid" 2>/dev/null || { echo "[developer-path] the starter stopped" >&2; exit 1; }
    sleep 0.5
done

node examples/connect-starter/dist/check.js

echo "[developer-path] the Python client, against the same account:"
PYTHONPATH="$REPO/clients/python" "$PYTHON" clients/python/examples/account_status.py
