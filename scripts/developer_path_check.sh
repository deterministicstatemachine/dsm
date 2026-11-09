#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The developer path end to end, exactly as BUILDING_APPS.md and the
# walkthrough videos show it, against real local storage nodes:
#
#   make app-dev        your app's account (and the local set), funded
#   make dev-wallet     a player's wallet in the terminal, funded
#   make dev-wallet2    a second player's, for the match
#   make starter        the Connect starter app, here in the background
#   examples/connect-starter test: the code the starter's page shows is the
#     code it runs, every piece, in TypeScript and in Python, against the real
#     clients (src/shown-code.test.ts)
#   examples/connect-starter check: every helper once, through the starter's
#     own HTTP API on one side and the terminal wallets on the other: connect,
#     send inside and over the grant, prove what is owned, sign in, issue and
#     give an item, open a vault and trade, referee a match, disconnect
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
        for log in "$STARTER_LOG" .dsm-dev/app/host.log .dsm-dev/wallet/host.log .dsm-dev/wallet2/host.log; do
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
make --no-print-directory dev-wallet2

(cd examples/connect-starter && npm ci --no-audit --no-fund && npm run build)
echo "[developer-path] the code the starter's page shows is the code it runs:"
(cd examples/connect-starter && DEVELOPER_PATH_PYTHON="$PYTHON" npm test)
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
