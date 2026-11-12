#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# A built dsm-app-host, smoke-tested before it is packaged: it runs on this
# machine, says its version, refuses what it must, and starts.
#
#   - `--version` names VERSION, and `--help` lists `--network beta`;
#   - an ingress on an address other machines can reach is refused;
#   - a start against a temporary data directory makes a new account (the
#     recovery mnemonic is written) and keeps running while it waits for the
#     network. The start runs offline: it is given the beta network's config
#     with every node's address replaced by a closed local port, so nothing is
#     written to the beta network from a build machine.
#
# usage: scripts/release/smoke_app_host.sh <dsm-app-host> <version>

set -euo pipefail

BIN="$1"
VERSION="$2"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
PID=""
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null || :
    rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '[smoke] %s\n' "$*"; }
fail() { printf '[smoke] FAILED: %s\n' "$*" >&2; exit 1; }

got="$("$BIN" --version)"
[ "$got" = "dsm-app-host $VERSION" ] || fail "--version says '$got', not 'dsm-app-host $VERSION'"
say "--version: $got"

help="$("$BIN" --help)"
case "$help" in *"--network beta"*) ;; *) fail "--help does not list --network beta" ;; esac
say "--help lists --network beta"

if "$BIN" --data-dir "$WORK/r/data" --ingress-secret-dir "$WORK/r/ingress" --network beta \
    --game-bind 0.0.0.0:18787 --relay-bind 127.0.0.1:18443 \
    --relay-endpoint https://127.0.0.1:18443 >"$WORK/refused.log" 2>&1; then
    fail "an ingress on 0.0.0.0 was taken"
fi
grep -q "loopback" "$WORK/refused.log" || fail "the refusal does not say why: $(cat "$WORK/refused.log")"
say "an ingress on 0.0.0.0 is refused"

sed -E 's#endpoint = "https://[^"]+"#endpoint = "https://127.0.0.1:9"#' \
    "$REPO/dsm_client/frontend/public/dsm_env_config.toml" >"$WORK/offline.toml"
grep -q 'https://127.0.0.1:9' "$WORK/offline.toml" || fail "no node address to replace in the beta config"
"$BIN" --data-dir "$WORK/data" --ingress-secret-dir "$WORK/ingress" --env-config "$WORK/offline.toml" \
    --game-bind 127.0.0.1:18787 --relay-bind 127.0.0.1:18443 \
    --relay-endpoint https://127.0.0.1:18443 --relay-name 127.0.0.1 >"$WORK/start.log" 2>&1 &
PID=$!
for _ in $(seq 1 120); do
    grep -q "created this account" "$WORK/start.log" && break
    kill -0 "$PID" 2>/dev/null || { tail -30 "$WORK/start.log" >&2; fail "the host stopped before it made an account"; }
    sleep 0.5
done
grep -q "created this account" "$WORK/start.log" || { tail -30 "$WORK/start.log" >&2; fail "no account within a minute"; }
[ -s "$WORK/data/RECOVERY_MNEMONIC" ] || fail "no recovery mnemonic in the data directory"
sleep 2
kill -0 "$PID" 2>/dev/null || { tail -30 "$WORK/start.log" >&2; fail "the host stopped while waiting for the network"; }
say "started offline: made an account (recovery mnemonic written) and is waiting for the network"
say "passed: $BIN"
