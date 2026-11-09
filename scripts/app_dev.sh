#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# A DSM account on this machine, run by dsm-app-host against the developer's
# own storage set (scripts/dev_net.sh): your application's account ("app"),
# or the terminal dev wallet ("wallet"). Each is one real DSM identity on the
# same SDK path a phone runs.
#
# Under .dsm-dev/<name>/ (never in git):
#   data/                   the account's state, sealed seed and RECOVERY_MNEMONIC
#   ingress/ingress-token   this launch's ingress secret (only your server reads it)
#   ingress-url             the address the ingress listens on
#   relay-url               the address wallets reach the relay on
#   host.log, host.pid
#
# Usage:
#   scripts/app_dev.sh up <app|wallet>
#   scripts/app_dev.sh down <app|wallet>
#   scripts/app_dev.sh status <app|wallet>
#
# The relay listens on 127.0.0.1 only. A phone reaches it
# through `adb reverse` (Android, make phones-local) or directly (the
# iOS Simulator). Its certificate names 127.0.0.1, so the connect code
# names https://127.0.0.1:8443.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_BIN="$REPO/target/release/dsm-app-host"
NET="$REPO/.dsm-dev/net"

ports_of() {
    case "$1" in
        app) echo "8787 8443" ;;
        wallet) echo "8788 8444" ;;
        *) echo "usage: $0 up|down|status app|wallet" >&2; exit 2 ;;
    esac
}

NAME="${2:-app}"
read -r INGRESS_PORT RELAY_PORT <<<"$(ports_of "$NAME")"
DIR="$REPO/.dsm-dev/$NAME"
INGRESS_URL="http://127.0.0.1:$INGRESS_PORT"
RELAY_URL="https://127.0.0.1:$RELAY_PORT"

ready() {
    local secret
    [ -s "$DIR/ingress/ingress-token" ] || return 1
    secret="$(cat "$DIR/ingress/ingress-token")"
    curl -fsS --max-time 5 -H "Authorization: Bearer $secret" \
        "$INGRESS_URL/activity/0" >/dev/null 2>&1
}

running() {
    [ -f "$DIR/host.pid" ] && kill -0 "$(cat "$DIR/host.pid")" 2>/dev/null
}

up() {
    "$REPO/scripts/dev_net.sh" up
    echo "[app-dev] building dsm-app-host (release)"
    (cd "$REPO" && cargo build --release --locked -p dsm-app-host)
    if running && ready; then
        echo "[app-dev] $NAME already running"
        show
        return 0
    fi
    mkdir -p "$DIR/data" "$DIR/ingress"
    chmod 700 "$DIR/data" "$DIR/ingress"
    rm -f "$DIR/ingress/ingress-token"
    echo "$INGRESS_URL" >"$DIR/ingress-url"
    echo "$RELAY_URL" >"$DIR/relay-url"
    RUST_LOG=info nohup "$HOST_BIN" \
        --data-dir "$DIR/data" \
        --ingress-secret-dir "$DIR/ingress" \
        --env-config "$NET/dsm_env_config.toml" \
        --game-bind "127.0.0.1:$INGRESS_PORT" \
        --relay-bind "127.0.0.1:$RELAY_PORT" \
        --relay-endpoint "$RELAY_URL" \
        --relay-name 127.0.0.1 \
        >"$DIR/host.log" 2>&1 &
    echo $! >"$DIR/host.pid"
    for _ in $(seq 1 240); do
        if ready; then
            show
            return 0
        fi
        if ! running; then
            echo "[app-dev] the $NAME host stopped; its log:" >&2
            tail -30 "$DIR/host.log" >&2
            return 1
        fi
        sleep 0.5
    done
    echo "[app-dev] the $NAME host did not answer in two minutes; its log is $DIR/host.log" >&2
    return 1
}

show() {
    echo "[app-dev] $NAME account running"
    echo "  ingress:        $INGRESS_URL   (your server calls this)"
    echo "  ingress secret: $DIR/ingress/ingress-token"
    echo "  relay:          $RELAY_URL   (wallets reach this)"
    echo "  recovery:       $DIR/data/RECOVERY_MNEMONIC"
    echo "  log:            $DIR/host.log"
}

down() {
    if running; then
        kill "$(cat "$DIR/host.pid")"
        echo "[app-dev] stopped the $NAME host"
    fi
    rm -f "$DIR/host.pid"
}

status() {
    if running && ready; then
        show
    else
        echo "[app-dev] the $NAME host is not running: make app-dev"
        return 1
    fi
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    *) echo "usage: $0 up|down|status app|wallet" >&2; exit 2 ;;
esac
