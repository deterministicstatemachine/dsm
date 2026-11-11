#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# A DSM account on this machine, run by dsm-app-host: your application's
# account ("app"), or a terminal dev wallet ("wallet", and "wallet2" for a
# second player). Each is one real DSM identity on the same SDK path a phone
# runs.
#
# The accounts live on one storage set, chosen when the first of them is made
# and recorded in .dsm-dev/set (asked for; else the recorded one; else local
# when a set of your own is prepared here, make nodes-up; else beta):
#   beta    the beta network's hosted set, the one the wallet ships configured
#           for (dsm_client/frontend/public/dsm_env_config.toml). Nothing to
#           run but the host; the default.
#   local   a storage set of your own: five nodes on this machine
#           (scripts/dev_net.sh; needs PostgreSQL).
# An account exists only on the set it was made on, so changing sets means
# `make dev-reset` (forget the accounts) first.
#
# Under .dsm-dev/<name>/ (never in git):
#   data/                   the account's state, sealed seed and RECOVERY_MNEMONIC
#   ingress/ingress-token   this launch's ingress secret (only your server reads it)
#   ingress-url             the address the ingress listens on
#   relay-url               the address wallets reach the relay on
#   host.log, host.pid
#
# Usage:
#   scripts/app_dev.sh up <app|wallet|wallet2> [beta|local]
#   scripts/app_dev.sh down <app|wallet|wallet2>
#   scripts/app_dev.sh status <app|wallet|wallet2>
#   scripts/app_dev.sh reset        forget every account here (and the local set, if that is where they were)
#
# The relay listens on 127.0.0.1 only. A phone reaches it
# through `adb reverse` (Android, make phones-local) or directly (the
# iOS Simulator). Its certificate names 127.0.0.1, so the connect code
# names https://127.0.0.1:8443.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_BIN="$REPO/target/release/dsm-app-host"
NET="$REPO/.dsm-dev/net"
SET_FILE="$REPO/.dsm-dev/set"
BETA_ENV="$REPO/dsm_client/frontend/public/dsm_env_config.toml"
LOCAL_ENV="$NET/dsm_env_config.toml"

ports_of() {
    case "$1" in
        app) echo "8787 8443" ;;
        wallet) echo "8788 8444" ;;
        wallet2) echo "8789 8445" ;;
        *) echo "usage: $0 up|down|status app|wallet|wallet2 [beta|local] | reset" >&2; exit 2 ;;
    esac
}

NAME="${2:-app}"
read -r INGRESS_PORT RELAY_PORT <<<"$(ports_of "$NAME")"
DIR="$REPO/.dsm-dev/$NAME"
INGRESS_URL="http://127.0.0.1:$INGRESS_PORT"
RELAY_URL="https://127.0.0.1:$RELAY_PORT"

recorded_set() {
    [ -f "$SET_FILE" ] && cat "$SET_FILE" || :
}

describe_set() {
    case "$1" in
        beta) echo "the beta network (hosted; $BETA_ENV)" ;;
        local) echo "your local set ($LOCAL_ENV)" ;;
    esac
}

# The set this account goes on: the one asked for, which must agree with the
# one already recorded for this machine's accounts; else the recorded one;
# else local when a set of your own is already prepared here; else beta.
choose_set() {
    local asked="${1:-}" recorded
    case "$asked" in
        "" | beta | local) ;;
        *) echo "usage: $0 up app|wallet|wallet2 [beta|local]" >&2; exit 2 ;;
    esac
    recorded="$(recorded_set)"
    if [ -n "$recorded" ] && [ -n "$asked" ] && [ "$asked" != "$recorded" ]; then
        echo "[app-dev] the accounts on this machine are on $(describe_set "$recorded")," >&2
        echo "          and an account exists only on the set it was made on." >&2
        if [ "$recorded" = local ]; then
            echo "          make app-dev-local keeps using them; make dev-reset forgets them, then make app-dev makes new ones on the beta network." >&2
        else
            echo "          make app-dev keeps using them; make dev-reset forgets them, then make app-dev-local makes new ones on a set of your own." >&2
        fi
        exit 1
    fi
    if [ -n "$recorded" ]; then
        SET="$recorded"
    elif [ -n "$asked" ]; then
        SET="$asked"
    elif [ -f "$LOCAL_ENV" ]; then
        SET=local
    else
        SET=beta
    fi
}

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
    choose_set "${1:-}"
    local env_config
    if [ "$SET" = local ]; then
        "$REPO/scripts/dev_net.sh" up
        env_config="$LOCAL_ENV"
    else
        env_config="$BETA_ENV"
    fi
    echo "[app-dev] building dsm-app-host (release)"
    (cd "$REPO" && cargo build --release --locked -p dsm-app-host)
    if running && ready; then
        echo "[app-dev] $NAME already running"
        show
        return 0
    fi
    mkdir -p "$DIR/data" "$DIR/ingress"
    chmod 700 "$DIR/data" "$DIR/ingress"
    echo "$SET" >"$SET_FILE"
    rm -f "$DIR/ingress/ingress-token"
    echo "$INGRESS_URL" >"$DIR/ingress-url"
    echo "$RELAY_URL" >"$DIR/relay-url"
    RUST_LOG=info nohup "$HOST_BIN" \
        --data-dir "$DIR/data" \
        --ingress-secret-dir "$DIR/ingress" \
        --env-config "$env_config" \
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
    echo "  storage set:    $(describe_set "$(recorded_set)")"
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

# Forget every account made on this machine. Accounts on the local set go
# with the set (dev_net.sh reset drops its databases too).
reset() {
    local name
    if [ "$(recorded_set)" = local ]; then
        "$REPO/scripts/dev_net.sh" reset
    else
        for name in app wallet wallet2; do
            if [ -d "$REPO/.dsm-dev/$name" ]; then
                "$0" down "$name"
                rm -rf "${REPO:?}/.dsm-dev/$name"
                echo "[app-dev] removed the $name account"
            fi
        done
    fi
    rm -f "$SET_FILE"
    echo "[app-dev] forgot the accounts; the next make app-dev (or app-dev-local) makes new ones"
}

case "${1:-}" in
    up) up "${3:-}" ;;
    down) down ;;
    status) status ;;
    reset) reset ;;
    *) echo "usage: $0 up|down|status app|wallet|wallet2 [beta|local] | reset" >&2; exit 2 ;;
esac
