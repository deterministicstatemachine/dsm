#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# A developer's own storage set on this machine: the network's pinned register
# members as five storage nodes, each the production binary on its own Postgres
# database, served over TLS from a CA of this set's own (owner ruling #2:
# nothing is relaxed for development). `dsm-dev-net prepare` sets each node up
# as the SDK's test harness does: its database already holds its member's
# pinned register incarnation, and its certificate names its member.
#
# Everything lives under .dsm-dev/net/ (never in git):
#   dsm_env_config.toml                the client config: wallets and app hosts use it
#   dsm-node-N.toml/.crt/.key          each node's config and TLS
#   dsm-node-N-ca.pem                  each node's own CA (inline in both configs too)
#   logs/, run/                        each node's log and pid
#
# Usage:
#   scripts/dev_net.sh up       prepare the set if it is new, then start every node
#   scripts/dev_net.sh down     stop every node
#   scripts/dev_net.sh status   every node's health over verified TLS
#   scripts/dev_net.sh reset    stop, drop every node's database, forget the set and
#                               the accounts made on it (.dsm-dev/app, .dsm-dev/wallet)
#
# DSM_DEV_PG_URL names the Postgres server's administrative database. The
# default is this login's role on the server at localhost: over Debian/Ubuntu's
# socket where there is one, else TCP port 5432 (Homebrew's). The server must
# run with fsync=on and full_page_writes=on: a node refuses one that cannot
# keep an acknowledgement.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="$REPO/.dsm-dev/net"
# The default server: this login's role on the server at localhost. Where
# Debian/Ubuntu's PostgreSQL has its socket, that is the way in: it takes the
# login name there (peer authentication) and wants a password over TCP. The
# login name is `id -un`, not $USER, which a container, sudo or cron shell may
# not set.
pg_default() {
    local login
    login="$(id -un)"
    if [ -S /var/run/postgresql/.s.PGSQL.5432 ]; then
        echo "postgresql://$login@/postgres?host=/var/run/postgresql&sslmode=disable"
    else
        echo "postgresql://$login@localhost:5432/postgres?sslmode=disable"
    fi
}
PG_URL="${DSM_DEV_PG_URL:-$(pg_default)}"
FIRST_PORT=8080
NODE_BIN="$REPO/target/release/storage_node"
DEV_NET_BIN="$REPO/target/release/dsm-dev-net"

build() {
    echo "[dev-net] building the storage node and dsm-dev-net (release)"
    (cd "$REPO" && cargo build --release --locked -p dsm_storage_node -p dsm-dev-net)
}

members() {
    local config
    for config in "$NET"/dsm-node-*.toml; do
        basename "$config" .toml
    done
}

port_of() {
    sed -n 's/^port = \([0-9][0-9]*\)$/\1/p' "$NET/$1.toml"
}

healthy() {
    curl -fsS --cacert "$NET/$1-ca.pem" --connect-timeout 2 --max-time 5 \
        "https://127.0.0.1:$(port_of "$1")/api/v2/health" >/dev/null 2>&1
}

up() {
    build
    if [ ! -f "$NET/dsm_env_config.toml" ]; then
        "$DEV_NET_BIN" prepare --dir "$NET" --pg "$PG_URL" --first-port "$FIRST_PORT"
    fi
    mkdir -p "$NET/logs" "$NET/run"
    local failed=0 member up_now
    for member in $(members); do
        if healthy "$member"; then
            echo "[dev-net] $member already serving on :$(port_of "$member")"
            continue
        fi
        RUST_LOG=info nohup "$NODE_BIN" --config "$NET/$member.toml" \
            >"$NET/logs/$member.log" 2>&1 &
        echo $! >"$NET/run/$member.pid"
        up_now=0
        for _ in $(seq 1 40); do
            sleep 0.5
            if healthy "$member"; then up_now=1; break; fi
            kill -0 "$(cat "$NET/run/$member.pid")" 2>/dev/null || break
        done
        if [ "$up_now" = 1 ]; then
            echo "[dev-net] $member serving on https://127.0.0.1:$(port_of "$member")"
        else
            echo "[dev-net] $member did not start; its log:" >&2
            tail -20 "$NET/logs/$member.log" >&2
            failed=1
        fi
    done
    echo "[dev-net] client config: $NET/dsm_env_config.toml"
    return "$failed"
}

down() {
    local pidfile
    for pidfile in "$NET"/run/*.pid; do
        [ -f "$pidfile" ] || continue
        if kill "$(cat "$pidfile")" 2>/dev/null; then
            echo "[dev-net] stopped $(basename "$pidfile" .pid)"
        fi
        rm -f "$pidfile"
    done
}

status() {
    if [ ! -f "$NET/dsm_env_config.toml" ]; then
        echo "[dev-net] no set prepared: make nodes-up"
        return 1
    fi
    local failed=0 member
    for member in $(members); do
        if healthy "$member"; then
            echo "[dev-net] $member healthy on https://127.0.0.1:$(port_of "$member")"
        else
            echo "[dev-net] $member NOT serving on :$(port_of "$member")"
            failed=1
        fi
    done
    return "$failed"
}

reset() {
    # Accounts made on this set (scripts/app_dev.sh) exist only on it: they go
    # with it.
    local name
    for name in app wallet wallet2; do
        if [ -d "$REPO/.dsm-dev/$name" ]; then
            "$REPO/scripts/app_dev.sh" down "$name"
            rm -rf "${REPO:?}/.dsm-dev/$name"
            echo "[dev-net] removed the $name account made on this set"
        fi
    done
    down
    build
    "$DEV_NET_BIN" drop --pg "$PG_URL"
    rm -rf "$NET"
    echo "[dev-net] forgot the set; the next up prepares a new one"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    reset) reset ;;
    *) echo "usage: $0 up|down|status|reset" >&2; exit 2 ;;
esac
