#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# DSM storage dev nodes: five nodes on localhost, running the production
# binary on the production path (owner ruling #2). Nothing is relaxed for
# development: every node serves TLS under a certificate from a local dev CA,
# pins its peers to that CA, and requires admin and gossip tokens. This script
# generates that material once, under dev-pki/ (never in git), and creates
# each node's database. A database left at another schema version is refused
# by the node (ruling #3); `reset` drops the dev databases so they are created
# fresh.
#
# Usage (from anywhere):
#   start_dev_nodes.sh [start]   generate what is missing, create databases, start
#   start_dev_nodes.sh stop      stop the nodes this script started
#   start_dev_nodes.sh status    health-check every node over verified TLS
#   start_dev_nodes.sh reset     stop, then drop the dev databases

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_DIR="$(cd "$NODE_DIR/.." && pwd)"
cd "$NODE_DIR"

PKI_DIR="dev-pki"
NODES=(1 2 3 4 5)
PG_SERVER="${DSM_DEV_PG_SERVER:-postgresql://localhost:5432}"
BIN="$REPO_DIR/target/release/storage_node"

port_of() { echo $((8079 + $1)); }
db_of() { echo "dsm_storage_node$1"; }

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "error: $1 is required" >&2; exit 1; }
}

# The dev CA, one certificate per node for 127.0.0.1/localhost, and the
# tokens. Existing material is kept, so restarts keep the same identities.
ensure_pki() {
    need openssl
    mkdir -p "$PKI_DIR"
    chmod 700 "$PKI_DIR"
    if [ ! -f "$PKI_DIR/ca.crt" ]; then
        echo "generating the dev CA"
        openssl genrsa -out "$PKI_DIR/ca.key" 4096 2>/dev/null
        openssl req -new -x509 -days 3650 -key "$PKI_DIR/ca.key" \
            -subj "/CN=DSM dev storage CA" -out "$PKI_DIR/ca.crt"
    fi
    for n in "${NODES[@]}"; do
        if [ ! -f "$PKI_DIR/node$n.crt" ]; then
            echo "issuing the certificate of dev-node-$n"
            openssl genrsa -out "$PKI_DIR/node$n.key" 2048 2>/dev/null
            openssl req -new -key "$PKI_DIR/node$n.key" \
                -subj "/CN=dev-node-$n" -out "$PKI_DIR/node$n.csr"
            printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n' \
                > "$PKI_DIR/node$n.ext"
            openssl x509 -req -days 825 -in "$PKI_DIR/node$n.csr" \
                -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial \
                -extfile "$PKI_DIR/node$n.ext" -out "$PKI_DIR/node$n.crt" 2>/dev/null
            rm -f "$PKI_DIR/node$n.csr" "$PKI_DIR/node$n.ext"
        fi
    done
    chmod 600 "$PKI_DIR"/*.key
    for t in admin gossip; do
        if [ ! -f "$PKI_DIR/$t.token" ]; then
            openssl rand -base64 33 | tr -d '\n/+=' > "$PKI_DIR/$t.token"
            chmod 600 "$PKI_DIR/$t.token"
        fi
    done
}

ensure_databases() {
    need psql
    for n in "${NODES[@]}"; do
        local db
        db="$(db_of "$n")"
        if ! psql "$PG_SERVER/postgres" -Atc "SELECT 1 FROM pg_database WHERE datname = '$db'" | grep -q 1; then
            echo "creating database $db"
            psql "$PG_SERVER/postgres" -qc "CREATE DATABASE $db"
        fi
    done
}

ensure_binary() {
    if [ ! -x "$BIN" ]; then
        echo "building the release storage_node"
        (cd "$REPO_DIR" && cargo build --release --locked -p dsm_storage_node)
    fi
}

healthy() {
    curl -fsS --cacert "$PKI_DIR/ca.crt" --connect-timeout 2 --max-time 5 \
        "https://127.0.0.1:$(port_of "$1")/api/v2/health" >/dev/null 2>&1
}

start() {
    ensure_pki
    ensure_databases
    ensure_binary
    mkdir -p logs
    local failed=0
    for n in "${NODES[@]}"; do
        if healthy "$n"; then
            echo "dev-node-$n already serving on :$(port_of "$n")"
            continue
        fi
        DSM_ADMIN_TOKEN="$(cat "$PKI_DIR/admin.token")" \
        DSM_GOSSIP_TOKEN="$(cat "$PKI_DIR/gossip.token")" \
        RUST_LOG=info nohup "$BIN" --config "config/dev/node$n.toml" \
            > "logs/dev-node$n.log" 2>&1 &
        echo $! > "dev-node$n.pid"
        local up=0
        for _ in $(seq 1 20); do
            sleep 1
            if healthy "$n"; then up=1; break; fi
            kill -0 "$(cat "dev-node$n.pid")" 2>/dev/null || break
        done
        if [ "$up" = 1 ]; then
            echo "dev-node-$n serving on https://127.0.0.1:$(port_of "$n")"
        else
            echo "dev-node-$n did not start; see logs/dev-node$n.log" >&2
            failed=1
        fi
    done
    echo "trust anchor for clients: $NODE_DIR/$PKI_DIR/ca.crt"
    return "$failed"
}

stop() {
    for n in "${NODES[@]}"; do
        local pid_file="dev-node$n.pid"
        [ -f "$pid_file" ] || continue
        local pid
        pid="$(cat "$pid_file")"
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo "stopped dev-node-$n (pid $pid)"
        fi
        rm -f "$pid_file"
    done
}

status() {
    local down=0
    for n in "${NODES[@]}"; do
        if healthy "$n"; then
            echo "dev-node-$n healthy on :$(port_of "$n")"
        else
            echo "dev-node-$n not answering on :$(port_of "$n")"
            down=1
        fi
    done
    return "$down"
}

reset() {
    stop
    need psql
    for n in "${NODES[@]}"; do
        psql "$PG_SERVER/postgres" -qc "DROP DATABASE IF EXISTS $(db_of "$n")"
        echo "dropped $(db_of "$n")"
    done
}

case "${1:-start}" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    reset) reset ;;
    *) echo "usage: $0 [start|stop|status|reset]" >&2; exit 2 ;;
esac
