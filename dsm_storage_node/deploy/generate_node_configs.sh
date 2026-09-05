#!/usr/bin/env bash
# DSM Storage Node — Per-Node Config Generator
#
# Generates per-node deploy bundles for N EC2 instances.
#
# Usage:
#   ./generate_node_configs.sh IP1 IP2 IP3 IP4 IP5 IP6
#
# Output:
#   deploy/nodes/node-{1..N}/
#     ├── .env                     (PostgreSQL credentials)
#     ├── config/node.toml         (node-specific config)
#     ├── certs/ca.crt             (shared CA certificate)
#     ├── certs/node.crt           (per-node TLS cert)
#     ├── certs/node.key           (per-node TLS key)
#     └── docker-compose.node.yml  (copied from deploy/)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/../config/production.toml"
COMPOSE_SRC="${SCRIPT_DIR}/docker-compose.node.yml"
OUT_DIR="${SCRIPT_DIR}/nodes"

FORCE=0
ARGS=()
for a in "$@"; do
    case "$a" in
        --force) FORCE=1 ;;
        *) ARGS+=("$a") ;;
    esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 [--force] IP1 IP2 [IP3 ... IPN]"
    echo "  Generates per-node deploy bundles for DSM storage nodes."
    echo "  Minimum 2 nodes; recommended 6 for N=6 K=3 replication."
    echo "  --force: overwrite an existing bundle directory (see the warning below)."
    exit 1
fi

# THIS SCRIPT MINTS A NEW CA AND DELETES THE OLD ONE.
#
# The CA private key exists in exactly one place — ${OUT_DIR}/ca/ca.key. It is
# not in git (only the public cert is, as scripts/ca.crt) and it cannot be
# reconstructed. Deleting it means the deployed fleet's certificates can never
# be reissued or extended: every node must be redeployed with a new CA, and
# every client CA bundle re-pushed, before anything can talk to anything.
#
# Running this to LOOK at the output would therefore destroy the running
# fleet's deployment material. So an existing bundle directory is never
# clobbered silently.
if [ -e "${OUT_DIR}" ] && [ "${FORCE}" -ne 1 ]; then
    echo "REFUSING: ${OUT_DIR} already exists."
    echo
    echo "  Regenerating replaces the CA (private key NOT recoverable — not in git),"
    echo "  every per-node key, and any saved image tar in that directory."
    echo "  The live fleet's certs chain to the CA that is there now."
    echo
    echo "  To inspect what would be generated, copy the directory aside first."
    echo "  To genuinely re-issue the fleet's identity, re-run with --force and be"
    echo "  ready to redeploy EVERY node and re-push the client CA bundle."
    exit 1
fi

IPS=("$@")
N="${#IPS[@]}"
echo "Generating config for ${N} nodes: ${IPS[*]}"

# Clean output
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

# ----- Generate Self-Signed TLS CA -----
CA_DIR="${OUT_DIR}/ca"
mkdir -p "${CA_DIR}"

echo "Generating CA key and certificate..."
openssl genrsa -out "${CA_DIR}/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key "${CA_DIR}/ca.key" \
    -subj "/C=XX/O=DSM/CN=DSM-Storage-CA" \
    -out "${CA_DIR}/ca.crt" 2>/dev/null

# Generate a random PostgreSQL password (shared across all nodes for simplicity)
PG_PASS="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"

# ----- The canonical storage set: PHASE 1 LEAVES IT UNSET -----
# A set member is `(id, register_incarnation)`, and the incarnation is minted by
# the node itself on first boot into its own database — never derivable from the
# node id or its keys, because a node that kept its key but lost its register
# must come back as a DIFFERENT member. This generator therefore cannot know the
# member list, and inventing one would produce a fleet whose configured
# incarnations no node actually holds; every node would refuse to start.
#
# So these bundles ship with `[storage_set]` commented out (register INACTIVE,
# every claim refused — the correct state for a fleet that has not agreed on a
# set yet). Boot them, collect each node's logged
# `register incarnation for node <id>: <Base32-Crockford>`, write the full member
# list into every node config AND the client env config, then restart.
echo "Storage set: NOT configured by this generator (phase 1)."
echo "  Boot the fleet, collect each node's logged register incarnation, then"
echo "  write [[storage_set.members]] into every node config and restart."

# ----- Per-Node Bundles -----
for i in $(seq 1 "${N}"); do
    IDX=$((i - 1))
    IP="${IPS[$IDX]}"
    NODE_ID="dsm-node-${i}"
    NODE_DIR="${OUT_DIR}/node-${i}"

    echo "  [${i}/${N}] ${NODE_ID} @ ${IP}"
    mkdir -p "${NODE_DIR}/config" "${NODE_DIR}/certs"

    # --- TLS cert for this node ---
    openssl genrsa -out "${NODE_DIR}/certs/node.key" 2048 2>/dev/null
    openssl req -new -key "${NODE_DIR}/certs/node.key" \
        -subj "/C=XX/O=DSM/CN=${NODE_ID}" \
        -addext "subjectAltName=IP:${IP},DNS:${NODE_ID}" \
        -out "${NODE_DIR}/certs/node.csr" 2>/dev/null

    # Sign with CA (SAN extension)
    cat > "${NODE_DIR}/certs/ext.cnf" <<EXTEOF
subjectAltName=IP:${IP},DNS:${NODE_ID}
EXTEOF
    openssl x509 -req -days 3650 \
        -in "${NODE_DIR}/certs/node.csr" \
        -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" -CAcreateserial \
        -extfile "${NODE_DIR}/certs/ext.cnf" \
        -out "${NODE_DIR}/certs/node.crt" 2>/dev/null
    rm -f "${NODE_DIR}/certs/node.csr" "${NODE_DIR}/certs/ext.cnf"
    cp "${CA_DIR}/ca.crt" "${NODE_DIR}/certs/ca.crt"
    chmod 600 "${NODE_DIR}/certs/node.key"

    # --- Build peer list (all nodes except self) ---
    PEERS=""
    for j in $(seq 1 "${N}"); do
        if [ "${j}" -ne "${i}" ]; then
            PEER_IP="${IPS[$((j - 1))]}"
            if [ -n "${PEERS}" ]; then
                PEERS="${PEERS}, "
            fi
            PEERS="${PEERS}\"https://${PEER_IP}:8080\""
        fi
    done

    # --- Node config from template ---
    DB_URL="postgresql://postgres:5432/dsm_storage?user=dsm&password=${PG_PASS}"
    # Escape '&' in DB_URL so sed doesn't interpret it as backreference
    DB_URL_ESCAPED="${DB_URL//&/\\&}"
    sed -e "s|__NODE_ID__|${NODE_ID}|g" \
        -e "s|__LISTEN_ADDR__|0.0.0.0|g" \
        -e "s|__PORT__|8080|g" \
        -e "s|__DATABASE_URL__|${DB_URL_ESCAPED}|g" \
        -e "s|peers = .*|peers = [${PEERS}]|g" \
        "${TEMPLATE}" > "${NODE_DIR}/config/node.toml"

    # --- .env for docker-compose ---
    cat > "${NODE_DIR}/.env" <<ENVEOF
POSTGRES_DB=dsm_storage
POSTGRES_USER=dsm
POSTGRES_PASSWORD=${PG_PASS}
DSM_PORT=8080
DSM_METRICS_PORT=9090
RUST_LOG=info
ENVEOF

    # --- docker-compose ---
    cp "${COMPOSE_SRC}" "${NODE_DIR}/docker-compose.node.yml"
done

echo ""
echo "Node bundles generated in: ${OUT_DIR}/"
echo "  Nodes: ${N}"
echo "  CA cert: ${CA_DIR}/ca.crt"
echo "  PG password: ${PG_PASS}"
echo ""
echo "Next: run deploy/push_and_start.sh to deploy to EC2 instances."
