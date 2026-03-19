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

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 IP1 IP2 [IP3 ... IPN]"
    echo "  Generates per-node deploy bundles for DSM storage nodes."
    echo "  Minimum 2 nodes; recommended 6 for N=6 K=3 replication."
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
    DB_URL="postgresql://dsm:${PG_PASS}@postgres:5432/dsm_storage"
    sed -e "s|__NODE_ID__|${NODE_ID}|g" \
        -e "s|__LISTEN_ADDR__|0.0.0.0|g" \
        -e "s|__PORT__|8080|g" \
        -e "s|__DATABASE_URL__|${DB_URL}|g" \
        -e "s|# peers = .*|peers = [${PEERS}]|g" \
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
