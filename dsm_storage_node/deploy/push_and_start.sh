#!/usr/bin/env bash
# DSM Storage Node — Deploy to EC2 Instances
#
# Builds the Docker image, pushes node bundles to each EC2 instance,
# and starts docker compose on each.
#
# Prerequisites:
#   1. Run generate_node_configs.sh first to create node bundles
#   2. SSH key access to all EC2 instances (ssh-agent or ~/.ssh/config)
#   3. Docker installed on each EC2 instance
#
# Usage:
#   ./push_and_start.sh IP1 IP2 IP3 IP4 IP5 IP6 [--ssh-user ubuntu] [--ssh-key path/to/key]
#
# Options:
#   --ssh-user USER   SSH username (default: ubuntu)
#   --ssh-key  PATH   SSH private key path (default: uses ssh-agent)
#   --skip-build      Skip Docker image build (use existing image)
#   --image-tar PATH  Use a pre-built image tar instead of building
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODES_DIR="${SCRIPT_DIR}/nodes"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DOCKERFILE="${SCRIPT_DIR}/../Dockerfile.cloud"

SSH_USER="ubuntu"
SSH_KEY=""
SKIP_BUILD=false
IMAGE_TAR=""

# Parse IPs and flags
IPS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-user) SSH_USER="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --image-tar) IMAGE_TAR="$2"; shift 2 ;;
        *) IPS+=("$1"); shift ;;
    esac
done

N="${#IPS[@]}"
if [ "${N}" -lt 1 ]; then
    echo "Usage: $0 IP1 IP2 ... [--ssh-user ubuntu] [--ssh-key key]"
    exit 1
fi

# SSH options
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
if [ -n "${SSH_KEY}" ]; then
    SSH_OPTS="${SSH_OPTS} -i ${SSH_KEY}"
fi

# --- Step 1: Build Docker image ---
if [ "${SKIP_BUILD}" = false ] && [ -z "${IMAGE_TAR}" ]; then
    echo "==> Building Docker image..."
    docker build --platform linux/amd64 -f "${DOCKERFILE}" -t dsm-storage-node:latest "${WORKSPACE_ROOT}"
    echo "==> Saving image to tar..."
    IMAGE_TAR="${NODES_DIR}/dsm-storage-node.tar"
    docker save dsm-storage-node:latest -o "${IMAGE_TAR}"
    echo "    Image saved: ${IMAGE_TAR} ($(du -h "${IMAGE_TAR}" | cut -f1))"
fi

if [ -z "${IMAGE_TAR}" ]; then
    IMAGE_TAR="${NODES_DIR}/dsm-storage-node.tar"
    if [ ! -f "${IMAGE_TAR}" ]; then
        echo "ERROR: No image tar found. Run without --skip-build or provide --image-tar."
        exit 1
    fi
fi

# --- Step 2: Deploy to each node ---
REMOTE_DIR="/opt/dsm-storage"

for i in $(seq 1 "${N}"); do
    IDX=$((i - 1))
    IP="${IPS[$IDX]}"
    NODE_DIR="${NODES_DIR}/node-${i}"

    if [ ! -d "${NODE_DIR}" ]; then
        echo "ERROR: ${NODE_DIR} not found. Run generate_node_configs.sh first."
        exit 1
    fi

    echo ""
    echo "==> [${i}/${N}] Deploying to ${IP} (${SSH_USER}@${IP})"

    # Create remote directory
    # shellcheck disable=SC2086
    ssh ${SSH_OPTS} "${SSH_USER}@${IP}" "sudo mkdir -p ${REMOTE_DIR} && sudo chown ${SSH_USER}:${SSH_USER} ${REMOTE_DIR}"

    # Upload image tar
    echo "    Uploading Docker image..."
    # shellcheck disable=SC2086
    scp ${SSH_OPTS} "${IMAGE_TAR}" "${SSH_USER}@${IP}:${REMOTE_DIR}/dsm-storage-node.tar"

    # Upload node bundle
    echo "    Uploading node bundle..."
    # shellcheck disable=SC2086
    scp ${SSH_OPTS} -r "${NODE_DIR}/config" "${SSH_USER}@${IP}:${REMOTE_DIR}/config"
    # shellcheck disable=SC2086
    scp ${SSH_OPTS} -r "${NODE_DIR}/certs" "${SSH_USER}@${IP}:${REMOTE_DIR}/certs"
    # shellcheck disable=SC2086
    scp ${SSH_OPTS} "${NODE_DIR}/.env" "${SSH_USER}@${IP}:${REMOTE_DIR}/.env"
    # shellcheck disable=SC2086
    scp ${SSH_OPTS} "${NODE_DIR}/docker-compose.node.yml" "${SSH_USER}@${IP}:${REMOTE_DIR}/docker-compose.node.yml"

    # Load image and start
    echo "    Loading Docker image and starting services..."
    # shellcheck disable=SC2086
    ssh ${SSH_OPTS} "${SSH_USER}@${IP}" bash <<REMOTEOF
set -e
cd ${REMOTE_DIR}
docker load -i dsm-storage-node.tar
rm -f dsm-storage-node.tar
chmod 644 certs/node.key
docker compose -f docker-compose.node.yml down 2>/dev/null || true
docker compose -f docker-compose.node.yml up -d
echo "Services started on ${IP}"
REMOTEOF

    echo "    Node ${i} deployed."
done

echo ""
echo "==> All ${N} nodes deployed. Running health checks..."
sleep 5

# --- Step 3: Health check ---
HEALTHY=0
for i in $(seq 1 "${N}"); do
    IDX=$((i - 1))
    IP="${IPS[$IDX]}"
    if curl -sf --insecure --connect-timeout 5 "https://${IP}:8080/api/v2/health" >/dev/null 2>&1; then
        echo "  [OK]   node-${i} @ ${IP}"
        HEALTHY=$((HEALTHY + 1))
    else
        echo "  [WAIT] node-${i} @ ${IP} (may still be starting)"
    fi
done

echo ""
echo "Health: ${HEALTHY}/${N} nodes responding."
if [ "${HEALTHY}" -lt "${N}" ]; then
    echo "Some nodes are still starting. Run: deploy/check_nodes.sh ${IPS[*]}"
fi
