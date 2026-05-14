#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform/gcp"

SSH_KEY="" SSH_PUB_KEY="" GCP_PROJECT="" SKIP_TF=false SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --ssh-pub-key) SSH_PUB_KEY="$2"; shift 2 ;;
        --gcp-project) GCP_PROJECT="$2"; shift 2 ;;
        --skip-terraform) SKIP_TF=true; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "${SSH_KEY}" ] || [ -z "${GCP_PROJECT}" ]; then
    echo "Usage: $0 --ssh-key ~/.ssh/id_ed25519 --gcp-project PROJECT_ID [options]"
    exit 1
fi

[ -z "${SSH_PUB_KEY}" ] && SSH_PUB_KEY="${SSH_KEY}.pub"
[ ! -f "${SSH_PUB_KEY}" ] && echo "ERROR: SSH public key not found at ${SSH_PUB_KEY}" && exit 1
PUB_KEY_CONTENT="$(cat "${SSH_PUB_KEY}")"

echo "=============================================="
echo " DSM Storage Node Multi-Region Deployment (GCP)"
echo "=============================================="
echo "  Project:    ${GCP_PROJECT}"
echo "  Regions:    us-east1, europe-west1, asia-southeast1"
echo "  Nodes:      6 total (2 per region)"
echo "  SSH key:    ${SSH_KEY}"
echo ""

if [ "${SKIP_TF}" = false ]; then
    echo "==> [1/5] Provisioning VMs via Terraform..."
    cd "${TERRAFORM_DIR}"
    terraform init -input=false
    terraform apply -input=false -auto-approve \
        -var="gcp_project=${GCP_PROJECT}" \
        -var="ssh_public_key=${PUB_KEY_CONTENT}"
    cd "${SCRIPT_DIR}"
else
    echo "==> [1/5] Skipping Terraform (--skip-terraform)"
fi

echo "==> [2/5] Extracting node IPs..."
cd "${TERRAFORM_DIR}"
IPS_JSON=$(terraform output -json all_node_ips)
cd "${SCRIPT_DIR}"
IPS=$(echo "${IPS_JSON}" | python3 -c "import sys,json; print(' '.join(json.load(sys.stdin)))")
IPS_ARRAY=(${IPS})
N="${#IPS_ARRAY[@]}"
for i in $(seq 0 $((N - 1))); do echo "      node-$((i + 1)): ${IPS_ARRAY[$i]}"; done

echo "==> [3/5] Waiting for SSH readiness..."
MAX_WAIT=300
for IP in "${IPS_ARRAY[@]}"; do
    ELAPSED=0; printf "    Waiting for %s..." "${IP}"
    while ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
          -i "${SSH_KEY}" "ubuntu@${IP}" "test -f /opt/dsm-storage/.bootstrap-done" 2>/dev/null; do
        sleep 5; ELAPSED=$((ELAPSED + 5))
        [ "${ELAPSED}" -ge "${MAX_WAIT}" ] && echo " TIMEOUT" && exit 1
        printf "."
    done
    echo " ready"
done

echo "==> [4/5] Generating configs and deploying..."
"${SCRIPT_DIR}/generate_node_configs.sh" ${IPS}
BUILD_FLAG=""; [ "${SKIP_BUILD}" = true ] && BUILD_FLAG="--skip-build"
"${SCRIPT_DIR}/push_and_start.sh" ${IPS} --ssh-key "${SSH_KEY}" ${BUILD_FLAG}

echo "==> [5/5] Health check..."
sleep 10
"${SCRIPT_DIR}/check_nodes.sh" ${IPS}

echo ""
echo "=============================================="
echo " GCP Deployment Complete"
echo "=============================================="
echo "Node IPs: ${IPS}"
echo "SSH:      ssh -i ${SSH_KEY} ubuntu@${IPS_ARRAY[0]}"
echo "Teardown: ./teardown_gcp.sh --ssh-key ${SSH_KEY} --gcp-project ${GCP_PROJECT}"
