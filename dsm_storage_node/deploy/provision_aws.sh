#!/usr/bin/env bash
# DSM Storage Nodes — Multi-Region AWS Provisioning
#
# Provisions 6 EC2 instances across 3 AWS regions (us-east-1, eu-west-1,
# ap-southeast-1), generates per-node configs, builds + deploys the Docker
# image, and verifies health.
#
# Prerequisites:
#   1. Terraform >= 1.5 installed
#   2. AWS credentials configured (aws configure, env vars, or IAM role)
#   3. SSH key pair (will be passed to Terraform)
#   4. Docker installed locally (for building the image)
#
# Usage:
#   ./provision_aws.sh --ssh-key ~/.ssh/id_ed25519
#
# Options:
#   --ssh-key PATH        SSH private key path (required)
#   --ssh-pub-key PATH    SSH public key path (default: ${ssh-key}.pub)
#   --skip-terraform       Skip Terraform, use existing instances
#   --skip-build           Skip Docker image build
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform/aws"

SSH_KEY=""
SSH_PUB_KEY=""
SKIP_TF=false
SKIP_BUILD=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --ssh-pub-key) SSH_PUB_KEY="$2"; shift 2 ;;
        --skip-terraform) SKIP_TF=true; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "${SSH_KEY}" ]; then
    echo "Usage: $0 --ssh-key ~/.ssh/id_ed25519 [options]"
    echo ""
    echo "Options:"
    echo "  --ssh-key PATH        SSH private key path (required)"
    echo "  --ssh-pub-key PATH    SSH public key path (default: \${ssh-key}.pub)"
    echo "  --skip-terraform       Skip Terraform provisioning"
    echo "  --skip-build           Skip Docker image build"
    exit 1
fi

# Derive public key path if not specified
if [ -z "${SSH_PUB_KEY}" ]; then
    SSH_PUB_KEY="${SSH_KEY}.pub"
fi

if [ ! -f "${SSH_PUB_KEY}" ]; then
    echo "ERROR: SSH public key not found at ${SSH_PUB_KEY}"
    exit 1
fi

PUB_KEY_CONTENT="$(cat "${SSH_PUB_KEY}")"

echo "=============================================="
echo " DSM Storage Node Multi-Region Deployment"
echo "=============================================="
echo "  Regions:    us-east-1, eu-west-1, ap-southeast-1"
echo "  Nodes:      6 total (2 per region)"
echo "  SSH key:    ${SSH_KEY}"
echo "  Terraform:  $(${SKIP_TF} && echo "SKIP" || echo "YES")"
echo ""

# --- Step 1: Terraform ---
if [ "${SKIP_TF}" = false ]; then
    echo "==> [1/5] Provisioning EC2 instances across 3 regions via Terraform..."
    cd "${TERRAFORM_DIR}"

    terraform init -input=false

    terraform apply -input=false -auto-approve \
        -var="ssh_public_key=${PUB_KEY_CONTENT}"

    cd "${SCRIPT_DIR}"
else
    echo "==> [1/5] Skipping Terraform (--skip-terraform)"
fi

# --- Step 2: Extract IPs ---
echo "==> [2/5] Extracting node IP addresses from all regions..."
cd "${TERRAFORM_DIR}"
IPS_JSON=$(terraform output -json all_node_ips)
cd "${SCRIPT_DIR}"

# Convert JSON array to space-separated string
IPS=$(echo "${IPS_JSON}" | python3 -c "import sys,json; print(' '.join(json.load(sys.stdin)))")
IPS_ARRAY=(${IPS})
N="${#IPS_ARRAY[@]}"

echo "    ${N} nodes:"
for i in $(seq 0 $((N - 1))); do
    echo "      node-$((i + 1)): ${IPS_ARRAY[$i]}"
done

# --- Step 3: Wait for SSH readiness ---
echo "==> [3/5] Waiting for instances to accept SSH (may take 1-3 min across regions)..."
MAX_WAIT=300

for IP in "${IPS_ARRAY[@]}"; do
    ELAPSED=0
    printf "    Waiting for %s..." "${IP}"
    while ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
          -i "${SSH_KEY}" "ubuntu@${IP}" "test -f /opt/dsm-storage/.bootstrap-done" 2>/dev/null; do
        sleep 5
        ELAPSED=$((ELAPSED + 5))
        if [ "${ELAPSED}" -ge "${MAX_WAIT}" ]; then
            echo " TIMEOUT"
            echo "ERROR: Instance ${IP} not ready after ${MAX_WAIT}s"
            exit 1
        fi
        printf "."
    done
    echo " ready"
done

# --- Step 4: Generate configs and deploy ---
echo "==> [4/5] Generating configs and deploying..."

# Generate per-node bundles (TLS certs, config, .env)
"${SCRIPT_DIR}/generate_node_configs.sh" ${IPS}

# Build, push, and start
BUILD_FLAG=""
if [ "${SKIP_BUILD}" = true ]; then
    BUILD_FLAG="--skip-build"
fi
"${SCRIPT_DIR}/push_and_start.sh" ${IPS} --ssh-key "${SSH_KEY}" ${BUILD_FLAG}

# --- Step 5: Final health check ---
echo "==> [5/5] Final health verification..."
sleep 10
"${SCRIPT_DIR}/check_nodes.sh" ${IPS}

echo ""
echo "=============================================="
echo " Multi-Region Deployment Complete"
echo "=============================================="
echo ""
echo "Node IPs: ${IPS}"
echo ""
echo "Useful commands:"
echo "  Check health:  ./check_nodes.sh ${IPS}"
echo "  SSH to node 1: ssh -i ${SSH_KEY} ubuntu@${IPS_ARRAY[0]}"
echo "  Tear down:     ./teardown_aws.sh --ssh-key ${SSH_KEY}"
echo ""
echo "Cost: ~\$90/month for 6x t3.small across 3 regions."
echo "Run ./teardown_aws.sh to stop billing when done."
echo ""
