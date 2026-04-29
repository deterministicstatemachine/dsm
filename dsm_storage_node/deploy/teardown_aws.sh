#!/usr/bin/env bash
# DSM Storage Nodes — Multi-Region AWS Teardown
#
# Stops Docker containers on each node, then destroys all Terraform-managed
# AWS resources across all 3 regions. Run this to stop billing.
#
# Usage:
#   ./teardown_aws.sh --ssh-key ~/.ssh/id_ed25519
#
# Options:
#   --ssh-key PATH    SSH private key (required for graceful container stop)
#   --force           Skip graceful stop, just destroy infrastructure
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform/aws"

SSH_KEY=""
FORCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --force) FORCE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=============================================="
echo " DSM Storage Node Multi-Region Teardown"
echo "=============================================="

# --- Step 1: Graceful container shutdown ---
if [ "${FORCE}" = false ] && [ -n "${SSH_KEY}" ]; then
    echo "==> [1/2] Stopping Docker containers on each node..."

    cd "${TERRAFORM_DIR}"
    IPS_JSON=$(terraform output -json all_node_ips 2>/dev/null || echo "[]")
    cd "${SCRIPT_DIR}"

    IPS=$(echo "${IPS_JSON}" | python3 -c "import sys,json; ips=json.load(sys.stdin); print(' '.join(ips) if ips else '')" 2>/dev/null || echo "")

    if [ -n "${IPS}" ]; then
        for IP in ${IPS}; do
            printf "  Stopping %s... " "${IP}"
            ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
                -i "${SSH_KEY}" "ubuntu@${IP}" \
                "cd /opt/dsm-storage && docker compose -f docker-compose.node.yml down 2>/dev/null" \
                2>/dev/null && echo "done" || echo "skipped (unreachable)"
        done
    else
        echo "  No node IPs found in Terraform state (may already be destroyed)"
    fi
else
    if [ "${FORCE}" = true ]; then
        echo "==> [1/2] Skipping graceful stop (--force)"
    else
        echo "==> [1/2] Skipping graceful stop (no --ssh-key provided)"
    fi
fi

# --- Step 2: Destroy Terraform resources across all regions ---
echo "==> [2/2] Destroying AWS infrastructure across all regions..."
cd "${TERRAFORM_DIR}"

if [ ! -f "terraform.tfstate" ]; then
    echo "  No Terraform state found. Nothing to destroy."
    exit 0
fi

# Need ssh_public_key for destroy (Terraform validates all variables)
# Use a dummy value since we're destroying
terraform destroy -auto-approve \
    -var="ssh_public_key=teardown-placeholder" \
    2>&1

echo ""
echo "=============================================="
echo " Teardown Complete — All AWS resources destroyed"
echo "=============================================="
echo ""
echo " All EC2 instances, security groups, and key pairs across"
echo " us-east-1, eu-west-1, and ap-southeast-1 have been removed."
echo " No further AWS charges will accrue for these resources."
