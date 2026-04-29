#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform/gcp"
SSH_KEY="" GCP_PROJECT="" FORCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --gcp-project) GCP_PROJECT="$2"; shift 2 ;;
        --force) FORCE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[ -z "${GCP_PROJECT}" ] && echo "Usage: $0 --ssh-key KEY --gcp-project ID [--force]" && exit 1

echo "==> [1/2] Stopping containers..."
if [ "${FORCE}" = false ] && [ -n "${SSH_KEY}" ]; then
    cd "${TERRAFORM_DIR}"
    IPS=$(terraform output -json all_node_ips 2>/dev/null | python3 -c "import sys,json; print(' '.join(json.load(sys.stdin)))" 2>/dev/null || echo "")
    cd "${SCRIPT_DIR}"
    for IP in ${IPS}; do
        printf "  %s... " "${IP}"
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes -i "${SSH_KEY}" "ubuntu@${IP}" \
            "cd /opt/dsm-storage && docker compose -f docker-compose.node.yml down 2>/dev/null" 2>/dev/null && echo "done" || echo "skipped"
    done
fi

echo "==> [2/2] Destroying GCP infrastructure..."
cd "${TERRAFORM_DIR}"
[ ! -f "terraform.tfstate" ] && echo "No state found." && exit 0
terraform destroy -auto-approve -var="gcp_project=${GCP_PROJECT}" -var="ssh_public_key=teardown"
echo "Teardown complete."
