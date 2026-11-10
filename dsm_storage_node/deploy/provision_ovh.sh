#!/usr/bin/env bash
# DSM Storage Node: the beta fleet on OVHcloud Public Cloud (OpenStack).
#
# Creates the instances (terraform/ovh), waits for their bootstrap, generates
# the per-node bundles and deploys the image, then checks every node's health.
# Afterwards the two-phase bring-up applies as for every fleet: collect each
# node's logged register incarnation, write the member list into every node
# config and the client env config, restart (config/production.toml).
#
# Usage:
#   ./provision_ovh.sh --ssh-key ~/.ssh/dsm_fleet --ssh-cidr 1.2.3.4/32 \
#       [--openrc ~/.config/openstack/dsm-ovh-openrc.sh] \
#       [--password-file ~/.config/openstack/dsm-ovh.password] \
#       [--ca-dir path/to/ca] [--skip-terraform] [--skip-build] [--image-tar PATH]
#
# The OpenStack RC file is the one the OVHcloud panel offers for the project's
# OpenStack user. It reads the password from its standard input, so it is
# sourced with --password-file (mode 0600) as that input: nothing is typed and
# nothing is printed. --ca-dir reuses an existing fleet CA so clients that
# bundle it keep trusting the nodes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform/ovh"

SSH_KEY="" SSH_PUB_KEY="" SSH_CIDR="" CA_DIR="" IMAGE_TAR=""
OPENRC="${HOME}/.config/openstack/dsm-ovh-openrc.sh"
PASSWORD_FILE="${HOME}/.config/openstack/dsm-ovh.password"
SKIP_TF=0 SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --ssh-pub-key) SSH_PUB_KEY="$2"; shift 2 ;;
        --ssh-cidr) SSH_CIDR="$2"; shift 2 ;;
        --openrc) OPENRC="$2"; shift 2 ;;
        --password-file) PASSWORD_FILE="$2"; shift 2 ;;
        --ca-dir) CA_DIR="$2"; shift 2 ;;
        --image-tar) IMAGE_TAR="$2"; shift 2 ;;
        --skip-terraform) SKIP_TF=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "${SSH_KEY}" ] || { [ "${SKIP_TF}" -eq 0 ] && [ -z "${SSH_CIDR}" ]; }; then
    sed -n 2,20p "$0"
    exit 1
fi

[ -z "${SSH_PUB_KEY}" ] && SSH_PUB_KEY="${SSH_KEY}.pub"
[ -f "${SSH_PUB_KEY}" ] || { echo "ERROR: SSH public key not found at ${SSH_PUB_KEY}"; exit 1; }
[ -f "${OPENRC}" ] || { echo "ERROR: OpenStack RC file not found at ${OPENRC}"; exit 1; }
[ -f "${PASSWORD_FILE}" ] || { echo "ERROR: password file not found at ${PASSWORD_FILE}"; exit 1; }
PUB_KEY_CONTENT="$(cat "${SSH_PUB_KEY}")"

# shellcheck disable=SC1090
source "${OPENRC}" < "${PASSWORD_FILE}"
# The panel's RC file names the region family (BHS); the OpenStack endpoints
# carry the numbered region (BHS5), which terraform/ovh/variables.tf defaults.
unset OS_REGION_NAME

echo "=============================================="
echo " DSM Storage Node Deployment (OVHcloud)"
echo "=============================================="
echo "  Tenant:     ${OS_TENANT_NAME:-${OS_PROJECT_NAME:-?}}"
echo "  Nodes:      5 (quorum 3 of 5)"
echo "  SSH key:    ${SSH_KEY}"
echo ""

if [ "${SKIP_TF}" -eq 0 ]; then
    echo "==> [1/5] Provisioning instances via Terraform..."
    cd "${TERRAFORM_DIR}"
    terraform init -input=false
    # Terraform shows its plan and asks before it applies anything: the
    # nodes' databases live on their instances, so no apply goes through unread.
    terraform apply \
        -var="ssh_public_key=${PUB_KEY_CONTENT}" \
        -var="allowed_ssh_cidr=${SSH_CIDR}"
    cd "${SCRIPT_DIR}"
else
    echo "==> [1/5] Skipping Terraform (--skip-terraform)"
fi

echo "==> [2/5] Extracting node IPs..."
cd "${TERRAFORM_DIR}"
IPS_JSON=$(terraform output -json all_node_ips)
cd "${SCRIPT_DIR}"
IPS=$(echo "${IPS_JSON}" | python3 -c "import sys,json; print(' '.join(json.load(sys.stdin)))")
read -r -a IPS_ARRAY <<< "${IPS}"
N="${#IPS_ARRAY[@]}"
for i in $(seq 0 $((N - 1))); do echo "      node-$((i + 1)): ${IPS_ARRAY[$i]}"; done

echo "==> [3/5] Waiting for SSH readiness..."
MAX_WAIT=600
for IP in "${IPS_ARRAY[@]}"; do
    ELAPSED=0; printf "    Waiting for %s..." "${IP}"
    while ! ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o BatchMode=yes \
          -i "${SSH_KEY}" "ubuntu@${IP}" "test -f /opt/dsm-storage/.bootstrap-done" 2>/dev/null; do
        sleep 5; ELAPSED=$((ELAPSED + 5))
        [ "${ELAPSED}" -ge "${MAX_WAIT}" ] && echo " TIMEOUT" && exit 1
        printf "."
    done
    echo " ready"
done

echo "==> [4/5] Generating configs and deploying..."
GEN_ARGS=()
[ -n "${CA_DIR}" ] && GEN_ARGS+=(--ca-dir "${CA_DIR}")
"${SCRIPT_DIR}/generate_node_configs.sh" "${GEN_ARGS[@]+"${GEN_ARGS[@]}"}" ${IPS}
PUSH_ARGS=(--ssh-key "${SSH_KEY}")
[ "${SKIP_BUILD}" -eq 1 ] && PUSH_ARGS+=(--skip-build)
[ -n "${IMAGE_TAR}" ] && PUSH_ARGS+=(--image-tar "${IMAGE_TAR}")
"${SCRIPT_DIR}/push_and_start.sh" ${IPS} "${PUSH_ARGS[@]}"

echo "==> [5/5] Health check..."
sleep 10
"${SCRIPT_DIR}/check_nodes.sh" ${IPS}

echo ""
echo "=============================================="
echo " OVHcloud Deployment Complete (phase 1)"
echo "=============================================="
echo "Node IPs: ${IPS}"
echo "SSH:      ssh -i ${SSH_KEY} ubuntu@${IPS_ARRAY[0]}"
echo "Next:     collect each node's logged register incarnation, write the"
echo "          member list into every node config and the client env config,"
echo "          restart (config/production.toml, two-phase bring-up)."
