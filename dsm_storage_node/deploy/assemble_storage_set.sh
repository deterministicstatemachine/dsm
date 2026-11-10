#!/usr/bin/env bash
# DSM Storage Node — phase 2 of the two-phase bring-up (config/production.toml).
#
# Every node was deployed with no `[storage_set]` and minted its register
# incarnation into its own database at first boot. This script reads each
# node's logged incarnation, writes the full member list (id, incarnation,
# endpoint, and the CA each member is known by) into EVERY node's config,
# restarts the nodes, and checks that all of them log the same storage set id.
# It prints the members and that id: pin them in dsm::economic::register,
# dsm_sdk::sdk::storage_set and the bundled client env config
# (frontend/public/dsm_env_config.toml), whose `[[nodes]]` entries carry the
# same `ca_cert`.
#
# Usage:
#   ./assemble_storage_set.sh --ssh-key ~/.ssh/dsm-deploy --ca-file deploy/nodes/ca/ca.crt \
#       IP1 IP2 IP3 IP4 IP5
#
# Node i is `dsm-node-i` at IPi (the order generate_node_configs.sh used), and
# every member's certificate chains to the one CA in --ca-file: this is the
# fleet one operator runs. A node whose configured incarnation is not the one
# in its database refuses to start, so a wrong value here is loud, never silent.
set -euo pipefail

SSH_KEY="" SSH_USER="ubuntu" CA_FILE=""
IPS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --ssh-user) SSH_USER="$2"; shift 2 ;;
        --ca-file) CA_FILE="$2"; shift 2 ;;
        *) IPS+=("$1"); shift ;;
    esac
done
N="${#IPS[@]}"
{ [ "${N}" -ge 2 ] && [ -n "${CA_FILE}" ]; } || { sed -n 2,21p "$0"; exit 1; }
[ -f "${CA_FILE}" ] || { echo "ERROR: --ca-file ${CA_FILE} not found"; exit 1; }
CA_PEM="$(openssl x509 -in "${CA_FILE}" 2>/dev/null)" || { echo "ERROR: ${CA_FILE} is not a certificate"; exit 1; }

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)
[ -n "${SSH_KEY}" ] && SSH_OPTS+=(-i "${SSH_KEY}")
remote() { ssh "${SSH_OPTS[@]}" "${SSH_USER}@$1" "$2"; }

REMOTE_DIR=/opt/dsm-storage
CONTAINER=dsm-storage-storage-node-1   # compose project `dsm-storage` (the directory), service storage-node

echo "==> Collecting incarnations"
declare -a INC
for i in $(seq 1 "${N}"); do
    IP="${IPS[$((i - 1))]}"
    ID="dsm-node-${i}"
    VALUE=""
    for _ in $(seq 1 40); do
        VALUE="$(remote "${IP}" "docker logs ${CONTAINER} 2>&1 | grep -a 'register incarnation for node ${ID}: ' | tail -1" \
                 | grep -aoE '[0-9A-Z]{52}' | tail -1)"
        [ -n "${VALUE}" ] && break
        sleep 3
    done
    [ -n "${VALUE}" ] || { echo "ERROR: ${ID} @ ${IP} logged no incarnation"; remote "${IP}" "docker logs --tail 30 ${CONTAINER}"; exit 1; }
    INC[$i]="${VALUE}"
    echo "    ${ID} ${VALUE}"
done

MEMBERS=$'\n[storage_set]\n'
for i in $(seq 1 "${N}"); do
    MEMBERS+=$'\n[[storage_set.members]]\n'
    MEMBERS+="id = \"dsm-node-${i}\""$'\n'
    MEMBERS+="register_incarnation = \"${INC[$i]}\""$'\n'
    MEMBERS+="endpoint = \"https://${IPS[$((i - 1))]}:8080\""$'\n'
    MEMBERS+='ca_cert = """'$'\n'"${CA_PEM}"$'\n'
    MEMBERS+='"""'$'\n'
done

echo "==> Writing the member list into every node config and restarting"
for i in $(seq 1 "${N}"); do
    IP="${IPS[$((i - 1))]}"
    remote "${IP}" "set -e; cd ${REMOTE_DIR}
        if sudo grep -q '^\[storage_set\]' config/node.toml; then echo 'ERROR: dsm-node-${i} already has a storage set configured'; exit 1; fi
        sudo cp config/node.toml config/node.toml.phase1
        printf '%s' '${MEMBERS}' | sudo tee -a config/node.toml > /dev/null
        docker compose -f docker-compose.node.yml restart storage-node > /dev/null"
    echo "    dsm-node-${i} restarted"
done

echo "==> Checking every member logs the same set id"
sleep 15
SET_ID=""
for i in $(seq 1 "${N}"); do
    IP="${IPS[$((i - 1))]}"
    LOGGED=""
    for _ in $(seq 1 20); do
        LOGGED="$(remote "${IP}" "docker logs ${CONTAINER} 2>&1 | grep -a 'storage set configured' | tail -1" | grep -aoE 'id=[0-9A-Z]{52}' | cut -d= -f2)"
        [ -n "${LOGGED}" ] && break
        sleep 3
    done
    [ -n "${LOGGED}" ] || { echo "ERROR: dsm-node-${i} logged no set id"; remote "${IP}" "docker logs --tail 30 ${CONTAINER}"; exit 1; }
    [ -z "${SET_ID}" ] && SET_ID="${LOGGED}"
    [ "${LOGGED}" = "${SET_ID}" ] || { echo "ERROR: dsm-node-${i} logged ${LOGGED}, others ${SET_ID}"; exit 1; }
    HTTP="$(curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 5 "https://${IP}:8080/api/v2/health")"
    echo "    dsm-node-${i} set id ${LOGGED} health ${HTTP}"
done

echo ""
echo "STORAGE SET ASSEMBLED: ${N} members, id ${SET_ID}"
for i in $(seq 1 "${N}"); do echo "  dsm-node-${i} ${INC[$i]} https://${IPS[$((i - 1))]}:8080"; done
echo "Pin these in dsm::economic::register, dsm_sdk::sdk::storage_set and the client env config,"
echo "whose [[nodes]] entries carry this CA as each member's ca_cert."
