#!/usr/bin/env bash
# DSM Storage Node — Health Check
#
# Polls /api/v2/health on each node.
#
# Usage:
#   ./check_nodes.sh IP1 IP2 IP3 IP4 IP5 IP6
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 IP1 [IP2 ... IPN]"
    exit 1
fi

IPS=("$@")
N="${#IPS[@]}"
HEALTHY=0
UNHEALTHY=0

echo "DSM Storage Node Health Check (${N} nodes)"
echo "=============================================="

for i in $(seq 1 "${N}"); do
    IDX=$((i - 1))
    IP="${IPS[$IDX]}"
    printf "  node-%-2d @ %-16s " "${i}" "${IP}"

    # Health endpoint
    HTTP_CODE=$(curl -sf --insecure -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${IP}:8080/api/v2/health" 2>/dev/null || echo "000")

    if [ "${HTTP_CODE}" = "200" ]; then
        echo "[OK]   HTTP 200"
        HEALTHY=$((HEALTHY + 1))
    else
        echo "[FAIL] HTTP ${HTTP_CODE}"
        UNHEALTHY=$((UNHEALTHY + 1))
    fi
done

echo ""
echo "Summary: ${HEALTHY}/${N} healthy, ${UNHEALTHY}/${N} unreachable"

if [ "${UNHEALTHY}" -gt 0 ]; then
    exit 1
fi
