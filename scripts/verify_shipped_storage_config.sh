#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Does a clean install point at storage nodes that actually exist, with a CA
# that actually validates them?
#
# It shipped not doing so. The packaged config listed six GCP nodes that were
# dead, and the packaged ca.crt shared its subject name with the live CA
# (CN=DSM-Storage-CA) while carrying a DIFFERENT KEY — so it looked right in
# every human check and failed every real handshake. A freshly installed wallet
# could not publish a CPTA policy at all; the wizard hung on "Publishing
# policy…" until it gave up.
#
# Subject names are not identity. This verifies the packaged CA against a
# certificate fetched live from each configured node, which is the only check
# that would have caught it.
#
# Usage: scripts/verify_shipped_storage_config.sh
# Exit 0 = a clean install can reach its fleet.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$REPO/dsm_client/frontend/public/dsm_env_config.toml"
CA="$REPO/dsm_client/frontend/public/ca.crt"
TIMEOUT="${DSM_VERIFY_TIMEOUT:-15}"

fail=0
note() { printf '  %-52s %s\n' "$1" "$2"; }
bad()  { fail=1; note "$1" "FAIL — $2"; }

echo "Packaged storage configuration"
echo "  config: ${CONFIG#"$REPO"/}"
echo "  ca:     ${CA#"$REPO"/}"
echo

[[ -f "$CONFIG" ]] || { echo "missing $CONFIG"; exit 2; }
[[ -f "$CA" ]]     || { echo "missing $CA"; exit 2; }

endpoints=$(grep -E '^[[:space:]]*endpoint[[:space:]]*=' "$CONFIG" \
            | sed -E 's/.*"(.*)".*/\1/')

if [[ -z "$endpoints" ]]; then
  echo "no [[nodes]] endpoints configured"; exit 1
fi

echo "CA identity"
note "subject" "$(openssl x509 -in "$CA" -noout -subject 2>/dev/null | sed 's/^subject=//')"
note "expires" "$(openssl x509 -in "$CA" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
if ! openssl x509 -in "$CA" -noout -checkend 0 >/dev/null 2>&1; then
  bad "validity" "the packaged CA has expired"
fi
echo

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

echo "Nodes"
n=0
while read -r ep; do
  [[ -z "$ep" ]] && continue
  n=$((n + 1))
  hostport=${ep#*://}

  # Reachable at all? Any HTTP status proves a server answered; 401 is a
  # perfectly good answer from a node that wants auth.
  code=$(curl -sk --max-time "$TIMEOUT" -o /dev/null -w '%{http_code}' "$ep/api/v1/health" 2>/dev/null)
  if [[ -z "$code" || "$code" == "000" ]]; then
    bad "$hostport reachable" "no response within ${TIMEOUT}s"
    continue
  fi
  note "$hostport reachable" "HTTP $code"

  # The check that matters: does the CA we SHIP validate the cert this node
  # actually presents right now?
  if ! echo | timeout "$TIMEOUT" openssl s_client -connect "$hostport" 2>/dev/null \
       | openssl x509 -outform PEM > "$tmp/node.pem" 2>/dev/null || [[ ! -s "$tmp/node.pem" ]]; then
    bad "$hostport certificate" "could not retrieve a certificate"
    continue
  fi
  if openssl verify -CAfile "$CA" "$tmp/node.pem" >/dev/null 2>&1; then
    note "$hostport validated by packaged CA" "OK"
  else
    bad "$hostport validated by packaged CA" \
        "$(openssl verify -CAfile "$CA" "$tmp/node.pem" 2>&1 | tail -1 | sed 's/.*: //')"
  fi
done <<< "$endpoints"

echo
if [[ $fail -eq 0 ]]; then
  echo "PASS — $n configured node(s) reachable and validated by the packaged CA."
else
  echo "FAIL — a clean install would not be able to reach its storage fleet."
  echo "       Promote the intended fleet's config and CA into"
  echo "       dsm_client/frontend/public/ before releasing."
fi
exit $fail
