#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Does a clean install point at storage nodes that actually exist, with a CA for
# each that actually validates it?
#
# It shipped not doing so. The packaged config listed six GCP nodes that were
# dead, and the packaged CA shared its subject name with the live CA
# (CN=DSM-Storage-CA) while carrying a DIFFERENT KEY — so it looked right in
# every human check and failed every real handshake. A freshly installed wallet
# could not publish a CPTA policy at all; the wizard hung on "Publishing
# policy…" until it gave up.
#
# Subject names are not identity. This verifies the CA the config names for each
# member against the certificate fetched live from that member, and that the
# certificate names it, which is the only check that would have caught it.
#
# Usage: scripts/verify_shipped_storage_config.sh
# Exit 0 = a clean install can reach its fleet.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$REPO/dsm_client/frontend/public/dsm_env_config.toml"
TIMEOUT="${DSM_VERIFY_TIMEOUT:-15}"

fail=0
note() { printf '  %-52s %s\n' "$1" "$2"; }
bad()  { fail=1; note "$1" "FAIL — $2"; }

echo "Packaged storage configuration"
echo "  config: ${CONFIG#"$REPO"/}"
echo

[[ -f "$CONFIG" ]] || { echo "missing $CONFIG"; exit 2; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# Each member's name and endpoint, one per line, and its CA in a file of its own.
members=$(python3 - "$CONFIG" "$tmp" <<'PY_MEMBERS'
import pathlib, sys, tomllib
config = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
for node in config.get("nodes", []):
    if "ca_cert" in node:
        pathlib.Path(sys.argv[2], node["name"] + ".ca.pem").write_text(node["ca_cert"])
    print(node["name"], node["endpoint"])
PY_MEMBERS
) || { echo "could not read $CONFIG"; exit 2; }

if [[ -z "$members" ]]; then
  echo "no [[nodes]] endpoints configured"; exit 1
fi

echo "Nodes"
n=0
while read -r name ep; do
  [[ -z "$ep" ]] && continue
  n=$((n + 1))
  CA="$tmp/$name.ca.pem"
  if [[ ! -f "$CA" ]]; then
    bad "$name CA" "the config names no ca_cert for it"
    continue
  fi
  if ! openssl x509 -in "$CA" -noout -checkend 0 >/dev/null 2>&1; then
    bad "$name CA" "its CA has expired, or is not a certificate"
  fi
  hostport=${ep#*://}

  # Reachable at all? Any HTTP status proves a server answered; 401 is a
  # perfectly good answer from a node that wants auth.
  code=$(curl -sk --max-time "$TIMEOUT" -o /dev/null -w '%{http_code}' "$ep/api/v1/health" 2>/dev/null)
  if [[ -z "$code" || "$code" == "000" ]]; then
    bad "$hostport reachable" "no response within ${TIMEOUT}s"
    continue
  fi
  note "$hostport reachable" "HTTP $code"

  # The check that matters: does the CA we SHIP for this member validate the
  # cert it actually presents right now, and does that cert name it?
  if ! echo | timeout "$TIMEOUT" openssl s_client -connect "$hostport" 2>/dev/null \
       | openssl x509 -outform PEM > "$tmp/node.pem" 2>/dev/null || [[ ! -s "$tmp/node.pem" ]]; then
    bad "$hostport certificate" "could not retrieve a certificate"
    continue
  fi
  if openssl verify -CAfile "$CA" -verify_hostname "$name" "$tmp/node.pem" >/dev/null 2>&1; then
    note "$hostport is $name, validated by its CA" "OK"
  else
    bad "$hostport is $name, validated by its CA" \
        "$(openssl verify -CAfile "$CA" -verify_hostname "$name" "$tmp/node.pem" 2>&1 | tail -1 | sed 's/.*: //')"
  fi
done <<< "$members"

echo
if [[ $fail -eq 0 ]]; then
  echo "PASS — $n configured node(s) reachable and validated by their packaged CAs."
else
  echo "FAIL — a clean install would not be able to reach its storage fleet."
  echo "       Promote the intended fleet's config into"
  echo "       dsm_client/frontend/public/ before releasing."
fi
exit $fail
