#!/usr/bin/env bash
# Verify one of the two inputs to the CANONICAL STORAGE SET id across the two
# layers that must name it identically: the member names. Read-only: it opens
# a TLS connection to each node and reads the certificate subject. Nothing is
# written, deployed or restarted.
#
#   ./verify_storage_set_alignment.sh ../../dsm_client/frontend/public/dsm_env_config.toml IP1 IP2 IP3 IP4 IP5
#
# WHY THIS EXISTS. A client derives the storage_set_id every vault is born
# under from the (`[[nodes]] name`, register incarnation) pairs of its env
# config, and takes a member's answer only when that node echoes the same name
# back as x-dsm-node-id. A node answers with its own `[node] id`. If the two
# name lists differ by even one character, the client's set id is one no
# member serves: no answer it reads is taken as a member's, so no write of its
# becomes final and no vault is ever born. That failure is silent at deploy
# time and only appears on a device.
#
# The member ids are compared directly rather than re-deriving the set id here:
# equal name lists are necessary, and a second hash implementation in bash
# would be one more thing that can drift from the Rust one. The register
# incarnations, the id's other input, are checked by each node at startup
# (a configured incarnation that is not the one in its database refuses to
# start) and by the bundled-config test in dsm_sdk::sdk::storage_set.
#
# The node's `[node] id` is the CN of the certificate it serves (both come from
# NODE_ID in generate_node_configs.sh), which is what makes this checkable from
# outside without shell access to the fleet.
set -uo pipefail

CONFIG="${1:?usage: $0 <client-env-config.toml> IP1 [IP2 ...]}"
shift
[ "$#" -ge 1 ] || { echo "usage: $0 <client-env-config.toml> IP1 [IP2 ...]"; exit 1; }
IPS=("$@")

[ -f "$CONFIG" ] || { echo "FAIL: no such config: $CONFIG"; exit 1; }

# --- the client's view: the [[nodes]] name entries, in file order ---
CLIENT_IDS="$(awk '/^\[\[nodes\]\]/{n=1;next} n&&/^name *=/{gsub(/.*= *"|" *$/,"");print;n=0}' "$CONFIG")"
CLIENT_N="$(printf '%s\n' "$CLIENT_IDS" | grep -c . || true)"

# --- the fleet's view: each node's certificate CN ---
NODE_IDS=""
UNREACHABLE=0
for ip in "${IPS[@]}"; do
    cn="$(timeout 12 openssl s_client -connect "$ip:8080" -servername "$ip" </dev/null 2>/dev/null \
          | openssl x509 -noout -subject 2>/dev/null \
          | sed -n 's/.*CN *= *\([^,]*\).*/\1/p' | tr -d ' \r')"
    if [ -z "$cn" ]; then
        echo "UNREACHABLE  $ip — cannot read its certificate; alignment UNKNOWN, not OK"
        UNREACHABLE=$((UNREACHABLE+1))
        continue
    fi
    printf "  %-18s node id = %s\n" "$ip" "$cn"
    NODE_IDS="${NODE_IDS}${cn}\n"
done

echo
echo "client config : $CONFIG (${CLIENT_N} members)"
printf '%s\n' "$CLIENT_IDS" | sed 's/^/  /'

if [ "$UNREACHABLE" -gt 0 ]; then
    echo
    echo "FAIL: ${UNREACHABLE} node(s) unreachable — refusing to report alignment on a partial fleet."
    exit 1
fi

LEFT="$(printf '%s\n' "$CLIENT_IDS" | grep . | sort)"
RIGHT="$(printf "%b" "$NODE_IDS" | grep . | sort)"

if [ "$LEFT" = "$RIGHT" ]; then
    echo
    echo "OK: both layers name the same ${CLIENT_N}-member set."
    exit 0
fi

echo
echo "FAIL: the client and the fleet do NOT name the same set."
echo "  only in the client config:"; comm -23 <(echo "$LEFT") <(echo "$RIGHT") | sed 's/^/    /'
echo "  only on the fleet:";        comm -13 <(echo "$LEFT") <(echo "$RIGHT") | sed 's/^/    /'
echo
echo "Fix the CLIENT config to match the nodes: the node id is baked into each"
echo "TLS certificate, so renaming nodes means reissuing certs and redeploying,"
echo "while the client's name field carries no other meaning."
exit 1
