#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# TWO-HOP ATOMIC ROUTE SETTLEMENT — fleet-side proof. Needs NO device access (release builds are not
# debuggable), only the storage fleet and a host-built dlv_binding_probe. Read-only.
#
#   ./scripts/two_hop_route_fleet_proof.sh baseline <input_token_b32> <output_token_b32> <outdir>
#   ./scripts/two_hop_route_fleet_proof.sh verify   <input_token_b32> <output_token_b32> <outdir>
#
#   env: DSM_NODES      storage node IPs (default: the five GCP beta nodes)
#        DSM_CA         CA certificate for the self-signed fleet
#        DSM_PROBE      path to a built dlv_binding_probe
#        DSM_PROBE_ENV  env config with an ABSOLUTE custom_ca_certs path, for the probe
#
# Take the baseline after both LP vaults are advertised and before the trader swaps; verify after the
# swap settled and both LPs reconciled. The two vaults are DISCOVERED from the fleet's advertisement
# keys: hop 2 is the one vault whose pair holds the OUTPUT token; hop 1 is the one vault pairing the
# input with hop 2's other asset. Other liquidity on the fleet (other vaults on the input) is ignored.
# Balance deltas (trader: input down, output up, intermediate unchanged; LPs: reserves) are read from
# the devices' own screens and recorded beside this output — this script proves the settlement object:
#
#   binding   on EACH vault exactly one generation newly consumed since the baseline, BOUND_FINAL by a
#             bundle that names that parent, with the SAME tx_id and SAME value digest on both vaults
#             (one binding transaction over both vault keys, one bundle); each frontier FREE
#   receipts  exactly one new vault receipt per vault, both under ONE route commitment X, each
#             readable on a quorum of the storage set
set -uo pipefail
MODE="${1:?baseline|verify}"; IN="${2:?input token (Base32 policy commit)}"; OUTP="${3:?output token (Base32 policy commit)}"; OUT="${4:?outdir}"
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"
NODES="${DSM_NODES:-34.58.75.224 35.254.209.202 146.148.99.141 104.197.96.66 35.184.46.44}"
CA="${DSM_CA:-$ROOT/dsm_client/frontend/public/ca.crt}"
PROBE="${DSM_PROBE:-$ROOT/dsm_client/deterministic_state_machine/target/release/dlv_binding_probe}"
QUORUM=3
mkdir -p "$OUT/$MODE"; PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($3)" || bad "$1 — expected [$3], got [$2]"; }
list(){ for ip in $NODES; do curl -s --cacert "$CA" --max-time 10 "https://$ip:8080/api/v2/object/list?prefix=$1&limit=1000"; done \
          | grep -ao "$1[0-9A-HJKMNP-TV-Z/]*" | sort -u; }
[ -x "$PROBE" ] && [ -n "${DSM_PROBE_ENV:-}" ] || { echo "set DSM_PROBE and DSM_PROBE_ENV"; exit 2; }

echo "== discovering the route's vaults from the fleet ($MODE) =="
list "sofi/vault/" | awk -F/ 'NF==5 && length($5)==52 {print $3, $4, $5}' > "$OUT/$MODE/ads.txt"
ROUTE="$(python3 - "$OUT/$MODE/ads.txt" "$IN" "$OUTP" <<'PY'
import sys
ads = [l.split() for l in open(sys.argv[1]) if l.strip()]
IN, OUTP = sys.argv[2], sys.argv[3]
hop2 = [x for x in ads if OUTP in (x[0], x[1])]
if len(hop2) != 1: print(f"ERR {len(hop2)} advertised vaults hold the output token"); sys.exit()
c, d, v2 = hop2[0]; mid = d if c == OUTP else c
hop1 = [x for x in ads if x[2] != v2 and {x[0], x[1]} == {IN, mid}]
if len(hop1) != 1: print(f"ERR {len(hop1)} advertised vaults pair the input with the intermediate"); sys.exit()
a, b, v1 = hop1[0]
print(v1, a, b, v2, c, d, mid, OUTP)
PY
)"
case "$ROUTE" in ERR*|"") bad "route discovery: ${ROUTE:-no advertisements}"; echo "PASS=$PASS FAIL=$FAIL"; exit 1;; esac
read -r V1 A1 B1 V2 A2 B2 MID OUTP <<<"$ROUTE"
echo "  hop 1 vault ${V1:0:12}… (${A1:0:8}…/${B1:0:8}…)  hop 2 vault ${V2:0:12}… (${A2:0:8}…/${B2:0:8}…)"
echo "  input ${IN:0:12}…  intermediate ${MID:0:12}…  output ${OUTP:0:12}…"

for pair in "1 $V1 $A1 $B1" "2 $V2 $A2 $B2"; do
  read -r H V TA TB <<<"$pair"
  # verify pins the baseline frontier: the route consumes it, and an LP's reconcile re-anchors the vault
  # past it, so only a pinned read still observes its binding after the owners catch up.
  PIN=""
  if [ "$MODE" = verify ]; then
    PIN=$(awk '/^== generation=/{g=$2; sub("generation=","",g); r=$3} /^parent_c_n=/{if (r=="role=frontier") {sub("parent_c_n=",""); print g":"$0}}' "$OUT/baseline/probe_$H.txt" 2>/dev/null)
    [ -n "$PIN" ] || bad "hop $H: no baseline frontier to pin"
  fi
  DSM_ENV_CONFIG_PATH="$DSM_PROBE_ENV" "$PROBE" "$V" "$TA" "$TB" 30 $PIN > "$OUT/$MODE/probe_$H.txt" 2> "$OUT/$MODE/probe_$H.err" \
    || { bad "probe could not ask about hop $H: $(head -c 300 "$OUT/$MODE/probe_$H.err")"; }
  list "sofi/vault-receipt/$V/" > "$OUT/$MODE/receipts_$H.txt"
done
if [ "$MODE" = baseline ]; then
  for H in 1 2; do echo "  hop $H: $(grep -c '^== generation' "$OUT/baseline/probe_$H.txt") probed generation(s), $(wc -l < "$OUT/baseline/receipts_$H.txt" | tr -d ' ') receipt(s)"; done
  echo "baseline saved to $OUT/baseline"; exit 0
fi
[ -d "$OUT/baseline" ] || { echo "no baseline in $OUT"; exit 1; }

echo; echo "== binding: one transaction over both vault keys =="
python3 - "$OUT" <<'PY'
import sys
out = sys.argv[1]
def rows(path):
    rs, cur = [], None
    for line in open(path):
        line = line.strip()
        if line.startswith("== generation="):
            cur = {"generation": int(line.split("generation=")[1].split()[0]), "role": line.split("role=")[1].strip()}
            rs.append(cur)
        elif "=" in line and cur is not None:
            k, v = line.split("=", 1); cur[k] = v
    return rs
fails, seen = [], []
for h in ("1", "2"):
    base_front = [r for r in rows(f"{out}/baseline/probe_{h}.txt") if r["role"] == "frontier"]
    after = rows(f"{out}/verify/probe_{h}.txt")
    pinned = [r for r in after if r["role"] == "pinned"]
    front = [r for r in after if r["role"] == "frontier"]
    if len(base_front) != 1 or len(pinned) != 1:
        fails.append(f"hop {h}: expected the one baseline frontier pinned, got {len(base_front)} baseline / {len(pinned)} pinned"); continue
    b, r = base_front[0], pinned[0]
    if (r["generation"], r.get("parent_c_n")) != (b["generation"], b.get("parent_c_n")):
        fails.append(f"hop {h}: the pinned parent is not the baseline frontier"); continue
    if r.get("verdict") != "BOUND_FINAL": fails.append(f"hop {h}: baseline frontier generation {r['generation']} verdict={r.get('verdict')}")
    if r.get("bundle_parent_matches") != "true": fails.append(f"hop {h}: the bound bundle does not name this parent")
    if len(front) != 1 or front[0].get("verdict") != "FREE": fails.append(f"hop {h}: frontier not FREE ({[f.get('verdict') for f in front]})")
    elif front[0]["generation"] != b["generation"] + 1: fails.append(f"hop {h}: frontier generation {front[0]['generation']}, expected exactly one advance to {b['generation'] + 1}")
    seen.append((h, r.get("tx_id"), r.get("value_digest"), r.get("holders")))
if len(seen) == 2:
    if seen[0][1] != seen[1][1]: fails.append(f"tx_id differs: hop1 {seen[0][1]} vs hop2 {seen[1][1]}")
    if seen[0][2] != seen[1][2]: fails.append(f"value digest differs: hop1 {seen[0][2]} vs hop2 {seen[1][2]}")
for f in fails: print("FAIL " + f)
if not fails:
    print(f"OK tx_id={seen[0][1]} digest={seen[0][2]} holders={seen[0][3]}/{seen[1][3]}")
sys.exit(1 if fails else 0)
PY
[ $? -eq 0 ] && ok "one binding transaction and one bundle hold both vault parents; both frontiers free" \
             || bad "the register does not show one transaction over both vaults"

echo; echo "== receipts: one per vault, one route commitment, at quorum =="
XS=""
for H in 1 2; do
  NEW=$(comm -13 "$OUT/baseline/receipts_$H.txt" "$OUT/verify/receipts_$H.txt")
  N=$(printf '%s\n' $NEW | grep -c .)
  check "hop $H: exactly one new vault receipt" "$N" "1"
  for key in $NEW; do
    XS="$XS ${key##*/}"; holders=0
    # object/get is device-auth gated (401 without a device token); each node's own listing reads its local object store.
    for ip in $NODES; do curl -s --cacert "$CA" --max-time 10 "https://$ip:8080/api/v2/object/list?prefix=$key&limit=2" | grep -aqF "$key" && holders=$((holders+1)); done
    [ "$holders" -ge "$QUORUM" ] && ok "hop $H receipt on $holders nodes" || bad "hop $H receipt below quorum ($holders): $key"
  done
done
check "both receipts name ONE route commitment" "$(printf '%s\n' $XS | sort -u | grep -c .)" "1"

echo; echo "PASS=$PASS FAIL=$FAIL  ($OUT)"; [ "$FAIL" = 0 ]
