#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# TWO-HOP ATOMIC ROUTE SETTLEMENT — device-side proof over the rig's client DBs (DEBUG builds: needs run-as)
# and the storage fleet. For release builds use two_hop_route_fleet_proof.sh.
# Read-only on devices and fleet.
#
#   ./scripts/two_hop_route_rig_proof.sh baseline <trader-serial> <LP1-serial> <LP2-serial> <outdir>
#   ./scripts/two_hop_route_rig_proof.sh verify   <trader-serial> <LP1-serial> <LP2-serial> <outdir>
#
#   env: DSM_NODES     storage node IPs (default: the five GCP beta nodes)
#        DSM_CA        CA certificate for the self-signed fleet
#        DSM_PROBE_ENV an env config (with an absolute custom_ca_certs path) for dlv_binding_probe
#        DSM_PROBE     path to a built dlv_binding_probe
#
# Take the baseline AFTER both LP vaults are funded and advertised and BEFORE the trader swaps.
# Verify AFTER the trader's swap settled and BOTH LPs tapped Reconcile. The route's three assets are
# DERIVED from the two LP vault records — the asset both vaults hold is the intermediate, LP1's other
# asset is the input, LP2's other asset is the output — never passed in, never hardcoded.
#
# Asserted, all relative to the baseline:
#   trader  exactly the route's ends moved: input down by X, output up by Z, intermediate unchanged
#   LP1     one generation on: input reserve up by X, intermediate reserve down by Y
#   LP2     one generation on: intermediate reserve up by Y (the SOFI that left vault A arrived in B),
#           output reserve down by Z
#   trader  ONE new trader fence, released; TWO published vault receipts under ONE route commitment
#           (one per vault); ONE published SoFi receipt bound to the fence's bundle
#   fleet   both vault receipts readable on a quorum of the storage set
#   binding the production observer on each vault: the consumed generation is BOUND_FINAL by a bundle
#           that names it, with the SAME tx_id and value digest on both vaults (one binding
#           transaction over both keys, one bundle), and each frontier is FREE
set -uo pipefail
MODE="${1:?baseline|verify}"; T="${2:?trader serial}"; L1="${3:?LP1 serial}"; L2="${4:?LP2 serial}"; OUT="${5:?outdir}"
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"
NODES="${DSM_NODES:-34.58.75.224 35.254.209.202 146.148.99.141 104.197.96.66 35.184.46.44}"
CA="${DSM_CA:-$ROOT/dsm_client/frontend/public/ca.crt}"
PROBE="${DSM_PROBE:-$ROOT/dsm_client/deterministic_state_machine/target/release/dlv_binding_probe}"
QUORUM=3
mkdir -p "$OUT/$MODE"; PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($3)" || bad "$1 — expected [$3], got [$2]"; }
tid_for(){ for t in $(adb devices -l 2>/dev/null | grep -o 'transport_id:[0-9]*' | cut -d: -f2); do [ "$(adb -t "$t" shell getprop ro.serialno 2>/dev/null | tr -d '\r')" = "$1" ] && { echo "$t"; return 0; }; done; return 1; }
pull(){
  local tid; tid="$(tid_for "$1")" || { echo "device $1 not attached" >&2; return 1; }
  adb -t "$tid" shell "run-as com.dsm.wallet cat files/dsm_client.db" > "$2" 2>/dev/null
  adb -t "$tid" shell "run-as com.dsm.wallet cat files/dsm_client.db-wal" > "$2-wal" 2>/dev/null || true
  [ -s "$2-wal" ] || rm -f "$2-wal"
  [ -s "$2" ]
}

echo "== pulling ($MODE) =="
for role in t l1 l2; do
  case $role in t) s="$T";; l1) s="$L1";; l2) s="$L2";; esac
  pull "$s" "$OUT/$MODE/$role.db" || exit 1
done

python3 - "$MODE" "$OUT" <<'PY' > "$OUT/$MODE/state.txt" || { cat "$OUT/$MODE/state.txt"; exit 1; }
import json, sqlite3, sys
sys.path.insert(0, 'scripts')
from dsm_head_decode import b32, b3, decode
mode, out = sys.argv[1], sys.argv[2]
d = f"{out}/{mode}"
def conn(role): return sqlite3.connect(f"{d}/{role}.db")
def head(c): return decode(c.execute("SELECT head_bytes FROM bcr_device_heads").fetchone()[0])
state = {}
for role in ("t", "l1", "l2"):
    c = conn(role); h = head(c)
    state[role] = {"schema": c.execute("PRAGMA user_version").fetchone()[0], "balances": h["balances"]}
    if role != "t":
        recs = c.execute("SELECT vault_id, owner_genesis, owner_devid, policy_commit_a, policy_commit_b, fee_bps FROM amm_vault_records").fetchall()
        state[role]["vault_count"] = len(recs)
        if recs:
            vid, og, od, pa, pb, fee = recs[0]
            legs = {}
            for pc in (pa, pb):
                leaf = h["reserves"].get(b3(b"DSM/vault-reserve/v1", og, od, vid, pc))
                legs[b32(pc)] = list(leaf) if leaf else None
            state[role].update(vault=b32(vid), token_a=b32(pa), token_b=b32(pb), fee_bps=fee, legs=legs)
    if role == "t":
        state[role]["fences"] = [
            {"ordinal": o, "tx_id": b32(tx), "state": st}
            for o, tx, st in c.execute("SELECT insertion_ordinal, tx_id, state FROM trader_parent_fence ORDER BY insertion_ordinal")]
        state[role]["artifacts"] = [
            {"ordinal": o, "key": k, "purpose": p, "state": st, "bound_root": b32(br)}
            for o, k, p, st, br in c.execute("SELECT insertion_ordinal, object_key, purpose, state, bound_root FROM frozen_publication_artifact ORDER BY insertion_ordinal")]
json.dump(state, open(f"{d}/state.json", "w"), indent=1)
print(f"trader balances: { {k[:10]: v for k, v in state['t']['balances'].items()} }")
for r in ("l1", "l2"):
    print(f"{r} vault {state[r].get('vault','-')[:12]}… legs { {k[:10]: v for k, v in (state[r].get('legs') or {}).items()} }")
PY
cat "$OUT/$MODE/state.txt"
[ "$MODE" = baseline ] && { echo "baseline saved to $OUT/baseline/state.json"; exit 0; }
[ -f "$OUT/baseline/state.json" ] || { echo "no baseline in $OUT"; exit 1; }

echo; echo "== the route, derived from the two vaults =="
ROUTE="$(python3 - "$OUT" <<'PY'
import json, sys
b = json.load(open(f"{sys.argv[1]}/baseline/state.json"))
p1 = {b["l1"]["token_a"], b["l1"]["token_b"]}; p2 = {b["l2"]["token_a"], b["l2"]["token_b"]}
shared = p1 & p2
if len(shared) != 1: print("ERR the two vaults do not share exactly one asset"); sys.exit(0)
mid = shared.pop(); inp = (p1 - {mid}).pop(); outp = (p2 - {mid}).pop()
print(inp, mid, outp)
PY
)"
case "$ROUTE" in ERR*) bad "$ROUTE"; echo "PASS=$PASS FAIL=$FAIL"; exit 1;; esac
read -r IN MID OUTP <<<"$ROUTE"
echo "  input ${IN:0:12}…  intermediate ${MID:0:12}…  output ${OUTP:0:12}…"

python3 - "$OUT" "$IN" "$MID" "$OUTP" <<'PY' > "$OUT/verify/deltas.txt"
import json, sys
out, IN, MID, OUTP = sys.argv[1:5]
b = json.load(open(f"{out}/baseline/state.json")); a = json.load(open(f"{out}/verify/state.json"))
def bal(s, r, pc): return s[r]["balances"].get(pc, 0)
def leg(s, r, pc): return tuple(s[r]["legs"][pc]) if s[r].get("legs") and s[r]["legs"].get(pc) else (None, None)
lines = {}
lines["SCHEMAS"] = " ".join(str(a[r]["schema"]) for r in ("t", "l1", "l2"))
lines["VAULTS"] = f"{a['l1'].get('vault_count')} {a['l2'].get('vault_count')}"
lines["T_IN"] = bal(a, "t", IN) - bal(b, "t", IN)
lines["T_MID"] = bal(a, "t", MID) - bal(b, "t", MID)
lines["T_OUT"] = bal(a, "t", OUTP) - bal(b, "t", OUTP)
for r, x, y in (("l1", IN, MID), ("l2", MID, OUTP)):
    (xa, xs), (ya, ys) = leg(a, r, x), leg(a, r, y)
    (xb, xsb), (yb, ysb) = leg(b, r, x), leg(b, r, y)
    lines[f"{r.upper()}_X"] = (xa - xb) if None not in (xa, xb) else "missing"
    lines[f"{r.upper()}_Y"] = (ya - yb) if None not in (ya, yb) else "missing"
    lines[f"{r.upper()}_GEN"] = f"{xsb}->{xs} {ysb}->{ys}"
nb_f = {f["ordinal"] for f in b["t"]["fences"]}; nb_a = {x["ordinal"] for x in b["t"]["artifacts"]}
new_f = [f for f in a["t"]["fences"] if f["ordinal"] not in nb_f]
new_a = [x for x in a["t"]["artifacts"] if x["ordinal"] not in nb_a]
lines["FENCES"] = " ".join(f"{f['state']}:{f['tx_id']}" for f in new_f) or "none"
rc = [x for x in new_a if x["purpose"] == "trader-settlement-receipt"]
sr = [x for x in new_a if x["purpose"] == "sofi-receipt"]
lines["RECEIPTS"] = " ".join(f"{x['state']}:{x['key']}" for x in rc) or "none"
lines["SOFI_RECEIPTS"] = " ".join(f"{x['state']}:{x['bound_root']}" for x in sr) or "none"
lines["VAULT_L1"] = a["l1"]["vault"]; lines["VAULT_L2"] = a["l2"]["vault"]
for k, v in lines.items(): print(f"{k}={v}")
PY
get(){ grep "^$1=" "$OUT/verify/deltas.txt" | cut -d= -f2-; }
echo; echo "== devices =="
S3=($(get SCHEMAS)); check "the three devices share one client schema" "$(printf '%s\n' "${S3[@]}" | sort -u | wc -l | tr -d ' ')" "1"
check "each LP owns exactly one vault" "$(get VAULTS)" "1 1"
X=$(( -$(get T_IN) )); Z=$(get T_OUT)
[ "$X" -gt 0 ] && ok "trader paid the route's input ($X)" || bad "trader input did not decrease (Δ=$(get T_IN))"
[ "$Z" -gt 0 ] && ok "trader received the route's output ($Z)" || bad "trader output did not increase (Δ=$Z)"
check "the intermediate asset never touched the trader" "$(get T_MID)" "0"
check "LP1 input reserve rose by exactly the trader's input" "$(get L1_X)" "$X"
Y=$(( -$(get L1_Y) ))
[ "$Y" -gt 0 ] && ok "LP1 released the intermediate ($Y)" || bad "LP1 intermediate reserve did not decrease (Δ=$(get L1_Y))"
check "LP2 intermediate reserve rose by exactly what LP1 released" "$(get L2_X)" "$Y"
check "LP2 output reserve fell by exactly the trader's output" "$(get L2_Y)" "$(( -Z ))"
for r in L1 L2; do
  G=($(get ${r}_GEN)); from="${G[0]%->*}"; to="${G[0]#*->}"
  check "$r both legs advanced one generation together" "$(get ${r}_GEN)" "$from->$((from+1)) $from->$((from+1))"
done

echo; echo "== the trader's one settlement =="
F=($(get FENCES)); check "exactly one new trader fence" "${#F[@]}" "1"
FSTATE="${F[0]%%:*}"; TX="${F[0]#*:}"
check "that fence is released" "$FSTATE" "released"
R=($(get RECEIPTS)); check "exactly two new vault receipts" "${#R[@]}" "2"
XS="$(printf '%s\n' "${R[@]}" | sed -E 's|.*/([0-9A-HJKMNP-TV-Z]+)$|\1|' | sort -u | wc -l | tr -d ' ')"
check "both vault receipts name ONE route commitment" "$XS" "1"
for v in "$(get VAULT_L1)" "$(get VAULT_L2)"; do
  printf '%s\n' "${R[@]}" | grep -q "sofi/vault-receipt/$v/" && ok "a receipt for vault ${v:0:12}…" || bad "no receipt for vault ${v:0:12}…"
done
printf '%s\n' "${R[@]}" | grep -qv "^published:" && bad "a vault receipt is not published" || ok "both vault receipts published"
SR=($(get SOFI_RECEIPTS)); check "exactly one new SoFi receipt" "${#SR[@]}" "1"
check "the SoFi receipt is published and bound to the fence's bundle" "${SR[0]:-none}" "published:$TX"

echo; echo "== fleet: both vault receipts at quorum =="
for entry in "${R[@]}"; do
  key="${entry#*:}"; holders=0
  for ip in $NODES; do
    # object/get is device-auth gated (401 without a device token). A node's own listing reads its local
    # object store, so the exact key in that node's listing is that node holding the object.
    curl -s --cacert "$CA" --max-time 10 "https://$ip:8080/api/v2/object/list?prefix=$key&limit=2" | grep -aqF "$key" && holders=$((holders+1))
  done
  [ "$holders" -ge "$QUORUM" ] && ok "$key on $holders nodes" || bad "$key below quorum ($holders)"
done

echo; echo "== binding: one transaction over both vault keys =="
if [ ! -x "$PROBE" ] || [ -z "${DSM_PROBE_ENV:-}" ]; then
  bad "set DSM_PROBE (built dlv_binding_probe) and DSM_PROBE_ENV (env config with an absolute CA path)"
else
  for r in l1 l2; do
    read -r V TA TB FEE <<<"$(python3 -c "import json;s=json.load(open('$OUT/verify/state.json'))['$r'];print(s['vault'],s['token_a'],s['token_b'],s['fee_bps'])")"
    # The route consumes each vault's baseline frontier and the LP's reconcile re-anchors past it, so the
    # parent is pinned. Its c_n is recorded only by the fleet baseline (hop 1 = LP1, hop 2 = LP2); the
    # generation must agree with this device baseline's legs, and a wrong pairing cannot read BOUND_FINAL.
    h=${r#l}
    PIN=$(awk '/^== generation=/{g=$2; sub("generation=","",g); k=$3} /^parent_c_n=/{if (k=="role=frontier") {sub("parent_c_n=",""); print g":"$0}}' "$OUT/fleet/baseline/probe_$h.txt" 2>/dev/null)
    GEN=$(python3 -c "import json;s=json.load(open('$OUT/baseline/state.json'))['$r'];g={v[1] for v in s['legs'].values()};print(g.pop() if len(g)==1 else 'split')")
    [ -n "$PIN" ] && [ "${PIN%%:*}" = "$GEN" ] || bad "no fleet baseline frontier for ${V:0:12}… at its baseline generation $GEN (pin: ${PIN:-none})"
    DSM_ENV_CONFIG_PATH="$DSM_PROBE_ENV" "$PROBE" "$V" "$TA" "$TB" "$FEE" $PIN > "$OUT/verify/probe_$r.txt" 2> "$OUT/verify/probe_$r.err" \
      || bad "probe could not ask about ${V:0:12}…: $(head -c 300 "$OUT/verify/probe_$r.err")"
  done
  python3 - "$OUT/verify/probe_l1.txt" "$OUT/verify/probe_l2.txt" "$TX" <<'PY'
import sys
def rows(path):
    out, cur = [], None
    for line in open(path):
        line = line.strip()
        if line.startswith("== generation="):
            cur = {"generation": int(line.split("generation=")[1].split()[0]), "role": line.split("role=")[1].strip()}
            out.append(cur)
        elif "=" in line and cur is not None:
            k, v = line.split("=", 1); cur[k] = v
    return out
fails, seen = [], []
for label, path in (("LP1", sys.argv[1]), ("LP2", sys.argv[2])):
    rs = rows(path)
    pinned = [r for r in rs if r["role"] == "pinned"]
    frontier = [r for r in rs if r["role"] == "frontier"]
    if len(pinned) != 1:
        fails.append(f"{label}: expected the baseline frontier pinned, got {len(pinned)} pinned row(s)"); continue
    last = pinned[0]
    if last.get("verdict") != "BOUND_FINAL": fails.append(f"{label}: baseline frontier generation {last['generation']} verdict={last.get('verdict')}")
    if last.get("bundle_parent_matches") != "true": fails.append(f"{label}: the bound bundle does not name this parent")
    if len(frontier) != 1 or frontier[0].get("verdict") != "FREE": fails.append(f"{label}: frontier not FREE ({[f.get('verdict') for f in frontier]})")
    elif frontier[0]["generation"] != last["generation"] + 1: fails.append(f"{label}: frontier generation {frontier[0]['generation']}, expected exactly one advance to {last['generation'] + 1}")
    seen.append((label, last.get("tx_id"), last.get("value_digest")))
if len(seen) == 2:
    if seen[0][1] != seen[1][1]: fails.append(f"tx_id differs across vaults: {seen[0][1]} vs {seen[1][1]}")
    if seen[0][2] != seen[1][2]: fails.append(f"value digest differs across vaults: {seen[0][2]} vs {seen[1][2]}")
    if sys.argv[3] and seen[0][1] and len(seen[0][1]) == len(sys.argv[3]) and seen[0][1] != sys.argv[3]:
        fails.append(f"the binding tx_id {seen[0][1]} is not the trader fence's {sys.argv[3]}")
for f in fails: print("FAIL " + f)
if not fails: print(f"OK one binding transaction {seen[0][1]} holds both vault parents with one bundle; both frontiers free")
sys.exit(1 if fails else 0)
PY
  [ $? -eq 0 ] && ok "one binding transaction, one bundle, over both vault parents; both frontiers free" || bad "the binding register does not show one transaction over both vaults"
fi

echo; echo "PASS=$PASS FAIL=$FAIL  ($OUT)"; [ "$FAIL" = 0 ]
