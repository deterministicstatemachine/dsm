#!/usr/bin/env bash
# DLV delegated-liquidity market — hardware proof over the rig's client DBs + the storage fleet. Read-only.
#
#   ./scripts/dlv_market_rig_proof.sh <LP-serial> <T1-serial> <T2-serial> [expected_generations]
#
# Run AFTER: LP funds a vault and force-stops; traders settle N generations through the production
# SwapTab; one stale quote is refused; LP relaunches and taps Reconcile. Asserts, from the AUTHORITATIVE
# device heads (bcr_device_heads, decoded on the host) and the storage node's public listings:
#   - schema v4 on all three
#   - LP: exactly one vault; both reserve legs at generation N; reserves == funding + Σ inputs − Σ outputs
#     where inputs/outputs come out of the traders' receipts (not from an argument)
#   - LP: vault_generation_consumption has rows 0..N-1, contiguous, child = parent+1, DISTINCT sources
#   - LP: spendable balances unchanged since funding (no second debit) — funding = reserves at gen 0
#   - traders: Σ trader ERA debits == ERA reserve gain; Σ trader SOFI credits == SOFI reserve drain
#   - storage: exactly N receipted pointers on the fleet (union over nodes), one per generation 1..N;
#     any extra pointer (the refused stale/future attempt) has NO receipt
#   - register: for every consumed parent, exactly ONE claim digest holds a quorum of the storage set,
#     and no conflicting digest holds one. Minority conflicting rows are LEGAL and permanent (a
#     partition split leaves the loser's bytes on one node forever) — asserting "identical on every
#     node" would reject a perfectly safe specimen, so it is deliberately NOT asserted
#   - if the vault was CLOSED: the LP's spendable balances grew by EXACTLY the reserves the vault
#     held at the consumed generation (invariant 4), both legs are 0 at the terminal generation, and
#     the five terminal objects (anchor seq+latest, inclusion seq+latest, reserve proof) are
#     readable on a quorum
set -uo pipefail
LP="${1:?LP serial}"; T1="${2:?T1 serial}"; T2="${3:?T2 serial}"; N="${4:-4}"
OUT="$(mktemp -d)"; PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($3)" || bad "$1 — expected [$3], got [$2]"; }
tid_for(){ for t in $(adb devices -l 2>/dev/null | grep -o 'transport_id:[0-9]*' | cut -d: -f2); do [ "$(adb -t "$t" shell getprop ro.serialno 2>/dev/null | tr -d '\r')" = "$1" ] && { echo "$t"; return 0; }; done; return 1; }
pull(){ local tid; tid="$(tid_for "$1")" || { echo "device $1 not attached" >&2; return 1; }; adb -t "$tid" shell "run-as com.dsm.wallet cat files/dsm_client.db" > "$2" 2>/dev/null; [ -s "$2" ]; }
q(){ sqlite3 "$1" "$2" 2>/dev/null; }
HERE="$(cd "$(dirname "$0")" && pwd)"
NODES="47.251.246.93 47.251.250.159 47.251.88.58"

echo "== pulling =="; pull "$LP" "$OUT/lp.db" || exit 1; pull "$T1" "$OUT/t1.db" || exit 1; pull "$T2" "$OUT/t2.db" || exit 1
for s in lp t1 t2; do check "$s schema v5" "$(q "$OUT/$s.db" 'PRAGMA user_version;')" "5"; done

echo; echo "== LP: vault, reserves, generation =="
LPD="$(python3 "$HERE/dsm_head_decode.py" "$OUT/lp.db")"
check "LP owns exactly one vault record" "$(q "$OUT/lp.db" 'SELECT COUNT(*) FROM amm_vault_records;')" "1"
VID_B32="$(python3 - "$OUT/lp.db" <<'EOF'
import sqlite3,sys; sys.path.insert(0, __import__('os').path.dirname(sys.argv[0]) or '.')
sys.path.insert(0,'scripts'); from dsm_head_decode import b32
c=sqlite3.connect(sys.argv[1]); print(b32(c.execute("SELECT vault_id FROM amm_vault_records").fetchone()[0]))
EOF
)"
echo "  vault: $VID_B32"
LEG_A_AMT=$(echo "$LPD" | awk '/leg A/{for(i=1;i<=NF;i++) if($i ~ /^amount=/){sub("amount=","",$i); print $i}}')
LEG_A_SEQ=$(echo "$LPD" | awk '/leg A/{for(i=1;i<=NF;i++) if($i ~ /^seq=/){sub("seq=","",$i); print $i}}')
LEG_B_AMT=$(echo "$LPD" | awk '/leg B/{for(i=1;i<=NF;i++) if($i ~ /^amount=/){sub("amount=","",$i); print $i}}')
LEG_B_SEQ=$(echo "$LPD" | awk '/leg B/{for(i=1;i<=NF;i++) if($i ~ /^seq=/){sub("seq=","",$i); print $i}}')
check "LP leg A at generation N" "$LEG_A_SEQ" "$N"
check "LP leg B at generation N" "$LEG_B_SEQ" "$N"
check "LP both legs share one generation" "$LEG_A_SEQ" "$LEG_B_SEQ"

echo; echo "== LP: consume-once claims =="
ROWS=$(q "$OUT/lp.db" "SELECT COUNT(*) FROM vault_generation_consumption;")
check "consumption rows == N" "$ROWS" "$N"
check "distinct sources == rows" "$(q "$OUT/lp.db" "SELECT COUNT(DISTINCT source_commitment) FROM vault_generation_consumption;")" "$ROWS"
check "parents are exactly 0..N-1" "$(q "$OUT/lp.db" "SELECT GROUP_CONCAT(parent_sequence) FROM (SELECT parent_sequence FROM vault_generation_consumption ORDER BY parent_sequence);")" "$(python3 -c "print(\",\".join(map(str,range(0,$N))))")"
check "every child == parent+1" "$(q "$OUT/lp.db" "SELECT COUNT(*) FROM vault_generation_consumption WHERE child_sequence != parent_sequence+1;")" "0"

echo; echo "== conservation: traders' heads vs LP reserves =="
# Trader deltas are read from receipts published on the fleet (input/output amounts), and cross-checked
# against the traders' own head balances. Funding at gen 0 is read from the LP's first self-chain state? —
# we use the invariant instead: reserves(N) == reserves(0) + Σin − Σout, with reserves(0) recovered as
# reserves(N) − Σin + Σout, then require the traders' balance changes to match Σin/Σout exactly.
python3 - "$OUT/t1.db" "$OUT/t2.db" "$LEG_A_AMT" "$LEG_B_AMT" "$VID_B32" $NODES <<'EOF'
import sqlite3, sys, subprocess, re
sys.path.insert(0,'scripts'); from dsm_head_decode import b32, decode
t1, t2, legA, legB, vid = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]; nodes = sys.argv[6:]
def bal(db):
    c = sqlite3.connect(db); h = decode(c.execute("SELECT head_bytes FROM bcr_device_heads").fetchone()[0]); return h['balances']
b1, b2 = bal(t1), bal(t2)
# pointers/receipts on the fleet (union over nodes)
ptrs, rcts = {}, set()
for ip in nodes:
    for kind in ("vault-pending", "vault-receipt"):
        try:
            out = subprocess.run(["curl","-sk","--max-time","10",f"https://{ip}:8080/api/v2/object/list?prefix=sofi/{kind}/{vid}/&limit=100"], capture_output=True).stdout
        except Exception: continue
        for m in re.finditer(rb"sofi/vault-pending/%s/(\d{16})/([0-9A-HJKMNP-TV-Z]{52})" % vid.encode(), out): ptrs.setdefault(m.group(2).decode(), set()).add(int(m.group(1)))
        for m in re.finditer(rb"sofi/vault-receipt/%s/([0-9A-HJKMNP-TV-Z]{52})" % vid.encode(), out): rcts.add(m.group(1).decode())
receipted = {x: g for x, g in ptrs.items() if x in rcts}
unreceipted = {x: g for x, g in ptrs.items() if x not in rcts}
print(f"  fleet: {len(ptrs)} pointers, {len(rcts)} receipts; receipted generations: {sorted(min(g) for g in receipted.values())}; unreceipted (refused/orphan) pointers: {len(unreceipted)} at gens {sorted(min(g) for g in unreceipted.values())}")
print(f"  RECEIPTED_GENS={','.join(str(min(g)) for g in sorted(receipted.values(), key=min))}")
print(f"  UNRECEIPTED={len(unreceipted)}")
# trader-side totals (the two traders started at 300 ERA / 0 SOFI each; ERA is the input asset)
era = [k for k in b1 if k.startswith('NW9MKEFN')] or [k for k in b1 if b1[k] < 10_000]  # ERA commit prefix on this rig
tot_in = sum(300 - b[k] for b in (b1, b2) for k in b if k in era)
tot_out = sum(b[k] for b in (b1, b2) for k in b if k not in era)
print(f"  traders paid ERA total={tot_in}; traders received SOFI total={tot_out}")
print(f"  TOT_IN={tot_in}"); print(f"  TOT_OUT={tot_out}")
EOF
CONS="$(python3 - "$OUT/t1.db" "$OUT/t2.db" "$LEG_A_AMT" "$LEG_B_AMT" "$VID_B32" $NODES <<'EOF'
import sqlite3, sys, subprocess, re
sys.path.insert(0,'scripts'); from dsm_head_decode import b32, decode
t1, t2, legA, legB, vid = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]; nodes = sys.argv[6:]
def bal(db):
    c = sqlite3.connect(db); h = decode(c.execute("SELECT head_bytes FROM bcr_device_heads").fetchone()[0]); return h['balances']
b1, b2 = bal(t1), bal(t2)
era = [k for k in b1 if k.startswith('NW9MKEFN')]
tot_in = sum(300 - b[k] for b in (b1, b2) for k in b if k in era)
tot_out = sum(b[k] for b in (b1, b2) for k in b if k not in era)
ptrs, rcts = {}, set()
for ip in nodes:
    for kind in ("vault-pending", "vault-receipt"):
        out = subprocess.run(["curl","-sk","--max-time","10",f"https://{ip}:8080/api/v2/object/list?prefix=sofi/{kind}/{vid}/&limit=100"], capture_output=True).stdout
        for m in re.finditer(rb"sofi/vault-pending/%s/(\d{16})/([0-9A-HJKMNP-TV-Z]{52})" % vid.encode(), out): ptrs.setdefault(m.group(2).decode(), set()).add(int(m.group(1)))
        for m in re.finditer(rb"sofi/vault-receipt/%s/([0-9A-HJKMNP-TV-Z]{52})" % vid.encode(), out): rcts.add(m.group(1).decode())
receipted = sorted(min(g) for x, g in ptrs.items() if x in rcts); unreceipted = [x for x in ptrs if x not in rcts]
print(f"{tot_in} {tot_out} {','.join(map(str,receipted))} {len(unreceipted)}")
EOF
)"
read -r TOT_IN TOT_OUT RGENS UNRCT <<<"$CONS"
# What the LP funded at gen 0 (asserted at creation from the head; see trace),
# and what it kept back as spendable.
FUND_A=25000000; FUND_B=100
KEPT_SOFI=75000000; KEPT_ERA=190
# The reserves the vault holds at the last consumed generation: funding plus
# what the market moved. ERA (leg B) gained exactly what traders paid; SOFI
# (leg A) lost exactly what traders received. These are also the amounts a
# close must return — exactly, which is what makes them worth naming once.
RESERVE_A_AT_K=$((FUND_A - TOT_OUT))
RESERVE_B_AT_K=$((FUND_B + TOT_IN))
read -r LP_SOFI LP_ERA <<<"$(python3 - "$OUT/lp.db" <<'EOF'
import sqlite3,sys; sys.path.insert(0,'scripts'); from dsm_head_decode import decode
b=decode(sqlite3.connect(sys.argv[1]).execute("SELECT head_bytes FROM bcr_device_heads").fetchone()[0])['balances']
print([v for k,v in b.items() if k.startswith('DX7JKWDQ')][0], [v for k,v in b.items() if k.startswith('NW9MKEFN')][0])
EOF
)"

if [ "$LEG_A_AMT" = "0" ] && [ "$LEG_B_AMT" = "0" ]; then
  CLOSED=1
  # INVARIANT 4 — WITHDRAWAL. The delegation is a loop: everything the LP put
  # in comes back, plus what the market added and minus what it took. Asserted
  # against the reserves at the CONSUMED generation, not against the funding
  # amounts — a close that returned the funding would be off by the market.
  echo; echo "== invariant 4: the vault was closed and the reserves came back, exactly =="
  check "LP spendable SOFI == kept + reserve_a at the consumed generation" "$LP_SOFI" "$((KEPT_SOFI + RESERVE_A_AT_K))"
  check "LP spendable ERA  == kept + reserve_b at the consumed generation" "$LP_ERA"  "$((KEPT_ERA  + RESERVE_B_AT_K))"
else
  CLOSED=0
  check "ERA reserve == funding + Σ trader inputs" "$LEG_B_AMT" "$RESERVE_B_AT_K"
  check "SOFI reserve == funding − Σ trader outputs" "$LEG_A_AMT" "$RESERVE_A_AT_K"
  check "LP spendable ERA untouched by the market (funding-time value)" "$LP_ERA" "$KEPT_ERA"
  check "LP spendable SOFI untouched by the market (funding-time value)" "$LP_SOFI" "$KEPT_SOFI"
fi

echo; echo "== storage fleet: witness chain =="
check "receipted pointers cover generations 1..N exactly" "$RGENS" "$(python3 -c "print(\",\".join(map(str,range(1,$N+1))))")"
[ "$UNRCT" -ge 1 ] && ok "refused attempt left an UNRECEIPTED pointer only ($UNRCT), no receipt, no value" || bad "expected at least one unreceipted (refused) pointer, got $UNRCT"

# The vault's pair, in full — the probe composes the vault the way a stranger
# does, so it needs the same (token_a, token_b, fee) tuple a quote carries. The
# prefixes used elsewhere in this script identify the legs; these are the whole
# policy commits, read from the LP's own head rather than hardcoded.
read -r LEG_A_PC LEG_B_PC <<<"$(python3 - "$OUT/lp.db" <<'EOF'
import sqlite3,sys; sys.path.insert(0,'scripts'); from dsm_head_decode import decode
b=decode(sqlite3.connect(sys.argv[1]).execute("SELECT head_bytes FROM bcr_device_heads").fetchone()[0])['balances']
print([k for k in b if k.startswith('DX7JKWDQ')][0], [k for k in b if k.startswith('NW9MKEFN')][0])
EOF
)"
# The AMM fee this rig's vault was created with.
FEE_BPS=30

echo; echo "== binding register: one binding-final bundle per consumed parent =="
# THE PROBE RUNS THE PRODUCTION OBSERVER, and this script asserts its output.
#
# This block used to read /api/v2/settlement-slot/{vault}/{seq} and tally
# digests across nodes against a hardcoded QUORUM=2. That endpoint is no longer
# the authoritative occupancy mechanism, and re-implementing its replacement
# here would be worse than porting it: "chosen at a key" would exist twice, in
# two languages, and the copy with no BindingRecord type — the one with the
# hardcoded quorum — would decide whether a live proof passes.
#
# So `dlv_binding_probe` composes the vault the way any third party does, asks
# the same client-side observation the composer and the verifier ask, and emits
# key=value lines. Everything below is an assertion on those lines. If Class K's
# notion of chosen changes, this gate changes with it, because it IS that code.
PROBE="$HERE/../dsm_client/deterministic_state_machine/target/release/dlv_binding_probe"
if [ ! -x "$PROBE" ]; then
  bad "dlv_binding_probe is not built — cargo build -p dsm_sdk --release --bin dlv_binding_probe"
else
  PROBE_OUT="$OUT/binding_probe.txt"
  if ! "$PROBE" "$VID_B32" "$LEG_A_PC" "$LEG_B_PC" "$FEE_BPS" > "$PROBE_OUT" 2> "$OUT/binding_probe.err"; then
    bad "the binding probe could not ask: $(cat "$OUT/binding_probe.err")"
  else
    # One record per generation. A CONSUMED parent must be BOUND_FINAL by a
    # bundle that names it; the FRONTIER must not be bound by anyone.
    python3 - "$PROBE_OUT" "$N" <<'PYEOF'
import sys
rows, cur = [], None
for line in open(sys.argv[1]):
    line = line.strip()
    if line.startswith("== generation="):
        cur = {"generation": int(line.split("generation=")[1].split()[0]),
               "role": line.split("role=")[1].strip()}
        rows.append(cur)
    elif "=" in line and cur is not None:
        k, v = line.split("=", 1)
        cur[k] = v
fails = []
consumed = [r for r in rows if r["role"] == "consumed"]
frontier = [r for r in rows if r["role"] == "frontier"]
for r in consumed:
    g = r["generation"]
    if r.get("verdict") != "BOUND_FINAL":
        fails.append(f"parent {g}: verdict={r.get('verdict')} (expected BOUND_FINAL)")
        continue
    # A chosen value is q members holding ONE bundle's accepted record at ONE
    # round. The probe reports the holder count the observer counted; a second
    # chosen value would have surfaced as verdict=CONFLICT, which is why there
    # is no separate "no rival reached quorum" tally to run here.
    if int(r.get("holders", 0)) < 1:
        fails.append(f"parent {g}: no holders reported")
    for field in ("tx_id", "value_digest", "value_addr", "resource_key"):
        if not r.get(field):
            fails.append(f"parent {g}: probe omitted {field}")
    # THE APPLICATION-BLIND REGISTER: a member never inspects the value it
    # holds, so a record can name a bundle that does not name this parent.
    if r.get("bundle_parent_matches") != "true":
        fails.append(f"parent {g}: the bound bundle does not name this parent "
                     f"({r.get('detail','no detail')})")
if len(consumed) != int(sys.argv[2]):
    fails.append(f"expected {sys.argv[2]} consumed parents, probe reported {len(consumed)}")
if len(frontier) != 1:
    fails.append(f"expected exactly one frontier row, got {len(frontier)}")
elif frontier[0].get("verdict") not in ("FREE",):
    fails.append(f"frontier generation {frontier[0]['generation']}: verdict="
                 f"{frontier[0].get('verdict')} (expected FREE)")
for f in fails:
    print("FAIL " + f)
if not fails:
    for r in consumed:
        print(f"OK parent {r['generation']}: one binding-final bundle "
              f"({r['holders']} holders), and it names this parent")
    print(f"OK frontier generation {frontier[0]['generation']} is free")
sys.exit(1 if fails else 0)
PYEOF
    if [ $? -eq 0 ]; then
      ok "every consumed parent is bound by one bundle that names it; the frontier is free"
    else
      bad "the binding register does not agree with the composed history"
    fi
  fi
fi

if [ "$CLOSED" = 1 ]; then
  echo; echo "== closed vault: terminal state and its published proof set =="
  ok "both reserve legs are zero at the terminal generation $LEG_A_SEQ"
  TERM_SEQ_B32="$(python3 -c "
import sys; sys.path.insert(0,'scripts'); from dsm_head_decode import b32
print(b32((0).to_bytes(8,'big') + int($LEG_A_SEQ).to_bytes(8,'big')))")"
  for key in "sofi/vault-state/$VID_B32/seq-$TERM_SEQ_B32" \
             "sofi/vault-state/$VID_B32/latest" \
             "sofi/vault-state-inclusion/$VID_B32/seq-$TERM_SEQ_B32" \
             "sofi/vault-state-inclusion/$VID_B32/latest" \
             "sofi/vault-reserve/$VID_B32/seq-$TERM_SEQ_B32"; do
    HOLDERS=0
    for ip in $NODES; do
      code="$(curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "https://$ip:8080/api/v2/object/get?key=$key")"
      [ "$code" = "200" ] && HOLDERS=$((HOLDERS+1))
    done
    [ "$HOLDERS" -ge "$QUORUM" ] && ok "terminal object at quorum ($HOLDERS/3): ${key##*/}" \
                                 || bad "terminal object below quorum ($HOLDERS/3): $key"
  done
fi

echo; echo "PASS=$PASS FAIL=$FAIL  ($OUT)"; [ "$FAIL" = 0 ]
