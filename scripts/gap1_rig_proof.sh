#!/usr/bin/env bash
# Gap 1 criterion 6 — verify two sequential online transfers on one relationship.
#
# Run AFTER two transfers have been sent 9FF -> D3 on the installed build.
# Pulls both client DBs and asserts every criterion. Read-only; it never writes
# to a device.
#
#   ./scripts/gap1_rig_proof.sh <sender-serial> <recipient-serial> [expected_sender_balance] [expected_recipient_balance]
#
# 8XK (RFGYB0PQ8XK) is QUARANTINED — this script refuses to touch it.

set -uo pipefail

SENDER="${1:-RFGYB0PQ9FF}"
RECIPIENT="${2:-RF8Y90PX5GN}"
EXP_SENDER="${3:-}"
EXP_RECIPIENT="${4:-}"
QUARANTINED="RFGYB0PQ8XK"

OUT="$(mktemp -d)"
PASS=0
FAIL=0

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($3)" || bad "$1 — expected [$3], got [$2]"; }

for s in "$SENDER" "$RECIPIENT"; do
  if [ "$s" = "$QUARANTINED" ]; then
    echo "REFUSING: $s is quarantined. Its canonical head is damaged and must be" >&2
    echo "reconstructed deterministically, not exercised." >&2
    exit 2
  fi
done

tid_for() {
  for t in $(adb devices -l 2>/dev/null | grep -o 'transport_id:[0-9]*' | cut -d: -f2); do
    [ "$(adb -t "$t" shell getprop ro.serialno 2>/dev/null | tr -d '\r')" = "$1" ] && { echo "$t"; return 0; }
  done
  return 1
}

pull() {  # pull <serial> <dest>  — transport ids rotate, so resolve by serial
  local tid; tid="$(tid_for "$1")" || { echo "device $1 not attached" >&2; return 1; }
  adb -t "$tid" shell "run-as com.dsm.wallet cat files/dsm_client.db" > "$2" 2>/dev/null
  [ -s "$2" ] || { echo "empty DB pulled from $1" >&2; return 1; }
}

q() { sqlite3 "$1" "$2" 2>/dev/null; }

echo "== pulling =="
pull "$SENDER"    "$OUT/sender.db"    || exit 1
pull "$RECIPIENT" "$OUT/recipient.db" || exit 1
echo "  sender=$SENDER recipient=$RECIPIENT"

S="$OUT/sender.db"; R="$OUT/recipient.db"

echo
echo "== sender: settlement state =="

# Tips converge — chain_tip and local_bilateral_chain_tip must agree, and the
# relationship must not be flagged for reconcile.
DIVERGED=$(q "$S" "SELECT COUNT(*) FROM contacts WHERE chain_tip IS NOT local_bilateral_chain_tip;")
check "tips converge on every contact" "$DIVERGED" "0"
RECON=$(q "$S" "SELECT COUNT(*) FROM contacts WHERE needs_online_reconcile != 0;")
check "no contact flagged needs_online_reconcile" "$RECON" "0"

# No residue: the gate is a lock released at finalization, and every pending EK
# head must have been promoted.
GATES=$(q "$S" "SELECT COUNT(*) FROM pending_online_outbox;")
check "no pending gates remain" "$GATES" "0"
HEADS=$(q "$S" "SELECT COUNT(*) FROM pending_local_cert_heads;")
check "no pending EK heads remain" "$HEADS" "0"

# Both proposals terminal.
UNFIN=$(q "$S" "SELECT COUNT(*) FROM sender_online_proposal WHERE status != 'finalized';")
check "all proposals finalized" "$UNFIN" "0"

# Outbox rows survive finalization and reach a terminal transport state.
BADOB=$(q "$S" "SELECT COUNT(*) FROM sender_outbox WHERE status NOT IN ('gc_pending','complete');")
check "all outbox rows gc_pending/complete" "$BADOB" "0"

# Exactly-once: one lifecycle row per commitment, one per submission id.
OBN=$(q "$S" "SELECT COUNT(*)||'/'||COUNT(DISTINCT commitment)||'/'||COUNT(DISTINCT submission_id) FROM sender_outbox;")
echo "  outbox rows/distinct commitments/distinct submission_ids: $OBN"
DUPC=$(q "$S" "SELECT COUNT(*)-COUNT(DISTINCT commitment) FROM sender_outbox;")
check "no duplicate commitment in outbox" "$DUPC" "0"
DUPS=$(q "$S" "SELECT COUNT(*)-COUNT(DISTINCT submission_id) FROM sender_outbox;")
check "no duplicate submission_id in outbox" "$DUPS" "0"

# The EK chain actually advanced — this is what transfer #2 depends on.
echo "  cert heads (side|step|pk):"
q "$S" "SELECT '    '||side||' | '||step_count||' | '||substr(hex(chain_head_pubkey),1,10) FROM cert_chain_heads;"
LOCAL_STEP=$(q "$S" "SELECT step_count FROM cert_chain_heads WHERE side=0;")
[ -n "$LOCAL_STEP" ] && ok "sender Local cert head present (step=$LOCAL_STEP)" \
                     || bad "sender Local cert head MISSING — transfer #2 fell back to the root AK"

# Durable reconcile queue must be empty: a stranded repair means a projection
# silently disagrees with canonical state.
if q "$S" "SELECT 1 FROM projection_repair_queue LIMIT 1;" >/dev/null 2>&1; then
  REP=$(q "$S" "SELECT COUNT(*) FROM projection_repair_queue;")
  check "no stranded projection repairs" "$REP" "0"
fi

echo
echo "== recipient: exactly-once apply =="
APPLIES=$(q "$R" "SELECT COUNT(*)||'/'||COUNT(DISTINCT canonical_apply_id)||'/'||COUNT(DISTINCT nonce_hash)||'/'||COUNT(DISTINCT child_tip) FROM canonical_apply_identity;")
echo "  applies/distinct ids/nonces/children: $APPLIES"
DUPA=$(q "$R" "SELECT COUNT(*)-COUNT(DISTINCT canonical_apply_id) FROM canonical_apply_identity;")
check "no duplicate canonical apply" "$DUPA" "0"
DUPN=$(q "$R" "SELECT COUNT(*)-COUNT(DISTINCT nonce_hash) FROM canonical_apply_identity;")
check "no duplicate apply nonce (no double credit)" "$DUPN" "0"
DUPM=$(q "$R" "SELECT COUNT(*)-COUNT(DISTINCT prepared_receipt_commitment) FROM accepted_transition_marker;")
check "no duplicate acceptance marker" "$DUPM" "0"

echo
echo "== balances =="
SB=$(q "$S" "SELECT available FROM balance_projections WHERE token_id='ERA';")
RB=$(q "$R" "SELECT available FROM balance_projections WHERE token_id='ERA';")
echo "  sender ERA=${SB:-<none>}   recipient ERA=${RB:-<none>}"
[ -n "$EXP_SENDER" ]    && check "sender balance exact"    "${SB:-}" "$EXP_SENDER"
[ -n "$EXP_RECIPIENT" ] && check "recipient balance exact" "${RB:-}" "$EXP_RECIPIENT"

echo
echo "=============================================="
echo "  PASS=$PASS  FAIL=$FAIL"
echo "  artifacts: $OUT"
echo "=============================================="
[ "$FAIL" -eq 0 ] || exit 1

cat <<'NOTE'

Still to confirm from the SENDER logcat (not visible in the DB):
  * transfer #2 logs  used_root_ak=false
  * two lines matching "FINALIZED atomically on acceptance proof"
NOTE
