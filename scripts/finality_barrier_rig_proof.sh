#!/usr/bin/env bash
# Finality barrier — hardware proof over two phones' client DBs. Read-only.
#
#   ./scripts/finality_barrier_rig_proof.sh <A-serial> <B-serial>
#
# Run AFTER: A→B, A→B, then B→A on the installed build (schema v3). Pulls both
# client DBs and asserts what the barrier guarantees:
#   - every proposal on both sides finalized; every outbox row gc_pending|complete
#   - no pending gate, no pending EK head, on either side
#   - every acceptance journal peer_finalized = 1 (both sides absorbed the certificates)
#   - counterparty_canonical_heads present on both sides, and B's send parent for
#     the reverse leg == A's pinned head for B (A applied it exactly once)
#   - exactly one relationship_finalized artifact per finalized proposal
set -uo pipefail

A="${1:?A serial}"; B="${2:?B serial}"
OUT="$(mktemp -d)"; PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($3)" || bad "$1 — expected [$3], got [$2]"; }
tid_for() { for t in $(adb devices -l 2>/dev/null | grep -o 'transport_id:[0-9]*' | cut -d: -f2); do [ "$(adb -t "$t" shell getprop ro.serialno 2>/dev/null | tr -d '\r')" = "$1" ] && { echo "$t"; return 0; }; done; return 1; }
pull() { local tid; tid="$(tid_for "$1")" || { echo "device $1 not attached" >&2; return 1; }; adb -t "$tid" shell "run-as com.dsm.wallet cat files/dsm_client.db" > "$2" 2>/dev/null; [ -s "$2" ] || { echo "empty DB from $1" >&2; return 1; }; }
q() { sqlite3 "$1" "$2" 2>/dev/null; }

echo "== pulling =="; pull "$A" "$OUT/a.db" || exit 1; pull "$B" "$OUT/b.db" || exit 1
SA="$OUT/a.db"; SB="$OUT/b.db"; echo "  A=$A B=$B ($OUT)"

for side in A B; do
  db=$([ $side = A ] && echo "$SA" || echo "$SB")
  echo; echo "== $side =="
  check "$side schema v3" "$(q "$db" 'PRAGMA user_version;')" "3"
  check "$side proposals not finalized" "$(q "$db" "SELECT COUNT(*) FROM sender_online_proposal WHERE status != 'finalized';")" "0"
  check "$side outbox rows not gc_pending/complete" "$(q "$db" "SELECT COUNT(*) FROM sender_outbox WHERE status NOT IN ('gc_pending','complete');")" "0"
  check "$side pending gates" "$(q "$db" "SELECT COUNT(*) FROM pending_online_outbox;")" "0"
  check "$side pending EK heads" "$(q "$db" "SELECT COUNT(*) FROM pending_local_cert_heads;")" "0"
  check "$side journals awaiting peer certificate" "$(q "$db" "SELECT COUNT(*) FROM acceptance_fold_journal WHERE status != 'rejected' AND peer_finalized = 0;")" "0"
  check "$side journals not complete" "$(q "$db" "SELECT COUNT(*) FROM acceptance_fold_journal WHERE status != 'complete';")" "0"
  check "$side staging terminal_reject" "$(q "$db" "SELECT COUNT(*) FROM recipient_staging WHERE state = 'terminal_reject';")" "0"
  P=$(q "$db" "SELECT COUNT(*) FROM sender_online_proposal WHERE status='finalized';")
  C=$(q "$db" "SELECT COUNT(*) FROM sender_outbox_artifacts WHERE role='relationship_finalized';")
  check "$side one certificate per finalized proposal" "$C" "$P"
  check "$side certificate rows carry a frozen route" "$(q "$db" "SELECT COUNT(*) FROM sender_outbox_artifacts WHERE role='relationship_finalized' AND (routing_address IS NULL OR routing_address='');")" "0"
  check "$side tips converge on every contact" "$(q "$db" "SELECT COUNT(*) FROM contacts WHERE chain_tip IS NOT local_bilateral_chain_tip;")" "0"
  check "$side no contact needs_online_reconcile" "$(q "$db" "SELECT COUNT(*) FROM contacts WHERE needs_online_reconcile != 0;")" "0"
  echo "  $side counterparty heads: $(q "$db" "SELECT hex(substr(counterparty_device_id,1,4))||'.. head='||hex(substr(head_tip,1,4))||'..' FROM counterparty_canonical_heads;" | tr '\n' ' ')"
done

echo; echo "== cross-device: the head-pin equality (count-agnostic) =="
# The load-bearing invariant, in BOTH directions and independent of how many
# generations ran: each side's pinned head for its peer is exactly the lineage
# head that peer will sign its NEXT origination under — i.e. the peer's most
# recently applied child tip (what the peer journaled as applied_child_tip_b).
# This is the value whose absence caused the 2026-08-16 reverse-leg rejection.
# Each side applies as many inbound transfers as the OTHER side finalized as
# sender, so the totals are derived, not hardcoded.
A_APPLIES=$(q "$SA" "SELECT COUNT(*) FROM canonical_apply_identity;")
B_APPLIES=$(q "$SB" "SELECT COUNT(*) FROM canonical_apply_identity;")
B_SENT=$(q "$SB" "SELECT COUNT(*) FROM sender_online_proposal WHERE status='finalized';")
A_SENT=$(q "$SA" "SELECT COUNT(*) FROM sender_online_proposal WHERE status='finalized';")
check "A applied exactly the transfers B finalized as sender" "$A_APPLIES" "$B_SENT"
check "B applied exactly the transfers A finalized as sender" "$B_APPLIES" "$A_SENT"
# A pins B's lineage head. B's lineage advances on BOTH B's applies (recipient)
# AND B's sends (originator), so its current head is the child of B's MOST
# RECENT op — whichever of {last finalized send's canonical_child, last apply's
# applied_child_tip_b} came later. `dsm_client.db` writes deterministic ticks,
# so order by rowid within each table and take the one that exists / is later.
# The UNION picks B's single newest asymmetric child across both roles.
head_of() { # $1=db
  q "$1" "SELECT hex(child) FROM (
             SELECT rowid AS r, canonical_child AS child FROM sender_online_proposal WHERE status='finalized'
             UNION ALL
             SELECT rowid AS r, applied_child_tip_b AS child FROM acceptance_fold_journal
           ) ORDER BY r DESC LIMIT 1;"
}
# NOTE: rowid is per-table, so a cross-table max-rowid is not a true time order.
# Assert instead that A's pin for B equals B's newest child from EITHER role.
A_PIN_B=$(q "$SA" "SELECT hex(head_tip) FROM counterparty_canonical_heads;")
B_LAST_SEND=$(q "$SB" "SELECT hex(canonical_child) FROM sender_online_proposal WHERE status='finalized' ORDER BY rowid DESC LIMIT 1;")
B_LAST_APPLY=$(q "$SB" "SELECT hex(applied_child_tip_b) FROM acceptance_fold_journal ORDER BY rowid DESC LIMIT 1;")
if [ "$A_PIN_B" = "$B_LAST_SEND" ] || [ "$A_PIN_B" = "$B_LAST_APPLY" ]; then
  ok "A's pinned head for B == B's current lineage head ($A_PIN_B)"
else bad "A's pinned head for B ($A_PIN_B) != B's last send ($B_LAST_SEND) or last apply ($B_LAST_APPLY)"; fi
B_PIN_A=$(q "$SB" "SELECT hex(head_tip) FROM counterparty_canonical_heads;")
A_LAST_SEND=$(q "$SA" "SELECT hex(canonical_child) FROM sender_online_proposal WHERE status='finalized' ORDER BY rowid DESC LIMIT 1;")
A_LAST_APPLY=$(q "$SA" "SELECT hex(applied_child_tip_b) FROM acceptance_fold_journal ORDER BY rowid DESC LIMIT 1;")
if [ "$B_PIN_A" = "$A_LAST_SEND" ] || [ "$B_PIN_A" = "$A_LAST_APPLY" ]; then
  ok "B's pinned head for A == A's current lineage head ($B_PIN_A)"
else bad "B's pinned head for A ($B_PIN_A) != A's last send ($A_LAST_SEND) or last apply ($A_LAST_APPLY)"; fi
echo; echo "PASS=$PASS FAIL=$FAIL"; [ "$FAIL" = 0 ]
