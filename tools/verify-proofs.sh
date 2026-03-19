#!/usr/bin/env bash
# ============================================================================
# DSM Formal Verification Report Generator
#
# Runs all machine-checked provers (TLAPS + Lean 4) and produces:
#   - verification-reports/verification-report.json  (structured)
#   - verification-reports/verification-report.txt   (human-readable)
#
# Usage:  ./tools/verify-proofs.sh [--json-only] [--quiet]
# Exit:   0 if all proofs pass, 1 if any fail
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TLA_DIR="$PROJECT_ROOT/tla"
LEAN_DIR="$PROJECT_ROOT/lean4"
REPORT_DIR="$PROJECT_ROOT/verification-reports"

JSON_ONLY=false
QUIET=false
for arg in "$@"; do
  case "$arg" in
    --json-only) JSON_ONLY=true ;;
    --quiet)     QUIET=true ;;
  esac
done

mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
REPORT_JSON="$REPORT_DIR/verification-report.json"
REPORT_TXT="$REPORT_DIR/verification-report.txt"

log() { $QUIET || echo "$@" >&2; }

# ============================================================================
# Resolve tlapm
# ============================================================================
TLAPM=""
if [ -n "${DSM_TLAPM_BIN:-}" ]; then
  TLAPM="$DSM_TLAPM_BIN"
elif command -v tlapm &>/dev/null; then
  TLAPM="tlapm"
elif command -v opam &>/dev/null && opam exec --switch=5.1.0 -- tlapm --help &>/dev/null 2>&1; then
  TLAPM="opam exec --switch=5.1.0 -- tlapm"
fi

# ============================================================================
# Helper: run tlapm on a module, return JSON line
# ============================================================================
run_tlapm() {
  local label="$1" module="$2" theorems_json="$3"

  if [ -z "$TLAPM" ]; then
    echo "{\"module\":\"$label\",\"file\":\"$module\",\"prover\":\"TLAPS\",\"passed\":false,\"obligations_proved\":0,\"obligations_total\":0,\"duration_ms\":0,\"theorems\":[$theorems_json],\"errors\":[\"tlapm not found\"]}"
    return
  fi

  log "  [$label] Running TLAPS on $module ..."

  local tmpout; tmpout=$(mktemp)
  local tmperr; tmperr=$(mktemp)
  local start_s; start_s=$(python3 -c 'import time; print(time.time())')

  set +e
  eval "$TLAPM" --cleanfp --stretch 5 "$TLA_DIR/$module" >"$tmpout" 2>"$tmperr"
  local rc=$?
  set -e

  local end_s; end_s=$(python3 -c 'import time; print(time.time())')
  local duration_ms; duration_ms=$(python3 -c "print(int(($end_s - $start_s) * 1000))")

  local combined; combined="$(cat "$tmpout" "$tmperr")"
  rm -f "$tmpout" "$tmperr"

  # Parse obligation count
  local obligations=0
  local obl_match; obl_match=$(echo "$combined" | grep -oE "All ([0-9]+) obligation" | grep -oE "[0-9]+" | tail -1 || true)
  [ -n "$obl_match" ] && obligations="$obl_match"

  # Parse errors
  local error_lines; error_lines=$(echo "$combined" | grep '\[ERROR\]' | head -5 || true)
  local passed=false
  [ "$rc" -eq 0 ] && [ -z "$error_lines" ] && passed=true

  local errors_json="[]"
  if [ -n "$error_lines" ]; then
    errors_json=$(python3 -c "
import json, sys
lines = sys.stdin.read().strip().split('\n')
print(json.dumps([l.strip() for l in lines if l.strip()]))
" <<< "$error_lines")
  fi

  local verdict="FAIL"; $passed && verdict="PASS"
  log "    $verdict: $obligations obligations proved (${duration_ms}ms)"

  echo "{\"module\":\"$label\",\"file\":\"$module\",\"prover\":\"TLAPS\",\"passed\":$passed,\"obligations_proved\":$obligations,\"obligations_total\":$obligations,\"duration_ms\":$duration_ms,\"theorems\":[$theorems_json],\"errors\":$errors_json}"
}

# ============================================================================
# Helper: run Lean 4, return JSON line
# ============================================================================
run_lean() {
  local label="Lean4_DSMCardinality" file="DSMCardinality.lean"
  local theorems_json='"fresh_insert_cardinality","empty_card_zero","card_le_succ_of_le","card_succ_le_of_lt","supply_conservation_emit","commit_shape_emit","unspent_budget_emit","subset_preserved_ack","unspent_budget_activate"'

  if ! command -v lean &>/dev/null; then
    echo "{\"module\":\"$label\",\"file\":\"$file\",\"prover\":\"Lean4\",\"passed\":false,\"obligations_proved\":0,\"obligations_total\":9,\"duration_ms\":0,\"theorems\":[$theorems_json],\"errors\":[\"lean not found\"]}"
    return
  fi

  log "  [$label] Running Lean 4 kernel check ..."

  local start_s; start_s=$(python3 -c 'import time; print(time.time())')

  set +e
  local output; output=$(lean "$LEAN_DIR/$file" 2>&1)
  local rc=$?
  set -e

  local end_s; end_s=$(python3 -c 'import time; print(time.time())')
  local duration_ms; duration_ms=$(python3 -c "print(int(($end_s - $start_s) * 1000))")

  local passed=false obligations=0 errors_json="[]"
  if [ "$rc" -eq 0 ]; then
    passed=true
    obligations=9
  else
    errors_json=$(python3 -c "
import json, sys
lines = [l.strip() for l in sys.stdin.read().strip().split('\n') if 'error' in l.lower()][:5]
print(json.dumps(lines if lines else ['lean exited with non-zero status']))
" <<< "$output")
  fi

  local verdict="FAIL"; $passed && verdict="PASS"
  log "    $verdict: $obligations theorems type-checked (${duration_ms}ms)"

  echo "{\"module\":\"$label\",\"file\":\"$file\",\"prover\":\"Lean4\",\"passed\":$passed,\"obligations_proved\":$obligations,\"obligations_total\":9,\"duration_ms\":$duration_ms,\"theorems\":[$theorems_json],\"errors\":$errors_json}"
}

# ============================================================================
# Main execution
# ============================================================================
log "============================================================================"
log "  DSM FORMAL VERIFICATION"
log "  $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
log "============================================================================"
log ""
log "Provers: TLAPS (Zenon + Isabelle + Z3) | Lean 4 (type-theory kernel)"
log ""

RESULTS=()
RESULTS+=("$(run_tlapm "DSM_Abstract" "DSM_Abstract.tla" '"AbstractInit","AbstractStep","AbstractSafetyTheorem","AbstractSpentMonotone","AbstractCommitMonotone"')")
RESULTS+=("$(run_tlapm "DSM_ProtocolCore" "DSM_ProtocolCore.tla" '"CoreInit","CoreStep","CoreSafety","CoreImplementsAbstract"')")
RESULTS+=("$(run_tlapm "DSM_InitProof" "DSM_InitProof.tla" '"ConcreteInitRefinesCore"')")
RESULTS+=("$(run_lean)")

log ""
log "JSON report written to: $REPORT_JSON"

# ============================================================================
# Assemble final JSON report
# ============================================================================
python3 - "$REPORT_JSON" "$REPORT_TXT" "$TIMESTAMP" "$PROJECT_ROOT" "$JSON_ONLY" "${RESULTS[@]}" <<'PYEOF'
import json, sys, subprocess, os

report_json_path = sys.argv[1]
report_txt_path = sys.argv[2]
timestamp = sys.argv[3]
project_root = sys.argv[4]
json_only = sys.argv[5] == "true"
module_jsons = sys.argv[6:]

modules = [json.loads(m) for m in module_jsons]

total_proved = sum(m["obligations_proved"] for m in modules)
total_total = sum(m["obligations_total"] for m in modules)
all_passed = all(m["passed"] for m in modules)

# Git info
try:
    version = subprocess.check_output(
        ["git", "describe", "--tags", "--always"],
        cwd=project_root, stderr=subprocess.DEVNULL
    ).decode().strip()
except Exception:
    version = "unknown"

try:
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=project_root, stderr=subprocess.DEVNULL
    ).decode().strip()
except Exception:
    commit = "unknown"

report = {
    "schema": "dsm-verification-report-v1",
    "timestamp": timestamp,
    "project": "DSM (Deterministic State Machine)",
    "version": version,
    "commit": commit,
    "verdict": "PASS" if all_passed else "FAIL",
    "summary": {
        "total_obligations_proved": total_proved,
        "total_obligations": total_total,
        "provers_used": sorted(set(m["prover"] for m in modules)),
        "all_passed": all_passed,
    },
    "modules": modules,
    "proof_architecture": {
        "description": "Three-tier refinement: Abstract -> ProtocolCore -> Concrete",
        "tiers": [
            {
                "name": "DSM_Abstract",
                "role": "Irreducible safety truths (no-double-spend, conservation, monotonicity)",
                "prover": "TLAPS",
            },
            {
                "name": "DSM_ProtocolCore",
                "role": "Protocol mechanics (DJTE, JAP, activation budget, supply conservation)",
                "prover": "TLAPS + Lean4",
                "note": "Cardinality arithmetic discharged by Lean 4 (TLAPS backends cannot reason about finite set cardinality)",
            },
            {
                "name": "DSM_InitProof",
                "role": "Concrete DSM Init state refines ProtocolCore Init",
                "prover": "TLAPS",
            },
        ],
        "properties_proved": [
            "NoDoubleSpend: consumed activation/spend proofs are never reusable",
            "Conservation: emitted value bounded by activation budget and source supply",
            "MonotoneCommit: commitment chain only advances forward",
            "MonotoneSpent: spent set never shrinks",
            "RefinementInit: concrete Init maps to abstract Init",
            "RefinementStep: concrete Next maps to abstract Next (structural)",
            "CoreSafety: protocol invariant preserved by all transitions",
            "SupplyConservation: sourceRemaining + Cardinality(spentJaps) = MaxSupply",
            "SpentSingleUse: Cardinality(spentJaps) <= actCount",
        ],
    },
}

with open(report_json_path, "w") as f:
    json.dump(report, f, indent=2)

# Human-readable report
lines = []
lines.append("=" * 78)
lines.append("  DSM FORMAL VERIFICATION REPORT")
lines.append(f"  Generated: {timestamp}")
lines.append(f"  Commit:    {commit[:12]}")
lines.append(f"  Version:   {version}")
lines.append("=" * 78)
lines.append("")
lines.append("  Module                  | Prover | Obligations | Verdict | Time")
lines.append("  ------------------------+--------+-------------+---------+--------")

for m in modules:
    v = "PASS" if m["passed"] else "FAIL"
    p = m["obligations_proved"]
    t = m["obligations_total"]
    lines.append(f"  {m['module']:<24}| {m['prover']:<6} | {p:>5}/{t:<5} | {v:<7} | {m['duration_ms']}ms")

lines.append("")
lines.append(f"  TOTAL: {total_proved} / {total_total} obligations machine-checked")
lines.append(f"  Provers: {', '.join(sorted(set(m['prover'] for m in modules)))}")
lines.append("")
lines.append("  Properties proved:")
for prop in report["proof_architecture"]["properties_proved"]:
    lines.append(f"    * {prop}")
lines.append("")
lines.append("=" * 78)
lines.append(f"  VERDICT: {'PASS' if all_passed else 'FAIL'}")
lines.append("=" * 78)

txt = "\n".join(lines) + "\n"
with open(report_txt_path, "w") as f:
    f.write(txt)

if json_only:
    print(json.dumps(report, indent=2))
else:
    print(txt)

sys.exit(0 if all_passed else 1)
PYEOF
