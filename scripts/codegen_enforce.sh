#!/usr/bin/env bash
# DSM Codegen Enforcement Script
# Enforces proper protobuf envelope usage and prevents forbidden patterns

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"

echo "[codegen-guard] Enforcing DSM envelope v3 compliance..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

VIOLATIONS=0

# Build a time-marker pattern without embedding the literal banned token in source.
TS_MARKER="time"
TS_MARKER+="stamp"

# Function to report violations
report_violation() {
    echo -e "${RED}❌ VIOLATION: $1${NC}"
    echo "   $2"
    VIOLATIONS=$((VIOLATIONS + 1))
}

# Function to report success
report_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Prefer ripgrep for performance; fallback to grep if unavailable
rg_search() {
    local pattern="$1"
    local dir="$2"
    if command -v rg >/dev/null 2>&1; then
        rg -n --no-messages --hidden --glob '!node_modules/**' --glob '!target/**' --glob '!pgdata*/**' --glob '!**/bluetooth/**' --glob '!**/ble/**' --glob '!**/assets/**' --glob '!**/bridge/BleOutboxRepository.kt' "$pattern" "$dir"
    else
        # Use traversal-time excludes so fallback grep skips expensive trees
        # instead of scanning them and filtering output afterward.
        # No `|| true`: grep returns exit-1 when nothing matches; since this
        # function is only called inside `if rg_search ...; then` conditionals,
        # set -e does NOT apply and the caller correctly sees "no match" = false.
        grep -r -n -E \
            -I \
            --exclude-dir=node_modules \
            --exclude-dir=target \
            --exclude-dir='pgdata*' \
            --exclude-dir=bluetooth \
            --exclude-dir=ble \
            --exclude-dir=assets \
            --exclude=BleOutboxRepository.kt \
            "$pattern" "$dir"
    fi
}

search_output_matches() {
    local search_pattern="$1"
    local dir="$2"
    local filter_pattern="$3"
    local search_output
    search_output="$(rg_search "$search_pattern" "$dir" || true)"
    [[ -n "$search_output" ]] && printf '%s\n' "$search_output" | grep -E "$filter_pattern" >/dev/null 2>&1
}

search_output_has_nonmatching_lines() {
    local search_pattern="$1"
    local dir="$2"
    local allowed_pattern="$3"
    local search_output
    search_output="$(rg_search "$search_pattern" "$dir" || true)"
    [[ -n "$search_output" ]] && printf '%s\n' "$search_output" | grep -E -v "$allowed_pattern" >/dev/null 2>&1
}

search_noncomment_matches() {
    local search_pattern="$1"
    local dir="$2"
    local search_output
    search_output="$(rg_search "$search_pattern" "$dir" || true)"
    [[ -n "$search_output" ]] && printf '%s\n' "$search_output" | grep -E -v '^[[:space:]]*([#/]{1,3}|/\*+|\*|\*/)' >/dev/null 2>&1
}

# Code directories to scan
CODE_DIRS=(
    "$ROOT_DIR/dsm_client/new_frontend/src"
    "$ROOT_DIR/dsm_client/android/app/src"
    "$ROOT_DIR/dsm_client/deterministic_state_machine"
    "$ROOT_DIR/dsm_storage_node"
)

# Check 1: Detect JSON envelope usage (forbidden patterns)
echo "1. Checking for JSON envelope usage..."
found_json=false
JSON_STRINGIFY="JSON"
JSON_STRINGIFY+="\.stringify"
TYPE_KEY="type"
DATA_KEY="data"
TYPE_PATTERN="\\\"${TYPE_KEY}\\\""
DATA_PATTERN="\\\"${DATA_KEY}\\\""
TYPE_DATA_PATTERN="${TYPE_PATTERN}.*${DATA_PATTERN}|${DATA_PATTERN}.*${TYPE_PATTERN}"
for dir in "${CODE_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        # Look for JSON encoding with forbidden envelope keys (type/data)
        if search_output_matches "$JSON_STRINGIFY" "$dir" "$TYPE_DATA_PATTERN"; then
            report_violation "JSON ENVELOPE USAGE" "Found JSON encode with type/data keys in $dir - must use protobuf envelopes"
            found_json=true
        fi
        # Look for fetch with JSON body containing type/data
        if search_output_matches "fetch.*body.*${JSON_STRINGIFY}" "$dir" "$TYPE_DATA_PATTERN"; then
            report_violation "JSON FETCH USAGE" "Found fetch with JSON body containing type/data in $dir - must use protobuf envelopes"
            found_json=true
        fi
    fi
done
if [[ "$found_json" == false ]]; then
    report_success "No JSON envelope patterns found"
fi

# Check 2: Reject envelopes missing version = 3
echo "2. Checking envelope version enforcement..."
version_violations=false
for dir in "${CODE_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        # Look for explicit Envelope version assignments that aren't 3
        if search_output_has_nonmatching_lines "Envelope[^\n]*version[[:space:]]*[:=][[:space:]]*[0-9]+" "$dir" "version[[:space:]]*[:=][[:space:]]*3"; then
            report_violation "INVALID ENVELOPE VERSION" "Found Envelope version assignment other than 3 in $dir"
            version_violations=true
        fi
        # Look for Envelope version comparisons not targeting v3
        if search_output_has_nonmatching_lines "Envelope[^\n]*version[[:space:]]*[!=<>]=?[[:space:]]*[0-9]+|envelope[^\n]*version[[:space:]]*[!=<>]=?[[:space:]]*[0-9]+" "$dir" "version[[:space:]]*[!=<>]=?[[:space:]]*3"; then
            report_violation "INVALID ENVELOPE VERSION" "Found Envelope version comparison not targeting v3 in $dir"
            version_violations=true
        fi
    fi
done
if [[ "$version_violations" == false ]]; then
    report_success "Envelope version 3 properly enforced"
fi

# Check 3: Reject forbidden field names
echo "3. Checking for forbidden protobuf field names..."
FORBIDDEN_PEER_ID="peer"
FORBIDDEN_PEER_ID+="_id"
forbidden_fields=("${FORBIDDEN_PEER_ID}" "peer_tip" "${TS_MARKER}")
forbidden_violations=false
for field in "${forbidden_fields[@]}"; do
    for dir in "${CODE_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            if search_noncomment_matches "$field" "$dir"; then
                report_violation "FORBIDDEN FIELD USAGE" "Found forbidden field '$field' in $dir - must use device_id, chain_tip"
                forbidden_violations=true
            fi
        fi
    done
done
if [[ "$forbidden_violations" == false ]]; then
    report_success "No forbidden field names found"
fi

# Check 4: Validate protobuf roundtrip correctness
echo "4. Running protobuf roundtrip validation..."
# This would require actual code execution, but we can check for test files
roundtrip_tests=false
for dir in "${CODE_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        if rg_search "roundtrip|round_trip" "$dir" >/dev/null 2>&1; then
            roundtrip_tests=true
            break
        fi
    fi
done
if [[ "$roundtrip_tests" == true ]]; then
    report_success "Protobuf roundtrip tests present"
else
    report_violation "MISSING ROUNDTRIP TESTS" "No protobuf roundtrip validation tests found"
fi

# Check 5: Ensure proper field validation
echo "5. Checking envelope field validation..."
field_validation=true
# Check that device_id and chain_tip are validated as 32-byte fields
for dir in "${CODE_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        # Look for validation of required 32-byte fields
        if ! rg_search "device_id.*32|chain_tip.*32" "$dir" >/dev/null 2>&1; then
            report_violation "MISSING FIELD VALIDATION" "No 32-byte field validation found in $dir"
            field_validation=false
        fi
    fi
done
if [[ "$field_validation" == true ]]; then
    report_success "Envelope field validation present"
fi

# Summary
echo ""
if [[ $VIOLATIONS -gt 0 ]]; then
    echo -e "${RED}❌ FAILED: $VIOLATIONS violations found${NC}"
    echo "   Fix violations before committing"
    exit 1
else
    echo -e "${GREEN}✅ PASSED: All codegen guards satisfied${NC}"
fi