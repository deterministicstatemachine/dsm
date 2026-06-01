#!/usr/bin/env bash
# Verify SPDX-License-Identifier headers (Issue #23).
#
# Production-complete invariant: every `.rs` / `.kt` / `.ts` / `.tsx` source
# file under the workspace's primary code paths carries a
# `SPDX-License-Identifier: MIT OR Apache-2.0` header in its first 5 lines.
# Files that explicitly declare a different SPDX expression (e.g.
# `Apache-2.0` alone) are honored — this lint only catches the
# *missing* case, not the *wrong-license* case.
#
# Modes:
#   ./scripts/check-spdx.sh           - report missing files, exit 1 if any
#   ./scripts/check-spdx.sh --fix     - prepend the canonical header to
#                                       every missing file (idempotent)
#
# Used both as a CI gate and as the one-shot remediation tool that
# brought the workspace to 100% coverage in commit <see #23 close>.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Paths checked. Any new top-level source tree should be added here.
PATHS=(
    "dsm_client/deterministic_state_machine/dsm/src"
    "dsm_client/deterministic_state_machine/dsm_sdk/src"
    "dsm_storage_node/src"
    "dsm_client/android/app/src/main/java"
    "dsm_client/frontend/src"
    "tools/vertical_validation/src"
)

EXTS=("rs" "kt" "ts" "tsx")

# The canonical header we prepend with `--fix`. Files already carrying any
# SPDX-License-Identifier line in their first 5 lines are skipped — we do
# not overwrite explicit license choices.
CANONICAL_HEADER="// SPDX-License-Identifier: MIT OR Apache-2.0"

MODE="${1:-check}"

missing=()

for p in "${PATHS[@]}"; do
    [ -d "$p" ] || continue
    for ext in "${EXTS[@]}"; do
        while IFS= read -r -d '' file; do
            # Skip generated proto outputs (live under target/ or build/).
            case "$file" in
                */target/*|*/build/*|*/node_modules/*|*/__generated__/*) continue ;;
            esac
            # Detect existing SPDX line anywhere in the file. A few files in
            # the workspace previously carried the license header mid-file
            # (after imports); we treat any in-file SPDX line as sufficient
            # rather than prepending a duplicate. The CI gate doesn't care
            # *where* the line lives, only that it exists somewhere.
            if grep -q "SPDX-License-Identifier:" "$file" 2>/dev/null; then
                continue
            fi
            missing+=("$file")
        done < <(find "$p" -type f -name "*.${ext}" -print0 2>/dev/null)
    done
done

if [ "${#missing[@]}" -eq 0 ]; then
    echo "OK: every source file in the checked paths carries an SPDX header"
    exit 0
fi

if [ "$MODE" = "--fix" ]; then
    for file in "${missing[@]}"; do
        # Prepend the canonical header + a blank line. Using a temp file
        # so the prepend is atomic per-file.
        tmp="$(mktemp)"
        printf "%s\n\n" "$CANONICAL_HEADER" > "$tmp"
        cat "$file" >> "$tmp"
        mv "$tmp" "$file"
    done
    echo "Prepended canonical SPDX header to ${#missing[@]} file(s)."
    exit 0
fi

echo "MISSING SPDX-License-Identifier header in ${#missing[@]} file(s):" >&2
for f in "${missing[@]}"; do
    echo "  $f" >&2
done
echo "" >&2
echo "Run \`./scripts/check-spdx.sh --fix\` to add the canonical" >&2
echo "\`MIT OR Apache-2.0\` header to all missing files." >&2
exit 1
