#!/usr/bin/env bash
# Prevents unauthorized modifications to the Bluetooth core.

set -euo pipefail

echo "[ble-guard] Checking for unauthorized Bluetooth modifications..."

# Determine the base reference to compare against.
# In CI environments like GitHub Actions, we compare against the base/target branch.
BASE_REF="${GITHUB_BASE_REF:-origin/main}"

# Fallback: if not found, just check for any local uncommitted/staged changes,
# or modifications in the last commit.
if ! git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
    BASE_REF="HEAD"
fi

# Get list of changed files
CHANGED_FILES=$(git diff --name-only "$BASE_REF" 2>/dev/null || git diff --name-only HEAD || echo "")

# Look for changes in our protected directories
# 1) Rust Bluetooth SDK
# 2) Android Kotlin Bluetooth bridge/coordinator 
BLE_MODS=$(echo "$CHANGED_FILES" | grep -Ei "dsm_sdk/src/bluetooth|android/app/src/main/java/com/dsm/wallet/bridge/ble|android/app/src/main/java/com/dsm/wallet/bridge/UnifiedBleBridge" || true)

if [[ -n "$BLE_MODS" ]]; then
    echo "❌ ERROR: Modifications to the Bluetooth core layers are strictly prohibited."
    echo "The following protected files were modified:"
    echo "$BLE_MODS"
    echo ""
    echo "Please revert your Bluetooth changes or seek authorization from the core owner. Exiting."
    exit 1
fi

echo "✅ No unauthorized Bluetooth modifications detected."
exit 0
