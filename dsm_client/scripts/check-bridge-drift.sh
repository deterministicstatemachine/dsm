#!/bin/bash

##
# DSM Bridge Drift Detection - CI Gate
# 
# This script ensures that the generated TypeScript bridge is always in sync
# with the Kotlin @BridgeExport annotations. If any drift is detected, the
# build fails immediately.
##

set -e

echo "🔍 DSM Bridge Drift Detection - Starting..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Paths
ANDROID_DIR="./android"
FRONTEND_DIR="./frontend"
GENERATED_BRIDGE="$FRONTEND_DIR/src/services/DsmBridge.generated.ts"
MANIFEST_FILE="$ANDROID_DIR/app/build/generated/ksp/debug/bridge_manifest.json"

echo "📍 Checking paths..."
echo "   Android: $ANDROID_DIR"
echo "   Frontend: $FRONTEND_DIR"
echo "   Generated Bridge: $GENERATED_BRIDGE"
echo "   Manifest: $MANIFEST_FILE"

# Step 1: Check if Android build has been run
if [ ! -f "$MANIFEST_FILE" ]; then
    echo -e "${RED}❌ Bridge manifest not found: $MANIFEST_FILE${NC}"
    echo -e "${YELLOW}   Run Android build first: cd android && ./gradlew kspKotlinDebug${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Bridge manifest found${NC}"

# Step 2: Check if TypeScript bridge exists
if [ ! -f "$GENERATED_BRIDGE" ]; then
    echo -e "${RED}❌ Generated TypeScript bridge not found: $GENERATED_BRIDGE${NC}"
    echo -e "${YELLOW}   Run bridge generation: cd frontend && npm run gen-bridge${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Generated TypeScript bridge found${NC}"

# Step 3: Store current bridge content
TEMP_DIR=$(mktemp -d)
cp "$GENERATED_BRIDGE" "$TEMP_DIR/bridge.old.ts"

echo "🔄 Regenerating TypeScript bridge to check for drift..."

# Step 4: Regenerate the bridge
cd "$FRONTEND_DIR"
npm run gen-bridge

# Step 5: Check for differences
if ! diff -q "$GENERATED_BRIDGE" "$TEMP_DIR/bridge.old.ts" > /dev/null; then
    echo -e "${RED}❌ DRIFT DETECTED: TypeScript bridge is out of sync!${NC}"
    echo ""
    echo -e "${YELLOW}Changes detected in generated bridge:${NC}"
    diff "$TEMP_DIR/bridge.old.ts" "$GENERATED_BRIDGE" || true
    echo ""
    echo -e "${RED}The TypeScript bridge has drifted from the Kotlin annotations.${NC}"
    echo -e "${YELLOW}To fix this:${NC}"
    echo "   1. Commit the updated bridge file"
    echo "   2. Or run: cd android && ./gradlew generateTypeScriptBridge"
    echo ""
    
    # Clean up
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo -e "${GREEN}✅ No drift detected - bridge is in sync${NC}"

# Step 6: Verify the manifest is recent
MANIFEST_AGE=$(find "$MANIFEST_FILE" -mtime +1 | wc -l)
if [ "$MANIFEST_AGE" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Warning: Bridge manifest is more than 1 day old${NC}"
    echo -e "${YELLOW}   Consider running a fresh Android build${NC}"
fi

# Step 7: Count exported methods
if command -v jq &> /dev/null; then
    METHOD_COUNT=$(jq '.methods | length' "$MANIFEST_FILE")
    echo -e "${GREEN}📊 Bridge exports $METHOD_COUNT methods${NC}"
fi

# Clean up
rm -rf "$TEMP_DIR"

echo -e "${GREEN}🎉 DSM Bridge Drift Detection - PASSED${NC}"
echo "   The TypeScript bridge is perfectly aligned with Kotlin annotations"
echo "   No manual maintenance required"
