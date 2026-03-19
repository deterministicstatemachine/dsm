#!/bin/bash

##
# DSM Bridge Autogeneration - End-to-End Test
# 
# This script demonstrates the complete autogeneration workflow:
# Kotlin @BridgeExport → KSP → JSON Manifest → TypeScript Bridge
##

set -e

echo "🚀 DSM Bridge Autogeneration - End-to-End Test"
echo "=============================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

cd "$(dirname "$0")/.."

echo -e "${BLUE}📋 Step 1: Checking Kotlin @BridgeExport annotations...${NC}"
BRIDGE_EXPORTS=$(grep -r "@BridgeExport" android/app/src/main/java/ | wc -l)
echo "   Found $BRIDGE_EXPORTS @BridgeExport annotations"

echo -e "${BLUE}🔧 Step 2: Running KSP to generate manifest...${NC}"
cd android
./gradlew kspKotlinDebug --quiet
cd ..

MANIFEST_FILE="android/app/build/generated/ksp/debug/bridge_manifest.json"
if [ -f "$MANIFEST_FILE" ]; then
    echo -e "${GREEN}✅ Bridge manifest generated successfully${NC}"
    
    if command -v jq &> /dev/null; then
        METHOD_COUNT=$(jq '.methods | length' "$MANIFEST_FILE")
        echo "   Exported methods: $METHOD_COUNT"
        echo "   Generated at: $(jq -r '.generatedAt | todate' "$MANIFEST_FILE")"
    fi
else
    echo "❌ Failed to generate bridge manifest"
    exit 1
fi

echo -e "${BLUE}🔄 Step 3: Generating TypeScript bridge...${NC}"
cd new_frontend

# Check if ts-node is available
if ! command -v npx &> /dev/null; then
    echo "Installing dependencies..."
    npm install
fi

npm run gen-bridge

GENERATED_BRIDGE="src/services/DsmBridge.generated.ts"
if [ -f "$GENERATED_BRIDGE" ]; then
    echo -e "${GREEN}✅ TypeScript bridge generated successfully${NC}"
    
    LINES=$(wc -l < "$GENERATED_BRIDGE")
    METHODS=$(grep -c "async.*(" "$GENERATED_BRIDGE" || echo "0")
    echo "   Generated lines: $LINES"
    echo "   Generated methods: $METHODS"
else
    echo "❌ Failed to generate TypeScript bridge"
    exit 1
fi

cd ..

echo -e "${BLUE}🔍 Step 4: Verifying bridge alignment...${NC}"
chmod +x scripts/check-bridge-drift.sh
./scripts/check-bridge-drift.sh

echo ""
echo -e "${GREEN}🎉 SUCCESS: Complete autogeneration workflow verified!${NC}"
echo ""
echo "📊 Summary:"
echo "   • Kotlin annotations: $BRIDGE_EXPORTS"
echo "   • Manifest methods: $(jq '.methods | length' "$MANIFEST_FILE" 2>/dev/null || echo "N/A")"
echo "   • TypeScript methods: $(grep -c "async.*(" "new_frontend/$GENERATED_BRIDGE" 2>/dev/null || echo "N/A")"
echo ""
echo -e "${YELLOW}🔄 To add a new bridge method:${NC}"
echo "   1. Add @BridgeExport annotation to Kotlin method"
echo "   2. Run: cd android && ./gradlew generateTypeScriptBridge"  
echo "   3. Commit the generated TypeScript file"
echo ""
echo -e "${GREEN}✨ Zero drift, zero maintenance, perfect alignment!${NC}"
