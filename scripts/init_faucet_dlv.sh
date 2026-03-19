#!/bin/bash
# Initialize Faucet DLV for ERA Token
# This script creates and stores the faucet DLV in storage nodes

set -e

echo "🔄 Initializing Faucet DLV for ERA Token..."

# Configuration
ERA_SUPPLY=1000000000000  # 1 trillion ERA tokens
DLV_ID="faucet-era-dlv"
CAPACITY_BYTES=1000000  # 1MB capacity
STAKE_HASH="0000000000000000000000000000000000000000000000000000000000000000"

# Check if DLV already exists
echo "📊 Checking existing DLV slots..."
EXISTING_COUNT=$(psql -h localhost -p 5432 -U dsm -d dsm_storage_node1 -t -c "SELECT COUNT(*) FROM dlv_slots WHERE dlv_id = '$DLV_ID';" 2>/dev/null || echo "0")

if [ "$EXISTING_COUNT" -gt 0 ]; then
    echo "✅ Faucet DLV already exists (count: $EXISTING_COUNT)"
    exit 0
fi

echo "📝 Creating faucet DLV with $ERA_SUPPLY ERA tokens..."

# Create DLV record
psql -h localhost -p 5432 -U dsm -d dsm_storage_node1 << EOF
INSERT INTO dlv_slots (dlv_id, capacity_bytes, used_bytes, stake_hash)
VALUES ('$DLV_ID', $CAPACITY_BYTES, 0, decode('$STAKE_HASH', 'hex'));
EOF

# Also create in other dev nodes if they exist
for node in dsm_storage_node2 dsm_storage_node3 dsm_storage_node4 dsm_storage_node5; do
    echo "📝 Creating DLV in $node..."
    psql -h localhost -p 5432 -U dsm -d "$node" << EOF 2>/dev/null || echo "⚠️  $node not available, skipping..."
INSERT INTO dlv_slots (dlv_id, capacity_bytes, used_bytes, stake_hash)
VALUES ('$DLV_ID', $CAPACITY_BYTES, 0, decode('$STAKE_HASH', 'hex'));
EOF
done

echo "✅ Faucet DLV initialized successfully!"
echo "🔍 Verifying DLV creation..."
psql -h localhost -p 5432 -U dsm -d dsm_storage_node1 -c "SELECT dlv_id, capacity_bytes, used_bytes FROM dlv_slots WHERE dlv_id = '$DLV_ID';" || echo "❌ Verification failed"