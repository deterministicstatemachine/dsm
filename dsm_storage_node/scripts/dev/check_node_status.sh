#!/bin/bash

echo "DSM Storage Node Status Check"
echo "========================================"

# Function to check if a port is in use
check_port() {
    local port=$1
    local node_name=$2
    
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null; then
        echo "✓ $node_name (port $port): Running"
        return 0
    else
        echo "✗ $node_name (port $port): Not running"
        return 1
    fi
}

# Function to check node health via API
check_health() {
    local port=$1
    local node_name=$2
    
    local response=$(curl -s -f http://localhost:$port/api/v2/health 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "  🏥 Health check: ✓ OK"
        echo "  📊 Status: $response"
    else
        echo "  🏥 Health check: ✗ Failed"
    fi
}

check_status() {
    local port=$1
    local node_name=$2
    echo "  📈 Node status: use /metrics for detailed telemetry"
}

running_count=0
total_nodes=5

echo
echo "Checking individual nodes..."
echo "----------------------------"

# Check each node
for i in {1..5}; do
    port=$((8079 + i))
    node_name="Node $i"
    
    echo
    echo "🔍 Checking $node_name (http://localhost:$port)"
    
    if check_port $port "$node_name"; then
        ((running_count++))
        check_health $port "$node_name"
        check_status $port "$node_name"
    fi
done

echo
echo "=================================="
echo "Summary"
echo "=================================="
echo "Running nodes: $running_count/$total_nodes"

if [ $running_count -eq $total_nodes ]; then
    echo "🎉 All nodes are running!"
    exit 0
elif [ $running_count -gt 0 ]; then
    echo "⚠️  Some nodes are not running"
    exit 1
else
    echo "❌ No nodes are running"
    exit 2
fi
