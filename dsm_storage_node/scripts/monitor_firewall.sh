#!/bin/bash

# DSM Storage Node - Firewall Monitoring
echo "🔍 DSM Storage Node - Firewall Status Monitor"
echo "============================================="

echo "📊 Connection Statistics:"
echo "========================"

# Show current connections to DSM ports
echo "DSM API (8080):"
netstat -an | grep ":8080" | wc -l | xargs echo "  Active connections:"

echo "DSM P2P (8081):"
netstat -an | grep ":8081" | wc -l | xargs echo "  Active connections:"

echo "DSM Metrics (9090):"
netstat -an | grep ":9090" | wc -l | xargs echo "  Active connections:"

echo ""
echo "🔥 Firewall Status:"
echo "=================="

# Application Firewall
echo "Application Firewall:"
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "  Not available"

# pfctl
echo "pfctl:"
if sudo pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
    echo "  Status: Enabled"
    echo "  Active rules: $(sudo pfctl -s rules 2>/dev/null | wc -l)"
else
    echo "  Status: Disabled or not available"
fi

echo ""
echo "📈 Recent Activity (last 10 connections):"
echo "========================================"
log show --predicate 'process == "socketfilterfw"' --last 10m --style compact 2>/dev/null | tail -10 || echo "No recent firewall activity"
