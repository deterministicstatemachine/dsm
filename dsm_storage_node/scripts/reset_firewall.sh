#!/bin/bash

# DSM Storage Node - Firewall Reset
echo "🔄 Resetting DSM Storage Node Firewall Configuration"
echo "=================================================="

# Disable pfctl
echo "Disabling pfctl..."
sudo pfctl -d 2>/dev/null || echo "pfctl already disabled"

# Reset Application Firewall to defaults
echo "Resetting Application Firewall..."
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off

# Remove DSM app from firewall
DSM_BINARY="./target/release/dsm_storage_node"
if [[ -f "$DSM_BINARY" ]]; then
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --remove "$DSM_BINARY" 2>/dev/null || true
fi

# Clean up temp files
rm -f /tmp/dsm_pf.conf

echo "✅ Firewall configuration reset complete"
echo "⚠️  Note: Your system is now less protected. Re-run setup_firewall_macos.sh to restore security."
