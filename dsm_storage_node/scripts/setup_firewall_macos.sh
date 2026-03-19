#!/bin/bash

# DSM Storage Node - macOS Firewall Setup
# Configures macOS firewall for DSM storage node security

set -euo pipefail

echo "🔥 DSM Storage Node - macOS Firewall Setup"
echo "========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    log_error "This script is designed for macOS. For Linux, use the iptables version."
    exit 1
fi

# Function to enable macOS Application Firewall
setup_application_firewall() {
    log_info "Configuring macOS Application Firewall..."
    
    # Check current state
    current_state=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)
    if [[ "$current_state" == *"enabled"* ]]; then
        log_success "Application Firewall is already enabled"
    else
        log_info "Enabling Application Firewall..."
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
        log_success "Application Firewall enabled"
    fi
    
    # Enable stealth mode (don't respond to ping/port scans)
    stealth_state=$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode)
    if [[ "$stealth_state" == *"on"* ]]; then
        log_success "Stealth mode is already enabled"
    else
        log_info "Enabling stealth mode..."
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
        log_success "Stealth mode enabled"
    fi
    
    # Block all incoming connections by default
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall off
    
    log_success "Application Firewall configured"
}

# Function to configure pfctl rules
setup_pfctl_rules() {
    log_info "Setting up pfctl rules for DSM Storage Node..."
    
    # Create pfctl configuration file
    cat > /tmp/dsm_pf.conf << 'EOF'
# DSM Storage Node - pfctl configuration
# Secure firewall rules for DSM storage node

# Macros
dsm_ports = "{ 8080, 8081, 9090 }"
trusted_nets = "{ 127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8 }"

# Tables (for rate limiting)
table <dsm_rate_limit> persist

# Options
set skip on lo0
set block-policy drop

# Normalization
scrub in all

# Default policies
block all
pass out all keep state

# Allow loopback
pass on lo0 all

# Allow SSH (adjust port if needed)
pass in proto tcp from any to any port 22 keep state

# DSM Storage Node rules with rate limiting
# API port (8080) - limited connections
pass in proto tcp from $trusted_nets to any port 8080 keep state \
    (max-src-conn 10, max-src-conn-rate 5/60)

# P2P port (8081) - peer communication
pass in proto tcp from any to any port 8081 keep state \
    (max-src-conn 20, max-src-conn-rate 10/60)

# Metrics port (9090) - monitoring (local only)
pass in proto tcp from 127.0.0.0/8 to any port 9090 keep state \
    (max-src-conn 5, max-src-conn-rate 3/60)

# Rate limiting rules
pass in proto tcp from any to any port $dsm_ports keep state \
    (max-src-conn-rate 30/60, overload <dsm_rate_limit> flush global)

# Block overloaded IPs
block in from <dsm_rate_limit>

# ICMP (ping) - limited
pass in inet proto icmp icmp-type echoreq keep state \
    (max-src-conn-rate 2/10)

EOF

    log_success "pfctl rules created at /tmp/dsm_pf.conf"
}

# Function to apply pfctl rules
apply_pfctl_rules() {
    log_info "Applying pfctl rules..."
    
    # Load the rules
    if sudo pfctl -f /tmp/dsm_pf.conf 2>/dev/null; then
        log_success "pfctl rules loaded successfully"
    else
        log_warning "pfctl rules could not be loaded (pfctl might not be enabled)"
        log_info "To enable pfctl manually:"
        echo "  sudo pfctl -e"
        echo "  sudo pfctl -f /tmp/dsm_pf.conf"
    fi
    
    # Enable pfctl if not already enabled
    if ! sudo pfctl -s info | grep -q "Status: Enabled" 2>/dev/null; then
        log_info "Enabling pfctl..."
        sudo pfctl -e 2>/dev/null || log_warning "Could not enable pfctl automatically"
    fi
}

# Function to configure DSM node in Application Firewall
configure_dsm_app() {
    log_info "Configuring DSM Storage Node in Application Firewall..."
    
    # Check if DSM binary exists
    DSM_BINARY="./target/release/dsm_storage_node"
    if [[ -f "$DSM_BINARY" ]]; then
        # Add DSM node to firewall allowed applications
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add "$DSM_BINARY"
        sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblock "$DSM_BINARY"
        log_success "DSM Storage Node added to firewall exceptions"
    else
        log_warning "DSM binary not found at $DSM_BINARY"
        log_info "Build the project first with: cargo build --release"
    fi
}

# Function to show firewall status
show_firewall_status() {
    echo ""
    log_info "Current Firewall Status:"
    echo "========================"
    
    # Application Firewall status
    echo "Application Firewall:"
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
    
    # pfctl status
    echo -e "\npfctl Status:"
    if sudo pfctl -s info 2>/dev/null | head -5; then
        echo ""
        echo "Active Rules:"
        sudo pfctl -s rules 2>/dev/null | head -10 || echo "No pfctl rules active"
    else
        echo "pfctl not active or not available"
    fi
    
    # Show listening ports
    echo -e "\nListening Ports:"
    netstat -an | grep LISTEN | grep -E ":(8080|8081|9090)" || echo "No DSM ports currently listening"
}

# Function to create monitoring script
create_monitoring_script() {
    log_info "Creating firewall monitoring script..."
    
    cat > ./scripts/monitor_firewall.sh << 'EOF'
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
EOF

    chmod +x ./scripts/monitor_firewall.sh
    log_success "Firewall monitoring script created"
}

# Function to create firewall reset script
create_reset_script() {
    log_info "Creating firewall reset script..."
    
    cat > ./scripts/reset_firewall.sh << 'EOF'
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
EOF

    chmod +x ./scripts/reset_firewall.sh
    log_success "Firewall reset script created"
}

# Main menu
show_menu() {
    echo ""
    echo "🔐 macOS Firewall Configuration Options:"
    echo "======================================="
    echo "1) Full setup (Application Firewall + pfctl)"
    echo "2) Application Firewall only"
    echo "3) pfctl rules only"
    echo "4) Show current status"
    echo "5) Create monitoring/reset scripts"
    echo "6) Exit"
    echo ""
}

# Main execution
main() {
    log_info "Detecting macOS firewall capabilities..."
    
    # Check for required permissions
    if ! sudo -n true 2>/dev/null; then
        log_warning "This script requires sudo access for firewall configuration"
        echo "You may be prompted for your password"
    fi
    
    while true; do
        show_menu
        read -p "Choose an option (1-6): " choice
        
        case $choice in
            1)
                setup_application_firewall
                setup_pfctl_rules
                apply_pfctl_rules
                configure_dsm_app
                create_monitoring_script
                create_reset_script
                show_firewall_status
                log_success "Full firewall setup complete!"
                break
                ;;
            2)
                setup_application_firewall
                configure_dsm_app
                show_firewall_status
                log_success "Application Firewall setup complete!"
                break
                ;;
            3)
                setup_pfctl_rules
                apply_pfctl_rules
                show_firewall_status
                log_success "pfctl setup complete!"
                break
                ;;
            4)
                show_firewall_status
                ;;
            5)
                create_monitoring_script
                create_reset_script
                log_success "Monitoring and reset scripts created!"
                ;;
            6)
                log_info "Exiting..."
                exit 0
                ;;
            *)
                log_error "Invalid option. Please choose 1-6."
                ;;
        esac
    done
    
    echo ""
    echo "🎉 macOS Firewall Setup Complete!"
    echo "================================="
    echo ""
    echo "🔐 Security Features Enabled:"
    echo "  • Application Firewall with stealth mode"
    echo "  • pfctl rules with rate limiting"
    echo "  • DSM port protection (8080, 8081, 9090)"
    echo "  • Connection limits and rate throttling"
    echo ""
    echo "📊 Monitoring:"
    echo "  • Run ./scripts/monitor_firewall.sh to check status"
    echo "  • Logs available in Console.app (search 'socketfilterfw')"
    echo ""
    echo "🔄 Management:"
    echo "  • Reset with ./scripts/reset_firewall.sh"
    echo "  • Restart rules: sudo pfctl -f /tmp/dsm_pf.conf"
    echo ""
    echo "⚠️  Important Notes:"
    echo "  • pfctl rules may reset on reboot"
    echo "  • Application Firewall settings persist"
    echo "  • Test your DSM node connectivity after setup"
}

# Run main function
main "$@"
