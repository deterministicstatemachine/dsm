#!/bin/bash

# DSM Storage Node - Firewall Setup for Production
echo "🔥 Setting up firewall rules for DSM Storage Node..."

# Enable UFW if available (Ubuntu/Debian)
if command -v ufw &> /dev/null; then
    echo "Configuring UFW firewall..."
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    # Allow SSH (adjust port as needed)
    sudo ufw allow 22/tcp
    
    # Allow DSM node communication on specific ports
    sudo ufw allow 8080/tcp comment "DSM Node API"
    sudo ufw allow 8081/tcp comment "DSM Node P2P"
    sudo ufw allow 9090/tcp comment "DSM Metrics"
    
    # Rate limiting for API endpoints
    sudo ufw limit 8080/tcp
    sudo ufw limit 8081/tcp
    
    sudo ufw --force enable
    echo "UFW firewall configured successfully"
fi

# Configure iptables rules (alternative/additional)
echo "Setting up iptables rules..."
cat > /tmp/dsm_iptables_rules << 'RULES'
# DSM Storage Node - iptables rules
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT

# Allow established connections
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (adjust port as needed)
-A INPUT -p tcp --dport 22 -j ACCEPT

# Rate limit and allow DSM node ports
-A INPUT -p tcp --dport 8080 -m limit --limit 60/min --limit-burst 10 -j ACCEPT
-A INPUT -p tcp --dport 8081 -m limit --limit 100/min --limit-burst 20 -j ACCEPT
-A INPUT -p tcp --dport 9090 -m limit --limit 30/min --limit-burst 5 -j ACCEPT

# Drop everything else
-A INPUT -j DROP

COMMIT
RULES

echo "iptables rules created at /tmp/dsm_iptables_rules"
echo "To apply: sudo iptables-restore < /tmp/dsm_iptables_rules"
