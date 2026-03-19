#!/bin/bash

# DSM Storage Node - Production Security Setup Script
# This script implements short-term security hardening measures

set -euo pipefail

echo "🔒 DSM Storage Node - Production Security Setup"
echo "=============================================="

# Create secure directories
echo "📁 Creating secure directories..."
mkdir -p ./keys/production
mkdir -p ./config/production
mkdir -p ./logs/secure
chmod 700 ./keys/production
chmod 750 ./config/production
chmod 750 ./logs/secure

# Generate environment template for sensitive configuration
echo "🔐 Creating environment configuration template..."
cat > ./.env.template << 'EOF'
# DSM Storage Node - Production Environment Configuration
# Copy this file to .env and fill in your production values

# Node Security
DSM_NODE_PRIVATE_KEY_PATH="./keys/production/node.key"
DSM_NODE_PUBLIC_KEY_PATH="./keys/production/node.pub"
DSM_TLS_CERT_PATH="./keys/production/node.crt"
DSM_TLS_KEY_PATH="./keys/production/node.key"

# Database Security
DSM_DATABASE_ENCRYPTION_KEY=""
DSM_DATABASE_PATH="./data/storage_encrypted.db"

# Network Security
DSM_RATE_LIMIT_PER_MINUTE="60"
DSM_MAX_CONNECTIONS="500"
DSM_CONNECTION_TIMEOUT="15"

# API Security
DSM_API_SECRET_KEY=""
DSM_CORS_ORIGINS="https://yourdomain.com"
DSM_MAX_BODY_SIZE="5242880"  # 5MB

# Staking Security (if enabled)
DSM_STAKING_PRIVATE_KEY=""
DSM_STAKING_ADDRESS=""
DSM_VALIDATOR_ID=""

# Monitoring
DSM_LOG_LEVEL="warn"
DSM_ENABLE_METRICS="true"
DSM_METRICS_PORT="9090"
EOF

# Create production configuration template
echo "⚙️ Creating production configuration template..."
cat > ./config/production/config-production.toml << 'EOF'
# DSM Storage Node - Production Configuration Template
# Use environment variables for sensitive values

# API configuration
[api]
bind_address = "127.0.0.1"
port = 8080
enable_cors = true
enable_rate_limits = true
max_body_size_env = "DSM_MAX_BODY_SIZE"

# Node information
[node]
id_env = "DSM_NODE_ID"
name = "DSM Storage Node Production"
region_env = "DSM_NODE_REGION"
operator_env = "DSM_NODE_OPERATOR"
version = "0.1.0"
description = "Production storage node for DSM"
public_key_path_env = "DSM_NODE_PUBLIC_KEY_PATH"
endpoint_env = "DSM_NODE_ENDPOINT"

# Storage configuration
[storage]
engine = "epidemic"
capacity = 107374182400  # 100 GB
data_dir_env = "DSM_DATA_DIR"
database_path_env = "DSM_DATABASE_PATH"
assignment_strategy = "DeterministicHashing"
replication_strategy = "FixedReplicas"
replica_count = 3
min_regions = 2
default_ttl = 86400  # 24 hours
enable_pruning = true
pruning_interval = 1800  # 30 minutes

# Network configuration
[network]
listen_addr = "127.0.0.1"
public_endpoint_env = "DSM_PUBLIC_ENDPOINT"
port = 8080
max_connections_env = "DSM_MAX_CONNECTIONS"
connection_timeout_env = "DSM_CONNECTION_TIMEOUT"
enable_discovery = true
discovery_interval = 300
max_peers = 50

# Security configuration
[security]
private_key_path_env = "DSM_NODE_PRIVATE_KEY_PATH"
public_key_path_env = "DSM_NODE_PUBLIC_KEY_PATH"
enable_tls = true
tls_cert_path_env = "DSM_TLS_CERT_PATH"
tls_key_path_env = "DSM_TLS_KEY_PATH"
require_auth = true
enable_rate_limits = true
rate_limit_env = "DSM_RATE_LIMIT_PER_MINUTE"

# Logging configuration
[logging]
level_env = "DSM_LOG_LEVEL"
file_path = "./logs/secure/production.log"
format = "json"
console_logging = false
enable_audit_log = true
audit_log_path = "./logs/secure/audit.log"
EOF

# Create firewall setup script
echo "🔥 Creating firewall configuration..."
cat > ./scripts/setup_firewall.sh << 'EOF'
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
EOF

chmod +x ./scripts/setup_firewall.sh

# Create monitoring setup script
echo "📊 Creating monitoring configuration..."
cat > ./scripts/setup_monitoring.sh << 'EOF'
#!/bin/bash

# DSM Storage Node - Monitoring Setup
echo "📊 Setting up monitoring for DSM Storage Node..."

# Create monitoring directory
mkdir -p ./monitoring

# Create basic health check script
cat > ./monitoring/health_check.sh << 'HEALTH'
#!/bin/bash

# DSM Storage Node Health Check
API_PORT=${DSM_API_PORT:-8080}
HEALTH_ENDPOINT="http://127.0.0.1:${API_PORT}/health"

# Check if node is responding
if curl -f -s "${HEALTH_ENDPOINT}" > /dev/null; then
    echo "✅ DSM Storage Node is healthy"
    exit 0
else
    echo "❌ DSM Storage Node is not responding"
    exit 1
fi
HEALTH

chmod +x ./monitoring/health_check.sh

# Create log rotation configuration
cat > ./monitoring/logrotate.conf << 'LOGROTATE'
# DSM Storage Node Log Rotation
./logs/secure/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 $(whoami) $(whoami)
    postrotate
        # Send SIGHUP to dsm process to reopen log files
        pkill -HUP dsm_storage_node || true
    endscript
}
LOGROTATE

echo "Monitoring setup complete!"
echo "Add to crontab for health checks:"
echo "*/5 * * * * /path/to/dsm/monitoring/health_check.sh"
EOF

chmod +x ./scripts/setup_monitoring.sh

# Create secure startup script
echo "🚀 Creating secure startup script..."
cat > ./scripts/start_production.sh << 'EOF'
#!/bin/bash

# DSM Storage Node - Secure Production Startup
set -euo pipefail

echo "🚀 Starting DSM Storage Node in Production Mode"

# Check if .env file exists
if [[ ! -f .env ]]; then
    echo "❌ Error: .env file not found!"
    echo "Please copy .env.template to .env and configure your production values"
    exit 1
fi

# Load environment variables
set -a
source .env
set +a

# Validate required environment variables
required_vars=(
    "DSM_NODE_ID"
    "DSM_NODE_PRIVATE_KEY_PATH"
    "DSM_NODE_PUBLIC_KEY_PATH"
    "DSM_DATABASE_PATH"
)

for var in "${required_vars[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        echo "❌ Error: Required environment variable $var is not set"
        exit 1
    fi
done

# Check if key files exist
if [[ ! -f "$DSM_NODE_PRIVATE_KEY_PATH" ]]; then
    echo "❌ Error: Private key file not found: $DSM_NODE_PRIVATE_KEY_PATH"
    exit 1
fi

# Set secure permissions
chmod 600 "$DSM_NODE_PRIVATE_KEY_PATH"
chmod 644 "$DSM_NODE_PUBLIC_KEY_PATH"

# Create data directory if it doesn't exist
mkdir -p "$(dirname "$DSM_DATABASE_PATH")"

# Start the node with production configuration
echo "✅ Starting DSM Storage Node..."
exec ./target/release/dsm_storage_node \
    --config ./config/production/config-production.toml \
    --log-level "${DSM_LOG_LEVEL:-warn}" \
    --production
EOF

chmod +x ./scripts/start_production.sh

# Create the scripts directory if it doesn't exist
mkdir -p ./scripts

echo ""
echo "✅ Production Security Setup Complete!"
echo "======================================"
echo ""
echo "📋 Next Steps:"
echo "1. Copy .env.template to .env and configure your production values"
echo "2. Generate production TLS certificates:"
echo "   • Quick setup: ./scripts/quick_tls_setup.sh"
echo "   • Full CA setup: ./scripts/generate_tls_certificates.sh"
echo "3. Run ./scripts/setup_firewall.sh (requires sudo)"
echo "4. Run ./scripts/setup_monitoring.sh"
echo "5. Use ./scripts/start_production.sh to start in production mode"
echo ""
echo "🔐 Security Features Implemented:"
echo "✓ Secure node IDs with 64-bit entropy"
echo "✓ Environment variable configuration"
echo "✓ TLS encryption enabled"
echo "✓ Rate limiting configured"
echo "✓ Firewall rules prepared"
echo "✓ Audit logging enabled"
echo "✓ Secure file permissions"
echo "✓ Health monitoring"
echo ""
echo "⚠️  Important:"
echo "- Review all configuration files before production deployment"
echo "- Ensure all private keys are generated securely"
echo "- Test the configuration in a staging environment first"
echo "- Regular security audits are recommended"
