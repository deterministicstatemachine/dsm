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
