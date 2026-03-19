#!/bin/bash

# DSM Storage Node - Quick TLS Setup
# Generates self-signed certificates for development/testing

set -euo pipefail

echo "🚀 Quick TLS Certificate Setup for DSM Storage Node"
echo "=================================================="

# Configuration
CERT_DIR="./keys/production"
KEY_SIZE=4096
CERT_VALIDITY_DAYS=365

# Create directory
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

# Get domain/IP from user or use localhost
read -p "Enter node domain/IP (press Enter for localhost): " NODE_DOMAIN
NODE_DOMAIN=${NODE_DOMAIN:-localhost}

echo "🔐 Generating self-signed TLS certificate..."

# Generate private key and certificate in one command
openssl req -x509 -nodes -days $CERT_VALIDITY_DAYS -newkey rsa:$KEY_SIZE \
    -keyout "$CERT_DIR/node.key" -out "$CERT_DIR/node.crt" \
    -subj "/C=US/ST=CA/L=SF/O=DSM/OU=Storage/CN=DSM-Storage-Node" \
    -addext "subjectAltName=DNS:localhost,DNS:${NODE_DOMAIN},IP:127.0.0.1"

# Set secure permissions
chmod 600 "$CERT_DIR/node.key"
chmod 644 "$CERT_DIR/node.crt"

# Update .env file if it exists
if [[ -f ".env" ]]; then
    echo "📝 Updating .env file..."
    
    # Create backup
    cp .env .env.backup
    
    # Update certificate paths
    sed -i.tmp \
        -e "s|DSM_TLS_CERT_PATH=.*|DSM_TLS_CERT_PATH=\"$CERT_DIR/node.crt\"|" \
        -e "s|DSM_TLS_KEY_PATH=.*|DSM_TLS_KEY_PATH=\"$CERT_DIR/node.key\"|" \
        .env
    
    # Clean up temp file
    rm -f .env.tmp
fi

echo ""
echo "✅ TLS Certificate Generation Complete!"
echo "======================================"
echo ""
echo "📁 Files created:"
echo "  • Private key: $CERT_DIR/node.key"
echo "  • Certificate: $CERT_DIR/node.crt"
echo ""
echo "🔍 Certificate info:"
openssl x509 -in "$CERT_DIR/node.crt" -noout -subject -dates
echo ""
echo "🚀 Your DSM storage node is now ready for TLS!"
echo ""
echo "⚠️  Note: This is a self-signed certificate suitable for development."
echo "   For production, consider using the full certificate generation script:"
echo "   ./scripts/generate_tls_certificates.sh"
