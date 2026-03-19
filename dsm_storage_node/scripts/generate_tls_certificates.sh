#!/bin/bash

# DSM Storage Node - TLS Certificate Generation Script
# Generates production-ready TLS certificates for secure node communication

set -euo pipefail

echo "🔐 DSM Storage Node - TLS Certificate Generation"
echo "==============================================="

# Configuration
CERT_DIR="./keys/production"
CA_DIR="./keys/ca"
CERT_VALIDITY_DAYS=365
KEY_SIZE=4096

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
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

# Create directories
log_info "Creating certificate directories..."
mkdir -p "$CERT_DIR"
mkdir -p "$CA_DIR"
chmod 700 "$CERT_DIR"
chmod 700 "$CA_DIR"

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    log_error "OpenSSL is not installed. Please install OpenSSL first."
    echo "On macOS: brew install openssl"
    echo "On Ubuntu/Debian: sudo apt-get install openssl"
    exit 1
fi

log_success "OpenSSL found: $(openssl version)"

# Function to generate Certificate Authority (CA)
generate_ca() {
    log_info "Generating Certificate Authority (CA)..."
    
    # Generate CA private key
    openssl genrsa -out "$CA_DIR/ca.key" $KEY_SIZE
    chmod 600 "$CA_DIR/ca.key"
    
    # Create CA configuration
    cat > "$CA_DIR/ca.conf" << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = DSM Protocol
OU = DSM Storage Network
CN = DSM Storage CA
emailAddress = admin@dsm.network

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

    # Generate CA certificate
    openssl req -new -x509 -key "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" \
        -days $((CERT_VALIDITY_DAYS * 3)) -config "$CA_DIR/ca.conf"
    
    chmod 644 "$CA_DIR/ca.crt"
    log_success "Certificate Authority generated"
}

# Function to generate node certificate
generate_node_certificate() {
    local node_id=${1:-"dsm-node"}
    local node_name=${2:-"DSM Storage Node"}
    
    log_info "Generating certificate for $node_name ($node_id)..."
    
    # Generate node private key
    openssl genrsa -out "$CERT_DIR/node.key" $KEY_SIZE
    chmod 600 "$CERT_DIR/node.key"
    
    # Get node configuration from environment or prompt
    read -p "Enter node domain/IP (default: localhost): " NODE_DOMAIN
    NODE_DOMAIN=${NODE_DOMAIN:-localhost}
    
    read -p "Enter additional SANs (comma-separated, optional): " ADDITIONAL_SANS
    
    # Build SAN list
    SAN_LIST="DNS:localhost,DNS:${NODE_DOMAIN},IP:127.0.0.1"
    if [[ -n "$ADDITIONAL_SANS" ]]; then
        # Clean up and add additional SANs
        CLEANED_SANS=$(echo "$ADDITIONAL_SANS" | tr ',' '\n' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//' | grep -v '^$' | paste -sd ',' -)
        if [[ -n "$CLEANED_SANS" ]]; then
            SAN_LIST="${SAN_LIST},${CLEANED_SANS}"
        fi
    fi
    
    # Create node certificate configuration
    cat > "$CERT_DIR/node.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = DSM Protocol
OU = DSM Storage Network
CN = $node_name
emailAddress = node@dsm.network

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = $SAN_LIST
EOF

    # Generate Certificate Signing Request (CSR)
    openssl req -new -key "$CERT_DIR/node.key" -out "$CERT_DIR/node.csr" \
        -config "$CERT_DIR/node.conf"
    
    # Sign the certificate with CA
    openssl x509 -req -in "$CERT_DIR/node.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
        -CAcreateserial -out "$CERT_DIR/node.crt" -days $CERT_VALIDITY_DAYS \
        -extensions v3_req -extfile "$CERT_DIR/node.conf"
    
    chmod 644 "$CERT_DIR/node.crt"
    
    # Clean up CSR
    rm "$CERT_DIR/node.csr"
    
    log_success "Node certificate generated for $node_name"
}

# Function to generate self-signed certificate (alternative)
generate_self_signed() {
    log_info "Generating self-signed certificate..."
    
    read -p "Enter node domain/IP (default: localhost): " NODE_DOMAIN
    NODE_DOMAIN=${NODE_DOMAIN:-localhost}
    
    # Create self-signed certificate configuration
    cat > "$CERT_DIR/selfsigned.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = DSM Protocol
OU = DSM Storage Network
CN = DSM Storage Node
emailAddress = node@dsm.network

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = DNS:localhost,DNS:${NODE_DOMAIN},IP:127.0.0.1
EOF

    # Generate private key and self-signed certificate
    openssl req -x509 -nodes -days $CERT_VALIDITY_DAYS -newkey rsa:$KEY_SIZE \
        -keyout "$CERT_DIR/node.key" -out "$CERT_DIR/node.crt" \
        -config "$CERT_DIR/selfsigned.conf"
    
    chmod 600 "$CERT_DIR/node.key"
    chmod 644 "$CERT_DIR/node.crt"
    
    log_success "Self-signed certificate generated"
}

# Function to verify certificates
verify_certificates() {
    log_info "Verifying certificates..."
    
    if [[ -f "$CERT_DIR/node.crt" && -f "$CERT_DIR/node.key" ]]; then
        # Check certificate validity
        if openssl x509 -in "$CERT_DIR/node.crt" -text -noout > /dev/null 2>&1; then
            log_success "Certificate is valid"
            
            # Display certificate information
            echo ""
            echo "📋 Certificate Information:"
            echo "=========================="
            openssl x509 -in "$CERT_DIR/node.crt" -text -noout | grep -E "(Subject:|Not Before|Not After|DNS:|IP Address:)"
            
            # Check if CA signed
            if [[ -f "$CA_DIR/ca.crt" ]]; then
                if openssl verify -CAfile "$CA_DIR/ca.crt" "$CERT_DIR/node.crt" > /dev/null 2>&1; then
                    log_success "Certificate is properly signed by CA"
                else
                    log_warning "Certificate verification with CA failed"
                fi
            fi
            
        else
            log_error "Certificate verification failed"
            return 1
        fi
        
        # Check key-certificate pair
        cert_modulus=$(openssl x509 -noout -modulus -in "$CERT_DIR/node.crt" | openssl md5)
        key_modulus=$(openssl rsa -noout -modulus -in "$CERT_DIR/node.key" | openssl md5)
        
        if [[ "$cert_modulus" == "$key_modulus" ]]; then
            log_success "Private key matches certificate"
        else
            log_error "Private key does not match certificate"
            return 1
        fi
        
    else
        log_error "Certificate or key file not found"
        return 1
    fi
}

# Function to update environment file
update_env_file() {
    log_info "Updating .env file with certificate paths..."
    
    if [[ -f ".env" ]]; then
        # Update TLS certificate paths in .env
        sed -i.bak \
            -e "s|DSM_TLS_CERT_PATH=.*|DSM_TLS_CERT_PATH=\"$CERT_DIR/node.crt\"|" \
            -e "s|DSM_TLS_KEY_PATH=.*|DSM_TLS_KEY_PATH=\"$CERT_DIR/node.key\"|" \
            .env
        
        if [[ -f "$CA_DIR/ca.crt" ]]; then
            # Add CA certificate path if not present
            if ! grep -q "DSM_CA_CERT_PATH" .env; then
                echo "DSM_CA_CERT_PATH=\"$CA_DIR/ca.crt\"" >> .env
            else
                sed -i.bak "s|DSM_CA_CERT_PATH=.*|DSM_CA_CERT_PATH=\"$CA_DIR/ca.crt\"|" .env
            fi
        fi
        
        log_success ".env file updated with certificate paths"
    else
        log_warning ".env file not found - please update manually"
    fi
}

# Main menu
show_menu() {
    echo ""
    echo "🔐 TLS Certificate Generation Options:"
    echo "====================================="
    echo "1) Generate CA and CA-signed certificate (Recommended for production)"
    echo "2) Generate self-signed certificate (Quick setup for development)"
    echo "3) Generate additional node certificate (if CA exists)"
    echo "4) Verify existing certificates"
    echo "5) Show certificate information"
    echo "6) Exit"
    echo ""
}

# Main execution
main() {
    # Check if certificates already exist
    if [[ -f "$CERT_DIR/node.crt" && -f "$CERT_DIR/node.key" ]]; then
        log_warning "Certificates already exist in $CERT_DIR"
        read -p "Do you want to regenerate them? (y/N): " REGENERATE
        if [[ ! "$REGENERATE" =~ ^[Yy]$ ]]; then
            log_info "Using existing certificates"
            verify_certificates
            exit 0
        fi
    fi
    
    while true; do
        show_menu
        read -p "Choose an option (1-6): " choice
        
        case $choice in
            1)
                generate_ca
                generate_node_certificate
                verify_certificates
                update_env_file
                log_success "CA and node certificate generation complete!"
                break
                ;;
            2)
                generate_self_signed
                verify_certificates
                update_env_file
                log_success "Self-signed certificate generation complete!"
                break
                ;;
            3)
                if [[ ! -f "$CA_DIR/ca.crt" ]]; then
                    log_error "CA certificate not found. Please generate CA first (option 1)."
                    continue
                fi
                read -p "Enter node ID: " NODE_ID
                read -p "Enter node name: " NODE_NAME
                generate_node_certificate "$NODE_ID" "$NODE_NAME"
                verify_certificates
                log_success "Additional node certificate generated!"
                ;;
            4)
                verify_certificates
                ;;
            5)
                if [[ -f "$CERT_DIR/node.crt" ]]; then
                    echo ""
                    echo "📋 Certificate Details:"
                    echo "======================"
                    openssl x509 -in "$CERT_DIR/node.crt" -text -noout
                else
                    log_error "No certificate found to display"
                fi
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
    echo "🎉 TLS Certificate Setup Complete!"
    echo "=================================="
    echo ""
    echo "📁 Certificate files created:"
    echo "  - Private key: $CERT_DIR/node.key"
    echo "  - Certificate: $CERT_DIR/node.crt"
    if [[ -f "$CA_DIR/ca.crt" ]]; then
        echo "  - CA certificate: $CA_DIR/ca.crt"
    fi
    echo ""
    echo "🔐 Security Notes:"
    echo "  - Keep private keys secure (600 permissions set)"
    echo "  - Distribute CA certificate to clients if using CA-signed certificates"
    echo "  - Certificates expire in $CERT_VALIDITY_DAYS days"
    echo "  - Consider certificate rotation for production"
    echo ""
    echo "🚀 Next Steps:"
    echo "  1. Update your .env file (done automatically)"
    echo "  2. Configure your DSM node to use TLS"
    echo "  3. Test the secure connection"
    echo "  4. Set up certificate monitoring for expiration"
}

# Run main function
main "$@"
