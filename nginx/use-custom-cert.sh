#!/bin/bash
# Setup script for using custom CA certificates
# This script helps you prepare and verify custom certificates from a local CA

set -e

SSL_DIR="./nginx/ssl"
CERT_SOURCE="${1:-}"
KEY_SOURCE="${2:-}"
CA_CHAIN_SOURCE="${3:-}"

echo "=== Custom CA Certificate Setup ==="
echo ""

# Create SSL directory if it doesn't exist
mkdir -p "$SSL_DIR"

# Function to check if file exists and is readable
check_file() {
    if [ ! -f "$1" ] || [ ! -r "$1" ]; then
        echo "Error: File not found or not readable: $1"
        return 1
    fi
    return 0
}

# Interactive mode if no arguments provided
if [ -z "$CERT_SOURCE" ]; then
    echo "This script helps you set up custom CA certificates."
    echo ""
    read -p "Enter path to your certificate file (cert.pem): " CERT_SOURCE
    read -p "Enter path to your private key file (key.pem): " KEY_SOURCE
    read -p "Enter path to CA chain file (optional, press Enter to skip): " CA_CHAIN_SOURCE
fi

# Verify certificate file
if [ -z "$CERT_SOURCE" ]; then
    echo "Error: Certificate file path is required"
    exit 1
fi

if ! check_file "$CERT_SOURCE"; then
    exit 1
fi

# Verify key file
if [ -z "$KEY_SOURCE" ]; then
    echo "Error: Private key file path is required"
    exit 1
fi

if ! check_file "$KEY_SOURCE"; then
    exit 1
fi

# Copy certificate
echo "Copying certificate..."
cp "$CERT_SOURCE" "$SSL_DIR/cert.pem"

# Copy private key
echo "Copying private key..."
cp "$KEY_SOURCE" "$SSL_DIR/key.pem"

# Copy CA chain if provided
if [ -n "$CA_CHAIN_SOURCE" ] && [ -f "$CA_CHAIN_SOURCE" ]; then
    echo "Copying CA chain..."
    cp "$CA_CHAIN_SOURCE" "$SSL_DIR/ca-chain.pem"
    echo ""
    echo "Note: Update nginx.conf to use ca-chain.pem:"
    echo "  Uncomment: ssl_trusted_certificate /etc/nginx/ssl/ca-chain.pem;"
fi

# Set secure permissions
echo "Setting secure file permissions..."
chmod 644 "$SSL_DIR/cert.pem"
chmod 600 "$SSL_DIR/key.pem"
if [ -f "$SSL_DIR/ca-chain.pem" ]; then
    chmod 644 "$SSL_DIR/ca-chain.pem"
fi

# Verify certificate
echo ""
echo "Verifying certificate..."
if command -v openssl &> /dev/null; then
    echo "Certificate information:"
    openssl x509 -in "$SSL_DIR/cert.pem" -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After"
    
    echo ""
    echo "Verifying certificate and key match..."
    CERT_MD5=$(openssl x509 -noout -modulus -in "$SSL_DIR/cert.pem" | openssl md5)
    KEY_MD5=$(openssl rsa -noout -modulus -in "$SSL_DIR/key.pem" | openssl md5)
    
    if [ "$CERT_MD5" = "$KEY_MD5" ]; then
        echo "✓ Certificate and private key match!"
    else
        echo "⚠ Warning: Certificate and private key do not match!"
        exit 1
    fi
else
    echo "⚠ openssl not found - skipping certificate verification"
fi

echo ""
echo "✓ Custom CA certificates installed successfully!"
echo ""
echo "Certificate files in $SSL_DIR/:"
ls -lh "$SSL_DIR/"*.pem
echo ""
echo "Next steps:"
echo "1. If using custom CA, update docker-compose.yml to use custom config:"
echo "   volumes:"
echo "     - ./nginx/nginx-custom-ca.conf:/etc/nginx/conf.d/default.conf:ro"
echo ""
echo "2. Or update nginx.conf if you need to uncomment CA chain:"
echo "   ssl_trusted_certificate /etc/nginx/ssl/ca-chain.pem;"
echo ""
echo "3. Start services:"
echo "   docker compose up -d"
