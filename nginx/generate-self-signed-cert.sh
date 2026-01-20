#!/bin/bash
# Generate self-signed SSL certificate for testing
# For production, use Let's Encrypt with certbot

set -e

SSL_DIR="./nginx/ssl"
DOMAIN="${SSL_DOMAIN:-localhost}"

echo "=== Generating Self-Signed SSL Certificate ==="
echo "Domain: $DOMAIN"
echo ""

# Create SSL directory if it doesn't exist
mkdir -p "$SSL_DIR"

# Generate private key
echo "Generating private key..."
openssl genrsa -out "$SSL_DIR/key.pem" 2048

# Generate certificate signing request
echo "Generating certificate signing request..."
openssl req -new -key "$SSL_DIR/key.pem" -out "$SSL_DIR/csr.pem" \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN"

# Generate self-signed certificate (valid for 365 days)
echo "Generating self-signed certificate (valid for 365 days)..."
openssl x509 -req -days 365 -in "$SSL_DIR/csr.pem" -signkey "$SSL_DIR/key.pem" \
  -out "$SSL_DIR/cert.pem" \
  -extensions v3_req -extfile <(
    cat <<EOF
[req]
distinguished_name = req_distinguished_name
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $DOMAIN
DNS.2 = *.$DOMAIN
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
  )

# Set permissions
chmod 600 "$SSL_DIR/key.pem"
chmod 644 "$SSL_DIR/cert.pem"

# Clean up CSR
rm -f "$SSL_DIR/csr.pem"

echo ""
echo "✓ Self-signed certificate generated successfully!"
echo ""
echo "Certificate files:"
echo "  - $SSL_DIR/cert.pem"
echo "  - $SSL_DIR/key.pem"
echo ""
echo "Note: Self-signed certificates will show a security warning in browsers."
echo "For production, use Let's Encrypt with: ./setup-letsencrypt.sh"
echo ""
