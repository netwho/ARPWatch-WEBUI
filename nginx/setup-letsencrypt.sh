#!/bin/bash
# Setup Let's Encrypt SSL certificate using certbot
# This script requires a domain name pointing to your server

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <your-domain.com> [email@example.com]"
    echo ""
    echo "Example: $0 arpwatch.example.com admin@example.com"
    exit 1
fi

DOMAIN="$1"
EMAIL="${2:-admin@${DOMAIN}}"

echo "=== Setting up Let's Encrypt SSL for $DOMAIN ==="
echo "Email: $EMAIL"
echo ""

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo "Certbot is not installed. Installing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y certbot
    elif command -v yum &> /dev/null; then
        sudo yum install -y certbot
    else
        echo "Please install certbot manually: https://certbot.eff.org/"
        exit 1
    fi
fi

# Create directories
mkdir -p ./nginx/ssl
mkdir -p ./nginx/logs
mkdir -p ./certbot/webroot

# Make sure nginx is running to handle ACME challenge
echo "Starting nginx container for ACME challenge..."
docker compose up -d nginx

# Wait for nginx to be ready
sleep 5

# Request certificate using webroot method
echo "Requesting certificate from Let's Encrypt..."
sudo certbot certonly \
    --webroot \
    --webroot-path=./certbot/webroot \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    -d "$DOMAIN"

# Copy certificates to nginx ssl directory
echo "Copying certificates to nginx directory..."
sudo cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ./nginx/ssl/cert.pem
sudo cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" ./nginx/ssl/key.pem
sudo chown -R $(whoami):$(whoami) ./nginx/ssl

# Restart nginx
echo "Restarting nginx..."
docker compose restart nginx

echo ""
echo "✓ Let's Encrypt certificate installed successfully!"
echo ""
echo "Certificate will auto-renew via certbot timer."
echo "To manually renew: sudo certbot renew"
echo ""
echo "Setup auto-renewal (recommended):"
echo "  sudo certbot renew --dry-run"
echo ""
