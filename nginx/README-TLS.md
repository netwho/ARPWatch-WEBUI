# TLS/SSL Configuration Guide

This guide explains how to set up HTTPS for ARPWatch-WEBUI using nginx with TLS.

## Certificate Options

1. **Self-Signed Certificate** - For testing (browsers will show warnings)
2. **Let's Encrypt Certificate** - Free, trusted certificates for production
3. **Custom CA Certificate** - Certificates from your organization's Certificate Authority

## Quick Start

### Option 1: Custom CA Certificate (Enterprise/Internal)

If you have certificates from your organization's Certificate Authority:

```bash
# Use the setup script (interactive)
chmod +x nginx/use-custom-cert.sh
./nginx/use-custom-cert.sh

# Or provide paths directly
./nginx/use-custom-cert.sh /path/to/cert.pem /path/to/key.pem [ca-chain.pem]

# Enable custom CA mode in .env
echo "CUSTOM_CA=true" >> .env

# Start services
docker compose up -d
```

**Manual setup:**
```bash
# Copy your certificates
cp /path/to/your-cert.pem nginx/ssl/cert.pem
cp /path/to/your-key.pem nginx/ssl/key.pem

# Optional: Copy CA chain if you have intermediate certificates
cp /path/to/ca-chain.pem nginx/ssl/ca-chain.pem

# Set permissions
chmod 644 nginx/ssl/cert.pem
chmod 600 nginx/ssl/key.pem

# Enable custom CA mode
echo "CUSTOM_CA=true" >> .env

# Start services
docker compose up -d
```

**For CA chain support:**
1. Copy `nginx/nginx-custom-ca.conf` configuration (already included)
2. Uncomment the `ssl_trusted_certificate` line if using intermediate certificates
3. Or mount custom config in docker-compose.yml:
   ```yaml
   volumes:
     - ./nginx/nginx-custom-ca.conf:/etc/nginx/conf.d/default.conf:ro
   ```

### Option 2: Self-Signed Certificate (Testing)

```bash
# Generate self-signed certificate
chmod +x nginx/generate-self-signed-cert.sh
./nginx/generate-self-signed-cert.sh

# Or for a specific domain
SSL_DOMAIN=arpwatch.local ./nginx/generate-self-signed-cert.sh

# Start services
docker compose up -d
```

**Note:** Browsers will show a security warning for self-signed certificates. Accept it for testing.

### Option 3: Let's Encrypt Certificate (Production)

```bash
# Make sure your domain points to this server
# DNS: A record for your-domain.com → server IP

# Setup Let's Encrypt
chmod +x nginx/setup-letsencrypt.sh
./nginx/setup-letsencrypt.sh your-domain.com your-email@example.com

# Start services
docker compose up -d
```

## Configuration Files

### Environment Variables (.env)

Add to your `.env` file:

```env
# TLS/SSL Configuration
HTTP_PORT=80          # HTTP port (redirects to HTTPS)
HTTPS_PORT=443        # HTTPS port
SSL_DOMAIN=localhost  # Domain for self-signed cert (optional)

# Custom CA Configuration
CUSTOM_CA=false       # Set to true if using custom CA certificates
```

### Nginx Configuration

- `nginx/nginx.conf` - Main nginx configuration with TLS
- `nginx/ssl/` - Directory for SSL certificates
  - `cert.pem` - Certificate file
  - `key.pem` - Private key file

## Certificate Files

### Self-Signed Certificate

Generated files:
- `nginx/ssl/cert.pem` - Self-signed certificate
- `nginx/ssl/key.pem` - Private key

### Let's Encrypt Certificate

Certificates are stored in:
- `/etc/letsencrypt/live/your-domain.com/` (on host)
- Copied to `nginx/ssl/` for nginx to use

### Custom CA Certificate

Certificates should be placed in `nginx/ssl/`:
- `cert.pem` - Server certificate from your CA
- `key.pem` - Private key
- `ca-chain.pem` - CA chain/intermediate certificates (optional)

## Access URLs

After setup, access the application at:
- **HTTPS:** `https://localhost` or `https://your-domain.com`
- **HTTP:** `http://localhost` (automatically redirects to HTTPS)

## Let's Encrypt Auto-Renewal

Let's Encrypt certificates expire after 90 days. Set up auto-renewal:

```bash
# Test renewal
sudo certbot renew --dry-run

# Add to crontab (runs twice daily)
sudo crontab -e
# Add line:
0 0,12 * * * certbot renew --quiet && docker compose -f /path/to/docker-compose.yml restart nginx
```

## Troubleshooting

### Certificate Not Found

If nginx fails to start due to missing certificates:

```bash
# Check if certificates exist
ls -la nginx/ssl/

# Generate self-signed if missing
./nginx/generate-self-signed-cert.sh
```

### Certificate Permission Issues

```bash
# Fix permissions
chmod 644 nginx/ssl/cert.pem
chmod 600 nginx/ssl/key.pem
chown $(whoami):$(whoami) nginx/ssl/*.pem
```

### Nginx SSL Error

Check nginx logs:

```bash
# View nginx logs
docker compose logs nginx

# Or check log files
tail -f nginx/logs/error.log
```

### Let's Encrypt Challenge Failed

1. Ensure port 80 is accessible from internet
2. Check DNS is pointing to your server
3. Verify nginx is running: `docker compose ps nginx`
4. Check certbot webroot: `ls -la certbot/webroot/`

### Bypass TLS (Development Only)

To access directly without nginx:

1. Edit `docker-compose.yml`:
   ```yaml
   backend:
     ports:
       - "8000:8000"
   frontend:
     ports:
       - "8080:80"
   ```

2. Restart: `docker compose up -d`

## Security Notes

1. **Production:** Use Let's Encrypt, a trusted CA, or your organization's CA
2. **Self-signed:** Only for testing/development
3. **Custom CA:** Ensure clients have your CA certificate installed in their trust store
4. **Private Keys:** Never commit `key.pem` to git - add `nginx/ssl/*.pem` to `.gitignore`
5. **HTTPS Only:** HTTP automatically redirects to HTTPS
6. **HSTS:** Security headers are configured for secure connections

## Custom CA Certificate Setup Details

### Certificate Format

Certificates should be in PEM format:
- Certificate: Base64 encoded X.509 certificate
- Private Key: RSA or ECDSA private key in PEM format
- CA Chain: Concatenated intermediate certificates (if applicable)

### File Structure

```
nginx/ssl/
├── cert.pem       # Server certificate (required)
├── key.pem        # Private key (required)
└── ca-chain.pem   # CA chain/intermediate certs (optional)
```

### Certificate Verification

The `use-custom-cert.sh` script automatically verifies:
- Certificate and key match (same modulus)
- Certificate validity period
- Certificate details (Subject, Issuer, dates)

### Client Trust Setup

For browsers/clients to trust your custom CA:

**Windows:**
1. Open Certificate Manager: `certmgr.msc`
2. Import CA certificate to "Trusted Root Certification Authorities"

**Linux:**
```bash
# Copy CA cert to system trust store
sudo cp ca-cert.pem /usr/local/share/ca-certificates/your-ca.crt
sudo update-ca-certificates
```

**macOS:**
1. Open Keychain Access
2. Import CA certificate
3. Trust the certificate

**Browser-specific:**
- Chrome/Edge: Uses system certificate store
- Firefox: Tools → Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import

## Firewall Configuration

Ensure ports are open:

```bash
# Allow HTTP (for Let's Encrypt challenges)
sudo ufw allow 80/tcp

# Allow HTTPS
sudo ufw allow 443/tcp

# Or for iptables
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

## Architecture

```
Internet
   ↓
[Port 80/443] ← Nginx (TLS termination)
   ↓
   ├── /api → Backend (port 8000)
   └── / → Frontend (port 80)
```

- Nginx handles all TLS/SSL
- Backend and Frontend are not directly exposed
- All traffic is encrypted between client and nginx
