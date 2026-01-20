# ARPWatch-WEBUI Quick Start Guide

Get ARPWatch-WEBUI running in **5 minutes** using prebuilt Docker images!

## 📦 What You Need

- Docker and Docker Compose installed
- Linux system with network interface access
- Root/sudo access

## 🚀 Installation Steps

### Step 1: Download Files

Create a directory and download the required files:

```bash
# Create directory
mkdir arpwatch-webui && cd arpwatch-webui

# Download docker-compose file
curl -O https://raw.githubusercontent.com/netwho/ARPWatch-WEBUI/main/docker-compose.yml

# Download environment template
curl -O https://raw.githubusercontent.com/netwho/ARPWatch-WEBUI/main/env_example
```

Or clone the entire repository:

```bash
git clone https://github.com/netwho/ARPWatch-WEBUI.git
cd ARPWatch-WEBUI
```

### Step 2: Find Your Network Interface

```bash
ip link show
```

You'll see output like:
```
1: lo: <LOOPBACK,UP,LOWER_UP> ...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
3: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

Common interface names:
- `eth0` - Traditional Ethernet
- `ens18`, `ens33` - Modern Ethernet (systemd naming)
- `enp0s3` - PCI Ethernet

**Choose the interface connected to the network you want to monitor.**

### Step 3: Configure Environment

```bash
# Copy the example file
cp env_example .env

# Edit the file
nano .env
```

**REQUIRED: Set your network interface**

Change this line:
```env
ARPWATCH_INTERFACE=eth0
```

To your interface (from Step 2):
```env
ARPWATCH_INTERFACE=ens18
```

**That's it! The other settings have sensible defaults.**

Optional settings you can adjust:
```env
# Enable/disable features
ENABLE_OS_FINGERPRINTING=true
ENABLE_PORT_SCANNING=true
SCAN_PORTS=21,22,80,443,445

# Exclude IP ranges (comma-separated CIDR)
EXCLUDE_IP_RANGES=169.254.0.0/16

# Ports (if not using nginx)
HTTP_PORT=80
HTTPS_PORT=443
```

### Step 4: Start ARPWatch-WEBUI

```bash
# Pull images from Docker Hub (first time only)
docker compose pull

# Start all services
docker compose up -d
```

You'll see:
```
[+] Running 4/4
 ✔ Container arpwatch-daemon    Started
 ✔ Container arpwatch-backend   Started
 ✔ Container arpwatch-frontend  Started
 ✔ Container arpwatch-nginx     Started
```

### Step 5: Access the Dashboard

Open your browser and go to:

- **HTTPS**: `https://localhost` or `https://your-server-ip`
- **HTTP**: `http://localhost` (redirects to HTTPS)

**Note**: You'll see a certificate warning (self-signed cert). This is normal - click "Advanced" and proceed.

### Step 6: Verify It's Working

```bash
# Check container status (all should be healthy)
docker compose ps

# View logs
docker compose logs -f

# Check if arpwatch is capturing
docker compose logs arpwatch
# Should show: "listening on ens18" (or your interface)
```

## 📊 What You'll See

After a few minutes, the dashboard will show:
- **Active hosts** on your network
- **MAC addresses** and IP addresses
- **Hostnames** (reverse DNS lookup)
- **OS detection** (if enabled)
- **Recent events** (new devices, changes)

## 🔧 Common Commands

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# View all logs
docker compose logs -f

# View specific service logs
docker compose logs -f arpwatch
docker compose logs -f backend

# Restart a service
docker compose restart arpwatch

# Check status
docker compose ps

# Update to latest images
docker compose pull
docker compose up -d
```

## 🐛 Troubleshooting

### No Hosts Appearing?

1. **Check arpwatch is running:**
   ```bash
   docker compose logs arpwatch
   # Should show "listening on INTERFACE"
   ```

2. **Verify interface name:**
   ```bash
   ip link show
   # Compare with ARPWATCH_INTERFACE in .env
   ```

3. **Generate network traffic:**
   ```bash
   # Ping your gateway to generate ARP traffic
   ping -c 4 192.168.1.1
   ```

4. **Check data is being collected:**
   ```bash
   docker compose exec backend ls -la /var/lib/arpwatch/
   # Should show arp.dat file
   ```

### Wrong Network Interface?

```bash
# Edit .env file
nano .env
# Change: ARPWATCH_INTERFACE=correct-interface

# Restart arpwatch
docker compose restart arpwatch

# Check it picked up the change
docker compose logs arpwatch
```

### Can't Access Web UI?

```bash
# Check if containers are running
docker compose ps

# Check nginx logs
docker compose logs nginx

# Verify ports aren't in use
sudo netstat -tulpn | grep -E ':(80|443)'
```

### Certificate Warning?

This is normal with self-signed certificates. To fix:

**Option 1: Accept the warning** (easiest)
- Click "Advanced" → "Proceed to localhost"

**Option 2: Use Let's Encrypt** (for public servers)
```bash
./nginx/setup-letsencrypt.sh your-domain.com your-email@example.com
docker compose restart nginx
```

## 📚 Files You Need

**Minimum required files:**
1. `docker-compose.yml` - Defines all services
2. `.env` - Your configuration (created from `env_example`)

**Optional but helpful:**
3. `nginx/ssl/` - TLS certificates (auto-generated if missing)
4. `nginx/logs/` - Nginx access/error logs

## 🎯 What's Happening Behind the Scenes

When you run `docker compose up -d`:

1. **Docker pulls images** from Docker Hub (netwho/arpwatch-webui)
2. **Arpwatch daemon** starts monitoring your network interface
3. **Backend API** starts processing ARP data
4. **Frontend** serves the web dashboard
5. **Nginx** provides HTTPS access and reverse proxy

All data is stored in Docker volumes (persists across restarts).

## 🔄 Updating

To update to the latest version:

```bash
# Pull latest images
docker compose pull

# Recreate containers
docker compose up -d

# Check versions
docker images | grep arpwatch-webui
```

## 🛑 Stopping and Removing

```bash
# Stop services (keeps data)
docker compose down

# Stop and remove all data (WARNING: deletes everything!)
docker compose down -v
```

## 📖 More Information

- **Full Documentation**: See [README.md](README.md)
- **Docker Hub**: https://hub.docker.com/r/netwho/arpwatch-webui
- **GitHub**: https://github.com/netwho/ARPWatch-WEBUI
- **Issues**: https://github.com/netwho/ARPWatch-WEBUI/issues

---

**That's it! You should now have ARPWatch-WEBUI running. 🎉**

Need help? Open an issue on GitHub!
