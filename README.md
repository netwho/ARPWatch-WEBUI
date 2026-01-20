# Arpwatch Web UI

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.4.0-blue.svg)](VERSION)
[![Docker](https://img.shields.io/badge/Docker-20.10%2B-2496ED.svg?logo=docker)](https://www.docker.com/)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-netwho%2Farpwatch--webui-blue.svg?logo=docker)](https://hub.docker.com/r/netwho/arpwatch-webui)

**Author:** Walter Hofstetter  
**License:** GPLv2 (see `LICENSE`)

A modern, containerized web interface for monitoring Arpwatch network activity. This project provides a real-time dashboard to view ARP (Address Resolution Protocol) entries, monitor network changes, and track ARP events with automatic reverse DNS lookup.

## 📸 Screenshots

![Dashboard](screenshot/Sample.png)

## 🚀 Features

- **Real-time Monitoring**: Auto-refreshing dashboard showing current ARP table
- **Event Logging**: Track new stations, changed ethernet addresses, and flip-flop events
- **Search & Filter**: Quickly find hosts by IP address, MAC address, or hostname
- **Statistics Dashboard**: Overview of total hosts, active hosts, and network changes
- **OS Fingerprinting**: Automatic OS detection using nmap
- **Port Scanning**: Optional port scanning for discovered hosts
- **TLS/SSL Support**: Built-in HTTPS with nginx reverse proxy
- **Modern UI**: Clean, responsive design built with React
- **Fully Containerized**: Everything runs in Docker - no host installation required!

## 🎯 Quick Start

Get up and running in 5 minutes with prebuilt Docker images!

### Prerequisites

- Docker and Docker Compose installed
- Linux host (for network monitoring capabilities)
- Root/sudo access (for network interface monitoring)

### Step 1: Create Project Directory

```bash
mkdir arpwatch-webui && cd arpwatch-webui
```

### Step 2: Download Configuration Files

Download the required files from the repository:

```bash
# Download docker-compose file
curl -O https://raw.githubusercontent.com/netwho/ARPWatch-WEBUI/main/docker-compose.all-in-one.yml

# Download environment example file
curl -O https://raw.githubusercontent.com/netwho/ARPWatch-WEBUI/main/env_example
```

Or clone the entire repository:

```bash
git clone https://github.com/netwho/ARPWatch-WEBUI.git
cd ARPWatch-WEBUI
```

### Step 3: Configure Environment

1. **Find your network interface:**
   ```bash
   ip link show
   ```
   
   Common interface names:
   - `eth0` - Traditional Ethernet
   - `ens18`, `ens33` - Modern Ethernet (systemd naming)
   - `enp0s3` - PCI Ethernet
   - `wlan0` - Wireless (not recommended for ARP monitoring)

2. **Create your `.env` file:**
   ```bash
   cp env_example .env
   ```

3. **Edit the `.env` file:**
   ```bash
   nano .env
   ```
   
   **Required setting:**
   ```env
   # Replace with YOUR network interface
   ARPWATCH_INTERFACE=ens18
   ```
   
   **Optional settings (already configured with sensible defaults):**
   ```env
   # Enable/disable features
   ENABLE_OS_FINGERPRINTING=true
   ENABLE_PORT_SCANNING=true
   SCAN_PORTS=21,22,80,443,445
   
   # Exclude specific IP ranges (CIDR notation)
   EXCLUDE_IP_RANGES=169.254.0.0/16
   
   # Ports (if not using nginx)
   BACKEND_PORT=8000
   FRONTEND_PORT=8080
   HTTP_PORT=80
   HTTPS_PORT=443
   ```

### Step 4: Pull and Start Containers

```bash
# Pull prebuilt images from Docker Hub
docker compose -f docker-compose.all-in-one.yml pull

# Start all services
docker compose -f docker-compose.all-in-one.yml up -d
```

### Step 5: Access the Web UI

**Default access (with nginx):**
- HTTPS: `https://localhost` or `https://your-server-ip`
- HTTP: `http://localhost` (redirects to HTTPS)

**Direct access (if nginx ports are commented out in docker-compose):**
- Frontend: `http://localhost:8080`
- Backend API: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`

### Step 6: Verify Everything Works

```bash
# Check container status
docker compose -f docker-compose.all-in-one.yml ps

# View logs
docker compose -f docker-compose.all-in-one.yml logs -f

# Check arpwatch is capturing traffic
docker compose -f docker-compose.all-in-one.yml logs arpwatch
```

**Troubleshooting:** If you don't see any hosts after a few minutes, see the [Troubleshooting](#-troubleshooting) section below.

## 🐳 Docker Hub Images

Prebuilt images are available on Docker Hub:

- `netwho/arpwatch-webui:arpwatch-latest` - ARPWatch daemon (126MB)
- `netwho/arpwatch-webui:backend-latest` - FastAPI backend (427MB)
- `netwho/arpwatch-webui:frontend-latest` - React frontend (56.8MB)
- `netwho/arpwatch-webui:nginx-latest` - Nginx reverse proxy with TLS (53.8MB)

Pull all images:
```bash
docker pull netwho/arpwatch-webui:arpwatch-latest
docker pull netwho/arpwatch-webui:backend-latest
docker pull netwho/arpwatch-webui:frontend-latest
docker pull netwho/arpwatch-webui:nginx-latest
```

## 📋 Deployment Options

### Option 1: Using Prebuilt Images (Recommended)

This is the easiest method - uses prebuilt images from Docker Hub.

```bash
# With environment file
cp env_example .env
nano .env  # Configure ARPWATCH_INTERFACE
docker compose -f docker-compose.all-in-one.yml up -d

# Or with environment variable
export ARPWATCH_INTERFACE=ens18
docker compose -f docker-compose.all-in-one.yml up -d
```

### Option 2: Build from Source

Build images locally from source code.

```bash
# Clone repository
git clone https://github.com/netwho/ARPWatch-WEBUI.git
cd ARPWatch-WEBUI

# Build and start
export ARPWATCH_INTERFACE=ens18
docker compose -f docker-compose.all-in-one.yml build
docker compose -f docker-compose.all-in-one.yml up -d
```

### Option 3: Using the Quick Start Script

The repository includes an automated setup script:

```bash
./quick-start.sh
```

This script will:
- Detect your network interfaces
- Let you select which interface to monitor
- Set up the environment automatically
- Build and start all containers
- Display access information

## 🏗️ Architecture

The all-in-one setup consists of 4 containerized services:

### 1. Arpwatch Daemon Container
- Monitors network interface for ARP activity
- Logs events and maintains ARP database
- Uses host network mode for direct interface access
- Data stored in Docker volumes

### 2. Backend API Container (FastAPI)
- RESTful API to access Arpwatch data
- Parses ARP database and log files
- OS fingerprinting with nmap
- Optional port scanning
- Exposes endpoints for hosts, events, and statistics

### 3. Frontend Container (React + Nginx)
- Modern web interface built with React
- Real-time updates with auto-refresh
- Responsive design for desktop and mobile
- Served via Nginx

### 4. Nginx Reverse Proxy Container
- TLS/SSL termination
- HTTP to HTTPS redirect
- Proxies requests to frontend and backend
- Let's Encrypt support

## 📡 API Endpoints

- `GET /api/hosts` - Get all ARP entries with reverse DNS hostnames
- `GET /api/hosts/{ip_address}` - Get specific host by IP
- `GET /api/events?limit=100` - Get recent ARP events
- `GET /api/stats` - Get statistics summary
- `GET /api/search?q=query` - Search hosts by IP, MAC, or hostname
- `GET /api/debug` - Debug endpoint to check arpwatch data files

Full API documentation available at: `https://localhost/docs`

## ⚙️ Configuration

### Environment Variables

All configuration is done via the `.env` file. See `env_example` for all available options.

**Required:**
- `ARPWATCH_INTERFACE` - Network interface to monitor (e.g., `eth0`, `ens18`)

**Optional Features:**
- `ENABLE_OS_FINGERPRINTING` - Enable OS detection (default: `true`)
- `ENABLE_PORT_SCANNING` - Enable port scanning (default: `true`)
- `SCAN_PORTS` - Ports to scan (default: `21,22,80,443,445`)
- `EXCLUDE_IP_RANGES` - CIDR ranges to exclude (default: `169.254.0.0/16`)

**Ports:**
- `HTTP_PORT` - HTTP port (default: `80`)
- `HTTPS_PORT` - HTTPS port (default: `443`)
- `BACKEND_PORT` - Backend API port for direct access (default: `8000`)
- `FRONTEND_PORT` - Frontend port for direct access (default: `8080`)

**TLS/SSL:**
- `SSL_DOMAIN` - Domain name for certificates (default: `localhost`)
- `CUSTOM_CA` - Use custom CA certificates (default: `false`)

### Changing Network Interface

**Method 1: Edit `.env` file**
```bash
nano .env
# Change: ARPWATCH_INTERFACE=your-interface
docker compose -f docker-compose.all-in-one.yml restart arpwatch
```

**Method 2: Environment variable**
```bash
export ARPWATCH_INTERFACE=ens18
docker compose -f docker-compose.all-in-one.yml up -d
```

### Excluding IP Ranges

To exclude specific IP ranges from monitoring (e.g., VPN, guest networks):

```env
# Single range
EXCLUDE_IP_RANGES=169.254.0.0/16

# Multiple ranges (comma-separated, no spaces)
EXCLUDE_IP_RANGES=169.254.0.0/16,192.168.2.0/24,10.0.0.0/8
```

## 🔒 TLS/SSL Setup

The nginx container supports multiple certificate options:

### Option 1: Self-Signed Certificate (Default)

```bash
./nginx/generate-self-signed-cert.sh
docker compose -f docker-compose.all-in-one.yml restart nginx
```

### Option 2: Let's Encrypt

```bash
./nginx/setup-letsencrypt.sh your-domain.com your-email@example.com
docker compose -f docker-compose.all-in-one.yml restart nginx
```

### Option 3: Custom CA Certificate

```bash
# Copy your certificates
./nginx/use-custom-cert.sh /path/to/cert.pem /path/to/key.pem

# Update .env
echo "CUSTOM_CA=true" >> .env

# Restart
docker compose -f docker-compose.all-in-one.yml restart nginx
```

## 🔍 Usage

### Basic Commands

```bash
# Start all services
docker compose -f docker-compose.all-in-one.yml up -d

# Stop all services
docker compose -f docker-compose.all-in-one.yml down

# View logs
docker compose -f docker-compose.all-in-one.yml logs -f

# View specific service logs
docker compose -f docker-compose.all-in-one.yml logs -f arpwatch
docker compose -f docker-compose.all-in-one.yml logs -f backend

# Restart a service
docker compose -f docker-compose.all-in-one.yml restart arpwatch

# Check service status
docker compose -f docker-compose.all-in-one.yml ps

# Update to latest images
docker compose -f docker-compose.all-in-one.yml pull
docker compose -f docker-compose.all-in-one.yml up -d
```

### Viewing Data

The dashboard displays:
- **Total Hosts**: Number of unique IP addresses seen
- **Active Hosts**: Currently active entries in ARP table
- **New Hosts**: Recently discovered hosts
- **Changed Hosts**: Hosts with MAC address changes

### Event Types

- **new**: New station detected on network
- **changed**: Ethernet address changed for existing IP
- **flip-flop**: Rapid MAC address changes (potential security issue)
- **info**: General ARP activity

## 📊 Monitoring

### Health Checks

All containers include health checks:

```bash
# Check health status
docker compose -f docker-compose.all-in-one.yml ps

# Should show (healthy) for all services
```

### Performance

- **CPU**: Low usage, ~1-5% per container
- **Memory**: 
  - Arpwatch: ~10-20 MB
  - Backend: ~100-200 MB
  - Frontend: ~50-100 MB
  - Nginx: ~10-20 MB
- **Storage**: Minimal, grows with ARP database size

## 🐛 Troubleshooting

### No Hosts Appearing

1. **Check arpwatch is running and capturing:**
   ```bash
   docker compose -f docker-compose.all-in-one.yml logs arpwatch
   # Should show "listening on INTERFACE"
   ```

2. **Verify correct interface:**
   ```bash
   ip link show
   # Compare with ARPWATCH_INTERFACE in .env
   ```

3. **Check for network activity:**
   ```bash
   # Generate some ARP traffic
   ping -c 4 192.168.1.1
   ```

4. **Verify arpwatch data directory:**
   ```bash
   docker compose -f docker-compose.all-in-one.yml exec backend ls -la /var/lib/arpwatch
   # Should show arp.dat file
   ```

### Backend API Errors

1. **Check backend logs:**
   ```bash
   docker compose -f docker-compose.all-in-one.yml logs backend
   ```

2. **Verify volumes are mounted:**
   ```bash
   docker compose -f docker-compose.all-in-one.yml exec backend ls -la /var/lib/arpwatch
   docker compose -f docker-compose.all-in-one.yml exec backend ls -la /var/log/arpwatch
   ```

3. **Test API directly:**
   ```bash
   curl http://localhost:8000/api/hosts
   ```

### Frontend Not Loading

1. **Check if container is running:**
   ```bash
   docker compose -f docker-compose.all-in-one.yml ps frontend
   ```

2. **Check nginx configuration:**
   ```bash
   docker compose -f docker-compose.all-in-one.yml logs nginx
   ```

3. **Verify ports are not in use:**
   ```bash
   sudo netstat -tulpn | grep -E ':(80|443|8000|8080)'
   ```

### Permission Denied Errors

Arpwatch requires privileged access for packet capture:

```bash
# Verify container has necessary capabilities
docker inspect arpwatch-daemon | grep -A 10 CapAdd

# Should show NET_RAW and NET_ADMIN
```

### SSL/TLS Certificate Issues

1. **Regenerate self-signed certificate:**
   ```bash
   ./nginx/generate-self-signed-cert.sh
   docker compose -f docker-compose.all-in-one.yml restart nginx
   ```

2. **Check certificate files:**
   ```bash
   ls -la nginx/ssl/
   # Should show cert.pem and key.pem
   ```

## 📝 Advanced Configuration

### Custom Docker Compose File

Create a custom compose file for your specific needs:

```bash
cp docker-compose.all-in-one.yml docker-compose.custom.yml
# Edit docker-compose.custom.yml
docker compose -f docker-compose.custom.yml up -d
```

### Running Without Nginx

To expose backend and frontend directly without nginx:

1. Edit `docker-compose.all-in-one.yml`
2. Uncomment the `ports:` sections for backend and frontend
3. Comment out or remove the nginx service
4. Restart: `docker compose -f docker-compose.all-in-one.yml up -d`

### Multiple Network Interfaces

To monitor multiple interfaces, run separate instances:

```bash
# Instance 1 (ens18)
ARPWATCH_INTERFACE=ens18 HTTP_PORT=8081 HTTPS_PORT=8443 docker compose -f docker-compose.all-in-one.yml -p arpwatch-ens18 up -d

# Instance 2 (ens19)
ARPWATCH_INTERFACE=ens19 HTTP_PORT=8082 HTTPS_PORT=8444 docker compose -f docker-compose.all-in-one.yml -p arpwatch-ens19 up -d
```

## 🔒 Security Considerations

- Arpwatch requires privileged access to monitor network traffic
- Container runs with `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities
- Uses host network mode for interface access
- Consider network isolation for production deployments
- Enable HTTPS for production use
- Review firewall rules and network access policies
- Consider adding authentication for production deployments

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📚 Additional Documentation

- [CONTAINER_DEPLOYMENT.md](CONTAINER_DEPLOYMENT.md) - Detailed container deployment guide
- [README-PREBUILT.md](README-PREBUILT.md) - Using prebuilt images and offline deployment
- [HOST_SETUP.md](HOST_SETUP.md) - Legacy host-based installation
- [CHANGELOG.md](CHANGELOG.md) - Version history and changes

## 📄 License

This project is licensed under the GNU General Public License v2 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Arpwatch](https://linux.die.net/man/8/arpwatch) - The original ARP monitoring tool
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [React](https://react.dev/) - Frontend library

---

**Questions or Issues?** Please open an issue on [GitHub](https://github.com/netwho/ARPWatch-WEBUI/issues).
