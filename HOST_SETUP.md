# Arpwatch Host Setup

Since arpwatch requires direct network interface access, it's recommended to run it natively on the host rather than in a container.

## Quick Setup

### Option 1: Using the Installation Script (Recommended)

```bash
cd ~/arpwatch-ui
sudo ./install-arpwatch.sh ens18
```

Replace `ens18` with your network interface name if different.

### Option 2: Manual Setup with Systemd

1. **Install arpwatch:**
   ```bash
   sudo apt-get update
   sudo apt-get install -y arpwatch
   ```

2. **Create directories:**
   ```bash
   sudo mkdir -p /var/lib/arpwatch /var/log/arpwatch
   sudo chown -R arpwatch:arpwatch /var/lib/arpwatch /var/log/arpwatch
   ```

3. **Create systemd service:**
   ```bash
   sudo nano /etc/systemd/system/arpwatch.service
   ```
   
   Paste this content (replace `ens18` with your interface):
   ```ini
   [Unit]
   Description=ARPwatch daemon
   After=network.target

   [Service]
   Type=forking
   User=arpwatch
   Group=arpwatch
   ExecStart=/usr/sbin/arpwatch -i ens18 -d -f /var/lib/arpwatch/arp.dat
   ExecStop=/bin/kill -TERM $MAINPID
   PIDFile=/run/arpwatch.pid
   AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
   CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
   Restart=on-failure
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

4. **Enable and start:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable arpwatch
   sudo systemctl start arpwatch
   sudo systemctl status arpwatch
   ```

### Option 3: Standalone Script (No systemd)

```bash
cd ~/arpwatch-ui
sudo chmod +x arpwatch-standalone.sh
sudo ./arpwatch-standalone.sh ens18
```

## Verify Installation

```bash
# Check if arpwatch is running
ps aux | grep arpwatch

# Check if data file is being created
ls -la /var/lib/arpwatch/arp.dat

# View arpwatch logs
sudo journalctl -u arpwatch -f
```

## Management Commands

```bash
# Start arpwatch
sudo systemctl start arpwatch

# Stop arpwatch
sudo systemctl stop arpwatch

# Restart arpwatch
sudo systemctl restart arpwatch

# Check status
sudo systemctl status arpwatch

# View logs
sudo journalctl -u arpwatch -f
```

## Configuration

### Change Network Interface

Edit the systemd service:
```bash
sudo nano /etc/systemd/system/arpwatch.service
```

Change the `-i ens18` parameter to your interface, then:
```bash
sudo systemctl daemon-reload
sudo systemctl restart arpwatch
```

### Arpwatch Parameters

The default command is:
```bash
/usr/sbin/arpwatch -i ens18 -d -f /var/lib/arpwatch/arp.dat
```

- `-i ens18`: Network interface to monitor
- `-d`: Run as daemon
- `-f /var/lib/arpwatch/arp.dat`: Database file location

Additional useful parameters:
- `-u arpwatch`: Run as specific user (default)
- `-e`: Send email alerts (requires mail configuration)
- `-r file`: Read from pcap file instead of live interface

## Troubleshooting

### Arpwatch not starting

```bash
# Check logs
sudo journalctl -u arpwatch -n 50

# Try running manually to see errors
sudo -u arpwatch /usr/sbin/arpwatch -i ens18 -f /var/lib/arpwatch/arp.dat
```

### Permission issues

```bash
# Fix permissions
sudo chown -R arpwatch:arpwatch /var/lib/arpwatch /var/log/arpwatch
```

### Interface not found

```bash
# List available interfaces
ip link show

# Update the service file with correct interface name
sudo nano /etc/systemd/system/arpwatch.service
sudo systemctl daemon-reload
sudo systemctl restart arpwatch
```

## Docker Compose

After setting up arpwatch on the host, start the web UI containers:

```bash
cd ~/arpwatch-ui
docker compose up -d
```

The backend container will automatically read from `/var/lib/arpwatch/arp.dat` on the host.

