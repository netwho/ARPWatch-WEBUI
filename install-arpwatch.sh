#!/bin/bash
# Arpwatch installation and setup script for Debian/Ubuntu

set -e

INTERFACE=${1:-ens18}
ARPWATCH_DATA_DIR="/var/lib/arpwatch"
ARPWATCH_LOG_DIR="/var/log/arpwatch"

echo "=== Arpwatch Host Installation ==="
echo "Interface: $INTERFACE"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Install arpwatch if not already installed
if ! command -v arpwatch &> /dev/null; then
    echo "Installing arpwatch..."
    apt-get update
    apt-get install -y arpwatch
else
    echo "Arpwatch is already installed"
fi

# Create directories
echo "Creating directories..."
mkdir -p "$ARPWATCH_DATA_DIR"
mkdir -p "$ARPWATCH_LOG_DIR"

# Set proper permissions
chown -R arpwatch:arpwatch "$ARPWATCH_DATA_DIR"
chown -R arpwatch:arpwatch "$ARPWATCH_LOG_DIR"
chmod 755 "$ARPWATCH_DATA_DIR"
chmod 755 "$ARPWATCH_LOG_DIR"

# Create arp.dat file if it doesn't exist
touch "$ARPWATCH_DATA_DIR/arp.dat"
chown arpwatch:arpwatch "$ARPWATCH_DATA_DIR/arp.dat"
chmod 644 "$ARPWATCH_DATA_DIR/arp.dat"

# Check if interface exists
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo "ERROR: Interface $INTERFACE not found!"
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/://'
    exit 1
fi

# Try to set capabilities on arpwatch binary (alternative to systemd capabilities)
echo "Setting capabilities on arpwatch binary..."
if command -v setcap &> /dev/null; then
    setcap cap_net_raw,cap_net_admin=eip /usr/sbin/arpwatch 2>/dev/null || echo "Note: setcap may have failed, will use systemd capabilities"
fi

# Create wrapper script to handle arpwatch daemonization
echo "Creating wrapper script..."
cat > /usr/local/bin/arpwatch-wrapper.sh << 'WRAPPER_EOF'
#!/bin/bash
INTERFACE="$1"
DATAFILE="$2"
PIDFILE="/run/arpwatch.pid"

# Ensure data file exists and is writable
touch "$DATAFILE"
chown arpwatch:arpwatch "$DATAFILE" 2>/dev/null || true

# Start arpwatch as daemon
/usr/sbin/arpwatch -i "$INTERFACE" -d -f "$DATAFILE"

# Wait a moment for it to start
sleep 2

# Find the arpwatch PID and write to PID file
for i in {1..5}; do
    PID=$(pgrep -f "arpwatch.*$INTERFACE" | head -1)
    if [ -n "$PID" ]; then
        # Write PID file
        echo "$PID" > "$PIDFILE" 2>/dev/null || true
        # Keep script running so systemd doesn't think service exited
        while pgrep -f "arpwatch.*$INTERFACE" > /dev/null; do
            sleep 5
        done
        exit 0
    fi
    sleep 1
done
echo "ERROR: Arpwatch failed to start"
exit 1
WRAPPER_EOF
chmod +x /usr/local/bin/arpwatch-wrapper.sh

# Create systemd service file
echo "Creating systemd service..."
cat > /etc/systemd/system/arpwatch.service << EOF
[Unit]
Description=ARPwatch daemon
After=network.target

[Service]
Type=simple
User=arpwatch
Group=arpwatch
ExecStart=/usr/local/bin/arpwatch-wrapper.sh $INTERFACE $ARPWATCH_DATA_DIR/arp.dat
ExecStop=/bin/kill -TERM \$(cat /run/arpwatch.pid 2>/dev/null) || true
PIDFile=/run/arpwatch.pid
RuntimeDirectory=arpwatch
RuntimeDirectoryMode=0755
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
TimeoutStartSec=10
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
echo "Enabling arpwatch service..."
systemctl daemon-reload
systemctl enable arpwatch.service

# Start the service
echo "Starting arpwatch..."
systemctl start arpwatch.service

# Check status
sleep 2
if systemctl is-active --quiet arpwatch; then
    echo "✓ Arpwatch is running!"
    echo ""
    echo "Service status:"
    systemctl status arpwatch --no-pager -l
    echo ""
    echo "To check logs: sudo journalctl -u arpwatch -f"
    echo "To restart: sudo systemctl restart arpwatch"
    echo "To stop: sudo systemctl stop arpwatch"
else
    echo "✗ Arpwatch failed to start!"
    echo "Check logs with: sudo journalctl -u arpwatch -n 50"
    exit 1
fi

