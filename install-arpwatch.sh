#!/bin/bash
# Arpwatch installation and setup script for Debian/Ubuntu

set -euo pipefail

INTERFACE=${1:-ens18}
ARPWATCH_DATA_DIR="/var/lib/arpwatch"
ARPWATCH_LOG_DIR="/var/log/arpwatch"
WRAPPER_PATH="/usr/local/bin/arpwatch-wrapper.sh"
SERVICE_PATH="/etc/systemd/system/arpwatch.service"

echo "=== Arpwatch Host Installation ==="
echo "Interface: $INTERFACE"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Warn/optionally remove an existing install so we can replace the wrapper/service
EXISTING=0
if systemctl list-unit-files 2>/dev/null | grep -q '^arpwatch\.service'; then EXISTING=1; fi
if systemctl status arpwatch 2>/dev/null | grep -q 'Loaded:'; then EXISTING=1; fi
if [ -f "$SERVICE_PATH" ] || [ -x "$WRAPPER_PATH" ]; then EXISTING=1; fi

if [ "$EXISTING" -eq 1 ]; then
    echo "Existing arpwatch installation detected."
    read -r -p "Remove existing arpwatch service and wrapper before reinstall? [y/N]: " REMOVE_OLD
    if [[ "$REMOVE_OLD" =~ ^[Yy]$ ]]; then
        echo "Stopping and disabling old service (if running)..."
        systemctl stop arpwatch.service 2>/dev/null || true
        systemctl disable arpwatch.service 2>/dev/null || true
        echo "Removing old service definition and wrapper..."
        rm -f "$SERVICE_PATH"
        rm -f "$WRAPPER_PATH"
        systemctl daemon-reload
        echo "Old arpwatch service removed."
    else
        echo "Aborting at user request."
        exit 0
    fi
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
cat > "$WRAPPER_PATH" << 'WRAPPER_EOF'
#!/bin/bash
set -euo pipefail

INTERFACE="$1"
DATAFILE="$2"

if [ -z "${INTERFACE:-}" ] || [ -z "${DATAFILE:-}" ]; then
    echo "Usage: $0 <interface> <datafile>" >&2
    exit 1
fi

# Ensure data file exists and is owned by arpwatch
mkdir -p "$(dirname "$DATAFILE")"
touch "$DATAFILE"
chown arpwatch:arpwatch "$DATAFILE" 2>/dev/null || true
chmod 644 "$DATAFILE" 2>/dev/null || true

# Run arpwatch in the foreground under systemd; -a disables bogon filtering complaints
exec /usr/sbin/arpwatch -i "$INTERFACE" -d -a -f "$DATAFILE"
WRAPPER_EOF
chmod +x "$WRAPPER_PATH"

# Create systemd service file
echo "Creating systemd service..."
cat > "$SERVICE_PATH" << EOF
[Unit]
Description=ARPwatch daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=arpwatch
Group=arpwatch
ExecStart=$WRAPPER_PATH $INTERFACE $ARPWATCH_DATA_DIR/arp.dat
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true

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

