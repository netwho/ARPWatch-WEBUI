#!/bin/bash
# Standalone arpwatch startup script (alternative to systemd)

set -e

INTERFACE=${1:-ens18}
ARPWATCH_DATA_DIR="/var/lib/arpwatch"
ARPWATCH_LOG_DIR="/var/log/arpwatch"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Create directories
mkdir -p "$ARPWATCH_DATA_DIR"
mkdir -p "$ARPWATCH_LOG_DIR"

# Set proper permissions
chown -R arpwatch:arpwatch "$ARPWATCH_DATA_DIR"
chown -R arpwatch:arpwatch "$ARPWATCH_LOG_DIR"

# Check if interface exists
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo "ERROR: Interface $INTERFACE not found!"
    exit 1
fi

# Start arpwatch as daemon
echo "Starting arpwatch on interface $INTERFACE..."
su -s /bin/sh arpwatch -c "/usr/sbin/arpwatch -i $INTERFACE -d -f $ARPWATCH_DATA_DIR/arp.dat"

sleep 2

if pgrep -x arpwatch > /dev/null; then
    echo "Arpwatch started successfully, PID: $(pgrep -x arpwatch)"
    echo "Data file: $ARPWATCH_DATA_DIR/arp.dat"
else
    echo "ERROR: Arpwatch failed to start!"
    exit 1
fi

