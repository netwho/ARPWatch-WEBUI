FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    arpwatch \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create directories for arpwatch data and logs
RUN mkdir -p /var/lib/arpwatch /var/log/arpwatch

# Copy configuration if needed
# COPY arpwatch.conf /etc/arpwatch.conf

# Install iproute2 for network tools
RUN apt-get update && \
    apt-get install -y \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create startup script that runs arpwatch as daemon and keeps container alive
RUN echo '#!/bin/sh' > /start-arpwatch.sh && \
    echo 'set -e' >> /start-arpwatch.sh && \
    echo 'INTERFACE=${INTERFACE:-eth0}' >> /start-arpwatch.sh && \
    echo 'echo "=== Arpwatch Startup ==="' >> /start-arpwatch.sh && \
    echo 'echo "Interface: $INTERFACE"' >> /start-arpwatch.sh && \
    echo 'echo "Checking interface..."' >> /start-arpwatch.sh && \
    echo 'ip link show "$INTERFACE" || (echo "ERROR: Interface not found!" && exit 1)' >> /start-arpwatch.sh && \
    echo 'echo "Starting arpwatch as daemon..."' >> /start-arpwatch.sh && \
    echo 'arpwatch -i "$INTERFACE" -d -f /var/lib/arpwatch/arp.dat' >> /start-arpwatch.sh && \
    echo 'sleep 2' >> /start-arpwatch.sh && \
    echo 'if pgrep -x arpwatch > /dev/null; then' >> /start-arpwatch.sh && \
    echo '  echo "Arpwatch started successfully, PID: $(pgrep -x arpwatch)"' >> /start-arpwatch.sh && \
    echo 'else' >> /start-arpwatch.sh && \
    echo '  echo "ERROR: Arpwatch failed to start!"' >> /start-arpwatch.sh && \
    echo '  exit 1' >> /start-arpwatch.sh && \
    echo 'fi' >> /start-arpwatch.sh && \
    echo 'echo "Keeping container alive..."' >> /start-arpwatch.sh && \
    echo 'while true; do' >> /start-arpwatch.sh && \
    echo '  if ! pgrep -x arpwatch > /dev/null; then' >> /start-arpwatch.sh && \
    echo '    echo "ERROR: Arpwatch process died!"' >> /start-arpwatch.sh && \
    echo '    exit 1' >> /start-arpwatch.sh && \
    echo '  fi' >> /start-arpwatch.sh && \
    echo '  sleep 30' >> /start-arpwatch.sh && \
    echo 'done' >> /start-arpwatch.sh && \
    chmod +x /start-arpwatch.sh

# Start arpwatch
CMD ["/start-arpwatch.sh"]

