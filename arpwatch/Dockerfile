FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Replace sources.list with clean version including universe repository
# Remove any existing sources and create clean one
RUN rm -f /etc/apt/sources.list.d/*.list 2>/dev/null || true && \
    echo "deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse" > /etc/apt/sources.list

# Update package lists - handle clock sync errors gracefully
# Use --allow-releaseinfo-change to handle repository metadata changes
RUN apt-get -o Acquire::Check-Valid-Until=false \
    -o APT::Get::AllowUnauthenticated=false \
    --allow-releaseinfo-change update || \
    (echo "Warning: apt-get update had issues, trying without updates repo..." && \
     echo "deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse" > /etc/apt/sources.list && \
     apt-get -o Acquire::Check-Valid-Until=false update)

# Install all required packages in one go
# Use flags to handle clock sync and repository issues
RUN apt-get -o Acquire::Check-Valid-Until=false \
    -o APT::Get::AllowUnauthenticated=true \
    -o APT::Get::Assume-Yes=true \
    install --no-install-recommends \
    ca-certificates \
    tcpdump \
    iproute2 \
    net-tools \
    procps \
    arpwatch \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Configure rsyslog to write arpwatch messages to log file (if rsyslog is installed)
RUN if [ -d /etc/rsyslog.d ]; then \
        echo "# Capture all arpwatch messages" > /etc/rsyslog.d/50-arpwatch.conf && \
        echo "# Use programname matching to capture arpwatch messages" >> /etc/rsyslog.d/50-arpwatch.conf && \
        echo "if \$programname == 'arpwatch' or \$programname == 'Arpwatch' then {" >> /etc/rsyslog.d/50-arpwatch.conf && \
        echo "    /var/log/arpwatch/arpwatch.log" >> /etc/rsyslog.d/50-arpwatch.conf && \
        echo "    stop" >> /etc/rsyslog.d/50-arpwatch.conf && \
        echo "}" >> /etc/rsyslog.d/50-arpwatch.conf && \
        echo "# Also capture mail facility messages (arpwatch sends email-formatted logs)" >> /etc/rsyslog.d/50-arpwatch.conf && \
        echo "mail.* -/var/log/arpwatch/arpwatch.log" >> /etc/rsyslog.d/50-arpwatch.conf && \
        echo "& stop" >> /etc/rsyslog.d/50-arpwatch.conf; \
    fi

# Create directories for arpwatch data and logs
RUN mkdir -p /var/lib/arpwatch /var/log/arpwatch && \
    chown -R arpwatch:arpwatch /var/lib/arpwatch /var/log/arpwatch

# Create startup script that runs arpwatch and handles network interfaces
RUN echo '#!/bin/bash' > /start-arpwatch.sh && \
    echo '# Do not exit on error - we want to debug issues' >> /start-arpwatch.sh && \
    echo 'set +e' >> /start-arpwatch.sh && \
    echo 'INTERFACE=${INTERFACE:-eth0}' >> /start-arpwatch.sh && \
    echo 'echo "=== Arpwatch Container Startup ==="' >> /start-arpwatch.sh && \
    echo 'echo "Network mode: host (direct access to host interfaces)"' >> /start-arpwatch.sh && \
    echo 'echo "Interface: $INTERFACE"' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo '# Show all available interfaces' >> /start-arpwatch.sh && \
    echo 'echo "Available network interfaces:"' >> /start-arpwatch.sh && \
    echo 'ip link show | grep -E "^[0-9]+:" | awk "{print \$2}" | sed "s/://" | grep -v lo || true' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo '# Wait for network interface to be available' >> /start-arpwatch.sh && \
    echo 'echo "Waiting for interface $INTERFACE to be available..."' >> /start-arpwatch.sh && \
    echo 'FOUND=0' >> /start-arpwatch.sh && \
    echo 'for i in $(seq 1 30); do' >> /start-arpwatch.sh && \
    echo '  if ip link show "$INTERFACE" >/dev/null 2>&1; then' >> /start-arpwatch.sh && \
    echo '    echo "✓ Interface $INTERFACE found"' >> /start-arpwatch.sh && \
    echo '    FOUND=1' >> /start-arpwatch.sh && \
    echo '    break' >> /start-arpwatch.sh && \
    echo '  fi' >> /start-arpwatch.sh && \
    echo '  sleep 1' >> /start-arpwatch.sh && \
    echo 'done' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo 'if [ $FOUND -eq 0 ]; then' >> /start-arpwatch.sh && \
    echo '  echo "✗ ERROR: Interface $INTERFACE not found after 30 seconds!"' >> /start-arpwatch.sh && \
    echo '  echo "Available interfaces:"' >> /start-arpwatch.sh && \
    echo '  ip link show | grep -E "^[0-9]+:" | awk "{print \$2}" | sed "s/://" | grep -v lo' >> /start-arpwatch.sh && \
    echo '  echo ""' >> /start-arpwatch.sh && \
    echo '  echo "Please set ARPWATCH_INTERFACE to one of the interfaces above"' >> /start-arpwatch.sh && \
    echo '  exit 1' >> /start-arpwatch.sh && \
    echo 'fi' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo '# Create arp.dat if it does not exist' >> /start-arpwatch.sh && \
    echo '# Ensure directory exists and is writable' >> /start-arpwatch.sh && \
    echo 'mkdir -p /var/lib/arpwatch' >> /start-arpwatch.sh && \
    echo 'chmod 755 /var/lib/arpwatch' >> /start-arpwatch.sh && \
    echo 'if [ ! -f /var/lib/arpwatch/arp.dat ]; then' >> /start-arpwatch.sh && \
    echo '  touch /var/lib/arpwatch/arp.dat' >> /start-arpwatch.sh && \
    echo 'fi' >> /start-arpwatch.sh && \
    echo '# Make file writable by root (since arpwatch runs as root)' >> /start-arpwatch.sh && \
    echo 'chown root:root /var/lib/arpwatch/arp.dat' >> /start-arpwatch.sh && \
    echo 'chmod 644 /var/lib/arpwatch/arp.dat' >> /start-arpwatch.sh && \
    echo '# Verify file is writable' >> /start-arpwatch.sh && \
    echo 'if [ -w /var/lib/arpwatch/arp.dat ]; then' >> /start-arpwatch.sh && \
    echo '  echo "✓ arp.dat is writable"' >> /start-arpwatch.sh && \
    echo 'else' >> /start-arpwatch.sh && \
    echo '  echo "✗ ERROR: arp.dat is NOT writable!"' >> /start-arpwatch.sh && \
    echo '  ls -la /var/lib/arpwatch/arp.dat' >> /start-arpwatch.sh && \
    echo 'fi' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo '# Create log file if it does not exist' >> /start-arpwatch.sh && \
    echo 'LOG_FILE="/var/log/arpwatch/arpwatch.log"' >> /start-arpwatch.sh && \
    echo 'mkdir -p /var/log/arpwatch' >> /start-arpwatch.sh && \
    echo 'touch "$LOG_FILE"' >> /start-arpwatch.sh && \
    echo '# Make writable by syslog (for rsyslog) and root (for tee)' >> /start-arpwatch.sh && \
    echo 'chown syslog:syslog "$LOG_FILE" 2>/dev/null || chown root:root "$LOG_FILE"' >> /start-arpwatch.sh && \
    echo 'chmod 666 "$LOG_FILE"  # Writable by all for tee and rsyslog' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo '# Start syslog daemon to capture arpwatch logs' >> /start-arpwatch.sh && \
    echo 'if command -v rsyslogd >/dev/null 2>&1; then' >> /start-arpwatch.sh && \
    echo '  echo "Starting rsyslog daemon..."' >> /start-arpwatch.sh && \
    echo '  # Kill any existing rsyslogd and remove pidfile' >> /start-arpwatch.sh && \
    echo '  killall rsyslogd 2>/dev/null || true' >> /start-arpwatch.sh && \
    echo '  rm -f /run/rsyslogd.pid 2>/dev/null || true' >> /start-arpwatch.sh && \
    echo '  # Ensure log file directory and file exist with correct permissions for rsyslog' >> /start-arpwatch.sh && \
    echo '  mkdir -p /var/log/arpwatch' >> /start-arpwatch.sh && \
    echo '  touch "$LOG_FILE"' >> /start-arpwatch.sh && \
    echo '  # Make writable by syslog user (rsyslog runs as syslog)' >> /start-arpwatch.sh && \
    echo '  chown syslog:syslog "$LOG_FILE" 2>/dev/null || chown root:root "$LOG_FILE"' >> /start-arpwatch.sh && \
    echo '  chmod 666 "$LOG_FILE"  # Writable by rsyslog (syslog user) and for tee (any user)' >> /start-arpwatch.sh && \
    echo '  # Verify and create rsyslog config if needed' >> /start-arpwatch.sh && \
    echo '  if [ ! -f /etc/rsyslog.d/50-arpwatch.conf ]; then' >> /start-arpwatch.sh && \
    echo '    mkdir -p /etc/rsyslog.d' >> /start-arpwatch.sh && \
    echo '    echo "# Capture arpwatch messages" > /etc/rsyslog.d/50-arpwatch.conf' >> /start-arpwatch.sh && \
    echo '    echo "if \\$programname == '\''arpwatch'\'' or \\$programname == '\''Arpwatch'\'' then {" >> /etc/rsyslog.d/50-arpwatch.conf' >> /start-arpwatch.sh && \
    echo '    echo "    /var/log/arpwatch/arpwatch.log" >> /etc/rsyslog.d/50-arpwatch.conf' >> /start-arpwatch.sh && \
    echo '    echo "    stop" >> /etc/rsyslog.d/50-arpwatch.conf' >> /start-arpwatch.sh && \
    echo '    echo "}" >> /etc/rsyslog.d/50-arpwatch.conf' >> /start-arpwatch.sh && \
    echo '    echo "# Also capture mail facility (arpwatch uses mail facility for email format)" >> /etc/rsyslog.d/50-arpwatch.conf' >> /start-arpwatch.sh && \
    echo '    echo "mail.* -/var/log/arpwatch/arpwatch.log" >> /etc/rsyslog.d/50-arpwatch.conf' >> /start-arpwatch.sh && \
    echo '    echo "& stop" >> /etc/rsyslog.d/50-arpwatch.conf' >> /start-arpwatch.sh && \
    echo '  fi' >> /start-arpwatch.sh && \
    echo '  # Start rsyslog with full config' >> /start-arpwatch.sh && \
    echo '  rsyslogd -n -i /tmp/rsyslogd.pid -f /etc/rsyslog.conf 2>&1 &' >> /start-arpwatch.sh && \
    echo '  sleep 3' >> /start-arpwatch.sh && \
    echo '  # Test rsyslog' >> /start-arpwatch.sh && \
    echo '  logger -t arpwatch "Rsyslog test message - $(date)"' >> /start-arpwatch.sh && \
    echo '  sleep 2' >> /start-arpwatch.sh && \
    echo '  if [ -s "$LOG_FILE" ]; then' >> /start-arpwatch.sh && \
    echo '    echo "✓ Rsyslog is writing to log file"' >> /start-arpwatch.sh && \
    echo '  else' >> /start-arpwatch.sh && \
    echo '    echo "⚠ Warning: Log file still empty - checking rsyslog..."' >> /start-arpwatch.sh && \
    echo '    ps aux | grep rsyslog | grep -v grep || echo "rsyslog not running"' >> /start-arpwatch.sh && \
    echo '  fi' >> /start-arpwatch.sh && \
    echo 'elif command -v syslogd >/dev/null 2>&1; then' >> /start-arpwatch.sh && \
    echo '  echo "Starting syslogd..."' >> /start-arpwatch.sh && \
    echo '  killall syslogd 2>/dev/null || true' >> /start-arpwatch.sh && \
    echo '  syslogd -O "$LOG_FILE" &' >> /start-arpwatch.sh && \
    echo '  sleep 2' >> /start-arpwatch.sh && \
    echo 'fi' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo '# Start arpwatch as daemon (it will log to syslog, which rsyslog writes to LOG_FILE)' >> /start-arpwatch.sh && \
    echo 'echo "Starting arpwatch on interface $INTERFACE..."' >> /start-arpwatch.sh && \
    echo 'echo "Log file: $LOG_FILE"' >> /start-arpwatch.sh && \
    echo 'echo "Data file: /var/lib/arpwatch/arp.dat"' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo '# Show interface details before starting' >> /start-arpwatch.sh && \
    echo 'ip link show "$INTERFACE"' >> /start-arpwatch.sh && \
    echo 'ip addr show "$INTERFACE" || true' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo '# Start arpwatch as daemon' >> /start-arpwatch.sh && \
    echo 'echo "Launching arpwatch..."' >> /start-arpwatch.sh && \
    echo '# Export INTERFACE so it is available' >> /start-arpwatch.sh && \
    echo 'export INTERFACE' >> /start-arpwatch.sh && \
    echo '# Try to start arpwatch as arpwatch user first' >> /start-arpwatch.sh && \
    echo 'echo "Attempting to start arpwatch as arpwatch user..."' >> /start-arpwatch.sh && \
    echo '# Export LOG_FILE for use in su command' >> /start-arpwatch.sh && \
    echo 'export LOG_FILE' >> /start-arpwatch.sh && \
    echo '# Start arpwatch and redirect output to log file using tee (writes to both file and stdout)' >> /start-arpwatch.sh && \
    echo '# Run arpwatch WITHOUT -d flag so output goes to stdout/stderr, then redirect with tee' >> /start-arpwatch.sh && \
    echo '# Ensure log file is writable before starting arpwatch' >> /start-arpwatch.sh && \
    echo 'chmod 666 "$LOG_FILE"' >> /start-arpwatch.sh && \
    echo '# Run arpwatch as root directly (avoids permission issues with tee)' >> /start-arpwatch.sh && \
    echo '# Start arpwatch and suppress sendmail errors (we do not need email notifications)' >> /start-arpwatch.sh && \
    echo '/usr/sbin/arpwatch -i "$INTERFACE" -a -f /var/lib/arpwatch/arp.dat 2>&1 | grep -v "sendmail\|execl.*sendmail\|reaper.*sendmail" | tee -a "$LOG_FILE" &' >> /start-arpwatch.sh && \
    echo 'sleep 3' >> /start-arpwatch.sh && \
    echo 'if pgrep -x arpwatch > /dev/null; then' >> /start-arpwatch.sh && \
    echo '  echo "✓ Arpwatch started - output being written to $LOG_FILE"' >> /start-arpwatch.sh && \
    echo '  echo "Waiting 5 seconds for arpwatch to generate some output..."' >> /start-arpwatch.sh && \
    echo '  sleep 5' >> /start-arpwatch.sh && \
    echo '  if [ -s "$LOG_FILE" ]; then' >> /start-arpwatch.sh && \
    echo '    echo "✓ Log file has content: $(wc -l < "$LOG_FILE") lines"' >> /start-arpwatch.sh && \
    echo '  else' >> /start-arpwatch.sh && \
    echo '    echo "⚠ Log file is still empty - arpwatch may need time to detect hosts"' >> /start-arpwatch.sh && \
    echo '  fi' >> /start-arpwatch.sh && \
    echo 'else' >> /start-arpwatch.sh && \
    echo '  echo "✗ ERROR: Arpwatch failed to start!"' >> /start-arpwatch.sh && \
    echo '  echo "Trying alternative method..."' >> /start-arpwatch.sh && \
    echo '  # Try running as root if arpwatch user fails' >> /start-arpwatch.sh && \
    echo '  # Ensure file is writable before starting' >> /start-arpwatch.sh && \
    echo '  chmod 644 /var/lib/arpwatch/arp.dat' >> /start-arpwatch.sh && \
    echo '  chown root:root /var/lib/arpwatch/arp.dat' >> /start-arpwatch.sh && \
    echo '  # Start arpwatch and redirect output to log file' >> /start-arpwatch.sh && \
    echo '  # Use tee to write to both log file and stdout (for Docker logs)' >> /start-arpwatch.sh && \
    echo '  export LOG_FILE' >> /start-arpwatch.sh && \
    echo '  chmod 666 "$LOG_FILE"  # Ensure writable' >> /start-arpwatch.sh && \
    echo '  /usr/sbin/arpwatch -i "$INTERFACE" -a -f /var/lib/arpwatch/arp.dat 2>&1 | tee -a "$LOG_FILE" &' >> /start-arpwatch.sh && \
    echo '  sleep 3' >> /start-arpwatch.sh && \
    echo '  if pgrep -x arpwatch > /dev/null; then' >> /start-arpwatch.sh && \
    echo '    echo "Arpwatch started as root - output being written to $LOG_FILE"' >> /start-arpwatch.sh && \
    echo '  else' >> /start-arpwatch.sh && \
    echo '    echo "Failed to start as root too. Showing error..."' >> /start-arpwatch.sh && \
    echo '    /usr/sbin/arpwatch -i "$INTERFACE" -a -f /var/lib/arpwatch/arp.dat 2>&1 | head -20 || true' >> /start-arpwatch.sh && \
    echo '  fi' >> /start-arpwatch.sh && \
    echo 'fi' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo '# Wait a moment and check if it started' >> /start-arpwatch.sh && \
    echo 'sleep 5' >> /start-arpwatch.sh && \
    echo 'if pgrep -x arpwatch > /dev/null; then' >> /start-arpwatch.sh && \
    echo '  echo "✓ Arpwatch started successfully, PID: $(pgrep -x arpwatch)"' >> /start-arpwatch.sh && \
    echo '  echo "Running as user: $(ps -o user= -p $(pgrep -x arpwatch))"' >> /start-arpwatch.sh && \
    echo '  echo "Data file: /var/lib/arpwatch/arp.dat"' >> /start-arpwatch.sh && \
    echo '  echo "Checking arp.dat file status..."' >> /start-arpwatch.sh && \
    echo '  ls -la /var/lib/arpwatch/arp.dat' >> /start-arpwatch.sh && \
    echo '  echo "File size: $(stat -c%s /var/lib/arpwatch/arp.dat 2>/dev/null || echo 0) bytes"' >> /start-arpwatch.sh && \
    echo '  echo "Waiting 10 seconds for arpwatch to write initial data..."' >> /start-arpwatch.sh && \
    echo '  sleep 10' >> /start-arpwatch.sh && \
    echo '  echo "File size after wait: $(stat -c%s /var/lib/arpwatch/arp.dat 2>/dev/null || echo 0) bytes"' >> /start-arpwatch.sh && \
    echo '  if [ -s /var/lib/arpwatch/arp.dat ]; then' >> /start-arpwatch.sh && \
    echo '    echo "✓ arp.dat contains data"' >> /start-arpwatch.sh && \
    echo '  else' >> /start-arpwatch.sh && \
    echo '    echo "⚠ Warning: arp.dat is still empty after 10 seconds"' >> /start-arpwatch.sh && \
    echo '    echo "This may be normal if no hosts have been detected yet"' >> /start-arpwatch.sh && \
    echo '  fi' >> /start-arpwatch.sh && \
    echo '  echo "Log directory: /var/log/arpwatch"' >> /start-arpwatch.sh && \
    echo 'else' >> /start-arpwatch.sh && \
    echo '  echo "✗ ERROR: Arpwatch failed to start!"' >> /start-arpwatch.sh && \
    echo '  echo "Checking if arpwatch binary exists..."' >> /start-arpwatch.sh && \
    echo '  ls -la /usr/sbin/arpwatch || echo "Arpwatch binary not found!"' >> /start-arpwatch.sh && \
    echo '  echo "Checking interface..."' >> /start-arpwatch.sh && \
    echo '  ip link show "$INTERFACE" || echo "Interface not found!"' >> /start-arpwatch.sh && \
    echo '  echo "Attempting to run arpwatch without daemon mode to see full error..."' >> /start-arpwatch.sh && \
    echo '  echo "--- Error output start ---"' >> /start-arpwatch.sh && \
    echo '  /usr/sbin/arpwatch -i "$INTERFACE" -a -f /var/lib/arpwatch/arp.dat 2>&1 &' >> /start-arpwatch.sh && \
    echo '  sleep 3' >> /start-arpwatch.sh && \
    echo '  kill %1 2>/dev/null || true' >> /start-arpwatch.sh && \
    echo '  echo "--- Error output end ---"' >> /start-arpwatch.sh && \
    echo '  echo "Container will keep running for debugging..."' >> /start-arpwatch.sh && \
    echo '  echo "Sleeping for 1 hour for debugging..."' >> /start-arpwatch.sh && \
    echo '  sleep 3600' >> /start-arpwatch.sh && \
    echo 'fi' >> /start-arpwatch.sh && \
    echo '' >> /start-arpwatch.sh && \
    echo '# Keep container alive and monitor arpwatch process' >> /start-arpwatch.sh && \
    echo 'echo "Monitoring arpwatch process..."' >> /start-arpwatch.sh && \
    echo 'while true; do' >> /start-arpwatch.sh && \
    echo '  if ! pgrep -x arpwatch > /dev/null; then' >> /start-arpwatch.sh && \
    echo '    echo "✗ ERROR: Arpwatch process died! Restarting..."' >> /start-arpwatch.sh && \
    echo '    export INTERFACE' >> /start-arpwatch.sh && \
    echo '    # Ensure file is writable before restarting' >> /start-arpwatch.sh && \
    echo '    chmod 644 /var/lib/arpwatch/arp.dat' >> /start-arpwatch.sh && \
    echo '    chown root:root /var/lib/arpwatch/arp.dat' >> /start-arpwatch.sh && \
    echo '    chmod 666 "$LOG_FILE"  # Ensure writable' >> /start-arpwatch.sh && \
    echo '    /usr/sbin/arpwatch -i "$INTERFACE" -a -f /var/lib/arpwatch/arp.dat 2>&1 | grep -v "sendmail\|execl.*sendmail\|reaper.*sendmail" | tee -a "$LOG_FILE" &' >> /start-arpwatch.sh && \
    echo '    sleep 3' >> /start-arpwatch.sh && \
    echo '  fi' >> /start-arpwatch.sh && \
    echo '  sleep 30' >> /start-arpwatch.sh && \
    echo 'done' >> /start-arpwatch.sh && \
    chmod +x /start-arpwatch.sh

# Start arpwatch
CMD ["/start-arpwatch.sh"]

