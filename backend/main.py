from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import os
import re
import json
import socket
import subprocess
from pathlib import Path
import time
import threading
import sys
from collections import deque
from datetime import datetime

app = FastAPI(title="Arpwatch API", version="0.2.6")

# In-memory log buffer to capture application logs
LOG_BUFFER = deque(maxlen=500)  # Keep last 500 log entries

class LogCapture:
    """Capture stdout/stderr to buffer"""
    def __init__(self, original_stream, prefix=""):
        self.original_stream = original_stream
        self.prefix = prefix
    
    def write(self, message):
        if message.strip():  # Only log non-empty messages
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {self.prefix}{message.rstrip()}"
            LOG_BUFFER.append(log_entry)
        self.original_stream.write(message)
        self.original_stream.flush()
    
    def flush(self):
        self.original_stream.flush()

# Redirect stdout and stderr to capture logs
sys.stdout = LogCapture(sys.stdout)
sys.stderr = LogCapture(sys.stderr, "[ERROR] ")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add middleware to log requests
@app.middleware("http")
async def log_requests(request, call_next):
    """Log all HTTP requests (only log API endpoints, not static files)"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    # Only log API endpoints to reduce noise
    if request.url.path.startswith("/api/") and request.url.path != "/api/logs":
        print(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.3f}s")
    return response

# Configuration
ARPWATCH_DATA_DIR = os.getenv("ARPWATCH_DATA_DIR", "/var/lib/arpwatch")
ARPWATCH_LOG_DIR = os.getenv("ARPWATCH_LOG_DIR", "/var/log/arpwatch")
ARP_DAT_FILE = os.path.join(ARPWATCH_DATA_DIR, "arp.dat")
OS_CACHE_FILE = os.path.join(ARPWATCH_DATA_DIR, "os_fingerprint_cache.json")
DNS_CACHE_FILE = os.path.join(ARPWATCH_DATA_DIR, "dns_hostname_cache.json")

# Feature flags
ENABLE_OS_FINGERPRINTING = os.getenv("ENABLE_OS_FINGERPRINTING", "true").lower() == "true"
ENABLE_PORT_SCANNING = os.getenv("ENABLE_PORT_SCANNING", "true").lower() == "true"

# Port scanning configuration
SCAN_PORTS_STR = os.getenv("SCAN_PORTS", "21,22,80,443,445")
DEFAULT_SCAN_PORTS = [int(p.strip()) for p in SCAN_PORTS_STR.split(",") if p.strip().isdigit()]

# OS fingerprinting behavior/tuning
OS_FINGERPRINT_RETRY_HOURS = int(os.getenv("OS_FINGERPRINT_RETRY_HOURS", "0"))
OS_FINGERPRINT_TIMEOUT = int(os.getenv("OS_FINGERPRINT_TIMEOUT", "10"))

# Background rescan flag
rescan_in_progress = False

# IP range exclusion (comma-separated CIDR notation, e.g., "192.168.2.0/24,10.0.0.0/8")
EXCLUDE_IP_RANGES_STR = os.getenv("EXCLUDE_IP_RANGES", "")
EXCLUDE_IP_RANGES = [r.strip() for r in EXCLUDE_IP_RANGES_STR.split(",") if r.strip()] if EXCLUDE_IP_RANGES_STR else []

def ip_in_range(ip: str, cidr: str) -> bool:
    """Check if an IP address is within a CIDR range"""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(cidr, strict=False)
        return ip_obj in network
    except:
        return False

def should_exclude_ip(ip: str) -> bool:
    """Check if an IP should be excluded based on configured ranges"""
    if not EXCLUDE_IP_RANGES:
        return False
    for cidr in EXCLUDE_IP_RANGES:
        if ip_in_range(ip, cidr):
            return True
    return False

# OS fingerprinting cache
os_cache: Dict[str, Dict] = {}

def load_os_cache():
    """Load OS fingerprinting cache from file"""
    global os_cache
    if os.path.exists(OS_CACHE_FILE):
        try:
            with open(OS_CACHE_FILE, 'r') as f:
                os_cache = json.load(f)
        except Exception as e:
            print(f"Error loading OS cache: {e}")
            os_cache = {}

def save_os_cache():
    """Save OS fingerprinting cache to file"""
    try:
        with open(OS_CACHE_FILE, 'w') as f:
            json.dump(os_cache, f, indent=2)
    except Exception as e:
        print(f"Error saving OS cache: {e}")

def get_cached_os(ip_address: str) -> Optional[str]:
    """Return cached OS fingerprint without triggering a scan"""
    if ip_address in os_cache:
        return os_cache[ip_address].get("os")
    return None

# DNS hostname cache
dns_cache: Dict[str, str] = {}

def load_dns_cache():
    """Load DNS hostname cache from file"""
    global dns_cache
    if os.path.exists(DNS_CACHE_FILE):
        try:
            with open(DNS_CACHE_FILE, 'r') as f:
                dns_cache = json.load(f)
        except Exception as e:
            print(f"Error loading DNS cache: {e}")
            dns_cache = {}

def save_dns_cache():
    """Save DNS hostname cache to file"""
    try:
        with open(DNS_CACHE_FILE, 'w') as f:
            json.dump(dns_cache, f, indent=2)
    except Exception as e:
        print(f"Error saving DNS cache: {e}")

def get_cached_hostname(ip_address: str) -> Optional[str]:
    """Return cached hostname without performing DNS lookup"""
    cached = dns_cache.get(ip_address)
    # Return None if cache has empty string (failed lookup) or None
    return cached if cached else None

def get_hostname_with_cache(ip_address: str, force_lookup: bool = False) -> Optional[str]:
    """Get hostname from cache or perform DNS lookup if not cached or forced"""
    try:
        # Check cache first
        if not force_lookup and ip_address in dns_cache:
            cached = dns_cache[ip_address]
            return cached if cached else None
        
        # Only perform DNS lookup if forced (for new/changed hosts)
        if force_lookup:
            try:
                print(f"Performing DNS lookup for {ip_address}...")
                hostname = reverse_dns_lookup(ip_address, timeout=1)
                # Cache the result (even if None, to avoid repeated failed lookups)
                dns_cache[ip_address] = hostname if hostname else ""
                try:
                    save_dns_cache()
                except Exception as e:
                    print(f"[ERROR] Error saving DNS cache: {e}")
                if hostname:
                    print(f"DNS lookup successful: {ip_address} -> {hostname}")
                else:
                    print(f"DNS lookup failed for {ip_address} (no hostname)")
                return hostname
            except Exception as e:
                print(f"[ERROR] Error in DNS lookup for {ip_address}: {e}")
                # Cache failure to avoid repeated attempts
                dns_cache[ip_address] = ""
                try:
                    save_dns_cache()
                except:
                    pass
                return None
        
        return None
    except Exception as e:
        print(f"Error in get_hostname_with_cache for {ip_address}: {e}")
        return None

# Load caches on startup
load_os_cache()
load_dns_cache()

@app.on_event("startup")
async def startup_event():
    """Log startup information"""
    print("=" * 60)
    print("Arpwatch API Server Starting")
    print("=" * 60)
    print(f"OS Fingerprinting: {'Enabled' if ENABLE_OS_FINGERPRINTING else 'Disabled'}")
    print(f"Port Scanning: {'Enabled' if ENABLE_PORT_SCANNING else 'Disabled'}")
    print(f"ARP Data File: {ARP_DAT_FILE}")
    print(f"OS Cache: {len(os_cache)} entries loaded")
    print(f"DNS Cache: {len(dns_cache)} entries loaded")
    print("=" * 60)
    print("Server ready and listening on port 8000")
    print("=" * 60)

class ARPEntry(BaseModel):
    ip_address: str
    mac_address: str
    hostname: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    age: Optional[str] = None  # Human-readable age (e.g., "2h 30m")
    os_fingerprint: Optional[str] = None  # OS detected by nmap
    status: str  # "active", "new", "changed", "flip-flop"

class ARPEvent(BaseModel):
    timestamp: str
    event_type: str
    ip_address: str
    mac_address: str
    hostname: Optional[str] = None
    message: str

class Stats(BaseModel):
    total_hosts: int
    active_hosts: int
    new_hosts: int
    changed_hosts: int
    os_distribution: Dict[str, int]  # OS type -> count

class PortScanResult(BaseModel):
    ip_address: str
    ports: List[Dict[str, Any]]  # List of {port, state, service, version}
    scan_time: str
    status: str  # "success", "error", "timeout"
    error: Optional[str] = None

class FingerprintUpdate(BaseModel):
    os_fingerprint: str

def reverse_dns_lookup(ip_address, timeout=2):
    """Perform reverse DNS lookup for an IP address with timeout"""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, OSError, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)

def os_fingerprint(ip_address: str, force: bool = False) -> Optional[str]:
    """Perform OS fingerprinting using nmap (cached, with optional retries)"""
    # Check if OS fingerprinting is enabled
    if not ENABLE_OS_FINGERPRINTING:
        return None
    
    # Check cache first
    if not force and ip_address in os_cache:
        cached_entry = os_cache[ip_address]
        os_result = cached_entry.get("os")
        timestamp_str = cached_entry.get("timestamp")
        
        # If we have a result, return it
        if os_result:
            return os_result
        
        # If result is None/Unknown, check if we should retry
        if timestamp_str:
            try:
                cached_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                now = datetime.now()
                hours_since = (now - cached_time).total_seconds() / 3600
                
                # If retries are disabled (default) or we haven't reached the window, skip
                if OS_FINGERPRINT_RETRY_HOURS <= 0 or hours_since < OS_FINGERPRINT_RETRY_HOURS:
                    return None  # Return cached unknown without blocking the request
            except Exception:
                return None  # If timestamp parsing fails, avoid retrying in request path
    
    # No cache or should retry - perform scan
    
    # Run nmap OS detection (aggressive, no ping, timeout)
    # Note: This may take up to 30 seconds per IP on first scan
    try:
        # Use -Pn to skip host discovery, -O for OS detection, --osscan-limit for faster scan
        # --max-retries 1 and -T4 for speed, --privileged equivalent via capabilities
        result = subprocess.run(
            ["nmap", "-Pn", "-O", "--osscan-limit", "--max-retries", "1", "-T4", ip_address],
            capture_output=True,
            timeout=OS_FINGERPRINT_TIMEOUT,  # Tunable, defaults to 10s to keep API responsive
            text=True
        )
        
        output = result.stdout + result.stderr
        
        # Parse nmap output for OS detection
        os_match = re.search(r'OS details?: (.+?)(?:\n|$)', output, re.IGNORECASE)
        if os_match:
            os_info = os_match.group(1).strip()
            # Clean up OS string
            os_info = re.sub(r'\s+', ' ', os_info)
            # Store in cache
            os_cache[ip_address] = {
                "os": os_info,
                "timestamp": datetime.now().isoformat()
            }
            save_os_cache()
            return os_info
        
        # If no OS detected, cache as None (Unknown) with timestamp
        os_cache[ip_address] = {
            "os": None,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown"
        }
        save_os_cache()
        return None  # Return None to indicate "Unknown"
        
    except subprocess.TimeoutExpired:
        # Cache failure with timestamp for retry after 24 hours
        os_cache[ip_address] = {
            "os": None,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown",
            "error": "timeout"
        }
        save_os_cache()
        return None  # Return None to show "Unknown"
    except Exception as e:
        print(f"Error running nmap for {ip_address}: {e}")
        # Cache failure with timestamp for retry after 24 hours
        os_cache[ip_address] = {
            "os": None,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown",
            "error": str(e)
        }
        save_os_cache()
        return None  # Return None to show "Unknown"

def rescan_os_fingerprints():
    """Trigger OS fingerprinting for all known hosts in the background."""
    global rescan_in_progress
    if rescan_in_progress:
        return
    rescan_in_progress = True
    try:
        entries = parse_arp_dat()
        for ip in entries.keys():
            if should_exclude_ip(ip):
                continue
            os_fingerprint(ip, force=True)
    finally:
        rescan_in_progress = False

def format_age(last_seen_timestamp: Optional[str]) -> Optional[str]:
    """Format age from timestamp to human-readable string"""
    if not last_seen_timestamp:
        return None
    
    try:
        # Try to parse various timestamp formats
        # Arpwatch log format: "Nov 18 10:30:45" or ISO format
        if 'T' in last_seen_timestamp or '-' in last_seen_timestamp:
            # ISO format
            dt = datetime.fromisoformat(last_seen_timestamp.replace('Z', '+00:00'))
        else:
            # Try arpwatch format: "Nov 18 10:30:45"
            try:
                dt = datetime.strptime(last_seen_timestamp, "%b %d %H:%M:%S")
                # Assume current year
                dt = dt.replace(year=datetime.now().year)
            except:
                return None
        
        now = datetime.now()
        delta = now - dt
        
        if delta.total_seconds() < 60:
            return f"{int(delta.total_seconds())}s"
        elif delta.total_seconds() < 3600:
            minutes = int(delta.total_seconds() / 60)
            return f"{minutes}m"
        elif delta.total_seconds() < 86400:
            hours = int(delta.total_seconds() / 3600)
            minutes = int((delta.total_seconds() % 3600) / 60)
            if minutes > 0:
                return f"{hours}h {minutes}m"
            return f"{hours}h"
        else:
            days = int(delta.total_seconds() / 86400)
            hours = int((delta.total_seconds() % 86400) / 3600)
            if hours > 0:
                return f"{days}d {hours}h"
            return f"{days}d"
    except Exception as e:
        print(f"Error formatting age: {e}")
        return None

def get_inactivity_status(last_seen_timestamp: Optional[str]) -> str:
    """Determine status based on inactivity time (color coding)"""
    if not last_seen_timestamp:
        return "active-green"  # Default to green if no timestamp
    
    try:
        # Parse timestamp
        if 'T' in last_seen_timestamp or '-' in last_seen_timestamp:
            dt = datetime.fromisoformat(last_seen_timestamp.replace('Z', '+00:00'))
        else:
            try:
                dt = datetime.strptime(last_seen_timestamp, "%b %d %H:%M:%S")
                dt = dt.replace(year=datetime.now().year)
            except:
                return "active-green"
        
        now = datetime.now()
        delta = now - dt
        
        hours_inactive = delta.total_seconds() / 3600
        
        if hours_inactive >= 24:
            return "active-red"  # Red: older than 24 hours
        elif hours_inactive >= 6:
            return "active-orange"  # Orange: 6-24 hours
        else:
            return "active-green"  # Green: less than 6 hours
    except:
        return "active-green"

def scan_ports(ip_address: str, ports: Optional[List[int]] = None) -> PortScanResult:
    """Scan common ports on a host using nmap"""
    # Check if port scanning is enabled
    if not ENABLE_PORT_SCANNING:
        return PortScanResult(
            ip_address=ip_address,
            ports=[],
            scan_time=datetime.now().isoformat(),
            status="error",
            error="Port scanning is disabled"
        )
    
    # Check if IP is in excluded range
    if should_exclude_ip(ip_address):
        return PortScanResult(
            ip_address=ip_address,
            ports=[],
            scan_time=datetime.now().isoformat(),
            status="error",
            error="IP address is in excluded range"
        )
    
    # Use default ports if not specified
    if ports is None:
        ports = DEFAULT_SCAN_PORTS
    
    ports_str = ','.join(map(str, ports))
    
    try:
        # Run nmap port scan: -Pn (no ping), -sV (version detection), -T4 (aggressive timing)
        result = subprocess.run(
            ["nmap", "-Pn", "-sV", "-T4", "--max-retries", "1", "-p", ports_str, ip_address],
            capture_output=True,
            timeout=20,  # 20 second timeout
            text=True
        )
        
        output = result.stdout + result.stderr
        
        # Parse nmap output for open ports
        ports_found = []
        
        # Look for port scan results in nmap output
        # Format: "PORT   STATE SERVICE VERSION"
        lines = output.split('\n')
        in_port_section = False
        
        for line in lines:
            line = line.strip()
            if 'PORT' in line and 'STATE' in line and 'SERVICE' in line:
                in_port_section = True
                continue
            
            if in_port_section:
                if not line or line.startswith('Nmap scan report') or line.startswith('MAC Address'):
                    if ports_found:
                        break
                    continue
                
                # Parse port line: "21/tcp   open   ftp     vsftpd 3.0.3"
                parts = line.split()
                if len(parts) >= 3:
                    port_part = parts[0]
                    state = parts[1] if len(parts) > 1 else "unknown"
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = ' '.join(parts[3:]) if len(parts) > 3 else None
                    
                    # Extract port number
                    port_match = re.search(r'(\d+)/', port_part)
                    if port_match:
                        port_num = int(port_match.group(1))
                        ports_found.append({
                            "port": port_num,
                            "state": state,
                            "service": service,
                            "version": version or ""
                        })
        
        return PortScanResult(
            ip_address=ip_address,
            ports=ports_found,
            scan_time=datetime.now().isoformat(),
            status="success"
        )
        
    except subprocess.TimeoutExpired:
        return PortScanResult(
            ip_address=ip_address,
            ports=[],
            scan_time=datetime.now().isoformat(),
            status="timeout",
            error="Scan timed out after 20 seconds"
        )
    except Exception as e:
        return PortScanResult(
            ip_address=ip_address,
            ports=[],
            scan_time=datetime.now().isoformat(),
            status="error",
            error=str(e)
        )

def is_ip_address(text):
    """Check if text is an IP address"""
    parts = text.split('.')
    if len(parts) == 4:
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    return False

def is_mac_address(text):
    """Check if text is a MAC address"""
    # Remove colons and dashes
    cleaned = text.replace(':', '').replace('-', '')
    # Check if it's 12 hex characters
    if len(cleaned) == 12:
        try:
            int(cleaned, 16)
            return True
        except ValueError:
            return False
    return False

def parse_arp_dat():
    """Parse arpwatch database file (arp.dat)"""
    entries = {}
    
    if not os.path.exists(ARP_DAT_FILE):
        return entries
    
    # Check file size to prevent reading very large files
    try:
        file_size = os.path.getsize(ARP_DAT_FILE)
        if file_size > 5 * 1024 * 1024:  # 5MB limit
            print(f"[WARNING] arp.dat file is very large ({file_size / 1024 / 1024:.2f} MB), may cause performance issues")
        else:
            print(f"Reading arp.dat file ({file_size / 1024:.2f} KB)")
    except Exception as e:
        print(f"[ERROR] Error checking arp.dat file size: {e}")
    
    # Get file modification time as fallback for age calculation
    try:
        file_mtime = os.path.getmtime(ARP_DAT_FILE)
        file_timestamp = datetime.fromtimestamp(file_mtime).strftime("%b %d %H:%M:%S")
    except:
        file_timestamp = None
    
    try:
        with open(ARP_DAT_FILE, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse arp.dat format: MAC IP [hostname] [timestamp]
                # Arpwatch stores MAC first, then IP
                parts = line.split()
                if len(parts) >= 2:
                    first = parts[0]
                    second = parts[1]
                    
                    # Determine which is MAC and which is IP by checking format
                    if is_mac_address(first):
                        mac = first
                        ip = second
                    elif is_mac_address(second):
                        ip = first
                        mac = second
                    else:
                        # If neither is clearly a MAC, assume first is MAC (arpwatch standard)
                        mac = first
                        ip = second
                    
                    # Clean up IP address (remove any colons that might have been inserted)
                    if ':' in ip and not ip.count(':') == 5:  # Not IPv6
                        ip = ip.replace(':', '.')
                    
                    # Validate IP format
                    if not is_ip_address(ip):
                        # Try to fix malformed IPs like "17:2.:28:.1:84:.4:"
                        ip_cleaned = ip.replace(':', '').replace('.', '')
                        if len(ip_cleaned) >= 7:  # At least 7 digits for an IP
                            # Try to reconstruct: take first 3, next 2-3, next 2-3, rest
                            # This is a heuristic fix
                            ip = ip.replace(':', '.').replace('..', '.')
                            # Remove trailing dots/colons
                            ip = ip.rstrip('.:')
                    
                    # Skip if IP is still invalid
                    if not is_ip_address(ip):
                        continue
                    
                    # Get hostname from file or cache (don't do DNS lookup here to avoid noise)
                    hostname = None
                    if len(parts) > 2:
                        # Check if third part is a hostname (not a timestamp)
                        potential_hostname = parts[2]
                        if not re.match(r'^\d+$', potential_hostname):  # Not just digits
                            hostname = potential_hostname
                    
                    # If no hostname in file, check cache (but don't do DNS lookup here)
                    if not hostname:
                        cached_hostname = get_cached_hostname(ip)
                        if cached_hostname:
                            hostname = cached_hostname
                        # If cache has empty string, it means we tried before and failed - skip
                        elif ip in dns_cache and dns_cache[ip] == "":
                            hostname = None  # Known to have no hostname
                        # Otherwise, leave as None - DNS lookup will happen only for new/changed hosts
                    
                    # Try to extract timestamp from line (arpwatch sometimes includes it)
                    line_timestamp = None
                    for part in parts:
                        # Check if part looks like a timestamp (e.g., "Nov 18 10:30:45" or Unix timestamp)
                        if re.match(r'^\d{10,}$', part):  # Unix timestamp
                            try:
                                line_timestamp = datetime.fromtimestamp(int(part)).strftime("%b %d %H:%M:%S")
                            except:
                                pass
                        elif re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}$', part):  # Date format
                            line_timestamp = part
                    
                    entries[ip] = {
                        "ip_address": ip,
                        "mac_address": mac,
                        "hostname": hostname,
                        "status": "active",
                        "file_timestamp": line_timestamp or file_timestamp  # Use line timestamp or file mtime
                    }
    except Exception as e:
        print(f"Error parsing arp.dat: {e}")
    
    return entries

def parse_log_files():
    """Parse arpwatch log files for events"""
    events = []

    # If the log directory is missing or unreadable, bail out gracefully
    if not os.path.exists(ARPWATCH_LOG_DIR):
        print(f"[WARNING] ARP log directory does not exist: {ARPWATCH_LOG_DIR}")
        return events

    print(f"Scanning log directory: {ARPWATCH_LOG_DIR}")
    try:
        log_files = [
            os.path.join(ARPWATCH_LOG_DIR, f)
            for f in os.listdir(ARPWATCH_LOG_DIR)
            if os.path.isfile(os.path.join(ARPWATCH_LOG_DIR, f)) and f.endswith('.log')
        ]
        if log_files:
            print(f"Found {len(log_files)} log file(s) in {ARPWATCH_LOG_DIR}")
        else:
            print(f"No .log files found in {ARPWATCH_LOG_DIR}")
    except Exception as e:
        print(f"[ERROR] Error reading log directory {ARPWATCH_LOG_DIR}: {e}")
        log_files = []
    
    # Also check syslog if available
    syslog_path = "/var/log/syslog"
    if os.path.exists(syslog_path):
        print(f"Also checking syslog: {syslog_path}")
        log_files.append(syslog_path)
    
    for log_file in log_files:
        try:
            # Skip very large files to prevent timeouts (limit to 10MB)
            try:
                file_size = os.path.getsize(log_file)
                if file_size > 10 * 1024 * 1024:  # 10MB
                    print(f"Skipping large log file {log_file} ({file_size} bytes)")
                    continue
            except:
                pass
            
            # Read only last 1000 lines to prevent memory issues
            try:
                with open(log_file, 'r', errors='ignore') as f:
                    lines = f.readlines()
                    # Only process last 1000 lines
                    lines = lines[-1000:] if len(lines) > 1000 else lines
                    for line in lines:
                        # Parse arpwatch log entries
                        # Format: timestamp hostname arpwatch: message
                        if 'arpwatch' in line.lower():
                            # Try to extract timestamp, IP, MAC, and event type
                            match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+).*?arpwatch[:\s]+(.*)', line, re.IGNORECASE)
                            if match:
                                timestamp = match.group(1)
                                message = match.group(2)
                                
                                # Extract IP and MAC from message
                                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
                                mac_match = re.search(r'([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})', message, re.IGNORECASE)
                                
                                event_type = "info"
                                if "new station" in message.lower():
                                    event_type = "new"
                                elif "changed ethernet" in message.lower():
                                    event_type = "changed"
                                elif "flip flop" in message.lower():
                                    event_type = "flip-flop"
                                
                                events.append({
                                    "timestamp": timestamp,
                                    "event_type": event_type,
                                    "ip_address": ip_match.group(1) if ip_match else "unknown",
                                    "mac_address": mac_match.group(1) if mac_match else "unknown",
                                    "message": message
                                })
            except Exception as e:
                print(f"Error reading log file {log_file}: {e}")
                continue
        except Exception as e:
            print(f"Error parsing log file {log_file}: {e}")
            continue
    
    # Sort by timestamp (most recent first)
    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    if events:
        print(f"✓ Parsed {len(events)} events from log files")
        # Log summary of event types
        event_types = {}
        for event in events[:20]:  # Check first 20 events
            event_type = event.get("event_type", "unknown")
            event_types[event_type] = event_types.get(event_type, 0) + 1
        if event_types:
            type_summary = ", ".join([f"{k}: {v}" for k, v in event_types.items()])
            print(f"  Recent event types: {type_summary}")
    else:
        print("  No events found in log files")
    return events[:100]  # Return last 100 events

def get_last_seen_timestamps():
    """Get last seen timestamp for each IP from log files"""
    last_seen = {}
    events = parse_log_files()
    
    for event in events:
        ip = event.get("ip_address")
        timestamp = event.get("timestamp")
        if ip and ip != "unknown" and timestamp:
            # Keep the most recent timestamp for each IP
            if ip not in last_seen or timestamp > last_seen[ip]:
                last_seen[ip] = timestamp
    
    return last_seen

@app.get("/")
async def root():
    return {
        "message": "Arpwatch API", 
        "version": "0.2.6",
        "features": {
            "os_fingerprinting": ENABLE_OS_FINGERPRINTING,
            "port_scanning": ENABLE_PORT_SCANNING,
            "scan_ports": DEFAULT_SCAN_PORTS
        }
    }

@app.get("/api/hosts", response_model=List[ARPEntry])
def get_hosts():
    """Get all ARP entries with OS fingerprinting and age"""
    try:
        entries = parse_arp_dat()
    except Exception as e:
        print(f"Error parsing arp.dat in get_hosts: {e}")
        entries = {}
    
    try:
        last_seen_map = get_last_seen_timestamps()
    except Exception as e:
        print(f"Error getting last seen timestamps: {e}")
        last_seen_map = {}
    
    # Get recent events to identify new/changed hosts that need DNS lookup
    try:
        recent_events = parse_log_files()
        new_or_changed_ips = set()
        for event in recent_events[:50]:  # Check last 50 events
            event_type = event.get("event_type", "")
            if event_type in ["new", "changed"]:
                ip = event.get("ip_address")
                if ip and ip != "unknown":
                    new_or_changed_ips.add(ip)
        if new_or_changed_ips:
            print(f"Found {len(new_or_changed_ips)} new/changed hosts requiring DNS lookup")
    except Exception as e:
        print(f"[ERROR] Error parsing log files in get_hosts: {e}")
        new_or_changed_ips = set()
    
    result = []
    for ip, entry in entries.items():
        try:
            # Skip excluded IP ranges (e.g., VPN ranges)
            if should_exclude_ip(ip):
                continue
            
            # Get hostname - use cached or perform DNS lookup only for new/changed hosts
            hostname = entry.get("hostname")
            if not hostname and ip in new_or_changed_ips:
                try:
                    # Only do DNS lookup for new/changed hosts that aren't in cache
                    hostname = get_hostname_with_cache(ip, force_lookup=True)
                    if hostname:
                        print(f"DNS lookup for {ip}: {hostname}")
                    else:
                        print(f"DNS lookup for {ip}: no hostname found")
                except Exception as e:
                    print(f"[ERROR] Error doing DNS lookup for {ip}: {e}")
                    hostname = None
            
            # Get last seen timestamp - prefer log events, fallback to file timestamp
            last_seen = last_seen_map.get(ip)
            if not last_seen:
                # Use timestamp from arp.dat file (file modification time or line timestamp)
                last_seen = entry.get("file_timestamp")
            
            # Calculate age
            try:
                age = format_age(last_seen) if last_seen else None
            except Exception as e:
                print(f"Error formatting age for {ip}: {e}")
                age = None
            
            # Get OS fingerprint from cache only (don't trigger new scans to avoid timeouts)
            try:
                os_info = get_cached_os(ip)
            except Exception as e:
                print(f"Error getting cached OS for {ip}: {e}")
                os_info = None
            
            # Determine status based on inactivity
            try:
                status = get_inactivity_status(last_seen) if last_seen else entry.get("status", "active")
            except Exception as e:
                print(f"Error getting status for {ip}: {e}")
                status = "active"
            
            result.append(ARPEntry(
                ip_address=entry["ip_address"],
                mac_address=entry["mac_address"],
                hostname=hostname,
                first_seen=None,  # Could be extracted from logs if needed
                last_seen=last_seen,
                age=age,
                os_fingerprint=os_info,
                status=status
            ))
        except Exception as e:
            print(f"[ERROR] Error processing entry for {ip}: {e}")
            continue
    
    print(f"✓ Returning {len(result)} host entries")
    print("=" * 60)
    return result

@app.get("/api/hosts/{ip_address}", response_model=ARPEntry)
def get_host(ip_address: str):
    """Get specific ARP entry by IP"""
    entries = parse_arp_dat()
    if ip_address not in entries:
        raise HTTPException(status_code=404, detail="Host not found")
    return entries[ip_address]

@app.get("/api/events", response_model=List[ARPEvent])
def get_events(limit: int = 100):
    """Get recent ARP events"""
    try:
        events = parse_log_files()
        return events[:limit]
    except Exception as e:
        print(f"Error getting events: {e}")
        return []

@app.get("/api/stats", response_model=Stats)
def get_stats():
    """Get statistics about ARP entries including OS distribution"""
    try:
        entries = parse_arp_dat()
    except Exception as e:
        print(f"Error parsing arp.dat in get_stats: {e}")
        entries = {}
    
    try:
        events = parse_log_files()
    except Exception as e:
        print(f"Error parsing log files in get_stats: {e}")
        events = []
    
    try:
        last_seen_map = get_last_seen_timestamps()
    except Exception as e:
        print(f"Error getting last seen timestamps in get_stats: {e}")
        last_seen_map = {}
    
    active_hosts = len(entries)
    new_hosts = len([e for e in events if e.get("event_type") == "new"])
    changed_hosts = len([e for e in events if e.get("event_type") == "changed"])
    
    # Calculate OS distribution
    os_distribution = {}
    try:
        for ip in entries.keys():
            try:
                # Get OS from cache (don't trigger new scans)
                if ip in os_cache:
                    os_info = os_cache[ip].get("os")
                    if os_info:
                        # Simplify OS name (e.g., "Linux 3.x" -> "Linux")
                        os_simple = os_info.split()[0] if os_info else "Unknown"
                        os_distribution[os_simple] = os_distribution.get(os_simple, 0) + 1
                else:
                    os_distribution["Unknown"] = os_distribution.get("Unknown", 0) + 1
            except Exception as e:
                print(f"Error processing OS for {ip} in stats: {e}")
                os_distribution["Unknown"] = os_distribution.get("Unknown", 0) + 1
    except Exception as e:
        print(f"Error calculating OS distribution: {e}")
    
    return Stats(
        total_hosts=active_hosts,
        active_hosts=active_hosts,
        new_hosts=new_hosts,
        changed_hosts=changed_hosts,
        os_distribution=os_distribution
    )

@app.get("/api/search")
def search_hosts(q: str):
    """Search hosts by IP, MAC, or hostname"""
    entries = parse_arp_dat()
    q_lower = q.lower()
    
    results = []
    for entry in entries.values():
        if (q_lower in entry["ip_address"].lower() or
            q_lower in entry["mac_address"].lower() or
            (entry.get("hostname") and q_lower in entry["hostname"].lower())):
            results.append(entry)
    
    return results

@app.get("/api/scan/{ip_address}", response_model=PortScanResult)
def scan_host_ports(ip_address: str):
    """Scan configured ports on a host"""
    # Check if port scanning is enabled
    if not ENABLE_PORT_SCANNING:
        raise HTTPException(status_code=403, detail="Port scanning is disabled")
    
    # Validate IP address
    if not is_ip_address(ip_address):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    
    # Perform port scan
    result = scan_ports(ip_address)
    return result

@app.get("/api/fingerprints/unknown", response_model=List[ARPEntry])
def get_unknown_fingerprints():
    """Return hosts whose OS fingerprint is unknown (cached-only, no scans)."""
    entries = parse_arp_dat()
    last_seen_map = get_last_seen_timestamps()
    result = []
    for ip, entry in entries.items():
        if should_exclude_ip(ip):
            continue
        cached_os = get_cached_os(ip)
        if cached_os:
            continue  # already known
        last_seen = last_seen_map.get(ip) or entry.get("file_timestamp")
        age = format_age(last_seen) if last_seen else None
        status = get_inactivity_status(last_seen) if last_seen else entry.get("status", "active")
        result.append(ARPEntry(
            ip_address=entry["ip_address"],
            mac_address=entry["mac_address"],
            hostname=entry.get("hostname"),
            first_seen=None,
            last_seen=last_seen,
            age=age,
            os_fingerprint=None,
            status=status
        ))
    return result

@app.post("/api/fingerprints/{ip_address}", response_model=ARPEntry)
def set_manual_fingerprint(ip_address: str, body: FingerprintUpdate):
    """Manually set OS fingerprint for a host (persists in cache)."""
    entries = parse_arp_dat()
    if ip_address not in entries:
        raise HTTPException(status_code=404, detail="Host not found")
    os_value = body.os_fingerprint.strip()
    if not os_value:
        raise HTTPException(status_code=400, detail="OS fingerprint cannot be empty")
    os_cache[ip_address] = {
        "os": os_value,
        "timestamp": datetime.now().isoformat(),
        "manual": True
    }
    save_os_cache()
    entry = entries[ip_address]
    last_seen_map = get_last_seen_timestamps()
    last_seen = last_seen_map.get(ip_address) or entry.get("file_timestamp")
    age = format_age(last_seen) if last_seen else None
    status = get_inactivity_status(last_seen) if last_seen else entry.get("status", "active")
    return ARPEntry(
        ip_address=entry["ip_address"],
        mac_address=entry["mac_address"],
        hostname=entry.get("hostname"),
        first_seen=None,
        last_seen=last_seen,
        age=age,
        os_fingerprint=os_value,
        status=status
    )

@app.post("/api/os-fingerprint/rescan")
def trigger_os_rescan():
    """Start a background OS fingerprint rescan for all known hosts."""
    global rescan_in_progress
    if rescan_in_progress:
        return {"status": "in_progress"}
    
    thread = threading.Thread(target=rescan_os_fingerprints, daemon=True)
    thread.start()
    return {"status": "started"}

@app.get("/api/os-fingerprint/status")
def os_rescan_status():
    """Return status of the OS fingerprint background rescan."""
    return {"status": "in_progress" if rescan_in_progress else "idle"}

@app.get("/api/config")
def get_config():
    """Get API configuration and feature flags"""
    try:
        return {
            "os_fingerprinting_enabled": ENABLE_OS_FINGERPRINTING,
            "port_scanning_enabled": ENABLE_PORT_SCANNING,
            "scan_ports": DEFAULT_SCAN_PORTS,
            "exclude_ip_ranges": EXCLUDE_IP_RANGES
        }
    except Exception as e:
        print(f"Error getting config: {e}")
        # Return safe defaults
        return {
            "os_fingerprinting_enabled": True,
            "port_scanning_enabled": True,
            "scan_ports": [21, 22, 80, 443, 445],
            "exclude_ip_ranges": []
        }

@app.get("/api/logs")
def get_logs():
    """Get last 100 lines of backend application logs"""
    try:
        # Get logs from in-memory buffer
        log_lines = list(LOG_BUFFER)[-100:]  # Get last 100 entries
        
        if log_lines:
            return {"logs": log_lines}
        
        # If buffer is empty, add a message and try to get docker logs as fallback
        log_lines = [
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Log buffer is empty.",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Attempting to fetch docker logs..."
        ]
        
        try:
            import subprocess
            result = subprocess.run(
                ["docker", "logs", "--tail", "20", "arpwatch-backend", "2>&1"],
                capture_output=True,
                text=True,
                timeout=3
            )
            if result.stdout:
                docker_logs = result.stdout.strip().split('\n')
                if docker_logs:
                    log_lines.extend(docker_logs[-18:])  # Add docker logs, keeping first 2 messages
                    return {"logs": log_lines}
        except Exception as e:
            log_lines.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error fetching docker logs: {str(e)}")
        
        # Return message if no logs available
        log_lines.extend([
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] No logs available yet.",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Logs will appear here as the application processes requests.",
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Total log buffer size: {len(LOG_BUFFER)} entries"
        ])
        return {"logs": log_lines}
    except Exception as e:
        return {
            "logs": [
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] Error retrieving logs: {str(e)}",
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Check container logs manually: docker logs arpwatch-backend"
            ]
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

