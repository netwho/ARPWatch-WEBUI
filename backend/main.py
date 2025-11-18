from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import os
import re
import json
import socket
from pathlib import Path

app = FastAPI(title="Arpwatch API", version="0.1.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
ARPWATCH_DATA_DIR = os.getenv("ARPWATCH_DATA_DIR", "/var/lib/arpwatch")
ARPWATCH_LOG_DIR = os.getenv("ARPWATCH_LOG_DIR", "/var/log/arpwatch")
ARP_DAT_FILE = os.path.join(ARPWATCH_DATA_DIR, "arp.dat")

class ARPEntry(BaseModel):
    ip_address: str
    mac_address: str
    hostname: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
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

def reverse_dns_lookup(ip_address):
    """Perform reverse DNS lookup for an IP address"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None

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
    
    try:
        with open(ARP_DAT_FILE, 'r') as f:
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
                    
                    # Get hostname from file or reverse DNS
                    hostname = None
                    if len(parts) > 2:
                        # Check if third part is a hostname (not a timestamp)
                        potential_hostname = parts[2]
                        if not re.match(r'^\d+$', potential_hostname):  # Not just digits
                            hostname = potential_hostname
                    
                    # If no hostname, try reverse DNS (with timeout to avoid hanging)
                    if not hostname:
                        try:
                            socket.setdefaulttimeout(2)  # 2 second timeout
                            hostname = reverse_dns_lookup(ip)
                        except:
                            pass
                    
                    entries[ip] = {
                        "ip_address": ip,
                        "mac_address": mac,
                        "hostname": hostname,
                        "status": "active"
                    }
    except Exception as e:
        print(f"Error parsing arp.dat: {e}")
    
    return entries

def parse_log_files():
    """Parse arpwatch log files for events"""
    events = []
    
    log_files = [
        os.path.join(ARPWATCH_LOG_DIR, f) 
        for f in os.listdir(ARPWATCH_LOG_DIR) 
        if os.path.isfile(os.path.join(ARPWATCH_LOG_DIR, f)) and f.endswith('.log')
    ]
    
    # Also check syslog if available
    syslog_path = "/var/log/syslog"
    if os.path.exists(syslog_path):
        log_files.append(syslog_path)
    
    for log_file in log_files:
        try:
            with open(log_file, 'r') as f:
                for line in f:
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
            print(f"Error parsing log file {log_file}: {e}")
    
    # Sort by timestamp (most recent first)
    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return events[:100]  # Return last 100 events

@app.get("/")
async def root():
    return {"message": "Arpwatch API", "version": "0.1.0"}

@app.get("/api/hosts", response_model=List[ARPEntry])
async def get_hosts():
    """Get all ARP entries"""
    entries = parse_arp_dat()
    return list(entries.values())

@app.get("/api/hosts/{ip_address}", response_model=ARPEntry)
async def get_host(ip_address: str):
    """Get specific ARP entry by IP"""
    entries = parse_arp_dat()
    if ip_address not in entries:
        raise HTTPException(status_code=404, detail="Host not found")
    return entries[ip_address]

@app.get("/api/events", response_model=List[ARPEvent])
async def get_events(limit: int = 100):
    """Get recent ARP events"""
    events = parse_log_files()
    return events[:limit]

@app.get("/api/stats", response_model=Stats)
async def get_stats():
    """Get statistics about ARP entries"""
    entries = parse_arp_dat()
    events = parse_log_files()
    
    active_hosts = len(entries)
    new_hosts = len([e for e in events if e.get("event_type") == "new"])
    changed_hosts = len([e for e in events if e.get("event_type") == "changed"])
    
    return Stats(
        total_hosts=active_hosts,
        active_hosts=active_hosts,
        new_hosts=new_hosts,
        changed_hosts=changed_hosts
    )

@app.get("/api/search")
async def search_hosts(q: str):
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

@app.get("/api/debug")
async def debug_info():
    """Debug endpoint to check arpwatch data files"""
    debug_info = {
        "arp_dat_exists": os.path.exists(ARP_DAT_FILE),
        "arp_dat_path": ARP_DAT_FILE,
        "data_dir_exists": os.path.exists(ARPWATCH_DATA_DIR),
        "data_dir": ARPWATCH_DATA_DIR,
        "log_dir_exists": os.path.exists(ARPWATCH_LOG_DIR),
        "log_dir": ARPWATCH_LOG_DIR,
    }
    
    if os.path.exists(ARP_DAT_FILE):
        try:
            stat = os.stat(ARP_DAT_FILE)
            debug_info["arp_dat_size"] = stat.st_size
            debug_info["arp_dat_modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            
            # Read first few lines
            with open(ARP_DAT_FILE, 'r') as f:
                lines = f.readlines()[:10]
                debug_info["arp_dat_preview"] = [line.strip() for line in lines]
        except Exception as e:
            debug_info["arp_dat_error"] = str(e)
    
    if os.path.exists(ARPWATCH_DATA_DIR):
        try:
            files = os.listdir(ARPWATCH_DATA_DIR)
            debug_info["data_dir_files"] = files
        except Exception as e:
            debug_info["data_dir_error"] = str(e)
    
    if os.path.exists(ARPWATCH_LOG_DIR):
        try:
            files = os.listdir(ARPWATCH_LOG_DIR)
            debug_info["log_dir_files"] = files
        except Exception as e:
            debug_info["log_dir_error"] = str(e)
    
    # Try to parse and show count
    entries = parse_arp_dat()
    debug_info["parsed_entries_count"] = len(entries)
    
    return debug_info

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

