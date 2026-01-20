#!/usr/bin/env python3
"""
Interactive quick setup helper for ARPWatch-WEBUI.

What it does:
- Lists network interfaces (via `ip link show`) and lets you pick one.
- Proposes default ports for nginx (HTTP/HTTPS) and direct UI/API, suggesting
  alternates if defaults look occupied.
- Asks about TLS and can optionally generate a self-signed cert via openssl.
- Creates target folder (default: current working dir) with nginx/ssl subdir.
- Writes a ready-to-use .env with your selections (asks before overwriting).
- Prints next steps (docker compose up, logs).

What it does NOT do:
- It does not run docker compose automatically.
- It does not obtain Let’s Encrypt; only optional self-signed via openssl.
"""

import os
import pathlib
import socket
import subprocess
import sys
from typing import List


DEFAULT_HTTP = 80
DEFAULT_HTTPS = 443
DEFAULT_UI = 8080
DEFAULT_API = 8000


def run(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    except Exception as exc:
        print(f"Warning: failed to run {' '.join(cmd)} ({exc})")
        return ""
    return out


def list_interfaces() -> List[str]:
    out = run(["ip", "link", "show"])
    names = []
    for line in out.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        # Format: "2: ens18: <...>"
        parts = line.split(":")
        if len(parts) >= 2:
            name = parts[1].strip().split("@")[0]
            if name and name != "lo":
                names.append(name)
    return sorted(set(names))


def port_free(port: int, host: str = "0.0.0.0") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def suggest_port(default: int) -> int:
    if port_free(default):
        return default
    for alt in range(default + 1, default + 20):
        if port_free(alt):
            return alt
    return default  # fallback


def prompt_choice(prompt: str, options: List[str], default: str = "") -> str:
    if not options:
        return input(f"{prompt} ").strip() or default
    print(prompt)
    for idx, opt in enumerate(options, 1):
        mark = " (default)" if opt == default and default else ""
        print(f"  [{idx}] {opt}{mark}")
    while True:
        choice = input(f"Select [1-{len(options)}] or enter name (default {default}): ").strip()
        if not choice and default:
            return default
        if choice.isdigit():
            i = int(choice)
            if 1 <= i <= len(options):
                return options[i - 1]
        if choice in options:
            return choice
        print("Invalid choice, try again.")


def yes_no(prompt: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    resp = input(f"{prompt} {suffix}: ").strip().lower()
    if not resp:
        return default
    return resp.startswith("y")


def main():
    print("=== ARPWatch-WEBUI Quick Setup ===")

    home = pathlib.Path.home()
    default_target = home / "ARPWatch-WEBUI"
    user_target = input(f"Target directory [default: {default_target}]: ").strip()
    target_dir = pathlib.Path(user_target) if user_target else default_target
    print(f"Target directory (will be created if missing): {target_dir}")
    if target_dir.exists():
        print("Note: directory already exists; files may be overwritten only if you confirm.")

    # Interfaces
    interfaces = list_interfaces()
    default_iface = interfaces[0] if interfaces else ""
    iface = prompt_choice("Select network interface to monitor:", interfaces, default_iface)
    if not iface:
        print("No interface selected; aborting.")
        sys.exit(1)

    # Ports suggestions
    http_port = suggest_port(DEFAULT_HTTP)
    https_port = suggest_port(DEFAULT_HTTPS)
    ui_port = suggest_port(DEFAULT_UI)
    api_port = suggest_port(DEFAULT_API)

    print("\nPort suggestions (change if you like):")
    http_port = int(input(f"HTTP port for nginx (default {http_port}): ").strip() or http_port)
    https_port = int(input(f"HTTPS port for nginx (default {https_port}): ").strip() or https_port)
    ui_port = int(input(f"Direct frontend port (if exposing without nginx, default {ui_port}): ").strip() or ui_port)
    api_port = int(input(f"Direct backend port (if exposing without nginx, default {api_port}): ").strip() or api_port)

    use_tls = yes_no("Enable TLS via nginx? (self-signed/Let’s Encrypt/custom)", True)

    print("\nSummary:")
    print(f"  Interface: {iface}")
    print(f"  HTTP port: {http_port}")
    print(f"  HTTPS port: {https_port}")
    print(f"  Frontend direct port: {ui_port}")
    print(f"  Backend direct port: {api_port}")
    print(f"  TLS enabled: {'yes' if use_tls else 'no'}")

    if not yes_no("Proceed with directory setup?", True):
        print("Aborted.")
        return

    target_dir.mkdir(parents=True, exist_ok=True)
    ssl_dir = target_dir / "nginx" / "ssl"
    ssl_dir.mkdir(parents=True, exist_ok=True)

    # Write .env with selections
    env_path = target_dir / ".env"
    env_content = f"""# Generated by quick_setup.py
ARPWATCH_INTERFACE={iface}
HTTP_PORT={http_port}
HTTPS_PORT={https_port}
BACKEND_PORT={api_port}
FRONTEND_PORT={ui_port}
ENABLE_OS_FINGERPRINTING=true
ENABLE_PORT_SCANNING=true
SCAN_PORTS=21,22,80,443,445
EXCLUDE_IP_RANGES=169.254.0.0/16
CUSTOM_CA={"false" if not use_tls else "false"}
OS_FINGERPRINT_TIMEOUT=10
OS_FINGERPRINT_RETRY_HOURS=0
"""
    if env_path.exists():
        if yes_no(f"{env_path} exists. Overwrite?", False):
            env_path.write_text(env_content)
            print(f"Wrote {env_path}")
        else:
            print("Skipped writing .env (existing preserved).")
    else:
        env_path.write_text(env_content)
        print(f"Wrote {env_path}")

    # Optional self-signed TLS generation
    if use_tls and yes_no("Generate self-signed cert now with openssl?", False):
        cert_path = ssl_dir / "cert.pem"
        key_path = ssl_dir / "key.pem"
        domain = input("Common Name (CN) for cert [localhost]: ").strip() or "localhost"
        subj = f"/CN={domain}"
        try:
            run([
                "openssl", "req", "-x509", "-nodes", "-days", "825",
                "-newkey", "rsa:2048",
                "-keyout", str(key_path),
                "-out", str(cert_path),
                "-subj", subj
            ])
            print(f"Generated self-signed cert:\n  {cert_path}\n  {key_path}")
        except Exception as exc:
            print(f"Self-signed generation failed: {exc}")

    # Write docker-compose.yml (prebuilt images) into target_dir
    compose_path = target_dir / "docker-compose.yml"
    compose_content = f"""# Generated by quick_setup.py (prebuilt images)
services:
  arpwatch:
    image: netwho/arpwatch-webui:arpwatch-latest
    container_name: arpwatch-daemon
    network_mode: host
    environment:
      - INTERFACE=${{ARPWATCH_INTERFACE:-{iface}}}
    volumes:
      - arpwatch-data:/var/lib/arpwatch:rw
      - arpwatch-logs:/var/log/arpwatch:rw
    cap_add:
      - NET_RAW
      - NET_ADMIN
    privileged: true
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "pgrep", "-x", "arpwatch"]
      interval: 30s
      timeout: 10s
      retries: 3

  backend:
    image: netwho/arpwatch-webui:backend-latest
    container_name: arpwatch-backend
    expose:
      - "8000"
    volumes:
      - arpwatch-data:/var/lib/arpwatch:ro
      - arpwatch-logs:/var/log/arpwatch:ro
      - backend-cache:/tmp:rw
    environment:
      - ARPWATCH_DATA_DIR=/var/lib/arpwatch
      - ARPWATCH_LOG_DIR=/var/log/arpwatch
      - ENABLE_OS_FINGERPRINTING=${{ENABLE_OS_FINGERPRINTING:-true}}
      - ENABLE_PORT_SCANNING=${{ENABLE_PORT_SCANNING:-true}}
      - SCAN_PORTS=${{SCAN_PORTS:-21,22,80,443,445}}
      - EXCLUDE_IP_RANGES=${{EXCLUDE_IP_RANGES:-169.254.0.0/16}}
    cap_add:
      - NET_RAW
      - NET_ADMIN
    depends_on:
      arpwatch:
        condition: service_started
        required: false
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  frontend:
    image: netwho/arpwatch-webui:frontend-latest
    container_name: arpwatch-frontend
    expose:
      - "80"
    depends_on:
      backend:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s

  nginx:
    image: netwho/arpwatch-webui:nginx-latest
    container_name: arpwatch-nginx
    ports:
      - "${{HTTP_PORT:-{http_port}}}:80"
      - "${{HTTPS_PORT:-{https_port}}}:443"
    volumes:
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./nginx/logs:/var/log/nginx
      - certbot-webroot:/var/www/certbot:ro
    environment:
      - CUSTOM_CA=${{CUSTOM_CA:-false}}
    depends_on:
      - frontend
      - backend
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-check-certificate", "--tries=1", "--spider", "http://localhost/"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  arpwatch-data:
    driver: local
    name: arpwatch-data
  arpwatch-logs:
    driver: local
    name: arpwatch-logs
  backend-cache:
    driver: local
    name: backend-cache
  certbot-webroot:
    driver: local
    name: certbot-webroot
"""
    if compose_path.exists():
        if yes_no(f"{compose_path} exists. Overwrite?", False):
            compose_path.write_text(compose_content)
            print(f"Wrote {compose_path}")
        else:
            print("Skipped writing docker-compose.yml (existing preserved).")
    else:
        compose_path.write_text(compose_content)
        print(f"Wrote {compose_path}")

    print("\nCreated/ensured:")
    print(f"  {target_dir}")
    print(f"  {ssl_dir}")
    os.chdir(target_dir)
    print(f"Changed working directory to: {target_dir}")

    # Write a brief next-steps note
    note = f"""
Next steps:
1) Review .env (already written):
   {env_path}
   Adjust if needed (interface/ports/TLS/custom CA).

2) Certificates (if TLS not generated here):
   - Self-signed: ./nginx/generate-self-signed-cert.sh
   - Let’s Encrypt: ./nginx/setup-letsencrypt.sh <domain> <email>
   - Custom: place cert.pem/key.pem in {ssl_dir} and set CUSTOM_CA=true in .env

3) Run (prebuilt images):
   cd {target_dir}
   docker compose up -d

4) Check status/logs:
   docker compose ps
   docker compose logs -f nginx backend frontend arpwatch
"""
    print(note)
    (target_dir / "QUICK_SETUP_NEXT_STEPS.txt").write_text(note)
    print(f"Saved next steps to {target_dir / 'QUICK_SETUP_NEXT_STEPS.txt'}")


if __name__ == "__main__":
    main()
