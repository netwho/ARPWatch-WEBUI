#!/usr/bin/env python3
"""
Interactive quick setup helper for ARPWatch-WEBUI.

What it does:
- Lists network interfaces (via `ip link show`) and lets you pick one.
- Proposes default ports for nginx (HTTP/HTTPS) and direct UI/API, suggesting
  alternates if defaults look occupied.
- Asks about TLS and reminds where to place certs.
- Creates target folder ~/ARPWatch-WEBUI with nginx/ssl subdir if requested.
- Prints next steps (copy cert/key, docker compose, logs).

What it does NOT do:
- It does not modify your system services or run docker compose automatically.
- It does not generate certificates.
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
    target_dir = home / "ARPWatch-WEBUI"
    print(f"Target directory (will be created if missing): {target_dir}")
    if target_dir.exists():
        print("Note: directory already exists; will not overwrite existing files.")

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

    print("\nCreated/ensured:")
    print(f"  {target_dir}")
    print(f"  {ssl_dir}")

    # Write a brief next-steps note
    note = f"""
Next steps:
1) Copy configuration:
   cp env_example {target_dir}/.env
   Then edit {target_dir}/.env and set:
     ARPWATCH_INTERFACE={iface}
     HTTP_PORT={http_port}
     HTTPS_PORT={https_port}
     FRONTEND_PORT={ui_port}
     BACKEND_PORT={api_port}

2) Certificates (if TLS):
   - Self-signed: ./nginx/generate-self-signed-cert.sh
   - Let’s Encrypt: ./nginx/setup-letsencrypt.sh <domain> <email>
   - Custom: place cert.pem/key.pem in {ssl_dir} and set CUSTOM_CA=true in .env

3) Run:
   cd {target_dir}
   docker compose -f docker-compose.all-in-one.yml up -d
   # or: docker compose up -d

4) Check status/logs:
   docker compose ps
   docker compose logs -f nginx backend frontend arpwatch
"""
    print(note)
    (target_dir / "QUICK_SETUP_NEXT_STEPS.txt").write_text(note)
    print(f"Saved next steps to {target_dir / 'QUICK_SETUP_NEXT_STEPS.txt'}")


if __name__ == "__main__":
    main()
