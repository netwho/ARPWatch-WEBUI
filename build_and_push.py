#!/usr/bin/env python3
"""
Build and push ARPWatch-WEBUI images to Docker Hub.

Features:
- Prompts for Docker Hub username and password/PAT (stdin, not stored).
- Prompts for version tag (default: 0.4.0) and repository (default: netwho/arpwatch-webui).
- Uses docker buildx (multi-arch) with --push per image.

Usage:
  python3 build_and_push.py

Prereqs:
- docker and docker buildx available
- logged-in network access
"""

import getpass
import subprocess
import sys
from typing import List, Tuple


IMAGES: List[Tuple[str, str, str]] = [
    # (component suffix, dockerfile path, build context)
    ("arpwatch", "arpwatch/Dockerfile", "./arpwatch"),
    ("backend", "backend/Dockerfile", "./backend"),
    ("frontend", "frontend/Dockerfile", "./frontend"),
    ("nginx", "nginx/Dockerfile", "./nginx"),
]


def run(cmd: list, **kwargs):
    """Run a command and raise on failure."""
    print(f"+ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kwargs)


def main():
    print("== Build & Push ARPWatch-WEBUI Images ==")
    username = input("Docker Hub username: ").strip()
    if not username:
        print("Username is required")
        sys.exit(1)

    password = getpass.getpass("Docker Hub password or PAT: ")
    if not password:
        print("Password/PAT is required")
        sys.exit(1)

    version = input("Version tag [0.4.0]: ").strip() or "0.4.0"
    repo = input("Repository [netwho/arpwatch-webui]: ").strip() or "netwho/arpwatch-webui"
    platforms = input("Platforms (comma-separated) [linux/amd64,linux/arm64]: ").strip() or "linux/amd64,linux/arm64"

    try:
        run(["docker", "login", "-u", username, "--password-stdin"], input=password.encode())
    except subprocess.CalledProcessError:
        print("Docker login failed.")
        sys.exit(1)

    for suffix, dockerfile, context in IMAGES:
        tags = [
            f"{repo}:{suffix}-{version}",
            f"{repo}:{suffix}-latest",
        ]
        cmd = [
            "docker", "buildx", "build",
            "--platform", platforms,
            "-f", dockerfile,
            context,
            "--push",
        ]
        for tag in tags:
            cmd.extend(["-t", tag])

        try:
            run(cmd)
        except subprocess.CalledProcessError:
            print(f"Build/push failed for {suffix}. Stopping.")
            sys.exit(1)

    print("All images built and pushed successfully.")


if __name__ == "__main__":
    main()
