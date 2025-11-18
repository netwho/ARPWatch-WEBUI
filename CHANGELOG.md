# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-11-18

### Added
- Initial release of Arpwatch Web UI
- Real-time ARP table monitoring dashboard
- Event logging for new stations, changed MAC addresses, and flip-flop events
- Search and filter functionality for hosts
- Statistics dashboard with host counts
- Automatic reverse DNS lookup for hostnames
- RESTful API with FastAPI backend
- Modern React frontend with responsive design
- Docker Compose setup for easy deployment
- Systemd service setup script for Arpwatch host installation
- Comprehensive documentation and setup guides

### Features
- Auto-refreshing dashboard (configurable refresh interval)
- IP and MAC address parsing with format validation
- Hostname resolution via reverse DNS
- Event history tracking
- Search by IP, MAC, or hostname
- Statistics overview (total hosts, active hosts, new hosts, changed hosts)

### Technical Details
- Backend: FastAPI (Python 3.11+)
- Frontend: React 18.2+ with Nginx
- Arpwatch: Runs natively on host (systemd service)
- Data persistence: Host-mounted volumes

