# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2025-12-18

### Added
- Backend now mounts host `/var/log/syslog` by default so arpwatch events are visible in the UI counters; documented how to adjust if syslog lives elsewhere or journald-only hosts.

### Changed
- Bumped project version to 0.3.1.

## [0.3.0] - 2025-12-13

### Added
- **Fingerprint Management:**
  - Export functionality for manual fingerprints (MAC/IP mapping) to JSON file
  - Import functionality to merge fingerprint data from JSON files
  - "Show all records" toggle in fingerprints tab to view all fingerprints (not just unknown)
  - Edit/overwrite/delete functionality for existing fingerprints
  - IP Address sorting in fingerprints table
- **Chart Visualization:**
  - Toggle between bar chart and pie chart for OS distribution
  - Chart type preference saved to localStorage
- **DNS Lookup:**
  - "Lookup Hostnames" button to trigger reverse DNS lookups for IPs without hostnames
- **Host Management:**
  - Automatic cleanup of idle hosts (inactive for >7 days) with backup creation
- **UI Improvements:**
  - Improved font contrast for table fields (MAC, Hostname, OS, Age) - brighter colors
  - Dark theme support for port scan results

### Changed
- Auto-refresh disabled by default (can be enabled via toggle)
- Auto-refresh toggle styled as normal text with transparent background
- Rescanning logic now preserves existing fingerprints (manual and auto-detected)
- Rescanning will not overwrite existing fingerprints with "Unknown"

### Fixed
- Added `python-multipart` dependency for file upload support (fixes 502 errors on import)
- Bar chart hover effects removed (no background color change on mouse over)
- Statistics cards hover effects removed for better readability
- Tooltip styling improved with dark gray background

## [0.2.6] - 2025-12-13

### Changed
- Auto-refresh disabled by default (can be enabled via toggle)
- Auto-refresh toggle styled as normal text with transparent background
- Improved UI consistency for theme switching and controls

### Fixed
- Bar chart hover effects removed (no background color change on mouse over)
- Statistics cards hover effects removed for better readability
- Tooltip styling improved with dark gray background

## [0.2.5] - 2025-12-12

- Version bump to v0.2.5.
- Added Fingerprints tab and manual OS fingerprint assignment.
- Added sortable columns and UI tweaks (scan icon alignment, rescan button).

## [0.2.3] - 2025-12-12

- Version bump to v0.2.3.

## [0.2.1] - 2025-11-18

### Changed
- OS fingerprinting now shows "Unknown" instead of "Scanning..." when detection fails
- OS fingerprinting automatically retries once per day for entries marked as "Unknown"
- Improved caching logic to track scan attempts and timestamps

## [0.2.0] - 2025-11-18

### Added
- Port scanning feature with configurable ports (default: 21, 22, 80, 443, 445)
- Configuration options in docker-compose.yml to enable/disable features:
  - `ENABLE_OS_FINGERPRINTING` - Enable/disable OS fingerprinting (default: true)
  - `ENABLE_PORT_SCANNING` - Enable/disable port scanning (default: true)
  - `SCAN_PORTS` - Comma-separated list of ports to scan (default: "21,22,80,443,445")
- API endpoint `/api/config` to retrieve current configuration
- Vertical bar chart for OS distribution
- Horizontal layout for statistics cards

### Changed
- Statistics cards now display horizontally in a row
- OS distribution chart changed to vertical bar chart
- Improved responsive design for mobile devices

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

