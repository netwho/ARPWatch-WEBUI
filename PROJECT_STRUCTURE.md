# Project Structure

```
arpwatch-ui/
├── .github/
│   ├── workflows/
│   │   └── docker-build.yml      # GitHub Actions CI/CD
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md         # Bug report template
│       └── feature_request.md    # Feature request template
│
├── backend/
│   ├── Dockerfile                # Backend container definition
│   ├── main.py                   # FastAPI application
│   └── requirements.txt          # Python dependencies
│
├── frontend/
│   ├── Dockerfile                # Frontend multi-stage build
│   ├── nginx.conf                # Nginx configuration
│   ├── package.json              # Node.js dependencies
│   ├── public/
│   │   └── index.html            # HTML template
│   └── src/
│       ├── App.js                # Main React component
│       ├── App.css               # Component styles
│       ├── index.js              # React entry point
│       └── index.css             # Global styles
│
├── .gitignore                    # Git ignore rules
├── CONTRIBUTING.md               # Contribution guidelines
├── docker-compose.yml            # Docker Compose configuration
├── GITHUB_SETUP.md              # GitHub upload instructions
├── HOST_SETUP.md                # Arpwatch host installation guide
├── install-arpwatch.sh          # Automated installation script
├── arpwatch-standalone.sh       # Standalone arpwatch script
├── LICENSE                      # MIT License
├── Makefile                     # Convenience commands
└── README.md                    # Main documentation
```

## Key Files

- **docker-compose.yml**: Orchestrates backend and frontend containers
- **install-arpwatch.sh**: Sets up arpwatch as a systemd service on the host
- **backend/main.py**: FastAPI REST API with reverse DNS lookup
- **frontend/src/App.js**: React web interface
- **HOST_SETUP.md**: Detailed instructions for arpwatch installation

## Note

The `arpwatch/` directory contains an old Dockerfile that is no longer used. Arpwatch now runs natively on the host system for better network access.

