# Contributing to Arpwatch Web UI

Thank you for your interest in contributing to Arpwatch Web UI! This document provides guidelines and instructions for contributing.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Docker version, etc.)
- Relevant logs or error messages

### Suggesting Features

Feature suggestions are welcome! Please open an issue describing:
- The feature you'd like to see
- Why it would be useful
- How it might work

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test your changes thoroughly
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

- **Python**: Follow PEP 8 style guidelines
- **JavaScript/React**: Use ESLint configuration
- **Docker**: Follow best practices for multi-stage builds
- **Documentation**: Update README.md and relevant docs

### Testing

Before submitting a PR:
- Test locally with `docker compose up --build`
- Verify the web UI works correctly
- Check that API endpoints respond properly
- Ensure no console errors

## Development Setup

1. Clone the repository
2. Install arpwatch on your host (see README.md)
3. Run `docker compose up --build`
4. Access the UI at `http://localhost:8080`

## Questions?

Feel free to open an issue for any questions or concerns.

