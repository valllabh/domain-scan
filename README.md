# Subdomain Finder

[![CI](https://github.com/domain-scan/domain-scan/workflows/CI/badge.svg)](https://github.com/domain-scan/domain-scan/actions/workflows/ci.yml)
[![Release](https://github.com/domain-scan/domain-scan/workflows/Release/badge.svg)](https://github.com/domain-scan/domain-scan/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/domain-scan/domain-scan)](https://goreportcard.com/report/github.com/domain-scan/domain-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/domain-scan/domain-scan)](https://github.com/domain-scan/domain-scan/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/domain-scan/domain-scan)](https://ghcr.io/domain-scan/domain-scan)

A comprehensive Go-based tool for discovering and verifying active subdomains through multiple techniques including passive enumeration, TLS certificate analysis, and HTTP service verification.

## Quick Start

```bash
# Download and install
curl -sSL https://github.com/domain-scan/domain-scan/releases/latest/download/domain-scan_$(uname -s)_$(uname -m).tar.gz | tar -xz
sudo mv domain-scan /usr/local/bin/

# Run a basic scan
domain-scan discover example.com

# Or with Docker
docker run --rm ghcr.io/domain-scan/domain-scan:latest discover example.com

# Or with Homebrew
brew install domain-scan/tap/domain-scan
domain-scan discover example.com

# For development (from source)
git clone https://github.com/domain-scan/domain-scan.git
cd domain-scan
make init && make run-discover
```

## Overview

This tool performs comprehensive subdomain discovery and verification by combining multiple techniques:
1. **Passive Discovery**: Uses subfinder to enumerate subdomains from passive sources
2. **TLS Certificate Analysis**: Probes domains using httpx with TLS certificate inspection  
3. **HTTP Service Verification**: Scans discovered subdomains for active HTTP/HTTPS services
4. **Keyword Extraction**: Automatically extracts keywords from domain names
5. **Keyword Filtering**: Filters domains from SSL certificates based on organizational relevance
6. **Deduplication**: Outputs unique active HTTP services

## How It Works

The tool combines three powerful techniques for comprehensive subdomain discovery and verification:

### 1. Subfinder Integration
- Uses ProjectDiscovery's subfinder to query passive DNS sources
- Discovers subdomains from certificate transparency logs, DNS records, and other sources
- Provides comprehensive initial subdomain enumeration

### 2. TLS Certificate Analysis
- Inspects Subject Alternative Names (SANs) in SSL/TLS certificates
- Finds additional subdomains not discovered by passive sources
- Filters domains based on organizational relevance using keywords
- Leverages certificate transparency for passive reconnaissance

#### SSL Certificate Keyword Filtering
When analyzing SSL certificates, domains often contain Subject Alternative Names (SANs) from multiple organizations due to shared hosting or third-party services. For example, if `apple.com` has a subdomain `status.apple.com` pointing to a third-party SaaS provider, that provider's certificate might also contain domains like `status.microsoft.com` or other unrelated organizations.

The keyword filtering system:
1. **Extracts keywords** from target domains (e.g., `apple.com` → `apple`, `iphone.com` → `iphone`)
2. **Filters certificate domains** to only include those matching organizational keywords
3. **Prevents noise** from unrelated domains in shared certificates
4. **Examples**:
   - Target: `apple.com` → Keywords: `apple`
   - Certificate contains: `status.apple.com`, `store.apple.com`, `status.microsoft.com`
   - Filtered result: `status.apple.com`, `store.apple.com` (excludes `status.microsoft.com`)

### 3. HTTP Service Verification
- Scans all discovered subdomains for active HTTP/HTTPS services
- Tests multiple ports (configurable) for web services
- Verifies actual accessibility and responsiveness
- Returns only active, reachable services

### Key Features

- **Integrated Subfinder**: Built-in subfinder execution for comprehensive discovery
- **TLS Certificate Analysis**: Inspects Subject Alternative Names in SSL certificates with keyword filtering
- **HTTP Service Scanning**: Verifies active HTTP/HTTPS services on discovered subdomains
- **Configurable Port Scanning**: Customizable port list for HTTP service detection
- **Automatic Keyword Extraction**: Extracts keywords from domain names automatically
- **SSL Certificate Filtering**: Filters domains from SSL certificates based on organizational relevance
- **Concurrent Processing**: Uses httpx with configurable threads for fast scanning
- **Timeout Protection**: Configurable timeouts for reliable operation
- **Progress Indicators**: Real-time feedback on scanning progress
- **Deduplication**: Automatically removes duplicate subdomains

## Usage

```bash
domain-scan discover [domains...] [flags]
```

### Basic Commands

```bash
# Get help
domain-scan --help
domain-scan discover --help

# Check configuration
domain-scan config

# Install dependencies
domain-scan install
```

### Discovery Options

- `domains`: Target domains for subdomain discovery
- `--keywords`: Additional keywords for filtering SSL certificate domains (automatically extracted from target domains and combined with any provided keywords)
- `--ports`: Comma-separated ports for HTTP scanning (default: 80,443,8080,8443,3000,8000,8888)
- `--profile`: Use predefined configuration profile (quick, comprehensive)
- `--output`: Output file path (default: stdout)
- `--format`: Output format (text, json)
- `--max-subdomains`: Maximum subdomains to scan for HTTP services
- `--timeout`: Timeout in seconds
- `--threads`: Number of concurrent threads
- `--quiet`: Suppress progress output

### Discovery Method Controls

- `--passive`: Enable passive subdomain discovery (default: true)
- `--cert`: Enable TLS certificate analysis (default: true) 
- `--http`: Enable HTTP service verification (default: true)
- `--no-passive`: Disable passive subdomain discovery
- `--no-cert`: Disable TLS certificate analysis
- `--no-http`: Disable HTTP service verification

### Examples

```bash
# Basic discovery (keywords automatically extracted from domain names)
domain-scan discover example.com

# Quick scan profile (limited subdomains, basic ports)
domain-scan discover example.com --profile quick

# Comprehensive scan profile (more subdomains and ports)
domain-scan discover example.com --profile comprehensive

# Additional keywords (combined with auto-extracted ones) and custom ports
domain-scan discover example.com --keywords staging,prod --ports 80,443,8080

# Multiple domains with additional keywords (auto-extracted from both domains)
domain-scan discover example.com test.com --keywords staging,prod

# Save results to JSON file
domain-scan discover example.com --output results.json --format json

# Disable specific discovery methods
domain-scan discover example.com --no-passive --no-cert

# Quiet mode with custom limits
domain-scan discover example.com --quiet --max-subdomains 500 --timeout 15
```

## Default Port Configuration

The tool scans the following ports by default:
- **80** (HTTP)
- **443** (HTTPS) 
- **8080** (HTTP alternate)
- **8443** (HTTPS alternate)
- **3000** (Development servers)
- **8000** (Development/testing)
- **8888** (Development/testing)

## Integration with Main Project

This tool can be used standalone or integrated with the main reconnaissance script. The tool is self-contained and includes:

1. **Subfinder Integration**: Direct subfinder execution for comprehensive discovery
2. **Automatic Keyword Extraction**: No need for separate keyword extraction utilities  
3. **TLS Certificate Analysis**: Additional discovery through certificate inspection with organizational filtering
4. **HTTP Service Verification**: Ensures only active services are reported
5. **Unified Output**: All active HTTP services in a single, deduplicated list

## Dependencies

### Required Tools
- `subfinder` - Must be installed and available in PATH
- `httpx` - Must be installed and available in PATH

### Go Dependencies
- `github.com/projectdiscovery/httpx/runner` - HTTP toolkit for probing and TLS inspection

## Prerequisites

Ensure required tools are installed:

```bash
# Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Configuration

The tool uses these default settings:
- **Timeout**: 10 seconds per domain
- **Threads**: 10 concurrent connections (TLS), 50 (HTTP scanning)
- **TLS Probe**: Enabled for certificate inspection
- **Subfinder**: Silent mode with all sources enabled
- **HTTP Scanning**: Tests both HTTP and HTTPS protocols
- **Default Ports**: 80,443,8080,8443,3000,8000,8888

## Security Considerations

This tool is designed for defensive security purposes:
- Performs passive reconnaissance and active HTTP probing
- No exploitation or intrusive testing beyond HTTP requests
- Helps organizations understand their external attack surface
- Complies with responsible disclosure practices
- Only tests for HTTP service availability

## Output Format

The tool outputs active HTTP services to stdout, one per line, making it easy to pipe to other tools or save to files. Progress information and statistics are sent to stderr.

**Example Output:**
```
https://store.example.com
http://staging.example.com:8080
https://staging.example.com:8443
```

## Progress Indicators

The tool provides real-time feedback through stderr:
- 🔍 Subdomain discovery progress
- 📋 Discovery statistics
- 🔐 TLS certificate analysis progress
- 🌐 HTTP service scanning progress
- ✅ Active service discoveries
- 📊 Final statistics

## Workflow

1. **Parse Arguments**: Extract target domains, keywords, and ports
2. **Keyword Extraction**: Auto-extract keywords from domain names and combine with any manually provided keywords
3. **Subfinder Discovery**: Run subfinder to get initial subdomain list
4. **TLS Certificate Analysis**: Probe domains for additional subdomains via certificate SANs, filtering by organizational relevance
5. **HTTP Service Scanning**: Test all discovered subdomains for active HTTP services
6. **SSL Certificate Filtering**: Filter certificate domains based on keyword relevance to target organization
7. **Deduplication**: Remove duplicate entries
8. **Output**: Print active HTTP services to stdout

## Limitations

- Requires subfinder and httpx to be installed and available in PATH
- TLS certificate analysis limited to domains with valid SSL/TLS certificates  
- SSL certificate keyword filtering may exclude domains from shared certificates that don't match organizational keywords
- HTTP scanning limited to specified ports
- Performance depends on target domain response times and network connectivity
- Large subdomain lists may take considerable time to scan

## Installation

### Binary Downloads

Download the latest release for your platform from the [releases page](https://github.com/domain-scan/domain-scan/releases).

### Package Managers

#### Homebrew (macOS/Linux)
```bash
brew install domain-scan/tap/domain-scan
```

#### APT (Debian/Ubuntu)
```bash
wget https://github.com/domain-scan/domain-scan/releases/latest/download/domain-scan_amd64.deb
sudo dpkg -i domain-scan_amd64.deb
```

#### RPM (RHEL/CentOS/Fedora)
```bash
wget https://github.com/domain-scan/domain-scan/releases/latest/download/domain-scan_amd64.rpm
sudo rpm -i domain-scan_amd64.rpm
```

#### Alpine Linux
```bash
wget https://github.com/domain-scan/domain-scan/releases/latest/download/domain-scan_amd64.apk
sudo apk add --allow-untrusted domain-scan_amd64.apk
```

### Docker

```bash
# Run with Docker
docker run --rm ghcr.io/domain-scan/domain-scan:latest --help

# Basic domain discovery
docker run --rm ghcr.io/domain-scan/domain-scan:latest discover example.com

# With custom options
docker run --rm ghcr.io/domain-scan/domain-scan:latest discover example.com --profile quick

# Save results to file (using volume mount)
docker run --rm -v $(pwd):/output ghcr.io/domain-scan/domain-scan:latest discover example.com --output /output/results.json --format json
```

### From Source

```bash
go install github.com/domain-scan/domain-scan@latest
```

## Testing

The tool includes comprehensive test coverage:

```bash
# Run all tests
go test -v ./...

# Run with coverage
make test-coverage

# Run specific test packages
go test -v ./pkg/utils
go test -v ./pkg/discovery
go test -v ./pkg/domainscan
```

## Development

This section covers everything needed for developing and contributing to domain-scan.

**Quick Navigation:**
- [Building](#building)
- [Running During Development](#running-during-development) 
- [Code Quality](#code-quality)
- [Make Commands Reference](#make-commands-reference)

### Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Development build with race detection
make dev
```

### Running During Development

```bash
# Run with custom arguments
make run ARGS="discover example.com --profile quick"

# Quick shortcuts for testing
make run-help          # Show help
make run-discover      # Test discovery with example.com
make run-config        # Show current configuration
make run-install       # Install dependencies

# Examples
make run ARGS="discover example.com --keywords staging,prod --ports 80,443"
make run ARGS="discover test.com --format json --output results.json"
```

### Code Quality

```bash
# Format code
make fmt

# Lint code
make lint

# Security scan
make security

# Vulnerability check
make vuln
```

### Make Commands Reference

The project includes a comprehensive Makefile with targets for all development tasks. Run `make help` to see all available targets.

**Quick Start**: `make init && make test && make run-discover`

#### Build Targets
```bash
make build           # Build for current platform
make build-all       # Build for multiple platforms (Linux, macOS, Windows)
make dev             # Development build with race detection
make clean           # Clean build artifacts
```

#### Development & Testing
```bash
make run ARGS="..."  # Build and run with custom arguments
make run-help        # Show application help
make run-discover    # Quick test discovery with example.com
make run-config      # Show current configuration
make run-install     # Install dependencies

make test            # Run all tests
make test-coverage   # Run tests with HTML coverage report
make bench           # Run benchmark tests
```

#### Code Quality & Security
```bash
make fmt             # Format code with gofmt
make lint            # Run golangci-lint (installs if needed)
make security        # Run gosec security scanner
make vuln            # Check for vulnerabilities with govulncheck
```

#### Dependencies & Environment
```bash
make deps            # Install and verify Go dependencies
make init            # Initialize development environment
make update          # Update all dependencies
```

#### Release & Distribution
```bash
make release         # Create release using GoReleaser
make snapshot        # Create snapshot release for testing
make docker          # Build Docker image
make docker-run      # Run Docker container
```

#### Installation
```bash
make install         # Install binary to $GOPATH/bin
make uninstall       # Remove binary from $GOPATH/bin
```

#### Documentation & Help
```bash
make docs            # Generate command documentation
make help            # Show all available targets
```

#### Example Development Workflow
```bash
# Initialize environment
make init

# Run tests
make test

# Test the application
make run-discover

# Test with custom arguments
make run ARGS="discover example.com --keywords api,admin --ports 80,443,8080"

# Format and lint code
make fmt lint

# Create a snapshot build
make snapshot
```

## Release Process

This project uses automated releases via GitHub Actions and [GoReleaser](https://goreleaser.com/).

### Creating a Release

1. **Ensure all changes are on the main branch**
2. **Create and push a new tag**:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. **GitHub Actions will automatically**:
   - Run all tests and quality checks
   - Build binaries for multiple platforms (Linux, macOS, Windows)
   - Create packages (DEB, RPM, APK)
   - Build and push Docker images (multi-architecture)
   - Generate release notes and publish to GitHub
   - Update Homebrew formula

### Release Artifacts

Each release automatically produces:

- **Cross-platform binaries** for Linux, macOS, and Windows
- **Linux packages** (DEB, RPM, APK) for easy installation
- **Docker images** for both amd64 and arm64 architectures
- **Homebrew formula** for macOS and Linux users
- **Checksums** for artifact verification

### Versioning

The project follows [Semantic Versioning](https://semver.org/):
- `v1.0.0` - Major release with breaking changes
- `v1.1.0` - Minor release with new features
- `v1.1.1` - Patch release with bug fixes

### Development Releases

For testing unreleased changes:

```bash
# Create a snapshot build locally
make snapshot

# Or use the manual test workflow in GitHub Actions
```

## Troubleshooting

**Common Issues:**
- Ensure subfinder and httpx are installed and in PATH
- Check network connectivity for target domains
- Verify domain names are correct and accessible
- For large subdomain lists, consider using smaller port ranges
- Monitor system resources during intensive scans

**Installation Issues:**
- For package installations, ensure you have appropriate permissions
- For Docker, ensure the Docker daemon is running
- For Homebrew, run `brew update` if the formula isn't found