# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

domain-scan is a comprehensive Go-based security tool for discovering and verifying active subdomains through multiple techniques including passive enumeration, TLS certificate analysis, and HTTP service verification. The tool is designed for defensive security purposes to help organizations understand their external attack surface.

## Core Architecture

### CLI Structure
- **Main Entry Point**: `main_new.go` - Simple entry point that delegates to the cobra command system
- **Command System**: `cmd/` directory contains cobra-based CLI commands:
  - `root.go` - Base command with configuration handling
  - `discover.go` - Main discovery command with comprehensive flag support
  - `config.go` - Configuration management command
  - `install.go` - Dependency installation command

### Core Library (`pkg/`)
- **domainscan/**: Main scanner logic
  - `scanner.go` - Primary Scanner type with DiscoverAssets and ScanWithOptions methods
  - `config.go` - Configuration structures with validation
  - `result.go` - Result structures for discovery output
  - `errors.go` - Custom error types for the library
- **discovery/**: Discovery method implementations
  - `passive.go` - Subfinder integration for passive enumeration
  - `certificate.go` - TLS certificate analysis for SAN extraction
  - `http.go` - HTTP service verification and scanning
- **types/**: Shared type definitions
- **utils/**: Utility functions for keywords and dependencies

### Configuration System
- Uses Viper for configuration management with YAML support
- Default config in `config.yaml` with profiles (quick, comprehensive)
- Supports environment variables and CLI flag overrides
- Configuration hierarchy: CLI flags > config file > defaults

## Development Commands

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

# Quick shortcuts for common commands
make run-help          # Show help
make run-discover      # Test discovery with example.com
make run-config        # Show current configuration
make run-install       # Install dependencies

# Examples of custom runs
make run ARGS="discover example.com --keywords staging,prod --ports 80,443"
make run ARGS="discover multiple.com domains.com --profile comprehensive"
make run ARGS="config --help"
```

### Testing
```bash
# Run all tests with coverage
make test

# Run tests with HTML coverage report
make test-coverage

# Run benchmarks
make bench
```

### Code Quality
```bash
# Format code
make fmt

# Lint code (installs golangci-lint if needed)
make lint

# Security scan
make security

# Vulnerability check
make vuln
```

### Dependencies
```bash
# Install and tidy dependencies
make deps

# Initialize development environment (installs tools)
make init

# Update all dependencies
make update
```

### Release Management
```bash
# Create snapshot release
make snapshot

# Create full release
make release
```

## External Dependencies

The tool requires these external security tools to be installed:
- **subfinder** - For passive subdomain enumeration from multiple sources
- **httpx** - For HTTP probing and TLS certificate analysis

Use `domain-scan install` to automatically install these dependencies, or install manually:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Library Usage Pattern

The library can be used programmatically with two main approaches:

### Simple Discovery
```go
scanner := domainscan.New(nil) // Uses default config
result, err := scanner.DiscoverAssets(ctx, []string{"example.com"})
```

### Advanced Discovery with Options
```go
config := domainscan.DefaultConfig()
scanner := domainscan.New(config)

req := &domainscan.ScanRequest{
    Domains:        []string{"example.com"},
    Keywords:       []string{}, // Keywords are extracted from domains automatically
    Ports:          []int{80, 443, 8080},
    MaxSubdomains:  1000,
    EnablePassive:  true,
    EnableCertScan: true,
    EnableHTTPScan: true,
}

result, err := scanner.ScanWithOptions(ctx, req)
```

## Key Configuration Options

- **discovery.max_subdomains**: Limits HTTP scanning to prevent overwhelming targets
- **discovery.timeout**: Per-request timeout for HTTP operations
- **discovery.threads**: Concurrency level for HTTP scanning
- **ports.default**: Default ports for HTTP service verification
- **keywords**: Keywords for filtering SSL certificate domains by organizational relevance (auto-extracted from domains if not specified)

## Testing Strategy

- Comprehensive unit tests in `main_test.go`
- Integration tests that check for external tool availability
- Conditional test skipping when dependencies are missing
- Test coverage includes edge cases like missing tools and invalid inputs

## Release Process

The project uses automated releases via GitHub Actions and GoReleaser:

### Creating Releases
```bash
# Create and push a new tag to trigger release
git tag v1.0.0
git push origin v1.0.0
```

### Release Workflow
- Tests run automatically on tag push
- Cross-platform binaries are built (Linux, macOS, Windows)
- Packages are created (DEB, RPM, APK)
- Docker images are built for multiple architectures
- GitHub release is created with changelog
- Homebrew formula is updated automatically

### Available Installation Methods
- Direct binary download from GitHub releases
- Package managers (Homebrew, APT, RPM, Alpine)
- Docker images on GitHub Container Registry
- Go install for source builds

### Testing Releases
```bash
# Test GoReleaser configuration
goreleaser check

# Create snapshot build locally
make snapshot

# Use GitHub Actions test workflow for validation
```

## Security Considerations

- Tool is designed for defensive security and authorized reconnaissance only
- Performs only passive reconnaissance and HTTP service verification
- No exploitation or intrusive testing beyond basic HTTP requests
- Respects rate limiting and timeouts to avoid overwhelming targets
- Keywords and port lists can be customized to focus scanning scope