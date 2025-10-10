# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

domain-scan is a comprehensive Go-based security tool that integrates [ProjectDiscovery's](https://projectdiscovery.io) excellent security tools ([subfinder](https://github.com/projectdiscovery/subfinder) and [httpx](https://github.com/projectdiscovery/httpx)) to discover and verify active subdomains through multiple techniques including passive enumeration, TLS certificate analysis, and HTTP service verification. The tool is designed for defensive security purposes to help organizations understand their external attack surface.

## Core Architecture

### CLI Structure
- **Main Entry Point**: `main_new.go` - Simple entry point that delegates to the cobra command system
- **Command System**: `cmd/` directory contains cobra-based CLI commands:
  - `root.go` - Base command with configuration handling
  - `discover.go` - Main discovery command with comprehensive flag support
  - `config.go` - Configuration management command

### Core Library (`pkg/`)
- **domainscan/**: Main scanner logic
  - `scanner.go` - Primary Scanner type with DiscoverAssets and ScanWithOptions methods
  - `config.go` - Configuration structures with validation
  - `result.go` - Result structures for discovery output
  - `errors.go` - Custom error types for the library
  - `queue.go` - Message queue-based domain processing system
  - `domain_state.go` - Domain state tracking and scan completion management
  - `progress.go` - Progress callback system for UI integration
  - `cli_progress.go` - CLI-specific progress handler implementation
- **discovery/**: Discovery method implementations
  - `passive.go` - Subfinder integration for passive enumeration
  - `certificate.go` - TLS certificate analysis for SAN extraction
  - `http.go` - HTTP service verification and scanning
- **types/**: Shared type definitions
- **utils/**: Utility functions for keywords and TLD handling

### Configuration System
- Uses Viper for configuration management with YAML support
- Default config in `config.yaml` with customizable settings
- Supports environment variables and CLI flag overrides
- Configuration hierarchy: CLI flags > config file > defaults

### Progress Callback System
The tool now supports flexible progress callbacks for different UI frameworks:
- **Silent Mode**: No progress callbacks for background processing
- **CLI Progress**: Built-in terminal progress handler
- **Custom Progress**: Implement your own progress handler for web/desktop apps
- **Real-time Updates**: Progress callbacks fire on domain discovery and liveness detection

## Development Commands

### Building
```bash
# Build for current platform
make build

# Build for all platforms (Linux, macOS)
make build-all

# Development build with race detection
make dev
```

### Running During Development
```bash
# Run with custom arguments
make run ARGS="discover example.com --keywords staging,prod"

# Quick shortcuts for common commands
make run-help          # Show help
make run-discover      # Test discovery with example.com
make run-config        # Show current configuration

# Examples of custom runs
make run ARGS="discover example.com --keywords staging,prod --timeout 15"
make run ARGS="discover multiple.com domains.com --format json --quiet"
make run ARGS="config show"
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

# Vulnerability check (shows all vulnerabilities)
make vuln

# Vulnerability check (excluding documented exceptions)
make vuln-check
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

## Integrated Security Tools

The tool integrates these excellent security tools from [ProjectDiscovery](https://projectdiscovery.io):
- **[subfinder](https://github.com/projectdiscovery/subfinder)** - For passive subdomain enumeration from multiple sources
- **[httpx](https://github.com/projectdiscovery/httpx)** - For HTTP probing and TLS certificate analysis

These tools are now integrated directly into domain-scan, eliminating the need for separate installation.

## Library Usage Pattern

The library now supports an SDK-first architecture with flexible progress callbacks for clean integration into various types of applications.

### Silent SDK Usage (No Output)
Perfect for background services, batch processing, or when you want complete control over output:
```go
// Create scanner with no progress callback - completely silent
scanner := domainscan.New(nil)

// Run scan with no console output
result, err := scanner.DiscoverAssets(ctx, []string{"example.com"})
```

### CLI Progress Handler
Use the built-in CLI progress handler for terminal applications:
```go
scanner := domainscan.New(nil)
progressHandler := domainscan.NewCLIProgressHandler()
scanner.SetProgressCallback(progressHandler)

result, err := scanner.ScanWithOptions(ctx, req)
```

### Custom Progress Handler
Implement your own progress handler for web apps, desktop apps, or any custom UI:
```go
type MyProgressHandler struct {
    onUpdate func(message string)
}

func (p *MyProgressHandler) OnStart(domains []string, keywords []string) {
    p.onUpdate(fmt.Sprintf("Starting scan for %d domains", len(domains)))
}

func (p *MyProgressHandler) OnDomainTraceFound(domain string, totalFound int) {
    p.onUpdate(fmt.Sprintf("Found: %s (%d total)", domain, totalFound))
}

func (p *MyProgressHandler) OnLiveDomainFound(domain string, url string, totalLive int) {
    p.onUpdate(fmt.Sprintf("Live: %s (%d live)", url, totalLive))
}

func (p *MyProgressHandler) OnEnd(result *AssetDiscoveryResult) {
    p.onUpdate(fmt.Sprintf("Complete: %d domains, %d live", result.Statistics.TotalSubdomains, result.Statistics.ActiveServices))
}

// Usage
scanner := domainscan.New(nil)
progressHandler := &MyProgressHandler{
    onUpdate: func(message string) {
        // Send to web UI, log, etc.
        fmt.Println(message)
    },
}
scanner.SetProgressCallback(progressHandler)
```

### Advanced Discovery with Options
```go
config := domainscan.DefaultConfig()
scanner := domainscan.New(config)

req := &domainscan.ScanRequest{
    Domains:  []string{"example.com"},
    Keywords: []string{}, // Keywords are extracted from domains automatically
    Timeout:  10 * time.Second,
}

result, err := scanner.ScanWithOptions(ctx, req)
```

## Queue-Based Architecture

The tool uses a message queue-based architecture for efficient domain processing:

### Core Components

1. **Domain Processor** (`pkg/domainscan/queue.go`): Manages domain discovery using message queues
   - Separate queues for passive discovery and certificate analysis
   - Worker pools for concurrent processing
   - Progress callback integration

2. **Domain Tracker** (`pkg/domainscan/domain_state.go`): Provides memory-efficient tracking of discovered domains
   - Scan completion state management (passive, certificate, liveness)
   - Port-specific certificate scan tracking
   - Pending scan sets for efficient querying

3. **Progress System** (`pkg/domainscan/progress.go`, `pkg/domainscan/cli_progress.go`): 
   - Flexible progress callback interface
   - CLI progress handler for terminal output
   - Custom progress handlers for different UI frameworks

### Processing Flow

1. Initial domains are queued for passive discovery
2. Passive discovery workers find subdomains and queue them for certificate analysis
3. Certificate analysis workers:
   - Extract domains from TLS certificates
   - Perform HTTP service verification
   - Queue newly discovered domains for passive discovery
4. Process continues until all queues are empty

### Benefits

- **Concurrent Processing**: Multiple workers handle different scan types simultaneously
- **Deduplication**: Efficient tracking prevents duplicate work
- **Scalability**: Queue-based design can handle large domain lists
- **Flexibility**: Progress callbacks enable integration with any UI framework
- **Memory Efficiency**: Optimized data structures for large domain sets

## Key Configuration Options

- **discovery.timeout**: Per-request timeout for HTTP operations
- **discovery.threads**: Concurrency level for HTTP scanning
- **ports.default**: Default ports for HTTP service verification
- **keywords**: Keywords for filtering SSL certificate domains by organizational relevance (auto-extracted from domains if not specified)

## Testing Strategy

- Comprehensive unit tests in `main_test.go`
- Integration tests for integrated security tools
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
- Cross-platform binaries are built (Linux, macOS)
- Packages are created (DEB, RPM, APK)
- GitHub release is created with changelog
- Homebrew formula is updated automatically

### Available Installation Methods
- Direct binary download from GitHub releases
- Package managers (Homebrew, APT, RPM, Alpine)
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

**Important**: See [SECURITY.md](SECURITY.md) for comprehensive security policies, vulnerability reporting, and responsible usage guidelines.

## Vulnerability Management

The project uses automated security scanning:
- `make security` - Runs gosec static analysis
- `make vuln` - Shows all vulnerabilities including documented exceptions
- `make vuln-check` - Shows only actionable vulnerabilities

Known exceptions are documented in `govulncheck.yaml` with risk assessments and review schedules.