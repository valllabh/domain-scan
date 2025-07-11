# Subdomain Finder

A comprehensive Go-based tool for discovering and verifying active subdomains through multiple techniques including passive enumeration, TLS certificate analysis, and HTTP service verification.

## Overview

This tool performs comprehensive subdomain discovery and verification by combining multiple techniques:
1. **Passive Discovery**: Uses subfinder to enumerate subdomains from passive sources
2. **TLS Certificate Analysis**: Probes domains using httpx with TLS certificate inspection  
3. **HTTP Service Verification**: Scans discovered subdomains for active HTTP/HTTPS services
4. **Keyword Extraction**: Automatically extracts keywords from domain names
5. **Keyword Filtering**: Filters discovered subdomains based on relevant keywords
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
- Leverages certificate transparency for passive reconnaissance

### 3. HTTP Service Verification
- Scans all discovered subdomains for active HTTP/HTTPS services
- Tests multiple ports (configurable) for web services
- Verifies actual accessibility and responsiveness
- Returns only active, reachable services

### Key Features

- **Integrated Subfinder**: Built-in subfinder execution for comprehensive discovery
- **TLS Certificate Analysis**: Inspects Subject Alternative Names in SSL certificates
- **HTTP Service Scanning**: Verifies active HTTP/HTTPS services on discovered subdomains
- **Configurable Port Scanning**: Customizable port list for HTTP service detection
- **Automatic Keyword Extraction**: Extracts keywords from domain names automatically
- **Manual Keyword Override**: Optionally specify custom keywords for filtering
- **Concurrent Processing**: Uses httpx with configurable threads for fast scanning
- **Timeout Protection**: Configurable timeouts for reliable operation
- **Progress Indicators**: Real-time feedback on scanning progress
- **Deduplication**: Automatically removes duplicate subdomains

## Usage

```bash
go run main.go <domain1> <domain2> ... [--keywords comma,separated,keywords] [--ports comma,separated,ports]
```

### Parameters

- `domain1, domain2, ...`: Target domains for subdomain discovery
- `--keywords`: Optional comma-separated keywords for filtering (if not provided, keywords are auto-extracted)
- `--ports`: Optional comma-separated ports for HTTP scanning (default: 80,443,8080,8443,3000,8000,8888)

### Examples

```bash
# Basic usage with automatic keyword extraction and default ports
go run main.go example.com

# With custom keywords
go run main.go example.com --keywords "api,admin,dev,staging"

# With custom ports
go run main.go example.com --ports "80,443,8080,8443"

# Multiple domains with custom keywords and ports
go run main.go example.com test.com --keywords "api,admin,test" --ports "80,443,3000,8000"

# Comprehensive scan with all options
go run main.go example.com corp.com --keywords "api,admin,dev,staging,test" --ports "80,443,8080,8443,3000,8000,8888,9000"
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
3. **TLS Certificate Analysis**: Additional discovery through certificate inspection
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
https://api.example.com
http://admin.example.com:8080
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
2. **Keyword Extraction**: Auto-extract keywords from domain names (if not provided)
3. **Subfinder Discovery**: Run subfinder to get initial subdomain list
4. **TLS Certificate Analysis**: Probe domains for additional subdomains via certificate SANs
5. **HTTP Service Scanning**: Test all discovered subdomains for active HTTP services
6. **Filtering**: Filter results based on keywords
7. **Deduplication**: Remove duplicate entries
8. **Output**: Print active HTTP services to stdout

## Limitations

- Requires subfinder and httpx to be installed and available in PATH
- TLS certificate analysis limited to domains with valid SSL/TLS certificates  
- Keyword filtering may miss relevant subdomains not containing specified terms
- HTTP scanning limited to specified ports
- Performance depends on target domain response times and network connectivity
- Large subdomain lists may take considerable time to scan

## Testing

The tool includes comprehensive test coverage:

```bash
# Run all tests
go test -v

# Run specific test categories
go test -v -run TestExtractKeywords
go test -v -run TestRunSubfinder
go test -v -run TestScanHTTPServices
```

## Troubleshooting

**Common Issues:**
- Ensure subfinder and httpx are installed and in PATH
- Check network connectivity for target domains
- Verify domain names are correct and accessible
- For large subdomain lists, consider using smaller port ranges
- Monitor system resources during intensive scans