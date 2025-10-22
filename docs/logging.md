# Logging Strategy

Comprehensive logging approach for domain-scan using ProjectDiscovery's gologger.

## Table of Contents

- [Overview](#overview)
- [Logging Levels](#logging-levels)
- [Architecture](#architecture)
- [Usage Guidelines](#usage-guidelines)
- [Migration Examples](#migration-examples)
- [Configuration](#configuration)

## Overview

**Logger**: ProjectDiscovery's `gologger`

**Why gologger:**
- Already in dependencies through subfinder and httpx (no new deps)
- Supports structured logging with levels
- Battle tested in security tools
- Supports Debug, Info, Warning, Error, Fatal levels
- Integrates seamlessly with ProjectDiscovery SDK tools

**Key Principle**: All output uses gologger except in exceptional cases

**Consistent Experience**: Logging flags control both domain-scan and subfinder/httpx output for unified behavior

### Unified Logging Behavior

| Flag | gologger Level | Subfinder/httpx Output | Use Case |
|------|----------------|------------------------|----------|
| (default) | Info + Warning + Error | Normal findings | Normal user experience, interactive scans |
| `--debug` | Debug + Info + Warning + Error | Debug requests/responses | Full troubleshooting, development |
| `--silent` | Warning + Error only | Findings only | Automation, CI/CD pipelines |

## Logging Levels

### Debug (--debug flag)
**Use for**: Internal flow, technical details, troubleshooting

Examples:
- Discovery method details
- Cache hits/misses
- Certificate parsing
- Domain processing steps
- Internal state changes
- Function entry/exit traces

```go
logger.Debug().Msgf("Starting passive scan for %d domains", len(domains))
logger.Debug().Msgf("Bulk enumeration completed successfully")
logger.Debug().Msgf("Found subdomain: %s (total unique: %d)", subdomain, total)
```

### Info
**Use for**: Major milestones, operational events, user-facing messages

Examples:
- Scan phase transitions
- Discovery completion
- Report generation
- File operations (saved, loaded)
- Progress updates
- Command start/completion
- Real-time findings

```go
logger.Info().Msgf("Starting domain asset discovery for: %v", domains)
logger.Info().Msgf("Passive discovery completed: found %d unique subdomains", len(subdomains))
logger.Info().Msgf("Found %d live domains", found)
logger.Info().Msgf("Running bulk certificate analysis for %d targets", len(targets))
logger.Info().Msgf("Discovery complete: %d domains, %d live", total, live)
```

### Warning
**Use for**: Non-fatal issues, degraded functionality

Examples:
- Cache save failures
- Partial results
- Malformed data (skipped)
- Configuration issues
- Network timeouts (non-fatal)

```go
logger.Warning().Msgf("Failed to save domain cache: %v", err)
logger.Warning().Msgf("Skipping malformed certificate: %v", err)
logger.Warning().Msgf("Bulk certificate analysis error: %v", err)
```

### Error
**Use for**: Fatal errors that will be returned to caller

Examples:
- Engine initialization failures
- File read/write errors (fatal)
- Network errors
- Invalid configuration

```go
logger.Error().Msgf("Failed to initialize subfinder runner: %v", err)
return nil, fmt.Errorf("failed to initialize subfinder runner: %w", err)
```

### Silent (--silent flag)
**Use for**: Minimal output for automation

Only warnings and errors displayed. Suppresses info messages (progress, milestones).

## Architecture

### Logger Initialization

**Location**: `pkg/logging/logger.go`

```go
package logging

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// InitLogger configures the global logger based on log level string
func InitLogger(logLevel string) {
	var level levels.Level
	switch logLevel {
	case "trace", "debug":
		level = levels.LevelDebug
	case "info":
		level = levels.LevelInfo
	case "warn":
		level = levels.LevelWarning
	case "error":
		level = levels.LevelError
	case "silent":
		level = levels.LevelSilent
	default:
		level = levels.LevelInfo
	}

	gologger.DefaultLogger.SetMaxLevel(level)
}

// GetLogger returns the configured logger instance
func GetLogger() *gologger.Logger {
	return gologger.DefaultLogger
}
```

### Scanner Integration

**Location**: `pkg/domainscan/scanner.go`

```go
// New creates scanner and initializes logger (default: Info level)
func New(config *Config) *Scanner {
	if config == nil {
		config = DefaultConfig()
	}

	// Initialize logger based on log level
	logging.InitLogger(config.LogLevel)
	logger := logging.GetLogger()

	return &Scanner{
		config: config,
		logger: logger,
	}
}

// UpdateConfig validates and updates the scanner configuration
// Also reconfigures logger if log level changed
func (s *Scanner) UpdateConfig(config *Config) error {
	if err := config.Validate(); err != nil {
		return err
	}

	s.config = config
	logging.InitLogger(config.LogLevel)
	s.logger = logging.GetLogger()

	return nil
}
```

### Command Integration

**Location**: `cmd/discover.go`, `cmd/root.go`

```go
import (
	"github.com/valllabh/domain-scan/pkg/logging"
)

// Get logger instance in commands
var logger = logging.GetLogger()

// Use throughout command
logger.Info().Msgf("Starting domain asset discovery for: %v", domains)
```

### Subfinder/httpx Integration

**Location**: `pkg/discovery/passive.go`, `pkg/discovery/certificate.go`

Logging flags are passed through to subfinder/httpx for consistent experience:

```go
// Subfinder options with logging
options := &runner.Options{
	Verbose: config.LogLevel == "debug",  // Enable debug output
	Silent:  config.LogLevel == "silent", // Suppress progress
	// ... other options
}
```

## Usage Guidelines

### When to Log

**DO Log:**
- State changes (discovery started, scan completed)
- Resource operations (file saved, cache loaded)
- Errors and warnings
- Debug traces when --debug enabled

**DO NOT Log:**
- Every loop iteration (too verbose, use sampled logging)
- Sensitive data (credentials, tokens)
- Redundant information
- Internal variables dumps without context

### Log Message Format

**Good:**
```go
logger.Debug().Msgf("Loaded %d domains from cache: %s", count, path)
logger.Warning().Msgf("Failed to parse certificate for %s: %v", domain, err)
logger.Info().Msgf("Discovery completed: %d domains in %v", count, duration)
```

**Bad:**
```go
logger.Debug().Msgf("Debug: %v", someComplexStruct) // Too vague
logger.Info().Msgf("Processing...") // No context
logger.Warning().Msgf("Error") // No details
```

### Error Handling Pattern

**Standard pattern:**
```go
// Log the error with context, then return wrapped error
if err != nil {
	logger.Error().Msgf("Failed to create temp directory: %v", err)
	return "", fmt.Errorf("failed to create temp directory: %w", err)
}
```

**Warning pattern (non-fatal):**
```go
// Log warning but continue execution
if err := saveDomainsToCache(domains, cacheFile); err != nil {
	logger.Warning().Msgf("Failed to save domain cache: %v", err)
	// Continue - cache save is non-critical
}
```

## Migration Examples

### Example 1: Warning Messages

**Before:**
```go
fmt.Printf("Warning: Failed to save domain cache: %v\n", err)
```

**After:**
```go
logger.Warning().Msgf("Failed to save domain cache: %v", err)
```

### Example 2: Debug Messages

**Before:**
```go
if debug {
	fmt.Printf("Debug: Loaded %d domains\n", len(domains))
}
```

**After:**
```go
logger.Debug().Msgf("Loaded %d domains", len(domains))
```

### Example 3: Zap Logger Calls

**Before:**
```go
sugar.Debugf("Starting passive scan for %d domains", len(domains))
sugar.Infof("Passive discovery completed: found %d subdomains", len(subdomains))
sugar.Warnf("Bulk certificate analysis error: %v", err)
```

**After:**
```go
logger := logging.GetLogger()
logger.Debug().Msgf("Starting passive scan for %d domains", len(domains))
logger.Info().Msgf("Passive discovery completed: found %d subdomains", len(subdomains))
logger.Warning().Msgf("Bulk certificate analysis error: %v", err)
```

### Example 4: User-Facing Messages

**Before:**
```go
// cmd/discover.go
fmt.Printf("Starting domain asset discovery for: %v\n", domains)
fmt.Printf("Discovery completed successfully\n")
```

**After:**
```go
// cmd/discover.go
logger.Info().Msgf("Starting domain asset discovery for: %v", domains)
logger.Info().Msgf("Discovery completed successfully")
```

## Configuration

### Command Flags

**Default (no flags)**: Info level logging (normal user experience)
- gologger: Info, Warning, Error messages
- Subfinder/httpx: Normal findings output
```bash
./domain-scan discover example.com
```

**--log-level debug**: Debug logging (full troubleshooting)
- gologger: Debug, Info, Warning, Error (all messages)
- Subfinder/httpx: Debug output (show requests/responses)
```bash
./domain-scan discover example.com --log-level debug
```

**--log-level silent**: Silent mode (automation, CI/CD)
- gologger: Warning, Error only
- Subfinder/httpx: Findings only (suppress progress)
```bash
./domain-scan discover example.com --log-level silent
```

**Flag Inheritance**: Log level is passed through to:
1. gologger (via InitLogger)
2. Subfinder SDK (via runner.Options.Verbose/Silent)
3. httpx (via httpx options)
4. Progress handlers (via scanner config)

### Configuration File

**Location**: `config.yaml`

```yaml
log_level: info  # trace, debug, info, warn, error, silent
```

### SDK Usage

```go
// Create scanner with custom log level
config := domainscan.DefaultConfig()
config.LogLevel = "debug"
scanner := domainscan.New(config)

// Or update log level dynamically
config.LogLevel = "silent"
scanner.UpdateConfig(config)
```

## File-by-File Migration Plan

### Priority 1: Core Logging Infrastructure
1. **pkg/logging/logger.go** (DONE) - Added InitLogger and GetLogger for gologger
2. **pkg/domainscan/scanner.go** - Replace zap logger with gologger
3. **pkg/domainscan/config.go** - Already has LogLevel field
4. **pkg/discovery/passive.go** - Replace zap logger with gologger
5. **pkg/discovery/certificate.go** - Replace zap logger with gologger
6. **pkg/discovery/http.go** - Replace zap logger with gologger

### Priority 2: Commands
7. **cmd/discover.go** - Use gologger for user-facing messages
8. **cmd/config.go** - Use gologger for config operations
9. **cmd/sources.go** - Use gologger for sources management
10. **cmd/root.go** - Initialize gologger on startup

### Priority 3: Supporting Files
11. **pkg/domainscan/cli_progress.go** - Convert progress messages to gologger
12. **pkg/domainscan/result.go** - Add logger for result processing
13. **pkg/utils/*.go** - Update any logging in utility functions

## Testing

### Verify Debug Output
```bash
./domain-scan discover example.com --log-level debug 2>&1 | grep -i debug
```

### Verify Warning Output
```bash
./domain-scan discover example.com 2>&1 | grep -i warning
```

### Verify Info Output
```bash
./domain-scan discover example.com 2>&1 | grep -i "completed\|discovery"
```

### Verify Silent Mode
```bash
./domain-scan discover example.com --log-level silent 2>&1
```

## Future Enhancements

- Structured logging with fields (key-value pairs)
- Log file output (in addition to stderr)
- JSON log format for parsing
- Log rotation for long-running scans
- Per-module log levels
- Correlation IDs for multi-domain scans
