# Domain-scan SDK Examples

This directory contains examples of how to use domain-scan as an SDK in different applications.

## SDK-First Architecture

The domain-scan library now supports an SDK-first architecture with progress callbacks, enabling clean integration into various types of applications.

## Usage Patterns

### 1. Silent SDK Usage (No Output)

Perfect for background services, batch processing, or when you want complete control over output:

```go
import "github.com/valllabh/domain-scan/pkg/domainscan"

// Create scanner with no progress callback - completely silent
scanner := domainscan.New(nil)

// Run scan with no console output
result, err := scanner.DiscoverAssets(ctx, []string{"example.com"})
if err != nil {
    // Handle error
}

// Process results however you want
fmt.Printf("Found %d subdomains\n", result.Statistics.TotalSubdomains)
```

### 2. CLI Progress Handler (Same as Command Line)

Use the built-in CLI progress handler for terminal applications:

```go
import "github.com/valllabh/domain-scan/pkg/domainscan"

// Create scanner
scanner := domainscan.New(nil)

// Use built-in CLI progress handler
progressHandler := domainscan.NewCLIProgressHandler()
scanner.SetProgressCallback(progressHandler)

// Run scan with same output as 'domain-scan discover' command
result, err := scanner.ScanWithOptions(ctx, req)
```

### 3. Custom Progress Handler

Implement your own progress handler for web apps, desktop apps, or any custom UI:

```go
import (
    "github.com/valllabh/domain-scan/pkg/domainscan"
    "github.com/valllabh/domain-scan/pkg/types"
)

// Custom progress handler for your application
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

## Progress Callback Interface

The simplified `ProgressCallback` interface focuses on what users care about:

```go
type ProgressCallback interface {
    OnStart(domains []string, keywords []string)
    OnDomainTraceFound(domain string, totalFound int)
    OnLiveDomainFound(domain string, url string, totalLive int)
    OnEnd(result *AssetDiscoveryResult)
}
```

## Benefits

- **Silent by Default**: No unwanted console output when used as a library
- **Flexible UI**: Implement progress display for any framework (web, desktop, mobile)
- **Separation of Concerns**: Business logic separated from presentation
- **Backward Compatible**: CLI maintains identical functionality and user experience
- **Easy Integration**: Clean SDK interface for other Go applications

## Command Line Usage Unchanged

The command line interface remains exactly the same:

```bash
# All existing commands work identically
domain-scan discover example.com
domain-scan discover example.com --quiet  # Silent mode
domain-scan discover example.com --profile quick
```

The only difference is that `--quiet` mode now truly suppresses all progress output by not setting a progress callback, rather than using a logger that swallows output.