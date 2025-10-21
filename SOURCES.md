# Source Tracking Feature

domain-scan now tracks the discovery source for each domain, allowing you to understand how and where each domain was found.

## Overview

Each domain entry includes a `sources` array that tracks all discovery methods that found that domain. A single domain can be discovered by multiple sources, providing higher confidence in its validity.

## Source Types

| Source Name | Type | Description |
|------------|------|-------------|
| `subfinder` | `passive` | Found via passive DNS enumeration from public sources |
| `certificate` | `certificate` | Found in TLS certificate Subject Alternative Names (SANs) |
| `httpx` | `http` | Verified as live via HTTP/HTTPS probe |

## Output Formats

### 1. domains.json (Default Output)

Located at `./result/{domain}/domains.json`

```json
{
  "domains": {
    "https://blog.example.com": {
      "domain": "https://blog.example.com",
      "status": 200,
      "is_live": true,
      "ip": "93.184.216.34",
      "sources": [
        {"name": "subfinder", "type": "passive"},
        {"name": "certificate", "type": "certificate"},
        {"name": "httpx", "type": "http"}
      ]
    },
    "https://example.com": {
      "domain": "https://example.com",
      "status": 200,
      "is_live": true,
      "ip": "93.184.216.34",
      "sources": [
        {"name": "subfinder", "type": "passive"},
        {"name": "httpx", "type": "http"}
      ]
    }
  }
}
```

### 2. CLI JSON Output

Using `--format json` flag:

```bash
./domain-scan discover example.com --format json
```

Returns the full scan result including sources in the same format as domains.json.

## SDK Usage

### Basic Access

```go
scanner := domainscan.New(nil)
result, _ := scanner.DiscoverAssets(ctx, []string{"example.com"})

for domain, entry := range result.Domains {
    fmt.Printf("Domain: %s\n", domain)
    for _, src := range entry.Sources {
        fmt.Printf("  - Found via %s (%s)\n", src.Name, src.Type)
    }
}
```

### Filter by Source Type

```go
// Find all domains discovered via passive enumeration
var passiveDomains []string
for domain, entry := range result.Domains {
    for _, src := range entry.Sources {
        if src.Type == "passive" {
            passiveDomains = append(passiveDomains, domain)
            break
        }
    }
}
```

### High Confidence Filtering

```go
// Domains found by multiple sources have higher confidence
var highConfidenceDomains []string
for domain, entry := range result.Domains {
    if len(entry.Sources) >= 2 {
        highConfidenceDomains = append(highConfidenceDomains, domain)
    }
}
```

### Source Statistics

```go
// Count domains by source
sourceStats := make(map[string]int)
for _, entry := range result.Domains {
    for _, src := range entry.Sources {
        sourceStats[src.Name]++
    }
}

for source, count := range sourceStats {
    fmt.Printf("%s: %d domains\n", source, count)
}
```

## CLI Examples

### Basic Scan with Sources

```bash
# Scan and view domains.json
./domain-scan discover example.com
cat result/example.com/domains.json | jq '.domains."https://blog.example.com".sources'
```

### JSON Output to File

```bash
# Save full results with sources
./domain-scan discover example.com --format json --output results.json
cat results.json | jq '.domains | to_entries | .[0].value.sources'
```

### Quiet Mode JSON

```bash
# Get clean JSON output
./domain-scan discover example.com --format json --quiet
```

## Use Cases

1. **Attribution**: Know exactly how each domain was discovered
2. **Confidence Scoring**: Prioritize domains found by multiple sources
3. **Method Analysis**: Understand which discovery methods are most effective
4. **Filtering**: Focus on specific discovery types (e.g., only passive results)
5. **Auditing**: Track the complete discovery chain for compliance

## Example Scenarios

### Scenario 1: Only Passive Discovery
Domain found via subfinder but not verified live yet:
```json
{
  "sources": [
    {"name": "subfinder", "type": "passive"}
  ]
}
```

### Scenario 2: Certificate Discovery
Domain found in TLS certificate and verified:
```json
{
  "sources": [
    {"name": "certificate", "type": "certificate"},
    {"name": "httpx", "type": "http"}
  ]
}
```

### Scenario 3: Multiple Sources (High Confidence)
Domain found via all methods:
```json
{
  "sources": [
    {"name": "subfinder", "type": "passive"},
    {"name": "certificate", "type": "certificate"},
    {"name": "httpx", "type": "http"}
  ]
}
```

## Integration

The sources field is automatically included in all outputs, so any tool consuming domain-scan results gets this information without configuration.

For programmatic access, use the SDK as shown above or parse the JSON output from CLI.
