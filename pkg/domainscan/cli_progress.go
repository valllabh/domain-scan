package domainscan

import (
	"fmt"
	"strings"
	"time"
)

// CLIProgressHandler implements ProgressCallback for command line interface
type CLIProgressHandler struct {
	startTime    time.Time
	totalDomains int
	liveDomains  int
}

// NewCLIProgressHandler creates a new CLI progress handler
func NewCLIProgressHandler() *CLIProgressHandler {
	return &CLIProgressHandler{
		startTime: time.Now(),
	}
}

// OnStart is called when domain asset discovery begins
func (c *CLIProgressHandler) OnStart(domains []string, keywords []string) {
	c.startTime = time.Now()

	fmt.Printf("🔍 Starting domain discovery for %d domains\n", len(domains))
	if len(keywords) > 0 {
		fmt.Printf("🔑 Using keywords: %s\n", strings.Join(keywords, ", "))
	}
	fmt.Printf("\n")
}

// OnProgress is called with unified progress updates
func (c *CLIProgressHandler) OnProgress(totalDomains, liveDomains int) {
	c.totalDomains = totalDomains
	c.liveDomains = liveDomains

	fmt.Printf("Progress: %d domains discovered, %d live services\n", totalDomains, liveDomains)
}

// OnEnd is called when the entire scan finishes
func (c *CLIProgressHandler) OnEnd(result *AssetDiscoveryResult) {
	duration := time.Since(c.startTime)
	fmt.Printf("✅ Discovery completed in %v\n", duration)
	fmt.Printf("📊 Results: %d domains, %d live services\n\n",
		result.Statistics.TotalSubdomains, result.Statistics.ActiveServices)
}
