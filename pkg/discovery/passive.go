package discovery

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// ProgressCallback defines the interface for progress reporting during discovery
// This is kept for backward compatibility but is no longer used in the queue-based system
type ProgressCallback interface {
	// OnDomainTraceFound is called when any domain is discovered
	OnDomainTraceFound(domain string, totalFound int)

	// OnLiveDomainFound is called when a live domain is verified
	OnLiveDomainFound(domain string, url string, totalLive int)
}

// PassiveDiscovery performs passive subdomain discovery using subfinder SDK with progress reporting
func PassiveDiscovery(ctx context.Context, domains []string, progress ProgressCallback) ([]string, error) {
	var subdomains []string
	totalFound := 0

	if len(domains) == 0 {
		return subdomains, nil
	}

	// Enumerate subdomains for each domain
	for _, domain := range domains {
		// Create subfinder options with ResultCallback for memory-efficient progress reporting
		options := &runner.Options{
			Threads:            10,         // Reasonable default for concurrent enumeration
			Timeout:            30,         // 30 second timeout per source
			MaxEnumerationTime: 10,         // 10 minute max per domain
			Resolvers:          []string{}, // Use default resolvers
			All:                true,       // Use all available sources
			Silent:             true,       // Silent mode for clean output
			Verbose:            false,      // Disable verbose logging
			RemoveWildcard:     false,      // Don't remove wildcards (faster)
			CaptureSources:     false,      // Don't capture source information
			ResultCallback: func(result *resolve.HostEntry) {
				// This callback is called for each unique subdomain found
				subdomains = append(subdomains, result.Host)
				totalFound++

				// Report progress if callback is provided
				if progress != nil {
					progress.OnDomainTraceFound(result.Host, totalFound)
				}
			},
		}

		// Initialize subfinder runner
		subfinderRunner, err := runner.NewRunner(options)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize subfinder: %w", err)
		}

		// Run enumeration with context - no writers needed since we use ResultCallback
		_, err = subfinderRunner.EnumerateSingleDomainWithCtx(ctx, domain, nil)
		if err != nil {
			// Continue with other domains if one fails
			continue
		}
	}

	return subdomains, nil
}
