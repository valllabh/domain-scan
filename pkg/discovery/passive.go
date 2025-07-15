package discovery

import (
	"context"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"go.uber.org/zap"
)

// PassiveDiscoveryWithLogger performs passive subdomain discovery using subfinder SDK with logging
func PassiveDiscoveryWithLogger(ctx context.Context, domains []string, logger *zap.SugaredLogger) ([]string, error) {
	// Use a map to track unique subdomains and avoid duplicates
	uniqueSubdomains := make(map[string]bool)

	if len(domains) == 0 {
		return nil, nil
	}

	if logger != nil {
		logger.Infof("Starting passive discovery for %d domains", len(domains))
		logger.Debugf("Domains to process: %v", domains)
	}

	// Create subfinder options with ResultCallback for memory-efficient progress reporting
	options := &runner.Options{
		Threads:            10,         // Reasonable default for concurrent enumeration
		Timeout:            30,         // 30 second timeout per source
		MaxEnumerationTime: 10,         // 10 minute max per domain
		Resolvers:          []string{}, // Use default resolvers
		All:                true,       // Use all available sources
		Verbose:            false,      // Disable verbose logging
		RemoveWildcard:     false,      // Don't remove wildcards (faster)
		CaptureSources:     false,      // Don't capture source information
		ResultCallback: func(result *resolve.HostEntry) {
			// Only add if not already seen (deduplication)
			if !uniqueSubdomains[result.Host] {
				uniqueSubdomains[result.Host] = true
				if logger != nil {
					logger.Debugf("Found subdomain: %s (total unique: %d)", result.Host, len(uniqueSubdomains))
				}
			}
		},
	}

	// Initialize subfinder runner
	if logger != nil {
		logger.Debugf("Initializing subfinder runner for %d domains", len(domains))
	}
	subfinderRunner, err := runner.NewRunner(options)
	if err != nil {
		if logger != nil {
			logger.Errorf("Failed to initialize subfinder runner: %v", err)
		}
		return nil, err
	}

	// Run enumeration with context using EnumerateMultipleDomainsWithCtx for bulk processing
	if logger != nil {
		logger.Debugf("Starting bulk enumeration for domains: %v", domains)
	}

	// Convert domains slice to io.Reader (one domain per line)
	domainsText := strings.Join(domains, "\n")
	domainsReader := strings.NewReader(domainsText)

	err = subfinderRunner.EnumerateMultipleDomainsWithCtx(ctx, domainsReader, nil)
	if err != nil {
		if logger != nil {
			logger.Errorf("Bulk enumeration failed: %v", err)
		}
		return nil, err
	}

	if logger != nil {
		logger.Debugf("Bulk enumeration completed successfully")
	}

	// Convert map keys to slice for return
	subdomains := make([]string, 0, len(uniqueSubdomains))
	for subdomain := range uniqueSubdomains {
		subdomains = append(subdomains, subdomain)
	}

	if logger != nil {
		logger.Infof("Passive discovery completed: found %d unique subdomains", len(subdomains))
		if len(subdomains) > 0 {
			logger.Debugf("First few subdomains found: %v", subdomains[:min(5, len(subdomains))])
		}
	}

	return subdomains, nil
}
