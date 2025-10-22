package discovery

import (
	"context"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// PassiveDiscoveryWithLogger performs passive subdomain discovery using subfinder SDK with logging
func PassiveDiscoveryWithLogger(ctx context.Context, domains []string, logger *gologger.Logger) ([]string, error) {
	return PassiveDiscoveryWithOptions(ctx, domains, []string{}, logger)
}

// PassiveDiscoveryWithOptions performs passive subdomain discovery with configurable sources
func PassiveDiscoveryWithOptions(ctx context.Context, domains []string, sources []string, logger *gologger.Logger) ([]string, error) {
	// Use a map to track unique subdomains and avoid duplicates
	uniqueSubdomains := make(map[string]bool)

	if len(domains) == 0 {
		return nil, nil
	}

	if logger != nil {
		logger.Info().Msgf("Starting passive discovery for %d domains", len(domains))
		logger.Debug().Msgf("Domains to process: %v", domains)
	}

	// Create subfinder options with ResultCallback for memory-efficient progress reporting
	options := &runner.Options{
		Threads:            10,         // Reasonable default for concurrent enumeration
		Timeout:            30,         // 30 second timeout per source
		MaxEnumerationTime: 10,         // 10 minute max per domain
		Resolvers:          []string{}, // Use default resolvers
		All:                len(sources) == 0, // Use all sources if none specified
		Sources:            sources,    // Specific sources to use
		Verbose:            false,      // Disable verbose logging
		RemoveWildcard:     false,      // Don't remove wildcards (faster)
		CaptureSources:     false,      // Don't capture source information
		ResultCallback: func(result *resolve.HostEntry) {
			// Only add if not already seen (deduplication)
			if !uniqueSubdomains[result.Host] {
				uniqueSubdomains[result.Host] = true
				if logger != nil {
					logger.Debug().Msgf("Found subdomain: %s (total unique: %d)", result.Host, len(uniqueSubdomains))
				}
			}
		},
	}

	// Initialize subfinder runner
	if logger != nil {
		logger.Debug().Msgf("Initializing subfinder runner for %d domains", len(domains))
	}
	subfinderRunner, err := runner.NewRunner(options)
	if err != nil {
		if logger != nil {
			logger.Error().Msgf("Failed to initialize subfinder runner: %v", err)
		}
		return nil, err
	}

	// Run enumeration with context using EnumerateMultipleDomainsWithCtx for bulk processing
	if logger != nil {
		logger.Debug().Msgf("Starting bulk enumeration for domains: %v", domains)
	}

	// Convert domains slice to io.Reader (one domain per line)
	domainsText := strings.Join(domains, "\n")
	domainsReader := strings.NewReader(domainsText)

	err = subfinderRunner.EnumerateMultipleDomainsWithCtx(ctx, domainsReader, nil)
	if err != nil {
		if logger != nil {
			logger.Error().Msgf("Bulk enumeration failed: %v", err)
		}
		return nil, err
	}

	if logger != nil {
		logger.Debug().Msgf("Bulk enumeration completed successfully")
	}

	// Convert map keys to slice for return
	subdomains := make([]string, 0, len(uniqueSubdomains))
	for subdomain := range uniqueSubdomains {
		subdomains = append(subdomains, subdomain)
	}

	if logger != nil {
		logger.Info().Msgf("Passive discovery completed: found %d unique subdomains", len(subdomains))
		if len(subdomains) > 0 {
			logger.Debug().Msgf("First few subdomains found: %v", subdomains[:min(5, len(subdomains))])
		}
	}

	return subdomains, nil
}
