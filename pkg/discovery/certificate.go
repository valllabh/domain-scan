package discovery

import (
	"context"
	"fmt"
	"sync"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/valllabh/domain-scan/pkg/types"
	"github.com/valllabh/domain-scan/pkg/utils"
	"go.uber.org/zap"
)

// addSource adds a source to a domain entry, avoiding duplicates
func addSource(entry *types.DomainEntry, name string, sourceType string) {
	// Check if source already exists
	for _, src := range entry.Sources {
		if src.Name == name && src.Type == sourceType {
			return
		}
	}
	// Add new source
	entry.Sources = append(entry.Sources, types.Source{
		Name: name,
		Type: sourceType,
	})
}

// BulkCertificateAnalysisForScanner analyzes TLS certificates for multiple targets using bulk httpx call
func BulkCertificateAnalysisForScanner(ctx context.Context, targets []string, keywords []string, logger *zap.SugaredLogger) ([]*types.DomainEntry, []string, error) {
	var domainEntries []*types.DomainEntry
	var subdomains []string
	var resultMutex sync.Mutex

	// Map to track domain entries by target
	domainEntriesMap := make(map[string]*types.DomainEntry)

	if len(targets) == 0 {
		return domainEntries, subdomains, nil
	}

	if logger != nil {
		logger.Infof("Starting bulk HTTP/TLS analysis for %d targets", len(targets))
		logger.Debugf("Bulk targets: %v", targets)
	}

	// Create httpx runner options for bulxk processing
	opts := &runner.Options{
		Methods:         "GET",
		StatusCode:      true,
		ProbeAllIPS:     false,
		Timeout:         10,
		Threads:         50, // Use reasonable thread count instead of len(targets)
		TLSGrab:         true,
		InputTargetHost: goflags.StringSlice(targets), // Use all targets in bulk
		OnResult: func(result runner.Result) {
			resultMutex.Lock()
			defer resultMutex.Unlock()

			if logger != nil {
				logger.Debugf("Processing result for %s: status=%d, error=%v", result.URL, result.StatusCode, result.Err)
			}

			// Use result host as target key to maintain consistency with scanner expectations
			target := result.URL

			// Get or create domain entry for this target
			domainEntry, exists := domainEntriesMap[target]
			if !exists {
				domainEntry = &types.DomainEntry{
					Domain:  target,
					Status:  0,
					IsLive:  false,
					Sources: []types.Source{},
				}
				domainEntriesMap[target] = domainEntry
			}

			// Process ANY successful HTTP response
			if result.Err == nil && result.StatusCode > 0 {
				domainEntry.IsLive = true
				domainEntry.Status = result.StatusCode

				// Capture IP address if available
				if len(result.A) > 0 {
					domainEntry.IP = result.A[0] // Use first IPv4 address
				}

				// Add httpx as source for live domain
				addSource(domainEntry, "httpx", "http")

				if logger != nil {
					logger.Debugf("Updated domain entry: %s (status: %d, live: %t, ip: %s)", target, result.StatusCode, true, domainEntry.IP)
				}
			}

			// ALSO process TLS certificate data if available
			if result.TLSData != nil {
				if logger != nil {
					logger.Debugf("Processing TLS data for %s", result.URL)
				}

				// Add certificate as source
				addSource(domainEntry, "certificate", "certificate")

				// Filter SubjectANs based on keywords and collect subdomains
				for _, san := range result.TLSData.SubjectAN {
					if utils.MatchesKeywords(san, keywords) {
						subdomains = append(subdomains, san)
					}
				}

				if logger != nil {
					logger.Debugf("Processed TLS data for %s: %d SANs found", target, len(result.TLSData.SubjectAN))
				}
			}
		},
	}

	// Validate options before creating runner
	if err := opts.ValidateOptions(); err != nil {
		if logger != nil {
			logger.Errorf("Failed to validate httpx options: %v", err)
		}
		return domainEntries, subdomains, fmt.Errorf("failed to validate httpx options: %v", err)
	}

	// Create and run httpx runner
	httpxRunner, err := runner.New(opts)
	if err != nil {
		if logger != nil {
			logger.Errorf("Failed to create httpx runner: %v", err)
		}
		return domainEntries, subdomains, fmt.Errorf("failed to create httpx runner: %v", err)
	}
	defer httpxRunner.Close()

	// Execute bulk scan
	if logger != nil {
		logger.Infof("Executing bulk httpx scan for %d targets", len(targets))
	}

	httpxRunner.RunEnumeration()

	// Convert map to slice
	for _, entry := range domainEntriesMap {
		domainEntries = append(domainEntries, entry)
	}

	if logger != nil {
		logger.Infof("Bulk analysis completed: %d domain entries, %d subdomains",
			len(domainEntries), len(subdomains))
	}

	return domainEntries, subdomains, nil
}
