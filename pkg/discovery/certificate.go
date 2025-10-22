package discovery

import (
	"context"
	"fmt"
	"sync"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/valllabh/domain-scan/pkg/types"
	"github.com/valllabh/domain-scan/pkg/utils"
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
// If extractNewDomains is false, it will load certificate info but NOT extract new domains from SANs
func BulkCertificateAnalysisForScanner(ctx context.Context, targets []string, keywords []string, extractNewDomains bool, logger *gologger.Logger) ([]*types.DomainEntry, []string, error) {
	var domainEntries []*types.DomainEntry
	var subdomains []string
	var resultMutex sync.Mutex

	// Map to track domain entries by target
	domainEntriesMap := make(map[string]*types.DomainEntry)

	if len(targets) == 0 {
		return domainEntries, subdomains, nil
	}

	if logger != nil {
		logger.Info().Msgf("Starting bulk HTTP/TLS analysis for %d targets", len(targets))
		logger.Debug().Msgf("Bulk targets: %v", targets)
	}

	// Pre-populate all targets as non-live domains with passive source
	// httpx will update these if they respond
	for _, target := range targets {
		bareDomain := utils.ExtractBareDomain(target)
		domainEntriesMap[bareDomain] = &types.DomainEntry{
			Domain:  bareDomain,
			Status:  0,
			IsLive:  false,
			Sources: []types.Source{{Name: "traced", Type: "passive"}},
		}
	}

	// Create httpx runner options for bulk processing
	opts := &runner.Options{
		Methods:         "GET",
		StatusCode:      true,
		ProbeAllIPS:     false,
		Timeout:         10,
		Threads:         50, // Use reasonable thread count instead of len(targets)
		TLSGrab:         true,
		FollowRedirects: true, // Enable redirect following to capture FinalURL
		MaxRedirects:    10,   // Follow up to 10 redirects
		InputTargetHost: goflags.StringSlice(targets), // Use all targets in bulk
		OnResult: func(result runner.Result) {
			resultMutex.Lock()
			defer resultMutex.Unlock()

			if logger != nil {
				logger.Debug().Msgf("Processing result for %s: status=%d, error=%v", result.URL, result.StatusCode, result.Err)
			}

			// Extract bare domain from URL to use as map key
			bareDomain := utils.ExtractBareDomain(result.URL)

			// Get existing domain entry for this domain (should always exist due to pre-population)
			domainEntry, exists := domainEntriesMap[bareDomain]
			if !exists {
				// Fallback if domain wasn't pre-populated
				domainEntry = &types.DomainEntry{
					Domain:  bareDomain,
					Status:  0,
					IsLive:  false,
					Sources: []types.Source{{Name: "traced", Type: "passive"}},
				}
				domainEntriesMap[bareDomain] = domainEntry
			}

			// Process ANY successful HTTP response
			if result.Err == nil && result.StatusCode > 0 {
				domainEntry.IsLive = true
				domainEntry.Status = result.StatusCode
				domainEntry.URL = result.URL // Store the full URL (http:// or https://)

				// Capture IP address if available
				if len(result.A) > 0 {
					domainEntry.IP = result.A[0] // Use first IPv4 address
				}

				// Capture redirect information if domain redirects
				isRedirectStatus := result.StatusCode >= 300 && result.StatusCode < 400
				hasRedirectChain := len(result.ChainStatusCodes) > 0

				// Check if there's a redirect by looking at FinalURL, redirect status, or chain
				if isRedirectStatus || hasRedirectChain || (result.FinalURL != "" && result.FinalURL != result.URL) {
					finalURL := result.FinalURL
					if finalURL == "" || finalURL == result.URL {
						// If FinalURL is empty/same, use Location header or mark as unknown
						finalURL = result.Location
					}

					statusCodes := result.ChainStatusCodes
					if len(statusCodes) == 0 && isRedirectStatus {
						statusCodes = []int{result.StatusCode}
					}

					domainEntry.Redirect = &types.RedirectInfo{
						IsRedirect:  true,
						RedirectsTo: finalURL,
						StatusCodes: statusCodes,
					}

					if logger != nil {
						logger.Debug().Msgf("Redirect detected: %s -> %s (codes: %v, chainLen: %d)",
							result.URL, finalURL, statusCodes, len(result.Chain))
					}
				}

				// Add httpx as source for live domain
				addSource(domainEntry, "httpx", "http")

				if logger != nil {
					logger.Debug().Msgf("Updated domain entry: %s (url: %s, status: %d, live: %t, ip: %s)", bareDomain, result.URL, result.StatusCode, true, domainEntry.IP)
				}
			}

			// ALSO process TLS certificate data if available
			if result.TLSData != nil {
				if logger != nil {
					logger.Debug().Msgf("Processing TLS data for %s", result.URL)
				}

				// Add certificate as source
				addSource(domainEntry, "certificate", "certificate")

				// Capture certificate metadata (always load this)
				domainEntry.Certificate = &types.CertificateInfo{
					IssuedOn:  result.TLSData.NotBefore,
					ExpiresOn: result.TLSData.NotAfter,
					Issuer:    result.TLSData.IssuerCN,
					Subject:   result.TLSData.SubjectCN,
				}

				// Only extract new domains from SANs if extractNewDomains is true
				if extractNewDomains {
					// Filter SubjectANs based on keywords and collect subdomains
					for _, san := range result.TLSData.SubjectAN {
						if utils.MatchesKeywords(san, keywords) {
							subdomains = append(subdomains, san)
						}
					}

					if logger != nil {
						logger.Debug().Msgf("Processed TLS data for %s: %d SANs found", bareDomain, len(result.TLSData.SubjectAN))
					}
				} else {
					if logger != nil {
						logger.Debug().Msgf("Certificate info loaded for %s (domain extraction disabled)", bareDomain)
					}
				}
			}
		},
	}

	// Validate options before creating runner
	if err := opts.ValidateOptions(); err != nil {
		if logger != nil {
			logger.Error().Msgf("Failed to validate httpx options: %v", err)
		}
		return domainEntries, subdomains, fmt.Errorf("failed to validate httpx options: %v", err)
	}

	// Create and run httpx runner
	httpxRunner, err := runner.New(opts)
	if err != nil {
		if logger != nil {
			logger.Error().Msgf("Failed to create httpx runner: %v", err)
		}
		return domainEntries, subdomains, fmt.Errorf("failed to create httpx runner: %v", err)
	}
	defer httpxRunner.Close()

	// Execute bulk scan
	if logger != nil {
		logger.Info().Msgf("Executing bulk httpx scan for %d targets", len(targets))
	}

	httpxRunner.RunEnumeration()

	// Convert map to slice
	for _, entry := range domainEntriesMap {
		domainEntries = append(domainEntries, entry)
	}

	if logger != nil {
		logger.Info().Msgf("Bulk analysis completed: %d domain entries, %d subdomains",
			len(domainEntries), len(subdomains))
	}

	return domainEntries, subdomains, nil
}
