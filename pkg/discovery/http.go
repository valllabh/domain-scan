package discovery

import (
	"context"
	"fmt"
	"sync"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/valllabh/domain-scan/pkg/types"
)

// DomainLivenessTracker interface to avoid circular imports
type DomainLivenessTracker interface {
	IsLivenessCompleted(domain string) bool
	MarkLivenessCompleted(domain string)
}

// HTTPServiceScan scans subdomains for active HTTP services using httpx SDK with progress reporting
func HTTPServiceScan(ctx context.Context, subdomains []string, ports []int, progress ProgressCallback) ([]types.WebAsset, error) {
	return HTTPServiceScanWithTracker(ctx, subdomains, ports, progress, nil)
}

// HTTPServiceScanWithTracker scans subdomains for active HTTP services with liveness tracking optimization
func HTTPServiceScanWithTracker(ctx context.Context, subdomains []string, ports []int, progress ProgressCallback, tracker DomainLivenessTracker) ([]types.WebAsset, error) {
	var webAssets []types.WebAsset
	var mu sync.Mutex
	totalLive := 0

	if len(subdomains) == 0 || len(ports) == 0 {
		return webAssets, nil
	}

	// Create URLs with ports, skipping domains already marked as live if tracker is provided
	var targets []string
	domainsToScan := make(map[string]bool)

	for _, subdomain := range subdomains {
		// Skip domains already marked as live when tracker is available
		if tracker != nil && tracker.IsLivenessCompleted(subdomain) {
			// Domain is already known to be live from certificate analysis
			// Still create a basic web asset for it but skip actual HTTP probing
			for _, port := range ports {
				var url string
				if port == 443 {
					url = fmt.Sprintf("https://%s", subdomain)
				} else if port == 80 {
					url = fmt.Sprintf("http://%s", subdomain)
				} else {
					// For non-standard ports, prefer HTTPS if 443 is in ports list
					scheme := "http"
					for _, p := range ports {
						if p == 443 {
							scheme = "https"
							break
						}
					}
					url = fmt.Sprintf("%s://%s:%d", scheme, subdomain, port)
				}

				// Add a basic asset for already-live domains
				asset := types.WebAsset{
					URL:        url,
					StatusCode: 200, // Assume success since it was live during cert analysis
				}
				webAssets = append(webAssets, asset)
			}
			continue
		}

		domainsToScan[subdomain] = true

		for _, port := range ports {
			// Add http and https versions
			if port == 443 {
				targets = append(targets, fmt.Sprintf("https://%s", subdomain))
			} else if port == 80 {
				targets = append(targets, fmt.Sprintf("http://%s", subdomain))
			} else {
				targets = append(targets, fmt.Sprintf("http://%s:%d", subdomain, port))
				targets = append(targets, fmt.Sprintf("https://%s:%d", subdomain, port))
			}
		}
	}

	// If no targets to scan (all were already live), return early
	if len(targets) == 0 {
		return webAssets, nil
	}

	// Configure httpx options
	options := runner.Options{
		Methods:         "GET",
		StatusCode:      true,
		Silent:          true,
		Threads:         50,
		Timeout:         10,
		InputTargetHost: goflags.StringSlice(targets),
		OnResult: func(r runner.Result) {
			// Handle results
			if r.Err != nil {
				// Skip failed requests
				return
			}

			asset := types.WebAsset{
				URL:        r.URL,
				StatusCode: r.StatusCode,
			}

			mu.Lock()
			webAssets = append(webAssets, asset)
			totalLive++
			currentTotal := totalLive
			mu.Unlock()

			// Mark domain as live in tracker if provided
			if tracker != nil && r.Host != "" {
				tracker.MarkLivenessCompleted(r.Host)
			}

			// Report progress if callback is provided
			if progress != nil {
				// Extract domain from URL for progress reporting
				domain := r.Host
				if domain == "" {
					domain = r.URL
				}
				progress.OnLiveDomainFound(domain, r.URL, currentTotal)
			}
		},
	}

	// Validate options
	if err := options.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("failed to validate httpx options: %w", err)
	}

	// Create httpx runner
	httpxRunner, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("failed to create httpx runner: %w", err)
	}
	defer httpxRunner.Close()

	// Run enumeration
	httpxRunner.RunEnumeration()

	return webAssets, nil
}
