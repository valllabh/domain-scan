package discovery

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/valllabh/domain-scan/pkg/types"
	"github.com/valllabh/domain-scan/pkg/utils"
)

// DomainTracker interface to avoid circular imports
type DomainTracker interface {
	IsCertificateCompleted(domain string, port int) bool
	MarkCertificateCompleted(domain string, port int)
	AddDomain(domain string) bool
}

// CertificateAnalysisSimple performs TLS certificate analysis without tracker interface
func CertificateAnalysisSimple(ctx context.Context, domains []string, ports []int, keywords []string) ([]types.TLSAsset, []types.WebAsset, []string, error) {
	var tlsAssets []types.TLSAsset
	var webAssets []types.WebAsset
	var newDomains []string
	discoveredDomains := make(map[string]bool)


	if len(domains) == 0 {
		return tlsAssets, webAssets, newDomains, nil
	}

	if len(ports) == 0 {
		ports = []int{443, 80} // Default ports for certificate analysis
	}

	for _, domain := range domains {
		// Try HTTPS first (port 443)
		domainTlsAssets, domainWebAssets, domainSubdomains, err := analyzeDomainCertificateOnPort(ctx, domain, 443, keywords)
		if err == nil {
			tlsAssets = append(tlsAssets, domainTlsAssets...)
			webAssets = append(webAssets, domainWebAssets...)

			// Collect newly discovered domains
			for _, discoveredDomain := range domainSubdomains {
				if !discoveredDomains[discoveredDomain] {
					discoveredDomains[discoveredDomain] = true
					newDomains = append(newDomains, discoveredDomain)
				}
			}
		}

		// Try other ports if specified and different from 443
		for _, port := range ports {
			if port == 443 {
				continue // Already tried above
			}

			domainTlsAssets, domainWebAssets, domainSubdomains, err := analyzeDomainCertificateOnPort(ctx, domain, port, keywords)
			if err != nil {
				continue // Skip failed ports
			}

			tlsAssets = append(tlsAssets, domainTlsAssets...)
			webAssets = append(webAssets, domainWebAssets...)

			// Collect newly discovered domains
			for _, discoveredDomain := range domainSubdomains {
				if !discoveredDomains[discoveredDomain] {
					discoveredDomains[discoveredDomain] = true
					newDomains = append(newDomains, discoveredDomain)
				}
			}
		}
	}

	return tlsAssets, webAssets, newDomains, nil
}

// CertificateAnalysis performs TLS certificate analysis to discover subdomains with port-aware tracking
func CertificateAnalysis(ctx context.Context, domains []string, ports []int, keywords []string, tracker DomainTracker) ([]types.TLSAsset, []string, error) {
	var tlsAssets []types.TLSAsset
	var newDomains []string
	discoveredDomains := make(map[string]bool)

	if len(domains) == 0 {
		return tlsAssets, newDomains, nil
	}

	if len(ports) == 0 {
		ports = []int{443, 80} // Default ports for certificate analysis
	}

	for _, domain := range domains {
		for _, port := range ports {
			// Skip if this domain:port combination already analyzed
			if tracker != nil && tracker.IsCertificateCompleted(domain, port) {
				continue
			}

			domainTlsAssets, _, domainSubdomains, err := analyzeDomainCertificateOnPort(ctx, domain, port, keywords)
			if err != nil {
				// Continue with other ports/domains on error
				continue
			}

			tlsAssets = append(tlsAssets, domainTlsAssets...)

			// Mark certificate analysis completed for this domain:port
			if tracker != nil {
				tracker.MarkCertificateCompleted(domain, port)
			}

			// Collect newly discovered domains
			for _, discoveredDomain := range domainSubdomains {
				if !discoveredDomains[discoveredDomain] {
					discoveredDomains[discoveredDomain] = true

					// Add to tracker and collect as new domain if it wasn't already known
					if tracker == nil || tracker.AddDomain(discoveredDomain) {
						newDomains = append(newDomains, discoveredDomain)
					}
				}
			}
		}
	}

	return tlsAssets, newDomains, nil
}

// analyzeDomainCertificateOnPort analyzes TLS certificates for a single domain on a specific port
func analyzeDomainCertificateOnPort(ctx context.Context, domain string, port int, keywords []string) ([]types.TLSAsset, []types.WebAsset, []string, error) {
	var tlsAssets []types.TLSAsset
	var webAssets []types.WebAsset
	var subdomains []string
	var resultMutex sync.Mutex

	if domain == "" {
		return tlsAssets, webAssets, subdomains, nil
	}

	// Create target with port
	target := fmt.Sprintf("%s:%d", domain, port)

	opts := &runner.Options{
		Methods:         "GET",
		StatusCode:      true,
		Silent:          true,
		Timeout:         10,
		Threads:         1, // Single thread for individual domain:port analysis
		TLSProbe:        true,
		InputTargetHost: goflags.StringSlice{target}, // Use target directly
		OnResult: func(result runner.Result) {
			resultMutex.Lock()
			defer resultMutex.Unlock()
			
			// Process ANY successful HTTP response (not just TLS)
			if result.Err == nil && result.StatusCode > 0 {
				webAsset := types.WebAsset{
					URL:        result.URL,
					StatusCode: result.StatusCode,
				}
				webAssets = append(webAssets, webAsset)
			}
			

			// ALSO process TLS certificate data if available
			if result.TLSData != nil {
				// Create TLS asset with port information
				tlsAsset := types.TLSAsset{
					Domain:     fmt.Sprintf("%s:%d", domain, port),
					SubjectANs: result.TLSData.SubjectAN,
					Issuer:     "", // Will be populated from certificate if available
				}
				tlsAssets = append(tlsAssets, tlsAsset)

				// Extract and filter subdomains from Subject Alternative Names
				for _, san := range result.TLSData.SubjectAN {
					// Skip empty or wildcard entries
					if san == "" || strings.HasPrefix(san, "*") {
						continue
					}

					// If no keywords provided, include all domains
					if len(keywords) == 0 {
						subdomains = append(subdomains, san)
						continue
					}

					// Filter domains based on keywords (organization relevance)
					// This filters out domains from other organizations in shared certificates
					isRelevant := false
					for _, keyword := range keywords {
						if containsKeyword(san, keyword) {
							isRelevant = true
							break
						}
					}

					if isRelevant {
						subdomains = append(subdomains, san)
					}
				}
			}
		},
	}

	r, err := runner.New(opts)
	if err != nil {
		return tlsAssets, webAssets, subdomains, fmt.Errorf("error creating httpx runner for %s: %w", target, err)
	}
	defer r.Close()

	// Run enumeration with proper synchronization
	done := make(chan bool, 1)
	go func() {
		r.RunEnumeration()
		done <- true
	}()

	// Wait for completion with timeout
	timeout := time.After(15 * time.Second)
	select {
	case <-done:
		// Wait a bit more for callbacks to complete
		time.Sleep(200 * time.Millisecond)
	case <-timeout:
		// Timeout - return current results
		return tlsAssets, webAssets, subdomains, nil
	case <-ctx.Done():
		// Context cancelled - return current results anyway
		return tlsAssets, webAssets, subdomains, nil
	}
	return tlsAssets, webAssets, subdomains, nil
}

// analyzeDomainCertificate analyzes TLS certificates for a single domain (backward compatibility)
// This function is kept for backward compatibility but internally uses the port-aware version
func analyzeDomainCertificate(ctx context.Context, domain string, keywords []string) ([]types.TLSAsset, []string, error) {
	// Use default HTTPS port for backward compatibility
	tlsAssets, _, subdomains, err := analyzeDomainCertificateOnPort(ctx, domain, 443, keywords)
	return tlsAssets, subdomains, err
}

// containsKeyword checks if a domain contains a specific keyword
// This is used to filter domains from SSL certificates based on organizational relevance
func containsKeyword(domain, keyword string) bool {
	// Convert to lowercase for case-insensitive matching
	keywordLower := strings.ToLower(keyword)

	// Check if keyword matches extracted keywords from the domain (organization level)
	extractedKeywords := utils.ExtractKeywordsFromDomains([]string{domain})
	for _, extracted := range extractedKeywords {
		if strings.ToLower(extracted) == keywordLower {
			return true
		}
	}

	// Also check direct substring match in the organization part only
	// Extract organization name from domain using the same logic as keyword extraction
	orgPart := getOrganizationPart(domain)
	if orgPart != "" {
		orgPartLower := strings.ToLower(orgPart)
		if strings.Contains(orgPartLower, keywordLower) {
			return true
		}
	}

	return false
}

// getOrganizationPart extracts the organization part from a domain name
func getOrganizationPart(domain string) string {
	// Use the same TLD loading logic as in utils package
	// Create a minimal TLD loader here to avoid circular imports
	tlds := map[string]bool{
		// Basic fallback TLDs - in production, this should use the same JSON as utils
		"com": true, "net": true, "org": true, "edu": true, "gov": true, "mil": true,
		"biz": true, "info": true, "name": true, "pro": true, "int": true, "arpa": true,
		"app": true, "dev": true, "ai": true, "uk": true, "us": true, "ca": true,
		"au": true, "de": true, "fr": true, "jp": true, "in": true, "cn": true,
		"br": true, "mx": true, "nz": true, "za": true,

		// Multi-level TLDs
		"co.uk": true, "co.in": true, "co.za": true, "co.nz": true, "co.jp": true,
		"gov.in": true, "gov.uk": true, "gov.au": true, "gov.za": true,
		"ac.uk": true, "ac.in": true, "ac.za": true, "ac.nz": true,
		"com.au": true, "com.br": true, "com.cn": true, "com.mx": true, "com.ar": true,
		"net.au": true, "net.br": true, "net.cn": true, "net.mx": true, "net.nz": true,
		"org.au": true, "org.br": true, "org.cn": true, "org.mx": true, "org.nz": true, "org.za": true,
		"edu.au": true, "edu.br": true, "edu.cn": true, "edu.mx": true,
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}

	// Remove TLD parts from the end
	domainWithoutTLD := parts

	// Check for multi-level TLDs first (longest match)
	if len(parts) >= 3 {
		twoLevelTLD := strings.ToLower(parts[len(parts)-2] + "." + parts[len(parts)-1])
		if tlds[twoLevelTLD] {
			// Remove two-level TLD
			domainWithoutTLD = parts[:len(parts)-2]
		} else if tlds[strings.ToLower(parts[len(parts)-1])] {
			// Remove single-level TLD
			domainWithoutTLD = parts[:len(parts)-1]
		}
	} else if len(parts) == 2 && tlds[strings.ToLower(parts[len(parts)-1])] {
		// Remove single-level TLD
		domainWithoutTLD = parts[:len(parts)-1]
	}

	// Return the last part after removing TLD (organization name)
	if len(domainWithoutTLD) > 0 {
		return domainWithoutTLD[len(domainWithoutTLD)-1]
	}

	return ""
}

// ClassifySisterDomains separates sister domains from subdomains based on organization keywords and TLD analysis
func ClassifySisterDomains(discoveredDomains []string, originalDomains []string, keywords []string) (subdomains []string, sisterDomains []string) {
	originalTLDs := make(map[string]bool)

	// Extract TLDs from original domains
	for _, domain := range originalDomains {
		tld := getTLD(domain)
		if tld != "" {
			originalTLDs[tld] = true
		}
	}

	for _, domain := range discoveredDomains {
		if isSisterDomain(domain, originalTLDs, keywords) {
			sisterDomains = append(sisterDomains, domain)
		} else {
			subdomains = append(subdomains, domain)
		}
	}

	return subdomains, sisterDomains
}

// isSisterDomain determines if a domain is a sister domain (same organization, different TLD)
func isSisterDomain(domain string, originalTLDs map[string]bool, keywords []string) bool {
	// Must contain organization keywords
	hasOrgKeywords := false
	for _, keyword := range keywords {
		if containsKeyword(domain, keyword) {
			hasOrgKeywords = true
			break
		}
	}

	if !hasOrgKeywords {
		return false
	}

	// Must have different TLD from original domains (indicating sister organization)
	domainTLD := getTLD(domain)
	if domainTLD == "" {
		return false
	}

	// If TLD matches any original domain TLD, it's likely a subdomain, not sister domain
	if originalTLDs[domainTLD] {
		return false
	}

	return true // Different TLD + same organization = sister domain
}

// getTLD extracts the top-level domain from a domain name
func getTLD(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return ""
	}

	// Basic TLD extraction - could be enhanced with full TLD list
	// For now, handle common cases
	switch len(parts) {
	case 2:
		return parts[1] // example.com -> com
	case 3:
		// Check for common two-part TLDs
		twoPartTLD := strings.Join(parts[1:], ".")
		commonTwoPartTLDs := []string{
			"co.uk", "co.in", "co.za", "co.jp", "co.nz",
			"com.au", "com.br", "com.cn", "com.mx",
			"gov.uk", "gov.in", "gov.au",
			"ac.uk", "ac.in", "ac.za",
		}

		for _, knownTLD := range commonTwoPartTLDs {
			if twoPartTLD == knownTLD {
				return knownTLD
			}
		}

		// If not a known two-part TLD, assume single-part
		return parts[2]
	default:
		// For longer domains, try two-part TLD first, then single-part
		if len(parts) >= 3 {
			twoPartTLD := strings.Join(parts[len(parts)-2:], ".")
			commonTwoPartTLDs := []string{
				"co.uk", "co.in", "co.za", "co.jp", "co.nz",
				"com.au", "com.br", "com.cn", "com.mx",
				"gov.uk", "gov.in", "gov.au",
				"ac.uk", "ac.in", "ac.za",
			}

			for _, knownTLD := range commonTwoPartTLDs {
				if twoPartTLD == knownTLD {
					return knownTLD
				}
			}
		}

		// Default to last part
		return parts[len(parts)-1]
	}
}
