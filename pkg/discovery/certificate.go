package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/valllabh/domain-scan/pkg/types"
	"github.com/valllabh/domain-scan/pkg/utils"
	"github.com/projectdiscovery/httpx/runner"
)

// CertificateAnalysis performs TLS certificate analysis to discover subdomains
func CertificateAnalysis(ctx context.Context, domains []string, keywords []string) ([]types.TLSAsset, []string, error) {
	var tlsAssets []types.TLSAsset
	var subdomains []string
	subdomainMap := make(map[string]bool)

	if len(domains) == 0 {
		return tlsAssets, subdomains, nil
	}

	for _, domain := range domains {
		domainAssets, domainSubdomains, err := analyzeDomainCertificate(ctx, domain, keywords)
		if err != nil {
			return tlsAssets, subdomains, fmt.Errorf("error analyzing domain %s: %w", domain, err)
		}

		tlsAssets = append(tlsAssets, domainAssets...)
		
		// Deduplicate subdomains
		for _, subdomain := range domainSubdomains {
			if !subdomainMap[subdomain] {
				subdomainMap[subdomain] = true
				subdomains = append(subdomains, subdomain)
			}
		}
	}

	return tlsAssets, subdomains, nil
}

// analyzeDomainCertificate analyzes TLS certificates for a single domain
func analyzeDomainCertificate(ctx context.Context, domain string, keywords []string) ([]types.TLSAsset, []string, error) {
	var tlsAssets []types.TLSAsset
	var subdomains []string

	if domain == "" {
		return tlsAssets, subdomains, nil
	}

	opts := &runner.Options{
		Timeout:  10,
		Threads:  10,
		TLSProbe: true,
		OnResult: func(result runner.Result) {
			if result.TLSData != nil {
				// Create TLS asset
				tlsAsset := types.TLSAsset{
					Domain:     domain,
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
		return tlsAssets, subdomains, fmt.Errorf("error creating httpx runner: %w", err)
	}
	defer r.Close()

	// Process the domain with context
	select {
	case <-ctx.Done():
		return tlsAssets, subdomains, ctx.Err()
	default:
		r.RunEnumeration()
	}

	return tlsAssets, subdomains, nil
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