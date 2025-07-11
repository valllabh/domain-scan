package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/domain-scan/domain-scan/pkg/types"
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

				// Extract subdomains from Subject Alternative Names
				for _, san := range result.TLSData.SubjectAN {
					if strings.Contains(san, domain) {
						continue // skip parent domain
					}

					// Check if the SAN contains any of the keywords
					for _, kw := range keywords {
						if strings.Contains(san, kw) {
							subdomains = append(subdomains, san)
							break
						}
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