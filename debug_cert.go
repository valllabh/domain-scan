package main

import (
	"context"
	"fmt"

	"github.com/valllabh/domain-scan/pkg/discovery"
)

func main() {
	ctx := context.Background()
	domains := []string{"apple.com"}
	ports := []int{443}
	keywords := []string{"apple"}

	fmt.Printf("Testing certificate analysis for: %v\n", domains)
	fmt.Printf("Ports: %v\n", ports)
	fmt.Printf("Keywords: %v\n", keywords)

	tlsAssets, webAssets, newDomains, err := discovery.CertificateAnalysisSimple(ctx, domains, ports, keywords)
	
	fmt.Printf("\nResults:\n")
	fmt.Printf("Error: %v\n", err)
	fmt.Printf("TLS Assets: %d\n", len(tlsAssets))
	fmt.Printf("Web Assets: %d\n", len(webAssets))
	fmt.Printf("New Domains: %d\n", len(newDomains))

	if len(webAssets) > 0 {
		fmt.Printf("\nWeb Assets:\n")
		for i, asset := range webAssets {
			fmt.Printf("  %d: %s (status: %d)\n", i+1, asset.URL, asset.StatusCode)
		}
	}

	if len(tlsAssets) > 0 {
		fmt.Printf("\nTLS Assets:\n")
		for i, asset := range tlsAssets {
			fmt.Printf("  %d: %s (SANs: %v)\n", i+1, asset.Domain, asset.SubjectANs)
		}
	}

	if len(newDomains) > 0 {
		fmt.Printf("\nNew Domains:\n")
		for i, domain := range newDomains {
			fmt.Printf("  %d: %s\n", i+1, domain)
		}
	}
}