package main

import (
	"context"
	"fmt"
	"log"

	"github.com/valllabh/domain-scan/pkg/domainscan"
)

func main() {
	// Create a scanner with default configuration
	scanner := domainscan.New(domainscan.DefaultConfig())

	// Perform asset discovery
	result, err := scanner.DiscoverAssets(context.Background(), []string{"example.com"})
	if err != nil {
		log.Fatalf("Discovery failed: %v", err)
	}

	// Display results
	fmt.Printf("🔍 Domain Asset Discovery Results\n")
	fmt.Printf("================================\n\n")

	fmt.Printf("📊 Statistics:\n")
	fmt.Printf("- Total subdomains: %d\n", result.Statistics.TotalSubdomains)
	fmt.Printf("- Active services: %d\n", result.Statistics.ActiveServices)
	fmt.Printf("- Passive results: %d\n", result.Statistics.PassiveResults)
	fmt.Printf("- Certificate results: %d\n", result.Statistics.CertificateResults)
	fmt.Printf("- HTTP results: %d\n", result.Statistics.HTTPResults)
	fmt.Printf("- Duration: %v\n\n", result.Statistics.Duration)

	fmt.Printf("🌐 Active Web Services:\n")
	for _, service := range result.ActiveServices {
		fmt.Printf("- %s [%d]\n", service.URL, service.StatusCode)
	}

	if len(result.Errors) > 0 {
		fmt.Printf("\n⚠️  Errors encountered:\n")
		for _, err := range result.Errors {
			fmt.Printf("- %v\n", err)
		}
	}
}