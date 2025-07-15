package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/valllabh/domain-scan/pkg/domainscan"
)

func main() {
	// Create enterprise configuration
	config := &domainscan.Config{
		Discovery: domainscan.DiscoveryConfig{
			Timeout:            30 * time.Second,
			Threads:            100,
			PassiveEnabled:     true,
			CertificateEnabled: true,
			HTTPEnabled:        true,
		},
		Keywords: []string{},
	}

	// Create scanner with enterprise config
	scanner := domainscan.New(config)

	// Define enterprise domains to scan
	domains := []string{
		"corp.example.com",
		"internal.example.com",
		"enterprise.example.com",
	}

	// Create comprehensive scan request
	req := &domainscan.ScanRequest{
		Domains:        domains,
		Keywords:       config.Keywords,
		Timeout:        config.Discovery.Timeout,
		EnablePassive:  true,
		EnableCertScan: true,
		EnableHTTPScan: true,
	}

	fmt.Println("🏢 Starting Enterprise Asset Discovery")
	fmt.Printf("Domains: %v\n", domains)
	fmt.Printf("Keywords: %v\n", req.Keywords)
	fmt.Printf("Timeout: %v\n\n", req.Timeout)

	// Execute scan
	result, err := scanner.ScanWithOptions(context.Background(), req)
	if err != nil {
		log.Fatalf("Enterprise discovery failed: %v", err)
	}

	// Generate enterprise report
	generateEnterpriseReport(result)
}

func generateEnterpriseReport(result *domainscan.AssetDiscoveryResult) {
	fmt.Printf("\n📋 Enterprise Asset Discovery Report\n")
	fmt.Printf("====================================\n\n")

	// Executive summary
	fmt.Printf("📊 Executive Summary:\n")
	fmt.Printf("- Discovery Duration: %v\n", result.Statistics.Duration)
	fmt.Printf("- Total Subdomains Found: %d\n", result.Statistics.TotalSubdomains)
	fmt.Printf("- Active Web Services: %d\n", result.Statistics.ActiveServices)
	fmt.Printf("- Targets Scanned: %d\n", result.Statistics.TargetsScanned)
	fmt.Printf("- Passive Sources: %d results\n", result.Statistics.PassiveResults)
	fmt.Printf("- Certificate Analysis: %d results\n", result.Statistics.CertificateResults)
	fmt.Printf("- HTTP Verification: %d results\n\n", result.Statistics.HTTPResults)

	// Active services by status code
	fmt.Printf("🌐 Active Services by Status:\n")
	statusCounts := make(map[int]int)
	for _, entry := range result.Domains {
		if entry.IsLive {
			statusCounts[entry.Status]++
		}
	}
	for status, count := range statusCounts {
		fmt.Printf("- HTTP %d: %d services\n", status, count)
	}
	fmt.Println()

	// TLS certificate information (simplified for new structure)
	fmt.Printf("🔐 TLS Certificate Analysis:\n")
	httpsDomains := 0
	for _, entry := range result.Domains {
		if strings.HasPrefix(entry.Domain, "https://") {
			httpsDomains++
		}
	}
	fmt.Printf("- HTTPS enabled domains: %d\n\n", httpsDomains)

	// High-value targets (example keywords for demonstration)
	fmt.Printf("🎯 High-Value Targets:\n")
	highValueKeywords := []string{"portal", "intranet", "internal"}
	for _, entry := range result.Domains {
		if entry.IsLive {
			for _, keyword := range highValueKeywords {
				if containsKeyword(entry.Domain, keyword) {
					fmt.Printf("- %s [%d] - Contains '%s'\n", entry.Domain, entry.Status, keyword)
					break
				}
			}
		}
	}
	fmt.Println()

	// All discovered services
	fmt.Printf("📝 Complete Service Inventory:\n")
	for _, entry := range result.Domains {
		if entry.IsLive {
			fmt.Printf("- %s [%d]\n", entry.Domain, entry.Status)
		}
	}

	// Error summary
	if len(result.Errors) > 0 {
		fmt.Printf("\n⚠️  Issues Encountered:\n")
		for _, err := range result.Errors {
			fmt.Printf("- %v\n", err)
		}
	}
}

func containsKeyword(url, keyword string) bool {
	return len(url) > 0 && len(keyword) > 0 &&
		strings.Contains(strings.ToLower(url), strings.ToLower(keyword))
}
