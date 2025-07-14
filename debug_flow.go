package main

import (
	"context"
	"fmt"
	"os"

	"github.com/valllabh/domain-scan/pkg/domainscan"
)

// Debug logger that prints to stderr
type debugLogger struct{}

func (d debugLogger) Debugf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
}

func (d debugLogger) Infof(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[INFO] "+format+"\n", args...)
}

func (d debugLogger) Warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[WARN] "+format+"\n", args...)
}

func (d debugLogger) Errorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}

func main() {
	ctx := context.Background()
	keywords := []string{"apple"}
	ports := []int{443}
	maxDomains := 10
	logger := debugLogger{}

	fmt.Println("Creating domain processor...")
	
	// Create processor with debug logging
	processor := domainscan.NewDomainProcessor(ctx, keywords, ports, maxDomains, nil, false, true, logger)
	
	// Start workers
	processor.Start()
	
	fmt.Println("Queueing apple.com for certificate analysis...")
	
	// Add apple.com domain and queue it for certificate analysis
	processor.AddDomain("apple.com")
	processor.QueueCertificate("apple.com")
	
	fmt.Println("Waiting for completion...")
	
	// Wait for completion
	processor.WaitForCompletion()
	
	// Get results
	results := processor.GetResults()
	
	fmt.Printf("\nFinal Results:\n")
	fmt.Printf("Total Domains: %d\n", len(results.Subdomains))
	fmt.Printf("Active Services: %d\n", results.Statistics.ActiveServices)
	fmt.Printf("Web Assets: %d\n", len(results.ActiveServices))
	
	if len(results.ActiveServices) > 0 {
		fmt.Println("Live Services:")
		for i, service := range results.ActiveServices {
			fmt.Printf("  %d: %s (status: %d)\n", i+1, service.URL, service.StatusCode)
		}
	}
}