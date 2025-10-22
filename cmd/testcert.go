package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/valllabh/domain-scan/pkg/discovery"
	"github.com/valllabh/domain-scan/pkg/logging"
	"github.com/valllabh/domain-scan/pkg/utils"
)

var testcertCmd = &cobra.Command{
	Use:   "testcert [domain...]",
	Short: "Test certificate discovery flow for debugging",
	Long:  `Tests the certificate discovery flow and shows all domains found in certificates, including filtering details.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runTestCert,
}

var (
	testCertKeywords []string
	testCertPorts    []int
)

func init() {
	rootCmd.AddCommand(testcertCmd)
	testcertCmd.Flags().StringSliceVar(&testCertKeywords, "keywords", []string{}, "Keywords to filter certificate domains (optional)")
	testcertCmd.Flags().IntSliceVar(&testCertPorts, "ports", []int{443, 8443}, "Ports to scan for certificates")
}

func runTestCert(cmd *cobra.Command, args []string) error {
	// Initialize logger
	logging.InitLogger("debug")
	logger := logging.GetLogger()

	// Extract keywords from domains if not provided
	keywords := utils.LoadKeywords(args, testCertKeywords)

	fmt.Printf("Testing certificate discovery\n")
	fmt.Printf("Domains: %v\n", args)
	fmt.Printf("Keywords: %v\n", keywords)
	fmt.Printf("Ports: %v\n\n", testCertPorts)

	// Prepare targets with ports
	var targets []string
	for _, domain := range args {
		for _, port := range testCertPorts {
			targets = append(targets, fmt.Sprintf("%s:%d", domain, port))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run certificate analysis
	fmt.Printf("Scanning %d targets...\n\n", len(targets))

	domainEntries, allSubdomains, _, err := discovery.BulkCertificateAnalysisForScanner(
		ctx,
		targets,
		keywords,
		true, // Always extract new domains in test mode
		logger,
	)

	if err != nil {
		return fmt.Errorf("certificate analysis failed: %v", err)
	}

	// Display results
	fmt.Printf("\n📊 Results:\n")
	fmt.Printf("  Total domain entries: %d\n", len(domainEntries))
	fmt.Printf("  Filtered subdomains: %d\n\n", len(allSubdomains))

	// Show live domains
	if len(domainEntries) > 0 {
		fmt.Printf("✅ Live domains:\n")
		for _, entry := range domainEntries {
			if entry.Reachable {
				fmt.Printf("  • %s (status: %d)\n", entry.Domain, entry.Status)
			}
		}
		fmt.Println()
	}

	// Show filtered subdomains
	if len(allSubdomains) > 0 {
		fmt.Printf("🔎 Filtered subdomains (matched keywords):\n")
		uniqueDomains := make(map[string]bool)
		for _, domain := range allSubdomains {
			uniqueDomains[domain] = true
		}
		for domain := range uniqueDomains {
			fmt.Printf("  • %s\n", domain)
		}
	}

	return nil
}
