package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/valllabh/domain-scan/pkg/domainscan"
)

func main() {
	// Initialize scanner
	scanner := domainscan.New(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Run discovery (using a small domain for demo)
	// Replace with your domain: result, err := scanner.DiscoverAssets(ctx, []string{"yourdomain.com"})
	fmt.Println("Note: This example shows SDK usage patterns for accessing source information")
	fmt.Println("Replace 'yourdomain.com' with your actual domain to run a real scan\n")

	// Example 1: Access sources for each domain
	fmt.Println("=== Example 1: Accessing Domain Sources ===")
	fmt.Println("for domain, entry := range result.Domains {")
	fmt.Println("    fmt.Printf(\"Domain: %s\\n\", domain)")
	fmt.Println("    for _, src := range entry.Sources {")
	fmt.Println("        fmt.Printf(\"  - Discovered via: %s (type: %s)\\n\", src.Name, src.Type)")
	fmt.Println("    }")
	fmt.Println("}")

	// Example 2: Filter domains by source type
	fmt.Println("\n=== Example 2: Filter Domains by Source Type ===")
	fmt.Println("// Get all domains found via passive discovery")
	fmt.Println("var passiveDomains []string")
	fmt.Println("for domain, entry := range result.Domains {")
	fmt.Println("    for _, src := range entry.Sources {")
	fmt.Println("        if src.Type == \"passive\" {")
	fmt.Println("            passiveDomains = append(passiveDomains, domain)")
	fmt.Println("            break")
	fmt.Println("        }")
	fmt.Println("    }")
	fmt.Println("}")

	// Example 3: Find high confidence domains (multiple sources)
	fmt.Println("\n=== Example 3: Find High Confidence Domains ===")
	fmt.Println("// Domains found by multiple sources have higher confidence")
	fmt.Println("var highConfidenceDomains []string")
	fmt.Println("for domain, entry := range result.Domains {")
	fmt.Println("    if len(entry.Sources) >= 2 {")
	fmt.Println("        highConfidenceDomains = append(highConfidenceDomains, domain)")
	fmt.Println("    }")
	fmt.Println("}")

	// Example 4: Count domains by source
	fmt.Println("\n=== Example 4: Statistics by Source ===")
	fmt.Println("sourceStats := make(map[string]int)")
	fmt.Println("for _, entry := range result.Domains {")
	fmt.Println("    for _, src := range entry.Sources {")
	fmt.Println("        sourceStats[src.Name]++")
	fmt.Println("    }")
	fmt.Println("}")
	fmt.Println("for source, count := range sourceStats {")
	fmt.Println("    fmt.Printf(\"%s: %d domains\\n\", source, count)")
	fmt.Println("}")

	// Example 5: JSON output structure
	fmt.Println("\n=== Example 5: JSON Output Structure ===")
	exampleResult := map[string]interface{}{
		"domains": map[string]interface{}{
			"https://blog.example.com": map[string]interface{}{
				"domain":  "https://blog.example.com",
				"status":  200,
				"is_live": true,
				"sources": []map[string]string{
					{"name": "subfinder", "type": "passive"},
					{"name": "httpx", "type": "http"},
				},
			},
			"https://api.example.com": map[string]interface{}{
				"domain":  "https://api.example.com",
				"status":  200,
				"is_live": true,
				"sources": []map[string]string{
					{"name": "subfinder", "type": "passive"},
					{"name": "certificate", "type": "certificate"},
					{"name": "httpx", "type": "http"},
				},
			},
		},
		"statistics": map[string]interface{}{
			"total_subdomains": 2,
			"active_services":  2,
		},
	}

	jsonOutput, _ := json.MarshalIndent(exampleResult, "", "  ")
	fmt.Println(string(jsonOutput))

	// Prevent unused variable errors
	_ = scanner
	_ = ctx
}
