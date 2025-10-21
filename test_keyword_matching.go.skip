package main

import (
	"fmt"
	"github.com/valllabh/domain-scan/pkg/utils"
)

func main() {
	// Test keyword extraction from qualys.com
	domains := []string{"qualys.com"}
	keywords := utils.ExtractKeywordsFromDomains(domains)
	fmt.Printf("Keywords extracted from qualys.com: %v\n", keywords)

	// Test if qualys.in matches the extracted keywords
	testDomains := []string{"qualys.in", "qualysguard.com", "something-qualys.net", "unrelated.com"}

	for _, domain := range testDomains {
		matches := utils.MatchesKeywords(domain, keywords)
		fmt.Printf("Does '%s' match keywords %v? %t\n", domain, keywords, matches)
	}
}
