package utils

import "strings"

// ExtractKeywordsFromDomains extracts keywords from domain names
func ExtractKeywordsFromDomains(domains []string) []string {
	keywordMap := make(map[string]bool)

	for _, domain := range domains {
		// Simple keyword extraction - get the main part before TLD
		parts := strings.Split(domain, ".")
		if len(parts) >= 2 {
			// Take the second-to-last part as the main keyword
			mainPart := parts[len(parts)-2]
			// Split by hyphens and underscores
			subParts := strings.FieldsFunc(mainPart, func(r rune) bool {
				return r == '-' || r == '_'
			})
			for _, part := range subParts {
				if len(part) > 2 {
					keywordMap[part] = true
				}
			}
		}
	}

	var keywords []string
	for keyword := range keywordMap {
		keywords = append(keywords, keyword)
	}

	return keywords
}