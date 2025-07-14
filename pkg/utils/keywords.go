package utils

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed tlds.json
var tldsJSON []byte

var tldSet map[string]bool

// loadTLDs loads and parses the embedded TLD data once
func loadTLDs() map[string]bool {
	var tlds []string
	if err := json.Unmarshal(tldsJSON, &tlds); err != nil {
		// Fallback to basic TLDs if JSON parsing fails
		return map[string]bool{
			"com": true, "org": true, "net": true, "edu": true, "gov": true,
			"co.uk": true, "co.in": true, "gov.in": true, "gov.uk": true,
			"ac.uk": true, "com.au": true, "org.au": true,
		}
	}

	tldMap := make(map[string]bool, len(tlds))
	for _, tld := range tlds {
		tldMap[tld] = true
	}

	return tldMap
}

// getTLDs returns the cached TLD set, loading it if necessary
func getTLDs() map[string]bool {
	if tldSet == nil {
		tldSet = loadTLDs()
	}
	return tldSet
}

// ExtractKeywordsFromDomains extracts keywords from domain names
func ExtractKeywordsFromDomains(domains []string) []string {
	keywordMap := make(map[string]bool)
	tlds := getTLDs()

	for _, domain := range domains {
		domain = strings.ToLower(domain)

		// Remove TLDs from the end first
		for {
			found := false
			for tld := range tlds {
				if strings.HasSuffix(domain, "."+tld) {
					domain = domain[:len(domain)-len(tld)-1]
					found = true
					break
				}
			}
			if !found {
				break
			}
		}

		if domain == "" {
			continue
		}

		// Now explode by dots and take the last element
		parts := strings.Split(domain, ".")
		if len(parts) == 0 {
			continue
		}

		orgPart := parts[len(parts)-1]

		// Split by hyphens and underscores
		subParts := strings.FieldsFunc(orgPart, func(r rune) bool {
			return r == '-' || r == '_'
		})
		for _, part := range subParts {
			if len(part) >= 2 { // Allow 2+ character keywords (3m, hp, etc.)
				keywordMap[part] = true
			}
		}
	}

	var keywords []string
	for keyword := range keywordMap {
		keywords = append(keywords, keyword)
	}

	return keywords
}
