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

		// Remove TLDs from the end efficiently
		domain = removeTLDs(domain, tlds)

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

// LoadKeywords combines domain extraction and argument keywords
func LoadKeywords(domains []string, keywordsInArgument []string) []string {
	keywordMap := make(map[string]bool)

	// Extract keywords from domains
	extractedKeywords := ExtractKeywordsFromDomains(domains)
	for _, keyword := range extractedKeywords {
		keywordMap[keyword] = true
	}

	// Add keywords from arguments
	for _, keyword := range keywordsInArgument {
		if keyword != "" {
			keywordMap[strings.ToLower(strings.TrimSpace(keyword))] = true
		}
	}

	// Convert back to slice with pre-allocation
	finalKeywords := make([]string, 0, len(keywordMap))
	for keyword := range keywordMap {
		finalKeywords = append(finalKeywords, keyword)
	}

	return finalKeywords
}

// MatchesKeywords checks if a domain matches any of the provided keywords
func MatchesKeywords(domain string, keywords []string) bool {
	if len(keywords) == 0 {
		return true // Accept all if no keywords specified
	}

	domainLower := strings.ToLower(domain)
	for _, keyword := range keywords {
		if strings.Contains(domainLower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// removeTLDs removes the longest matching TLD suffix from a domain
// Only removes the TLD suffix once, not iteratively
func removeTLDs(domain string, tlds map[string]bool) string {
	longestTLD := ""

	// Find the longest TLD suffix that matches
	for suffix := range tlds {
		if strings.HasSuffix(domain, "."+suffix) || domain == suffix {
			if len(suffix) > len(longestTLD) {
				longestTLD = suffix
			}
		}
	}

	if longestTLD != "" {
		if domain == longestTLD {
			// Entire domain is a TLD
			return ""
		}
		// Remove the TLD and its preceding dot
		return domain[:len(domain)-len(longestTLD)-1]
	}

	return domain
}
