package utils

import (
	"reflect"
	"testing"
)

func TestExtractKeywordsFromDomains(t *testing.T) {
	tests := []struct {
		name     string
		domains  []string
		expected []string
	}{
		// Basic TLD tests (.com, .org)
		{
			name:     "single domain .com",
			domains:  []string{"example.com"},
			expected: []string{"example"},
		},
		{
			name:     "multiple domains basic TLDs",
			domains:  []string{"test.com", "demo.org"},
			expected: []string{"test", "demo"},
		},
		{
			name:     "subdomain .com",
			domains:  []string{"api.example.com"},
			expected: []string{"example"},
		},
		
		// UK domains (.co.uk)
		{
			name:     "single domain .co.uk",
			domains:  []string{"apple.co.uk"},
			expected: []string{"apple"},
		},
		{
			name:     "subdomain .co.uk",
			domains:  []string{"api.apple.co.uk"},
			expected: []string{"apple"},
		},
		{
			name:     "multiple UK domains",
			domains:  []string{"apple.co.uk", "microsoft.co.uk"},
			expected: []string{"apple", "microsoft"},
		},
		
		// India domains (.co.in)
		{
			name:     "single domain .co.in",
			domains:  []string{"reliance.co.in"},
			expected: []string{"reliance"},
		},
		{
			name:     "subdomain .co.in",
			domains:  []string{"portal.infosys.co.in"},
			expected: []string{"infosys"},
		},
		{
			name:     "multiple India domains",
			domains:  []string{"tcs.co.in", "wipro.co.in"},
			expected: []string{"tcs", "wipro"},
		},
		
		// Government domains (.gov.in)
		{
			name:     "single domain .gov.in",
			domains:  []string{"uidai.gov.in"},
			expected: []string{"uidai"},
		},
		{
			name:     "subdomain .gov.in",
			domains:  []string{"portal.nrega.gov.in"},
			expected: []string{"nrega"},
		},
		{
			name:     "multiple gov domains .gov.in",
			domains:  []string{"uidai.gov.in", "railways.gov.in"},
			expected: []string{"uidai", "railways"},
		},
		
		// Complex multi-level TLDs
		{
			name:     "academic domain .ac.uk",
			domains:  []string{"cambridge.ac.uk"},
			expected: []string{"cambridge"},
		},
		{
			name:     "government domain .gov.uk",
			domains:  []string{"hmrc.gov.uk"},
			expected: []string{"hmrc"},
		},
		{
			name:     "subdomain academic .ac.uk",
			domains:  []string{"portal.oxford.ac.uk"},
			expected: []string{"oxford"},
		},
		
		// Other country domains
		{
			name:     "australia domain .com.au",
			domains:  []string{"commonwealth.com.au"},
			expected: []string{"commonwealth"},
		},
		{
			name:     "canada domain .ca",
			domains:  []string{"shopify.ca"},
			expected: []string{"shopify"},
		},
		{
			name:     "germany domain .de",
			domains:  []string{"siemens.de"},
			expected: []string{"siemens"},
		},
		{
			name:     "subdomain australia .com.au",
			domains:  []string{"api.telstra.com.au"},
			expected: []string{"telstra"},
		},
		
		// Real-world examples from user description
		{
			name:     "apple.com extraction",
			domains:  []string{"apple.com"},
			expected: []string{"apple"},
		},
		{
			name:     "apple.co.uk extraction",
			domains:  []string{"apple.co.uk"},
			expected: []string{"apple"},
		},
		{
			name:     "iphone.com extraction",
			domains:  []string{"iphone.com"},
			expected: []string{"iphone"},
		},
		{
			name:     "iphone.co.in extraction",
			domains:  []string{"iphone.co.in"},
			expected: []string{"iphone"},
		},
		{
			name:     "mixed TLD domains (deduplicated)",
			domains:  []string{"apple.com", "apple.co.uk", "iphone.com", "iphone.co.in"},
			expected: []string{"apple", "iphone"},
		},
		
		// Hyphenated domains
		{
			name:     "domain with hyphens .com",
			domains:  []string{"multi-word-domain.com"},
			expected: []string{"multi", "word", "domain"},
		},
		{
			name:     "domain with hyphens .co.uk",
			domains:  []string{"rolls-royce.co.uk"},
			expected: []string{"rolls", "royce"},
		},
		{
			name:     "complex hyphenated .gov.uk",
			domains:  []string{"driver-vehicle-licensing.gov.uk"},
			expected: []string{"driver", "vehicle", "licensing"},
		},
		
		// Underscored domains  
		{
			name:     "domain with underscores .com",
			domains:  []string{"test_domain.com"},
			expected: []string{"test", "domain"},
		},
		{
			name:     "domain with underscores .co.in",
			domains:  []string{"state_bank.co.in"},
			expected: []string{"state", "bank"},
		},
		
		// Complex nested subdomains
		{
			name:     "deep subdomain .com",
			domains:  []string{"api.v2.services.example.com"},
			expected: []string{"example"},
		},
		{
			name:     "deep subdomain .co.uk",
			domains:  []string{"mail.secure.services.lloyds.co.uk"},
			expected: []string{"lloyds"},
		},
		{
			name:     "deep subdomain .gov.in",
			domains:  []string{"citizen.portal.digital.india.gov.in"},
			expected: []string{"india"},
		},
		
		// Domains with numbers
		{
			name:     "domain with numbers .com",
			domains:  []string{"channel4.com"},
			expected: []string{"channel4"},
		},
		{
			name:     "domain with numbers .co.uk",
			domains:  []string{"3m.co.uk"},
			expected: []string{"3m"},
		},
		
		// Edge cases and filtering
		{
			name:     "short parts filtered out .co.uk",
			domains:  []string{"ab.cd.example.co.uk"},
			expected: []string{"example"},
		},
		{
			name:     "very short organization name included",
			domains:  []string{"hp.com"},
			expected: []string{"hp"}, // "hp" is 2 chars, now included
		},
		{
			name:     "empty domains",
			domains:  []string{},
			expected: []string{},
		},
		{
			name:     "mixed case .co.uk",
			domains:  []string{"API.Example.CO.UK"},
			expected: []string{"example"},
		},
		{
			name:     "mixed TLDs same organization",
			domains:  []string{"google.com", "google.co.uk", "google.ca"},
			expected: []string{"google"},
		},
		{
			name:     "mixed organizations and TLDs",
			domains:  []string{"apple.com", "microsoft.co.uk", "google.ca", "amazon.com.au"},
			expected: []string{"apple", "microsoft", "google", "amazon"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractKeywordsFromDomains(tt.domains)
			if !stringSliceEqual(result, tt.expected) {
				t.Errorf("ExtractKeywordsFromDomains() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	
	// Convert to maps for comparison (order doesn't matter for keywords)
	mapA := make(map[string]bool)
	mapB := make(map[string]bool)
	
	for _, s := range a {
		mapA[s] = true
	}
	for _, s := range b {
		mapB[s] = true
	}
	
	return reflect.DeepEqual(mapA, mapB)
}