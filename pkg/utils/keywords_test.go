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
		{
			name:     "single domain",
			domains:  []string{"example.com"},
			expected: []string{"example"},
		},
		{
			name:     "multiple domains",
			domains:  []string{"test.com", "demo.org"},
			expected: []string{"test", "demo"},
		},
		{
			name:     "domain with hyphens",
			domains:  []string{"multi-word-domain.com"},
			expected: []string{"multi", "word", "domain"},
		},
		{
			name:     "domain with underscores",
			domains:  []string{"test_domain.com"},
			expected: []string{"test", "domain"},
		},
		{
			name:     "subdomain",
			domains:  []string{"api.example.com"},
			expected: []string{"example"},
		},
		{
			name:     "short parts filtered out",
			domains:  []string{"ab.cd.example.com"},
			expected: []string{"example"},
		},
		{
			name:     "empty domains",
			domains:  []string{},
			expected: []string{},
		},
		{
			name:     "mixed case",
			domains:  []string{"API.Example.COM"},
			expected: []string{"Example"},
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