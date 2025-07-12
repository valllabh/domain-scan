package discovery

import (
	"testing"
)

func TestContainsKeyword(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		keyword  string
		expected bool
	}{
		// Basic .com TLD tests
		{
			name:     "direct match .com",
			domain:   "api.apple.com",
			keyword:  "apple",
			expected: true,
		},
		{
			name:     "case insensitive match .com",
			domain:   "API.APPLE.COM",
			keyword:  "apple",
			expected: true,
		},
		{
			name:     "keyword in subdomain .com",
			domain:   "status.apple.com",
			keyword:  "apple",
			expected: true,
		},
		{
			name:     "no match different org .com",
			domain:   "status.microsoft.com",
			keyword:  "apple",
			expected: false,
		},
		
		// UK domains (.co.uk)
		{
			name:     "direct match .co.uk",
			domain:   "api.apple.co.uk",
			keyword:  "apple",
			expected: true,
		},
		{
			name:     "subdomain .co.uk",
			domain:   "status.apple.co.uk",
			keyword:  "apple",
			expected: true,
		},
		{
			name:     "no match different org .co.uk",
			domain:   "admin.microsoft.co.uk",
			keyword:  "apple",
			expected: false,
		},
		{
			name:     "keyword extracted from .co.uk domain",
			domain:   "services.iphone.co.uk",
			keyword:  "iphone",
			expected: true,
		},
		
		// India domains (.co.in)
		{
			name:     "direct match .co.in",
			domain:   "api.reliance.co.in",
			keyword:  "reliance",
			expected: true,
		},
		{
			name:     "subdomain .co.in",
			domain:   "mail.infosys.co.in",
			keyword:  "infosys",
			expected: true,
		},
		{
			name:     "no match different org .co.in",
			domain:   "portal.tcs.co.in",
			keyword:  "infosys",
			expected: false,
		},
		
		// Government domains (.gov.in)
		{
			name:     "direct match .gov.in",
			domain:   "portal.uidai.gov.in",
			keyword:  "uidai",
			expected: true,
		},
		{
			name:     "subdomain .gov.in",
			domain:   "services.nrega.gov.in",
			keyword:  "nrega",
			expected: true,
		},
		{
			name:     "no match different dept .gov.in",
			domain:   "admin.railways.gov.in",
			keyword:  "uidai",
			expected: false,
		},
		
		// Other country domains
		{
			name:     "australia .com.au",
			domain:   "www.commonwealth.com.au",
			keyword:  "commonwealth",
			expected: true,
		},
		{
			name:     "canada .ca",
			domain:   "portal.shopify.ca",
			keyword:  "shopify",
			expected: true,
		},
		{
			name:     "germany .de",
			domain:   "services.siemens.de",
			keyword:  "siemens",
			expected: true,
		},
		
		// Complex multi-level domains
		{
			name:     "UK academic .ac.uk",
			domain:   "portal.cambridge.ac.uk",
			keyword:  "cambridge",
			expected: true,
		},
		{
			name:     "UK government .gov.uk",
			domain:   "services.hmrc.gov.uk",
			keyword:  "hmrc",
			expected: true,
		},
		
		// Hyphenated organizations
		{
			name:     "hyphenated keyword .com",
			domain:   "api.lloyd-george.com",
			keyword:  "lloyd",
			expected: true,
		},
		{
			name:     "hyphenated keyword .co.uk",
			domain:   "portal.rolls-royce.co.uk",
			keyword:  "rolls",
			expected: true,
		},
		{
			name:     "full hyphenated match .co.uk",
			domain:   "services.rolls-royce.co.uk",
			keyword:  "rolls-royce",
			expected: true,
		},
		
		// Real-world examples based on user's description
		{
			name:     "apple status subdomain",
			domain:   "status.apple.com",
			keyword:  "apple",
			expected: true,
		},
		{
			name:     "apple uat subdomain",
			domain:   "status-uat.apple.com",
			keyword:  "apple",
			expected: true,
		},
		{
			name:     "microsoft in apple certificate (should not match)",
			domain:   "status.microsoft.com",
			keyword:  "apple",
			expected: false,
		},
		{
			name:     "iphone .com domain",
			domain:   "www.iphone.com",
			keyword:  "iphone",
			expected: true,
		},
		{
			name:     "iphone .co.in domain",
			domain:   "ftp.iphone.co.in",
			keyword:  "iphone",
			expected: true,
		},
		
		// Edge cases
		{
			name:     "extracted keyword match complex domain",
			domain:   "iphone.dev.example.com",
			keyword:  "example", // extracts "example", not "iphone"
			expected: true,
		},
		{
			name:     "subdomain should not match as keyword",
			domain:   "iphone.dev.example.com",
			keyword:  "iphone", // "iphone" is subdomain, not organization
			expected: false,
		},
		{
			name:     "partial match in extracted keyword",
			domain:   "test.apple-services.com",
			keyword:  "apple",
			expected: true,
		},
		{
			name:     "empty keyword",
			domain:   "example.com",
			keyword:  "",
			expected: true, // empty string is contained in any string
		},
		{
			name:     "empty domain",
			domain:   "",
			keyword:  "apple",
			expected: false,
		},
		
		// Numbers in domain names
		{
			name:     "domain with numbers .com",
			domain:   "api.channel4.com",
			keyword:  "channel4",
			expected: true,
		},
		{
			name:     "domain with numbers .co.uk",
			domain:   "services.3m.co.uk",
			keyword:  "3m",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsKeyword(tt.domain, tt.keyword)
			if result != tt.expected {
				t.Errorf("containsKeyword(%q, %q) = %v; expected %v", tt.domain, tt.keyword, result, tt.expected)
			}
		})
	}
}