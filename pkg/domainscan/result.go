package domainscan

import (
	"github.com/valllabh/domain-scan/pkg/types"
	"time"
)

// DomainEntry is now in types package
type DomainEntry = types.DomainEntry

// AssetDiscoveryResult represents the result of a domain asset discovery scan
type AssetDiscoveryResult struct {
	Domains    map[string]*DomainEntry `json:"domains"` // Main output domains map
	Statistics DiscoveryStats          `json:"statistics"`
	Errors     []error                 `json:"errors,omitempty"`
}

// DiscoveryStats contains statistics about the discovery process
type DiscoveryStats struct {
	TotalSubdomains    int           `json:"total_subdomains"`     // Total domains discovered
	TracedDomains      int           `json:"traced_domains"`       // Domains found but not live
	ActiveServices     int           `json:"active_services"`      // Live domains with HTTP services
	PassiveResults     int           `json:"passive_results"`      // Domains from passive enumeration
	CertificateResults int           `json:"certificate_results"`  // Domains from certificate analysis
	HTTPResults        int           `json:"http_results"`         // Domains with HTTP responses
	Duration           time.Duration `json:"duration"`             // Total scan duration
	TargetsScanned     int           `json:"targets_scanned"`      // Number of targets scanned
}

// ScanRequest represents a request for domain asset discovery
type ScanRequest struct {
	Domains  []string      `json:"domains"`
	Keywords []string      `json:"keywords,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
}

// DefaultScanRequest returns a default scan request
func DefaultScanRequest(domains []string) *ScanRequest {
	return &ScanRequest{
		Domains:  domains,
		Keywords: []string{},
		Timeout:  10 * time.Second,
	}
}
