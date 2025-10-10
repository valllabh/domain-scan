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
	TotalSubdomains    int           `json:"total_subdomains"`
	ActiveServices     int           `json:"active_services"`
	PassiveResults     int           `json:"passive_results"`
	CertificateResults int           `json:"certificate_results"`
	HTTPResults        int           `json:"http_results"`
	Duration           time.Duration `json:"duration"`
	TargetsScanned     int           `json:"targets_scanned"`
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
