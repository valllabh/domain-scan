package domainscan

import (
	"time"
	"github.com/domain-scan/domain-scan/pkg/types"
)

// AssetDiscoveryResult represents the result of a domain asset discovery scan
type AssetDiscoveryResult struct {
	Subdomains     []string        `json:"subdomains"`
	ActiveServices []types.WebAsset      `json:"active_services"`
	TLSAssets     []types.TLSAsset      `json:"tls_assets"`
	Statistics    DiscoveryStats  `json:"statistics"`
	Errors        []error         `json:"errors,omitempty"`
}

// These types are now in pkg/types

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
	Domains            []string      `json:"domains"`
	Keywords           []string      `json:"keywords,omitempty"`
	Ports              []int         `json:"ports,omitempty"`
	MaxSubdomains      int           `json:"max_subdomains,omitempty"`
	Timeout            time.Duration `json:"timeout,omitempty"`
	EnablePassive      bool          `json:"enable_passive"`
	EnableCertScan     bool          `json:"enable_cert_scan"`
	EnableHTTPScan     bool          `json:"enable_http_scan"`
}

// DefaultScanRequest returns a default scan request
func DefaultScanRequest(domains []string) *ScanRequest {
	return &ScanRequest{
		Domains:        domains,
		Keywords:       []string{},
		Ports:          []int{80, 443, 8080, 8443, 3000, 8000, 8888},
		MaxSubdomains:  1000,
		Timeout:        10 * time.Second,
		EnablePassive:  true,
		EnableCertScan: true,
		EnableHTTPScan: true,
	}
}