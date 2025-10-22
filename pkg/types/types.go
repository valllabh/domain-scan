package types

import "time"

// Source represents where a domain was discovered from
type Source struct {
	Name        string           `json:"name"`                   // e.g., "subfinder", "certificate", "httpx"
	Type        string           `json:"type"`                   // e.g., "passive", "certificate", "http"
	Certificate *CertificateInfo `json:"certificate,omitempty"` // Certificate info if discovered from certificate SAN
}

// CertificateInfo contains TLS certificate metadata
type CertificateInfo struct {
	IssuedOn  time.Time `json:"issued_on,omitempty"`  // Certificate not before date
	ExpiresOn time.Time `json:"expires_on,omitempty"` // Certificate not after date
	Issuer    string    `json:"issuer,omitempty"`     // Certificate issuer
	Subject   string    `json:"subject,omitempty"`    // Certificate subject
}

// RedirectInfo contains HTTP redirect information
type RedirectInfo struct {
	IsRedirect  bool   `json:"is_redirect"`            // Whether this domain redirects
	RedirectsTo string `json:"redirects_to,omitempty"` // Final URL after all redirects
	StatusCodes []int  `json:"status_codes,omitempty"` // HTTP status codes in redirect chain
}

// DomainEntry represents a single domain with its protocol, port, and status
type DomainEntry struct {
	Domain      string           `json:"domain"`                // Bare domain (e.g., "example.com")
	URL         string           `json:"url,omitempty"`         // Full URL if HTTP verified (e.g., "https://example.com")
	Status      int              `json:"status"`                // HTTP status code
	Reachable   bool             `json:"reachable"`             // Whether domain is reachable
	IP          string           `json:"ip,omitempty"`          // IP address if resolved
	Redirect    *RedirectInfo    `json:"redirect,omitempty"`    // Redirect information if domain redirects
	Sources     []Source         `json:"sources,omitempty"`     // Discovery sources for this domain
	Certificate *CertificateInfo `json:"certificate,omitempty"` // TLS certificate info if available
}
