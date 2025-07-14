package types

import "time"

// WebAsset represents a discovered web service
type WebAsset struct {
	URL          string            `json:"url"`
	StatusCode   int               `json:"status_code"`
	Title        string            `json:"title,omitempty"`
	Server       string            `json:"server,omitempty"`
	Technologies []string          `json:"technologies,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	ResponseSize int               `json:"response_size,omitempty"`
}

// TLSAsset represents TLS certificate information
type TLSAsset struct {
	Domain     string    `json:"domain"`
	SubjectANs []string  `json:"subject_ans"`
	Issuer     string    `json:"issuer"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidTo    time.Time `json:"valid_to"`
	Algorithm  string    `json:"algorithm,omitempty"`
}
