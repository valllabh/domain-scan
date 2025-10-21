package types

// Source represents where a domain was discovered from
type Source struct {
	Name string `json:"name"` // e.g., "subfinder", "certificate", "httpx"
	Type string `json:"type"` // e.g., "passive", "certificate", "http"
}

// DomainEntry represents a single domain with its protocol, port, and status
type DomainEntry struct {
	Domain  string   `json:"domain"`            // protocol+domain+port (e.g., "https://example.com:443")
	Status  int      `json:"status"`            // HTTP status code
	IsLive  bool     `json:"is_live"`           // Whether domain is live
	IP      string   `json:"ip,omitempty"`      // IP address if resolved
	Sources []Source `json:"sources,omitempty"` // Discovery sources for this domain
}
