package types

// DomainEntry represents a single domain with its protocol, port, and status
type DomainEntry struct {
	Domain         string `json:"domain"`           // protocol+domain+port (e.g., "https://example.com:443")
	Status         int    `json:"status"`           // HTTP status code
	IsLive         bool   `json:"is_live"`          // Whether domain is live
	HadPassiveScan bool   `json:"had_passive_scan"` // Whether passive scan was performed
}
