package domainscan

import (
	"strings"
	"sync"
)

// ScanState represents the completion status of different scan types for a domain
type ScanState uint8

const (
	PassiveCompleted     ScanState = 1 << 0 // 0x01 - Passive subdomain discovery completed
	CertificateCompleted ScanState = 1 << 1 // 0x02 - Certificate analysis completed
	LivenessCompleted    ScanState = 1 << 2 // 0x04 - Liveness check completed
)

// DomainTracker provides memory-efficient tracking of discovered domains and their scan states
type DomainTracker struct {
	// Memory-efficient sets using map[string]struct{}
	allDomains     map[string]struct{}         // All discovered domains (deduplicated)
	domainStates   map[string]ScanState        // Scan completion state per domain
	portCertStates map[string]map[int]struct{} // Port-specific certificate scan tracking

	// Pending scan sets for efficient querying
	pendingPassive     map[string]struct{} // Domains needing passive discovery
	pendingCertificate map[string]struct{} // Domains needing certificate analysis
	pendingLiveness    map[string]struct{} // Domains needing liveness check

	// Configuration
	requiredPorts []int // Ports that need to be scanned for certificate completion
	currentRound  int   // Current discovery round

	// Thread safety
	mu sync.RWMutex
}

// NewDomainTracker creates a new domain tracker with specified ports for certificate scanning
func NewDomainTracker(ports []int) *DomainTracker {
	if len(ports) == 0 {
		ports = []int{443, 80} // Default ports
	}

	return &DomainTracker{
		allDomains:         make(map[string]struct{}),
		domainStates:       make(map[string]ScanState),
		portCertStates:     make(map[string]map[int]struct{}),
		pendingPassive:     make(map[string]struct{}),
		pendingCertificate: make(map[string]struct{}),
		pendingLiveness:    make(map[string]struct{}),
		requiredPorts:      ports,
		currentRound:       1,
	}
}

// AddDomain adds a domain to tracking if it doesn't already exist
// Returns true if domain was newly added, false if it already existed
func (dt *DomainTracker) AddDomain(domain string) bool {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	// Check if domain already exists
	if _, exists := dt.allDomains[domain]; exists {
		return false
	}

	// Add to all tracking maps
	dt.allDomains[domain] = struct{}{}
	dt.domainStates[domain] = 0 // No scans completed initially

	// Add to pending scan queues
	dt.pendingPassive[domain] = struct{}{}
	dt.pendingCertificate[domain] = struct{}{}
	dt.pendingLiveness[domain] = struct{}{}

	return true
}

// MarkPassiveCompleted marks passive discovery as completed for a domain
func (dt *DomainTracker) MarkPassiveCompleted(domain string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	dt.domainStates[domain] |= PassiveCompleted
	delete(dt.pendingPassive, domain)
}

// MarkBatchPassiveCompleted marks passive discovery as completed for multiple domains
func (dt *DomainTracker) MarkBatchPassiveCompleted(domains []string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	for _, domain := range domains {
		dt.domainStates[domain] |= PassiveCompleted
		delete(dt.pendingPassive, domain)
	}
}

// MarkCertificateCompleted marks certificate analysis as completed for a domain on a specific port
// Also marks liveness as completed since we connected to get the certificate
func (dt *DomainTracker) MarkCertificateCompleted(domain string, port int) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	// Initialize port tracking for domain if needed
	if dt.portCertStates[domain] == nil {
		dt.portCertStates[domain] = make(map[int]struct{})
	}
	dt.portCertStates[domain][port] = struct{}{}

	// Mark liveness completed since we successfully connected to get certificate
	dt.domainStates[domain] |= LivenessCompleted
	delete(dt.pendingLiveness, domain)

	// Check if all required ports have been scanned for certificate completion
	if dt.allRequiredPortsScanned(domain) {
		dt.domainStates[domain] |= CertificateCompleted
		delete(dt.pendingCertificate, domain)
	}
}

// MarkLivenessCompleted marks liveness check as completed for a domain
func (dt *DomainTracker) MarkLivenessCompleted(domain string) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	dt.domainStates[domain] |= LivenessCompleted
	delete(dt.pendingLiveness, domain)
}

// allRequiredPortsScanned checks if all required ports have been scanned for certificate analysis
func (dt *DomainTracker) allRequiredPortsScanned(domain string) bool {
	portMap, exists := dt.portCertStates[domain]
	if !exists {
		return false
	}

	for _, port := range dt.requiredPorts {
		if _, scanned := portMap[port]; !scanned {
			return false
		}
	}

	return true
}

// IsCertificateCompleted checks if certificate analysis is completed for a domain on a specific port
func (dt *DomainTracker) IsCertificateCompleted(domain string, port int) bool {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	portMap, exists := dt.portCertStates[domain]
	if !exists {
		return false
	}

	_, scanned := portMap[port]
	return scanned
}

// IsLivenessCompleted checks if liveness check is completed for a domain
func (dt *DomainTracker) IsLivenessCompleted(domain string) bool {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	return dt.domainStates[domain]&LivenessCompleted != 0
}

// IsPassiveCompleted checks if passive discovery is completed for a domain
func (dt *DomainTracker) IsPassiveCompleted(domain string) bool {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	return dt.domainStates[domain]&PassiveCompleted != 0
}

// GetPendingPassive returns domains that need passive discovery
func (dt *DomainTracker) GetPendingPassive() []string {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	domains := make([]string, 0, len(dt.pendingPassive))
	for domain := range dt.pendingPassive {
		domains = append(domains, domain)
	}
	return domains
}

// GetPendingCertificate returns domains that need certificate analysis
func (dt *DomainTracker) GetPendingCertificate() []string {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	domains := make([]string, 0, len(dt.pendingCertificate))
	for domain := range dt.pendingCertificate {
		domains = append(domains, domain)
	}
	return domains
}

// GetPendingLiveness returns domains that need liveness checking
func (dt *DomainTracker) GetPendingLiveness() []string {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	domains := make([]string, 0, len(dt.pendingLiveness))
	for domain := range dt.pendingLiveness {
		domains = append(domains, domain)
	}
	return domains
}

// GetAllDomains returns all discovered domains as a slice
func (dt *DomainTracker) GetAllDomains() []string {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	domains := make([]string, 0, len(dt.allDomains))
	for domain := range dt.allDomains {
		domains = append(domains, domain)
	}
	return domains
}

// GetDomainCount returns the total number of discovered domains
func (dt *DomainTracker) GetDomainCount() int {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	return len(dt.allDomains)
}

// SetCurrentRound sets the current discovery round
func (dt *DomainTracker) SetCurrentRound(round int) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	dt.currentRound = round
}

// GetCurrentRound returns the current discovery round
func (dt *DomainTracker) GetCurrentRound() int {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	return dt.currentRound
}

// GetStatistics returns statistics about the discovery process
func (dt *DomainTracker) GetStatistics() DomainTrackerStats {
	dt.mu.RLock()
	defer dt.mu.RUnlock()

	return DomainTrackerStats{
		TotalDomains:       len(dt.allDomains),
		PendingPassive:     len(dt.pendingPassive),
		PendingCertificate: len(dt.pendingCertificate),
		PendingLiveness:    len(dt.pendingLiveness),
		CurrentRound:       dt.currentRound,
	}
}

// DomainTrackerStats provides statistics about the domain tracking process
type DomainTrackerStats struct {
	TotalDomains       int `json:"total_domains"`
	PendingPassive     int `json:"pending_passive"`
	PendingCertificate int `json:"pending_certificate"`
	PendingLiveness    int `json:"pending_liveness"`
	CurrentRound       int `json:"current_round"`
}
