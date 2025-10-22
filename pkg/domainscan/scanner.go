package domainscan

import (
	"context"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/valllabh/domain-scan/pkg/discovery"
	"github.com/valllabh/domain-scan/pkg/logging"
	"github.com/valllabh/domain-scan/pkg/types"
	"github.com/valllabh/domain-scan/pkg/utils"
)

// Scanner orchestrates domain asset discovery using passive enumeration,
// certificate analysis, and HTTP verification to identify active subdomains
type Scanner struct {
	config   *Config
	logger   *gologger.Logger
	progress ProgressCallback
}

// New creates a new Scanner instance with the given configuration.
// If config is nil, uses DefaultConfig(). Returns nil if config validation fails.
func New(config *Config) *Scanner {
	if config == nil {
		config = DefaultConfig()
	}
	if err := config.Validate(); err != nil {
		return nil
	}

	// Initialize gologger based on log level
	logging.InitLogger(config.LogLevel)
	logger := logging.GetLogger()

	return &Scanner{
		config: config,
		logger: logger,
	}
}

// SetProgressCallback sets a progress callback for real-time updates.
// Enables integration with CLI, web UIs, or custom progress handlers.
func (s *Scanner) SetProgressCallback(callback ProgressCallback) {
	s.progress = callback
}

// DiscoverAssets performs comprehensive domain asset discovery using scanner's configuration.
// Automatically extracts keywords from domains and applies configured discovery methods.
func (s *Scanner) DiscoverAssets(ctx context.Context, domains []string) (*AssetDiscoveryResult, error) {
	req := DefaultScanRequest(domains)
	req.Keywords = s.config.Keywords
	req.Timeout = s.config.Discovery.Timeout

	return s.ScanWithOptions(ctx, req)
}

// ScanWithOptions performs domain asset discovery with custom options.
// Implements the core discovery algorithm: passive enumeration -> certificate analysis -> HTTP verification.
func (s *Scanner) ScanWithOptions(ctx context.Context, req *ScanRequest) (*AssetDiscoveryResult, error) {
	if len(req.Domains) == 0 {
		return nil, NewError(ErrInvalidConfig, "no domains provided", nil)
	}

	domains := req.Domains
	keywords := utils.LoadKeywords(domains, req.Keywords)
	outputDomains := make(map[string]*DomainEntry)

	// Global tracking to prevent infinite loops
	processedDomains := make(map[string]bool)

	if s.progress != nil {
		s.progress.OnStart(domains, keywords)
	}

	s.logDebug("Starting passiveScan with domains: %v", domains)
	s.passiveScanWithTracking(ctx, domains, keywords, outputDomains, processedDomains, 0)
	s.logDebug("Completed passiveScan")

	result := &AssetDiscoveryResult{
		Domains:    outputDomains,
		Statistics: DiscoveryStats{},
		Errors:     []error{},
	}

	// Update statistics
	result.Statistics.TotalSubdomains = len(outputDomains)
	result.Statistics.ActiveServices = s.countLiveDomainsFromMap(outputDomains)
	result.Statistics.TracedDomains = result.Statistics.TotalSubdomains - result.Statistics.ActiveServices

	if s.progress != nil {
		s.progress.OnEnd(result)
	}

	return result, nil
}

// logDebug logs debug message using gologger
func (s *Scanner) logDebug(msg string, args ...interface{}) {
	if s.logger != nil {
		s.logger.Debug().Msgf(msg, args...)
	}
}

// logInfo logs info message using gologger
func (s *Scanner) logInfo(msg string, args ...interface{}) {
	if s.logger != nil {
		s.logger.Info().Msgf(msg, args...)
	}
}

// logWarn logs warn message using gologger
func (s *Scanner) logWarn(msg string, args ...interface{}) {
	if s.logger != nil {
		s.logger.Warning().Msgf(msg, args...)
	}
}

// logError logs error message using gologger
func (s *Scanner) logError(msg string, args ...interface{}) {
	if s.logger != nil {
		s.logger.Error().Msgf(msg, args...)
	}
}

// passiveScanWithTracking performs passive subdomain enumeration using subfinder.
// Collects subdomains for each input domain and batches them for certificate analysis.
func (s *Scanner) passiveScanWithTracking(ctx context.Context, domains []string, keywords []string, outputDomains map[string]*DomainEntry, processedDomains map[string]bool, depth int) {
	// Check if passive discovery is disabled
	if !s.config.Discovery.EnablePassive {
		s.logDebug("Passive discovery disabled, skipping")
		// Always perform HTTP verification on original domains even if certificate discovery is disabled
		// This ensures we at least check if the provided domains are live
		s.httpVerificationOnly(ctx, domains, outputDomains, processedDomains)

		// If certificate discovery is enabled, also scan certificates for additional domains
		if s.config.Discovery.EnableCertificate {
			s.certificateScanWithTracking(ctx, domains, keywords, outputDomains, processedDomains, depth)
		}
		return
	}

	// Check recursion depth limit
	if s.config.Discovery.RecursionDepth > 0 && depth >= s.config.Discovery.RecursionDepth {
		s.logDebug("Recursion depth limit reached (%d), skipping passive scan", depth)
		return
	}
	// Filter unprocessed domains for bulk processing
	var unprocessedDomains []string
	for _, domain := range domains {
		passiveKey := "passive:" + domain
		if processedDomains[passiveKey] {
			s.logDebug("Skipping passive scan for %s (already processed)", domain)
			continue
		}
		processedDomains[passiveKey] = true
		unprocessedDomains = append(unprocessedDomains, domain)
	}

	if len(unprocessedDomains) == 0 {
		s.logDebug("No unprocessed domains for passive scan")
		return
	}

	s.logInfo("Starting bulk passive scan for %d domains", len(unprocessedDomains))
	s.logDebug("Domains to process: %v", unprocessedDomains)

	// Check if we've hit max domains limit before passive discovery
	if s.config.Discovery.MaxDomains > 0 && len(outputDomains) >= s.config.Discovery.MaxDomains {
		s.logInfo("Max domains limit reached (%d), skipping further discovery", s.config.Discovery.MaxDomains)
		return
	}

	// Run bulk passive discovery with configured sources
	subdomains, err := discovery.PassiveDiscoveryWithOptions(ctx, unprocessedDomains, s.config.Discovery.Sources, s.logger)
	if err != nil {
		s.logError("Bulk passive discovery failed: %v", err)
		return
	}

	s.logInfo("Bulk passive discovery found %d subdomains", len(subdomains))
	s.logDebug("Found subdomains: %v", subdomains)

	// Track passive discovery source for all discovered subdomains
	for _, subdomain := range subdomains {
		entry, exists := outputDomains[subdomain]
		if !exists {
			entry = &DomainEntry{
				Domain:  subdomain,
				Sources: []types.Source{},
			}
			outputDomains[subdomain] = entry
		}
		addSource(entry, "subfinder", "passive")
	}

	// Prepare certificate scan batch with original domains + discovered subdomains
	certScanBatch := make([]string, 0, len(unprocessedDomains)+len(subdomains))
	certScanBatch = append(certScanBatch, unprocessedDomains...)
	certScanBatch = append(certScanBatch, subdomains...)

	s.logInfo("Processing certificate scans for %d domains", len(certScanBatch))
	s.logDebug("certScanBatch domains: %v", certScanBatch)
	s.certificateScanWithTracking(ctx, certScanBatch, keywords, outputDomains, processedDomains, depth)
	s.logInfo("Completed all certificate scans")
}

// certificateScanWithTracking performs certificate analysis on bulk domains.
// Filters already processed domains and performs HTTP verification with certificate analysis.
func (s *Scanner) certificateScanWithTracking(ctx context.Context, domains []string, keywords []string, outputDomains map[string]*DomainEntry, processedDomains map[string]bool, depth int) {
	// Check if certificate discovery is disabled
	if !s.config.Discovery.EnableCertificate {
		s.logDebug("Certificate discovery disabled, skipping")
		return
	}

	// Check if we've hit max domains limit
	if s.config.Discovery.MaxDomains > 0 && len(outputDomains) >= s.config.Discovery.MaxDomains {
		s.logInfo("Max domains limit reached (%d), skipping certificate scan", s.config.Discovery.MaxDomains)
		return
	}
	if len(domains) == 0 {
		return
	}

	validDomains := s.filterUnprocessedDomains(domains, processedDomains, "cert")
	if len(validDomains) == 0 {
		return
	}

	newDomains := s.bulkAnalyzeAndMerge(ctx, validDomains, keywords, s.config.Discovery.EnableCertificate, "cert", "certificate analysis", outputDomains, processedDomains)

	s.logInfo("Found %d new domains from certificate", len(newDomains))
	s.logDebug("New domains: %v", newDomains)

	// Only recurse if recursive discovery is enabled
	if !s.config.Discovery.Recursive {
		s.logDebug("Recursive discovery disabled, skipping recursion")
		return
	}

	// Check recursion depth limit
	if s.config.Discovery.RecursionDepth > 0 && depth+1 >= s.config.Discovery.RecursionDepth {
		s.logDebug("Recursion depth limit would be reached (%d), skipping recursion", depth+1)
		return
	}

	for _, newDomain := range newDomains {
		// Check max domains limit before each recursive call
		if s.config.Discovery.MaxDomains > 0 && len(outputDomains) >= s.config.Discovery.MaxDomains {
			s.logInfo("Max domains limit reached (%d), stopping recursion", s.config.Discovery.MaxDomains)
			return
		}

		if s.isSubdomain(newDomain) {
			s.logDebug("Recursively calling cert scan for subdomain: %s (depth %d)", newDomain, depth+1)
			s.certificateScanWithTracking(ctx, []string{newDomain}, keywords, outputDomains, processedDomains, depth+1)
		} else {
			s.logDebug("Recursively calling passive scan for main domain: %s (depth %d)", newDomain, depth+1)
			s.passiveScanWithTracking(ctx, []string{newDomain}, keywords, outputDomains, processedDomains, depth+1)
		}
	}
}

// isSubdomain determines if a domain is a subdomain by counting DNS labels.
// Domains with more than 2 parts (e.g., sub.example.com) are considered subdomains.
func (s *Scanner) isSubdomain(domain string) bool {
	parts := strings.Split(domain, ".")
	return len(parts) > 2
}

// countLiveDomainsFromMap counts domains that responded to HTTP requests.
// Used for progress reporting and final statistics calculation.
func (s *Scanner) countLiveDomainsFromMap(domains map[string]*DomainEntry) int {
	count := 0
	for _, entry := range domains {
		if entry.IsLive {
			count++
		}
	}
	return count
}

// GetConfig returns a copy of the current scanner configuration.
// Useful for inspection and debugging of active settings.
func (s *Scanner) GetConfig() *Config {
	return s.config
}

// UpdateConfig validates and updates the scanner configuration.
// Returns error if the new configuration is invalid.
// Also reinitializes logger if log level changed.
func (s *Scanner) UpdateConfig(config *Config) error {
	if config == nil {
		return NewError(ErrInvalidConfig, "config cannot be nil", nil)
	}

	if err := config.Validate(); err != nil {
		return NewError(ErrInvalidConfig, "invalid configuration", err)
	}

	s.config = config

	// Reinitialize logger if log level changed
	logging.InitLogger(config.LogLevel)
	s.logger = logging.GetLogger()

	return nil
}

// filterUnprocessedDomains filters domains that haven't been processed yet using a tracking map.
// Marks domains as processed and returns the list of unprocessed domains.
func (s *Scanner) filterUnprocessedDomains(domains []string, processedDomains map[string]bool, keyPrefix string) []string {
	var validDomains []string
	for _, domain := range domains {
		key := keyPrefix + ":" + domain

		if processedDomains[key] {
			s.logDebug("Skipping %s scan for %s (already processed)", keyPrefix, domain)
			continue
		}
		processedDomains[key] = true
		s.logDebug("Starting %s scan for domain: %s", keyPrefix, domain)
		validDomains = append(validDomains, domain)
	}
	return validDomains
}

// httpVerificationOnly performs HTTP verification on domains without certificate discovery.
// Used when passive discovery is disabled to still verify if domains are live.
func (s *Scanner) httpVerificationOnly(ctx context.Context, domains []string, outputDomains map[string]*DomainEntry, processedDomains map[string]bool) {
	s.bulkAnalyzeAndMerge(ctx, domains, []string{}, false, "http", "HTTP verification", outputDomains, processedDomains)
}

// bulkAnalyzeAndMerge performs bulk certificate analysis and merges results into outputDomains.
// Returns the list of newly discovered domains from certificate SANs.
func (s *Scanner) bulkAnalyzeAndMerge(ctx context.Context, domains []string, keywords []string, extractNewDomains bool, processKeyPrefix string, operationName string, outputDomains map[string]*DomainEntry, processedDomains map[string]bool) []string {
	// Filter unprocessed domains if not already filtered
	var targetDomains []string
	if processKeyPrefix != "cert" {
		// For HTTP verification, filter here
		for _, domain := range domains {
			key := processKeyPrefix + ":" + domain
			if processedDomains[key] {
				s.logDebug("Skipping %s for %s (already processed)", operationName, domain)
				continue
			}
			processedDomains[key] = true
			targetDomains = append(targetDomains, domain)
		}
	} else {
		// For certificate scan, already filtered by caller
		targetDomains = domains
	}

	if len(targetDomains) == 0 {
		s.logDebug("No unprocessed domains for %s", operationName)
		return []string{}
	}

	s.logInfo("Running bulk %s for %d targets", operationName, len(targetDomains))
	s.logDebug("Bulk targets: %v", targetDomains)

	domainEntries, newDomains, err := discovery.BulkCertificateAnalysisForScanner(ctx, targetDomains, keywords, extractNewDomains, s.logger)
	if err != nil {
		s.logWarn("Bulk %s error: %v", operationName, err)
		return []string{}
	}

	s.logInfo("Bulk %s results - domainEntries: %d, newDomains: %d", operationName, len(domainEntries), len(newDomains))

	logPrefix := "Added"
	if processKeyPrefix == "http" {
		logPrefix = "Verified"
	}
	s.mergeDomainEntries(domainEntries, outputDomains, logPrefix)

	return newDomains
}

// mergeDomainEntries merges domain entries into outputDomains and updates progress
func (s *Scanner) mergeDomainEntries(domainEntries []*DomainEntry, outputDomains map[string]*DomainEntry, logPrefix string) {
	liveDomainCount := s.countLiveDomainsFromMap(outputDomains)
	for _, domainEntry := range domainEntries {
		// Merge with existing entry if present
		if existing, exists := outputDomains[domainEntry.Domain]; exists {
			existing.Status = domainEntry.Status
			existing.IsLive = domainEntry.IsLive
			existing.URL = domainEntry.URL
			existing.IP = domainEntry.IP
			existing.Redirect = domainEntry.Redirect
			existing.Certificate = domainEntry.Certificate
			// Merge sources
			for _, src := range domainEntry.Sources {
				addSource(existing, src.Name, src.Type)
			}
		} else {
			outputDomains[domainEntry.Domain] = domainEntry
		}

		s.logInfo("%s domain %s (live: %t, status: %d)", logPrefix, domainEntry.Domain, domainEntry.IsLive, domainEntry.Status)

		if domainEntry.IsLive {
			liveDomainCount++
		}

		if s.progress != nil {
			s.progress.OnProgress(len(outputDomains), liveDomainCount)
		}
	}
}

// addSource adds a source to a domain entry, avoiding duplicates
func addSource(entry *DomainEntry, name string, sourceType string) {
	// Check if source already exists
	for _, src := range entry.Sources {
		if src.Name == name && src.Type == sourceType {
			return
		}
	}
	// Add new source
	entry.Sources = append(entry.Sources, types.Source{
		Name: name,
		Type: sourceType,
	})
}
