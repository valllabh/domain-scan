package domainscan

import (
	"context"
	"log"
	"strings"

	"github.com/valllabh/domain-scan/pkg/discovery"
	"github.com/valllabh/domain-scan/pkg/logging"
	"github.com/valllabh/domain-scan/pkg/utils"
	"go.uber.org/zap"
)

// Logger interface for customizable logging
type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

// SugaredLogger interface for Zap sugared logging
type SugaredLogger interface {
	Debugf(template string, args ...interface{})
	Infof(template string, args ...interface{})
	Warnf(template string, args ...interface{})
	Errorf(template string, args ...interface{})
}

// Scanner orchestrates domain asset discovery using passive enumeration,
// certificate analysis, and HTTP verification to identify active subdomains
type Scanner struct {
	config   *Config
	logger   Logger
	sugar    *zap.SugaredLogger
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

	// Initialize zap logger based on log level
	zapLogger := logging.InitZapLogger(config.LogLevel)
	sugar := zapLogger.Sugar()

	return &Scanner{
		config: config,
		logger: log.Default(),
		sugar:  sugar,
	}
}

// SetLogger sets a custom logger for the scanner.
// Used for backward compatibility with standard log interface.
func (s *Scanner) SetLogger(logger Logger) {
	s.logger = logger
}

// SetSugaredLogger sets a Zap sugared logger for structured logging.
// Provides better performance and structured output than standard logger.
func (s *Scanner) SetSugaredLogger(sugar *zap.SugaredLogger) {
	s.sugar = sugar
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
	req.MaxDiscoveryRounds = s.config.Discovery.MaxDiscoveryRounds
	req.Timeout = s.config.Discovery.Timeout
	req.EnablePassive = s.config.Discovery.PassiveEnabled
	req.EnableCertScan = s.config.Discovery.CertificateEnabled
	req.EnableHTTPScan = s.config.Discovery.HTTPEnabled
	req.EnableSisterDomains = s.config.Discovery.SisterDomainEnabled

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
	s.passiveScanWithTracking(ctx, domains, keywords, outputDomains, processedDomains)
	s.logDebug("Completed passiveScan")

	result := &AssetDiscoveryResult{
		Domains:    outputDomains,
		Statistics: DiscoveryStats{},
		Errors:     []error{},
	}

	// Update statistics
	result.Statistics.TotalSubdomains = len(outputDomains)
	result.Statistics.ActiveServices = s.countLiveDomainsFromMap(outputDomains)

	if s.progress != nil {
		s.progress.OnEnd(result)
	}

	return result, nil
}

// logDebug logs debug message if sugar logger is available
func (s *Scanner) logDebug(msg string, args ...interface{}) {
	if s.sugar != nil {
		s.sugar.Debugf(msg, args...)
	}
}

// logInfo logs info message if sugar logger is available
func (s *Scanner) logInfo(msg string, args ...interface{}) {
	if s.sugar != nil {
		s.sugar.Infof(msg, args...)
	}
}

// logWarn logs warn message if sugar logger is available
func (s *Scanner) logWarn(msg string, args ...interface{}) {
	if s.sugar != nil {
		s.sugar.Warnf(msg, args...)
	}
}

// logError logs error message if sugar logger is available
func (s *Scanner) logError(msg string, args ...interface{}) {
	if s.sugar != nil {
		s.sugar.Errorf(msg, args...)
	}
}

// passiveScanWithTracking performs passive subdomain enumeration using subfinder.
// Collects subdomains for each input domain and batches them for certificate analysis.
func (s *Scanner) passiveScanWithTracking(ctx context.Context, domains []string, keywords []string, outputDomains map[string]*DomainEntry, processedDomains map[string]bool) {
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

	// Run bulk passive discovery
	subdomains, err := discovery.PassiveDiscoveryWithLogger(ctx, unprocessedDomains, s.sugar)
	if err != nil {
		s.logError("Bulk passive discovery failed: %v", err)
		return
	}

	s.logInfo("Bulk passive discovery found %d subdomains", len(subdomains))
	s.logDebug("Found subdomains: %v", subdomains)

	// Prepare certificate scan batch with original domains + discovered subdomains
	certScanBatch := make([]string, 0, len(unprocessedDomains)+len(subdomains))
	certScanBatch = append(certScanBatch, unprocessedDomains...)
	certScanBatch = append(certScanBatch, subdomains...)

	s.logInfo("Processing certificate scans for %d domains", len(certScanBatch))
	s.logDebug("certScanBatch domains: %v", certScanBatch)
	s.certificateScanWithTracking(ctx, certScanBatch, keywords, outputDomains, processedDomains)
	s.logInfo("Completed all certificate scans")
}

// certificateScanWithTracking performs certificate analysis on bulk domains.
// Filters already processed domains and performs HTTP verification with certificate analysis.
func (s *Scanner) certificateScanWithTracking(ctx context.Context, domains []string, keywords []string, outputDomains map[string]*DomainEntry, processedDomains map[string]bool) {
	if len(domains) == 0 {
		return
	}

	validDomains := s.filterUnprocessedDomains(domains, processedDomains, "cert")
	if len(validDomains) == 0 {
		return
	}

	s.logInfo("Running bulk certificate analysis for %d targets", len(validDomains))
	s.logDebug("Bulk targets: %v", validDomains)

	domainEntries, newDomains, err := discovery.BulkCertificateAnalysisForScanner(ctx, validDomains, keywords, s.sugar)
	if err != nil {
		s.logWarn("Bulk certificate analysis error: %v", err)
		return
	}

	s.logInfo("Bulk certificate analysis results - domainEntries: %d, newDomains: %d", len(domainEntries), len(newDomains))

	liveDomainCount := s.countLiveDomainsFromMap(outputDomains)
	for _, domainEntry := range domainEntries {
		outputDomains[domainEntry.Domain] = domainEntry
		s.logInfo("Added domain %s (live: %t, status: %d)", domainEntry.Domain, domainEntry.IsLive, domainEntry.Status)

		if domainEntry.IsLive {
			liveDomainCount++
		}

		if s.progress != nil {
			s.progress.OnProgress(len(outputDomains), liveDomainCount)
		}
	}

	s.logInfo("Found %d new domains from certificate", len(newDomains))
	s.logDebug("New domains: %v", newDomains)
	for _, newDomain := range newDomains {
		if s.isSubdomain(newDomain) {
			s.logDebug("Recursively calling cert scan for subdomain: %s", newDomain)
			s.certificateScanWithTracking(ctx, []string{newDomain}, keywords, outputDomains, processedDomains)
		} else {
			s.logDebug("Recursively calling passive scan for main domain: %s", newDomain)
			s.passiveScanWithTracking(ctx, []string{newDomain}, keywords, outputDomains, processedDomains)
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
func (s *Scanner) UpdateConfig(config *Config) error {
	if config == nil {
		return NewError(ErrInvalidConfig, "config cannot be nil", nil)
	}

	if err := config.Validate(); err != nil {
		return NewError(ErrInvalidConfig, "invalid configuration", err)
	}

	s.config = config
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
