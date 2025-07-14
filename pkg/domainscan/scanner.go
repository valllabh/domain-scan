package domainscan

import (
	"context"
	"log"

	"github.com/valllabh/domain-scan/pkg/utils"
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

// Scanner represents the main domain asset discovery scanner
type Scanner struct {
	config   *Config
	logger   Logger
	sugar    SugaredLogger
	progress ProgressCallback
}

// New creates a new Scanner instance with the given configuration
func New(config *Config) *Scanner {
	if config == nil {
		config = DefaultConfig()
	}
	if err := config.Validate(); err != nil {
		log.Printf("Warning: config validation failed: %v", err)
	}

	return &Scanner{
		config: config,
		logger: log.Default(),
	}
}

// SetLogger sets a custom logger for the scanner
func (s *Scanner) SetLogger(logger Logger) {
	s.logger = logger
}

// SetSugaredLogger sets a Zap sugared logger for the scanner
func (s *Scanner) SetSugaredLogger(sugar SugaredLogger) {
	s.sugar = sugar
}

// SetProgressCallback sets a progress callback for the scanner
func (s *Scanner) SetProgressCallback(callback ProgressCallback) {
	s.progress = callback
}

// DiscoverAssets performs comprehensive domain asset discovery
func (s *Scanner) DiscoverAssets(ctx context.Context, domains []string) (*AssetDiscoveryResult, error) {
	req := DefaultScanRequest(domains)
	req.Keywords = s.config.Keywords
	req.Ports = s.config.Ports.Default
	req.MaxSubdomains = s.config.Discovery.MaxSubdomains
	req.MaxDiscoveryRounds = s.config.Discovery.MaxDiscoveryRounds
	req.Timeout = s.config.Discovery.Timeout
	req.EnablePassive = s.config.Discovery.PassiveEnabled
	req.EnableCertScan = s.config.Discovery.CertificateEnabled
	req.EnableHTTPScan = s.config.Discovery.HTTPEnabled
	req.EnableSisterDomains = s.config.Discovery.SisterDomainEnabled

	return s.ScanWithOptions(ctx, req)
}

// ScanWithOptions performs domain asset discovery using message queue-based processing
func (s *Scanner) ScanWithOptions(ctx context.Context, req *ScanRequest) (*AssetDiscoveryResult, error) {
	if len(req.Domains) == 0 {
		return nil, NewError(ErrInvalidConfig, "no domains provided", nil)
	}

	// Extract keywords if not provided
	keywords := req.Keywords
	if len(keywords) == 0 {
		keywords = utils.ExtractKeywordsFromDomains(req.Domains)
	}

	// Notify start of discovery
	if s.progress != nil {
		s.progress.OnStart(req.Domains, keywords)
	}

	// Create domain processor with message queues
	processor := NewDomainProcessor(ctx, keywords, req.Ports, s.progress, req.EnablePassive, req.EnableCertScan, s.sugar)

	// Queue initial domains appropriately based on enabled features
	for _, domain := range req.Domains {
		// Add domain to tracking first
		processor.AddDomain(domain)

		if req.EnablePassive {
			processor.QueuePassive(domain)
		} else if req.EnableCertScan {
			// If passive is disabled but cert is enabled, go directly to certificate analysis
			processor.QueueCertificate(domain)
		}
	}

	// Start processing with worker pools
	processor.Start()

	// Wait for completion (all queues empty)
	processor.WaitForCompletion()

	// Get final results
	result := processor.GetResults()

	if s.progress != nil {
		s.progress.OnEnd(result)
	}

	return result, nil
}

// GetConfig returns the current scanner configuration
func (s *Scanner) GetConfig() *Config {
	return s.config
}

// UpdateConfig updates the scanner configuration
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
