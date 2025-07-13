package domainscan

import (
	"context"
	"log"
	"time"

	"github.com/valllabh/domain-scan/pkg/discovery"
	"github.com/valllabh/domain-scan/pkg/types"
	"github.com/valllabh/domain-scan/pkg/utils"
)

// Logger interface for customizable logging
type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

// Scanner represents the main domain asset discovery scanner
type Scanner struct {
	config   *Config
	logger   Logger
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
	req.Timeout = s.config.Discovery.Timeout
	req.EnablePassive = s.config.Discovery.PassiveEnabled
	req.EnableCertScan = s.config.Discovery.CertificateEnabled
	req.EnableHTTPScan = s.config.Discovery.HTTPEnabled

	return s.ScanWithOptions(ctx, req)
}

// ScanWithOptions performs domain asset discovery with custom options
func (s *Scanner) ScanWithOptions(ctx context.Context, req *ScanRequest) (*AssetDiscoveryResult, error) {
	if len(req.Domains) == 0 {
		return nil, NewError(ErrInvalidConfig, "no domains provided", nil)
	}

	startTime := time.Now()

	result := &AssetDiscoveryResult{
		Subdomains:     make([]string, 0),
		ActiveServices: make([]types.WebAsset, 0),
		TLSAssets:     make([]types.TLSAsset, 0),
		Statistics:    DiscoveryStats{},
		Errors:        make([]error, 0),
	}

	// Step 1: Extract keywords if not provided
	keywords := req.Keywords
	if len(keywords) == 0 {
		keywords = utils.ExtractKeywordsFromDomains(req.Domains)
	}
	
	// Notify start of discovery
	if s.progress != nil {
		s.progress.OnDiscoveryStart(req.Domains, keywords)
	}

	// Check and install dependencies if needed
	if s.config.Dependencies.AutoInstall {
		if s.progress != nil {
			s.progress.OnDependencyCheck()
		}
		if err := s.checkDependencies(ctx); err != nil {
			result.Errors = append(result.Errors, err)
			return result, err
		}
	}

	allDomains := make(map[string]bool)
	
	// Add original domains
	for _, domain := range req.Domains {
		allDomains[domain] = true
	}

	// Step 2: Passive subdomain discovery
	if req.EnablePassive {
		if s.progress != nil {
			s.progress.OnPassiveDiscoveryStart()
		}
		subdomains, err := discovery.PassiveDiscovery(ctx, req.Domains)
		if err != nil {
			result.Errors = append(result.Errors, NewError(ErrPassiveDiscoveryFailed, "passive discovery failed", err))
		} else {
			for _, subdomain := range subdomains {
				allDomains[subdomain] = true
			}
			result.Statistics.PassiveResults = len(subdomains)
		}
		if s.progress != nil {
			s.progress.OnPassiveDiscoveryComplete(subdomains, err)
		}
	}

	// Step 3: TLS certificate analysis
	if req.EnableCertScan {
		if s.progress != nil {
			s.progress.OnCertificateAnalysisStart()
		}
		tlsAssets, tlsSubdomains, err := discovery.CertificateAnalysis(ctx, req.Domains, keywords)
		if err != nil {
			result.Errors = append(result.Errors, NewError(ErrCertificateAnalysisFailed, "certificate analysis failed", err))
		} else {
			result.TLSAssets = tlsAssets
			for _, subdomain := range tlsSubdomains {
				allDomains[subdomain] = true
			}
			result.Statistics.CertificateResults = len(tlsSubdomains)
		}
		if s.progress != nil {
			s.progress.OnCertificateAnalysisComplete(tlsAssets, tlsSubdomains, err)
		}
	}

	// Convert map to slice
	var allSubdomains []string
	for domain := range allDomains {
		allSubdomains = append(allSubdomains, domain)
	}
	result.Subdomains = allSubdomains
	result.Statistics.TotalSubdomains = len(allSubdomains)

	// Step 4: HTTP service verification
	if req.EnableHTTPScan && len(allSubdomains) > 0 {
		// Apply subdomain limit
		subdomainsToScan := allSubdomains
		if req.MaxSubdomains > 0 && len(allSubdomains) > req.MaxSubdomains {
			if s.progress != nil {
				s.progress.OnHTTPScanLimitApplied(req.MaxSubdomains, len(allSubdomains))
			}
			subdomainsToScan = allSubdomains[:req.MaxSubdomains]
		}
		
		totalTargets := len(subdomainsToScan) * len(req.Ports)
		if s.progress != nil {
			s.progress.OnHTTPScanStart(totalTargets)
		}

		webAssets, err := discovery.HTTPServiceScan(ctx, subdomainsToScan, req.Ports)
		if err != nil {
			result.Errors = append(result.Errors, NewError(ErrHTTPScanFailed, "HTTP scanning failed", err))
		} else {
			result.ActiveServices = webAssets
			result.Statistics.HTTPResults = len(webAssets)
			result.Statistics.TargetsScanned = totalTargets
		}
		if s.progress != nil {
			s.progress.OnHTTPScanComplete(webAssets, err)
		}
	}

	// Final statistics
	result.Statistics.Duration = time.Since(startTime)
	result.Statistics.ActiveServices = len(result.ActiveServices)

	if s.progress != nil {
		s.progress.OnScanComplete(result)
	}

	return result, nil
}

// checkDependencies ensures required tools are available
func (s *Scanner) checkDependencies(ctx context.Context) error {
	if err := utils.CheckAndInstallDependencies(); err != nil {
		return NewError(ErrDependencyMissing, "dependency check failed", err)
	}
	
	return nil
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