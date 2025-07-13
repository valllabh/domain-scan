package domainscan

import (
	"log"

	"github.com/valllabh/domain-scan/pkg/types"
)

// CLIProgressHandler implements ProgressCallback for command line interface
type CLIProgressHandler struct{}

// NewCLIProgressHandler creates a new CLI progress handler
func NewCLIProgressHandler() *CLIProgressHandler {
	return &CLIProgressHandler{}
}

// OnDiscoveryStart is called when domain asset discovery begins
func (c *CLIProgressHandler) OnDiscoveryStart(domains []string, keywords []string) {
	log.Printf("🔍 Starting domain asset discovery for %d domains", len(domains))
	if len(keywords) > 0 {
		log.Printf("🔑 Using keywords: %v", keywords)
	}
}

// OnDependencyCheck is called when checking/installing dependencies
func (c *CLIProgressHandler) OnDependencyCheck() {
	log.Println("🔧 Checking dependencies...")
}

// OnPassiveDiscoveryStart is called when passive subdomain discovery begins
func (c *CLIProgressHandler) OnPassiveDiscoveryStart() {
	log.Println("🔍 Starting passive subdomain discovery")
}

// OnPassiveDiscoveryComplete is called when passive discovery finishes
func (c *CLIProgressHandler) OnPassiveDiscoveryComplete(subdomains []string, err error) {
	if err != nil {
		log.Printf("⚠️  Passive discovery failed: %v", err)
	} else {
		log.Printf("📋 Passive discovery found %d subdomains", len(subdomains))
	}
}

// OnCertificateAnalysisStart is called when TLS certificate analysis begins
func (c *CLIProgressHandler) OnCertificateAnalysisStart() {
	log.Println("🔐 Starting TLS certificate analysis")
}

// OnCertificateAnalysisComplete is called when certificate analysis finishes
func (c *CLIProgressHandler) OnCertificateAnalysisComplete(tlsAssets []types.TLSAsset, newDomains []string, err error) {
	if err != nil {
		log.Printf("⚠️  Certificate analysis failed: %v", err)
	} else {
		log.Printf("🔐 Certificate analysis found %d additional subdomains", len(newDomains))
	}
}

// OnHTTPScanStart is called when HTTP service verification begins
func (c *CLIProgressHandler) OnHTTPScanStart(totalTargets int) {
	log.Println("🌐 Starting HTTP service verification")
}

// OnHTTPScanLimitApplied is called when subdomain limit is applied for HTTP scanning
func (c *CLIProgressHandler) OnHTTPScanLimitApplied(limit int, total int) {
	log.Printf("⚠️  Limiting HTTP scan to %d subdomains (found %d)", limit, total)
}

// OnHTTPScanComplete is called when HTTP scanning finishes
func (c *CLIProgressHandler) OnHTTPScanComplete(activeServices []types.WebAsset, err error) {
	if err != nil {
		log.Printf("⚠️  HTTP scanning failed: %v", err)
	} else {
		log.Printf("🌐 HTTP scanning found %d active services", len(activeServices))
	}
}

// OnScanComplete is called when the entire scan finishes
func (c *CLIProgressHandler) OnScanComplete(result *AssetDiscoveryResult) {
	log.Printf("✅ Domain asset discovery completed in %v", result.Statistics.Duration)
	log.Printf("📊 Results: %d subdomains, %d active services", 
		result.Statistics.TotalSubdomains, result.Statistics.ActiveServices)
}