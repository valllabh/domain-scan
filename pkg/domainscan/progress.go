package domainscan

import "github.com/domain-scan/domain-scan/pkg/types"

// ProgressCallback provides optional progress updates for long-running operations
type ProgressCallback interface {
	// OnDiscoveryStart is called when domain asset discovery begins
	OnDiscoveryStart(domains []string, keywords []string)
	
	// OnDependencyCheck is called when checking/installing dependencies
	OnDependencyCheck()
	
	// OnPassiveDiscoveryStart is called when passive subdomain discovery begins
	OnPassiveDiscoveryStart()
	
	// OnPassiveDiscoveryComplete is called when passive discovery finishes
	OnPassiveDiscoveryComplete(subdomains []string, err error)
	
	// OnCertificateAnalysisStart is called when TLS certificate analysis begins
	OnCertificateAnalysisStart()
	
	// OnCertificateAnalysisComplete is called when certificate analysis finishes
	OnCertificateAnalysisComplete(tlsAssets []types.TLSAsset, newDomains []string, err error)
	
	// OnHTTPScanStart is called when HTTP service verification begins
	OnHTTPScanStart(totalTargets int)
	
	// OnHTTPScanLimitApplied is called when subdomain limit is applied for HTTP scanning
	OnHTTPScanLimitApplied(limit int, total int)
	
	// OnHTTPScanComplete is called when HTTP scanning finishes
	OnHTTPScanComplete(activeServices []types.WebAsset, err error)
	
	// OnScanComplete is called when the entire scan finishes
	OnScanComplete(result *AssetDiscoveryResult)
}