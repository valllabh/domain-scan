package domainscan

// ProgressCallback provides optional progress updates for long-running operations
type ProgressCallback interface {
	// OnStart is called when domain asset discovery begins
	OnStart(domains []string, keywords []string)

	// OnProgress is called with unified progress updates
	OnProgress(totalDomains, liveDomains int)

	// OnEnd is called when the entire scan finishes
	OnEnd(result *AssetDiscoveryResult)
}
