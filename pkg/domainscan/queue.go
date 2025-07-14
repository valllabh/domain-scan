package domainscan

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/valllabh/domain-scan/pkg/discovery"
	"github.com/valllabh/domain-scan/pkg/types"
)

// ScanType represents the type of scan to perform
type ScanType int

const (
	Passive     ScanType = iota // Passive subdomain discovery
	Certificate                 // Certificate analysis
)

// ScanMessage represents a domain scanning task
type ScanMessage struct {
	Domain   string
	ScanType ScanType
}

// DomainProcessor manages domain discovery using message queues
type DomainProcessor struct {
	// Queues for different scan types
	passiveQueue     chan ScanMessage
	certificateQueue chan ScanMessage

	// State tracking for deduplication
	processedPassive map[string]bool // Domains that completed passive scan
	processedCert    map[string]bool // Domains that completed certificate scan
	allDomains       map[string]bool // All discovered domains
	liveDomains      map[string]bool // Domains marked as live

	// Configuration
	keywords      []string // Organization keywords for filtering
	ports         []int    // Ports for certificate analysis
	enablePassive bool     // Whether passive discovery is enabled
	enableCert    bool     // Whether certificate analysis is enabled

	// Worker management
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	progress ProgressCallback

	// Results
	tlsAssets []types.TLSAsset
	webAssets []types.WebAsset
	errors    []error
	mu        sync.RWMutex // Protects shared state

	// Statistics
	startTime time.Time

	// Debug logging
	sugar SugaredLogger
}

// NewDomainProcessor creates a new domain processor with message queues
func NewDomainProcessor(ctx context.Context, keywords []string, ports []int, progress ProgressCallback, enablePassive, enableCert bool, sugar SugaredLogger) *DomainProcessor {
	processorCtx, cancel := context.WithCancel(ctx)

	dp := &DomainProcessor{
		passiveQueue:     make(chan ScanMessage, 1000),
		certificateQueue: make(chan ScanMessage, 1000),
		processedPassive: make(map[string]bool),
		processedCert:    make(map[string]bool),
		allDomains:       make(map[string]bool),
		liveDomains:      make(map[string]bool),
		keywords:         keywords,
		ports:            ports,
		enablePassive:    enablePassive,
		enableCert:       enableCert,
		ctx:              processorCtx,
		cancel:           cancel,
		progress:         progress,
		tlsAssets:        make([]types.TLSAsset, 0),
		webAssets:        make([]types.WebAsset, 0),
		errors:           make([]error, 0),
		startTime:        time.Now(),
		sugar:            sugar,
	}

	dp.debug("processor created: keywords=%v ports=%v passive=%t cert=%t",
		keywords, ports, enablePassive, enableCert)

	return dp
}

// debug is a helper method for debug logging
func (dp *DomainProcessor) debug(format string, args ...interface{}) {
	if dp.sugar != nil {
		dp.sugar.Debugf(format, args...)
	}
}

// IsRelevantDomain checks if a domain contains target organization keywords
func (dp *DomainProcessor) IsRelevantDomain(domain string) bool {
	if len(dp.keywords) == 0 {
		return true // If no keywords, accept all domains
	}

	domainLower := strings.ToLower(domain)
	for _, keyword := range dp.keywords {
		if strings.Contains(domainLower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// AddDomain adds a domain to the tracking system
func (dp *DomainProcessor) AddDomain(domain string) {
	dp.mu.Lock()
	if !dp.allDomains[domain] {
		dp.allDomains[domain] = true
		totalDomains := len(dp.allDomains)
		liveDomains := len(dp.liveDomains)
		dp.mu.Unlock()

		dp.debug("add domain: %s (total=%d live=%d)", domain, totalDomains, liveDomains)

		// Send progress update outside the lock
		if dp.progress != nil {
			dp.progress.OnProgress(totalDomains, liveDomains)
		}
	} else {
		dp.mu.Unlock()
		dp.debug("add domain: %s (duplicate)", domain)
	}
}

// QueuePassive adds a domain to the passive discovery queue
func (dp *DomainProcessor) QueuePassive(domain string) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	if !dp.processedPassive[domain] {
		dp.debug("queue passive: %s", domain)
		select {
		case dp.passiveQueue <- ScanMessage{Domain: domain, ScanType: Passive}:
			dp.debug("queued passive: %s ✓", domain)
		case <-dp.ctx.Done():
			dp.debug("queue passive: %s failed (ctx cancelled)", domain)
		}
	} else {
		dp.debug("queue passive: %s (already processed)", domain)
	}
}

// QueueCertificate adds a domain to the certificate analysis queue
func (dp *DomainProcessor) QueueCertificate(domain string) {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	if !dp.processedCert[domain] {
		dp.debug("queue cert: %s", domain)
		select {
		case dp.certificateQueue <- ScanMessage{Domain: domain, ScanType: Certificate}:
			dp.debug("queued cert: %s ✓", domain)
		case <-dp.ctx.Done():
			dp.debug("queue cert: %s failed (ctx cancelled)", domain)
		}
	} else {
		dp.debug("queue cert: %s (already processed)", domain)
	}
}

// Start begins processing with worker pools
func (dp *DomainProcessor) Start() {
	dp.debug("starting workers...")

	// Start passive discovery workers only if passive discovery is enabled
	if dp.enablePassive {
		dp.debug("starting 3 passive workers")
		for i := 0; i < 3; i++ {
			dp.wg.Add(1)
			go dp.passiveWorker(i)
		}
	}

	// Start certificate analysis workers only if certificate analysis is enabled
	if dp.enableCert {
		dp.debug("starting 10 certificate workers")
		for i := 0; i < 10; i++ {
			dp.wg.Add(1)
			go dp.certificateWorker(i)
		}
	}

	dp.debug("all workers started")
}

// passiveWorker processes passive discovery queue
func (dp *DomainProcessor) passiveWorker(id int) {
	defer dp.wg.Done()
	dp.debug("passive worker %d started", id)

	for {
		select {
		case msg := <-dp.passiveQueue:
			dp.debug("passive worker %d processing: %s", id, msg.Domain)
			dp.processPassiveMessage(msg, id)
		case <-dp.ctx.Done():
			dp.debug("passive worker %d stopping (ctx done)", id)
			return
		}
	}
}

// certificateWorker processes certificate analysis queue
func (dp *DomainProcessor) certificateWorker(id int) {
	defer dp.wg.Done()
	dp.debug("cert worker %d started", id)

	for {
		select {
		case msg := <-dp.certificateQueue:
			dp.debug("cert worker %d processing: %s", id, msg.Domain)
			dp.processCertificateMessage(msg, id)
		case <-dp.ctx.Done():
			dp.debug("cert worker %d stopping (ctx done)", id)
			return
		}
	}
}

// processPassiveMessage handles passive discovery for a domain
func (dp *DomainProcessor) processPassiveMessage(msg ScanMessage, workerID int) {
	dp.mu.Lock()
	if dp.processedPassive[msg.Domain] {
		dp.mu.Unlock()
		dp.debug("passive worker %d: %s already processed", workerID, msg.Domain)
		return // Skip duplicates
	}
	dp.processedPassive[msg.Domain] = true
	dp.mu.Unlock()

	dp.debug("passive worker %d: starting discovery for %s", workerID, msg.Domain)

	// Run passive discovery
	subdomains, err := discovery.PassiveDiscovery(dp.ctx, []string{msg.Domain}, nil)
	if err != nil {
		dp.debug("passive worker %d: %s failed - %v", workerID, msg.Domain, err)
		dp.mu.Lock()
		dp.errors = append(dp.errors, err)
		dp.mu.Unlock()
		return
	}

	dp.debug("passive worker %d: %s found %d subdomains", workerID, msg.Domain, len(subdomains))

	// Process discovered domains
	newCount := 0
	for _, domain := range subdomains {
		if dp.IsRelevantDomain(domain) {
			dp.mu.Lock()
			if !dp.allDomains[domain] {
				dp.allDomains[domain] = true
				totalDomains := len(dp.allDomains)
				liveDomains := len(dp.liveDomains)
				dp.mu.Unlock()
				newCount++

				// Send immediate progress update for each new domain
				if dp.progress != nil {
					dp.progress.OnProgress(totalDomains, liveDomains)
				}

				// Queue for certificate analysis if enabled
				if dp.enableCert {
					dp.QueueCertificate(domain)
				}
			} else {
				dp.mu.Unlock()
			}
		}
	}

	dp.debug("passive worker %d: %s completed (%d new domains)", workerID, msg.Domain, newCount)
}

// processCertificateMessage handles certificate analysis for a domain
func (dp *DomainProcessor) processCertificateMessage(msg ScanMessage, workerID int) {
	dp.mu.Lock()
	if dp.processedCert[msg.Domain] {
		dp.mu.Unlock()
		dp.debug("cert worker %d: %s already processed", workerID, msg.Domain)
		return // Skip duplicates
	}

	// Mark as processed - no max domain gate here since this domain was already queued
	dp.processedCert[msg.Domain] = true
	dp.mu.Unlock()

	dp.debug("cert worker %d: starting analysis for %s on ports %v", workerID, msg.Domain, dp.ports)

	// Run certificate analysis on all ports (use the original function without tracker)
	tlsAssets, webAssets, newDomains, err := discovery.CertificateAnalysisSimple(dp.ctx, []string{msg.Domain}, dp.ports, dp.keywords)
	if err != nil {
		dp.debug("cert worker %d: %s failed - %v", workerID, msg.Domain, err)
		dp.mu.Lock()
		dp.errors = append(dp.errors, err)
		dp.mu.Unlock()
		return
	}

	dp.debug("cert worker %d: %s found %d TLS assets, %d web assets, %d new domains", workerID, msg.Domain, len(tlsAssets), len(webAssets), len(newDomains))

	dp.mu.Lock()
	// Add TLS assets
	dp.tlsAssets = append(dp.tlsAssets, tlsAssets...)

	// Add real web assets from HTTP responses (with correct ports and status codes)
	dp.webAssets = append(dp.webAssets, webAssets...)

	// Mark domain as live only if we got actual HTTP responses
	if len(webAssets) > 0 {
		dp.liveDomains[msg.Domain] = true
	}

	// Track counts for progress update
	totalDomains := len(dp.allDomains)
	liveDomains := len(dp.liveDomains)
	dp.mu.Unlock()

	dp.debug("cert worker %d: %s marked as live (total=%d live=%d)", workerID, msg.Domain, totalDomains, liveDomains)

	// Send immediate progress update
	if dp.progress != nil {
		dp.progress.OnProgress(totalDomains, liveDomains)
	}

	// Process discovered domains
	newCount := 0
	for _, domain := range newDomains {
		if dp.IsRelevantDomain(domain) {
			dp.mu.Lock()
			if !dp.allDomains[domain] {
				dp.allDomains[domain] = true
				totalDomains := len(dp.allDomains)
				liveDomains := len(dp.liveDomains)
				dp.mu.Unlock()
				newCount++

				// Send immediate progress update for each new domain
				if dp.progress != nil {
					dp.progress.OnProgress(totalDomains, liveDomains)
				}

				// Queue for passive discovery to find more subdomains if enabled
				if dp.enablePassive {
					dp.QueuePassive(domain)
				}
			} else {
				dp.mu.Unlock()
			}
		}
	}

	dp.debug("cert worker %d: %s completed (%d new domains queued)", workerID, msg.Domain, newCount)
}

// updateProgress sends progress updates to the callback
func (dp *DomainProcessor) updateProgress() {
	if dp.progress != nil {
		dp.mu.RLock()
		totalDomains := len(dp.allDomains)
		liveDomains := len(dp.liveDomains)
		dp.mu.RUnlock()

		dp.progress.OnProgress(totalDomains, liveDomains)
	}
}

// WaitForCompletion waits until all queues are empty and workers are idle
func (dp *DomainProcessor) WaitForCompletion() {
	// Monitor queues until they're empty and no work is being processed
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	lastActivity := time.Now()
	const idleTimeout = 60 * time.Second // Increased timeout for certificate analysis

	for {
		select {
		case <-ticker.C:
			passiveLen := len(dp.passiveQueue)
			certLen := len(dp.certificateQueue)

			if passiveLen > 0 || certLen > 0 {
				lastActivity = time.Now()
			} else if time.Since(lastActivity) > idleTimeout {
				// Queues have been empty for idle timeout, assume completion
				dp.cancel()
				dp.wg.Wait()
				return
			}
		case <-dp.ctx.Done():
			dp.wg.Wait()
			return
		}
	}
}

// GetResults returns the final discovery results
func (dp *DomainProcessor) GetResults() *AssetDiscoveryResult {
	dp.mu.RLock()
	defer dp.mu.RUnlock()

	// Convert domain maps to slices
	var allDomainsList []string
	for domain := range dp.allDomains {
		allDomainsList = append(allDomainsList, domain)
	}

	duration := time.Since(dp.startTime)

	return &AssetDiscoveryResult{
		Subdomains:     allDomainsList,
		ActiveServices: dp.webAssets,
		TLSAssets:      dp.tlsAssets,
		Statistics: DiscoveryStats{
			TotalSubdomains:    len(dp.allDomains),
			ActiveServices:     len(dp.liveDomains),
			PassiveResults:     len(dp.processedPassive),
			CertificateResults: len(dp.processedCert),
			HTTPResults:        len(dp.liveDomains),
			Duration:           duration,
			TargetsScanned:     len(dp.processedCert) * len(dp.ports),
		},
		Errors: dp.errors,
	}
}
