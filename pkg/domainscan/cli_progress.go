package domainscan

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// CLIProgressHandler implements ProgressCallback for command line interface
type CLIProgressHandler struct {
	startTime      time.Time
	animationIndex int
	totalDomains   int
	liveDomains    int
	animating      bool
	stopAnimation  chan bool
	mu             sync.RWMutex
}

var spinnerChars = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// NewCLIProgressHandler creates a new CLI progress handler
func NewCLIProgressHandler() *CLIProgressHandler {
	return &CLIProgressHandler{
		startTime:     time.Now(),
		stopAnimation: make(chan bool, 1),
	}
}

// OnStart is called when domain asset discovery begins
func (c *CLIProgressHandler) OnStart(domains []string, keywords []string) {
	c.startTime = time.Now()

	fmt.Printf("🔍 Starting domain discovery for %d domains\n", len(domains))
	if len(keywords) > 0 {
		fmt.Printf("🔑 Using keywords: %s\n", strings.Join(keywords, ", "))
	}
	fmt.Printf("\n")
	
	// Start background animation
	c.startAnimation()
}

// OnProgress is called with unified progress updates
func (c *CLIProgressHandler) OnProgress(totalDomains, liveDomains int) {
	c.mu.Lock()
	c.totalDomains = totalDomains
	c.liveDomains = liveDomains
	c.mu.Unlock()
	
	// Force immediate display update with current animation frame
	c.updateProgressDisplay()
}

// OnEnd is called when the entire scan finishes
func (c *CLIProgressHandler) OnEnd(result *AssetDiscoveryResult) {
	// Stop background animation
	c.stopAnimationLoop()
	
	// Clear the progress line
	fmt.Printf("\r%s\r", strings.Repeat(" ", 80))

	duration := time.Since(c.startTime)
	fmt.Printf("✅ Discovery completed in %v\n", duration)
	fmt.Printf("📊 Results: %d domains, %d live services\n\n",
		result.Statistics.TotalSubdomains, result.Statistics.ActiveServices)
}

// updateProgressDisplay displays animated progress with counts
func (c *CLIProgressHandler) updateProgressDisplay() {
	c.mu.RLock()
	animationChar := spinnerChars[c.animationIndex]
	totalDomains := c.totalDomains
	liveDomains := c.liveDomains
	c.mu.RUnlock()

	// Build progress message: [spinner] Discovering domains | total X ➔ live Y
	message := fmt.Sprintf("\r%s Discovering domains | total %d ➔ live %d",
		animationChar, totalDomains, liveDomains)

	// Pad with spaces to clear previous longer messages
	if len(message) < 80 {
		message += strings.Repeat(" ", 80-len(message))
	}

	// Always display progress immediately
	fmt.Print(message)
}

// startAnimation begins the background animation loop
func (c *CLIProgressHandler) startAnimation() {
	c.mu.Lock()
	if c.animating {
		c.mu.Unlock()
		return // Already animating
	}
	c.animating = true
	c.mu.Unlock()

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				c.animationIndex = (c.animationIndex + 1) % len(spinnerChars)
				c.mu.Unlock()
				c.updateProgressDisplay()
			case <-c.stopAnimation:
				return
			}
		}
	}()
}

// stopAnimationLoop stops the background animation
func (c *CLIProgressHandler) stopAnimationLoop() {
	c.mu.Lock()
	if !c.animating {
		c.mu.Unlock()
		return // Not animating
	}
	c.animating = false
	c.mu.Unlock()

	select {
	case c.stopAnimation <- true:
	default:
		// Channel might be full, that's okay
	}
}
