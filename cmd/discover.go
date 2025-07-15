package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/valllabh/domain-scan/pkg/domainscan"
	"github.com/valllabh/domain-scan/pkg/utils"
)

// DomainResult represents the structured output format for domains.json
// containing both discovered and live domains for consumption by other tools
type DomainResult struct {
	AllDomains  []string `json:"all-domains"`
	LiveDomains []string `json:"live-domains"`
}

var (
	keywords      []string
	maxSubdomains int
	timeout       int
	threads       int
	outputFile    string
	outputFormat  string
	resultDir     string
	quiet         bool
	debug         bool
	logLevel      string
)

// discoverCmd represents the discover command
var discoverCmd = &cobra.Command{
	Use:   "discover [domains...]",
	Short: "Discover web assets for specified domains",
	Long: `Discover performs comprehensive web asset discovery including:
- Passive subdomain enumeration using subfinder
- TLS certificate analysis for additional subdomains with organizational filtering
- HTTP/HTTPS service verification (httpx auto-detects ports)

The results include all discovered subdomains and active web services.

Keywords are used to filter domains found in SSL certificates to exclude domains 
from other organizations in shared certificates. For example, if a target domain 
uses a third-party service that has other organizations' domains in the same 
certificate, keywords ensure only relevant domains are included in results.`,
	Example: `  # Basic discovery
  domain-scan discover example.com

  # Scan multiple domains
  domain-scan discover example.com domain2.com

  # Additional keywords (combined with auto-extracted)
  domain-scan discover example.com --keywords staging,prod

  # Output to file in JSON format
  domain-scan discover example.com --output results.json --format json

  # Multiple domains with custom settings
  domain-scan discover example.com domain2.com --max-subdomains 500`,
	Args: cobra.MinimumNArgs(1),
	RunE: runDiscover,
}

func init() {
	rootCmd.AddCommand(discoverCmd)

	// Discovery flags
	discoverCmd.Flags().StringSliceVarP(&keywords, "keywords", "k", []string{}, "Additional keywords for filtering SSL certificate domains (auto-extracted from domains and combined with provided keywords)")
	discoverCmd.Flags().IntVar(&maxSubdomains, "max-subdomains", 0, "Maximum subdomains to scan for HTTP services")
	discoverCmd.Flags().IntVar(&timeout, "timeout", 0, "Timeout in seconds")
	discoverCmd.Flags().IntVar(&threads, "threads", 0, "Number of threads")

	// Output flags
	discoverCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	discoverCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format (text, json)")
	discoverCmd.Flags().StringVar(&resultDir, "result-dir", "./result", "Directory to save results (creates {result-dir}/{first-domain}/domains.json)")
	discoverCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode (suppress progress output)")
	discoverCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging for troubleshooting (deprecated, use --loglevel debug)")
	discoverCmd.Flags().StringVar(&logLevel, "loglevel", "", "Log level (trace, debug, info, warn, error, silent)")

	// All discovery methods are enabled by default

	_ = viper.BindPFlag("discovery.max_subdomains", discoverCmd.Flags().Lookup("max-subdomains"))
	_ = viper.BindPFlag("discovery.timeout", discoverCmd.Flags().Lookup("timeout"))
	_ = viper.BindPFlag("discovery.threads", discoverCmd.Flags().Lookup("threads"))
	_ = viper.BindPFlag("keywords", discoverCmd.Flags().Lookup("keywords"))
	_ = viper.BindPFlag("log_level", discoverCmd.Flags().Lookup("loglevel"))
}

// runDiscover executes the domain discovery command with the provided arguments.
// Orchestrates configuration loading, scanner setup, and result output.
func runDiscover(cmd *cobra.Command, args []string) error {
	// Load configuration
	config := loadDiscoveryConfig()

	// Apply command-line overrides
	applyFlagOverrides(cmd, config)

	// Create scanner
	scanner := domainscan.New(config)

	// Set progress callback for CLI (unless quiet mode)
	if !quiet {
		progressHandler := domainscan.NewCLIProgressHandler()
		scanner.SetProgressCallback(progressHandler)
	}

	// Create scan request
	req := &domainscan.ScanRequest{
		Domains:             args,
		Keywords:            keywords,
		MaxDiscoveryRounds:  config.Discovery.MaxDiscoveryRounds,
		Timeout:             getTimeout(config),
		EnablePassive:       true, // Always enabled
		EnableCertScan:      true, // Always enabled
		EnableHTTPScan:      true, // Always enabled
		EnableSisterDomains: config.Discovery.SisterDomainEnabled,
	}

	// Combine all keyword sources efficiently
	allKeywordSources := [][]string{
		utils.ExtractKeywordsFromDomains(req.Domains),
		req.Keywords,
	}
	if len(keywords) == 0 {
		allKeywordSources = append(allKeywordSources, config.Keywords)
	}

	keywordMap := make(map[string]bool)
	for _, keywordList := range allKeywordSources {
		for _, keyword := range keywordList {
			if keyword != "" {
				keywordMap[keyword] = true
			}
		}
	}

	req.Keywords = make([]string, 0, len(keywordMap))
	for keyword := range keywordMap {
		req.Keywords = append(req.Keywords, keyword)
	}

	// Run discovery
	ctx := context.Background()
	result, err := scanner.ScanWithOptions(ctx, req)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	// Output results
	err = outputResults(result)
	if err != nil {
		return err
	}

	// Always create domains.json in result directory
	return createDomainsJSON(result, args[0])
}

// loadDiscoveryConfig creates and loads configuration from viper settings.
// Applies configuration file values and environment variables.
func loadDiscoveryConfig() *domainscan.Config {
	config := domainscan.DefaultConfig()

	// Load from viper
	if viper.IsSet("discovery.timeout") {
		config.Discovery.Timeout = time.Duration(viper.GetInt("discovery.timeout")) * time.Second
	}
	if viper.IsSet("discovery.threads") {
		config.Discovery.Threads = viper.GetInt("discovery.threads")
	}
	if viper.IsSet("keywords") {
		config.Keywords = viper.GetStringSlice("keywords")
	}
	if viper.IsSet("log_level") {
		config.LogLevel = viper.GetString("log_level")
	}

	return config
}

// applyFlagOverrides applies command-line flag values to the configuration.
// Only applies values for flags that were explicitly changed by the user.
func applyFlagOverrides(cmd *cobra.Command, config *domainscan.Config) {
	if cmd.Flags().Changed("timeout") {
		config.Discovery.Timeout = time.Duration(timeout) * time.Second
	}
	if cmd.Flags().Changed("threads") {
		config.Discovery.Threads = threads
	}
	if cmd.Flags().Changed("keywords") {
		config.Keywords = keywords
	}
	// Handle legacy --debug flag and new --loglevel flag
	if cmd.Flags().Changed("debug") && debug {
		config.LogLevel = "debug"
	}
	if cmd.Flags().Changed("loglevel") {
		config.LogLevel = logLevel
	}
}

// getTimeout returns the effective timeout duration.
// Prioritizes command-line flag over configuration value.
func getTimeout(config *domainscan.Config) time.Duration {
	if timeout > 0 {
		return time.Duration(timeout) * time.Second
	}
	return config.Discovery.Timeout
}

// outputResults formats and outputs discovery results to stdout or file.
// Supports both text and JSON output formats with live domain highlighting.
func outputResults(result *domainscan.AssetDiscoveryResult) error {
	var output []byte
	var err error

	switch strings.ToLower(outputFormat) {
	case "json":
		output, err = json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
	default: // text
		var sb strings.Builder
		for _, entry := range result.Domains {
			if entry.IsLive {
				// Color live domains green
				sb.WriteString(fmt.Sprintf("%s \033[32m[%d]\033[0m\n", entry.Domain, entry.Status))
			} else {
				sb.WriteString(fmt.Sprintf("%s [%d]\n", entry.Domain, entry.Status))
			}
		}
		output = []byte(sb.String())
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, output, 0600)
	}

	fmt.Print(string(output))
	return nil
}

// createDomainsJSON creates a structured domains.json file in the result directory.
// Separates all discovered domains from live domains for downstream tool consumption.
func createDomainsJSON(result *domainscan.AssetDiscoveryResult, firstDomain string) error {
	// Create result directory structure
	domainDir := filepath.Join(resultDir, firstDomain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return fmt.Errorf("failed to create result directory: %w", err)
	}

	// Prepare all domains and live domains from result.Domains
	var allDomains []string
	var liveDomains []string

	for domainURL, entry := range result.Domains {
		// Extract domain name from URL for all domains
		if domain := extractDomainFromURL(domainURL); domain != "" {
			allDomains = append(allDomains, domain)
		}

		// Add live domains with full URL
		if entry.IsLive {
			liveDomains = append(liveDomains, domainURL)
		}
	}

	// Create domain result structure
	domainResult := DomainResult{
		AllDomains:  allDomains,
		LiveDomains: liveDomains,
	}

	// Marshal to JSON
	output, err := json.MarshalIndent(domainResult, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domains JSON: %w", err)
	}

	// Write to domains.json
	domainsPath := filepath.Join(domainDir, "domains.json")
	if err := os.WriteFile(domainsPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write domains.json: %w", err)
	}

	// Print the full path as an end event
	fmt.Printf("\nResults saved to: %s\n", domainsPath)

	return nil
}

// extractDomainFromURL extracts the domain name from a URL.
// Removes protocol, port, and path components to return clean domain.
func extractDomainFromURL(url string) string {
	// Remove protocol
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}

	// Remove port and path
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// DebugLogger implements the Logger interface for conditional debug output.
// Provides backward compatibility with legacy debug flag functionality.
type DebugLogger struct {
	enabled bool
}

// Printf outputs formatted debug message if debug mode is enabled.
func (d *DebugLogger) Printf(format string, v ...interface{}) {
	if d.enabled {
		log.Printf(format, v...)
	}
}

// Println outputs debug message if debug mode is enabled.
func (d *DebugLogger) Println(v ...interface{}) {
	if d.enabled {
		log.Println(v...)
	}
}
