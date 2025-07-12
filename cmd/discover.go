package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/domain-scan/domain-scan/pkg/domainscan"
	"github.com/domain-scan/domain-scan/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	keywords      []string
	ports         []int
	maxSubdomains int
	timeout       int
	threads       int
	profile       string
	outputFile    string
	outputFormat  string
	enablePassive bool
	enableCert    bool
	enableHTTP    bool
	quiet         bool
)

// discoverCmd represents the discover command
var discoverCmd = &cobra.Command{
	Use:   "discover [domains...]",
	Short: "Discover web assets for specified domains",
	Long: `Discover performs comprehensive web asset discovery including:
- Passive subdomain enumeration using subfinder
- TLS certificate analysis for additional subdomains with organizational filtering
- HTTP/HTTPS service verification on specified ports

The results include all discovered subdomains and active web services.

Keywords are used to filter domains found in SSL certificates to exclude domains 
from other organizations in shared certificates. For example, if a target domain 
uses a third-party service that has other organizations' domains in the same 
certificate, keywords ensure only relevant domains are included in results.`,
	Example: `  # Basic discovery
  domain-scan discover example.com

  # Use a specific profile
  domain-scan discover example.com --profile quick

  # Additional keywords (combined with auto-extracted) and custom ports
  domain-scan discover example.com --keywords staging,prod --ports 80,443,8080

  # Output to file in JSON format
  domain-scan discover example.com --output results.json --format json

  # Disable specific discovery methods
  domain-scan discover example.com --no-passive --no-cert`,
	Args: cobra.MinimumNArgs(1),
	RunE: runDiscover,
}

func init() {
	rootCmd.AddCommand(discoverCmd)

	// Discovery flags
	discoverCmd.Flags().StringSliceVarP(&keywords, "keywords", "k", []string{}, "Additional keywords for filtering SSL certificate domains (auto-extracted from domains and combined with provided keywords)")
	discoverCmd.Flags().IntSliceVarP(&ports, "ports", "p", []int{}, "Ports to scan (comma-separated)")
	discoverCmd.Flags().IntVar(&maxSubdomains, "max-subdomains", 0, "Maximum subdomains to scan for HTTP services")
	discoverCmd.Flags().IntVar(&timeout, "timeout", 0, "Timeout in seconds")
	discoverCmd.Flags().IntVar(&threads, "threads", 0, "Number of threads")
	discoverCmd.Flags().StringVar(&profile, "profile", "", "Configuration profile (quick, comprehensive)")

	// Output flags
	discoverCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	discoverCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format (text, json)")
	discoverCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode (suppress progress output)")

	// Method toggles
	discoverCmd.Flags().BoolVar(&enablePassive, "passive", true, "Enable passive subdomain discovery")
	discoverCmd.Flags().BoolVar(&enableCert, "cert", true, "Enable TLS certificate analysis")
	discoverCmd.Flags().BoolVar(&enableHTTP, "http", true, "Enable HTTP service verification")
	discoverCmd.Flags().Bool("no-passive", false, "Disable passive subdomain discovery")
	discoverCmd.Flags().Bool("no-cert", false, "Disable TLS certificate analysis")
	discoverCmd.Flags().Bool("no-http", false, "Disable HTTP service verification")

	// Bind flags to viper
	if err := viper.BindPFlag("discovery.max_subdomains", discoverCmd.Flags().Lookup("max-subdomains")); err != nil {
		log.Printf("Warning: failed to bind max-subdomains flag: %v", err)
	}
	if err := viper.BindPFlag("discovery.timeout", discoverCmd.Flags().Lookup("timeout")); err != nil {
		log.Printf("Warning: failed to bind timeout flag: %v", err)
	}
	if err := viper.BindPFlag("discovery.threads", discoverCmd.Flags().Lookup("threads")); err != nil {
		log.Printf("Warning: failed to bind threads flag: %v", err)
	}
	if err := viper.BindPFlag("keywords", discoverCmd.Flags().Lookup("keywords")); err != nil {
		log.Printf("Warning: failed to bind keywords flag: %v", err)
	}
	if err := viper.BindPFlag("ports.custom", discoverCmd.Flags().Lookup("ports")); err != nil {
		log.Printf("Warning: failed to bind ports flag: %v", err)
	}
}

func runDiscover(cmd *cobra.Command, args []string) error {
	// Load configuration
	config := loadDiscoveryConfig()

	// Apply command-line overrides
	applyFlagOverrides(cmd, config)

	// Create scanner
	scanner := domainscan.New(config)

	// Set quiet mode
	if quiet {
		scanner.SetLogger(&quietLogger{})
	}

	// Create scan request
	req := &domainscan.ScanRequest{
		Domains:        args,
		Keywords:       keywords,
		Ports:          getPorts(config),
		MaxSubdomains:  getMaxSubdomains(config),
		Timeout:        getTimeout(config),
		EnablePassive:  getEnablePassive(cmd),
		EnableCertScan: getEnableCert(cmd),
		EnableHTTPScan: getEnableHTTP(cmd),
	}

	// Extract keywords from domains automatically
	extractedKeywords := utils.ExtractKeywordsFromDomains(req.Domains)
	
	// Combine extracted keywords with manually provided keywords and config keywords
	keywordMap := make(map[string]bool)
	
	// Add extracted keywords first
	for _, keyword := range extractedKeywords {
		keywordMap[keyword] = true
	}
	
	// Add manually provided keywords (from --keywords flag)
	for _, keyword := range req.Keywords {
		keywordMap[keyword] = true
	}
	
	// Add config keywords if no manual keywords were provided
	if len(keywords) == 0 {
		for _, keyword := range config.Keywords {
			keywordMap[keyword] = true
		}
	}
	
	// Convert back to slice
	var finalKeywords []string
	for keyword := range keywordMap {
		finalKeywords = append(finalKeywords, keyword)
	}
	req.Keywords = finalKeywords

	// Run discovery
	ctx := context.Background()
	result, err := scanner.ScanWithOptions(ctx, req)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	// Output results
	return outputResults(result)
}

func loadDiscoveryConfig() *domainscan.Config {
	config := domainscan.DefaultConfig()

	// Load from viper
	if viper.IsSet("discovery.max_subdomains") {
		config.Discovery.MaxSubdomains = viper.GetInt("discovery.max_subdomains")
	}
	if viper.IsSet("discovery.timeout") {
		config.Discovery.Timeout = time.Duration(viper.GetInt("discovery.timeout")) * time.Second
	}
	if viper.IsSet("discovery.threads") {
		config.Discovery.Threads = viper.GetInt("discovery.threads")
	}
	if viper.IsSet("keywords") {
		config.Keywords = viper.GetStringSlice("keywords")
	}

	// Apply profile
	if profile != "" {
		applyProfile(config, profile)
	}

	return config
}

func applyFlagOverrides(cmd *cobra.Command, config *domainscan.Config) {
	if cmd.Flags().Changed("max-subdomains") {
		config.Discovery.MaxSubdomains = maxSubdomains
	}
	if cmd.Flags().Changed("timeout") {
		config.Discovery.Timeout = time.Duration(timeout) * time.Second
	}
	if cmd.Flags().Changed("threads") {
		config.Discovery.Threads = threads
	}
	if cmd.Flags().Changed("keywords") {
		config.Keywords = keywords
	}
}

func applyProfile(config *domainscan.Config, profileName string) {
	switch profileName {
	case "quick":
		config.Discovery.MaxSubdomains = 100
		config.Discovery.Timeout = 5 * time.Second
		config.Ports.Custom = []int{80, 443}
	case "comprehensive":
		config.Discovery.MaxSubdomains = 5000
		config.Discovery.Timeout = 15 * time.Second
		config.Ports.Custom = []int{80, 443, 8080, 8443, 3000, 8000, 8888, 9000}
	}
}

func getPorts(config *domainscan.Config) []int {
	if len(ports) > 0 {
		return ports
	}
	if len(config.Ports.Custom) > 0 {
		return config.Ports.Custom
	}
	return config.Ports.Default
}

func getMaxSubdomains(config *domainscan.Config) int {
	if maxSubdomains > 0 {
		return maxSubdomains
	}
	return config.Discovery.MaxSubdomains
}

func getTimeout(config *domainscan.Config) time.Duration {
	if timeout > 0 {
		return time.Duration(timeout) * time.Second
	}
	return config.Discovery.Timeout
}

func getEnablePassive(cmd *cobra.Command) bool {
	if cmd.Flags().Changed("no-passive") {
		noPassive, _ := cmd.Flags().GetBool("no-passive")
		return !noPassive
	}
	return enablePassive
}

func getEnableCert(cmd *cobra.Command) bool {
	if cmd.Flags().Changed("no-cert") {
		noCert, _ := cmd.Flags().GetBool("no-cert")
		return !noCert
	}
	return enableCert
}

func getEnableHTTP(cmd *cobra.Command) bool {
	if cmd.Flags().Changed("no-http") {
		noHTTP, _ := cmd.Flags().GetBool("no-http")
		return !noHTTP
	}
	return enableHTTP
}

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
		for _, service := range result.ActiveServices {
			sb.WriteString(service.URL + "\n")
		}
		output = []byte(sb.String())
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, output, 0600)
	}

	fmt.Print(string(output))
	return nil
}

// quietLogger implements a quiet logger that suppresses output
type quietLogger struct{}

func (q *quietLogger) Printf(format string, v ...interface{}) {}
func (q *quietLogger) Println(v ...interface{})               {}
