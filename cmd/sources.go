package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/valllabh/domain-scan/pkg/logging"
)

// List of known subfinder sources (based on subfinder documentation)
var knownSources = []string{
	"alienvault", "anubis", "bevigil", "binaryedge", "bufferover",
	"censys", "certspotter", "chaos", "chinaz", "commoncrawl",
	"crtsh", "dnsdumpster", "dnsrepo", "fofa", "fullhunt",
	"github", "hackertarget", "hunter", "intelx", "passivetotal",
	"quake", "rapiddns", "robtex", "securitytrails", "shodan",
	"sitedossier", "subdomaincenter", "threatbook", "threatcrowd",
	"virustotal", "whoisxmlapi", "yahoo", "zoomeye",
}

var sourcesCmd = &cobra.Command{
	Use:   "sources",
	Short: "Manage passive discovery sources",
	Long: `Manage subfinder sources used for passive subdomain discovery.

Sources can be configured to control which passive discovery sources are used.
By default, all available sources are used when the sources list is empty.`,
}

var sourcesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured and available sources",
	Long: `List passive discovery sources.

Shows:
- Currently configured sources (from config)
- All available subfinder sources

When no sources are configured, all available sources are used.`,
	RunE: runSourcesList,
}

var sourcesEnableCmd = &cobra.Command{
	Use:   "enable [source...]",
	Short: "Enable specific sources",
	Long: `Enable one or more passive discovery sources.

This adds the specified sources to the configuration.
If this is the first source being enabled, it will switch from "all sources" mode
to "specific sources" mode.

Example:
  domain-scan sources enable crtsh censys shodan`,
	Args: cobra.MinimumNArgs(1),
	RunE: runSourcesEnable,
}

var sourcesDisableCmd = &cobra.Command{
	Use:   "disable [source...]",
	Short: "Disable specific sources",
	Long: `Disable one or more passive discovery sources.

This removes the specified sources from the configuration.

Example:
  domain-scan sources disable yahoo chinaz`,
	Args: cobra.MinimumNArgs(1),
	RunE: runSourcesDisable,
}

var sourcesResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset to use all sources",
	Long: `Reset sources configuration to use all available sources.

This clears the sources list in the configuration, which means
all available subfinder sources will be used.`,
	RunE: runSourcesReset,
}

func init() {
	rootCmd.AddCommand(sourcesCmd)
	sourcesCmd.AddCommand(sourcesListCmd)
	sourcesCmd.AddCommand(sourcesEnableCmd)
	sourcesCmd.AddCommand(sourcesDisableCmd)
	sourcesCmd.AddCommand(sourcesResetCmd)
}

func runSourcesList(cmd *cobra.Command, args []string) error {
	logger := logging.GetLogger()

	// Get configured sources
	configuredSources := viper.GetStringSlice("discovery.sources")

	logger.Info().Msg("Configured Sources:")
	if len(configuredSources) == 0 {
		logger.Info().Msg("  (all sources enabled - default behavior)")
	} else {
		sort.Strings(configuredSources)
		for _, source := range configuredSources {
			logger.Info().Msgf("  \u2713 %s", source)
		}
	}

	logger.Info().Msg("\nAvailable Sources:")
	sort.Strings(knownSources)
	for _, source := range knownSources {
		enabled := ""
		if len(configuredSources) == 0 || contains(configuredSources, source) {
			enabled = " (enabled)"
		}
		logger.Info().Msgf("  - %s%s", source, enabled)
	}

	logger.Info().Msgf("\nTotal available: %d sources", len(knownSources))
	return nil
}

func runSourcesEnable(cmd *cobra.Command, args []string) error {
	logger := logging.GetLogger()

	// Get current sources
	currentSources := viper.GetStringSlice("discovery.sources")
	sourcesMap := make(map[string]bool)
	for _, s := range currentSources {
		sourcesMap[s] = true
	}

	// Add new sources
	added := []string{}
	for _, source := range args {
		source = strings.ToLower(strings.TrimSpace(source))
		if !sourcesMap[source] {
			sourcesMap[source] = true
			added = append(added, source)
		}
	}

	// Convert back to slice
	newSources := make([]string, 0, len(sourcesMap))
	for s := range sourcesMap {
		newSources = append(newSources, s)
	}
	sort.Strings(newSources)

	// Update config
	viper.Set("discovery.sources", newSources)
	if err := viper.WriteConfig(); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	if len(added) > 0 {
		logger.Info().Msgf("Enabled sources: %s", strings.Join(added, ", "))
	} else {
		logger.Info().Msg("All specified sources were already enabled")
	}

	logger.Info().Msgf("\nTotal configured sources: %d", len(newSources))
	return nil
}

func runSourcesDisable(cmd *cobra.Command, args []string) error {
	logger := logging.GetLogger()

	// Get current sources
	currentSources := viper.GetStringSlice("discovery.sources")
	if len(currentSources) == 0 {
		return fmt.Errorf("cannot disable sources when using all sources (default). Use 'sources enable' first to select specific sources")
	}

	sourcesMap := make(map[string]bool)
	for _, s := range currentSources {
		sourcesMap[s] = true
	}

	// Remove sources
	removed := []string{}
	for _, source := range args {
		source = strings.ToLower(strings.TrimSpace(source))
		if sourcesMap[source] {
			delete(sourcesMap, source)
			removed = append(removed, source)
		}
	}

	// Convert back to slice
	newSources := make([]string, 0, len(sourcesMap))
	for s := range sourcesMap {
		newSources = append(newSources, s)
	}
	sort.Strings(newSources)

	// Update config
	viper.Set("discovery.sources", newSources)
	if err := viper.WriteConfig(); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	if len(removed) > 0 {
		logger.Info().Msgf("Disabled sources: %s", strings.Join(removed, ", "))
	} else {
		logger.Info().Msg("None of the specified sources were enabled")
	}

	logger.Info().Msgf("\nTotal configured sources: %d", len(newSources))
	return nil
}

func runSourcesReset(cmd *cobra.Command, args []string) error {
	logger := logging.GetLogger()

	viper.Set("discovery.sources", []string{})
	if err := viper.WriteConfig(); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logger.Info().Msg("Reset sources configuration to use all available sources")
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
