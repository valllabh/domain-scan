package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration settings",
	Long: `Manage domain-scan configuration settings including profiles,
keywords, ports, and discovery options. Configuration is stored in
YAML format and supports profiles for different scanning scenarios.`,
}

// configShowCmd shows the current configuration
var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  `Display the current configuration including all settings and profiles.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return showConfig()
	},
}

// configSetCmd sets a configuration value
var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long: `Set a configuration value using dot notation.
	
Examples:
  domain-scan config set discovery.max_subdomains 2000
  domain-scan config set ports.custom [80,443,8080]
  domain-scan config set keywords [api,admin,dev]`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setConfig(args[0], args[1])
	},
}

// configEditCmd opens the config file in an editor
var configEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit configuration file",
	Long:  `Open the configuration file in your default editor.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return editConfig()
	},
}

// configInitCmd initializes a new configuration file
var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	Long:  `Create a new configuration file with default settings.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return initConfigFile()
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configEditCmd)
	configCmd.AddCommand(configInitCmd)
}

func showConfig() error {
	fmt.Println("Current Configuration:")
	fmt.Printf("Config file: %s\n\n", viper.ConfigFileUsed())

	// Get all settings
	settings := viper.AllSettings()
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	fmt.Print(string(data))
	return nil
}

func setConfig(key, value string) error {
	// Parse the value
	var parsedValue interface{}
	
	// Try to parse as array
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.Trim(value, "[]")
		if value == "" {
			parsedValue = []string{}
		} else {
			parts := strings.Split(value, ",")
			var result []string
			for _, part := range parts {
				result = append(result, strings.TrimSpace(part))
			}
			parsedValue = result
		}
	} else {
		// Try to parse as number, boolean, or string
		if value == "true" {
			parsedValue = true
		} else if value == "false" {
			parsedValue = false
		} else {
			parsedValue = value
		}
	}

	viper.Set(key, parsedValue)
	
	// Save to config file
	if err := viper.WriteConfig(); err != nil {
		// If config file doesn't exist, create it
		if err := viper.SafeWriteConfig(); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}
	}

	fmt.Printf("Set %s = %v\n", key, parsedValue)
	return nil
}

func editConfig() error {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		// Create default config file
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		
		configDir := filepath.Join(home, ".domain-scan")
		configFile = filepath.Join(configDir, "config.yaml")
		
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
		
		if err := createDefaultConfig(configFile); err != nil {
			return fmt.Errorf("failed to create default config: %w", err)
		}
	}

	// Open in editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi" // Default to vi
	}

	fmt.Printf("Opening %s in %s...\n", configFile, editor)
	return runEditor(editor, configFile)
}

func initConfigFile() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	
	configDir := filepath.Join(home, ".domain-scan")
	configFile := filepath.Join(configDir, "config.yaml")
	
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	if _, err := os.Stat(configFile); err == nil {
		return fmt.Errorf("config file already exists: %s", configFile)
	}
	
	if err := createDefaultConfig(configFile); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	
	fmt.Printf("Created config file: %s\n", configFile)
	return nil
}

func createDefaultConfig(filename string) error {
	defaultConfig := `# Domain-scan configuration file
discovery:
  max_subdomains: 1000
  timeout: 10
  threads: 50
  passive_enabled: true
  certificate_enabled: true
  http_enabled: true

ports:
  default: [80, 443, 8080, 8443, 3000, 8000, 8888]
  web: [80, 443, 8080, 8443]
  dev: [3000, 8000, 8888, 9000]
  enterprise: [80, 443, 8080, 8443, 8000, 9000, 8443]
  
keywords:
  - api
  - admin
  - dev
  - staging
  - test

profiles:
  quick:
    max_subdomains: 100
    ports: [80, 443]
    timeout: 5
  comprehensive:
    max_subdomains: 5000
    ports: [80, 443, 8080, 8443, 3000, 8000, 8888, 9000]
    timeout: 15

dependencies:
  auto_install: true
  check_paths: true
`

	return os.WriteFile(filename, []byte(defaultConfig), 0644)
}

func runEditor(editor, filename string) error {
	// This is a simplified implementation
	// In a real implementation, you'd want to handle different editors properly
	fmt.Printf("Please manually edit the file: %s\n", filename)
	return nil
}