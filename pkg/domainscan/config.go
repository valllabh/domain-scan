package domainscan

import (
	"errors"
	"time"
)

// Config represents the configuration for domain scanning
type Config struct {
	Discovery DiscoveryConfig `yaml:"discovery" json:"discovery"`
	Keywords  []string        `yaml:"keywords" json:"keywords"`
	LogLevel  string          `yaml:"log_level" json:"log_level"`
}

// DiscoveryConfig contains settings for asset discovery
type DiscoveryConfig struct {
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	Threads          int           `yaml:"threads" json:"threads"`
	EnablePassive    bool          `yaml:"enable_passive" json:"enable_passive"`
	EnableCertificate bool         `yaml:"enable_certificate" json:"enable_certificate"`
	Recursive        bool          `yaml:"recursive" json:"recursive"`
	RecursionDepth   int           `yaml:"recursion_depth" json:"recursion_depth"`
	MaxDomains       int           `yaml:"max_domains" json:"max_domains"` // 0 means unlimited
	Sources          []string      `yaml:"sources" json:"sources"` // Subfinder sources to use
}


// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Discovery: DiscoveryConfig{
			Timeout:          10 * time.Second,
			Threads:          50,
			EnablePassive:    true,
			EnableCertificate: true,
			Recursive:        true,
			RecursionDepth:   0, // 0 means unlimited
			MaxDomains:       0, // 0 means unlimited
			Sources:          []string{}, // Empty means all sources
		},
		Keywords: []string{},
		LogLevel: "info",
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Discovery.Timeout <= 0 {
		c.Discovery.Timeout = 10 * time.Second
	}
	if c.Discovery.Threads <= 0 {
		c.Discovery.Threads = 50
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"trace": true, "debug": true, "info": true,
		"warn": true, "error": true, "silent": true,
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	} else if !validLogLevels[c.LogLevel] {
		return errors.New("invalid log level: must be one of trace, debug, info, warn, error, silent")
	}

	return nil
}
