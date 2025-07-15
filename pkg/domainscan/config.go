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
	MaxDiscoveryRounds  int           `yaml:"max_discovery_rounds" json:"max_discovery_rounds"`
	Timeout             time.Duration `yaml:"timeout" json:"timeout"`
	Threads             int           `yaml:"threads" json:"threads"`
	PassiveEnabled      bool          `yaml:"passive_enabled" json:"passive_enabled"`
	CertificateEnabled  bool          `yaml:"certificate_enabled" json:"certificate_enabled"`
	HTTPEnabled         bool          `yaml:"http_enabled" json:"http_enabled"`
	SisterDomainEnabled bool          `yaml:"sister_domain_enabled" json:"sister_domain_enabled"`
}


// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Discovery: DiscoveryConfig{
			MaxDiscoveryRounds:  3,
			Timeout:             10 * time.Second,
			Threads:             50,
			PassiveEnabled:      true,
			CertificateEnabled:  true,
			HTTPEnabled:         true,
			SisterDomainEnabled: true,
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
