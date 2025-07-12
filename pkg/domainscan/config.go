package domainscan

import "time"

// Config represents the configuration for domain scanning
type Config struct {
	Discovery    DiscoveryConfig `yaml:"discovery" json:"discovery"`
	Ports        PortConfig      `yaml:"ports" json:"ports"`
	Keywords     []string        `yaml:"keywords" json:"keywords"`
	Dependencies DependencyConfig `yaml:"dependencies" json:"dependencies"`
}

// DiscoveryConfig contains settings for asset discovery
type DiscoveryConfig struct {
	MaxSubdomains     int           `yaml:"max_subdomains" json:"max_subdomains"`
	Timeout           time.Duration `yaml:"timeout" json:"timeout"`
	Threads           int           `yaml:"threads" json:"threads"`
	PassiveEnabled    bool          `yaml:"passive_enabled" json:"passive_enabled"`
	CertificateEnabled bool         `yaml:"certificate_enabled" json:"certificate_enabled"`
	HTTPEnabled       bool          `yaml:"http_enabled" json:"http_enabled"`
}

// PortConfig defines port scanning configuration
type PortConfig struct {
	Default    []int            `yaml:"default" json:"default"`
	Web        []int            `yaml:"web" json:"web"`
	Dev        []int            `yaml:"dev" json:"dev"`
	Enterprise []int            `yaml:"enterprise" json:"enterprise"`
	Custom     []int            `yaml:"custom" json:"custom"`
	Profiles   map[string][]int `yaml:"profiles" json:"profiles"`
}

// DependencyConfig contains dependency management settings
type DependencyConfig struct {
	AutoInstall bool `yaml:"auto_install" json:"auto_install"`
	CheckPaths  bool `yaml:"check_paths" json:"check_paths"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Discovery: DiscoveryConfig{
			MaxSubdomains:      1000,
			Timeout:            10 * time.Second,
			Threads:            50,
			PassiveEnabled:     true,
			CertificateEnabled: true,
			HTTPEnabled:        true,
		},
		Ports: PortConfig{
			Default:    []int{80, 443, 8080, 8443, 3000, 8000, 8888},
			Web:        []int{80, 443, 8080, 8443},
			Dev:        []int{3000, 8000, 8888, 9000},
			Enterprise: []int{80, 443, 8080, 8443, 8000, 9000, 8443},
			Profiles: map[string][]int{
				"quick":        {80, 443},
				"comprehensive": {80, 443, 8080, 8443, 3000, 8000, 8888, 9000},
			},
		},
		Keywords: []string{},
		Dependencies: DependencyConfig{
			AutoInstall: true,
			CheckPaths:  true,
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Discovery.MaxSubdomains <= 0 {
		c.Discovery.MaxSubdomains = 1000
	}
	if c.Discovery.Timeout <= 0 {
		c.Discovery.Timeout = 10 * time.Second
	}
	if c.Discovery.Threads <= 0 {
		c.Discovery.Threads = 50
	}
	if len(c.Ports.Default) == 0 {
		c.Ports.Default = []int{80, 443, 8080, 8443, 3000, 8000, 8888}
	}
	return nil
}