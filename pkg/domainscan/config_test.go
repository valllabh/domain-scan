package domainscan

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig() should not return nil")
	}

	// Test discovery defaults
	if config.Discovery.Timeout != 10*time.Second {
		t.Errorf("Expected Timeout to be 10s, got %v", config.Discovery.Timeout)
	}

	if config.Discovery.Threads != 50 {
		t.Errorf("Expected Threads to be 50, got %d", config.Discovery.Threads)
	}

	if !config.Discovery.PassiveEnabled {
		t.Error("Expected PassiveEnabled to be true")
	}

	if !config.Discovery.CertificateEnabled {
		t.Error("Expected CertificateEnabled to be true")
	}

	if !config.Discovery.HTTPEnabled {
		t.Error("Expected HTTPEnabled to be true")
	}

	// Port configuration removed - httpx auto-detects ports

	// Test keywords defaults (should be empty by default)
	if len(config.Keywords) != 0 {
		t.Errorf("Expected 0 default keywords, got %d", len(config.Keywords))
	}

}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		expect func(*Config) bool
	}{
		{
			name: "valid config",
			config: &Config{
				Discovery: DiscoveryConfig{
					Timeout: 5 * time.Second,
					Threads: 25,
				},
			},
			expect: func(c *Config) bool {
				return c.Discovery.Timeout == 5*time.Second &&
					c.Discovery.Threads == 25
			},
		},
		{
			name: "zero values get defaults",
			config: &Config{
				Discovery: DiscoveryConfig{
					Timeout: 0,
					Threads: 0,
				},
			},
			expect: func(c *Config) bool {
				return c.Discovery.Timeout == 10*time.Second &&
					c.Discovery.Threads == 50
			},
		},
		{
			name: "negative values get defaults",
			config: &Config{
				Discovery: DiscoveryConfig{
					Timeout: -1,
					Threads: -1,
				},
			},
			expect: func(c *Config) bool {
				return c.Discovery.Timeout == 10*time.Second &&
					c.Discovery.Threads == 50
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err != nil {
				t.Errorf("Validate() returned error: %v", err)
			}

			if !tt.expect(tt.config) {
				t.Errorf("Config validation did not produce expected results")
			}
		})
	}
}
