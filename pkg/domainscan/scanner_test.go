package domainscan

import (
	"context"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name:   "with nil config",
			config: nil,
		},
		{
			name:   "with valid config",
			config: DefaultConfig(),
		},
		{
			name: "with custom config",
			config: &Config{
				Discovery: DiscoveryConfig{
					MaxSubdomains: 500,
					Timeout:       5 * time.Second,
					Threads:       25,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := New(tt.config)

			if scanner == nil {
				t.Fatal("New() should not return nil")
			}

			if scanner.config == nil {
				t.Fatal("Scanner config should not be nil")
			}

			if scanner.logger == nil {
				t.Fatal("Scanner logger should not be nil")
			}
		})
	}
}

func TestScannerSetLogger(t *testing.T) {
	scanner := New(nil)

	// Create a mock logger
	mockLogger := &testLogger{}
	scanner.SetLogger(mockLogger)

	// Test that the logger was set
	if scanner.logger != mockLogger {
		t.Error("SetLogger() did not set the logger correctly")
	}
}

func TestScannerGetConfig(t *testing.T) {
	config := DefaultConfig()
	scanner := New(config)

	retrievedConfig := scanner.GetConfig()
	if retrievedConfig != config {
		t.Error("GetConfig() did not return the correct config")
	}
}

func TestScannerUpdateConfig(t *testing.T) {
	scanner := New(nil)

	newConfig := &Config{
		Discovery: DiscoveryConfig{
			MaxSubdomains: 500,
			Timeout:       5 * time.Second,
			Threads:       25,
		},
	}

	// Test updating with valid config
	err := scanner.UpdateConfig(newConfig)
	if err != nil {
		t.Errorf("UpdateConfig() with valid config should not error: %v", err)
	}

	if scanner.config != newConfig {
		t.Error("UpdateConfig() did not update the config correctly")
	}

	// Test updating with nil config
	err = scanner.UpdateConfig(nil)
	if err == nil {
		t.Error("UpdateConfig() with nil config should return error")
	}
}

func TestScanWithOptionsValidation(t *testing.T) {
	scanner := New(nil)
	ctx := context.Background()

	// Test with empty domains
	req := &ScanRequest{
		Domains: []string{},
	}

	result, err := scanner.ScanWithOptions(ctx, req)
	if err == nil {
		t.Error("ScanWithOptions() with empty domains should return error")
	}

	// The scanner returns nil on validation errors (as seen in the implementation)
	if result != nil {
		t.Error("ScanWithOptions() should return nil result on validation error")
	}
}

func TestDefaultScanRequest(t *testing.T) {
	domains := []string{"example.com", "test.com"}
	req := DefaultScanRequest(domains)

	if req == nil {
		t.Fatal("DefaultScanRequest() should not return nil")
	}

	if len(req.Domains) != len(domains) {
		t.Errorf("Expected %d domains, got %d", len(domains), len(req.Domains))
	}

	for i, domain := range domains {
		if req.Domains[i] != domain {
			t.Errorf("Expected domain %s at index %d, got %s", domain, i, req.Domains[i])
		}
	}

	// Check defaults
	if req.MaxSubdomains != 1000 {
		t.Errorf("Expected MaxSubdomains to be 1000, got %d", req.MaxSubdomains)
	}

	if req.Timeout != 10*time.Second {
		t.Errorf("Expected Timeout to be 10s, got %v", req.Timeout)
	}

	if !req.EnablePassive {
		t.Error("Expected EnablePassive to be true")
	}

	if !req.EnableCertScan {
		t.Error("Expected EnableCertScan to be true")
	}

	if !req.EnableHTTPScan {
		t.Error("Expected EnableHTTPScan to be true")
	}
}

// testLogger is a mock logger for testing
type testLogger struct {
	messages []string
}

func (l *testLogger) Printf(format string, v ...interface{}) {
	l.messages = append(l.messages, format)
}

func (l *testLogger) Println(v ...interface{}) {
	l.messages = append(l.messages, "println")
}
