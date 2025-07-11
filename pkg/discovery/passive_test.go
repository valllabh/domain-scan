package discovery

import (
	"context"
	"os/exec"
	"testing"
)

func TestPassiveDiscovery(t *testing.T) {
	ctx := context.Background()
	
	tests := []struct {
		name        string
		domains     []string
		expectError bool
		expectNil   bool
	}{
		{
			name:        "empty domains",
			domains:     []string{},
			expectError: false,
			expectNil:   true, // Returns nil slice for empty domains
		},
		{
			name:        "single domain without subfinder",
			domains:     []string{"example.com"},
			expectError: !commandExists("subfinder"),
			expectNil:   !commandExists("subfinder"), // Returns nil if subfinder not found
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := PassiveDiscovery(ctx, tt.domains)
			
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			
			if tt.expectNil && result != nil {
				t.Error("Expected nil result but got non-nil")
			}
			
			if !tt.expectNil && result == nil {
				t.Error("Expected non-nil result but got nil")
			}
			
			if !tt.expectNil && tt.name == "empty domains" && len(result) != 0 {
				t.Error("Empty domains should return empty result")
			}
		})
	}
}

func TestFindBinary(t *testing.T) {
	tests := []struct {
		name       string
		binary     string
		shouldFind bool
	}{
		{
			name:       "nonexistent binary",
			binary:     "nonexistent-binary-12345",
			shouldFind: false,
		},
		{
			name:       "subfinder",
			binary:     "subfinder",
			shouldFind: commandExists("subfinder"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := findBinary(tt.binary)
			
			if tt.shouldFind {
				if err != nil {
					t.Errorf("Expected to find %s, but got error: %v", tt.binary, err)
				}
				if path == "" {
					t.Errorf("Expected non-empty path for %s", tt.binary)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error for %s, but found at: %s", tt.binary, path)
				}
			}
		})
	}
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}