package discovery

import (
	"context"
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
			expectNil:   true, // Returns empty slice for empty domains
		},
		{
			name:        "single domain with subfinder SDK",
			domains:     []string{"example.com"},
			expectError: false,
			expectNil:   false, // SDK should always work
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := PassiveDiscoveryWithLogger(ctx, tt.domains, nil)

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
