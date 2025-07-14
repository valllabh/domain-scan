package discovery

import (
	"context"
	"testing"
)

func TestHTTPServiceScan(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		subdomains  []string
		ports       []int
		expectError bool
		expectNil   bool
	}{
		{
			name:        "empty subdomains",
			subdomains:  []string{},
			ports:       []int{80, 443},
			expectError: false, // Early return for empty inputs
			expectNil:   true,  // Returns nil slice for empty inputs
		},
		{
			name:        "empty ports",
			subdomains:  []string{"example.com"},
			ports:       []int{},
			expectError: false, // Early return for empty inputs
			expectNil:   true,  // Returns nil slice for empty inputs
		},
		{
			name:        "valid inputs with httpx SDK",
			subdomains:  []string{"example.com"},
			ports:       []int{80, 443},
			expectError: false, // SDK should always work
			expectNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := HTTPServiceScan(ctx, tt.subdomains, tt.ports, nil)

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

			if !tt.expectNil && (tt.name == "empty subdomains" || tt.name == "empty ports") && len(result) != 0 {
				t.Error("Empty inputs should return empty result")
			}
		})
	}
}
