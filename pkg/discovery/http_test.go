package discovery

import (
	"context"
	"testing"
)

func TestHTTPServiceScan(t *testing.T) {
	ctx := context.Background()
	
	tests := []struct {
		name       string
		subdomains []string
		ports      []int
		expectError bool
		expectNil   bool
	}{
		{
			name:       "empty subdomains",
			subdomains: []string{},
			ports:      []int{80, 443},
			expectError: false, // Early return for empty inputs
			expectNil:   true,  // Returns nil slice for empty inputs
		},
		{
			name:       "empty ports",
			subdomains: []string{"example.com"},
			ports:      []int{},
			expectError: false, // Early return for empty inputs
			expectNil:   true,  // Returns nil slice for empty inputs
		},
		{
			name:       "valid inputs without httpx",
			subdomains: []string{"example.com"},
			ports:      []int{80, 443},
			expectError: !httpxExists(),
			expectNil:   !httpxExists(), // Returns nil if httpx not found
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := HTTPServiceScan(ctx, tt.subdomains, tt.ports)
			
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

func TestFindHTTPXBinary(t *testing.T) {
	path, err := findHTTPXBinary()
	
	httpxAvailable := httpxExists()
	
	if httpxAvailable {
		if err != nil {
			t.Errorf("Expected to find httpx, but got error: %v", err)
		}
		if path == "" {
			t.Error("Expected non-empty path for httpx")
		}
	} else {
		if err == nil {
			t.Errorf("Expected error for httpx, but found at: %s", path)
		}
	}
}

func TestParseHTTPXOutput(t *testing.T) {
	tests := []struct {
		name           string
		line           string
		expectedURL    string
		expectedStatus int
		shouldBeNil    bool
	}{
		{
			name:           "url with status code",
			line:           "https://example.com [200]",
			expectedURL:    "https://example.com",
			expectedStatus: 200,
			shouldBeNil:    false,
		},
		{
			name:           "url with different status",
			line:           "http://test.com [404]",
			expectedURL:    "http://test.com",
			expectedStatus: 404,
			shouldBeNil:    false,
		},
		{
			name:           "url only",
			line:           "https://example.com",
			expectedURL:    "https://example.com",
			expectedStatus: 200, // fallback
			shouldBeNil:    false,
		},
		{
			name:           "empty line",
			line:           "",
			expectedURL:    "",
			expectedStatus: 200, // fallback status
			shouldBeNil:    false, // function returns WebAsset even for empty
		},
		{
			name:           "invalid format",
			line:           "not a url",
			expectedURL:    "not a url",
			expectedStatus: 200, // fallback
			shouldBeNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHTTPXOutput(tt.line)
			
			if tt.shouldBeNil {
				if result != nil {
					t.Errorf("Expected nil result for line: %s", tt.line)
				}
				return
			}
			
			if result == nil {
				t.Errorf("Expected non-nil result for line: %s", tt.line)
				return
			}
			
			if result.URL != tt.expectedURL {
				t.Errorf("Expected URL %s, got %s", tt.expectedURL, result.URL)
			}
			
			if result.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, result.StatusCode)
			}
		})
	}
}

func httpxExists() bool {
	path, err := findHTTPXBinary()
	return err == nil && path != ""
}