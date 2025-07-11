package main

import (
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestExtractKeywordsFromDomains(t *testing.T) {
	tests := []struct {
		name     string
		domains  []string
		expected []string
	}{
		{
			name:     "single domain",
			domains:  []string{"example.com"},
			expected: []string{"example"},
		},
		{
			name:     "multiple domains",
			domains:  []string{"test.com", "demo.org"},
			expected: []string{"test", "demo"},
		},
		{
			name:     "domain with hyphens",
			domains:  []string{"multi-word-domain.com"},
			expected: []string{"multi", "word", "domain"},
		},
		{
			name:     "domain with underscores",
			domains:  []string{"test_domain.com"},
			expected: []string{"test", "domain"},
		},
		{
			name:     "subdomain",
			domains:  []string{"api.example.com"},
			expected: []string{"example"},
		},
		{
			name:     "short parts filtered out",
			domains:  []string{"ab.cd.example.com"},
			expected: []string{"example"},
		},
		{
			name:     "empty domains",
			domains:  []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractKeywordsFromDomains(tt.domains)
			if !stringSliceEqual(result, tt.expected) {
				t.Errorf("extractKeywordsFromDomains() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRunSubfinder(t *testing.T) {
	if !commandExists("subfinder") {
		t.Skip("subfinder not installed, skipping test")
	}

	tests := []struct {
		name    string
		domains []string
	}{
		{
			name:    "single domain",
			domains: []string{"example.com"},
		},
		{
			name:    "multiple domains",
			domains: []string{"example.com", "test.com"},
		},
		{
			name:    "empty domains",
			domains: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runSubfinder(tt.domains)
			if tt.name == "empty domains" {
				if len(result) != 0 {
					t.Errorf("runSubfinder() with empty domains should return empty slice, got %v", result)
				}
			} else {
				// For non-empty domains, result should be a slice (can be empty if no subdomains found)
				if result == nil {
					t.Errorf("runSubfinder() should not return nil")
				}
			}
		})
	}
}

func TestRunSubfinderWithoutSubfinder(t *testing.T) {
	if commandExists("subfinder") {
		t.Skip("subfinder is installed, skipping test for missing command")
	}

	domains := []string{"example.com"}
	result := runSubfinder(domains)
	
	if len(result) != 0 {
		t.Errorf("runSubfinder() without subfinder should return empty slice, got %v", result)
	}
}

func TestProcessDomainsTLS(t *testing.T) {
	tests := []struct {
		name     string
		domains  []string
		keywords []string
	}{
		{
			name:     "single domain with keywords",
			domains:  []string{"example.com"},
			keywords: []string{"api", "test"},
		},
		{
			name:     "multiple domains",
			domains:  []string{"example.com", "test.com"},
			keywords: []string{"api"},
		},
		{
			name:     "empty domains",
			domains:  []string{},
			keywords: []string{"api"},
		},
		{
			name:     "empty keywords",
			domains:  []string{"example.com"},
			keywords: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processDomainsTLS(tt.domains, tt.keywords)
			// Function should return a slice (can be empty), not nil
			if result == nil {
				t.Errorf("processDomainsTLS() should return empty slice, not nil")
			}
		})
	}
}

func TestProcessDomainTLS(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		keywords []string
	}{
		{
			name:     "valid domain with keywords",
			domain:   "example.com",
			keywords: []string{"api", "test"},
		},
		{
			name:     "empty domain",
			domain:   "",
			keywords: []string{"api"},
		},
		{
			name:     "empty keywords",
			domain:   "example.com",
			keywords: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processDomainTLS(tt.domain, tt.keywords)
			// Function should return a slice (can be empty), not nil
			if result == nil {
				t.Errorf("processDomainTLS() should return empty slice, not nil")
			}
		})
	}
}

func TestMainWithInvalidArgs(t *testing.T) {
	// Test with no arguments
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	os.Args = []string{"main"}
	
	// Capture stderr
	stderrR, stderrW, _ := os.Pipe()
	oldStderr := os.Stderr
	os.Stderr = stderrW
	
	defer func() {
		os.Stderr = oldStderr
		stderrW.Close()
	}()
	
	// Test should exit with code 1 - we'll check stderr output instead
	defer func() {
		if r := recover(); r != nil {
			// Expected if os.Exit is called
			stderrW.Close()
			stderr, _ := io.ReadAll(stderrR)
			stderrStr := string(stderr)
			if !strings.Contains(stderrStr, "Usage:") {
				t.Errorf("Expected stderr to contain 'Usage:', got: %s", stderrStr)
			}
		}
	}()
	
	main()
}

func TestMainWithValidArgs(t *testing.T) {
	if !commandExists("subfinder") {
		t.Skip("subfinder not installed, skipping integration test")
	}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	os.Args = []string{"main", "example.com"}
	
	// Capture stdout
	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w
	
	// Capture stderr
	stderrR, stderrW, _ := os.Pipe()
	oldStderr := os.Stderr
	os.Stderr = stderrW
	
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		w.Close()
		stderrW.Close()
	}()
	
	// Run main in goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected if os.Exit is called
			}
		}()
		main()
		w.Close()
		stderrW.Close()
	}()
	
	// Read stdout
	w.Close()
	stderrW.Close()
	
	stdout, _ := io.ReadAll(r)
	stderr, _ := io.ReadAll(stderrR)
	
	stdoutStr := string(stdout)
	stderrStr := string(stderr)
	
	// Check that stderr contains expected messages
	if !strings.Contains(stderrStr, "Starting subdomain discovery") {
		t.Errorf("Expected stderr to contain 'Starting subdomain discovery', got: %s", stderrStr)
	}
	
	// Check that stdout contains at least the input domain
	if !strings.Contains(stdoutStr, "example.com") {
		t.Errorf("Expected stdout to contain 'example.com', got: %s", stdoutStr)
	}
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	
	// Convert to maps for comparison (order doesn't matter for keywords)
	mapA := make(map[string]bool)
	mapB := make(map[string]bool)
	
	for _, s := range a {
		mapA[s] = true
	}
	for _, s := range b {
		mapB[s] = true
	}
	
	return reflect.DeepEqual(mapA, mapB)
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	if err == nil {
		return true
	}
	
	// For httpx, also check in Go bin directory
	if cmd == "httpx" {
		goPath := os.Getenv("GOPATH")
		if goPath == "" {
			goPath = os.Getenv("HOME") + "/go"
		}
		httpxPath := goPath + "/bin/httpx"
		if _, err := os.Stat(httpxPath); err == nil {
			return true
		}
	}
	
	return false
}

func TestScanHTTPServices(t *testing.T) {
	if !commandExists("httpx") {
		t.Skip("httpx not installed, skipping test")
	}

	tests := []struct {
		name       string
		subdomains []string
		ports      []string
	}{
		{
			name:       "single subdomain with common ports",
			subdomains: []string{"google.com"},
			ports:      []string{"80", "443"},
		},
		{
			name:       "empty subdomains",
			subdomains: []string{},
			ports:      []string{"80", "443"},
		},
		{
			name:       "empty ports",
			subdomains: []string{"google.com"},
			ports:      []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanHTTPServices(tt.subdomains, tt.ports)
			if result == nil {
				t.Errorf("scanHTTPServices() should return empty slice, not nil")
			}
			
			if tt.name == "empty subdomains" || tt.name == "empty ports" {
				if len(result) != 0 {
					t.Errorf("scanHTTPServices() should return empty slice for empty inputs, got %v", result)
				}
			}
		})
	}
}

func TestScanHTTPServicesWithoutHttpx(t *testing.T) {
	if commandExists("httpx") {
		t.Skip("httpx is installed, skipping test for missing command")
	}

	subdomains := []string{"google.com"}
	ports := []string{"80", "443"}
	result := scanHTTPServices(subdomains, ports)
	
	if len(result) != 0 {
		t.Errorf("scanHTTPServices() without httpx should return empty slice, got %v", result)
	}
}

func TestMainWithPortsFlag(t *testing.T) {
	if !commandExists("subfinder") || !commandExists("httpx") {
		t.Skip("subfinder or httpx not installed, skipping integration test")
	}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	os.Args = []string{"main", "example.com", "--ports", "80,443"}
	
	// Capture stdout  
	_, stdoutW, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = stdoutW
	
	// Capture stderr
	stderrR, stderrW, _ := os.Pipe()
	oldStderr := os.Stderr
	os.Stderr = stderrW
	
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		stdoutW.Close()
		stderrW.Close()
	}()
	
	// Run main in goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected if os.Exit is called
			}
		}()
		main()
		stdoutW.Close()
		stderrW.Close()
	}()
	
	// Read stderr
	stdoutW.Close()
	stderrW.Close()
	
	stderr, _ := io.ReadAll(stderrR)
	stderrStr := string(stderr)
	
	// Check that stderr contains expected messages
	if !strings.Contains(stderrStr, "Will scan ports: [80 443]") {
		t.Errorf("Expected stderr to contain port configuration, got: %s", stderrStr)
	}
	
	if !strings.Contains(stderrStr, "HTTP service scan") {
		t.Errorf("Expected stderr to contain HTTP service scan message, got: %s", stderrStr)
	}
}