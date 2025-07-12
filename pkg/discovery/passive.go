package discovery

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// PassiveDiscovery performs passive subdomain discovery using subfinder
func PassiveDiscovery(ctx context.Context, domains []string) ([]string, error) {
	var subdomains []string

	if len(domains) == 0 {
		return subdomains, nil
	}

	// Create temporary file with domains
	tmpFile, err := os.CreateTemp("", "domains_*.txt")
	if err != nil {
		return nil, fmt.Errorf("error creating temp file: %w", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			// Log error but don't fail the operation for temp file cleanup
			log.Printf("Warning: failed to remove temp file %s: %v", tmpFile.Name(), err)
		}
	}()

	// Write domains to temp file
	for _, domain := range domains {
		if _, err := tmpFile.WriteString(domain + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write domain to temp file: %w", err)
		}
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	// Find subfinder binary
	subfinderPath, err := findBinary("subfinder")
	if err != nil {
		return nil, fmt.Errorf("subfinder not found: %w", err)
	}

	// Run subfinder with context
	cmd := exec.CommandContext(ctx, subfinderPath, "-dL", tmpFile.Name(), "-all", "-silent") // #nosec G204 - trusted tool path
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running subfinder: %w", err)
	}

	// Parse output
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error parsing subfinder output: %w", err)
	}

	return subdomains, nil
}

// findBinary finds a binary in common locations
func findBinary(name string) (string, error) {
	// Try PATH first
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}

	// Try Go bin directory
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = os.Getenv("HOME") + "/go"
	}
	
	binPath := goPath + "/bin/" + name
	if _, err := os.Stat(binPath); err == nil {
		return binPath, nil
	}

	return "", fmt.Errorf("binary %s not found in PATH or %s/bin", name, goPath)
}