package discovery

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/domain-scan/domain-scan/pkg/types"
)

// HTTPServiceScan scans subdomains for active HTTP services
func HTTPServiceScan(ctx context.Context, subdomains []string, ports []int) ([]types.WebAsset, error) {
	var webAssets []types.WebAsset

	if len(subdomains) == 0 || len(ports) == 0 {
		return webAssets, nil
	}

	// Create URLs with ports
	var targets []string
	for _, subdomain := range subdomains {
		for _, port := range ports {
			// Add http and https versions
			if port == 443 {
				targets = append(targets, fmt.Sprintf("https://%s", subdomain))
			} else if port == 80 {
				targets = append(targets, fmt.Sprintf("http://%s", subdomain))
			} else {
				targets = append(targets, fmt.Sprintf("http://%s:%d", subdomain, port))
				targets = append(targets, fmt.Sprintf("https://%s:%d", subdomain, port))
			}
		}
	}

	// Write targets to temp file for httpx
	tmpFile, err := os.CreateTemp("", "http_targets_*.txt")
	if err != nil {
		return nil, fmt.Errorf("error creating temp file for HTTP targets: %w", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			// Log error but don't fail the operation for temp file cleanup
			log.Printf("Warning: failed to remove temp file %s: %v", tmpFile.Name(), err)
		}
	}()

	for _, target := range targets {
		if _, err := tmpFile.WriteString(target + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write target to temp file: %w", err)
		}
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	// Find httpx binary
	httpxPath, err := findHTTPXBinary()
	if err != nil {
		return nil, fmt.Errorf("httpx not found: %w", err)
	}

	// Run httpx with context
	cmd := exec.CommandContext(ctx, httpxPath, "-l", tmpFile.Name(), "-silent", "-status-code", "-timeout", "10", "-threads", "50") // #nosec G204 - trusted tool path
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("httpx execution failed: %w, stderr: %s", err, string(exitError.Stderr))
		}
		return nil, fmt.Errorf("error running httpx: %w", err)
	}

	// Parse httpx output
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			asset := parseHTTPXOutput(line)
			if asset != nil {
				webAssets = append(webAssets, *asset)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error parsing httpx output: %w", err)
	}

	return webAssets, nil
}

// findHTTPXBinary finds ProjectDiscovery's httpx binary
func findHTTPXBinary() (string, error) {
	// Check Go bin directory first (preferred for ProjectDiscovery's httpx)
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = os.Getenv("HOME") + "/go"
	}
	
	httpxPath := goPath + "/bin/httpx"
	if _, err := os.Stat(httpxPath); err == nil {
		// Verify it's the correct httpx by checking help output
		cmd := exec.Command(httpxPath, "-h") // #nosec G204 - trusted tool path
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), "projectdiscovery") {
			return httpxPath, nil
		}
	}
	
	// Check PATH but verify it's ProjectDiscovery's httpx
	if path, err := exec.LookPath("httpx"); err == nil {
		cmd := exec.Command(path, "-h") // #nosec G204 - trusted tool from PATH
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), "projectdiscovery") {
			return path, nil
		}
	}
	
	return "", fmt.Errorf("ProjectDiscovery's httpx not found")
}

// parseHTTPXOutput parses httpx output line and creates WebAsset
func parseHTTPXOutput(line string) *types.WebAsset {
	// httpx with -status-code outputs: URL [STATUS_CODE]
	if strings.Contains(line, "[") && strings.Contains(line, "]") {
		parts := strings.Split(line, " [")
		if len(parts) >= 2 {
			url := strings.TrimSpace(parts[0])
			statusCodeStr := strings.TrimRight(parts[1], "]")
			
			statusCode, err := strconv.Atoi(statusCodeStr)
			if err != nil {
				statusCode = 0
			}

			return &types.WebAsset{
				URL:        url,
				StatusCode: statusCode,
			}
		}
	} else {
		// Fallback: just the URL
		return &types.WebAsset{
			URL:        line,
			StatusCode: 200, // Assume success if no status code
		}
	}

	return nil
}