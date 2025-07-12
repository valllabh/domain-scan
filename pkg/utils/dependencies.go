package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// CheckAndInstallDependencies checks if required tools are installed and installs them if needed
func CheckAndInstallDependencies() error {
	dependencies := []struct {
		name        string
		installPath string
		checkPaths  []string
	}{
		{
			name:        "subfinder",
			installPath: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
			checkPaths:  []string{"subfinder"},
		},
		{
			name:        "httpx",
			installPath: "github.com/projectdiscovery/httpx/cmd/httpx@latest",
			checkPaths:  []string{"httpx"},
		},
	}

	for _, dep := range dependencies {
		if !isDependencyInstalled(dep.name, dep.checkPaths) {
			fmt.Fprintf(os.Stderr, "📦 Installing %s...\n", dep.name)
			if !installDependency(dep.name, dep.installPath) {
				return fmt.Errorf("failed to install %s", dep.name)
			}
		}
	}

	return nil
}

// isDependencyInstalled checks if a dependency is installed
func isDependencyInstalled(name string, checkPaths []string) bool {
	// For httpx, we need to check specifically for ProjectDiscovery's httpx
	if name == "httpx" {
		// Check Go bin directory first (preferred)
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
				return true
			}
		}
		
		// Check PATH but verify it's ProjectDiscovery's httpx
		if path, err := exec.LookPath("httpx"); err == nil {
			cmd := exec.Command(path, "-h") // #nosec G204 - trusted tool from PATH
			output, err := cmd.Output()
			if err == nil && strings.Contains(string(output), "projectdiscovery") {
				return true
			}
		}
		
		return false
	}

	// For other dependencies, check normally
	// Check in PATH
	for _, path := range checkPaths {
		if _, err := exec.LookPath(path); err == nil {
			return true
		}
	}

	// Check in Go bin directory
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = os.Getenv("HOME") + "/go"
	}
	
	for _, path := range checkPaths {
		binPath := goPath + "/bin/" + path
		if _, err := os.Stat(binPath); err == nil {
			return true
		}
	}

	return false
}

// installDependency installs a Go dependency
func installDependency(name, installPath string) bool {
	fmt.Fprintf(os.Stderr, "⏳ Installing %s from %s...\n", name, installPath)
	
	cmd := exec.Command("go", "install", "-v", installPath)
	cmd.Stdout = os.Stderr // Show install progress
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to install %s: %v\n", name, err)
		return false
	}
	
	fmt.Fprintf(os.Stderr, "✅ Successfully installed %s\n", name)
	return true
}