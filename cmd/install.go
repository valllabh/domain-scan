package cmd

import (
	"fmt"

	"github.com/valllabh/domain-scan/pkg/utils"
	"github.com/spf13/cobra"
)

// installCmd represents the install command
var installCmd = &cobra.Command{
	Use:   "install [tool]",
	Short: "Install required dependencies",
	Long: `Install required dependencies for domain-scan including subfinder and httpx.
	
Available tools:
- subfinder: Passive subdomain discovery tool
- httpx: HTTP toolkit for service verification
- all: Install all required tools`,
	ValidArgs: []string{"subfinder", "httpx", "all"},
	Args:      cobra.MaximumNArgs(1),
	RunE:      runInstall,
}

func init() {
	rootCmd.AddCommand(installCmd)
}

func runInstall(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		args = []string{"all"}
	}

	tool := args[0]

	switch tool {
	case "all":
		fmt.Println("🔧 Installing all dependencies...")
		return utils.CheckAndInstallDependencies()
	case "subfinder":
		fmt.Println("🔧 Installing subfinder...")
		return installSpecificTool("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	case "httpx":
		fmt.Println("🔧 Installing httpx...")
		return installSpecificTool("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
	default:
		return fmt.Errorf("unknown tool: %s", tool)
	}
}

func installSpecificTool(name, installPath string) error {
	// Check if already installed
	if isDependencyInstalled(name) {
		fmt.Printf("✅ %s is already installed\n", name)
		return nil
	}

	// Install the tool
	if err := installDependency(name, installPath); err != nil {
		return fmt.Errorf("failed to install %s: %w", name, err)
	}

	fmt.Printf("✅ Successfully installed %s\n", name)
	return nil
}

// These functions are simplified versions for demonstration
// In the real implementation, you'd import from utils package
func isDependencyInstalled(name string) bool {
	// This would use the actual dependency checking logic
	return false
}

func installDependency(name, installPath string) error {
	// This would use the actual installation logic
	return utils.CheckAndInstallDependencies()
}