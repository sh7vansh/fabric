package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"fabric/internal/pki"

	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Completely remove Fabric, its services, and configuration from this system",
	RunE:  runUninstall,
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
}

func runUninstall(cmd *cobra.Command, args []string) error {
	fmt.Println("[+] Starting Fabric uninstallation...")

	// 1. Uninstall services if they exist (silently ignore errors if not installed)
	_ = UninstallService("thread")
	_ = UninstallService("server")
	_ = UninstallService("node")
	_ = UninstallService("socket")

	// 2. Remove Root CA from system trust store (if it was installed)
	trustStore := pki.NewSystemTrustStore()
	if installed, _ := trustStore.IsInstalled("fabric-ca"); installed {
		fmt.Println("[+] Removing Fabric Root CA from system trust store...")
		if err := trustStore.UninstallCA("fabric-ca"); err != nil {
			fmt.Printf("[!] Warning: Failed to fully remove CA certificate: %v\n", err)
		}
	}

	// 3. Remove configuration directory
	home, err := os.UserHomeDir()
	if err == nil {
		configDir := filepath.Join(home, ".config", "fabric")
		if _, err := os.Stat(configDir); err == nil {
			fmt.Printf("[+] Removing configuration directory: %s\n", configDir)
			_ = os.RemoveAll(configDir)
		}
	}

	// 4. Remove binaries
	binaries := []string{"fabric", "fabric-server", "fabric-thread", "fabric-socket", "fabric-node"}
	var dirs []string
	dirs = append(dirs, "/usr/local/bin")
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "bin"))
	}

	for _, dir := range dirs {
		for _, bin := range binaries {
			binPath := filepath.Join(dir, bin)
			if _, err := os.Stat(binPath); err == nil {
				fmt.Printf("[+] Removing binary: %s\n", binPath)
				// Try to remove directly
				if err := os.Remove(binPath); err != nil {
					// If permission denied, try with sudo
					fmt.Printf("[*] Elevating privileges to remove %s...\n", binPath)
					_ = exec.Command("sudo", "rm", "-f", binPath).Run()
				}
			}
		}
	}

	fmt.Println("\n[+] Fabric has been completely uninstalled from this system.")
	return nil
}
