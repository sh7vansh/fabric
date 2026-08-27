package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fabric/internal/firewall"
	"fabric/internal/pki"

	"github.com/spf13/cobra"
)

var uninstallYesFlag bool

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Completely remove Fabric, its services, and configuration from this system",
	RunE:  runUninstall,
}

func init() {
	uninstallCmd.Flags().BoolVarP(&uninstallYesFlag, "yes", "y", false, "Accept all prompts non-interactively")
	rootCmd.AddCommand(uninstallCmd)
}

func runUninstall(cmd *cobra.Command, args []string) error {
	fmt.Println("[+] Starting Fabric uninstallation...")

	// 1. Detect if host was configured as Server or Remote Thread before configs are wiped
	isServerOrRemoteThread := false
	home, err := os.UserHomeDir()
	if err == nil {
		for _, envPath := range []string{
			filepath.Join(home, ".fabric", "server.env"),
			filepath.Join(home, ".config", "fabric", "server.env"),
			"/etc/fabric/server.env",
		} {
			if _, err := os.Stat(envPath); err == nil {
				isServerOrRemoteThread = true
				break
			}
		}
		if !isServerOrRemoteThread {
			for _, envPath := range []string{
				filepath.Join(home, ".fabric", "thread.env"),
				filepath.Join(home, ".config", "fabric", "thread.env"),
				"/etc/fabric/thread.env",
			} {
				if data, err := os.ReadFile(envPath); err == nil {
					if strings.Contains(string(data), "FABRIC_MODE=remote") || strings.Contains(string(data), "FABRIC_LISTEN=") {
						isServerOrRemoteThread = true
						break
					}
				}
			}
		}
	}

	// 2. Uninstall services if they exist (silently ignore errors if not installed)
	_ = UninstallService("thread")
	_ = UninstallService("server")
	_ = UninstallService("node")
	_ = UninstallService("socket")

	// 3. Remove Root CA from system trust store (if it was installed)
	trustStore := pki.NewSystemTrustStore()
	if installed, _ := trustStore.IsInstalled("fabric-ca"); installed {
		fmt.Println("[+] Removing Fabric Root CA from system trust store...")
		if err := trustStore.UninstallCA("fabric-ca"); err != nil {
			fmt.Printf("[!] Warning: Failed to fully remove CA certificate: %v\n", err)
		}
	}

	// 4. Firewall Rule Teardown
	fwMgr := getFirewallManager()
	backend := fwMgr.DetectBackend()
	if backend != firewall.BackendNone && isServerOrRemoteThread {
		portsToClose := []struct {
			port  int
			proto string
		}{
			{8443, "tcp"},
			{51820, "udp"},
		}

		if uninstallYesFlag || !isTerminalInput() {
			for _, p := range portsToClose {
				err := fwMgr.ClosePortWithBackend(backend, p.port, p.proto)
				if err == nil {
					fmt.Printf("[+] Removed Fabric firewall rule (closed %d/%s in %s)\n", p.port, p.proto, backend)
				} else {
					manual := fwMgr.GetClosePortManualInstructions(backend, p.port, p.proto)
					if manual != "" {
						fmt.Printf("    Manual removal command: %s\n", manual)
					}
				}
			}
		} else {
			reader := bufio.NewReader(os.Stdin)
			promptMsg := fmt.Sprintf("Remove Fabric firewall rules (8443/tcp, 51820/udp) from %s? (Y/n)", backend)
			choice := prompt(reader, promptMsg, "Y")
			if strings.ToLower(choice) == "y" || strings.ToLower(choice) == "yes" || choice == "" {
				for _, p := range portsToClose {
					err := fwMgr.ClosePortWithBackend(backend, p.port, p.proto)
					if err == nil {
						fmt.Printf("[+] Removed Fabric firewall rule (closed %d/%s in %s)\n", p.port, p.proto, backend)
					} else {
						manual := fwMgr.GetClosePortManualInstructions(backend, p.port, p.proto)
						if manual != "" {
							fmt.Printf("    Manual removal command: %s\n", manual)
						}
					}
				}
			} else {
				fmt.Println("[*] Skipped firewall rule removal.")
			}
		}
	}

	// 5. Remove configuration directory
	if home != "" {
		configDir := filepath.Join(home, ".config", "fabric")
		if _, err := os.Stat(configDir); err == nil {
			fmt.Printf("[+] Removing configuration directory: %s\n", configDir)
			_ = os.RemoveAll(configDir)
		}
		fabricDir := filepath.Join(home, ".fabric")
		if _, err := os.Stat(fabricDir); err == nil {
			fmt.Printf("[+] Removing state directory: %s\n", fabricDir)
			_ = os.RemoveAll(fabricDir)
		}
	}

	// 6. Remove binaries
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
					// If permission denied, try with non-interactive sudo
					_ = exec.Command("sudo", "-n", "rm", "-f", binPath).Run()
				}
			}
		}
	}

	fmt.Println("\n[+] Fabric has been completely uninstalled from this system.")
	return nil
}

