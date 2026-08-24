package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fabric/internal/pki"

	"github.com/spf13/cobra"
)

var (
	setupRoleFlag    string
	setupHostFlag    string
	setupTokenFlag   string
	setupDomainFlag  string
	setupAutoToken   bool
	setupNonInteract bool
	setupTrustCA     bool
	setupUntrustCA   bool
)

var setupCmd = &cobra.Command{
	Use:     "setup [flags]",
	Short:   "Interactive setup wizard to configure this machine as a Socket or Node",
	GroupID: "cluster",
	Long: `Interactive onboarding wizard to configure the local machine as either a central
Fabric Socket (control plane) or a Fabric Node (agent daemon). Supports interactive prompts,
non-interactive automation flags, and automatic root CA trust installation.`,
	Example: `  # Launch interactive setup wizard
  fabric setup

  # Install local mesh root CA into the OS/browser trust store
  fabric setup --trust-ca

  # Remove local mesh root CA from the OS trust store
  fabric setup --untrust-ca

  # Set up as a socket control plane non-interactively
  fabric setup --role=socket --domain=fabric.mesh --auto-token -y

  # Set up as a node connecting to an existing socket
  fabric setup --role=node --host=ws://192.168.1.50:8080/ws --token=secret-token -y`,
	RunE: func(cmd *cobra.Command, args []string) error {
		reader := bufio.NewReader(os.Stdin)

		if setupUntrustCA {
			trustStore := pki.NewSystemTrustStore()
			if err := trustStore.UninstallCA("fabric-ca"); err != nil {
				return fmt.Errorf("failed to remove root CA from system trust store: %w", err)
			}
			fmt.Println("[+] Successfully removed Fabric Root CA from system trust store.")
			return nil
		}

		if setupTrustCA {
			return installLocalCATrust()
		}

		fmt.Println("==================================================")
		fmt.Println("       Fabric Mesh Network - Setup Wizard         ")
		fmt.Println("==================================================")

		role := strings.ToLower(strings.TrimSpace(setupRoleFlag))
		if role == "" {
			if setupNonInteract {
				role = "socket"
			} else {
				fmt.Println("\nSelect role for this machine:")
				fmt.Println("  1) Socket (Central Control Plane & Mesh Router)")
				fmt.Println("  2) Node   (Distributed Agent Daemon)")
				choice := prompt(reader, "Enter choice [1 or 2]", "1")
				if choice == "2" || strings.ToLower(choice) == "node" {
					role = "node"
				} else {
					role = "socket"
				}
			}
		}

		if role == "socket" {
			return runSocketSetup(reader)
		} else if role == "node" {
			return runNodeSetup(reader)
		} else {
			return fmt.Errorf("invalid role: %s. Must be 'socket' or 'node'", role)
		}
	},
}

func init() {
	setupCmd.Flags().StringVarP(&setupRoleFlag, "role", "r", "", "Machine role: 'socket' or 'node'")
	setupCmd.Flags().StringVarP(&setupHostFlag, "host", "H", "", "Socket URL (for node setup)")
	setupCmd.Flags().StringVar(&setupTokenFlag, "token", "", "Pre-shared cluster token")
	setupCmd.Flags().StringVar(&setupDomainFlag, "domain", "fabric.mesh", "Domain for mesh DNS")
	setupCmd.Flags().BoolVar(&setupAutoToken, "auto-token", false, "Auto-generate a secure random token")
	setupCmd.Flags().BoolVarP(&setupNonInteract, "yes", "y", false, "Accept all defaults non-interactively")
	setupCmd.Flags().BoolVar(&setupTrustCA, "trust-ca", false, "Install Fabric Root CA into system trust store")
	setupCmd.Flags().BoolVar(&setupUntrustCA, "untrust-ca", false, "Remove Fabric Root CA from system trust store")
}

func runSocketSetup(reader *bufio.Reader) error {
	fmt.Println("\n[+] Configuring Socket (Control Plane)...")

	token := setupTokenFlag
	if token == "" {
		if setupAutoToken || setupNonInteract {
			token = generateSecureToken()
		} else {
			auto := prompt(reader, "Auto-generate secure cluster token? (Y/n)", "Y")
			if strings.ToLower(auto) == "y" || strings.ToLower(auto) == "yes" {
				token = generateSecureToken()
			} else {
				token = prompt(reader, "Enter cluster token", "default-secret")
			}
		}
	}

	domain := setupDomainFlag
	if !setupNonInteract && domain == "fabric.mesh" {
		domain = prompt(reader, "Mesh DNS Domain", "fabric.mesh")
	}

	localIP := getOutboundIP()

	// 1. Initialize local Cluster Root CA
	home, _ := os.UserHomeDir()
	caDir := filepath.Join(home, ".fabric", "ca")
	ca, err := pki.LoadOrInitCA(caDir, domain)
	if err != nil {
		fmt.Printf("[!] Warning: Could not initialize cluster Root CA: %v\n", err)
	} else {
		fmt.Printf("[+] Initialized Fabric Root CA in %s\n", caDir)
		trust := setupTrustCA
		if !setupNonInteract && !trust {
			resp := prompt(reader, "Install Fabric Root CA into system trust store for automatic HTTPS? (Y/n)", "Y")
			if strings.ToLower(resp) == "y" || strings.ToLower(resp) == "yes" {
				trust = true
			}
		}
		if trust {
			trustStore := pki.NewSystemTrustStore()
			if err := trustStore.InstallCA(ca.CertPEM(), "fabric-ca"); err != nil {
				fmt.Printf("[!] Note: Could not auto-install CA to system trust store (run with sudo or 'fabric setup --trust-ca'): %v\n", err)
			} else {
				fmt.Println("[+] Successfully installed Fabric Root CA into system trust store.")
			}
		}
	}

	// 2. Save local CLI config
	cliCfg := &Config{
		Host:  "ws://localhost:8080/ws",
		Token: token,
	}
	if err := SaveConfig(cliCfg); err != nil {
		fmt.Printf("[!] Warning: Could not save CLI config: %v\n", err)
	} else {
		fmt.Println("[+] CLI configuration saved to ~/.fabric/config.json")
	}

	// 3. Save environment file and optionally install service
	envContent := fmt.Sprintf("FABRIC_TOKEN=%s\nFABRIC_DOMAIN=%s\n", token, domain)
	saveDaemonConfigAndService(reader, "socket", envContent)

	fmt.Println("\n==================================================")
	fmt.Println("         Socket Setup Complete!                   ")
	fmt.Println("==================================================")
	fmt.Printf("Cluster Token: %s\n", token)
	fmt.Printf("Mesh Domain:   %s\n", domain)
	fmt.Printf("Socket URL:    ws://%s:8080/ws (or wss:// for TLS)\n", localIP)
	fmt.Println("\nTo stitch a remote node via SSH, run:")
	fmt.Printf("  fabric stitch user@<remote-ip>\n\n")
	fmt.Println("Or manually on target node:")
	fmt.Printf("  fabric setup --role=node --host=ws://%s:8080/ws --token=%s\n", localIP, token)
	fmt.Println("==================================================")

	return nil
}

func installLocalCATrust() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	certPath := filepath.Join(home, ".fabric", "ca", "ca.crt")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("could not find Root CA at %s (run 'fabric setup --role=socket' first): %w", certPath, err)
	}

	trustStore := pki.NewSystemTrustStore()
	if err := trustStore.InstallCA(certPEM, "fabric-ca"); err != nil {
		return fmt.Errorf("failed to install CA into system trust store (try running with sudo): %w", err)
	}
	fmt.Println("[+] Successfully installed Fabric Root CA into system trust store.")
	return nil
}

func runNodeSetup(reader *bufio.Reader) error {
	fmt.Println("\n[+] Configuring Node (Agent Daemon)...")

	host := setupHostFlag
	if host == "" {
		if setupNonInteract {
			host = "ws://localhost:8080/ws"
		} else {
			host = prompt(reader, "Socket WebSocket URL (e.g. ws://192.168.1.50:8080/ws)", "ws://localhost:8080/ws")
		}
	}

	token := setupTokenFlag
	if token == "" {
		if setupNonInteract {
			token = "default-secret"
		} else {
			token = prompt(reader, "Cluster Token", "default-secret")
		}
	}

	domain := setupDomainFlag
	if !setupNonInteract && domain == "fabric.mesh" {
		domain = prompt(reader, "Mesh DNS Domain", "fabric.mesh")
	}

	// 1. Save local CLI config
	cliCfg := &Config{
		Host:  host,
		Token: token,
	}
	if err := SaveConfig(cliCfg); err != nil {
		fmt.Printf("[!] Warning: Could not save CLI config: %v\n", err)
	} else {
		fmt.Println("[+] CLI configuration saved to ~/.fabric/config.json")
	}

	// 2. Save environment file and optionally install service
	envContent := fmt.Sprintf("FABRIC_SOCKET_URL=%s\nFABRIC_TOKEN=%s\nFABRIC_DOMAIN=%s\n", host, token, domain)
	saveDaemonConfigAndService(reader, "node", envContent)

	fmt.Println("\n==================================================")
	fmt.Println("          Node Setup Complete!                    ")
	fmt.Println("==================================================")
	fmt.Printf("Connected Socket: %s\n", host)
	fmt.Printf("Mesh Domain:      %s\n", domain)
	fmt.Println("\nManage daemon service with:")
	fmt.Println("  fabric service status node")
	fmt.Println("  fabric service restart node")
	fmt.Println("==================================================")

	return nil
}

func saveDaemonConfigAndService(reader *bufio.Reader, role, envContent string) {
	envDir := "/etc/fabric"
	if err := runPrivilegedCommand("mkdir", "-p", envDir); err != nil {
		home, _ := os.UserHomeDir()
		envDir = filepath.Join(home, ".fabric")
		_ = os.MkdirAll(envDir, 0755)
	}

	envPath := filepath.Join(envDir, role+".env")
	if os.Geteuid() == 0 || !strings.HasPrefix(envDir, "/etc") {
		_ = os.WriteFile(envPath, []byte(envContent), 0600)
	} else {
		tmpFile, err := os.CreateTemp("", role+"-env-*")
		if err == nil {
			_, _ = tmpFile.WriteString(envContent)
			tmpFile.Close()
			_ = runPrivilegedCommand("cp", tmpFile.Name(), envPath)
			_ = runPrivilegedCommand("chmod", "600", envPath)
			_ = os.Remove(tmpFile.Name())
		}
	}
	fmt.Printf("[+] %s environment written to %s\n", strings.Title(role), envPath)

	if _, err := exec.LookPath("systemctl"); err == nil {
		installSvc := false
		if setupNonInteract {
			installSvc = true
		} else {
			resp := prompt(reader, fmt.Sprintf("Install and start fabric-%s as a systemd service? (Y/n)", role), "Y")
			if strings.ToLower(resp) == "y" || strings.ToLower(resp) == "yes" {
				installSvc = true
			}
		}
		if installSvc {
			if err := InstallService(role); err != nil {
				fmt.Printf("[!] Note: Could not auto-install systemd service: %v\n", err)
			}
		}
	}
}

func prompt(reader *bufio.Reader, message, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", message, defaultValue)
	} else {
		fmt.Printf("%s: ", message)
	}

	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultValue
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}

func generateSecureToken() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("secret-%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
