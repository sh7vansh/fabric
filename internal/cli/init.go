package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fabric/internal/pki"

	"github.com/spf13/cobra"
)

var (
	initRoleFlag    string
	initServerFlag  string
	initHostFlag    string
	initTokenFlag   string
	initDomainFlag  string
	initAutoToken   bool
	initNonInteract bool
	initTrustCA     bool
	initUntrustCA   bool
)

var initCmd = &cobra.Command{
	Use:     "init [flags]",
	Short:   "Interactive CLI and configuration onboarding wizard",
	GroupID: "system",
	Long: `Interactive onboarding wizard to configure the local operator workspace (~/.fabric/config.json),
participation role (cli, server, agent, or both), cluster tokens, and Root CA trust.`,
	Example: `  # Launch interactive setup wizard
  fabric init

  # Set up as a dedicated Fabric Server
  fabric init --role server

  # Set up as a managed Agent thread
  fabric init --role agent --server ws://gateway:8080/ws --token secret-token

  # Non-interactive CLI setup for scripts
  fabric init -y --server ws://gateway:8080/ws --token secret-token

  # Install local Fabric Root CA into the OS trust store
  fabric init --trust-ca

  # Remove local Fabric Root CA from the OS trust store
  fabric init --untrust-ca`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().StringVar(&initRoleFlag, "role", "", "Machine participation role: 'cli', 'server', 'agent', or 'both'")
	initCmd.Flags().StringVarP(&initServerFlag, "server", "s", "", "Fabric server WebSocket URL (e.g. ws://192.168.1.50:8080/ws)")
	initCmd.Flags().StringVarP(&initHostFlag, "host", "H", "", "Server URL (deprecated, use --server)")
	initCmd.Flags().StringVar(&initTokenFlag, "token", "", "Pre-shared cluster token")
	initCmd.Flags().StringVar(&initDomainFlag, "domain", "fabric.mesh", "Domain for Fabric DNS")
	initCmd.Flags().BoolVar(&initAutoToken, "auto-token", false, "Auto-generate a secure random token")
	initCmd.Flags().BoolVarP(&initNonInteract, "yes", "y", false, "Accept all defaults non-interactively")
	initCmd.Flags().BoolVar(&initTrustCA, "trust-ca", false, "Install Fabric Root CA into system trust store")
	initCmd.Flags().BoolVar(&initUntrustCA, "untrust-ca", false, "Remove Fabric Root CA from system trust store")
}

func parseRoleChoice(input string) string {
	val := strings.ToLower(strings.TrimSpace(input))
	switch val {
	case "2", "server":
		return "server"
	case "3", "agent":
		return "agent"
	case "4", "both":
		return "both"
	case "1", "cli", "client":
		return "cli"
	default:
		return "cli"
	}
}

func runInit(cmd *cobra.Command, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	if initUntrustCA {
		trustStore := pki.NewSystemTrustStore()
		if err := trustStore.UninstallCA("fabric-ca"); err != nil {
			return fmt.Errorf("failed to remove root CA from system trust store: %w", err)
		}
		fmt.Println("[+] Successfully removed Fabric Root CA from system trust store.")
		return nil
	}

	if initTrustCA {
		return installLocalCATrust()
	}

	fmt.Println("==================================================")
	fmt.Println("         Fabric Onboarding & Setup                ")
	fmt.Println("==================================================")

	// 1. Role Selection
	role := "cli"
	if initRoleFlag != "" {
		role = parseRoleChoice(initRoleFlag)
	} else if !initNonInteract {
		fmt.Println("How will this machine participate in the Fabric?")
		fmt.Println("  [1] CLI only     (Operator CLI / workstation — default)")
		fmt.Println("  [2] Server       (Run Fabric Server & control-plane daemon)")
		fmt.Println("  [3] Agent        (Join as a managed thread / run fabric-agent)")
		fmt.Println("  [4] Both         (Run Fabric Server + local Agent thread)")
		roleChoice := prompt(reader, "Choice", "1")
		role = parseRoleChoice(roleChoice)
	}

	// 2. Server URL
	serverURL := initServerFlag
	if serverURL == "" {
		serverURL = initHostFlag
	}
	if serverURL == "" {
		defaultSrv := "ws://localhost:8080/ws"
		if initNonInteract {
			serverURL = defaultSrv
		} else if role == "server" || role == "both" {
			serverURL = prompt(reader, "Fabric Server listen URL", defaultSrv)
		} else {
			serverURL = prompt(reader, "Fabric Server WebSocket URL (e.g. ws://192.168.1.50:8080/ws)", defaultSrv)
		}
	}

	// 3. Cluster Token
	token := initTokenFlag
	if token == "" {
		if initAutoToken {
			token = generateSecureToken()
		} else if initNonInteract {
			token = "default-secret"
		} else if role == "server" || role == "both" {
			auto := prompt(reader, "Auto-generate secure cluster token? (Y/n)", "Y")
			if strings.ToLower(auto) == "y" || strings.ToLower(auto) == "yes" || auto == "" {
				token = generateSecureToken()
			} else {
				token = prompt(reader, "Enter cluster token", "default-secret")
			}
		} else {
			token = prompt(reader, "Enter cluster token", "default-secret")
		}
	}

	// 4. Fabric Domain
	domain := initDomainFlag
	if !initNonInteract && domain == "fabric.mesh" {
		domain = prompt(reader, "Fabric Domain", "fabric.mesh")
	}

	// 5. CA Trust Store Setup
	home, _ := os.UserHomeDir()
	caDir := filepath.Join(home, ".fabric", "ca")
	caCertPath := filepath.Join(caDir, "ca.crt")
	if _, err := os.Stat(caCertPath); err == nil {
		if !initNonInteract {
			resp := prompt(reader, "Install Fabric Root CA into system trust store for automatic HTTPS? (Y/n)", "Y")
			if strings.ToLower(resp) == "y" || strings.ToLower(resp) == "yes" {
				_ = installLocalCATrust()
			}
		}
	}

	// 6. Save CLI Config
	cliCfg := &Config{
		Host:  serverURL,
		Token: token,
	}
	if err := SaveConfig(cliCfg); err != nil {
		fmt.Printf("[!] Warning: Could not save CLI config: %v\n", err)
	} else {
		fmt.Println("[+] CLI configuration saved to ~/.fabric/config.json")
	}

	// 7. Write Service Environment Files and Start Services
	var startedServices []string
	if role == "server" || role == "both" {
		if err := writeRoleEnv("server", serverURL, token, domain); err == nil {
			fmt.Println("[+] Configured server environment (~/.fabric/server.env)")
		}
		if !initNonInteract {
			if err := InstallService("server"); err == nil {
				startedServices = append(startedServices, "fabric-server")
			}
		}
	}

	if role == "agent" || role == "both" {
		if err := writeRoleEnv("agent", serverURL, token, domain); err == nil {
			fmt.Println("[+] Configured agent environment (~/.fabric/agent.env)")
		}
		if !initNonInteract {
			if err := InstallService("agent"); err == nil {
				startedServices = append(startedServices, "fabric-agent")
			}
		}
	}

	// 8. Completion Summary
	fmt.Println("\n==================================================")
	fmt.Println("         Fabric Initialization Complete!          ")
	fmt.Println("==================================================")
	fmt.Printf("Role:          %s\n", formatRoleDisplay(role))
	fmt.Printf("Server URL:    %s\n", serverURL)
	fmt.Printf("Cluster Token: %s\n", token)
	fmt.Printf("Domain:        %s\n", domain)
	if len(startedServices) > 0 {
		fmt.Printf("Services:      %s [active]\n", strings.Join(startedServices, ", "))
	}

	if role == "server" || role == "both" {
		fmt.Println("\nTo stitch remote machines via SSH, run:")
		fmt.Println("  fabric stitch user@<remote-ip>")
	}
	fmt.Println("\nTo inspect threads:")
	fmt.Println("  fabric ps")
	fmt.Println("==================================================")

	return nil
}

func formatRoleDisplay(role string) string {
	switch role {
	case "server":
		return "Server (Control Plane)"
	case "agent":
		return "Agent (Thread)"
	case "both":
		return "Server + Agent"
	default:
		return "CLI only (Operator Workstation)"
	}
}

func writeRoleEnv(role, serverURL, token, domain string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	fabricDir := filepath.Join(home, ".fabric")
	_ = os.MkdirAll(fabricDir, 0755)
	configDir := filepath.Join(home, ".config", "fabric")
	_ = os.MkdirAll(configDir, 0755)

	var sb strings.Builder
	if role == "server" {
		sb.WriteString(fmt.Sprintf("FABRIC_TOKEN=%s\n", token))
		sb.WriteString(fmt.Sprintf("FABRIC_DOMAIN=%s\n", domain))
		sb.WriteString("FABRIC_HTTP_PORT=8080\n")
	} else if role == "agent" {
		sb.WriteString(fmt.Sprintf("FABRIC_SERVER_URL=%s\n", serverURL))
		sb.WriteString(fmt.Sprintf("FABRIC_TOKEN=%s\n", token))
		sb.WriteString(fmt.Sprintf("FABRIC_DOMAIN=%s\n", domain))
	}

	content := []byte(sb.String())
	_ = os.WriteFile(filepath.Join(fabricDir, role+".env"), content, 0600)
	_ = os.WriteFile(filepath.Join(configDir, role+".env"), content, 0600)
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
		return fmt.Errorf("could not find Root CA at %s: %w", certPath, err)
	}

	trustStore := pki.NewSystemTrustStore()
	if err := trustStore.InstallCA(certPEM, "fabric-ca"); err != nil {
		return fmt.Errorf("failed to install CA into system trust store (try running with sudo): %w", err)
	}
	fmt.Println("[+] Successfully installed Fabric Root CA into system trust store.")
	return nil
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
