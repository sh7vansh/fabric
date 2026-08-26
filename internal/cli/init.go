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

	"fabric/internal/firewall"
	"fabric/internal/pki"

	"github.com/spf13/cobra"
)

var (
	initRoleFlag     string
	initModeFlag     string
	initRemoteFlag   bool
	initServerFlag   string
	initHostFlag     string
	initTokenFlag    string
	initDomainFlag   string
	initAutoToken    bool
	initNonInteract  bool
	initOpenFirewall bool
	initTrustCA      bool
	initUntrustCA    bool

	defaultFirewallManager *firewall.Manager
)

func getFirewallManager() *firewall.Manager {
	if defaultFirewallManager != nil {
		return defaultFirewallManager
	}
	return firewall.NewManager()
}

func SetDefaultFirewallManager(mgr *firewall.Manager) {
	defaultFirewallManager = mgr
}

var initCmd = &cobra.Command{
	Use:     "init [flags]",
	Short:   "Initialize Fabric functionality (Thread, Server, or Both)",
	GroupID: "system",
	Long: `Interactive onboarding wizard to configure the local operator workspace (~/.fabric/config.json),
participation role (thread, server, or both), operating mode (local or remote), cluster tokens, and Root CA trust.`,
	Example: `  # Launch interactive setup wizard
  fabric init

  # Set up as a dedicated Fabric Server
  fabric init --role server

  # Set up as a managed Thread
  fabric init --role thread --server wss://gateway:8443/ws --token secret-token

  # Set up as a Thread in remote mode
  fabric init --role thread --mode remote --token secret-token

  # Non-interactive setup for scripts
  fabric init -y --server wss://gateway:8443/ws --token secret-token

  # Non-interactive setup with automatic firewall port configuration
  fabric init --role server --open-firewall -y

  # Install local Fabric Root CA into the OS trust store
  fabric init --trust-ca

  # Remove local Fabric Root CA from the OS trust store
  fabric init --untrust-ca`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().StringVar(&initRoleFlag, "role", "", "Machine participation role: 'thread' (default), 'server', 'both', or 'cli'")
	initCmd.Flags().StringVar(&initModeFlag, "mode", "local", "Operating mode: 'local' (default) or 'remote'")
	initCmd.Flags().BoolVar(&initRemoteFlag, "remote", false, "Set operating mode to remote (shorthand for --mode=remote)")
	initCmd.Flags().StringVarP(&initServerFlag, "server", "s", "", "Fabric server WebSocket URL (e.g. wss://192.168.1.50:8443/ws)")
	initCmd.Flags().StringVarP(&initHostFlag, "host", "H", "", "Server URL (deprecated, use --server)")
	initCmd.Flags().StringVar(&initTokenFlag, "token", "", "Pre-shared cluster token")
	initCmd.Flags().StringVar(&initDomainFlag, "domain", "fabric.mesh", "Domain for Fabric DNS")
	initCmd.Flags().BoolVar(&initAutoToken, "auto-token", false, "Auto-generate a secure random token")
	initCmd.Flags().BoolVarP(&initNonInteract, "yes", "y", false, "Accept all defaults non-interactively")
	initCmd.Flags().BoolVar(&initOpenFirewall, "open-firewall", false, "Automatically configure local firewall rules")
	initCmd.Flags().BoolVar(&initTrustCA, "trust-ca", false, "Install Fabric Root CA into system trust store")
	initCmd.Flags().BoolVar(&initUntrustCA, "untrust-ca", false, "Remove Fabric Root CA from system trust store")
}

func parseRoleChoice(input string) string {
	val := strings.ToLower(strings.TrimSpace(input))
	switch val {
	case "2", "server":
		return "server"
	case "3", "both":
		return "both"
	case "agent":
		WarnDeprecated("--role=agent", "--role=thread")
		return "thread"
	case "cli", "client":
		return "cli"
	case "1", "thread":
		return "thread"
	default:
		return "thread"
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
	role := "thread"
	if initRoleFlag != "" {
		if strings.ToLower(strings.TrimSpace(initRoleFlag)) == "agent" {
			WarnDeprecated("--role=agent", "--role=thread")
		}
		role = parseRoleChoice(initRoleFlag)
	} else if !initNonInteract {
		fmt.Println("How will this machine participate in the Fabric?")
		fmt.Println("  [1] Thread       (Join machine as a Thread — default)")
		fmt.Println("  [2] Server       (Run Fabric Server & control-plane daemon)")
		fmt.Println("  [3] Both         (Run Fabric Server + local Thread)")
		roleChoice := prompt(reader, "Choice", "1")
		role = parseRoleChoice(roleChoice)
	}

	// 2. Operating Mode Selection
	mode := "local"
	if initRemoteFlag {
		mode = "remote"
	} else if initModeFlag != "" && initModeFlag != "local" {
		m := strings.ToLower(strings.TrimSpace(initModeFlag))
		if m == "remote" || m == "inverted" {
			mode = "remote"
		} else {
			mode = "local"
		}
	} else if !initNonInteract && (role == "thread" || role == "both") {
		fmt.Println("\nSelect Thread Operating Mode:")
		fmt.Println("  [1] local  (Default: Standard local environment execution)")
		fmt.Println("  [2] remote (Alternate: Remote/direct execution behavior)")
		modeChoice := prompt(reader, "Choice", "1")
		if modeChoice == "2" || strings.ToLower(modeChoice) == "remote" {
			mode = "remote"
		}
	}

	// 3. Server URL
	serverURL := initServerFlag
	if serverURL == "" {
		serverURL = initHostFlag
	}
	if serverURL == "" {
		defaultSrv := "wss://localhost:8443/ws"
		if initNonInteract {
			serverURL = defaultSrv
		} else if role == "server" {
			serverURL = prompt(reader, "Fabric Server listen URL", defaultSrv)
		} else {
			serverURL = prompt(reader, "Fabric Server WebSocket URL (e.g. wss://192.168.1.50:8443/ws)", defaultSrv)
		}
	}

	// 4. Cluster Token
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
			token = prompt(reader, "Cluster Token", "default-secret")
		}
	}

	// 5. Fabric DNS Domain
	domain := initDomainFlag
	if domain == "" {
		domain = "fabric.mesh"
	}
	if !initNonInteract && initDomainFlag == "fabric.mesh" {
		domain = prompt(reader, "Fabric Domain", "fabric.mesh")
	}

	// 6. CA Trust Setup
	if !initNonInteract && role != "server" {
		trustChoice := prompt(reader, "Trust private Fabric Root CA in system trust store? (y/N)", "N")
		if strings.ToLower(trustChoice) == "y" || strings.ToLower(trustChoice) == "yes" {
			_ = installLocalCATrust()
		}
	}

	// 7. Save CLI Config
	caPath := ""
	if home, err := os.UserHomeDir(); err == nil {
		for _, p := range []string{
			filepath.Join(home, ".fabric", "ca", "ca.crt"),
			filepath.Join(home, ".fabric", "ca.crt"),
			"/etc/fabric/ca.crt",
		} {
			if _, err := os.Stat(p); err == nil {
				caPath = p
				break
			}
		}
	}

	cliCfg := &Config{
		Host:   serverURL,
		Token:  token,
		CACert: caPath,
	}
	if err := SaveConfig(cliCfg); err != nil {
		fmt.Printf("[!] Warning: Could not save CLI config: %v\n", err)
	} else {
		fmt.Println("[+] CLI configuration saved to ~/.fabric/config.json")
	}

	// 8. Write Service Environment Files and Start Services
	var startedServices []string
	if role == "server" || role == "both" {
		if err := writeRoleEnv("server", serverURL, token, domain, "local"); err == nil {
			fmt.Println("[+] Configured server environment (~/.fabric/server.env)")
		}
		if !initNonInteract {
			if err := InstallService("server"); err == nil {
				startedServices = append(startedServices, "fabric-server")
			}
		}
	}

	if role == "thread" || role == "both" {
		if err := writeRoleEnv("thread", serverURL, token, domain, mode); err == nil {
			fmt.Println("[+] Configured thread environment (~/.fabric/thread.env)")
		}
		if !initNonInteract {
			if err := InstallService("thread"); err == nil {
				startedServices = append(startedServices, "fabric-thread")
			}
		}
	}

	// 9. Firewall Configuration
	configureInitFirewall(reader, role, mode, initNonInteract, initOpenFirewall)

	// 10. Completion Summary
	fmt.Println("\n==================================================")
	fmt.Println("         Fabric Initialization Complete!          ")
	fmt.Println("==================================================")
	fmt.Printf("Role:          %s\n", formatRoleDisplay(role, mode))
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

func formatRoleDisplay(role, mode string) string {
	switch role {
	case "server":
		return "Server (Control Plane)"
	case "thread":
		return fmt.Sprintf("Thread (%s mode)", mode)
	case "both":
		return fmt.Sprintf("Server + Thread (%s mode)", mode)
	default:
		return fmt.Sprintf("Thread (%s mode)", mode)
	}
}

func writeRoleEnv(role, serverURL, token, domain, mode string) error {
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
		sb.WriteString("FABRIC_PORT=8443\n")
	} else if role == "thread" || role == "agent" {
		sb.WriteString(fmt.Sprintf("FABRIC_SERVER_URL=%s\n", serverURL))
		if mode == "" {
			mode = "local"
		}
		sb.WriteString(fmt.Sprintf("FABRIC_MODE=%s\n", mode))
		if mode == "remote" {
			sb.WriteString("FABRIC_LISTEN=:8443\n")
		}
		sb.WriteString(fmt.Sprintf("FABRIC_TOKEN=%s\n", token))
		sb.WriteString(fmt.Sprintf("FABRIC_DOMAIN=%s\n", domain))
	}

	content := []byte(sb.String())
	_ = os.WriteFile(filepath.Join(fabricDir, role+".env"), content, 0600)
	_ = os.WriteFile(filepath.Join(configDir, role+".env"), content, 0600)

	// Write agent.env fallback if writing thread.env
	if role == "thread" {
		_ = os.WriteFile(filepath.Join(fabricDir, "agent.env"), content, 0600)
		_ = os.WriteFile(filepath.Join(configDir, "agent.env"), content, 0600)
	}
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

func configureInitFirewall(reader *bufio.Reader, role, mode string, nonInteract, autoOpen bool) {
	if role == "thread" && (mode == "local" || mode == "") {
		fmt.Println("[+] Operating in local mode: outbound-only connectivity (zero inbound ports required).")
		return
	}

	fwMgr := getFirewallManager()
	backend := fwMgr.DetectBackend()
	if backend == firewall.BackendNone {
		return
	}

	port := 8443
	comment := "Fabric Server Control Plane"
	purpose := "Server"
	if role == "thread" && mode == "remote" {
		comment = "Fabric Remote Thread Listener"
		purpose = "Remote Thread"
	} else if role == "both" {
		purpose = "Server + Thread"
	}

	if autoOpen || nonInteract {
		err := fwMgr.OpenPortWithBackend(backend, port, "tcp", comment)
		if err == nil {
			fmt.Printf("[+] Configured %s firewall rule (opened %d/tcp for %s)\n", backend, port, purpose)
		} else {
			fmt.Printf("[!] Warning: Could not automatically configure %s firewall: %v\n", backend, err)
			manual := fwMgr.GetOpenPortManualInstructions(backend, port, "tcp", comment)
			if manual != "" {
				fmt.Printf("    Manual firewall command: %s\n", manual)
			}
		}
		return
	}

	promptMsg := fmt.Sprintf("Open port %d/tcp in %s? (Y/n)", port, backend)
	choice := prompt(reader, promptMsg, "Y")
	if strings.ToLower(choice) == "y" || strings.ToLower(choice) == "yes" || choice == "" {
		err := fwMgr.OpenPortWithBackend(backend, port, "tcp", comment)
		if err == nil {
			fmt.Printf("[+] Configured %s firewall rule (opened %d/tcp for %s)\n", backend, port, purpose)
		} else {
			fmt.Printf("[!] Warning: Could not configure %s firewall: %v\n", backend, err)
			manual := fwMgr.GetOpenPortManualInstructions(backend, port, "tcp", comment)
			if manual != "" {
				fmt.Printf("    Manual firewall command: %s\n", manual)
			}
		}
	} else {
		fmt.Println("[*] Skipped firewall configuration.")
		manual := fwMgr.GetOpenPortManualInstructions(backend, port, "tcp", comment)
		if manual != "" {
			fmt.Printf("    To open manually: %s\n", manual)
		}
	}
}

