package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	initACMEFlag     bool

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
	Example: `  # Initialize Server interactively
  fabric init --role=server

  # Join local machine as a Thread
  fabric init --role=thread --server=wss://192.168.1.50:8443/ws

  # Initialize non-interactively with auto-generated token
  fabric init -y --role=server --auto-token

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
	initCmd.Flags().BoolVar(&initACMEFlag, "acme", false, "Enable automatic Let's Encrypt / ACME TLS certification (opens port 80/tcp)")
	initCmd.Flags().BoolVar(&initTrustCA, "trust-ca", false, "Install Fabric Root CA into system trust store")
	initCmd.Flags().BoolVar(&initUntrustCA, "untrust-ca", false, "Remove Fabric Root CA from system trust store")

	_ = initCmd.Flags().MarkHidden("host")
}

func validateAndParseRole(input string) (string, error) {
	val := strings.ToLower(strings.TrimSpace(input))
	switch val {
	case "2", "server":
		return "server", nil
	case "3", "both":
		return "both", nil
	case "agent":
		WarnDeprecated("--role=agent", "--role=thread")
		return "thread", nil
	case "cli", "client":
		return "cli", nil
	case "1", "thread":
		return "thread", nil
	default:
		return "", fmt.Errorf("invalid role %q: must be 'thread', 'server', 'both', or 'cli'", input)
	}
}

func parseRoleChoice(input string) string {
	role, err := validateAndParseRole(input)
	if err != nil {
		return "thread"
	}
	return role
}

func runInit(cmd *cobra.Command, args []string) error {
	defer func() {
		initRoleFlag = ""
		initModeFlag = ""
		initRemoteFlag = false
		initServerFlag = ""
		initHostFlag = ""
		initTokenFlag = ""
		initDomainFlag = "fabric.mesh"
		initAutoToken = false
		initNonInteract = false
		initOpenFirewall = false
		initACMEFlag = false
		initTrustCA = false
		initUntrustCA = false
	}()

	// 1. Early flag validation before privilege check
	if initRoleFlag != "" {
		if _, err := validateAndParseRole(initRoleFlag); err != nil {
			return err
		}
	}
	if initModeFlag != "" {
		m := strings.ToLower(strings.TrimSpace(initModeFlag))
		if m != "local" && m != "remote" && m != "inverted" {
			return fmt.Errorf("invalid mode %q: must be 'local' or 'remote'", initModeFlag)
		}
	}

	// CLI configuration role does not require root privileges
	isCLIRole := strings.ToLower(strings.TrimSpace(initRoleFlag)) == "cli" || strings.ToLower(strings.TrimSpace(initRoleFlag)) == "client"

	// Enforce administrative privileges for fabric init
	if !isCLIRole && os.Geteuid() != 0 && os.Getenv("FABRIC_INIT_ALLOW_NON_ROOT") != "1" {
		if sudoPath, err := exec.LookPath("sudo"); err == nil {
			sudoCmd := exec.Command(sudoPath, os.Args...)
			sudoCmd.Stdin = os.Stdin
			sudoCmd.Stdout = os.Stdout
			sudoCmd.Stderr = os.Stderr
			return sudoCmd.Run()
		}
		return fmt.Errorf("'fabric init' requires root privileges (please run with 'sudo fabric init')")
	}

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
		} else if role == "server" || role == "both" {
			serverURL = prompt(reader, "Fabric Server listen URL", defaultSrv)
		} else {
			// Thread only role: Require active Server URL
			fmt.Println("\n--------------------------------------------------")
			fmt.Println("  Joining as a Thread requires an active Fabric Server.")
			fmt.Println("  If this machine should host the Server instead, re-run")
			fmt.Println("  'sudo fabric init' and select option [2] Server or [3] Both.")
			fmt.Println("--------------------------------------------------")
			for {
				serverURL = prompt(reader, "Fabric Server WebSocket URL (e.g. wss://192.168.1.50:8443/ws)", "")
				if serverURL != "" {
					break
				}
				fmt.Println("[!] Server URL is required to join the mesh. Please enter the WebSocket URL of your Fabric Server.")
			}
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
			// Thread only role: Require Server Cluster Token
			fmt.Println("\nEnter the pre-shared Cluster Token from your Fabric Server:")
			for {
				token = prompt(reader, "Cluster Token", "")
				if token != "" {
					break
				}
				fmt.Println("[!] Cluster Token is required to authenticate with the Fabric Server.")
			}
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

	// 6. CA Initialization and Trust Setup
	caPath := ""
	if role == "server" || role == "both" {
		_, path, err := pki.BootstrapCA("", domain)
		if err != nil {
			return fmt.Errorf("failed to bootstrap Certificate Authority: %w", err)
		}
		caPath = path
		if _, err := os.Stat("/etc/fabric/ca.crt"); err == nil {
			caPath = "/etc/fabric/ca.crt"
		}
	}

	if !initNonInteract {
		trustChoice := prompt(reader, "Trust private Fabric Root CA in system trust store? (y/N)", "N")
		if strings.ToLower(trustChoice) == "y" || strings.ToLower(trustChoice) == "yes" {
			if err := installLocalCATrust(); err != nil {
				fmt.Printf("[!] Warning: %v\n", err)
			}
		}
	}

	// 7. Save CLI Config
	if caPath == "" {
		if _, err := os.Stat("/etc/fabric/ca.crt"); err == nil {
			caPath = "/etc/fabric/ca.crt"
		} else if path, _, err := pki.FindCACert(""); err == nil {
			caPath = path
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
	svcMgr := GetServiceManager()
	if role == "server" || role == "both" {
		if err := writeRoleEnv("server", serverURL, token, domain, "local"); err == nil {
			fmt.Println("[+] Configured server environment (~/.fabric/server.env)")
		}
		if err := svcMgr.Install("server", nil); err == nil {
			startedServices = append(startedServices, "fabric-server")
		}
	}

	if role == "thread" || role == "both" {
		if err := writeRoleEnv("thread", serverURL, token, domain, mode); err == nil {
			fmt.Println("[+] Configured thread environment (~/.fabric/thread.env)")
		}
		if err := svcMgr.Install("thread", nil); err == nil {
			startedServices = append(startedServices, "fabric-thread")
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
	case "cli":
		return "CLI (Operator)"
	default:
		return fmt.Sprintf("Thread (%s mode)", mode)
	}
}

func writeRoleEnv(role, serverURL, token, domain, mode string) error {
	var targetDirs []string
	home, err := os.UserHomeDir()
	if err == nil {
		targetDirs = append(targetDirs, filepath.Join(home, ".fabric"))
		targetDirs = append(targetDirs, filepath.Join(home, ".config", "fabric"))
	}

	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		sudoHome := os.Getenv("SUDO_HOME")
		if sudoHome == "" {
			sudoHome = filepath.Join("/home", sudoUser)
		}
		targetDirs = append(targetDirs, filepath.Join(sudoHome, ".fabric"))
		targetDirs = append(targetDirs, filepath.Join(sudoHome, ".config", "fabric"))
	}

	if os.Geteuid() == 0 {
		targetDirs = append(targetDirs, "/etc/fabric")
	}

	caDir := "/etc/fabric/ca"
	if os.Geteuid() != 0 && home != "" {
		caDir = filepath.Join(home, ".fabric", "ca")
	}

	var sb strings.Builder
	if role == "server" {
		sb.WriteString(fmt.Sprintf("FABRIC_TOKEN=%s\n", token))
		sb.WriteString(fmt.Sprintf("FABRIC_DOMAIN=%s\n", domain))
		sb.WriteString("FABRIC_PORT=8443\n")
		sb.WriteString(fmt.Sprintf("FABRIC_CA_DIR=%s\n", caDir))
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
	for _, dir := range targetDirs {
		_ = os.MkdirAll(dir, 0755)
		_ = os.WriteFile(filepath.Join(dir, role+".env"), content, 0644)
		if role == "thread" {
			_ = os.WriteFile(filepath.Join(dir, "agent.env"), content, 0644)
		}

		if sudoUIDStr := os.Getenv("SUDO_UID"); sudoUIDStr != "" {
			if uid, err := strconv.Atoi(sudoUIDStr); err == nil {
				gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
				_ = os.Chown(dir, uid, gid)
				_ = os.Chown(filepath.Join(dir, role+".env"), uid, gid)
				if role == "thread" {
					_ = os.Chown(filepath.Join(dir, "agent.env"), uid, gid)
				}
			}
		}
	}
	return nil
}

func installLocalCATrust() error {
	foundPath, certPEM, err := pki.FindCACert("")
	if err != nil {
		return err
	}

	trustStore := pki.NewSystemTrustStore()
	if err := trustStore.InstallCA(certPEM, "fabric-ca"); err != nil {
		return fmt.Errorf("failed to install CA from %s into system trust store (try running with sudo): %w", foundPath, err)
	}
	fmt.Printf("[+] Successfully installed Fabric Root CA (%s) into system trust store.\n", foundPath)
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

type initPortSpec struct {
	port    int
	proto   string
	comment string
	purpose string
}

func applyInitOpenPort(fwMgr *firewall.Manager, backend firewall.Backend, p initPortSpec) {
	err := fwMgr.OpenPortWithBackend(backend, p.port, p.proto, p.comment)
	if err == nil {
		fmt.Printf("[+] Configured %s firewall rule (opened %d/%s for %s)\n", backend, p.port, p.proto, p.purpose)
	} else {
		fmt.Printf("[!] Warning: Could not automatically configure %s firewall: %v\n", backend, err)
		manual := fwMgr.GetOpenPortManualInstructions(backend, p.port, p.proto, p.comment)
		if manual != "" {
			fmt.Printf("    Manual firewall command: %s\n", manual)
		}
	}
}

func configureInitFirewall(reader *bufio.Reader, role, mode string, nonInteract, autoOpen bool) {
	if role == "thread" && (mode == "local" || mode == "") {
		fmt.Println("[+] Operating in local mode: outbound-only connectivity (zero inbound ports required).")
		return
	}

	fwMgr := getFirewallManager()
	backend := fwMgr.DetectBackend()
	if backend == firewall.BackendNone {
		fmt.Println("[*] No active Linux firewall detected (ufw/firewalld/nftables/iptables); skipping firewall rule configuration.")
		return
	}

	var ports []initPortSpec
	if role == "server" || role == "both" {
		purpose := "Server"
		if role == "both" {
			purpose = "Server + Thread"
		}
		ports = append(ports, initPortSpec{
			port:    8443,
			proto:   "tcp",
			comment: "Fabric Server Control Plane",
			purpose: purpose,
		})
		ports = append(ports, initPortSpec{
			port:    51820,
			proto:   "udp",
			comment: "Fabric WireGuard Gateway",
			purpose: "WireGuard Gateway",
		})
		if initACMEFlag {
			ports = append(ports, initPortSpec{
				port:    80,
				proto:   "tcp",
				comment: "Fabric ACME HTTP Challenge",
				purpose: "ACME HTTP Challenge",
			})
		}
	} else if role == "thread" && mode == "remote" {
		ports = append(ports, initPortSpec{
			port:    8443,
			proto:   "tcp",
			comment: "Fabric Remote Thread Listener",
			purpose: "Remote Thread",
		})
	}

	for _, p := range ports {
		if autoOpen || nonInteract {
			applyInitOpenPort(fwMgr, backend, p)
			continue
		}

		promptMsg := fmt.Sprintf("Open port %d/%s in %s for %s? (Y/n)", p.port, p.proto, backend, p.purpose)
		choice := prompt(reader, promptMsg, "Y")
		if strings.ToLower(choice) == "y" || strings.ToLower(choice) == "yes" || choice == "" {
			applyInitOpenPort(fwMgr, backend, p)
		} else {
			fmt.Printf("[*] Skipped firewall configuration for port %d/%s.\n", p.port, p.proto)
			manual := fwMgr.GetOpenPortManualInstructions(backend, p.port, p.proto, p.comment)
			if manual != "" {
				fmt.Printf("    To open manually: %s\n", manual)
			}
		}
	}
}


