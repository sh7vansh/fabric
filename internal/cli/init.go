package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fabric/internal/pki"

	"github.com/spf13/cobra"
)

var (
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
Fabric server WebSocket URL, cluster tokens, and Root CA trust.`,
	Example: `  # Launch interactive setup wizard
  fabric init

  # Non-interactive CLI setup for scripts
  fabric init -y --server ws://gateway:8080/ws --token secret-token

  # Install local Fabric Root CA into the OS trust store
  fabric init --trust-ca

  # Remove local Fabric Root CA from the OS trust store
  fabric init --untrust-ca`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().StringVarP(&initServerFlag, "server", "s", "", "Fabric server WebSocket URL (e.g. ws://192.168.1.50:8080/ws)")
	initCmd.Flags().StringVarP(&initHostFlag, "host", "H", "", "Server URL (deprecated, use --server)")
	initCmd.Flags().StringVar(&initTokenFlag, "token", "", "Pre-shared cluster token")
	initCmd.Flags().StringVar(&initDomainFlag, "domain", "fabric.mesh", "Domain for Fabric DNS")
	initCmd.Flags().BoolVar(&initAutoToken, "auto-token", false, "Auto-generate a secure random token")
	initCmd.Flags().BoolVarP(&initNonInteract, "yes", "y", false, "Accept all defaults non-interactively")
	initCmd.Flags().BoolVar(&initTrustCA, "trust-ca", false, "Install Fabric Root CA into system trust store")
	initCmd.Flags().BoolVar(&initUntrustCA, "untrust-ca", false, "Remove Fabric Root CA from system trust store")
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

	serverURL := initServerFlag
	if serverURL == "" {
		serverURL = initHostFlag
	}
	if serverURL == "" {
		if initNonInteract {
			serverURL = "ws://localhost:8080/ws"
		} else {
			serverURL = prompt(reader, "Fabric Server WebSocket URL (e.g. ws://192.168.1.50:8080/ws)", "ws://localhost:8080/ws")
		}
	}

	token := initTokenFlag
	if token == "" {
		if initAutoToken {
			token = generateSecureToken()
		} else if initNonInteract {
			token = "default-secret"
		} else {
			auto := prompt(reader, "Auto-generate secure cluster token? (Y/n)", "Y")
			if strings.ToLower(auto) == "y" || strings.ToLower(auto) == "yes" {
				token = generateSecureToken()
			} else {
				token = prompt(reader, "Enter cluster token", "default-secret")
			}
		}
	}

	domain := initDomainFlag
	if !initNonInteract && domain == "fabric.mesh" {
		domain = prompt(reader, "Fabric Domain", "fabric.mesh")
	}

	// 1. Initialize local Root CA if present or requested
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

	// 2. Save CLI config
	cliCfg := &Config{
		Host:  serverURL,
		Token: token,
	}
	if err := SaveConfig(cliCfg); err != nil {
		fmt.Printf("[!] Warning: Could not save CLI config: %v\n", err)
	} else {
		fmt.Println("[+] CLI configuration saved to ~/.fabric/config.json")
	}

	fmt.Println("\n==================================================")
	fmt.Println("         Fabric Initialization Complete!          ")
	fmt.Println("==================================================")
	fmt.Printf("Server URL:    %s\n", serverURL)
	fmt.Printf("Cluster Token: %s\n", token)
	fmt.Printf("Domain:        %s\n", domain)
	fmt.Println("\nTo stitch a remote machine via SSH, run:")
	fmt.Printf("  fabric stitch user@<remote-ip>\n\n")
	fmt.Println("To inspect threads:")
	fmt.Println("  fabric ps")
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

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
