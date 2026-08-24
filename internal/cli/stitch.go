package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"fabric/internal/protocol"

	"github.com/spf13/cobra"
)

var (
	stitchIdentityFlag string
	stitchPortFlag     string
	stitchSocketURL    string
	stitchTokenFlag    string
	stitchDomainFlag   string
	stitchNoWait       bool
)

var stitchCmd = &cobra.Command{
	Use:   "stitch [flags] [user@]hostname[:port]",
	Short: "Bootstrap and stitch a remote host into the Fabric mesh over SSH",
	Args:  cobra.ExactArgs(1),
	RunE:  runStitch,
}

func init() {
	rootCmd.AddCommand(stitchCmd)
	stitchCmd.Flags().StringVarP(&stitchIdentityFlag, "identity", "i", "", "SSH identity key file")
	stitchCmd.Flags().StringVarP(&stitchPortFlag, "port", "p", "22", "SSH port on target host")
	stitchCmd.Flags().StringVar(&stitchSocketURL, "socket-url", "", "Socket URL override (e.g. ws://192.168.1.50:8080/ws)")
	stitchCmd.Flags().StringVar(&stitchTokenFlag, "token", "", "Cluster token override")
	stitchCmd.Flags().StringVar(&stitchDomainFlag, "domain", "fabric.mesh", "Domain to register on the mesh")
	stitchCmd.Flags().BoolVar(&stitchNoWait, "no-wait", false, "Do not wait for mesh connection verification")
}

func runStitch(cmd *cobra.Command, args []string) error {
	rawTarget := args[0]
	cfg := GetConfig()

	// Parse optional :port suffix from target (e.g. user@host:2222)
	sshPort := stitchPortFlag
	target := rawTarget
	if colonIdx := strings.LastIndex(rawTarget, ":"); colonIdx != -1 {
		// Ensure it's not an IPv6 address without user
		portCandidate := rawTarget[colonIdx+1:]
		if !strings.Contains(portCandidate, "]") {
			target = rawTarget[:colonIdx]
			sshPort = portCandidate
		}
	}

	socketURL := stitchSocketURL
	if socketURL == "" {
		socketURL = cfg.Host
	}

	// If socket URL is localhost or loopback, auto-detect outbound network IP
	u, err := url.Parse(socketURL)
	if err == nil {
		host, port, err := net.SplitHostPort(u.Host)
		if err == nil && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
			outboundIP := getOutboundIP()
			u.Host = net.JoinHostPort(outboundIP, port)
			socketURL = u.String()
			fmt.Printf("[+] Detected local loopback socket. Resolving remote socket URL to: %s\n", socketURL)
		}
	}

	token := stitchTokenFlag
	if token == "" {
		token = cfg.Token
	}

	fmt.Printf("[+] Stitching target '%s' (port %s) into Fabric mesh...\n", target, sshPort)
	fmt.Printf("[+] Target Socket URL: %s\n", socketURL)

	// Build remote bootstrap script
	bootstrapScript := fmt.Sprintf(`#!/usr/bin/env bash
set -e

echo "[+] Initializing Fabric node setup on remote host..."

SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
fi

$SUDO mkdir -p /etc/fabric /usr/local/bin

# Write node environment configuration
cat << 'EOF' | $SUDO tee /etc/fabric/node.env > /dev/null
FABRIC_SOCKET_URL=%s
FABRIC_TOKEN=%s
FABRIC_DOMAIN=%s
EOF

$SUDO chmod 600 /etc/fabric/node.env

# If fabric binary exists, install service directly
if command -v fabric >/dev/null 2>&1; then
    echo "[+] Fabric CLI found on target."
    $SUDO fabric service install node || true
elif [ -f /usr/local/bin/fabric ]; then
    $SUDO /usr/local/bin/fabric service install node || true
else
    # Install using install.sh if available or download
    echo "[+] Installing Fabric binaries on remote..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL https://get.fabric.mesh/install.sh 2>/dev/null | FABRIC_NO_SETUP=1 bash || true
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl daemon-reload || true
    $SUDO systemctl restart fabric-node || true
    $SUDO systemctl enable fabric-node || true
    echo "[+] fabric-node systemd service enabled and started."
fi
`, socketURL, token, stitchDomainFlag)

	// Build ssh command
	var sshArgs []string
	if sshPort != "" && sshPort != "22" {
		sshArgs = append(sshArgs, "-p", sshPort)
	}
	if stitchIdentityFlag != "" {
		sshArgs = append(sshArgs, "-i", stitchIdentityFlag)
	}
	sshArgs = append(sshArgs, "-o", "StrictHostKeyChecking=accept-new", target, "bash -s")

	sshCmd := exec.Command("ssh", sshArgs...)
	sshCmd.Stdin = strings.NewReader(bootstrapScript)
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr

	if err := sshCmd.Run(); err != nil {
		return fmt.Errorf("remote SSH bootstrap failed: %w", err)
	}

	fmt.Println("[+] Remote bootstrap executed successfully.")

	if stitchNoWait {
		return nil
	}

	// Verification loop: Poll Socket /nodes endpoint for newly joined node
	fmt.Print("[+] Waiting for node to establish WebSocket connection to Socket...")
	client := NewClient(cfg)

	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Extract target host without user prefix for matching
	targetHostOnly := target
	if atIdx := strings.LastIndex(target, "@"); atIdx != -1 {
		targetHostOnly = target[atIdx+1:]
	}

	for {
		select {
		case <-timeout:
			fmt.Println(" (timeout)")
			fmt.Println("[!] Warning: Node did not show up in the mesh within 15 seconds.")
			fmt.Println("    Check target logs via SSH: ssh " + target + " journalctl -u fabric-node -n 20")
			return nil
		case <-ticker.C:
			fmt.Print(".")
			resp, err := client.DoHTTP("GET", "/nodes", nil)
			if err != nil {
				continue
			}

			var nodes []protocol.NodeMetadata
			if err := json.NewDecoder(resp.Body).Decode(&nodes); err == nil {
				resp.Body.Close()
				for _, n := range nodes {
					if n.Hostname == targetHostOnly || strings.HasPrefix(n.RemoteIP, targetHostOnly) || targetHostOnly == "localhost" || targetHostOnly == "127.0.0.1" {
						fmt.Println(" Connected!")
						fmt.Println("\n==================================================")
						fmt.Println("         Node Stitched Successfully!              ")
						fmt.Println("==================================================")
						fmt.Printf("Hostname:  %s\n", n.Hostname)
						fmt.Printf("Remote IP: %s\n", n.RemoteIP)
						fmt.Printf("OS/Arch:   %s/%s\n", n.OS, n.Arch)
						fmt.Printf("Status:    %s\n", n.Status)
						fmt.Println("\nTest remote execution with:")
						fmt.Printf("  fabric exec %s uname -a\n", n.Hostname)
						fmt.Println("==================================================")
						return nil
					}
				}
			} else {
				resp.Body.Close()
			}
		}
	}
}
