package provision

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"fabric/internal/protocol"
)

// StitchHostOptions defines parameters for provisioning a remote machine into the mesh.
type StitchHostOptions struct {
	Target       string
	SSHPort      string
	IdentityKey  string
	SocketURL    string
	Token        string
	Domain       string
	NoWait       bool
	SilentOutput bool
}

// RemoteExecutor defines an interface for executing a bootstrap script on a remote host.
type RemoteExecutor interface {
	Run(script string) error
}

// SSHExecutor implements RemoteExecutor using the local OpenSSH client.
type SSHExecutor struct {
	Target      string
	Port        string
	IdentityKey string
	Silent      bool
}

func (e *SSHExecutor) Run(script string) error {
	var sshArgs []string
	if e.Port != "" && e.Port != "22" {
		sshArgs = append(sshArgs, "-p", e.Port)
	}
	if e.IdentityKey != "" {
		sshArgs = append(sshArgs, "-i", e.IdentityKey)
	}
	sshArgs = append(sshArgs, "-o", "StrictHostKeyChecking=accept-new", e.Target, "bash -s")

	sshCmd := exec.Command("ssh", sshArgs...)
	sshCmd.Stdin = strings.NewReader(script)
	if !e.Silent {
		sshCmd.Stdout = os.Stdout
		sshCmd.Stderr = os.Stderr
	}

	return sshCmd.Run()
}

// GenerateStitchScript generates the bash script to bootstrap a node.
func GenerateStitchScript(opts StitchHostOptions, socketURL string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -e

echo "[+] Initializing Fabric node setup on remote host..."

SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
fi

$SUDO mkdir -p /etc/fabric /usr/local/bin

cat << ENVEOF | $SUDO tee /etc/fabric/node.env > /dev/null
FABRIC_SOCKET_URL=%s
FABRIC_TOKEN=%s
FABRIC_DOMAIN=%s
ENVEOF

$SUDO chmod 600 /etc/fabric/node.env

if command -v fabric >/dev/null 2>&1; then
    echo "[+] Fabric CLI found on target."
    $SUDO fabric service install node || true
elif [ -f /usr/local/bin/fabric ]; then
    $SUDO /usr/local/bin/fabric service install node || true
else
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
`, socketURL, opts.Token, opts.Domain)
}

// NodeVerifierFunc is a callback that queries the Socket for connected nodes.
type NodeVerifierFunc func(socketURL, token string) ([]protocol.NodeMetadata, error)

// ExecuteStitchHost performs the full bootstrap and mesh join verification workflow.
func ExecuteStitchHost(opts StitchHostOptions, exec RemoteExecutor, verifier NodeVerifierFunc) (*protocol.NodeMetadata, error) {
	socketURL := opts.SocketURL
	u, err := url.Parse(socketURL)
	if err == nil {
		host, port, err := net.SplitHostPort(u.Host)
		if err == nil && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
			outboundIP := GetOutboundIP()
			u.Host = net.JoinHostPort(outboundIP, port)
			socketURL = u.String()
			if !opts.SilentOutput {
				fmt.Printf("[+] Detected local loopback socket. Resolving remote socket URL to: %s\n", socketURL)
			}
		}
	}

	if !opts.SilentOutput {
		fmt.Printf("[+] Stitching target '%s' (port %s) into Fabric mesh...\n", opts.Target, opts.SSHPort)
		fmt.Printf("[+] Target Socket URL: %s\n", socketURL)
	}

	bootstrapScript := GenerateStitchScript(opts, socketURL)

	if exec == nil {
		exec = &SSHExecutor{
			Target:      opts.Target,
			Port:        opts.SSHPort,
			IdentityKey: opts.IdentityKey,
			Silent:      opts.SilentOutput,
		}
	}

	if err := exec.Run(bootstrapScript); err != nil {
		return nil, fmt.Errorf("remote SSH bootstrap failed: %w", err)
	}

	if !opts.SilentOutput {
		fmt.Println("[+] Remote bootstrap executed successfully.")
	}

	if opts.NoWait || verifier == nil {
		return nil, nil
	}

	if !opts.SilentOutput {
		fmt.Print("[+] Waiting for node to establish WebSocket connection to Socket...")
	}

	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	targetHostOnly := opts.Target
	if atIdx := strings.LastIndex(opts.Target, "@"); atIdx != -1 {
		targetHostOnly = opts.Target[atIdx+1:]
	}

	for {
		select {
		case <-timeout:
			if !opts.SilentOutput {
				fmt.Println(" (timeout)")
				fmt.Println("[!] Warning: Node did not show up in the mesh within 15 seconds.")
				fmt.Println("    Check target logs via SSH: ssh " + opts.Target + " journalctl -u fabric-node -n 20")
			}
			return nil, fmt.Errorf("node connection verification timed out after 15s")
		case <-ticker.C:
			if !opts.SilentOutput {
				fmt.Print(".")
			}
			nodes, err := verifier(socketURL, opts.Token)
			if err != nil {
				continue
			}

			for _, n := range nodes {
				if n.Hostname == targetHostOnly || strings.HasPrefix(n.RemoteIP, targetHostOnly) || targetHostOnly == "localhost" || targetHostOnly == "127.0.0.1" {
					if !opts.SilentOutput {
						fmt.Println(" Connected!")
					}
					return &n, nil
				}
			}
		}
	}
}

// GetOutboundIP determines preferred local outbound IPv4 address.
func GetOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
