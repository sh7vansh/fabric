package provision

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	Tags         []string
	BinaryPath   string
	BinaryData   []byte
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

// FindLocalBinary locates the fabric-node binary on the local machine.
func FindLocalBinary(preferredPath string) (string, error) {
	if preferredPath != "" {
		if _, err := os.Stat(preferredPath); err == nil {
			return preferredPath, nil
		}
		return "", fmt.Errorf("specified binary path not found: %s", preferredPath)
	}

	// 1. Check directory of current executable
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		candidate := filepath.Join(execDir, "fabric-node")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// 2. Check system PATH
	if p, err := exec.LookPath("fabric-node"); err == nil {
		return p, nil
	}

	// 3. Check common bin locations
	candidates := []string{
		"./bin/fabric-node",
		"bin/fabric-node",
		"/usr/local/bin/fabric-node",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf("fabric-node binary not found locally")
}

// PackageBinaryPayload compresses and base64-encodes binary data into an embedded payload string.
func PackageBinaryPayload(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// GenerateStitchScript generates the self-contained air-gapped bootstrap script for a remote host.
func GenerateStitchScript(opts StitchHostOptions, socketURL string) string {
	payload := ""
	if len(opts.BinaryData) > 0 {
		if p, err := PackageBinaryPayload(opts.BinaryData); err == nil {
			payload = p
		}
	} else {
		binPath, err := FindLocalBinary(opts.BinaryPath)
		if err == nil {
			if data, readErr := os.ReadFile(binPath); readErr == nil {
				if p, pkgErr := PackageBinaryPayload(data); pkgErr == nil {
					payload = p
				}
			}
		}
	}

	tagsJoined := strings.Join(opts.Tags, ",")

	return fmt.Sprintf(`#!/usr/bin/env bash
set -e

echo "[+] Initializing Fabric air-gapped zero-internet bootstrap..."

# 1. Privilege Level Detection
IS_ROOT=0
SUDO=""
if [ "$EUID" -eq 0 ]; then
    IS_ROOT=1
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    IS_ROOT=1
    SUDO="sudo"
fi

# 2. Systemd Capability Detection
HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=1
fi

# 3. Determine Installation Paths
if [ "$IS_ROOT" -eq 1 ]; then
    INSTALL_BIN_DIR="/usr/local/bin"
    CONFIG_DIR="/etc/fabric"
    RUN_DIR="/var/run/fabric"
    $SUDO mkdir -p "$INSTALL_BIN_DIR" "$CONFIG_DIR" "$RUN_DIR"
else
    INSTALL_BIN_DIR="$HOME/.local/bin"
    CONFIG_DIR="$HOME/.config/fabric"
    RUN_DIR="$HOME/.fabric"
    mkdir -p "$INSTALL_BIN_DIR" "$CONFIG_DIR" "$RUN_DIR"
fi

TARGET_BIN="$INSTALL_BIN_DIR/fabric-node"
ENV_FILE="$CONFIG_DIR/node.env"

# 4. Extract Injected Self-Contained Binary Payload
PAYLOAD="%s"
if [ -n "$PAYLOAD" ]; then
    echo "[+] Unpacking injected fabric-node binary to $TARGET_BIN..."
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        (echo "$PAYLOAD" | base64 -d | gzip -d | $SUDO tee "$TARGET_BIN" > /dev/null 2>&1) || (echo "$PAYLOAD" | base64 -d | gunzip | $SUDO tee "$TARGET_BIN" > /dev/null 2>&1)
        $SUDO chmod 755 "$TARGET_BIN"
    else
        (echo "$PAYLOAD" | base64 -d | gzip -d > "$TARGET_BIN" 2>/dev/null) || (echo "$PAYLOAD" | base64 -d | gunzip > "$TARGET_BIN" 2>/dev/null)
        chmod 755 "$TARGET_BIN"
    fi
fi

# Validate binary integrity and executable permissions
if [ ! -s "$TARGET_BIN" ] || [ ! -x "$TARGET_BIN" ]; then
    if command -v fabric-node >/dev/null 2>&1; then
        TARGET_BIN="$(command -v fabric-node)"
    elif [ -x "/usr/local/bin/fabric-node" ]; then
        TARGET_BIN="/usr/local/bin/fabric-node"
    else
        echo "[!] Binary validation failed: $TARGET_BIN not found or not executable" >&2
        exit 1
    fi
fi
echo "[+] Validated binary integrity: $TARGET_BIN"

# 5. Write Environment Configuration
ENV_CONTENT="FABRIC_SOCKET_URL=%s
FABRIC_TOKEN=%s
FABRIC_DOMAIN=%s
FABRIC_TAGS=%s"

if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
    echo "$ENV_CONTENT" | $SUDO tee "$ENV_FILE" > /dev/null
    $SUDO chmod 600 "$ENV_FILE"
else
    echo "$ENV_CONTENT" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
fi

# 6. Multi-Tier Init Selection & Service Activation
if [ "$IS_ROOT" -eq 1 ] && [ "$HAS_SYSTEMD" -eq 1 ]; then
    # Tier 1: Root / Sudo with systemd (System service)
    echo "[+] Configuring systemd system service (/etc/systemd/system/fabric-node.service)..."
    cat << 'UNIT_EOF' | $SUDO tee /etc/systemd/system/fabric-node.service > /dev/null
[Unit]
Description=Fabric Mesh Network Node
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/fabric/node.env
ExecStart=/usr/local/bin/fabric-node
Restart=always
RestartSec=3s
LimitNOFILE=65536
ExecStopPost=/usr/bin/resolvectl revert lo

[Install]
WantedBy=multi-user.target
UNIT_EOF

    $SUDO chmod 644 /etc/systemd/system/fabric-node.service
    $SUDO systemctl daemon-reload
    $SUDO systemctl restart fabric-node || true
    $SUDO systemctl enable fabric-node || true
    echo "[+] Systemd system service enabled and active."

elif [ "$IS_ROOT" -eq 0 ] && [ "$HAS_SYSTEMD" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
    # Tier 2: Non-root with systemd (User service)
    echo "[+] Configuring systemd user service (~/.config/systemd/user/fabric-node.service)..."
    mkdir -p "$HOME/.config/systemd/user"
    cat << UNIT_EOF > "$HOME/.config/systemd/user/fabric-node.service"
[Unit]
Description=Fabric Mesh Network Node (User)
After=network.target

[Service]
Type=simple
EnvironmentFile=-$HOME/.config/fabric/node.env
ExecStart=$TARGET_BIN
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=default.target
UNIT_EOF

    chmod 644 "$HOME/.config/systemd/user/fabric-node.service"
    loginctl enable-linger "$(whoami)" 2>/dev/null || true
    systemctl --user daemon-reload || true
    systemctl --user restart fabric-node || true
    systemctl --user enable fabric-node || true
    echo "[+] Systemd user service enabled and active."

else
    # Tier 3: Non-systemd / Edge / Container (Supervised background daemon)
    echo "[+] Configuring standalone supervisor daemon in $RUN_DIR..."
    PIDFILE="$RUN_DIR/fabric-node.pid"
    SUPERVISOR="$RUN_DIR/fabric-node-supervisor.sh"

    if [ -f "$PIDFILE" ]; then
        OLD_PID=$(cat "$PIDFILE" 2>/dev/null || true)
        if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
            kill "$OLD_PID" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$PIDFILE"
    fi

    cat << 'SUPERVISOR_EOF' > "$SUPERVISOR"
#!/usr/bin/env bash
PIDFILE="$1"
ENVFILE="$2"
BIN="$3"
if [ -f "$ENVFILE" ]; then
    set -a
    . "$ENVFILE"
    set +a
fi
while true; do
    "$BIN" &
    CHILD_PID=$!
    echo "$CHILD_PID" > "$PIDFILE"
    wait "$CHILD_PID"
    sleep 2
done
SUPERVISOR_EOF

    chmod 755 "$SUPERVISOR"
    nohup "$SUPERVISOR" "$PIDFILE" "$ENV_FILE" "$TARGET_BIN" > /dev/null 2>&1 &
    echo $! > "$RUN_DIR/fabric-node-supervisor.pid"
    echo "[+] Supervised background daemon started (PID file: $PIDFILE)."
fi
`, payload, socketURL, opts.Token, opts.Domain, tagsJoined)
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
