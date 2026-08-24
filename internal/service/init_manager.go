package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// InitTier represents the init system detected or targeted on the host.
type InitTier int

const (
	TierSystemdSystem InitTier = 1 // Root or sudo with active systemd
	TierSystemdUser   InitTier = 2 // Non-root user with active systemd
	TierSupervisor    InitTier = 3 // Non-systemd or standalone container supervisor
)

// BootstrapScriptOptions holds parameters needed to render the remote air-gapped bootstrap shell script.
type BootstrapScriptOptions struct {
	SocketURL      string
	Token          string
	Domain         string
	Tags           []string
	NodePayload    string
	CliPayload     string
}

// InitManager is the deep module encapsulating multi-tier init rules,
// canonical unit templates, local lifecycle operations, and remote bootstrap script generation.
type InitManager struct{}

// NewInitManager creates a new InitManager.
func NewInitManager() *InitManager {
	return &InitManager{}
}

// DetectTier detects the appropriate init tier for the current host environment.
func (m *InitManager) DetectTier() InitTier {
	hasSystemd := m.IsSystemdAvailable()
	isPriv := m.IsPrivileged()

	if hasSystemd && isPriv {
		return TierSystemdSystem
	}
	if hasSystemd && !isPriv {
		return TierSystemdUser
	}
	return TierSupervisor
}

// IsSystemdAvailable checks if systemctl and /run/systemd/system exist.
func (m *InitManager) IsSystemdAvailable() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return true
	}
	return false
}

// IsPrivileged checks if current process has root UID or passwordless sudo.
func (m *InitManager) IsPrivileged() bool {
	if os.Geteuid() == 0 {
		return true
	}
	if _, err := exec.LookPath("sudo"); err == nil {
		cmd := exec.Command("sudo", "-n", "true")
		if err := cmd.Run(); err == nil {
			return true
		}
	}
	return false
}

// GenerateSystemdSystemUnit renders the systemd system service unit file content.
func (m *InitManager) GenerateSystemdSystemUnit(role, binPath string) string {
	roleDisplay := "Socket"
	if role == "node" {
		roleDisplay = "Node"
	}
	home, _ := os.UserHomeDir()
	userEnvPath := ""
	if home != "" {
		userEnvPath = fmt.Sprintf("EnvironmentFile=-%s\n", filepath.Join(home, ".fabric", role+".env"))
	}
	execStopPost := ""
	if role == "node" {
		execStopPost = "ExecStopPost=/usr/bin/resolvectl revert lo\n"
	}

	return fmt.Sprintf(`[Unit]
Description=Fabric Mesh Network %s
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/fabric/%s.env
%sExecStart=%s
%sRestart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, roleDisplay, role, userEnvPath, binPath, execStopPost)
}

// GenerateSystemdUserUnit renders the systemd user service unit file content.
func (m *InitManager) GenerateSystemdUserUnit(role, userBinPath, userEnvPath string) string {
	roleDisplay := "Socket"
	if role == "node" {
		roleDisplay = "Node"
	}

	return fmt.Sprintf(`[Unit]
Description=Fabric Mesh Network %s (User)
After=network.target

[Service]
Type=simple
EnvironmentFile=-%s
ExecStart=%s
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=default.target
`, roleDisplay, userEnvPath, userBinPath)
}

// GenerateSupervisorScript renders the standalone background supervisor shell script content.
func (m *InitManager) GenerateSupervisorScript(pidFile, envFile, targetBin string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
PIDFILE="%s"
ENVFILE="%s"
BIN="%s"
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
`, pidFile, envFile, targetBin)
}

// GetStandalonePaths returns run directory, pid file, supervisor script, and binary path for standalone mode.
func (m *InitManager) GetStandalonePaths(role string) (runDir, pidFile, supervisorScript, binPath string) {
	home, _ := os.UserHomeDir()
	if os.Geteuid() == 0 {
		runDir = "/var/run/fabric"
	} else {
		runDir = filepath.Join(home, ".fabric")
	}
	pidFile = filepath.Join(runDir, fmt.Sprintf("fabric-%s.pid", role))
	supervisorScript = filepath.Join(runDir, fmt.Sprintf("fabric-%s-supervisor.sh", role))

	binaryName := "fabric-" + role
	var err error
	binPath, err = exec.LookPath(binaryName)
	if err != nil {
		if os.Geteuid() == 0 {
			binPath = "/usr/local/bin/" + binaryName
		} else {
			binPath = filepath.Join(home, ".local", "bin", binaryName)
		}
	}
	return
}

// InstallService installs and starts the service according to the detected host init tier.
func (m *InitManager) InstallService(role string) error {
	if role != "socket" && role != "node" {
		return fmt.Errorf("invalid role: %s (must be 'socket' or 'node')", role)
	}

	tier := m.DetectTier()
	serviceName := "fabric-" + role
	binaryName := "fabric-" + role

	binPath, err := exec.LookPath(binaryName)
	if err != nil {
		binPath = "/usr/local/bin/" + binaryName
	}
	home, _ := os.UserHomeDir()

	switch tier {
	case TierSystemdSystem:
		unitContent := m.GenerateSystemdSystemUnit(role, binPath)
		unitPath := filepath.Join("/etc/systemd/system", serviceName+".service")

		tmpFile, err := os.CreateTemp("", serviceName+"-*.service")
		if err != nil {
			return fmt.Errorf("creating temp unit file: %w", err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(unitContent); err != nil {
			return fmt.Errorf("writing unit content: %w", err)
		}
		tmpFile.Close()

		if err := m.RunPrivileged("cp", tmpFile.Name(), unitPath); err != nil {
			return fmt.Errorf("copying unit file to %s: %w", unitPath, err)
		}
		if err := m.RunPrivileged("chmod", "644", unitPath); err != nil {
			return fmt.Errorf("setting permissions on %s: %w", unitPath, err)
		}

		fmt.Printf("[+] Installed systemd unit %s\n", unitPath)
		_ = m.RunPrivileged("systemctl", "daemon-reload")
		if err := m.RunPrivileged("systemctl", "enable", "--now", serviceName); err != nil {
			fmt.Printf("[!] Warning: Could not enable system service: %v\n", err)
		} else {
			fmt.Printf("[+] Service %s enabled and started!\n", serviceName)
		}
		return nil

	case TierSystemdUser:
		userUnitDir := filepath.Join(home, ".config", "systemd", "user")
		_ = os.MkdirAll(userUnitDir, 0755)

		userEnvPath := filepath.Join(home, ".config", "fabric", role+".env")
		userBinPath := filepath.Join(home, ".local", "bin", binaryName)
		if binPath != "" && binPath != "/usr/local/bin/"+binaryName {
			userBinPath = binPath
		}

		unitContent := m.GenerateSystemdUserUnit(role, userBinPath, userEnvPath)
		unitPath := filepath.Join(userUnitDir, serviceName+".service")
		if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
			return fmt.Errorf("writing user unit file: %w", err)
		}

		fmt.Printf("[+] Installed user systemd unit %s\n", unitPath)
		_ = exec.Command("loginctl", "enable-linger").Run()
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		if err := exec.Command("systemctl", "--user", "enable", "--now", serviceName).Run(); err != nil {
			fmt.Printf("[!] Warning: Could not enable user service: %v\n", err)
		} else {
			fmt.Printf("[+] User service %s enabled and started!\n", serviceName)
		}
		return nil

	default:
		runDir, pidFile, supervisorScript, targetBin := m.GetStandalonePaths(role)
		_ = os.MkdirAll(runDir, 0755)

		envFile := filepath.Join(runDir, role+".env")
		supervisorContent := m.GenerateSupervisorScript(pidFile, envFile, targetBin)

		if err := os.WriteFile(supervisorScript, []byte(supervisorContent), 0755); err != nil {
			return fmt.Errorf("writing supervisor script: %w", err)
		}

		fmt.Printf("[+] Installed supervisor script %s\n", supervisorScript)
		return m.StartStandalone(role)
	}
}

// HandleAction performs start, stop, restart, or status on the service.
func (m *InitManager) HandleAction(action, role string) error {
	serviceName := "fabric-" + role
	home, _ := os.UserHomeDir()

	userUnit := filepath.Join(home, ".config", "systemd", "user", serviceName+".service")
	systemUnit := filepath.Join("/etc/systemd/system", serviceName+".service")

	if _, err := os.Stat(userUnit); err == nil {
		cmd := exec.Command("systemctl", "--user", action, serviceName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	if _, err := os.Stat(systemUnit); err == nil {
		return m.RunPrivileged("systemctl", action, serviceName)
	}

	// Standalone daemon handling
	switch action {
	case "start":
		return m.StartStandalone(role)
	case "stop":
		m.StopStandalone(role)
		fmt.Printf("[+] fabric-%s stopped\n", role)
		return nil
	case "restart":
		m.StopStandalone(role)
		return m.StartStandalone(role)
	case "status":
		return m.CheckStandaloneStatus(role)
	default:
		if m.IsSystemdAvailable() {
			return m.RunPrivileged("systemctl", action, serviceName)
		}
		return fmt.Errorf("unknown action %s", action)
	}
}

// UninstallService removes system, user, or standalone services for the given role.
func (m *InitManager) UninstallService(role string) error {
	serviceName := "fabric-" + role
	home, _ := os.UserHomeDir()

	// 1. Check user unit
	userUnit := filepath.Join(home, ".config", "systemd", "user", serviceName+".service")
	if _, err := os.Stat(userUnit); err == nil {
		_ = exec.Command("systemctl", "--user", "stop", serviceName).Run()
		_ = exec.Command("systemctl", "--user", "disable", serviceName).Run()
		_ = os.Remove(userUnit)
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		fmt.Printf("[+] Uninstalled user service %s\n", serviceName)
	}

	// 2. Check system unit
	systemUnit := filepath.Join("/etc/systemd/system", serviceName+".service")
	if _, err := os.Stat(systemUnit); err == nil {
		_ = m.RunPrivileged("systemctl", "stop", serviceName)
		_ = m.RunPrivileged("systemctl", "disable", serviceName)
		_ = m.RunPrivileged("rm", "-f", systemUnit)
		_ = m.RunPrivileged("systemctl", "daemon-reload")
		fmt.Printf("[+] Uninstalled system service %s\n", serviceName)
	}

	// 3. Standalone cleanup
	m.StopStandalone(role)
	runDir, _, supervisorScript, _ := m.GetStandalonePaths(role)
	_ = os.Remove(supervisorScript)
	_ = os.Remove(filepath.Join(runDir, role+".env"))

	fmt.Printf("[+] Uninstalled service %s\n", serviceName)
	return nil
}

// StartStandalone starts the background supervisor process.
func (m *InitManager) StartStandalone(role string) error {
	runDir, pidFile, supervisorScript, _ := m.GetStandalonePaths(role)
	_ = os.MkdirAll(runDir, 0755)

	m.StopStandalone(role)

	cmd := exec.Command("nohup", supervisorScript)
	cmd.Dir = runDir
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start supervisor daemon: %w", err)
	}
	_ = os.WriteFile(filepath.Join(runDir, fmt.Sprintf("fabric-%s-supervisor.pid", role)), []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	fmt.Printf("[+] Standalone supervisor for %s started (PID file: %s)\n", role, pidFile)
	return nil
}

// StopStandalone stops any active standalone supervisor and child process.
func (m *InitManager) StopStandalone(role string) {
	runDir, pidFile, _, _ := m.GetStandalonePaths(role)
	if data, err := os.ReadFile(pidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
		_ = os.Remove(pidFile)
	}
	supPidFile := filepath.Join(runDir, fmt.Sprintf("fabric-%s-supervisor.pid", role))
	if data, err := os.ReadFile(supPidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
		_ = os.Remove(supPidFile)
	}
}

// CheckStandaloneStatus prints whether a standalone daemon is running.
func (m *InitManager) CheckStandaloneStatus(role string) error {
	_, pidFile, _, _ := m.GetStandalonePaths(role)
	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Printf("fabric-%s is stopped (no PID file)\n", role)
		return nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		fmt.Printf("fabric-%s is stopped (invalid PID)\n", role)
		return nil
	}
	if err := syscall.Kill(pid, 0); err == nil {
		fmt.Printf("fabric-%s (pid %d) is running...\n", role, pid)
		return nil
	}
	fmt.Printf("fabric-%s is stopped (stale PID %d)\n", role, pid)
	return nil
}

// RunPrivileged executes a command as root or with sudo if needed.
func (m *InitManager) RunPrivileged(name string, args ...string) error {
	var cmd *exec.Cmd
	if os.Geteuid() != 0 {
		if _, err := exec.LookPath("sudo"); err == nil {
			cmd = exec.Command("sudo", append([]string{name}, args...)...)
		} else {
			cmd = exec.Command(name, args...)
		}
	} else {
		cmd = exec.Command(name, args...)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RenderBootstrapScript renders the canonical air-gapped bootstrap shell script for remote stitching.
func (m *InitManager) RenderBootstrapScript(opts BootstrapScriptOptions) string {
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

# Extract CLI binary if available
CLI_PAYLOAD="%s"
if [ -n "$CLI_PAYLOAD" ]; then
    echo "[+] Unpacking injected fabric CLI to $INSTALL_BIN_DIR/fabric..."
    TARGET_CLI="$INSTALL_BIN_DIR/fabric"
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        (echo "$CLI_PAYLOAD" | base64 -d | gzip -d | $SUDO tee "$TARGET_CLI" > /dev/null 2>&1) || (echo "$CLI_PAYLOAD" | base64 -d | gunzip | $SUDO tee "$TARGET_CLI" > /dev/null 2>&1)
        $SUDO chmod 755 "$TARGET_CLI"
    else
        (echo "$CLI_PAYLOAD" | base64 -d | gzip -d > "$TARGET_CLI" 2>/dev/null) || (echo "$CLI_PAYLOAD" | base64 -d | gunzip > "$TARGET_CLI" 2>/dev/null)
        chmod 755 "$TARGET_CLI"
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
`, opts.NodePayload, opts.CliPayload, opts.SocketURL, opts.Token, opts.Domain, tagsJoined)
}
