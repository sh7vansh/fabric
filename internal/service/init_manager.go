package service

import (
	"encoding/base64"
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
	ServerURL     string
	SocketURL     string
	ListenAddr    string
	Mode          string
	Token         string
	Domain        string
	Tags          []string
	ThreadPayload string
	NodePayload   string
	CliPayload    string
	CAPayload     string
	CertPayload   string
	KeyPayload    string
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
	roleDisplay := "Server"
	if role == "thread" || role == "agent" || role == "node" {
		roleDisplay = "Thread"
	} else if role == "socket" {
		roleDisplay = "Server"
	}
	home, _ := os.UserHomeDir()
	userEnvPath := ""
	if home != "" {
		userEnvPath = fmt.Sprintf("EnvironmentFile=-%s\n", filepath.Join(home, ".fabric", role+".env"))
	}
	execStopPost := ""
	if role == "thread" || role == "agent" || role == "node" {
		execStopPost = "ExecStopPost=-/usr/bin/resolvectl revert lo\n"
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
	roleDisplay := "Server"
	if role == "thread" || role == "agent" || role == "node" {
		roleDisplay = "Thread"
	} else if role == "socket" {
		roleDisplay = "Server"
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

	canonicalRole := role
	if role == "agent" || role == "node" {
		canonicalRole = "thread"
	} else if role == "socket" {
		canonicalRole = "server"
	}

	pidFile = filepath.Join(runDir, fmt.Sprintf("fabric-%s.pid", canonicalRole))
	supervisorScript = filepath.Join(runDir, fmt.Sprintf("fabric-%s-supervisor.sh", canonicalRole))

	binaryName := "fabric-" + canonicalRole
	if canonicalRole == "thread" {
		if _, err := exec.LookPath("fabric-thread"); err != nil {
			if _, err2 := exec.LookPath("fabric-agent"); err2 == nil {
				binaryName = "fabric-agent"
			} else if _, err3 := exec.LookPath("fabric-node"); err3 == nil {
				binaryName = "fabric-node"
			}
		}
	} else if canonicalRole == "server" {
		if _, err := exec.LookPath("fabric-server"); err != nil {
			if _, err2 := exec.LookPath("fabric-socket"); err2 == nil {
				binaryName = "fabric-socket"
			}
		}
	}

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
	if role != "thread" && role != "agent" && role != "node" && role != "server" && role != "socket" {
		return fmt.Errorf("invalid role: %s (must be 'thread', 'agent', 'server', 'node', or 'socket')", role)
	}

	canonicalRole := role
	if role == "agent" || role == "node" {
		canonicalRole = "thread"
	} else if role == "socket" {
		canonicalRole = "server"
	}

	tier := m.DetectTier()
	serviceName := "fabric-" + canonicalRole
	binaryName := "fabric-" + canonicalRole
	if canonicalRole == "thread" {
		if _, err := exec.LookPath("fabric-thread"); err != nil {
			if _, err2 := exec.LookPath("fabric-agent"); err2 == nil {
				binaryName = "fabric-agent"
			} else if _, err3 := exec.LookPath("fabric-node"); err3 == nil {
				binaryName = "fabric-node"
			}
		}
	} else if canonicalRole == "server" {
		if _, err := exec.LookPath("fabric-server"); err != nil {
			if _, err2 := exec.LookPath("fabric-socket"); err2 == nil {
				binaryName = "fabric-socket"
			}
		}
	}

	binPath, err := exec.LookPath(binaryName)
	if err != nil {
		binPath = "/usr/local/bin/" + binaryName
	}
	home, _ := os.UserHomeDir()

	switch tier {
	case TierSystemdSystem:
		systemBinPath := "/usr/local/bin/" + binaryName
		if _, err := os.Stat(systemBinPath); err != nil {
			if _, err2 := os.Stat("/usr/bin/" + binaryName); err2 == nil {
				systemBinPath = "/usr/bin/" + binaryName
			} else if binPath != "" {
				_ = m.RunPrivileged("cp", binPath, systemBinPath)
				_ = m.RunPrivileged("chmod", "755", systemBinPath)
			}
		}

		// Seamless migration of legacy service units
		if canonicalRole == "thread" {
			for _, legacySvc := range []string{"fabric-agent", "fabric-node"} {
				legacyUnit := filepath.Join("/etc/systemd/system", legacySvc+".service")
				if _, err := os.Stat(legacyUnit); err == nil {
					_ = m.RunPrivileged("systemctl", "stop", legacySvc)
					_ = m.RunPrivileged("systemctl", "disable", legacySvc)
					_ = m.RunPrivileged("rm", "-f", legacyUnit)
				}
			}
		} else if canonicalRole == "server" {
			legacyUnit := "/etc/systemd/system/fabric-socket.service"
			if _, err := os.Stat(legacyUnit); err == nil {
				_ = m.RunPrivileged("systemctl", "stop", "fabric-socket")
				_ = m.RunPrivileged("systemctl", "disable", "fabric-socket")
				_ = m.RunPrivileged("rm", "-f", legacyUnit)
			}
		}

		_ = m.RunPrivileged("mkdir", "-p", "/etc/fabric")
		userEnvCandidates := []string{
			filepath.Join(home, ".fabric", canonicalRole+".env"),
			filepath.Join(home, ".config", "fabric", canonicalRole+".env"),
			filepath.Join(home, ".fabric", role+".env"),
			filepath.Join(home, ".config", "fabric", role+".env"),
		}
		if canonicalRole == "thread" {
			userEnvCandidates = append(userEnvCandidates,
				filepath.Join(home, ".fabric", "agent.env"),
				filepath.Join(home, ".config", "fabric", "agent.env"),
				filepath.Join(home, ".fabric", "node.env"),
				filepath.Join(home, ".config", "fabric", "node.env"),
			)
		}
		for _, uEnv := range userEnvCandidates {
			if data, err := os.ReadFile(uEnv); err == nil && len(data) > 0 {
				tmpEnv, tmpErr := os.CreateTemp("", canonicalRole+"-*.env")
				if tmpErr == nil {
					_, _ = tmpEnv.Write(data)
					tmpEnv.Close()
					_ = m.RunPrivileged("cp", tmpEnv.Name(), filepath.Join("/etc/fabric", canonicalRole+".env"))
					_ = m.RunPrivileged("chmod", "644", filepath.Join("/etc/fabric", canonicalRole+".env"))
					_ = os.Remove(tmpEnv.Name())
					break
				}
			}
		}

		// Also sync user CA to /etc/fabric/ca so system service shares the identical CA
		userCADir := filepath.Join(home, ".fabric", "ca")
		if _, err := os.Stat(filepath.Join(userCADir, "ca.crt")); err == nil {
			_ = m.RunPrivileged("mkdir", "-p", "/etc/fabric/ca")
			_ = m.RunPrivileged("cp", filepath.Join(userCADir, "ca.crt"), "/etc/fabric/ca/ca.crt")
			if _, errKey := os.Stat(filepath.Join(userCADir, "ca.key")); errKey == nil {
				_ = m.RunPrivileged("cp", filepath.Join(userCADir, "ca.key"), "/etc/fabric/ca/ca.key")
				_ = m.RunPrivileged("chmod", "600", "/etc/fabric/ca/ca.key")
			}
			_ = m.RunPrivileged("chmod", "644", "/etc/fabric/ca/ca.crt")
			_ = m.RunPrivileged("cp", filepath.Join(userCADir, "ca.crt"), "/etc/fabric/ca.crt")
			_ = m.RunPrivileged("chmod", "644", "/etc/fabric/ca.crt")
		}

		// Sync config.json to /etc/fabric/config.json
		userCfgPath := filepath.Join(home, ".fabric", "config.json")
		if _, err := os.Stat(userCfgPath); err == nil {
			_ = m.RunPrivileged("cp", userCfgPath, "/etc/fabric/config.json")
			_ = m.RunPrivileged("chmod", "644", "/etc/fabric/config.json")
		}

		unitContent := m.GenerateSystemdSystemUnit(canonicalRole, systemBinPath)
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

		// Seamless migration of user service units
		if canonicalRole == "thread" {
			for _, legacySvc := range []string{"fabric-agent", "fabric-node"} {
				legacyUnit := filepath.Join(userUnitDir, legacySvc+".service")
				if _, err := os.Stat(legacyUnit); err == nil {
					_ = exec.Command("systemctl", "--user", "stop", legacySvc).Run()
					_ = exec.Command("systemctl", "--user", "disable", legacySvc).Run()
					_ = os.Remove(legacyUnit)
				}
			}
		} else if canonicalRole == "server" {
			legacyUnit := filepath.Join(userUnitDir, "fabric-socket.service")
			if _, err := os.Stat(legacyUnit); err == nil {
				_ = exec.Command("systemctl", "--user", "stop", "fabric-socket").Run()
				_ = exec.Command("systemctl", "--user", "disable", "fabric-socket").Run()
				_ = os.Remove(legacyUnit)
			}
		}

		userEnvPath := filepath.Join(home, ".config", "fabric", canonicalRole+".env")
		if _, err := os.Stat(userEnvPath); err != nil {
			if _, err2 := os.Stat(filepath.Join(home, ".fabric", canonicalRole+".env")); err2 == nil {
				userEnvPath = filepath.Join(home, ".fabric", canonicalRole+".env")
			}
		}

		userBinPath := filepath.Join(home, ".local", "bin", binaryName)
		if binPath != "" && binPath != "/usr/local/bin/"+binaryName {
			userBinPath = binPath
		}

		unitContent := m.GenerateSystemdUserUnit(canonicalRole, userBinPath, userEnvPath)
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
		runDir, pidFile, supervisorScript, targetBin := m.GetStandalonePaths(canonicalRole)
		_ = os.MkdirAll(runDir, 0755)

		envFile := filepath.Join(runDir, canonicalRole+".env")
		supervisorContent := m.GenerateSupervisorScript(pidFile, envFile, targetBin)

		if err := os.WriteFile(supervisorScript, []byte(supervisorContent), 0755); err != nil {
			return fmt.Errorf("writing supervisor script: %w", err)
		}

		fmt.Printf("[+] Installed supervisor script %s\n", supervisorScript)
		return m.StartStandalone(canonicalRole)
	}
}

// HandleAction performs start, stop, restart, or status on the service.
func (m *InitManager) HandleAction(action, role string) error {
	serviceNames := []string{"fabric-" + role}
	if role == "thread" || role == "agent" || role == "node" {
		serviceNames = []string{"fabric-thread", "fabric-agent", "fabric-node"}
	} else if role == "server" || role == "socket" {
		serviceNames = []string{"fabric-server", "fabric-socket"}
	}

	home, _ := os.UserHomeDir()

	for _, sName := range serviceNames {
		userUnit := filepath.Join(home, ".config", "systemd", "user", sName+".service")
		if _, err := os.Stat(userUnit); err == nil {
			cmd := exec.Command("systemctl", "--user", action, sName)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}

		systemUnit := filepath.Join("/etc/systemd/system", sName+".service")
		if _, err := os.Stat(systemUnit); err == nil {
			return m.RunPrivileged("systemctl", action, sName)
		}
	}

	canonicalRole := role
	if role == "agent" || role == "node" {
		canonicalRole = "thread"
	} else if role == "socket" {
		canonicalRole = "server"
	}

	// Standalone daemon handling
	switch action {
	case "start":
		return m.StartStandalone(canonicalRole)
	case "stop":
		m.StopStandalone(canonicalRole)
		fmt.Printf("[+] fabric-%s stopped\n", canonicalRole)
		return nil
	case "restart":
		m.StopStandalone(canonicalRole)
		return m.StartStandalone(canonicalRole)
	case "status":
		return m.CheckStandaloneStatus(canonicalRole)
	default:
		if m.IsSystemdAvailable() {
			return m.RunPrivileged("systemctl", action, "fabric-"+canonicalRole)
		}
		return fmt.Errorf("unknown action %s", action)
	}
}

// UninstallService removes system, user, or standalone services for the given role.
func (m *InitManager) UninstallService(role string) error {
	serviceNames := []string{"fabric-" + role}
	if role == "thread" || role == "agent" || role == "node" {
		serviceNames = []string{"fabric-thread", "fabric-agent", "fabric-node"}
	} else if role == "server" || role == "socket" {
		serviceNames = []string{"fabric-server", "fabric-socket"}
	}

	home, _ := os.UserHomeDir()

	for _, sName := range serviceNames {
		// 1. Check user unit
		userUnit := filepath.Join(home, ".config", "systemd", "user", sName+".service")
		if _, err := os.Stat(userUnit); err == nil {
			_ = exec.Command("systemctl", "--user", "stop", sName).Run()
			_ = exec.Command("systemctl", "--user", "disable", sName).Run()
			_ = os.Remove(userUnit)
			_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
			fmt.Printf("[+] Uninstalled user service %s\n", sName)
		}

		// 2. Check system unit
		systemUnit := filepath.Join("/etc/systemd/system", sName+".service")
		if _, err := os.Stat(systemUnit); err == nil {
			_ = m.RunPrivileged("systemctl", "stop", sName)
			_ = m.RunPrivileged("systemctl", "disable", sName)
			_ = m.RunPrivileged("rm", "-f", systemUnit)
			_ = m.RunPrivileged("systemctl", "daemon-reload")
			fmt.Printf("[+] Uninstalled system service %s\n", sName)
		}

		// 3. Standalone cleanup
		canonicalRole := strings.TrimPrefix(sName, "fabric-")
		m.StopStandalone(canonicalRole)
		runDir, _, supervisorScript, _ := m.GetStandalonePaths(canonicalRole)
		_ = os.Remove(supervisorScript)
		_ = os.Remove(filepath.Join(runDir, canonicalRole+".env"))
	}

	canonicalRole := role
	if role == "agent" || role == "node" {
		canonicalRole = "thread"
	}
	fmt.Printf("[+] Uninstalled service fabric-%s\n", canonicalRole)
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
			cmd = exec.Command("sudo", append([]string{"-n", name}, args...)...)
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

	serverURL := opts.ServerURL
	if serverURL == "" {
		serverURL = opts.SocketURL
	}
	mode := opts.Mode
	if mode == "inverted" {
		mode = "remote"
	} else if mode == "normal" {
		mode = "local"
	}
	if mode == "" {
		if opts.ListenAddr != "" {
			mode = "remote"
		} else {
			mode = "local"
		}
	}

	threadPayload := opts.ThreadPayload
	if threadPayload == "" {
		threadPayload = opts.NodePayload
	}

	rawEnv := fmt.Sprintf("FABRIC_SERVER_URL=%s\nFABRIC_SOCKET_URL=%s\nFABRIC_MODE=%s\nFABRIC_LISTEN=%s\nFABRIC_TOKEN=%s\nFABRIC_DOMAIN=%s\nFABRIC_TAGS=%s\n",
		serverURL, serverURL, mode, opts.ListenAddr, opts.Token, opts.Domain, tagsJoined)
	envB64 := base64.StdEncoding.EncodeToString([]byte(rawEnv))

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

TARGET_BIN="$INSTALL_BIN_DIR/fabric-thread"
ENV_FILE="$CONFIG_DIR/thread.env"

# 4. Extract Injected Self-Contained Binary Payload
PAYLOAD="%s"
if [ -n "$PAYLOAD" ]; then
    echo "[+] Unpacking injected fabric-thread binary to $TARGET_BIN..."
    TMP_BIN="${TARGET_BIN}.tmp.$$"
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        (echo "$PAYLOAD" | base64 -d | gzip -d | $SUDO tee "$TMP_BIN" > /dev/null 2>&1) || (echo "$PAYLOAD" | base64 -d | gunzip | $SUDO tee "$TMP_BIN" > /dev/null 2>&1)
        $SUDO chmod 755 "$TMP_BIN"
        $SUDO mv -f "$TMP_BIN" "$TARGET_BIN"
    else
        (echo "$PAYLOAD" | base64 -d | gzip -d > "$TMP_BIN" 2>/dev/null) || (echo "$PAYLOAD" | base64 -d | gunzip > "$TMP_BIN" 2>/dev/null)
        chmod 755 "$TMP_BIN"
        mv -f "$TMP_BIN" "$TARGET_BIN"
    fi
fi

# Extract CLI binary if available
CLI_PAYLOAD="%s"
if [ -n "$CLI_PAYLOAD" ]; then
    echo "[+] Unpacking injected fabric CLI to $INSTALL_BIN_DIR/fabric..."
    TARGET_CLI="$INSTALL_BIN_DIR/fabric"
    TMP_CLI="${TARGET_CLI}.tmp.$$"
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        (echo "$CLI_PAYLOAD" | base64 -d | gzip -d | $SUDO tee "$TMP_CLI" > /dev/null 2>&1) || (echo "$CLI_PAYLOAD" | base64 -d | gunzip | $SUDO tee "$TMP_CLI" > /dev/null 2>&1)
        $SUDO chmod 755 "$TMP_CLI"
        $SUDO mv -f "$TMP_CLI" "$TARGET_CLI"
    else
        (echo "$CLI_PAYLOAD" | base64 -d | gzip -d > "$TMP_CLI" 2>/dev/null) || (echo "$CLI_PAYLOAD" | base64 -d | gunzip > "$TMP_CLI" 2>/dev/null)
        chmod 755 "$TMP_CLI"
        mv -f "$TMP_CLI" "$TARGET_CLI"
    fi
fi

# Validate binary integrity and executable permissions
if [ ! -s "$TARGET_BIN" ] || [ ! -x "$TARGET_BIN" ]; then
    if command -v fabric-thread >/dev/null 2>&1; then
        TARGET_BIN="$(command -v fabric-thread)"
    elif [ -x "/usr/local/bin/fabric-thread" ]; then
        TARGET_BIN="/usr/local/bin/fabric-thread"
    elif command -v fabric-node >/dev/null 2>&1; then
        TARGET_BIN="$(command -v fabric-node)"
    elif [ -x "/usr/local/bin/fabric-node" ]; then
        TARGET_BIN="/usr/local/bin/fabric-node"
    else
        echo "[!] Binary validation failed: $TARGET_BIN not found or not executable" >&2
        exit 1
    fi
fi
echo "[+] Validated binary integrity: $TARGET_BIN"

# 5. Extract Injected mTLS PKI Payloads
CA_PAYLOAD="%s"
if [ -n "$CA_PAYLOAD" ]; then
    echo "[+] Unpacking Root CA certificate to $CONFIG_DIR/ca.crt..."
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        echo "$CA_PAYLOAD" | base64 -d | $SUDO tee "$CONFIG_DIR/ca.crt" > /dev/null
        $SUDO chmod 644 "$CONFIG_DIR/ca.crt"
    else
        echo "$CA_PAYLOAD" | base64 -d > "$CONFIG_DIR/ca.crt"
        chmod 644 "$CONFIG_DIR/ca.crt"
    fi
fi

CERT_PAYLOAD="%s"
if [ -n "$CERT_PAYLOAD" ]; then
    echo "[+] Unpacking thread leaf certificate to $CONFIG_DIR/client.crt..."
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        echo "$CERT_PAYLOAD" | base64 -d | $SUDO tee "$CONFIG_DIR/client.crt" > /dev/null
        $SUDO chmod 644 "$CONFIG_DIR/client.crt"
    else
        echo "$CERT_PAYLOAD" | base64 -d > "$CONFIG_DIR/client.crt"
        chmod 644 "$CONFIG_DIR/client.crt"
    fi
fi

KEY_PAYLOAD="%s"
if [ -n "$KEY_PAYLOAD" ]; then
    echo "[+] Unpacking thread leaf private key to $CONFIG_DIR/client.key..."
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
        echo "$KEY_PAYLOAD" | base64 -d | $SUDO tee "$CONFIG_DIR/client.key" > /dev/null
        $SUDO chmod 600 "$CONFIG_DIR/client.key"
    else
        echo "$KEY_PAYLOAD" | base64 -d > "$CONFIG_DIR/client.key"
        chmod 600 "$CONFIG_DIR/client.key"
    fi
fi

# 6. Write Environment Configuration
ENV_B64="%s"
if [ "$IS_ROOT" -eq 1 ] && [ -n "$SUDO" ]; then
    echo "$ENV_B64" | base64 -d | $SUDO tee "$ENV_FILE" > /dev/null
    $SUDO chmod 600 "$ENV_FILE"
    # Legacy fallback link
    $SUDO cp -f "$ENV_FILE" "$CONFIG_DIR/node.env" 2>/dev/null || true
else
    echo "$ENV_B64" | base64 -d > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    cp -f "$ENV_FILE" "$CONFIG_DIR/node.env" 2>/dev/null || true
fi

# 7. Multi-Tier Init Selection & Service Activation
if [ "$IS_ROOT" -eq 1 ] && [ "$HAS_SYSTEMD" -eq 1 ]; then
    # Disable any legacy units
    $SUDO systemctl stop fabric-node fabric-agent 2>/dev/null || true
    $SUDO systemctl disable fabric-node fabric-agent 2>/dev/null || true
    $SUDO rm -f /etc/systemd/system/fabric-node.service /etc/systemd/system/fabric-agent.service

    # Tier 1: Root / Sudo with systemd (System service)
    echo "[+] Configuring systemd system service (/etc/systemd/system/fabric-thread.service)..."
    cat << 'UNIT_EOF' | $SUDO tee /etc/systemd/system/fabric-thread.service > /dev/null
[Unit]
Description=Fabric Mesh Network Thread
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/fabric/thread.env
ExecStart=/usr/local/bin/fabric-thread
Restart=always
RestartSec=3s
LimitNOFILE=65536
ExecStopPost=-/usr/bin/resolvectl revert lo

[Install]
WantedBy=multi-user.target
UNIT_EOF

    $SUDO chmod 644 /etc/systemd/system/fabric-thread.service
    $SUDO systemctl daemon-reload
    $SUDO systemctl restart fabric-thread || true
    $SUDO systemctl enable fabric-thread || true
    echo "[+] Systemd system service enabled and active."

elif [ "$IS_ROOT" -eq 0 ] && [ "$HAS_SYSTEMD" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
    # Tier 2: Non-root with systemd (User service)
    systemctl --user stop fabric-node fabric-agent 2>/dev/null || true
    systemctl --user disable fabric-node fabric-agent 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/fabric-node.service" "$HOME/.config/systemd/user/fabric-agent.service"

    echo "[+] Configuring systemd user service (~/.config/systemd/user/fabric-thread.service)..."
    mkdir -p "$HOME/.config/systemd/user"
    cat << UNIT_EOF > "$HOME/.config/systemd/user/fabric-thread.service"
[Unit]
Description=Fabric Mesh Network Thread (User)
After=network.target

[Service]
Type=simple
EnvironmentFile=-$HOME/.config/fabric/thread.env
ExecStart=$TARGET_BIN
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=default.target
UNIT_EOF

    chmod 644 "$HOME/.config/systemd/user/fabric-thread.service"
    loginctl enable-linger "$(whoami)" 2>/dev/null || true
    systemctl --user daemon-reload || true
    systemctl --user restart fabric-thread || true
    systemctl --user enable fabric-thread || true
    echo "[+] Systemd user service enabled and active."

else
    # Tier 3: Non-systemd / Edge / Container (Supervised background daemon)
    echo "[+] Configuring standalone supervisor daemon in $RUN_DIR..."
    PIDFILE="$RUN_DIR/fabric-thread.pid"
    SUPERVISOR="$RUN_DIR/fabric-thread-supervisor.sh"

    if [ -f "$PIDFILE" ]; then
        OLD_PID=$(cat "$PIDFILE" 2>/dev/null || true)
        if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
            kill "$OLD_PID" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$PIDFILE"
    fi

    cat << 'SUPERVISOR_EOF' > "$SUPERVISOR"
` + m.GenerateSupervisorScript("$PIDFILE", "$ENV_FILE", "$TARGET_BIN") + `SUPERVISOR_EOF

    chmod 755 "$SUPERVISOR"
    nohup "$SUPERVISOR" > /dev/null 2>&1 &
    echo $! > "$RUN_DIR/fabric-thread-supervisor.pid"
    echo "[+] Supervised background daemon started (PID file: $PIDFILE)."
fi

# 8. Firewall Configuration (Remote Listening Mode)
if [ "%s" = "remote" ]; then
    PORT_NUM="%s"
    PORT_NUM="${PORT_NUM#:}"
    [ -z "$PORT_NUM" ] && PORT_NUM="8443"
    echo "[+] Configuring firewall for remote listening port ($PORT_NUM/tcp)..."
    if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -qi "status: active"; then
        $SUDO ufw allow "$PORT_NUM/tcp" comment "Fabric Remote Thread Listener" 2>/dev/null || $SUDO ufw allow "$PORT_NUM/tcp" || true
        echo "[+] Configured ufw rule for port $PORT_NUM/tcp"
    elif command -v firewall-cmd >/dev/null 2>&1 && $SUDO firewall-cmd --state 2>/dev/null | grep -qi "running"; then
        $SUDO firewall-cmd --permanent --add-port="$PORT_NUM/tcp" 2>/dev/null && $SUDO firewall-cmd --reload 2>/dev/null || true
        echo "[+] Configured firewalld rule for port $PORT_NUM/tcp"
    elif command -v nft >/dev/null 2>&1; then
        $SUDO nft add rule inet filter input tcp dport "$PORT_NUM" accept comment "Fabric Remote Thread Listener" 2>/dev/null || $SUDO nft add rule inet filter input tcp dport "$PORT_NUM" accept 2>/dev/null || true
        echo "[+] Configured nftables rule for port $PORT_NUM/tcp"
    elif command -v iptables >/dev/null 2>&1; then
        $SUDO iptables -I INPUT -p tcp --dport "$PORT_NUM" -m comment --comment "Fabric Remote Thread Listener" -j ACCEPT 2>/dev/null || $SUDO iptables -I INPUT -p tcp --dport "$PORT_NUM" -j ACCEPT 2>/dev/null || true
        echo "[+] Configured iptables rule for port $PORT_NUM/tcp"
    fi
fi
`, threadPayload, opts.CliPayload, opts.CAPayload, opts.CertPayload, opts.KeyPayload, envB64, mode, opts.ListenAddr)
}

// RenderRemoteSwitchScript renders a lightweight SSH command to switch an existing thread to remote mode.
func (m *InitManager) RenderRemoteSwitchScript(listenPort string) string {
	if !strings.HasPrefix(listenPort, ":") {
		listenPort = ":" + listenPort
	}
	portNum := strings.TrimPrefix(listenPort, ":")
	if portNum == "" {
		portNum = "8443"
	}

	return fmt.Sprintf(`#!/usr/bin/env bash
set -e

PORT="%s"

# Locate environment file
ENV_FILE="/etc/fabric/thread.env"
if [ ! -f "$ENV_FILE" ] && [ -f "$HOME/.config/fabric/thread.env" ]; then
    ENV_FILE="$HOME/.config/fabric/thread.env"
elif [ ! -f "$ENV_FILE" ] && [ -f "/etc/fabric/node.env" ]; then
    ENV_FILE="/etc/fabric/node.env"
elif [ ! -f "$ENV_FILE" ] && [ -f "$HOME/.config/fabric/node.env" ]; then
    ENV_FILE="$HOME/.config/fabric/node.env"
fi

if [ -f "$ENV_FILE" ]; then
    if grep -q "FABRIC_LISTEN=" "$ENV_FILE" 2>/dev/null; then
        if [ "$EUID" -eq 0 ]; then
            sed -i "s|^FABRIC_LISTEN=.*|FABRIC_LISTEN=$PORT|" "$ENV_FILE"
            sed -i "s|^FABRIC_MODE=.*|FABRIC_MODE=remote|" "$ENV_FILE" 2>/dev/null || true
        elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            sudo sed -i "s|^FABRIC_LISTEN=.*|FABRIC_LISTEN=$PORT|" "$ENV_FILE"
            sudo sed -i "s|^FABRIC_MODE=.*|FABRIC_MODE=remote|" "$ENV_FILE" 2>/dev/null || true
        else
            sed -i "s|^FABRIC_LISTEN=.*|FABRIC_LISTEN=$PORT|" "$ENV_FILE"
            sed -i "s|^FABRIC_MODE=.*|FABRIC_MODE=remote|" "$ENV_FILE" 2>/dev/null || true
        fi
    else
        if [ "$EUID" -eq 0 ]; then
            echo "FABRIC_MODE=remote" >> "$ENV_FILE"
            echo "FABRIC_LISTEN=$PORT" >> "$ENV_FILE"
        elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            echo "FABRIC_MODE=remote" | sudo tee -a "$ENV_FILE" > /dev/null
            echo "FABRIC_LISTEN=$PORT" | sudo tee -a "$ENV_FILE" > /dev/null
        else
            echo "FABRIC_MODE=remote" >> "$ENV_FILE"
            echo "FABRIC_LISTEN=$PORT" >> "$ENV_FILE"
        fi
    fi
fi

# Restart service across tiers
if [ "$EUID" -eq 0 ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl restart fabric-thread 2>/dev/null || systemctl restart fabric-node || true
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    sudo systemctl restart fabric-thread 2>/dev/null || sudo systemctl restart fabric-node || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl --user restart fabric-thread 2>/dev/null || systemctl --user restart fabric-node 2>/dev/null || true
fi

# Standalone supervisor daemon check
RUN_DIR="/var/run/fabric"
[ -f "$HOME/.fabric/fabric-thread.pid" ] && RUN_DIR="$HOME/.fabric"
[ -f "$HOME/.fabric/fabric-node.pid" ] && RUN_DIR="$HOME/.fabric"
if [ -f "$RUN_DIR/fabric-thread.pid" ]; then
    PID=$(cat "$RUN_DIR/fabric-thread.pid" 2>/dev/null || true)
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
    fi
elif [ -f "$RUN_DIR/fabric-node.pid" ]; then
    PID=$(cat "$RUN_DIR/fabric-node.pid" 2>/dev/null || true)
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
    fi
fi

# Firewall Configuration for Remote Mode
SUDO=""
if [ "$EUID" -ne 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    SUDO="sudo"
fi

if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -qi "status: active"; then
    $SUDO ufw allow "%s/tcp" comment "Fabric Remote Thread Listener" 2>/dev/null || $SUDO ufw allow "%s/tcp" || true
elif command -v firewall-cmd >/dev/null 2>&1 && $SUDO firewall-cmd --state 2>/dev/null | grep -qi "running"; then
    $SUDO firewall-cmd --permanent --add-port="%s/tcp" 2>/dev/null && $SUDO firewall-cmd --reload 2>/dev/null || true
elif command -v nft >/dev/null 2>&1; then
    $SUDO nft add rule inet filter input tcp dport "%s" accept comment "Fabric Remote Thread Listener" 2>/dev/null || $SUDO nft add rule inet filter input tcp dport "%s" accept 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
    $SUDO iptables -I INPUT -p tcp --dport "%s" -m comment --comment "Fabric Remote Thread Listener" -j ACCEPT 2>/dev/null || $SUDO iptables -I INPUT -p tcp --dport "%s" -j ACCEPT 2>/dev/null || true
fi
`, listenPort, portNum, portNum, portNum, portNum, portNum, portNum, portNum)
}

// RenderInvertedSwitchScript is a deprecated alias for RenderRemoteSwitchScript.
func (m *InitManager) RenderInvertedSwitchScript(listenPort string) string {
	return m.RenderRemoteSwitchScript(listenPort)
}

