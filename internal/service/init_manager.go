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
	ServerURL     string
	SocketURL     string
	ThreadName    string
	NodeName      string
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
	renderer := NewBootstrapRenderer()
	return renderer.GenerateSupervisorScript(pidFile, envFile, targetBin)
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

// WriteServiceEnv writes or updates the service environment file for the given role.
func (m *InitManager) WriteServiceEnv(role string, env ConfigEnv) error {
	if len(env) == 0 {
		return nil
	}

	canonicalRole := role
	if role == "agent" || role == "node" {
		canonicalRole = "thread"
	} else if role == "socket" {
		canonicalRole = "server"
	}

	var envDir string
	if os.Geteuid() == 0 {
		envDir = "/etc/fabric"
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		envDir = filepath.Join(home, ".fabric")
	}

	if err := os.MkdirAll(envDir, 0755); err != nil {
		return err
	}

	var sb strings.Builder
	for k, v := range env {
		sb.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	}

	envPath := filepath.Join(envDir, canonicalRole+".env")
	return os.WriteFile(envPath, []byte(sb.String()), 0600)
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
			_ = m.RunPrivileged("mkdir", "-p", "/etc/fabric")
			_ = m.RunPrivileged("chmod", "755", "/etc/fabric")
			_ = m.RunPrivileged("mkdir", "-p", "/etc/fabric/ca")
			_ = m.RunPrivileged("chmod", "755", "/etc/fabric/ca")
			_ = m.RunPrivileged("cp", filepath.Join(userCADir, "ca.crt"), "/etc/fabric/ca/ca.crt")
			_ = m.RunPrivileged("chmod", "644", "/etc/fabric/ca/ca.crt")
			_ = m.RunPrivileged("cp", filepath.Join(userCADir, "ca.crt"), "/etc/fabric/ca.crt")
			_ = m.RunPrivileged("chmod", "644", "/etc/fabric/ca.crt")
			if _, errKey := os.Stat(filepath.Join(userCADir, "ca.key")); errKey == nil {
				_ = m.RunPrivileged("cp", filepath.Join(userCADir, "ca.key"), "/etc/fabric/ca/ca.key")
				_ = m.RunPrivileged("chmod", "600", "/etc/fabric/ca/ca.key")
			}
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
	renderer := NewBootstrapRenderer()
	return renderer.RenderBootstrapScript(opts)
}

// RenderRemoteSwitchScript renders a lightweight SSH command to switch an existing thread to remote mode.
func (m *InitManager) RenderRemoteSwitchScript(listenPort string) string {
	renderer := NewBootstrapRenderer()
	return renderer.RenderRemoteSwitchScript(listenPort)
}

// RenderInvertedSwitchScript is a deprecated alias for RenderRemoteSwitchScript.
func (m *InitManager) RenderInvertedSwitchScript(listenPort string) string {
	renderer := NewBootstrapRenderer()
	return renderer.RenderInvertedSwitchScript(listenPort)
}


