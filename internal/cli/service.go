package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:     "service",
	Short:   "Manage background service units for Fabric Socket and Node",
	GroupID: "system",
	Long: `Manage the lifecycle of background service units for fabric-socket and fabric-node.

Supports multi-tier init environments: system systemd, user systemd (--user), and standalone supervisors.`,
	Example: `  # Install and start fabric-node as a background service
  fabric service install node

  # Check the status of the local socket service
  fabric service status socket

  # Restart the agent daemon
  fabric service restart node

  # Uninstall and remove service
  fabric service uninstall node`,
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install [socket|node]",
	Short: "Install and enable a service for fabric-socket or fabric-node",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		role := strings.ToLower(args[0])
		return InstallService(role)
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall [socket|node]",
	Short: "Stop, disable, and remove the service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		role := strings.ToLower(args[0])
		return UninstallService(role)
	},
}

func newServiceActionCmd(action, desc string) *cobra.Command {
	return &cobra.Command{
		Use:   action + " [socket|node]",
		Short: desc,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role := strings.ToLower(args[0])
			return HandleServiceAction(action, role)
		},
	}
}

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(newServiceActionCmd("start", "Start the fabric service"))
	serviceCmd.AddCommand(newServiceActionCmd("stop", "Stop the fabric service"))
	serviceCmd.AddCommand(newServiceActionCmd("restart", "Restart the fabric service"))
	serviceCmd.AddCommand(newServiceActionCmd("status", "Check the status of the fabric service"))
	serviceCmd.AddCommand(serviceUninstallCmd)
}

func isSystemdAvailable() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return true
	}
	return false
}

func isPrivileged() bool {
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

func getStandalonePaths(role string) (runDir, pidFile, supervisorScript, binPath string) {
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

func InstallService(role string) error {
	if role != "socket" && role != "node" {
		return fmt.Errorf("invalid role: %s (must be 'socket' or 'node')", role)
	}

	serviceName := "fabric-" + role
	binaryName := "fabric-" + role

	binPath, err := exec.LookPath(binaryName)
	if err != nil {
		binPath = "/usr/local/bin/" + binaryName
	}

	roleDisplay := "Socket"
	if role == "node" {
		roleDisplay = "Node"
	}

	home, _ := os.UserHomeDir()

	// Tier 1: Root / Sudo with systemd
	if isSystemdAvailable() && isPrivileged() {
		userEnvPath := ""
		if home != "" {
			userEnvPath = fmt.Sprintf("EnvironmentFile=-%s\n", filepath.Join(home, ".fabric", role+".env"))
		}
		execStopPost := ""
		if role == "node" {
			execStopPost = "ExecStopPost=/usr/bin/resolvectl revert lo\n"
		}

		unitContent := fmt.Sprintf(`[Unit]
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

		if err := runPrivilegedCommand("cp", tmpFile.Name(), unitPath); err != nil {
			return fmt.Errorf("copying unit file to %s: %w", unitPath, err)
		}
		if err := runPrivilegedCommand("chmod", "644", unitPath); err != nil {
			return fmt.Errorf("setting permissions on %s: %w", unitPath, err)
		}

		fmt.Printf("[+] Installed systemd unit %s\n", unitPath)
		_ = runPrivilegedCommand("systemctl", "daemon-reload")
		if err := runPrivilegedCommand("systemctl", "enable", "--now", serviceName); err != nil {
			fmt.Printf("[!] Warning: Could not enable system service: %v\n", err)
		} else {
			fmt.Printf("[+] Service %s enabled and started!\n", serviceName)
		}
		return nil
	}

	// Tier 2: Non-root with systemd
	if isSystemdAvailable() && !isPrivileged() {
		userUnitDir := filepath.Join(home, ".config", "systemd", "user")
		_ = os.MkdirAll(userUnitDir, 0755)

		userEnvPath := filepath.Join(home, ".config", "fabric", role+".env")
		userBinPath := filepath.Join(home, ".local", "bin", binaryName)
		if binPath != "" && binPath != "/usr/local/bin/"+binaryName {
			userBinPath = binPath
		}

		unitContent := fmt.Sprintf(`[Unit]
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
	}

	// Tier 3: Non-systemd / Standalone Supervisor
	runDir, pidFile, supervisorScript, targetBin := getStandalonePaths(role)
	_ = os.MkdirAll(runDir, 0755)

	envFile := filepath.Join(runDir, role+".env")
	supervisorContent := fmt.Sprintf(`#!/usr/bin/env bash
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

	if err := os.WriteFile(supervisorScript, []byte(supervisorContent), 0755); err != nil {
		return fmt.Errorf("writing supervisor script: %w", err)
	}

	fmt.Printf("[+] Installed supervisor script %s\n", supervisorScript)
	return startStandaloneDaemon(role)
}

func startStandaloneDaemon(role string) error {
	runDir, pidFile, supervisorScript, _ := getStandalonePaths(role)
	_ = os.MkdirAll(runDir, 0755)

	// Kill existing process if running
	stopStandaloneDaemon(role)

	cmd := exec.Command("nohup", supervisorScript)
	cmd.Dir = runDir
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start supervisor daemon: %w", err)
	}
	_ = os.WriteFile(filepath.Join(runDir, fmt.Sprintf("fabric-%s-supervisor.pid", role)), []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	fmt.Printf("[+] Standalone supervisor for %s started (PID file: %s)\n", role, pidFile)
	return nil
}

func stopStandaloneDaemon(role string) {
	runDir, pidFile, _, _ := getStandalonePaths(role)
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

func checkStandaloneStatus(role string) error {
	_, pidFile, _, _ := getStandalonePaths(role)
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

func HandleServiceAction(action, role string) error {
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
		return runPrivilegedCommand("systemctl", action, serviceName)
	}

	// Standalone daemon handling
	switch action {
	case "start":
		return startStandaloneDaemon(role)
	case "stop":
		stopStandaloneDaemon(role)
		fmt.Printf("[+] fabric-%s stopped\n", role)
		return nil
	case "restart":
		stopStandaloneDaemon(role)
		return startStandaloneDaemon(role)
	case "status":
		return checkStandaloneStatus(role)
	default:
		if isSystemdAvailable() {
			return runPrivilegedCommand("systemctl", action, serviceName)
		}
		return fmt.Errorf("unknown action %s", action)
	}
}

func UninstallService(role string) error {
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
		_ = runPrivilegedCommand("systemctl", "stop", serviceName)
		_ = runPrivilegedCommand("systemctl", "disable", serviceName)
		_ = runPrivilegedCommand("rm", "-f", systemUnit)
		_ = runPrivilegedCommand("systemctl", "daemon-reload")
		fmt.Printf("[+] Uninstalled system service %s\n", serviceName)
	}

	// 3. Standalone cleanup
	stopStandaloneDaemon(role)
	runDir, _, supervisorScript, _ := getStandalonePaths(role)
	_ = os.Remove(supervisorScript)
	_ = os.Remove(filepath.Join(runDir, role+".env"))

	fmt.Printf("[+] Uninstalled service %s\n", serviceName)
	return nil
}

func runPrivilegedCommand(name string, args ...string) error {
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
