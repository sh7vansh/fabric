package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:     "service",
	Short:   "Manage systemd service units for Fabric Socket and Node",
	GroupID: "system",
	Long: `Manage the lifecycle of background systemd service units for fabric-socket and fabric-node.

Supports installing unit definitions, checking status, and starting/stopping/restarting daemons.`,
	Example: `  # Install and start fabric-node as a background systemd service
  fabric service install node

  # Check the status of the local socket service
  fabric service status socket

  # Restart the agent daemon
  fabric service restart node

  # Uninstall and remove systemd service
  fabric service uninstall node`,
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install [socket|node]",
	Short: "Install and enable a systemd service for fabric-socket or fabric-node",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		role := strings.ToLower(args[0])
		return InstallService(role)
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall [socket|node]",
	Short: "Stop, disable, and remove the systemd service",
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
			return runSystemctl(action, "fabric-"+strings.ToLower(args[0]))
		},
	}
}

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(newServiceActionCmd("start", "Start the fabric systemd service"))
	serviceCmd.AddCommand(newServiceActionCmd("stop", "Stop the fabric systemd service"))
	serviceCmd.AddCommand(newServiceActionCmd("restart", "Restart the fabric systemd service"))
	serviceCmd.AddCommand(newServiceActionCmd("status", "Check the status of the fabric systemd service"))
	serviceCmd.AddCommand(serviceUninstallCmd)
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

	// Copy into /etc/systemd/system and set permissions
	if err := runPrivilegedCommand("cp", tmpFile.Name(), unitPath); err != nil {
		return fmt.Errorf("copying unit file to %s: %w", unitPath, err)
	}
	if err := runPrivilegedCommand("chmod", "644", unitPath); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", unitPath, err)
	}

	fmt.Printf("[+] Installed %s\n", unitPath)

	// Daemon reload & enable
	if err := runPrivilegedCommand("systemctl", "daemon-reload"); err != nil {
		fmt.Printf("[!] Warning: systemctl daemon-reload failed: %v\n", err)
	}
	if err := runPrivilegedCommand("systemctl", "enable", "--now", serviceName); err != nil {
		fmt.Printf("[!] Warning: Could not enable service automatically: %v\n", err)
	} else {
		fmt.Printf("[+] Service %s enabled and started!\n", serviceName)
	}

	return nil
}

func UninstallService(role string) error {
	serviceName := "fabric-" + role
	unitPath := filepath.Join("/etc/systemd/system", serviceName+".service")

	_ = runPrivilegedCommand("systemctl", "stop", serviceName)
	_ = runPrivilegedCommand("systemctl", "disable", serviceName)
	_ = runPrivilegedCommand("rm", "-f", unitPath)
	_ = runPrivilegedCommand("systemctl", "daemon-reload")

	fmt.Printf("[+] Uninstalled service %s\n", serviceName)
	return nil
}

func runSystemctl(action, service string) error {
	return runPrivilegedCommand("systemctl", action, service)
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
