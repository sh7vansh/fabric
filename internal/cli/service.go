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
	Use:   "service",
	Short: "Manage systemd service units for Fabric Socket and Node",
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

var serviceStartCmd = &cobra.Command{
	Use:   "start [socket|node]",
	Short: "Start the fabric systemd service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSystemctl("start", "fabric-"+strings.ToLower(args[0]))
	},
}

var serviceStopCmd = &cobra.Command{
	Use:   "stop [socket|node]",
	Short: "Stop the fabric systemd service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSystemctl("stop", "fabric-"+strings.ToLower(args[0]))
	},
}

var serviceRestartCmd = &cobra.Command{
	Use:   "restart [socket|node]",
	Short: "Restart the fabric systemd service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSystemctl("restart", "fabric-"+strings.ToLower(args[0]))
	},
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status [socket|node]",
	Short: "Check the status of the fabric systemd service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSystemctl("status", "fabric-"+strings.ToLower(args[0]))
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

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(serviceStartCmd)
	serviceCmd.AddCommand(serviceStopCmd)
	serviceCmd.AddCommand(serviceRestartCmd)
	serviceCmd.AddCommand(serviceStatusCmd)
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

	var envFile string
	if role == "socket" {
		envFile = "/etc/fabric/socket.env"
	} else {
		envFile = "/etc/fabric/node.env"
	}

	unitContent := fmt.Sprintf(`[Unit]
Description=Fabric Mesh Network %s
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-%s
EnvironmentFile=-%%h/.fabric/%s.env
ExecStart=%s
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, strings.Title(role), envFile, role, binPath)

	unitPath := filepath.Join("/etc/systemd/system", serviceName+".service")
	sudo := getSudoPrefix()

	tmpFile, err := os.CreateTemp("", serviceName+"-*.service")
	if err != nil {
		return fmt.Errorf("creating temp unit file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(unitContent); err != nil {
		return fmt.Errorf("writing unit content: %w", err)
	}
	tmpFile.Close()

	// Copy into /etc/systemd/system
	cmd := exec.Command("sh", "-c", fmt.Sprintf("%s cp %s %s && %s chmod 644 %s", sudo, tmpFile.Name(), unitPath, sudo, unitPath))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("installing unit file to %s: %w", unitPath, err)
	}

	fmt.Printf("[+] Installed %s\n", unitPath)

	// Daemon reload & enable
	_ = exec.Command("sh", "-c", fmt.Sprintf("%s systemctl daemon-reload", sudo)).Run()
	if err := exec.Command("sh", "-c", fmt.Sprintf("%s systemctl enable --now %s", sudo, serviceName)).Run(); err != nil {
		fmt.Printf("[!] Warning: Could not enable service automatically: %v\n", err)
	} else {
		fmt.Printf("[+] Service %s enabled and started!\n", serviceName)
	}

	return nil
}

func UninstallService(role string) error {
	serviceName := "fabric-" + role
	unitPath := filepath.Join("/etc/systemd/system", serviceName+".service")
	sudo := getSudoPrefix()

	_ = exec.Command("sh", "-c", fmt.Sprintf("%s systemctl stop %s", sudo, serviceName)).Run()
	_ = exec.Command("sh", "-c", fmt.Sprintf("%s systemctl disable %s", sudo, serviceName)).Run()
	_ = exec.Command("sh", "-c", fmt.Sprintf("%s rm -f %s", sudo, unitPath)).Run()
	_ = exec.Command("sh", "-c", fmt.Sprintf("%s systemctl daemon-reload", sudo)).Run()

	fmt.Printf("[+] Uninstalled service %s\n", serviceName)
	return nil
}

func runSystemctl(action, service string) error {
	sudo := getSudoPrefix()
	cmd := exec.Command("sh", "-c", fmt.Sprintf("%s systemctl %s %s", sudo, action, service))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func getSudoPrefix() string {
	if os.Geteuid() == 0 {
		return ""
	}
	if _, err := exec.LookPath("sudo"); err == nil {
		return "sudo"
	}
	return ""
}
