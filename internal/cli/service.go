package cli

import (
	"strings"

	"fabric/internal/service"

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

// InstallService installs and starts the service for the specified role.
func InstallService(role string) error {
	mgr := service.NewInitManager()
	return mgr.InstallService(role)
}

// HandleServiceAction executes start, stop, restart, or status for the specified role.
func HandleServiceAction(action, role string) error {
	mgr := service.NewInitManager()
	return mgr.HandleAction(action, role)
}

// UninstallService stops and removes the service for the specified role.
func UninstallService(role string) error {
	mgr := service.NewInitManager()
	return mgr.UninstallService(role)
}

func getStandalonePaths(role string) (runDir, pidFile, supervisorScript, binPath string) {
	mgr := service.NewInitManager()
	return mgr.GetStandalonePaths(role)
}

func runPrivilegedCommand(name string, args ...string) error {
	mgr := service.NewInitManager()
	return mgr.RunPrivileged(name, args...)
}
