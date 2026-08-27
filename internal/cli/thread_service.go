package cli

import (
	"fabric/internal/service"

	"github.com/spf13/cobra"
)

var threadServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage local fabric-thread daemon service unit",
	Long: `Manage the lifecycle of the local fabric-thread background daemon service unit.

Supports multi-tier init environments: system systemd, user systemd, and standalone supervisors.`,
	Example: `  # Install and start fabric-thread as a background service
  fabric thread service install

  # Inspect status of the local thread service
  fabric thread service status

  # Restart the local thread service
  fabric thread service restart

  # Stop the local thread service
  fabric thread service stop

  # Uninstall and remove the service unit
  fabric thread service uninstall`,
}

var threadServiceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install and enable the fabric-thread service",
	RunE: func(cmd *cobra.Command, args []string) error {
		return InstallService("thread")
	},
}

var threadServiceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop, disable, and remove the fabric-thread service",
	RunE: func(cmd *cobra.Command, args []string) error {
		return UninstallService("thread")
	},
}

func newThreadServiceActionCmd(action, desc string) *cobra.Command {
	return &cobra.Command{
		Use:   action,
		Short: desc,
		RunE: func(cmd *cobra.Command, args []string) error {
			return HandleServiceAction(action, "thread")
		},
	}
}

func init() {
	threadServiceCmd.AddCommand(threadServiceInstallCmd)
	threadServiceCmd.AddCommand(newThreadServiceActionCmd("start", "Start the fabric-thread service"))
	threadServiceCmd.AddCommand(newThreadServiceActionCmd("stop", "Stop the fabric-thread service"))
	threadServiceCmd.AddCommand(newThreadServiceActionCmd("restart", "Restart the fabric-thread service"))
	threadServiceCmd.AddCommand(newThreadServiceActionCmd("status", "Check the status of the fabric-thread service"))
	threadServiceCmd.AddCommand(threadServiceUninstallCmd)
}

// InstallService installs and starts the service for the specified role.
func InstallService(role string) error {
	mgr := service.NewInitManager()
	return mgr.InstallService(role)
}

// UninstallService stops, disables, and removes the service for the specified role.
func UninstallService(role string) error {
	mgr := service.NewInitManager()
	return mgr.UninstallService(role)
}

// HandleServiceAction executes start, stop, restart, or status for the specified role.
func HandleServiceAction(action, role string) error {
	mgr := service.NewInitManager()
	return mgr.HandleAction(action, role)
}
