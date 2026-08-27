package cli

import (
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
		mgr := GetServiceManager()
		return mgr.Install("thread", nil)
	},
}

var threadServiceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop, disable, and remove the fabric-thread service",
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := GetServiceManager()
		return mgr.Uninstall("thread")
	},
}

func newThreadServiceActionCmd(action, desc string) *cobra.Command {
	return &cobra.Command{
		Use:   action,
		Short: desc,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := GetServiceManager()
			return mgr.HandleAction(action, "thread")
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
