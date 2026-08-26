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

var agentCmd = &cobra.Command{
	Use:     "agent",
	Short:   "Manage background fabric-thread service (deprecated, use 'fabric thread service')",
	GroupID: "system",
	Long: `Manage the lifecycle of the local fabric-thread background daemon service unit (deprecated).

Please use 'fabric thread service' instead.`,
	Example: `  # Install and start fabric-thread as a background service
  fabric agent install

  # Inspect status of the local thread service
  fabric agent status

  # Restart the local thread service
  fabric agent restart

  # Stop the local thread service
  fabric agent stop

  # Uninstall and remove the service unit
  fabric agent uninstall`,
}

var agentInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install and enable the fabric-thread service (deprecated)",
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric agent", "fabric thread service")
		return InstallService("thread")
	},
}

var agentUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop, disable, and remove the fabric-thread service (deprecated)",
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric agent", "fabric thread service")
		return UninstallService("thread")
	},
}

func newAgentActionCmd(action, desc string) *cobra.Command {
	return &cobra.Command{
		Use:   action,
		Short: desc + " (deprecated, use 'fabric thread service " + action + "')",
		RunE: func(cmd *cobra.Command, args []string) error {
			WarnDeprecated("fabric agent", "fabric thread service")
			return HandleServiceAction(action, "thread")
		},
	}
}

func init() {
	threadServiceCmd.AddCommand(threadServiceInstallCmd)
	threadServiceCmd.AddCommand(newThreadServiceActionCmd("start", "Start the fabric-thread service"))
	threadServiceCmd.AddCommand(newThreadServiceActionCmd("stop", "Stop the fabric-thread service"))
	threadServiceCmd.AddCommand(newThreadServiceActionCmd("restart", "Restart the fabric-thread service"))
	threadServiceCmd.AddCommand(newThreadServiceActionCmd("status", "Inspect fabric-thread service status"))
	threadServiceCmd.AddCommand(threadServiceUninstallCmd)

	threadCmd.AddCommand(threadServiceCmd)

	agentCmd.AddCommand(agentInstallCmd)
	agentCmd.AddCommand(newAgentActionCmd("start", "Start the fabric-thread service"))
	agentCmd.AddCommand(newAgentActionCmd("stop", "Stop the fabric-thread service"))
	agentCmd.AddCommand(newAgentActionCmd("restart", "Restart the fabric-thread service"))
	agentCmd.AddCommand(newAgentActionCmd("status", "Inspect fabric-thread service status"))
	agentCmd.AddCommand(agentUninstallCmd)
}
