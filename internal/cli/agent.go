package cli

import (
	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:     "agent",
	Short:   "Manage background fabric-agent systemd service",
	GroupID: "system",
	Long: `Manage the lifecycle of the local fabric-agent background daemon service unit.

Supports multi-tier init environments: system systemd, user systemd, and standalone supervisors.`,
	Example: `  # Install and start fabric-agent as a background service
  fabric agent install

  # Inspect status of the local agent service
  fabric agent status

  # Restart the local agent service
  fabric agent restart

  # Stop the local agent service
  fabric agent stop

  # Uninstall and remove the service unit
  fabric agent uninstall`,
}

var agentInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install and enable the fabric-agent service",
	RunE: func(cmd *cobra.Command, args []string) error {
		return InstallService("agent")
	},
}

var agentUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop, disable, and remove the fabric-agent service",
	RunE: func(cmd *cobra.Command, args []string) error {
		return UninstallService("agent")
	},
}

func newAgentActionCmd(action, desc string) *cobra.Command {
	return &cobra.Command{
		Use:   action,
		Short: desc,
		RunE: func(cmd *cobra.Command, args []string) error {
			return HandleServiceAction(action, "agent")
		},
	}
}

func init() {
	agentCmd.AddCommand(agentInstallCmd)
	agentCmd.AddCommand(newAgentActionCmd("start", "Start the fabric-agent service"))
	agentCmd.AddCommand(newAgentActionCmd("stop", "Stop the fabric-agent service"))
	agentCmd.AddCommand(newAgentActionCmd("restart", "Restart the fabric-agent service"))
	agentCmd.AddCommand(newAgentActionCmd("status", "Inspect fabric-agent service status"))
	agentCmd.AddCommand(agentUninstallCmd)
}
