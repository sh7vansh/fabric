package cli

import (
	"strings"

	"fabric/internal/service"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:        "service",
	Short:      "Manage background service units (deprecated, use 'fabric thread service')",
	GroupID:    "system",
	Deprecated: "use 'fabric thread service' instead.",
	Long: `Manage the lifecycle of background service units (deprecated).

Please use 'fabric thread service' instead.`,
	Example: `  # Install and start fabric-thread as a background service
  fabric thread service install

  # Check the status of the local thread service
  fabric thread service status`,
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install [role]",
	Short: "Install and enable service (deprecated, use 'fabric thread service install')",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric service", "fabric thread service")
		role := "thread"
		if len(args) > 0 {
			role = strings.ToLower(args[0])
		}
		if role == "node" || role == "agent" {
			role = "thread"
		}
		return InstallService(role)
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall [role]",
	Short: "Stop, disable, and remove service (deprecated, use 'fabric thread service uninstall')",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric service", "fabric thread service")
		role := "thread"
		if len(args) > 0 {
			role = strings.ToLower(args[0])
		}
		if role == "node" || role == "agent" {
			role = "thread"
		}
		return UninstallService(role)
	},
}

func newServiceActionCmd(action, desc string) *cobra.Command {
	return &cobra.Command{
		Use:   action + " [role]",
		Short: desc + " (deprecated, use 'fabric thread service " + action + "')",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			WarnDeprecated("fabric service", "fabric thread service")
			role := "thread"
			if len(args) > 0 {
				role = strings.ToLower(args[0])
			}
			if role == "node" || role == "agent" {
				role = "thread"
			}
			return HandleServiceAction(action, role)
		},
	}
}

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(newServiceActionCmd("start", "Start the service"))
	serviceCmd.AddCommand(newServiceActionCmd("stop", "Stop the service"))
	serviceCmd.AddCommand(newServiceActionCmd("restart", "Restart the service"))
	serviceCmd.AddCommand(newServiceActionCmd("status", "Check the status of the service"))
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

