package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

var (
	depMu             sync.Mutex
	deprecationWriter io.Writer = os.Stderr
)

// SetDeprecationWriter overrides the destination for deprecation warnings (useful for tests).
func SetDeprecationWriter(w io.Writer) {
	depMu.Lock()
	defer depMu.Unlock()
	deprecationWriter = w
}

// WarnDeprecated prints a standardized deprecation notice to stderr.
func WarnDeprecated(deprecated, replacement string) {
	depMu.Lock()
	defer depMu.Unlock()
	if deprecationWriter != nil {
		fmt.Fprintf(deprecationWriter, "Warning: '%s' is deprecated. Use '%s' instead.\n", deprecated, replacement)
	}
}

// Deprecated node commands
var nodeCmd = &cobra.Command{
	Use:     "node",
	Short:   "Manage fabric nodes (deprecated, use 'fabric thread')",
	Hidden:  true,
	Example: `  # List all active online nodes
  fabric node ls

  # Show detailed telemetry and metadata for worker-1
  fabric node inspect worker-1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric node", "fabric thread")
		return runThreadLs(cmd, args)
	},
}

var nodeLsCmd = &cobra.Command{
	Use:    "ls [flags]",
	Short:  "List all online nodes connected to the mesh (deprecated, use 'fabric thread ls')",
	Hidden: true,
	Example: `  # Table view of active nodes
  fabric node ls

  # Output in JSON format
  fabric node ls --format json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric node ls", "fabric thread ls")
		return runThreadLs(cmd, args)
	},
}

var nodeInspectCmd = &cobra.Command{
	Use:    "inspect NODE [NODE...]",
	Short:  "Display detailed information for one or more nodes (deprecated, use 'fabric thread inspect')",
	Hidden: true,
	Example: `  # Inspect worker-1
  fabric node inspect worker-1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric node inspect", "fabric thread inspect")
		return runThreadInspect(cmd, args)
	},
}

// Deprecated agent commands
var agentCmd = &cobra.Command{
	Use:     "agent",
	Short:   "Manage background fabric-thread service (deprecated, use 'fabric thread service')",
	GroupID: "system",
	Hidden:  true,
	Long: `Manage the lifecycle of the local fabric-thread background daemon service unit (deprecated).

Please use 'fabric thread service' instead.`,
	Example: `  # Install and start fabric-thread as a background service
  fabric thread service install

  # Check the status of the local thread service
  fabric thread service status`,
}

var agentInstallCmd = &cobra.Command{
	Use:    "install",
	Short:  "Install and enable service (deprecated, use 'fabric thread service install')",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric agent", "fabric thread service")
		mgr := GetServiceManager()
		return mgr.Install("thread", nil)
	},
}

var agentUninstallCmd = &cobra.Command{
	Use:    "uninstall",
	Short:  "Stop, disable, and remove service (deprecated, use 'fabric thread service uninstall')",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric agent", "fabric thread service")
		mgr := GetServiceManager()
		return mgr.Uninstall("thread")
	},
}

func newAgentActionCmd(action, desc string) *cobra.Command {
	return &cobra.Command{
		Use:    action,
		Short:  desc + " (deprecated, use 'fabric thread service " + action + "')",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			WarnDeprecated("fabric agent", "fabric thread service")
			mgr := GetServiceManager()
			return mgr.HandleAction(action, "thread")
		},
	}
}

// Deprecated service commands
var serviceCmd = &cobra.Command{
	Use:        "service",
	Short:      "Manage background service units (deprecated, use 'fabric thread service')",
	GroupID:    "system",
	Hidden:     true,
	Deprecated: "use 'fabric thread service' instead.",
	Long: `Manage the lifecycle of background service units (deprecated).

Please use 'fabric thread service' instead.`,
	Example: `  # Install and start fabric-thread as a background service
  fabric thread service install

  # Check the status of the local thread service
  fabric thread service status`,
}

func normalizeServiceRole(args []string) string {
	role := "thread"
	if len(args) > 0 {
		role = strings.ToLower(args[0])
	}
	switch role {
	case "node", "agent":
		return "thread"
	case "socket", "hub":
		return "server"
	default:
		return role
	}
}

var serviceInstallCmd = &cobra.Command{
	Use:    "install [role]",
	Short:  "Install and enable service (deprecated, use 'fabric thread service install')",
	Hidden: true,
	Args:   cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric service", "fabric thread service")
		mgr := GetServiceManager()
		return mgr.Install(normalizeServiceRole(args), nil)
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:    "uninstall [role]",
	Short:  "Stop, disable, and remove service (deprecated, use 'fabric thread service uninstall')",
	Hidden: true,
	Args:   cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric service", "fabric thread service")
		mgr := GetServiceManager()
		return mgr.Uninstall(normalizeServiceRole(args))
	},
}

func newServiceActionCmd(action, desc string) *cobra.Command {
	return &cobra.Command{
		Use:    action + " [role]",
		Short:  desc + " (deprecated, use 'fabric thread service " + action + "')",
		Hidden: true,
		Args:   cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			WarnDeprecated("fabric service", "fabric thread service")
			mgr := GetServiceManager()
			return mgr.HandleAction(action, normalizeServiceRole(args))
		},
	}
}

// Deprecated setup command
var setupCmd = &cobra.Command{
	Use:        "setup [flags]",
	Short:      "Interactive setup wizard (deprecated, use 'fabric init')",
	GroupID:    "system",
	Hidden:     true,
	Deprecated: "use 'fabric init' instead.",
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric setup", "fabric init")
		return runInit(cmd, args)
	},
}

func init() {
	// Register flags for deprecated node commands
	registerThreadListingFlags(nodeLsCmd)
	nodeInspectCmd.Flags().StringVarP(&threadInspectFormatFlag, "format", "f", "", "Output format ('json', 'table', or Go template)")
	nodeInspectCmd.Flags().StringVarP(&threadInspectOutputFlag, "output", "o", "", "Output format ('json', 'table')")

	nodeCmd.AddCommand(nodeLsCmd)
	nodeCmd.AddCommand(nodeInspectCmd)

	// Register agent subcommands
	agentCmd.AddCommand(agentInstallCmd)
	agentCmd.AddCommand(newAgentActionCmd("start", "Start the service"))
	agentCmd.AddCommand(newAgentActionCmd("stop", "Stop the service"))
	agentCmd.AddCommand(newAgentActionCmd("restart", "Restart the service"))
	agentCmd.AddCommand(newAgentActionCmd("status", "Check the status of the service"))
	agentCmd.AddCommand(agentUninstallCmd)

	// Register service subcommands
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(newServiceActionCmd("start", "Start the service"))
	serviceCmd.AddCommand(newServiceActionCmd("stop", "Stop the service"))
	serviceCmd.AddCommand(newServiceActionCmd("restart", "Restart the service"))
	serviceCmd.AddCommand(newServiceActionCmd("status", "Check the status of the service"))
	serviceCmd.AddCommand(serviceUninstallCmd)

	// Register flags for setup
	setupCmd.Flags().StringVarP(&initServerFlag, "server", "s", "", "Fabric server WebSocket URL")
	setupCmd.Flags().StringVarP(&initHostFlag, "host", "H", "", "Server URL (deprecated, use --server)")
	setupCmd.Flags().StringVar(&initTokenFlag, "token", "", "Pre-shared cluster token")
	setupCmd.Flags().StringVar(&initDomainFlag, "domain", "fabric.mesh", "Domain for Fabric DNS")
	setupCmd.Flags().BoolVar(&initAutoToken, "auto-token", false, "Auto-generate a secure random token")
	setupCmd.Flags().BoolVarP(&initNonInteract, "yes", "y", false, "Accept all defaults non-interactively")
	setupCmd.Flags().BoolVar(&initTrustCA, "trust-ca", false, "Install Fabric Root CA into system trust store")
	setupCmd.Flags().BoolVar(&initUntrustCA, "untrust-ca", false, "Remove Fabric Root CA from system trust store")

	_ = setupCmd.Flags().MarkHidden("host")

	// Wire deprecated commands to rootCmd
	rootCmd.AddCommand(nodeCmd)
	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(serviceCmd)
	rootCmd.AddCommand(setupCmd)
}
