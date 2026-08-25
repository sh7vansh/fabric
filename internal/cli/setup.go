package cli

import (
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:        "setup [flags]",
	Short:      "Interactive setup wizard (deprecated, use 'fabric init')",
	GroupID:    "system",
	Deprecated: "use 'fabric init' instead.",
	RunE: func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric setup", "fabric init")
		return runInit(cmd, args)
	},
}

func init() {
	setupCmd.Flags().StringVarP(&initServerFlag, "server", "s", "", "Fabric server WebSocket URL")
	setupCmd.Flags().StringVarP(&initHostFlag, "host", "H", "", "Server URL (deprecated, use --server)")
	setupCmd.Flags().StringVar(&initTokenFlag, "token", "", "Pre-shared cluster token")
	setupCmd.Flags().StringVar(&initDomainFlag, "domain", "fabric.mesh", "Domain for Fabric DNS")
	setupCmd.Flags().BoolVar(&initAutoToken, "auto-token", false, "Auto-generate a secure random token")
	setupCmd.Flags().BoolVarP(&initNonInteract, "yes", "y", false, "Accept all defaults non-interactively")
	setupCmd.Flags().BoolVar(&initTrustCA, "trust-ca", false, "Install Fabric Root CA into system trust store")
	setupCmd.Flags().BoolVar(&initUntrustCA, "untrust-ca", false, "Remove Fabric Root CA from system trust store")
}
