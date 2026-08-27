package cli

import (
	"github.com/spf13/cobra"
)

var psCmd = &cobra.Command{
	Use:     "ps [flags]",
	Short:   "Quick list of connected threads (shorthand for 'thread ls')",
	GroupID: "core",
	Example: `  # List all active threads in the Fabric
  fabric ps

  # Show only thread names
  fabric ps -q

  # Filter by tag
  fabric ps -l prod`,
}

func init() {
	registerThreadListingFlags(psCmd)
	psCmd.RunE = runThreadLs
}
