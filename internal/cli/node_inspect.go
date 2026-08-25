package cli

import (
	"encoding/json"
	"fabric/internal/protocol"
	"fmt"

	"github.com/spf13/cobra"
)

var threadInspectCmd = &cobra.Command{
	Use:   "inspect THREAD [THREAD...]",
	Short: "Display detailed information and telemetry for one or more threads",
	Example: `  # Inspect worker-1
  fabric thread inspect worker-1

  # Inspect multiple threads
  fabric thread inspect worker-1 worker-2`,
	RunE: runThreadInspect,
}

func init() {
	nodeInspectCmd.RunE = func(cmd *cobra.Command, args []string) error {
		WarnDeprecated("fabric node inspect", "fabric thread inspect")
		return runThreadInspect(cmd, args)
	}
}

func runThreadInspect(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: fabric thread inspect THREAD [THREAD...]")
	}

	client := NewClient(GetConfig())
	var results []protocol.NodeMetadata

	for _, threadName := range args {
		meta, err := client.GetNode(threadName)
		if err != nil {
			return err
		}
		results = append(results, *meta)
	}

	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(b))
	return nil
}
