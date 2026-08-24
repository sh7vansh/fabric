package cli

import (
	"encoding/json"
	"fabric/internal/protocol"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	nodeInspectCmd.RunE = runNodeInspect
}

func runNodeInspect(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: fabric node inspect NODE [NODE...]")
	}

	client := NewClient(GetConfig())
	var results []protocol.NodeMetadata

	for _, nodeName := range args {
		meta, err := client.GetNode(nodeName)
		if err != nil {
			return err
		}
		results = append(results, *meta)
	}

	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
