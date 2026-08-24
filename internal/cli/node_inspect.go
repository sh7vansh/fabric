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
		resp, err := client.DoHTTP("GET", "/nodes/"+nodeName, nil)
		if err != nil {
			return fmt.Errorf("error inspecting node %s: %w", nodeName, err)
		}
		if resp.StatusCode == 404 {
			resp.Body.Close()
			return fmt.Errorf("node not found: %s", nodeName)
		}

		var meta protocol.NodeMetadata
		err = json.NewDecoder(resp.Body).Decode(&meta)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("error decoding response for node %s: %w", nodeName, err)
		}
		results = append(results, meta)
	}

	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
