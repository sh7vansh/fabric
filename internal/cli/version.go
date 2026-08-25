package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the current semantic release version of Fabric.
var Version = "2.3.1"

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Show Fabric version information for CLI and server",
	GroupID: "system",
	Example: `  # Display CLI version and query server version
  fabric version`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("CLI Version: %s\n", Version)

		client := NewClient(GetConfig())
		resp, err := client.DoHTTP("GET", "/version", nil)
		if err != nil {
			fmt.Printf("Server Version: <unreachable: %v>\n", err)
			return nil
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			if len(client.Config.DirectNodes) > 0 {
				fmt.Printf("Server Version: <not configured: direct mTLS mode>\n")
			} else {
				fmt.Printf("Server Version: <offline>\n")
			}
			return nil
		}

		var ver struct {
			Version string `json:"version"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&ver); err != nil {
			fmt.Printf("Server Version: <invalid response>\n")
			return nil
		}
		fmt.Printf("Server Version: %s\n", ver.Version)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
