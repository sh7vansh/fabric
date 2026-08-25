package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the current semantic release version of Fabric.
var Version = "2.2.1"

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Show Fabric version information for client and socket",
	GroupID: "system",
	Example: `  # Display client version and query socket version
  fabric version`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Client Version: %s\n", Version)


		client := NewClient(GetConfig())
		resp, err := client.DoHTTP("GET", "/version", nil)
		if err != nil {
			fmt.Printf("Socket Version: <unreachable: %v>\n", err)
			return nil
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			if len(client.Config.DirectNodes) > 0 {
				fmt.Printf("Socket Version: <not configured: direct mTLS mode>\n")
			} else {
				fmt.Printf("Socket Version: <offline>\n")
			}
			return nil
		}

		var ver struct {
			Version string `json:"version"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&ver); err != nil {
			fmt.Printf("Socket Version: <invalid response>\n")
			return nil
		}
		fmt.Printf("Socket Version: %s\n", ver.Version)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
