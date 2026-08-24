package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show Fabric version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		clientVersion := "1.0.0"
		fmt.Printf("Client Version: %s\n", clientVersion)

		client := NewClient(GetConfig())
		resp, err := client.DoHTTP("GET", "/version", nil)
		if err != nil {
			fmt.Printf("Socket Version: <unreachable: %v>\n", err)
			return nil
		}
		defer resp.Body.Close()

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
