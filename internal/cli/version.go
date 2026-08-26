package cli

import (
	"encoding/json"
	"fmt"

	"fabric/internal/version"

	"github.com/spf13/cobra"
)

// Version is an alias to the canonical version module definition.
var Version = version.Version

type ServerVersionInfo struct {
	Version         string `json:"version"`
	GitCommit       string `json:"git_commit,omitempty"`
	BuildDate       string `json:"build_date,omitempty"`
	GoVersion       string `json:"go_version,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	Domain          string `json:"domain,omitempty"`
	Role            string `json:"role,omitempty"`
	ServerID        string `json:"server_id,omitempty"`
	GatewayID       string `json:"gateway_id,omitempty"`
	Region          string `json:"region,omitempty"`
}

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Show Fabric version and build telemetry for CLI and server",
	GroupID: "system",
	Example: `  # Display CLI and Server build details
  fabric version`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := version.GetBuildInfo()
		fmt.Println("Fabric CLI:")
		fmt.Printf("  Version:          %s\n", info.Version)
		fmt.Printf("  Git Commit:       %s\n", info.GitCommit)
		fmt.Printf("  Build Date:       %s\n", info.BuildDate)
		fmt.Printf("  Go Version:       %s\n", info.GoVersion)
		fmt.Printf("  Protocol Version: %s\n", info.ProtocolVersion)
		fmt.Printf("  OS/Arch:          %s/%s\n", info.OS, info.Arch)

		client := NewClient(GetConfig())
		resp, err := client.DoHTTP("GET", "/version", nil)
		if err != nil {
			fmt.Printf("\nFabric Server:\n  Status:           <unreachable: %v>\n", err)
			return nil
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			if len(client.Config.DirectNodes) > 0 {
				fmt.Printf("\nFabric Server:\n  Status:           <not configured: direct mTLS mode>\n")
			} else {
				fmt.Printf("\nFabric Server:\n  Status:           <offline: HTTP %d>\n", resp.StatusCode)
			}
			return nil
		}

		var srvVer ServerVersionInfo
		if err := json.NewDecoder(resp.Body).Decode(&srvVer); err != nil {
			fmt.Printf("\nFabric Server:\n  Status:           <invalid response>\n")
			return nil
		}

		srvID := srvVer.ServerID
		if srvID == "" {
			srvID = srvVer.GatewayID
		}

		fmt.Println("\nFabric Server:")
		fmt.Printf("  Version:          %s\n", srvVer.Version)
		if srvVer.ProtocolVersion != "" {
			fmt.Printf("  Protocol Version: %s\n", srvVer.ProtocolVersion)
		}
		if srvVer.GitCommit != "" {
			fmt.Printf("  Git Commit:       %s\n", srvVer.GitCommit)
		}
		if srvVer.BuildDate != "" {
			fmt.Printf("  Build Date:       %s\n", srvVer.BuildDate)
		}
		if srvVer.GoVersion != "" {
			fmt.Printf("  Go Version:       %s\n", srvVer.GoVersion)
		}
		if srvVer.Domain != "" {
			fmt.Printf("  Domain:           %s\n", srvVer.Domain)
		}
		if srvID != "" {
			fmt.Printf("  Server ID:        %s\n", srvID)
		}
		if srvVer.Region != "" {
			fmt.Printf("  Region:           %s\n", srvVer.Region)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
