package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"text/template"

	"fabric/internal/protocol"

	"github.com/spf13/cobra"
)

var (
	peerQuietFlag         bool
	peerLsFormatFlag      string
	peerInspectFormatFlag string
)

var peerCmd = &cobra.Command{
	Use:     "peer",
	Short:   "Manage server-to-server federation peers",
	GroupID: "network",
	Example: `  # List all connected server peers
  fabric peer ls

  # Connect to a remote server peer
  fabric peer add wss://core-eu.fabric.io:443

  # Disconnect a server peer
  fabric peer rm srv-eu-west

  # Inspect detailed telemetry for a peer
  fabric peer inspect srv-eu-west`,
}

var peerLsCmd = &cobra.Command{
	Use:   "ls [flags]",
	Short: "List connected server peers",
	Example: `  # Table view of active peers
  fabric peer ls

  # Output in JSON format
  fabric peer ls --format json

  # Display only peer server IDs
  fabric peer ls -q`,
	RunE: runPeerLs,
}

var peerAddCmd = &cobra.Command{
	Use:   "add <endpoint>",
	Short: "Connect to a remote server peer",
	Args:  cobra.ExactArgs(1),
	Example: `  # Connect to a core server
  fabric peer add wss://core-hub.fabric.io:443

  # Connect to an on-premise server over TLS
  fabric peer add 192.168.1.50:8443`,
	RunE: func(cmd *cobra.Command, args []string) error {
		endpoint := args[0]
		client := NewClient(GetConfig())
		if err := client.AddPeer(endpoint); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Initiated peering connection to %s\n", endpoint)
		return nil
	},
}

var peerRmCmd = &cobra.Command{
	Use:     "rm <server-id>",
	Aliases: []string{"remove", "disconnect"},
	Short:   "Disconnect and remove a server peer",
	Args:    cobra.ExactArgs(1),
	Example: `  # Disconnect peer srv-eu-west
  fabric peer rm srv-eu-west`,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverID := args[0]
		client := NewClient(GetConfig())
		if err := client.RemovePeer(serverID); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Removed peer server %s\n", serverID)
		return nil
	},
}

var peerInspectCmd = &cobra.Command{
	Use:   "inspect <server-id>",
	Short: "Detailed telemetry and routing table for a peer",
	Args:  cobra.ExactArgs(1),
	Example: `  # Inspect peer telemetry
  fabric peer inspect srv-eu-west`,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverID := args[0]
		client := NewClient(GetConfig())
		info, err := client.GetPeer(serverID)
		if err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		if peerInspectFormatFlag == "json" || peerInspectFormatFlag == "" {
			b, _ := json.MarshalIndent(info, "", "  ")
			fmt.Fprintln(out, string(b))
			return nil
		}

		tmpl, err := template.New("format").Parse(peerInspectFormatFlag)
		if err != nil {
			return err
		}
		tmpl.Execute(out, info)
		fmt.Fprintln(out)
		return nil
	},
}

func init() {
	peerLsCmd.Flags().BoolVarP(&peerQuietFlag, "quiet", "q", false, "Only display peer server IDs")
	peerLsCmd.Flags().StringVar(&peerLsFormatFlag, "format", "", "Pretty-print peers using a Go template or json")
	peerInspectCmd.Flags().StringVar(&peerInspectFormatFlag, "format", "", "Pretty-print peer using a Go template or json")

	peerCmd.AddCommand(peerLsCmd)
	peerCmd.AddCommand(peerAddCmd)
	peerCmd.AddCommand(peerRmCmd)
	peerCmd.AddCommand(peerInspectCmd)

	rootCmd.AddCommand(peerCmd)
}

func runPeerLs(cmd *cobra.Command, args []string) error {
	defer func() {
		peerQuietFlag = false
		peerLsFormatFlag = ""
	}()

	client := NewClient(GetConfig())
	peers, err := client.ListPeers()
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()

	if peerLsFormatFlag == "json" {
		if peers == nil {
			peers = []protocol.GatewayPeerInfo{}
		}
		b, _ := json.MarshalIndent(peers, "", "  ")
		fmt.Fprintln(out, string(b))
		return nil
	}

	if peerLsFormatFlag != "" {
		tmpl, err := template.New("format").Parse(peerLsFormatFlag)
		if err != nil {
			return err
		}
		for _, p := range peers {
			tmpl.Execute(out, p)
			fmt.Fprintln(out)
		}
		return nil
	}

	if peerQuietFlag {
		for _, p := range peers {
			sID := p.ServerID
			if sID == "" {
				sID = p.GatewayID
			}
			fmt.Fprintln(out, sID)
		}
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SERVER ID\tREGION\tTOPOLOGY\tRTT\tTHREADS\tSTATUS\tENDPOINT")
	for _, p := range peers {
		sID := p.ServerID
		if sID == "" {
			sID = p.GatewayID
		}
		topoStr := strings.ToUpper(p.Topology)
		if topoStr == "" {
			topoStr = "CORE"
		}
		regStr := p.Region
		if regStr == "" {
			regStr = "default"
		}
		rttStr := p.RTT
		if rttStr == "" {
			rttStr = "0ms"
		}
		epStr := p.Endpoint
		if epStr == "" {
			epStr = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", sID, regStr, topoStr, rttStr, p.ThreadCount, p.Status, epStr)
	}
	w.Flush()
	return nil
}
