package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"text/template"
	"time"

	"fabric/internal/protocol"

	"github.com/spf13/cobra"
)

var (
	quietFlag      bool
	formatFlag     string
	tagFilterFlag  string
	peerFilterFlag string
)

var threadCmd = &cobra.Command{
	Use:     "thread",
	Short:   "Manage Fabric threads",
	GroupID: "threads",
	Example: `  # List all connected threads
  fabric thread ls

  # Output threads in JSON format
  fabric thread ls --format json

  # Filter threads by tag
  fabric thread ls -l web

  # Filter threads by peer gateway
  fabric thread ls --peer gw-eu-west

  # Inspect a specific thread
  fabric thread inspect worker-1`,
}

var threadLsCmd = &cobra.Command{
	Use:   "ls [flags]",
	Short: "List all connected threads",
	Example: `  # Table view of active threads
  fabric thread ls

  # Output in JSON format
  fabric thread ls --format json

  # Display only thread names
  fabric thread ls -q

  # Filter by tag
  fabric thread ls -l prod

  # Filter by gateway
  fabric thread ls --peer gw-eu-west`,
}

func registerThreadListingFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&quietFlag, "quiet", "q", false, "Only display thread names")
	cmd.Flags().StringVar(&formatFlag, "format", "", "Pretty-print threads using a Go template or json")
	cmd.Flags().StringVarP(&tagFilterFlag, "tag", "l", "", "Filter threads by tag")
	cmd.Flags().StringVarP(&peerFilterFlag, "peer", "p", "", "Filter threads by gateway ID")
}

func init() {
	registerThreadListingFlags(threadLsCmd)
	threadLsCmd.RunE = runThreadLs

	threadCmd.AddCommand(threadLsCmd)
	threadCmd.AddCommand(threadInspectCmd)
	threadCmd.AddCommand(threadServiceCmd)
}

func runThreadLs(cmd *cobra.Command, args []string) error {
	defer func() {
		quietFlag = false
		formatFlag = ""
		tagFilterFlag = ""
		peerFilterFlag = ""
	}()

	client := NewClient(GetConfig())
	nodes, err := client.ListNodes()
	if err != nil {
		return err
	}

	if tagFilterFlag != "" {
		var filtered []protocol.NodeMetadata
		for _, n := range nodes {
			for _, t := range n.Tags {
				if t == tagFilterFlag {
					filtered = append(filtered, n)
					break
				}
			}
		}
		nodes = filtered
	}

	if peerFilterFlag != "" {
		var filtered []protocol.NodeMetadata
		for _, n := range nodes {
			if strings.EqualFold(n.ServerID, peerFilterFlag) || strings.EqualFold(n.GatewayID, peerFilterFlag) {
				filtered = append(filtered, n)
			}
		}
		nodes = filtered
	}

	if quietFlag {
		for _, n := range nodes {
			fmt.Fprintln(cmd.OutOrStdout(), n.Hostname)
		}
		return nil
	}

	if formatFlag != "" {
		if strings.ToLower(formatFlag) == "json" {
			b, err := json.MarshalIndent(nodes, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(b))
			return nil
		}

		tmpl, err := template.New("format").Parse(formatFlag + "\n")
		if err != nil {
			return fmt.Errorf("invalid format template: %w", err)
		}
		for _, n := range nodes {
			if err := tmpl.Execute(cmd.OutOrStdout(), n); err != nil {
				return err
			}
		}
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "THREAD\tHOSTNAME\tPLATFORM\tSERVER\tSTATUS\tTAGS\tIP\tDOMAIN\tUPTIME")
	for _, n := range nodes {
		uptime := ""
		if t, err := time.Parse(time.RFC3339, n.ConnectedAt); err == nil {
			uptime = time.Since(t).Round(time.Second).String()
		}
		tagsStr := "-"
		if len(n.Tags) > 0 {
			tagsStr = strings.Join(n.Tags, ",")
		}
		platform := "-"
		if n.OS != "" && n.Arch != "" {
			platform = n.OS + "/" + n.Arch
		} else if n.OS != "" {
			platform = n.OS
		} else if n.Arch != "" {
			platform = n.Arch
		}
		domainStr := n.Domain
		if domainStr == "" {
			domainStr = "fabric.mesh"
		}
		if n.Hostname != "" && !strings.Contains(n.Hostname, ".") && !strings.HasPrefix(domainStr, n.Hostname+".") {
			domainStr = n.Hostname + "." + domainStr
		}
		displayName := n.Hostname
		if displayName == "" {
			displayName = n.ID
		}
		gwStr := n.ServerID
		if gwStr == "" {
			gwStr = n.GatewayID
		}
		if gwStr == "" {
			gwStr = "local"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", displayName, n.Hostname, platform, gwStr, n.Status, tagsStr, n.RemoteIP, domainStr, uptime)
	}
	w.Flush()
	return nil
}
