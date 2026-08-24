package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"text/template"
	"time"

	"fabric/internal/protocol"

	"github.com/spf13/cobra"
)

var (
	quietFlag     bool
	formatFlag    string
	tagFilterFlag string
)

func registerNodeListingFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&quietFlag, "quiet", "q", false, "Only display numeric IDs")
	cmd.Flags().StringVar(&formatFlag, "format", "", "Pretty-print nodes using a Go template or json")
	cmd.Flags().StringVarP(&tagFilterFlag, "tag", "l", "", "Filter nodes by tag")
	cmd.RunE = runNodeLs
}

func init() {
	registerNodeListingFlags(nodeLsCmd)
	registerNodeListingFlags(psCmd)
}

func runNodeLs(cmd *cobra.Command, args []string) error {
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

	if formatFlag == "json" {
		b, _ := json.MarshalIndent(nodes, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	if formatFlag != "" {
		tmpl, err := template.New("format").Parse(formatFlag)
		if err != nil {
			return err
		}
		for _, n := range nodes {
			tmpl.Execute(os.Stdout, n)
			fmt.Println()
		}
		return nil
	}

	if quietFlag {
		for _, n := range nodes {
			fmt.Println(n.ID)
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NODE ID\tHOSTNAME\tSTATUS\tTAGS\tIP\tDOMAIN\tUPTIME")
	for _, n := range nodes {
		uptime := ""
		if t, err := time.Parse(time.RFC3339, n.ConnectedAt); err == nil {
			uptime = time.Since(t).Round(time.Second).String()
		}
		tagsStr := "-"
		if len(n.Tags) > 0 {
			tagsStr = strings.Join(n.Tags, ",")
		}
		domainStr := n.Domain
		if domainStr == "" {
			domainStr = "fabric.mesh"
		}
		if n.Hostname != "" && !strings.Contains(n.Hostname, ".") && !strings.HasPrefix(domainStr, n.Hostname+".") {
			domainStr = n.Hostname + "." + domainStr
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.Hostname, n.Status, tagsStr, n.RemoteIP, domainStr, uptime)
	}
	w.Flush()
	return nil
}
