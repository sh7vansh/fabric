package cli

import (
	"encoding/json"
	"fabric/internal/protocol"
	"fmt"
	"os"
	"text/tabwriter"
	"text/template"
	"time"

	"github.com/spf13/cobra"
)

var quietFlag bool
var formatFlag string

func init() {
	nodeLsCmd.Flags().BoolVarP(&quietFlag, "quiet", "q", false, "Only display numeric IDs")
	nodeLsCmd.Flags().StringVar(&formatFlag, "format", "", "Pretty-print nodes using a Go template or json")

	// psCmd shares flags
	psCmd.Flags().BoolVarP(&quietFlag, "quiet", "q", false, "Only display numeric IDs")
	psCmd.Flags().StringVar(&formatFlag, "format", "", "Pretty-print nodes using a Go template or json")

	nodeLsCmd.RunE = runNodeLs
	psCmd.RunE = runNodeLs
}

func runNodeLs(cmd *cobra.Command, args []string) error {
	client := NewClient(GetConfig())
	resp, err := client.DoHTTP("GET", "/nodes", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var nodes []protocol.NodeMetadata
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		return err
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
	fmt.Fprintln(w, "NODE ID\tHOSTNAME\tSTATUS\tIP\tDOMAIN\tUPTIME")
	for _, n := range nodes {
		uptime := ""
		if t, err := time.Parse(time.RFC3339, n.ConnectedAt); err == nil {
			uptime = time.Since(t).Round(time.Second).String()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.Hostname, n.Status, n.RemoteIP, n.Domain, uptime)
	}
	w.Flush()
	return nil
}
