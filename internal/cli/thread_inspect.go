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
	threadInspectFormatFlag string
	threadInspectOutputFlag string
)

var threadInspectCmd = &cobra.Command{
	Use:   "inspect THREAD [THREAD...]",
	Short: "Display detailed information and telemetry for one or more threads",
	Example: `  # Inspect worker-1 (human-readable card view)
  fabric thread inspect worker-1

  # Inspect in JSON format
  fabric thread inspect -o json worker-1
  fabric thread inspect --format json worker-1

  # Inspect multiple threads
  fabric thread inspect worker-1 worker-2`,
	RunE: runThreadInspect,
}

func init() {
	threadInspectCmd.Flags().StringVarP(&threadInspectFormatFlag, "format", "f", "", "Output format ('json', 'table', or Go template)")
	threadInspectCmd.Flags().StringVarP(&threadInspectOutputFlag, "output", "o", "", "Output format ('json', 'table')")
}

func runThreadInspect(cmd *cobra.Command, args []string) error {
	defer func() {
		threadInspectFormatFlag = ""
		threadInspectOutputFlag = ""
	}()

	if len(args) < 1 {
		return fmt.Errorf("usage: fabric thread inspect THREAD [THREAD...]")
	}

	client := NewClient(GetConfig())
	var results []protocol.NodeMetadata

	for _, threadName := range args {
		meta, err := client.GetNode(threadName)
		if err != nil {
			return err
		}
		results = append(results, *meta)
	}

	isJSON := strings.ToLower(threadInspectFormatFlag) == "json" || strings.ToLower(threadInspectOutputFlag) == "json"
	if isJSON {
		b, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return nil
	}

	templateFmt := threadInspectFormatFlag
	if templateFmt == "" && threadInspectOutputFlag != "" && threadInspectOutputFlag != "table" && threadInspectOutputFlag != "json" {
		templateFmt = threadInspectOutputFlag
	}
	if templateFmt != "" && templateFmt != "table" {
		tmpl, err := template.New("format").Parse(templateFmt + "\n")
		if err != nil {
			return fmt.Errorf("invalid format template: %w", err)
		}
		for _, n := range results {
			if err := tmpl.Execute(cmd.OutOrStdout(), n); err != nil {
				return err
			}
		}
		return nil
	}

	out := cmd.OutOrStdout()
	for i, n := range results {
		if i > 0 {
			fmt.Fprintln(out, "")
		}
		displayName := n.ThreadName
		if displayName == "" {
			displayName = n.Hostname
		}
		if displayName == "" {
			displayName = n.ID
		}
		statusBadge := strings.ToUpper(n.Status)
		if statusBadge == "ONLINE" {
			statusBadge = "[ONLINE]"
		} else if statusBadge != "" && !strings.HasPrefix(statusBadge, "[") {
			statusBadge = "[" + statusBadge + "]"
		}
		fmt.Fprintln(out, "==================================================")
		fmt.Fprintf(out, "  Thread: %s %s\n", displayName, statusBadge)
		fmt.Fprintln(out, "==================================================")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  Hostname:\t%s\n", n.Hostname)
		if n.SessionID != "" {
			fmt.Fprintf(w, "  Session ID:\t%s\n", n.SessionID)
		}
		domainStr := n.Domain
		if domainStr == "" {
			domainStr = "fabric.mesh"
		}
		fmt.Fprintf(w, "  Domain:\t%s\n", domainStr)
		platform := "-"
		if n.OS != "" && n.Arch != "" {
			platform = n.OS + "/" + n.Arch
		} else if n.OS != "" {
			platform = n.OS
		} else if n.Arch != "" {
			platform = n.Arch
		}
		fmt.Fprintf(w, "  OS / Arch:\t%s\n", platform)
		if n.Version != "" {
			fmt.Fprintf(w, "  Version:\t%s\n", n.Version)
		}
		fmt.Fprintf(w, "  Remote IP:\t%s\n", n.RemoteIP)
		fmt.Fprintf(w, "  Status:\t%s\n", n.Status)
		serverID := n.ServerID
		if serverID == "" {
			serverID = n.GatewayID
		}
		if serverID == "" {
			serverID = "local"
		}
		fmt.Fprintf(w, "  Server ID:\t%s\n", serverID)
		tagsStr := "-"
		if len(n.Tags) > 0 {
			tagsStr = strings.Join(n.Tags, ", ")
		}
		fmt.Fprintf(w, "  Tags:\t%s\n", tagsStr)
		if n.ConnectedAt != "" {
			connStr := n.ConnectedAt
			if t, err := time.Parse(time.RFC3339, n.ConnectedAt); err == nil {
				connStr = fmt.Sprintf("%s (%s ago)", n.ConnectedAt, time.Since(t).Round(time.Second).String())
			}
			fmt.Fprintf(w, "  Connected At:\t%s\n", connStr)
		}
		if n.LastSeen != "" {
			lastSeenStr := n.LastSeen
			if t, err := time.Parse(time.RFC3339, n.LastSeen); err == nil {
				lastSeenStr = fmt.Sprintf("%s (%s ago)", n.LastSeen, time.Since(t).Round(time.Second).String())
			}
			fmt.Fprintf(w, "  Last Seen:\t%s\n", lastSeenStr)
		}
		w.Flush()
		fmt.Fprintln(out, "==================================================")
	}
	return nil
}
