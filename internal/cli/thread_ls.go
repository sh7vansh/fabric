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
	outputFlag     string
	jsonFlag       bool
	wideFlag       bool
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
  fabric thread ls --json
  fabric thread ls --format json
  fabric thread ls -o json

  # Display wide output (all columns)
  fabric thread ls -o wide
  fabric thread ls --wide

  # Filter threads by tag
  fabric thread ls -l web

  # Filter threads by peer server
  fabric thread ls --peer srv-eu-west

  # Inspect a specific thread
  fabric thread inspect worker-1`,
}

var threadLsCmd = &cobra.Command{
	Use:   "ls [flags]",
	Short: "List all connected threads",
	Example: `  # Table view of active threads
  fabric thread ls

  # Wide output with all columns
  fabric thread ls -o wide
  fabric thread ls --wide

  # Output in JSON format
  fabric thread ls --json
  fabric thread ls -o json

  # Display only thread names
  fabric thread ls -q

  # Filter by tag
  fabric thread ls -l prod

  # Filter by server
  fabric thread ls --peer srv-eu-west`,
}

func registerThreadListingFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&quietFlag, "quiet", "q", false, "Only display thread names")
	cmd.Flags().StringVarP(&outputFlag, "output", "o", "", "Output format ('wide', 'json', 'table', or Go template)")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "", "Pretty-print threads using a Go template or json")
	cmd.Flags().BoolVar(&jsonFlag, "json", false, "Output in JSON format")
	cmd.Flags().BoolVarP(&wideFlag, "wide", "w", false, "Display extended table columns")
	cmd.Flags().StringVarP(&tagFilterFlag, "tag", "l", "", "Filter threads by tag")
	cmd.Flags().StringVarP(&peerFilterFlag, "peer", "p", "", "Filter threads by server ID")
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
		outputFlag = ""
		jsonFlag = false
		wideFlag = false
		tagFilterFlag = ""
		peerFilterFlag = ""
	}()

	client := NewClient(GetConfig())
	allThreads, err := client.ListThreads()
	if err != nil {
		return err
	}

	var computeThreads []protocol.ThreadMetadata
	var controlPlaneEntry *protocol.ThreadMetadata

	for _, n := range allThreads {
		if n.ID == "socket" || strings.Contains(n.Status, "control-plane") || (len(n.Tags) == 2 && n.Tags[0] == "relay" && n.Tags[1] == "control-plane") {
			cpCopy := n
			controlPlaneEntry = &cpCopy
		} else {
			computeThreads = append(computeThreads, n)
		}
	}

	if tagFilterFlag != "" {
		var filtered []protocol.ThreadMetadata
		for _, n := range computeThreads {
			for _, t := range n.Tags {
				if t == tagFilterFlag {
					filtered = append(filtered, n)
					break
				}
			}
		}
		computeThreads = filtered
	}

	if peerFilterFlag != "" {
		var filtered []protocol.ThreadMetadata
		for _, n := range computeThreads {
			if strings.EqualFold(n.ServerID, peerFilterFlag) || strings.EqualFold(n.GatewayID, peerFilterFlag) {
				filtered = append(filtered, n)
			}
		}
		computeThreads = filtered
	}

	if quietFlag {
		for _, n := range computeThreads {
			fmt.Fprintln(cmd.OutOrStdout(), n.Hostname)
		}
		return nil
	}

	isJSON := jsonFlag || strings.ToLower(formatFlag) == "json" || strings.ToLower(outputFlag) == "json"
	if isJSON {
		b, err := json.MarshalIndent(computeThreads, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return nil
	}

	templateFmt := formatFlag
	if templateFmt == "" && outputFlag != "" && outputFlag != "wide" && outputFlag != "table" && outputFlag != "json" {
		templateFmt = outputFlag
	}
	if templateFmt != "" && templateFmt != "wide" && templateFmt != "table" {
		tmpl, err := template.New("format").Parse(templateFmt + "\n")
		if err != nil {
			return fmt.Errorf("invalid format template: %w", err)
		}
		for _, n := range computeThreads {
			if err := tmpl.Execute(cmd.OutOrStdout(), n); err != nil {
				return err
			}
		}
		return nil
	}

	out := cmd.OutOrStdout()

	// Empty state handling
	if len(computeThreads) == 0 {
		if tagFilterFlag != "" {
			fmt.Fprintf(out, "No threads found with tag %q.\nTo view all connected threads, run: fabric ps\n", tagFilterFlag)
		} else if peerFilterFlag != "" {
			fmt.Fprintf(out, "No threads found for server %q.\nTo view all connected threads, run: fabric ps\n", peerFilterFlag)
		} else {
			fmt.Fprintln(out, "No active threads connected to the Fabric.")
			fmt.Fprintln(out, "\nTo connect your first thread:")
			fmt.Fprintln(out, "  • Onboard a remote machine over SSH: fabric stitch user@<host-ip>")
			fmt.Fprintln(out, "  • Initialize a local thread daemon:  sudo fabric init --role=thread")
		}
		if controlPlaneEntry != nil {
			serverStatus := "online"
			if strings.Contains(controlPlaneEntry.Status, "unreachable") {
				serverStatus = "unreachable"
			}
			fmt.Fprintf(out, "\nControl Plane: %s (%s)\n", serverStatus, controlPlaneEntry.RemoteIP)
		}
		return nil
	}

	isWide := wideFlag || strings.ToLower(outputFlag) == "wide" || strings.ToLower(formatFlag) == "wide"

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	if isWide {
		fmt.Fprintln(w, "THREAD\tHOSTNAME\tPLATFORM\tSERVER\tSTATUS\tTAGS\tIP\tDOMAIN\tUPTIME")
		for _, n := range computeThreads {
			uptime := ""
			if t, err := time.Parse(time.RFC3339, n.ConnectedAt); err == nil {
				uptime = time.Since(t).Round(time.Second).String()
			}
			tagsStr := "-"
			if len(n.Tags) > 0 {
				tagsStr = strings.Join(n.Tags, ",")
			}
			platform := FormatPlatform(n.OS, n.Arch)
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
	} else {
		// Default 5 columns: THREAD, STATUS, PLATFORM, IP, UPTIME
		fmt.Fprintln(w, "THREAD\tSTATUS\tPLATFORM\tIP\tUPTIME")
		for _, n := range computeThreads {
			uptime := ""
			if t, err := time.Parse(time.RFC3339, n.ConnectedAt); err == nil {
				uptime = time.Since(t).Round(time.Second).String()
			}
			platform := FormatPlatform(n.OS, n.Arch)
			displayName := n.Hostname
			if displayName == "" {
				displayName = n.ID
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", displayName, n.Status, platform, n.RemoteIP, uptime)
		}
	}
	w.Flush()

	if controlPlaneEntry != nil {
		serverStatus := "online"
		if strings.Contains(controlPlaneEntry.Status, "unreachable") {
			serverStatus = "unreachable"
		}
		fmt.Fprintf(out, "\nControl Plane: %s (%s)\n", serverStatus, controlPlaneEntry.RemoteIP)
	}

	return nil
}
