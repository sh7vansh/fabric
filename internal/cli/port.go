package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var portCmd = &cobra.Command{
	Use:     "port THREAD [LOCAL_PORT:REMOTE_PORT]",
	Short:   "List port mappings or forward a TCP port across the Fabric",
	GroupID: "core",
	Long: `Forward local TCP ports through the Fabric relay directly to target threads,
allowing access to private services without opening firewall ports.`,
	Example: `  # Inspect exposed port status on worker-1
  fabric port worker-1

  # Forward local port 8080 to remote port 80 on worker-1
  fabric port worker-1 8080:80

  # Forward local port 3000 to remote port 3000
  fabric port worker-1 3000:3000`,
}

func init() {
	portCmd.RunE = runPort
}

func runPort(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: fabric port THREAD [LOCAL_PORT:REMOTE_PORT]")
	}

	threadName := args[0]
	client := NewClient(GetConfig())

	if len(args) == 1 {
		// Inspection mode
		meta, err := client.GetNode(threadName)
		if err != nil {
			return err
		}

		domain := meta.Domain
		if domain == "" {
			domain = "fabric.mesh"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "80/tcp -> http://%s.%s:80\n", meta.Hostname, domain)
		return nil
	}

	// Forwarding tunnel mode: LOCAL:REMOTE
	localPort, remotePort, err := ParsePortSpec(args[1])
	if err != nil {
		return err
	}

	return client.ForwardPort(threadName, localPort, remotePort)
}
