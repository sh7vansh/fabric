package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	portCmd.RunE = runPort
}

func runPort(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: fabric port NODE [LOCAL_PORT:REMOTE_PORT]")
	}

	nodeName := args[0]
	client := NewClient(GetConfig())

	if len(args) == 1 {
		// Inspection mode
		meta, err := client.GetNode(nodeName)
		if err != nil {
			return err
		}

		domain := meta.Domain
		if domain == "" {
			domain = "fabric.mesh"
		}
		fmt.Printf("80/tcp -> http://%s.%s:80\n", meta.Hostname, domain)
		return nil
	}

	// Forwarding tunnel mode: LOCAL:REMOTE
	localPort, remotePort, err := ParsePortSpec(args[1])
	if err != nil {
		return err
	}

	return client.ForwardPort(nodeName, localPort, remotePort)
}
