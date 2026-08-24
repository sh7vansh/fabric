package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	hostFlag   string
	tokenFlag  string
	caCertFlag string
)

var rootCmd = &cobra.Command{
	Use:   "fabric",
	Short: "Fabric is a lightweight remote execution and service discovery mesh.",
	Long: `Fabric is a lightweight remote execution, service discovery, and networking mesh.

It connects distributed nodes behind firewalls/NATs to a central relay socket
over persistent outbound WebSocket tunnels without requiring inbound ports.`,
	Example: `  # List all connected nodes in the mesh
  fabric node ls

  # Open an interactive bash session on a worker node
  fabric exec -i -t worker-1 /bin/bash

  # Copy files to a remote node
  fabric cp ./app.tar.gz worker-1:/opt/app/

  # Forward a local port to a remote service
  fabric port worker-1 8080:80

  # Scan network and bootstrap remote hosts over SSH
  fabric stitch discover 192.168.1.0/24

  # Learn more about architecture, networking, and workflows
  fabric help architecture
  fabric help networking
  fabric help workflows`,
}

var nodeCmd = &cobra.Command{
	Use:     "node",
	Short:   "Manage fabric nodes",
	GroupID: "cluster",
	Example: `  # List all active online nodes
  fabric node ls

  # Show detailed telemetry and metadata for worker-1
  fabric node inspect worker-1`,
}

func init() {
	rootCmd.AddGroup(
		&cobra.Group{
			ID:    "core",
			Title: "Core Execution Commands:",
		},
		&cobra.Group{
			ID:    "network",
			Title: "Mesh & Networking Commands:",
		},
		&cobra.Group{
			ID:    "cluster",
			Title: "Node & Cluster Management Commands:",
		},
		&cobra.Group{
			ID:    "system",
			Title: "System & Service Commands:",
		},
		&cobra.Group{
			ID:    "topics",
			Title: "Help Topics & Guides:",
		},
	)

	rootCmd.PersistentFlags().StringVarP(&hostFlag, "host", "H", "", "Socket URL to connect to (e.g., ws://localhost:8080/ws)")
	rootCmd.PersistentFlags().StringVar(&tokenFlag, "token", "", "Pre-shared token for authentication")
	rootCmd.PersistentFlags().StringVar(&caCertFlag, "ca-cert", "", "Path to custom Root CA certificate for TLS verification")

	nodeCmd.GroupID = "cluster"
	setupCmd.GroupID = "cluster"

	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(psCmd)
	rootCmd.AddCommand(cpCmd)
	rootCmd.AddCommand(portCmd)
	rootCmd.AddCommand(nodeCmd)
	rootCmd.AddCommand(setupCmd)

	nodeCmd.AddCommand(nodeLsCmd)
	nodeCmd.AddCommand(nodeInspectCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func GetConfig() *Config {
	return LoadConfig(hostFlag, tokenFlag, caCertFlag)
}
