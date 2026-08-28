package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	serverFlag string
	hostFlag   string
	tokenFlag  string
	caCertFlag string
	remoteFlag string
	directFlag string
)

var rootCmd = &cobra.Command{
	Use:   "fabric",
	Short: "Fabric is a lightweight remote execution and service discovery mesh.",
	Long: `Fabric is a lightweight remote execution, service discovery, and networking mesh.

It connects distributed threads behind firewalls/NATs to a central Fabric server
over persistent outbound WebSocket tunnels without requiring inbound ports.`,
	Example: `  # List all connected threads in the Fabric
  fabric ps
  fabric thread ls

  # Open an interactive bash session on a remote thread
  fabric exec -i -t worker-1 /bin/bash

  # Copy files to a remote thread
  fabric cp ./app.tar.gz worker-1:/opt/app/

  # Forward a local port to a remote service on a thread
  fabric port worker-1 8080:80

  # Bootstrap a remote machine or scan subnet over SSH
  fabric stitch 192.168.1.0/24

  # Learn more about architecture, networking, threads, and workflows
  fabric help architecture
  fabric help networking
  fabric help threads
  fabric help stitch
  fabric help workflows`,
}

func init() {
	rootCmd.AddGroup(
		&cobra.Group{
			ID:    "core",
			Title: "Core Execution Commands:",
		},
		&cobra.Group{
			ID:    "threads",
			Title: "Thread Management Commands:",
		},
		&cobra.Group{
			ID:    "network",
			Title: "Mesh & Networking Commands:",
		},
		&cobra.Group{
			ID:    "system",
			Title: "System & Lifecycle Commands:",
		},
		&cobra.Group{
			ID:    "cluster",
			Title: "Cluster & Node Commands (Deprecated):",
		},
		&cobra.Group{
			ID:    "topics",
			Title: "Help Topics & Guides:",
		},
	)

	rootCmd.PersistentFlags().StringVarP(&serverFlag, "server", "s", "", "Fabric server URL to connect to (e.g. wss://localhost:8443/ws)")
	rootCmd.PersistentFlags().StringVarP(&hostFlag, "host", "H", "", "Socket URL to connect to (deprecated, use --server)")
	rootCmd.PersistentFlags().StringVar(&tokenFlag, "token", "", "Pre-shared token for authentication")
	rootCmd.PersistentFlags().StringVar(&caCertFlag, "ca-cert", "", "Path to custom Root CA certificate for TLS verification")
	rootCmd.PersistentFlags().StringVar(&remoteFlag, "remote", "", "Directly connect to a listening thread (e.g. 192.168.1.10:8443)")
	rootCmd.PersistentFlags().StringVar(&directFlag, "direct", "", "Directly connect to a listening node (deprecated, use --remote)")

	_ = rootCmd.PersistentFlags().MarkHidden("host")
	_ = rootCmd.PersistentFlags().MarkHidden("direct")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		cmd.SilenceUsage = true
	}

	rootCmd.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "Help about any command or topic",
		Long:  `Help provides help for any command in the application.`,
		Run: func(c *cobra.Command, args []string) {
			if len(args) > 0 {
				topic := strings.ToLower(args[0])
				if topic == "stitch" || topic == "stitch-guide" {
					fmt.Fprint(c.OutOrStdout(), topicStitchGuideCmd.Long)
					return
				}
			}
			cmd, _, err := c.Root().Find(args)
			if cmd == nil || err != nil {
				c.Printf("Unknown help topic %#q\n", args)
				_ = c.Root().Usage()
				return
			}
			if cmd.GroupID == "topics" {
				fmt.Fprint(c.OutOrStdout(), cmd.Long)
				return
			}
			cmd.InitDefaultHelpFlag()
			_ = cmd.Help()
		},
	})

	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(psCmd)
	rootCmd.AddCommand(cpCmd)
	rootCmd.AddCommand(portCmd)
	rootCmd.AddCommand(threadCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(configCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		var exitErr *ExitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, FormatError(err))
		os.Exit(1)
	}
}

func GetConfig() *Config {
	srv := serverFlag
	if srv == "" && hostFlag != "" {
		WarnDeprecated("--host / -H", "--server / -s")
		srv = hostFlag
	}
	rem := remoteFlag
	if rem == "" && directFlag != "" {
		WarnDeprecated("--direct", "--remote")
		rem = directFlag
	}
	return LoadConfig(srv, tokenFlag, rem, caCertFlag)
}
