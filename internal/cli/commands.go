package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var execCmd = &cobra.Command{
	Use:     "exec [flags] TARGET COMMAND [ARG...]",
	Short:   "Execute a command or interactive shell on a remote node",
	GroupID: "core",
	Long: `Execute commands directly on remote nodes or attach an interactive pseudo-terminal (PTY) session.

Stdout and stderr are streamed back in real time. When interactive/PTY flags are passed,
terminal raw mode is configured for a native shell experience.`,
	Example: `  # Run a single non-interactive command
  fabric exec worker-1 uptime

  # Launch an interactive bash session with PTY allocation
  fabric exec -i -t worker-1 /bin/bash

  # Run with custom environment variables and working directory
  fabric exec -e APP_ENV=production -w /opt/app worker-1 ./start.sh

  # Run a long-running process in detached background mode
  fabric exec -d worker-1 /usr/local/bin/backup.sh`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("exec not implemented")
	},
}

var psCmd = &cobra.Command{
	Use:     "ps [flags]",
	Short:   "List active nodes (convenience alias for 'node ls')",
	GroupID: "core",
	Example: `  # List all active nodes in the mesh
  fabric ps

  # Show only node IDs
  fabric ps -q`,
}

var cpCmd = &cobra.Command{
	Use:     "cp [flags] SRC_PATH DEST_PATH",
	Short:   "Copy files/folders between a node and the local filesystem",
	GroupID: "core",
	Long: `Stream files and directories between the local machine and remote fabric nodes.

Paths targeting remote nodes use the format: <node>:<path> (e.g. worker-1:/var/log).
Transfers are compressed and streamed incrementally as Tar chunks over WebSocket envelopes.`,
	Example: `  # Upload a local directory to a remote node
  fabric cp ./dist/ worker-1:/var/www/html/

  # Download a remote file to the local directory
  fabric cp worker-1:/var/log/syslog ./syslog.log`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("cp not implemented")
	},
}

var portCmd = &cobra.Command{
	Use:     "port NODE [LOCAL_PORT:REMOTE_PORT]",
	Short:   "List port mappings or forward a TCP port across the mesh",
	GroupID: "network",
	Long: `Forward local TCP ports through the mesh relay directly to target nodes,
allowing access to private services without opening firewall ports.`,
	Example: `  # Inspect exposed port status on worker-1
  fabric port worker-1

  # Forward local port 8080 to remote port 80 on worker-1
  fabric port worker-1 8080:80

  # Forward local port 3000 to remote port 3000
  fabric port worker-1 3000:3000`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("port not implemented")
	},
}

var nodeLsCmd = &cobra.Command{
	Use:   "ls [flags]",
	Short: "List all online nodes connected to the mesh",
	Example: `  # Table view of active nodes
  fabric node ls

  # Output in JSON format
  fabric node ls --format json

  # Display only node IDs
  fabric node ls -q`,
}

var nodeInspectCmd = &cobra.Command{
	Use:   "inspect NODE [NODE...]",
	Short: "Display detailed information and telemetry for one or more nodes",
	Example: `  # Inspect worker-1
  fabric node inspect worker-1

  # Inspect multiple nodes
  fabric node inspect worker-1 worker-2`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("node inspect not implemented")
	},
}

// Global flags for exec (populated later by ticket 007)
var (
	execPty         bool
	execInteractive bool
	execDetached    bool
	execEnv         []string
	execWorkdir     string
	execUser        string
)

func init() {
	execCmd.Flags().BoolVarP(&execInteractive, "interactive", "i", false, "Keep STDIN open even if not attached")
	execCmd.Flags().BoolVarP(&execPty, "tty", "t", false, "Allocate a pseudo-TTY")
	execCmd.Flags().BoolVarP(&execDetached, "detach", "d", false, "Run command in background")
	execCmd.Flags().StringArrayVarP(&execEnv, "env", "e", []string{}, "Set environment variables")
	execCmd.Flags().StringVarP(&execWorkdir, "workdir", "w", "", "Working directory inside the node")
	execCmd.Flags().StringVarP(&execUser, "user", "u", "", "Username or UID")

}
