package cli

import (
	"github.com/spf13/cobra"
)

var execCmd = &cobra.Command{
	Use:     "exec [flags] THREAD COMMAND [ARG...]",
	Short:   "Execute a command or interactive shell on a remote thread",
	GroupID: "core",
	Long: `Execute commands directly on remote threads or attach an interactive pseudo-terminal (PTY) session.

Stdout and stderr are streamed back in real time. When interactive/PTY flags are passed,
terminal raw mode is configured for a native shell experience.`,
	Example: `  # Run a single non-interactive command
  fabric exec worker-1 uptime

  # Launch an interactive bash session with PTY allocation
  fabric exec -i -t worker-1 /bin/bash

  # Run verification across all threads in parallel
  fabric exec --all nginx -t

  # Run on all threads matching a tag
  fabric exec -l web uptime`,
}

var psCmd = &cobra.Command{
	Use:     "ps [flags]",
	Short:   "Quick list of connected threads (shorthand for 'thread ls')",
	GroupID: "core",
	Example: `  # List all active threads in the Fabric
  fabric ps

  # Show only thread names
  fabric ps -q`,
}

var cpCmd = &cobra.Command{
	Use:     "cp [flags] SRC_PATH DEST_PATH",
	Short:   "Copy files/folders between a thread and the local filesystem",
	GroupID: "core",
	Long: `Stream files and directories between the local machine and remote fabric threads.

Paths targeting remote threads use the format: <thread>:<path> (e.g. worker-1:/var/log).
Transfers are compressed and streamed incrementally as Tar chunks over WebSocket envelopes.`,
	Example: `  # Upload a local directory to a remote thread
  fabric cp ./dist/ worker-1:/var/www/html/

  # Download a remote file to the local directory
  fabric cp worker-1:/var/log/syslog ./syslog.log`,
}

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

var nodeLsCmd = &cobra.Command{
	Use:   "ls [flags]",
	Short: "List all online nodes connected to the mesh (deprecated, use 'fabric thread ls')",
	Example: `  # Table view of active nodes
  fabric node ls

  # Output in JSON format
  fabric node ls --format json`,
}

var nodeInspectCmd = &cobra.Command{
	Use:   "inspect NODE [NODE...]",
	Short: "Display detailed information for one or more nodes (deprecated, use 'fabric thread inspect')",
	Example: `  # Inspect worker-1
  fabric node inspect worker-1`,
}

// Global flags for exec
var (
	execPty         bool
	execInteractive bool
	execDetached    bool
	execEnv         []string
	execWorkdir     string
	execUser        string
	execAll         bool
	execTag         string
	execConcurrency int
)

func init() {
	execCmd.Flags().BoolVarP(&execInteractive, "interactive", "i", false, "Keep STDIN open even if not attached")
	execCmd.Flags().BoolVarP(&execPty, "tty", "t", false, "Allocate a pseudo-TTY")
	execCmd.Flags().BoolVarP(&execDetached, "detach", "d", false, "Run command in background")
	execCmd.Flags().StringArrayVarP(&execEnv, "env", "e", []string{}, "Set environment variables")
	execCmd.Flags().StringVarP(&execWorkdir, "workdir", "w", "", "Working directory inside the node")
	execCmd.Flags().StringVarP(&execUser, "user", "u", "", "Username or UID")
	execCmd.Flags().BoolVarP(&execAll, "all", "a", false, "Execute across all connected nodes in parallel")
	execCmd.Flags().StringVarP(&execTag, "tag", "l", "", "Filter target nodes by tag")
	execCmd.Flags().IntVarP(&execConcurrency, "concurrency", "c", 10, "Maximum concurrent execution worker pool limit")
}
