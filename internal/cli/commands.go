package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var execCmd = &cobra.Command{
	Use:   "exec [flags] TARGET COMMAND [ARG...]",
	Short: "Execute a command on a remote node",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("exec not implemented")
	},
}

var psCmd = &cobra.Command{
	Use:   "ps",
	Short: "List active nodes (alias for node ls)",
}

var cpCmd = &cobra.Command{
	Use:   "cp [OPTIONS] SRC_PATH DEST_PATH",
	Short: "Copy files/folders between a node and the local filesystem",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("cp not implemented")
	},
}

var portCmd = &cobra.Command{
	Use:   "port NODE [PRIVATE_PORT[/PROTO]]",
	Short: "List port mappings or forward a port",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("port not implemented")
	},
}

var nodeLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List active nodes",
}

var nodeInspectCmd = &cobra.Command{
	Use:   "inspect NODE [NODE...]",
	Short: "Display detailed information on one or more nodes",
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
