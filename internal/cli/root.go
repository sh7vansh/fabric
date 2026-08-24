package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	hostFlag  string
	tokenFlag string
)

var rootCmd = &cobra.Command{
	Use:   "fabric",
	Short: "Fabric is a lightweight remote execution and service discovery mesh.",
}

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage fabric nodes",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&hostFlag, "host", "H", "", "Socket URL to connect to (e.g., ws://localhost:8080/ws)")
	rootCmd.PersistentFlags().StringVar(&tokenFlag, "token", "", "Pre-shared token for authentication")

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
	return LoadConfig(hostFlag, tokenFlag)
}
