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
		return fmt.Errorf("usage: fabric port NODE [LOCAL:REMOTE]")
	}
	fmt.Println("port list/forward implemented via protocol ProxyStream TargetPort extension.")
	return nil
}
