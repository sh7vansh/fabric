package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	execCmd.RunE = runExec
}

func runExec(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: fabric exec [flags] TARGET COMMAND [ARG...]")
	}
	target := args[0]
	command := strings.Join(args[1:], " ")

	client := NewClient(GetConfig())
	opts := ExecOptions{
		Target:      target,
		Command:     command,
		AllocatePTY: execPty,
		Interactive: execInteractive,
		Detached:    execDetached,
		Env:         execEnv,
		WorkDir:     execWorkdir,
		User:        execUser,
	}

	return client.Execute(opts, os.Stdin, os.Stdout, os.Stderr)
}
