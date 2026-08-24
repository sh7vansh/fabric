package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func init() {
	execCmd.RunE = runExec
}

func runExec(cmd *cobra.Command, args []string) error {
	client := NewClient(GetConfig())

	isFleet := execAll || execTag != ""
	if isFleet {
		if len(args) < 1 {
			return fmt.Errorf("usage: fabric exec [flags] --all|--tag <tag> COMMAND [ARG...]")
		}
		command := strings.Join(args, " ")

		opts := ExecOptions{
			Command:     command,
			All:         execAll,
			Tag:         execTag,
			Concurrency: execConcurrency,
			Detached:    execDetached,
			Env:         execEnv,
			WorkDir:     execWorkdir,
			User:        execUser,
		}

		fleetRes, err := client.Execute(opts, nil, os.Stdout, os.Stderr)
		if fleetRes != nil && len(fleetRes.Results) > 0 {
			printFleetSummary(fleetRes)
		}
		return err
	}

	// Single target mode
	if len(args) < 2 {
		return fmt.Errorf("usage: fabric exec [flags] TARGET COMMAND [ARG...]")
	}
	target := args[0]
	command := strings.Join(args[1:], " ")

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

	_, err := client.Execute(opts, os.Stdin, os.Stdout, os.Stderr)
	return err
}

func printFleetSummary(fleetRes *FleetResult) {
	fmt.Println("\n==================================================")
	fmt.Println("             Fleet Execution Summary              ")
	fmt.Println("==================================================")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NODE\tSTATUS\tEXIT CODE\tDURATION")
	for _, r := range fleetRes.Results {
		status := "SUCCESS"
		if !r.Success {
			status = "FAILED"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Node, status, r.ExitCode, r.Duration)
	}
	w.Flush()
	fmt.Println("==================================================")
	fmt.Printf("Total: %d | Succeeded: %d | Failed: %d\n\n", fleetRes.Total, fleetRes.SucceededCount, fleetRes.FailedCount)
}
