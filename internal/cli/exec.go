package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

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
	execCmd.Flags().StringVarP(&execWorkdir, "workdir", "w", "", "Working directory inside the thread")
	execCmd.Flags().StringVarP(&execUser, "user", "u", "", "Username or UID")
	execCmd.Flags().BoolVarP(&execAll, "all", "a", false, "Execute across all connected threads in parallel")
	execCmd.Flags().StringVarP(&execTag, "tag", "l", "", "Filter target threads by tag")
	execCmd.Flags().IntVarP(&execConcurrency, "concurrency", "c", 10, "Maximum concurrent execution worker pool limit")

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
		return fmt.Errorf("usage: fabric exec [flags] THREAD COMMAND [ARG...]")
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
	fmt.Fprintln(w, "THREAD\tSTATUS\tEXIT CODE\tDURATION")
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
