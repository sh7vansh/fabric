package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"fabric/internal/protocol"

	"github.com/spf13/cobra"
)

func init() {
	execCmd.RunE = runExec
}

// LinePrefixedWriter buffers streamed output chunks and prints complete lines prefixed with the node identifier.
type LinePrefixedWriter struct {
	prefix string
	out    io.Writer
	mu     *sync.Mutex
	buf    bytes.Buffer
}

func NewLinePrefixedWriter(prefix string, out io.Writer, mu *sync.Mutex) *LinePrefixedWriter {
	return &LinePrefixedWriter{
		prefix: prefix,
		out:    out,
		mu:     mu,
	}
}

func (w *LinePrefixedWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n = len(p)
	w.buf.Write(p)

	for {
		line, err := w.buf.ReadBytes('\n')
		if err != nil {
			// Incomplete line remaining in buffer
			w.buf.Write(line)
			break
		}
		fmt.Fprintf(w.out, "[%s] %s", w.prefix, string(line))
	}
	return n, nil
}

func (w *LinePrefixedWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.buf.Len() > 0 {
		fmt.Fprintf(w.out, "[%s] %s\n", w.prefix, w.buf.String())
		w.buf.Reset()
	}
}

// NodeExecResult stores execution telemetry for each targeted node.
type NodeExecResult struct {
	Node     string
	Success  bool
	ExitCode string
	Duration time.Duration
	Error    error
}

func runExec(cmd *cobra.Command, args []string) error {
	client := NewClient(GetConfig())

	// Multi-node broadcast mode (--all or --tag)
	if execAll || execTag != "" {
		if len(args) < 1 {
			return fmt.Errorf("usage: fabric exec [flags] --all|--tag <tag> COMMAND [ARG...]")
		}
		command := strings.Join(args, " ")

		allNodes, err := client.ListNodes()
		if err != nil {
			return fmt.Errorf("failed to query active mesh nodes: %w", err)
		}

		var targets []protocol.NodeMetadata
		if execTag != "" {
			for _, n := range allNodes {
				for _, t := range n.Tags {
					if t == execTag {
						targets = append(targets, n)
						break
					}
				}
			}
			if len(targets) == 0 {
				return fmt.Errorf("no active nodes found with tag %q", execTag)
			}
		} else {
			targets = allNodes
			if len(targets) == 0 {
				return fmt.Errorf("no active nodes connected to mesh")
			}
		}

		return runMultiNodeExec(client, targets, command)
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

	return client.Execute(opts, os.Stdin, os.Stdout, os.Stderr)
}

func runMultiNodeExec(client *Client, targets []protocol.NodeMetadata, command string) error {
	concurrency := execConcurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	sem := make(chan struct{}, concurrency)
	results := make([]NodeExecResult, len(targets))
	var wg sync.WaitGroup
	var outMu sync.Mutex

	for i, node := range targets {
		wg.Add(1)
		go func(idx int, targetMeta protocol.NodeMetadata) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			startTime := time.Now()
			stdoutWriter := NewLinePrefixedWriter(targetMeta.Hostname, os.Stdout, &outMu)
			stderrWriter := NewLinePrefixedWriter(targetMeta.Hostname, os.Stderr, &outMu)

			opts := ExecOptions{
				Target:      targetMeta.Hostname,
				Command:     command,
				AllocatePTY: false,
				Interactive: false,
				Detached:    execDetached,
				Env:         execEnv,
				WorkDir:     execWorkdir,
				User:        execUser,
			}

			err := client.Execute(opts, nil, stdoutWriter, stderrWriter)
			stdoutWriter.Flush()
			stderrWriter.Flush()

			duration := time.Since(startTime).Round(time.Millisecond)

			res := NodeExecResult{
				Node:     targetMeta.Hostname,
				Duration: duration,
			}

			if err != nil {
				res.Success = false
				res.Error = err
				if strings.HasPrefix(err.Error(), "exit code ") {
					res.ExitCode = strings.TrimPrefix(err.Error(), "exit code ")
				} else {
					res.ExitCode = "ERR"
				}
			} else {
				res.Success = true
				res.ExitCode = "0"
			}

			results[idx] = res
		}(i, node)
	}

	wg.Wait()

	// Render summary table
	fmt.Println("\n==================================================")
	fmt.Println("             Fleet Execution Summary              ")
	fmt.Println("==================================================")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NODE\tSTATUS\tEXIT CODE\tDURATION")
	hasFailure := false
	succeededCount := 0
	for _, r := range results {
		status := "SUCCESS"
		if !r.Success {
			status = "FAILED"
			hasFailure = true
		} else {
			succeededCount++
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Node, status, r.ExitCode, r.Duration)
	}
	w.Flush()
	fmt.Println("==================================================")
	fmt.Printf("Total: %d | Succeeded: %d | Failed: %d\n\n", len(results), succeededCount, len(results)-succeededCount)

	if hasFailure {
		return fmt.Errorf("fleet execution failed on 1 or more nodes")
	}
	return nil
}
