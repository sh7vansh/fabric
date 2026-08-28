package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var cpQuietFlag bool

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

func init() {
	cpCmd.Flags().BoolVarP(&cpQuietFlag, "quiet", "q", false, "Suppress transfer summary output")
	cpCmd.RunE = runCp
}

func parsePathSpec(spec string) (thread string, path string, isRemote bool) {
	if idx := strings.Index(spec, ":"); idx != -1 {
		return spec[:idx], spec[idx+1:], true
	}
	return "", spec, false
}

func runCp(cmd *cobra.Command, args []string) error {
	defer func() {
		cpQuietFlag = false
	}()

	if len(args) < 2 {
		return fmt.Errorf("usage: fabric cp [flags] SRC_PATH DEST_PATH")
	}

	srcThread, srcPath, srcIsRemote := parsePathSpec(args[0])
	destThread, destPath, destIsRemote := parsePathSpec(args[1])

	if srcIsRemote && destIsRemote {
		return fmt.Errorf("thread-to-thread copy is not supported")
	}
	if !srcIsRemote && !destIsRemote {
		return fmt.Errorf("at least one of SRC_PATH or DEST_PATH must be a remote thread (e.g. thread:/path)")
	}

	client := NewClient(GetConfig())
	start := time.Now()

	if !srcIsRemote && destIsRemote {
		// Upload: local -> remote thread
		bytes, err := client.Upload(destThread, srcPath, destPath)
		if err != nil {
			return err
		}
		if !cpQuietFlag {
			elapsed := time.Since(start).Round(time.Millisecond)
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Transferred %s to %s:%s in %s\n", formatBytes(bytes), destThread, destPath, elapsed)
		}
		return nil
	}

	// Download: remote thread -> local
	bytes, err := client.Download(srcThread, srcPath, destPath)
	if err != nil {
		return err
	}
	if !cpQuietFlag {
		elapsed := time.Since(start).Round(time.Millisecond)
		fmt.Fprintf(cmd.OutOrStdout(), "✓ Transferred %s from %s:%s to %s in %s\n", formatBytes(bytes), srcThread, srcPath, destPath, elapsed)
	}
	return nil
}
