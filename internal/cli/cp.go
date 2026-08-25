package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	cpCmd.RunE = runCp
}

func parsePathSpec(spec string) (thread string, path string, isRemote bool) {
	if idx := strings.Index(spec, ":"); idx != -1 {
		return spec[:idx], spec[idx+1:], true
	}
	return "", spec, false
}

func runCp(cmd *cobra.Command, args []string) error {
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

	if !srcIsRemote && destIsRemote {
		// Upload: local -> remote thread
		return client.Upload(destThread, srcPath, destPath)
	}

	// Download: remote thread -> local
	return client.Download(srcThread, srcPath, destPath)
}
