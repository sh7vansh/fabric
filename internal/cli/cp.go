package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	cpCmd.RunE = runCp
}

func parsePathSpec(spec string) (node string, path string, isRemote bool) {
	if idx := strings.Index(spec, ":"); idx != -1 {
		return spec[:idx], spec[idx+1:], true
	}
	return "", spec, false
}

func runCp(cmd *cobra.Command, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: fabric cp [OPTIONS] SRC_PATH DEST_PATH")
	}

	srcNode, srcPath, srcIsRemote := parsePathSpec(args[0])
	destNode, destPath, destIsRemote := parsePathSpec(args[1])

	if srcIsRemote && destIsRemote {
		return fmt.Errorf("node-to-node copy is not supported")
	}
	if !srcIsRemote && !destIsRemote {
		return fmt.Errorf("at least one of SRC_PATH or DEST_PATH must be a remote node (e.g. node:path)")
	}

	client := NewClient(GetConfig())

	if !srcIsRemote && destIsRemote {
		// Upload: local -> remote node
		return client.Upload(destNode, srcPath, destPath)
	}

	// Download: remote node -> local
	return client.Download(srcNode, srcPath, destPath)
}
