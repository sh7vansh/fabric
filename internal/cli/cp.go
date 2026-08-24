package cli

import (
	"encoding/json"
	"fabric/internal/protocol"
	"fmt"
	"strings"
	"time"

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
	conn, err := client.DialWebSocket()
	if err != nil {
		return fmt.Errorf("failed to connect to socket: %w", err)
	}
	defer conn.Close()

	mux, err := protocol.NewStreamMultiplexer(conn, false)
	if err != nil {
		return err
	}

	stream, err := mux.Session.Open()
	if err != nil {
		return err
	}
	defer stream.Close()

	transferID := fmt.Sprintf("xfer-%d", time.Now().UnixNano())

	if !srcIsRemote && destIsRemote {
		// Upload: local -> remote node
		req := protocol.CopyRequest{
			Type:           protocol.TypeCopyRequest,
			TransferID:     transferID,
			TargetHostname: destNode,
			Direction:      "upload",
			RemotePath:     destPath,
		}

		b, _ := json.Marshal(req)
		stream.Write(b)

		if err := protocol.CreateTar(stream, srcPath); err != nil {
			return fmt.Errorf("failed to create upload archive: %w", err)
		}
		return nil
	}

	// Download: remote node -> local
	req := protocol.CopyRequest{
		Type:           protocol.TypeCopyRequest,
		TransferID:     transferID,
		TargetHostname: srcNode,
		Direction:      "download",
		RemotePath:     srcPath,
	}

	b, _ := json.Marshal(req)
	stream.Write(b)

	if err := protocol.ExtractTar(stream, destPath); err != nil {
		return fmt.Errorf("failed to extract download archive: %w", err)
	}
	return nil
}
