package cli

import (
	"encoding/json"
	"fabric/internal/protocol"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
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

		dir := filepath.Dir(srcPath)
		base := filepath.Base(srcPath)
		tarCmd := exec.Command("tar", "-cf", "-", "-C", dir, base)
		stdout, err := tarCmd.StdoutPipe()
		if err != nil {
			return err
		}
		if err := tarCmd.Start(); err != nil {
			return fmt.Errorf("failed to start tar: %w", err)
		}

		io.Copy(stream, stdout)
		tarCmd.Wait()
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

	destDir := destPath
	tarCmd := exec.Command("tar", "-xf", "-", "-C", destDir)
	stdin, err := tarCmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := tarCmd.Start(); err != nil {
		return fmt.Errorf("failed to start local tar unpacker: %w", err)
	}

	io.Copy(stdin, stream)
	stdin.Close()
	tarCmd.Wait()
	return nil
}
