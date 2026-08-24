package main

import (
	"encoding/json"
	"fabric/internal/protocol"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
)

func handleCopyRequest(stream net.Conn, envelope []byte) {
	defer stream.Close()

	var req protocol.CopyRequest
	if err := json.Unmarshal(envelope, &req); err != nil {
		return
	}

	if req.Direction == "download" {
		dir := filepath.Dir(req.RemotePath)
		base := filepath.Base(req.RemotePath)
		cmd := exec.Command("tar", "-cf", "-", "-C", dir, base)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return
		}
		if err := cmd.Start(); err != nil {
			return
		}

		io.Copy(stream, stdout)
		cmd.Wait()
	} else if req.Direction == "upload" {
		os.MkdirAll(req.RemotePath, 0755)
		cmd := exec.Command("tar", "-xf", "-", "-C", req.RemotePath)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return
		}

		if err := cmd.Start(); err != nil {
			return
		}

		io.Copy(stdin, stream)
		stdin.Close()
		cmd.Wait()
	}
}
