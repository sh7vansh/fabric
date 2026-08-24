package main

import (
	"encoding/base64"
	"fabric/internal/protocol"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/gorilla/websocket"
)

var (
	copyWriters     = make(map[string]io.WriteCloser)
	copyWritersLock sync.RWMutex
)

func handleCopyRequest(c *websocket.Conn, req protocol.CopyRequest) {
	if req.Direction == "download" {
		// Node -> CLI: package RemotePath into tar
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

		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := stdout.Read(buf)
				if n > 0 {
					c.WriteJSON(protocol.CopyStream{
						Type:       protocol.TypeCopyStream,
						TransferID: req.TransferID,
						Data:       base64.StdEncoding.EncodeToString(buf[:n]),
					})
				}
				if err != nil {
					break
				}
			}
			cmd.Wait()
			c.WriteJSON(protocol.CopyStream{
				Type:       protocol.TypeCopyStream,
				TransferID: req.TransferID,
				IsEOF:      true,
			})
		}()
	} else if req.Direction == "upload" {
		// CLI -> Node: unpack tar to RemotePath
		os.MkdirAll(req.RemotePath, 0755)
		cmd := exec.Command("tar", "-xf", "-", "-C", req.RemotePath)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return
		}

		copyWritersLock.Lock()
		copyWriters[req.TransferID] = stdin
		copyWritersLock.Unlock()

		if err := cmd.Start(); err != nil {
			return
		}

		go func() {
			cmd.Wait()
		}()
	}
}

func handleCopyStream(stream protocol.CopyStream) {
	copyWritersLock.RLock()
	w, ok := copyWriters[stream.TransferID]
	copyWritersLock.RUnlock()

	if ok {
		if stream.IsEOF {
			w.Close()
			copyWritersLock.Lock()
			delete(copyWriters, stream.TransferID)
			copyWritersLock.Unlock()
		} else {
			data, _ := base64.StdEncoding.DecodeString(stream.Data)
			w.Write(data)
		}
	}
}
