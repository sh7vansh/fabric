package main

import (
	"encoding/base64"
	"fabric/internal/protocol"
	"github.com/gorilla/websocket"
	"io"
	"os/exec"
	"sync"
)

var (
	copyWriters     = make(map[string]io.WriteCloser)
	copyWritersLock sync.RWMutex
)

func handleCopyRequest(c *websocket.Conn, req protocol.CopyRequest) {
	if req.Direction == "download" {
		// Node -> CLI
		cmd := exec.Command("tar", "-cf", "-", "-C", ".", req.RemotePath)
		stdout, _ := cmd.StdoutPipe()
		cmd.Start()

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
		// CLI -> Node
		cmd := exec.Command("tar", "-xf", "-", "-C", req.RemotePath) // assumes RemotePath is the dest dir
		stdin, _ := cmd.StdinPipe()

		copyWritersLock.Lock()
		copyWriters[req.TransferID] = stdin
		copyWritersLock.Unlock()

		cmd.Start()

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
