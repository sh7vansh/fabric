package main

import (
	"encoding/json"
	"fabric/internal/protocol"
	"log"
	"net"
)

func handleCopyRequest(stream net.Conn, envelope []byte) {
	defer stream.Close()

	var req protocol.CopyRequest
	if err := json.Unmarshal(envelope, &req); err != nil {
		return
	}

	if req.Direction == "download" {
		if err := protocol.CreateTar(stream, req.RemotePath); err != nil {
			log.Println("Error creating tar for download:", err)
		}
	} else if req.Direction == "upload" {
		if err := protocol.ExtractTar(stream, req.RemotePath); err != nil {
			log.Println("Error extracting tar for upload:", err)
		}
	}
}
