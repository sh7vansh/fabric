package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"

	"fabric/internal/protocol"
)

func handleProxyRequest(stream net.Conn, envelope []byte) {
	defer stream.Close()

	var req protocol.ProxyRequest
	if err := json.Unmarshal(envelope, &req); err != nil {
		return
	}

	port := 80
	if req.TargetPort > 0 {
		port = req.TargetPort
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Println("Node proxy dial error:", err)
		return
	}
	defer conn.Close()

	go io.Copy(stream, conn)
	io.Copy(conn, stream)
}
