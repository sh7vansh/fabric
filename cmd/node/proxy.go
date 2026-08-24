package main

import (
	"encoding/json"
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

	targetAddr, err := protocol.ValidateProxyDestination(req.TargetHost, req.TargetPort)
	if err != nil {
		log.Println("Blocked proxy request:", err)
		return
	}

	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Println("Node proxy dial error:", err)
		return
	}
	defer conn.Close()

	go io.Copy(stream, conn)
	io.Copy(conn, stream)
}
