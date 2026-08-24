package main

import (
	"encoding/json"
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
		resp := protocol.ProxyResponse{
			Type:    protocol.TypeProxyResponse,
			Success: false,
			Error:   err.Error(),
		}
		if b, marshalErr := json.Marshal(resp); marshalErr == nil {
			stream.Write(b)
		}
		return
	}

	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Println("Node proxy dial error:", err)
		resp := protocol.ProxyResponse{
			Type:    protocol.TypeProxyResponse,
			Success: false,
			Error:   err.Error(),
		}
		if b, marshalErr := json.Marshal(resp); marshalErr == nil {
			stream.Write(b)
		}
		return
	}
	defer conn.Close()

	protocol.Proxy(stream, conn)
}
