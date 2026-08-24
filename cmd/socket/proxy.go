package main

import (
	"encoding/json"
	"log"
	"net"

	"fabric/internal/protocol"
)

// StartTCPProxy listens on raw TCP and forwards traffic to the mesh nodes.
func StartTCPProxy() {
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		log.Println("TCP Proxy error:", err)
		return
	}
	log.Println("Starting TCP Proxy on :80")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}

		go handleTCPConn(conn)
	}
}

func handleTCPConn(conn net.Conn) {
	defer conn.Close()

	nodesLock.RLock()
	var targetNode *NodeState
	for _, n := range nodes {
		targetNode = n
		break
	}
	nodesLock.RUnlock()

	if targetNode == nil {
		return
	}

	stream, err := targetNode.Mux.Session.Open()
	if err != nil {
		return
	}
	defer stream.Close()

	req := protocol.ProxyRequest{
		Type: protocol.TypeProxyRequest,
	}
	b, _ := json.Marshal(req)
	stream.Write(b)

	protocol.Proxy(stream, conn)
}
