package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"fabric/internal/protocol"
)

var (
	proxyConns     = make(map[string]net.Conn)
	proxyConnsLock sync.RWMutex
	connIDCounter  int
	connIDLock     sync.Mutex
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
	// For raw TCP without SNI/Host peeking, we just route to the first available node.
	nodesLock.RLock()
	var targetNodeName string
	for name := range nodes {
		targetNodeName = name
		break
	}
	nodeConn := nodes[targetNodeName]
	nodesLock.RUnlock()

	if nodeConn == nil {
		conn.Close()
		return
	}

	connIDLock.Lock()
	connIDCounter++
	connID := fmt.Sprintf("conn-%d", connIDCounter)
	connIDLock.Unlock()

	proxyConnsLock.Lock()
	proxyConns[connID] = conn
	proxyConnsLock.Unlock()

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			nodeConn.WriteJSON(protocol.ProxyStream{
				Type:     protocol.TypeProxyStream,
				ConnID:   connID,
				Data:     base64.StdEncoding.EncodeToString(buf[:n]),
				IsClosed: false,
			})
		}
		if err != nil {
			if err != io.EOF {
				log.Println("TCP proxy read error:", err)
			}
			nodeConn.WriteJSON(protocol.ProxyStream{
				Type:     protocol.TypeProxyStream,
				ConnID:   connID,
				Data:     "",
				IsClosed: true,
			})
			proxyConnsLock.Lock()
			delete(proxyConns, connID)
			proxyConnsLock.Unlock()
			conn.Close()
			break
		}
	}
}
